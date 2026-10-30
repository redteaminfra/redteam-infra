# Copyright (c) 2026, Oracle and/or its affiliates.
"""Exact persisted identity joins for routed sketch components."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from app.storage.job_repository import StoredJobRun
from app.storage.sketch_chain_repository import StoredSketchChain
from app.services.sketch_state_workspaces import validate_existing_sketch_state_workspace


class SketchComponentIdentityError(ValueError):
    pass


@dataclass(frozen=True)
class ResolvedSketchComponent:
    component_id: str
    role: str
    provider: str
    hostname: str
    workspace: Path
    provider_input: dict[str, Any]


@dataclass(frozen=True)
class ResolvedChannelSketchComponents:
    edge: ResolvedSketchComponent
    middle: ResolvedSketchComponent


def child_inputs_from_job(job: StoredJobRun) -> dict[str, dict[str, Any]]:
    raw = job.input.get("childInputs")
    if not isinstance(raw, dict):
        raise ValueError("mixed sketch job is missing childInputs")
    if not raw or not all(isinstance(key, str) and isinstance(value, dict) for key, value in raw.items()):
        raise ValueError("mixed sketch job has invalid childInputs")
    return {str(key): value for key, value in raw.items()}


def components_from_job(job: StoredJobRun, child_inputs: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    if "components" in job.input:
        raw = job.input["components"]
        if not isinstance(raw, list) or not raw or not all(isinstance(component, dict) for component in raw):
            raise ValueError("mixed sketch job has invalid components")
        return [dict(component) for component in raw]
    return legacy_components(
        child_inputs,
        middle_provider=_required(job.input, "middleProvider"),
        edge_provider=_required(job.input, "edgeProvider"),
    )


def legacy_components(
    child_inputs: dict[str, dict[str, Any]],
    *,
    middle_provider: str,
    edge_provider: str,
) -> list[dict[str, Any]]:
    """Recover only the historical, provably unique two-child layout."""

    if len(child_inputs) != 2:
        raise ValueError("legacy mixed sketch job does not have exactly two child inputs")
    resolved: list[dict[str, Any]] = []
    for component_id, child in child_inputs.items():
        provider = str(child.get("provider") or "")
        persisted_component_id = child.get("componentId")
        if persisted_component_id not in {None, "", component_id}:
            raise ValueError("legacy mixed sketch child component identity is ambiguous")
        role = child_role(child)
        expected_provider = middle_provider if role == "middle" else edge_provider
        if provider != expected_provider:
            raise ValueError("legacy mixed sketch child provider does not match its role")
        resolved.append({"componentId": component_id, "role": role, "provider": provider})
    if {component["role"] for component in resolved} != {"middle", "edge"}:
        raise ValueError("legacy mixed sketch child roles are ambiguous")
    return sorted(resolved, key=lambda component: 0 if component["role"] == "middle" else 1)


def child_role(child: dict[str, Any]) -> str:
    """Derive one unambiguous provider-child role from persisted counts."""

    middle_count = _count(child.get("middleCount"))
    edge_count = _count(child.get("edgeCount"))
    edge_count_per_region = _count(child.get("edgeCountPerRegion"))
    if middle_count > 0 and edge_count == 0 and edge_count_per_region == 0:
        return "middle"
    if middle_count == 0 and (edge_count > 0 or edge_count_per_region > 0):
        return "edge"
    raise ValueError("mixed sketch child role is ambiguous")


def validated_component_identities(
    job: StoredJobRun,
    child_inputs: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], bool]:
    """Validate the component evidence used by mixed deploy and recovery."""

    components = components_from_job(job, child_inputs)
    component_ids = [component.get("componentId") for component in components]
    unique_ids = {
        component_id
        for component_id in component_ids
        if isinstance(component_id, str)
        and component_id
        and component_ids.count(component_id) == 1
    }
    validated_by_id: dict[str, dict[str, Any]] = {}
    for component in components:
        component_id = component.get("componentId")
        if component_id not in unique_ids or component_id not in child_inputs:
            continue
        child = child_inputs[component_id]
        try:
            identity_matches = (
                child.get("provider") == component.get("provider")
                and child_role(child) == component.get("role")
                and child.get("componentId") in {None, "", component_id}
            )
        except (TypeError, ValueError):
            identity_matches = False
        if identity_matches:
            validated_by_id[component_id] = component
    componentless_fallback = (
        len(validated_by_id) == len(components) == len(child_inputs) == 2
        and {component.get("role") for component in validated_by_id.values()} == {"middle", "edge"}
        and len({(component.get("role"), component.get("provider")) for component in validated_by_id.values()}) == 2
    )
    return components, validated_by_id, componentless_fallback


def resolve_channel_sketch_components(
    engagement_id: str,
    chain: StoredSketchChain,
    deploy_job: StoredJobRun,
    channel: dict[str, Any],
    sketch_rows: list[dict[str, Any]],
    *,
    workspace_validator: Callable[..., Any] = validate_existing_sketch_state_workspace,
) -> ResolvedChannelSketchComponents:
    """Join a routed channel to exact persisted deploy components and workspaces."""

    if chain.engagement_id != engagement_id or deploy_job.target_id != engagement_id:
        raise SketchComponentIdentityError("sketch component engagement identity does not match")
    if deploy_job.id != chain.deploy_job_id:
        raise SketchComponentIdentityError("sketch deploy job does not match the persisted chain")
    if _text(channel.get("chainId")) != chain.chain_id:
        raise SketchComponentIdentityError("channel chain identity does not match")
    if _text(deploy_job.input.get("engagementId")) != engagement_id or _text(deploy_job.input.get("chainId")) != chain.chain_id:
        raise SketchComponentIdentityError("sketch deploy job identity does not match")

    edge_row = _unique_route_row(sketch_rows, channel, chain.chain_id, "edge", "edgeComponentId")
    middle_row = _unique_route_row(sketch_rows, channel, chain.chain_id, "middle", "middleComponentId")
    _require_persisted_row(chain, edge_row, "edge")
    _require_persisted_row(chain, middle_row, "middle")
    if "childInputs" in deploy_job.input:
        if not isinstance(deploy_job.input["childInputs"], dict):
            raise SketchComponentIdentityError("sketch deploy child inputs are malformed")
        _require_deploy_job(deploy_job, {"mixed_provider_sketch_deploy"}, engagement_id)
        return _resolve_keyed_components(
            engagement_id, chain, deploy_job, channel, edge_row, middle_row,
            workspace_validator=workspace_validator,
        )
    provider = _text(chain.edge_provider)
    _require_deploy_job(
        deploy_job,
        {f"{provider}_sketch_deploy", f"{provider}_sketch_reconcile"},
        engagement_id,
    )
    if "components" in deploy_job.input:
        raise SketchComponentIdentityError("shared sketch deploy has unexpected component evidence")
    return _resolve_shared_same_provider(
        engagement_id, chain, deploy_job, edge_row, middle_row,
        workspace_validator=workspace_validator,
    )


def _resolve_keyed_components(
    engagement_id: str,
    chain: StoredSketchChain,
    deploy_job: StoredJobRun,
    channel: dict[str, Any],
    edge_row: dict[str, Any],
    middle_row: dict[str, Any],
    *,
    workspace_validator: Callable[..., Any],
) -> ResolvedChannelSketchComponents:
    try:
        child_inputs = child_inputs_from_job(deploy_job)
        components, validated, legacy_fallback = validated_component_identities(deploy_job, child_inputs)
    except ValueError as exc:
        raise SketchComponentIdentityError("sketch deploy component evidence is malformed") from exc
    if len(components) != len(child_inputs) or len(validated) != len(components):
        raise SketchComponentIdentityError("sketch deploy component identities are incomplete or ambiguous")
    for component in components:
        component_id = _text(component.get("componentId"))
        role = _text(component.get("role"))
        expected_provider = _text(chain.edge_provider if role == "edge" else chain.middle_provider if role == "middle" else "")
        if not expected_provider or _text(component.get("provider")) != expected_provider or _text(child_inputs[component_id].get("provider")) != expected_provider:
            raise SketchComponentIdentityError("sketch deploy provider identity does not match the persisted chain")
    workspace_map = deploy_job.input.get("terraformWorkingDirectories")
    modern = isinstance(deploy_job.input.get("components"), list)
    if modern and (not isinstance(workspace_map, dict) or set(workspace_map) != set(child_inputs)):
        raise SketchComponentIdentityError("sketch deploy workspace mapping is incomplete or ambiguous")
    if not modern and not legacy_fallback:
        raise SketchComponentIdentityError("legacy sketch component identity is not uniquely recoverable")

    def resolve(role: str, row: dict[str, Any]) -> ResolvedSketchComponent:
        component_id = _text(row.get("componentId"))
        component = validated.get(component_id)
        child = child_inputs.get(component_id)
        if component is None or child is None or component.get("role") != role:
            raise SketchComponentIdentityError(f"selected {role} component is not present in deploy evidence")
        if modern and _text(child.get("componentId")) != component_id:
            raise SketchComponentIdentityError(f"selected {role} child component identity does not match")
        provider = _text(component.get("provider"))
        expected_provider = _text(chain.edge_provider if role == "edge" else chain.middle_provider)
        if provider != expected_provider or provider != _text(row.get("provider")) or provider != _text(child.get("provider")):
            raise SketchComponentIdentityError(f"selected {role} provider identity does not match")
        for key, expected in (("engagementId", engagement_id), ("chainId", chain.chain_id)):
            actual = _text(child.get(key))
            if modern and actual != expected:
                raise SketchComponentIdentityError(f"selected {role} child {key} does not match")
            if not modern and actual and actual != expected:
                raise SketchComponentIdentityError(f"selected {role} child {key} does not match")
        workspace_text = _text(child.get("terraformWorkingDirectory"))
        if not workspace_text:
            raise SketchComponentIdentityError(f"selected {role} workspace is unavailable")
        if isinstance(workspace_map, dict) and _text(workspace_map.get(component_id)) != workspace_text:
            raise SketchComponentIdentityError(f"selected {role} workspace mapping does not match")
        try:
            prepared = workspace_validator(
                engagement_id, chain.chain_id, provider, Path(workspace_text), component_id=component_id,
            )
        except ValueError as exc:
            raise SketchComponentIdentityError(f"selected {role} workspace is not canonical") from exc
        return ResolvedSketchComponent(component_id, role, provider, _text(row.get("hostname")), prepared.path, child)

    return ResolvedChannelSketchComponents(resolve("edge", edge_row), resolve("middle", middle_row))


def _resolve_shared_same_provider(
    engagement_id: str,
    chain: StoredSketchChain,
    deploy_job: StoredJobRun,
    edge_row: dict[str, Any],
    middle_row: dict[str, Any],
    *,
    workspace_validator: Callable[..., Any],
) -> ResolvedChannelSketchComponents:
    provider = _text(chain.edge_provider)
    if not provider or provider != _text(chain.middle_provider):
        raise SketchComponentIdentityError("non-keyed sketch deploy evidence is not a shared same-provider workspace")
    if _text(edge_row.get("provider")) != provider or _text(middle_row.get("provider")) != provider:
        raise SketchComponentIdentityError("shared sketch provider identity does not match")
    middle_count = _strict_count(deploy_job.input.get("middleCount"), "middleCount")
    edge_count = _strict_count(deploy_job.input.get("edgeCount"), "edgeCount")
    if middle_count != 1 or edge_count != chain.edge_count:
        raise SketchComponentIdentityError("shared sketch deploy role counts do not match the persisted chain")
    chain_rows = [row for row in chain.nodes if isinstance(row, dict)]
    middle_rows = [row for row in chain_rows if _text(row.get("chainId")) == chain.chain_id and _text(row.get("role")) == "middle"]
    edge_rows = [row for row in chain_rows if _text(row.get("chainId")) == chain.chain_id and _text(row.get("role")) == "edge"]
    if len(middle_rows) != 1 or len(edge_rows) != chain.edge_count:
        raise SketchComponentIdentityError("shared sketch rows do not match persisted role counts")
    identities = [(_text(row.get("hostname")), _text(row.get("componentId"))) for row in middle_rows + edge_rows]
    if (
        any(not hostname or not component_id for hostname, component_id in identities)
        or len({hostname for hostname, _ in identities}) != len(identities)
        or len({component_id for _, component_id in identities}) != len(identities)
    ):
        raise SketchComponentIdentityError("shared sketch row identities are missing or ambiguous")
    if any(_text(row.get("provider")) != provider for row in middle_rows + edge_rows):
        raise SketchComponentIdentityError("shared sketch row provider identity does not match")
    workspace_text = _text(chain.terraform_working_directory) or _text(deploy_job.input.get("terraformWorkingDirectory"))
    if not workspace_text or (
        _text(chain.terraform_working_directory)
        and _text(deploy_job.input.get("terraformWorkingDirectory"))
        and _text(chain.terraform_working_directory) != _text(deploy_job.input.get("terraformWorkingDirectory"))
    ):
        raise SketchComponentIdentityError("shared sketch workspace identity does not match")
    try:
        prepared = workspace_validator(engagement_id, chain.chain_id, provider, Path(workspace_text), component_id=None)
    except ValueError as exc:
        raise SketchComponentIdentityError("shared sketch workspace is not canonical") from exc
    return ResolvedChannelSketchComponents(
        ResolvedSketchComponent(_text(edge_row["componentId"]), "edge", provider, _text(edge_row.get("hostname")), prepared.path, deploy_job.input),
        ResolvedSketchComponent(_text(middle_row["componentId"]), "middle", provider, _text(middle_row.get("hostname")), prepared.path, deploy_job.input),
    )


def _unique_route_row(
    rows: list[dict[str, Any]],
    channel: dict[str, Any],
    chain_id: str,
    role: str,
    component_field: str,
) -> dict[str, Any]:
    hostname = _text(channel.get(role))
    component_id = _text(channel.get(component_field))
    if not hostname or not component_id:
        raise SketchComponentIdentityError(f"channel omitted selected {role} component identity")
    matches = [
        row for row in rows
        if isinstance(row, dict)
        and _text(row.get("chainId")) == chain_id
        and _text(row.get("role")) == role
        and _text(row.get("hostname")) == hostname
        and _text(row.get("componentId")) == component_id
    ]
    if len(matches) != 1:
        raise SketchComponentIdentityError(f"selected {role} route identity is missing or ambiguous")
    return matches[0]


def _require_persisted_row(chain: StoredSketchChain, selected: dict[str, Any], role: str) -> None:
    identity = tuple(_text(selected.get(key)) for key in ("chainId", "hostname", "componentId", "role", "provider"))
    matches = [
        row for row in chain.nodes
        if isinstance(row, dict)
        and tuple(_text(row.get(key)) for key in ("chainId", "hostname", "componentId", "role", "provider")) == identity
    ]
    if len(matches) != 1 or identity[3] != role:
        raise SketchComponentIdentityError(f"selected {role} row does not match persisted chain evidence")


def _required(values: dict[str, Any], key: str) -> str:
    value = _text(values.get(key))
    if not value:
        raise ValueError(f"mixed sketch job is missing {key}")
    return value


def _require_deploy_job(job: StoredJobRun, actions: set[str], engagement_id: str) -> None:
    if (
        job.action not in actions
        or job.status != "succeeded"
        or job.target != f"engagement:{engagement_id}"
        or job.target_type != "engagement"
        or job.target_id != engagement_id
    ):
        raise SketchComponentIdentityError("persisted sketch deploy job evidence is not authoritative")


def _strict_count(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise SketchComponentIdentityError(f"shared sketch deploy {field} is invalid")
    if type(value) is int:
        parsed = value
    elif isinstance(value, str) and value.strip().isascii() and value.strip().isdigit():
        parsed = int(value.strip())
    else:
        raise SketchComponentIdentityError(f"shared sketch deploy {field} is invalid")
    if parsed < 0:
        raise SketchComponentIdentityError(f"shared sketch deploy {field} is invalid")
    return parsed


def _count(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("mixed sketch child count is invalid") from exc


def _text(value: Any) -> str:
    return str(value or "").strip()
