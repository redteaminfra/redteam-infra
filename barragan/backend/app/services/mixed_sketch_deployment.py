# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import re
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from app.core.runtime import start_runtime_task
from app.domain import JobEvent, JobRunDetail
from app.integrations.terraform_runner import LocalTerraformCommandRunner, TerraformCommandRunner
from app.services.credentials import resolve_default_credential_alias
from app.services.digitalocean_sketch_deployment import (
    DIGITALOCEAN_SKETCH_CONFIRMATION,
    DIGITALOCEAN_SKETCH_DEPLOY_ACTION,
    DIGITALOCEAN_SKETCH_TEARDOWN_ACTION,
    DIGITALOCEAN_SKETCH_WORKSPACE_NAME,
    run_digitalocean_sketch_job,
)
from app.services.engagements import get_engagement
from app.services.linode_sketch_deployment import (
    LINODE_SKETCH_CONFIRMATION,
    LINODE_SKETCH_DEPLOY_ACTION,
    LINODE_SKETCH_TEARDOWN_ACTION,
    LINODE_SKETCH_WORKSPACE_NAME,
    run_linode_sketch_job,
)
from app.services.managed_host_image_continuity import resolve_or_pin_profile_for_new_managed_host
from app.services.outbound_channel_artifacts import (
    collect_existing_outbound_channels_from_jobs,
    derive_pending_outbound_channels_from_sketch_rows,
)
from app.services.provider_region_policy import get_provider_region_policy
from app.services.redteam_infra_template import redteam_infra_sketch_template_dir
from app.services.sketch_ssh_keys import ensure_sketch_ssh_key
from app.services.sketch_component_identity import (
    child_inputs_from_job as _child_inputs_from_job,
    child_role as _child_role,
    components_from_job as _components_from_job,
    legacy_components as _legacy_components,
    validated_component_identities as _validated_component_identities,
)
from app.services.sketch_transport_ssh_keys import (
    ensure_sketch_transport_ssh_key,
)
from app.services.sketch_state_workspaces import (
    PreparedSketchStateWorkspace,
    grant_collaborator_access_to_existing_sketch_state_workspace,
    prepare_sketch_state_workspace,
    retained_compute_image_for_workspace,
    validate_existing_sketch_state_workspace,
)
from app.services.template_compatibility import (
    disable_legacy_sketch_local_artifacts,
    ensure_linode_firewall_protocol_compatibility,
    ensure_sketch_resource_name_suffix_compatibility,
)
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun


MIXED_SKETCH_DEPLOY_ACTION = "mixed_provider_sketch_deploy"
MIXED_SKETCH_TEARDOWN_ACTION = "mixed_provider_sketch_teardown"
MIXED_SKETCH_CONFIRMATION = "mutate-mixed-provider-sketch-testing"
SKETCH_PROVIDERS = {"linode", "digitalocean"}

BackgroundRunner = Callable[[Callable[[], None]], None]


class MixedSketchGuardrailError(ValueError):
    pass


def start_guarded_mixed_sketch_run(
    body: dict[str, Any],
    *,
    repository: JobRepository | None = None,
    runner: TerraformCommandRunner | None = None,
    background_runner: BackgroundRunner | None = None,
) -> JobRunDetail:
    spec = _guarded_body(body)
    repo = repository or SqlAlchemyJobRepository()
    ensure_sketch_ssh_key(spec["engagementId"])
    ensure_sketch_transport_ssh_key(spec["engagementId"])
    child_inputs = _child_inputs(
        spec,
        "",
        "",
        "",
        "",
    )
    workspace_root = _chain_root_from_children(child_inputs)
    job = repo.save(_new_mixed_job(MIXED_SKETCH_DEPLOY_ACTION, body, spec, child_inputs, workspace_root))
    running = repo.save(
        replace(
            job,
            status="running",
            started_at=_now(),
            events=job.events
            + [
                JobEvent(
                    _next_sequence(job.events),
                    "info",
                    "Mixed-provider sketch run started",
                    {
                        "workspace": "mixed-provider-sketch",
                        "workspaceDir": str(workspace_root),
                        "middleProvider": spec["middleProvider"],
                        "edgeProvider": spec["edgeProvider"],
                        "components": spec["components"],
                    },
                )
            ],
        )
    )
    task_runner = background_runner or (
        lambda task: start_runtime_task(task, name="barragan-mixed-sketch-runner", synchronous_when_testing=True)
    )
    task_runner(lambda: _run_persisted_mixed_sketch_job(running.id, repo, runner))
    return running.to_detail()


def get_guarded_mixed_sketch_run(job_id: str, *, repository: JobRepository | None = None) -> JobRunDetail | None:
    job = (repository or SqlAlchemyJobRepository()).get(job_id)
    if job is None or job.action not in {MIXED_SKETCH_DEPLOY_ACTION, MIXED_SKETCH_TEARDOWN_ACTION}:
        return None
    return job.to_detail()


def start_guarded_mixed_sketch_teardown(
    job_id: str,
    *,
    repository: JobRepository | None = None,
    runner: TerraformCommandRunner | None = None,
    background_runner: BackgroundRunner | None = None,
) -> JobRunDetail | None:
    repo = repository or SqlAlchemyJobRepository()
    existing = repo.get(job_id)
    if existing is None or existing.action != MIXED_SKETCH_DEPLOY_ACTION:
        return None
    spec = _spec_from_job(existing)
    child_inputs = _child_inputs_from_job(existing)
    components = _components_from_job(existing, child_inputs)
    automatic_cleanup_evidence = _verified_deploy_cleanup_evidence(existing, child_inputs)
    automatically_clean = automatic_cleanup_evidence[0] if automatic_cleanup_evidence else set()
    if automatically_clean == {str(component["componentId"]) for component in components}:
        workspace_root = _chain_root_from_children(child_inputs)
    else:
        workspace_root = _validate_retained_children(spec, child_inputs)
    teardown = repo.save(
        _new_mixed_job(
            MIXED_SKETCH_TEARDOWN_ACTION,
            existing.input,
            spec,
            child_inputs,
            workspace_root,
            requested_by=existing.requested_by,
            parent_job_id=existing.id,
        )
    )
    if automatically_clean == {str(component["componentId"]) for component in components}:
        # Derive the audit basis from the same ordered evidence that proved
        # cleanup; a looser second scan must not relabel an unattempted child.
        attempted_components = automatic_cleanup_evidence[1] if automatic_cleanup_evidence else set()
        teardown = repo.save(
            replace(
                teardown,
                events=teardown.events
                + _resequenced(
                    _automatic_cleanup_retirement_events(
                        teardown,
                        components,
                        source_job_id=existing.id,
                        attempted_component_ids=attempted_components,
                    ),
                    start=len(teardown.events) + 1,
                ),
            )
        )
    running = repo.save(
        replace(
            teardown,
            status="running",
            started_at=_now(),
            events=teardown.events
            + [
                JobEvent(
                    _next_sequence(teardown.events),
                    "info",
                    "Mixed-provider sketch teardown started",
                    {"workspace": "mixed-provider-sketch", "parentJobId": existing.id},
                )
            ],
        )
    )
    task_runner = background_runner or (
        lambda task: start_runtime_task(task, name="barragan-mixed-sketch-teardown-runner", synchronous_when_testing=True)
    )
    task_runner(lambda: _run_persisted_mixed_sketch_job(running.id, repo, runner))
    return running.to_detail()


def resume_guarded_mixed_sketch_teardown(
    job_id: str,
    *,
    repository: JobRepository | None = None,
    runner: TerraformCommandRunner | None = None,
    background_runner: BackgroundRunner | None = None,
) -> JobRunDetail | None:
    """Resume the same persisted mixed-provider teardown child."""

    repo = repository or SqlAlchemyJobRepository()
    job = repo.get(job_id)
    if job is None or job.action != MIXED_SKETCH_TEARDOWN_ACTION:
        return None
    child_inputs = _child_inputs_from_job(job)
    components = _components_from_job(job, child_inputs)
    retirement_components = _automatic_cleanup_retirement_component_ids(job, child_inputs)
    cleaned_components = _cleaned_teardown_component_ids(job, child_inputs) | retirement_components
    if retirement_components != {str(component["componentId"]) for component in components}:
        _validate_retained_children(
            _spec_from_job(job), child_inputs, cleaned_component_ids=cleaned_components
        )
    running = repo.save(
        replace(
            job,
            status="running",
            started_at=job.started_at or _now(),
            finished_at=None,
            events=job.events
            + [
                JobEvent(
                    _next_sequence(job.events),
                    "info",
                    "Mixed-provider sketch teardown resumed",
                    {"parentJobId": str(job.input.get("parentJobId") or "")},
                )
            ],
        )
    )
    task_runner = background_runner or (
        lambda task: start_runtime_task(task, name="barragan-mixed-sketch-teardown-runner", synchronous_when_testing=True)
    )
    task_runner(lambda: _run_persisted_mixed_sketch_job(running.id, repo, runner))
    return running.to_detail()


def _run_persisted_mixed_sketch_job(
    job_id: str,
    repository: JobRepository,
    runner: TerraformCommandRunner | None,
) -> JobRunDetail | None:
    job = repository.get(job_id)
    if job is None:
        return None
    try:
        status, events, artifacts = run_mixed_sketch_job(job, repository=repository, runner=runner)
    except Exception as exc:
        status = "failed"
        events = [
            JobEvent(
                0,
                "error",
                "mixed-provider sketch job failed",
                {"detail": type(exc).__name__, "chainId": str(job.input.get("chainId") or "")},
            )
        ]
        artifacts = []
    finished = repository.save(
        replace(
            job,
            status=status,
            finished_at=_now(),
            artifact_refs=artifacts,
            events=job.events + _resequenced(events, start=len(job.events) + 1),
        )
    )
    return finished.to_detail()


def run_mixed_sketch_job(
    job: StoredJobRun,
    *,
    repository: JobRepository,
    runner: TerraformCommandRunner | None = None,
) -> tuple[str, list[JobEvent], list[str]]:
    terraform = runner or LocalTerraformCommandRunner()
    if job.action == MIXED_SKETCH_DEPLOY_ACTION:
        return _deploy(job, terraform, repository)
    if job.action == MIXED_SKETCH_TEARDOWN_ACTION:
        return _teardown(job, terraform)
    raise ValueError(f"unsupported mixed sketch action: {job.action}")


def _deploy(
    parent: StoredJobRun,
    runner: TerraformCommandRunner,
    repository: JobRepository,
) -> tuple[str, list[JobEvent], list[str]]:
    events: list[JobEvent] = []
    child_inputs = _child_inputs_from_job(parent)
    completed_children: list[StoredJobRun] = []
    rows: list[dict[str, Any]] = []
    artifacts: list[str] = [f"terraform:mixed-sketch:{parent.target_id}:{parent.input.get('chainId')}"]

    for component in _components_from_job(parent, child_inputs):
        component_id = str(component["componentId"])
        child = _child_job(parent, component_id, child_inputs[component_id], deploy=True)
        role = str(component["role"])
        events.append(_event("info", f"{component_id} {role} provider deploy started", parent, {"role": role, "componentId": component_id, "provider": child.input["provider"]}))
        status, child_events, child_artifacts = _run_provider_child(child, runner, deploy=True)
        artifacts.extend(child_artifacts)
        events.extend(_annotated_child_events(component_id, role, child.input["provider"], child_events))
        if status != "succeeded":
            events.append(_event("error", f"{component_id} {role} provider deploy failed", parent, {"role": role, "componentId": component_id, "provider": child.input["provider"]}))
            _teardown_completed_children(parent, completed_children, runner, events)
            return "failed", events, artifacts
        completed_children.append(child)
        rows.extend(_rows_from_events(child_events))
        events.append(_event("info", f"{component_id} {role} provider deploy completed", parent, {"role": role, "componentId": component_id, "provider": child.input["provider"]}))

    outbound_channels = derive_pending_outbound_channels_from_sketch_rows(
        str(parent.input["engagementName"]),
        str(parent.input["chainId"]),
        rows,
        existing_outbound_channels=collect_existing_outbound_channels_from_jobs(repository.list(), str(parent.input["engagementId"])),
    )
    events.append(
        _event(
            "info",
            "mixed-provider sketch output recorded",
            parent,
            {
                "phase": "output",
                "sketchInfrastructure": rows,
                "outboundChannels": outbound_channels,
            },
        )
    )
    return "succeeded", events, artifacts


def _teardown(parent: StoredJobRun, runner: TerraformCommandRunner) -> tuple[str, list[JobEvent], list[str]]:
    events: list[JobEvent] = []
    child_inputs = _child_inputs_from_job(parent)
    components = _components_from_job(parent, child_inputs)
    retirement_components = _automatic_cleanup_retirement_component_ids(parent, child_inputs)
    cleaned_components = _cleaned_teardown_component_ids(parent, child_inputs) | retirement_components
    if retirement_components != {str(component["componentId"]) for component in components}:
        _validate_retained_children(
            _spec_from_job(parent), child_inputs, cleaned_component_ids=cleaned_components
        )
    artifacts: list[str] = [f"terraform:mixed-sketch-teardown:{parent.target_id}:{parent.input.get('chainId')}"]
    statuses: list[str] = []
    for component in reversed(components):
        component_id = str(component["componentId"])
        if component_id in cleaned_components:
            statuses.append("succeeded")
            events.append(
                _event(
                    "info",
                    f"{component_id} provider teardown already verified",
                    parent,
                    {
                        "role": str(component["role"]),
                        "componentId": component_id,
                        "provider": str(component["provider"]),
                        "phase": "cleanup",
                        "cleanupVerified": True,
                    },
                )
            )
            continue
        child = _child_job(parent, component_id, child_inputs[component_id], deploy=False)
        role = str(component["role"])
        events.append(_event("info", f"{component_id} {role} provider teardown started", parent, {"role": role, "componentId": component_id, "provider": child.input["provider"]}))
        status, child_events, child_artifacts = _run_provider_child(child, runner, deploy=False)
        statuses.append(status)
        artifacts.extend(child_artifacts)
        events.extend(_annotated_child_events(component_id, role, child.input["provider"], child_events))
        events.append(_event("info" if status == "succeeded" else "error", f"{component_id} {role} provider teardown {status}", parent, {"role": role, "componentId": component_id, "provider": child.input["provider"]}))
    if all(status == "succeeded" for status in statuses):
        events.append(_event("info", "mixed-provider sketch teardown verified", parent, {"phase": "cleanup", "cleanupVerified": True, "sketchInfrastructure": []}))
        return "succeeded", events, artifacts
    return "failed", events, artifacts


def _guarded_body(body: dict[str, Any]) -> dict[str, Any]:
    if body.get("confirmMutation") not in {MIXED_SKETCH_CONFIRMATION, LINODE_SKETCH_CONFIRMATION, DIGITALOCEAN_SKETCH_CONFIRMATION}:
        raise MixedSketchGuardrailError(f'confirmMutation must equal "{MIXED_SKETCH_CONFIRMATION}"')
    engagement_id = _required(body, "engagementId")
    engagement = get_engagement(engagement_id)
    if engagement is None:
        raise MixedSketchGuardrailError("engagementId must reference an existing engagement")
    selected_image_profile = resolve_or_pin_profile_for_new_managed_host(engagement_id)
    middle_provider = _provider(body, "middleProvider")
    raw_edges = body.get("edges")
    legacy_edge_alias = _alias(body, "edgeCredentialAlias")
    legacy_edge_count = _count(body.get("edgeCount"), field="edgeCount", default=1)
    edge_intents = raw_edges if isinstance(raw_edges, list) and raw_edges else [
        {"id": f"edge-{index:02d}", "provider": body.get("edgeProvider"), "region": body.get("edgeRegion"), "size": body.get("edgeSize")}
        for index in range(1, legacy_edge_count + 1)
    ]
    if len(edge_intents) > 10:
        raise MixedSketchGuardrailError("edges must contain from 1 to 10 rows")
    normalized_edges: list[dict[str, Any]] = []
    for index, edge in enumerate(edge_intents, start=1):
        if not isinstance(edge, dict):
            raise MixedSketchGuardrailError("each edge must be an object")
        edge_id = str(edge.get("id") or f"edge-{index:02d}").strip()
        provider = _provider(edge, "provider")
        region = _required(edge, "region")
        _validate_region(provider, region)
        normalized_edges.append({"id": edge_id, "provider": provider, "region": region, "size": str(edge.get("size") or _default_size(provider)).strip() or _default_size(provider), "credentialAlias": _alias(edge, "credentialAlias") or legacy_edge_alias or _default_alias(provider)})
    if len({edge["id"] for edge in normalized_edges}) != len(normalized_edges):
        raise MixedSketchGuardrailError("edge ids must be unique")
    edge_provider = str(normalized_edges[0]["provider"])
    edge_regions: list[str] = []
    regional_counts: dict[str, int] = {}
    for edge in normalized_edges:
        region = str(edge["region"])
        if region not in regional_counts:
            edge_regions.append(region)
            regional_counts[region] = 0
        regional_counts[region] += 1
    edge_count_per_region = next(iter(regional_counts.values()))
    middle_region = _required(body, "middleRegion")
    edge_region = str(normalized_edges[0]["region"])
    _validate_region(middle_provider, middle_region)
    edge_count = len(normalized_edges)
    middle_alias = _alias(body, "middleCredentialAlias") or _default_alias(middle_provider)
    edge_alias = _alias(body, "edgeCredentialAlias") or normalized_edges[0]["credentialAlias"] or _default_alias(edge_provider)
    if not middle_alias:
        raise MixedSketchGuardrailError(f"mixed-provider sketch mutation requires an active default {middle_provider} credential")
    missing_edge_provider = next((edge["provider"] for edge in normalized_edges if not edge.get("credentialAlias")), None)
    if missing_edge_provider:
        raise MixedSketchGuardrailError(f"mixed-provider sketch mutation requires an active default {missing_edge_provider} credential")
    individual_edges = _requires_individual_edge_components(normalized_edges)
    return {
        "engagementId": engagement_id,
        "engagementName": engagement.name,
        "managedHostImageProfile": selected_image_profile.name,
        "chainId": str(body.get("chainId") or "chain-1").strip() or "chain-1",
        "assignedProxy": str(body.get("assignedProxy") or "proxy01").strip() or "proxy01",
        "middleProvider": middle_provider,
        "edgeProvider": edge_provider,
        "middleCredentialAlias": middle_alias,
        "edgeCredentialAlias": edge_alias,
        "middleRegion": middle_region,
        "edgeRegion": edge_region,
        "middleSize": str(body.get("middleSize") or _default_size(middle_provider)).strip() or _default_size(middle_provider),
        "edgeSize": str(normalized_edges[0]["size"]),
        "edgeCount": edge_count,
        "edgeRegions": edge_regions,
        "edgeCountPerRegion": edge_count_per_region,
        "edges": normalized_edges,
        "individualEdges": individual_edges,
        "components": (
            [{"componentId": "middle", "role": "middle", "provider": middle_provider, "middleOrdinal": 1}]
            + [
                {"componentId": edge["id"], "role": "edge", "provider": edge["provider"], "edgeId": edge["id"], "edgeOrdinal": index}
                for index, edge in enumerate(normalized_edges, start=1)
            ]
            if individual_edges
            else [
                {"componentId": "middle", "role": "middle", "provider": middle_provider, "middleOrdinal": 1},
                {"componentId": "edges", "role": "edge", "provider": edge_provider, "edgeId": "", "edgeOrdinal": 1},
            ]
        ),
    }


def _child_inputs(
    spec: dict[str, Any],
    private_key_path: str,
    public_key_path: str,
    transport_private_key_path: str,
    transport_public_key_path: str,
) -> dict[str, dict[str, Any]]:
    children: dict[str, dict[str, Any]] = {}
    edges = {str(edge["id"]): edge for edge in spec["edges"]}
    for component in spec["components"]:
        component_id = str(component["componentId"])
        role = str(component["role"])
        edge = edges.get(component_id)
        provider = str(component["provider"])
        children[component_id] = _provider_child_input(
            spec, provider=provider,
            credential_alias=str((edge or {}).get("credentialAlias") or (spec["middleCredentialAlias"] if role == "middle" else spec["edgeCredentialAlias"] or _default_alias(provider) or "")),
            middle_count=1 if role == "middle" else 0,
            edge_count=0 if role == "middle" else (1 if spec["individualEdges"] else int(spec["edgeCount"])),
            workspace=_prepare_workspace(spec, provider, component_id), private_key_path=private_key_path, public_key_path=public_key_path,
            transport_private_key_path=transport_private_key_path, transport_public_key_path=transport_public_key_path,
            component_id=component_id, edge=edge, middle_ordinal=int(component.get("middleOrdinal") or 1), edge_ordinal=int(component.get("edgeOrdinal") or 1),
        )
    return children


def _provider_child_input(
    spec: dict[str, Any],
    *,
    provider: str,
    credential_alias: str,
    middle_count: int,
    edge_count: int,
    workspace: Path,
    private_key_path: str,
    public_key_path: str,
    transport_private_key_path: str,
    transport_public_key_path: str,
    component_id: str = "",
    edge: dict[str, Any] | None = None,
    middle_ordinal: int = 1,
    edge_ordinal: int = 1,
) -> dict[str, Any]:
    return {
        "provider": provider,
        "confirmMutation": LINODE_SKETCH_CONFIRMATION if provider == "linode" else DIGITALOCEAN_SKETCH_CONFIRMATION,
        "engagementId": spec["engagementId"],
        "engagementName": spec["engagementName"],
        "chainId": spec["chainId"],
        "assignedProxy": spec["assignedProxy"],
        "middleCredentialAlias": credential_alias,
        "edgeCredentialAlias": credential_alias,
        "middleRegion": spec["middleRegion"] if middle_count else str((edge or {}).get("region") or spec["edgeRegion"]),
        "edgeRegion": str((edge or {}).get("region") or spec["edgeRegion"]) if edge_count else spec["middleRegion"],
        "middleSize": spec["middleSize"] if middle_count else _default_size(provider),
        "edgeSize": str((edge or {}).get("size") or spec["edgeSize"]) if edge_count else _default_size(provider),
        "middleCount": middle_count,
        "edgeCount": edge_count,
        "edges": [] if not edge_count else ([edge] if edge is not None else list(spec.get("edges") or [])),
        "edgeRegions": [] if not edge_count else ([str(edge["region"])] if edge is not None else list(spec.get("edgeRegions") or [str((edge or {}).get("region") or spec["edgeRegion"])])),
        "edgeCountPerRegion": 1 if edge is not None and edge_count else int(spec.get("edgeCountPerRegion") or edge_count) if edge_count else 0,
        "terraformWorkingDirectory": str(workspace),
        "workspace": LINODE_SKETCH_WORKSPACE_NAME if provider == "linode" else DIGITALOCEAN_SKETCH_WORKSPACE_NAME,
        "sshPrivateKeyPath": private_key_path,
        "sshPublicKeyPath": public_key_path,
        "sketchTransportSshPrivateKeyPath": transport_private_key_path,
        "sketchTransportSshPublicKeyPath": transport_public_key_path,
        "componentId": component_id,
        "edgeId": str((edge or {}).get("id") or ""),
        "middleOrdinal": middle_ordinal,
        "edgeOrdinal": edge_ordinal,
        "resourceNameSuffix": _component_resource_name_suffix(spec["chainId"], component_id),
        "materializeKeyFiles": True,
        "managedHostImageProfile": spec["managedHostImageProfile"],
    }


def _prepare_workspace(spec: dict[str, Any], provider: str, component_id: str) -> Path:
    destination = prepare_sketch_state_workspace(
        str(spec["engagementId"]),
        str(spec["chainId"]),
        provider,
        component_id=component_id,
        template_directory=redteam_infra_sketch_template_dir(provider),
    ).path
    ensure_sketch_resource_name_suffix_compatibility(destination, provider)
    ensure_linode_firewall_protocol_compatibility(destination, provider)
    disable_legacy_sketch_local_artifacts(destination)
    return destination


def _chain_root_from_children(child_inputs: dict[str, dict[str, Any]]) -> Path:
    first = next(iter(child_inputs.values()))
    return Path(str(first["terraformWorkingDirectory"])).parents[2]


def _validate_retained_children(
    spec: dict[str, Any],
    child_inputs: dict[str, dict[str, Any]],
    *,
    cleaned_component_ids: set[str] | None = None,
) -> Path:
    cleaned = cleaned_component_ids or set()
    roots: set[Path] = set()
    retained: list[tuple[dict[str, Any], PreparedSketchStateWorkspace]] = []
    components = list(spec["components"]) or _legacy_components(
        child_inputs,
        middle_provider=str(spec["middleProvider"]),
        edge_provider=str(spec["edgeProvider"]),
    )
    for component in components:
        component_id = str(component["componentId"])
        child = child_inputs.get(component_id)
        if child is None:
            raise MixedSketchGuardrailError("retained mixed sketch component input is unavailable")
        validated = validate_existing_sketch_state_workspace(
            str(spec["engagementId"]),
            str(spec["chainId"]),
            str(component["provider"]),
            Path(str(child.get("terraformWorkingDirectory") or "")),
            component_id=component_id,
        )
        retained.append((component, validated))
        roots.add(validated.path.parents[2])
    if len(roots) != 1:
        raise MixedSketchGuardrailError("retained mixed sketch components do not share one canonical chain root")
    for component, validated in retained:
        if str(component["componentId"]) in cleaned:
            continue
        retained_compute_image_for_workspace(
            str(spec["engagementId"]),
            str(spec["chainId"]),
            str(component["provider"]),
            validated.path,
            component_id=str(component["componentId"]),
        )
    for component, validated in retained:
        grant_collaborator_access_to_existing_sketch_state_workspace(
            str(spec["engagementId"]),
            str(spec["chainId"]),
            str(component["provider"]),
            validated.path,
            component_id=str(component["componentId"]),
        )
    return next(iter(roots))


def _component_resource_name_suffix(chain_id: str, component_id: str) -> str:
    """Keep component-local provider resources distinct within one chain.

    Upstream templates derive firewall labels from the engagement name and
    ``resource_name_suffix``.  A heterogeneous chain runs one Terraform state
    per component, so every component must receive a stable suffix even when
    the chain itself is the first chain for its proxy.
    """

    base = _chain_resource_name_suffix(chain_id)
    normalized = "".join(character for character in component_id.lower() if character.isalnum())
    return f"{base}-{normalized}" if normalized else base


def _chain_resource_name_suffix(chain_id: str) -> str:
    proxy_match = re.search(r"(?:^|[^0-9])proxy0*([1-9][0-9]*)", chain_id.strip().lower())
    if proxy_match:
        ordinal = int(proxy_match.group(1))
    else:
        numeric_groups = re.findall(r"([0-9]+)", chain_id)
        ordinal = max(1, int(numeric_groups[-1])) if numeric_groups else 1
    return "" if ordinal <= 1 else f"-{ordinal:02d}"


def _new_mixed_job(
    action: str,
    body: dict[str, Any],
    spec: dict[str, Any],
    child_inputs: dict[str, dict[str, Any]],
    workspace_root: Path,
    *,
    requested_by: str | None = None,
    parent_job_id: str | None = None,
) -> StoredJobRun:
    created_at = _now()
    safe_input = {
        "confirmMutation": body.get("confirmMutation"),
        **spec,
        "terraformWorkspaceRoot": str(workspace_root),
        "terraformWorkingDirectories": {component_id: child["terraformWorkingDirectory"] for component_id, child in child_inputs.items()},
        "childInputs": child_inputs,
        "components": spec["components"],
    }
    if parent_job_id:
        safe_input["parentJobId"] = parent_job_id
    return StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=action,
        status="queued",
        target=f"engagement:{spec['engagementId']}",
        target_type="engagement",
        target_id=str(spec["engagementId"]),
        requested_by=str(requested_by or body.get("requestedBy") or "operator"),
        input=safe_input,
        artifact_refs=[],
        created_at=created_at,
        started_at=None,
        finished_at=None,
        events=[
            JobEvent(
                1,
                "info",
                "Mixed-provider sketch run queued" if action == MIXED_SKETCH_DEPLOY_ACTION else "Mixed-provider sketch teardown queued",
                {
                    "workspace": "mixed-provider-sketch",
                    "workspaceDir": str(workspace_root),
                    "engagementId": spec["engagementId"],
                    "chainId": spec["chainId"],
                    "middleProvider": spec["middleProvider"],
                    "edgeProvider": spec["edgeProvider"],
                },
            )
        ],
    )


def _run_provider_child(child: StoredJobRun, runner: TerraformCommandRunner, *, deploy: bool) -> tuple[str, list[JobEvent], list[str]]:
    provider = str(child.input["provider"])
    if provider == "linode":
        return run_linode_sketch_job(replace(child, action=LINODE_SKETCH_DEPLOY_ACTION if deploy else LINODE_SKETCH_TEARDOWN_ACTION), runner=runner, existing_outbound_channels=[])
    if provider == "digitalocean":
        return run_digitalocean_sketch_job(replace(child, action=DIGITALOCEAN_SKETCH_DEPLOY_ACTION if deploy else DIGITALOCEAN_SKETCH_TEARDOWN_ACTION), runner=runner, existing_outbound_channels=[])
    raise ValueError(f"unsupported sketch provider: {provider}")


def _child_job(parent: StoredJobRun, role: str, child_input: dict[str, Any], *, deploy: bool) -> StoredJobRun:
    provider = str(child_input["provider"])
    action = (
        LINODE_SKETCH_DEPLOY_ACTION
        if provider == "linode" and deploy
        else LINODE_SKETCH_TEARDOWN_ACTION
        if provider == "linode"
        else DIGITALOCEAN_SKETCH_DEPLOY_ACTION
        if deploy
        else DIGITALOCEAN_SKETCH_TEARDOWN_ACTION
    )
    return StoredJobRun(
        id=f"{parent.id}-{role}",
        action=action,
        status="running",
        target=parent.target,
        target_type=parent.target_type,
        target_id=parent.target_id,
        requested_by=parent.requested_by,
        input=child_input,
        artifact_refs=[],
        created_at=parent.created_at,
        started_at=parent.started_at,
        finished_at=None,
        events=[],
    )


def _teardown_completed_children(
    parent: StoredJobRun,
    completed_children: list[StoredJobRun],
    runner: TerraformCommandRunner,
    events: list[JobEvent],
) -> None:
    for child in reversed(completed_children):
        role = "middle" if int(child.input.get("middleCount") or 0) else "edge"
        component_id = str(child.input.get("componentId") or role)
        status, child_events, _artifacts = _run_provider_child(child, runner, deploy=False)
        events.extend(_annotated_child_events(component_id, role, child.input["provider"], child_events))
        events.append(_event("info" if status == "succeeded" else "error", f"{role} provider rollback {status}", parent, {"role": role, "provider": child.input["provider"]}))


def _rows_from_events(events: list[JobEvent]) -> list[dict[str, Any]]:
    for event in reversed(events):
        rows = event.data.get("sketchInfrastructure")
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _annotated_child_events(component_id: str, role: str, provider: Any, events: list[JobEvent]) -> list[JobEvent]:
    annotated = []
    for event in events:
        if event.data.get("phase") == "outbound_channel_derivation":
            continue
        annotated.append(
            JobEvent(
                0,
                event.level,
                event.message,
                {
                    **event.data,
                    "componentId": component_id,
                    "componentRole": role,
                    "componentProvider": str(provider),
                },
            )
        )
    return annotated


def _cleaned_teardown_component_ids(
    job: StoredJobRun,
    child_inputs: dict[str, dict[str, Any]],
) -> set[str]:
    """Resolve successful child cleanup evidence from this teardown job only."""

    components, validated_by_id, componentless_fallback = _validated_component_identities(job, child_inputs)
    cleaned: set[str] = set()
    for event in job.events:
        if not (
            event.level == "info"
            and event.message == "terraform cleanup verified"
            and event.data.get("phase") == "cleanup"
            and event.data.get("cleanupVerified") is True
            and event.data.get("sketchInfrastructure") == []
        ):
            continue
        component_id = event.data.get("componentId")
        role = event.data.get("componentRole")
        provider = event.data.get("componentProvider")
        if isinstance(component_id, str) and component_id:
            component = validated_by_id.get(component_id)
            if component is None:
                continue
            if role != component.get("role") or provider != component.get("provider"):
                continue
            cleaned.add(component_id)
            continue
        if not componentless_fallback:
            continue
        matches = [
            component
            for component in components
            if role == component.get("role") and provider == component.get("provider")
        ]
        if len(matches) == 1:
            cleaned.add(str(matches[0]["componentId"]))
    return cleaned


def _verified_deploy_cleanup_component_ids(
    job: StoredJobRun,
    child_inputs: dict[str, dict[str, Any]],
) -> set[str]:
    """Prove a failed mixed deploy left no attempted provider component live."""

    evidence = _verified_deploy_cleanup_evidence(job, child_inputs)
    return evidence[0] if evidence else set()


def _verified_deploy_cleanup_evidence(
    job: StoredJobRun,
    child_inputs: dict[str, dict[str, Any]],
) -> tuple[set[str], set[str]] | None:
    """Return all clean component IDs and the strictly proven attempted IDs."""

    if job.action != MIXED_SKETCH_DEPLOY_ACTION or job.status != "failed":
        return None
    components, validated_by_id, componentless_fallback = _validated_component_identities(job, child_inputs)
    if len(validated_by_id) != len(components) or len(validated_by_id) != len(child_inputs):
        return None
    if any(event.message == "mixed-provider sketch output recorded" for event in job.events):
        return None

    phases: dict[str, dict[str, int]] = {component_id: {} for component_id in validated_by_id}
    for event in job.events:
        event_component_id = _validated_event_component_id(
            event, components, validated_by_id, componentless_fallback
        )
        if event_component_id is None:
            continue
        component = validated_by_id[event_component_id]
        role = str(component["role"])
        if (
            event.level == "info"
            and event.message == f"{event_component_id} {role} provider deploy started"
            and event.data.get("componentId") == event_component_id
            and event.data.get("role") == role
            and event.data.get("provider") == component.get("provider")
        ):
            phase = "started"
        elif event.level == "error" and event.message == "terraform apply failed":
            phase = "apply_failed"
        elif event.level == "info" and event.message == "terraform destroy completed":
            phase = "destroyed"
        elif (
            event.level == "info"
            and event.message == "terraform cleanup verified"
            and event.data.get("phase") == "cleanup"
            and event.data.get("cleanupVerified") is True
            and "sketchInfrastructure" not in event.data
            and event.data.get("remainingOutputs") == []
        ):
            phase = "cleaned"
        elif (
            event.level == "error"
            and event.message == f"{event_component_id} {role} provider deploy failed"
            and event.data.get("componentId") == event_component_id
            and event.data.get("role") == role
            and event.data.get("provider") == component.get("provider")
        ):
            phase = "failed"
        elif "provider deploy completed" in event.message:
            return None
        else:
            continue
        if phase in phases[event_component_id]:
            return None
        phases[event_component_id][phase] = event.sequence
    attempted = {component_id for component_id, evidence in phases.items() if "started" in evidence}
    evidenced = {component_id for component_id, evidence in phases.items() if evidence}
    if not attempted or evidenced - attempted:
        return None
    required = ("started", "apply_failed", "destroyed", "cleaned", "failed")
    for component_id in attempted:
        evidence = phases[component_id]
        if any(phase not in evidence for phase in required):
            return None
        ordered_sequences = [evidence[phase] for phase in required]
        if len(set(ordered_sequences)) != len(required) or ordered_sequences != sorted(ordered_sequences):
            return None
    return set(validated_by_id), attempted


def _validated_event_component_id(
    event: JobEvent,
    components: list[dict[str, Any]],
    validated_by_id: dict[str, dict[str, Any]],
    componentless_fallback: bool,
) -> str | None:
    component_id = event.data.get("componentId")
    role = event.data.get("componentRole")
    provider = event.data.get("componentProvider")
    if isinstance(component_id, str) and component_id:
        component = validated_by_id.get(component_id)
        if component is None:
            return None
        event_role = role if role is not None else event.data.get("role")
        event_provider = provider if provider is not None else event.data.get("provider")
        if event_role == component.get("role") and event_provider == component.get("provider"):
            return component_id
        return None
    if not componentless_fallback:
        return None
    matches = [
        component
        for component in components
        if role == component.get("role") and provider == component.get("provider")
    ]
    return str(matches[0]["componentId"]) if len(matches) == 1 else None


def _automatic_cleanup_retirement_events(
    teardown: StoredJobRun,
    components: list[dict[str, Any]],
    *,
    source_job_id: str,
    attempted_component_ids: set[str],
) -> list[JobEvent]:
    return [
        _event(
            "info",
            f"{component['componentId']} provider cleanup already verified",
            teardown,
            {
                "phase": "cleanup",
                "cleanupVerified": True,
                "sketchInfrastructure": [],
                "remainingOutputs": [],
                "componentId": str(component["componentId"]),
                "componentRole": str(component["role"]),
                "componentProvider": str(component["provider"]),
                "evidenceSource": "failed_mixed_deploy_automatic_cleanup",
                "sourceJobId": source_job_id,
                "cleanupBasis": (
                    "automatic_cleanup_verified"
                    if str(component["componentId"]) in attempted_component_ids
                    else "not_attempted"
                ),
            },
        )
        for component in components
    ]


def _automatic_cleanup_retirement_component_ids(
    job: StoredJobRun,
    child_inputs: dict[str, dict[str, Any]],
) -> set[str]:
    source_job_id = job.input.get("parentJobId")
    if job.action != MIXED_SKETCH_TEARDOWN_ACTION or not isinstance(source_job_id, str) or not source_job_id:
        return set()
    components, validated_by_id, _fallback = _validated_component_identities(job, child_inputs)
    if len(validated_by_id) != len(components) or len(validated_by_id) != len(child_inputs):
        return set()
    verified: set[str] = set()
    for event in job.events:
        component_id = event.data.get("componentId")
        component = validated_by_id.get(component_id) if isinstance(component_id, str) else None
        if component is None:
            continue
        if (
            event.level == "info"
            and event.message == f"{component_id} provider cleanup already verified"
            and event.data.get("phase") == "cleanup"
            and event.data.get("cleanupVerified") is True
            and event.data.get("sketchInfrastructure") == []
            and event.data.get("remainingOutputs") == []
            and event.data.get("componentRole") == component.get("role")
            and event.data.get("componentProvider") == component.get("provider")
            and event.data.get("evidenceSource") == "failed_mixed_deploy_automatic_cleanup"
            and event.data.get("sourceJobId") == source_job_id
            and event.data.get("cleanupBasis") in {"automatic_cleanup_verified", "not_attempted"}
        ):
            verified.add(component_id)
    return verified


def _spec_from_job(job: StoredJobRun) -> dict[str, Any]:
    return {
        "engagementId": _required(job.input, "engagementId"),
        "engagementName": _required(job.input, "engagementName"),
        "chainId": _required(job.input, "chainId"),
        "assignedProxy": _required(job.input, "assignedProxy"),
        "middleProvider": _required(job.input, "middleProvider"),
        "edgeProvider": _required(job.input, "edgeProvider"),
        "middleCredentialAlias": _required(job.input, "middleCredentialAlias"),
        "edgeCredentialAlias": _required(job.input, "edgeCredentialAlias"),
        "middleRegion": _required(job.input, "middleRegion"),
        "edgeRegion": _required(job.input, "edgeRegion"),
        "middleSize": _required(job.input, "middleSize"),
        "edgeSize": _required(job.input, "edgeSize"),
        "edgeCount": _count(job.input.get("edgeCount"), field="edgeCount", default=1),
        "edges": list(job.input.get("edges") or [{"id": "edge-01", "provider": _required(job.input, "edgeProvider"), "region": _required(job.input, "edgeRegion"), "size": _required(job.input, "edgeSize")}]),
        "components": list(job.input.get("components") or []),
        "individualEdges": bool(job.input.get("individualEdges")),
        "managedHostImageProfile": _required(job.input, "managedHostImageProfile"),
    }


def _event(level: str, message: str, parent: StoredJobRun, data: dict[str, Any]) -> JobEvent:
    return JobEvent(
        0,
        level,
        message,
        {
            "provider": "mixed",
            "engagementId": parent.input.get("engagementId"),
            "chainId": parent.input.get("chainId"),
            "middleProvider": parent.input.get("middleProvider"),
            "edgeProvider": parent.input.get("edgeProvider"),
            **data,
        },
    )


def _resequenced(events: list[JobEvent], *, start: int) -> list[JobEvent]:
    return [JobEvent(start + index, event.level, event.message, event.data) for index, event in enumerate(events)]


def _next_sequence(events: list[JobEvent]) -> int:
    return max((event.sequence for event in events), default=0) + 1


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _provider(data: dict[str, Any], key: str) -> str:
    provider = _required(data, key).lower()
    if provider not in SKETCH_PROVIDERS:
        raise MixedSketchGuardrailError(f"{key} must be linode or digitalocean")
    return provider


def _validate_region(provider: str, region: str) -> None:
    if region not in set(get_provider_region_policy(provider).allowed_regions):
        raise MixedSketchGuardrailError(
            f"{provider} sketch deployments are restricted to configured allowed regions; blocked: {region}"
        )


def _count(value: Any, *, field: str, default: int) -> int:
    try:
        count = default if value in (None, "") else int(value)
    except (TypeError, ValueError) as exc:
        raise MixedSketchGuardrailError(f"{field} must be an integer from 1 to 10") from exc
    if count < 0 or count > 10:
        raise MixedSketchGuardrailError(f"{field} must be an integer from 1 to 10")
    return count


def _alias(data: dict[str, Any], key: str) -> str | None:
    value = str(data.get(key) or "").strip().lower()
    return value or None


def _default_alias(provider: str) -> str | None:
    try:
        return resolve_default_credential_alias(provider)
    except RuntimeError:
        return None


def _default_size(provider: str) -> str:
    return "g6-nanode-1" if provider == "linode" else "s-1vcpu-1gb"


def _requires_individual_edge_components(edges: list[dict[str, Any]]) -> bool:
    """Use one copied provider workspace per edge when batch Terraform cannot express it."""

    if len({str(edge["provider"]) for edge in edges}) > 1:
        return True
    if len({str(edge["size"]) for edge in edges}) > 1:
        return True
    regional_counts: dict[str, int] = {}
    for edge in edges:
        region = str(edge["region"])
        regional_counts[region] = regional_counts.get(region, 0) + 1
    return len(set(regional_counts.values())) > 1


def _required(data: dict[str, Any], key: str) -> str:
    value = str(data.get(key) or "").strip()
    if not value:
        raise MixedSketchGuardrailError(f"{key} is required")
    return value
