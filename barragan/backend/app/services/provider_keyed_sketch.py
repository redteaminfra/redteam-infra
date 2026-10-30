# Copyright (c) 2026, Oracle and/or its affiliates.
"""Experimental, DevTest-only provider-scoped Sketch state contract.

This module does not dispatch Terraform. Callers bind the administrator-managed
provider connection, prepare one workspace, render the complete topology, and
inspect the exact saved plan before invoking ``terraform apply``. Existing
chain/component workspaces are deliberately outside this path.
"""

from __future__ import annotations

import hashlib
import fcntl
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from app.storage.credential_repository import CredentialRepository, SqlAlchemyCredentialRepository
from app.services.sketch_state_workspaces import (
    _chmod_tree,
    _private_root,
    _set_private_directory_access,
    _set_private_file_access,
    _token,
    _unsafe_private_directory,
    _unsafe_workspace_descendant,
)
from app.services.terraform_plan_gate import (
    PROVIDER_FIREWALL_COMPUTED_ATTRIBUTES,
    PlannedResourceChange,
    TerraformPlanGateError,
    saved_plan_resource_changes,
)

SCHEMA = "provider-keyed-v2"
_PROVIDERS = frozenset({"linode", "digitalocean"})
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_TOPOLOGY_NAME = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,63}$")


class ProviderKeyedSketchError(ValueError):
    pass


@dataclass(frozen=True)
class ProviderKeyedWorkspace:
    path: Path
    state_path: Path
    terraform_data_dir: Path
    schema: str
    provider: str
    provider_connection_id: str
    connection_fingerprint: str
    source_revision: str
    source_sha256: str


def resolve_default_provider_connection(
    provider: str,
    *,
    repository: CredentialRepository | None = None,
) -> str:
    """Return the immutable ID of Barragan's active provider default.

    The ID survives secret rotation; a different default is a different
    connection and must not silently claim an existing Terraform state.
    """

    if provider not in _PROVIDERS:
        raise ProviderKeyedSketchError("unsupported Sketch provider")
    credential = (repository or SqlAlchemyCredentialRepository()).get_default(provider)
    if credential is None or credential.status != "active" or credential.provider != provider:
        raise ProviderKeyedSketchError("active default provider connection is unavailable")
    try:
        return _token(credential.id, "provider connection id")
    except ValueError as exc:
        raise ProviderKeyedSketchError("provider connection id is invalid") from exc


def prepare_provider_keyed_workspace(
    engagement_id: str,
    provider: str,
    provider_connection_id: str,
    *,
    template_root: Path,
    source_revision: str,
    root: Path,
    environment: str,
    deployment_target: str,
) -> ProviderKeyedWorkspace:
    """Copy one committed upstream provider root into an isolated state scope.

    ``provider_connection_id`` is the immutable ID of Barragan's
    administrator-managed credential record, not a user, token, or alias.
    The current pilot permits one connection per engagement/provider; a
    changed default cannot silently create an adjacent state. Reuse requires
    the same schema, connection, source, and source files.
    """

    if environment != "devtest" or deployment_target != "barragan-testing":
        raise ProviderKeyedSketchError("provider-keyed-v2 requires DevTest barragan-testing scope")
    engagement = _token(engagement_id, "engagement id")
    if provider not in _PROVIDERS:
        raise ProviderKeyedSketchError("unsupported Sketch provider")
    try:
        connection_id = _token(provider_connection_id, "provider connection id")
    except ValueError as exc:
        raise ProviderKeyedSketchError("provider connection id is invalid") from exc
    if not _REVISION.fullmatch(source_revision):
        raise ProviderKeyedSketchError("upstream source revision must be a full Git commit")
    source = template_root.resolve(strict=True)
    if _git_revision(source) != source_revision or _git_dirty(source):
        raise ProviderKeyedSketchError("upstream template source must match a clean committed revision")
    template = source / "external" / "sketch" / provider
    if not template.is_dir() or template.is_symlink():
        raise ProviderKeyedSketchError("upstream Sketch provider template is unavailable")
    tracked_files = _tracked_template_files(source, provider)
    source_files = _source_files(template, tracked_files)
    source_sha256 = hashlib.sha256(json.dumps(source_files, sort_keys=True).encode()).hexdigest()
    if not source_files or "middle.tf" not in source_files or "edge.tf" not in source_files:
        raise ProviderKeyedSketchError("upstream Sketch provider template is incomplete")
    overlays = {
        "providers.tf": "barragan-v2/providers.tf",
        ".terraform.lock.hcl": "barragan-v2/.terraform.lock.hcl",
    }
    if provider in {"digitalocean", "linode"}:
        overlays["firewall.tf"] = "barragan-v2/firewall.tf"
    if any(source_name not in source_files or target_name not in source_files
           for target_name, source_name in overlays.items()
           if target_name != ".terraform.lock.hcl") or overlays[".terraform.lock.hcl"] not in source_files:
        raise ProviderKeyedSketchError("provider-keyed provider pin is missing")
    rendered_files = dict(source_files)
    for target_name, source_name in overlays.items():
        rendered_files[target_name] = source_files[source_name]
    fingerprint = hashlib.sha256(f"{provider}\0{connection_id}".encode()).hexdigest()
    state_root = _private_root(root)
    provider_root = state_root / engagement / SCHEMA / provider
    target = provider_root / fingerprint
    current = state_root
    for name in (engagement, SCHEMA, provider):
        current = current / name
        if current.exists() and (current.is_symlink() or _unsafe_private_directory(current)):
            raise ProviderKeyedSketchError("provider-keyed state ancestor is unsafe")
    if provider_root.exists() and any(child.name != fingerprint for child in provider_root.iterdir()):
        raise ProviderKeyedSketchError("provider connection changed; existing state requires reviewed rebind")
    marker = {
        "schema": SCHEMA,
        "engagement_id": engagement,
        "provider": provider,
        "provider_connection_id": connection_id,
        "connection_fingerprint": fingerprint,
        "source_revision": source_revision,
        "source_files": source_files,
        "rendered_files": rendered_files,
    }
    marker_path = target / ".barragan-provider-keyed-state.json"
    if target.exists():
        if target.is_symlink() or not target.is_dir():
            raise ProviderKeyedSketchError("provider-keyed state path is unsafe")
        if any(path.is_symlink() or _unsafe_workspace_descendant(path) for path in [target, *target.rglob("*")]):
            raise ProviderKeyedSketchError("provider-keyed state ownership or permissions are unsafe")
        try:
            retained = json.loads(marker_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProviderKeyedSketchError("provider-keyed state ownership marker is missing") from exc
        if retained != marker or _source_files(target, tuple(rendered_files)) != rendered_files:
            raise ProviderKeyedSketchError("provider-keyed state source or ownership changed")
        if any(
            _terraform_loadable(path.name) and path.relative_to(target).as_posix() not in tracked_files
            for path in target.rglob("*") if path.is_file()
        ):
            raise ProviderKeyedSketchError("provider-keyed state contains an unpinned Terraform source file")
    else:
        current = state_root
        for name in (engagement, SCHEMA, provider):
            current = current / name
            if current.exists():
                if current.is_symlink() or _unsafe_private_directory(current):
                    raise ProviderKeyedSketchError("provider-keyed state ancestor is unsafe")
            else:
                current.mkdir(mode=0o700)
                _set_private_directory_access(current)
        target.mkdir(mode=0o700)
        for relative in tracked_files:
            destination = target / relative
            destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            shutil.copy2(template / relative, destination)
        for target_name, source_name in overlays.items():
            shutil.copy2(template / source_name, target / target_name)
        _chmod_tree(target)
        marker_path.write_text(json.dumps(marker, sort_keys=True) + "\n", encoding="utf-8")
        _set_private_file_access(marker_path)
    data_dir = target / ".terraform-data"
    data_dir.mkdir(mode=0o700, exist_ok=True)
    data_dir.chmod(0o700)
    return ProviderKeyedWorkspace(
        path=target,
        state_path=target / "terraform.tfstate",
        terraform_data_dir=data_dir,
        schema=SCHEMA,
        provider=provider,
        provider_connection_id=connection_id,
        connection_fingerprint=fingerprint,
        source_revision=source_revision,
        source_sha256=source_sha256,
    )


def compile_provider_topology(
    middles: Mapping[str, Any],
    edge_groups: Mapping[str, Any],
    *,
    previous: Mapping[str, Any] | None = None,
    regional_high_water: Mapping[str, int] | None = None,
    external_middles: Mapping[str, Any] | None = None,
    provider: str | None = None,
) -> dict[str, Any]:
    """Expand group counts into durable regional ordinals.

    Decreasing a count is ambiguous and must be expressed by explicit
    ``ordinals``. A retired regional ordinal stays allocated forever in this
    engagement/provider scope, including when all nodes in its group retire.
    """

    if not isinstance(middles, Mapping) or not middles:
        raise ProviderKeyedSketchError("at least one middle node is required")
    if not isinstance(edge_groups, Mapping):
        raise ProviderKeyedSketchError("edge groups must be a map")
    prior = previous or {}
    if prior and prior.get("schema") != SCHEMA:
        raise ProviderKeyedSketchError("existing topology uses a different state schema")
    high_water = dict(regional_high_water or {})
    for region, ordinal in prior.get("regional_high_water", {}).items():
        high_water[region] = max(high_water.get(region, 0), ordinal)
    baseline_high_water = high_water.copy()
    previous_groups = prior.get("edge_groups", {})
    result_middles: dict[str, dict[str, Any]] = {}
    used_middle_ordinals: set[int] = set()
    for name, raw in middles.items():
        _name(name, "middle node")
        if not isinstance(raw, Mapping):
            raise ProviderKeyedSketchError("middle node must be an object")
        ordinal = _positive_int(raw.get("ordinal"), "middle ordinal")
        if ordinal in used_middle_ordinals:
            raise ProviderKeyedSketchError("middle ordinals must be unique")
        used_middle_ordinals.add(ordinal)
        result_middles[name] = {"region": _region(raw.get("region"), "middle region"), "ordinal": ordinal}
    prior_external = prior.get("external_middles", {})
    if not isinstance(prior_external, dict):
        raise ProviderKeyedSketchError("retained external middle identity is invalid")
    requested_external = external_middles if external_middles is not None else prior_external
    if not isinstance(requested_external, Mapping):
        raise ProviderKeyedSketchError("external middles must be a map")
    result_external: dict[str, dict[str, str]] = {}
    for name, raw in requested_external.items():
        _name(name, "external middle")
        if name in result_middles or not isinstance(raw, Mapping) or set(raw) != {
            "provider", "chain_id", "terraform_address", "provider_instance_id",
        }:
            raise ProviderKeyedSketchError("external middle identity is invalid")
        foreign = raw["provider"]
        if (not isinstance(foreign, str) or foreign not in _PROVIDERS
                or (provider is not None and foreign == provider)):
            raise ProviderKeyedSketchError("external middle provider is invalid")
        prefix = "linode_instance" if foreign == "linode" else "digitalocean_droplet"
        if (raw["terraform_address"] != f'{prefix}.middle["{name}"]'
                or not isinstance(raw["chain_id"], str) or not raw["chain_id"]
                or not isinstance(raw["provider_instance_id"], str)
                or not raw["provider_instance_id"]):
            raise ProviderKeyedSketchError("external middle identity is invalid")
        result_external[name] = dict(raw)
    if any(result_external.get(name) != identity for name, identity in prior_external.items()):
        raise ProviderKeyedSketchError("retained external middle identity is immutable")
    result_groups: dict[str, dict[str, Any]] = {}
    used_edges: set[tuple[str, int]] = set()
    reserved_explicit: dict[str, set[int]] = {}
    for raw in edge_groups.values():
        if not isinstance(raw, Mapping) or "ordinals" not in raw:
            continue
        region = _region(raw.get("region"), "edge region")
        values = raw["ordinals"]
        if not isinstance(values, list):
            raise ProviderKeyedSketchError("edge ordinals must be a list")
        reserved_explicit.setdefault(region, set()).update(_positive_int(value, "edge ordinal") for value in values)
    for name, raw in sorted(edge_groups.items()):
        _name(name, "edge group")
        if not isinstance(raw, Mapping):
            raise ProviderKeyedSketchError("edge group must be an object")
        region = _region(raw.get("region"), "edge region")
        middle_node = raw.get("middle_node")
        if (not isinstance(middle_node, str)
                or middle_node not in result_middles and middle_node not in result_external):
            raise ProviderKeyedSketchError("edge group references an unknown middle node")
        has_count = "count" in raw
        has_ordinals = "ordinals" in raw
        if has_count == has_ordinals:
            raise ProviderKeyedSketchError("edge group requires exactly one of count or ordinals")
        prior_group = previous_groups.get(name, {})
        prior_ordinals = list(prior_group.get("ordinals", []))
        if prior_group and (prior_group.get("region") != region or prior_group.get("middle_node") != middle_node):
            raise ProviderKeyedSketchError("retained edge group region and middle node are immutable")
        if has_count:
            count = _positive_int(raw["count"], "edge count")
            if count < len(prior_ordinals):
                raise ProviderKeyedSketchError("reduce an edge group with explicit ordinals")
            ordinals = prior_ordinals.copy()
            while len(ordinals) < count:
                high_water[region] = int(high_water.get(region, 0)) + 1
                while high_water[region] in reserved_explicit.get(region, set()):
                    high_water[region] += 1
                ordinals.append(high_water[region])
        else:
            values = raw["ordinals"]
            if not isinstance(values, list) or (not values and not prior_group):
                raise ProviderKeyedSketchError("edge ordinals must be a list; only a retained group may become empty")
            ordinals = [_positive_int(value, "edge ordinal") for value in values]
            if len(set(ordinals)) != len(ordinals):
                raise ProviderKeyedSketchError("edge ordinals must be unique")
            additions = set(ordinals) - set(prior_ordinals)
            if (prior or regional_high_water) and any(value <= int(baseline_high_water.get(region, 0)) for value in additions):
                raise ProviderKeyedSketchError("retired regional ordinals cannot be reused")
            high_water[region] = max([int(high_water.get(region, 0)), *ordinals])
        for ordinal in ordinals:
            identity = (region, ordinal)
            if identity in used_edges:
                raise ProviderKeyedSketchError("edge ordinals overlap within a region")
            used_edges.add(identity)
        result_groups[name] = {"region": region, "middle_node": middle_node, "ordinals": sorted(ordinals)}
    if set(previous_groups) - set(result_groups):
        raise ProviderKeyedSketchError("retire selected edges with explicit ordinals before removing a group")
    result = {
        "schema": SCHEMA,
        "middles": dict(sorted(result_middles.items())),
        "edge_groups": dict(sorted(result_groups.items())),
        "regional_high_water": dict(sorted(high_water.items())),
    }
    if result_external:
        result["external_middles"] = dict(sorted(result_external.items()))
    return result


def reserve_provider_topology(
    workspace: ProviderKeyedWorkspace,
    middles: Mapping[str, Any],
    edge_groups: Mapping[str, Any],
) -> dict[str, Any]:
    """Persist one complete provider topology and engagement-wide ordinals.

    A single lock serializes allocation across provider-connection workspaces in
    the engagement. The high-water ledger is written first: a crash can leave
    an unused ordinal, but cannot allow an ordinal to be reused. A failed
    Terraform plan leaves the desired topology for an exact forward retry.
    """

    schema_root = _validated_provider_workspace(workspace)
    lock_path = schema_root / ".regional-ordinals.lock"
    ledger_path = schema_root / "regional-ordinals.json"
    topology_path = workspace.path / ".barragan-topology.json"
    if _unsafe_private_directory(schema_root):
        raise ProviderKeyedSketchError("provider-keyed schema directory is unsafe")
    try:
        descriptor = os.fdopen(os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), "r+b")
    except OSError as exc:
        raise ProviderKeyedSketchError("regional ordinal lock is unsafe") from exc
    try:
        _set_private_file_access(lock_path)
        fcntl.flock(descriptor.fileno(), fcntl.LOCK_EX)
        if (schema_root / ".mixed-external-reservation.json").exists():
            raise ProviderKeyedSketchError("mixed external reservation must finish first")
        if not ledger_path.exists() and any(schema_root.glob("*/*/.barragan-topology.json")):
            raise ProviderKeyedSketchError("engagement regional ordinal ledger is missing")
        ledger = _read_json(ledger_path, default={})
        prior = _read_json(topology_path, default={})
        _validate_provider_state_phase(workspace, prior)
        if not isinstance(ledger, dict) or not all(
            isinstance(region, str) and type(value) is int and value >= 0
            for region, value in ledger.items()
        ):
            raise ProviderKeyedSketchError("engagement regional ordinal ledger is invalid")
        compiled = compile_provider_topology(
            middles, edge_groups, previous=prior, regional_high_water=ledger,
            provider=workspace.provider,
        )
        _write_json(ledger_path, compiled["regional_high_water"])
        _write_json(topology_path, compiled)
        return compiled
    finally:
        fcntl.flock(descriptor.fileno(), fcntl.LOCK_UN)
        descriptor.close()


def _validated_provider_workspace(workspace: ProviderKeyedWorkspace) -> Path:
    schema_root = workspace.path.parents[1]
    if (schema_root.name != SCHEMA or workspace.path.parent.name != workspace.provider
            or workspace.path.name != workspace.connection_fingerprint):
        raise ProviderKeyedSketchError("provider-keyed workspace path is invalid")
    marker = workspace.path / ".barragan-provider-keyed-state.json"
    if workspace.path.is_symlink() or workspace.path.resolve(strict=True) != workspace.path or marker.is_symlink():
        raise ProviderKeyedSketchError("provider-keyed state path is unsafe")
    try:
        ownership = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProviderKeyedSketchError("provider-keyed state ownership marker is missing") from exc
    if any(ownership.get(field) != expected for field, expected in {
        "schema": SCHEMA,
        "provider": workspace.provider,
        "provider_connection_id": workspace.provider_connection_id,
        "connection_fingerprint": workspace.connection_fingerprint,
        "source_revision": workspace.source_revision,
    }.items()):
        raise ProviderKeyedSketchError("provider-keyed state ownership marker changed")
    pinned_files = ownership.get("source_files")
    rendered_files = ownership.get("rendered_files")
    if (not isinstance(pinned_files, dict)
            or hashlib.sha256(json.dumps(pinned_files, sort_keys=True).encode()).hexdigest() != workspace.source_sha256
            or not isinstance(rendered_files, dict)
            or _source_files(workspace.path, tuple(rendered_files)) != rendered_files):
        raise ProviderKeyedSketchError("provider-keyed Terraform source changed")
    return schema_root


def _validate_provider_state_phase(workspace: ProviderKeyedWorkspace, prior: Any) -> None:
    phase = _read_json(workspace.path / ".barragan-apply-phase.json", default={})
    if phase and phase not in (
        {"schema": SCHEMA, "phase": "apply_started"},
        {"schema": SCHEMA, "phase": "applied"},
    ):
        raise ProviderKeyedSketchError("provider-keyed apply phase metadata is invalid")
    if workspace.state_path.exists() and not prior:
        raise ProviderKeyedSketchError("retained Terraform state has no provider topology metadata")
    if phase and not workspace.state_path.is_file():
        raise ProviderKeyedSketchError("provider-keyed Terraform state is missing after an apply began")


def reserve_mixed_external_provider_topologies(
    workspaces: Mapping[str, ProviderKeyedWorkspace],
    proposal: Any,
) -> dict[str, dict[str, Any]]:
    """Persist a reviewed opposite-provider pair under the shared ordinal lock.

    A durable intent marker permits exact forward recovery if the process stops
    between file replacements. This only reserves desired topology; it neither
    runs Terraform nor authorizes either Apply.
    """
    from app.services.provider_keyed_mixed_append_reservation import (
        MixedAppendReservationProposal, _digest,
    )

    if (type(proposal) is not MixedAppendReservationProposal
            or set(workspaces) != _PROVIDERS
            or len(proposal.reservations) != 2
            or tuple(row.provider for row in proposal.reservations)
               != proposal.reviewed_provider_order
            or set(proposal.reviewed_provider_order) != _PROVIDERS):
        raise ProviderKeyedSketchError("mixed external reservation pair is invalid")
    roots = {_validated_provider_workspace(workspaces[provider]) for provider in _PROVIDERS}
    if len(roots) != 1 or any(workspaces[p].provider != p for p in _PROVIDERS):
        raise ProviderKeyedSketchError("mixed provider workspaces do not share one engagement")
    schema_root = roots.pop()
    if _unsafe_private_directory(schema_root):
        raise ProviderKeyedSketchError("provider-keyed schema directory is unsafe")
    ledger_path = schema_root / "regional-ordinals.json"
    marker_path = schema_root / ".mixed-external-reservation.json"
    lock_path = schema_root / ".regional-ordinals.lock"
    try:
        descriptor = os.fdopen(os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), "r+b")
    except OSError as exc:
        raise ProviderKeyedSketchError("regional ordinal lock is unsafe") from exc
    try:
        _set_private_file_access(lock_path)
        fcntl.flock(descriptor.fileno(), fcntl.LOCK_EX)
        ledger = _read_json(ledger_path, default={})
        prior = {p: _read_json(workspaces[p].path / ".barragan-topology.json", default={})
                 for p in _PROVIDERS}
        for provider in _PROVIDERS:
            _validate_provider_state_phase(workspaces[provider], prior[provider])
        expected = {row.provider: row.proposed_topology for row in proposal.reservations}
        for row in proposal.reservations:
            proposed = row.proposed_topology
            foreign = proposed.get("external_middles", {}).get(row.foreign_middle_key)
            group = proposed.get("edge_groups", {}).get(row.edge_group_key)
            if (foreign != {
                    "provider": row.foreign_middle_provider,
                    "chain_id": row.chain_id,
                    "terraform_address": row.foreign_middle_address,
                    "provider_instance_id": row.foreign_middle_id,
                } or group != {
                    "region": row.edge_region, "middle_node": row.foreign_middle_key,
                    "ordinals": [row.edge_ordinal],
                } or row.foreign_middle_provider == row.provider
                or row.edge_address != (
                    f'{"linode_instance" if row.provider == "linode" else "digitalocean_droplet"}'
                    f'.edge["{row.edge_region}-{row.edge_ordinal:02d}"]'
                )):
                raise ProviderKeyedSketchError("mixed external reservation identity differs")
        retained_marker = _read_json(marker_path, default={})
        original_ledger = (retained_marker.get("original_ledger") if retained_marker
                           else proposal.original_high_water)
        original_topologies = (retained_marker.get("original_topologies") if retained_marker
                               else proposal.original_topologies)
        completed = (not retained_marker and ledger == proposal.proposed_high_water
                     and prior == expected)
        marker = {
            "schema": "mixed-external-reservation-v1",
            "order": list(proposal.reviewed_provider_order),
            "prior": {row.provider: row.prior_topology_sha256 for row in proposal.reservations},
            "ledger": proposal.original_high_water_sha256,
            "original_ledger": original_ledger,
            "original_topologies": original_topologies,
            "proposed": expected,
        }
        if retained_marker and retained_marker != marker:
            raise ProviderKeyedSketchError("another mixed external reservation is unfinished")
        if not isinstance(original_ledger, dict) or _digest(original_ledger) != proposal.original_high_water_sha256:
            raise ProviderKeyedSketchError("original regional ordinal ledger differs")
        if (not isinstance(original_topologies, dict)
                or set(original_topologies) != _PROVIDERS
                or any(_digest(original_topologies[row.provider]) != row.prior_topology_sha256
                       for row in proposal.reservations)):
            raise ProviderKeyedSketchError("original provider topology differs")
        if _digest(ledger) not in {proposal.original_high_water_sha256,
                                   _digest(proposal.proposed_high_water)}:
            raise ProviderKeyedSketchError("regional ordinal ledger changed since review")
        for row in proposal.reservations:
            current = prior[row.provider]
            if current != original_topologies[row.provider] and not (
                (retained_marker or completed) and current == row.proposed_topology
            ):
                raise ProviderKeyedSketchError("provider topology changed since review")
        if not retained_marker and not completed and ledger != original_ledger:
            raise ProviderKeyedSketchError("regional ordinal ledger changed since review")
        # Recompile from the reviewed original ledger, even when recovering a
        # partial file transaction; advance the cursor in reviewed order.
        high_water = dict(original_ledger)
        for row in proposal.reservations:
            original = original_topologies[row.provider]
            proposed = row.proposed_topology
            compiled = compile_provider_topology(
                proposed["middles"], proposed["edge_groups"], previous=original,
                regional_high_water=high_water,
                external_middles=proposed["external_middles"], provider=row.provider,
            )
            if compiled != proposed:
                raise ProviderKeyedSketchError("external reservation differs from compiled topology")
            high_water = proposed["regional_high_water"]
        if high_water != proposal.proposed_high_water:
            raise ProviderKeyedSketchError("mixed external reservation ledger differs")
        if completed:
            return expected  # exact original and completed proposal revalidated
        if not retained_marker:
            _write_json(marker_path, marker)
        _write_json(ledger_path, proposal.proposed_high_water)
        for row in proposal.reservations:
            _write_json(workspaces[row.provider].path / ".barragan-topology.json",
                        row.proposed_topology)
        marker_path.unlink()
        directory = os.open(schema_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return expected
    finally:
        fcntl.flock(descriptor.fileno(), fcntl.LOCK_UN)
        descriptor.close()


def resume_mixed_external_provider_topologies(
    workspaces: Mapping[str, ProviderKeyedWorkspace],
) -> dict[str, dict[str, Any]]:
    """Finish an interrupted reviewed pair using only its durable intent marker.

    The marker was fsynced after both proposals were compiled and before any
    ledger/topology replacement. A fresh worker needs no in-memory proposal.
    """
    from app.services.provider_keyed_mixed_append_reservation import _digest

    if set(workspaces) != _PROVIDERS:
        raise ProviderKeyedSketchError("mixed provider workspaces are incomplete")
    roots = {_validated_provider_workspace(workspaces[p]) for p in _PROVIDERS}
    if len(roots) != 1 or any(workspaces[p].provider != p for p in _PROVIDERS):
        raise ProviderKeyedSketchError("mixed provider workspaces do not share one engagement")
    schema_root = roots.pop()
    if _unsafe_private_directory(schema_root):
        raise ProviderKeyedSketchError("provider-keyed schema directory is unsafe")
    lock_path = schema_root / ".regional-ordinals.lock"
    marker_path = schema_root / ".mixed-external-reservation.json"
    ledger_path = schema_root / "regional-ordinals.json"
    try:
        descriptor = os.fdopen(os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), "r+b")
    except OSError as exc:
        raise ProviderKeyedSketchError("regional ordinal lock is unsafe") from exc
    try:
        _set_private_file_access(lock_path)
        fcntl.flock(descriptor.fileno(), fcntl.LOCK_EX)
        marker = _read_json(marker_path, default={})
        if (not isinstance(marker, dict)
                or set(marker) != {"schema", "order", "prior", "ledger",
                                    "original_ledger", "original_topologies", "proposed"}
                or marker["schema"] != "mixed-external-reservation-v1"
                or not isinstance(marker["order"], list)
                or len(marker["order"]) != 2
                or set(marker["order"]) != _PROVIDERS
                or any(not isinstance(marker[key], dict) or set(marker[key]) != _PROVIDERS
                       for key in ("prior", "original_topologies", "proposed"))
                or not isinstance(marker["original_ledger"], dict)
                or _digest(marker["original_ledger"]) != marker["ledger"]):
            raise ProviderKeyedSketchError("durable mixed reservation marker is invalid")
        current_ledger = _read_json(ledger_path, default={})
        original = marker["original_topologies"]
        proposed = marker["proposed"]
        high_water = dict(marker["original_ledger"])
        for provider in marker["order"]:
            workspace = workspaces[provider]
            current = _read_json(workspace.path / ".barragan-topology.json", default={})
            _validate_provider_state_phase(workspace, current)
            if (_digest(original[provider]) != marker["prior"][provider]
                    or current not in (original[provider], proposed[provider])):
                raise ProviderKeyedSketchError("provider topology changed during reservation")
            next_topology = proposed[provider]
            try:
                compiled = compile_provider_topology(
                    next_topology["middles"], next_topology["edge_groups"],
                    previous=original[provider], regional_high_water=high_water,
                    external_middles=next_topology["external_middles"], provider=provider,
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ProviderKeyedSketchError("durable mixed reservation differs from review") from exc
            if compiled != next_topology:
                raise ProviderKeyedSketchError("durable mixed reservation differs from review")
            high_water = next_topology["regional_high_water"]
        if current_ledger not in (marker["original_ledger"], high_water):
            raise ProviderKeyedSketchError("regional ordinal ledger changed during reservation")
        _write_json(ledger_path, high_water)
        for provider in marker["order"]:
            _write_json(workspaces[provider].path / ".barragan-topology.json",
                        proposed[provider])
        marker_path.unlink()
        directory = os.open(schema_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return proposed
    finally:
        fcntl.flock(descriptor.fileno(), fcntl.LOCK_UN)
        descriptor.close()


def read_provider_topology(workspace: ProviderKeyedWorkspace) -> dict[str, Any]:
    """Read the persisted complete topology for a prepared workspace."""

    if (workspace.path.parents[1] / ".mixed-external-reservation.json").exists():
        raise ProviderKeyedSketchError("mixed external reservation must finish first")
    topology = _read_json(workspace.path / ".barragan-topology.json", default={})
    if topology and (not isinstance(topology, dict) or topology.get("schema") != SCHEMA):
        raise ProviderKeyedSketchError("persisted provider topology has an invalid schema")
    return topology


def mark_provider_keyed_apply_started(workspace: ProviderKeyedWorkspace) -> None:
    """Record a state-loss fence immediately before applying a saved plan."""

    if not read_provider_topology(workspace):
        raise ProviderKeyedSketchError("provider topology must be reserved before apply")
    _write_json(workspace.path / ".barragan-apply-phase.json", {"schema": SCHEMA, "phase": "apply_started"})


def mark_provider_keyed_applied(workspace: ProviderKeyedWorkspace) -> None:
    """Record successful apply only after Terraform has written retained state."""

    if not workspace.state_path.is_file():
        raise ProviderKeyedSketchError("cannot mark provider-keyed apply without Terraform state")
    phase = _read_json(workspace.path / ".barragan-apply-phase.json", default={})
    if phase != {"schema": SCHEMA, "phase": "apply_started"}:
        raise ProviderKeyedSketchError("provider-keyed apply was not fenced")
    _write_json(workspace.path / ".barragan-apply-phase.json", {"schema": SCHEMA, "phase": "applied"})


def require_provider_keyed_plan(
    saved_plan_json: str,
    *,
    provider: str,
    expected_node_changes: set[tuple[str, str]],
    expected_dependent_updates: set[str] = frozenset(),
    expected_shared_creates: set[str] = frozenset(),
) -> list[PlannedResourceChange]:
    """Fail closed on any unlisted saved-plan resource action.

    The caller must name every intended keyed node create/delete and every
    allowed in-place shared artifact update. Retained nodes cannot be updated
    or replaced under this contract.
    """

    if provider not in _PROVIDERS:
        raise TerraformPlanGateError("unsupported provider-keyed Sketch provider")
    node_type = "linode_instance" if provider == "linode" else "digitalocean_droplet"
    node_address = re.compile(rf'^{node_type}\.(?:middle|edge)\["[A-Za-z0-9._-]+"\]$')
    shared = ({"random_password.root_password"}
              if provider == "linode" else {"digitalocean_ssh_key.key"})
    artifacts = {"local_file.ssh_stanza[0]", "local_file.ansible_inventory[0]"}
    for address, action in expected_node_changes:
        if action not in {"create", "delete"} or not node_address.fullmatch(address):
            raise TerraformPlanGateError("expected keyed node change is invalid")
    firewall_address = "linode_firewall.firewall" if provider == "linode" else "digitalocean_firewall.firewall"
    # An address/action match cannot establish a safe initial firewall policy.
    # New firewalls need an explicit create-policy validator before this gate
    # can authorize them, including during an otherwise approved node create.
    if firewall_address in expected_shared_creates:
        raise TerraformPlanGateError("provider-keyed firewall create requires policy validation")
    if not expected_dependent_updates <= (artifacts | {firewall_address}):
        raise TerraformPlanGateError("expected shared update is invalid")
    if not expected_shared_creates <= (shared | artifacts):
        raise TerraformPlanGateError("expected shared create is invalid")
    expected = (expected_node_changes
                | {(address, "update") for address in expected_dependent_updates}
                | {(address, "create") for address in expected_shared_creates})
    changes = saved_plan_resource_changes(saved_plan_json)
    actual = {(change.address, change.action) for change in changes}
    if len(actual) != len(changes) or actual != expected:
        rendered = ", ".join(f"{action} {address}" for address, action in sorted(actual)) or "no changes"
        raise TerraformPlanGateError(f"provider-keyed plan contains unapproved resource changes: {rendered}")
    if firewall_address in expected_dependent_updates:
        _require_firewall_node_delta(saved_plan_json, provider, firewall_address, expected_node_changes)
    return changes


def _require_firewall_node_delta(
    saved_plan_json: str,
    provider: str,
    firewall_address: str,
    expected_node_changes: set[tuple[str, str]],
) -> None:
    """Authorize only a provable attachment and host-CIDR delta.

    New provider IDs/IPs are normally unknown until apply. A saved plan that
    leaves an entire attachment or ingress rule unknown cannot prove this
    boundary and is rejected. The caller must not infer approval from an
    address/action match alone.
    """
    try:
        resources = json.loads(saved_plan_json)["resource_changes"]
    except (ValueError, KeyError, TypeError) as exc:
        raise TerraformPlanGateError("saved provider-keyed plan is invalid") from exc
    by_address = {item.get("address"): item for item in resources if isinstance(item, dict)}
    if len(by_address) != len(resources):
        raise TerraformPlanGateError("saved provider-keyed plan contains duplicate resource addresses")
    firewall_change = by_address[firewall_address]["change"]
    before, after = firewall_change.get("before"), firewall_change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise TerraformPlanGateError("provider-keyed firewall update lacks before/after values")
    unknown = firewall_change.get("after_unknown", {})
    if not isinstance(unknown, dict):
        raise TerraformPlanGateError("provider-keyed firewall unknown metadata is invalid")
    computed = PROVIDER_FIREWALL_COMPUTED_ATTRIBUTES[provider]
    if any(value not in (False, None, {}, []) for key, value in unknown.items() if key not in computed):
        raise TerraformPlanGateError("provider-keyed firewall has unprovable unknown values")

    removed_ids: set[str] = set()
    added_ids: set[str] = set()
    removed_cidrs: set[str] = set()
    added_cidrs: set[str] = set()
    ip_field = "ipv4" if provider == "linode" else "ipv4_address"
    for address, action in expected_node_changes:
        change = by_address.get(address, {}).get("change", {})
        values = change.get("before" if action == "delete" else "after")
        if not isinstance(values, dict):
            raise TerraformPlanGateError("provider-keyed node change lacks provable identity")
        node_unknown = change.get("after_unknown", {})
        if action == "create" and (
            not isinstance(node_unknown, dict)
            or node_unknown.get("id") not in (None, False)
            or node_unknown.get(ip_field) not in (None, False, [], {})
        ):
            raise TerraformPlanGateError("provider-keyed node identity remains unknown")
        node_id = values.get("id")
        ip_values = values.get(ip_field)
        if not isinstance(node_id, (str, int)) or isinstance(node_id, bool) or not str(node_id):
            raise TerraformPlanGateError("provider-keyed node ID is unknown")
        if provider == "linode":
            if not isinstance(ip_values, list) or not ip_values:
                raise TerraformPlanGateError("provider-keyed node IP is unknown")
            ips = ip_values
        else:
            ips = [ip_values]
        try:
            cidrs = {str(ipaddress.IPv4Network(f"{ip}/32")) for ip in ips}
        except (ValueError, TypeError) as exc:
            raise TerraformPlanGateError("provider-keyed node IP is invalid") from exc
        if action == "delete":
            removed_ids.add(str(node_id))
            removed_cidrs.update(cidrs)
        else:
            added_ids.add(str(node_id))
            added_cidrs.update(cidrs)

    attachment = "linodes" if provider == "linode" else "droplet_ids"
    before_ids = _identities(before.get(attachment), "firewall attachments")
    after_ids = _identities(after.get(attachment), "firewall attachments")
    if before_ids - after_ids != removed_ids or after_ids - before_ids != added_ids:
        raise TerraformPlanGateError("provider-keyed firewall attachments do not match node changes")

    ingress = "inbound" if provider == "linode" else "inbound_rule"
    before_rules, before_other = _host_rules(provider, before.get(ingress))
    after_rules, after_other = _host_rules(provider, after.get(ingress))
    if before_rules.keys() != after_rules.keys() or before_rules.keys() != {"tcp", "udp", "icmp"}:
        raise TerraformPlanGateError("provider-keyed firewall host rules are incomplete")
    if before_other != after_other:
        raise TerraformPlanGateError("provider-keyed firewall ingress policy changed")
    address_field = "ipv4" if provider == "linode" else "source_addresses"
    for protocol in ("tcp", "udp", "icmp"):
        old = before_rules[protocol]
        new = after_rules[protocol]
        old_cidrs = _cidrs(old.get(address_field))
        new_cidrs = _cidrs(new.get(address_field))
        if old_cidrs - new_cidrs != removed_cidrs or new_cidrs - old_cidrs != added_cidrs:
            raise TerraformPlanGateError("provider-keyed firewall host CIDRs do not match node changes")
        if {k: v for k, v in old.items() if k != address_field} != {k: v for k, v in new.items() if k != address_field}:
            raise TerraformPlanGateError("provider-keyed firewall host rule policy changed")

    excluded = computed | {attachment, ingress}
    if {k: v for k, v in before.items() if k not in excluded} != {k: v for k, v in after.items() if k not in excluded}:
        raise TerraformPlanGateError("provider-keyed firewall policy or metadata changed")


def _identities(value: Any, label: str) -> set[str]:
    if not isinstance(value, list) or any(not isinstance(item, (str, int)) or isinstance(item, bool) for item in value):
        raise TerraformPlanGateError(f"provider-keyed {label} are invalid")
    normalized = [str(item) for item in value]
    if len(set(normalized)) != len(normalized):
        raise TerraformPlanGateError(f"provider-keyed {label} contain duplicates")
    return set(normalized)


def _cidrs(value: Any) -> set[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise TerraformPlanGateError("provider-keyed firewall host CIDRs are invalid")
    try:
        normalized = [str(ipaddress.IPv4Network(item, strict=True)) for item in value]
    except ValueError as exc:
        raise TerraformPlanGateError("provider-keyed firewall host CIDRs are invalid") from exc
    if len(set(normalized)) != len(normalized) or any(not item.endswith("/32") for item in normalized):
        raise TerraformPlanGateError("provider-keyed firewall host CIDRs are invalid")
    return set(normalized)


def _host_rules(provider: str, value: Any) -> tuple[dict[str, dict[str, Any]], list[str]]:
    if not isinstance(value, list) or any(not isinstance(rule, dict) for rule in value):
        raise TerraformPlanGateError("provider-keyed firewall ingress is invalid")
    host: dict[str, dict[str, Any]] = {}
    other: list[str] = []
    for rule in value:
        if provider == "linode":
            match = re.search(r"-host-(tcp|udp|icmp)$", str(rule.get("label", "")))
            protocol = match.group(1) if match else None
        else:
            protocol = rule.get("protocol") if rule.get("port_range") == "1-65535" and rule.get("source_addresses") not in (["::/0"], ["0.0.0.0/0"]) else None
        if protocol in {"tcp", "udp", "icmp"}:
            if protocol in host:
                raise TerraformPlanGateError("provider-keyed firewall host rules are ambiguous")
            host[protocol] = rule
        else:
            other.append(json.dumps(rule, sort_keys=True, separators=(",", ":")))
    return host, sorted(other)


def _name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _TOPOLOGY_NAME.fullmatch(value):
        raise ProviderKeyedSketchError(f"{label} name is invalid")
    return value


def _terraform_loadable(name: str) -> bool:
    return name.endswith((".tf", ".tf.json", ".tfvars", ".tfvars.json"))


def _region(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ProviderKeyedSketchError(f"{label} must be a provider region")
    return _token(value, label).lower()


def _positive_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 1:
        raise ProviderKeyedSketchError(f"{label} must be a positive integer")
    return value


def _git_revision(source: Path) -> str:
    result = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    if result.returncode:
        raise ProviderKeyedSketchError("upstream template source is not a Git checkout")
    return result.stdout.strip()


def _read_json(path: Path, *, default: Any) -> Any:
    if not path.exists():
        return default
    if path.is_symlink() or not path.is_file():
        raise ProviderKeyedSketchError("provider-keyed state metadata path is unsafe")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProviderKeyedSketchError("provider-keyed state metadata is unreadable") from exc


def _write_json(path: Path, value: Any) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, prefix=".barragan-write-", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            _set_private_file_access(temporary)
            os.fsync(stream.fileno())
        assert temporary is not None
        temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _git_dirty(source: Path) -> bool:
    result = subprocess.run(["git", "-C", str(source), "status", "--porcelain"], capture_output=True, text=True, check=False)
    if result.returncode:
        raise ProviderKeyedSketchError("upstream template source status is unavailable")
    return bool(result.stdout.strip())


def _tracked_template_files(source: Path, provider: str) -> tuple[str, ...]:
    prefix = f"external/sketch/{provider}/"
    result = subprocess.run(
        ["git", "-C", str(source), "ls-files", "-z", "--", f"external/sketch/{provider}"],
        capture_output=True, check=False,
    )
    if result.returncode:
        raise ProviderKeyedSketchError("upstream template file inventory is unavailable")
    return tuple(sorted(path.decode("utf-8").removeprefix(prefix) for path in result.stdout.split(b"\0") if path))


def _source_files(root: Path, names: tuple[str, ...]) -> dict[str, str]:
    files: dict[str, str] = {}
    for name in names:
        path = root / name
        if path.is_symlink() or not path.is_file() or path.resolve().is_relative_to(root.resolve()) is False:
            raise ProviderKeyedSketchError("upstream template source contains a symlink")
        files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return files
