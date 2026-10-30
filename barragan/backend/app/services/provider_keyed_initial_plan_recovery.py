# Copyright (c) 2026, Oracle and/or its affiliates.
"""Conservative local abandonment of a failed DevTest keyed initial plan.

This never calls Terraform or a provider. A running/interrupted job must first
be terminalized by a separate worker-recovery controller with proof of death.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import stat
from pathlib import Path
from typing import Callable

from app.services.provider_keyed_initial_plan_gate import (
    _SOURCE_REVISION,
    _SOURCE_SHA256,
    _verify_audited_workspace,
)
from app.services.provider_keyed_runtime_preflight import _require_lease
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, SCHEMA
from app.services.sketch_state_workspaces import _collaborator_group_gid, _default_state_root, _token
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository


_ACTION = "provider_keyed_initial_plan"
_OWNER_FILE = ".barragan-initial-plan-owner.json"
_PLAN_FILE = ".barragan-initial-full.tfplan"
_EXPECTED_OWNER_KEYS = frozenset({
    "schema", "engagementId", "provider", "providerConnectionId",
    "coreJobId", "planJobId", "sourceRevision",
})


class ProviderKeyedPlanRecoveryError(ValueError):
    """A failed plan workspace cannot be safely abandoned."""


def abandon_failed_digitalocean_initial_plan(
    engagement_id: str,
    failed_plan_job_id: str,
    *,
    lease_owner: str,
    environment: str,
    state_root: Path,
    job_repository: JobRepository | None = None,
    lease_lookup: Callable[[str], tuple[str, str] | None] | None = None,
) -> None:
    """Remove only the failed job's local workspace after exact checks.

    The failed job remains in the job repository as the audit record. A saved
    plan, Terraform state, or apply-phase fence is a reconciliation case and
    is deliberately never removed here.
    """

    if environment != "devtest":
        raise ProviderKeyedPlanRecoveryError("failed-plan recovery requires DevTest")
    try:
        engagement = _token(engagement_id, "engagement id")
        plan_job_id = _token(failed_plan_job_id, "plan job id")
        owner = _token(lease_owner, "lease owner")
    except ValueError as exc:
        raise ProviderKeyedPlanRecoveryError("recovery identity is invalid") from exc
    if not isinstance(state_root, Path) or state_root != _default_state_root():
        raise ProviderKeyedPlanRecoveryError("Sketch state root differs from configured root")
    _require_canonical_private_directory(state_root)
    lookup = lease_lookup
    if lookup is None:
        from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
        lookup = _db_lease_lookup
    _require_lease(lookup, engagement, owner)

    jobs = job_repository or SqlAlchemyJobRepository()
    failed = jobs.get(plan_job_id)
    if (failed is None or failed.id != plan_job_id or failed.action != _ACTION
            or failed.status != "failed" or failed.target_type != "engagement"
            or failed.target_id != engagement or failed.target != f"engagement:{engagement}"
            or not isinstance(failed.input, dict)
            or failed.input.get("engagementId") != engagement
            or set(failed.input) != {"engagementId", "coreJobId", "mutation"}
            or not isinstance(failed.input.get("coreJobId"), str)
            or failed.input.get("mutation") is not False
            or failed.artifact_refs or not failed.finished_at):
        raise ProviderKeyedPlanRecoveryError("exact terminal failed plan job is unavailable")
    related = jobs.list_for_engagement(engagement)
    if failed not in related:
        raise ProviderKeyedPlanRecoveryError("failed plan job is absent from engagement audit")
    if any(job.action == _ACTION and job.id != plan_job_id
           and (job.status != "failed" or job.artifact_refs)
           for job in related):
        raise ProviderKeyedPlanRecoveryError("another provider plan has retained evidence or activity")

    engagement_root = state_root / engagement
    schema_root = engagement_root / SCHEMA
    provider_root = schema_root / "digitalocean"
    for path in (engagement_root, schema_root, provider_root):
        _require_canonical_private_directory(path)
    workspaces = list(provider_root.iterdir())
    if len(workspaces) != 1 or not workspaces[0].is_dir():
        raise ProviderKeyedPlanRecoveryError("provider workspace identity is ambiguous")
    root = workspaces[0]
    _require_canonical_private_directory(root)
    marker_path = root / ".barragan-provider-keyed-state.json"
    owner_path = root / _OWNER_FILE
    marker = _read_private_json(marker_path, owner_only=False)
    recorded_owner = _read_private_json(owner_path)
    connection_id = recorded_owner.get("providerConnectionId")
    if not isinstance(connection_id, str):
        raise ProviderKeyedPlanRecoveryError("plan ownership marker is invalid")
    expected_fingerprint = hashlib.sha256(f"digitalocean\0{connection_id}".encode()).hexdigest()
    if (root.name != expected_fingerprint or set(recorded_owner) != _EXPECTED_OWNER_KEYS
            or recorded_owner != {
                "schema": SCHEMA, "engagementId": engagement,
                "provider": "digitalocean", "providerConnectionId": connection_id,
                "coreJobId": failed.input["coreJobId"], "planJobId": plan_job_id,
                "sourceRevision": _SOURCE_REVISION,
            }
            or any(marker.get(key) != value for key, value in {
                "schema": SCHEMA, "engagement_id": engagement,
                "provider": "digitalocean", "provider_connection_id": connection_id,
                "connection_fingerprint": expected_fingerprint,
                "source_revision": _SOURCE_REVISION,
            }.items())):
        raise ProviderKeyedPlanRecoveryError("provider workspace ownership differs from failed job")
    workspace = ProviderKeyedWorkspace(
        root, root / "terraform.tfstate", root / ".terraform-data", SCHEMA,
        "digitalocean", connection_id, expected_fingerprint,
        _SOURCE_REVISION, _SOURCE_SHA256,
    )
    lock_path = root / ".barragan-initial-full-plan.lock"
    if not os.path.lexists(lock_path):
        # The owner marker precedes topology reservation and the plan runner.
        # A terminal failure in that interval has no workspace lock yet.
        descriptor = os.open(
            lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
        )
    else:
        _require_private_regular_file(lock_path)
        descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "r+b") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ProviderKeyedPlanRecoveryError("provider plan workspace is busy") from exc
        # Recheck the DB and lease under the workspace lock before deletion.
        if jobs.get(plan_job_id) != failed or jobs.list_for_engagement(engagement) != related:
            raise ProviderKeyedPlanRecoveryError("provider plan job changed during recovery")
        _require_lease(lookup, engagement, owner)
        _verify_audited_workspace(workspace)
        if _read_private_json(owner_path) != recorded_owner:
            raise ProviderKeyedPlanRecoveryError("plan ownership changed during recovery")
        _require_absent_execution_evidence(root)
        _require_known_tree(engagement_root, root, marker)
        shutil.rmtree(engagement_root)


def _require_absent_execution_evidence(root: Path) -> None:
    for name in ("terraform.tfstate", "terraform.tfstate.backup", _PLAN_FILE,
                 ".barragan-apply-phase.json"):
        if os.path.lexists(root / name):
            raise ProviderKeyedPlanRecoveryError("Terraform plan, state, or apply evidence requires review")
    if any(path.name.startswith("terraform.tfstate") for path in root.iterdir()):
        raise ProviderKeyedPlanRecoveryError("Terraform state evidence requires review")


def _require_known_tree(engagement_root: Path, root: Path, marker: dict) -> None:
    """Reject every path outside audited source and known plan-generated paths."""

    schema_root = engagement_root / SCHEMA
    material_root = schema_root / ".plan-material"
    material = material_root / "digitalocean"
    rendered = marker.get("rendered_files")
    if not isinstance(rendered, dict) or not rendered:
        raise ProviderKeyedPlanRecoveryError("rendered source inventory is unavailable")
    allowed_files = {
        root / name for name in rendered
    } | {
        root / ".barragan-provider-keyed-state.json",
        root / ".barragan-topology.json", root / _OWNER_FILE,
        root / ".barragan-initial-full-plan.lock",
        schema_root / ".regional-ordinals.lock",
        schema_root / "regional-ordinals.json",
        material / "admin-private", material / "admin-public",
        material / "inputs.json",
    }
    allowed_dirs = {
        engagement_root, schema_root, schema_root / "digitalocean", root,
        root / ".terraform-data", material_root, material,
        material / "ssh-output",
    }
    for file in allowed_files:
        for parent in file.parents:
            if parent == engagement_root.parent:
                break
            allowed_dirs.add(parent)
    # Terraform init's data directory may contain only its known provider
    # installation hierarchy. Any other entry is uncertain and refused.
    plugin_roots = {
        root / ".terraform-data" / "providers" / "registry.terraform.io"
        / "digitalocean" / "digitalocean" / "2.103.0" / "linux_amd64":
            frozenset({"terraform-provider-digitalocean_v2.103.0", "README.md",
                       "CHANGELOG.md", "LICENSE"}),
        root / ".terraform-data" / "providers" / "registry.terraform.io"
        / "hashicorp" / "local" / "2.9.1" / "linux_amd64":
            frozenset({"terraform-provider-local_v2.9.1_x5", "LICENSE.txt"}),
    }
    for plugin_root in plugin_roots:
        allowed_dirs.update(plugin_root.parents)
        allowed_dirs.add(plugin_root)
    for path in engagement_root.rglob("*"):
        if path.is_symlink():
            raise ProviderKeyedPlanRecoveryError("symlinked recovery artifact is unsafe")
        info = path.lstat()
        if info.st_uid != os.geteuid():
            raise ProviderKeyedPlanRecoveryError("recovery artifact ownership differs")
        cache_path = root / ".terraform-data" in path.parents
        private_material = path == material_root or material_root in path.parents
        if stat.S_ISDIR(info.st_mode):
            mode = stat.S_IMODE(info.st_mode)
            if (path not in allowed_dirs or mode & 0o700 != 0o700
                    or (mode & 0o022 if cache_path else
                        mode & 0o077 if private_material else mode & 0o027)):
                raise ProviderKeyedPlanRecoveryError("unrecognized or unsafe recovery directory")
            if not cache_path and not private_material and mode & 0o050:
                _require_collaborator_group(info)
        elif stat.S_ISREG(info.st_mode):
            plugin_file = path.name in plugin_roots.get(path.parent, ())
            if path not in allowed_files and not plugin_file:
                raise ProviderKeyedPlanRecoveryError("unrecognized recovery file")
            private_file = private_material or path in {
                root / _OWNER_FILE, root / ".barragan-initial-full-plan.lock",
            }
            mode = stat.S_IMODE(info.st_mode)
            if (mode & 0o600 != 0o600 or
                    (mode & 0o022 if plugin_file else
                     mode & 0o077 if private_file else mode & 0o027)):
                raise ProviderKeyedPlanRecoveryError("recovery file is not private")
            if not plugin_file and not private_file and mode & 0o040:
                _require_collaborator_group(info)
        else:
            raise ProviderKeyedPlanRecoveryError("special recovery artifact is unsafe")


def _require_canonical_private_directory(path: Path) -> None:
    if not path.is_absolute() or not path.is_dir() or path.is_symlink() or path.resolve(strict=True) != path:
        raise ProviderKeyedPlanRecoveryError("recovery directory is not canonical")
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid != os.geteuid() or mode & 0o700 != 0o700 or mode & 0o027:
        raise ProviderKeyedPlanRecoveryError("recovery directory is not private or owned")
    if mode & 0o050:
        _require_collaborator_group(info)


def _require_private_regular_file(path: Path, *, owner_only: bool = True) -> None:
    if not path.is_file() or path.is_symlink():
        raise ProviderKeyedPlanRecoveryError("recovery file is missing or unsafe")
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    if (info.st_uid != os.geteuid() or not stat.S_ISREG(info.st_mode)
            or mode & 0o600 != 0o600
            or mode & (0o077 if owner_only else 0o027)):
        raise ProviderKeyedPlanRecoveryError("recovery file is not private or owned")
    if not owner_only and mode & 0o040:
        _require_collaborator_group(info)


def _require_collaborator_group(info: os.stat_result) -> None:
    expected_gid = _collaborator_group_gid()
    if expected_gid is None or info.st_gid != expected_gid:
        raise ProviderKeyedPlanRecoveryError("group-readable recovery artifact is outside barragan group")


def _read_private_json(path: Path, *, owner_only: bool = True) -> dict:
    _require_private_regular_file(path, owner_only=owner_only)
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ProviderKeyedPlanRecoveryError("recovery ownership metadata is unreadable") from exc
    if not isinstance(result, dict):
        raise ProviderKeyedPlanRecoveryError("recovery ownership metadata is invalid")
    return result
