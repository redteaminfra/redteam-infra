# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only DevTest boundary for a retained DigitalOcean keyed initial plan.

The caller holds the engagement mutation lease. Passing this check does not
start Terraform or authorize an apply; the saved-plan apply gate must repeat
its own source, credential, plan, and provider checks at mutation time.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Callable

from app.integrations.oci_deployment_targets import normalized_oci_deployment_target
from app.services.core_ssh import active_core_connection_details
from app.services.engagement_teardown import engagement_teardown_in_progress
from app.services.managed_host_image_continuity import managed_host_image_profile_named
from app.services.provider_keyed_initial_plan_gate import _SOURCE_REVISION, _SOURCE_SHA256, _verify_audited_workspace
from app.services.provider_keyed_persisted_intent import compile_fresh_digitalocean_persisted_intent
from app.services.provider_keyed_review_authorization import require_fresh_digitalocean_review_authorization
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _inert_aborted_intent, _require_lease
from app.services.provider_keyed_saved_plan_runner import _credential_snapshot, _require_absent_initial_state, _require_canonical_workspace_paths, _topology_hash
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, SCHEMA, resolve_default_provider_connection
from app.services.provider_keyed_terraform_release import _REVIEWED_PATH, _REVIEWED_SHA256
from app.services.sketch_state_workspaces import _default_state_root, _unsafe_private_directory
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.engagement_repository import SqlAlchemyEngagementRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_PLAN_ACTION = "provider_keyed_initial_plan"
_OWNER = ".barragan-initial-plan-owner.json"
_PLAN = ".barragan-initial-full.tfplan"
_EVIDENCE_KEYS = frozenset({
    "coreJobId", "corePlanId", "revisionId", "providerConnectionId", "selectorTag",
    "sourceRevision", "planPath", "planSha256", "sourceSha256", "markerSha256",
    "topologySha256", "lockfileSha256", "inputSha256", "credentialSecretSha256",
    "credentialUpdatedAt", "terraformBinaryPath", "terraformBinarySha256", "terraformVersion",
    "adminPublicKeySha256", "adminPrivateKeyPath", "adminPublicKeyPath", "sshOutputDirectory",
})


class ProviderKeyedPlannedStatePreflightError(ValueError):
    """Retained plan or current reviewed intent cannot be proved read-only."""


def preflight_planned_digitalocean_provider(
    engagement_id: str, core_job_id: str, plan_job_id: str, *,
    lease_owner: str, environment: str, state_root: Path,
    allowed_apply_job_id: str | None = None,
    lease_lookup: Callable[[str], tuple[str, str] | None] | None = None,
    engagement_repository=None, sketch_repository=None, job_repository=None,
    plan_repository=None, credential_repository=None,
) -> tuple[object, ProviderKeyedWorkspace, dict]:
    """Return current intent, canonical workspace, and exact retained evidence.

    This function creates no directory, file, job, or provider resource.
    ``allowed_apply_job_id`` only permits the exact queued/running apply job
    under the core plan's existing mutation lease; all other gates remain.
    """
    try:
        if environment != "devtest" or state_root != _default_state_root():
            raise ValueError("DevTest configured Sketch state root required")
        if not isinstance(state_root, Path) or not state_root.is_absolute() or state_root.resolve(strict=True) != state_root:
            raise ValueError("Sketch state root is not canonical")
        if any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,119}", value)
               for value in (engagement_id, core_job_id, plan_job_id, lease_owner)):
            raise ValueError("provider identity is invalid")
        if allowed_apply_job_id is not None and (
                not isinstance(allowed_apply_job_id, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,119}", allowed_apply_job_id)):
            raise ValueError("allowed apply job identity is invalid")
        lookup = lease_lookup or _db_lease_lookup
        _require_lease(lookup, engagement_id, lease_owner)
        engagements = engagement_repository or SqlAlchemyEngagementRepository()
        chains_repo = sketch_repository or SqlAlchemySketchChainRepository()
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        if engagement_teardown_in_progress(engagement_id, repository=jobs) is not None:
            raise ValueError("engagement teardown is active")
        engagement = engagements.get(engagement_id)
        core_job = jobs.get(core_job_id)
        plan_job = jobs.get(plan_job_id)
        if engagement is None or core_job is None or plan_job is None:
            raise ValueError("reviewed engagement or job is missing")
        target = normalized_oci_deployment_target(engagement.input_parameters.get("deploymentTarget"))
        if (engagement.id != engagement_id or engagement.status not in {"planned", "deployed"}
                or core_job.id != core_job_id or core_job.target_type != "oci_compartment"
                or core_job.target != f"oci-compartment:{target['name']}"
                or core_job.target_id != target["compartmentId"]):
            raise ValueError("core identity differs")
        active_id, _ = active_core_connection_details(jobs, engagement_id)
        if active_id != core_job_id:
            raise ValueError("core generation is no longer active")
        core_plan_id = core_job.input.get("corePlanId")
        core_plan = plans.get(core_plan_id) if isinstance(core_plan_id, str) else None
        if core_plan is None or core_plan.id != core_plan_id or lease_owner != core_plan_id:
            raise ValueError("reviewed core plan is missing")
        profile = managed_host_image_profile_named(core_plan.evidence["managedHostImageProfile"])
        all_chains = chains_repo.list_for_engagement(engagement_id)
        current_chains = [chain for chain in all_chains if not _inert_aborted_intent(chain, engagement_id)]
        intent = compile_fresh_digitalocean_persisted_intent(
            engagement, current_chains, core_job, core_plan, profile,
            environment=environment, provider_state_exists=False,
        )
        related_jobs = jobs.list_for_engagement(engagement_id)
        authority_actions = {
            "provider_keyed_initial", _PLAN_ACTION,
            "provider_keyed_initial_apply", "provider_keyed_initial_destroy",
            "provider_keyed_comprehensive_teardown", "engagement_comprehensive_teardown",
        }
        authority_jobs = {job.id: job for job in related_jobs
                          if job.action in authority_actions}
        matching = [job for job in related_jobs if job.action == _PLAN_ACTION]
        successful = [job for job in matching if job.status == "succeeded"]
        if (len(successful) != 1 or successful[0] != plan_job
                or plan_job.id != plan_job_id or plan_job.status != "succeeded"
                or plan_job.target_type != "engagement" or plan_job.target_id != engagement_id
                or plan_job.target != f"engagement:{engagement_id}"
                or plan_job.input != {"engagementId": engagement_id, "coreJobId": core_job_id, "mutation": False}
                or not plan_job.finished_at):
            raise ValueError("successful provider plan job is not unique")
        if any(not _safe_failed_predecessor(job, plan_job, engagement_id)
               for job in matching if job.id != plan_job_id):
            raise ValueError("earlier provider plan job has ambiguous evidence")
        execution_jobs = [job for job in related_jobs if job.action in {
            "provider_keyed_initial_apply", "provider_keyed_initial_destroy",
        }]
        if allowed_apply_job_id is None:
            if execution_jobs:
                raise ValueError("provider execution already has an audit record")
        elif (len(execution_jobs) != 1
              or execution_jobs[0].id != allowed_apply_job_id
              or execution_jobs[0].action != "provider_keyed_initial_apply"
              or execution_jobs[0].status not in {"queued", "running"}
              or execution_jobs[0].target_type != "engagement"
              or execution_jobs[0].target_id != engagement_id
              or execution_jobs[0].target != f"engagement:{engagement_id}"
              or execution_jobs[0].input != {
                  "engagementId": engagement_id, "coreJobId": core_job_id,
                  "corePlanId": core_plan_id, "planJobId": plan_job_id, "mutation": True,
              }
              or type(execution_jobs[0].input.get("mutation")) is not bool
              or jobs.get(allowed_apply_job_id) != execution_jobs[0]):
            raise ValueError("provider apply job does not match the active lease")
        connection_id = resolve_default_provider_connection("digitalocean", repository=credentials)
        require_fresh_digitalocean_review_authorization(
            intent, core_plan, connection_id=connection_id, credential_repository=credentials,
        )
        root = state_root / engagement_id / SCHEMA
        provider_root = root / "digitalocean"
        fingerprint = hashlib.sha256(f"digitalocean\0{connection_id}".encode()).hexdigest()
        workspace_root = provider_root / fingerprint
        for directory in (state_root, state_root / engagement_id, root, provider_root, workspace_root):
            _private_directory(directory)
        if set(path.name for path in root.iterdir()) != {"digitalocean", ".plan-material", ".regional-ordinals.lock", "regional-ordinals.json"}:
            raise ValueError("provider state tree has ambiguous entries")
        if [path.name for path in provider_root.iterdir()] != [fingerprint]:
            raise ValueError("provider workspace is not unique")
        workspace = ProviderKeyedWorkspace(
            workspace_root, workspace_root / "terraform.tfstate", workspace_root / ".terraform-data",
            SCHEMA, "digitalocean", connection_id, fingerprint, _SOURCE_REVISION, _SOURCE_SHA256,
        )
        _require_canonical_workspace_paths(workspace)
        _verify_audited_workspace(workspace)
        _require_absent_initial_state(workspace)
        if os.path.lexists(workspace_root / ".barragan-apply-phase.json"):
            raise ValueError("provider apply phase already exists")
        owner = _json_file(workspace_root / _OWNER, private=True)
        if owner != {"schema": SCHEMA, "engagementId": engagement_id, "provider": "digitalocean",
                     "providerConnectionId": connection_id, "coreJobId": core_job_id,
                     "planJobId": plan_job_id, "sourceRevision": _SOURCE_REVISION}:
            raise ValueError("provider plan owner differs")
        evidence_events = [event for event in plan_job.events if event.message == "reviewed provider plan saved"]
        if len(evidence_events) != 1 or set(evidence_events[0].data) != _EVIDENCE_KEYS:
            raise ValueError("exact provider plan evidence is unavailable")
        evidence = evidence_events[0].data
        if (evidence["coreJobId"] != core_job_id or evidence["corePlanId"] != core_plan_id
                or evidence["revisionId"] != intent.revision_id
                or evidence["providerConnectionId"] != connection_id
                or evidence["selectorTag"] != intent.selector_tag
                or evidence["sourceRevision"] != _SOURCE_REVISION
                or evidence["sourceSha256"] != _SOURCE_SHA256
                or evidence["terraformVersion"] != "1.15.5"):
            raise ValueError("provider plan evidence differs from current intent")
        plan_path = workspace_root / _PLAN
        if evidence["planPath"] != str(plan_path) or plan_job.artifact_refs != [str(plan_path)]:
            raise ValueError("saved provider plan path differs")
        for key, path in (("planSha256", plan_path),
                          ("markerSha256", workspace_root / ".barragan-provider-keyed-state.json"),
                          ("topologySha256", workspace_root / ".barragan-topology.json"),
                          ("lockfileSha256", workspace_root / ".terraform.lock.hcl")):
            if evidence[key] != _digest(path):
                raise ValueError("saved provider plan digest differs")
        if plan_path.stat().st_mode & 0o077:
            raise ValueError("saved provider plan is not private")
        if evidence["topologySha256"] != _topology_hash(workspace):
            raise ValueError("provider topology differs")
        if _json_file(workspace_root / ".barragan-topology.json") != intent.topology:
            raise ValueError("provider topology differs from current intent")
        secret_digest, updated_at, _ = _credential_snapshot(connection_id, credentials)
        if (evidence["credentialSecretSha256"] != secret_digest
                or evidence["credentialUpdatedAt"] != updated_at):
            raise ValueError("provider credential changed since plan")
        material_root = root / ".plan-material"
        material = material_root / "digitalocean"
        output = material / "ssh-output"
        for directory in (material_root, material, output):
            _private_directory(directory)
        if set(path.name for path in material_root.iterdir()) != {"digitalocean"}:
            raise ValueError("provider material is ambiguous")
        if set(path.name for path in material.iterdir()) != {"inputs.json", "ssh-output"}:
            raise ValueError("provider material contains unexpected keys")
        inputs = material / "inputs.json"
        if evidence["inputSha256"] != [[str(inputs), _digest(inputs)]]:
            raise ValueError("provider inputs changed")
        if inputs.stat().st_mode & 0o077:
            raise ValueError("provider inputs are not private")
        if (evidence["adminPrivateKeyPath"] != str(material / "admin-private")
                or evidence["adminPublicKeyPath"] != str(material / "admin-public")
                or evidence["sshOutputDirectory"] != str(output)
                or any(output.iterdir())):
            raise ValueError("provider key material or output path differs")
        marker = _json_file(workspace_root / ".barragan-provider-keyed-state.json")
        rendered = marker.get("rendered_files")
        if (not isinstance(rendered, dict) or marker.get("engagement_id") != engagement_id
                or marker.get("provider_connection_id") != connection_id):
            raise ValueError("provider source inventory is missing")
        allowed = set(rendered) | {".barragan-provider-keyed-state.json", ".barragan-topology.json",
                                   _OWNER, _PLAN, ".barragan-initial-full-plan.lock",
                                   ".terraform.lock.hcl", ".terraform-data"}
        for path in workspace_root.rglob("*"):
            relative = path.relative_to(workspace_root).as_posix()
            if relative.startswith(".terraform-data/"):
                continue
            if path.is_symlink() or (path.is_dir() and relative != ".terraform-data" and not any(
                    name.startswith(relative + "/") for name in allowed
            )) or (path.is_file() and relative not in allowed):
                raise ValueError("provider workspace has unknown artifacts")
        if (evidence["terraformBinaryPath"] != str(_REVIEWED_PATH)
                or evidence["terraformBinarySha256"] != _REVIEWED_SHA256
                or _binary_digest(_REVIEWED_PATH) != _REVIEWED_SHA256):
            raise ValueError("Terraform release differs from saved plan")
        if (engagements.get(engagement_id) != engagement or jobs.get(core_job_id) != core_job
                or jobs.get(plan_job_id) != plan_job or plans.get(core_plan_id) != core_plan
                or chains_repo.list_for_engagement(engagement_id) != all_chains
                or {job.id: job for job in jobs.list_for_engagement(engagement_id)
                    if job.action in authority_actions} != authority_jobs
                or active_core_connection_details(jobs, engagement_id)[0] != core_job_id
                or engagement_teardown_in_progress(engagement_id, repository=jobs) is not None):
            raise ValueError("provider intent changed during preflight")
        _require_lease(lookup, engagement_id, lease_owner)
        return intent, workspace, evidence
    except Exception as exc:
        raise ProviderKeyedPlannedStatePreflightError("retained provider plan preflight failed") from exc


def _private_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir() or path.resolve(strict=True) != path or _unsafe_private_directory(path):
        raise ValueError("provider state directory is unsafe")


def _digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise ValueError("provider artifact is unsafe")
    info = path.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError("provider artifact permissions are unsafe")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json_file(path: Path, *, private: bool = False) -> dict:
    _digest(path)
    if private and (path.stat().st_mode & 0o077):
        raise ValueError("provider owner is not private")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("provider marker is invalid")
    return value


def _binary_digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path or not os.access(path, os.X_OK):
        raise ValueError("Terraform binary is unsafe")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_failed_predecessor(job: object, current: object, engagement_id: str) -> bool:
    """Match recovery's terminal no-artifact contract and require earlier order."""
    try:
        earlier = datetime.fromisoformat(job.finished_at.replace("Z", "+00:00"))
        later = datetime.fromisoformat(current.created_at.replace("Z", "+00:00"))
        return (
            job.status == "failed" and job.action == _PLAN_ACTION
            and job.target_type == "engagement"
            and job.target_id == engagement_id
            and job.target == f"engagement:{engagement_id}"
            and isinstance(job.input, dict)
            and set(job.input) == {"engagementId", "coreJobId", "mutation"}
            and job.input["engagementId"] == engagement_id
            and isinstance(job.input["coreJobId"], str) and job.input["coreJobId"]
            and job.input["mutation"] is False
            and job.artifact_refs == []
            and all(event.message != "reviewed provider plan saved" for event in job.events)
            and earlier <= later
        )
    except (AttributeError, TypeError, ValueError):
        return False
