# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only reconstruction of an applied DevTest DigitalOcean keyed pilot.

This boundary proves applied provider evidence independently for a later
attachment-proof retry. It does not authorize that retry or inspect the
continuation parent claim/phase. It never dispatches a plan, apply, provider
request, or chain mutation, and cannot recover a failed Terraform apply.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Callable, Literal

from app.integrations.oci_deployment_targets import normalized_oci_deployment_target
from app.services.core_ssh import active_core_connection_details
from app.services.engagement_teardown import engagement_teardown_in_progress
from app.services.managed_host_image_continuity import managed_host_image_profile_named
from app.services.provider_keyed_initial_attachment_adapter import derive_digitalocean_initial_attachment_intent
from app.services.provider_keyed_initial_plan_gate import _SOURCE_REVISION, _SOURCE_SHA256, _verify_audited_workspace
from app.services.provider_keyed_persisted_intent import compile_fresh_digitalocean_persisted_intent
from app.services.provider_keyed_planned_state_preflight import (
    _EVIDENCE_KEYS, _digest, _json_file, _private_directory, _safe_failed_predecessor,
)
from app.services.provider_keyed_review_authorization import require_fresh_digitalocean_review_authorization
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _inert_aborted_intent, _require_lease
from app.services.provider_keyed_saved_plan_runner import _credential_snapshot, _require_canonical_workspace_paths, _topology_hash
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, SCHEMA, resolve_default_provider_connection
from app.services.sketch_state_workspaces import _collaborator_group_gid, _default_state_root
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.engagement_repository import SqlAlchemyEngagementRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,119}\Z")
_PLAN_ACTION = "provider_keyed_initial_plan"
_APPLY_ACTION = "provider_keyed_initial_apply"
_REVIEWED_RECOVERY_CHILDREN = frozenset({
    ("eng-09c806850ec5", "job-engagement-teardown-db19aa91df17",
     "job-provider-keyed-initial-destroy-apply-db19aa91df17"),
    ("eng-6ad4d5fb880e", "job-engagement-teardown-b4f1bceb4a7d",
     "job-provider-keyed-initial-destroy-apply-b4f1bceb4a7d"),
})


class ProviderKeyedPostapplyPreflightError(ValueError):
    """Retained applied identity cannot be proven without mutation."""


def preflight_applied_digitalocean_provider(
    engagement_id: str,
    core_job_id: str,
    *,
    lease_owner: str,
    environment: str,
    state_root: Path,
    lease_lookup: Callable[[str], tuple[str, str] | None] | None = None,
    engagement_repository=None,
    sketch_repository=None,
    job_repository=None,
    plan_repository=None,
    credential_repository=None,
) -> tuple[object, ProviderKeyedWorkspace, dict, object]:
    """Operational applied read under the original core-plan lease boundary."""
    try:
        if not isinstance(lease_owner, str) or not _IDENTITY.fullmatch(lease_owner):
            raise ValueError("post-apply lease owner")
        lookup = lease_lookup or _db_lease_lookup
        _require_lease(lookup, engagement_id, lease_owner)
        jobs = job_repository or SqlAlchemyJobRepository()
        if engagement_teardown_in_progress(engagement_id, repository=jobs) is not None:
            raise ValueError("engagement teardown is active")
        result = read_applied_digitalocean_provider_for_teardown(
            engagement_id, core_job_id, environment=environment, state_root=state_root,
            mode="applied_read", allowed_teardown_parent_id=None,
            engagement_repository=engagement_repository, sketch_repository=sketch_repository,
            job_repository=jobs, plan_repository=plan_repository,
            credential_repository=credential_repository,
        )
        if result[0].core_plan_id != lease_owner:
            raise ValueError("applied core plan lease differs")
        if engagement_teardown_in_progress(engagement_id, repository=jobs) is not None:
            raise ValueError("engagement teardown is active")
        _require_lease(lookup, engagement_id, lease_owner)
        return result
    except Exception:
        raise ProviderKeyedPostapplyPreflightError("retained applied provider preflight failed") from None


def read_applied_digitalocean_provider_for_teardown(
    engagement_id: str, core_job_id: str, *, environment: str, state_root: Path,
    mode: Literal["applied_read", "materialized_read", "destroy_started_read",
                  "destroy_started_recovery_read"],
    allowed_teardown_parent_id: str | None = None,
    incident_destroy_child_id: str | None = None,
    incident_recovery_child=None,
    engagement_repository=None, sketch_repository=None, job_repository=None,
    plan_repository=None, credential_repository=None,
) -> tuple[object, ProviderKeyedWorkspace, dict, object]:
    """Read immutable applied evidence without granting mutation authority.

    Successful apply attempts to delete the saved binary plan. If deletion
    failed, the exact private binary may remain for controlled cleanup.
    """
    try:
        if (environment != "devtest" or mode not in (
                "applied_read", "materialized_read", "destroy_started_read",
                "destroy_started_recovery_read")
                or not isinstance(state_root, Path)
                or state_root != _default_state_root() or not state_root.is_absolute()
                or state_root.resolve(strict=True) != state_root
                or any(not isinstance(value, str) or not _IDENTITY.fullmatch(value)
                       for value in (engagement_id, core_job_id))
                or (mode in {"destroy_started_read", "destroy_started_recovery_read"} and (
                    not allowed_teardown_parent_id or not incident_destroy_child_id
                    or incident_destroy_child_id != f"job-provider-keyed-initial-destroy-apply-{core_job_id.removeprefix('job-')}"))
                or (mode not in {"destroy_started_read", "destroy_started_recovery_read"}
                    and incident_destroy_child_id is not None)
                or (mode == "destroy_started_recovery_read" and (
                    (engagement_id, allowed_teardown_parent_id, incident_destroy_child_id)
                    not in _REVIEWED_RECOVERY_CHILDREN
                    or incident_recovery_child is None))
                or (mode != "destroy_started_recovery_read" and incident_recovery_child is not None)
                or (allowed_teardown_parent_id is not None
                    and (not isinstance(allowed_teardown_parent_id, str)
                         or not _IDENTITY.fullmatch(allowed_teardown_parent_id)))):
            raise ValueError("post-apply scope or identity")
        engagements = engagement_repository or SqlAlchemyEngagementRepository()
        chains_repo = sketch_repository or SqlAlchemySketchChainRepository()
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        if not _teardown_boundary_matches(engagement_id, jobs, allowed_teardown_parent_id):
            raise ValueError("engagement teardown is active")
        if mode in {"destroy_started_read", "destroy_started_recovery_read"}:
            child = jobs.get(incident_destroy_child_id)
            if (child is None or child.action != "provider_keyed_initial_destroy_apply"
                    or child.status != "running" or child.target_id != engagement_id
                    or child.input.get("teardownParentId") != allowed_teardown_parent_id
                    or child.input.get("coreJobId") != core_job_id
                    or (mode == "destroy_started_read" and (
                        len(child.events) != 9
                        or child.events[-1].message != "provider destroy command started before GO"))
                    or (mode == "destroy_started_recovery_read" and child != incident_recovery_child)):
                raise ValueError("incident destroy child differs")
        engagement = engagements.get(engagement_id)
        core = jobs.get(core_job_id)
        if engagement is None or core is None or engagement.id != engagement_id or core.id != core_job_id:
            raise ValueError("reviewed engagement or core job is unavailable")
        target = normalized_oci_deployment_target(engagement.input_parameters.get("deploymentTarget"))
        if (engagement.status not in {"planned", "deployed"}
                or core.target_type != "oci_compartment"
                or core.target != f"oci-compartment:{target['name']}"
                or core.target_id != target["compartmentId"]
                or active_core_connection_details(jobs, engagement_id)[0] != core_job_id):
            raise ValueError("core generation differs")
        core_plan_id = core.input.get("corePlanId") if isinstance(core.input, dict) else None
        core_plan = plans.get(core_plan_id) if isinstance(core_plan_id, str) else None
        if (core_plan is None or core_plan.id != core_plan_id
                or core_plan.status != "applied" or core_plan.apply_job_id != core_job_id):
            raise ValueError("applied core plan differs")
        profile = managed_host_image_profile_named(core_plan.evidence["managedHostImageProfile"])
        all_chains = chains_repo.list_for_engagement(engagement_id)
        current = [chain for chain in all_chains if not _inert_aborted_intent(chain, engagement_id)]
        intent = compile_fresh_digitalocean_persisted_intent(
            engagement, current, core, core_plan, profile,
            environment=environment, provider_state_exists=True,
            mode="applied_read" if mode in {
                "destroy_started_read", "destroy_started_recovery_read"} else mode,
        )
        related = jobs.list_for_engagement(engagement_id)
        plan_jobs = [job for job in related if job.action == _PLAN_ACTION]
        apply_jobs = [job for job in related if job.action == _APPLY_ACTION]
        destroy_jobs = [job for job in related if job.action == "provider_keyed_initial_destroy"]
        expected_plan_id, expected_apply_id = _child_ids(core_job_id)
        if len(apply_jobs) != 1 or destroy_jobs:
            raise ValueError("provider child jobs are not unique")
        successful_plans = [job for job in plan_jobs if job.status == "succeeded"]
        if len(successful_plans) != 1:
            raise ValueError("successful provider plan job is not unique")
        plan_job, apply_job = successful_plans[0], apply_jobs[0]
        if any(not _safe_failed_predecessor(job, plan_job, engagement_id)
               for job in plan_jobs if job.id != plan_job.id):
            raise ValueError("earlier provider plan job has ambiguous evidence")
        if (plan_job.id != expected_plan_id or jobs.get(expected_plan_id) != plan_job
                or plan_job.status != "succeeded" or not plan_job.started_at or not plan_job.finished_at
                or plan_job.target_type != "engagement" or plan_job.target_id != engagement_id
                or plan_job.target != f"engagement:{engagement_id}"
                or plan_job.requested_by != core.requested_by
                or plan_job.input != {"engagementId": engagement_id, "coreJobId": core_job_id,
                                      "mutation": False}
                or apply_job.id != expected_apply_id or jobs.get(expected_apply_id) != apply_job
                or apply_job.status != "succeeded" or not apply_job.started_at or not apply_job.finished_at
                or apply_job.target_type != "engagement" or apply_job.target_id != engagement_id
                or apply_job.target != f"engagement:{engagement_id}"
                or apply_job.requested_by != core.requested_by
                or apply_job.input != {"engagementId": engagement_id, "coreJobId": core_job_id,
                                       "corePlanId": core_plan_id, "planJobId": expected_plan_id,
                                       "mutation": True}):
            raise ValueError("provider child audit differs")
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
        if (set(path.name for path in root.iterdir()) != {
                "digitalocean", ".plan-material", ".regional-ordinals.lock", "regional-ordinals.json"}
                or [path.name for path in provider_root.iterdir()] != [fingerprint]):
            raise ValueError("provider root is not unique")
        workspace = ProviderKeyedWorkspace(
            workspace_root, workspace_root / "terraform.tfstate", workspace_root / ".terraform-data",
            SCHEMA, "digitalocean", connection_id, fingerprint, _SOURCE_REVISION, _SOURCE_SHA256,
        )
        _require_canonical_workspace_paths(workspace)
        _private_directory(workspace.terraform_data_dir)
        _verify_audited_workspace(workspace)
        _digest(workspace.state_path)
        expected_phase = ("destroy_started" if mode in {
            "destroy_started_read", "destroy_started_recovery_read"} else "applied")
        if _applied_phase_marker(workspace_root / ".barragan-apply-phase.json") != {
                "schema": SCHEMA, "phase": expected_phase}:
            raise ValueError("provider apply phase differs")
        owner = _json_file(workspace_root / ".barragan-initial-plan-owner.json", private=True)
        if owner != {"schema": SCHEMA, "engagementId": engagement_id, "provider": "digitalocean",
                      "providerConnectionId": connection_id, "coreJobId": core_job_id,
                      "planJobId": expected_plan_id, "sourceRevision": _SOURCE_REVISION}:
            raise ValueError("provider workspace owner differs")
        evidence_events = [event for event in plan_job.events if event.message == "reviewed provider plan saved"]
        if (len(evidence_events) != 1 or evidence_events[0].level != "info"
                or set(evidence_events[0].data) != _EVIDENCE_KEYS):
            raise ValueError("reviewed plan evidence is unavailable")
        evidence = evidence_events[0].data
        if (evidence["coreJobId"] != core_job_id or evidence["corePlanId"] != core_plan_id
                or evidence["revisionId"] != intent.revision_id
                or evidence["providerConnectionId"] != connection_id
                or evidence["selectorTag"] != intent.selector_tag
                or evidence["sourceRevision"] != _SOURCE_REVISION
                or evidence["sourceSha256"] != _SOURCE_SHA256
                or evidence["planPath"] != str(workspace_root / ".barragan-initial-full.tfplan")
                or plan_job.artifact_refs != [evidence["planPath"]]):
            raise ValueError("reviewed plan event differs")
        plan_path = workspace_root / ".barragan-initial-full.tfplan"
        if os.path.lexists(plan_path) and (
                _digest(plan_path) != evidence["planSha256"] or plan_path.stat().st_mode & 0o077):
            raise ValueError("retained saved plan differs")
        for key, name in (("markerSha256", ".barragan-provider-keyed-state.json"),
                          ("topologySha256", ".barragan-topology.json"),
                          ("lockfileSha256", ".terraform.lock.hcl")):
            if evidence[key] != _digest(workspace_root / name):
                raise ValueError("reviewed artifact digest differs")
        if (evidence["topologySha256"] != _topology_hash(workspace)
                or _json_file(workspace_root / ".barragan-topology.json") != intent.topology):
            raise ValueError("reviewed topology differs")
        secret_digest, updated_at, _ = _credential_snapshot(connection_id, credentials)
        if (evidence["credentialSecretSha256"], evidence["credentialUpdatedAt"]) != (secret_digest, updated_at):
            raise ValueError("provider credential changed since plan")
        material_root = root / ".plan-material"
        material = material_root / "digitalocean"
        for directory in (material_root, material, material / "ssh-output"):
            _private_directory(directory)
        inputs = material / "inputs.json"
        if (evidence["inputSha256"] != [[str(inputs), _digest(inputs)]]
                or inputs.stat().st_mode & 0o077
                or evidence["adminPrivateKeyPath"] != str(material / "admin-private")
                or evidence["adminPublicKeyPath"] != str(material / "admin-public")
                or evidence["sshOutputDirectory"] != str(material / "ssh-output")
                or any(os.path.lexists(material / name) for name in ("admin-private", "admin-public"))):
            raise ValueError("reviewed plan material differs")
        # The adapter revalidates exact plan-event shape, successful apply
        # event, applied phase, retained state SHA and all provider identities.
        derive_digitalocean_initial_attachment_intent(
            intent, workspace, evidence, apply_job, expected_phase=expected_phase,
        )
        if (engagements.get(engagement_id) != engagement or jobs.get(core_job_id) != core
                or jobs.get(expected_plan_id) != plan_job or jobs.get(expected_apply_id) != apply_job
                or plans.get(core_plan_id) != core_plan or chains_repo.list_for_engagement(engagement_id) != all_chains
                or jobs.list_for_engagement(engagement_id) != related
                or active_core_connection_details(jobs, engagement_id)[0] != core_job_id
                or not _teardown_boundary_matches(engagement_id, jobs, allowed_teardown_parent_id)
                or (mode in {"destroy_started_read", "destroy_started_recovery_read"}
                    and jobs.get(incident_destroy_child_id) != child)):
            raise ValueError("persisted post-apply intent changed during preflight")
        return intent, workspace, evidence, apply_job
    except Exception:
        raise ProviderKeyedPostapplyPreflightError("retained applied provider preflight failed") from None


def _teardown_boundary_matches(engagement_id: str, jobs, allowed_parent_id: str | None) -> bool:
    active = engagement_teardown_in_progress(engagement_id, repository=jobs)
    return active is None if allowed_parent_id is None else active is not None and active.id == allowed_parent_id


def _applied_phase_marker(path: Path) -> dict:
    """Read the writer's owner-private or Barragan-collaborator phase marker."""
    marker = _json_file(path)
    info = path.stat()
    mode = stat.S_IMODE(info.st_mode)
    collaborator_gid = _collaborator_group_gid()
    if mode != 0o600 and not (
            mode == 0o640 and collaborator_gid is not None
            and collaborator_gid == info.st_gid):
        raise ValueError("applied phase marker access differs from writer policy")
    return marker


def _child_ids(core_job_id: str) -> tuple[str, str]:
    suffix = core_job_id.removeprefix("job-")
    return (f"job-provider-keyed-initial-plan-{suffix}",
            f"job-provider-keyed-initial-apply-{suffix}")
