# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant, single-attempt DevTest continuation after a reviewed v2 core run.

No dispatcher calls this module. A failed or interrupted child requires
reconciliation; this service never replays Terraform apply.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from uuid import uuid4

from app.domain import JobEvent
from app.integrations.oci_deployment_targets import OciDeploymentTargetError, normalized_oci_deployment_target
from app.services.provider_keyed_digitalocean_attachment import (
    DigitalOceanAttachmentStillSettling,
    reconcile_digitalocean_initial_attachment,
)
from app.services.provider_keyed_initial_attachment_adapter import derive_digitalocean_initial_attachment_intent
from app.services.provider_keyed_initial_apply_job import run_fresh_digitalocean_initial_apply_job
from app.services.provider_keyed_initial_plan_job import run_fresh_digitalocean_initial_plan_job
from app.services.provider_keyed_planned_state_preflight import preflight_planned_digitalocean_provider
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.engagement_repository import SqlAlchemyEngagementRepository
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun


ACTION = "provider_keyed_initial"
CORE_ACTION = "pilot_standard_rti_guarded_execute"
PLAN_ACTION = "provider_keyed_initial_plan"
APPLY_ACTION = "provider_keyed_initial_apply"
_CLAIM_OWNER = f"provider-keyed-continuation-{uuid4().hex}"
_CLAIM_SECONDS = 3600
_ATTACHMENT_BACKOFF_SECONDS = 30


class ProviderKeyedInitialContinuationError(ValueError):
    """Reviewed continuation cannot safely advance."""


def start_fresh_digitalocean_initial_continuation(
    core_job_id: str,
    *,
    environment: str,
    state_root: Path,
    template_root: Path,
    job_repository: JobRepository | None = None,
    engagement_repository=None,
    plan_repository=None,
    sketch_repository=None,
    credential_repository=None,
    ssh_key_repository=None,
    lease_lookup: Callable[[str], tuple[str, str] | None] | None = None,
    plan_runner: Callable = run_fresh_digitalocean_initial_plan_job,
    planned_preflight: Callable = preflight_planned_digitalocean_provider,
    apply_runner: Callable = run_fresh_digitalocean_initial_apply_job,
    attachment_intent_builder: Callable = derive_digitalocean_initial_attachment_intent,
    attachment_reconciler: Callable = reconcile_digitalocean_initial_attachment,
) -> StoredJobRun:
    """Claim one parent and synchronously run plan then apply once.

    Success deliberately ends at ``awaiting_host_proof`` with
    the parent running and the core plan lease held for later gates.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    engagements = engagement_repository or SqlAlchemyEngagementRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    core = jobs.get(core_job_id)
    if environment != "devtest" or core is None or core.action != CORE_ACTION or core.status != "succeeded":
        raise ProviderKeyedInitialContinuationError("successful DevTest core job is required")
    engagement_id = core.input.get("engagementId") if isinstance(core.input, dict) else None
    plan_id = core.input.get("corePlanId") if isinstance(core.input, dict) else None
    if not isinstance(engagement_id, str) or not engagement_id or not isinstance(plan_id, str) or not plan_id:
        raise ProviderKeyedInitialContinuationError("reviewed core identity is incomplete")
    engagement = engagements.get(engagement_id)
    plan = plans.get(plan_id)
    try:
        target = normalized_oci_deployment_target(engagement.input_parameters.get("deploymentTarget")) if engagement else None
    except (OciDeploymentTargetError, TypeError, AttributeError):
        target = None
    chain_ids = core.input.get("pendingSketchChainIds")
    fingerprints = core.input.get("pendingSketchChainFingerprints")
    if (engagement is None or engagement.id != engagement_id
            or engagement.sketch_state_schema != "provider-keyed-v2"
            or plan is None or plan.id != plan_id or plan.engagement_id != engagement_id
            or plan.status != "applied" or plan.apply_job_id != core.id
            or plan.evidence.get("sketchStateSchema") != "provider-keyed-v2"
            or core.input.get("sketchStateSchema") != "provider-keyed-v2"
            or core.input.get("postCoreSketchContinuationEligible") is not False
            or not isinstance(chain_ids, list) or len(chain_ids) != 2
            or any(not isinstance(value, str) or not value for value in chain_ids)
            or len(set(chain_ids)) != len(chain_ids)
            or not isinstance(fingerprints, dict) or set(fingerprints) != set(chain_ids)
            or any(not isinstance(value, str) or not value for value in fingerprints.values())
            or plan.evidence.get("pendingSketchChainIds") != chain_ids
            or plan.evidence.get("pendingSketchChainFingerprints") != fingerprints
            or core.target_type != "oci_compartment"
            or target is None or core.target != f"oci-compartment:{target['name']}"
            or core.target_id != target["compartmentId"]
            or lookup(engagement_id) != (plan_id, "provider_keyed_initial")):
        raise ProviderKeyedInitialContinuationError("reviewed v2 core plan or lease differs")

    parent_id, plan_job_id, apply_job_id = _job_ids(core.id)
    parent = jobs.save_if_absent(_new_job(
        parent_id, ACTION, core, engagement_id,
        {"engagementId": engagement_id, "coreJobId": core.id, "corePlanId": plan_id,
         "planJobId": plan_job_id, "applyJobId": apply_job_id,
         "phase": "queued", "mutation": True},
    ))
    if not _same_parent(parent, core, engagement_id, plan_id, plan_job_id, apply_job_id):
        raise ProviderKeyedInitialContinuationError("deterministic continuation job differs")
    if parent.status != "queued" or parent.started_at or parent.finished_at:
        return parent
    if parent.input.get("phase") != "queued":
        raise ProviderKeyedInitialContinuationError("queued continuation phase differs")
    claimed_at = _now()
    claim_token = uuid4().hex
    claimed = jobs.claim_lease(
        parent.id, owner=_CLAIM_OWNER, token=claim_token,
        claimed_at=claimed_at, expires_at=_expiry(claimed_at), eligible_statuses={"queued"},
    )
    if claimed is None:
        return jobs.get(parent.id) or parent
    parent = _advance(jobs, claimed, claim_token, "planning", "provider plan child starting", status="running")
    try:
        _require_lease(lookup, engagement_id, plan_id)
        plan_child = _save_new_child(jobs, _new_job(
            plan_job_id, PLAN_ACTION, core, engagement_id,
            {"engagementId": engagement_id, "coreJobId": core.id, "mutation": False},
        ))
        parent = _advance(jobs, parent, claim_token, "plan_queued", "provider plan child queued")
        planned = plan_runner(
            plan_child.id, lease_owner=plan_id, environment=environment,
            state_root=state_root, template_root=template_root, lease_lookup=lookup,
            job_repository=jobs, engagement_repository=engagements,
            sketch_repository=sketch_repository, plan_repository=plans,
            credential_repository=credentials, ssh_key_repository=ssh_key_repository,
        )
        if planned.id != plan_child.id or planned.status != "succeeded" or jobs.get(plan_child.id) != planned:
            raise ProviderKeyedInitialContinuationError("provider plan child did not succeed exactly once")
        parent = _advance(jobs, parent, claim_token, "plan_succeeded", "provider plan child succeeded")
        _require_lease(lookup, engagement_id, plan_id)
        # This read-only preflight must run before an apply audit row exists.
        reviewed = planned_preflight(
            engagement_id, core.id, plan_child.id, lease_owner=plan_id,
            environment=environment, state_root=state_root, lease_lookup=lookup,
            engagement_repository=engagements, sketch_repository=sketch_repository,
            job_repository=jobs, plan_repository=plans,
            credential_repository=credentials,
        )
        if not isinstance(reviewed, tuple) or len(reviewed) != 3:
            raise ProviderKeyedInitialContinuationError("reviewed plan preflight evidence is incomplete")
        parent = _advance(jobs, parent, claim_token, "apply_preflight_passed", "provider apply preflight passed")
        _require_lease(lookup, engagement_id, plan_id)
        apply_child = _save_new_child(jobs, _new_job(
            apply_job_id, APPLY_ACTION, core, engagement_id,
            {"engagementId": engagement_id, "coreJobId": core.id, "corePlanId": plan_id,
             "planJobId": plan_child.id, "mutation": True},
        ))
        parent = _advance(jobs, parent, claim_token, "apply_queued", "provider apply child queued")
        applied = apply_runner(
            apply_child.id, environment=environment, state_root=state_root,
            lease_lookup=lookup, job_repository=jobs, engagement_repository=engagements,
            sketch_repository=sketch_repository, plan_repository=plans,
            credential_repository=credentials, ssh_key_repository=ssh_key_repository,
        )
        if applied.id != apply_child.id or applied.status != "succeeded" or jobs.get(apply_child.id) != applied:
            raise ProviderKeyedInitialContinuationError("provider apply child requires reconciliation")
        _require_lease(lookup, engagement_id, plan_id)
        parent = _advance(jobs, parent, claim_token, "reconciling_attachment", "provider attachment proof started")
        attachment_intent = attachment_intent_builder(*reviewed, applied)
        try:
            evidence = attachment_reconciler(
                reviewed[1], attachment_intent, environment=environment,
                deployment_target="barragan-testing", credential_repository=credentials,
                max_attempts=12, poll_interval_seconds=10.0,
            )
        except DigitalOceanAttachmentStillSettling:
            _require_lease(lookup, engagement_id, plan_id)
            return _advance(
                jobs, parent, claim_token, "attachment_pending",
                "provider attachment still settling; proof pending",
                data={"attachmentProofPending": True, "hostProofPending": True},
                attachment_backoff_seconds=_ATTACHMENT_BACKOFF_SECONDS,
            )
        if (evidence.provider_membership_verified is not True
                or evidence.host_policy_verified is not False
                or evidence.state_sha256 != attachment_intent.state_sha256
                or evidence.firewall_id != attachment_intent.firewall_id
                or set(evidence.verified_droplet_ids) != {node.droplet_id for node in attachment_intent.nodes}
                or len(evidence.verified_droplet_ids) != len(attachment_intent.nodes)
                or type(evidence.attempts) is not int or not 1 <= evidence.attempts <= 12):
            raise ProviderKeyedInitialContinuationError("provider attachment evidence differs")
        _require_lease(lookup, engagement_id, plan_id)
        return _advance(
            jobs, parent, claim_token, "awaiting_host_proof",
            "provider attachment proven; host proof pending",
            data={"stateSha256": evidence.state_sha256, "firewallId": evidence.firewall_id,
                  "verifiedDropletIds": list(evidence.verified_droplet_ids),
                  "attempts": evidence.attempts, "providerMembershipVerified": True,
                  "hostProofPending": True},
        )
    except Exception:
        try:
            return _advance(
                jobs, parent, claim_token, "attention", "provider continuation stopped; reconciliation required",
                status="failed",
            )
        except Exception:
            raise ProviderKeyedInitialContinuationError("provider continuation stopped; reconciliation required") from None


def _job_ids(core_job_id: str) -> tuple[str, str, str]:
    suffix = core_job_id.removeprefix("job-")
    return (f"job-provider-keyed-initial-{suffix}",
            f"job-provider-keyed-initial-plan-{suffix}",
            f"job-provider-keyed-initial-apply-{suffix}")


def _new_job(job_id: str, action: str, core: StoredJobRun, engagement_id: str, inputs: dict) -> StoredJobRun:
    return StoredJobRun(
        id=job_id, action=action, status="queued", target=f"engagement:{engagement_id}",
        target_type="engagement", target_id=engagement_id, requested_by=core.requested_by,
        input=inputs, artifact_refs=[], created_at=_now(), started_at=None, finished_at=None,
        events=[JobEvent(1, "info", "provider continuation job queued", {"creationToken": uuid4().hex})],
    )


def _same_parent(job: StoredJobRun, core: StoredJobRun, engagement_id: str,
                 plan_id: str, plan_job_id: str, apply_job_id: str) -> bool:
    inputs = {key: value for key, value in job.input.items()
              if not key.startswith("claim") and key not in {"nextAttachmentCheckAt", "attachmentRecheckCount"}}
    recheck_count = job.input.get("attachmentRecheckCount")
    next_check = job.input.get("nextAttachmentCheckAt")
    return (job.action == ACTION and job.target == f"engagement:{engagement_id}"
            and job.target_type == "engagement" and job.target_id == engagement_id
            and job.requested_by == core.requested_by
            and inputs == {
                "engagementId": engagement_id, "coreJobId": core.id, "corePlanId": plan_id,
                "planJobId": plan_job_id, "applyJobId": apply_job_id,
                "phase": job.input.get("phase"), "mutation": True,
            } and ((recheck_count is None and next_check is None)
                   or (type(recheck_count) is int and recheck_count >= 0
                       and isinstance(next_check, str) and bool(next_check)))
            and job.input.get("phase") in {
                "queued", "planning", "plan_queued", "plan_succeeded", "apply_preflight_passed",
                "apply_queued", "reconciling_attachment", "attachment_pending",
                "awaiting_host_proof", "binding_host_identity", "host_identity_bound", "attention",
                "bootstrap_preparing", "bootstrap_contacted", "bootstrap_root_started",
                "bootstrap_chain_completed", "awaiting_strict_host_proof",
            })


def _save_new_child(jobs: JobRepository, expected: StoredJobRun) -> StoredJobRun:
    if jobs.get(expected.id) is not None:
        raise ProviderKeyedInitialContinuationError("provider child already has an audit record")
    stored = jobs.save_if_absent(expected)
    if (stored.id != expected.id or stored.action != expected.action or stored.status != "queued"
            or stored.target != expected.target or stored.target_type != expected.target_type
            or stored.target_id != expected.target_id or stored.requested_by != expected.requested_by
            or stored.input != expected.input or stored.events != expected.events
            or stored.started_at is not None or stored.finished_at is not None):
        raise ProviderKeyedInitialContinuationError("provider child creation raced with another writer")
    return stored


def _advance(jobs: JobRepository, parent: StoredJobRun, token: str, phase: str,
             message: str, *, status: str = "running", data: dict | None = None,
             attachment_backoff_seconds: int | None = None) -> StoredJobRun:
    now = _now()
    renewed = jobs.renew_lease(
        parent.id, owner=_CLAIM_OWNER, token=token,
        heartbeat_at=now, expires_at=_expiry(now),
    )
    if renewed is None or renewed.input.get("claimToken") != token:
        raise ProviderKeyedInitialContinuationError("provider continuation claim was lost")
    inputs = {**renewed.input, "phase": phase}
    if attachment_backoff_seconds is not None:
        next_check = _expiry(now, seconds=attachment_backoff_seconds)
        inputs.update({"nextAttachmentCheckAt": next_check, "attachmentRecheckCount": 0,
                       "claimExpiresAt": next_check})
    elif phase == "awaiting_host_proof":
        # Fenced phase handoff: a new worker may claim this completed GET-only
        # phase immediately without stealing the continuation's live claim.
        inputs["claimExpiresAt"] = now
    updated = replace(
        renewed, status=status, started_at=renewed.started_at or now,
        finished_at=now if status == "failed" else None,
        input=inputs,
        events=[*renewed.events, JobEvent(len(renewed.events) + 1,
            "error" if status == "failed" else "info", message, data or {})],
    )
    stored = jobs.save_if_leased(updated, owner=_CLAIM_OWNER, token=token)
    if stored is None or stored.input.get("phase") != phase:
        raise ProviderKeyedInitialContinuationError("provider continuation progress could not be saved")
    return stored


def _require_lease(lookup: Callable, engagement_id: str, plan_id: str) -> None:
    if lookup(engagement_id) != (plan_id, "provider_keyed_initial"):
        raise ProviderKeyedInitialContinuationError("core plan mutation lease changed")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _expiry(now: str, *, seconds: int = _CLAIM_SECONDS) -> str:
    return (datetime.fromisoformat(now) + timedelta(seconds=seconds)).isoformat()
