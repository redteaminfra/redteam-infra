# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant GET-only attachment recheck after a successful keyed provider apply.

An expired claim is not evidence that its worker died. Reclaiming is safe here
because both workers can only read provider state and the parent claim token
fences every persisted result. Terraform apply is never replayed.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from uuid import uuid4

from app.domain import JobEvent
from app.services.provider_keyed_digitalocean_attachment import (
    DigitalOceanAttachmentStillSettling, reconcile_digitalocean_initial_attachment,
)
from app.services.provider_keyed_initial_attachment_adapter import derive_digitalocean_initial_attachment_intent
from app.services.provider_keyed_postapply_preflight import preflight_applied_digitalocean_provider
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun


_CLAIM_OWNER = f"provider-keyed-attachment-recheck-{uuid4().hex}"
ACTION = "provider_keyed_initial"
CORE_ACTION = "pilot_standard_rti_guarded_execute"
_CLAIM_SECONDS = 3600
_MIN_BACKOFF_SECONDS = 30
_MAX_BACKOFF_SECONDS = 300
_ELIGIBLE_PHASES = {"attachment_pending", "reconciling_attachment"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ProviderKeyedInitialAttachmentRecheckError(ValueError):
    """Attachment recheck cannot safely advance."""


def recheck_digitalocean_initial_attachment(
    parent_id: str,
    *,
    environment: str,
    state_root: Path,
    job_repository: JobRepository | None = None,
    plan_repository=None,
    engagement_repository=None,
    sketch_repository=None,
    credential_repository=None,
    lease_lookup: Callable[[str], tuple[str, str] | None] | None = None,
    postapply_preflight: Callable = preflight_applied_digitalocean_provider,
    attachment_intent_builder: Callable = derive_digitalocean_initial_attachment_intent,
    attachment_reconciler: Callable = reconcile_digitalocean_initial_attachment,
    clock: Callable[[], str] = _now,
) -> StoredJobRun:
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    parent = jobs.get(parent_id)
    if environment != "devtest" or parent is None or parent.id != parent_id:
        raise ProviderKeyedInitialAttachmentRecheckError("DevTest attachment parent is unavailable")
    values = parent.input if isinstance(parent.input, dict) else {}
    engagement_id, core_id, plan_id = (values.get(key) for key in ("engagementId", "coreJobId", "corePlanId"))
    if any(not isinstance(value, str) or not value for value in (engagement_id, core_id, plan_id)):
        raise ProviderKeyedInitialAttachmentRecheckError("attachment parent identity is incomplete")
    core = jobs.get(core_id)
    plan = plans.get(plan_id)
    if (core is None or core.id != core_id or core.action != CORE_ACTION or core.status != "succeeded"
            or core.input.get("engagementId") != engagement_id or core.input.get("corePlanId") != plan_id
            or core.input.get("sketchStateSchema") != "provider-keyed-v2"
            or plan is None or plan.id != plan_id or plan.engagement_id != engagement_id
            or plan.status != "applied" or plan.apply_job_id != core_id
            or plan.evidence.get("sketchStateSchema") != "provider-keyed-v2"
            or parent_id != _parent_id(core_id)
            or not _same_parent(parent, core, engagement_id, plan_id)
            or parent.status != "running" or parent.finished_at is not None
            or not parent.started_at or values.get("phase") not in _ELIGIBLE_PHASES
            or lookup(engagement_id) != (plan_id, ACTION)):
        raise ProviderKeyedInitialAttachmentRecheckError("reviewed attachment parent or lease differs")
    now = clock()
    if values["phase"] == "attachment_pending" and not _due(values.get("nextAttachmentCheckAt"), now):
        raise ProviderKeyedInitialAttachmentRecheckError("attachment recheck is not due")
    token = uuid4().hex
    claimed = jobs.claim_lease(
        parent_id, owner=_CLAIM_OWNER, token=token, claimed_at=now,
        expires_at=_later(now, _CLAIM_SECONDS), eligible_statuses={"running"},
        eligible_phases=_ELIGIBLE_PHASES,
    )
    if claimed is None:
        raise ProviderKeyedInitialAttachmentRecheckError("attachment recheck claim is unavailable")
    if (claimed.input.get("phase") not in _ELIGIBLE_PHASES
            or claimed.input.get("corePlanId") != plan_id):
        raise ProviderKeyedInitialAttachmentRecheckError("attachment recheck claim changed")
    if (claimed.input["phase"] == "attachment_pending"
            and not _due(claimed.input.get("nextAttachmentCheckAt"), now)):
        _defer_moved_check(jobs, claimed, token, now)
        raise ProviderKeyedInitialAttachmentRecheckError("attachment recheck is not due")
    current = _save_phase(jobs, claimed, token, "reconciling_attachment", "provider attachment recheck started")
    try:
        _require_lease(lookup, engagement_id, plan_id)
        reviewed = postapply_preflight(
            engagement_id, core_id, lease_owner=plan_id, environment=environment,
            state_root=state_root, lease_lookup=lookup,
            job_repository=jobs, plan_repository=plans, engagement_repository=engagement_repository,
            sketch_repository=sketch_repository, credential_repository=credentials,
        )
        if not isinstance(reviewed, tuple) or len(reviewed) != 4:
            raise ValueError("retained applied evidence is incomplete")
        attachment_intent = attachment_intent_builder(*reviewed)
        evidence = attachment_reconciler(
            reviewed[1], attachment_intent, environment=environment,
            deployment_target="barragan-testing", credential_repository=credentials,
            max_attempts=12, poll_interval_seconds=10.0,
        )
        _require_lease(lookup, engagement_id, plan_id)
        data = _proof_data(evidence, attachment_intent)
        return _save_phase(
            jobs, current, token, "awaiting_host_proof",
            "provider attachment proven; host proof pending", data=data,
        )
    except DigitalOceanAttachmentStillSettling:
        try:
            _require_lease(lookup, engagement_id, plan_id)
            count = current.input.get("attachmentRecheckCount", 0)
            if type(count) is not int or count < 0:
                raise ValueError("attachment recheck count differs")
            count += 1
            backoff = min(_MIN_BACKOFF_SECONDS * (2 ** min(count, 4)), _MAX_BACKOFF_SECONDS)
            next_check = _later(clock(), backoff)
            return _save_phase(
                jobs, current, token, "attachment_pending", "provider attachment still settling; proof pending",
                data={"attachmentProofPending": True, "hostProofPending": True},
                next_check=next_check, recheck_count=count,
            )
        except Exception:
            return _attention(jobs, current, token)
    except Exception:
        return _attention(jobs, current, token)


def _attention(jobs: JobRepository, parent: StoredJobRun, token: str) -> StoredJobRun:
    try:
        return _save_phase(
            jobs, parent, token, "attention",
            "provider attachment recheck stopped; reconciliation required", status="failed",
        )
    except Exception:
        raise ProviderKeyedInitialAttachmentRecheckError(
            "provider attachment recheck stopped; reconciliation required",
        ) from None


def _defer_moved_check(jobs: JobRepository, parent: StoredJobRun, token: str, now: str) -> None:
    next_check = parent.input.get("nextAttachmentCheckAt")
    if not _future(next_check, now):
        raise ProviderKeyedInitialAttachmentRecheckError("attachment recheck schedule changed")
    updated = replace(
        parent,
        input={**parent.input, "claimExpiresAt": next_check},
        events=[*parent.events, JobEvent(len(parent.events) + 1, "info",
                                         "provider attachment recheck deferred to current schedule", {})],
    )
    if jobs.save_if_leased(updated, owner=_CLAIM_OWNER, token=token) is None:
        raise ProviderKeyedInitialAttachmentRecheckError("attachment recheck claim was lost")


def _parent_id(core_id: str) -> str:
    return f"job-provider-keyed-initial-{core_id.removeprefix('job-')}"


def _same_parent(parent: StoredJobRun, core: StoredJobRun, engagement_id: str, plan_id: str) -> bool:
    suffix = core.id.removeprefix("job-")
    inputs = parent.input
    base = {key: value for key, value in inputs.items()
            if not key.startswith("claim") and key not in {"nextAttachmentCheckAt", "attachmentRecheckCount"}}
    count = inputs.get("attachmentRecheckCount")
    next_check = inputs.get("nextAttachmentCheckAt")
    return (
        parent.action == ACTION and parent.target == f"engagement:{engagement_id}"
        and parent.target_type == "engagement" and parent.target_id == engagement_id
        and parent.requested_by == core.requested_by
        and base == {"engagementId": engagement_id, "coreJobId": core.id, "corePlanId": plan_id,
                     "planJobId": f"job-provider-keyed-initial-plan-{suffix}",
                     "applyJobId": f"job-provider-keyed-initial-apply-{suffix}",
                     "phase": inputs.get("phase"), "mutation": True}
        and ((count is None and next_check is None)
             or (type(count) is int and count >= 0 and isinstance(next_check, str) and bool(next_check)))
    )


def _proof_data(evidence, intent) -> dict:
    if (evidence.provider_membership_verified is not True
            or evidence.host_policy_verified is not False
            or evidence.state_sha256 != intent.state_sha256
            or evidence.firewall_id != intent.firewall_id
            or set(evidence.verified_droplet_ids) != {node.droplet_id for node in intent.nodes}
            or len(evidence.verified_droplet_ids) != len(intent.nodes)
            or type(evidence.attempts) is not int or not 1 <= evidence.attempts <= 12):
        raise ValueError("provider attachment evidence differs")
    return {"stateSha256": evidence.state_sha256, "firewallId": evidence.firewall_id,
            "verifiedDropletIds": list(evidence.verified_droplet_ids), "attempts": evidence.attempts,
            "providerMembershipVerified": True, "hostProofPending": True}


def _save_phase(jobs: JobRepository, parent: StoredJobRun, token: str, phase: str, message: str,
                *, status: str = "running", data: dict | None = None,
                next_check: str | None = None, recheck_count: int | None = None) -> StoredJobRun:
    now = _now()
    renewed = jobs.renew_lease(
        parent.id, owner=_CLAIM_OWNER, token=token, heartbeat_at=now,
        expires_at=_later(now, _CLAIM_SECONDS),
    )
    if renewed is None or renewed.input.get("claimToken") != token:
        raise ProviderKeyedInitialAttachmentRecheckError("attachment recheck claim was lost")
    inputs = {**renewed.input, "phase": phase}
    if next_check is not None:
        inputs.update({"nextAttachmentCheckAt": next_check, "attachmentRecheckCount": recheck_count,
                       "claimExpiresAt": next_check})
    else:
        if phase == "awaiting_host_proof":
            # Release only through this token-fenced phase save. A later binder
            # can claim promptly without treating a live claim as abandoned.
            inputs["claimExpiresAt"] = now
        if phase != "reconciling_attachment":
            inputs.pop("nextAttachmentCheckAt", None)
            inputs.pop("attachmentRecheckCount", None)
    updated = replace(
        renewed, status=status, finished_at=now if status == "failed" else None,
        input=inputs, events=[*renewed.events, JobEvent(
            len(renewed.events) + 1, "error" if status == "failed" else "info", message, data or {},
        )],
    )
    stored = jobs.save_if_leased(updated, owner=_CLAIM_OWNER, token=token)
    if stored is None or stored.input.get("phase") != phase:
        raise ProviderKeyedInitialAttachmentRecheckError("attachment recheck result could not be saved")
    return stored


def _due(next_check: object, now: str) -> bool:
    try:
        return isinstance(next_check, str) and datetime.fromisoformat(next_check) <= datetime.fromisoformat(now)
    except (TypeError, ValueError):
        return False


def _future(next_check: object, now: str) -> bool:
    try:
        return isinstance(next_check, str) and datetime.fromisoformat(next_check) > datetime.fromisoformat(now)
    except (TypeError, ValueError):
        return False


def _later(now: str, seconds: int) -> str:
    return (datetime.fromisoformat(now) + timedelta(seconds=seconds)).isoformat()


def _require_lease(lookup: Callable, engagement_id: str, plan_id: str) -> None:
    if lookup(engagement_id) != (plan_id, ACTION):
        raise ProviderKeyedInitialAttachmentRecheckError("core plan mutation lease changed")
