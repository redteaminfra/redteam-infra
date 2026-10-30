# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant terminal-only keyed bootstrap to teardown lease handoff.

This does not start a destroy. A pending handoff can retry only after a fresh
read-only audit of the actual retained journal and scratch artifacts.
"""

from __future__ import annotations

from app.services.provider_keyed_published_initial_cleanup_authority import queued_cleanup_event_data

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from uuid import uuid4

from app.services.engagement_teardown import (
    ENGAGEMENT_TEARDOWN_ACTION, _fingerprint, _parent_id,
    _validated_parent_boundary, engagement_teardown_in_progress,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_initial_continuation import _job_ids
from app.services.provider_keyed_teardown_quiescence import (
    audit_pending_provider_keyed_bootstrap, audit_terminal_provider_keyed_bootstrap,
)
from app.services.provider_keyed_teardown_scope import build_digitalocean_keyed_teardown_scope
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest


_OLD_OPERATION = "provider_keyed_initial"
_NEW_OPERATION = "provider_keyed_teardown_fence"
_HANDOFF_OWNER = "provider-keyed-teardown-handoff"
_FINAL = "provider bootstrap completed; strict host proof pending"


class ProviderKeyedTeardownHandoffError(ValueError):
    """The complete terminal teardown handoff boundary was not proven."""


def handoff_terminal_provider_keyed_teardown(
    teardown_parent_id: str, *, environment: str = "devtest",
    job_repository=None, plan_repository=None,
    lease_lookup: Callable[[str], tuple[str, str] | None] | None = None,
    scope_builder: Callable = build_digitalocean_keyed_teardown_scope,
    quiescence_auditor: Callable = audit_terminal_provider_keyed_bootstrap,
    pending_quiescence_auditor: Callable = audit_pending_provider_keyed_bootstrap,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    token_factory: Callable[[], str] = lambda: uuid4().hex,
):
    """Fence one terminal bootstrap parent, then retag its existing core lease.

    The caller must have already queued the exact comprehensive teardown.
    Retag failure leaves a durable pending phase and never releases the lease.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        if environment != "devtest" or not isinstance(teardown_parent_id, str) or not teardown_parent_id:
            raise ValueError("unsupported environment or parent")
        teardown = jobs.get(teardown_parent_id)
        if (teardown is None or teardown.id != teardown_parent_id
                or teardown.action != ENGAGEMENT_TEARDOWN_ACTION
                or teardown.status != "queued" or teardown.started_at is not None
                or teardown.finished_at is not None or teardown.input.get("phase") != "queued"
                or teardown.input.get("mutation") is not True
                or len(teardown.events) != 1
                or teardown.events[0].message != "engagement teardown queued"):
            raise ValueError("confirmed queued teardown parent differs")
        core, snapshot = _validated_parent_boundary(teardown, jobs)
        if _fingerprint({key: value for key, value in snapshot.items() if key != "snapshotId"}) != snapshot["snapshotId"]:
            raise ValueError("queued confirmation snapshot changed")
        engagement_id, core_job_id = snapshot["engagementId"], core.id
        if (teardown.id != _parent_id(core_job_id)
                or engagement_teardown_in_progress(engagement_id, repository=jobs) != teardown
                or core.status != "succeeded" or core.input.get("sketchStateSchema") != "provider-keyed-v2"
                or core.input.get("corePlanId") != snapshot["providerScopes"][0]["corePlanId"]
                or snapshot["coreJobId"] != core_job_id
                or teardown.events[0].data != queued_cleanup_event_data(snapshot)):
            raise ValueError("reviewed core and teardown identity differ")
        plan_id = core.input["corePlanId"]
        plan = plans.get(plan_id)
        if (plan is None or plan.id != plan_id or plan.engagement_id != engagement_id
                or plan.status != "applied" or plan.apply_job_id != core_job_id
                or lookup(engagement_id) != (plan_id, _OLD_OPERATION)):
            raise ValueError("core plan or mutation lease differs")
        reviewed_scope = snapshot["providerScopes"][0]
        current_scope = scope_builder(
            engagement_id, core_job_id, environment=environment,
            allowed_teardown_parent_id=teardown_parent_id,
            job_repository=jobs, plan_repository=plans,
        )
        if current_scope != reviewed_scope or jobs.get(teardown_parent_id) != teardown:
            raise ValueError("confirmed provider scope changed")
        workspace = Path(reviewed_scope["workspace"])
        bootstrap_id = _job_ids(core_job_id)[0]
        starting = jobs.get(bootstrap_id)
        if starting is None:
            raise ValueError("bootstrap parent is absent")
        if starting.input.get("phase") == "teardown_handoff_pending":
            # The same persisted row and complete source journal, including
            # its sealed handoff event, are audited; no virtual terminal job.
            proof = pending_quiescence_auditor(
                core_job_id, confirmed_scope=reviewed_scope,
                confirmed_scope_sha256=_fingerprint(snapshot),
                workspace_root=workspace, job_repository=jobs,
            )
            fenced = jobs.get(proof.parent_job_id)
            if fenced != starting:
                raise ValueError("pending handoff changed during audit")
        else:
            # This audit rereads the parent and core and checks staged-key cleanup.
            proof = quiescence_auditor(
                core_job_id, confirmed_scope=reviewed_scope,
                workspace_root=workspace, job_repository=jobs,
            )
            parent = jobs.get(proof.parent_job_id)
            if (parent is None or parent.status != "running"
                    or parent.input.get("phase") != "awaiting_strict_host_proof"
                    or not parent.events or parent.events[-1].message != _FINAL
                    or jobs.get(teardown_parent_id) != teardown
                    or lookup(engagement_id) != (plan_id, _OLD_OPERATION)):
                raise ValueError("terminal handoff boundary changed")
            old_owner, old_token = parent.input.get("claimOwner"), parent.input.get("claimToken")
            current_time = now()
            token = token_factory()
            if (not isinstance(current_time, datetime) or current_time.tzinfo is None
                    or not isinstance(token, str) or len(token) < 16):
                raise ValueError("handoff clock or claim token is invalid")
            fenced = jobs.fence_terminal_provider_bootstrap_handoff(
                parent.id, old_owner=old_owner, old_token=old_token,
                new_owner=_HANDOFF_OWNER, new_token=token,
                claimed_at=current_time.isoformat(),
                expires_at=(current_time + timedelta(minutes=5)).isoformat(),
                expected_event_count=len(parent.events),
                expected_event_digest=job_event_digest(parent.events),
                expected_final_message=_FINAL,
                confirmed_scope_sha256=_fingerprint(snapshot),
            )
        if (fenced is None or jobs.get(fenced.id) != fenced
                or jobs.get(teardown_parent_id) != teardown
                or lookup(engagement_id) != (plan_id, _OLD_OPERATION)):
            # If the CAS succeeded, its pending marker is durable. Do not undo it.
            raise ValueError("teardown or lease changed during handoff")
        plans.retag_if_operation(engagement_id, plan_id, _OLD_OPERATION, _NEW_OPERATION)
        if (lookup(engagement_id) != (plan_id, _NEW_OPERATION)
                or jobs.get(teardown_parent_id) != teardown
                or jobs.get(fenced.id) != fenced):
            raise ValueError("retagged lease could not be verified")
        return fenced
    except Exception:
        raise ProviderKeyedTeardownHandoffError(
            "terminal keyed teardown handoff is unproved; no destroy was started") from None
