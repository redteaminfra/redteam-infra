# Copyright (c) 2026, Oracle and/or its affiliates.
"""DevTest-only, exact-state dispatch of the first provider-keyed continuation."""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from app.core.command_environment import barragan_subprocess_env
from app.services.provider_keyed_host_binding import bind_initial_digitalocean_host_identity
from app.services.provider_keyed_initial_attachment_recheck import recheck_digitalocean_initial_attachment
from app.services.provider_keyed_initial_bootstrap import bootstrap_initial_digitalocean_chains
from app.services.provider_keyed_initial_host_publication import publish_initial_digitalocean_host_proof
from app.services.provider_keyed_initial_continuation import (
    _job_ids, _same_parent, start_fresh_digitalocean_initial_continuation,
)
from app.services.provider_keyed_runtime_preflight import preflight_fresh_digitalocean_provider
from app.services.redteam_infra_template import TEMPLATE_ROOT_ENV
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository


class ProviderKeyedInitialDispatchError(ValueError):
    pass


def _unclaimed_queued_parent(parent) -> bool:
    return parent is not None and parent.status == "queued" and isinstance(parent.input, dict) and not any(
        key in parent.input for key in
        ("claimOwner", "claimToken", "claimClaimedAt", "claimExpiresAt")
    )


_SAFE_PHASES = {"attachment_pending", "awaiting_host_proof", "binding_host_identity",
                "host_identity_bound"}
_RUNTIME_PHASES = _SAFE_PHASES | {"awaiting_strict_host_proof"}


def _due_delay(value: object, now: datetime) -> float:
    if not isinstance(value, str):
        raise ProviderKeyedInitialDispatchError("attachment schedule is incomplete")
    try:
        due = datetime.fromisoformat(value)
    except ValueError:
        raise ProviderKeyedInitialDispatchError("attachment schedule differs") from None
    if due.tzinfo is None:
        raise ProviderKeyedInitialDispatchError("attachment schedule differs")
    return max(0.0, (due - now).total_seconds())


def _phase_authority(core_job_id: str, jobs, plans, environment: str):
    """Re-read the private core pin and retained lease before each phase."""
    from app.services.guarded_test_deployment import _require_configured_keyed_source
    from app.services.provider_keyed_initial_continuation import _db_lease_lookup

    core = jobs.get(core_job_id)
    inputs = core.input if core is not None and isinstance(core.input, dict) else {}
    engagement_id, plan_id = inputs.get("engagementId"), inputs.get("corePlanId")
    plan = plans.get(plan_id) if isinstance(plan_id, str) else None
    pin = inputs.get("providerKeyedSourcePin")
    if (environment != "devtest" or core is None or core.status != "succeeded"
            or core.action != "pilot_standard_rti_guarded_execute"
            or inputs.get("sketchStateSchema") != "provider-keyed-v2"
            or inputs.get("providerKeyedDispatchAuthorized") is not True
            or not isinstance(engagement_id, str) or not engagement_id
            or not isinstance(plan_id, str) or not plan_id
            or plan is None or plan.engagement_id != engagement_id or plan.status != "applied"
            or plan.stage != "applied"
            or plan.apply_job_id != core.id
            or plan.evidence.get("sketchStateSchema") != "provider-keyed-v2"
            or _db_lease_lookup(engagement_id) != (plan_id, "provider_keyed_initial")
            or not isinstance(pin, dict) or not isinstance(pin.get("root"), str)):
        raise ProviderKeyedInitialDispatchError("reviewed keyed continuation authority differs")
    try:
        if _require_configured_keyed_source(pin) != pin:
            raise ValueError
    except Exception:
        raise ProviderKeyedInitialDispatchError("pinned keyed source requires reconciliation") from None
    return core, plan, pin


def advance_fresh_keyed_initial_phases(
    core_job_id: str, *, environment: str, rollout_enabled: bool = False,
    job_repository=None, plan_repository=None,
    dispatch: Callable | None = None,
    recheck: Callable | None = None,
    bind: Callable | None = None,
    bootstrap: Callable | None = None,
    publish_host_proof: Callable | None = None,
    wait: Callable[[float], None] = time.sleep,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
):
    """Advance reclaimable phases and one fresh, non-reclaimable strict proof.

    A pending attachment has a durable due time. Waiting holds no parent claim;
    restart re-enters through the same phase classifier. Bootstrap preparation
    and every later host-command phase are deliberately never replayed here.
    """
    if environment != "devtest" or rollout_enabled is not True:
        return None
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    recheck = recheck or recheck_digitalocean_initial_attachment
    bind = bind or bind_initial_digitalocean_host_identity
    bootstrap = bootstrap or bootstrap_initial_digitalocean_chains
    publish_host_proof = publish_host_proof or publish_initial_digitalocean_host_proof
    parent_id, plan_child, apply_child = _job_ids(core_job_id)
    parent = jobs.get(parent_id)
    if parent is not None and parent.status == "queued" and not isinstance(parent.input, dict):
        raise ProviderKeyedInitialDispatchError("provider continuation parent is malformed")
    if parent is None or _unclaimed_queued_parent(parent):
        start = dispatch or dispatch_fresh_keyed_initial
        parent = start(core_job_id, environment=environment, rollout_enabled=True,
                       job_repository=jobs, plan_repository=plans)
    fresh_bootstrap = False
    while True:
        retained = jobs.get(parent_id)
        if retained is None:
            raise ProviderKeyedInitialDispatchError("provider continuation parent was not retained")
        parent = retained
        if parent.status != "running" or parent.finished_at is not None:
            return parent
        if not isinstance(parent.input, dict) or parent.input.get("phase") is None:
            raise ProviderKeyedInitialDispatchError("provider continuation phase is malformed")
        phase = parent.input["phase"]
        if phase not in _RUNTIME_PHASES:
            return parent
        if phase == "awaiting_strict_host_proof" and not fresh_bootstrap:
            return parent
        core, _plan, pin = _phase_authority(core_job_id, jobs, plans, environment)
        if not _same_parent(parent, core, core.input["engagementId"], core.input["corePlanId"],
                            plan_child, apply_child):
            raise ProviderKeyedInitialDispatchError("provider continuation parent differs")
        # Another live worker owns this phase. Its claim is not evidence of a
        # crash, even if this process is performing startup recovery.
        expiry = parent.input.get("claimExpiresAt")
        claim_delay = _due_delay(expiry, clock()) if expiry is not None else 0.0
        if claim_delay > 0:
            # A live worker may still own this phase. Wait for its next
            # durable transition or expiry without taking its claim. There
            # is no DevTest scheduler to rearm this task after a fixed cap.
            wait(min(claim_delay, 300.0))
            continue
        state_root = _default_state_root()
        if phase == "attachment_pending":
            delay = _due_delay(parent.input.get("nextAttachmentCheckAt"), clock())
            if delay > 0:
                wait(min(delay, 300.0))
                continue
            updated = recheck(parent_id, environment=environment, state_root=state_root,
                              job_repository=jobs, plan_repository=plans)
        elif phase in {"awaiting_host_proof", "binding_host_identity"}:
            updated = bind(parent_id, environment=environment, state_root=state_root,
                           job_repository=jobs, plan_repository=plans)
        elif phase == "host_identity_bound":
            env = barragan_subprocess_env()
            env[TEMPLATE_ROOT_ENV] = pin["root"]
            updated = bootstrap(parent_id, environment=environment, state_root=state_root,
                                bootstrap_env=env, job_repository=jobs, plan_repository=plans)
            fresh_bootstrap = (updated is not None
                and updated.input.get("phase") == "awaiting_strict_host_proof"
                and bool(updated.events)
                and updated.events[-1].message ==
                    "provider bootstrap completed; strict host proof pending")
        else:
            # Startup recovery deliberately excludes this phase. Its child
            # journal reserves first host contact and is never replayed.
            updated = publish_host_proof(parent_id, environment=environment,
                                         state_root=state_root, job_repository=jobs,
                                         plan_repository=plans)
        if updated is None or updated.id != parent_id:
            raise ProviderKeyedInitialDispatchError("provider continuation phase result differs")
        if (updated.status == "running" and updated.input.get("phase") == phase
                and phase != "attachment_pending"):
            # GET-only attachment settling before binding/preparation. Retry
            # later without reclaiming a bootstrap contact or root command.
            wait(30.0)


def dispatch_fresh_keyed_initial(
    core_job_id: str, *, environment: str,
    rollout_enabled: bool = False,
    job_repository=None, plan_repository=None,
    continuation: Callable = start_fresh_digitalocean_initial_continuation,
    preflight: Callable = preflight_fresh_digitalocean_provider,
):
    """Start only an absent or inert queued parent; never replay a provider child."""
    from app.services.guarded_test_deployment import _require_configured_keyed_source
    from app.services.provider_keyed_initial_continuation import _db_lease_lookup

    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    core = jobs.get(core_job_id)
    inputs = core.input if core is not None and isinstance(core.input, dict) else {}
    engagement_id = inputs.get("engagementId")
    plan_id = inputs.get("corePlanId")
    if (environment != "devtest" or rollout_enabled is not True
            or core is None or core.status != "succeeded"
            or core.action != "pilot_standard_rti_guarded_execute"
            or inputs.get("sketchStateSchema") != "provider-keyed-v2"
            or inputs.get("providerKeyedDispatchAuthorized") is not True
            or not isinstance(engagement_id, str) or not engagement_id
            or not isinstance(plan_id, str) or not plan_id):
        raise ProviderKeyedInitialDispatchError("successful DevTest keyed core is required")
    terminal = core.events[-1] if core.events else None
    if (terminal is None or terminal.message != "pilot Standard RTI run finished"
            or terminal.data.get("ok") is not True
            or terminal.data.get("mutationStatus") != "deployed"
            or terminal.data.get("ansibleStatus") != "validated"
            or terminal.data.get("finalCleanupStatus") != "pending_operator_teardown"):
        raise ProviderKeyedInitialDispatchError("successful core result evidence differs")
    plan = plans.get(plan_id)
    if (plan is None or plan.engagement_id != engagement_id or plan.status != "applied"
            or plan.stage != "applied"
            or plan.apply_job_id != core.id
            or plan.evidence.get("sketchStateSchema") != "provider-keyed-v2"
            or _db_lease_lookup(engagement_id) != (plan_id, "provider_keyed_initial")):
        raise ProviderKeyedInitialDispatchError("reviewed core plan or lease differs")
    pin = inputs.get("providerKeyedSourcePin")
    try:
        retained_pin = _require_configured_keyed_source(pin)
    except Exception:
        raise ProviderKeyedInitialDispatchError("pinned keyed source requires reconciliation") from None
    if (not isinstance(pin, dict) or retained_pin != pin
            or not isinstance(pin.get("root"), str)):
        raise ProviderKeyedInitialDispatchError("pinned keyed source differs")
    state_root = _default_state_root()
    if not isinstance(state_root, Path) or os.path.lexists(state_root / engagement_id):
        raise ProviderKeyedInitialDispatchError("provider workspace requires reconciliation")
    parent_id, plan_child_id, apply_child_id = _job_ids(core.id)
    parent = jobs.get(parent_id)
    if (jobs.get(plan_child_id) is not None or jobs.get(apply_child_id) is not None
            or (parent is not None and (
                parent.action != "provider_keyed_initial" or parent.status != "queued"
                or parent.target != f"engagement:{engagement_id}"
                or parent.target_type != "engagement" or parent.target_id != engagement_id
                or parent.requested_by != core.requested_by
                or parent.started_at is not None or parent.finished_at is not None
                or parent.input != {
                    "engagementId": engagement_id, "coreJobId": core.id,
                    "corePlanId": plan_id, "planJobId": plan_child_id,
                    "applyJobId": apply_child_id, "phase": "queued", "mutation": True,
                }
                or len(parent.events) != 1
                or parent.events[0].sequence != 1 or parent.events[0].level != "info"
                or parent.events[0].message != "provider continuation job queued"
                or not isinstance(parent.events[0].data, dict)
                or set(parent.events[0].data) != {"creationToken"}
                or not isinstance(parent.events[0].data["creationToken"], str)
                or not parent.events[0].data["creationToken"]
                or parent.artifact_refs != []
            ))):
        raise ProviderKeyedInitialDispatchError("provider continuation already has execution evidence")
    # This read-only compiler rechecks complete current chains, active core,
    # reviewed provider authorization, lease, and the absence of state.
    preflight(
        engagement_id, core.id, lease_owner=plan_id, environment=environment,
        state_root=state_root, job_repository=jobs, plan_repository=plans,
    )
    if (jobs.get(core.id) != core or plans.get(plan_id) != plan
            or _db_lease_lookup(engagement_id) != (plan_id, "provider_keyed_initial")
            or os.path.lexists(state_root / engagement_id)):
        raise ProviderKeyedInitialDispatchError("provider dispatch authority changed")
    return continuation(
        core.id, environment=environment, state_root=state_root,
        template_root=Path(pin["root"]), job_repository=jobs,
    )


def recover_fresh_keyed_initial_dispatches(
    *, environment: str, rollout_enabled: bool = False,
    schedule: Callable[[Callable[[], None]], None],
) -> list[str]:
    """Schedule only exact applied v2 cores; each worker rechecks all authority."""
    if environment != "devtest" or rollout_enabled is not True:
        return []
    from app.storage.models import DeploymentPlanModel

    scheduled: list[str] = []
    jobs = SqlAlchemyJobRepository()
    for row in DeploymentPlanModel.query.filter_by(status="applied", stage="applied").all():
        evidence = row.evidence if isinstance(row.evidence, dict) else {}
        if (evidence.get("sketchStateSchema") != "provider-keyed-v2"
                or (isinstance(evidence.get("sketchAuthorization"), dict)
                    and evidence["sketchAuthorization"].get("kind") ==
                    "bounded-mixed-post-core-v1")
                or not isinstance(row.apply_job_id, str) or not row.apply_job_id):
            continue
        job_id = row.apply_job_id
        core = jobs.get(job_id)
        if (core is None or core.status != "succeeded"
                or not isinstance(core.input, dict)
                or core.input.get("providerKeyedDispatchAuthorized") is not True):
            continue
        schedule(lambda job_id=job_id: _recover_one(
            job_id, environment=environment, rollout_enabled=rollout_enabled,
        ))
        scheduled.append(job_id)
    return scheduled


def _recover_one(core_job_id: str, *, environment: str, rollout_enabled: bool) -> None:
    # The phase coordinator resumes only GET/binding and pre-contact bootstrap
    # phases. A one-shot command phase remains untouched on startup.
    parent_id, _, _ = _job_ids(core_job_id)
    parent = SqlAlchemyJobRepository().get(parent_id)
    parent_input = parent.input if parent is not None and isinstance(parent.input, dict) else {}
    malformed_queued = (parent is not None and parent.status == "queued"
                        and not isinstance(parent.input, dict))
    malformed_running = (parent is not None and parent.status == "running"
                         and (not isinstance(parent.input, dict) or parent_input.get("phase") is None))
    if (parent is not None and parent.status == "running"
            and parent_input.get("phase") == "awaiting_strict_host_proof"):
        _record_strict_host_attention(core_job_id, parent_id)
        return
    if (parent is not None and not _unclaimed_queued_parent(parent)
            and not malformed_running and not malformed_queued
            and (parent.status != "running" or parent_input.get("phase") not in _SAFE_PHASES)):
        return
    try:
        advance_fresh_keyed_initial_phases(
            core_job_id, environment=environment, rollout_enabled=rollout_enabled,
        )
    except Exception:
        # A concurrent worker may have claimed the inert parent between our
        # first read and the dispatcher CAS. That is progress, not attention.
        parent = SqlAlchemyJobRepository().get(parent_id)
        if parent is None or _unclaimed_queued_parent(parent):
            _record_dispatch_attention(core_job_id)
        elif (parent.finished_at is None and (
              (parent.status == "queued" and not isinstance(parent.input, dict))
              or (parent.status == "running" and (
                  not isinstance(parent.input, dict)
                  or parent.input.get("phase") in _SAFE_PHASES
                  or parent.input.get("phase") is None)))):
            # A malformed due time or changed authority can otherwise leave
            # this running parent with no worker. Compare the claim and phase
            # again inside the plan write, so a concurrent worker is not
            # mistaken for a stalled continuation.
            _record_dispatch_attention(core_job_id, stalled_parent_id=parent_id)


def _record_dispatch_attention(core_job_id: str, *, stalled_parent_id: str | None = None) -> None:
    from sqlalchemy import text
    from app.storage.database import db
    from app.storage.models import DeploymentPlanModel

    if stalled_parent_id is not None:
        if db.engine.dialect.name != "sqlite":
            return
        phases = sorted(_SAFE_PHASES)
        db.session.execute(text("""
            UPDATE deployment_plans
            SET stage = 'provider_keyed_initial_attention',
                error = 'provider continuation requires reconciliation'
            WHERE apply_job_id = :core_id AND status = 'applied'
              AND EXISTS (
                SELECT 1 FROM job_runs
                WHERE id = :parent_id AND action = 'provider_keyed_initial'
                  AND status IN ('queued', 'running') AND finished_at IS NULL
                  AND (json_extract(input, '$.coreJobId') = :core_id
                       OR json_type(input) != 'object'
                       OR json_extract(input, '$.phase') IS NULL)
                  AND ((status = 'running' AND (
                         json_extract(input, '$.phase') IN (:phase0, :phase1, :phase2, :phase3)
                         OR json_type(input) != 'object'
                         OR json_extract(input, '$.phase') IS NULL))
                       OR (status = 'queued' AND json_type(input) != 'object'))
                  AND (
                    json_extract(input, '$.claimToken') IS NULL
                    OR julianday(json_extract(input, '$.claimExpiresAt')) IS NULL
                    OR julianday(json_extract(input, '$.claimExpiresAt')) <= julianday('now')
                  )
              )
        """), {"core_id": core_job_id, "parent_id": stalled_parent_id,
               **{f"phase{index}": phase for index, phase in enumerate(phases)}})
        db.session.commit()
        return
    DeploymentPlanModel.query.filter_by(
        apply_job_id=core_job_id, status="applied",
    ).update({
        "stage": "provider_keyed_initial_attention",
        "error": "provider continuation requires reconciliation",
    }, synchronize_session=False)
    db.session.commit()


def _record_strict_host_attention(core_job_id: str, parent_id: str) -> None:
    """Expose an expired one-shot host phase on restart without replaying SSH."""
    from sqlalchemy import text
    from app.storage.database import db

    if db.engine.dialect.name != "sqlite":
        return
    db.session.execute(text("""
        UPDATE deployment_plans
        SET stage = 'provider_keyed_initial_attention',
            error = 'strict host proof requires reconciliation after restart'
        WHERE apply_job_id = :core_id AND status = 'applied'
          AND EXISTS (
            SELECT 1 FROM job_runs
            WHERE id = :parent_id AND action = 'provider_keyed_initial'
              AND status = 'running' AND finished_at IS NULL
              AND json_extract(input, '$.coreJobId') = :core_id
              AND json_extract(input, '$.phase') = 'awaiting_strict_host_proof'
              AND (julianday(json_extract(input, '$.claimExpiresAt')) IS NULL
                   OR julianday(json_extract(input, '$.claimExpiresAt')) <= julianday('now'))
          )
    """), {"core_id": core_job_id, "parent_id": parent_id})
    db.session.commit()
