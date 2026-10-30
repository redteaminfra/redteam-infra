# Copyright (c) 2026, Oracle and/or its affiliates.
"""One approved DevTest append Apply followed by strict new-edge proof."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from app.core.command_environment import barragan_subprocess_env
from app.services.provider_keyed_append_apply_job import (
    reconcile_interrupted_digitalocean_edge_append_apply,
    run_reviewed_digitalocean_edge_append_apply,
)
from app.services.provider_keyed_append_host_proof_job import (
    publish_reviewed_digitalocean_edge_append_host_proof,
)
from app.services.provider_keyed_append_plan_job import (
    reconcile_reviewed_digitalocean_edge_append_plan,
)
from app.services.redteam_infra_template import TEMPLATE_ROOT_ENV
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest


class ProviderKeyedAppendDispatchError(ValueError):
    pass


def approve_reviewed_digitalocean_edge_append(
    parent_id: str, *, expected_plan_sha256: str, requested_by: str,
    environment: str = "devtest", state_root: Path | None = None,
    job_repository=None,
):
    """Persist the single operator Apply click before scheduling any command."""
    jobs = job_repository or SqlAlchemyJobRepository()
    parent = jobs.get(parent_id)
    if (environment != "devtest" or parent is None or parent.status != "running"
            or parent.action != "provider_keyed_edge_append"
            or parent.input.get("phase") != "awaiting_apply"
            or parent.input.get("applyRequestedPlanSha256") is not None
            or not isinstance(expected_plan_sha256, str)
            or len(expected_plan_sha256) != 64
            or not isinstance(requested_by, str) or not requested_by):
        raise ProviderKeyedAppendDispatchError("reviewed append Apply is unavailable")
    try:
        if reconcile_reviewed_digitalocean_edge_append_plan(
                parent_id, environment=environment,
                state_root=state_root or _default_state_root(),
                job_repository=jobs) != parent:
            raise ValueError("review changed")
        plan = jobs.get(parent.input["planJobId"])
        if (plan is None or not plan.events
                or parent.input.get("planJournalSha256") != job_event_digest(plan.events)
                or plan.events[-1].data.get("planSha256") != expected_plan_sha256):
            raise ValueError("plan changed")
        approved = jobs.approve_provider_keyed_edge_append_apply(
            parent, plan, plan_sha256=expected_plan_sha256,
            requested_by=requested_by,
            requested_at=datetime.now(timezone.utc).isoformat(),
        )
        if approved is None:
            raise ValueError("review changed")
        return approved
    except Exception:
        raise ProviderKeyedAppendDispatchError("reviewed append Apply changed") from None


def _approved_parent(parent, jobs) -> bool:
    if (parent is None or parent.action != "provider_keyed_edge_append"
            or parent.status != "running" or not isinstance(parent.input, dict)):
        return False
    receipt = parent.input.get("applyRequestedPlanSha256")
    actor = parent.input.get("applyRequestedBy")
    at = parent.input.get("applyRequestedAt")
    plan = jobs.get(parent.input.get("planJobId"))
    requests = [event for event in parent.events
                if event.message == "provider append Apply requested"]
    return bool(
        isinstance(receipt, str) and len(receipt) == 64
        and isinstance(actor, str) and actor
        and isinstance(at, str) and at
        and plan is not None and plan.status == "succeeded" and plan.events
        and plan.events[-1].message == "reviewed append plan saved"
        and plan.events[-1].data.get("planSha256") == receipt
        and parent.input.get("planJournalSha256") == job_event_digest(plan.events)
        and len(requests) == 1 and requests[0].data == {
            "planJobId": plan.id, "planSha256": receipt,
            "requestedBy": actor, "requestedAt": at,
        }
    )


def advance_approved_digitalocean_edge_append(
    parent_id: str, *, environment: str = "devtest", rollout_enabled: bool = False,
    state_root: Path | None = None, job_repository=None,
    apply: Callable = run_reviewed_digitalocean_edge_append_apply,
    reconcile_apply: Callable = reconcile_interrupted_digitalocean_edge_append_apply,
    prove: Callable = publish_reviewed_digitalocean_edge_append_host_proof,
    wait: Callable[[float], None] = time.sleep,
):
    """Resume only the approved parent; never rerun an uncertain child."""
    if environment != "devtest" or rollout_enabled is not True:
        return None
    from app.services.guarded_test_deployment import _require_configured_keyed_source

    jobs = job_repository or SqlAlchemyJobRepository()
    root = state_root or _default_state_root()
    while True:
        parent = jobs.get(parent_id)
        if not _approved_parent(parent, jobs):
            return parent
        phase = parent.input.get("phase")
        if phase not in {"awaiting_apply", "apply_reserved", "awaiting_host_proof",
                         "host_proof_reserved", "awaiting_publication"}:
            return parent
        core = jobs.get(parent.input.get("coreJobId"))
        pin = core.input.get("providerKeyedSourcePin") if core is not None else None
        if (core is None or core.status != "succeeded"
                or core.input.get("engagementId") != parent.target_id
                or _require_configured_keyed_source(pin) != pin):
            raise ProviderKeyedAppendDispatchError("pinned append source differs")
        expiry = parent.input.get("claimExpiresAt")
        if isinstance(expiry, str):
            try:
                delay = (datetime.fromisoformat(expiry) -
                         datetime.now(timezone.utc)).total_seconds()
            except ValueError:
                raise ProviderKeyedAppendDispatchError("append claim time differs") from None
            if delay > 0:
                wait(min(delay, 300.0))
                continue
        if phase == "awaiting_apply":
            parent = apply(parent_id, environment=environment, state_root=root,
                           job_repository=jobs)
        elif phase == "apply_reserved":
            parent = reconcile_apply(parent_id, environment=environment, state_root=root,
                                     job_repository=jobs)
        else:
            env = barragan_subprocess_env()
            env[TEMPLATE_ROOT_ENV] = pin["root"]
            parent = prove(parent_id, environment=environment, state_root=root,
                           bootstrap_env=env, job_repository=jobs)
        if parent is None or parent.id != parent_id:
            raise ProviderKeyedAppendDispatchError("append phase handoff differs")
        if parent.status != "running":
            return parent


def recover_approved_digitalocean_edge_appends(
    *, environment: str, rollout_enabled: bool,
    schedule: Callable[[Callable[[], None]], None], job_repository=None,
) -> list[str]:
    """Startup resumes only parents bearing a persisted operator click."""
    if environment != "devtest" or rollout_enabled is not True:
        return []
    jobs = job_repository or SqlAlchemyJobRepository()
    selected = []
    for parent in jobs.list():
        if parent.action != "provider_keyed_edge_append" or parent.status != "running":
            continue
        if _approved_parent(parent, jobs):
            schedule(lambda parent_id=parent.id: advance_approved_digitalocean_edge_append(
                parent_id, environment=environment, rollout_enabled=True))
            selected.append(parent.id)
    return selected
