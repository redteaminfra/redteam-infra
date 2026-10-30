# Copyright (c) 2026, Oracle and/or its affiliates.
"""Internal, durable single-worker claim for one published mixed teardown.

POST and startup recovery share this one atomic claim. The infrastructure
children still retain their own exact one-shot fences and journals.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from threading import Event, Thread
from typing import Callable
from uuid import uuid4

from app.domain import JobEvent
from app.core.runtime import current_runtime, runtime_context
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    ACTION as PARENT_ACTION, saved_published_mixed_initial_review,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun


ACTION = "provider_keyed_mixed_published_dispatch_claim"
_CLAIM_KEYS = {"claimOwner", "claimToken", "claimClaimedAt",
               "claimHeartbeatAt", "claimExpiresAt"}
_LEASE_SECONDS = 120


@dataclass(frozen=True)
class DispatchClaim:
    parent_id: str
    marker_id: str
    owner: str
    token: str


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _marker_id(parent_id: str) -> str:
    return f"job-provider-keyed-mixed-published-dispatch-{parent_id.removeprefix('job-')}"


def _base(parent: StoredJobRun) -> dict:
    return {
        "engagementId": parent.target_id,
        "parentId": parent.id,
        "coreJobId": parent.input["coreJobId"],
        "corePlanId": parent.input["corePlanId"],
        "publishedSourceSha256": parent.input["publishedSourceSha256"],
        "mutation": False,
    }


def _marker(parent: StoredJobRun) -> StoredJobRun:
    stamp = _now().isoformat()
    return StoredJobRun(
        _marker_id(parent.id), ACTION, "queued",
        f"engagement:{parent.target_id}", "engagement", parent.target_id,
        parent.requested_by, _base(parent), [], stamp, None, None,
        [JobEvent(1, "info", "published mixed dispatch queued", {})],
    )


def _valid_marker(saved: StoredJobRun, parent: StoredJobRun) -> bool:
    return (saved.id == _marker_id(parent.id) and saved.action == ACTION
            and saved.status in {"queued", "running", "succeeded"}
            and saved.target == f"engagement:{parent.target_id}"
            and saved.target_type == "engagement"
            and saved.target_id == parent.target_id
            and saved.requested_by == parent.requested_by
            and {key: value for key, value in saved.input.items()
                 if key not in _CLAIM_KEYS} == _base(parent)
            and saved.artifact_refs == []
            and saved.events[:1] == [
                JobEvent(1, "info", "published mixed dispatch queued", {})]
            and (len(saved.events) == 1 if saved.status == "queued"
                 else len(saved.events) in {2, 3}))


def claim_published_mixed_dispatch(
    parent_id: str, *, job_repository=None, lease_lookup=None,
) -> DispatchClaim | None:
    """Return the sole schedule permission, or None when another owns it."""
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    parent = jobs.get(parent_id)
    if parent is None or parent.action != PARENT_ACTION or parent.status != "queued":
        return None
    review = saved_published_mixed_initial_review(parent)
    if (review.source.engagement_id != parent.target_id
            or lookup(parent.target_id) != (
                parent.input["corePlanId"], "provider_keyed_teardown_fence")):
        return None
    saved = jobs.save_if_absent(_marker(parent))
    if not _valid_marker(saved, parent) or saved.status == "succeeded":
        return None
    if saved.status == "queued":
        started = jobs.start_if_queued(
            saved, started_at=_now().isoformat(),
            event=JobEvent(2, "info", "published mixed dispatch started", {}))
        saved = started or jobs.get(saved.id)
    if (not _valid_marker(saved, parent) or saved.status != "running"
            or saved.events != [
                JobEvent(1, "info", "published mixed dispatch queued", {}),
                JobEvent(2, "info", "published mixed dispatch started", {})]):
        return None
    owner, token = f"mixed-published-dispatch-{uuid4().hex}", uuid4().hex
    at = _now()
    claimed = jobs.claim_lease(
        saved.id, owner=owner, token=token, claimed_at=at.isoformat(),
        expires_at=(at + timedelta(seconds=_LEASE_SECONDS)).isoformat(),
        eligible_statuses={"running"})
    if (claimed is None or not _valid_marker(claimed, parent)
            or claimed.input.get("claimOwner") != owner
            or claimed.input.get("claimToken") != token):
        return None
    if (jobs.get(parent.id) != parent or lookup(parent.target_id) != (
            parent.input["corePlanId"], "provider_keyed_teardown_fence")):
        release_published_mixed_dispatch(
            DispatchClaim(parent.id, saved.id, owner, token), job_repository=jobs)
        return None
    return DispatchClaim(parent.id, saved.id, owner, token)


def dispatch_claim_current(claim: DispatchClaim, *, job_repository=None) -> bool:
    jobs = job_repository or SqlAlchemyJobRepository()
    from app.storage.database import db
    db.session.expire_all()
    saved = jobs.get(claim.marker_id)
    if (saved is None or saved.status != "running"
            or saved.input.get("claimOwner") != claim.owner
            or saved.input.get("claimToken") != claim.token):
        return False
    try:
        return datetime.fromisoformat(saved.input["claimExpiresAt"]) > _now()
    except (KeyError, TypeError, ValueError):
        return False


def release_published_mixed_dispatch(
    claim: DispatchClaim, *, job_repository=None, completed: bool = False,
) -> None:
    jobs = job_repository or SqlAlchemyJobRepository()
    from app.storage.database import db
    db.session.expire_all()
    saved = jobs.get(claim.marker_id)
    if (saved is None or saved.status != "running"
            or saved.input.get("claimOwner") != claim.owner
            or saved.input.get("claimToken") != claim.token):
        return
    if completed:
        finished = replace(
            saved, status="succeeded", finished_at=_now().isoformat(),
            input={key: value for key, value in saved.input.items()
                   if key not in _CLAIM_KEYS},
            events=[*saved.events, JobEvent(
                3, "info", "published mixed dispatch completed", {})],
        )
        jobs.save_if_leased(finished, owner=claim.owner, token=claim.token)
    else:
        # Expire only this owner's claim. A restart can acquire it after an
        # exact child-level review; no provider command is replayed here.
        at = _now().isoformat()
        jobs.renew_lease(saved.id, owner=claim.owner, token=claim.token,
                         heartbeat_at=at, expires_at=at)


def run_claimed_published_mixed_dispatch(
    claim: DispatchClaim, *, environment: str, positive_control_ipv4: str,
    coordinator: Callable, job_repository=None, lease_lookup=None,
    heartbeat_seconds: int = 30,
) -> StoredJobRun:
    """Renew the internal claim while the private coordinator advances."""
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    runtime = current_runtime()
    stop, lost = Event(), Event()

    def beat() -> None:
        with runtime_context(runtime):
            pulse_jobs = SqlAlchemyJobRepository()
            while not stop.wait(heartbeat_seconds):
                at = _now()
                try:
                    renewed = pulse_jobs.renew_lease(
                        claim.marker_id, owner=claim.owner, token=claim.token,
                        heartbeat_at=at.isoformat(),
                        expires_at=(at + timedelta(seconds=_LEASE_SECONDS)).isoformat())
                except Exception:
                    # Lose authority before best-effort cleanup can fail.
                    lost.set()
                    from app.storage.database import db
                    try:
                        db.session.rollback()
                    except Exception:
                        pass
                    return
                if renewed is None:
                    lost.set()
                    return

    worker = Thread(target=beat, name="barragan-mixed-published-dispatch-heartbeat",
                    daemon=True)
    worker.start()
    completed = False
    try:
        def fence() -> None:
            if lost.is_set() or not dispatch_claim_current(
                    claim, job_repository=jobs):
                raise ValueError("published mixed dispatch claim changed")
        fence()
        result = coordinator(
            claim.parent_id, environment=environment,
            positive_control_ipv4=positive_control_ipv4,
            job_repository=jobs, lease_lookup=lookup,
            dispatch_fence=fence)
        completed = (result.id == claim.parent_id
                     and result.status == "succeeded"
                     and jobs.get(claim.parent_id) == result)
        return result
    finally:
        stop.set()
        worker.join(timeout=2)
        release_published_mixed_dispatch(
            claim, job_repository=jobs, completed=completed)


def schedule_published_mixed_dispatch(
    parent_id: str, *, environment: str, positive_control_ipv4: str,
    name: str, coordinator: Callable,
    start_task: Callable, job_repository=None, lease_lookup=None,
) -> bool:
    """Schedule exactly one worker across POST and startup recovery."""
    if environment != "devtest":
        return False
    claim = claim_published_mixed_dispatch(
        parent_id, job_repository=job_repository, lease_lookup=lease_lookup)
    if claim is None:
        return False
    try:
        start_task(
            lambda: run_claimed_published_mixed_dispatch(
                claim, environment=environment,
                positive_control_ipv4=positive_control_ipv4,
                coordinator=coordinator),
            name=name)
    except Exception:
        release_published_mixed_dispatch(claim, job_repository=job_repository)
        raise
    return True
