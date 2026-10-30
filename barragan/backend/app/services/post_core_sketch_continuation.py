# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import hashlib
import json
import logging
import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from uuid import uuid4

from app.core.runtime import start_runtime_task
from app.domain import JobEvent
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.deployment_plan_repository import (
    DeploymentPlanConflictError,
    SqlAlchemyDeploymentPlanRepository,
)
from app.storage.sketch_chain_repository import (
    SketchChainRepository,
    SqlAlchemySketchChainRepository,
)


POST_CORE_SKETCH_CONTINUATION_ACTION = "post_core_sketch_continuation"
PILOT_CORE_ACTION = "pilot_standard_rti_guarded_execute"

SketchDispatcher = Callable[[str, str, dict[str, Any]], dict[str, Any] | None]
BackgroundRunner = Callable[[Callable[[], None]], None]

_continuation_owner = f"runtime-{uuid4().hex}"
CONTINUATION_LEASE_SECONDS = 120
CONTINUATION_RECOVERY_INTERVAL_SECONDS = 30
_recovery_monitor_lock = threading.Lock()
_recovery_monitor_started = False


def snapshot_pending_sketch_chain_ids(
    engagement_id: str,
    *,
    repository: SketchChainRepository | None = None,
) -> list[str]:
    """Return the stable initial-chain set owned by a core deployment run."""

    chains = (repository or SqlAlchemySketchChainRepository()).list_for_engagement(engagement_id)
    return [chain.chain_id for chain in chains if chain.status == "pending"]


def sketch_chain_intent_fingerprint(chain) -> str:
    """Hash only the provider-affecting intent of a stored sketch chain."""

    payload = {
        "assignedProxy": chain.assigned_proxy,
        "middleProvider": chain.middle_provider,
        "middleRegion": chain.middle_region,
        "middleSize": chain.middle_size,
        "edgeProvider": chain.edge_provider,
        "edgeRegion": chain.edge_region,
        "edgeSize": chain.edge_size,
        "edgeCount": chain.edge_count,
        "edges": list(chain.edge_intents or []),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def start_post_core_sketch_continuation(
    core_job_id: str,
    *,
    job_repository: JobRepository | None = None,
    sketch_repository: SketchChainRepository | None = None,
    dispatcher: SketchDispatcher | None = None,
    background_runner: BackgroundRunner | None = None,
    retry_failed: bool = False,
) -> StoredJobRun | None:
    """Create/reclaim the deterministic continuation for one successful core job."""

    jobs = job_repository or SqlAlchemyJobRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    core_job = jobs.get(core_job_id)
    if (
        core_job is None
        or core_job.action != PILOT_CORE_ACTION
        or core_job.status != "succeeded"
        or core_job.input.get("postCoreSketchContinuationEligible") is not True
    ):
        return None

    engagement_id = str(core_job.input.get("engagementId") or core_job.target_id or "").strip()
    chain_ids = [str(value) for value in core_job.input.get("pendingSketchChainIds", []) if str(value).strip()]
    expected_fingerprints = {
        str(key): str(value)
        for key, value in (core_job.input.get("pendingSketchChainFingerprints") or {}).items()
        if str(key).strip() and str(value).strip()
    }
    core_plan_id = str(core_job.input.get("corePlanId") or "").strip()
    parent_id = _parent_id(core_job_id)
    parent = jobs.get(parent_id)
    if parent is None:
        now = _now()
        parent = jobs.save_if_absent(
            StoredJobRun(
                    id=parent_id,
                    action=POST_CORE_SKETCH_CONTINUATION_ACTION,
                    status="queued",
                    target=f"engagement:{engagement_id}",
                    target_type="engagement",
                    target_id=engagement_id,
                    requested_by=core_job.requested_by,
                    input={
                        "engagementId": engagement_id,
                        "coreJobId": core_job_id,
                        "corePlanId": core_plan_id,
                        "chainIds": chain_ids,
                        "expectedChainFingerprints": expected_fingerprints,
                        "outcomes": {},
                        "mutation": True,
                    },
                    artifact_refs=[],
                    created_at=now,
                    started_at=None,
                    finished_at=None,
                    events=[
                        JobEvent(
                            1,
                            "info",
                            "post-core sketch continuation queued",
                            {"coreJobId": core_job_id, "chainIds": chain_ids},
                        )
                    ],
            )
        )

    eligible_statuses = {"queued", "running"} | ({"failed"} if retry_failed else set())
    if parent.status not in eligible_statuses:
        return parent
    if core_plan_id and chain_ids:
        try:
            SqlAlchemyDeploymentPlanRepository().acquire(engagement_id, core_plan_id, "post_core")
        except DeploymentPlanConflictError:
            return None
    claimed_at = _now()
    claim_token = uuid4().hex
    expires_at = (datetime.fromisoformat(claimed_at) + timedelta(seconds=CONTINUATION_LEASE_SECONDS)).isoformat()
    claimed = jobs.claim_lease(
        parent_id,
        owner=_continuation_owner,
        token=claim_token,
        claimed_at=claimed_at,
        expires_at=expires_at,
        eligible_statuses=eligible_statuses,
    )

    if claimed is not None:
        task = lambda: _run_post_core_sketch_continuation(
            parent_id,
            claim_owner=_continuation_owner,
            claim_token=claim_token,
            job_repository=jobs,
            sketch_repository=chains,
            dispatcher=dispatcher,
        )
        try:
            if background_runner is not None:
                background_runner(task)
            else:
                start_runtime_task(
                    task,
                    name=f"barragan-post-core-sketch-{core_job_id}",
                    synchronous_when_testing=True,
                )
        except Exception:
            raise
    return jobs.get(parent_id)


def recover_post_core_sketch_continuations(
    *,
    job_repository: JobRepository | None = None,
    sketch_repository: SketchChainRepository | None = None,
    dispatcher: SketchDispatcher | None = None,
    background_runner: BackgroundRunner | None = None,
) -> list[str]:
    """Reclaim successful core runs whose continuation was interrupted or never scheduled."""

    jobs = job_repository or SqlAlchemyJobRepository()
    recovered: list[str] = []
    for job in jobs.list():
        if job.action != PILOT_CORE_ACTION or job.status != "succeeded":
            continue
        if (
            "pendingSketchChainIds" not in job.input
            or job.input.get("postCoreSketchContinuationEligible") is not True
        ):
            # Pre-contract core jobs did not own a chain snapshot and must not
            # implicitly absorb whatever happens to be pending at restart.
            continue
        parent = start_post_core_sketch_continuation(
            job.id,
            job_repository=jobs,
            sketch_repository=sketch_repository,
            dispatcher=dispatcher,
            background_runner=background_runner,
        )
        if parent is not None:
            recovered.append(parent.id)
    return recovered


def start_post_core_sketch_recovery_monitor(
    *,
    background_runner: BackgroundRunner | None = None,
) -> None:
    global _recovery_monitor_started
    with _recovery_monitor_lock:
        if _recovery_monitor_started:
            return
        _recovery_monitor_started = True
    task = lambda: run_post_core_sketch_recovery_monitor()
    try:
        if background_runner is not None:
            background_runner(task)
            return
        start_runtime_task(task, name="barragan-post-core-sketch-recovery-monitor")
    except Exception:
        with _recovery_monitor_lock:
            _recovery_monitor_started = False
        raise


def run_post_core_sketch_recovery_monitor(
    *,
    job_repository: JobRepository | None = None,
    sketch_repository: SketchChainRepository | None = None,
    dispatcher: SketchDispatcher | None = None,
    background_runner: BackgroundRunner | None = None,
    wait: Callable[[float], bool] | None = None,
    interval_seconds: float = CONTINUATION_RECOVERY_INTERVAL_SECONDS,
    max_cycles: int | None = None,
) -> None:
    """Periodically reconsider leases that were still live during startup recovery."""

    stop_event = threading.Event()
    wait_for_next_cycle = wait or stop_event.wait
    cycles = 0
    while max_cycles is None or cycles < max_cycles:
        if wait_for_next_cycle(interval_seconds):
            return
        try:
            recover_post_core_sketch_continuations(
                job_repository=job_repository,
                sketch_repository=sketch_repository,
                dispatcher=dispatcher,
                background_runner=background_runner,
            )
        except Exception:
            logging.getLogger("barragan.background").exception("Post-core sketch recovery monitor cycle failed")
        cycles += 1


def _run_post_core_sketch_continuation(
    parent_id: str,
    *,
    claim_owner: str,
    claim_token: str,
    job_repository: JobRepository,
    sketch_repository: SketchChainRepository,
    dispatcher: SketchDispatcher | None,
) -> None:
    parent = job_repository.get(parent_id)
    if (
        parent is None
        or parent.status not in {"queued", "running", "failed"}
        or not _lease_is_owned(parent, claim_owner, claim_token)
    ):
        return
    dispatch = dispatcher or _default_dispatcher
    outcomes = dict(parent.input.get("outcomes") or {})
    parent = job_repository.save(
        replace(
            parent,
            status="running",
            started_at=parent.started_at or _now(),
            finished_at=None,
            input={**parent.input, "outcomes": outcomes},
            events=parent.events
            + [
                JobEvent(
                    len(parent.events) + 1,
                    "info",
                    "post-core sketch continuation started",
                    {"coreJobId": parent.input.get("coreJobId")},
                )
            ],
        )
    )

    for chain_id in [str(value) for value in parent.input.get("chainIds", [])]:
        renewed = _renew_lease(job_repository, parent.id, claim_owner, claim_token)
        if renewed is None:
            return
        parent = renewed
        prior = outcomes.get(chain_id) if isinstance(outcomes.get(chain_id), dict) else {}
        if prior.get("state") in {"dispatched", "already_started"}:
            continue
        chain = sketch_repository.get(parent.target_id, chain_id)
        if chain is None:
            outcomes[chain_id] = {"state": "failed", "error": "snapshotted chain no longer exists"}
            parent = _save_progress(job_repository, parent, outcomes, chain_id, "failed")
            continue
        expected_fingerprint = str(
            (parent.input.get("expectedChainFingerprints") or {}).get(chain_id) or ""
        )
        exact_core_plan = bool(
            str(parent.input.get("corePlanId") or "").strip()
            or parent.input.get("expectedChainFingerprints")
        )
        if exact_core_plan and (
            not expected_fingerprint or sketch_chain_intent_fingerprint(chain) != expected_fingerprint
        ):
            outcomes[chain_id] = {
                "state": "failed",
                "error": "snapshotted chain intent changed after core plan review",
            }
            parent = _save_progress(job_repository, parent, outcomes, chain_id, "failed")
            continue
        if chain.status in {"deploying", "deployed"} or chain.deploy_job_id:
            outcomes[chain_id] = {
                "state": "already_started",
                "chainStatus": chain.status,
                "jobId": chain.deploy_job_id,
            }
            parent = _save_progress(job_repository, parent, outcomes, chain_id, "already started")
            continue
        if chain.status != "pending" and chain.status != "failed":
            outcomes[chain_id] = {"state": "failed", "error": f"chain is {chain.status}"}
            parent = _save_progress(job_repository, parent, outcomes, chain_id, "failed")
            continue
        try:
            from app.services.engagement_teardown import assert_engagement_mutation_allowed

            assert_engagement_mutation_allowed(parent.target_id, repository=job_repository)
            response = dispatch(
                parent.target_id,
                chain_id,
                {"coreJobId": parent.input.get("coreJobId"), "requestedBy": parent.requested_by},
            )
            child = (response or {}).get("job") or {}
            job_id = str(child.get("id") or "")
            if not job_id:
                raise RuntimeError("sketch deployment did not return a child job")
            outcomes[chain_id] = {"state": "dispatched", "jobId": job_id}
            parent = _save_progress(job_repository, parent, outcomes, chain_id, "dispatched", job_id=job_id)
        except Exception as exc:
            outcomes[chain_id] = {"state": "failed", "error": _safe_error(exc)}
            parent = _save_progress(job_repository, parent, outcomes, chain_id, "failed")

    failed = [chain_id for chain_id, outcome in outcomes.items() if outcome.get("state") == "failed"]
    latest = job_repository.get(parent_id) or parent
    job_repository.save(
        replace(
            latest,
            status="failed" if failed else "succeeded",
            finished_at=_now(),
            input={**latest.input, "outcomes": outcomes, "claimExpiresAt": _now()},
            events=latest.events
            + [
                JobEvent(
                    len(latest.events) + 1,
                    "error" if failed else "info",
                    "post-core sketch continuation completed with failures" if failed else "post-core sketch continuation completed",
                    {"failedChainIds": failed, "outcomes": outcomes},
                )
            ],
        )
    )
    core_plan_id = str(parent.input.get("corePlanId") or "").strip()
    if core_plan_id:
        SqlAlchemyDeploymentPlanRepository().release(parent.target_id, core_plan_id)


def _save_progress(
    repository: JobRepository,
    parent: StoredJobRun,
    outcomes: dict[str, Any],
    chain_id: str,
    state: str,
    *,
    job_id: str = "",
) -> StoredJobRun:
    latest = repository.get(parent.id) or parent
    return repository.save(
        replace(
            latest,
            input={**latest.input, "outcomes": outcomes},
            events=latest.events
            + [
                JobEvent(
                    len(latest.events) + 1,
                    "error" if state == "failed" else "info",
                    f"post-core sketch chain {state}",
                    {"chainId": chain_id, **({"jobId": job_id} if job_id else {})},
                )
            ],
        )
    )


def _default_dispatcher(engagement_id: str, chain_id: str, body: dict[str, Any]) -> dict[str, Any] | None:
    # Deferred import avoids a sketch_chains -> continuation import cycle.
    from app.services.sketch_chains import deploy_sketch_chain

    return deploy_sketch_chain(engagement_id, chain_id, body, allow_core_plan_continuation=True)


def _parent_id(core_job_id: str) -> str:
    return f"job-post-core-sketch-{core_job_id.removeprefix('job-')}"


def _safe_error(exc: Exception) -> str:
    errors = getattr(exc, "errors", None)
    if isinstance(errors, list) and errors:
        return "; ".join(str(value) for value in errors)
    return type(exc).__name__


def _lease_is_owned(job: StoredJobRun, owner: str, token: str) -> bool:
    if job.input.get("claimOwner") != owner or job.input.get("claimToken") != token:
        return False
    try:
        expires_at = datetime.fromisoformat(str(job.input.get("claimExpiresAt") or ""))
    except ValueError:
        return False
    return expires_at > datetime.now(timezone.utc)


def _renew_lease(repository: JobRepository, job_id: str, owner: str, token: str) -> StoredJobRun | None:
    claimed_at = _now()
    expires_at = (datetime.fromisoformat(claimed_at) + timedelta(seconds=CONTINUATION_LEASE_SECONDS)).isoformat()
    return repository.claim_lease(
        job_id,
        owner=owner,
        token=token,
        claimed_at=claimed_at,
        expires_at=expires_at,
        eligible_statuses={"running"},
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
