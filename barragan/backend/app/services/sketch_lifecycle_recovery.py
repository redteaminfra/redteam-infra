# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Callable

from app.core.runtime import start_runtime_task
from app.domain import JobEvent
from app.services.sketch_chains import (
    OUTBOUND_AUTO_CONFIGURATION_ACTION,
    _bootstrap_can_run,
    _start_outbound_auto_configuration,
    refresh_sketch_chain_from_job,
    resume_pending_sketch_bootstrap,
)
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository
from app.storage.sketch_chain_repository import (
    SketchChainRepository,
    SqlAlchemySketchChainRepository,
    StoredSketchChain,
)


STALE_CHAIN_STATUSES = {"deploying", "tearing_down", "starting", "stopping"}
STARTUP_CHAIN_STATUSES = STALE_CHAIN_STATUSES | {"deployed"}
STALE_AFTER = timedelta(minutes=20)
RECOVERY_INTERVAL_SECONDS = 15 * 60
MAX_RECOVERY_ROWS = 100
_monitor_lock = threading.Lock()
_monitor_started = False


def recover_sketch_lifecycle(
    *,
    startup: bool = False,
    now: datetime | None = None,
    job_repository: JobRepository | None = None,
    sketch_repository: SketchChainRepository | None = None,
) -> list[dict[str, str]]:
    """Reconcile exact recorded jobs; never restart a provider mutation."""

    jobs = job_repository or SqlAlchemyJobRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    current_time = now or datetime.now(timezone.utc)
    candidates = _recovery_candidates(chains, startup=startup, now=current_time)
    outcomes: list[dict[str, str]] = []
    for chain in candidates:
        job_id = chain.teardown_job_id or chain.deploy_job_id
        job = jobs.get(job_id) if job_id else None
        if job is None:
            outcomes.append(_outcome(chain, job_id, "missing_job"))
            continue
        if job.status in {"succeeded", "failed"}:
            resumed_bootstrap = False
            if not chain.teardown_job_id and job.status == "succeeded":
                resumed_bootstrap = resume_pending_sketch_bootstrap(
                    chain.engagement_id,
                    chain.chain_id,
                    repository=chains,
                    job_repository=jobs,
                    requested_by=job.requested_by,
                )
            refresh_sketch_chain_from_job(
                chain.engagement_id,
                chain.chain_id,
                repository=chains,
                job_repository=jobs,
                start_outbound_continuation=not bool(chain.teardown_job_id),
                requested_by=job.requested_by,
            )
            outcomes.append(_outcome(chain, job.id, "bootstrap_resumed" if resumed_bootstrap else "reconciled"))
            continue
        # A controller restart can interrupt the in-memory handoff after
        # Terraform has persisted its output but before the bootstrap result
        # is committed.  The job is then durably `running` with an explicit
        # bootstrap-start event.  Startup recovery is the safe boundary to
        # resume that idempotent bootstrap only; it never calls Terraform.
        if startup and not chain.teardown_job_id and _bootstrap_can_run(job):
            resumed_bootstrap = resume_pending_sketch_bootstrap(
                chain.engagement_id,
                chain.chain_id,
                repository=chains,
                job_repository=jobs,
                requested_by=job.requested_by,
            )
            outcomes.append(_outcome(chain, job.id, "bootstrap_resumed" if resumed_bootstrap else "nonterminal"))
            continue
        if not startup and job.status in {"queued", "running"}:
            _record_stale_attention(jobs, job.id)
            outcomes.append(_outcome(chain, job.id, "stale_attention"))
        else:
            outcomes.append(_outcome(chain, job.id, "nonterminal"))
    outcomes.extend(_recover_stale_outbound_parents(jobs, current_time))
    return outcomes


def start_sketch_lifecycle_recovery_monitor(
    *,
    background_runner: Callable[[Callable[[], None]], None] | None = None,
) -> None:
    global _monitor_started
    with _monitor_lock:
        if _monitor_started:
            return
        _monitor_started = True
    task = lambda: run_sketch_lifecycle_recovery_monitor()
    try:
        if background_runner is not None:
            background_runner(task)
        else:
            start_runtime_task(task, name="barragan-sketch-lifecycle-recovery-monitor")
    except Exception:
        with _monitor_lock:
            _monitor_started = False
        raise


def run_sketch_lifecycle_recovery_monitor(
    *,
    job_repository: JobRepository | None = None,
    sketch_repository: SketchChainRepository | None = None,
    wait: Callable[[float], bool] | None = None,
    interval_seconds: float = RECOVERY_INTERVAL_SECONDS,
    max_cycles: int | None = None,
) -> None:
    stop_event = threading.Event()
    wait_for_next_cycle = wait or stop_event.wait
    cycles = 0
    while max_cycles is None or cycles < max_cycles:
        if wait_for_next_cycle(interval_seconds):
            return
        try:
            recover_sketch_lifecycle(
                job_repository=job_repository,
                sketch_repository=sketch_repository,
            )
        except Exception:
            logging.getLogger("barragan.background").exception(
                "Sketch lifecycle recovery monitor cycle failed"
            )
        cycles += 1


def _recovery_candidates(
    repository: SketchChainRepository,
    *,
    startup: bool,
    now: datetime,
) -> list[StoredSketchChain]:
    selector = getattr(repository, "list_for_recovery", None)
    if not callable(selector):
        raise TypeError("sketch repository must implement list_for_recovery")
    if startup:
        return selector(statuses=STARTUP_CHAIN_STATUSES)
    return selector(statuses=STALE_CHAIN_STATUSES, updated_before=now - STALE_AFTER)


def _recover_stale_outbound_parents(
    repository: JobRepository,
    now: datetime,
) -> list[dict[str, str]]:
    selector = getattr(repository, "list_by_actions_and_statuses", None)
    if not callable(selector):
        return []
    outcomes: list[dict[str, str]] = []
    parents = selector(
        actions={OUTBOUND_AUTO_CONFIGURATION_ACTION},
        statuses={"queued", "running"},
        limit=MAX_RECOVERY_ROWS,
        stale_before=(now - STALE_AFTER).isoformat(),
        lease_expired_before=now.isoformat(),
    )
    for parent in parents:
        if not _outbound_parent_is_stale(parent, now):
            continue
        engagement_id = str(parent.input.get("engagementId") or parent.target_id or "").strip()
        chain_id = str(parent.input.get("chainId") or "").strip()
        deploy_job_id = str(parent.input.get("deployJobId") or "").strip()
        if not engagement_id or not chain_id or not deploy_job_id:
            continue
        resumed = _start_outbound_auto_configuration(
            engagement_id,
            chain_id,
            deploy_job_id=deploy_job_id,
            requested_by=parent.requested_by,
            repository=repository,
        )
        outcomes.append(
            {
                "engagementId": engagement_id,
                "chainId": chain_id,
                "jobId": parent.id,
                "state": "configuration_recovered" if resumed is not None else "configuration_unclaimed",
            }
        )
    return outcomes


def _outbound_parent_is_stale(parent, now: datetime) -> bool:
    expiry = str(parent.input.get("claimExpiresAt") or "").strip()
    if expiry:
        try:
            return datetime.fromisoformat(expiry) <= now
        except ValueError:
            return True
    heartbeat = str(parent.input.get("claimHeartbeatAt") or parent.started_at or parent.created_at or "").strip()
    try:
        return datetime.fromisoformat(heartbeat) <= now - STALE_AFTER
    except ValueError:
        return True


def _record_stale_attention(repository: JobRepository, job_id: str) -> None:
    job = repository.get(job_id)
    if job is None or job.input.get("lifecycleRecoveryAttention") == "stale_nonterminal":
        return
    repository.mark_stale_nonterminal_attention(
        job.id,
        expected_status=job.status,
        event=JobEvent(
            0,
            "warning",
            "lifecycle recovery found a stale nonterminal provider job; operator review required",
            {"recoveryState": "stale_nonterminal", "automaticRetry": False},
        ),
    )


def _outcome(chain: StoredSketchChain, job_id: str, state: str) -> dict[str, str]:
    return {
        "engagementId": chain.engagement_id,
        "chainId": chain.chain_id,
        "jobId": job_id,
        "state": state,
    }
