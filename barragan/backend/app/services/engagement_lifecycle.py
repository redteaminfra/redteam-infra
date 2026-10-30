# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.storage.engagement_lifecycle_repository import (
    EngagementLifecycleRepository,
    SqlAlchemyEngagementLifecycleRepository,
    StoredEngagementLifecycle,
    StoredEngagementLifecycleEvent,
)
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.provider_resource_repository import (
    ProviderResourceRepository,
    SqlAlchemyProviderResourceRepository,
    TERMINAL_RECORD_STATUSES,
    is_barragan_owned_record,
)
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository, SketchChainRepository


PILOT_JOB_ACTION = "pilot_standard_rti_guarded_execute"
ENGAGEMENT_TEARDOWN_ACTION = "engagement_comprehensive_teardown"
MIXED_ZERO_APPLY_TEARDOWN_ACTION = "provider_keyed_mixed_zero_apply_cleanup"
MIXED_INTERRUPTED_TEARDOWN_ACTION = "provider_keyed_mixed_interrupted_cleanup"
MIXED_PUBLISHED_TEARDOWN_ACTION = "provider_keyed_mixed_published_cleanup"
RUNNING_STATES = {"queued", "running"}
LIVE_SKETCH_STATES = {"deployed", "deploying", "starting", "stopping", "stopped", "tearing_down"}
FAILED_SKETCH_STATES = {"failed", "cleanup_required"}
LIFECYCLE_LABELS = {
    "not_deployed": "Not deployed",
    "deploying": "Deploying",
    "active": "Active",
    "tearing_down": "Tearing down",
    "cleanup_required": "Cleanup required",
    "destroyed": "Destroyed",
    "unknown": "Unknown",
}
ATTENTION_STATES = {"cleanup_required", "unknown"}
ARCHIVABLE_STATES = {"not_deployed", "destroyed"}


class UnsafeLifecycleTransitionError(ValueError):
    def __init__(self, engagement_id: str, action: str, lifecycle: dict[str, Any]):
        super().__init__(
            f"Engagement cannot be {action} while operational lifecycle is "
            f"{lifecycle['state']}. Reconcile or complete cleanup first."
        )
        self.engagement_id = engagement_id
        self.action = action
        self.lifecycle = lifecycle


@dataclass(frozen=True)
class LifecycleResolution:
    state: str
    evidence: list[dict[str, Any]]


def get_engagement_lifecycle(
    engagement_id: str,
    *,
    administrative_status: str = "",
    lifecycle_repository: EngagementLifecycleRepository | None = None,
    job_repository: JobRepository | None = None,
    provider_resource_repository: ProviderResourceRepository | None = None,
    sketch_chain_repository: SketchChainRepository | None = None,
    persist: bool = False,
    reason: str = "local_evidence_projection",
    use_runtime_repositories: bool = True,
) -> dict[str, Any]:
    repository = lifecycle_repository or SqlAlchemyEngagementLifecycleRepository()
    previous = repository.get(engagement_id)
    resolution = resolve_engagement_lifecycle(
        engagement_id,
        previous_state=previous.state if previous else None,
        job_repository=job_repository,
        provider_resource_repository=provider_resource_repository,
        sketch_chain_repository=sketch_chain_repository,
        use_runtime_repositories=use_runtime_repositories,
    )
    fingerprint = _fingerprint(resolution.evidence)
    now = _now() if persist else previous.reconciled_at if previous else ""
    current = StoredEngagementLifecycle(
        engagement_id=engagement_id,
        state=resolution.state,
        evidence_fingerprint=fingerprint,
        evidence=resolution.evidence,
        reconciled_at=now,
    )
    if persist:
        changed = previous is None or previous.state != current.state or previous.evidence_fingerprint != fingerprint
        if changed:
            current, _event = repository.save_transition(
                current,
                StoredEngagementLifecycleEvent(
                    id=None,
                    engagement_id=engagement_id,
                    previous_state=previous.state if previous else "not_deployed",
                    state=current.state,
                    evidence_fingerprint=fingerprint,
                    evidence=resolution.evidence,
                    reason=reason,
                    created_at=now,
                )
            )
        elif previous is not None:
            current = previous
    elif previous is not None and previous.state == resolution.state and previous.evidence_fingerprint == fingerprint:
        current = previous
    return _projection_dict(current, administrative_status)


def reconcile_engagement_lifecycle(
    engagement_id: str,
    *,
    administrative_status: str = "",
    lifecycle_repository: EngagementLifecycleRepository | None = None,
    job_repository: JobRepository | None = None,
    provider_resource_repository: ProviderResourceRepository | None = None,
    sketch_chain_repository: SketchChainRepository | None = None,
    reason: str = "operator_local_evidence_reconciliation",
    use_runtime_repositories: bool = True,
) -> dict[str, Any]:
    repository = lifecycle_repository or SqlAlchemyEngagementLifecycleRepository()
    previous = repository.get(engagement_id)
    previous_dict = _projection_dict(previous, administrative_status) if previous else None
    current = get_engagement_lifecycle(
        engagement_id,
        administrative_status=administrative_status,
        lifecycle_repository=repository,
        job_repository=job_repository,
        provider_resource_repository=provider_resource_repository,
        sketch_chain_repository=sketch_chain_repository,
        persist=True,
        reason=reason,
        use_runtime_repositories=use_runtime_repositories,
    )
    return {
        "previous": previous_dict,
        "current": current,
        "changed": previous_dict is None
        or previous_dict["state"] != current["state"]
        or previous_dict["evidenceFingerprint"] != current["evidenceFingerprint"],
    }


def assert_administrative_transition_allowed(
    engagement_id: str,
    action: str,
    *,
    administrative_status: str = "",
    lifecycle_repository: EngagementLifecycleRepository | None = None,
    job_repository: JobRepository | None = None,
    provider_resource_repository: ProviderResourceRepository | None = None,
    sketch_chain_repository: SketchChainRepository | None = None,
    use_runtime_repositories: bool = True,
) -> dict[str, Any]:
    if not use_runtime_repositories and lifecycle_repository is None:
        resolution = resolve_engagement_lifecycle(
            engagement_id,
            job_repository=job_repository,
            provider_resource_repository=provider_resource_repository,
            sketch_chain_repository=sketch_chain_repository,
            use_runtime_repositories=False,
        )
        transient = StoredEngagementLifecycle(
            engagement_id=engagement_id,
            state=resolution.state,
            evidence_fingerprint=_fingerprint(resolution.evidence),
            evidence=resolution.evidence,
            reconciled_at=_now(),
        )
        lifecycle = _projection_dict(transient, administrative_status)
    else:
        lifecycle = get_engagement_lifecycle(
            engagement_id,
            administrative_status=administrative_status,
            lifecycle_repository=lifecycle_repository,
            job_repository=job_repository,
            provider_resource_repository=provider_resource_repository,
            sketch_chain_repository=sketch_chain_repository,
            persist=True,
            reason=f"{action}_gate",
            use_runtime_repositories=use_runtime_repositories,
        )
    if lifecycle["state"] not in ARCHIVABLE_STATES:
        raise UnsafeLifecycleTransitionError(engagement_id, action, lifecycle)
    return lifecycle


def resolve_engagement_lifecycle(
    engagement_id: str,
    *,
    previous_state: str | None = None,
    job_repository: JobRepository | None = None,
    provider_resource_repository: ProviderResourceRepository | None = None,
    sketch_chain_repository: SketchChainRepository | None = None,
    use_runtime_repositories: bool = True,
) -> LifecycleResolution:
    jobs = (job_repository or SqlAlchemyJobRepository()).list_for_engagement(engagement_id)
    core_jobs = [job for job in jobs if job.action == PILOT_JOB_ACTION]
    teardown_jobs = [job for job in jobs if job.action in {
        ENGAGEMENT_TEARDOWN_ACTION, MIXED_ZERO_APPLY_TEARDOWN_ACTION,
        MIXED_INTERRUPTED_TEARDOWN_ACTION, MIXED_PUBLISHED_TEARDOWN_ACTION}]
    provider_records = (
        provider_resource_repository.list_for_engagement(engagement_id)
        if provider_resource_repository is not None
        else SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id)
        if use_runtime_repositories
        else []
    )
    sketch_chains = (
        sketch_chain_repository.list_for_engagement(engagement_id)
        if sketch_chain_repository is not None
        else SqlAlchemySketchChainRepository().list_for_engagement(engagement_id)
        if use_runtime_repositories
        else []
    )

    active_records = [
        record
        for record in provider_records
        if record.status.lower() not in TERMINAL_RECORD_STATUSES
        and is_barragan_owned_record(record)
    ]
    live_sketches = [chain for chain in sketch_chains if chain.status.lower() in LIVE_SKETCH_STATES]
    failed_sketches = [chain for chain in sketch_chains if chain.status.lower() in FAILED_SKETCH_STATES]
    evidence = _evidence(core_jobs + teardown_jobs, provider_records, sketch_chains)

    running_teardown = next(
        (
            job
            for job in teardown_jobs
            if job.status in RUNNING_STATES
            and not (
                job.input.get("phase") == "lifecycle_reconciliation"
                and _latest_event_value(job, "finalCleanupStatus") == "verified_clean"
            )
        ),
        None,
    )
    if running_teardown is not None:
        return LifecycleResolution("tearing_down", evidence)

    conclusive_teardown = teardown_jobs[0] if teardown_jobs else None
    # A completed teardown is historical once a strictly later core generation
    # begins. Keep its evidence, but resolve the new deployment from its own
    # jobs; an unfinished teardown always retains precedence above.
    if (conclusive_teardown is not None and conclusive_teardown.status == "succeeded"
            and conclusive_teardown.finished_at is not None):
        newer_core = [job for job in core_jobs
                      if _job_after(job.created_at, conclusive_teardown.finished_at)]
        if any(job.status in RUNNING_STATES or _job_has_lifecycle_mutation(job)
               for job in newer_core):
            core_jobs = newer_core
            conclusive_teardown = None
    if conclusive_teardown is not None:
        cleanup = _latest_event_value(conclusive_teardown, "finalCleanupStatus")
        remaining = list(conclusive_teardown.input.get("remainingOwnedResources") or [])
        if (
            conclusive_teardown.status in {"running", "succeeded"}
            and cleanup == "verified_clean"
            and not remaining
            and not active_records
            and not live_sketches
            and not failed_sketches
        ):
            return LifecycleResolution("destroyed", evidence)
        if conclusive_teardown.status in {"failed", "succeeded"}:
            return LifecycleResolution("cleanup_required", evidence)

    running = next((job for job in core_jobs if job.status in RUNNING_STATES), None)
    if running is not None:
        state = "tearing_down" if _is_teardown_job(running) else "deploying"
        return LifecycleResolution(state, evidence)

    if any(chain.status.lower() in {"deploying", "starting"} for chain in sketch_chains):
        return LifecycleResolution("deploying", evidence)
    if any(chain.status.lower() in {"stopping"} for chain in sketch_chains):
        return LifecycleResolution("tearing_down", evidence)

    conclusive = next((job for job in core_jobs if _job_has_lifecycle_mutation(job)), None)
    if conclusive is not None:
        cleanup = _latest_event_value(conclusive, "finalCleanupStatus")
        mutation = _latest_event_value(conclusive, "mutationStatus")
        if cleanup == "verified_clean":
            if (
                conclusive.status == "succeeded"
                and _inspector_cleanup_ok(conclusive)
                and not active_records
                and not live_sketches
            ):
                return LifecycleResolution("destroyed", evidence)
            if (
                conclusive.status == "failed"
                and _inspector_cleanup_ok(conclusive)
                and not active_records
                and not live_sketches
                and not failed_sketches
            ):
                return LifecycleResolution("destroyed", evidence)
            return LifecycleResolution("cleanup_required", evidence)
        if cleanup == "pending_operator_teardown" or mutation == "deployed":
            if conclusive.status == "succeeded" and not failed_sketches:
                return LifecycleResolution("active", evidence)
            return LifecycleResolution("cleanup_required", evidence)
        if mutation in {"destroy_failed", "partial", "failed"}:
            return LifecycleResolution("cleanup_required", evidence)

    if active_records or live_sketches or failed_sketches:
        return LifecycleResolution("cleanup_required", evidence)
    # Pending sketch configuration, terminal resource records, and failed
    # preflight jobs are useful audit evidence but do not prove deployment.
    if not core_jobs or all(not _job_has_lifecycle_mutation(job) for job in core_jobs):
        return LifecycleResolution(
            "unknown" if previous_state and previous_state not in {"not_deployed", "destroyed"} else "not_deployed",
            evidence,
        )
    return LifecycleResolution("unknown", evidence)


def _evidence(core_jobs: list[StoredJobRun], provider_records: list[Any], sketch_chains: list[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for job in core_jobs:
        row = {
            "kind": "engagement_teardown_job" if job.action in {
                ENGAGEMENT_TEARDOWN_ACTION, MIXED_ZERO_APPLY_TEARDOWN_ACTION,
                MIXED_INTERRUPTED_TEARDOWN_ACTION,
                MIXED_PUBLISHED_TEARDOWN_ACTION} else "core_job",
            "id": job.id,
            "status": job.status,
        }
        mutation = _latest_event_value(job, "mutationStatus")
        cleanup = _latest_event_value(job, "finalCleanupStatus")
        if mutation is not None:
            row["mutationStatus"] = str(mutation)
        if cleanup is not None:
            row["cleanupStatus"] = str(cleanup)
        if _is_teardown_job(job):
            row["phase"] = "teardown"
        rows.append(row)
    for record in provider_records:
        rows.append(
            {
                "kind": "owned_provider_resource" if is_barragan_owned_record(record) else "unmanaged_provider_resource",
                "id": record.id,
                "provider": record.provider,
                "resourceType": record.resource_type,
                "status": record.status,
            }
        )
    for chain in sketch_chains:
        rows.append({"kind": "sketch_chain", "id": chain.chain_id, "status": chain.status})
    return sorted(rows, key=lambda row: (str(row.get("kind")), str(row.get("id"))))


def _job_has_lifecycle_mutation(job: StoredJobRun) -> bool:
    mutation = str(_latest_event_value(job, "mutationStatus") or "").lower()
    cleanup = str(_latest_event_value(job, "finalCleanupStatus") or "").lower()
    return mutation in {"deployed", "destroyed", "destroy_failed", "partial", "failed"} or cleanup in {
        "pending_operator_teardown",
        "verified_clean",
    }


def _job_after(created_at: str, finished_at: str) -> bool:
    try:
        return datetime.fromisoformat(created_at.replace("Z", "+00:00")) > datetime.fromisoformat(
            finished_at.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return False


def _is_teardown_job(job: StoredJobRun) -> bool:
    return any("teardown" in event.message.lower() for event in job.events)


def _inspector_cleanup_ok(job: StoredJobRun) -> bool:
    for key in ("inspectorTeardownVerification", "inspectorCleanup"):
        value = _latest_event_value(job, key)
        if isinstance(value, dict) and value.get("ok") is False:
            return False
    return True


def _latest_event_value(job: StoredJobRun, key: str) -> Any:
    event = next((entry for entry in reversed(job.events) if entry.data.get(key) is not None), None)
    return event.data.get(key) if event else None


def _fingerprint(evidence: list[dict[str, Any]]) -> str:
    payload = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _projection_dict(lifecycle: StoredEngagementLifecycle | None, administrative_status: str) -> dict[str, Any]:
    state = lifecycle.state if lifecycle else "not_deployed"
    return {
        "state": state,
        "label": LIFECYCLE_LABELS[state],
        "attentionRequired": state in ATTENTION_STATES,
        "terminal": state in {"not_deployed", "destroyed"},
        "administrativeStatus": administrative_status,
        "evidence": lifecycle.evidence if lifecycle else [],
        "evidenceFingerprint": lifecycle.evidence_fingerprint if lifecycle else _fingerprint([]),
        "reconciledAt": lifecycle.reconciled_at if lifecycle and lifecycle.reconciled_at else None,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
