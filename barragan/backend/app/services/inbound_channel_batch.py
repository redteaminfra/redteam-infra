# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Callable
from uuid import UUID, uuid4

from app.core.runtime import has_runtime_context, start_runtime_task
from app.core.request_identity import current_request_identity
from app.domain import JobEvent
from app.services.engagement_operations import get_operations_overview, update_operations_overview
from app.services.engagements import get_engagement
from app.services.inbound_channel_apply import (
    InboundChannelApplyValidationError,
    _assert_no_secret_material,
    preflight_inbound_channel_apply,
    start_inbound_channel_apply,
    validate_inbound_channel,
)
from app.services.inbound_channel_workflow import (
    InboundChannelWorkflowValidationError,
    _INBOUND_CREATE_LOCK,
    _validate_new_channel_claim,
    derive_inbound_channel,
)
from app.services.sketch_provider_firewall import provider_ingress_preflight_errors
from app.services.inbound_mutation_fence import (
    InboundMutationLeaseConflict,
    InboundMutationLeaseRepository,
    acquire_inbound_mutation,
    active_inbound_batch,
    bind_inbound_batch,
    release_inbound_mutation,
)
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository


INBOUND_BATCH_ACTION = "inbound_channel_batch_apply"
INBOUND_PREPARE_ACTION = "inbound_channel_prepare"
MAX_BATCH_CHANNELS = 20
BackgroundRunner = Callable[[Callable[[], None]], None]


class InboundChannelBatchConflictError(InboundChannelWorkflowValidationError):
    pass


def latest_inbound_channel_batch(
    engagement_id: str,
    *,
    repository: JobRepository | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    repo = repository or SqlAlchemyJobRepository()
    jobs = repo.list_for_engagement(engagement_id) if hasattr(repo, "list_for_engagement") else repo.list()
    candidates = [job for job in jobs if job.action == INBOUND_BATCH_ACTION and job.target_id == engagement_id]
    latest = max(candidates, key=lambda job: job.created_at) if candidates else None
    return {"job": latest.to_detail().to_dict() if latest is not None else None}


def preview_inbound_channel_batch(engagement_id: str, submission_id: Any, bodies: Any) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    with _INBOUND_CREATE_LOCK:
        overview = get_operations_overview(engagement_id)
        channels = _preflight_batch(engagement.name, overview, bodies, engagement_id=engagement_id)
        fingerprint = _preview_fingerprint(engagement_id, overview, channels)
    return {
        "status": "ready",
        "submissionId": _submission_id(submission_id),
        "previewFingerprint": fingerprint,
        "channels": channels,
        "applyOrder": [str(channel["channelId"]) for channel in channels],
        "warnings": [],
        "summary": f"{len(channels)} inbound channels passed whole-batch preflight.",
    }


def prepare_reviewed_inbound_channel(
    engagement_id: str,
    submission_id: Any,
    preview_fingerprint: Any,
    body: Any,
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    lease_repository: InboundMutationLeaseRepository | None = None,
) -> dict[str, Any] | None:
    """Persist one reviewed route without scheduling infrastructure work."""
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    repo = repository or SqlAlchemyJobRepository()
    submission = _submission_id(submission_id)
    expected_fingerprint = str(preview_fingerprint or "").strip()
    if not expected_fingerprint:
        raise InboundChannelWorkflowValidationError(["previewFingerprint is required; review the channel again"])
    body_fingerprint = _body_fingerprint(body)
    with _INBOUND_CREATE_LOCK:
        existing = _prepare_submission_job(repo, engagement_id, submission)
        if existing is not None:
            return _prepare_replay(existing, expected_fingerprint, body_fingerprint)
        job_id = f"job-{uuid4().hex[:12]}"
        try:
            leases = acquire_inbound_mutation(engagement_id, job_id, INBOUND_PREPARE_ACTION, lease_repository)
        except InboundMutationLeaseConflict as exc:
            raise InboundChannelBatchConflictError([str(exc)]) from exc
        try:
            # A different worker may have completed this submission between
            # the optimistic lookup and our durable lease acquisition.
            existing = _prepare_submission_job(repo, engagement_id, submission)
            if existing is not None:
                return _prepare_replay(existing, expected_fingerprint, body_fingerprint)
            if active_inbound_batch(engagement_id, repo) is not None or _active_individual_mutation(repo, engagement_id) is not None:
                raise InboundChannelBatchConflictError(["another inbound channel mutation is already running for this engagement"])
            overview = get_operations_overview(engagement_id)
            try:
                channels = _preflight_batch(
                    engagement.name, overview, [body], engagement_id=engagement_id, job_repository=repo
                )
            except (InboundChannelWorkflowValidationError, InboundChannelApplyValidationError) as exc:
                raise InboundChannelBatchConflictError(["the reviewed channel is stale; review it again before saving", *exc.errors]) from exc
            actual_fingerprint = _preview_fingerprint(engagement_id, overview, channels)
            if actual_fingerprint != expected_fingerprint:
                raise InboundChannelBatchConflictError(["the reviewed channel is stale; review it again before saving"])
            channel = channels[0]
            validation = dict(channel.get("validation") or {})
            prepared = {
                **channel,
                "status": "Pending Apply",
                "validation": {
                    **validation,
                    "status": "Pending Apply",
                    "detail": "Saved for review. No infrastructure changes have run.",
                },
            }
            requested_by = _authenticated_actor(requested_by)
            now = _now()
            job = StoredJobRun(
                id=job_id,
                action=INBOUND_PREPARE_ACTION,
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by=requested_by,
                input={
                    "engagementId": engagement_id,
                    "channelId": prepared["channelId"],
                    "submissionId": submission,
                    "previewFingerprint": actual_fingerprint,
                    "submissionBodyFingerprint": body_fingerprint,
                    "reviewedChannel": prepared,
                    "mutation": False,
                },
                artifact_refs=[],
                created_at=now,
                started_at=now,
                finished_at=now,
                events=[JobEvent(1, "info", "inbound channel saved pending; no infrastructure changes ran", {
                    "mutation": False,
                    "channelId": prepared["channelId"],
                    "status": "Pending Apply",
                    "inboundChannels": [*overview.get("inboundChannels", []), prepared],
                })],
            )
            _assert_no_secret_material(job.to_detail().to_dict())
            saved = repo.save(job)
        finally:
            release_inbound_mutation(engagement_id, job_id, leases)
    return {"channel": prepared, "job": saved.to_detail().to_dict(), "status": "Pending Apply"}


def start_inbound_channel_batch(
    engagement_id: str,
    submission_id: Any,
    preview_fingerprint: Any,
    bodies: Any,
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    lease_repository: InboundMutationLeaseRepository | None = None,
    background_runner: BackgroundRunner | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    repo = repository or SqlAlchemyJobRepository()
    submission = _submission_id(submission_id)
    expected_fingerprint = str(preview_fingerprint or "").strip()
    if not expected_fingerprint:
        raise InboundChannelWorkflowValidationError(["previewFingerprint is required; review the batch again"])
    with _INBOUND_CREATE_LOCK:
        existing = _submission_job(repo, engagement_id, submission)
        if existing is not None:
            if str(existing.input.get("previewFingerprint") or "") != expected_fingerprint:
                raise InboundChannelBatchConflictError(["submissionId was already used for a different inbound channel batch"])
            if str(existing.input.get("submissionBodyFingerprint") or "") != _body_fingerprint(bodies):
                raise InboundChannelBatchConflictError(["submissionId was already used for a different inbound channel batch"])
            return {
                "batchId": existing.id,
                "channels": existing.input.get("reviewedChannels") if isinstance(existing.input.get("reviewedChannels"), list) else [],
                "job": existing.to_detail().to_dict(),
            }
        active = active_inbound_batch(engagement_id, repo)
        if active is not None:
            raise InboundChannelBatchConflictError([f"inbound channel batch {active.id} is already running for this engagement"])
        active_mutation = _active_individual_mutation(repo, engagement_id)
        if active_mutation is not None:
            raise InboundChannelBatchConflictError([f"inbound channel job {active_mutation.id} is already running for this engagement"])
        overview = get_operations_overview(engagement_id)
        try:
            channels = _preflight_batch(engagement.name, overview, bodies, engagement_id=engagement_id, job_repository=repo)
        except (InboundChannelWorkflowValidationError, InboundChannelApplyValidationError) as exc:
            raise InboundChannelBatchConflictError(["the reviewed batch is stale; review it again before applying", *exc.errors]) from exc
        actual_fingerprint = _preview_fingerprint(engagement_id, overview, channels)
        if actual_fingerprint != expected_fingerprint:
            raise InboundChannelBatchConflictError(["the reviewed batch is stale; review it again before applying"])
        requested_by = _authenticated_actor(requested_by)
        parent_id = f"job-{uuid4().hex[:12]}"
        try:
            leases = acquire_inbound_mutation(engagement_id, parent_id, INBOUND_BATCH_ACTION, lease_repository)
        except InboundMutationLeaseConflict as exc:
            raise InboundChannelBatchConflictError([str(exc)]) from exc
        parent = None
        prior_inbound_channels = list(overview.get("inboundChannels", []))
        try:
            parent = _new_parent(
                repo,
                engagement_id,
                channels,
                job_id=parent_id,
                requested_by=requested_by,
                submission_id=submission,
                preview_fingerprint=actual_fingerprint,
                submission_body_fingerprint=_body_fingerprint(bodies),
            )
            repo.save(parent)
            _reserve_channels(engagement_id, overview, channels, parent.id)
        except Exception:
            try:
                if parent is not None:
                    failed = replace(
                        parent,
                        status="failed",
                        finished_at=_now(),
                        input={**parent.input, "retryRequired": False},
                        events=[*parent.events, JobEvent(len(parent.events) + 1, "error", "inbound channel batch reservation failed; no apply was scheduled", {})],
                    )
                    repo.save(failed)
                # update_operations_overview records before it projects the
                # result. Restore the lease-protected pre-batch snapshot in
                # case the reservation commit succeeded but its readback
                # raised. No child apply has been scheduled at this point.
                try:
                    update_operations_overview(
                        engagement_id,
                        {"inboundChannels": prior_inbound_channels},
                    )
                except Exception:
                    pass
            finally:
                release_inbound_mutation(engagement_id, parent_id, leases)
            raise
    _schedule_parent(repo, parent, engagement_id, channels, requested_by, background_runner, leases)
    saved = repo.get(parent.id) or parent
    return {"batchId": parent.id, "channels": channels, "job": saved.to_detail().to_dict()}


def retry_inbound_channel_batch(
    engagement_id: str,
    batch_id: str,
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    lease_repository: InboundMutationLeaseRepository | None = None,
    background_runner: BackgroundRunner | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    repo = repository or SqlAlchemyJobRepository()
    with _INBOUND_CREATE_LOCK:
        if active_inbound_batch(engagement_id, repo) is not None or _active_individual_mutation(repo, engagement_id) is not None:
            raise InboundChannelBatchConflictError(["another inbound channel mutation is already running for this engagement"])
        source = repo.get(batch_id)
        if source is None or source.action != INBOUND_BATCH_ACTION or source.target_id != engagement_id:
            raise InboundChannelWorkflowValidationError([f"inbound channel batch {batch_id} was not found"])
        source_children = source.input.get("children")
        if not isinstance(source_children, list):
            raise InboundChannelWorkflowValidationError([f"inbound channel batch {batch_id} has no retryable rows"])
        overview = get_operations_overview(engagement_id)
        current = {
            str(row.get("channelId") or ""): row
            for row in overview.get("inboundChannels", [])
            if isinstance(row, dict)
        }
        retryable = {
            str(row.get("channelId") or ""): str(row.get("status") or "")
            for row in source_children
            if isinstance(row, dict) and str(row.get("status") or "") in {"failed", "validation_failed", "not_started"}
        }
        channels: list[dict[str, Any]] = []
        errors: list[str] = []
        for channel_id, source_status in retryable.items():
            channel = current.get(channel_id)
            status = str(channel.get("status") or "").lower() if channel else ""
            if channel is None or status in {"removed", "disabled"}:
                errors.append(f"inbound channel {channel_id} is no longer available to retry")
            else:
                channels.append({**channel, "batchRetryAction": "validate" if source_status == "validation_failed" else "apply"})
        if errors:
            raise InboundChannelWorkflowValidationError(errors)
        if not channels:
            raise InboundChannelWorkflowValidationError([f"inbound channel batch {batch_id} has no failed or not-started rows to retry"])
        requested_by = _authenticated_actor(requested_by)
        parent_id = f"job-{uuid4().hex[:12]}"
        try:
            leases = acquire_inbound_mutation(engagement_id, parent_id, INBOUND_BATCH_ACTION, lease_repository)
        except InboundMutationLeaseConflict as exc:
            raise InboundChannelBatchConflictError([str(exc)]) from exc
        parent = None
        prior_inbound_channels = list(overview.get("inboundChannels", []))
        try:
            parent = _new_parent(
                repo,
                engagement_id,
                channels,
                job_id=parent_id,
                requested_by=requested_by,
                submission_id=str(uuid4()),
                preview_fingerprint=str(source.input.get("previewFingerprint") or "retry"),
                submission_body_fingerprint=_body_fingerprint(channels),
                source_batch_id=batch_id,
            )
            repo.save(parent)
            _mark_reserved_channels(engagement_id, channels, parent.id)
        except Exception:
            try:
                if parent is not None:
                    children = [{**child, "status": "not_started"} for child in _children(parent)]
                    repo.save(replace(
                        parent,
                        status="failed",
                        finished_at=_now(),
                        input={**parent.input, "children": children, "retryRequired": True},
                        events=[*parent.events, JobEvent(
                            len(parent.events) + 1,
                            "error",
                            "inbound channel batch retry reservation failed; no apply was scheduled",
                            {"children": children},
                        )],
                    ))
                try:
                    update_operations_overview(
                        engagement_id,
                        {"inboundChannels": prior_inbound_channels},
                    )
                except Exception:
                    pass
            finally:
                release_inbound_mutation(engagement_id, parent_id, leases)
            raise
    _schedule_parent(repo, parent, engagement_id, channels, requested_by, background_runner, leases)
    saved = repo.get(parent.id) or parent
    return {"batchId": parent.id, "channels": channels, "job": saved.to_detail().to_dict()}


def recover_interrupted_inbound_channel_batches(
    *,
    repository: JobRepository | None = None,
    lease_repository: InboundMutationLeaseRepository | None = None,
) -> int:
    repo = repository or SqlAlchemyJobRepository()
    leases = lease_repository or (SqlAlchemyDeploymentPlanRepository() if has_runtime_context() else None)
    recovered = 0
    for job in repo.list():
        if job.action != INBOUND_BATCH_ACTION or job.status not in {"queued", "running"}:
            continue
        try:
            children = _children(job)
            interrupted_ids = {
                str(child.get("channelId") or "")
                for child in children
                if child.get("status") == "running"
            }
            children = [
                {**child, "status": "failed" if child.get("status") == "running" else "not_started"}
                if child.get("status") in {"queued", "running"}
                else child
                for child in children
            ]
            for channel_id in interrupted_ids:
                child_job = _latest_channel_job(repo, job.target_id, "inbound_channel_apply", channel_id)
                if child_job is not None and child_job.status in {"queued", "running"}:
                    repo.save(replace(child_job, status="failed", finished_at=_now(), events=[*child_job.events, JobEvent(len(child_job.events) + 1, "error", "inbound channel apply was interrupted; inspect and recover before retry", {"channelId": channel_id, "status": "Recovery Required"})]))
            repo.save(
                replace(
                    job,
                    status="failed",
                    finished_at=_now(),
                    input={**job.input, "children": children, "retryRequired": True},
                    events=[
                        *job.events,
                        JobEvent(len(job.events) + 1, "error", "inbound channel batch was interrupted; retry pending rows", {"children": children}),
                    ],
                )
            )
            recovered += 1
            try:
                _mark_recovery_rows(job.target_id, children)
            except Exception:
                # The terminal parent remains authoritative and startup must
                # continue even if the convenience projection cannot refresh.
                pass
        except Exception:
            # A single corrupt/temporarily unavailable job must not prevent
            # startup recovery from examining the remaining engagements.
            pass
        finally:
            try:
                release_inbound_mutation(job.target_id, job.id, leases)
            except Exception:
                pass
    return recovered


def _preflight_batch(
    engagement_name: str,
    overview: dict[str, Any],
    bodies: Any,
    *,
    engagement_id: str = "",
    job_repository: JobRepository | None = None,
) -> list[dict[str, Any]]:
    if not isinstance(bodies, list):
        raise InboundChannelWorkflowValidationError(["channels must be a list"])
    if not bodies:
        raise InboundChannelWorkflowValidationError(["add at least one inbound channel"])
    if len(bodies) > MAX_BATCH_CHANNELS:
        raise InboundChannelWorkflowValidationError([f"an inbound channel batch supports at most {MAX_BATCH_CHANNELS} rows"])
    simulated = {**overview, "inboundChannels": list(overview.get("inboundChannels", []))}
    channels: list[dict[str, Any]] = []
    errors: list[str] = []
    for index, body in enumerate(bodies, start=1):
        if not isinstance(body, dict):
            errors.append(f"row {index}: channel must be an object")
            continue
        try:
            normalized_body = dict(body)
            domain = str(normalized_body.get("domain") or "").strip().lower().rstrip(".")
            if domain:
                normalized_body["domain"] = domain
            channel = derive_inbound_channel(engagement_name, simulated, normalized_body)
            _validate_new_channel_claim(simulated, channel)
            channel = preflight_inbound_channel_apply(engagement_name, simulated, channel)
            channels.append(channel)
            simulated["inboundChannels"] = [*simulated["inboundChannels"], channel]
        except (InboundChannelWorkflowValidationError, InboundChannelApplyValidationError) as exc:
            errors.extend(f"row {index}: {error}" for error in exc.errors)
    if errors:
        raise InboundChannelWorkflowValidationError(errors)
    if engagement_id and has_runtime_context():
        checked_chains: set[str] = set()
        for index, channel in enumerate(channels, start=1):
            chain_id = str(channel.get("chainId") or "").strip()
            if not chain_id or chain_id in checked_chains:
                continue
            checked_chains.add(chain_id)
            errors.extend(
                f"row {index}: {error}"
                for error in provider_ingress_preflight_errors(
                    engagement_id,
                    chain_id,
                    job_repository=job_repository,
                )
            )
    if errors:
        raise InboundChannelWorkflowValidationError(errors)
    return channels


def _new_parent(
    repo: JobRepository,
    engagement_id: str,
    channels: list[dict[str, Any]],
    *,
    job_id: str,
    requested_by: str,
    submission_id: str,
    preview_fingerprint: str,
    submission_body_fingerprint: str,
    source_batch_id: str | None = None,
) -> StoredJobRun:
    now = _now()
    children = [{"channelId": channel["channelId"], "status": "queued", "jobId": ""} for channel in channels]
    job = StoredJobRun(
        id=job_id,
        action=INBOUND_BATCH_ACTION,
        status="queued",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by=requested_by,
        input={
            "engagementId": engagement_id,
            "children": children,
            "mutation": True,
            "retryRequired": False,
            "submissionId": submission_id,
            "previewFingerprint": preview_fingerprint,
            "submissionBodyFingerprint": submission_body_fingerprint,
            "reviewedChannels": channels,
            **({"sourceBatchId": source_batch_id} if source_batch_id else {}),
        },
        artifact_refs=[],
        created_at=now,
        started_at=None,
        finished_at=None,
        events=[JobEvent(1, "info", "inbound channel batch queued", {"children": children})],
    )
    _assert_no_secret_material(job.to_detail().to_dict())
    return job


def _reserve_channels(engagement_id: str, overview: dict[str, Any], channels: list[dict[str, Any]], batch_id: str) -> None:
    reserved = [_reserved(channel, batch_id) for channel in channels]
    update_operations_overview(
        engagement_id,
        {"inboundChannels": [*overview.get("inboundChannels", []), *reserved]},
    )


def _mark_reserved_channels(engagement_id: str, channels: list[dict[str, Any]], batch_id: str) -> None:
    overview = get_operations_overview(engagement_id) or {}
    ids = {str(channel.get("channelId") or "") for channel in channels}
    rows = [
        _reserved(row, batch_id) if isinstance(row, dict) and str(row.get("channelId") or "") in ids else row
        for row in overview.get("inboundChannels", [])
    ]
    if overview:
        update_operations_overview(engagement_id, {"inboundChannels": rows})


def _reserved(channel: dict[str, Any], batch_id: str) -> dict[str, Any]:
    validation = dict(channel.get("validation") or {})
    return {
        **channel,
        "status": "Batch Queued",
        "batchId": batch_id,
        "validation": {**validation, "status": "Batch Queued", "detail": "Reserved by reviewed inbound channel batch."},
    }


def _schedule_parent(
    repo: JobRepository,
    parent: StoredJobRun,
    engagement_id: str,
    channels: list[dict[str, Any]],
    requested_by: str,
    background_runner: BackgroundRunner | None,
    leases: InboundMutationLeaseRepository | None,
) -> None:
    task = lambda: _run_parent_guarded(repo, parent.id, engagement_id, channels, requested_by, leases)
    try:
        if background_runner is not None:
            background_runner(task)
        else:
            start_runtime_task(task, name="barragan-inbound-channel-batch-runner", synchronous_when_testing=True)
    except Exception as exc:
        try:
            try:
                current = repo.get(parent.id) or parent
                children = [{**child, "status": "not_started"} for child in _children(current)]
                repo.save(replace(current, status="failed", finished_at=_now(), input={**current.input, "children": children, "retryRequired": True}, events=[*current.events, JobEvent(len(current.events) + 1, "error", "inbound channel batch scheduler failed", {"errorType": type(exc).__name__, "children": children})]))
                _mark_not_started_channels(engagement_id, children)
            except Exception:
                pass
        finally:
            release_inbound_mutation(engagement_id, parent.id, leases)


def _run_parent_guarded(
    repo: JobRepository,
    parent_id: str,
    engagement_id: str,
    channels: list[dict[str, Any]],
    requested_by: str,
    leases: InboundMutationLeaseRepository | None,
) -> None:
    try:
        _run_parent(repo, parent_id, engagement_id, channels, requested_by)
    except Exception as exc:
        current = repo.get(parent_id)
        if current is not None and current.status in {"queued", "running"}:
            children = [
                {**child, "status": "failed" if child.get("status") == "running" else "not_started"}
                if child.get("status") in {"queued", "running"}
                else child
                for child in _children(current)
            ]
            repo.save(replace(current, status="failed", finished_at=_now(), input={**current.input, "children": children, "retryRequired": True}, events=[*current.events, JobEvent(len(current.events) + 1, "error", "inbound channel batch stopped unexpectedly", {"errorType": type(exc).__name__, "children": children})]))
            _mark_recovery_rows(engagement_id, children)
    finally:
        release_inbound_mutation(engagement_id, parent_id, leases)


def _run_parent(repo: JobRepository, parent_id: str, engagement_id: str, channels: list[dict[str, Any]], requested_by: str) -> None:
    parent = repo.get(parent_id)
    if parent is None:
        return
    with bind_inbound_batch(parent_id):
        parent = repo.save(replace(parent, status="running", started_at=_now(), events=[*parent.events, JobEvent(len(parent.events) + 1, "info", "inbound channel batch apply started", {})]))
        children = _children(parent)
        failed = False
        completed_with_issues = False
        for index, channel in enumerate(channels):
            if failed:
                children[index] = {**children[index], "status": "not_started"}
                continue
            channel_id = str(channel["channelId"])
            children[index] = {**children[index], "status": "running"}
            parent = _save_children(repo, parent, children, f"applying inbound channel {channel_id}")
            try:
                if channel.get("batchRetryAction") == "validate":
                    validation_result = validate_inbound_channel(
                        engagement_id,
                        channel_id,
                        confirmation=f"validate-inbound-{channel_id}",
                        requested_by=requested_by,
                        repository=repo,
                    )
                    validation_job_id = str((validation_result or {}).get("job", {}).get("id") or "")
                    validation_job = repo.get(validation_job_id) if validation_job_id else None
                    child_status = "validated" if validation_job is not None and validation_job.status == "succeeded" else "validation_failed"
                    completed_with_issues = completed_with_issues or child_status == "validation_failed"
                    children[index] = {
                        **children[index],
                        "status": child_status,
                        "jobId": validation_job_id,
                        "validationJobId": validation_job_id,
                    }
                    parent = _save_children(repo, parent, children, f"inbound channel {channel_id} {child_status}")
                    continue
                result = start_inbound_channel_apply(
                    engagement_id,
                    channel_id,
                    confirmation=f"apply-inbound-{channel_id}",
                    requested_by=requested_by,
                    repository=repo,
                    auto_validate=True,
                    channel=channel,
                    background_runner=lambda task: task(),
                )
                child_job_id = str((result or {}).get("job", {}).get("id") or "")
                child_job = repo.get(child_job_id) if child_job_id else None
                validation_job = None
                if child_job is None or child_job.status != "succeeded":
                    child_status = "failed"
                elif str(channel.get("validationProfile", {}).get("type") if isinstance(channel.get("validationProfile"), dict) else "") == "manual":
                    child_status = "awaiting_certificate"
                else:
                    validation_job = _latest_channel_job(repo, engagement_id, "inbound_channel_validation", channel_id)
                    if validation_job is None or validation_job.status != "succeeded":
                        child_status = "validation_failed"
                        completed_with_issues = True
                    else:
                        child_status = "validated"
                children[index] = {
                    **children[index],
                    "status": child_status,
                    "jobId": child_job_id,
                    "applyJobId": child_job_id,
                    **({"validationJobId": validation_job.id} if validation_job is not None else {}),
                }
                failed = child_status == "failed"
            except Exception as exc:
                children[index] = {**children[index], "status": "failed", "errorType": type(exc).__name__}
                failed = True
            parent = _save_children(repo, parent, children, f"inbound channel {channel_id} {children[index]['status']}")
    if failed:
        _mark_not_started_channels(engagement_id, children)
    status = "failed" if failed or completed_with_issues else "succeeded"
    parent = repo.get(parent_id) or parent
    repo.save(
        replace(
            parent,
            status=status,
            finished_at=_now(),
            input={**parent.input, "children": children, "retryRequired": failed, "completedWithIssues": completed_with_issues},
            events=[*parent.events, JobEvent(len(parent.events) + 1, "error" if status == "failed" else "info", "inbound channel batch needs attention" if status == "failed" else "inbound channel batch completed", {"children": children, "completedWithIssues": completed_with_issues})],
        )
    )


def _save_children(repo: JobRepository, parent: StoredJobRun, children: list[dict[str, Any]], message: str) -> StoredJobRun:
    parent = replace(parent, input={**parent.input, "children": [dict(child) for child in children]}, events=[*parent.events, JobEvent(len(parent.events) + 1, "info", message, {"children": children})])
    return repo.save(parent)


def _children(job: StoredJobRun) -> list[dict[str, Any]]:
    value = job.input.get("children")
    return [dict(row) for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _submission_id(value: Any) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        raise InboundChannelWorkflowValidationError(["submissionId is required"])
    try:
        return str(UUID(candidate))
    except ValueError as exc:
        raise InboundChannelWorkflowValidationError(["submissionId must be a UUID"]) from exc


def _preview_fingerprint(engagement_id: str, overview: dict[str, Any], channels: list[dict[str, Any]]) -> str:
    active_claims = [
        {
            key: row.get(key)
            for key in (
                "channelId",
                "status",
                "protocol",
                "mode",
                "externalPort",
                "relayPort",
                "middleRelayPort",
                "proxyRelayPort",
                "edge",
                "middle",
                "proxy",
                "domain",
            )
        }
        for row in overview.get("inboundChannels", [])
        if isinstance(row, dict) and str(row.get("status") or "").strip().lower() not in {"removed", "disabled"}
    ]
    payload = json.dumps(
        {"engagementId": engagement_id, "activeClaims": active_claims, "channels": channels},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _body_fingerprint(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _submission_job(repo: JobRepository, engagement_id: str, submission_id: str) -> StoredJobRun | None:
    jobs = repo.list_for_engagement(engagement_id) if hasattr(repo, "list_for_engagement") else repo.list()
    return next(
        (
            job
            for job in jobs
            if job.action == INBOUND_BATCH_ACTION
            and job.target_id == engagement_id
            and str(job.input.get("submissionId") or "") == submission_id
        ),
        None,
    )


def _prepare_submission_job(repo: JobRepository, engagement_id: str, submission_id: str) -> StoredJobRun | None:
    jobs = repo.list_for_engagement(engagement_id) if hasattr(repo, "list_for_engagement") else repo.list()
    matches = [
        job for job in jobs
        if job.action == INBOUND_PREPARE_ACTION
        and job.target_id == engagement_id
        and job.status == "succeeded"
        and str(job.input.get("submissionId") or "") == submission_id
    ]
    if len(matches) > 1:
        raise InboundChannelBatchConflictError(["submissionId has multiple completed pending-channel records"])
    return matches[0] if matches else None


def _prepare_replay(existing: StoredJobRun, preview_fingerprint: str, body_fingerprint: str) -> dict[str, Any]:
    if (
        str(existing.input.get("previewFingerprint") or "") != preview_fingerprint
        or str(existing.input.get("submissionBodyFingerprint") or "") != body_fingerprint
    ):
        raise InboundChannelBatchConflictError(["submissionId was already used for a different pending inbound channel"])
    channel = existing.input.get("reviewedChannel")
    if not isinstance(channel, dict):
        raise InboundChannelBatchConflictError(["saved pending channel audit record is incomplete"])
    return {"channel": channel, "job": existing.to_detail().to_dict(), "status": "Pending Apply"}


def _active_individual_mutation(repo: JobRepository, engagement_id: str) -> StoredJobRun | None:
    jobs = repo.list_for_engagement(engagement_id) if hasattr(repo, "list_for_engagement") else repo.list()
    return next(
        (
            job
            for job in jobs
            if job.action in {"inbound_channel_apply", "inbound_channel_validation", "inbound_channel_remove"}
            and job.status in {"queued", "running"}
        ),
        None,
    )


def _latest_channel_job(repo: JobRepository, engagement_id: str, action: str, channel_id: str) -> StoredJobRun | None:
    jobs = repo.list_for_engagement(engagement_id) if hasattr(repo, "list_for_engagement") else repo.list()
    candidates = [
        job for job in jobs
        if job.action == action and str(job.input.get("channelId") or "") == channel_id
    ]
    return max(candidates, key=lambda job: job.created_at) if candidates else None


def _mark_not_started_channels(engagement_id: str, children: list[dict[str, Any]]) -> None:
    not_started = {str(child.get("channelId") or "") for child in children if child.get("status") == "not_started"}
    if not not_started:
        return
    overview = get_operations_overview(engagement_id) or {}
    rows = []
    for row in overview.get("inboundChannels", []):
        if not isinstance(row, dict) or str(row.get("channelId") or "") not in not_started:
            rows.append(row)
            continue
        validation = dict(row.get("validation") or {})
        rows.append({
            **row,
            "status": "Batch Not Started",
            "validation": {**validation, "status": "Batch Not Started", "detail": "A previous batch row failed. Retry or remove this channel."},
        })
    if overview:
        update_operations_overview(engagement_id, {"inboundChannels": rows})


def _mark_recovery_rows(engagement_id: str, children: list[dict[str, Any]]) -> None:
    statuses = {str(child.get("channelId") or ""): str(child.get("status") or "") for child in children}
    overview = get_operations_overview(engagement_id) or {}
    rows = []
    for row in overview.get("inboundChannels", []):
        if not isinstance(row, dict):
            rows.append(row)
            continue
        state = statuses.get(str(row.get("channelId") or ""))
        if state not in {"failed", "not_started"}:
            rows.append(row)
            continue
        validation = dict(row.get("validation") or {})
        visible_status = "Recovery Required" if state == "failed" else "Batch Not Started"
        detail = "Apply was interrupted. Inspect the route state before retrying." if state == "failed" else "The batch stopped before this row. Retry or remove it."
        rows.append({**row, "status": visible_status, "validation": {**validation, "status": visible_status, "detail": detail}})
    update_operations_overview(engagement_id, {"inboundChannels": rows})


def _authenticated_actor(fallback: str) -> str:
    identity = current_request_identity()
    return identity.username if identity is not None else fallback
