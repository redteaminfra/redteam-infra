# Copyright (c) 2026, Oracle and/or its affiliates.
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Callable
from uuid import uuid4

from app.core.request_identity import current_request_identity
from app.domain import JobEvent, JobRunDetail, JobRunSummary
from app.jobs.dry_run import run_plan_only_job
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun


class JobNotFoundError(LookupError):
    pass


class JobExecutionError(ValueError):
    pass


JobExecutor = Callable[[StoredJobRun], tuple[str, list[JobEvent], list[str]]]


@dataclass(frozen=True)
class JobRunPage:
    jobs: list[JobRunSummary]
    total: int
    limit: int
    offset: int

    def to_dict(self) -> dict:
        return {
            "jobs": [job.to_dict() for job in self.jobs],
            "pagination": {
                "total": self.total,
                "limit": self.limit,
                "offset": self.offset,
                "hasMore": self.offset + len(self.jobs) < self.total,
            },
        }


def list_job_runs(repository: JobRepository | None = None) -> list[JobRunSummary]:
    return [job.to_summary() for job in _repository(repository).list()]


def list_job_run_page(
    *,
    limit: int,
    offset: int,
    repository: JobRepository | None = None,
) -> JobRunPage:
    repo = _repository(repository)
    list_summaries = getattr(repo, "list_summaries", None)
    if callable(list_summaries):
        jobs, total = list_summaries(limit=limit, offset=offset)
    else:
        all_jobs = list_job_runs(repository=repo)
        jobs = all_jobs[offset : offset + limit]
        total = len(all_jobs)
    return JobRunPage(jobs=jobs, total=total, limit=limit, offset=offset)


def get_job_run(job_id: str, repository: JobRepository | None = None) -> JobRunDetail | None:
    job = _repository(repository).get(job_id)
    if job is None:
        return None
    detail = job.to_detail()
    if job.action == "pilot_standard_rti_guarded_execute" and job.input.get("corePlanId"):
        from app.services.guarded_test_deployment import _sanitize_core_plan_job_detail

        return _sanitize_core_plan_job_detail(detail)
    return detail


def enqueue_job(
    action: str,
    target_type: str,
    target_id: str,
    requested_by: str,
    input_data: dict,
    repository: JobRepository | None = None,
) -> JobRunDetail:
    request_identity = current_request_identity()
    effective_requester = request_identity.username if request_identity is not None else requested_by
    job = StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=action,
        status="queued",
        target=f"{target_type}:{target_id}",
        target_type=target_type,
        target_id=target_id,
        requested_by=effective_requester,
        input=input_data,
        artifact_refs=[],
        created_at=_now(),
        started_at=None,
        finished_at=None,
        events=[JobEvent(1, "info", "job queued", {"action": action})],
    )
    return _repository(repository).save(job).to_detail()


def run_job(
    job_id: str,
    repository: JobRepository | None = None,
    executors: dict[str, JobExecutor] | None = None,
) -> JobRunDetail:
    repo = _repository(repository)
    job = repo.get(job_id)
    if job is None:
        raise JobNotFoundError("job not found")
    if job.status != "queued":
        raise JobExecutionError(f"job must be queued, found {job.status}")

    job = repo.save(replace(job, status="running", started_at=_now()))

    try:
        executor = _executor_for(job.action, executors)
        status, events, artifact_refs = executor(job)
    except Exception as exc:
        failed = replace(
            job,
            status="failed",
            finished_at=_now(),
            events=job.events + [JobEvent(_next_sequence(job.events), "error", _redact_exception(exc, job), {})],
        )
        return repo.save(failed).to_detail()

    finished = replace(
        job,
        status=status,
        artifact_refs=artifact_refs,
        finished_at=_now(),
        events=job.events + _renumber_events(events, _next_sequence(job.events)),
    )
    return repo.save(finished).to_detail()


def _executor_for(action: str, executors: dict[str, JobExecutor] | None) -> JobExecutor:
    if executors and action in executors:
        return executors[action]
    return lambda job: run_plan_only_job(job.action)


def _repository(repository: JobRepository | None) -> JobRepository:
    return repository or SqlAlchemyJobRepository()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _next_sequence(events: list[JobEvent]) -> int:
    if not events:
        return 1
    return max(event.sequence for event in events) + 1


def _renumber_events(events: list[JobEvent], first_sequence: int) -> list[JobEvent]:
    return [
        JobEvent(first_sequence + index, event.level, event.message, event.data)
        for index, event in enumerate(events)
    ]


def _redact_exception(exc: Exception, job: StoredJobRun) -> str:
    message = str(exc)
    for value in _sensitive_input_values(job.input):
        message = message.replace(value, "[redacted]")
    for marker in ("token", "secret", "password", "TF_VAR_linode_api_token"):
        if marker.lower() in message.lower():
            return "job execution failed with redacted sensitive details"
    return message


def _sensitive_input_values(data: object) -> list[str]:
    values: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            key_text = str(key).lower()
            if isinstance(value, str) and any(marker in key_text for marker in ("token", "secret", "password", "privatekey")):
                values.append(value)
            values.extend(_sensitive_input_values(value))
    elif isinstance(data, list):
        for item in data:
            values.extend(_sensitive_input_values(item))
    return [value for value in values if value]
