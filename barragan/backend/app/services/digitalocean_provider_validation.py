# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import threading
from dataclasses import replace
from datetime import datetime, timezone
from typing import Callable
from uuid import uuid4

from app.core.runtime import start_runtime_task
from app.domain import JobEvent, JobRunDetail
from app.integrations.digitalocean_validation import (
    DEFAULT_IMAGE,
    DEFAULT_REGION,
    DEFAULT_SIZE,
    DigitalOceanTransport,
    VALIDATION_CONFIRMATION,
    validate_digitalocean_sketch_create_destroy,
)
from app.services.credentials import resolve_credential_secret, resolve_default_credential_alias
from app.services.provider_catalog import preflight_digitalocean_sketch_live_readiness
from app.storage.credential_repository import CredentialRepository
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun


DIGITALOCEAN_PROVIDER_VALIDATION_ACTION = "digitalocean_sketch_provider_validation"

BackgroundRunner = Callable[[Callable[[], None]], None]


class DigitalOceanProviderValidationGuardrailError(ValueError):
    pass


def start_guarded_digitalocean_provider_validation_run(
    body: dict,
    *,
    repository: JobRepository | None = None,
    credential_repository: CredentialRepository | None = None,
    transport: DigitalOceanTransport | None = None,
    background_runner: BackgroundRunner | None = None,
) -> JobRunDetail:
    if body.get("confirmCreateDestroy") != VALIDATION_CONFIRMATION:
        raise DigitalOceanProviderValidationGuardrailError(f'confirmCreateDestroy must equal "{VALIDATION_CONFIRMATION}"')
    preflight = preflight_digitalocean_sketch_live_readiness(transport=transport)
    if not preflight.ready:
        raise DigitalOceanProviderValidationGuardrailError("DigitalOcean preflight must be ready before provider-smoke validation")
    alias = str(body.get("alias") or resolve_default_credential_alias("digitalocean", credential_repository) or "").strip()
    if not alias:
        raise DigitalOceanProviderValidationGuardrailError("DigitalOcean provider-smoke requires an active default digitalocean credential")

    repo = repository or SqlAlchemyJobRepository()
    job = repo.save(_new_validation_job(body, alias))
    running = repo.save(
        replace(
            job,
            status="running",
            started_at=_now(),
            events=job.events
            + [
                JobEvent(
                    _next_sequence(job.events),
                    "info",
                    "DigitalOcean provider-smoke started",
                    {
                        "provider": "digitalocean",
                        "mutation": True,
                        "preflight": preflight.to_dict(),
                    },
                )
            ],
        )
    )
    task_runner = background_runner or _start_background_task
    task_runner(lambda: _run_persisted_digitalocean_provider_validation(running.id, repo, credential_repository, transport))
    return running.to_detail()


def get_guarded_digitalocean_provider_validation_run(job_id: str, *, repository: JobRepository | None = None) -> JobRunDetail | None:
    job = (repository or SqlAlchemyJobRepository()).get(job_id)
    if job is None or job.action != DIGITALOCEAN_PROVIDER_VALIDATION_ACTION:
        return None
    return job.to_detail()


def run_digitalocean_provider_validation_job(
    job: StoredJobRun,
    *,
    credential_repository: CredentialRepository | None = None,
    transport: DigitalOceanTransport | None = None,
) -> tuple[str, list[JobEvent], list[str]]:
    alias = _required(job.input, "alias")
    token = resolve_credential_secret("digitalocean", alias, credential_repository)
    result = validate_digitalocean_sketch_create_destroy(
        token=token,
        credential_alias=alias,
        name=_required(job.input, "name"),
        region=_required(job.input, "region"),
        image=_required(job.input, "image"),
        size=_required(job.input, "size"),
        transport=transport,
    )
    body = result.to_dict()
    _assert_no_secret_material(body)
    return (
        "succeeded" if result.ok else "failed",
        [
            JobEvent(
                0,
                "info" if result.ok else "error",
                "DigitalOcean provider-smoke completed" if result.ok else "DigitalOcean provider-smoke failed",
                {
                    "provider": "digitalocean",
                    "mutation": True,
                    "validation": body,
                    "cleanupVerified": result.cleanup_verified,
                },
            )
        ],
        [f"provider-smoke:digitalocean:{job.id}"],
    )


def _run_persisted_digitalocean_provider_validation(
    job_id: str,
    repository: JobRepository,
    credential_repository: CredentialRepository | None,
    transport: DigitalOceanTransport | None,
) -> JobRunDetail | None:
    job = repository.get(job_id)
    if job is None:
        return None
    try:
        status, events, artifacts = run_digitalocean_provider_validation_job(
            job,
            credential_repository=credential_repository,
            transport=transport,
        )
    except Exception as exc:
        failed = replace(
            job,
            status="failed",
            finished_at=_now(),
            events=job.events
            + [
                JobEvent(
                    _next_sequence(job.events),
                    "error",
                    "DigitalOcean provider-smoke failed with redacted sensitive details",
                    {"errorType": type(exc).__name__},
                )
            ],
        )
        return repository.save(failed).to_detail()
    finished = replace(
        job,
        status=status,
        finished_at=_now(),
        artifact_refs=artifacts,
        events=job.events + _renumber_events(events, _next_sequence(job.events)),
    )
    return repository.save(finished).to_detail()


def _new_validation_job(body: dict, alias: str) -> StoredJobRun:
    now = _now()
    name = str(body.get("name") or f"barragan-do-validation-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}").strip()
    return StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=DIGITALOCEAN_PROVIDER_VALIDATION_ACTION,
        status="queued",
        target="provider:digitalocean",
        target_type="provider",
        target_id="digitalocean",
        requested_by=str(body.get("requestedBy") or "operator"),
        input={
            "provider": "digitalocean",
            "alias": alias,
            "name": name,
            "region": str(body.get("region") or DEFAULT_REGION).strip() or DEFAULT_REGION,
            "size": str(body.get("size") or DEFAULT_SIZE).strip() or DEFAULT_SIZE,
            "image": str(body.get("image") or DEFAULT_IMAGE).strip() or DEFAULT_IMAGE,
            "confirmCreateDestroy": "redacted",
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
                "DigitalOcean provider-smoke queued",
                {
                    "provider": "digitalocean",
                    "mutation": True,
                    "region": str(body.get("region") or DEFAULT_REGION).strip() or DEFAULT_REGION,
                    "size": str(body.get("size") or DEFAULT_SIZE).strip() or DEFAULT_SIZE,
                },
            )
        ],
    )


def _start_background_task(task: Callable[[], None]) -> None:
    start_runtime_task(task, name="barragan-digitalocean-provider-smoke")


def _required(data: dict, key: str) -> str:
    value = str(data.get(key) or "").strip()
    if not value:
        raise ValueError(f"{key} is required")
    return value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _next_sequence(events: list[JobEvent]) -> int:
    return max((event.sequence for event in events), default=0) + 1


def _renumber_events(events: list[JobEvent], first_sequence: int) -> list[JobEvent]:
    return [JobEvent(first_sequence + index, event.level, event.message, event.data) for index, event in enumerate(events)]


def _assert_no_secret_material(value: object) -> None:
    text = str(value)
    forbidden = (
        "BEGIN OPENSSH PRIVATE KEY",
        "do-token-sensitive-value",
        "DIGITALOCEAN_TOKEN",
        "TF_VAR_do_pat",
        "provider_token",
        "private_key_material",
        "user-data-sensitive-value",
    )
    leaked = [marker for marker in forbidden if marker in text]
    if leaked:
        raise ValueError("sensitive provider validation material was not redacted")
