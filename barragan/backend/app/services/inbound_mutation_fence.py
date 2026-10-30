# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator, Protocol

from app.core.runtime import has_runtime_context
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.deployment_plan_repository import (
    DeploymentPlanConflictError,
    SqlAlchemyDeploymentPlanRepository,
)


INBOUND_BATCH_ACTION = "inbound_channel_batch_apply"
_active_batch_id: ContextVar[str] = ContextVar("active_inbound_batch_id", default="")
_active_mutation_owner: ContextVar[str] = ContextVar("active_inbound_mutation_owner", default="")


class InboundMutationLeaseConflict(RuntimeError):
    pass


def active_inbound_mutation_owner() -> str:
    return _active_mutation_owner.get()


class InboundMutationLeaseRepository(Protocol):
    def acquire(self, engagement_id: str, owner_id: str, operation: str) -> bool: ...
    def release(self, engagement_id: str, owner_id: str) -> None: ...


def acquire_inbound_mutation(
    engagement_id: str,
    owner_id: str,
    operation: str,
    repository: InboundMutationLeaseRepository | None = None,
) -> InboundMutationLeaseRepository | None:
    """Atomically fence engagement mutations across workers and processes.

    The shared core-mutation lease is intentional: inbound route changes touch
    proxy/Homebase configuration and must not race core or capability Ansible.
    Pure unit helpers without a Barragan runtime remain side-effect free unless
    a lease repository is explicitly supplied.
    """
    if _active_mutation_owner.get():
        return None
    if repository is None and not has_runtime_context():
        return None
    leases = repository or SqlAlchemyDeploymentPlanRepository()
    try:
        leases.acquire(engagement_id, owner_id, operation[:40])
    except DeploymentPlanConflictError as exc:
        raise InboundMutationLeaseConflict("another engagement mutation is already in progress") from exc
    return leases


def release_inbound_mutation(
    engagement_id: str,
    owner_id: str,
    repository: InboundMutationLeaseRepository | None,
) -> None:
    if repository is not None:
        repository.release(engagement_id, owner_id)


@contextmanager
def bind_inbound_mutation(owner_id: str) -> Iterator[None]:
    token = _active_mutation_owner.set(owner_id)
    try:
        yield
    finally:
        _active_mutation_owner.reset(token)


def active_inbound_batch(engagement_id: str, repository: JobRepository | None = None) -> StoredJobRun | None:
    # Pure unit-level derivation helpers intentionally run without a Barragan
    # runtime. Live API and worker paths always bind one before mutation.
    if repository is None and not has_runtime_context():
        return None
    repo = repository or SqlAlchemyJobRepository()
    jobs = repo.list_for_engagement(engagement_id) if hasattr(repo, "list_for_engagement") else repo.list()
    return next(
        (
            job
            for job in jobs
            if job.action == INBOUND_BATCH_ACTION
            and job.target_id == engagement_id
            and job.status in {"queued", "running"}
            and job.id != _active_batch_id.get()
        ),
        None,
    )


@contextmanager
def bind_inbound_batch(batch_id: str) -> Iterator[None]:
    token = _active_batch_id.set(batch_id)
    mutation_token = _active_mutation_owner.set(batch_id)
    try:
        yield
    finally:
        _active_mutation_owner.reset(mutation_token)
        _active_batch_id.reset(token)
