# Copyright (c) 2026, Oracle and/or its affiliates.
from app.core.request_identity import RequestIdentity, bind_request_identity
from app.services.jobs import enqueue_job
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app import create_app
from app.core.config import TestConfig
from app.domain import JobEvent
class MemoryJobRepository:
    def __init__(self):
        self.jobs = {}

    def save(self, job):
        self.jobs[job.id] = job
        return job

    def get(self, job_id):
        return self.jobs.get(job_id)

    def list(self):
        return list(self.jobs.values())


def test_authenticated_request_identity_overrides_client_supplied_job_actor():
    repository = MemoryJobRepository()
    identity = RequestIdentity("user-example_operator_three", "example_operator_three", ("administrator",), "session-1")
    with bind_request_identity(identity):
        job = enqueue_job("example", "system", "one", "forged-operator", {}, repository)
    assert job.requested_by == "example_operator_three"


def test_internal_jobs_retain_explicit_system_identity():
    repository = MemoryJobRepository()
    job = enqueue_job("example", "system", "one", "scheduler:certificate", {}, repository)
    assert job.requested_by == "scheduler:certificate"


def test_repository_derives_actor_for_services_that_construct_jobs_directly():
    app = create_app(TestConfig)
    job = StoredJobRun(
        id="job-direct",
        action="direct",
        status="queued",
        target="system:one",
        target_type="system",
        target_id="one",
        requested_by="forged-user",
        input={},
        artifact_refs=[],
        created_at="2026-08-02T00:00:00+00:00",
        started_at=None,
        finished_at=None,
        events=[JobEvent(1, "info", "queued", {})],
    )
    identity = RequestIdentity("user-example_operator_three", "example_operator_three", ("administrator",), "session-1")
    with app.storage_context(), bind_request_identity(identity):
        stored = SqlAlchemyJobRepository().save(job)
    assert stored.requested_by == "example_operator_three"
