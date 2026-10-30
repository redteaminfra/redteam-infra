# Copyright (c) 2026, Oracle and/or its affiliates.
from app.domain import JobEvent
from app.services.core_ssh import active_core_connection_details, deployment_known_hosts_file, latest_core_connection_details
from app.storage.job_repository import StoredJobRun


def test_deployment_known_hosts_file_includes_engagement_and_deployment(tmp_path):
    path = deployment_known_hosts_file(tmp_path, "eng/a86", "job/core:001")

    assert str(path).endswith("eng_a86-job_core_001.known_hosts")


def test_latest_core_connection_details_returns_latest_job_with_details():
    older = _job("job-old", "2026-06-01T00:00:00+00:00", "198.51.100.10")
    newer = _job("job-new", "2026-06-02T00:00:00+00:00", "198.51.100.20")
    repo = _FakeJobRepository([newer, older])

    deployment_id, details = latest_core_connection_details(repo, "eng-zy01")

    assert deployment_id == "job-new"
    assert details[0]["publicIp"] == "198.51.100.20"


def test_active_core_connection_details_ignores_newer_non_core_event_with_duplicate_private_cidr():
    core = _job("job-core", "2026-06-01T00:00:00+00:00", "198.51.100.10")
    stale = StoredJobRun(
        id="job-stale-channel",
        action="outbound_channel_apply",
        status="succeeded",
        target="engagement:eng-zy01",
        target_type="engagement",
        target_id="eng-zy01",
        requested_by="operator",
        input={"engagementId": "eng-zy01"},
        artifact_refs=[],
        created_at="2026-06-02T00:00:00+00:00",
        started_at="2026-06-02T00:00:00+00:00",
        finished_at="2026-06-02T00:00:00+00:00",
        events=[
            JobEvent(
                1,
                "info",
                "stale channel evidence",
                {"connectionDetails": [{"role": "homebase", "publicIp": "198.51.100.99", "privateIp": "192.168.0.10"}]},
            )
        ],
    )
    repo = _FakeJobRepository([stale, core])

    deployment_id, details = active_core_connection_details(repo, "eng-zy01")

    assert deployment_id == "job-core"
    assert details[0]["publicIp"] == "198.51.100.10"


def _job(job_id: str, created_at: str, public_ip: str) -> StoredJobRun:
    return StoredJobRun(
        id=job_id,
        action="pilot_standard_rti_guarded_execute",
        status="succeeded",
        target="engagement:eng-zy01",
        target_type="engagement",
        target_id="eng-zy01",
        requested_by="operator",
        input={"engagementId": "eng-zy01"},
        artifact_refs=[],
        created_at=created_at,
        started_at=created_at,
        finished_at=created_at,
        events=[
            JobEvent(
                1,
                "info",
                "operator inspection ready",
                {"connectionDetails": [{"role": "homebase", "publicIp": public_ip}]},
            )
        ],
    )


class _FakeJobRepository:
    def __init__(self, jobs):
        self.jobs = list(jobs)

    def list(self):
        raise AssertionError("core lookup must not scan all jobs")

    def list_for_engagement(self, engagement_id):
        return [job for job in self.jobs if job.input.get("engagementId") == engagement_id]

    def get(self, job_id):
        return next((job for job in self.jobs if job.id == job_id), None)

    def save(self, job):
        self.jobs.insert(0, job)
        return job
