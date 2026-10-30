# Copyright (c) 2026, Oracle and/or its affiliates.
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.domain import JobEvent
from app.core.request_identity import RequestIdentity, bind_request_identity
from app.services.inbound_channel_batch import (
    InboundChannelBatchConflictError,
    prepare_reviewed_inbound_channel,
    preview_inbound_channel_batch,
    recover_interrupted_inbound_channel_batches,
    retry_inbound_channel_batch,
    start_inbound_channel_batch,
)
from app.services.inbound_channel_workflow import InboundChannelWorkflowValidationError
from app.storage.job_repository import StoredJobRun


class FakeJobs:
    def __init__(self):
        self.rows = {}

    def save(self, job):
        self.rows[job.id] = job
        return job

    def get(self, job_id):
        return self.rows.get(job_id)

    def list(self):
        return list(self.rows.values())

    def list_for_engagement(self, engagement_id, *, limit=None):
        rows = [job for job in self.rows.values() if job.target_id == engagement_id]
        return rows[:limit] if limit else rows


class ParentPostCommitReadbackFailureJobs(FakeJobs):
    def __init__(self):
        super().__init__()
        self.failed_once = False

    def save(self, job):
        super().save(job)
        if job.action == "inbound_channel_batch_apply" and not self.failed_once:
            self.failed_once = True
            raise RuntimeError("parent readback failed after commit")
        return job


class PreparePostCommitResponseFailureJobs(FakeJobs):
    def __init__(self):
        super().__init__()
        self.failed_once = False

    def save(self, job):
        super().save(job)
        if job.action == "inbound_channel_prepare" and not self.failed_once:
            self.failed_once = True
            raise RuntimeError("prepare response lost after commit")
        return job


class FakeLeases:
    def __init__(self):
        self.owner = ""
        self.released = []

    def acquire(self, _engagement_id, owner_id, _operation):
        if self.owner and self.owner != owner_id:
            from app.storage.deployment_plan_repository import DeploymentPlanConflictError
            raise DeploymentPlanConflictError("busy")
        self.owner = owner_id
        return True

    def release(self, engagement_id, owner_id):
        if self.owner == owner_id:
            self.owner = ""
        self.released.append((engagement_id, owner_id))


def test_prepare_reviewed_single_channel_is_atomic_idempotent_and_zero_infrastructure(monkeypatch):
    overview = _overview()
    existing_channel = {**_tcp("18079"), "channelId": "channel-existing", "status": "Removed"}
    overview["inboundChannels"] = [existing_channel]
    jobs = FakeJobs()
    leases = FakeLeases()
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: overview)
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)
    monkeypatch.setattr("app.services.inbound_channel_batch.update_operations_overview", lambda *_args: pytest.fail("must use one audit save"))
    body = _tcp("18080")
    submission = str(uuid4())
    preview = preview_inbound_channel_batch("eng-zy01", submission, [body])

    result = prepare_reviewed_inbound_channel(
        "eng-zy01", submission, preview["previewFingerprint"], body,
        repository=jobs, lease_repository=leases,
    )

    assert result["status"] == "Pending Apply"
    assert result["channel"]["chainId"] == body["chainId"]
    assert result["channel"]["edgeComponentId"] == body["edgeComponentId"]
    assert result["channel"]["rawRoutePlan"] == preview["channels"][0]["rawRoutePlan"]
    assert result["channel"]["validation"]["detail"] == "Saved for review. No infrastructure changes have run."
    assert len(jobs.rows) == 1
    job = next(iter(jobs.rows.values()))
    assert (job.action, job.status, job.input["mutation"]) == ("inbound_channel_prepare", "succeeded", False)
    assert job.events[0].data["inboundChannels"][-1] == result["channel"]
    assert job.events[0].data["inboundChannels"][0] == existing_channel
    assert leases.owner == ""

    monkeypatch.setattr(
        "app.services.inbound_channel_batch.get_operations_overview",
        lambda _id: pytest.fail("idempotent replay must precede mutable claim reads"),
    )
    replay = prepare_reviewed_inbound_channel(
        "eng-zy01", submission, preview["previewFingerprint"], body,
        repository=jobs, lease_repository=leases,
    )
    assert replay["job"]["id"] == result["job"]["id"]
    assert len(jobs.rows) == 1

    lookups = iter([None, job])
    monkeypatch.setattr("app.services.inbound_channel_batch._prepare_submission_job", lambda *_args: next(lookups))
    late_replay = prepare_reviewed_inbound_channel(
        "eng-zy01", submission, preview["previewFingerprint"], body,
        repository=jobs, lease_repository=leases,
    )
    assert late_replay["job"]["id"] == result["job"]["id"]
    assert len(jobs.rows) == 1


def test_prepare_rejects_invalid_submission_and_durable_or_active_mutation_without_write(monkeypatch):
    overview = _overview()
    jobs = FakeJobs()
    leases = FakeLeases()
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: overview)
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)
    body = _tcp("18080")

    with pytest.raises(InboundChannelWorkflowValidationError):
        prepare_reviewed_inbound_channel("eng-zy01", "not-a-uuid", "f" * 64, body, repository=jobs, lease_repository=leases)
    assert jobs.rows == {}

    preview = preview_inbound_channel_batch("eng-zy01", str(uuid4()), [body])
    leases.owner = "core-deploy-job"
    with pytest.raises(InboundChannelBatchConflictError):
        prepare_reviewed_inbound_channel(
            "eng-zy01", preview["submissionId"], preview["previewFingerprint"], body,
            repository=jobs, lease_repository=leases,
        )
    assert jobs.rows == {}

    leases.owner = ""
    jobs.save(_job("job-active", "inbound_channel_apply", "running"))
    with pytest.raises(InboundChannelBatchConflictError):
        prepare_reviewed_inbound_channel(
            "eng-zy01", preview["submissionId"], preview["previewFingerprint"], body,
            repository=jobs, lease_repository=leases,
        )
    assert list(jobs.rows) == ["job-active"]


def test_prepare_never_enters_apply_or_runtime_runner_seams(monkeypatch):
    overview = _overview()
    jobs = FakeJobs()
    leases = FakeLeases()
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: overview)
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)
    monkeypatch.setattr("app.services.inbound_channel_batch.start_inbound_channel_apply", lambda *_args, **_kwargs: pytest.fail("apply runner invoked"))
    monkeypatch.setattr("app.services.inbound_channel_batch.start_runtime_task", lambda *_args, **_kwargs: pytest.fail("runtime runner invoked"))
    body = _tcp("18080")
    preview = preview_inbound_channel_batch("eng-zy01", str(uuid4()), [body])

    result = prepare_reviewed_inbound_channel(
        "eng-zy01", preview["submissionId"], preview["previewFingerprint"], body,
        repository=jobs, lease_repository=leases,
    )

    assert result["job"]["status"] == "succeeded"
    assert result["job"]["artifactRefs"] == []


def test_preview_fingerprint_is_bound_to_immutable_engagement_id(monkeypatch):
    overview = _overview()
    jobs = FakeJobs()
    leases = FakeLeases()
    monkeypatch.setattr(
        "app.services.inbound_channel_batch.get_engagement",
        lambda engagement_id: SimpleNamespace(name="SAME") if engagement_id in {"eng-a", "eng-b"} else None,
    )
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: overview)
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)
    body = _tcp("18080")
    submission = str(uuid4())
    preview_a = preview_inbound_channel_batch("eng-a", submission, [body])
    preview_b = preview_inbound_channel_batch("eng-b", submission, [body])

    assert preview_a["previewFingerprint"] != preview_b["previewFingerprint"]
    same = prepare_reviewed_inbound_channel(
        "eng-a", submission, preview_a["previewFingerprint"], body,
        repository=jobs, lease_repository=leases,
    )
    assert same["status"] == "Pending Apply"

    with pytest.raises(InboundChannelBatchConflictError) as prepare_error:
        prepare_reviewed_inbound_channel(
            "eng-b", str(uuid4()), preview_a["previewFingerprint"], body,
            repository=jobs, lease_repository=leases,
        )
    assert "stale" in prepare_error.value.errors[0]
    with pytest.raises(InboundChannelBatchConflictError) as batch_error:
        start_inbound_channel_batch(
            "eng-b", str(uuid4()), preview_a["previewFingerprint"], [body],
            repository=jobs, lease_repository=leases,
            background_runner=lambda _task: pytest.fail("cross-engagement batch scheduled"),
        )
    assert "stale" in batch_error.value.errors[0]


def test_prepare_uses_authenticated_actor_and_replays_after_post_commit_response_loss(monkeypatch):
    overview = _overview()
    jobs = PreparePostCommitResponseFailureJobs()
    leases = FakeLeases()
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: overview)
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)
    body = _tcp("18080")
    submission = str(uuid4())
    preview = preview_inbound_channel_batch("eng-zy01", submission, [body])
    identity = RequestIdentity("member-example_operator_three", "example_operator_three", ("administrator",), "session-1")

    with bind_request_identity(identity), pytest.raises(RuntimeError, match="response lost"):
        prepare_reviewed_inbound_channel(
            "eng-zy01", submission, preview["previewFingerprint"], body,
            requested_by="forged-user", repository=jobs, lease_repository=leases,
        )

    replay = prepare_reviewed_inbound_channel(
        "eng-zy01", submission, preview["previewFingerprint"], body,
        requested_by="another-forgery", repository=jobs, lease_repository=leases,
    )
    assert replay["job"]["requestedBy"] == "example_operator_three"
    assert len(jobs.rows) == 1


def test_prepare_rejects_changed_submission_and_stale_review_without_write(monkeypatch):
    overview = _overview()
    jobs = FakeJobs()
    leases = FakeLeases()
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: overview)
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)
    body = _tcp("18080")
    submission = str(uuid4())
    preview = preview_inbound_channel_batch("eng-zy01", submission, [body])
    prepare_reviewed_inbound_channel("eng-zy01", submission, preview["previewFingerprint"], body, repository=jobs, lease_repository=leases)

    with pytest.raises(InboundChannelBatchConflictError, match="workflow validation failed"):
        prepare_reviewed_inbound_channel(
            "eng-zy01", submission, preview["previewFingerprint"], {**body, "edgeComponentId": "changed"},
            repository=jobs, lease_repository=leases,
        )
    with pytest.raises(InboundChannelBatchConflictError):
        prepare_reviewed_inbound_channel(
            "eng-zy01", str(uuid4()), "0" * 64, body, repository=jobs, lease_repository=leases,
        )
    assert len(jobs.rows) == 1


def test_prepare_lease_covers_fresh_read_and_rederive(monkeypatch):
    jobs = FakeJobs()
    leases = FakeLeases()
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr(
        "app.services.inbound_channel_batch.get_operations_overview",
        lambda _id: _overview() if leases.owner else pytest.fail("fresh read occurred outside durable lease"),
    )
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)
    body = _tcp("18080")
    overview = _overview()
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: overview)
    preview = preview_inbound_channel_batch("eng-zy01", str(uuid4()), [body])
    monkeypatch.setattr(
        "app.services.inbound_channel_batch.get_operations_overview",
        lambda _id: overview if leases.owner else pytest.fail("fresh read occurred outside durable lease"),
    )

    prepare_reviewed_inbound_channel(
        "eng-zy01", preview["submissionId"], preview["previewFingerprint"], body,
        repository=jobs, lease_repository=leases,
    )
    assert leases.released


def test_preview_projects_udp_relays_and_does_not_persist(monkeypatch):
    overview = _overview()
    updates = []
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: overview)
    monkeypatch.setattr("app.services.inbound_channel_batch.update_operations_overview", lambda *_args: updates.append(_args))
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)

    result = preview_inbound_channel_batch("eng-zy01", str(uuid4()), [_udp("53"), _udp("54")])

    assert [row["relayPort"] for row in result["channels"]] == ["8000", "8001"]
    assert len(result["previewFingerprint"]) == 64
    assert updates == []


@pytest.mark.parametrize("channels,error", [([], "add at least one"), ([{}] * 21, "at most 20")])
def test_preview_enforces_batch_bounds(monkeypatch, channels, error):
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: _overview())
    with pytest.raises(InboundChannelWorkflowValidationError) as exc:
        preview_inbound_channel_batch("eng-zy01", str(uuid4()), channels)
    assert error in exc.value.errors[0]


def test_preflight_aggregates_indexed_errors_without_mutation(monkeypatch):
    updates = []
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: _overview())
    monkeypatch.setattr("app.services.inbound_channel_batch.update_operations_overview", lambda *_args: updates.append(_args))
    with pytest.raises(InboundChannelWorkflowValidationError) as exc:
        preview_inbound_channel_batch("eng-zy01", str(uuid4()), [{"edge": "missing"}, {"edge": "also-missing"}])
    assert any(error.startswith("row 1:") for error in exc.value.errors)
    assert any(error.startswith("row 2:") for error in exc.value.errors)
    assert updates == []


def test_preflight_rejects_provider_readiness_before_mutation(monkeypatch):
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: _overview())
    monkeypatch.setattr("app.services.inbound_channel_batch.has_runtime_context", lambda: True)
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)
    monkeypatch.setattr(
        "app.services.inbound_channel_batch.provider_ingress_preflight_errors",
        lambda *_args, **_kwargs: ["edge provider workspace is unavailable"],
    )

    with pytest.raises(InboundChannelWorkflowValidationError) as exc:
        preview_inbound_channel_batch("eng-zy01", str(uuid4()), [_tcp("18080")])

    assert exc.value.errors == ["row 1: edge provider workspace is unavailable"]


def test_reservation_failure_terminalizes_parent_and_releases_lease(monkeypatch):
    state = _overview()
    jobs = FakeJobs()
    leases = FakeLeases()
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: state)
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)
    monkeypatch.setattr("app.services.inbound_channel_batch.update_operations_overview", lambda *_args: (_ for _ in ()).throw(RuntimeError("write failed")))
    submission = str(uuid4())
    bodies = [_tcp("18080")]
    preview = preview_inbound_channel_batch("eng-zy01", submission, bodies)

    with pytest.raises(RuntimeError, match="write failed"):
        start_inbound_channel_batch(
            "eng-zy01", submission, preview["previewFingerprint"], bodies,
            repository=jobs, lease_repository=leases,
        )

    parent = next(job for job in jobs.list() if job.action == "inbound_channel_batch_apply")
    assert parent.status == "failed"
    assert leases.owner == ""
    assert leases.released == [("eng-zy01", parent.id)]


def test_parent_post_commit_readback_failure_terminalizes_parent_and_releases_lease(monkeypatch):
    state = _overview()
    jobs = ParentPostCommitReadbackFailureJobs()
    leases = FakeLeases()
    updates = []
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: state)
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)
    monkeypatch.setattr("app.services.inbound_channel_batch.update_operations_overview", lambda *_args: updates.append(_args))
    submission = str(uuid4())
    bodies = [_tcp("18080")]
    preview = preview_inbound_channel_batch("eng-zy01", submission, bodies)

    with pytest.raises(RuntimeError, match="parent readback failed after commit"):
        start_inbound_channel_batch(
            "eng-zy01", submission, preview["previewFingerprint"], bodies,
            repository=jobs, lease_repository=leases,
        )

    parent = next(job for job in jobs.list() if job.action == "inbound_channel_batch_apply")
    assert parent.status == "failed"
    assert parent.finished_at is not None
    assert updates == [("eng-zy01", {"inboundChannels": []})]
    assert leases.owner == ""
    assert leases.released == [("eng-zy01", parent.id)]


def test_reservation_readback_failure_restores_pre_batch_projection(monkeypatch):
    state = _overview()
    jobs = FakeJobs()
    leases = FakeLeases()
    writes = 0
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: state)
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)

    def update(_engagement_id, body):
        nonlocal writes
        writes += 1
        state.update(body)
        if writes == 1:
            raise RuntimeError("projection failed after commit")

    monkeypatch.setattr("app.services.inbound_channel_batch.update_operations_overview", update)
    submission = str(uuid4())
    bodies = [_tcp("18080")]
    preview = preview_inbound_channel_batch("eng-zy01", submission, bodies)

    with pytest.raises(RuntimeError, match="projection failed after commit"):
        start_inbound_channel_batch(
            "eng-zy01", submission, preview["previewFingerprint"], bodies,
            repository=jobs, lease_repository=leases,
        )

    assert writes == 2
    assert state["inboundChannels"] == []
    assert next(job for job in jobs.list() if job.action == "inbound_channel_batch_apply").status == "failed"
    assert leases.owner == ""


def test_parent_rejects_secret_markers_and_releases_lease(monkeypatch):
    state = _overview()
    jobs = FakeJobs()
    leases = FakeLeases()
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: state)
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)
    body = {**_tcp("18080"), "purpose": "LINODE_TOKEN must not be persisted"}
    submission = str(uuid4())
    preview = preview_inbound_channel_batch("eng-zy01", submission, [body])

    with pytest.raises(Exception) as exc:
        start_inbound_channel_batch(
            "eng-zy01", submission, preview["previewFingerprint"], [body],
            repository=jobs, lease_repository=leases,
        )

    assert "forbidden secret marker" in exc.value.errors[0]
    assert jobs.list() == []
    assert leases.owner == ""


def test_scheduler_compensation_failure_still_releases_lease(monkeypatch):
    state = _overview()
    jobs = FakeJobs()
    leases = FakeLeases()
    writes = 0
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: state)
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)

    def update(_engagement_id, body):
        nonlocal writes
        writes += 1
        if writes > 1:
            raise RuntimeError("compensation projection failed")
        state.update(body)

    monkeypatch.setattr("app.services.inbound_channel_batch.update_operations_overview", update)
    submission = str(uuid4())
    bodies = [_tcp("18080")]
    preview = preview_inbound_channel_batch("eng-zy01", submission, bodies)
    result = start_inbound_channel_batch(
        "eng-zy01", submission, preview["previewFingerprint"], bodies,
        repository=jobs,
        lease_repository=leases,
        background_runner=lambda _task: (_ for _ in ()).throw(RuntimeError("scheduler failed")),
    )

    assert jobs.get(result["batchId"]).status == "failed"
    assert leases.owner == ""


def test_create_requires_exact_review_and_is_idempotent(monkeypatch):
    state = _overview()
    jobs = FakeJobs()
    calls = []
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: state)
    monkeypatch.setattr("app.services.inbound_channel_batch.update_operations_overview", lambda _id, body: state.update(body))
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)

    def apply(_engagement_id, channel_id, **_kwargs):
        calls.append(channel_id)
        child = replace(_job(f"child-{len(calls)}", "inbound_channel_apply", "succeeded"), input={"channelId": channel_id})
        jobs.save(child)
        jobs.save(replace(_job(f"validation-{len(calls)}", "inbound_channel_validation", "succeeded"), input={"channelId": channel_id}))
        return {"job": child.to_detail().to_dict(), "status": "Pending Apply"}

    monkeypatch.setattr("app.services.inbound_channel_batch.start_inbound_channel_apply", apply)
    submission = str(uuid4())
    bodies = [_tcp("18080"), _tcp("18081")]
    preview = preview_inbound_channel_batch("eng-zy01", submission, bodies)
    first = start_inbound_channel_batch(
        "eng-zy01", submission, preview["previewFingerprint"], bodies,
        repository=jobs, background_runner=lambda task: task(),
    )
    second = start_inbound_channel_batch(
        "eng-zy01", submission, preview["previewFingerprint"], bodies,
        repository=jobs, background_runner=lambda task: task(),
    )

    assert first["batchId"] == second["batchId"]
    assert calls == [first["channels"][0]["channelId"], first["channels"][1]["channelId"]]
    assert jobs.get(first["batchId"]).status == "succeeded"


def test_stale_preview_rejects_before_reservation(monkeypatch):
    state = _overview()
    updates = []
    jobs = FakeJobs()
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: state)
    monkeypatch.setattr("app.services.inbound_channel_batch.update_operations_overview", lambda *_args: updates.append(_args))
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)
    submission = str(uuid4())
    bodies = [_tcp("18080")]
    preview = preview_inbound_channel_batch("eng-zy01", submission, bodies)
    state["inboundChannels"] = [{**preview["channels"][0], "channelId": "unrelated-new-claim"}]

    with pytest.raises(InboundChannelBatchConflictError):
        start_inbound_channel_batch("eng-zy01", submission, preview["previewFingerprint"], bodies, repository=jobs)
    assert updates == []
    assert jobs.list() == []


def test_component_replacement_after_preview_rejects_before_job_or_reservation(monkeypatch):
    state = _overview()
    updates = []
    jobs = FakeJobs()
    leases = FakeLeases()
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: state)
    monkeypatch.setattr("app.services.inbound_channel_batch.update_operations_overview", lambda *_args: updates.append(_args))
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)
    submission = str(uuid4())
    bodies = [_tcp("18080")]
    preview = preview_inbound_channel_batch("eng-zy01", submission, bodies)
    state["sketchInfrastructure"][1]["componentId"] = "edge-sea-replacement"

    with pytest.raises(InboundChannelBatchConflictError):
        start_inbound_channel_batch(
            "eng-zy01", submission, preview["previewFingerprint"], bodies,
            repository=jobs, lease_repository=leases,
        )

    assert jobs.list() == []
    assert updates == []
    assert leases.owner == ""


def test_batch_exact_tuple_disambiguates_repeated_component_id_across_chains(monkeypatch):
    state = _overview()
    state["coreInfrastructure"].append({
        "hostname": "proxy02-zy01", "expectedHostname": "proxy02-zy01", "hostId": "proxy02", "logicalName": "proxy02", "role": "proxy", "publicIp": "203.0.113.12", "privateIp": "192.168.2.12",
    })
    state["sketchInfrastructure"].extend([
        {
            "chainId": "proxy02-chain-001", "componentId": "middle-02",
            "hostname": "middle02-zy01", "role": "middle", "proxy": "proxy02", "assignedProxyId": "proxy02", "status": "deployed",
        },
        {
            "chainId": "proxy02-chain-001", "componentId": "edge-sea-01",
            "hostname": "edge02-zy01", "role": "edge", "proxy": "proxy02", "assignedProxyId": "proxy02", "status": "deployed",
        },
    ])
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: state)
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)
    body = {
        **_tcp("18080"), "edge": "edge02-zy01", "chainId": "proxy02-chain-001",
        "edgeComponentId": "edge-sea-01", "terminatesOn": "proxy02",
    }

    result = preview_inbound_channel_batch("eng-zy01", str(uuid4()), [body])

    assert result["channels"][0]["chainId"] == "proxy02-chain-001"
    assert result["channels"][0]["edge"] == "edge02-zy01"
    assert result["channels"][0]["middleComponentId"] == "middle-02"


def test_child_failure_stops_later_rows_and_retains_success(monkeypatch):
    state = _overview()
    jobs = FakeJobs()
    calls = []
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: state)
    monkeypatch.setattr("app.services.inbound_channel_batch.update_operations_overview", lambda _id, body: state.update(body))
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)

    def apply(_engagement_id, channel_id, **_kwargs):
        calls.append(channel_id)
        status = "succeeded" if len(calls) == 1 else "failed"
        child = replace(_job(f"child-{len(calls)}", "inbound_channel_apply", status), input={"channelId": channel_id})
        jobs.save(child)
        if status == "succeeded":
            jobs.save(replace(_job(f"validation-{len(calls)}", "inbound_channel_validation", "succeeded"), input={"channelId": channel_id}))
        return {"job": child.to_detail().to_dict(), "status": "Pending Apply"}

    monkeypatch.setattr("app.services.inbound_channel_batch.start_inbound_channel_apply", apply)
    submission = str(uuid4())
    bodies = [_tcp("18080"), _tcp("18081"), _tcp("18082")]
    preview = preview_inbound_channel_batch("eng-zy01", submission, bodies)
    result = start_inbound_channel_batch(
        "eng-zy01", submission, preview["previewFingerprint"], bodies,
        repository=jobs, background_runner=lambda task: task(),
    )
    parent = jobs.get(result["batchId"])

    assert len(calls) == 2
    assert [child["status"] for child in parent.input["children"]] == ["validated", "failed", "not_started"]
    assert parent.status == "failed"
    assert parent.input["retryRequired"] is True


def test_restart_recovery_marks_interrupted_row_for_inspection(monkeypatch):
    jobs = FakeJobs()
    state = _overview()
    state["inboundChannels"] = [
        {**_tcp("18080"), "channelId": "one", "status": "Active"},
        {**_tcp("18081"), "channelId": "two", "status": "Applying"},
    ]
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: state)
    monkeypatch.setattr("app.services.inbound_channel_batch.update_operations_overview", lambda _id, body: state.update(body))
    parent = replace(
        _job("job-batch", "inbound_channel_batch_apply", "running"),
        input={"children": [{"channelId": "one", "status": "succeeded"}, {"channelId": "two", "status": "running"}]},
    )
    child = replace(
        _job("job-child", "inbound_channel_apply", "running"),
        input={"channelId": "two"},
    )
    jobs.save(parent)
    jobs.save(child)
    assert recover_interrupted_inbound_channel_batches(repository=jobs) == 1
    recovered = jobs.get(parent.id)
    assert recovered.status == "failed"
    assert [row["status"] for row in recovered.input["children"]] == ["succeeded", "failed"]
    assert jobs.get(child.id).status == "failed"
    assert state["inboundChannels"][1]["status"] == "Recovery Required"


def test_restart_projection_failure_does_not_leak_lease_or_abort(monkeypatch):
    jobs = FakeJobs()
    leases = FakeLeases()
    parent = replace(
        _job("job-batch", "inbound_channel_batch_apply", "running"),
        input={"children": [{"channelId": "one", "status": "queued"}]},
    )
    jobs.save(parent)
    leases.acquire("eng-zy01", parent.id, "inbound_channel_batch_apply")
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: {"inboundChannels": [{"channelId": "one"}]})
    monkeypatch.setattr("app.services.inbound_channel_batch.update_operations_overview", lambda *_args: (_ for _ in ()).throw(RuntimeError("projection unavailable")))

    assert recover_interrupted_inbound_channel_batches(repository=jobs, lease_repository=leases) == 1
    assert jobs.get(parent.id).status == "failed"
    assert leases.owner == ""


def test_validation_failure_does_not_block_later_rows(monkeypatch):
    state = _overview()
    jobs = FakeJobs()
    calls = []
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: state)
    monkeypatch.setattr("app.services.inbound_channel_batch.update_operations_overview", lambda _id, body: state.update(body))
    monkeypatch.setattr("app.services.inbound_channel_batch.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)

    def apply(_engagement_id, channel_id, **_kwargs):
        calls.append(channel_id)
        child = replace(_job(f"apply-{len(calls)}", "inbound_channel_apply", "succeeded"), input={"channelId": channel_id})
        jobs.save(child)
        validation_status = "failed" if len(calls) == 1 else "succeeded"
        validation = replace(
            _job(f"validation-{len(calls)}", "inbound_channel_validation", validation_status),
            input={"channelId": channel_id},
        )
        jobs.save(validation)
        return {"job": child.to_detail().to_dict(), "status": "Pending Apply"}

    monkeypatch.setattr("app.services.inbound_channel_batch.start_inbound_channel_apply", apply)
    submission = str(uuid4())
    bodies = [_tcp("18080"), _tcp("18081")]
    preview = preview_inbound_channel_batch("eng-zy01", submission, bodies)
    result = start_inbound_channel_batch(
        "eng-zy01", submission, preview["previewFingerprint"], bodies,
        repository=jobs, background_runner=lambda task: task(),
    )
    parent = jobs.get(result["batchId"])

    assert len(calls) == 2
    assert [row["status"] for row in parent.input["children"]] == ["validation_failed", "validated"]
    assert parent.status == "failed"
    assert parent.input["completedWithIssues"] is True
    assert parent.input["retryRequired"] is False


def test_retry_revalidates_validation_failure_without_reapplying(monkeypatch):
    state = _overview()
    channel = {**_tcp("18080"), "channelId": "one", "status": "Validation Failed"}
    state["inboundChannels"] = [channel]
    jobs = FakeJobs()
    source = replace(
        _job("job-source", "inbound_channel_batch_apply", "failed"),
        input={"children": [{"channelId": "one", "status": "validation_failed"}], "previewFingerprint": "reviewed"},
    )
    jobs.save(source)
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: state)
    monkeypatch.setattr("app.services.inbound_channel_batch.update_operations_overview", lambda _id, body: state.update(body))
    monkeypatch.setattr("app.services.inbound_channel_batch.start_inbound_channel_apply", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not reapply")))

    def validate(_engagement_id, channel_id, **_kwargs):
        job = replace(_job("job-validation", "inbound_channel_validation", "succeeded"), input={"channelId": channel_id})
        jobs.save(job)
        return {"job": job.to_detail().to_dict(), "status": "Validated"}

    monkeypatch.setattr("app.services.inbound_channel_batch.validate_inbound_channel", validate)
    result = retry_inbound_channel_batch(
        "eng-zy01", source.id, repository=jobs, background_runner=lambda task: task(),
    )
    parent = jobs.get(result["batchId"])
    assert parent.status == "succeeded"
    assert parent.input["children"][0]["status"] == "validated"
    assert parent.input["children"][0]["validationJobId"] == "job-validation"


def test_retry_reservation_readback_failure_restores_pre_retry_projection(monkeypatch):
    state = _overview()
    channel = {**_tcp("18080"), "channelId": "one", "status": "Failed"}
    state["inboundChannels"] = [channel]
    jobs = FakeJobs()
    leases = FakeLeases()
    source = replace(
        _job("job-source", "inbound_channel_batch_apply", "failed"),
        input={"children": [{"channelId": "one", "status": "failed"}], "previewFingerprint": "reviewed"},
    )
    jobs.save(source)
    writes = 0
    monkeypatch.setattr("app.services.inbound_channel_batch.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_batch.get_operations_overview", lambda _id: state)

    def update(_engagement_id, body):
        nonlocal writes
        writes += 1
        state.update(body)
        if writes == 1:
            raise RuntimeError("retry projection failed after commit")

    monkeypatch.setattr("app.services.inbound_channel_batch.update_operations_overview", update)

    with pytest.raises(RuntimeError, match="retry projection failed after commit"):
        retry_inbound_channel_batch(
            "eng-zy01", source.id, repository=jobs, lease_repository=leases,
        )

    retry_parent = next(job for job in jobs.list() if job.id != source.id)
    assert writes == 2
    assert state["inboundChannels"] == [channel]
    assert retry_parent.status == "failed"
    assert retry_parent.input["children"][0]["status"] == "not_started"
    assert retry_parent.input["retryRequired"] is True
    assert leases.owner == ""
    assert leases.released == [("eng-zy01", retry_parent.id)]


def _tcp(port):
    return {
        "edge": "edge-zy01-us-sea-01",
        "chainId": "proxy01-chain-001",
        "edgeComponentId": "edge-sea-01",
        "protocol": "TCP",
        "mode": "tcp-forward",
        "externalPort": port,
        "terminatesOn": "homebase",
        "internalPort": port,
    }


def _udp(port):
    return {
        "edge": "edge-zy01-us-sea-01",
        "chainId": "proxy01-chain-001",
        "edgeComponentId": "edge-sea-01",
        "protocol": "UDP",
        "mode": "udp-forward",
        "externalPort": port,
        "terminatesOn": "homebase",
        "internalPort": f"53{port}",
    }


def _job(job_id, action, status):
    return StoredJobRun(
        id=job_id,
        action=action,
        status=status,
        target="engagement:eng-zy01",
        target_type="engagement",
        target_id="eng-zy01",
        requested_by="operator",
        input={},
        artifact_refs=[],
        created_at="2026-09-09T00:00:00+00:00",
        started_at=None,
        finished_at=None,
        events=[JobEvent(1, "info", "test", {})],
    )


def _overview():
    return {
        "coreInfrastructure": [
            {"hostname": "homebase-zy01", "expectedHostname": "homebase-zy01", "hostId": "homebase", "logicalName": "homebase", "role": "homebase", "publicIp": "203.0.113.10", "privateIp": "192.168.0.10"},
            {"hostname": "proxy01-zy01", "expectedHostname": "proxy01-zy01", "hostId": "proxy01", "logicalName": "proxy01", "role": "proxy", "publicIp": "203.0.113.11", "privateIp": "192.168.2.11"},
        ],
        "sketchInfrastructure": [
            {
                "chainId": "proxy01-chain-001", "componentId": "middle-01",
                "hostname": "middle01-zy01", "role": "middle", "proxy": "proxy01", "assignedProxyId": "proxy01",
                "status": "deployed",
            },
            {
                "chainId": "proxy01-chain-001", "componentId": "edge-sea-01",
                "hostname": "edge-zy01-us-sea-01", "role": "edge", "proxy": "proxy01", "assignedProxyId": "proxy01",
                "status": "deployed",
            },
        ],
        "servicePlacements": [],
        "inboundChannels": [],
    }
