# Copyright (c) 2026, Oracle and/or its affiliates.
"""Public service reservation for one published, channel-free keyed append."""

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from app.asgi import create_app
from app.core.config import TestConfig
from app.core.runtime import runtime_context
from app.services.provider_keyed_initial_continuation import _job_ids
from app.services import engagement_teardown as teardown
from app.services.provider_keyed_append_source import audit_published_provider_keyed_append_source
from app.services.provider_keyed_published_dispatch import (
    _require_reviewed_shape, require_prequeue_published_generation,
)
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.models import CoreMutationLeaseModel
from app.storage.provider_resource_repository import (
    SqlAlchemyProviderResourceRepository, StoredProviderResourceRecord,
)
import test_provider_keyed_append_source as append_fixture
from test_provider_keyed_append_source import _case, _reviewed_append_parent


def test_start_reserves_reviewed_five_node_parent_once(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        core_id, engagement_id, _state_sha, _added = _case(client, tmp_path, monkeypatch)
        jobs, proposal = _reviewed_append_parent(core_id, engagement_id, tmp_path)
        snapshot = proposal.input["scopeSnapshot"]
        source = audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)
        invoked = []

        def coordinator(parent_id):
            current = jobs.get(parent_id)
            assert current.status == "queued"
            assert current.input["scopeSnapshot"] == snapshot
            assert current.input["publishedAppendSource"]["append_job_id"] == source.append_job_id
            invoked.append(parent_id)
            return current

        options = dict(job_repository=jobs, provider_keyed_coordinator=coordinator,
                       provider_keyed_environment="devtest",
                       provider_keyed_published_source=source,
                       provider_keyed_state_root=tmp_path)
        body = {"confirmation": snapshot["confirmationPhrase"],
                "snapshotId": snapshot["snapshotId"]}
        saved = teardown.start_engagement_teardown(core_id, body, **options)
        assert saved.id == proposal.id and saved.status == "queued"
        assert invoked == [proposal.id]
        lease = db.session.query(CoreMutationLeaseModel).filter_by(
            engagement_id=engagement_id).one()
        assert (lease.owner_id, lease.operation) == (
            source.initial_source.core_plan_id, "provider_keyed_teardown_fence")
        repeated = teardown.start_engagement_teardown(core_id, body, **options)
        assert repeated == saved and invoked == [proposal.id, proposal.id]
        assert len([job for job in jobs.list_for_engagement(engagement_id)
                    if job.action == teardown.ENGAGEMENT_TEARDOWN_ACTION]) == 1


def test_start_rejects_stale_five_node_review_without_reservation(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        core_id, engagement_id, _state_sha, _added = _case(client, tmp_path, monkeypatch)
        jobs, proposal = _reviewed_append_parent(core_id, engagement_id, tmp_path)
        snapshot = proposal.input["scopeSnapshot"]
        source = audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)
        state_path = tmp_path / "provider" / "terraform.tfstate"
        state_path.write_bytes(state_path.read_bytes() + b"\n")
        calls = []
        with pytest.raises((teardown.EngagementTeardownValidationError, ValueError)):
            teardown.start_engagement_teardown(
                core_id, {"confirmation": snapshot["confirmationPhrase"],
                          "snapshotId": snapshot["snapshotId"]},
                job_repository=jobs, provider_keyed_coordinator=lambda pid: calls.append(pid),
                provider_keyed_environment="devtest",
                provider_keyed_published_source=source,
                provider_keyed_state_root=tmp_path)
        assert calls == []
        assert jobs.get(proposal.id) is None
        assert db.session.query(CoreMutationLeaseModel).filter_by(
            engagement_id=engagement_id).count() == 0


def test_ordinary_public_post_reserves_five_node_parent_and_schedules_once(tmp_path, monkeypatch):
    class DevTest(TestConfig):
        ENVIRONMENT = "devtest"
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'public-post.sqlite'}"
        PROVIDER_KEYED_INITIAL_DISPATCH_ENABLED = False
        PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4 = "4.2.2.2"

    app = create_app(DevTest)
    client = app.test_client()
    materialized = append_fixture._materialized_args

    def complete_core_identity(*args, **kwargs):
        engagement, chains, core, plan, profile = materialized(*args, **kwargs)
        event = core.events[0]
        details = [*event.data["connectionDetails"],
                   {"role": "homebase", "displayName": "homebase",
                    "sshAlias": "homebase", "publicIp": "1.1.1.1"}]
        return (engagement, chains, replace(core, events=[replace(event, data={
            **event.data, "connectionDetails": details,
        })]), plan, profile)

    monkeypatch.setattr(append_fixture, "_materialized_args", complete_core_identity)
    with runtime_context(app.state.runtime):
        core_id, engagement_id, _state_sha, _added = _case(client, tmp_path, monkeypatch)
        jobs = SqlAlchemyJobRepository()
        core = jobs.get(core_id)
        instant = datetime.now(timezone.utc).isoformat()
        resources = SqlAlchemyProviderResourceRepository()
        for kind, provider_id in (("inspector_instance", "12345"),
                                  ("inspector_firewall", "67890")):
            adoption_id = f"job-{kind}-adoption"
            jobs.save(replace(core, id=adoption_id, action="inspector_readiness",
                              status="succeeded", target=f"engagement:{engagement_id}",
                              target_type="engagement", target_id=engagement_id,
                              finished_at=instant))
            resources.save(StoredProviderResourceRecord(
                id=f"record-{kind}", engagement_id=engagement_id,
                engagement_name=engagement_id, provider="linode",
                resource_type=kind, resource_id=provider_id,
                name=f"resource-{kind}", region="us-east", lifecycle_state="running",
                status="active", source="inspector", metadata={
                    "barraganOwned": True, "inspectionJobId": adoption_id,
                }, adoption_job_id=adoption_id, adopted_at=instant, updated_at=instant,
            ))
        jobs, proposal = _reviewed_append_parent(core_id, engagement_id, tmp_path)
        initial = jobs.get(_job_ids(core_id)[0])
        jobs.save(replace(initial, input={**initial.input, "phase": "completed"}))
        source = audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)
        snapshot = proposal.input["scopeSnapshot"]
        assert _require_reviewed_shape(jobs.get(core_id), snapshot, jobs)
        assert require_prequeue_published_generation(
            jobs.get(core_id), snapshot, environment="devtest", state_root=tmp_path,
            job_repository=jobs) == source
    monkeypatch.setattr("app.services.sketch_state_workspaces._default_state_root",
                        lambda: tmp_path)
    monkeypatch.setattr("app.services.provider_keyed_comprehensive_teardown.run_provider_keyed_comprehensive_handoff",
                        lambda parent_id, **_kw: jobs.get(parent_id))
    scheduled = []
    monkeypatch.setattr("app.core.runtime.start_runtime_task",
                        lambda task, *, name, **_kw: scheduled.append(name))
    url = f"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/{core_id}/teardown"
    body = {"confirmation": snapshot["confirmationPhrase"],
            "snapshotId": snapshot["snapshotId"]}
    stale = client.post(url, json={**body, "snapshotId": "stale"})
    assert stale.status_code == 409
    with runtime_context(app.state.runtime):
        assert jobs.get(proposal.id) is None
        record = resources.get("record-inspector_firewall")
        resources.save(replace(record, metadata={**record.metadata,
                                                 "inspectionJobId": "other-owner"}))
    unproved = client.post(url, json=body)
    assert unproved.status_code == 409
    with runtime_context(app.state.runtime):
        assert jobs.get(proposal.id) is None
        resources.save(record)
    posted = client.post(url, json=body)
    assert posted.status_code == 200, posted.json()
    assert posted.json()["job"]["id"] == proposal.id
    repeated = client.post(url, json=body)
    assert repeated.status_code == 200, repeated.json()
    assert repeated.json()["job"]["id"] == proposal.id
    assert scheduled.count("barragan-keyed-published-teardown") == 1
    with runtime_context(app.state.runtime):
        parent = jobs.get(proposal.id)
        assert parent.input["publishedAppendSource"]["append_job_id"] == source.append_job_id
        lease = db.session.query(CoreMutationLeaseModel).filter_by(
            engagement_id=engagement_id).one()
        assert (lease.owner_id, lease.operation) == (
            source.initial_source.core_plan_id, "provider_keyed_teardown_fence")
