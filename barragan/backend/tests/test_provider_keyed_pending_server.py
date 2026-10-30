# Copyright (c) 2026, Oracle and/or its affiliates.
"""The DevTest pending teardown route schedules work; it never performs GO."""

from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.asgi import create_app
from app.core.config import TestConfig
from app.core.runtime import runtime_context
from app.domain import JobEvent
from app.services import engagement_teardown, provider_keyed_comprehensive_teardown
from app.services import provider_keyed_pending_dispatch as dispatch
from app.services import provider_keyed_teardown_source
from app.storage.job_repository import SqlAlchemyJobRepository, SqliteJobRepository, StoredJobRun


def _job(identifier, action, status="succeeded", data=None):
    now = "2026-10-10T00:00:00+00:00"
    return StoredJobRun(
        identifier, action, status, "engagement:eng-disposable", "engagement",
        "eng-disposable", "operator", data or {}, [], now,
        now if status != "queued" else None, now if status == "succeeded" else None,
        [JobEvent(1, "info", "fixture", {})],
    )


def test_route_queues_one_pending_teardown_and_rejects_scope_drift_before_writer(
    tmp_path, monkeypatch,
):
    class DevTest(TestConfig):
        ENVIRONMENT = "devtest"
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'route.sqlite'}"
        PROVIDER_KEYED_INITIAL_DISPATCH_ENABLED = False  # Cleanup survives a disabled deploy rollout.
        PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4 = "4.2.2.2"

    scheduled = []
    handoffs = []
    monkeypatch.setattr(
        "app.services.provider_keyed_initial_dispatch.recover_fresh_keyed_initial_dispatches",
        lambda **_kw: pytest.fail("disabled initial deployment recovery ran"),
    )
    monkeypatch.setattr("app.core.runtime.start_runtime_task",
                        lambda task, *, name, **_kw: scheduled.append((task, name)))
    app = create_app(DevTest)
    core = _job("job-core", "pilot_standard_rti_guarded_execute", data={
        "engagementId": "eng-disposable", "sketchStateSchema": "provider-keyed-v2",
    })
    with runtime_context(app.state.runtime):
        SqlAlchemyJobRepository().save(core)

    snapshot = {"snapshotId": "reviewed-snapshot"}
    monkeypatch.setattr(engagement_teardown, "_current_scope_snapshot",
                        lambda *_a, **_kw: snapshot)
    preflights = []
    monkeypatch.setattr(dispatch, "require_prequeue_pending_diagnostic",
                        lambda *_a, **_kw: preflights.append("proved"))
    monkeypatch.setattr(provider_keyed_comprehensive_teardown,
                        "run_provider_keyed_comprehensive_handoff",
                        lambda parent_id, **_kw: handoffs.append(parent_id))

    def queue(core_id, body, *, provider_keyed_coordinator=None, **_kw):
        assert core_id == core.id and body["snapshotId"] == snapshot["snapshotId"]
        existing = SqlAlchemyJobRepository().get(engagement_teardown._parent_id(core.id))
        if existing is not None and existing.status == "succeeded":
            return existing
        if existing is not None and existing.status == "queued":
            provider_keyed_coordinator(existing.id)
            return existing
        parent = _job(engagement_teardown._parent_id(core.id),
                      "engagement_comprehensive_teardown", "queued",
                      {"phase": "queued", "coreJobId": core.id})
        SqlAlchemyJobRepository().save(parent)
        provider_keyed_coordinator(parent.id)
        return parent

    monkeypatch.setattr("app.asgi.start_engagement_teardown", queue)
    wrong = app.test_client().post(f"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/{core.id}/teardown",
                                   json={"snapshotId": "stale"})
    assert wrong.status_code == 409
    with runtime_context(app.state.runtime):
        assert SqlAlchemyJobRepository().get(engagement_teardown._parent_id(core.id)) is None
    good = app.test_client().post(f"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/{core.id}/teardown",
                                  json={"snapshotId": "reviewed-snapshot"})
    assert good.status_code == 200
    assert preflights == ["proved"] and handoffs == [engagement_teardown._parent_id(core.id)]
    assert [name for _task, name in scheduled if name == "barragan-keyed-pending-teardown"] == [
        "barragan-keyed-pending-teardown"]
    with runtime_context(app.state.runtime):
        stored = SqlAlchemyJobRepository().get(handoffs[0])
        assert stored.status == "queued"
        SqlAlchemyJobRepository().save(_job(
            dispatch._child_id(core.id), "provider_keyed_comprehensive_teardown", "queued",
            {"teardownParentId": stored.id, "scopeSnapshotId": snapshot["snapshotId"]},
        ))
    monkeypatch.setattr(provider_keyed_comprehensive_teardown, "_boundary",
                        lambda _id, *_a: (stored, core, snapshot, "provider_keyed_initial"))
    monkeypatch.setattr(dispatch, "_require_diagnostic_scope", lambda *_a: None)
    repeated = app.test_client().post(
        f"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/{core.id}/teardown",
        json={"snapshotId": "reviewed-snapshot"},
    )
    assert repeated.status_code == 200 and len(handoffs) == 2
    assert len([name for _task, name in scheduled
                if name == "barragan-keyed-pending-teardown"]) == 2
    with runtime_context(app.state.runtime):
        SqlAlchemyJobRepository().save(replace(stored, status="succeeded",
                                              finished_at="2026-10-10T00:00:02+00:00"))
    DevTest.PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4 = ""
    again = app.test_client().post(
        f"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/{core.id}/teardown",
        json={"snapshotId": "reviewed-snapshot"},
    )
    assert again.status_code == 200 and again.json()["job"]["status"] == "succeeded"
    assert len(handoffs) == 2
    second = replace(core, id="job-core-2")
    with runtime_context(app.state.runtime):
        SqlAlchemyJobRepository().save(second)
    denied = app.test_client().post(
        f"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/{second.id}/teardown",
        json={"snapshotId": "reviewed-snapshot"},
    )
    assert denied.status_code == 409
    with runtime_context(app.state.runtime):
        assert SqlAlchemyJobRepository().get(engagement_teardown._parent_id(second.id)) is None


def test_route_resumes_failed_prebinding_parent_before_coordinator_exists(tmp_path, monkeypatch):
    class DevTest(TestConfig):
        ENVIRONMENT = "devtest"
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'failed-resume.sqlite'}"
        PROVIDER_KEYED_INITIAL_DISPATCH_ENABLED = False
        PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4 = "4.2.2.2"

    app = create_app(DevTest)
    core = _job("job-core", "pilot_standard_rti_guarded_execute", data={
        "engagementId": "eng-disposable", "sketchStateSchema": "provider-keyed-v2",
    })
    snapshot = {"snapshotId": "sealed-failed-prebinding", "dnsCleanupManifest": {
        "schema": "provider-keyed-empty-dns-prebinding-v1"}}
    parent = _job(engagement_teardown._parent_id(core.id),
                  "engagement_comprehensive_teardown", "queued",
                  {"phase": "queued", "coreJobId": core.id, "scopeSnapshot": snapshot})
    with runtime_context(app.state.runtime):
        SqlAlchemyJobRepository().save(core)
        SqlAlchemyJobRepository().save(parent)
    monkeypatch.setattr(provider_keyed_comprehensive_teardown, "_boundary",
                        lambda *_a: (parent, core, snapshot, "provider_keyed_initial"))
    monkeypatch.setattr(dispatch, "_require_diagnostic_scope", lambda *_a: None)
    monkeypatch.setattr(provider_keyed_teardown_source, "load_keyed_teardown_source",
                        lambda *_a, **_kw: SimpleNamespace(variant="failed_prebinding"))
    monkeypatch.setattr("app.asgi.start_engagement_teardown",
                        lambda *_a, **_kw: parent)
    scheduled = []
    monkeypatch.setattr("app.core.runtime.start_runtime_task",
                        lambda task, *, name, **_kw: scheduled.append(name))

    response = app.test_client().post(
        f"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/{core.id}/teardown",
        json={"snapshotId": snapshot["snapshotId"]},
    )
    assert response.status_code == 200
    assert response.json()["job"]["id"] == parent.id
    assert scheduled == ["barragan-keyed-pending-teardown"]


def test_startup_selector_reschedules_queued_parent_with_existing_child_without_go(tmp_path, monkeypatch):
    database = tmp_path / "restart.sqlite"
    jobs = SqliteJobRepository(database)
    parent = _job("job-parent", "engagement_comprehensive_teardown", "queued",
                  {"phase": "queued", "scopeSnapshot": {"domainAssignments": []}})
    core = _job("job-core", "pilot_standard_rti_guarded_execute", data={"engagementId": parent.target_id})
    child = _job(dispatch._child_id(core.id), "provider_keyed_comprehensive_teardown", "queued",
                 {"phase": "queued", "teardownParentId": parent.id,
                  "scopeSnapshotId": "snapshot"})
    for row in (parent, core, child):
        jobs.save(row)
    snapshot = {"snapshotId": "snapshot", "domainAssignments": [],
                "dnsCleanupManifest": {"domains": []},
                "chains": [{"outboundChannelIds": []}, {"outboundChannelIds": []}],
                "providerScopes": [{"provider": "digitalocean"}]}
    monkeypatch.setattr(dispatch, "_boundary",
                        lambda parent_id, *_a: (jobs.get(parent_id), core, snapshot,
                                                 "provider_keyed_teardown_fence"))
    monkeypatch.setattr(dispatch, "_require_diagnostic_targets", lambda *_a: None)
    reopened = SqliteJobRepository(database)
    scheduled = []
    assert dispatch.recover_pending_keyed_dispatches(
        environment="devtest", state_root=tmp_path, positive_control_ipv4="4.2.2.2",
        schedule=lambda parent_id, delay: scheduled.append((parent_id, delay)),
        job_repository=reopened, plan_repository=object(),
        lease_lookup=lambda _id: None,
    ) == [parent.id]
    assert scheduled == [(parent.id, 0.0)]
    assert reopened.get(parent.id) == parent and reopened.get(child.id) == child
    jobs.save(replace(child, input={**child.input,
                                    "claimExpiresAt": "2026-10-10T00:05:00+00:00"}))
    delayed = []
    assert dispatch.recover_pending_keyed_dispatches(
        environment="devtest", state_root=tmp_path, positive_control_ipv4="4.2.2.2",
        schedule=lambda parent_id, delay: delayed.append((parent_id, delay)),
        job_repository=SqliteJobRepository(database), plan_repository=object(),
        lease_lookup=lambda _id: None,
        now=lambda: datetime(2026, 10, 10, tzinfo=timezone.utc),
    ) == [parent.id]
    assert delayed == [(parent.id, 300.0)]
    jobs.save(replace(parent, input={**parent.input, "publishedSource": {}}))
    assert dispatch.recover_pending_keyed_dispatches(
        environment="devtest", state_root=tmp_path, positive_control_ipv4="4.2.2.2",
        schedule=lambda parent_id, delay: scheduled.append((parent_id, delay)),
        job_repository=SqliteJobRepository(database),
        plan_repository=object(), lease_lookup=lambda _id: None,
    ) == []
    assert scheduled == [(parent.id, 0.0)]


@pytest.mark.parametrize("drift", ["domain", "channel", "provider"])
def test_pending_scope_rejects_published_routes_before_any_dispatch(drift):
    snapshot = {"domainAssignments": [], "dnsCleanupManifest": {"domains": []},
                "chains": [{"outboundChannelIds": []}, {"outboundChannelIds": []}],
                "providerScopes": [{"provider": "digitalocean"}]}
    if drift == "domain":
        snapshot["domainAssignments"] = [{"id": "assigned"}]
    elif drift == "channel":
        snapshot["chains"][0]["outboundChannelIds"] = ["channel-1"]
    else:
        snapshot["providerScopes"][0]["provider"] = "linode"
    with pytest.raises(dispatch.PendingKeyedDispatchAttention):
        dispatch._require_diagnostic_scope(_job("job-core", "pilot_standard_rti_guarded_execute"),
                                           snapshot)
