# Copyright (c) 2026, Oracle and/or its affiliates.
"""One reviewed operator action routes interrupted mixed cleanup through DevTest."""

from app.asgi import create_app
from app.core.config import TestConfig
from app.domain import JobEvent
from app.services import provider_keyed_mixed_interrupted_dispatch as dispatch
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun


def test_interrupted_teardown_preview_post_and_schedule(tmp_path, monkeypatch):
    class DevTestConfig(TestConfig):
        ENVIRONMENT = "devtest"
        PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4 = "1.1.1.1"
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'interrupted-http.sqlite3'}"

    app = create_app(DevTestConfig)
    core_id = "job-core-interrupted-http"
    core = StoredJobRun(
        core_id, "pilot_standard_rti_guarded_execute", "succeeded",
        "oci-compartment:testing", "oci_compartment", "compartment-testing",
        "operator", {"engagementId": "eng-interrupted-http", "engagementName": "Opaque",
                     "corePlanId": "plan-interrupted-http", "proxyCount": 2,
                     "sketchStateSchema": "provider-keyed-v2"}, [],
        "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:00+00:00",
        "2026-10-15T00:00:00+00:00", [JobEvent(1, "info", "core complete", {})],
    )
    initial = StoredJobRun(
        dispatch.initial_parent_id(core_id), "provider_keyed_mixed_initial", "running",
        "engagement:eng-interrupted-http", "engagement", "eng-interrupted-http",
        "operator", {"engagementId": "eng-interrupted-http", "coreJobId": core_id,
                     "phase": "apply_sealed"}, [],
        "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:00+00:00",
        None, [JobEvent(1, "info", "mixed plan", {})],
    )
    with app.storage_context():
        jobs = SqlAlchemyJobRepository()
        jobs.save(core)
        jobs.save(initial)
    preview = {"snapshotId": "a" * 64, "confirmationPhrase": "teardown-opaque",
               "engagementId": "eng-interrupted-http", "engagementName": "Opaque",
               "parentJobId": None, "orderedScope": []}
    calls = []
    monkeypatch.setattr(dispatch, "preview_mixed_interrupted_cleanup",
                        lambda *args, **kwargs: calls.append("preview") or preview)

    def reserve(_job, body, **_kwargs):
        calls.append("reserve")
        assert body["snapshotId"] == preview["snapshotId"]
        parent = StoredJobRun(
            dispatch.cleanup_parent_id(core_id), "provider_keyed_mixed_interrupted_cleanup",
            "queued", "engagement:eng-interrupted-http", "engagement",
            "eng-interrupted-http", "operator", {"coreJobId": core_id}, [],
            "2026-10-15T00:00:00+00:00", None, None, [],
        )
        SqlAlchemyJobRepository().save(parent)
        return parent

    monkeypatch.setattr(dispatch, "start_mixed_interrupted_cleanup", reserve)
    scheduled = []
    monkeypatch.setattr("app.core.runtime.start_runtime_task",
                        lambda task, **_kwargs: scheduled.append(task))
    client = app.test_client()
    path = f"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/{core_id}/teardown"
    response = client.get(path)
    assert response.status_code == 200
    assert response.get_json()["teardown"] == preview
    response = client.post(path, json={"snapshotId": "a" * 64,
                                       "confirmation": "teardown-opaque"})
    assert response.status_code == 200
    assert response.get_json()["job"]["action"] == "provider_keyed_mixed_interrupted_cleanup"
    assert calls == ["preview", "reserve"]
    assert len(scheduled) == 1
    duplicate = client.post(path, json={"snapshotId": "a" * 64,
                                        "confirmation": "teardown-opaque"})
    assert duplicate.status_code == 200
    assert len(scheduled) == 1
