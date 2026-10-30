# Copyright (c) 2026, Oracle and/or its affiliates.
"""HTTP contract for the normal one-confirmation mixed zero-Apply teardown route."""

from dataclasses import asdict, replace

import pytest

from app.asgi import create_app
from app.core.config import TestConfig
from app.domain import JobEvent
from app.services import provider_keyed_mixed_zero_apply_cleanup as cleanup
from app.services import provider_keyed_mixed_zero_apply_dispatch as dispatch
from app.services import provider_keyed_mixed_zero_apply_terminal as terminal
from app.services.provider_keyed_mixed_zero_apply_teardown_source import MixedZeroApplySource
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun


@pytest.fixture
def route(tmp_path, monkeypatch):
    class DevTestConfig(TestConfig):
        ENVIRONMENT = "devtest"
        PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4 = "1.1.1.1"
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'mixed-http.sqlite3'}"

    app = create_app(DevTestConfig)
    core_id = "job-core-mixed-http"
    initial_id = dispatch.initial_parent_id(core_id)
    core = StoredJobRun(
        core_id, "pilot_standard_rti_guarded_execute", "succeeded",
        "oci-compartment:testing", "oci_compartment", "compartment-testing",
        "operator", {"engagementId": "eng-mixed-http", "engagementName": "Opaque",
                     "corePlanId": "plan-mixed-http", "proxyCount": 2,
                     "sketchStateSchema": "provider-keyed-v2"}, [],
        "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:00+00:00",
        "2026-10-15T00:00:00+00:00", [JobEvent(1, "info", "core complete", {})],
    )
    initial = StoredJobRun(
        initial_id, dispatch.INITIAL_ACTION, "running",
        "engagement:eng-mixed-http", "engagement", "eng-mixed-http", "operator",
        {"engagementId": "eng-mixed-http", "coreJobId": core_id,
         "phase": "both_plans_saved"}, [],
        "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:00+00:00",
        None, [JobEvent(1, "info", "both plans saved", {})],
    )
    source = MixedZeroApplySource(
        "eng-mixed-http", core_id, "plan-mixed-http", initial_id,
        "a" * 64, "b" * 64, ("linode", "digitalocean"),
        ("c" * 64, "d" * 64), "e" * 64, "f" * 64,
        ("linode:inspector:10", "linode:inspector-firewall:20"),
    )
    with app.storage_context():
        jobs = SqlAlchemyJobRepository()
        jobs.save(core)
        jobs.save(initial)
    audit_calls = []
    monkeypatch.setattr(dispatch, "audit_mixed_zero_apply_teardown_source",
                        lambda *args, **kwargs: audit_calls.append((args, kwargs)) or source)
    reserve_calls = []

    def reserve(_engagement_id, _core_id, *, requested_by, **_kwargs):
        reserve_calls.append((_engagement_id, _core_id, requested_by))
        proposal = cleanup._proposal(source, requested_by)
        saved = SqlAlchemyJobRepository().save_if_absent(proposal)
        return saved

    monkeypatch.setattr(dispatch, "reserve_mixed_zero_apply_cleanup", reserve)
    scheduled = []
    monkeypatch.setattr("app.core.runtime.start_runtime_task",
                        lambda task, **_kwargs: scheduled.append(task))
    return app, app.test_client(), core, source, audit_calls, reserve_calls, scheduled


def test_http_preview_stale_confirmation_then_single_post_and_poll(route):
    app, client, core, source, audits, reserves, scheduled = route
    path = f"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/{core.id}"
    preview_response = client.get(path + "/teardown")
    assert preview_response.status_code == 200
    preview = preview_response.get_json()["teardown"]
    assert preview["snapshotId"] == dispatch._fingerprint(asdict(source))
    assert preview["parentJobId"] is None
    assert [row["id"] for row in preview["orderedScope"]] == [
        "sketch", "core", "inspector-verify", "inspector-cleanup"]
    assert len(audits) == 1

    stale = client.post(path + "/teardown", json={
        "confirmation": preview["confirmationPhrase"], "snapshotId": "0" * 64})
    assert stale.status_code == 400
    assert reserves == [] and scheduled == []

    accepted = client.post(path + "/teardown", json={
        "confirmation": preview["confirmationPhrase"],
        "snapshotId": preview["snapshotId"]})
    assert accepted.status_code == 200
    parent = accepted.get_json()["job"]
    assert parent["action"] == cleanup.ACTION and parent["status"] == "queued"
    assert len(reserves) == 1 and len(scheduled) == 1
    with app.storage_context():
        stored = SqlAlchemyJobRepository().get(parent["id"])
        assert stored is not None and stored.input["sourceSha256"] == preview["snapshotId"]

    polled = client.get(f"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/{parent['id']}")
    assert polled.status_code == 200
    detail = polled.get_json()["job"]
    assert detail["id"] == parent["id"]
    assert detail["phase"] == "core_destroy_preview"
    assert detail["progress"] == {"completed": 0, "total": 5}

    # A duplicate review is read from the saved source after the initial
    # lease has been fenced; it never calls the pre-fence source auditor.
    again = client.get(path + "/teardown")
    assert again.status_code == 200
    assert again.get_json()["teardown"]["parentJobId"] == parent["id"]
    assert len(audits) == 3  # initial GET, rejected POST, accepted POST


def test_http_duplicate_terminal_requires_historical_recognition(route, monkeypatch):
    app, client, core, source, _audits, _reserves, scheduled = route
    parent = replace(cleanup._proposal(source, "operator"), status="succeeded",
                     started_at="2026-10-15T00:00:01+00:00",
                     finished_at="2026-10-15T00:00:02+00:00")
    with app.storage_context():
        SqlAlchemyJobRepository().save(parent)
    path = f"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/{core.id}/teardown"
    preview = client.get(path).get_json()["teardown"]
    recognized = []
    monkeypatch.setattr(terminal, "recognize_mixed_zero_apply_terminal",
                        lambda *args, **kwargs: recognized.append((args, kwargs)) or parent)
    response = client.post(path, json={"snapshotId": preview["snapshotId"],
                                       "confirmation": preview["confirmationPhrase"]})
    assert response.status_code == 200
    assert response.get_json()["job"]["status"] == "succeeded"
    assert len(recognized) == 1 and scheduled == []


def test_http_mixed_teardown_is_devtest_only(route):
    app, client, core, _source, _audits, reserves, scheduled = route
    app.state.config.ENVIRONMENT = "production"
    path = f"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/{core.id}/teardown"
    assert client.get(path).status_code == 400
    response = client.post(path, json={"snapshotId": "a" * 64,
                                       "confirmation": "teardown-opaque"})
    assert response.status_code == 400
    assert reserves == [] and scheduled == []
