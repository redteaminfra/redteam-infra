# Copyright (c) 2026, Oracle and/or its affiliates.
"""Published mixed teardown requires an exact two-provider source."""

from dataclasses import replace

import pytest

from app.asgi import create_app
from app.core.config import TestConfig
from app.domain import JobEvent
from app.services.engagement_teardown import (
    EngagementTeardownValidationError,
    preview_engagement_teardown,
    preview_published_mixed_initial_scope,
    start_engagement_teardown,
)
from app.services.provider_keyed_mixed_initial_plan_parent import _parent_id
from app.services.provider_keyed_mixed_published_teardown_authority import (
    review_published_mixed_initial_teardown,
)
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_teardown_authority import _case


def test_authenticated_two_provider_scope_is_read_only(client, ready, tmp_path):
    with client.application.storage_context():
        source, args, _persisted = _case(ready, tmp_path)
        review = review_published_mixed_initial_teardown(**args)
        core_scope = {
            "jobId": source.core_job_id, "planId": source.core_plan_id,
            "ownedInspectorRecordIds": ["record-one", "record-two"],
            "stateSha256": "a" * 64,
        }
        preview = preview_published_mixed_initial_scope(review, core_scope, "Opaque")
        assert preview["startAvailable"] is False
        assert preview["confirmationPhrase"] == ""
        assert [row["provider"] for row in preview["orderedScope"][0]["items"]] == list(
            source.ordered_providers)
        assert [row["id"] for row in preview["orderedScope"]] == [
            "provider-keyed", "core", "inspector-cleanup"]
        assert preview_published_mixed_initial_scope(review, core_scope, "Opaque") == preview
        with pytest.raises(EngagementTeardownValidationError):
            preview_published_mixed_initial_scope(
                replace(review, provider_scopes=review.provider_scopes[:1]), core_scope, "Opaque")
        with pytest.raises(EngagementTeardownValidationError):
            preview_published_mixed_initial_scope(review, {
                **core_scope, "planId": "other"}, "Opaque")


@pytest.mark.parametrize("order", [("linode", "digitalocean"),
                                   ("digitalocean", "linode")])
def test_completed_mixed_http_cannot_fall_through_to_digitalocean_teardown(
        tmp_path, monkeypatch, order):
    class DevTestConfig(TestConfig):
        ENVIRONMENT = "devtest"
        PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4 = "1.1.1.1"
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'published-mixed-http.sqlite3'}"

    app = create_app(DevTestConfig)
    core_id = "job-core-published-mixed-http"
    engagement_id = "eng-published-mixed-http"
    timestamp = "2026-10-15T00:00:00+00:00"
    core = StoredJobRun(
        core_id, "pilot_standard_rti_guarded_execute", "succeeded",
        "oci-compartment:testing", "oci_compartment", "compartment-testing",
        "operator", {"engagementId": engagement_id, "engagementName": "Opaque",
                     "corePlanId": "plan-published-mixed-http", "proxyCount": 2,
                     "sketchStateSchema": "provider-keyed-v2"}, [],
        timestamp, timestamp, timestamp, [JobEvent(1, "info", "core complete", {})],
    )
    initial = StoredJobRun(
        _parent_id(core_id), "provider_keyed_mixed_initial", "succeeded",
        f"engagement:{engagement_id}", "engagement", engagement_id, "operator",
        {"engagementId": engagement_id, "coreJobId": core_id,
         "phase": "completed", "orderedProviders": list(order)}, [],
        timestamp, timestamp, timestamp,
        [JobEvent(1, "info", "mixed two-provider host proof published", {})],
    )
    with app.storage_context():
        jobs = SqlAlchemyJobRepository()
        jobs.save(core)
        jobs.save(initial)
    calls = []
    monkeypatch.setattr("app.services.engagement_teardown._current_scope_snapshot",
                        lambda *args, **kwargs: calls.append("digitalocean-scope"))
    client = app.test_client()
    path = f"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/{core_id}/teardown"
    for method in (client.get, lambda url: client.post(url, json={
            "snapshotId": "a" * 64, "confirmation": "teardown-opaque"})):
        response = method(path)
        assert response.status_code == 400
        assert "published mixed" in response.get_json()["errors"][0]
    assert calls == []
    with app.storage_context():
        jobs = SqlAlchemyJobRepository()
        teardown_id = f"job-engagement-teardown-{core_id.removeprefix('job-')}"
        assert jobs.get(teardown_id) is None
        with pytest.raises(EngagementTeardownValidationError):
            preview_engagement_teardown(core_id, job_repository=jobs)


        with pytest.raises(EngagementTeardownValidationError):
            start_engagement_teardown(core_id, {}, job_repository=jobs,
                                      provider_keyed_environment="devtest",
                                      provider_keyed_coordinator=lambda _id: None)
        jobs.save(StoredJobRun(
            teardown_id, "engagement_comprehensive_teardown", "queued",
            f"engagement:{engagement_id}", "engagement", engagement_id,
            "operator", {"coreJobId": core_id, "scopeSnapshot": {}}, [],
            timestamp, None, None, [JobEvent(1, "info", "queued", {})],
        ))
    for method in (client.get, lambda url: client.post(url, json={
            "snapshotId": "a" * 64, "confirmation": "teardown-opaque"})):
        response = method(path.replace(core_id, teardown_id))
        assert response.status_code == 400
    with app.storage_context():
        jobs = SqlAlchemyJobRepository()
        with pytest.raises(EngagementTeardownValidationError):
            preview_engagement_teardown(teardown_id, job_repository=jobs)
        with pytest.raises(EngagementTeardownValidationError):
            start_engagement_teardown(teardown_id, {}, job_repository=jobs,
                                      provider_keyed_environment="devtest",
                                      provider_keyed_coordinator=lambda _id: None)


def test_published_mixed_http_uses_one_review_and_schedules_once(tmp_path, monkeypatch):
    class DevTestConfig(TestConfig):
        ENVIRONMENT = "devtest"
        PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4 = "1.1.1.1"
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'published-route.sqlite3'}"

    app = create_app(DevTestConfig)
    core_id, engagement_id = "job-core-published-route", "eng-published-route"
    timestamp = "2026-10-15T00:00:00+00:00"
    core = StoredJobRun(
        core_id, "pilot_standard_rti_guarded_execute", "succeeded",
        "oci-compartment:testing", "oci_compartment", "compartment-testing",
        "operator", {"engagementId": engagement_id, "engagementName": "Opaque",
                     "corePlanId": "plan-published-route", "proxyCount": 2,
                     "sketchStateSchema": "provider-keyed-v2"}, [],
        timestamp, timestamp, timestamp, [JobEvent(1, "info", "core complete", {})],
    )
    initial = StoredJobRun(
        _parent_id(core_id), "provider_keyed_mixed_initial", "succeeded",
        f"engagement:{engagement_id}", "engagement", engagement_id, "operator",
        {"engagementId": engagement_id, "coreJobId": core_id,
         "phase": "completed", "orderedProviders": ["linode", "digitalocean"]}, [],
        timestamp, timestamp, timestamp,
        [JobEvent(1, "info", "mixed two-provider host proof published", {})],
    )
    with app.storage_context():
        jobs = SqlAlchemyJobRepository()
        jobs.save(core)
        jobs.save(initial)
    from app.services.provider_keyed_mixed_published_teardown_checkpoint import parent_id
    parent = StoredJobRun(
        parent_id(core_id), "provider_keyed_mixed_published_cleanup", "queued",
        f"engagement:{engagement_id}", "engagement", engagement_id, "operator",
        {"engagementId": engagement_id, "coreJobId": core_id,
         "corePlanId": "plan-published-route"}, [], timestamp, None, None,
        [JobEvent(1, "info", "published mixed cleanup review queued", {})],
    )
    from app.services import provider_keyed_mixed_published_dispatch as dispatch
    monkeypatch.setattr(dispatch, "preview_published_mixed_cleanup",
                        lambda *_a, **_k: {"snapshotId": "exact-review",
                                             "confirmationPhrase": "teardown-opaque"})

    def start(*_args, **_kwargs):
        with app.storage_context():
            jobs = SqlAlchemyJobRepository()
            existing = jobs.get(parent.id)
            return existing if existing is not None else jobs.save(parent)

    monkeypatch.setattr(dispatch, "start_published_mixed_cleanup", start)
    scheduled = []
    from app.services import provider_keyed_mixed_published_dispatch_claim as claim_service
    monkeypatch.setattr(claim_service, "schedule_published_mixed_dispatch",
                        lambda *_a, **_k: scheduled.append("schedule"))
    client = app.test_client()
    path = f"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/{core_id}/teardown"
    assert client.get(path).get_json()["teardown"]["snapshotId"] == "exact-review"
    for _ in range(2):
        response = client.post(path, json={"snapshotId": "exact-review",
                                           "confirmation": "teardown-opaque"})
        assert response.status_code == 200
        assert response.get_json()["job"]["id"] == parent.id
    assert scheduled == ["schedule", "schedule"]
