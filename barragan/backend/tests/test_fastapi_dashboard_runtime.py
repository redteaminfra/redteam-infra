# Copyright (c) 2026, Oracle and/or its affiliates.
from fastapi.testclient import TestClient

from app import create_app as create_reference_app
from app.asgi import create_app as create_fastapi_app
from app.core.config import TestConfig
from app.storage.database import db
from app.storage.engagement_repository import SqlAlchemyEngagementRepository, StoredEngagement
from app.storage.job_repository import SqlAlchemyJobRepository


ENGAGEMENT_ID = "eng-fastapi-dashboard"
ENGAGEMENT_NAME = "FAD01"


def test_fastapi_dashboard_read_routes_match_reference_contract(tmp_path, monkeypatch):
    reference_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_engagement(reference_app)
    from app.services import dashboard

    fixed_disk_usage = dashboard.shutil.disk_usage(tmp_path)
    monkeypatch.setattr(dashboard.shutil, "disk_usage", lambda _path: fixed_disk_usage)
    monkeypatch.setattr("app.services.provider_reconciliation.discover_provider_resources", lambda: [_provider_resource()])
    monkeypatch.setattr("app.services.provider_reconciliation.discover_provider_inventory", lambda: {
        "resources": [_provider_resource()], "evidence": {"status": "checked",
        "observedAt": "2026-10-22T00:00:00+00:00", "cached": False, "ageSeconds": 0,
        "detail": "Injected inventory.", "providers": []}})

    for path in ("/api/dashboard", "/api/dashboard?live=1"):
        reference_response = reference_client.get(path)
        fastapi_response = fastapi_client.get(path)

        assert fastapi_response.status_code == reference_response.status_code
        assert _normalized_dashboard_response(fastapi_response.json()) == _normalized_dashboard_response(reference_response.get_json())


def test_fastapi_dashboard_recovery_validation_matches_reference_contract(tmp_path):
    reference_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_engagement(reference_app)

    reference_response = reference_client.post("/api/dashboard/orphan-candidates/actions", json={"action": "track"})
    fastapi_response = fastapi_client.post("/api/dashboard/orphan-candidates/actions", json={"action": "track"})

    assert fastapi_response.status_code == reference_response.status_code
    assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_dashboard_recovery_action_tracks_provider_resource(tmp_path, monkeypatch):
    reference_app, _reference_client, fastapi_client = _clients(tmp_path)
    _seed_engagement(reference_app)
    monkeypatch.setattr("app.services.provider_reconciliation.discover_provider_resources", lambda: [_provider_resource()])

    response = fastapi_client.post(
        "/api/dashboard/orphan-candidates/actions",
        json={
            "candidateId": "linode:instance:12345",
            "action": "track",
            "requestedBy": "pytest",
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "tracked"
    assert body["candidate"]["engagementId"] == ENGAGEMENT_ID
    assert body["candidate"]["provider"] == "linode"
    assert body["job"]["action"] == "provider_orphan_track"
    assert body["job"]["status"] == "succeeded"
    assert body["job"]["targetType"] == "provider_orphan"
    assert body["job"]["events"][0]["data"]["providerRecord"]["status"] == "tracked"


def test_fastapi_dashboard_does_not_load_global_job_history(tmp_path, monkeypatch):
    reference_app, _reference_client, fastapi_client = _clients(tmp_path)
    _seed_engagement(reference_app)

    def fail_global_list(_repository):
        raise AssertionError("dashboard loaded unbounded global job history")

    monkeypatch.setattr(SqlAlchemyJobRepository, "list", fail_global_list)

    response = fastapi_client.get("/api/dashboard")

    assert response.status_code == 200
    assert isinstance(response.json()["dashboard"]["summary"]["jobRuns"], int)


def _clients(tmp_path):
    class SharedSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'barragan.sqlite3'}"

    reference_app = create_reference_app(SharedSqliteConfig)
    fastapi_app = create_fastapi_app(SharedSqliteConfig)
    return reference_app, reference_app.test_client(), fastapi_app.test_client()


def _seed_engagement(reference_app) -> None:
    with reference_app.storage_context():
        SqlAlchemyEngagementRepository().save(
            StoredEngagement(
                id=ENGAGEMENT_ID,
                name=ENGAGEMENT_NAME,
                status="draft",
                owner="pytest",
                template_id="",
                active_revision=None,
                input_parameters={},
                created_at="2026-07-06T00:00:00+00:00",
                updated_at="2026-07-06T00:00:00+00:00",
            )
        )
        db.session.remove()


def _provider_resource() -> dict[str, object]:
    return {
        "provider": "linode",
        "resourceType": "instance",
        "resourceId": "12345",
        "name": "edge-fad01-us-sea-proxy01-sea-01",
        "region": "us-sea",
        "lifecycleState": "running",
        "engagementId": ENGAGEMENT_ID,
        "engagementName": ENGAGEMENT_NAME,
        "metadata": {"barraganOwned": True, "publicIps": ["203.0.113.45"]},
        "source": "linode_api",
    }


def _normalized_dashboard_response(body: dict[str, object]) -> dict[str, object]:
    normalized = dict(body)
    dashboard = dict(normalized["dashboard"])  # type: ignore[index]
    dashboard["generatedAt"] = "<generated>"
    system_health = dict(dashboard["systemHealth"])  # type: ignore[index]
    api = dict(system_health["api"])  # type: ignore[index]
    api["checkedAt"] = "<generated>"
    system_health["api"] = api
    providers = dict(system_health["providers"])  # type: ignore[index]
    if providers.get("checkedAt"):
        providers["checkedAt"] = "<generated>"
    system_health["providers"] = providers
    dashboard["systemHealth"] = system_health
    normalized["dashboard"] = dashboard
    return normalized
