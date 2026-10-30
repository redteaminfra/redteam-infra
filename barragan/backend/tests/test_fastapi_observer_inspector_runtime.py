# Copyright (c) 2026, Oracle and/or its affiliates.
from fastapi.testclient import TestClient

from app import create_app as create_reference_app
from app.asgi import create_app as create_fastapi_app
from app.core.config import TestConfig
from app.services.credentials import CredentialStoreLockedError
from app.storage.database import db
from app.storage.engagement_repository import SqlAlchemyEngagementRepository, StoredEngagement
from app.storage.inspection_run_repository import SqlAlchemyInspectionRunRepository, StoredInspectionRun
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from tests.runtime_support import storage_context


ENGAGEMENT_ID = "eng-fastapi-inspector"


def test_fastapi_inspector_settings_and_inspections_match_reference_contract(tmp_path):
    reference_app, reference_client, fastapi_app, fastapi_client = _separate_clients(tmp_path)
    _seed_engagement(reference_app)
    _seed_engagement(fastapi_app.state.database)
    _seed_inspection(reference_app)
    _seed_inspection(fastapi_app.state.database)

    requests = (
        ("get", f"/api/engagements/{ENGAGEMENT_ID}/inspector-settings", {}),
        ("get", f"/api/engagements/{ENGAGEMENT_ID}/inspections", {}),
        (
            "patch",
            f"/api/engagements/{ENGAGEMENT_ID}/inspector-settings",
            {
                "enabled": True,
                "provider": "linode",
                "region": "us-sea",
                "size": "g6-nanode-1",
                "mode": "regular",
                "scheduleWeekdays": ["mon"],
                "scheduleTimeUtc": "23:15",
                "forbiddenTcpPorts": ["22", "2222", "5000", "5173", "5900"],
            },
        ),
        (
            "patch",
            f"/api/engagements/{ENGAGEMENT_ID}/inspector-settings",
            {
                "provider": "linode",
                "region": "us-lax",
                "size": "g6-nanode-1",
                "mode": "regular",
            },
        ),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inspections", {"triggerType": "bogus"}),
        ("get", "/api/engagements/eng-missing/inspector-settings", {}),
        ("get", "/api/engagements/eng-missing/inspections", {}),
    )

    for method, path, body in requests:
        reference_response = _request(reference_client, method, path, body)
        fastapi_response = _request(fastapi_client, method, path, body)

        assert fastapi_response.status_code == reference_response.status_code
        assert _scrub_volatile(fastapi_response.json()) == _scrub_volatile(reference_response.get_json())


def test_fastapi_observer_settings_and_checks_match_reference_contract(tmp_path):
    reference_app, reference_client, fastapi_app, fastapi_client = _separate_clients(tmp_path)
    _seed_engagement(reference_app)
    _seed_engagement(fastapi_app.state.database)

    requests = (
        ("get", f"/api/engagements/{ENGAGEMENT_ID}/observer-settings", {}),
        (
            "patch",
            f"/api/engagements/{ENGAGEMENT_ID}/observer-settings",
            {
                "provider": "linode",
                "region": "us-sea",
                "size": "g6-nanode-1",
                "forbiddenTcpPorts": ["22", "2222", "22"],
            },
        ),
        (
            "patch",
            f"/api/engagements/{ENGAGEMENT_ID}/observer-settings",
            {
                "provider": "linode",
                "region": "us-lax",
                "size": "g6-nanode-1",
                "forbiddenTcpPorts": ["22"],
            },
        ),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/observer-checks", {"confirmation": "observer-wrong"}),
        ("get", "/api/engagements/eng-missing/observer-settings", {}),
    )

    for method, path, body in requests:
        reference_response = _request(reference_client, method, path, body)
        fastapi_response = _request(fastapi_client, method, path, body)

        assert fastapi_response.status_code == reference_response.status_code
        assert _scrub_volatile(fastapi_response.json()) == _scrub_volatile(reference_response.get_json())


def test_fastapi_observer_and_inspection_locked_store_shapes_match_reference_contract(tmp_path, monkeypatch):
    reference_app, reference_client, fastapi_app, fastapi_client = _separate_clients(tmp_path)
    _seed_engagement(reference_app)
    _seed_engagement(fastapi_app.state.database)

    def locked(*_args, **_kwargs):
        raise CredentialStoreLockedError("credential store is locked")

    monkeypatch.setattr("app.asgi.start_inspection", locked)
    monkeypatch.setattr("app.asgi.start_observer_check", locked)
    monkeypatch.setattr("app.asgi.start_inspection", locked)
    monkeypatch.setattr("app.asgi.start_observer_check", locked)

    requests = (
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inspections", {"triggerType": "manual"}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/observer-checks", {"confirmation": "observer-fastapi-inspector"}),
    )
    for method, path, body in requests:
        reference_response = _request(reference_client, method, path, body)
        fastapi_response = _request(fastapi_client, method, path, body)

        assert fastapi_response.status_code == reference_response.status_code == 503
        assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_inspector_readiness_returns_durable_readiness_result(tmp_path, monkeypatch):
    _reference_app, _reference_client, fastapi_app, fastapi_client = _separate_clients(tmp_path)
    _seed_engagement(fastapi_app.state.database)
    job = {
        "id": "job-inspector-ready",
        "action": "inspector_readiness",
        "status": "succeeded",
        "targetType": "engagement",
        "targetId": ENGAGEMENT_ID,
        "events": [],
    }
    monkeypatch.setattr(
        "app.asgi.ensure_continuous_inspector_ready",
        lambda engagement_id, requested_by: {
            "required": True,
            "ready": True,
            "status": "ready",
            "job": job,
            "inspectorHost": {"publicIp": "198.51.100.25"},
        },
    )

    response = fastapi_client.post(
        f"/api/engagements/{ENGAGEMENT_ID}/inspector-readiness",
        json={"requestedBy": "operator"},
    )

    assert response.status_code == 202
    assert response.json()["readiness"]["ready"] is True
    assert response.json()["readiness"]["job"]["id"] == "job-inspector-ready"


def test_fastapi_inspector_cleanup_preview_and_start_are_guarded_jobs(tmp_path, monkeypatch):
    _reference_app, _reference_client, fastapi_app, fastapi_client = _separate_clients(tmp_path)
    _seed_engagement(fastapi_app.state.database)
    preview = {
        "engagementId": ENGAGEMENT_ID,
        "engagementName": "FastAPI Inspector",
        "confirmationToken": "destroy-inspector-fastapi-inspector",
        "canDestroy": True,
        "blockers": [],
        "hosts": [{"provider": "linode", "resourceType": "instance", "resourceId": "host-123"}],
        "resourceCount": 1,
        "scope": {"inspectorOnly": True, "coreInfrastructure": False},
    }
    job = {
        "id": "job-inspector-cleanup",
        "action": "inspector_cleanup",
        "status": "running",
        "targetType": "engagement",
        "targetId": ENGAGEMENT_ID,
        "events": [],
    }
    monkeypatch.setattr("app.asgi.preview_inspector_cleanup", lambda engagement_id: preview)
    monkeypatch.setattr(
        "app.asgi.start_inspector_cleanup",
        lambda engagement_id, body, requested_by: {"job": job, "status": "running"},
    )

    preview_response = fastapi_client.post(f"/api/engagements/{ENGAGEMENT_ID}/inspector-cleanup-preview", json={})
    cleanup_response = fastapi_client.post(
        f"/api/engagements/{ENGAGEMENT_ID}/inspector-cleanup",
        json={"confirmation": "destroy-inspector-fastapi-inspector", "requestedBy": "operator"},
    )

    assert preview_response.status_code == 200
    assert preview_response.json()["preview"]["scope"]["coreInfrastructure"] is False
    assert cleanup_response.status_code == 202
    assert cleanup_response.json()["job"]["action"] == "inspector_cleanup"


def _separate_clients(tmp_path):
    class ReferenceSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'reference.sqlite3'}"

    class FastApiSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'fastapi.sqlite3'}"

    reference_app = create_reference_app(ReferenceSqliteConfig)
    fastapi_app = create_fastapi_app(FastApiSqliteConfig)
    return reference_app, reference_app.test_client(), fastapi_app, fastapi_app.test_client()


def _request(client, method: str, path: str, body: dict):
    if method == "get":
        return client.get(path)
    return getattr(client, method)(path, json=body)


def _scrub_volatile(value):
    if isinstance(value, dict):
        scrubbed = {}
        for key, item in value.items():
            if key in {"createdAt", "updatedAt", "startedAt", "finishedAt"} and item:
                scrubbed[key] = "<timestamp>"
            else:
                scrubbed[key] = _scrub_volatile(item)
        return scrubbed
    if isinstance(value, list):
        return [_scrub_volatile(item) for item in value]
    return value


def _seed_engagement(reference_app) -> None:
    with storage_context(reference_app):
        SqlAlchemyEngagementRepository().save(
            StoredEngagement(
                id=ENGAGEMENT_ID,
                name="FastAPI Inspector",
                status="draft",
                owner="operator",
                template_id="standard-rti",
                active_revision=None,
                input_parameters={},
                description="FastAPI observer/inspector fixture",
                created_at="2026-07-06T00:00:00+00:00",
                updated_at="2026-07-06T00:00:00+00:00",
            )
        )
        db.session.remove()


def _seed_inspection(reference_app) -> None:
    with storage_context(reference_app):
        SqlAlchemyJobRepository().save(
            StoredJobRun(
                id=f"job-{ENGAGEMENT_ID}-inspection",
                action="inspector_inspection",
                status="succeeded",
                target=f"engagement:{ENGAGEMENT_ID}",
                target_type="engagement",
                target_id=ENGAGEMENT_ID,
                requested_by="operator",
                input={"engagementId": ENGAGEMENT_ID},
                artifact_refs=[],
                created_at="2026-07-06T00:00:00+00:00",
                started_at="2026-07-06T00:00:00+00:00",
                finished_at="2026-07-06T00:01:00+00:00",
                events=[],
            )
        )
        SqlAlchemyInspectionRunRepository().save(
            StoredInspectionRun(
                id=f"insp-{ENGAGEMENT_ID}",
                engagement_id=ENGAGEMENT_ID,
                job_id=f"job-{ENGAGEMENT_ID}-inspection",
                trigger_type="manual",
                mode="once",
                status="succeeded",
                provider="linode",
                region="us-sea",
                host={"publicIp": "198.51.100.25"},
                targets={"positive": []},
                evidence={"ok": True},
                findings=[],
                created_at="2026-07-06T00:00:00+00:00",
                started_at="2026-07-06T00:00:00+00:00",
                finished_at="2026-07-06T00:01:00+00:00",
            )
        )
        db.session.remove()
