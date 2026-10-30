# Copyright (c) 2026, Oracle and/or its affiliates.
from fastapi.testclient import TestClient

from app import create_app as create_reference_app
from app.asgi import create_app as create_fastapi_app
from app.core.config import TestConfig
from app.storage.database import db
from app.storage.engagement_repository import SqlAlchemyEngagementRepository, StoredEngagement
from tests.test_catalog_service import valid_standard_rti_payload


ENGAGEMENT_ID = "eng-fastapi-core"


def test_fastapi_engagement_core_read_routes_match_reference_contract(tmp_path):
    reference_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_engagement(reference_app)

    for path in (
        "/api/engagements",
        "/api/engagements?scope=all",
        f"/api/engagements/{ENGAGEMENT_ID}",
        "/api/engagements/eng-missing",
    ):
        reference_response = reference_client.get(path)
        fastapi_response = fastapi_client.get(path)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_engagement_core_validation_matches_reference_contract(tmp_path):
    reference_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_engagement(reference_app)

    requests = (
        ("post", "/api/engagements", {"name": "", "owner": ""}),
        ("patch", f"/api/engagements/{ENGAGEMENT_ID}", {"name": "", "owner": ""}),
        ("patch", "/api/engagements/eng-missing", {"name": "missing", "owner": "operator"}),
        ("delete", "/api/engagements/eng-missing", {}),
    )
    for method, path, body in requests:
        if method == "delete":
            reference_response = reference_client.delete(path)
            fastapi_response = fastapi_client.delete(path)
        else:
            reference_response = getattr(reference_client, method)(path, json=body)
            fastapi_response = getattr(fastapi_client, method)(path, json=body)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_engagement_delete_preserves_active_infrastructure_error_shape(tmp_path, monkeypatch):
    reference_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_engagement(reference_app)
    monkeypatch.setattr(
        "app.services.engagements._active_infrastructure_job",
        lambda requested_id, job_repository=None: type("ActiveJob", (), {"id": "job-active-infra"})()
        if requested_id == ENGAGEMENT_ID
        else None,
    )

    reference_response = reference_client.delete(f"/api/engagements/{ENGAGEMENT_ID}")
    fastapi_response = fastapi_client.delete(f"/api/engagements/{ENGAGEMENT_ID}")

    assert fastapi_response.status_code == reference_response.status_code
    assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_engagement_archive_preserves_active_infrastructure_error_shape(tmp_path, monkeypatch):
    reference_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_engagement(reference_app)
    monkeypatch.setattr(
        "app.services.engagements._active_infrastructure_job",
        lambda requested_id, job_repository=None: type("ActiveJob", (), {"id": "job-active-infra"})()
        if requested_id == ENGAGEMENT_ID
        else None,
    )

    reference_response = reference_client.post(f"/api/engagements/{ENGAGEMENT_ID}/archive")
    fastapi_response = fastapi_client.post(f"/api/engagements/{ENGAGEMENT_ID}/archive")

    assert fastapi_response.status_code == reference_response.status_code
    assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_engagement_archive_and_infrastructure_validation_match_reference_contract(tmp_path):
    reference_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_engagement(reference_app)

    requests = (
        ("post", "/api/engagements/eng-missing/archive", {}),
        ("post", "/api/engagements/eng-missing/infrastructure", {"templateId": "standard-rti", "inputParameters": valid_standard_rti_payload()}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/infrastructure", {}),
        (
            "post",
            f"/api/engagements/{ENGAGEMENT_ID}/infrastructure",
            {"templateId": "standard-rti", "inputParameters": {"engagementName": ""}},
        ),
    )
    for method, path, body in requests:
        reference_response = getattr(reference_client, method)(path, json=body)
        fastapi_response = getattr(fastapi_client, method)(path, json=body)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_engagement_core_successful_mutations_preserve_shapes(tmp_path):
    _reference_app, _reference_client, fastapi_client = _clients(tmp_path)

    created = fastapi_client.post(
        "/api/engagements",
        json={
            "name": "FEC02",
            "owner": "operator",
            "description": "FastAPI engagement core test",
        },
    )
    assert created.status_code == 201
    engagement_id = created.json()["engagement"]["id"]

    shown = fastapi_client.get(f"/api/engagements/{engagement_id}")
    updated = fastapi_client.patch(
        f"/api/engagements/{engagement_id}",
        json={
            "name": "FEC02-updated",
            "owner": "operator-two",
            "description": "Updated FastAPI engagement core test",
        },
    )
    deleted = fastapi_client.delete(f"/api/engagements/{engagement_id}")
    hidden = fastapi_client.get("/api/engagements")
    all_rows = fastapi_client.get("/api/engagements?scope=all")

    assert shown.status_code == 200
    assert shown.json()["engagement"]["name"] == "FEC02"
    assert updated.status_code == 200
    assert updated.json()["engagement"]["name"] == "FEC02-updated"
    assert updated.json()["engagement"]["owner"] == "operator-two"
    assert deleted.status_code == 200
    assert deleted.json()["engagement"]["status"] == "retired"
    assert engagement_id not in {row["id"] for row in hidden.json()["engagements"]}
    assert engagement_id in {row["id"] for row in all_rows.json()["engagements"]}


def test_fastapi_engagement_archive_and_infrastructure_success_preserve_shapes(tmp_path):
    reference_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_engagement(reference_app)

    configure_body = {"templateId": "standard-rti", "inputParameters": valid_standard_rti_payload()}
    reference_configure = reference_client.post(f"/api/engagements/{ENGAGEMENT_ID}/infrastructure", json=configure_body)
    fastapi_configure = fastapi_client.post(f"/api/engagements/{ENGAGEMENT_ID}/infrastructure", json=configure_body)
    reference_archive = reference_client.post(f"/api/engagements/{ENGAGEMENT_ID}/archive")
    fastapi_archive = fastapi_client.post(f"/api/engagements/{ENGAGEMENT_ID}/archive")

    assert fastapi_configure.status_code == reference_configure.status_code == 200
    assert fastapi_configure.json() == reference_configure.get_json()
    assert fastapi_configure.json()["engagement"]["templateId"] == "standard-rti"
    assert fastapi_archive.status_code == reference_archive.status_code == 200
    assert fastapi_archive.json() == reference_archive.get_json()
    assert fastapi_archive.json()["engagement"]["status"] == "archived"


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
                name="FEC01",
                status="draft",
                owner="operator",
                template_id="",
                active_revision=None,
                input_parameters={},
                description="FastAPI engagement core fixture",
                created_at="2026-07-06T00:00:00+00:00",
                updated_at="2026-07-06T00:00:00+00:00",
            )
        )
        db.session.remove()
