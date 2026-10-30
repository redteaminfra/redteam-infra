# Copyright (c) 2026, Oracle and/or its affiliates.
from pathlib import Path

from fastapi.testclient import TestClient

from app import create_app as create_reference_app
from app.asgi import create_app as create_fastapi_app
from app.core.config import TestConfig
from app.storage.database import db
from app.storage.engagement_repository import SqlAlchemyEngagementRepository, StoredEngagement
from tests.test_catalog_service import valid_standard_rti_payload
from tests.runtime_support import storage_context


ENGAGEMENT_ID = "eng-fastapi-revisions"


def test_fastapi_revision_list_create_and_detail_match_reference_contract(tmp_path):
    reference_app, reference_client, fastapi_app, fastapi_client = _separate_clients(tmp_path)
    _seed_engagement(reference_app)
    _seed_engagement(fastapi_app.state.database)

    reference_empty = reference_client.get(f"/api/engagements/{ENGAGEMENT_ID}/revisions")
    fastapi_empty = fastapi_client.get(f"/api/engagements/{ENGAGEMENT_ID}/revisions")

    assert fastapi_empty.status_code == reference_empty.status_code == 200
    assert fastapi_empty.json() == reference_empty.get_json()

    reference_created = reference_client.post(f"/api/engagements/{ENGAGEMENT_ID}/revisions")
    fastapi_created = fastapi_client.post(f"/api/engagements/{ENGAGEMENT_ID}/revisions")

    assert fastapi_created.status_code == reference_created.status_code == 201
    assert fastapi_created.json() == reference_created.get_json()

    revision_id = reference_created.get_json()["revision"]["id"]
    reference_detail = reference_client.get(f"/api/revisions/{revision_id}")
    fastapi_detail = fastapi_client.get(f"/api/revisions/{revision_id}")

    assert fastapi_detail.status_code == reference_detail.status_code == 200
    assert fastapi_detail.json() == reference_detail.get_json()


def test_fastapi_revision_missing_and_compile_error_shapes_match_reference_contract(tmp_path):
    reference_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_engagement(reference_app, input_parameters={})

    requests = (
        ("get", "/api/revisions/rev-missing", {}),
        ("post", "/api/revisions/rev-missing/render", {}),
        ("post", "/api/engagements/eng-missing/revisions", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/revisions", {}),
    )
    for method, path, body in requests:
        if method == "get":
            reference_response = reference_client.get(path)
            fastapi_response = fastapi_client.get(path)
        else:
            reference_response = getattr(reference_client, method)(path, json=body)
            fastapi_response = getattr(fastapi_client, method)(path, json=body)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_revision_render_matches_reference_contract(tmp_path):
    reference_app, reference_client, fastapi_app, fastapi_client = _separate_clients(tmp_path)
    _seed_engagement(reference_app)
    _seed_engagement(fastapi_app.state.database)
    revision_id = reference_client.post(f"/api/engagements/{ENGAGEMENT_ID}/revisions").get_json()["revision"]["id"]
    fastapi_client.post(f"/api/engagements/{ENGAGEMENT_ID}/revisions")

    reference_destination = tmp_path / "reference-render"
    fastapi_destination = tmp_path / "fastapi-render"
    body = {"renderJobId": "job-fastapi-revision-render"}
    reference_response = reference_client.post(
        f"/api/revisions/{revision_id}/render",
        json={**body, "renderDestination": str(reference_destination)},
    )
    fastapi_response = fastapi_client.post(
        f"/api/revisions/{revision_id}/render",
        json={**body, "renderDestination": str(fastapi_destination)},
    )

    assert fastapi_response.status_code == reference_response.status_code == 200
    assert _scrub_render_root(fastapi_response.json()) == _scrub_render_root(reference_response.get_json())
    assert (fastapi_destination / "engagements" / ENGAGEMENT_ID / "revisions" / "r0001" / "manifest.yaml").exists()
    assert (
        fastapi_destination
        / "engagements"
        / ENGAGEMENT_ID
        / "revisions"
        / "r0001"
        / "validation"
        / "gates.yaml"
    ).exists()


def _clients(tmp_path):
    class SharedSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'barragan.sqlite3'}"

    reference_app = create_reference_app(SharedSqliteConfig)
    fastapi_app = create_fastapi_app(SharedSqliteConfig)
    return reference_app, reference_app.test_client(), fastapi_app.test_client()


def _separate_clients(tmp_path):
    class ReferenceSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'reference.sqlite3'}"

    class FastApiSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'fastapi.sqlite3'}"

    reference_app = create_reference_app(ReferenceSqliteConfig)
    fastapi_app = create_fastapi_app(FastApiSqliteConfig)
    return reference_app, reference_app.test_client(), fastapi_app, fastapi_app.test_client()


def _seed_engagement(reference_app, input_parameters=None) -> None:
    with storage_context(reference_app):
        SqlAlchemyEngagementRepository().save(
            StoredEngagement(
                id=ENGAGEMENT_ID,
                name="Revision FastAPI",
                status="draft",
                owner="operator",
                template_id="standard-rti",
                active_revision=None,
                input_parameters=valid_standard_rti_payload() if input_parameters is None else input_parameters,
                description="FastAPI revision fixture",
                created_at="2026-07-06T00:00:00+00:00",
                updated_at="2026-07-06T00:00:00+00:00",
            )
        )
        db.session.remove()


def _scrub_render_root(body: dict) -> dict:
    scrubbed = dict(body)
    result = dict(scrubbed["renderResult"])
    result["root"] = str(Path("/render-root"))
    scrubbed["renderResult"] = result
    return scrubbed
