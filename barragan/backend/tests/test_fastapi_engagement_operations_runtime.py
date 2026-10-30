# Copyright (c) 2026, Oracle and/or its affiliates.
from fastapi.testclient import TestClient

from app import create_app as create_reference_app
from app.asgi import create_app as create_fastapi_app
from app.core.config import TestConfig
from app.storage.database import db
from app.storage.engagement_repository import SqlAlchemyEngagementRepository, StoredEngagement


ENGAGEMENT_ID = "eng-fastapi-ops"
ENGAGEMENT_NAME = "FAO01"


def test_fastapi_engagement_operations_read_routes_match_reference_contract(tmp_path, monkeypatch):
    reference_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_engagement(reference_app)
    monkeypatch.setattr(
        "app.services.provider_reconciliation.discover_provider_resources",
        lambda: (_ for _ in ()).throw(AssertionError("provider discovery should be explicit")),
    )

    for path in (
        f"/api/engagements/{ENGAGEMENT_ID}/operations",
        "/api/engagements/eng-missing/operations",
    ):
        reference_response = reference_client.get(path)
        fastapi_response = fastapi_client.get(path)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_engagement_operations_patch_matches_reference_contract(tmp_path):
    reference_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_engagement(reference_app)

    body = {"housekeepingItems": "Checked routing assumptions.", "ansibleTerraformUrl": "https://ignored.example.invalid"}
    reference_response = reference_client.patch(f"/api/engagements/{ENGAGEMENT_ID}/operations", json=body)
    fastapi_response = fastapi_client.patch(f"/api/engagements/{ENGAGEMENT_ID}/operations", json=body)

    assert fastapi_response.status_code == reference_response.status_code
    assert fastapi_response.json()["operations"]["housekeepingItems"] == reference_response.get_json()["operations"]["housekeepingItems"]
    assert "ansibleTerraformUrl" not in fastapi_response.json()["operations"]


def test_fastapi_engagement_operations_validation_matches_reference_contract(tmp_path):
    reference_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_engagement(reference_app)

    for path, body in (
        (f"/api/engagements/{ENGAGEMENT_ID}/operations", {"outboundChannels": "not-an-array"}),
        ("/api/engagements/eng-missing/operations", {"housekeepingItems": "missing"}),
    ):
        reference_response = reference_client.patch(path, json=body)
        fastapi_response = fastapi_client.patch(path, json=body)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_engagement_operations_live_provider_findings_match_reference_contract(tmp_path, monkeypatch):
    reference_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_engagement(reference_app)
    monkeypatch.setattr("app.services.provider_reconciliation.discover_provider_resources", lambda: [_provider_resource()])

    for path in (
        f"/api/engagements/{ENGAGEMENT_ID}/operations?live=1",
        f"/api/engagements/{ENGAGEMENT_ID}/operations?includeProviderFindings=1",
    ):
        reference_response = reference_client.get(path)
        fastapi_response = fastapi_client.get(path)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json()["operations"]["providerFindings"] == reference_response.get_json()["operations"]["providerFindings"]
        assert fastapi_response.json()["operations"]["providerFindings"][0]["candidateId"] == "oci:compute_instance:ocid1.instance.oc1..fao"


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
                owner="operator",
                template_id="",
                active_revision=None,
                input_parameters={},
                description="FastAPI engagement operations fixture",
                created_at="2026-07-06T00:00:00+00:00",
                updated_at="2026-07-06T00:00:00+00:00",
            )
        )
        db.session.remove()


def _provider_resource() -> dict[str, object]:
    return {
        "provider": "oci",
        "resourceType": "compute_instance",
        "resourceId": "ocid1.instance.oc1..fao",
        "name": "homebase-fao01",
        "region": "us-sanjose-1",
        "lifecycleState": "RUNNING",
        "engagementId": ENGAGEMENT_ID,
        "engagementName": ENGAGEMENT_NAME,
        "metadata": {},
        "source": "provider_inventory",
    }
