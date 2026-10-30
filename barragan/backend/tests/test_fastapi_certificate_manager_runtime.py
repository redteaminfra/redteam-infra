# Copyright (c) 2026, Oracle and/or its affiliates.
from fastapi.testclient import TestClient

from app import create_app as create_reference_app
from app.asgi import create_app as create_fastapi_app
from app.core.config import TestConfig
from app.domain import JobEvent
from app.storage.certificate_repository import SqlAlchemyCertificateRepository, StoredCertificateAsset
from app.storage.database import db
from app.storage.domain_repository import SqlAlchemyDomainRepository, StoredDomainAsset, StoredDomainAssignment
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun


NOW = "2026-07-06T00:00:00+00:00"
ENGAGEMENT_ID = "eng-of02-dev"
CERTIFICATE_ID = "cert-fastapi-manager"


def test_fastapi_certificate_manager_read_routes_match_reference_contract(tmp_path):
    reference_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_certificate_fixture(reference_app)

    for path in (
        f"/api/engagements/{ENGAGEMENT_ID}/certificate-profile",
        f"/api/engagements/{ENGAGEMENT_ID}/certificates",
        f"/api/engagements/{ENGAGEMENT_ID}/certificates/{CERTIFICATE_ID}",
        "/api/engagements/eng-missing/certificate-profile",
        "/api/engagements/eng-missing/certificates",
        f"/api/engagements/{ENGAGEMENT_ID}/certificates/cert-missing",
    ):
        reference_response = reference_client.get(path)
        fastapi_response = fastapi_client.get(path)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_certificate_manager_mutations_preserve_contract_shapes(tmp_path):
    reference_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_certificate_fixture(reference_app)

    profile = fastapi_client.patch(
        f"/api/engagements/{ENGAGEMENT_ID}/certificate-profile",
        json={"acmeEmail": "operator@example.com", "defaultEnvironment": "production"},
    )
    invalid_profile = fastapi_client.patch(
        f"/api/engagements/{ENGAGEMENT_ID}/certificate-profile",
        json={"acmeEmail": "not-an-email", "defaultEnvironment": "invalid"},
    )
    notes = fastapi_client.patch(
        f"/api/engagements/{ENGAGEMENT_ID}/certificates/{CERTIFICATE_ID}",
        json={"notes": "Updated opaque test note"},
    )
    invalid_notes = fastapi_client.patch(
        f"/api/engagements/{ENGAGEMENT_ID}/certificates/{CERTIFICATE_ID}",
        json={"name": "Not allowed"},
    )
    missing_notes = fastapi_client.patch(
        f"/api/engagements/{ENGAGEMENT_ID}/certificates/cert-missing",
        json={"notes": "Missing"},
    )

    assert profile.status_code == 200
    assert profile.json()["profile"]["acmeEmail"] == "operator@example.com"
    assert profile.json()["profile"]["defaultEnvironment"] == "production"
    assert invalid_profile.status_code == 400
    assert invalid_profile.json() == {
        "errors": ["acmeEmail must be a valid email address", "defaultEnvironment must be staging or production"]
    }
    assert notes.status_code == 200
    assert notes.json()["certificate"]["notes"] == "Updated opaque test note"
    assert invalid_notes.status_code == 400
    assert invalid_notes.json() == {"errors": ["unsupported certificate metadata fields: name"]}
    assert missing_notes.status_code == 404
    assert missing_notes.json() == {"error": "certificate not found"}

    # The Reference fallback and FastAPI implementation should agree on validation
    # failures that do not mutate state.
    reference_invalid = reference_client.patch(
        f"/api/engagements/{ENGAGEMENT_ID}/certificates/{CERTIFICATE_ID}",
        json={"name": "Not allowed"},
    )
    assert invalid_notes.json() == reference_invalid.get_json()


def _clients(tmp_path):
    class SharedSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'barragan.sqlite3'}"

    reference_app = create_reference_app(SharedSqliteConfig)
    fastapi_app = create_fastapi_app(SharedSqliteConfig)
    return reference_app, reference_app.test_client(), fastapi_app.test_client()


def _seed_certificate_fixture(reference_app) -> None:
    with reference_app.storage_context():
        domain_repo = SqlAlchemyDomainRepository()
        asset = domain_repo.save_asset(
            StoredDomainAsset(
                id="dom-fastapi-certificate",
                domain_name="fastapi-certificate.example",
                registrar="namecheap",
                registration_started_at="2026-01-01",
                expiration_at="2027-01-01",
                auto_renew=True,
                provider_status="active",
                notes="",
                risk_status="clear",
                risk_flags=(),
                cooldown_until="",
                assignable_override=False,
                metadata={"isOurDNS": True},
                last_synced_at=NOW,
                created_at=NOW,
                updated_at=NOW,
                catalog_state="auto",
            )
        )
        domain_repo.save_assignment(
            StoredDomainAssignment(
                id=None,
                domain_id=asset.id,
                engagement_id=ENGAGEMENT_ID,
                engagement_name="of02-dev reference",
                purpose="website",
                status="active",
                notes="",
                assigned_by="pytest",
                released_by="",
                assigned_at=NOW,
                released_at=None,
                purpose_tags=["website"],
            )
        )
        SqlAlchemyJobRepository().save(
            StoredJobRun(
                id="job-fastapi-certificate-ops",
                action="engagement_channels_update",
                status="succeeded",
                target=f"engagement:{ENGAGEMENT_ID}",
                target_type="engagement",
                target_id=ENGAGEMENT_ID,
                requested_by="pytest",
                input={"engagementId": ENGAGEMENT_ID},
                artifact_refs=[],
                created_at=NOW,
                started_at=NOW,
                finished_at=NOW,
                events=[
                    JobEvent(
                        1,
                        "info",
                        "operations ready",
                        {
                            "coreInfrastructure": [
                                {
                                    "hostname": "proxy01-of02-dev",
                                    "role": "proxy",
                                    "status": "deployed",
                                    "publicIp": "203.0.113.11",
                                }
                            ],
                            "inboundChannels": [],
                            "outboundChannels": [],
                            "sketchInfrastructure": [],
                        },
                    )
                ],
            )
        )
        SqlAlchemyCertificateRepository().save_asset(
            StoredCertificateAsset(
                id=CERTIFICATE_ID,
                engagement_id=ENGAGEMENT_ID,
                name="FastAPI manager cert",
                source="letsencrypt",
                target_proxy_id="proxy01-of02-dev",
                identifiers=("fastapi-certificate.example",),
                primary_identifier="fastapi-certificate.example",
                status="draft",
                notes="Initial opaque test note",
                created_at=NOW,
                updated_at=NOW,
            )
        )
        db.session.remove()
