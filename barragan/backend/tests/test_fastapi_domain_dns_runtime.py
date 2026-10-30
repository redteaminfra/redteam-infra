# Copyright (c) 2026, Oracle and/or its affiliates.
from dataclasses import dataclass

from fastapi.testclient import TestClient

from app import create_app as create_reference_app
from app.asgi import create_app as create_fastapi_app
from app.core.config import TestConfig
from app.integrations.namecheap import NamecheapHost
from app.services.domains import assign_domain
from app.storage.database import db
from app.storage.domain_repository import SqlAlchemyDomainRepository, StoredDomainAsset, StoredDomainDnsSnapshot
from tests.runtime_support import storage_context


def test_fastapi_domain_read_routes_match_reference_contract(tmp_path):
    config = _test_config(tmp_path)
    reference_app = create_reference_app(config)
    fastapi_client = create_fastapi_app(config).test_client()
    reference_client = reference_app.test_client()
    domain_id = _seed_domain_fixture(reference_app)

    for path in (
        "/api/domains",
        "/api/domains/purposes",
        f"/api/domains/{domain_id}",
        f"/api/domains/{domain_id}/hosts",
        "/api/domains/domain-missing",
        "/api/domains/domain-missing/hosts",
    ):
        reference_response = reference_client.get(path)
        fastapi_response = fastapi_client.get(path)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_engagement_domain_and_dns_read_routes_match_reference_contract(tmp_path):
    config = _test_config(tmp_path)
    reference_app = create_reference_app(config)
    fastapi_client = create_fastapi_app(config).test_client()
    reference_client = reference_app.test_client()
    _seed_domain_fixture(reference_app)

    for path in (
        "/api/engagements/eng-of02-dev/domains",
        "/api/engagements/eng-of02-dev/dns",
        "/api/engagements/eng-missing/domains",
        "/api/engagements/eng-missing/dns",
    ):
        reference_response = reference_client.get(path)
        fastapi_response = fastapi_client.get(path)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_domain_mutation_routes_match_reference_contract(tmp_path):
    reference_app, fastapi_app, reference_client, fastapi_client = _separate_clients(tmp_path)
    domain_id = "dom-fastapi-mutation"
    _seed_unassigned_domain(reference_app, domain_id, "fastapi-mutation.example")
    _seed_unassigned_domain(fastapi_app, domain_id, "fastapi-mutation.example")

    requests = (
        ("post", f"/api/domains/{domain_id}/assign", {"engagementId": "eng-of02-dev", "purposeTags": ["rti"], "assignedBy": "pytest"}),
        ("patch", f"/api/domains/{domain_id}/assignment", {"purposeTags": ["dns", "redirector"]}),
        ("patch", f"/api/domains/{domain_id}/risk", {"riskStatus": "cooldown", "riskFlags": ["review"], "notes": "opaque test note"}),
        ("patch", f"/api/domains/{domain_id}/catalog-state", {"catalogState": "waiting_to_be_used"}),
        ("post", f"/api/domains/{domain_id}/release", {"releasedBy": "pytest"}),
        ("patch", f"/api/domains/{domain_id}/catalog-state", {"catalogState": "used_in_past_engagements"}),
    )
    for method, path, body in requests:
        reference_response = getattr(reference_client, method)(path, json=body)
        fastapi_response = getattr(fastapi_client, method)(path, json=body)

        assert fastapi_response.status_code == reference_response.status_code
        assert _scrub_volatile(fastapi_response.json()) == _scrub_volatile(reference_response.get_json())


def test_fastapi_domain_validation_and_missing_shapes_match_reference_contract(tmp_path):
    reference_app, fastapi_app, reference_client, fastapi_client = _separate_clients(tmp_path)
    domain_id = "dom-fastapi-validation"
    _seed_unassigned_domain(reference_app, domain_id, "fastapi-validation.example")
    _seed_unassigned_domain(fastapi_app, domain_id, "fastapi-validation.example")

    for method, path, body in (
        ("post", "/api/domains/domain-missing/assign", {"engagementId": "eng-of02-dev", "purposeTags": ["rti"]}),
        ("post", f"/api/domains/{domain_id}/assign", {"engagementId": "", "purposeTags": ["rti"]}),
        ("post", f"/api/domains/{domain_id}/release", {}),
        ("patch", f"/api/domains/{domain_id}/assignment", {"purposeTags": ["rti"]}),
        ("patch", f"/api/domains/{domain_id}/risk", {"riskStatus": "invalid"}),
        ("patch", f"/api/domains/{domain_id}/catalog-state", {"catalogState": "invalid"}),
    ):
        reference_response = getattr(reference_client, method)(path, json=body)
        fastapi_response = getattr(fastapi_client, method)(path, json=body)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_namecheap_sync_route_matches_reference_contract(tmp_path, monkeypatch):
    reference_client, fastapi_client = _separate_clients(tmp_path)[2:]
    monkeypatch.setattr("app.services.domains._namecheap_client", lambda alias=None: FakeNamecheapAdapter())

    reference_response = reference_client.post("/api/domains/sync/namecheap", json={"includeHosts": True, "requestedBy": "pytest"})
    fastapi_response = fastapi_client.post("/api/domains/sync/namecheap", json={"includeHosts": True, "requestedBy": "pytest"})

    assert fastapi_response.status_code == reference_response.status_code == 201
    assert _scrub_volatile(fastapi_response.json()) == _scrub_volatile(reference_response.get_json())
    assert "secret" not in str(fastapi_response.json()).lower()


def test_fastapi_engagement_dns_preview_and_apply_validation_match_reference_contract(tmp_path, monkeypatch):
    reference_app, fastapi_app, reference_client, fastapi_client = _separate_clients(tmp_path)
    domain_id = "dom-fastapi-dns"
    _seed_assigned_domain(reference_app, domain_id, "fastapi-dns.example")
    _seed_assigned_domain(fastapi_app, domain_id, "fastapi-dns.example")
    monkeypatch.setattr("app.services.engagement_dns._dns_client_for_asset", lambda asset, body: FakeDnsAdapter())
    preview_body = {
        "domainId": domain_id,
        "records": [{"name": "@", "type": "A", "address": "203.0.113.20", "ttl": "600"}],
    }

    reference_preview = reference_client.post("/api/engagements/eng-of02-dev/dns/preview", json=preview_body)
    fastapi_preview = fastapi_client.post("/api/engagements/eng-of02-dev/dns/preview", json=preview_body)

    assert fastapi_preview.status_code == reference_preview.status_code == 201
    assert _scrub_volatile(fastapi_preview.json()) == _scrub_volatile(reference_preview.get_json())

    reference_apply = reference_client.post("/api/engagements/eng-of02-dev/dns/apply", json=preview_body)
    fastapi_apply = fastapi_client.post("/api/engagements/eng-of02-dev/dns/apply", json=preview_body)

    assert fastapi_apply.status_code == reference_apply.status_code == 400
    assert fastapi_apply.json() == reference_apply.get_json()

    for path in ("/api/engagements/eng-missing/dns/preview", "/api/engagements/eng-missing/dns/apply"):
        reference_missing = reference_client.post(path, json=preview_body)
        fastapi_missing = fastapi_client.post(path, json=preview_body)
        assert fastapi_missing.status_code == reference_missing.status_code
        assert fastapi_missing.json() == reference_missing.get_json()


def _seed_domain_fixture(reference_app) -> str:
    with storage_context(reference_app):
        repo = SqlAlchemyDomainRepository()
        asset = repo.save_asset(
            StoredDomainAsset(
                id="dom-fastapi-read",
                domain_name="fastapi-read.example",
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
                last_synced_at="2026-07-06T00:00:00+00:00",
                created_at="2026-07-06T00:00:00+00:00",
                updated_at="2026-07-06T00:00:00+00:00",
                catalog_state="auto",
            )
        )
        repo.save_snapshot(
            StoredDomainDnsSnapshot(
                id=None,
                domain_id=asset.id,
                provider="namecheap",
                hosts=[
                    {
                        "name": "@",
                        "type": "TXT",
                        "address": "8b87f3d8-ef1c-4188-912e-eba1049a1c02",
                        "ttl": "300",
                        "mxPref": "",
                        "hostId": "1",
                    }
                ],
                source="provider_snapshot",
                sync_job_id="job-fastapi-read",
                fetched_at="2026-07-06T00:00:00+00:00",
            )
        )
        assign_domain(asset.id, {"engagementId": "eng-of02-dev", "purposeTags": ["rti"], "assignedBy": "pytest"}, repository=repo)
        db.session.remove()
        return asset.id


def _seed_unassigned_domain(app, domain_id: str, domain_name: str) -> None:
    with storage_context(app):
        SqlAlchemyDomainRepository().save_asset(
            StoredDomainAsset(
                id=domain_id,
                domain_name=domain_name,
                registrar="namecheap",
                registration_started_at="2026-01-01",
                expiration_at="2027-01-01",
                auto_renew=True,
                provider_status="active",
                notes="",
                risk_status="clear",
                risk_flags=[],
                cooldown_until="",
                assignable_override=False,
                metadata={"isOurDNS": True},
                last_synced_at="2026-07-06T00:00:00+00:00",
                created_at="2026-07-06T00:00:00+00:00",
                updated_at="2026-07-06T00:00:00+00:00",
                catalog_state="auto",
            )
        )
        db.session.remove()


def _seed_assigned_domain(app, domain_id: str, domain_name: str) -> None:
    _seed_unassigned_domain(app, domain_id, domain_name)
    with storage_context(app):
        assign_domain(domain_id, {"engagementId": "eng-of02-dev", "purposeTags": ["rti"], "assignedBy": "pytest"})
        db.session.remove()


def _test_config(tmp_path):
    class SharedSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'barragan.sqlite3'}"

    return SharedSqliteConfig


def _separate_clients(tmp_path):
    class ReferenceSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'reference.sqlite3'}"

    class FastApiSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'fastapi.sqlite3'}"

    reference_app = create_reference_app(ReferenceSqliteConfig)
    fastapi_app = create_fastapi_app(FastApiSqliteConfig)
    return reference_app, fastapi_app.state.database, reference_app.test_client(), fastapi_app.test_client()


@dataclass(frozen=True)
class FakeNamecheapDomain:
    name: str
    created: str = "2026-01-01"
    expires: str = "2027-01-01"
    auto_renew: bool = True
    status: str = "active"
    metadata: dict | None = None


@dataclass(frozen=True)
class FakeNamecheapHost:
    name: str
    record_type: str
    address: str
    ttl: str = "600"
    mx_pref: str = ""
    host_id: str = ""


class FakeNamecheapAdapter:
    def get_domains(self):
        return [FakeNamecheapDomain("FastAPI-Sync.example", metadata={"isOurDNS": True})]

    def get_hosts(self, domain_name: str):
        return [FakeNamecheapHost("@", "A", "203.0.113.10", host_id="host-1")]


class FakeDnsAdapter:
    def __init__(self):
        self.hosts = [FakeNamecheapHost("@", "A", "203.0.113.10", host_id="provider-1")]

    def get_hosts(self, domain_name: str):
        return list(self.hosts)

    def set_hosts(self, domain_name: str, hosts: list[NamecheapHost]) -> bool:
        self.hosts = [
            FakeNamecheapHost(host.name, host.record_type, host.address, host.ttl, host.mx_pref)
            for host in hosts
        ]
        return True


def _scrub_volatile(value):
    if isinstance(value, dict):
        return {
            key: _scrub_volatile(item)
            for key, item in value.items()
            if key not in {"id", "createdAt", "updatedAt", "assignedAt", "releasedAt", "lastSyncedAt", "syncJobId", "fetchedAt", "created_at", "updated_at", "startedAt", "finishedAt"}
        }
    if isinstance(value, list):
        return [_scrub_volatile(item) for item in value]
    if isinstance(value, str) and value.startswith("job-"):
        return "job-scrubbed"
    return value
