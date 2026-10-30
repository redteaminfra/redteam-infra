# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from app import create_app as create_reference_app
from app.asgi import create_app as create_fastapi_app
from app.core.config import TestConfig
from app.services.credentials import test_master_key as credential_test_master_key
from app.storage.database import db
from app.storage.engagement_repository import SqlAlchemyEngagementRepository, StoredEngagement
from app.storage.models import SketchChainModel
from tests.runtime_support import storage_context


ENGAGEMENT_ID = "eng-fastapi-sketch-key"


def test_fastapi_sketch_ssh_key_lifecycle_matches_reference_contract(tmp_path, monkeypatch):
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", credential_test_master_key())
    reference_app, reference_client, fastapi_app, fastapi_client = _separate_clients(tmp_path)
    _seed_engagement(reference_app, ENGAGEMENT_ID, "SKKEY01")
    _seed_engagement(fastapi_app.state.database, ENGAGEMENT_ID, "SKKEY01")

    requests = (
        ("get", f"/api/engagements/{ENGAGEMENT_ID}/sketch-ssh-key", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-ssh-key", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-ssh-key", {}),
        ("get", f"/api/engagements/{ENGAGEMENT_ID}/sketch-ssh-key", {}),
        ("get", f"/api/engagements/{ENGAGEMENT_ID}/sketch-ssh-key/material", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-ssh-key/rotation-preview", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-ssh-key/rotate", {"confirmation": "wrong"}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-ssh-key/rotate", {"confirmation": "rotate-sketch-key"}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-ssh-key/removal-preview", {}),
        ("delete", f"/api/engagements/{ENGAGEMENT_ID}/sketch-ssh-key", {"confirmation": "wrong"}),
        ("delete", f"/api/engagements/{ENGAGEMENT_ID}/sketch-ssh-key", {"confirmation": "remove-sketch-key"}),
        ("get", f"/api/engagements/{ENGAGEMENT_ID}/sketch-ssh-key", {}),
        ("get", f"/api/engagements/{ENGAGEMENT_ID}/sketch-ssh-key/material", {}),
    )

    for method, path, body in requests:
        reference_response = _request(reference_client, method, path, body)
        fastapi_response = _request(fastapi_client, method, path, body)

        assert fastapi_response.status_code == reference_response.status_code
        assert _scrub_volatile(fastapi_response.json()) == _scrub_volatile(reference_response.get_json())


def test_fastapi_sketch_ssh_key_blocker_shapes_match_reference_contract(tmp_path, monkeypatch):
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", credential_test_master_key())
    reference_app, reference_client, fastapi_app, fastapi_client = _separate_clients(tmp_path)
    _seed_engagement(reference_app, ENGAGEMENT_ID, "SKKEY02")
    _seed_engagement(fastapi_app.state.database, ENGAGEMENT_ID, "SKKEY02")
    _seed_deployed_chain(reference_app, ENGAGEMENT_ID)
    _seed_deployed_chain(fastapi_app.state.database, ENGAGEMENT_ID)
    _request(reference_client, "post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-ssh-key", {})
    _request(fastapi_client, "post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-ssh-key", {})

    requests = (
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-ssh-key/rotate", {"confirmation": "rotate-sketch-key"}),
        ("delete", f"/api/engagements/{ENGAGEMENT_ID}/sketch-ssh-key", {"confirmation": "remove-sketch-key"}),
        ("post", "/api/engagements/eng-missing/sketch-ssh-key/rotation-preview", {}),
        ("post", "/api/engagements/eng-missing/sketch-ssh-key/removal-preview", {}),
        ("post", "/api/engagements/eng-missing/sketch-ssh-key", {}),
    )
    for method, path, body in requests:
        reference_response = _request(reference_client, method, path, body)
        fastapi_response = _request(fastapi_client, method, path, body)

        assert fastapi_response.status_code == reference_response.status_code
        assert _scrub_volatile(fastapi_response.json()) == _scrub_volatile(reference_response.get_json())


def _separate_clients(tmp_path):
    class ReferenceSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'reference.sqlite3'}"

    class FastApiSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'fastapi.sqlite3'}"

    reference_app = create_reference_app(ReferenceSqliteConfig)
    fastapi_app = create_fastapi_app(FastApiSqliteConfig)
    return reference_app, reference_app.test_client(), fastapi_app, fastapi_app.test_client()


def _request(client, method: str, path: str, body: dict[str, Any]):
    if isinstance(client, TestClient):
        return client.request(method.upper(), path, json=body)
    return client.open(path, method=method.upper(), json=body)


def _seed_engagement(reference_app, engagement_id: str, name: str) -> None:
    with storage_context(reference_app):
        SqlAlchemyEngagementRepository().save(
            StoredEngagement(
                id=engagement_id,
                name=name,
                status="draft",
                owner="operator",
                template_id="standard-rti",
                active_revision=None,
                input_parameters={},
                description="FastAPI sketch SSH key fixture",
                created_at="2026-07-06T00:00:00+00:00",
                updated_at="2026-07-06T00:00:00+00:00",
            )
        )
        db.session.remove()


def _seed_deployed_chain(reference_app, engagement_id: str) -> None:
    with storage_context(reference_app):
        db.session.add(
            SketchChainModel(
                engagement_id=engagement_id,
                chain_id="proxy01-sea-01",
                assigned_proxy="proxy01",
                middle_provider="linode",
                middle_region="us-sea",
                middle_size="g6-nanode-1",
                edge_provider="linode",
                edge_region="us-sea",
                edge_size="g6-nanode-1",
                status="deployed",
                nodes=[
                    {
                        "hostname": "middle-skkey-proxy01-sea-01",
                        "role": "middle",
                        "provider": "linode",
                        "publicIp": "203.0.113.30",
                    }
                ],
            )
        )
        db.session.commit()
        db.session.remove()


def _scrub_volatile(value):
    if isinstance(value, dict):
        scrubbed = {}
        for key, item in value.items():
            if key in {"createdAt", "updatedAt", "retiredAt"} and item:
                scrubbed[key] = "<timestamp>"
            elif key in {"fingerprint", "previousFingerprint", "removedFingerprint"} and item:
                scrubbed[key] = "<fingerprint>"
            elif key in {"privateKey", "publicKey"} and item:
                scrubbed[key] = f"<{key}>"
            else:
                scrubbed[key] = _scrub_volatile(item)
        return scrubbed
    if isinstance(value, list):
        return [_scrub_volatile(item) for item in value]
    return value
