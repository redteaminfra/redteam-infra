# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from app import create_app as create_reference_app
from app.asgi import create_app as create_fastapi_app
from app.core.config import TestConfig
from app.storage.database import db
from app.storage.engagement_repository import SqlAlchemyEngagementRepository, StoredEngagement
from app.storage.models import SketchChainModel
from tests.runtime_support import storage_context


ENGAGEMENT_ID = "eng-fastapi-sketch-chains"


def test_fastapi_sketch_chain_crud_and_validation_match_reference_contract(tmp_path):
    reference_app, reference_client, fastapi_app, fastapi_client = _separate_clients(tmp_path)
    _seed_engagement(reference_app)
    _seed_engagement(fastapi_app.state.database)

    requests = (
        ("get", f"/api/engagements/{ENGAGEMENT_ID}/sketch-chains", {}),
        ("get", "/api/engagements/eng-missing/sketch-chains", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-chains", {}),
        (
            "post",
            f"/api/engagements/{ENGAGEMENT_ID}/sketch-chains",
            {
                "assignedProxy": "proxy01",
                "middleProvider": "linode",
                "middleRegion": "us-sea",
                "middleSize": "g6-nanode-1",
                "edgeProvider": "linode",
                "edgeRegion": "us-sea",
                "edgeSize": "g6-nanode-1",
            },
        ),
        ("patch", f"/api/engagements/{ENGAGEMENT_ID}/sketch-chains/proxy01-sea-01", {"burned": True, "burnedNote": "parity"}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-chains/proxy01-sea-01/cancel", {"confirmation": "wrong"}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-chains/proxy01-sea-01/cancel", {"confirmation": "cancel-proxy01-sea-01"}),
        ("patch", f"/api/engagements/{ENGAGEMENT_ID}/sketch-chains/missing-chain", {"burned": True}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-chains/missing-chain/cancel", {"confirmation": "cancel-missing-chain"}),
    )
    for method, path, body in requests:
        reference_response = _request(reference_client, method, path, body)
        fastapi_response = _request(fastapi_client, method, path, body)

        assert fastapi_response.status_code == reference_response.status_code
        assert _scrub_volatile(fastapi_response.json()) == _scrub_volatile(reference_response.get_json())


def test_fastapi_sketch_chain_lifecycle_routes_match_reference_contract(tmp_path, monkeypatch):
    reference_app, reference_client, fastapi_app, fastapi_client = _separate_clients(tmp_path)
    _seed_engagement(reference_app)
    _seed_engagement(fastapi_app.state.database)
    _seed_chain(reference_app, status="deployed")
    _seed_chain(fastapi_app.state.database, status="deployed")
    _patch_lifecycle_functions(monkeypatch)

    requests = (
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-chains/proxy01-sea-01/deploy", {"confirmMutation": "mutate-linode-sketch"}, 202),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-chains/proxy01-sea-01/refresh", {}, 200),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-chains/proxy01-sea-01/stop", {"confirmation": "stop-proxy01-sea-01"}, 202),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-chains/proxy01-sea-01/start", {"confirmation": "start-proxy01-sea-01"}, 202),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-chains/proxy01-sea-01/teardown", {"confirmation": "teardown-proxy01-sea-01"}, 202),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-chains/proxy01-sea-01/edges/retire", {"edgeId": "edge-02", "confirmation": "retire-edge-proxy01-sea-01-edge-02"}, 202),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-chains/proxy01-sea-01/edges/replace", {"region": "us-dal", "confirmation": "replace-edge-proxy01-sea-01-us-dal"}, 202),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-chains/missing-chain/refresh", {}, 404),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-chains/missing-chain/deploy", {}, 404),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/sketch-chains/proxy01-sea-01/stop", {"confirmation": "wrong"}, 400),
    )
    for method, path, body, expected_status in requests:
        reference_response = _request(reference_client, method, path, body)
        fastapi_response = _request(fastapi_client, method, path, body)

        assert fastapi_response.status_code == reference_response.status_code == expected_status
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


def _seed_engagement(reference_app) -> None:
    with storage_context(reference_app):
        SqlAlchemyEngagementRepository().save(
            StoredEngagement(
                id=ENGAGEMENT_ID,
                name="FastAPI Sketch Chains",
                status="draft",
                owner="operator",
                template_id="standard-rti",
                active_revision=None,
                input_parameters={},
                description="FastAPI sketch chains fixture",
                created_at="2026-07-06T00:00:00+00:00",
                updated_at="2026-07-06T00:00:00+00:00",
            )
        )
        db.session.remove()


def _seed_chain(reference_app, *, status: str) -> None:
    with storage_context(reference_app):
        db.session.add(
            SketchChainModel(
                engagement_id=ENGAGEMENT_ID,
                chain_id="proxy01-sea-01",
                assigned_proxy="proxy01",
                middle_provider="linode",
                middle_region="us-sea",
                middle_size="g6-nanode-1",
                edge_provider="linode",
                edge_region="us-sea",
                edge_size="g6-nanode-1",
                status=status,
                deploy_job_id="job-sketch-deploy",
                terraform_working_directory="/tmp/sketch",
                nodes=[
                    {
                        "chainId": "proxy01-sea-01",
                        "hostname": "edge-fastapi-sketch",
                        "provider": "linode",
                        "role": "edge",
                        "publicIp": "203.0.113.42",
                        "region": "us-sea",
                        "proxy": "proxy01",
                        "status": status,
                    }
                ],
            )
        )
        db.session.commit()
        db.session.remove()


def _patch_lifecycle_functions(monkeypatch) -> None:
    from app.services.sketch_chains import SketchChainValidationError

    def _none_if_missing(_engagement_id: str, chain_id: str, payload: dict[str, Any]):
        if chain_id != "proxy01-sea-01":
            return None
        return payload

    def deploy(engagement_id: str, chain_id: str, body: dict[str, Any]):
        return _none_if_missing(engagement_id, chain_id, {"chain": _chain_payload("deploying"), "job": _job_payload("job-sketch-deploy", "linode_sketch_deploy")})

    def refresh(engagement_id: str, chain_id: str):
        return _none_if_missing(engagement_id, chain_id, {"sketchChain": _chain_payload("deployed")})

    def stop(engagement_id: str, chain_id: str, body: dict[str, Any]):
        if body.get("confirmation") != f"stop-{chain_id}":
            raise SketchChainValidationError([f'confirmation must equal "stop-{chain_id}"'])
        return _none_if_missing(engagement_id, chain_id, {"chain": _chain_payload("stopped"), "job": _job_payload("job-sketch-stop", "sketch_chain_stop")})

    def start(engagement_id: str, chain_id: str, body: dict[str, Any]):
        if body.get("confirmation") != f"start-{chain_id}":
            raise SketchChainValidationError([f'confirmation must equal "start-{chain_id}"'])
        return _none_if_missing(engagement_id, chain_id, {"chain": _chain_payload("deployed"), "job": _job_payload("job-sketch-start", "sketch_chain_start")})

    def teardown(engagement_id: str, chain_id: str, body: dict[str, Any]):
        if body.get("confirmation") != f"teardown-{chain_id}":
            raise SketchChainValidationError([f'confirmation must equal "teardown-{chain_id}"'])
        return _none_if_missing(engagement_id, chain_id, {"chain": _chain_payload("tearing_down"), "job": _job_payload("job-sketch-teardown", "linode_sketch_teardown")})

    def retire_edge(engagement_id: str, chain_id: str, body: dict[str, Any]):
        if body.get("confirmation") != f"retire-edge-{chain_id}-{body.get('edgeId', '')}":
            raise SketchChainValidationError([f'confirmation must equal "retire-edge-{chain_id}-{body.get("edgeId", "")}"'])
        return _none_if_missing(engagement_id, chain_id, {"chain": _chain_payload("reconciling"), "job": _job_payload("job-edge-retire", "sketch_edge_retire")})

    def replace_edge(engagement_id: str, chain_id: str, body: dict[str, Any]):
        if body.get("confirmation") != f"replace-edge-{chain_id}-{body.get('region', '')}":
            raise SketchChainValidationError([f'confirmation must equal "replace-edge-{chain_id}-{body.get("region", "")}"'])
        return _none_if_missing(engagement_id, chain_id, {"chain": _chain_payload("reconciling"), "job": _job_payload("job-edge-replace", "sketch_edge_replace")})

    patches = {
        "deploy_sketch_chain": deploy,
        "refresh_sketch_chain_from_job": refresh,
        "stop_sketch_chain": stop,
        "start_sketch_chain": start,
        "ensure_sketch_chain_teardown": teardown,
        "retire_sketch_chain_final_edge": retire_edge,
        "replace_sketch_chain_final_edge": replace_edge,
    }
    for name, value in patches.items():
        monkeypatch.setattr(f"app.asgi.{name}", value)
        monkeypatch.setattr(f"app.asgi.{name}", value)


def _chain_payload(status: str) -> dict[str, Any]:
    return {
        "chainId": "proxy01-sea-01",
        "engagementId": ENGAGEMENT_ID,
        "assignedProxy": "proxy01",
        "middleProvider": "linode",
        "middleRegion": "us-sea",
        "middleSize": "g6-nanode-1",
        "edgeProvider": "linode",
        "edgeRegion": "us-sea",
        "edgeSize": "g6-nanode-1",
        "status": status,
        "burned": False,
        "burnedNote": "",
        "deployJobId": "job-sketch-deploy",
        "teardownJobId": "",
        "terraformWorkingDirectory": "/tmp/sketch",
        "nodes": [],
        "createdAt": "2026-07-06T00:00:00+00:00",
        "updatedAt": "2026-07-06T00:00:00+00:00",
    }


def _job_payload(job_id: str, action: str) -> dict[str, Any]:
    return {
        "id": job_id,
        "action": action,
        "status": "running",
        "target": f"engagement:{ENGAGEMENT_ID}",
        "targetType": "engagement",
        "targetId": ENGAGEMENT_ID,
        "requestedBy": "operator",
        "input": {"engagementId": ENGAGEMENT_ID, "chainId": "proxy01-sea-01"},
        "artifactRefs": [],
        "createdAt": "2026-07-06T00:00:00+00:00",
        "startedAt": "2026-07-06T00:00:00+00:00",
        "finishedAt": None,
        "events": [],
    }


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
