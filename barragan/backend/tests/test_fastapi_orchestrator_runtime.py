# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi.testclient import TestClient

from app import create_app as create_reference_app
from app.asgi import create_app as create_fastapi_app
from app.core.config import TestConfig
from app.services.credentials import CredentialStoreLockedError
from app.services.digitalocean_provider_validation import DigitalOceanProviderValidationGuardrailError
from app.services.guarded_test_deployment import GuardedDeploymentConfirmationError
from app.services.linode_sketch_deployment import LinodeSketchGuardrailError
from app.services.engagement_teardown import EngagementTeardownValidationError


def test_fastapi_orchestrator_plan_and_readiness_routes_match_reference_contract(tmp_path, monkeypatch):
    _patch_plan_function(monkeypatch)
    _patch_readiness_functions(monkeypatch)
    reference_client, fastapi_client = _separate_clients(tmp_path)

    requests = (
        ("post", "/api/orchestrator/standard-rti/plan", {"engagementId": "eng-fastapi-orchestrator"}),
        ("get", "/api/orchestrator/barragan-testing/disposable/readiness", {}),
        ("get", "/api/orchestrator/barragan-testing/pilot-standard-rti/readiness?engagementId=eng-fastapi-orchestrator", {}),
    )
    for method, path, body in requests:
        reference_response = _request(reference_client, method, path, body)
        fastapi_response = _request(fastapi_client, method, path, body)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_orchestrator_disposable_and_pilot_mutation_routes_match_reference_contract(tmp_path, monkeypatch):
    _patch_guarded_deployment_functions(monkeypatch)
    reference_client, fastapi_client = _separate_clients(tmp_path)

    requests = (
        ("post", "/api/orchestrator/barragan-testing/disposable/run", {"confirmMutation": "ok"}),
        ("post", "/api/orchestrator/barragan-testing/disposable/run", {"confirmMutation": "bad"}),
        ("post", "/api/orchestrator/barragan-testing/pilot-standard-rti/run", {"confirmMutation": "ok"}),
        ("post", "/api/orchestrator/barragan-testing/pilot-standard-rti/run", {"confirmMutation": "bad"}),
        ("post", "/api/orchestrator/barragan-testing/pilot-standard-rti/runs", {"confirmMutation": "ok"}),
        ("post", "/api/orchestrator/barragan-testing/pilot-standard-rti/runs", {"confirmMutation": "bad"}),
        ("get", "/api/orchestrator/barragan-testing/pilot-standard-rti/runs/job-pilot", {}),
        ("get", "/api/orchestrator/barragan-testing/pilot-standard-rti/runs/job-missing", {}),
        ("post", "/api/orchestrator/barragan-testing/pilot-standard-rti/runs/job-pilot/teardown", {}),
        ("post", "/api/orchestrator/barragan-testing/pilot-standard-rti/runs/job-missing/teardown", {}),
    )
    for method, path, body in requests:
        reference_response = _request(reference_client, method, path, body)
        fastapi_response = _request(fastapi_client, method, path, body)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_orchestrator_sketch_provider_routes_match_reference_contract(tmp_path, monkeypatch):
    _patch_linode_sketch_functions(monkeypatch)
    _patch_digitalocean_validation_functions(monkeypatch)
    reference_client, fastapi_client = _separate_clients(tmp_path)

    requests = (
        ("post", "/api/orchestrator/barragan-testing/linode-sketch/runs", {"confirmMutation": "ok"}),
        ("post", "/api/orchestrator/barragan-testing/linode-sketch/runs", {"confirmMutation": "bad"}),
        ("post", "/api/orchestrator/barragan-testing/linode-sketch/runs", {"confirmMutation": "locked"}),
        ("get", "/api/orchestrator/barragan-testing/linode-sketch/runs/job-linode", {}),
        ("get", "/api/orchestrator/barragan-testing/linode-sketch/runs/job-missing", {}),
        ("post", "/api/orchestrator/barragan-testing/linode-sketch/runs/job-linode/teardown", {}),
        ("post", "/api/orchestrator/barragan-testing/linode-sketch/runs/job-missing/teardown", {}),
        ("post", "/api/orchestrator/barragan-testing/digitalocean-sketch/validation-runs", {"confirmCreateDestroy": "ok"}),
        ("post", "/api/orchestrator/barragan-testing/digitalocean-sketch/validation-runs", {"confirmCreateDestroy": "bad"}),
        ("post", "/api/orchestrator/barragan-testing/digitalocean-sketch/validation-runs", {"confirmCreateDestroy": "locked"}),
        ("get", "/api/orchestrator/barragan-testing/digitalocean-sketch/validation-runs/job-do", {}),
        ("get", "/api/orchestrator/barragan-testing/digitalocean-sketch/validation-runs/job-missing", {}),
    )
    for method, path, body in requests:
        reference_response = _request(reference_client, method, path, body)
        fastapi_response = _request(fastapi_client, method, path, body)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def test_active_comprehensive_teardown_rejects_direct_core_sketch_and_inspection_mutations(tmp_path, monkeypatch):
    class FastApiSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'conflict.sqlite3'}"

    def reject(_engagement_id: str):
        raise EngagementTeardownValidationError(["engagement teardown is running"])

    monkeypatch.setattr("app.asgi.assert_engagement_mutation_allowed", reject)
    client = create_fastapi_app(FastApiSqliteConfig).test_client()
    requests = (
        ("/api/orchestrator/barragan-testing/pilot-standard-rti/runs", {"engagementId": "eng-locked"}),
        ("/api/orchestrator/barragan-testing/linode-sketch/runs", {"engagementId": "eng-locked"}),
        ("/api/engagements/eng-locked/inspections", {}),
    )
    for path, body in requests:
        response = client.post(path, json=body)
        assert response.status_code == 409
        assert response.get_json()["errors"] == ["engagement teardown is running"]


def _separate_clients(tmp_path):
    class ReferenceSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'reference.sqlite3'}"

    class FastApiSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'fastapi.sqlite3'}"

    reference_app = create_reference_app(ReferenceSqliteConfig)
    fastapi_app = create_fastapi_app(FastApiSqliteConfig)
    return reference_app.test_client(), fastapi_app.test_client()


def _request(client, method: str, path: str, body: dict[str, Any]):
    if isinstance(client, TestClient):
        return client.request(method.upper(), path, json=body)
    return client.open(path, method=method.upper(), json=body)


def _patch_readiness_functions(monkeypatch) -> None:
    disposable = lambda: {"confirmationToken": "mutate-disposable", "ready": True}
    pilot = lambda engagement_id=None: {"confirmationToken": "mutate-pilot", "engagementId": engagement_id, "ready": True}
    for target in ("app.asgi",):
        monkeypatch.setattr(f"{target}.disposable_deployment_readiness", disposable)
        monkeypatch.setattr(f"{target}.pilot_standard_rti_readiness", pilot)


def _patch_plan_function(monkeypatch) -> None:
    plan = lambda **_kwargs: FakePlan()
    for target in ("app.asgi",):
        monkeypatch.setattr(f"{target}.plan_standard_rti_deployment", plan)


def _patch_guarded_deployment_functions(monkeypatch) -> None:
    def disposable_run(body: dict[str, Any]) -> dict[str, Any]:
        if body.get("confirmMutation") == "bad":
            raise GuardedDeploymentConfirmationError("confirmMutation rejected")
        return {"deployment": {"ok": True, "kind": "disposable"}}

    def pilot_run(body: dict[str, Any], **_kwargs) -> dict[str, Any]:
        if body.get("confirmMutation") == "bad":
            raise GuardedDeploymentConfirmationError("confirmMutation rejected")
        return {"deployment": {"ok": True, "kind": "pilot"}}

    def pilot_start(body: dict[str, Any], **_kwargs) -> FakeJobDetail:
        if body.get("confirmMutation") == "bad":
            raise GuardedDeploymentConfirmationError("confirmMutation rejected")
        return FakeJobDetail("job-pilot", "pilot_standard_rti_run")

    def pilot_get(job_id: str) -> FakeJobDetail | None:
        return FakeJobDetail(job_id, "pilot_standard_rti_run") if job_id == "job-pilot" else None

    def pilot_teardown(job_id: str) -> FakeJobDetail | None:
        return FakeJobDetail("job-pilot-teardown", "pilot_standard_rti_teardown") if job_id == "job-pilot" else None

    for target in ("app.asgi",):
        monkeypatch.setattr(f"{target}.run_guarded_disposable_deployment", disposable_run)
        monkeypatch.setattr(f"{target}.run_guarded_pilot_standard_rti", pilot_run)
        monkeypatch.setattr(f"{target}.start_guarded_pilot_standard_rti_run", pilot_start)
        monkeypatch.setattr(f"{target}.get_guarded_pilot_standard_rti_run", pilot_get)
        monkeypatch.setattr(f"{target}.start_guarded_pilot_standard_rti_teardown", pilot_teardown)


def _patch_linode_sketch_functions(monkeypatch) -> None:
    def start(body: dict[str, Any]) -> FakeJobDetail:
        if body.get("confirmMutation") == "bad":
            raise LinodeSketchGuardrailError("bad region")
        if body.get("confirmMutation") == "locked":
            raise CredentialStoreLockedError("credential store is locked")
        return FakeJobDetail("job-linode", "linode_sketch_deploy")

    def get(job_id: str) -> FakeJobDetail | None:
        return FakeJobDetail(job_id, "linode_sketch_deploy") if job_id == "job-linode" else None

    def teardown(job_id: str) -> FakeJobDetail | None:
        return FakeJobDetail("job-linode-teardown", "linode_sketch_teardown") if job_id == "job-linode" else None

    for target in ("app.asgi",):
        monkeypatch.setattr(f"{target}.start_guarded_linode_sketch_run", start)
        monkeypatch.setattr(f"{target}.get_guarded_linode_sketch_run", get)
        monkeypatch.setattr(f"{target}.teardown_guarded_linode_sketch_run", teardown)


def _patch_digitalocean_validation_functions(monkeypatch) -> None:
    def start(body: dict[str, Any]) -> FakeJobDetail:
        if body.get("confirmCreateDestroy") == "bad":
            raise DigitalOceanProviderValidationGuardrailError("bad confirmation")
        if body.get("confirmCreateDestroy") == "locked":
            raise CredentialStoreLockedError("credential store is locked")
        return FakeJobDetail("job-do", "digitalocean_provider_validation")

    def get(job_id: str) -> FakeJobDetail | None:
        return FakeJobDetail(job_id, "digitalocean_provider_validation") if job_id == "job-do" else None

    for target in ("app.asgi",):
        monkeypatch.setattr(f"{target}.start_guarded_digitalocean_provider_validation_run", start)
        monkeypatch.setattr(f"{target}.get_guarded_digitalocean_provider_validation_run", get)


@dataclass
class FakeJobDetail:
    id: str
    action: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action,
            "status": "running",
            "target": "engagement:eng-fastapi-orchestrator",
            "targetType": "engagement",
            "targetId": "eng-fastapi-orchestrator",
            "requestedBy": "operator",
            "input": {},
            "artifactRefs": [],
            "createdAt": "2026-07-06T00:00:00+00:00",
            "startedAt": "2026-07-06T00:00:00+00:00",
            "finishedAt": None,
            "events": [{"level": "INFO", "message": f"{self.action} queued"}],
        }


class FakePlan:
    def to_dict(self) -> dict[str, Any]:
        return {
            "engagementId": "eng-fastapi-orchestrator",
            "revision": {"id": "rev-fastapi-orchestrator"},
            "steps": [{"id": "render", "status": "planned"}],
        }
