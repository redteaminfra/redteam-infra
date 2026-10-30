# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import tempfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app import create_app
from app.core.config import TestConfig
from app.integrations.digitalocean_validation import DigitalOceanValidationResult, DigitalOceanValidationStep, VALIDATION_CONFIRMATION
from app.services import digitalocean_provider_validation as service
from app.services.credentials import test_master_key as credential_test_master_key
from app.services.provider_catalog import SketchProviderPreflight
from app.storage.job_repository import SqliteJobRepository


def _preflight(ready: bool = True) -> SketchProviderPreflight:
    return SketchProviderPreflight(
        provider="digitalocean",
        ready=ready,
        catalog_source="live" if ready else "unavailable",
        checked_region="sfo3",
        checked_size="s-1vcpu-1gb",
        errors=[] if ready else ["provider unavailable"],
        warnings=[],
    )


def _validation_result() -> DigitalOceanValidationResult:
    return DigitalOceanValidationResult(
        ok=True,
        mutation=True,
        credential_alias="do-barragan",
        name="barragan-do-validation-test",
        droplet_id=12345,
        public_ip="203.0.113.90",
        cleanup_verified=True,
        steps=[
            DigitalOceanValidationStep(
                name="create",
                status="done",
                detail="Disposable droplet created.",
                data={"dropletId": 12345},
            ),
            DigitalOceanValidationStep(
                name="cleanup",
                status="done",
                detail="Disposable droplet destroyed and verified absent.",
                data={"cleanupVerified": True},
            ),
        ],
    )


def test_digitalocean_provider_validation_requires_confirmation():
    with tempfile.TemporaryDirectory() as temp_dir:
        repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")

        with pytest.raises(service.DigitalOceanProviderValidationGuardrailError) as exc:
            service.start_guarded_digitalocean_provider_validation_run(
                {"confirmCreateDestroy": "wrong"},
                repository=repository,
            )

        assert f'confirmCreateDestroy must equal "{VALIDATION_CONFIRMATION}"' in str(exc.value)
        assert repository.list() == []


def test_digitalocean_provider_validation_requires_ready_preflight():
    with tempfile.TemporaryDirectory() as temp_dir:
        repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")

        with patch.object(service, "preflight_digitalocean_sketch_live_readiness", return_value=_preflight(False)):
            with pytest.raises(service.DigitalOceanProviderValidationGuardrailError) as exc:
                service.start_guarded_digitalocean_provider_validation_run(
                    {"confirmCreateDestroy": VALIDATION_CONFIRMATION},
                    repository=repository,
                )

        assert "preflight must be ready" in str(exc.value)
        assert repository.list() == []


def test_digitalocean_provider_validation_runs_as_redacted_job():
    with tempfile.TemporaryDirectory() as temp_dir:
        repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
        with (
            patch.object(service, "preflight_digitalocean_sketch_live_readiness", return_value=_preflight(True)),
            patch.object(service, "resolve_default_credential_alias", return_value="do-barragan"),
            patch.object(service, "resolve_credential_secret", return_value="do-token-sensitive-value") as resolve_secret,
            patch.object(service, "validate_digitalocean_sketch_create_destroy", return_value=_validation_result()) as validate,
        ):
            running = service.start_guarded_digitalocean_provider_validation_run(
                {
                    "confirmCreateDestroy": VALIDATION_CONFIRMATION,
                    "requestedBy": "operator@example.invalid",
                    "name": "barragan-do-validation-test",
                },
                repository=repository,
                background_runner=lambda task: task(),
            )

        completed = service.get_guarded_digitalocean_provider_validation_run(running.id, repository=repository)

    assert completed is not None
    assert completed.status == "succeeded"
    assert completed.input["alias"] == "do-barragan"
    assert completed.input["confirmCreateDestroy"] == "redacted"
    assert completed.artifact_refs == [f"provider-smoke:digitalocean:{completed.id}"]
    assert completed.events[-1].data["validation"]["publicIp"] == "203.0.113.90"
    assert completed.events[-1].data["cleanupVerified"] is True
    resolve_secret.assert_called_once_with("digitalocean", "do-barragan", None)
    validate.assert_called_once()
    rendered = str(completed.to_dict())
    assert "do-token-sensitive-value" not in rendered
    assert "TF_VAR_do_pat" not in rendered
    assert "BEGIN OPENSSH PRIVATE KEY" not in rendered
    assert "user-data-sensitive-value" not in rendered


def test_digitalocean_provider_validation_get_rejects_other_actions():
    with tempfile.TemporaryDirectory() as temp_dir:
        repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
        other = service._new_validation_job({"confirmCreateDestroy": VALIDATION_CONFIRMATION}, "do-barragan")
        repository.save(replace(other, action="other_action"))

        assert service.get_guarded_digitalocean_provider_validation_run(other.id, repository=repository) is None


def test_digitalocean_provider_validation_api_routes(monkeypatch):
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", credential_test_master_key())
    app = create_app(TestConfig)
    client = app.test_client()
    fake_job = SimpleNamespace(to_dict=lambda: {"id": "job-do-smoke", "status": "running"})

    with patch("app.asgi.start_guarded_digitalocean_provider_validation_run", return_value=fake_job):
        response = client.post(
            "/api/orchestrator/barragan-testing/digitalocean-sketch/validation-runs",
            json={"confirmCreateDestroy": VALIDATION_CONFIRMATION},
        )

    assert response.status_code == 201
    assert response.get_json()["job"]["id"] == "job-do-smoke"

    with patch("app.asgi.get_guarded_digitalocean_provider_validation_run", return_value=fake_job):
        response = client.get("/api/orchestrator/barragan-testing/digitalocean-sketch/validation-runs/job-do-smoke")

    assert response.status_code == 200
    assert response.get_json()["job"]["status"] == "running"
