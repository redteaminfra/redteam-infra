# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from app import create_app as create_reference_app
from app.asgi import create_app as create_fastapi_app
from app.core.config import TestConfig
from app.storage.database import db
from app.storage.engagement_repository import SqlAlchemyEngagementRepository, StoredEngagement
from app.storage.service_repository import SqlAlchemyEngagementServiceRepository, StoredEngagementService
from tests.runtime_support import storage_context


ENGAGEMENT_ID = "eng-fastapi-services"


def test_fastapi_service_catalogs_and_generic_services_match_reference_contract(tmp_path):
    reference_app, reference_client, fastapi_app, fastapi_client = _separate_clients(tmp_path)
    _seed_engagement(reference_app)
    _seed_engagement(fastapi_app.state.database)
    _seed_web_static_service(reference_app)
    _seed_web_static_service(fastapi_app.state.database)

    initial_requests = (
        ("get", f"/api/engagements/{ENGAGEMENT_ID}/services/legacy-homebase-roles", {}),
        ("get", f"/api/engagements/{ENGAGEMENT_ID}/services/desktop", {}),
        ("get", f"/api/engagements/{ENGAGEMENT_ID}/services", {}),
        ("get", f"/api/engagements/{ENGAGEMENT_ID}/services/generic", {}),
        ("get", "/api/engagements/eng-missing/services", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/services/generic", {}),
    )
    for method, path, body in initial_requests:
        reference_response = _request(reference_client, method, path, body)
        fastapi_response = _request(fastapi_client, method, path, body)

        assert fastapi_response.status_code == reference_response.status_code
        assert _scrub_volatile(fastapi_response.json()) == _scrub_volatile(reference_response.get_json())

    generic_body = {
        "serviceId": "generic-fastapi",
        "name": "Generic FastAPI",
        "targetHost": "proxy01",
        "internalPort": "18888",
        "protocol": "tcp",
        "scriptPath": "/opt/tools/generic-fastapi",
        "purpose": "FastAPI parity",
        "tags": ["test"],
        "notes": "tracked by WI-0171",
    }
    mutation_requests = (
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/services/generic", generic_body),
        ("patch", f"/api/engagements/{ENGAGEMENT_ID}/services/generic/generic-fastapi", {"purpose": "updated"}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/services/generic/generic-fastapi/disable", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/services/generic/generic-fastapi/restore", {}),
        ("delete", f"/api/engagements/{ENGAGEMENT_ID}/services/generic/generic-fastapi", {}),
    )
    for method, path, body in mutation_requests:
        reference_response = _request(reference_client, method, path, body)
        fastapi_response = _request(fastapi_client, method, path, body)

        assert fastapi_response.status_code == reference_response.status_code
        assert _scrub_volatile(fastapi_response.json()) == _scrub_volatile(reference_response.get_json())


def test_fastapi_ansible_backed_services_match_reference_route_contract(tmp_path, monkeypatch):
    reference_app, reference_client, fastapi_app, fastapi_client = _separate_clients(tmp_path)
    _seed_engagement(reference_app)
    _seed_engagement(fastapi_app.state.database)
    _seed_web_static_service(reference_app)
    _seed_web_static_service(fastapi_app.state.database)

    desktop_apply_calls = _patch_service_functions(monkeypatch)

    requests = (
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/services/backflips/apply-preview", {"proxyId": "proxy01"}, 201),
        (
            "post",
            f"/api/engagements/{ENGAGEMENT_ID}/services/backflips/apply",
            {"proxyId": "proxy01", "confirmation": "apply-service-backflips"},
            202,
        ),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/services/legacy-homebase-roles/firefox/apply-preview", {}, 201),
        (
            "post",
            f"/api/engagements/{ENGAGEMENT_ID}/services/legacy-homebase-roles/firefox/apply",
            {"confirmation": "apply-service-firefox"},
            202,
        ),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/services/desktop/apply-preview", {"apps": [{"slug": "firefox", "enabled": True}]}, 201),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/services/desktop/apply", {"apps": [{"slug": "firefox", "enabled": True}]}, 202),
        (
            "post",
            f"/api/engagements/{ENGAGEMENT_ID}/services/web-static/apply-preview",
            {"siteName": "fastapi-site", "domain": "fastapi.example"},
            201,
        ),
        (
            "post",
            f"/api/engagements/{ENGAGEMENT_ID}/services/web-static/apply",
            {"siteName": "fastapi-site", "domain": "fastapi.example"},
            202,
        ),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/services/web-static/web-fastapi-site/remove-preview", {}, 201),
        ("delete", f"/api/engagements/{ENGAGEMENT_ID}/services/web-static/web-fastapi-site", {"confirmation": "remove-web-fastapi-site"}, 202),
    )

    for method, path, body, expected_status in requests:
        reference_response = _request(reference_client, method, path, body)
        fastapi_response = _request(fastapi_client, method, path, body)

        assert fastapi_response.status_code == reference_response.status_code == expected_status
        assert _scrub_volatile(fastapi_response.json()) == _scrub_volatile(reference_response.get_json())

    capability_requests = (
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/capabilities/backflips/apply-preview", {"proxyId": "proxy01"}, 201),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/capabilities/backflips/apply", {"proxyId": "proxy01", "confirmation": "apply-service-backflips"}, 202),
        ("get", f"/api/engagements/{ENGAGEMENT_ID}/capabilities/desktop", {}, 200),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/capabilities/desktop/apply-preview", {"apps": [{"slug": "firefox", "enabled": True}]}, 201),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/capabilities/desktop/apply", {"desiredApps": [{"slug": "firefox", "enabled": True}]}, 202),
    )
    for method, path, body, expected_status in capability_requests:
        response = _request(fastapi_client, method, path, body)
        assert response.status_code == expected_status

    assert desktop_apply_calls[-1] == {
        "desiredApps": [
            {"slug": "firefox", "enabled": False},
            {"slug": "libreoffice", "enabled": True},
        ],
        "desiredStateSource": {
            "kind": "engagement-capability-selection",
            "selectedCapabilityIds": ["libreoffice"],
        },
    }


def test_fastapi_ansible_backed_service_validation_and_missing_shapes_match_reference_contract(tmp_path, monkeypatch):
    reference_app, reference_client, fastapi_app, fastapi_client = _separate_clients(tmp_path)
    _seed_engagement(reference_app)
    _seed_engagement(fastapi_app.state.database)
    _patch_service_functions(monkeypatch)

    requests = (
        ("post", "/api/engagements/eng-missing/services/backflips/apply-preview", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/services/backflips/apply", {"confirmation": "wrong"}),
        ("post", "/api/engagements/eng-missing/services/desktop/apply-preview", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/services/desktop/apply", {"invalid": True}),
        ("post", "/api/engagements/eng-missing/services/web-static/apply-preview", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/services/web-static/apply", {"siteName": "bad"}),
    )

    for method, path, body in requests:
        reference_response = _request(reference_client, method, path, body)
        fastapi_response = _request(fastapi_client, method, path, body)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_opsec_network_restriction_routes(tmp_path, monkeypatch):
    _, _, fastapi_app, fastapi_client = _separate_clients(tmp_path)
    _seed_engagement(fastapi_app.state.database)

    def get_opsec(engagement_id: str):
        if engagement_id != ENGAGEMENT_ID:
            return None
        return {
            "service": {"serviceId": "opsec-network-restrictions", "status": "Disabled"},
            "configuration": {"enabled": False, "destinations": [], "notes": "", "purpose": ""},
        }

    def apply_opsec(engagement_id: str, body: dict[str, Any], *, requested_by: str = "operator"):
        if engagement_id != ENGAGEMENT_ID:
            return None
        return {
            **_job_payload("job-opsec-apply", "opsec_network_restrictions_apply", requestedBy=requested_by),
            "status": "Applying",
            "service": {"serviceId": "opsec-network-restrictions", "status": "Applying"},
            "configuration": {
                "enabled": bool(body.get("enabled")),
                "destinations": body.get("destinations", []),
                "notes": body.get("notes", ""),
                "purpose": body.get("purpose", ""),
            },
        }

    monkeypatch.setattr("app.asgi.get_opsec_network_restrictions", get_opsec)
    monkeypatch.setattr("app.asgi.apply_opsec_network_restrictions", apply_opsec)

    get_response = fastapi_client.get(f"/api/engagements/{ENGAGEMENT_ID}/services/opsec-network-restrictions")
    assert get_response.status_code == 200
    assert get_response.json()["configuration"]["enabled"] is False

    apply_response = fastapi_client.post(
        f"/api/engagements/{ENGAGEMENT_ID}/services/opsec-network-restrictions/apply",
        json={"enabled": True, "destinations": ["10.10.0.0/24"], "notes": "client range"},
    )
    assert apply_response.status_code == 202
    assert apply_response.json()["job"]["action"] == "opsec_network_restrictions_apply"
    assert apply_response.json()["configuration"]["destinations"] == ["10.10.0.0/24"]

    assert fastapi_client.get("/api/engagements/eng-missing/services/opsec-network-restrictions").status_code == 404

    canonical_get = fastapi_client.get(f"/api/engagements/{ENGAGEMENT_ID}/capabilities/opsec-network-restrictions")
    assert canonical_get.status_code == 200
    canonical_apply = fastapi_client.post(
        f"/api/engagements/{ENGAGEMENT_ID}/capabilities/opsec-network-restrictions/apply",
        json={"enabled": True, "destinations": ["10.10.0.0/24"]},
    )
    assert canonical_apply.status_code == 202


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
                name="FastAPI Services",
                status="draft",
                owner="operator",
                template_id="standard-rti",
                active_revision=None,
                input_parameters={},
                description="FastAPI services fixture",
                created_at="2026-07-06T00:00:00+00:00",
                updated_at="2026-07-06T00:00:00+00:00",
            )
        )
        db.session.remove()


def _seed_web_static_service(reference_app) -> None:
    with storage_context(reference_app):
        SqlAlchemyEngagementServiceRepository().save(
            StoredEngagementService(
                engagement_id=ENGAGEMENT_ID,
                service_id="web-fastapi-site",
                service_type="web-static",
                name="fastapi-site",
                proxy_id="proxy01",
                status="Configured",
                config={
                    "siteName": "fastapi-site",
                    "domain": "fastapi.example",
                    "proxyId": "proxy01",
                    "internalPort": 18080,
                    "contentPath": "/opt/web/fastapi-site/html/",
                },
            )
        )
        db.session.remove()


def _patch_service_functions(monkeypatch) -> list[dict[str, Any]]:
    from app.services.backflips_service import BackflipsServiceValidationError
    from app.services.legacy_homebase_role_service import LegacyHomebaseRoleServiceValidationError
    from app.services.web_static_service import WebStaticServiceValidationError

    def _none_if_missing(engagement_id: str, payload: dict[str, Any]):
        if engagement_id != ENGAGEMENT_ID:
            return None
        return payload

    def preview_backflips(engagement_id: str, *, proxy_id: str = "proxy01", requested_by: str = "operator"):
        return _none_if_missing(engagement_id, _job_payload("job-backflips-preview", "backflips_service_apply_preview", proxyId=proxy_id, requestedBy=requested_by))

    def apply_backflips(engagement_id: str, *, confirmation: str, proxy_id: str = "proxy01", requested_by: str = "operator"):
        if confirmation != "apply-service-backflips":
            raise BackflipsServiceValidationError(['confirmation must equal "apply-service-backflips"'])
        return _none_if_missing(engagement_id, _job_payload("job-backflips-apply", "backflips_service_apply", proxyId=proxy_id, requestedBy=requested_by))

    def preview_legacy(engagement_id: str, role_slug: str, *, requested_by: str = "operator"):
        return _none_if_missing(engagement_id, _job_payload("job-legacy-preview", "legacy_homebase_role_service_apply_preview", roleSlug=role_slug, requestedBy=requested_by))

    def apply_legacy(engagement_id: str, role_slug: str, *, confirmation: str, requested_by: str = "operator"):
        if confirmation != f"apply-service-{role_slug}":
            raise LegacyHomebaseRoleServiceValidationError([f'confirmation must equal "apply-service-{role_slug}"'])
        return _none_if_missing(engagement_id, _job_payload("job-legacy-apply", "legacy_homebase_role_service_apply", roleSlug=role_slug, requestedBy=requested_by))

    def preview_desktop(engagement_id: str, desired_apps: dict[str, Any], *, requested_by: str = "operator"):
        return _none_if_missing(engagement_id, {**_job_payload("job-desktop-preview", "desktop_service_apply_preview", requestedBy=requested_by), "servicePlacements": []})

    desktop_apply_calls: list[dict[str, Any]] = []

    def apply_desktop(
        engagement_id: str,
        desired_apps: list[dict[str, Any]] | dict[str, Any],
        *,
        requested_by: str = "operator",
        desired_state_source: dict[str, Any] | None = None,
    ):
        if isinstance(desired_apps, dict) and desired_apps.get("invalid"):
            raise LegacyHomebaseRoleServiceValidationError(["apps must be valid desktop app intents"])
        desktop_apply_calls.append(
            {"desiredApps": desired_apps, "desiredStateSource": desired_state_source}
        )
        return _none_if_missing(engagement_id, {**_job_payload("job-desktop-apply", "desktop_service_apply", requestedBy=requested_by), "servicePlacements": []})

    def resolve_desktop_capabilities(engagement_id: str, *, root):
        if engagement_id != ENGAGEMENT_ID:
            return None
        return (
            [
                {"slug": "firefox", "enabled": False},
                {"slug": "libreoffice", "enabled": True},
            ],
            {
                "kind": "engagement-capability-selection",
                "selectedCapabilityIds": ["libreoffice"],
            },
        )

    def preview_web_static(engagement_id: str, body: dict[str, Any], *, requested_by: str = "operator"):
        return _none_if_missing(engagement_id, {**_job_payload("job-web-preview", "web_static_service_apply_preview", requestedBy=requested_by), "service": _web_service_payload()})

    def apply_web_static(
        engagement_id: str,
        body: dict[str, Any],
        *,
        requested_by: str = "operator",
        **_kwargs: Any,
    ):
        if body.get("siteName") == "bad":
            raise WebStaticServiceValidationError(["siteName must be a lowercase slug with letters, numbers, hyphens, and underscores"])
        return _none_if_missing(engagement_id, {**_job_payload("job-web-apply", "web_static_service_apply", requestedBy=requested_by), "service": _web_service_payload(), "status": "Applying"})

    def preview_web_static_remove(engagement_id: str, service_id: str, *, requested_by: str = "operator"):
        return _none_if_missing(engagement_id, {**_job_payload("job-web-remove-preview", "web_static_service_remove_preview", serviceId=service_id, requestedBy=requested_by), "service": _web_service_payload(), "confirmationToken": "remove-web-fastapi-site"})

    def remove_web_static(engagement_id: str, service_id: str, body: dict[str, Any], *, requested_by: str = "operator"):
        return _none_if_missing(engagement_id, {**_job_payload("job-web-remove", "web_static_service_remove", serviceId=service_id, requestedBy=requested_by), "service": {**_web_service_payload(), "status": "Removing"}, "status": "Removing"})

    patches = {
        "preview_backflips_service_apply": preview_backflips,
        "apply_backflips_service": apply_backflips,
        "preview_legacy_homebase_role_service_apply": preview_legacy,
        "apply_legacy_homebase_role_service": apply_legacy,
        "preview_desktop_service_apply": preview_desktop,
        "apply_desktop_service": apply_desktop,
        "desktop_capability_reconciliation_input": resolve_desktop_capabilities,
        "preview_web_static_service_apply": preview_web_static,
        "start_web_static_service_apply": apply_web_static,
        "preview_web_static_service_remove": preview_web_static_remove,
        "start_web_static_service_remove": remove_web_static,
    }
    for name, value in patches.items():
        monkeypatch.setattr(f"app.asgi.{name}", value)
    return desktop_apply_calls


def _job_payload(job_id: str, action: str, **input_data: Any) -> dict[str, Any]:
    return {
        "job": {
            "id": job_id,
            "action": action,
            "status": "succeeded",
            "target": f"engagement:{ENGAGEMENT_ID}",
            "targetType": "engagement",
            "targetId": ENGAGEMENT_ID,
            "requestedBy": input_data.get("requestedBy", "operator"),
            "input": input_data,
            "artifactRefs": [],
            "createdAt": "2026-07-06T00:00:00+00:00",
            "startedAt": "2026-07-06T00:00:00+00:00",
            "finishedAt": "2026-07-06T00:00:01+00:00",
            "events": [],
        },
        "workspace": {"status": "Pending Service Apply", "mutation": False},
    }


def _web_service_payload() -> dict[str, Any]:
    return {
        "serviceId": "web-fastapi-site",
        "serviceType": "web-static",
        "name": "fastapi-site",
        "proxyId": "proxy01",
        "status": "Configured",
        "config": {"siteName": "fastapi-site", "domain": "fastapi.example", "internalPort": 18080},
    }


def _scrub_volatile(value):
    if isinstance(value, dict):
        scrubbed = {}
        for key, item in value.items():
            if key in {"createdAt", "updatedAt"} and item:
                scrubbed[key] = "<timestamp>"
            else:
                scrubbed[key] = _scrub_volatile(item)
        return scrubbed
    if isinstance(value, list):
        return [_scrub_volatile(item) for item in value]
    return value
