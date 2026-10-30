# Copyright (c) 2026, Oracle and/or its affiliates.
import pytest

from app.services.generic_service import (
    GenericServiceValidationError,
    create_generic_service,
    disable_generic_service,
    restore_generic_service,
)
from app.storage.service_repository import StoredEngagementService


def test_generic_services_allow_multiple_distinct_listener_claims(monkeypatch):
    monkeypatch.setattr("app.services.generic_service.get_engagement", lambda _engagement_id: object())
    repo = _FakeServiceRepository()

    first = create_generic_service(
        "eng-zy01",
        {
            "serviceId": "generic-inventory",
            "name": "inventory",
            "targetHost": "proxy01",
            "internalPort": "443",
            "protocol": "tcp",
            "scriptPath": "/opt/tools/inventory.py",
            "purpose": "ad-hoc inventory test",
            "tags": "inventory, test",
        },
        repository=repo,
    )
    second = create_generic_service(
        "eng-zy01",
        {
            "serviceId": "generic-udp",
            "name": "udp responder",
            "targetHost": "proxy01",
            "internalPort": "443",
            "protocol": "udp",
        },
        repository=repo,
    )

    assert first["service"]["config"]["scriptPath"] == "/opt/tools/inventory.py"
    assert first["service"]["config"]["transport"] == "tcp"
    assert first["service"]["config"]["tags"] == ["inventory", "test"]
    assert second["service"]["config"]["transport"] == "udp"


def test_generic_service_rejects_normalized_tcp_listener_conflicts(monkeypatch):
    monkeypatch.setattr("app.services.generic_service.get_engagement", lambda _engagement_id: object())
    repo = _FakeServiceRepository()
    create_generic_service(
        "eng-zy01",
        {
            "serviceId": "generic-tcp",
            "name": "custom tcp",
            "targetHost": "proxy01",
            "internalPort": "443",
            "protocol": "tcp",
        },
        repository=repo,
    )

    with pytest.raises(GenericServiceValidationError) as exc:
        create_generic_service(
            "eng-zy01",
            {
                "serviceId": "generic-https",
                "name": "custom https",
                "targetHost": "proxy01",
                "internalPort": "443",
                "protocol": "https",
            },
            repository=repo,
        )

    assert exc.value.errors == ["custom tcp already claims proxy01:443/tcp"]


def test_disabled_generic_service_releases_listener_and_restore_rechecks_conflict(monkeypatch):
    monkeypatch.setattr("app.services.generic_service.get_engagement", lambda _engagement_id: object())
    repo = _FakeServiceRepository()
    create_generic_service(
        "eng-zy01",
        {
            "serviceId": "generic-old",
            "name": "old server",
            "targetHost": "proxy01",
            "internalPort": "8443",
            "protocol": "https",
        },
        repository=repo,
    )
    disable_generic_service("eng-zy01", "generic-old", repository=repo)
    create_generic_service(
        "eng-zy01",
        {
            "serviceId": "generic-new",
            "name": "new server",
            "targetHost": "proxy01",
            "internalPort": "8443",
            "protocol": "tcp",
        },
        repository=repo,
    )

    with pytest.raises(GenericServiceValidationError) as exc:
        restore_generic_service("eng-zy01", "generic-old", repository=repo)

    assert exc.value.errors == ["new server already claims proxy01:8443/tcp"]


def test_static_web_rejects_legacy_host_port_with_generic_listener(tmp_path, monkeypatch):
    from app.services.web_static_service import WebStaticServiceValidationError, apply_web_static_service

    monkeypatch.setattr("app.services.web_static_service.get_engagement", lambda _engagement_id: type("Engagement", (), {"name": "zy01"})())
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    service_repo = _FakeServiceRepository(
        [
            StoredEngagementService(
                engagement_id="eng-zy01",
                service_id="generic-conflict",
                service_type="generic",
                name="custom web",
                proxy_id="proxy01",
                status="Active",
                config={"targetHost": "proxy01", "internalPort": 18080, "protocol": "tcp"},
            )
        ]
    )

    with pytest.raises(WebStaticServiceValidationError) as exc:
        apply_web_static_service(
            "eng-zy01",
            {**_web_body("ff10"), "internalPort": "18080"},
            repository=_FakeJobRepository(),
            service_repository=service_repo,
            runner=lambda _command, _cwd: None,
            env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
            workspace_root=tmp_path / "workspaces",
        )

    assert exc.value.errors == [
        "Static Web site containers use Docker-internal port 8081; the shared proxy front owns public ports 80 and 443"
    ]


def test_static_web_service_conflicts_with_openresty_v2_capability(tmp_path, monkeypatch):
    from app.services.web_static_service import WebStaticServiceValidationError, apply_web_static_service

    monkeypatch.setattr("app.services.web_static_service.get_engagement", lambda _engagement_id: type("Engagement", (), {"name": "zy01"})())
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    service_repo = _FakeServiceRepository(
        [
            StoredEngagementService(
                engagement_id="eng-zy01",
                service_id="openresty-v2",
                service_type="ansible-capability",
                name="OpenResty v2",
                proxy_id="proxy01",
                status="Configured",
                config={"capabilityId": "redteam-infra.openresty-v2", "targetHost": "proxy01"},
            )
        ]
    )

    with pytest.raises(WebStaticServiceValidationError) as exc:
        apply_web_static_service(
            "eng-zy01",
            _web_body("ff10"),
            repository=_FakeJobRepository(),
            service_repository=service_repo,
            runner=lambda _command, _cwd: None,
            env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
            workspace_root=tmp_path / "workspaces",
        )

    assert exc.value.errors == [
        "OpenResty v2 already owns proxy01 /opt/web front proxy stack; disable it before enabling Static Web Site on this proxy."
    ]


def test_openresty_v2_capability_conflicts_with_native_static_web_same_proxy():
    from app.services.web_delivery_capabilities import (
        OPENRESTY_V2_CAPABILITY_ID,
        WebDeliveryCapabilityConflictError,
        assert_web_delivery_capability_available,
    )

    repo = _FakeServiceRepository(
        [
            StoredEngagementService(
                engagement_id="eng-zy01",
                service_id="web-ff10",
                service_type="web-static",
                name="ff10",
                proxy_id="proxy01",
                status="Configured",
                config={"siteName": "ff10", "internalPort": 18080},
            )
        ]
    )

    with pytest.raises(WebDeliveryCapabilityConflictError) as exc:
        assert_web_delivery_capability_available(
            "eng-zy01",
            host_id="proxy01",
            capability_id=OPENRESTY_V2_CAPABILITY_ID,
            repository=repo,
        )

    assert exc.value.errors == [
        "Static Web Site already owns proxy01 /opt/web front proxy stack; remove native static web sites before enabling OpenResty v2 on this proxy."
    ]


def test_openresty_v2_capability_allows_different_proxy_with_native_static_web():
    from app.services.web_delivery_capabilities import (
        OPENRESTY_V2_CAPABILITY_ID,
        assert_web_delivery_capability_available,
    )

    repo = _FakeServiceRepository(
        [
            StoredEngagementService(
                engagement_id="eng-zy01",
                service_id="web-ff10",
                service_type="web-static",
                name="ff10",
                proxy_id="proxy01",
                status="Configured",
                config={"siteName": "ff10", "internalPort": 18080},
            )
        ]
    )

    assert_web_delivery_capability_available(
        "eng-zy01",
        host_id="proxy02",
        capability_id=OPENRESTY_V2_CAPABILITY_ID,
        repository=repo,
    )


def _web_body(site_name):
    return {
        "proxyId": "proxy01",
        "siteName": site_name,
        "domain": f"{site_name}.example.invalid",
        "internalPort": "8081",
        "indexHtml": f"<html><body>hola {site_name}</body></html>\n",
    }


def _executable(tmp_path, name):
    path = tmp_path / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


class _FakeJobRepository:
    def list(self):
        return []

    def save(self, job):
        return job


class _FakeServiceRepository:
    def __init__(self, services=None):
        self.services = list(services or [])

    def list_for_engagement(self, engagement_id):
        return [service for service in self.services if service.engagement_id == engagement_id]

    def list_for_engagement_and_proxy(self, engagement_id, proxy_id):
        return [service for service in self.list_for_engagement(engagement_id) if service.proxy_id == proxy_id]

    def get(self, engagement_id, service_id):
        for service in self.services:
            if service.engagement_id == engagement_id and service.service_id == service_id:
                return service
        return None

    def save(self, service):
        self.services = [
            existing
            for existing in self.services
            if not (existing.engagement_id == service.engagement_id and existing.service_id == service.service_id)
        ]
        self.services.append(service)
        return service
