# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from app.storage.service_repository import EngagementServiceRepository, SqlAlchemyEngagementServiceRepository, StoredEngagementService


NATIVE_STATIC_WEB_CAPABILITY_ID = "barragan.static-web-site"
OPENRESTY_V2_CAPABILITY_ID = "redteam-infra.openresty-v2"
OPENRESTY_V2_SERVICE_TYPE = "ansible-capability"
WEB_STATIC_SERVICE_TYPE = "web-static"
CLAIMING_STATUSES = {"active", "configured", "applying", "removing", "remove failed"}


class WebDeliveryCapabilityConflictError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("web delivery capability conflict")
        self.errors = errors


def assert_web_delivery_capability_available(
    engagement_id: str,
    *,
    host_id: str,
    capability_id: str,
    service_id: str = "",
    repository: EngagementServiceRepository | None = None,
) -> None:
    conflicts = web_delivery_capability_conflicts(
        engagement_id,
        host_id=host_id,
        capability_id=capability_id,
        service_id=service_id,
        repository=repository,
    )
    if conflicts:
        raise WebDeliveryCapabilityConflictError(conflicts)


def web_delivery_capability_conflicts(
    engagement_id: str,
    *,
    host_id: str,
    capability_id: str,
    service_id: str = "",
    repository: EngagementServiceRepository | None = None,
) -> list[str]:
    repo = repository or SqlAlchemyEngagementServiceRepository()
    requested = _normalize_capability_id(capability_id)
    host = _text(host_id)
    errors: list[str] = []
    if requested not in {NATIVE_STATIC_WEB_CAPABILITY_ID, OPENRESTY_V2_CAPABILITY_ID}:
        return errors

    for service in repo.list_for_engagement(engagement_id):
        if service_id and service.service_id == service_id:
            continue
        if _service_host(service) != host:
            continue
        existing = _web_delivery_capability_id(service)
        if not existing:
            continue
        if requested == NATIVE_STATIC_WEB_CAPABILITY_ID and existing == OPENRESTY_V2_CAPABILITY_ID:
            errors.append(
                f"OpenResty v2 already owns {host} /opt/web front proxy stack; disable it before enabling Static Web Site on this proxy."
            )
        elif requested == OPENRESTY_V2_CAPABILITY_ID and existing == NATIVE_STATIC_WEB_CAPABILITY_ID:
            errors.append(
                f"Static Web Site already owns {host} /opt/web front proxy stack; remove native static web sites before enabling OpenResty v2 on this proxy."
            )
        elif requested == OPENRESTY_V2_CAPABILITY_ID and existing == OPENRESTY_V2_CAPABILITY_ID:
            errors.append(f"OpenResty v2 is already enabled on {host}.")
    return errors


def _web_delivery_capability_id(service: StoredEngagementService) -> str:
    if service.status.strip().lower() not in CLAIMING_STATUSES:
        return ""
    if service.service_type == WEB_STATIC_SERVICE_TYPE:
        return NATIVE_STATIC_WEB_CAPABILITY_ID
    configured = _normalize_capability_id((service.config or {}).get("capabilityId"))
    if configured == OPENRESTY_V2_CAPABILITY_ID:
        return OPENRESTY_V2_CAPABILITY_ID
    if service.service_type == OPENRESTY_V2_SERVICE_TYPE and service.service_id in {"openresty-v2", OPENRESTY_V2_CAPABILITY_ID}:
        return OPENRESTY_V2_CAPABILITY_ID
    return ""


def _service_host(service: StoredEngagementService) -> str:
    return _text((service.config or {}).get("targetHost") or service.proxy_id)


def _normalize_capability_id(value: object) -> str:
    text = _text(value).lower()
    if text in {"openresty-v2", "openresty_v2", "redteam-infra.openresty-v2"}:
        return OPENRESTY_V2_CAPABILITY_ID
    if text in {"static-web", "static web", "static-web-site", "barragan.static-web-site"}:
        return NATIVE_STATIC_WEB_CAPABILITY_ID
    return text


def _text(value: object) -> str:
    return str(value or "").strip()
