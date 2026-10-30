# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.storage.service_repository import EngagementServiceRepository, SqlAlchemyEngagementServiceRepository, StoredEngagementService


TCP_PROTOCOLS = {"tcp", "http", "https"}
UDP_PROTOCOLS = {"udp"}
CLAIMING_STATUSES = {"active", "configured", "applying", "removing", "remove failed"}


class ServiceListenerConflictError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("service listener conflict")
        self.errors = errors


@dataclass(frozen=True)
class ServiceListenerClaim:
    engagement_id: str
    service_id: str
    service_name: str
    service_type: str
    host_id: str
    port: str
    protocol: str
    transport: str
    status: str


def normalize_transport(protocol: str) -> str:
    normalized = str(protocol or "").strip().lower()
    if normalized in TCP_PROTOCOLS:
        return "tcp"
    if normalized in UDP_PROTOCOLS:
        return "udp"
    return normalized


def assert_listener_available(
    engagement_id: str,
    *,
    host_id: str,
    port: str | int,
    protocol: str,
    service_id: str = "",
    repository: EngagementServiceRepository | None = None,
) -> None:
    requested = ServiceListenerClaim(
        engagement_id=engagement_id,
        service_id=service_id,
        service_name="",
        service_type="",
        host_id=_text(host_id),
        port=_port_text(port),
        protocol=_text(protocol).lower(),
        transport=normalize_transport(_text(protocol)),
        status="active",
    )
    for claim in active_listener_claims(engagement_id, repository=repository):
        if service_id and claim.service_id == service_id:
            continue
        if _same_listener(requested, claim):
            raise ServiceListenerConflictError(
                [
                    (
                        f"{claim.service_name or claim.service_id} already claims "
                        f"{claim.host_id}:{claim.port}/{claim.transport}"
                    )
                ]
            )


def active_listener_claims(
    engagement_id: str,
    *,
    repository: EngagementServiceRepository | None = None,
) -> list[ServiceListenerClaim]:
    services = (repository or SqlAlchemyEngagementServiceRepository()).list_for_engagement(engagement_id)
    claims = []
    for service in services:
        claim = service_listener_claim(service)
        if claim is not None:
            claims.append(claim)
    return claims


def service_listener_claim(service: StoredEngagementService) -> ServiceListenerClaim | None:
    if service.status.strip().lower() not in CLAIMING_STATUSES:
        return None
    config = service.config or {}
    host_id = _text(config.get("targetHost") or service.proxy_id)
    port = _port_text(config.get("internalPort") or config.get("port"))
    protocol = _protocol_for_service(service)
    transport = normalize_transport(protocol)
    if not host_id or not port or transport not in {"tcp", "udp"}:
        return None
    return ServiceListenerClaim(
        engagement_id=service.engagement_id,
        service_id=service.service_id,
        service_name=service.name,
        service_type=service.service_type,
        host_id=host_id,
        port=port,
        protocol=protocol,
        transport=transport,
        status=service.status,
    )


def _same_listener(left: ServiceListenerClaim, right: ServiceListenerClaim) -> bool:
    return left.host_id == right.host_id and left.port == right.port and left.transport == right.transport


def _protocol_for_service(service: StoredEngagementService) -> str:
    configured = _text((service.config or {}).get("protocol")).lower()
    if configured:
        return configured
    if service.service_type == "web-static":
        return "http"
    return "tcp"


def _port_text(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    try:
        port = int(text)
    except ValueError:
        return ""
    if port < 1 or port > 65535:
        return ""
    return str(port)


def _text(value: Any) -> str:
    return str(value or "").strip()
