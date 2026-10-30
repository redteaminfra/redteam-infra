# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from app.services.engagements import get_engagement
from app.services.infra_orientation import try_enqueue_infra_orientation_refresh
from app.services.service_listener_claims import ServiceListenerConflictError, assert_listener_available, normalize_transport
from app.storage.service_repository import EngagementServiceRepository, SqlAlchemyEngagementServiceRepository, StoredEngagementService


GENERIC_SERVICE_TYPE = "generic"
GENERIC_SERVICE_NAME = "Generic Service"
GENERIC_ACTIVE_STATUS = "Active"
GENERIC_DISABLED_STATUS = "Disabled"
GENERIC_REMOVED_STATUS = "Removed"
GENERIC_PROTOCOLS = {"tcp", "udp", "http", "https"}
GENERIC_VALIDATION_PROFILE_TYPES = {
    "tcp-connect",
    "tcp-send-receive",
    "http",
    "udp-send-receive",
    "manual",
    "temporary-listener",
}
GENERIC_TARGET_HOSTS = {"homebase", "proxy01", "proxy02"}
MAX_COMPACT_TEXT = 500
MAX_NOTES_TEXT = 5000


class GenericServiceValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("generic service validation failed")
        self.errors = errors


@dataclass(frozen=True)
class GenericServiceIntent:
    service_id: str
    name: str
    target_host: str
    internal_port: str
    protocol: str
    script_path: str
    purpose: str
    tags: list[str]
    notes: str
    validation_profile: dict[str, str]

    def to_service(self, engagement_id: str, *, status: str = GENERIC_ACTIVE_STATUS) -> StoredEngagementService:
        return StoredEngagementService(
            engagement_id=engagement_id,
            service_id=self.service_id,
            service_type=GENERIC_SERVICE_TYPE,
            name=self.name,
            proxy_id=self.target_host,
            status=status,
            config={
                "targetHost": self.target_host,
                "internalPort": int(self.internal_port),
                "protocol": self.protocol,
                "transport": normalize_transport(self.protocol),
                "scriptPath": self.script_path,
                "purpose": self.purpose,
                "tags": self.tags,
                "notes": self.notes,
                "validationProfile": self.validation_profile,
            },
        )


def list_generic_services(
    engagement_id: str,
    *,
    repository: EngagementServiceRepository | None = None,
    include_removed: bool = True,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    services = []
    for service in (repository or SqlAlchemyEngagementServiceRepository()).list_for_engagement(engagement_id):
        if service.service_type != GENERIC_SERVICE_TYPE:
            continue
        if not include_removed and service.status == GENERIC_REMOVED_STATUS:
            continue
        services.append(service.to_dict())
    return {"services": services}


def create_generic_service(
    engagement_id: str,
    body: dict[str, Any],
    *,
    repository: EngagementServiceRepository | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    repo = repository or SqlAlchemyEngagementServiceRepository()
    intent = _intent_from_body(body, existing_service_id="")
    _assert_listener_available(engagement_id, intent, repository=repo)
    service = repo.save(intent.to_service(engagement_id))
    try_enqueue_infra_orientation_refresh(engagement_id)
    return {"service": service.to_dict()}


def update_generic_service(
    engagement_id: str,
    service_id: str,
    body: dict[str, Any],
    *,
    repository: EngagementServiceRepository | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    repo = repository or SqlAlchemyEngagementServiceRepository()
    service = _get_generic_service(repo, engagement_id, service_id)
    intent = _intent_from_body(body, existing_service_id=service.service_id, existing=service)
    status = service.status if service.status in {GENERIC_ACTIVE_STATUS, GENERIC_DISABLED_STATUS, GENERIC_REMOVED_STATUS} else GENERIC_ACTIVE_STATUS
    if status == GENERIC_ACTIVE_STATUS:
        _assert_listener_available(engagement_id, intent, repository=repo)
    saved = repo.save(intent.to_service(engagement_id, status=status))
    try_enqueue_infra_orientation_refresh(engagement_id)
    return {"service": saved.to_dict()}


def disable_generic_service(
    engagement_id: str,
    service_id: str,
    *,
    repository: EngagementServiceRepository | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    repo = repository or SqlAlchemyEngagementServiceRepository()
    service = _get_generic_service(repo, engagement_id, service_id)
    saved = repo.save(_with_status(service, GENERIC_DISABLED_STATUS))
    try_enqueue_infra_orientation_refresh(engagement_id)
    return {"service": saved.to_dict()}


def restore_generic_service(
    engagement_id: str,
    service_id: str,
    *,
    repository: EngagementServiceRepository | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    repo = repository or SqlAlchemyEngagementServiceRepository()
    service = _get_generic_service(repo, engagement_id, service_id)
    intent = _intent_from_service(service)
    _assert_listener_available(engagement_id, intent, repository=repo)
    saved = repo.save(_with_status(service, GENERIC_ACTIVE_STATUS))
    try_enqueue_infra_orientation_refresh(engagement_id)
    return {"service": saved.to_dict()}


def remove_generic_service(
    engagement_id: str,
    service_id: str,
    *,
    repository: EngagementServiceRepository | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    repo = repository or SqlAlchemyEngagementServiceRepository()
    service = _get_generic_service(repo, engagement_id, service_id)
    saved = repo.save(_with_status(service, GENERIC_REMOVED_STATUS))
    try_enqueue_infra_orientation_refresh(engagement_id)
    return {"service": saved.to_dict()}


def generic_service_placement(service: StoredEngagementService) -> dict[str, str]:
    config = service.config or {}
    return {
        "hostId": _text(config.get("targetHost") or service.proxy_id),
        "hostRole": "core",
        "service": service.name or GENERIC_SERVICE_NAME,
        "status": service.status,
        "port": _text(config.get("internalPort")),
        "detail": _generic_detail(service),
        "serviceId": service.service_id,
        "serviceType": service.service_type,
        "protocol": _text(config.get("protocol")),
        "transport": _text(config.get("transport") or normalize_transport(_text(config.get("protocol")))),
        "purpose": _text(config.get("purpose")),
        "tags": list(config.get("tags") or []),
        "notes": _text(config.get("notes")),
        "scriptPath": _text(config.get("scriptPath")),
        "validationProfile": dict(config.get("validationProfile") or {}),
    }


def _assert_listener_available(
    engagement_id: str,
    intent: GenericServiceIntent,
    *,
    repository: EngagementServiceRepository,
) -> None:
    try:
        assert_listener_available(
            engagement_id,
            host_id=intent.target_host,
            port=intent.internal_port,
            protocol=intent.protocol,
            service_id=intent.service_id,
            repository=repository,
        )
    except ServiceListenerConflictError as exc:
        raise GenericServiceValidationError(exc.errors) from exc


def _intent_from_body(
    body: dict[str, Any],
    *,
    existing_service_id: str,
    existing: StoredEngagementService | None = None,
) -> GenericServiceIntent:
    existing_config = dict(existing.config or {}) if existing is not None else {}
    name = _compact_text(body.get("name"), "name") or (existing.name if existing else "")
    if not name:
        raise GenericServiceValidationError(["name is required"])
    target_host = _compact_text(body.get("targetHost"), "targetHost") or _text(existing_config.get("targetHost")) or (existing.proxy_id if existing else "")
    if target_host not in GENERIC_TARGET_HOSTS:
        raise GenericServiceValidationError(["targetHost must be homebase, proxy01, or proxy02"])
    internal_port = _port_text(body.get("internalPort") if "internalPort" in body else existing_config.get("internalPort"), "internalPort")
    protocol = (_compact_text(body.get("protocol"), "protocol") or _text(existing_config.get("protocol")) or "tcp").lower()
    if protocol not in GENERIC_PROTOCOLS:
        raise GenericServiceValidationError(["protocol must be tcp, udp, http, or https"])
    service_id = existing_service_id or _service_id(body.get("serviceId"), name)
    script_path = _path_text(body.get("scriptPath") if "scriptPath" in body else existing_config.get("scriptPath"), "scriptPath")
    purpose = _compact_text(body.get("purpose") if "purpose" in body else existing_config.get("purpose"), "purpose")
    tags = _tags(body.get("tags") if "tags" in body else existing_config.get("tags"))
    notes = _notes(body.get("notes") if "notes" in body else existing_config.get("notes"))
    validation_profile = _validation_profile(body.get("validationProfile") if "validationProfile" in body else existing_config.get("validationProfile"), protocol)
    return GenericServiceIntent(
        service_id=service_id,
        name=name,
        target_host=target_host,
        internal_port=internal_port,
        protocol=protocol,
        script_path=script_path,
        purpose=purpose,
        tags=tags,
        notes=notes,
        validation_profile=validation_profile,
    )


def _intent_from_service(service: StoredEngagementService) -> GenericServiceIntent:
    return _intent_from_body({}, existing_service_id=service.service_id, existing=service)


def _get_generic_service(
    repository: EngagementServiceRepository,
    engagement_id: str,
    service_id: str,
) -> StoredEngagementService:
    service = repository.get(engagement_id, service_id)
    if service is None or service.service_type != GENERIC_SERVICE_TYPE:
        raise GenericServiceValidationError([f"generic service {service_id} was not found"])
    return service


def _with_status(service: StoredEngagementService, status: str) -> StoredEngagementService:
    return StoredEngagementService(
        engagement_id=service.engagement_id,
        service_id=service.service_id,
        service_type=service.service_type,
        name=service.name,
        proxy_id=service.proxy_id,
        status=status,
        config=dict(service.config or {}),
        apply_job_id=service.apply_job_id,
        created_at=service.created_at,
        updated_at=service.updated_at,
    )


def _generic_detail(service: StoredEngagementService) -> str:
    config = service.config or {}
    host = _text(config.get("targetHost") or service.proxy_id)
    port = _text(config.get("internalPort"))
    protocol = _text(config.get("protocol")).upper()
    status = service.status
    if status == GENERIC_ACTIVE_STATUS:
        return f"Operator-managed {protocol} service tracked on {host}:{port}."
    if status == GENERIC_DISABLED_STATUS:
        return f"Operator-managed service is disabled; {host}:{port} is released."
    if status == GENERIC_REMOVED_STATUS:
        return f"Operator-managed service record is removed; historical metadata is retained."
    return f"Operator-managed service is {status}."


def _service_id(raw_value: Any, name: str) -> str:
    requested = _slug(_text(raw_value))
    if requested:
        return requested
    return f"generic-{_slug(name) or 'service'}-{uuid4().hex[:6]}"


def _validation_profile(value: Any, protocol: str) -> dict[str, str]:
    if isinstance(value, dict):
        profile_type = _compact_text(value.get("type"), "validationProfile.type") or _default_profile_type(protocol)
        if profile_type not in GENERIC_VALIDATION_PROFILE_TYPES:
            raise GenericServiceValidationError(["validationProfile.type must be tcp-connect, tcp-send-receive, http, udp-send-receive, manual, or temporary-listener"])
        label = _compact_text(value.get("label"), "validationProfile.label") or _profile_label(profile_type)
        request_text = _safe_validation_text(value.get("requestText"), "validationProfile.requestText")
        expected_response = _safe_validation_text(value.get("expectedResponse"), "validationProfile.expectedResponse")
        if profile_type in {"tcp-send-receive", "udp-send-receive"} and not expected_response:
            raise GenericServiceValidationError(["validationProfile.expectedResponse is required for send/expect validation"])
        if profile_type == "udp-send-receive" and not request_text:
            raise GenericServiceValidationError(["validationProfile.requestText is required for UDP send/expect validation"])
        profile = {"type": profile_type, "label": label}
        if request_text:
            profile["requestText"] = request_text
        if expected_response:
            profile["expectedResponse"] = expected_response
        return profile
    profile_type = _default_profile_type(protocol)
    return {"type": profile_type, "label": _profile_label(profile_type)}


def _default_profile_type(protocol: str) -> str:
    if protocol == "http":
        return "http"
    if protocol == "udp":
        return "manual"
    return "tcp-connect"


def _profile_label(profile_type: str) -> str:
    labels = {
        "tcp-connect": "TCP reachability",
        "tcp-send-receive": "TCP send/expect",
        "http": "HTTP check",
        "udp-send-receive": "UDP send/expect",
        "manual": "Manual validation",
        "temporary-listener": "Temporary TCP listener",
    }
    return labels.get(profile_type, profile_type)


def _port_text(value: Any, field_name: str) -> str:
    text = _text(value)
    try:
        port = int(text)
    except ValueError as exc:
        raise GenericServiceValidationError([f"{field_name} must be a TCP or UDP port"]) from exc
    if port < 1 or port > 65535:
        raise GenericServiceValidationError([f"{field_name} must be between 1 and 65535"])
    return str(port)


def _path_text(value: Any, field_name: str) -> str:
    text = _compact_text(value, field_name)
    if "\n" in text or "\r" in text:
        raise GenericServiceValidationError([f"{field_name} must be a single path"])
    return text


def _compact_text(value: Any, field_name: str) -> str:
    text = _text(value)
    if "\x00" in text:
        raise GenericServiceValidationError([f"{field_name} must not contain null bytes"])
    if len(text) > MAX_COMPACT_TEXT:
        raise GenericServiceValidationError([f"{field_name} must be {MAX_COMPACT_TEXT} characters or fewer"])
    return text


def _safe_validation_text(value: Any, field_name: str) -> str:
    text = _compact_text(value, field_name)
    lowered = text.lower()
    if any(marker in lowered for marker in ("authorization:", "bearer ", "password", "token", "secret")):
        raise GenericServiceValidationError([f"{field_name} appears to contain credential material"])
    return text


def _notes(value: Any) -> str:
    text = _text(value)
    if "\x00" in text:
        raise GenericServiceValidationError(["notes must not contain null bytes"])
    if len(text) > MAX_NOTES_TEXT:
        raise GenericServiceValidationError([f"notes must be {MAX_NOTES_TEXT} characters or fewer"])
    return text


def _tags(value: Any) -> list[str]:
    raw_values = value if isinstance(value, list) else str(value or "").split(",")
    tags: list[str] = []
    for raw in raw_values:
        tag = _slug(_text(raw))
        if tag and tag not in tags:
            tags.append(tag)
    return tags[:20]


def _slug(value: str) -> str:
    return "-".join(part for part in re.sub(r"[^a-zA-Z0-9]+", "-", value.lower()).split("-") if part)[:80]


def _text(value: Any) -> str:
    return str(value or "").strip()
