# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import re
import threading
from typing import Any

from app.services.engagements import get_engagement
from app.services.engagement_operations import get_operations_overview, update_operations_overview
from app.services.inbound_channel_artifacts import (
    HTTP_ROUTE_HEALTH_EXPECTATION,
    managed_http_backend_service_id,
)
from app.services.inbound_channel_apply import (
    InboundChannelApplyValidationError,
    preflight_inbound_channel_apply,
    start_inbound_channel_apply,
)
from app.services.inbound_raw_route_plan import (
    InboundRawRoutePlanError,
    apply_plan_to_channel,
    is_raw_route,
    plan_new_raw_route,
)
from app.services.inbound_mutation_fence import active_inbound_batch

BACKFLIPS_PORT = "2222"
_INBOUND_CREATE_LOCK = threading.Lock()


class InboundChannelWorkflowValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("inbound channel workflow validation failed")
        self.errors = errors


def create_and_apply_inbound_channel(
    engagement_id: str,
    body: dict[str, Any],
    *,
    requested_by: str = "operator",
) -> dict[str, Any] | None:
    active_batch = active_inbound_batch(engagement_id)
    if active_batch is not None:
        raise InboundChannelWorkflowValidationError([f"inbound channel batch {active_batch.id} is already running for this engagement"])
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    with _INBOUND_CREATE_LOCK:
        overview = get_operations_overview(engagement_id)
        channel = derive_inbound_channel(engagement.name, overview, body)
        _validate_new_channel_claim(overview, channel)
        channel = preflight_inbound_channel_apply(engagement.name, overview, channel)
        # start_inbound_channel_apply persists the running job, including its
        # authoritative pending channel row, before this lock is released.
        result = start_inbound_channel_apply(
            engagement_id,
            str(channel["channelId"]),
            confirmation=f"apply-inbound-{channel['channelId']}",
            requested_by=requested_by,
            auto_validate=True,
            channel=channel,
        )
    if result is None:
        return None
    return {"channel": channel, **result}


def recover_inbound_channel(
    engagement_id: str,
    channel_id: str,
    *,
    requested_by: str = "operator",
) -> dict[str, Any] | None:
    active_batch = active_inbound_batch(engagement_id)
    if active_batch is not None:
        raise InboundChannelWorkflowValidationError([f"inbound channel batch {active_batch.id} is already running for this engagement"])
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    overview = get_operations_overview(engagement_id)
    channel = _inbound_channel_by_id(overview, channel_id)
    if channel is None:
        raise InboundChannelWorkflowValidationError([f"inbound channel {channel_id} was not found"])
    if _text(channel.get("status")).lower() != "removed":
        raise InboundChannelWorkflowValidationError([f"inbound channel {channel_id} is not removed"])
    recovered = {**channel, "status": "Pending Apply"}
    validation = dict(recovered.get("validation") or {})
    validation["status"] = "Pending Apply"
    validation["detail"] = "Recovery requested; apply is starting."
    recovered["validation"] = validation
    _validate_new_channel_claim(overview, recovered)
    recovered = preflight_inbound_channel_apply(engagement.name, overview, recovered)
    result = start_inbound_channel_apply(
        engagement_id,
        channel_id,
        confirmation=f"apply-inbound-{channel_id}",
        requested_by=requested_by,
        auto_validate=True,
        channel=recovered,
    )
    if result is None:
        return None
    return {"channel": recovered, **result}


def derive_inbound_channel(
    engagement_name: str,
    overview: dict[str, Any] | None,
    body: dict[str, Any],
) -> dict[str, Any]:
    overview = overview or {}
    service_binding = _service_binding(overview, body)
    effective_body = dict(body)
    if service_binding:
        _default_empty(effective_body, "protocol", service_binding.get("protocol") or "TCP")
        _default_empty(effective_body, "internalPort", service_binding.get("port"))
        _default_empty(effective_body, "terminatesOn", service_binding.get("hostId"))
        _default_empty(effective_body, "service", service_binding.get("service"))
        _default_empty(effective_body, "purpose", service_binding.get("purpose"))
        if not isinstance(effective_body.get("validationProfile"), dict):
            effective_body["validationProfile"] = service_binding.get("validationProfile")
    edge_name = _required(body, "edge")
    protocol = (_text(effective_body.get("protocol")) or "TCP").upper()
    mode = _mode_for(protocol, _text(effective_body.get("mode")))
    external_port = _port_text(effective_body, "externalPort")
    internal_port = _port_text(effective_body, "internalPort")
    backend_port = internal_port
    edge = _edge_row(overview, body)
    chain_id = _required_row_value(edge, "chainId", "selected edge does not have a chain ID")
    edge_component_id = _required_row_value(edge, "componentId", "selected edge does not have a component ID")
    proxy_id = _semantic_proxy_row_identity(edge, "edge")
    middle = _chain_role_row(overview, chain_id, "middle")
    middle_component_id = _required_row_value(middle, "componentId", "selected middle does not have a component ID")
    middle_proxy_id = _semantic_proxy_row_identity(middle, "middle")
    if proxy_id != middle_proxy_id:
        raise InboundChannelWorkflowValidationError([
            "selected edge and middle do not have the same assigned proxy"
        ])
    proxy = _core_identity_row(overview, proxy_id, "proxy")
    homebase = _core_identity_row(overview, "homebase", "homebase")
    terminates_on = _resolve_termination(effective_body, proxy, homebase, engagement_name)
    static_web_shared_front = (
        service_binding is not None
        and _text(service_binding.get("serviceType")) == "web-static"
    )
    go_sus_backend = _is_go_sus_backend(service_binding, effective_body)
    managed_http_backend_https = (
        mode == "https-openresty"
        and not static_web_shared_front
        and _text(terminates_on.get("hostname")) == _text(homebase.get("hostname"))
    )
    if static_web_shared_front:
        if mode not in {"http-openresty", "https-openresty"}:
            raise InboundChannelWorkflowValidationError([
                "Static Web uses the fixed shared HTTP/S front; choose HTTP/OpenResty or HTTPS/OpenResty rather than a TCP forward."
            ])
        expected_port = "443" if mode == "https-openresty" else "80"
        if external_port != expected_port:
            raise InboundChannelWorkflowValidationError([
                f"Static Web {mode.removesuffix('-openresty').upper()} routes use shared port {expected_port}."
            ])
        # The shared front owns public and proxy host ports. The site itself
        # remains Docker-internal on :8081 and is selected by Host/SNI.
        terminates_on = proxy
        internal_port = expected_port
    elif managed_http_backend_https:
        # The production proxy stack owns host TCP/443. HTTPS channels stop at
        # that shared front container; SNI selects the bound site behind it.
        terminates_on = proxy
        internal_port = "443"
    domain = _text(body.get("domain")) or "N/A"
    channel_id = _channel_id(edge["hostname"], external_port, terminates_on["hostname"], internal_port)
    if managed_http_backend_https:
        # The site identity is stable per engagement route.  It gives the
        # certificate manager a typed proxy-site owner without making the
        # GoSUS host configuration or its private authorization a certificate
        # concern.
        channel_id = _slug(f"{channel_id}-{domain}")
    if mode == "http-openresty":
        channel_id = _slug(f"{channel_id}-{domain}")
    validation_profile = _validation_profile(
        protocol,
        mode,
        channel_id,
        {"type": "tcp-connect", "label": "TLS-unbound route check"}
        if static_web_shared_front and mode == "https-openresty"
        else effective_body.get("validationProfile"),
        domain=domain,
    )
    if managed_http_backend_https:
        validation_profile = {
            "type": "manual",
            "label": (
                "Bind TLS certificate, then validate HTTPS upload from Inspector"
                if go_sus_backend
                else "Bind TLS certificate, then validate HTTPS from Inspector"
            ),
        }
    requested_service = _text(effective_body.get("service"))
    if (protocol == "UDP" or mode == "udp-forward") and requested_service.lower() == "static web":
        raise InboundChannelWorkflowValidationError(["Static Web service bindings require TCP or HTTPS inbound channels"])
    channel = {
        "channelId": channel_id,
        "domain": domain,
        "protocol": protocol,
        "mode": mode,
        "externalPort": external_port,
        # Relay sockets are resolved by the canonical raw-route planner. They
        # are internal controls rather than operator-selectable request data.
        "relayPort": "",
        "middleRelayPort": "",
        "proxyRelayPort": "",
        "edge": edge["hostname"],
        "edgeComponentId": edge_component_id,
        "middle": middle["hostname"],
        "middleComponentId": middle_component_id,
        "chainId": chain_id,
        "proxy": proxy["hostname"],
        "terminatesOn": terminates_on["hostname"],
        "service": requested_service or _service_for(protocol, mode),
        **({"serviceId": _text(service_binding.get("serviceId"))} if service_binding else {}),
        **({"serviceType": _text(service_binding.get("serviceType"))} if service_binding else {}),
        "internalPort": internal_port,
        **({"backendPort": backend_port} if managed_http_backend_https else {}),
        "purpose": _text(effective_body.get("purpose")) or "Inbound channel",
        "status": "Pending Apply",
        "validationProfile": validation_profile,
        "validation": {
            "profileType": validation_profile["type"],
            "profileLabel": validation_profile["label"],
            "status": "Pending Apply",
            "detail": "Channel recorded and apply is starting.",
        },
    }
    if managed_http_backend_https:
        channel["serviceId"] = managed_http_backend_service_id(channel_id)
        channel["serviceType"] = "web-http-backend"
    if is_raw_route(channel):
        try:
            channel = apply_plan_to_channel(
                channel,
                plan_new_raw_route(channel, overview.get("inboundChannels", []), overview),
            )
        except InboundRawRoutePlanError as exc:
            raise InboundChannelWorkflowValidationError(exc.errors) from exc
    _validate_inbound_route_model(channel)
    return channel


def _record_inbound_channel(engagement_id: str, channel: dict[str, Any]) -> None:
    overview = get_operations_overview(engagement_id)
    current = overview.get("inboundChannels", []) if isinstance(overview, dict) else []
    next_channels = []
    found = False
    for existing in current:
        if not isinstance(existing, dict):
            continue
        if _text(existing.get("channelId")) == channel["channelId"]:
            next_channels.append(channel)
            found = True
        else:
            next_channels.append(existing)
    if not found:
        next_channels.append(channel)
    update_operations_overview(engagement_id, {"inboundChannels": next_channels})


def _validate_new_channel_claim(overview: dict[str, Any], candidate: dict[str, Any]) -> None:
    candidate_id = _text(candidate.get("channelId"))
    candidate_protocol = _text(candidate.get("protocol")).upper()
    candidate_shared = _is_shared_web_channel(candidate)
    for channel in overview.get("inboundChannels", []):
        if not isinstance(channel, dict) or _text(channel.get("status")).lower() in {"disabled", "removed"}:
            continue
        if _text(channel.get("channelId")) == candidate_id:
            raise InboundChannelWorkflowValidationError([
                f"Inbound channel {candidate_id} already exists or is applying. Remove it before creating the route again."
            ])
        if candidate_shared and _is_shared_web_channel(channel):
            if (
                _text(channel.get("domain")).lower() == _text(candidate.get("domain")).lower()
                and _text(channel.get("externalPort")) == _text(candidate.get("externalPort"))
            ):
                raise InboundChannelWorkflowValidationError([
                    f"Inbound domain {_text(candidate.get('domain'))} already has an active shared web route."
                ])
            continue
        if _text(channel.get("protocol")).upper() != candidate_protocol:
            continue
        collisions = []
        for role, host_key, port_key, fallback_key in (
            ("edge", "edge", "externalPort", "externalPort"),
            ("middle", "middle", "middleRelayPort", "relayPort"),
            ("proxy", "proxy", "proxyRelayPort", "relayPort"),
        ):
            existing_port = _text(channel.get(port_key)) or _text(channel.get(fallback_key)) or _text(channel.get("externalPort"))
            candidate_port = _text(candidate.get(port_key)) or _text(candidate.get(fallback_key)) or _text(candidate.get("externalPort"))
            if _text(channel.get(host_key)) == _text(candidate.get(host_key)) and existing_port == candidate_port:
                collisions.append(f"{role} {_text(candidate.get(host_key))}:{candidate_port}/{candidate_protocol.lower()}")
        if collisions:
            raise InboundChannelWorkflowValidationError([
                f"Inbound channel {candidate_id} conflicts with {_text(channel.get('channelId'))} on {', '.join(collisions)}."
            ])


def _is_shared_web_channel(channel: dict[str, Any]) -> bool:
    return _text(channel.get("mode")) in {"http-openresty", "https-openresty"} or _text(channel.get("service")).lower() == "static web"


def _resolve_termination(
    body: dict[str, Any], proxy: dict[str, str], homebase: dict[str, str], _engagement_name: str
) -> dict[str, str]:
    requested = _text(body.get("terminatesOn"))
    if not requested:
        raise InboundChannelWorkflowValidationError(["terminatesOn is required"])
    proxy_identity = proxy["hostId"]
    allowed = {
        homebase["hostId"]: homebase,
        homebase["hostname"]: homebase,
        proxy_identity: proxy,
        proxy["hostname"]: proxy,
    }
    termination = allowed.get(requested)
    if termination is None:
        raise InboundChannelWorkflowValidationError([
            f"selected edge can terminate only on {proxy['hostname']} or {homebase['hostname']}"
        ])
    return termination


def _edge_row(overview: dict[str, Any], selection: dict[str, Any]) -> dict[str, str]:
    edge_name = _required(selection, "edge")
    chain_id = _text(selection.get("chainId"))
    component_id = _text(selection.get("edgeComponentId"))
    if bool(chain_id) != bool(component_id):
        raise InboundChannelWorkflowValidationError([
            "selected edge requires both chainId and edgeComponentId"
        ])
    rows = [
        row for row in _rows(overview, "sketchInfrastructure")
        if row.get("role") == "edge" and _active_sketch_row(row)
    ]
    if chain_id and component_id:
        matches = [
            row for row in rows
            if row.get("chainId") == chain_id
            and row.get("componentId") == component_id
            and row.get("hostname") == edge_name
        ]
        if len(matches) != 1:
            raise InboundChannelWorkflowValidationError([
                "selected edge chain/component identity is stale, mismatched, or ambiguous"
            ])
        return matches[0]
    # Compatibility is absence-only. Historical clients may submit a hostname,
    # but it is safe only while that hostname identifies one deployed component.
    matches = [
        row for row in rows
        if row.get("role") == "edge" and edge_name in {row.get("hostname", ""), _short_host(row.get("hostname", ""))}
    ]
    if len(matches) != 1:
        raise InboundChannelWorkflowValidationError([f"edge {edge_name} was not found uniquely in deployed sketch infrastructure"])
    return matches[0]


def _active_sketch_row(row: dict[str, str]) -> bool:
    status = _text(row.get("status")).lower()
    burned = _text(row.get("burned")).lower() in {"true", "1", "yes"}
    return not burned and status == "deployed"


def _chain_role_row(overview: dict[str, Any], chain_id: str, role: str) -> dict[str, str]:
    matches = [
        row for row in _rows(overview, "sketchInfrastructure")
        if row.get("chainId") == chain_id and row.get("role") == role and _active_sketch_row(row)
    ]
    if len(matches) != 1:
        raise InboundChannelWorkflowValidationError([f"{role} for sketch chain {chain_id} was not found uniquely"])
    return matches[0]


def _core_identity_row(overview: dict[str, Any], host_id: str, role: str) -> dict[str, str]:
    rows = [row for row in _rows(overview, "coreInfrastructure") if row.get("role") == role]
    if role == "homebase" and len(rows) != 1:
        raise InboundChannelWorkflowValidationError(["homebase was not found uniquely in core infrastructure"])
    modern = [row for row in rows if row.get("hostId") or row.get("logicalName")]
    valid_id = r"proxy[0-9]+" if role == "proxy" else re.escape(host_id)
    malformed = [
        row for row in modern
        if row.get("hostId") != row.get("logicalName")
        or not re.fullmatch(valid_id, row.get("hostId", ""))
        or row.get("hostname") != row.get("expectedHostname")
        or not re.fullmatch(rf"{re.escape(row.get('hostId', ''))}-[a-z0-9]+(?:-[a-z0-9]+)*", row.get("hostname", ""))
    ]
    if malformed:
        raise InboundChannelWorkflowValidationError([f"core {role} identity evidence is malformed"])
    matches = [row for row in modern if row.get("hostId") == host_id]
    if len(matches) != 1:
        raise InboundChannelWorkflowValidationError([f"{host_id} was not found uniquely in core infrastructure"])
    return matches[0]


def _semantic_proxy_row_identity(row: dict[str, str], role: str) -> str:
    proxy_id = _required_row_value(row, "proxy", f"selected {role} does not have an assigned proxy")
    assigned_proxy_id = _required_row_value(
        row, "assignedProxyId", f"selected {role} does not have a persisted assigned proxy ID"
    )
    if proxy_id != assigned_proxy_id or not re.fullmatch(r"proxy[0-9]+", assigned_proxy_id):
        raise InboundChannelWorkflowValidationError([f"selected {role} proxy identity is malformed or mismatched"])
    return assigned_proxy_id


def _inbound_channel_by_id(overview: dict[str, Any] | None, channel_id: str) -> dict[str, Any] | None:
    rows = overview.get("inboundChannels", []) if isinstance(overview, dict) else []
    for row in rows:
        if isinstance(row, dict) and _text(row.get("channelId")) == channel_id:
            return row
    return None


def _rows(overview: dict[str, Any], key: str) -> list[dict[str, str]]:
    rows = overview.get(key, [])
    if not isinstance(rows, list):
        return []
    return [{str(k): _text(v) for k, v in row.items()} for row in rows if isinstance(row, dict)]


def _service_binding(overview: dict[str, Any], body: dict[str, Any]) -> dict[str, Any] | None:
    service_id = _text(body.get("serviceId"))
    if not service_id:
        return None
    for row in overview.get("servicePlacements", []):
        if not isinstance(row, dict) or _text(row.get("serviceId")) != service_id:
            continue
        status = _text(row.get("status"))
        if status not in {"Active", "Configured", "Applying"}:
            raise InboundChannelWorkflowValidationError([f"service {service_id} is {status or 'not ready'} and cannot receive a new inbound channel"])
        return row
    raise InboundChannelWorkflowValidationError([f"service {service_id} was not found"])


def _is_go_sus_backend(service_binding: dict[str, Any] | None, body: dict[str, Any]) -> bool:
    """Identify the one capability-backed HTTP backend that has this profile.

    The capability does not create a proxy service by itself: its service is
    local to homebase until an operator creates a domain route.  Matching the
    displayed service name here is only a convenience; apply still resolves
    the selected capability's manifest-backed authorization and fails closed
    if GoSUS is not selected for homebase:9999.
    """

    candidate = service_binding or body
    return (
        _text(candidate.get("service")).strip().lower() == "go simple upload server"
        and _text(candidate.get("internalPort") or candidate.get("port")) == "9999"
    )


def _default_empty(body: dict[str, Any], key: str, value: Any) -> None:
    if not _text(body.get(key)) and value is not None:
        body[key] = value


def _mode_for(protocol: str, requested: str) -> str:
    if requested in {"tcp-forward", "http-openresty", "https-openresty", "udp-forward"}:
        return requested
    if protocol == "UDP":
        return "udp-forward"
    if protocol == "HTTPS":
        return "https-openresty"
    if protocol == "HTTP":
        return "http-openresty"
    return "tcp-forward"


def _validation_profile(protocol: str, mode: str, channel_id: str, requested: Any = None, *, domain: str = "localhost") -> dict[str, str]:
    if isinstance(requested, dict):
        profile_type = _text(requested.get("type"))
        if profile_type in {"temporary-listener", "tcp-send-receive", "udp-send-receive", "tcp-connect", "http", "manual"}:
            profile = {
                "type": profile_type,
                "label": _text(requested.get("label")) or _profile_label(profile_type),
            }
            request_text = str(requested.get("requestText") or "")
            expected_response = _text(requested.get("expectedResponse"))
            if profile_type == "http" and mode == "http-openresty":
                request_text = request_text or f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
                expected_response = HTTP_ROUTE_HEALTH_EXPECTATION
            if request_text:
                profile["requestText"] = request_text
            if expected_response:
                profile["expectedResponse"] = expected_response
            return profile
    if mode == "http-openresty":
        return {
            "type": "http",
            "label": "HTTP route check",
            "requestText": f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n",
            "expectedResponse": HTTP_ROUTE_HEALTH_EXPECTATION,
        }
    if protocol == "UDP" or mode == "udp-forward":
        return {
            "type": "udp-send-receive",
            "label": "UDP route check",
            "requestText": "PING",
            "expectedResponse": "FF0000",
        }
    return {
        "type": "temporary-listener",
        "label": "Route check",
        "expectedResponse": f"barragan-inbound-{channel_id}",
    }


def _profile_label(profile_type: str) -> str:
    if profile_type == "tcp-connect":
        return "TCP reachability"
    if profile_type == "tcp-send-receive":
        return "TCP send/expect"
    if profile_type == "http":
        return "HTTP check"
    if profile_type == "udp-send-receive":
        return "UDP send/expect"
    if profile_type == "manual":
        return "Manual validation"
    return "Route check"


def _service_for(protocol: str, mode: str) -> str:
    if mode in {"http-openresty", "https-openresty"}:
        return "OpenResty"
    if protocol == "UDP":
        return "UDP service"
    return "Inbound service"


def _validate_inbound_route_model(channel: dict[str, Any]) -> None:
    if not _has_backflips_proxy_socket_collision(channel):
        return
    proxy = _text(channel.get("proxy"))
    raise InboundChannelWorkflowValidationError([
        (
            f"SSH Backflips owns {proxy}:{BACKFLIPS_PORT}. "
            f"A generic inbound channel cannot also bind {proxy}:{BACKFLIPS_PORT} as its proxy relay listener. "
            "Use the SSH Backflips capability configuration, or choose a separate proxy relay port for a generic TCP route."
        )
    ])


def _has_backflips_proxy_socket_collision(channel: dict[str, Any]) -> bool:
    protocol = _text(channel.get("protocol")).upper()
    mode = _text(channel.get("mode"))
    if protocol == "UDP" or mode == "udp-forward":
        return False
    proxy = _text(channel.get("proxy"))
    if _text(channel.get("terminatesOn")) != proxy:
        return False
    # Backflips listener lifecycle belongs to its upstream CLI. It must never
    # become a generic raw route merely because the canonical allocator could
    # choose a different hidden relay socket.
    if _text(channel.get("externalPort")) != BACKFLIPS_PORT or _text(channel.get("internalPort")) != BACKFLIPS_PORT:
        return False
    return _is_backflips_like(channel)


def _is_backflips_like(channel: dict[str, Any]) -> bool:
    identities = {
        re.sub(r"[^a-z0-9]+", "", _text(channel.get(key)).lower())
        for key in ("serviceId", "serviceType", "service", "capabilityId", "capabilityProfileId", "capability", "purpose")
        if _text(channel.get(key))
    }
    return bool(identities & {"backflips", "backflipsv2", "barraganbackflipsv2", "sshbackflips"})


def _channel_id(edge: str, external_port: str, terminates_on: str, internal_port: str) -> str:
    return _slug(f"{_short_host(edge)}-{external_port}-to-{_short_host(terminates_on)}-{internal_port}")


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return normalized or "inbound-channel"


def _required(body: dict[str, Any], key: str) -> str:
    value = _text(body.get(key))
    if not value:
        raise InboundChannelWorkflowValidationError([f"{key} is required"])
    return value


def _required_row_value(row: dict[str, str], key: str, message: str) -> str:
    value = _text(row.get(key))
    if not value or value in {"N/A", "Not Deployed", "Not Ready"}:
        raise InboundChannelWorkflowValidationError([message])
    return value


def _port_text(body: dict[str, Any], key: str) -> str:
    value = _required(body, key)
    try:
        port = int(value)
    except ValueError as exc:
        raise InboundChannelWorkflowValidationError([f"{key} must be a TCP or UDP port"]) from exc
    if port < 1 or port > 65535:
        raise InboundChannelWorkflowValidationError([f"{key} must be between 1 and 65535"])
    return str(port)


def _short_host(value: str) -> str:
    return _text(value).split(".", 1)[0].split("-", 1)[0] if _text(value).startswith(("homebase-", "proxy")) else _text(value).split(".", 1)[0]


def _text(value: Any) -> str:
    return str(value or "").strip()
