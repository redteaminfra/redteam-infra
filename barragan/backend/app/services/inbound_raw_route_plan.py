# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping


RAW_ROUTE_PLAN_SCHEMA_VERSION = 1
RAW_RELAY_PORT_START = 8000
RAW_RELAY_PORT_END = 8080
RAW_MODES = {"tcp-forward", "udp-forward"}
BACKFLIPS_RESERVED_PORT = 2222
BACKFLIPS_IDENTITIES = {"backflips", "backflipsv2", "barraganbackflipsv2", "sshbackflips"}


class InboundRawRoutePlanError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("inbound raw route planning failed")
        self.errors = errors


def is_raw_route(channel: Mapping[str, Any]) -> bool:
    mode = _text(channel.get("mode"))
    if mode in RAW_MODES:
        return True
    return not mode and _text(channel.get("protocol") or "TCP").upper() in {"TCP", "UDP"}


def plan_new_raw_route(
    channel: Mapping[str, Any],
    active_channels: list[Mapping[str, Any]],
    infrastructure: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve and fingerprint a new raw route without mutating external state.

    A listener claim is scoped by exact component/host identity and transport.
    Therefore the same number may be reused on another host or by the other
    transport, while siblings on the same socket cannot collide.
    """

    if not is_raw_route(channel):
        return {}
    if _has_backflips_identity(channel):
        raise InboundRawRoutePlanError([
            f"SSH Backflips owns {_text(channel.get('proxy'))}:{BACKFLIPS_RESERVED_PORT}; a generic inbound channel cannot also bind this CLI-owned transport. Use the SSH Backflips capability configuration."
        ])
    if _backflips_owns_public_socket(channel, active_channels):
        raise InboundRawRoutePlanError([
            f"SSH Backflips already owns {_text(channel.get('edge'))}:{BACKFLIPS_RESERVED_PORT}/tcp; choose another public TCP port."
        ])
    existing = channel.get("rawRoutePlan")
    if isinstance(existing, Mapping):
        validated = validate_persisted_raw_route_plan(channel, existing, infrastructure=infrastructure)
        assert_raw_route_plan_available(validated, active_channels, exclude_channel_id=_text(channel.get("channelId")))
        return validated

    protocol = _transport(channel)
    public = _endpoint(channel, "edge", "edgeComponentId", "externalPort")
    middle_host = _required(channel, "middle")
    middle_component = _required(channel, "middleComponentId")
    proxy_host = _required(channel, "proxy")
    termination_host = _required(channel, "terminatesOn")
    termination_port = _port(channel, "internalPort")

    chain_id = _required(channel, "chainId")
    occupied_middle = _occupied(active_channels, "middle", middle_component, middle_host, protocol, chain_id)
    occupied_proxy = _occupied(active_channels, "proxy", _proxy_host_id(channel), proxy_host, protocol, chain_id)
    middle_relay = _next_available(occupied_middle, protocol, "middle", middle_host)
    proxy_relay = _next_available(occupied_proxy, protocol, "proxy", proxy_host)

    plan = {
        "schemaVersion": RAW_ROUTE_PLAN_SCHEMA_VERSION,
        "routeFamily": "raw",
        "transport": protocol,
        "allocation": {
            "provenance": "allocated-lowest-available",
            "pool": f"{RAW_RELAY_PORT_START}-{RAW_RELAY_PORT_END}",
            "scope": "exact-host-or-component-and-transport",
        },
        "public": public,
        "middleRelay": {"host": middle_host, "componentId": middle_component, "port": middle_relay},
        "proxyRelay": {"host": proxy_host, "hostId": _proxy_host_id(channel), "port": proxy_relay},
        "termination": {"host": termination_host, "port": termination_port},
    }
    plan["infrastructureRevision"] = _infrastructure_revision(channel, infrastructure or {})
    plan["infrastructureFingerprint"] = _fingerprint(plan["infrastructureRevision"])
    plan["routeFingerprint"] = _fingerprint(plan)
    _assert_no_collisions(plan, active_channels)
    return plan


def validate_persisted_raw_route_plan(
    channel: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    infrastructure: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    candidate = json.loads(json.dumps(plan))
    errors = _strict_persisted_type_errors(channel, candidate)
    if errors:
        raise InboundRawRoutePlanError(errors)
    if set(candidate) != {
        "schemaVersion", "routeFamily", "transport", "allocation", "public",
        "middleRelay", "proxyRelay", "termination", "infrastructureRevision",
        "infrastructureFingerprint", "routeFingerprint",
    }:
        errors.append("rawRoutePlan schema fields are invalid")
    if candidate.get("schemaVersion") != RAW_ROUTE_PLAN_SCHEMA_VERSION:
        errors.append(f"rawRoutePlan.schemaVersion must be {RAW_ROUTE_PLAN_SCHEMA_VERSION}")
    if candidate.get("routeFamily") != "raw":
        errors.append("rawRoutePlan.routeFamily must be raw")
    if candidate.get("transport") != _transport(channel):
        errors.append("rawRoutePlan transport does not match the channel")
    allocation = candidate.get("allocation")
    if allocation != {
        "provenance": "allocated-lowest-available",
        "pool": f"{RAW_RELAY_PORT_START}-{RAW_RELAY_PORT_END}",
        "scope": "exact-host-or-component-and-transport",
    }:
        errors.append("rawRoutePlan allocation metadata is invalid")
    expected = {
        "public": (_required(channel, "edge"), _required(channel, "edgeComponentId"), _port(channel, "externalPort")),
        "middleRelay": (_required(channel, "middle"), _required(channel, "middleComponentId"), None),
        "proxyRelay": (_required(channel, "proxy"), _proxy_host_id(channel), None),
        "termination": (_required(channel, "terminatesOn"), "", _port(channel, "internalPort")),
    }
    for name, (host, identity, fixed_port) in expected.items():
        endpoint = candidate.get(name)
        if not isinstance(endpoint, dict) or endpoint.get("host") != host:
            errors.append(f"rawRoutePlan.{name} host does not match the channel")
            continue
        identity_key = "componentId" if name in {"public", "middleRelay"} else "hostId"
        expected_keys = {"host", "port"} | ({identity_key} if identity else set())
        if set(endpoint) != expected_keys:
            errors.append(f"rawRoutePlan.{name} fields are invalid")
        if identity and endpoint.get(identity_key) != identity:
            errors.append(f"rawRoutePlan.{name} identity does not match the channel")
        port = endpoint.get("port")
        if not 1 <= port <= 65535 or (fixed_port is not None and port != fixed_port):
            errors.append(f"rawRoutePlan.{name}.port does not match the channel")
        if name in {"middleRelay", "proxyRelay"} and not RAW_RELAY_PORT_START <= port <= RAW_RELAY_PORT_END:
            errors.append(f"rawRoutePlan.{name}.port is outside the canonical relay pool")
    scalar_ports = {
        "externalPort": candidate.get("public", {}).get("port") if isinstance(candidate.get("public"), dict) else None,
        "middleRelayPort": candidate.get("middleRelay", {}).get("port") if isinstance(candidate.get("middleRelay"), dict) else None,
        "proxyRelayPort": candidate.get("proxyRelay", {}).get("port") if isinstance(candidate.get("proxyRelay"), dict) else None,
        "internalPort": candidate.get("termination", {}).get("port") if isinstance(candidate.get("termination"), dict) else None,
    }
    for key, planned_port in scalar_ports.items():
        value = channel.get(key)
        if value != str(planned_port):
            errors.append(f"rawRoutePlan.{key} does not match the persisted channel scalar")
    relay_value = channel.get("relayPort")
    if relay_value != str(scalar_ports["proxyRelayPort"]):
        errors.append("rawRoutePlan.relayPort does not match the persisted proxy relay")
    revision = candidate.get("infrastructureRevision")
    if not isinstance(revision, dict):
        errors.append("rawRoutePlan.infrastructureRevision is required")
    else:
        if set(revision) != {"chainId", "edge", "middle", "proxy", "termination"}:
            errors.append("rawRoutePlan infrastructure revision fields are invalid")
        expected_revision_fields = {
            "host", "componentId", "hostId", "provider", "providerResourceId",
            "deploymentJobId", "workspaceRevision", "publicIp", "privateIp",
        }
        for role in ("edge", "middle", "proxy", "termination"):
            row = revision.get(role)
            if not isinstance(row, dict) or set(row) != expected_revision_fields:
                errors.append(f"rawRoutePlan infrastructure revision {role} is invalid")
        if revision.get("chainId") != _required(channel, "chainId"):
            errors.append("rawRoutePlan infrastructure revision chain does not match the channel")
        revision_identities = {
            "edge": (_required(channel, "edge"), _required(channel, "edgeComponentId"), ""),
            "middle": (_required(channel, "middle"), _required(channel, "middleComponentId"), ""),
            "proxy": (_required(channel, "proxy"), "", _proxy_host_id(channel)),
            "termination": (_required(channel, "terminatesOn"), "", ""),
        }
        for role, (host, component_id, host_id) in revision_identities.items():
            row = revision.get(role)
            if isinstance(row, dict) and (
                row.get("host") != host
                or row.get("componentId") != component_id
                or row.get("hostId") != host_id
            ):
                errors.append(f"rawRoutePlan infrastructure revision {role} identity does not match the channel")
        fingerprint = candidate.get("infrastructureFingerprint")
        if fingerprint != _fingerprint(revision):
            errors.append("rawRoutePlan infrastructure fingerprint is invalid")
        if infrastructure is not None:
            current_revision = _infrastructure_revision(channel, infrastructure)
            if revision != current_revision:
                errors.append("rawRoutePlan infrastructure revision is stale; selected resources were recreated or changed")
    route_fingerprint = candidate.pop("routeFingerprint", "")
    if route_fingerprint != _fingerprint(candidate):
        errors.append("rawRoutePlan route fingerprint is invalid")
    candidate["routeFingerprint"] = route_fingerprint
    if errors:
        raise InboundRawRoutePlanError(errors)
    return candidate


def legacy_raw_route_resolution(channel: Mapping[str, Any]) -> dict[str, Any]:
    """Describe an unplanned historical route without rewriting its socket."""

    protocol = _transport(channel)
    fallback = _port(channel, "internalPort") if protocol == "udp" else _port(channel, "externalPort")
    middle = _optional_port_value(channel.get("middleRelayPort") or channel.get("relayPort")) or fallback
    proxy = _optional_port_value(channel.get("proxyRelayPort") or channel.get("relayPort")) or fallback
    provenance = "legacy-explicit-pinned" if any(
        _text(channel.get(key)) for key in ("middleRelayPort", "proxyRelayPort", "relayPort")
    ) else "legacy-behavior-fallback"
    return {
        "schemaVersion": 0,
        "provenance": provenance,
        "transport": protocol,
        "middleRelayPort": str(middle),
        "proxyRelayPort": str(proxy),
        "migrationRequired": True,
    }


def apply_plan_to_channel(channel: Mapping[str, Any], plan: Mapping[str, Any]) -> dict[str, Any]:
    if not plan:
        return dict(channel)
    middle = str(plan["middleRelay"]["port"])
    proxy = str(plan["proxyRelay"]["port"])
    return {
        **dict(channel),
        "relayPort": proxy,
        "middleRelayPort": middle,
        "proxyRelayPort": proxy,
        "rawRoutePlan": dict(plan),
    }


def raw_route_metadata(channel: Mapping[str, Any]) -> dict[str, Any]:
    if not is_raw_route(channel):
        return {}
    plan = channel.get("rawRoutePlan")
    if isinstance(plan, Mapping):
        return {"rawRoutePlan": validate_persisted_raw_route_plan(channel, plan)}
    if not all(_text(channel.get(key)) for key in ("externalPort", "internalPort", "edge", "middle", "proxy", "terminatesOn")):
        return {}
    return {"rawRouteLegacy": legacy_raw_route_resolution(channel)}


def is_backflips_route(channel: Mapping[str, Any]) -> bool:
    return _transport(channel) == "tcp" and _has_backflips_identity(channel)


def _has_backflips_identity(channel: Mapping[str, Any]) -> bool:
    identities = {
        _identity_token(channel.get(key))
        for key in (
            "serviceId", "serviceType", "service", "capabilityId",
            "capabilityProfileId", "capability", "purpose",
        )
        if _text(channel.get(key))
    }
    return bool(identities & BACKFLIPS_IDENTITIES)


def _backflips_owns_public_socket(
    channel: Mapping[str, Any],
    active_channels: list[Mapping[str, Any]],
) -> bool:
    if _transport(channel) != "tcp" or _port(channel, "externalPort") != BACKFLIPS_RESERVED_PORT:
        return False
    edge_host = _required(channel, "edge")
    edge_component = _required(channel, "edgeComponentId")
    for owner in active_channels:
        if (
            isinstance(owner, Mapping)
            and not _inactive(owner)
            and _transport(owner) == "tcp"
            and _text(owner.get("externalPort")) == str(BACKFLIPS_RESERVED_PORT)
            and _has_backflips_identity(owner)
            and _same_endpoint_identity(
                edge_component,
                edge_host,
                _text(owner.get("edgeComponentId")),
                _text(owner.get("edge")),
            )
        ):
            return True
    return False


def _same_endpoint_identity(left_identity: str, left_host: str, right_identity: str, right_host: str) -> bool:
    if left_identity and right_identity:
        return left_identity == right_identity
    return left_host == right_host


def _identity_token(value: Any) -> str:
    return "".join(character for character in _text(value).lower() if character.isalnum())


def _strict_persisted_type_errors(channel: Mapping[str, Any], plan: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    channel_strings = (
        "channelId", "protocol", "mode", "externalPort", "relayPort", "middleRelayPort",
        "proxyRelayPort", "edge", "edgeComponentId", "middle", "middleComponentId",
        "chainId", "proxy", "terminatesOn", "internalPort",
    )
    for key in channel_strings:
        value = channel.get(key)
        if type(value) is not str or not value.strip():
            errors.append(f"persisted raw channel {key} must be a non-empty string")
        elif value != value.strip():
            errors.append(f"persisted raw channel {key} must be a canonical string without surrounding whitespace")
    if type(plan.get("schemaVersion")) is not int:
        errors.append("rawRoutePlan.schemaVersion must be an integer")
    for key in ("routeFamily", "transport", "infrastructureFingerprint", "routeFingerprint"):
        if type(plan.get(key)) is not str or not plan.get(key):
            errors.append(f"rawRoutePlan.{key} must be a non-empty string")
    allocation = plan.get("allocation")
    if not isinstance(allocation, dict):
        errors.append("rawRoutePlan.allocation must be an object")
    elif any(type(allocation.get(key)) is not str for key in ("provenance", "pool", "scope")):
        errors.append("rawRoutePlan allocation fields must be strings")
    for name, identity_key in (("public", "componentId"), ("middleRelay", "componentId"), ("proxyRelay", "hostId"), ("termination", "")):
        endpoint = plan.get(name)
        if not isinstance(endpoint, dict):
            errors.append(f"rawRoutePlan.{name} must be an object")
            continue
        if type(endpoint.get("host")) is not str or not endpoint.get("host"):
            errors.append(f"rawRoutePlan.{name}.host must be a non-empty string")
        if identity_key and (type(endpoint.get(identity_key)) is not str or not endpoint.get(identity_key)):
            errors.append(f"rawRoutePlan.{name}.{identity_key} must be a non-empty string")
        if type(endpoint.get("port")) is not int:
            errors.append(f"rawRoutePlan.{name}.port must be an integer")
    revision = plan.get("infrastructureRevision")
    if not isinstance(revision, dict):
        errors.append("rawRoutePlan.infrastructureRevision must be an object")
    else:
        if type(revision.get("chainId")) is not str or not revision.get("chainId"):
            errors.append("rawRoutePlan infrastructure revision chainId must be a non-empty string")
        for role in ("edge", "middle", "proxy", "termination"):
            row = revision.get(role)
            if not isinstance(row, dict):
                errors.append(f"rawRoutePlan infrastructure revision {role} must be an object")
                continue
            if any(type(value) is not str for value in row.values()):
                errors.append(f"rawRoutePlan infrastructure revision {role} fields must be strings")
    return errors


def _assert_no_collisions(plan: Mapping[str, Any], active_channels: list[Mapping[str, Any]]) -> None:
    protocol = str(plan["transport"])
    claims = (
        ("edge", plan["public"]["componentId"], plan["public"]["host"], int(plan["public"]["port"])),
        ("middle", plan["middleRelay"]["componentId"], plan["middleRelay"]["host"], int(plan["middleRelay"]["port"])),
        ("proxy", plan["proxyRelay"]["hostId"], plan["proxyRelay"]["host"], int(plan["proxyRelay"]["port"])),
    )
    for role, identity, host, port in claims:
        if port in _occupied(active_channels, role, identity, host, protocol,
                             _text(plan["infrastructureRevision"].get("chainId"))):
            if role == "edge":
                raise InboundRawRoutePlanError([
                    f"Inbound channel already exists or is applying; raw route conflicts on {role} {host}:{port}/{protocol}."
                ])
            raise InboundRawRoutePlanError([f"raw route conflicts on {role} {host}:{port}/{protocol}"])


def assert_raw_route_plan_available(
    plan: Mapping[str, Any],
    active_channels: list[Mapping[str, Any]],
    *,
    exclude_channel_id: str = "",
) -> None:
    siblings = [
        row for row in active_channels
        if _text(row.get("channelId")) != exclude_channel_id
    ]
    _assert_no_collisions(plan, siblings)


def _same_socket_host(role: str, identity: str, host: str, chain_id: str,
                      other_identity: str, other_host: str, other_chain_id: str) -> bool:
    # Sketch component IDs are chain-local. Host equality still claims a socket
    # after label drift, and absent chain evidence must not free an alias claim.
    if host and host == other_host:
        return True
    return bool(identity and identity == other_identity and (
        role == "proxy" or not chain_id or not other_chain_id or chain_id == other_chain_id))


def _occupied(channels: list[Mapping[str, Any]], role: str, identity: str, host: str, protocol: str,
              chain_id: str = "") -> set[int]:
    occupied: set[int] = set()
    for row in channels:
        if not isinstance(row, Mapping) or _inactive(row) or not is_raw_route(row) or _transport(row) != protocol:
            continue
        plan = row.get("rawRoutePlan")
        if isinstance(plan, Mapping):
            endpoint_name = {"edge": "public", "middle": "middleRelay", "proxy": "proxyRelay"}[role]
            endpoint = plan.get(endpoint_name)
            identity_key = "componentId" if role in {"edge", "middle"} else "hostId"
            revision = plan.get("infrastructureRevision")
            other_chain = _text(revision.get("chainId")) if isinstance(revision, Mapping) else ""
            if isinstance(endpoint, Mapping) and _same_socket_host(
                    role, identity, host, chain_id, _text(endpoint.get(identity_key)),
                    _text(endpoint.get("host")), other_chain):
                _add_port(occupied, endpoint.get("port"))
            continue
        host_key = {"edge": "edge", "middle": "middle", "proxy": "proxy"}[role]
        identity_key = {"edge": "edgeComponentId", "middle": "middleComponentId", "proxy": "proxy"}[role]
        row_identity = _text(row.get(identity_key))
        if role == "proxy" and row_identity:
            row_identity = row_identity.split("-", 1)[0]
        if not _same_socket_host(role, identity, host, chain_id, row_identity,
                                 _text(row.get(host_key)), _text(row.get("chainId"))):
            continue
        fallback = row.get("externalPort") if role == "edge" else (
            row.get("internalPort") if protocol == "udp" else row.get("externalPort")
        )
        _add_port(occupied, row.get({"edge": "externalPort", "middle": "middleRelayPort", "proxy": "proxyRelayPort"}[role]) or row.get("relayPort") or fallback)
    return occupied


def _endpoint(channel: Mapping[str, Any], host_key: str, identity_key: str, port_key: str) -> dict[str, Any]:
    return {"host": _required(channel, host_key), "componentId": _required(channel, identity_key), "port": _port(channel, port_key)}


def _proxy_host_id(channel: Mapping[str, Any]) -> str:
    proxy = _required(channel, "proxy")
    return proxy.split("-", 1)[0]


def _next_available(occupied: set[int], protocol: str, role: str, host: str) -> int:
    port = next((value for value in range(RAW_RELAY_PORT_START, RAW_RELAY_PORT_END + 1) if value not in occupied), None)
    if port is None:
        raise InboundRawRoutePlanError([
            f"No {protocol.upper()} relay port is available in {RAW_RELAY_PORT_START}-{RAW_RELAY_PORT_END} "
            f"for {role} {host}. Remove an unused channel before trying again."
        ])
    return port


def _infrastructure_revision(channel: Mapping[str, Any], overview: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "chainId": _required(channel, "chainId"),
        "edge": _revision_row(
            overview.get("sketchInfrastructure"),
            host=_required(channel, "edge"),
            component_id=_required(channel, "edgeComponentId"),
        ),
        "middle": _revision_row(
            overview.get("sketchInfrastructure"),
            host=_required(channel, "middle"),
            component_id=_required(channel, "middleComponentId"),
        ),
        "proxy": _revision_row(
            overview.get("coreInfrastructure"),
            host=_required(channel, "proxy"),
            host_id=_proxy_host_id(channel),
        ),
        "termination": _revision_row(
            overview.get("coreInfrastructure"),
            host=_required(channel, "terminatesOn"),
        ),
    }


def _revision_row(rows: Any, *, host: str, component_id: str = "", host_id: str = "") -> dict[str, str]:
    match: Mapping[str, Any] | None = None
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            row_host = _text(row.get("hostname") or row.get("displayName") or row.get("sshAlias"))
            if row_host != host:
                continue
            if component_id and _text(row.get("componentId")) != component_id:
                continue
            if host_id and _text(row.get("hostId") or row.get("logicalName")) != host_id:
                continue
            match = row
            break
    source = match or {}
    return {
        "host": host,
        "componentId": component_id,
        "hostId": host_id,
        "provider": _text(source.get("provider") or ("oci" if host_id else "")),
        "providerResourceId": _text(source.get("providerResourceId") or source.get("providerInstanceId") or source.get("resourceId") or source.get("instanceId")),
        "deploymentJobId": _text(source.get("deploymentJobId") or source.get("deployJobId")),
        "workspaceRevision": _text(source.get("workspaceRevision") or source.get("workspaceId")),
        "publicIp": _text(source.get("publicIp")),
        "privateIp": _text(source.get("privateIp")),
    }


def _transport(channel: Mapping[str, Any]) -> str:
    return "udp" if _text(channel.get("mode")) == "udp-forward" or _text(channel.get("protocol")).upper() == "UDP" else "tcp"


def _inactive(channel: Mapping[str, Any]) -> bool:
    return _text(channel.get("status")).lower() in {"disabled", "removed"}


def _port(channel: Mapping[str, Any], key: str) -> int:
    return _optional_port(_required(channel, key))


def _optional_port(value: Any) -> int:
    try:
        port = int(_text(value))
    except ValueError as exc:
        raise InboundRawRoutePlanError(["raw route port must be numeric"]) from exc
    if not 1 <= port <= 65535:
        raise InboundRawRoutePlanError(["raw route port must be between 1 and 65535"])
    return port


def _optional_port_value(value: Any) -> int | None:
    return _optional_port(value) if _text(value) else None


def _required(channel: Mapping[str, Any], key: str) -> str:
    value = _text(channel.get(key))
    if not value:
        raise InboundRawRoutePlanError([f"{key} is required for raw route planning"])
    return value


def _add_port(target: set[int], value: Any) -> None:
    try:
        target.add(int(value))
    except (TypeError, ValueError):
        return


def _fingerprint(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _text(value: Any) -> str:
    return str(value or "").strip()
