# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import hashlib
import re
import shlex
from dataclasses import dataclass
from typing import Any, Mapping

from app.services.outbound_channel_artifacts import RenderedArtifact


SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
HOSTNAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$")
SUPPORTED_INBOUND_MODES = {"tcp-forward", "http-openresty", "https-openresty", "udp-forward"}
SUPPORTED_VALIDATION_PROFILE_TYPES = {"temporary-listener", "tcp-send-receive", "udp-send-receive", "tcp-connect", "http", "manual"}
MAX_VALIDATION_TEXT_CHARS = 4096
HTTP_ROUTE_HEALTH_EXPECTATION = "HTTP status below 500"
SECRET_MARKERS = (
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "LINODE_TOKEN",
    "DIGITALOCEAN_TOKEN",
    "OCI_CLI_AUTH",
    "provider_token",
    "private_key_material",
)
VALIDATION_SECRET_PATTERNS = (
    re.compile(r"authorization\s*:", re.IGNORECASE),
    re.compile(r"proxy-authorization\s*:", re.IGNORECASE),
    re.compile(r"\bcookie\s*:", re.IGNORECASE),
    re.compile(r"set-cookie\s*:", re.IGNORECASE),
    re.compile(r"x-api-(key|token)", re.IGNORECASE),
    re.compile(r"\bapi[_ -]?key\s*[:=]", re.IGNORECASE),
    re.compile(r"\bprivate[_ -]?key\s*[:=]", re.IGNORECASE),
    re.compile(r"\bbearer\s+\S+", re.IGNORECASE),
    re.compile(r"\bbasic\s+\S+", re.IGNORECASE),
    re.compile(r"\b(password|passwd|token|secret|access[_ -]?token|refresh[_ -]?token|client[_ -]?secret)\s*[:=]", re.IGNORECASE),
)
DEFAULT_VALIDATION_LABELS = {
    "temporary-listener": "Temporary TCP listener",
    "tcp-connect": "TCP reachability",
    "tcp-send-receive": "TCP send/expect",
    "http": "HTTP check",
    "udp-send-receive": "UDP send/expect",
    "manual": "Manual validation",
}


class InboundChannelArtifactValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("inbound channel artifact validation failed")
        self.errors = errors


@dataclass(frozen=True)
class InboundValidationProfile:
    profile_type: str
    label: str
    request_text: str = ""
    expected_response: str = ""

    def to_dict(self) -> dict[str, str]:
        body = {"type": self.profile_type, "label": self.label}
        if self.request_text:
            body["requestText"] = self.request_text
        if self.expected_response:
            body["expectedResponse"] = self.expected_response
        return body


@dataclass(frozen=True)
class InboundChannelArtifactSpec:
    engagement: str
    channel_id: str
    domain: str
    protocol: str
    external_port: int
    edge_hostname: str
    middle_hostname: str
    proxy_hostname: str
    terminates_on: str
    service: str
    internal_port: int
    purpose: str
    # A managed HTTPS backend terminates at the shared proxy front on
    # ``internal_port`` (443), then forwards to its application-specific
    # private Homebase port. Raw channels have no distinct backend port.
    backend_port: int | None = None
    service_id: str = ""
    service_type: str = ""
    mode: str = "tcp-forward"
    relay_port: int | None = None
    middle_relay_port: int | None = None
    proxy_relay_port: int | None = None
    edge_upstream_host: str = ""
    middle_upstream_host: str = ""
    proxy_upstream_host: str = ""
    validation_profile: InboundValidationProfile | Mapping[str, Any] | None = None
    sketch_chain_id: str = ""


@dataclass(frozen=True)
class InboundValidationPlan:
    profile_type: str
    profile_label: str
    listener_origin: str
    listener_command: list[str]
    probe_origin: str
    probe_command: list[str]
    expected_marker: str
    request_text: str = ""
    expected_response: str = ""

    @property
    def listener_shell_display(self) -> str:
        return " ".join(self.listener_command)

    @property
    def probe_shell_display(self) -> str:
        return " ".join(self.probe_command)

    def profile_to_dict(self) -> dict[str, str]:
        return InboundValidationProfile(
            profile_type=self.profile_type,
            label=self.profile_label,
            request_text=self.request_text,
            expected_response=self.expected_response,
        ).to_dict()

    def to_dict(self) -> dict[str, object]:
        return {
            "profileType": self.profile_type,
            "profileLabel": self.profile_label,
            "validationProfile": self.profile_to_dict(),
            "validationScope": "edge-local ingress route",
            "externalIngressVerified": False,
            "listenerOrigin": self.listener_origin,
            "listenerCommand": self.listener_command,
            "listenerShellDisplay": self.listener_shell_display,
            "probeOrigin": self.probe_origin,
            "probeCommand": self.probe_command,
            "probeShellDisplay": self.probe_shell_display,
            "expectedMarker": self.expected_marker,
            "expectedResponse": self.expected_response or self.expected_marker,
            "status": "Not Run",
            "detail": _validation_detail(self.profile_type),
        }


@dataclass(frozen=True)
class SketchNodeInboundBoundary:
    edge_node_artifacts: list[RenderedArtifact]
    middle_node_artifacts: list[RenderedArtifact]
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "edgeNodeArtifacts": [artifact.to_dict() for artifact in self.edge_node_artifacts],
            "middleNodeArtifacts": [artifact.to_dict() for artifact in self.middle_node_artifacts],
            "reason": self.reason,
        }


@dataclass(frozen=True)
class InboundChannelArtifacts:
    edge_stream: RenderedArtifact
    middle_stream: RenderedArtifact
    proxy_stream: RenderedArtifact
    validation: InboundValidationPlan
    sketch_node_boundary: SketchNodeInboundBoundary
    route_family: str

    def to_dict(self) -> dict[str, object]:
        return {
            "routeFamily": self.route_family,
            "sharedWebIngress": self.route_family == "shared-web-ingress",
            "edgeStream": self.edge_stream.to_dict(),
            "middleStream": self.middle_stream.to_dict(),
            "proxyStream": self.proxy_stream.to_dict(),
            "validation": self.validation.to_dict(),
            "sketchNodeBoundary": self.sketch_node_boundary.to_dict(),
        }


def render_inbound_channel_artifacts(spec: InboundChannelArtifactSpec) -> InboundChannelArtifacts:
    _validate_spec(spec)
    transport = _transport_protocol(spec)
    shared_web_ingress = is_shared_web_ingress(spec)
    route_family = inbound_route_family(spec)
    edge_listen_port = spec.external_port
    middle_listen_port = _middle_relay_port(spec)
    proxy_listen_port = _proxy_relay_port(spec)
    edge_stream = RenderedArtifact(
        target=_stream_target(
            spec,
            "edge",
            edge_listen_port,
            upstream_host=spec.edge_upstream_host or spec.middle_hostname,
            shared=shared_web_ingress,
        ),
        content=_render_stream_config(
            listen_port=edge_listen_port,
            upstream_host=spec.edge_upstream_host or spec.middle_hostname,
            upstream_port=middle_listen_port,
            transport=transport,
            proxy_protocol=_edge_should_emit_proxy_protocol(spec),
        ),
    )
    middle_stream = RenderedArtifact(
        target=_stream_target(
            spec,
            "middle",
            middle_listen_port,
            upstream_host=spec.middle_upstream_host or spec.proxy_hostname,
            shared=shared_web_ingress,
        ),
        content=_render_stream_config(
            listen_port=middle_listen_port,
            upstream_host=spec.middle_upstream_host or spec.proxy_hostname,
            upstream_port=proxy_listen_port,
            transport=transport,
        ),
    )
    termination_host = spec.proxy_upstream_host or ("127.0.0.1" if spec.terminates_on == spec.proxy_hostname else spec.terminates_on)
    proxy_stream = RenderedArtifact(
        target=_proxy_router_target(spec) if shared_web_ingress else _stream_target(
            spec,
            "proxy",
            proxy_listen_port,
            upstream_host=termination_host,
            shared=False,
        ),
        content=(
            _render_proxy_router_note(spec)
            if shared_web_ingress
            else _render_stream_config(
                listen_port=proxy_listen_port,
                upstream_host=termination_host,
                upstream_port=spec.internal_port,
                transport=transport,
                ownership_comment=(
                    f"Barragan-managed route {spec.channel_id}; owner: dedicated proxy stream."
                ),
            )
        ),
    )
    validation = _render_validation(spec)
    boundary = SketchNodeInboundBoundary(
        edge_node_artifacts=[edge_stream],
        middle_node_artifacts=[middle_stream],
        reason=(
            (
                f"HTTP/HTTPS sketch nodes receive reusable shared web pass-through for {edge_listen_port}/{transport}; "
                "domain and service routing remains on the proxy front OpenResty stack."
            )
            if shared_web_ingress
            else (
                f"Inbound sketch nodes receive only per-channel {transport.upper()} forward configuration; "
                "no provider credentials, operator accounts, full topology, or unrelated host aliases are rendered."
            )
        ),
    )
    artifacts = InboundChannelArtifacts(
        edge_stream=edge_stream,
        middle_stream=middle_stream,
        proxy_stream=proxy_stream,
        validation=validation,
        sketch_node_boundary=boundary,
        route_family=route_family,
    )
    _assert_no_secret_material(artifacts)
    return artifacts


def compact_inbound_channel_from_spec(spec: InboundChannelArtifactSpec, artifacts: InboundChannelArtifacts) -> dict[str, object]:
    shared_web_ingress = is_shared_web_ingress(spec)
    channel = {
        "channelId": spec.channel_id,
        "domain": spec.domain,
        "protocol": spec.protocol,
        "mode": spec.mode,
        "routeFamily": artifacts.route_family,
        "sharedWebIngress": shared_web_ingress,
        "externalPort": str(spec.external_port),
        "relayPort": str(_relay_port(spec)),
        "middleRelayPort": str(_middle_relay_port(spec)),
        "proxyRelayPort": str(_proxy_relay_port(spec)),
        "edge": spec.edge_hostname,
        "middle": spec.middle_hostname,
        "proxy": spec.proxy_hostname,
        "terminatesOn": spec.terminates_on,
        "service": spec.service,
        "internalPort": str(spec.internal_port),
        "purpose": spec.purpose,
        "status": "Pending Apply",
        "validationProfile": artifacts.validation.profile_to_dict(),
        "validation": artifacts.validation.to_dict(),
        "artifactTargets": {
            "edgeStream": artifacts.edge_stream.target,
            "middleStream": artifacts.middle_stream.target,
            "proxyStream": artifacts.proxy_stream.target,
        },
        "routingOwner": "proxy-front-openresty" if shared_web_ingress else "dedicated-stream-forward",
    }
    # Preserve typed-service identity through apply-state compaction.  The
    # apply worker uses this compact representation to persist the managed
    # proxy-site record after Ansible converges; dropping it here made a
    # successfully rendered GoSUS TLS route invisible to certificate issuance.
    if spec.service_id:
        channel["serviceId"] = spec.service_id
    if spec.service_type:
        channel["serviceType"] = spec.service_type
    if spec.backend_port is not None:
        channel["backendPort"] = str(spec.backend_port)
    if spec.sketch_chain_id:
        channel["chainId"] = spec.sketch_chain_id
    return channel


def _stream_target(spec: InboundChannelArtifactSpec, hop: str, listen_port: int, *, upstream_host: str, shared: bool) -> str:
    if shared:
        return f"/etc/nginx/streams/barragan-web-{hop}-to-{_safe_target_component(upstream_host)}-{listen_port}.conf"
    return f"/etc/nginx/streams/barragan-{spec.channel_id}-{hop}-{listen_port}.conf"


def _proxy_router_target(spec: InboundChannelArtifactSpec) -> str:
    if is_native_static_web_route(spec):
        route_group = "http" if spec.mode == "http-openresty" else "tls"
        return f"/opt/web/{route_group}/{_native_static_web_site_name(spec)}.map"
    if is_managed_http_backend_site(spec):
        # TLS-only maps are intentionally not included by the front HTTP/80
        # router. DNS-01 does not need a public HTTP endpoint, and GoSUS must
        # never become an accidental cleartext upload route.
        return f"/opt/web/tls/{_managed_http_backend_site_name(spec)}.map"
    if spec.mode != "http-openresty":
        return f"/opt/web/streams/barragan-web-front-{spec.external_port}.conf"
    return f"/opt/web/http/barragan-inbound-{spec.channel_id}.map"


def _render_proxy_router_note(spec: InboundChannelArtifactSpec) -> str:
    owner = (
        f"# Barragan-managed route {spec.channel_id}; "
        f"owner: {'shared proxy-front OpenResty' if is_shared_web_ingress(spec) else 'dedicated proxy stream'}."
    )
    if is_native_static_web_route(spec):
        site_name = _native_static_web_site_name(spec)
        service = f"web_{site_name.replace('-', '_')}"
        if spec.mode == "https-openresty":
            service = f"{service}_tls"
        return f"{owner}\n{spec.domain} {service}:8081;\n"
    if is_managed_http_backend_site(spec):
        return f"{owner}\n{spec.domain} {http_backend_service_name(spec.channel_id)}:8081;\n"
    if spec.mode == "http-openresty":
        route_service = http_backend_service_name(spec.channel_id)
        return f"{owner}\n{spec.domain} {route_service}:8081;\n"
    return "\n".join(
        [
            owner,
            "# Shared web ingress is routed by the proxy front OpenResty stack.",
            "# Edge and middle nodes provide standard-port pass-through only.",
            f"# Channel {spec.channel_id} binds domain/service routing on the proxy web stack, not this stream file.",
            "",
        ]
    )


def is_native_static_web_route(spec: InboundChannelArtifactSpec) -> bool:
    """Whether a managed Static Web service already owns the front host map."""

    return (
        spec.mode in {"http-openresty", "https-openresty"}
        and spec.service_type == "web-static"
        and bool(spec.service_id)
        and spec.service_id.startswith("web-")
    )


def is_managed_http_backend_site(spec: InboundChannelArtifactSpec) -> bool:
    """Whether Barragan owns the TLS site for a private HTTP backend route.

    The site container, rather than the final Homebase service, owns TLS and
    the certificate. Its typed identity is assigned while deriving the route,
    so certificate management never infers ownership from arbitrary paths.
    """

    return (
        spec.mode == "https-openresty"
        and spec.service_type == "web-http-backend"
        and bool(spec.service_id)
        and spec.service_id.startswith("http-site-")
    )


def _native_static_web_site_name(spec: InboundChannelArtifactSpec) -> str:
    return spec.service_id.removeprefix("web-")


def _managed_http_backend_site_name(spec: InboundChannelArtifactSpec) -> str:
    return _safe_target_component(spec.service_id.removeprefix("http-site-"))


def _safe_target_component(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip()).strip("-") or "upstream"


def http_backend_service_name(channel_id: str) -> str:
    """Return a stable Docker-DNS-safe label for an HTTP backend container."""

    prefix = "barragan-inbound-"
    digest = hashlib.sha256(channel_id.encode("utf-8")).hexdigest()[:10]
    slug = re.sub(r"[^a-z0-9]+", "-", channel_id.lower()).strip("-") or "route"
    max_slug_length = 63 - len(prefix) - len(digest) - 1
    slug = slug[:max_slug_length].rstrip("-") or "route"
    return f"{prefix}{slug}-{digest}"


def managed_http_backend_service_id(channel_id: str) -> str:
    """Return the stable ownership identity for a managed HTTPS backend site."""

    digest = hashlib.sha256(channel_id.encode("utf-8")).hexdigest()[:16]
    return f"http-site-{digest}"


def _render_stream_config(
    *,
    listen_port: int,
    upstream_host: str,
    upstream_port: int,
    transport: str = "tcp",
    proxy_protocol: bool = False,
    ownership_comment: str = "Managed by Barragan inbound channel artifacts.",
) -> str:
    listen_suffix = " udp reuseport" if transport == "udp" else ""
    lines = [
        f"# {ownership_comment}",
        f"# {transport.upper()} pass-through; service-specific modes must use dedicated renderers.",
        "server {",
        f"    listen {listen_port}{listen_suffix};",
        f"    proxy_pass {upstream_host}:{upstream_port};",
    ]
    if proxy_protocol:
        lines.append("    proxy_protocol on;")
    if transport == "udp":
        lines.append("    proxy_timeout 1s;")
    lines.extend(
        [
            f"    error_log /var/log/nginx/barragan-{upstream_host}-{listen_port}.error.log warn;",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def _render_validation(spec: InboundChannelArtifactSpec) -> InboundValidationPlan:
    profile = normalize_inbound_validation_profile(spec.validation_profile, channel_id=spec.channel_id)
    if spec.mode == "http-openresty" and profile.profile_type == "temporary-listener":
        profile = InboundValidationProfile(
            profile_type="http",
            label="HTTP route check",
            request_text=f"GET / HTTP/1.1\r\nHost: {spec.domain}\r\nConnection: close\r\n\r\n",
            expected_response=HTTP_ROUTE_HEALTH_EXPECTATION,
        )
    if _transport_protocol(spec) == "udp" and profile.profile_type not in {"udp-send-receive", "manual"}:
        raise ValueError("udp-forward requires validationProfile.type udp-send-receive or manual")
    marker = f"barragan-inbound-{spec.channel_id}"
    if profile.profile_type == "tcp-connect":
        return InboundValidationPlan(
            profile_type=profile.profile_type,
            profile_label=profile.label,
            listener_origin="",
            listener_command=[],
            probe_origin="selected_edge",
            probe_command=["sh", "-lc", f"nc -z -w 5 127.0.0.1 {spec.external_port}"],
            expected_marker="",
        )
    if profile.profile_type == "http":
        request_text = profile.request_text or "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        return InboundValidationPlan(
            profile_type=profile.profile_type,
            profile_label=profile.label,
            listener_origin="",
            listener_command=[],
            probe_origin="selected_edge",
            probe_command=["sh", "-lc", _nc_probe_command("tcp", request_text, "127.0.0.1", spec.external_port)],
            expected_marker="",
            request_text=request_text,
            expected_response=profile.expected_response or "",
        )
    if profile.profile_type == "manual":
        return InboundValidationPlan(
            profile_type=profile.profile_type,
            profile_label=profile.label,
            listener_origin="",
            listener_command=[],
            probe_origin="operator",
            probe_command=["sh", "-lc", "true"],
            expected_marker="",
            expected_response="",
        )
    if profile.profile_type == "tcp-send-receive":
        return InboundValidationPlan(
            profile_type=profile.profile_type,
            profile_label=profile.label,
            listener_origin="",
            listener_command=[],
            probe_origin="selected_edge",
            probe_command=["sh", "-lc", _nc_probe_command("tcp", profile.request_text, "127.0.0.1", spec.external_port)],
            expected_marker="",
            request_text=profile.request_text,
            expected_response=profile.expected_response,
        )
    if profile.profile_type == "udp-send-receive":
        return InboundValidationPlan(
            profile_type=profile.profile_type,
            profile_label=profile.label,
            listener_origin="",
            listener_command=[],
            probe_origin="selected_edge",
            probe_command=["sh", "-lc", _nc_probe_command("udp", profile.request_text, "127.0.0.1", spec.external_port)],
            expected_marker="",
            request_text=profile.request_text,
            expected_response=profile.expected_response,
        )
    return InboundValidationPlan(
        profile_type=profile.profile_type,
        profile_label=profile.label,
        listener_origin=spec.terminates_on,
        listener_command=["sh", "-lc", f"nc -l 0.0.0.0 {spec.internal_port}"],
        probe_origin="selected_edge",
        probe_command=["sh", "-lc", f"printf {marker!r} | nc -w 5 127.0.0.1 {spec.external_port}"],
        expected_marker=marker,
        expected_response=marker,
    )


def normalize_inbound_validation_profile(
    value: InboundValidationProfile | Mapping[str, Any] | None,
    *,
    channel_id: str,
) -> InboundValidationProfile:
    if isinstance(value, InboundValidationProfile):
        profile = value
    elif isinstance(value, Mapping):
        profile_type = _safe_validation_text(value.get("type"), "validationProfile.type") or "temporary-listener"
        label = _safe_validation_text(value.get("label"), "validationProfile.label") or DEFAULT_VALIDATION_LABELS.get(profile_type, profile_type)
        request_text = _safe_validation_text(value.get("requestText"), "validationProfile.requestText")
        expected_response = _safe_validation_text(value.get("expectedResponse"), "validationProfile.expectedResponse")
        profile = InboundValidationProfile(profile_type=profile_type, label=label, request_text=request_text, expected_response=expected_response)
    else:
        profile = InboundValidationProfile(
            profile_type="temporary-listener",
            label=DEFAULT_VALIDATION_LABELS["temporary-listener"],
            expected_response=f"barragan-inbound-{channel_id}",
        )

    profile_type = profile.profile_type.strip()
    if profile_type not in SUPPORTED_VALIDATION_PROFILE_TYPES:
        raise ValueError("validationProfile.type must be temporary-listener, tcp-send-receive, udp-send-receive, tcp-connect, http, or manual")

    label = profile.label.strip() or DEFAULT_VALIDATION_LABELS[profile_type]
    request_text = _safe_validation_text(profile.request_text, "validationProfile.requestText")
    expected_response = _safe_validation_text(profile.expected_response, "validationProfile.expectedResponse")
    if profile_type == "temporary-listener":
        return InboundValidationProfile(profile_type=profile_type, label=label, expected_response=f"barragan-inbound-{channel_id}")
    if profile_type in {"tcp-connect", "http", "manual"}:
        return InboundValidationProfile(
            profile_type=profile_type,
            label=label,
            request_text=request_text,
            expected_response=expected_response,
        )
    if not expected_response:
        raise ValueError("validationProfile.expectedResponse is required for tcp-send-receive and udp-send-receive")
    if profile_type == "udp-send-receive" and not request_text:
        raise ValueError("validationProfile.requestText is required for udp-send-receive")
    return InboundValidationProfile(
        profile_type=profile_type,
        label=label,
        request_text=request_text,
        expected_response=expected_response,
    )


def _safe_validation_text(value: Any, field_name: str) -> str:
    text = str(value or "")
    if "\x00" in text:
        raise ValueError(f"{field_name} must not contain null bytes")
    if len(text) > MAX_VALIDATION_TEXT_CHARS:
        raise ValueError(f"{field_name} must be {MAX_VALIDATION_TEXT_CHARS} characters or fewer")
    for marker in SECRET_MARKERS:
        if marker in text:
            raise ValueError(f"{field_name} contains forbidden secret marker {marker}")
    for pattern in VALIDATION_SECRET_PATTERNS:
        if pattern.search(text):
            raise ValueError(f"{field_name} appears to contain credential material")
    return text


def _nc_probe_command(transport: str, request_text: str, host: str, port: int) -> str:
    request = shlex.quote(request_text)
    safe_host = shlex.quote(host)
    if transport == "udp":
        return f"printf %s {request} | nc -u -w 5 {safe_host} {port}"
    return f"printf %s {request} | nc -w 5 {safe_host} {port}"


def _validation_detail(profile_type: str) -> str:
    if profile_type == "tcp-connect":
        return "Run a TCP connect check from the selected edge against the channel ingress port."
    if profile_type == "tcp-send-receive":
        return "Run a TCP client on the selected edge against the channel ingress port, then match expected response text."
    if profile_type == "http":
        return "Run an HTTP probe from the selected edge against the channel ingress port."
    if profile_type == "udp-send-receive":
        return "Run a UDP client on the selected edge against the channel ingress port, then match expected response text."
    if profile_type == "manual":
        return "No automatic service-specific validation is configured."
    return "Start the temporary listener on the termination host, run the marker client from the selected edge, verify receipt, then remove the listener."


def _edge_should_emit_proxy_protocol(spec: InboundChannelArtifactSpec) -> bool:
    return is_shared_web_ingress(spec)


def inbound_route_family(spec: InboundChannelArtifactSpec) -> str:
    return "shared-web-ingress" if is_shared_web_ingress(spec) else "dedicated-port-forward"


def is_shared_web_ingress(spec: InboundChannelArtifactSpec) -> bool:
    return spec.mode in {"http-openresty", "https-openresty"} or spec.service.strip().lower() == "static web"


def _transport_protocol(spec: InboundChannelArtifactSpec) -> str:
    if spec.mode.strip().lower() == "udp-forward" or spec.protocol.upper() == "UDP":
        return "udp"
    return "tcp"


def _relay_port(spec: InboundChannelArtifactSpec) -> int:
    if spec.relay_port is not None:
        return spec.relay_port
    return spec.internal_port if _transport_protocol(spec) == "udp" else spec.external_port


def _middle_relay_port(spec: InboundChannelArtifactSpec) -> int:
    return spec.middle_relay_port if spec.middle_relay_port is not None else _relay_port(spec)


def _proxy_relay_port(spec: InboundChannelArtifactSpec) -> int:
    return spec.proxy_relay_port if spec.proxy_relay_port is not None else _relay_port(spec)


def _validate_spec(spec: InboundChannelArtifactSpec) -> None:
    errors: list[str] = []
    if not SAFE_ID_PATTERN.match(spec.channel_id):
        errors.append("channelId must contain only letters, numbers, dots, dashes, or underscores")
    if spec.mode not in SUPPORTED_INBOUND_MODES:
        errors.append("mode must be tcp-forward, http-openresty, https-openresty, or udp-forward")
    if spec.protocol.upper() not in {"TCP", "HTTP", "HTTPS", "UDP"}:
        errors.append("protocol must be TCP, HTTP, HTTPS, or UDP")
    if is_shared_web_ingress(spec):
        if not _valid_hostish(spec.domain):
            errors.append("domain must be a hostname-like value")
    elif spec.domain.strip() not in {"", "N/A"} and not _valid_hostish(spec.domain):
        errors.append("domain must be a hostname-like value")
    for field_name, hostname in (
        ("edge", spec.edge_hostname),
        ("middle", spec.middle_hostname),
        ("proxy", spec.proxy_hostname),
        ("terminatesOn", spec.terminates_on),
    ):
        if not _valid_hostish(hostname):
            errors.append(f"{field_name} must be a hostname-like value")
    for field_name, port in (
        ("externalPort", spec.external_port),
        ("internalPort", spec.internal_port),
        ("relayPort", spec.relay_port) if spec.relay_port is not None else ("relayPort", 1),
        ("middleRelayPort", spec.middle_relay_port) if spec.middle_relay_port is not None else ("middleRelayPort", 1),
        ("proxyRelayPort", spec.proxy_relay_port) if spec.proxy_relay_port is not None else ("proxyRelayPort", 1),
    ):
        if port < 1 or port > 65535:
            errors.append(f"{field_name} must be between 1 and 65535")
    if _transport_protocol(spec) == "udp" and spec.mode != "udp-forward":
        errors.append("UDP protocol requires mode udp-forward")
    if spec.mode == "udp-forward" and spec.protocol.upper() != "UDP":
        errors.append("udp-forward mode requires protocol UDP")
    if spec.mode == "https-openresty" and spec.protocol.upper() not in {"HTTPS", "TCP"}:
        errors.append("https-openresty mode requires HTTPS or TCP protocol")
    if spec.mode == "http-openresty" and spec.protocol.upper() not in {"HTTP", "TCP"}:
        errors.append("http-openresty mode requires HTTP or TCP protocol")
    if spec.mode == "http-openresty" and spec.external_port != 80:
        errors.append("http-openresty mode requires externalPort 80")
    if not spec.service.strip():
        errors.append("service is required")
    if errors:
        raise InboundChannelArtifactValidationError(errors)


def _valid_hostish(value: str) -> bool:
    text = value.strip()
    return bool(text and HOSTNAME_PATTERN.match(text) and text not in {"N/A", "Not Deployed", "Not Ready"})


def _assert_no_secret_material(artifacts: InboundChannelArtifacts) -> None:
    body = str(artifacts.to_dict())
    leaked = [marker for marker in SECRET_MARKERS if marker in body]
    if leaked:
        raise InboundChannelArtifactValidationError([f"inbound artifacts contain forbidden secret marker {marker}" for marker in leaked])
