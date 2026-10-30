# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import PurePosixPath


PROXY_ID_PATTERN = re.compile(r"^proxy\d{2}$")
HOSTNAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$")
SAFE_PROFILE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
DEFAULT_DANTE_SOCKS_PORT = 1080
DEFAULT_SKETCH_OUTBOUND_PORT = 3333
PENDING_PROXY_CONFIGURATION_STATUS = "Pending Proxy Configuration"
SKETCH_SSH_USER = "sketchssh"
STANDARD_CORE_HOST_PRIVATE_IPS = {
    "homebase": "192.168.0.10",
    "proxy01": "192.168.2.11",
    "proxy02": "192.168.2.12",
}


class OutboundChannelArtifactValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("outbound channel artifact validation failed")
        self.errors = errors


@dataclass(frozen=True)
class CoreHost:
    name: str
    private_ip: str


@dataclass(frozen=True)
class OutboundChannelArtifactSpec:
    engagement: str
    profile_name: str
    proxy_id: str
    proxy_private_ip: str
    socks_port: int
    middle_hostname: str
    middle_ip: str
    edge_hostname: str
    edge_ip: str
    expected_edge_public_ip: str
    identity_file_path: str = ""


@dataclass(frozen=True)
class RenderedArtifact:
    target: str
    content: str

    def to_dict(self) -> dict[str, str]:
        return {"target": self.target, "content": self.content}


@dataclass(frozen=True)
class ValidationCommand:
    origin: str
    command: list[str]
    expected_public_ip: str

    def shell_display(self) -> str:
        return " ".join(self.command)

    def to_dict(self) -> dict[str, object]:
        return {
            "origin": self.origin,
            "command": self.command,
            "shellDisplay": self.shell_display(),
            "expectedPublicIp": self.expected_public_ip,
        }


@dataclass(frozen=True)
class SketchNodeOpsecBoundary:
    sketch_hosts_content: None
    middle_node_artifacts: list[RenderedArtifact]
    edge_node_artifacts: list[RenderedArtifact]
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "sketchHostsContent": self.sketch_hosts_content,
            "middleNodeArtifacts": [artifact.to_dict() for artifact in self.middle_node_artifacts],
            "edgeNodeArtifacts": [artifact.to_dict() for artifact in self.edge_node_artifacts],
            "reason": self.reason,
        }


@dataclass(frozen=True)
class OutboundChannelArtifacts:
    core_hosts: RenderedArtifact
    homebase_proxychains: RenderedArtifact
    proxy_ssh_config: RenderedArtifact
    proxy_systemd_service: RenderedArtifact
    validation: ValidationCommand
    sketch_node_boundary: SketchNodeOpsecBoundary

    def to_dict(self) -> dict[str, object]:
        return {
            "coreHosts": self.core_hosts.to_dict(),
            "homebaseProxychains": self.homebase_proxychains.to_dict(),
            "proxySshConfig": self.proxy_ssh_config.to_dict(),
            "proxySystemdService": self.proxy_systemd_service.to_dict(),
            "validation": self.validation.to_dict(),
            "sketchNodeBoundary": self.sketch_node_boundary.to_dict(),
        }


def derive_pending_outbound_channel_from_sketch_rows(
    engagement: str,
    chain_id: str,
    sketch_rows: list[dict[str, object]],
) -> dict[str, object] | None:
    channels = derive_pending_outbound_channels_from_sketch_rows(engagement, chain_id, sketch_rows)
    return channels[0] if channels else None


def derive_pending_outbound_channels_from_sketch_rows(
    engagement: str,
    chain_id: str,
    sketch_rows: list[dict[str, object]],
    *,
    existing_outbound_channels: list[dict[str, object]] | None = None,
) -> list[dict[str, object]]:
    engagement_slug = _artifact_slug(engagement, "engagement")
    middle = _sketch_row_for_role(sketch_rows, "middle")
    edges = _sketch_rows_for_role(sketch_rows, "edge")
    if middle is None or not edges:
        return []

    middle_ip = _row_text(middle, "publicIp")
    if not middle_ip:
        return []

    channels: list[dict[str, object]] = []
    channel_refs: list[dict[str, object]] = []
    edge_count = len(edges)
    for fallback_index, edge in enumerate(edges, start=1):
        edge_ip = _row_text(edge, "publicIp")
        if not edge_ip:
            continue
        edge_index = _edge_index(edge, fallback_index) if edge_count > 1 else 1
        channel_id = outbound_channel_id_for_edge(chain_id, edge_index, edge_count=edge_count)
        proxy_id = _row_text(edge, "proxy") or _row_text(edge, "assignedProxy") or _row_text(middle, "proxy") or _row_text(middle, "assignedProxy")
        channel_refs.append({"channelId": channel_id, "chainId": chain_id, "proxy": proxy_id})
    ports_by_channel = allocate_sketch_outbound_ports(channel_refs, existing_outbound_channels or [])
    for fallback_index, edge in enumerate(edges, start=1):
        edge_ip = _row_text(edge, "publicIp")
        if not edge_ip:
            continue
        edge_index = _edge_index(edge, fallback_index) if edge_count > 1 else 1
        channel_id = outbound_channel_id_for_edge(chain_id, edge_index, edge_count=edge_count)
        proxy_id = _row_text(edge, "proxy") or _row_text(edge, "assignedProxy") or _row_text(middle, "proxy") or _row_text(middle, "assignedProxy")
        proxy_private_ip = STANDARD_CORE_HOST_PRIVATE_IPS.get(proxy_id, "")
        spec = OutboundChannelArtifactSpec(
            engagement=engagement_slug,
            profile_name=channel_id,
            proxy_id=proxy_id,
            proxy_private_ip=proxy_private_ip,
            socks_port=ports_by_channel.get(channel_id, default_sketch_outbound_port_for_edge(chain_id, edge_index)),
            middle_hostname=_row_text(middle, "hostname"),
            middle_ip=middle_ip,
            edge_hostname=_row_text(edge, "hostname"),
            edge_ip=edge_ip,
            expected_edge_public_ip=edge_ip,
            identity_file_path=engagement_sketch_identity_file_path(engagement_slug),
        )
        artifacts = render_outbound_channel_artifacts(spec, _standard_core_hosts())
        artifact_dict = artifacts.to_dict()
        channels.append(
            {
                "channelId": channel_id,
                "chainId": chain_id,
                "edgeIndex": str(edge_index),
                "edgeCount": str(edge_count),
                "proxy": spec.proxy_id,
                "middle": spec.middle_hostname,
                "edge": spec.edge_hostname,
                "port": str(spec.socks_port),
                "provider": _row_text(edge, "provider") or _row_text(middle, "provider"),
                "region": _row_text(edge, "region"),
                "domain": spec.profile_name,
                "purpose": f"Sketch egress profile {spec.profile_name} via {spec.edge_hostname}",
                "status": PENDING_PROXY_CONFIGURATION_STATUS,
                "profileName": spec.profile_name,
                "publicationPath": artifacts.homebase_proxychains.target,
                "validation": artifacts.validation.to_dict(),
                "artifactTargets": {
                    "homebaseProxychains": artifacts.homebase_proxychains.target,
                    "proxySshConfig": artifacts.proxy_ssh_config.target,
                    "proxySystemdService": artifacts.proxy_systemd_service.target,
                },
                "artifacts": artifact_dict,
            }
        )
    return channels


def default_sketch_outbound_port_for_chain(chain_id: str) -> int:
    sequence = _chain_sequence(chain_id)
    return DEFAULT_SKETCH_OUTBOUND_PORT + sequence - 1


def default_sketch_outbound_port_for_edge(chain_id: str, edge_index: int) -> int:
    edge_sequence = max(int(edge_index), 1)
    return default_sketch_outbound_port_for_chain(chain_id) + edge_sequence - 1


def allocate_sketch_outbound_ports(
    channel_refs: list[dict[str, object]],
    existing_outbound_channels: list[dict[str, object]],
) -> dict[str, int]:
    """Assign stable, collision-free SOCKS ports for outbound channels.

    Ports are allocated per proxy from the team-standard sequence 3333, 3334,
    3335, and so on. Existing channel assignments are preserved whenever
    possible so refreshes/redeploys do not reshuffle operator-facing profiles.
    """
    current_ids = {_channel_identity(ref) for ref in channel_refs if _channel_identity(ref)}
    used_by_proxy: dict[str, set[int]] = {}
    preserved: dict[str, int] = {}
    for row in existing_outbound_channels:
        if _is_unreserved_outbound_candidate(row):
            continue
        proxy = _row_text(row, "proxy")
        port = _port_value(row)
        if not proxy or port is None:
            continue
        channel_id = _channel_identity(row)
        if channel_id in current_ids:
            preserved[channel_id] = port
            continue
        used_by_proxy.setdefault(proxy, set()).add(port)

    assigned: dict[str, int] = {}
    for ref in channel_refs:
        channel_id = _channel_identity(ref)
        proxy = _row_text(ref, "proxy")
        if not channel_id or not proxy:
            continue
        proxy_used = used_by_proxy.setdefault(proxy, set())
        preserved_port = preserved.get(channel_id)
        if preserved_port is not None and preserved_port not in proxy_used:
            assigned[channel_id] = preserved_port
            proxy_used.add(preserved_port)
            continue
        port = DEFAULT_SKETCH_OUTBOUND_PORT
        while port in proxy_used:
            port += 1
        assigned[channel_id] = port
        proxy_used.add(port)
    return assigned


def collect_existing_outbound_channels_from_jobs(
    jobs: list[object],
    engagement_id: str,
    *,
    exclude_job_id: str = "",
) -> list[dict[str, object]]:
    channels_by_id: dict[str, dict[str, object]] = {}
    removed_channel_ids: set[str] = set()
    for job in jobs:
        if str(getattr(job, "id", "") or "") == exclude_job_id:
            continue
        if _job_engagement_id(job) != engagement_id:
            continue
        events = getattr(job, "events", []) or []
        for event in reversed(events):
            event_data = getattr(event, "data", {}) or {}
            rows = event_data.get("outboundChannels") if isinstance(event_data, dict) else None
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                channel_id = _channel_identity(row)
                if not channel_id or channel_id in channels_by_id or channel_id in removed_channel_ids:
                    continue
                status = _row_text(row, "status").lower()
                if status in {"removed", "destroyed", "disabled"}:
                    removed_channel_ids.add(channel_id)
                    continue
                channels_by_id[channel_id] = row
    return list(channels_by_id.values())


def outbound_channel_id_for_edge(chain_id: str, edge_index: int, *, edge_count: int) -> str:
    if edge_count <= 1 and edge_index <= 1:
        return chain_id
    return f"{chain_id}-edge-{max(int(edge_index), 1):02d}"


def render_outbound_channel_artifacts(
    spec: OutboundChannelArtifactSpec,
    core_hosts: list[CoreHost],
) -> OutboundChannelArtifacts:
    _validate_inputs(spec, core_hosts)

    core_hosts_artifact = RenderedArtifact(
        target="/etc/hosts",
        content=render_core_hosts_content(spec.engagement, core_hosts),
    )
    homebase_proxychains = RenderedArtifact(
        target=f"/opt/{spec.proxy_id}/{spec.profile_name}-socks5.conf",
        content=render_homebase_proxychains_profile(spec),
    )
    proxy_ssh_config_path = f"/opt/ssh-proxy/config-{spec.socks_port}"
    proxy_ssh_config = RenderedArtifact(
        target=proxy_ssh_config_path,
        content=render_proxy_ssh_config(spec),
    )
    proxy_systemd_service = RenderedArtifact(
        target=f"/etc/systemd/system/ssh-proxy-{spec.socks_port}.service",
        content=render_proxy_systemd_service(spec, proxy_ssh_config_path),
    )
    validation = render_homebase_validation_command(spec)
    sketch_boundary = render_sketch_node_opsec_boundary()

    artifacts = OutboundChannelArtifacts(
        core_hosts=core_hosts_artifact,
        homebase_proxychains=homebase_proxychains,
        proxy_ssh_config=proxy_ssh_config,
        proxy_systemd_service=proxy_systemd_service,
        validation=validation,
        sketch_node_boundary=sketch_boundary,
    )
    _assert_no_secret_material(artifacts)
    return artifacts


def render_core_hosts_content(engagement: str, core_hosts: list[CoreHost]) -> str:
    engagement_name = _required_slug(engagement, "engagement")
    _validate_core_hosts(core_hosts)
    lines = [
        "# Managed by Barragan outbound channel artifacts.",
        "# Core node name resolution only; do not install on sketch nodes.",
    ]
    for host in sorted(core_hosts, key=lambda item: _core_host_sort_key(item.name)):
        name = _required_core_host_name(host.name)
        ip = _required_ip(host.private_ip, f"{name}.private_ip")
        engagement_qualified_name = f"{name}-{engagement_name}"
        lines.append(f"{ip} {engagement_qualified_name}.infra.redteam {engagement_qualified_name} {name}")
    return "\n".join(lines) + "\n"


def render_homebase_proxychains_profile(spec: OutboundChannelArtifactSpec) -> str:
    _validate_spec(spec)
    return "\n".join(
        [
            "# Managed by Barragan outbound channel artifacts.",
            f"# Profile {spec.profile_name} via {spec.proxy_id}:{spec.socks_port}.",
            "strict_chain",
            "proxy_dns",
            "tcp_read_time_out 15000",
            "tcp_connect_time_out 8000",
            "[ProxyList]",
            f"socks5 {spec.proxy_private_ip} {spec.socks_port}",
            "",
        ]
    )


def render_proxy_ssh_config(spec: OutboundChannelArtifactSpec) -> str:
    _validate_spec(spec)
    identity_file_path = _identity_file_path(spec)
    return "\n".join(
        [
            "ServerAliveInterval 30",
            "ServerAliveCountMax 3",
            "Compression yes",
            f"Host {spec.middle_hostname}",
            f"    Hostname {spec.middle_ip}",
            f"    IdentityFile {identity_file_path}",
            f"    User {SKETCH_SSH_USER}",
            "    UserKnownHostsFile /dev/null",
            "    StrictHostKeyChecking no",
            "    BatchMode yes",
            f"Host {spec.edge_hostname}",
            f"    Hostname {spec.edge_ip}",
            f"    DynamicForward 0.0.0.0:{spec.socks_port}",
            f"    ProxyJump {spec.middle_hostname}",
            f"    IdentityFile {identity_file_path}",
            f"    User {SKETCH_SSH_USER}",
            "    UserKnownHostsFile /dev/null",
            "    StrictHostKeyChecking no",
            "    BatchMode yes",
            "    RequestTTY no",
            "",
        ]
    )


def render_proxy_systemd_service(spec: OutboundChannelArtifactSpec, ssh_config_path: str | None = None) -> str:
    _validate_spec(spec)
    config_path = ssh_config_path or f"/opt/ssh-proxy/config-{spec.socks_port}"
    _required_absolute_path(config_path, "ssh_config_path")
    return "\n".join(
        [
            "[Unit]",
            f"Description=ssh forward socks proxy for {spec.socks_port} through {spec.middle_hostname} -> {spec.edge_hostname}",
            "After=network.target auditd.service",
            "",
            "[Service]",
            'Environment="AUTOSSH_GATETIME=0"',
            f"ExecStart=/usr/bin/autossh -M0 -F {config_path} -N {spec.edge_hostname}",
            "Restart=on-failure",
            "RestartSec=5s",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )


def render_homebase_validation_command(spec: OutboundChannelArtifactSpec) -> ValidationCommand:
    _validate_spec(spec)
    return ValidationCommand(
        origin="homebase",
        command=[
            "curl",
            "-sS",
            "--connect-timeout",
            "10",
            "-x",
            f"socks5h://{spec.proxy_id}:{spec.socks_port}",
            "https://ipv4.icanhazip.com",
        ],
        expected_public_ip=spec.expected_edge_public_ip,
    )


def render_sketch_node_opsec_boundary() -> SketchNodeOpsecBoundary:
    return SketchNodeOpsecBoundary(
        sketch_hosts_content=None,
        middle_node_artifacts=[],
        edge_node_artifacts=[],
        reason="Outbound channel foundation renders core and proxy-owned artifacts only; sketch nodes do not receive /etc/hosts enrichment or full topology.",
    )


def _validate_spec(spec: OutboundChannelArtifactSpec) -> None:
    errors: list[str] = []
    _collect_slug_error(errors, spec.engagement, "engagement")
    _collect_profile_name_error(errors, spec.profile_name)
    _collect_proxy_id_error(errors, spec.proxy_id)
    _collect_port_error(errors, spec.socks_port)
    _collect_ip_error(errors, spec.proxy_private_ip, "proxy_private_ip")
    _collect_hostname_error(errors, spec.middle_hostname, "middle_hostname")
    _collect_ip_error(errors, spec.middle_ip, "middle_ip")
    _collect_hostname_error(errors, spec.edge_hostname, "edge_hostname")
    _collect_ip_error(errors, spec.edge_ip, "edge_ip")
    _collect_ip_error(errors, spec.expected_edge_public_ip, "expected_edge_public_ip")
    _collect_absolute_path_error(errors, _identity_file_path(spec), "identity_file_path")
    if errors:
        raise OutboundChannelArtifactValidationError(errors)


def engagement_sketch_identity_file_path(engagement: str) -> str:
    engagement_name = _artifact_slug(engagement, "engagement")
    return f"/opt/ssh-proxy/keys/{engagement_name}-sketch"


def _identity_file_path(spec: OutboundChannelArtifactSpec) -> str:
    return spec.identity_file_path.strip() or engagement_sketch_identity_file_path(spec.engagement)


def _validate_inputs(spec: OutboundChannelArtifactSpec, core_hosts: list[CoreHost]) -> None:
    errors: list[str] = []
    try:
        _validate_spec(spec)
    except OutboundChannelArtifactValidationError as exc:
        errors.extend(exc.errors)
    try:
        _validate_core_hosts(core_hosts)
    except OutboundChannelArtifactValidationError as exc:
        errors.extend(exc.errors)
    if errors:
        raise OutboundChannelArtifactValidationError(errors)


def _validate_core_hosts(core_hosts: list[CoreHost]) -> None:
    errors: list[str] = []
    names = {host.name for host in core_hosts}
    seen_names: dict[str, str] = {}
    seen_ips: dict[str, str] = {}
    for required in ("homebase", "proxy01", "proxy02"):
        if required not in names:
            errors.append(f"core host {required} is required")
    for host in core_hosts:
        try:
            name = _required_core_host_name(host.name)
        except OutboundChannelArtifactValidationError as exc:
            errors.extend(exc.errors)
            name = str(host.name or "").strip()
        try:
            private_ip = _required_ip(host.private_ip, f"{name}.private_ip")
        except OutboundChannelArtifactValidationError as exc:
            errors.extend(exc.errors)
            private_ip = str(host.private_ip or "").strip()
        if name:
            if name in seen_names:
                errors.append(f"core host {name} is duplicated")
            seen_names[name] = private_ip
        if private_ip:
            previous_name = seen_ips.get(private_ip)
            if previous_name is not None and previous_name != name:
                errors.append(f"core host IP {private_ip} is assigned to both {previous_name} and {name}")
            seen_ips[private_ip] = name
    if errors:
        raise OutboundChannelArtifactValidationError(errors)


def _assert_no_secret_material(artifacts: OutboundChannelArtifacts) -> None:
    rendered = "\n".join(
        [
            artifacts.core_hosts.content,
            artifacts.homebase_proxychains.content,
            artifacts.proxy_ssh_config.content,
            artifacts.proxy_systemd_service.content,
            artifacts.validation.shell_display(),
        ]
    )
    forbidden_patterns = [
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN PRIVATE KEY",
        "LINODE_TOKEN",
        "OCI_CLI_AUTH",
        "provider_token",
        "private_key_material",
    ]
    matches = [pattern for pattern in forbidden_patterns if pattern in rendered]
    if matches:
        raise OutboundChannelArtifactValidationError([f"rendered artifact contains forbidden secret marker: {matches[0]}"])


def _required_slug(value: str, field: str) -> str:
    text = _required_text(value, field)
    if not SAFE_PROFILE_NAME_PATTERN.fullmatch(text):
        raise OutboundChannelArtifactValidationError([f"{field} must contain only letters, numbers, dots, underscores, or hyphens"])
    return text


def _artifact_slug(value: str, field: str) -> str:
    """Return the canonical safe slug used in rendered host paths and aliases."""
    text = _required_text(value, field)
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "engagement"


def _required_core_host_name(value: str) -> str:
    text = _required_text(value, "core_host.name")
    if text != "homebase" and not PROXY_ID_PATTERN.fullmatch(text):
        raise OutboundChannelArtifactValidationError(["core host names must be homebase or proxyNN"])
    return text


def _required_ip(value: str, field: str) -> str:
    text = _required_text(value, field)
    try:
        ipaddress.ip_address(text)
    except ValueError as exc:
        raise OutboundChannelArtifactValidationError([f"{field} must be an IP address"]) from exc
    return text


def _required_absolute_path(value: str, field: str) -> str:
    text = _required_text(value, field)
    path = PurePosixPath(text)
    if not path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise OutboundChannelArtifactValidationError([f"{field} must be an absolute POSIX path"])
    if "\n" in text or "\r" in text:
        raise OutboundChannelArtifactValidationError([f"{field} must not contain newlines"])
    return text


def _required_text(value: str, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise OutboundChannelArtifactValidationError([f"{field} is required"])
    if "\n" in text or "\r" in text:
        raise OutboundChannelArtifactValidationError([f"{field} must not contain newlines"])
    return text


def _collect_slug_error(errors: list[str], value: str, field: str) -> None:
    try:
        _required_slug(value, field)
    except OutboundChannelArtifactValidationError as exc:
        errors.extend(exc.errors)


def _collect_profile_name_error(errors: list[str], value: str) -> None:
    try:
        _required_slug(value, "profile_name")
    except OutboundChannelArtifactValidationError as exc:
        errors.extend(exc.errors)


def _collect_proxy_id_error(errors: list[str], value: str) -> None:
    try:
        text = _required_text(value, "proxy_id")
        if not PROXY_ID_PATTERN.fullmatch(text):
            errors.append("proxy_id must look like proxy01")
    except OutboundChannelArtifactValidationError as exc:
        errors.extend(exc.errors)


def _collect_hostname_error(errors: list[str], value: str, field: str) -> None:
    try:
        text = _required_text(value, field)
        if not HOSTNAME_PATTERN.fullmatch(text):
            errors.append(f"{field} must be a hostname")
    except OutboundChannelArtifactValidationError as exc:
        errors.extend(exc.errors)


def _collect_ip_error(errors: list[str], value: str, field: str) -> None:
    try:
        _required_ip(value, field)
    except OutboundChannelArtifactValidationError as exc:
        errors.extend(exc.errors)


def _collect_absolute_path_error(errors: list[str], value: str, field: str) -> None:
    try:
        _required_absolute_path(value, field)
    except OutboundChannelArtifactValidationError as exc:
        errors.extend(exc.errors)


def _collect_port_error(errors: list[str], value: int) -> None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        errors.append("socks_port must be an integer")
        return
    if port < 1 or port > 65535:
        errors.append("socks_port must be in the valid TCP range")
    if port == DEFAULT_DANTE_SOCKS_PORT:
        errors.append("socks_port 1080 is reserved for default proxy egress")


def _core_host_sort_key(name: str) -> tuple[int, str]:
    if name == "homebase":
        return (0, name)
    return (1, name)


def _standard_core_hosts() -> list[CoreHost]:
    return [
        CoreHost(name, private_ip)
        for name, private_ip in STANDARD_CORE_HOST_PRIVATE_IPS.items()
    ]


def _sketch_row_for_role(rows: list[dict[str, object]], role: str) -> dict[str, object] | None:
    for row in rows:
        if _row_text(row, "role") == role:
            return row
    return None


def _sketch_rows_for_role(rows: list[dict[str, object]], role: str) -> list[dict[str, object]]:
    return [row for row in rows if _row_text(row, "role") == role]


def _row_text(row: dict[str, object], key: str) -> str:
    return str(row.get(key) or "").strip()


def _channel_identity(row: dict[str, object]) -> str:
    channel_id = _row_text(row, "channelId")
    if channel_id and channel_id != "N/A":
        return channel_id
    chain_id = _row_text(row, "chainId")
    if chain_id and chain_id != "N/A":
        return chain_id
    return _row_text(row, "id")


def _is_unreserved_outbound_candidate(row: dict[str, object]) -> bool:
    status = _row_text(row, "status").lower()
    if status == PENDING_PROXY_CONFIGURATION_STATUS.lower():
        return True
    if status not in {"not ready", "not deployed"}:
        return False
    edge = _row_text(row, "edge").lower()
    middle = _row_text(row, "middle").lower()
    return edge in {"", "n/a", "not deployed"} and middle in {"", "n/a", "not deployed"}


def _port_value(row: dict[str, object]) -> int | None:
    for key in ("port", "listenerPort"):
        text = _row_text(row, key)
        if not text:
            continue
        try:
            port = int(text)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            return port
    return None


def _job_engagement_id(job: object) -> str:
    job_input = getattr(job, "input", {}) or {}
    if isinstance(job_input, dict):
        value = str(job_input.get("engagementId") or "").strip()
        if value:
            return value
    value = str(getattr(job, "target_id", "") or "").strip()
    if value:
        return value
    target = str(getattr(job, "target", "") or "").strip()
    if target.startswith("engagement:"):
        return target.split(":", 1)[1]
    return ""


def _edge_index(row: dict[str, object], fallback: int) -> int:
    for key in ("edgeIndex", "edgeOrdinal", "index"):
        text = _row_text(row, key)
        if not text:
            continue
        try:
            value = int(text)
        except ValueError:
            continue
        if value > 0:
            return value
    match = re.search(r"-(\d+)$", _row_text(row, "hostname"))
    if match:
        try:
            value = int(match.group(1))
        except ValueError:
            value = fallback
        if value > 0:
            return value
    return fallback


def _chain_sequence(chain_id: str) -> int:
    text = chain_id.strip()
    match = re.search(r"(?:^|[-_])(?:chain[-_])?(\d+)$", text)
    try:
        suffix_sequence = int(match.group(1)) if match else 1
    except ValueError:
        suffix_sequence = 1
    return max(suffix_sequence, 1)
