# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only Linode identity probe through the selected Sketch management route.

This is diagnostic raw evidence, not strict host proof. The current pinned
UFW/sshd interpreters are based on DigitalOcean captures; a Linode capture
must be independently reviewed before this observation can authorize publish.
The caller must reserve a one-shot claimed command journal before calling.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Mapping
from uuid import UUID, uuid4

from app.core.command_environment import barragan_subprocess_env
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, StartedCommand,
    UnreapedGatedCommandError, _private_scratch_path, run_gated_command,
)
from app.services.provider_keyed_host_binding import _regular_file_digest
from app.services.provider_keyed_host_identity_probe import _require_pinned_aliases
from app.services.provider_keyed_host_identity_probe import (
    DigitalOceanHostIdentityEvidence, DigitalOceanRawHostCollection,
    _collect_raw_firewall, _collect_raw_host_surface, _stable_firewall_commands,
)
from app.services.provider_keyed_initial_bootstrap import _sketch_file_snapshot
from app.services.sketch_bootstrap import SketchBootstrapSpec, render_strict_v2_sketch_identity_ssh_config
from app.services.sketch_ssh_keys import write_existing_sketch_ssh_key_files


_SCRIPT = """import json, os, socket, urllib.request
base = 'http://169.254.169.254/v1/'
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
def request(path, method, headers):
    url = base + path
    with opener.open(urllib.request.Request(url, method=method, headers=headers), timeout=3) as response:
        if response.status != 200 or response.geturl() != url:
            raise ValueError('Linode metadata endpoint changed')
        body = response.read(4097)
        if not body or len(body) > 4096 or response.read(1):
            raise ValueError('Linode metadata response is unbounded')
        return body.decode('utf-8', 'strict')
token = request('token', 'PUT', {'Metadata-Token-Expiry-Seconds': '60',
                                 'Accept': 'text/plain'}).strip()
if not token or len(token) > 1024 or any(ord(c) < 33 or ord(c) > 126 for c in token):
    raise ValueError('Linode metadata token differs')
instance = json.loads(request('instance', 'GET', {'Metadata-Token': token,
                                                  'Accept': 'application/json'}))
with open('/proc/sys/kernel/random/boot_id', encoding='ascii') as stream:
    boot_id = stream.read(128).strip()
print(json.dumps({'instance': instance, 'hostname': socket.gethostname(),
                  'boot_id': boot_id, 'ssh_connection': os.environ.get('SSH_CONNECTION')},
                 sort_keys=True, separators=(',', ':')))
"""
_ID = re.compile(r"[1-9][0-9]*\Z")


class LinodeHostDiagnosticPrerequisite(ValueError):
    """Linode raw identity exists, but a reviewed strict policy baseline does not."""


class LinodeHostProbeError(ValueError):
    """The selected Linode identity was not observed safely and exactly."""


@dataclass(frozen=True)
class LinodeRawHostIdentity:
    manifest_sha256: str
    chain_id: str
    terraform_address: str
    provider_instance_id: str
    image: str
    region: str
    public_ipv4: str
    hostname: str
    boot_id: str
    ssh_connection: tuple[str, int, str, int]
    invocation_id: str
    core_known_hosts_sha256: str
    sketch_known_hosts_sha256: str


@dataclass(frozen=True)
class LinodeRawHostCollection:
    """Private raw inputs only; no Linode host policy is interpreted."""
    identity: LinodeRawHostIdentity
    raw: DigitalOceanRawHostCollection
    policy_interpreted: bool = False


def _sudo_hostname_warning(hostname: str) -> str:
    """The only stderr allowed for Linode's read-only sudo observations."""
    return f"sudo: unable to resolve host {hostname}: Name or service not known\n"


def _parse_identity(raw: str, *, expected: Mapping[str, object], image: str,
                    predecessor: str) -> tuple[str, tuple[str, int, str, int]]:
    data = json.loads(raw)
    if (type(data) is not dict or set(data) != {"instance", "hostname", "boot_id", "ssh_connection"}
            or type(data["instance"]) is not dict):
        raise ValueError("Linode metadata shape differs")
    instance = data["instance"]
    if (type(instance.get("id")) is not int
            or str(instance["id"]) != expected["providerInstanceId"]
            or instance.get("label") != expected["hostname"]
            or instance.get("region") != expected["region"]
            or type(instance.get("image")) is not dict
            or instance["image"].get("id") != image
            or data["hostname"] != expected["hostname"]):
        raise ValueError("Linode metadata differs from retained provider identity")
    boot = str(UUID(data["boot_id"]))
    if boot != data["boot_id"].lower():
        raise ValueError("Linode boot identity differs")
    fields = data["ssh_connection"].split() if type(data["ssh_connection"]) is str else []
    if len(fields) != 4:
        raise ValueError("Linode SSH connection context differs")
    client, client_port, local, local_port = fields
    if (client != predecessor or local != expected["publicIp"]
            or not client_port.isascii() or not client_port.isdecimal()
            or not local_port.isascii() or not local_port.isdecimal()
            or not 1 <= int(client_port) <= 65535 or str(int(client_port)) != client_port
            or local_port != "22"
            or str(ipaddress.IPv4Address(client)) != client
            or str(ipaddress.IPv4Address(local)) != local):
        raise ValueError("Linode SSH predecessor or target differs")
    return boot, (client, int(client_port), local, 22)


def probe_linode_host_identity(
    *, manifest: Mapping[str, object], manifest_sha256: str,
    node: Mapping[str, object], expected_image: str,
    ssh_spec: SketchBootstrapSpec, reviewed_core_route: Mapping[str, str],
    core_known_hosts_sha256: str, sketch_known_hosts_sha256: str, scratch_path: Path,
    fence: Callable[[], None], scratch_intent_callback: Callable[[str], None],
    intent_callback: Callable[[CommandIntent], None],
    started_callback: Callable[[StartedCommand], None],
    heartbeat_callback: Callable[[StartedCommand], None],
    result_callback: Callable[[CommandAuditResult], None],
    runner: Callable = run_gated_command,
    ssh_executable: Path = Path("/usr/bin/ssh"),
    admin_key_materializer: Callable = write_existing_sketch_ssh_key_files,
    collect_raw: bool = False,
) -> LinodeRawHostIdentity | LinodeRawHostCollection:
    """Capture one manifest-selected identity; caller owns the claimed journal."""
    key_dir = config_path = None
    retain_scratch = False
    try:
        rows = manifest.get("nodes")
        if (manifest.get("schema") != "mixed-initial-host-binding-v1"
                or hashlib.sha256(json.dumps(manifest, sort_keys=True,
                    separators=(",", ":")).encode()).hexdigest() != manifest_sha256
                or type(rows) is not list or node not in rows or rows.count(node) != 1
                or node.get("provider") != "linode" or node.get("role") not in {"middle", "edge"}
                or not _ID.fullmatch(str(node.get("providerInstanceId")))
                or expected_image != "linode/ubuntu24.04"
                or not str(node.get("terraformAddress", "")).startswith(
                    f'linode_instance.{node["role"]}["')
                or not isinstance(manifest.get("engagementId"), str)):
            raise ValueError("Linode bound manifest differs")
        selected = [row for row in rows if row.get("chainId") == node.get("chainId")]
        middles = [row for row in selected if row.get("role") == "middle"]
        edges = [row for row in selected if row.get("role") == "edge"]
        if (len(selected) != 2 or len(middles) != 1
                or len(edges) != 1 or len(ssh_spec.edges) != 1
                or any(row.get("provider") != "linode" for row in selected)
                or middles[0].get("hostname") != ssh_spec.middle.name
                or middles[0].get("publicIp") != ssh_spec.middle.public_ip
                or edges[0].get("hostname") != ssh_spec.edges[0].name
                or edges[0].get("publicIp") != ssh_spec.edges[0].public_ip):
            raise ValueError("Linode selected chain differs")
        target = ssh_spec.middle if node["role"] == "middle" else next(
            (edge for edge in ssh_spec.edges if edge.name == node["hostname"]), None)
        if target is None or target.public_ip != node["publicIp"]:
            raise ValueError("Linode selected target differs")
        route = {"homebasePublicIp": ssh_spec.homebase.host,
                 "homebaseUser": ssh_spec.homebase.user,
                 "proxyPrivateIp": ssh_spec.proxy.host,
                 "proxyPublicIp": ssh_spec.proxy.host_key_alias,
                 "proxyUser": ssh_spec.proxy.user,
                 "coreSshKeyPath": ssh_spec.homebase.ssh_private_key_path}
        if (dict(reviewed_core_route) != route
                or ssh_spec.proxy.ssh_private_key_path != ssh_spec.homebase.ssh_private_key_path
                or ssh_spec.proxy_egress_ip != ssh_spec.proxy.host_key_alias):
            raise ValueError("Linode selected core route differs")
        predecessor = (ssh_spec.proxy_egress_ip if node["role"] == "middle"
                       else ssh_spec.middle.public_ip)
        policy = ssh_spec.host_policies.get(target.name)
        if policy != {
                "sketch_firewall_v2_enabled": True,
                "sketch_firewall_v2_ssh_sources": [predecessor + "/32"],
                "sketch_firewall_v2_rules": [],
        }:
            raise ValueError("Linode selected host policy differs")
        core = Path(ssh_spec.pinned_core_known_hosts_path)
        sketch = Path(ssh_spec.initial_sketch_known_hosts_path)
        if (core == sketch or not re.fullmatch(r"[0-9a-f]{64}", core_known_hosts_sha256)
                or not re.fullmatch(r"[0-9a-f]{64}", sketch_known_hosts_sha256)):
            raise ValueError("Linode trust files differ")
        executable = Path(ssh_executable)
        if (not executable.is_absolute() or executable.is_symlink()
                or executable.resolve(strict=True) != executable
                or not executable.is_file() or not os.access(executable, os.X_OK)):
            raise ValueError("Linode SSH executable differs")
        scratch = _private_scratch_path(scratch_path)
        fence()
        core_before = _regular_file_digest(core, require_content=True)
        sketch_before = _sketch_file_snapshot(sketch)
        if (core_before != core_known_hosts_sha256
                or sketch_before[2] != sketch_known_hosts_sha256):
            raise ValueError("Linode pinned trust digest differs")
        _require_pinned_aliases(core, (ssh_spec.homebase.host, ssh_spec.proxy.host_key_alias))
        aliases = (f"barragan-bootstrap-sketch-{ssh_spec.middle.name}",)
        if node["role"] == "edge":
            aliases += (f"barragan-bootstrap-sketch-{target.name}",)
        _require_pinned_aliases(sketch, aliases)
        fence()
        scratch_intent_callback(str(scratch))
        fence()
        key_dir = scratch / "keys"
        admin_private, _ = admin_key_materializer(manifest["engagementId"], key_dir)
        admin_private = Path(admin_private)
        key_stat = key_dir.stat()
        private_stat = admin_private.stat()
        if (key_dir.is_symlink() or key_dir.resolve(strict=True) != key_dir
                or not stat.S_ISDIR(key_stat.st_mode) or key_stat.st_uid != os.getuid()
                or stat.S_IMODE(key_stat.st_mode) != 0o700
                or admin_private.is_symlink() or admin_private.parent != key_dir
                or not stat.S_ISREG(private_stat.st_mode) or private_stat.st_uid != os.getuid()
                or private_stat.st_nlink != 1 or stat.S_IMODE(private_stat.st_mode) != 0o600):
            raise ValueError("Linode staged administration key differs")
        config = render_strict_v2_sketch_identity_ssh_config(
            replace(ssh_spec, admin_private_key_path=str(admin_private)))
        alias = f"barragan-bootstrap-user-{target.name}"
        if (config.count("  ConnectTimeout 15") != config.count("Host ")
                or f"Host {alias}\n" not in config
                or "StrictHostKeyChecking accept-new" in config
                or "ControlMaster no" not in config or "ControlPersist no" not in config):
            raise ValueError("Linode strict management route differs")
        config = config.replace("  ConnectTimeout 15", "  ConnectTimeout 15\n  ServerAliveInterval 10\n  ServerAliveCountMax 3")
        config_path = scratch / f"linode-identity-{uuid4().hex}.conf"
        fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            content = config.encode()
            offset = 0
            while offset < len(content):
                count = os.write(fd, content[offset:])
                if count <= 0:
                    raise OSError("Linode SSH config write was incomplete")
                offset += count
            os.fsync(fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                raise ValueError("Linode SSH config is unsafe")
        finally:
            os.close(fd)
        recorded_intent = recorded_start = recorded_result = None

        def on_intent(value):
            nonlocal recorded_intent
            fence()
            if recorded_intent is not None or value.scratch_path != str(scratch):
                raise ValueError("Linode command intent differs")
            intent_callback(value)
            recorded_intent = value

        def on_started(value):
            nonlocal recorded_start
            fence()
            if recorded_intent is None or recorded_start is not None or value.intent != recorded_intent:
                raise ValueError("Linode command start differs")
            started_callback(value)
            recorded_start = value

        def on_heartbeat(value):
            fence()
            if value != recorded_start or recorded_result is not None:
                raise ValueError("Linode command heartbeat differs")
            heartbeat_callback(value)

        def on_result(value):
            nonlocal recorded_result
            fence()
            if recorded_start is None or recorded_result is not None or value.started != recorded_start:
                raise ValueError("Linode command result differs")
            result_callback(value)
            recorded_result = value

        fence()
        outcome = runner([str(executable), "-F", str(config_path), alias,
                          "python3", "-c", shlex.quote(_SCRIPT)],
                         scratch_path=scratch, provider_keyed_v2=True,
                         env=barragan_subprocess_env(), intent_callback=on_intent,
                         started_callback=on_started, heartbeat_callback=on_heartbeat,
                         result_callback=on_result)
        fence()
        if (not isinstance(outcome, CommandResult) or recorded_intent is None
                or recorded_start is None or recorded_result is None
                or outcome.started != recorded_start or outcome.returncode != 0
                or outcome.returncode != recorded_result.returncode
                or recorded_result.returncode != 0 or outcome.stdout_truncated
                or outcome.stderr_truncated or recorded_result.stderr_bytes != 0
                or outcome.stderr or len(outcome.stdout.encode()) > 8192):
            raise ValueError("Linode metadata command is incomplete")
        if (_regular_file_digest(core, require_content=True) != core_before
                or _sketch_file_snapshot(sketch) != sketch_before):
            raise ValueError("Linode trust changed during observation")
        boot, connection = _parse_identity(outcome.stdout, expected=node,
                                           image=expected_image, predecessor=predecessor)
        identity = LinodeRawHostIdentity(
            manifest_sha256, node["chainId"], node["terraformAddress"],
            node["providerInstanceId"], expected_image, node["region"],
            node["publicIp"], node["hostname"], boot, connection,
            recorded_intent.invocation_id, core_before, sketch_before[2])
        if not collect_raw:
            return identity
        # Reuse the bounded, read-only remote collectors. Their evidence type
        # retains a historical provider name, but no DigitalOcean metadata or
        # provider API is contacted here.
        surface_identity = DigitalOceanHostIdentityEvidence(
            identity.manifest_sha256, identity.chain_id, identity.terraform_address,
            identity.provider_instance_id, identity.region, identity.public_ipv4,
            identity.hostname, identity.boot_id, alias, identity.invocation_id,
            identity.core_known_hosts_sha256, identity.sketch_known_hosts_sha256)
        expected_stderr = _sudo_hostname_warning(identity.hostname)
        before = _collect_raw_firewall(
            surface_identity, executable, config_path, alias, scratch,
            core, core_before, sketch, sketch_before, fence,
            intent_callback, started_callback, heartbeat_callback, result_callback, runner,
            expected_stderr=expected_stderr)
        surface = _collect_raw_host_surface(
            surface_identity, predecessor, executable, config_path, alias, scratch,
            core, core_before, sketch, sketch_before, fence,
            intent_callback, started_callback, heartbeat_callback, result_callback, runner,
            expected_stderr=expected_stderr)
        after = _collect_raw_firewall(
            surface_identity, executable, config_path, alias, scratch,
            core, core_before, sketch, sketch_before, fence,
            intent_callback, started_callback, heartbeat_callback, result_callback, runner,
            expected_stderr=expected_stderr)
        if (before.boot_id != identity.boot_id or surface.boot_id != identity.boot_id
                or after.boot_id != identity.boot_id
                or before.completed_at_ns > surface.started_at_ns
                or surface.completed_at_ns > after.started_at_ns
                or after.completed_at_ns - before.started_at_ns > 300_000_000_000
                or _stable_firewall_commands(before.commands)
                != _stable_firewall_commands(after.commands)
                or [(row.name, row.status, row.sha256, row.byte_count,
                     row.uid, row.gid, row.mode) for row in before.files]
                != [(row.name, row.status, row.sha256, row.byte_count,
                     row.uid, row.gid, row.mode) for row in after.files]):
            raise ValueError("Linode raw policy changed during bounded collection")
        return LinodeRawHostCollection(
            identity, DigitalOceanRawHostCollection(surface_identity, before, surface, after))
    except UnreapedGatedCommandError:
        retain_scratch = True
        raise
    except Exception as exc:
        raise LinodeHostProbeError("routed Linode host identity remains unproved") from exc
    finally:
        if not retain_scratch:
            if config_path is not None and (config_path.exists() or config_path.is_symlink()):
                if config_path.is_symlink():
                    raise LinodeHostProbeError("Linode probe scratch cleanup is unproved")
                config_path.unlink()
            if key_dir is not None and (key_dir.exists() or key_dir.is_symlink()):
                if key_dir.is_symlink():
                    raise LinodeHostProbeError("Linode probe key cleanup is unproved")
                shutil.rmtree(key_dir)


def require_reviewed_linode_host_policy(_identity: LinodeRawHostIdentity) -> None:
    """There is no validated Linode UFW/sshd profile in this revision."""
    raise LinodeHostDiagnosticPrerequisite(
        "Linode Ubuntu host UFW/sshd and transport raw baseline needs independent review")
