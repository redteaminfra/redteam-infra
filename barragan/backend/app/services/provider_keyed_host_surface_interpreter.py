# Copyright (c) 2026, Oracle and/or its affiliates.
"""Interpret bounded, routed SSH/account/socket evidence for one Sketch host."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re
from dataclasses import dataclass
from typing import Mapping

from app.services.provider_keyed_host_identity_probe import (
    DigitalOceanHostIdentityEvidence, DigitalOceanRawHostCollection,
)
from app.services.provider_keyed_mixed_linode_host_probe import LinodeRawHostCollection, LinodeRawHostIdentity


class HostSurfaceInterpretationError(ValueError):
    """The observed host surface is incomplete or outside the reviewed shape."""


@dataclass(frozen=True)
class ObservedListener:
    protocol: str
    state: str
    bind_address: str
    port: int
    process_names: tuple[str, ...]


@dataclass(frozen=True)
class ObservedHostSurface:
    identity: DigitalOceanHostIdentityEvidence
    predecessor_ipv4: str
    role: str
    admin_key_sha256: str
    transport_key_sha256: str
    user_key_sha256: frozenset[str]
    sketchssh_key_sha256: frozenset[str]
    listeners: tuple[ObservedListener, ...]
    alternate_keys_absent_observed: bool = False
    observed_context_verified: bool = True
    complete_ssh_policy: bool = False
    publication_eligible: bool = False


_SSHD_BASELINE = {
    "user": "d031579482c4bfbc89bc81d0ae99cf6390e78a8eb501dc473aef1ae8d49bbca1",
    "middle_sketchssh": "baa551f74ffd327fffe02305dcadd7f7b5f39e74aa2f2ae8f66c313f69faa163",
    "edge_sketchssh": "c215803d12a1988ab754c93bc09745f150bd8cacb7d16e3e0743c37b15124f03",
}
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_KEY = re.compile(r"ssh-ed25519 ([A-Za-z0-9+/]+={0,2})(?: [^\r\n]*)?\n\Z")
_TCP_LIFECYCLE_STATES = frozenset({
    "SYN-SENT", "SYN-RECV", "FIN-WAIT-1", "FIN-WAIT-2",
    "CLOSE-WAIT", "CLOSING", "LAST-ACK",
})
_PROCESS = re.compile(r'"([A-Za-z0-9_.-]+)",pid=([1-9][0-9]*),fd=([0-9]+)')


def _require(value: bool, label: str) -> None:
    if not value:
        raise HostSurfaceInterpretationError(label)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_ipv4(value: str) -> str:
    try:
        parsed = ipaddress.IPv4Address(value)
    except (TypeError, ValueError) as exc:
        raise HostSurfaceInterpretationError("predecessor is not IPv4") from exc
    _require(str(parsed) == value and not (parsed.is_unspecified or parsed.is_multicast or parsed.is_loopback),
             "predecessor is not canonical usable IPv4")
    return value


def _key_digest(raw: str) -> str:
    """Fingerprint one bare Ed25519 public key, ignoring its optional comment."""
    _require(type(raw) is str and len(raw.encode("utf-8")) <= 65536, "authorized key content differs")
    match = _KEY.fullmatch(raw)
    _require(match is not None, "authorized key is not exactly one bare Ed25519 key")
    try:
        blob = base64.b64decode(match.group(1), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HostSurfaceInterpretationError("authorized key encoding differs") from exc
    _require(base64.b64encode(blob).decode("ascii") == match.group(1)
             and len(blob) == 51 and blob[:19] == b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20",
             "authorized key blob differs")
    return _sha("ssh-ed25519 " + match.group(1))


def _key_digests(raw: str) -> frozenset[str]:
    _require(type(raw) is str and raw.endswith("\n") and 0 < len(raw.encode("utf-8")) <= 65536,
             "authorized key file differs")
    lines = raw.splitlines(keepends=True)
    _require(1 <= len(lines) <= 32, "authorized key count differs")
    digests = frozenset(_key_digest(line) for line in lines)
    _require(len(digests) == len(lines), "duplicate authorized key")
    return digests


def _accounts(rows: object, admin_digest: str, transport_digest: str) -> tuple[frozenset[str], frozenset[str]]:
    _require(type(rows) is tuple and len(rows) == 2, "account capture coverage differs")
    _require(_HEX64.fullmatch(admin_digest) is not None and _HEX64.fullmatch(transport_digest) is not None
             and admin_digest != transport_digest, "independent key digests differ")
    keys = []
    for row, name, uid, expected in zip(rows, ("user", "sketchssh"), (1000, 1001),
                                         (admin_digest, transport_digest)):
        digests = _key_digests(row[1]) if type(row) is tuple and len(row) == 5 else frozenset()
        _require(type(row) is tuple and len(row) == 5 and row[0] == name
                 and type(row[2]) is int and type(row[3]) is int and row[2] == row[3] == uid
                 and type(row[4]) is int and row[4] == 0o600
                 and expected in digests, "account/key identity differs")
        keys.append(digests)
    _require(transport_digest not in keys[0] and admin_digest not in keys[1],
             "admin and transport keys cross account boundary")
    return keys[0], keys[1]


def _sshd(rows: object, role: str) -> None:
    _require(type(rows) is tuple and len(rows) == 2 and [row[0] for row in rows] == ["user", "sketchssh"],
             "effective sshd context coverage differs")
    for name, raw in rows:
        _require(type(raw) is str and raw.endswith("\n") and len(raw.encode("utf-8")) <= 65536,
                 "effective sshd content differs")
        lines = raw.splitlines()
        _require(all(line and " " in line for line in lines), "effective sshd line differs")
        grouped: dict[str, list[str]] = {}
        for line in lines:
            key, value = line.split(" ", 1)
            grouped.setdefault(key, []).append(value)
        expected = {
            "usedns": "no", "pubkeyauthentication": "yes", "passwordauthentication": "no",
            "kbdinteractiveauthentication": "no", "hostbasedauthentication": "no",
            "gssapiauthentication": "no", "permitemptypasswords": "no", "strictmodes": "yes",
            "authorizedkeysfile": ".ssh/authorized_keys .ssh/authorized_keys2",
            "gatewayports": "yes" if name == "sketchssh" and role == "edge" else "no",
            "allowtcpforwarding": "local" if name == "sketchssh" and role == "middle" else "yes",
            "permitopen": "any", "forcecommand": "none", "disableforwarding": "no",
        }
        _require(all(grouped.get(key) == [value] for key, value in expected.items()),
                 "effective sshd security field differs")
        profile = "user" if name == "user" else role + "_sketchssh"
        _require(_sha(raw) == _SSHD_BASELINE[profile], "pinned observed sshd context differs")


def _endpoint(raw: str, *, local: bool) -> tuple[str, int | None]:
    _require(type(raw) is str and raw, "socket endpoint differs")
    if raw.startswith("["):
        _require("]:" in raw, "IPv6 socket endpoint differs")
        address, port = raw[1:].split("]:", 1)
    else:
        _require(":" in raw, "socket endpoint has no port")
        address, port = raw.rsplit(":", 1)
    if address == "*":
        _require(not local and port == "*", "unexpected wildcard endpoint")
        return address, None
    if "%" in address:
        _require(address == "127.0.0.53%lo", "socket zone differs")
        address = "127.0.0.53"
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise HostSurfaceInterpretationError("socket address differs") from exc
    _require(str(parsed) == address, "socket address is not canonical")
    if port == "*":
        _require(not local, "local socket port is wildcard")
        return address, None
    _require(port.isascii() and port.isdecimal() and str(int(port)) == port
             and 1 <= int(port) <= 65535, "socket port differs")
    return address, int(port)


def _listeners(raw: str, predecessor: str, public_ipv4: str, *, local_dns: bool = True,
               ssh_source_port: int | None = None) -> tuple[ObservedListener, ...]:
    _require(type(raw) is str and raw.endswith("\n") and 0 < len(raw.encode("utf-8")) <= 65536,
             "socket inventory is incomplete")
    observed = []
    categories = []
    for line in raw.splitlines():
        parts = line.split(maxsplit=6)
        if len(parts) == 6 and parts[:4] == ["tcp", "TIME-WAIT", "0", "0"]:
            address, port = _endpoint(parts[4], local=True)
            remote, remote_port = _endpoint(parts[5], local=False)
            _require(port is not None and remote != "*" and remote_port is not None,
                     "TIME-WAIT socket endpoint differs")
            observed.append(ObservedListener("tcp", "TIME-WAIT", address, port, ()))
            continue
        if len(parts) in {6, 7} and parts[0] == "tcp" and parts[1] in _TCP_LIFECYCLE_STATES:
            _require(all(len(value) <= 10 and value.isascii() and value.isdecimal()
                         and str(int(value)) == value and 0 <= int(value) <= 2**32 - 1
                         for value in parts[2:4]), "TCP lifecycle queue differs")
            _require(all(len(value) <= 64 and "%" not in value for value in parts[4:6]),
                     "TCP lifecycle endpoint syntax differs")
            address, port = _endpoint(parts[4], local=True)
            remote, remote_port = _endpoint(parts[5], local=False)
            _require(port is not None and remote_port is not None and remote != "*"
                     and not ipaddress.ip_address(address).is_unspecified
                     and not ipaddress.ip_address(remote).is_unspecified
                     and not ipaddress.ip_address(address).is_multicast
                     and not ipaddress.ip_address(remote).is_multicast
                     and ipaddress.ip_address(address).version == ipaddress.ip_address(remote).version,
                     "TCP lifecycle endpoint differs")
            names = ()
            if len(parts) == 7:
                process_matches = list(_PROCESS.finditer(parts[6]))
                reconstructed = 'users:((' + '),('.join(
                    match.group(0) for match in process_matches) + '))'
                _require(process_matches and parts[6].rstrip(" ") == reconstructed
                         and len({match.groups() for match in process_matches}) == len(process_matches),
                         "TCP lifecycle process attribution differs")
                names = tuple(sorted({match.group(1) for match in process_matches}))
            # Connection attempts and closing sessions are observations only;
            # they never satisfy a listener or established-management category.
            observed.append(ObservedListener("tcp", parts[1], address, port, names))
            continue
        _require(len(parts) == 7 and parts[0] in {"tcp", "udp"}
                 and parts[1] in {"LISTEN", "UNCONN", "ESTAB"}
                 and parts[2].isascii() and parts[2].isdecimal()
                 and parts[3].isascii() and parts[3].isdecimal(), "socket row syntax differs")
        protocol, state = parts[:2]
        address, port = _endpoint(parts[4], local=True)
        remote, remote_port = _endpoint(parts[5], local=False)
        process_matches = list(_PROCESS.finditer(parts[6]))
        matches = [match.groups() for match in process_matches]
        reconstructed = 'users:((' + '),('.join(match.group(0) for match in process_matches) + '))'
        _require(matches and parts[6].rstrip(" ") == reconstructed,
                 "socket process attribution differs")
        names = tuple(sorted({name for name, _pid, _fd in matches}))
        _require(port is not None, "local socket port differs")
        if state == "LISTEN":
            _require(protocol == "tcp" and remote_port is None, "LISTEN socket differs")
            if port == 22 and address in {"0.0.0.0", "::"} and names == ("sshd", "systemd"):
                category = ("ssh", address)
            elif port == 80 and address in {"0.0.0.0", "::"} and names == ("nginx",):
                category = ("nginx_firewall_required", address)
            elif port == 53 and address in {"127.0.0.53", "127.0.0.54"} and names == ("systemd-resolve",):
                category = ("dns", address, "tcp")
            else:
                raise HostSurfaceInterpretationError("unexpected public or local TCP listener")
        elif state == "UNCONN":
            _require(protocol == "udp" and port == 53 and address in {"127.0.0.53", "127.0.0.54"}
                     and remote_port is None and names == ("systemd-resolve",), "unexpected UDP listener")
            category = ("dns", address, "udp")
        else:
            if protocol == "tcp":
                if port != 22 and "sshd" not in names:
                    peer = ipaddress.ip_address(remote) if remote != "*" else None
                    _require(
                        address == public_ipv4 and 1024 <= port <= 65535
                        and remote_port is not None and peer is not None
                        and peer.version == 4 and not peer.is_unspecified
                        and not peer.is_multicast and not peer.is_loopback
                        and remote != "255.255.255.255"
                        and parts[4] == f"{address}:{port}"
                        and parts[5] == f"{remote}:{remote_port}"
                        and all(len(value) <= 10 and str(int(value)) == value
                                and int(value) <= 2**32 - 1 for value in parts[2:4])
                        and len(set(matches)) == len(matches),
                        "established application socket differs")
                    # A permitted connection observation supplies no listener
                    # or management authority, regardless of its process name.
                    observed.append(ObservedListener(protocol, state, address, port, names))
                    continue
                _require(port == 22 and address == public_ipv4 and remote == predecessor
                         and remote_port is not None and names == ("sshd",)
                         and (ssh_source_port is None or remote_port == ssh_source_port),
                         "established management SSH differs")
                category = ("management_session",)
            else:
                _require(port != 53 and address == public_ipv4 and remote_port == 53
                         and names == ("systemd-resolve",), "established resolver socket differs")
                category = ("resolver_session",)
        categories.append(category)
        observed.append(ObservedListener(protocol, state, address, port, names))
    expected_listeners = {("ssh", "0.0.0.0"), ("ssh", "::"),
                           ("nginx_firewall_required", "0.0.0.0"), ("nginx_firewall_required", "::")}
    if local_dns:
        expected_listeners |= {("dns", "127.0.0.53", "tcp"), ("dns", "127.0.0.54", "tcp"),
                               ("dns", "127.0.0.53", "udp"), ("dns", "127.0.0.54", "udp")}
    listening = [category for category in categories if category in expected_listeners]
    _require(len(listening) == len(expected_listeners) and set(listening) == expected_listeners
             and (local_dns or (not any(category[0] in {"dns", "resolver_session"}
                                        for category in categories)
                                and categories.count(("management_session",)) == 1)),
             "complete fresh-host listening socket inventory differs")
    return tuple(observed)


def _complete_ssh_proof(surface: object) -> bool:
    """Old collections remain observed-only; malformed versioned proof fails shut."""
    if surface.ssh_proof_version is None and surface.ssh_proof is None:
        return False
    _require(type(surface.ssh_proof_version) is int and surface.ssh_proof_version == 1
             and type(surface.ssh_proof) is dict,
             "SSH proof version differs")
    proof = surface.ssh_proof
    _require(set(proof) == {"service", "socket", "pid", "start_ticks",
                            "boot_epoch_s", "clock_ticks_per_second", "birth_wall_ns",
                            "cmdline", "exe", "environment_file", "environment_changed_ns",
                            "unit_file", "directory_changed_ns", "configuration"},
             "SSH proof coverage differs")
    service = proof["service"]
    _require(type(service) is dict and set(service) == {
        "MainPID", "ActiveState", "SubState", "ExecStart", "EnvironmentFiles",
        "Environment", "FragmentPath", "DropInPaths"}, "SSH service properties differ")
    _require(service["ActiveState"] == "active" and service["SubState"] == "running"
             and service["DropInPaths"] == "" and service["Environment"] == ""
             and service["FragmentPath"] in {
                 "/usr/lib/systemd/system/ssh.service", "/lib/systemd/system/ssh.service"}
             and service["EnvironmentFiles"] in {
                 "/etc/default/ssh", "/etc/default/ssh (ignore_errors=yes)",
                 "/etc/default/ssh (ignore_errors=no)"},
             "SSH service loading differs")
    pid = proof["pid"]
    _require(type(pid) is int and pid >= 2 and service["MainPID"] == str(pid),
             "SSH service MainPID differs")
    _require(type(proof["start_ticks"]) is int and proof["start_ticks"] > 0,
             "SSH daemon process identity differs")
    boot_epoch_s = proof["boot_epoch_s"]
    clock_ticks_per_second = proof["clock_ticks_per_second"]
    birth_wall_ns = proof["birth_wall_ns"]
    _require(all(type(value) is int and value > 0 for value in (
        boot_epoch_s, clock_ticks_per_second, birth_wall_ns))
        and clock_ticks_per_second <= 10000
        and birth_wall_ns == boot_epoch_s * 1_000_000_000
        + proof["start_ticks"] * 1_000_000_000 // clock_ticks_per_second,
        "SSH daemon birth time differs")
    exec_start = service["ExecStart"]
    _require(type(exec_start) is str and len(exec_start) <= 2048
             and exec_start.count("path=/usr/sbin/sshd") == 1
             and re.search(r"argv\[\]=/usr/sbin/sshd -D \$SSHD_OPTS\s*;", exec_start) is not None
             and exec_start.count("argv[]=") == 1
             and not re.search(r"(?:^|\s)-(?:f|o)(?:\s|$)", exec_start),
             "SSH service ExecStart overrides configuration")
    _require(proof["exe"] == "/usr/sbin/sshd"
             and type(proof["cmdline"]) is list and 1 <= len(proof["cmdline"]) <= 8
             and all(type(arg) is str and len(arg) <= 512 for arg in proof["cmdline"]),
             "SSH daemon executable or command line differs")
    command = " ".join(proof["cmdline"])
    _require(command.startswith(("/usr/sbin/sshd -D", "sshd: /usr/sbin/sshd -D", "sshd -D"))
             and not re.search(r"(?:^|\s)-(?:f|o)(?:\s|$|\S)", command),
             "SSH daemon command line overrides configuration")
    environment_file = proof["environment_file"]
    _require(type(environment_file) is str and len(environment_file) <= 8192,
             "SSH daemon environment input differs")
    active_environment = [line.strip() for line in environment_file.splitlines()
                          if line.strip() and not line.lstrip().startswith("#")]
    _require(active_environment == ["SSHD_OPTS="], "SSH daemon options differ")
    environment_changed_ns = proof["environment_changed_ns"]
    unit_file = proof["unit_file"]
    _require(type(environment_changed_ns) is int and environment_changed_ns > 0
             and type(unit_file) is list and len(unit_file) == 3
             and unit_file[0] == service["FragmentPath"]
             and type(unit_file[1]) is str and 0 < len(unit_file[1].encode("utf-8")) <= 16384
             and type(unit_file[2]) is int and unit_file[2] > 0,
             "SSH unit or environment timestamp differs")
    directories = proof["directory_changed_ns"]
    _require(type(directories) is list and len(directories) == 2
             and [row[0] for row in directories if type(row) is list and len(row) == 2]
             == ["/etc/ssh", "/etc/ssh/sshd_config.d"]
             and all(type(row[1]) is int and row[1] > 0 for row in directories),
             "SSH configuration directory timestamp differs")
    socket = proof["socket"]
    _require(type(socket) is str and len(socket) <= 2048
             and socket.count("ActiveState=active") == 1
             and 1 <= socket.count("Listen=") <= 2
             and all(re.fullmatch(r"Listen=(?:\[::\]|0\.0\.0\.0):22 \(Stream\)", line)
                     for line in socket.splitlines() if line.startswith("Listen=")),
             "SSH socket activation differs")
    files = proof["configuration"]
    _require(type(files) is list and 1 <= len(files) <= 17 and all(
        type(row) is list and len(row) == 3 and type(row[0]) is str
        and type(row[1]) is str and type(row[2]) is int and row[2] > 0
        for row in files), "SSH configuration graph differs")
    _require(files[0][0] == "/etc/ssh/sshd_config"
             and len({row[0] for row in files}) == len(files)
             and [row[0] for row in files[1:]] == sorted(row[0] for row in files[1:]),
             "SSH configuration roots differ")
    includes = []
    total = 0
    for path, raw, changed_ns in files:
        _require(path == "/etc/ssh/sshd_config" or re.fullmatch(
            r"/etc/ssh/sshd_config\.d/[A-Za-z0-9_.-]+\.conf", path) is not None,
            "SSH configuration path differs")
        total += len(raw.encode("utf-8"))
        _require(total <= 131072 and len(raw.encode("utf-8")) <= 65536,
                 "SSH configuration exceeds bound")
        for line in raw.splitlines():
            active = line.split("#", 1)[0].strip()
            if not active:
                continue
            _require("\\" not in active, "SSH continuation is unproved")
            fields = active.split()
            if fields[0].lower() == "include":
                _require(path == "/etc/ssh/sshd_config" and fields == [
                    "Include", "/etc/ssh/sshd_config.d/*.conf"],
                    "SSH Include graph differs")
                includes.append(fields)
            if fields[0].lower() == "match":
                _require(all(field.lower() != "rdomain" for field in fields[1:]),
                         "SSH Match RDomain is unproved")
    _require(len(includes) == 1, "SSH Include root differs")
    latest_input_ns = max(environment_changed_ns, unit_file[2],
                          *(row[2] for row in files), *(row[1] for row in directories))
    _require(birth_wall_ns > latest_input_ns + 2_000_000_000,
             "SSH daemon predates loaded inputs")
    ssh_listeners = []
    for row in surface.listeners_raw.splitlines():
        if " LISTEN " not in row or ":22 " not in row:
            continue
        ssh_listeners.append(row)
    _require(len(ssh_listeners) == 2 and all(
        re.search(r'"sshd",pid=' + str(pid) + r',fd=[0-9]+', row) for row in ssh_listeners),
        "SSH listener is not owned by service MainPID")
    return surface.alternate_authorized_keys_absent == ("user", "sketchssh")


def _interpret_host_surface(
    collection: DigitalOceanRawHostCollection, *, expected_identity: DigitalOceanHostIdentityEvidence,
    expected_predecessor_ipv4: str, expected_role: str,
    expected_admin_key_sha256: str, expected_transport_key_sha256: str,
    expected_policy: Mapping[str, object], local_dns: bool,
) -> ObservedHostSurface:
    """Interpret the captured context and explicit versioned SSH proof."""
    _require(type(collection) is DigitalOceanRawHostCollection
             and type(expected_identity) is DigitalOceanHostIdentityEvidence
             and collection.identity == expected_identity and collection.policy_interpreted is False,
             "raw host identity differs")
    predecessor = _canonical_ipv4(expected_predecessor_ipv4)
    _require(expected_role in {"middle", "edge"} and type(expected_policy) is dict
             and expected_policy == {"sketch_firewall_v2_enabled": True,
                                     "sketch_firewall_v2_ssh_sources": [predecessor + "/32"],
                                     "sketch_firewall_v2_rules": []},
             "reviewed host role/policy differs")
    before, surface, after = collection.firewall_before, collection.surface, collection.firewall_after
    _require(before.identity == surface.identity == after.identity == expected_identity
             and before.boot_id == surface.boot_id == after.boot_id == expected_identity.boot_id
             and before.policy_interpreted is False and surface.policy_interpreted is False
             and after.policy_interpreted is False and surface.predecessor_ipv4 == predecessor
             and len({expected_identity.invocation_id, before.invocation_id, surface.invocation_id,
                      after.invocation_id}) == 4,
             "surface identity/boot/collection binding differs")
    _require(all(type(value) is int and value > 0 for value in (
        before.started_at_ns, before.completed_at_ns, surface.started_at_ns,
        surface.completed_at_ns, after.started_at_ns, after.completed_at_ns))
             and before.started_at_ns <= before.completed_at_ns <= surface.started_at_ns
             <= surface.completed_at_ns <= after.started_at_ns <= after.completed_at_ns
             and after.completed_at_ns - before.started_at_ns <= 300_000_000_000,
             "surface timing differs")
    _require(type(surface.ssh_connection) is tuple and len(surface.ssh_connection) == 4
             and surface.ssh_connection[0] == predecessor
             and type(surface.ssh_connection[1]) is int and 1 <= surface.ssh_connection[1] <= 65535
             and surface.ssh_connection[2] == expected_identity.public_ipv4
             and surface.ssh_connection[3] == 22,
             "SSH_CONNECTION differs")
    user_keys, sketchssh_keys = _accounts(surface.accounts, expected_admin_key_sha256,
                                          expected_transport_key_sha256)
    _sshd(surface.effective_sshd, expected_role)
    listeners = _listeners(surface.listeners_raw, predecessor, expected_identity.public_ipv4,
                           local_dns=local_dns,
                           ssh_source_port=None if local_dns else surface.ssh_connection[1])
    _require(surface.alternate_authorized_keys_absent in ((), ("user", "sketchssh")),
             "alternate authorized-key absence evidence differs")
    complete = _complete_ssh_proof(surface)
    return ObservedHostSurface(expected_identity, predecessor, expected_role,
                               expected_admin_key_sha256, expected_transport_key_sha256,
                               user_keys, sketchssh_keys, listeners,
                               alternate_keys_absent_observed=(
                                   surface.alternate_authorized_keys_absent == ("user", "sketchssh")),
                               complete_ssh_policy=complete,
                               publication_eligible=False)


def interpret_digitalocean_host_surface(
    collection: DigitalOceanRawHostCollection, *, expected_identity: DigitalOceanHostIdentityEvidence,
    expected_predecessor_ipv4: str, expected_role: str,
    expected_admin_key_sha256: str, expected_transport_key_sha256: str,
    expected_policy: Mapping[str, object],
) -> ObservedHostSurface:
    """Interpret the unchanged DigitalOcean surface and SSH proof."""
    return _interpret_host_surface(collection, expected_identity=expected_identity,
                                   expected_predecessor_ipv4=expected_predecessor_ipv4,
                                   expected_role=expected_role,
                                   expected_admin_key_sha256=expected_admin_key_sha256,
                                   expected_transport_key_sha256=expected_transport_key_sha256,
                                   expected_policy=expected_policy, local_dns=True)


def interpret_linode_host_surface(
    collection: LinodeRawHostCollection, *, expected_identity: LinodeRawHostIdentity,
    expected_predecessor_ipv4: str, expected_role: str,
    expected_admin_key_sha256: str, expected_transport_key_sha256: str,
    expected_policy: Mapping[str, object],
) -> ObservedHostSurface:
    """Interpret the fresh Linode surface without granting publication eligibility."""
    _require(type(collection) is LinodeRawHostCollection
             and type(expected_identity) is LinodeRawHostIdentity
             and collection.identity == expected_identity and collection.policy_interpreted is False
             and expected_identity.image == "linode/ubuntu24.04",
             "Linode identity differs")
    raw = collection.raw
    identity = raw.identity
    _require(type(raw) is DigitalOceanRawHostCollection
             and type(identity) is DigitalOceanHostIdentityEvidence
             and (identity.manifest_sha256, identity.chain_id, identity.terraform_address,
                  identity.provider_instance_id, identity.region, identity.public_ipv4,
                  identity.hostname, identity.boot_id, identity.invocation_id,
                  identity.core_known_hosts_sha256, identity.sketch_known_hosts_sha256)
             == (expected_identity.manifest_sha256, expected_identity.chain_id,
                 expected_identity.terraform_address, expected_identity.provider_instance_id,
                 expected_identity.region, expected_identity.public_ipv4, expected_identity.hostname,
                 expected_identity.boot_id, expected_identity.invocation_id,
                 expected_identity.core_known_hosts_sha256, expected_identity.sketch_known_hosts_sha256)
             and type(expected_identity.ssh_connection) is tuple
             and len(expected_identity.ssh_connection) == 4
             and type(expected_identity.ssh_connection[1]) is int
             and 1 <= expected_identity.ssh_connection[1] <= 65535
             and type(raw.surface.ssh_connection) is tuple
             and len(raw.surface.ssh_connection) == 4
             and raw.surface.ssh_connection[0] == expected_identity.ssh_connection[0]
             and raw.surface.ssh_connection[2:] == expected_identity.ssh_connection[2:],
             "Linode raw evidence binding differs")
    observed = _interpret_host_surface(raw, expected_identity=identity,
                                       expected_predecessor_ipv4=expected_predecessor_ipv4,
                                       expected_role=expected_role,
                                       expected_admin_key_sha256=expected_admin_key_sha256,
                                       expected_transport_key_sha256=expected_transport_key_sha256,
                                       expected_policy=expected_policy, local_dns=False)
    _require(observed.complete_ssh_policy, "Linode complete SSH proof is absent")
    return observed
