# Copyright (c) 2026, Oracle and/or its affiliates.
"""Render the Barragan-owned post-deploy sketch bootstrap.

Redteam-infra's Terraform interface remains intentionally legacy: it installs
one initial administration key.  This module renders the *following* handoff
without embedding any key material: the administration key is authorized for
the normal ``user`` account and the independent transport key is authorized
only for ``sketchssh``.

The renderer is deliberately side-effect free.  Its caller owns creating the
workspace, materializing the referenced key files, invoking Ansible, recording
readiness, and removing temporary material.  Crucially, phase one invokes the
configured upstream ``sketch-playbook.yml``; Barragan does not maintain a partial
copy of that host-baseline playbook.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Mapping


_HOST_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_HOST_OR_IP = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]*$")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_KNOWN_HOSTS_PATH = re.compile(r"/[A-Za-z0-9._/-]+\Z")

ROOT_PLAYBOOK_COMMAND = (
    "ansible-playbook -f 1 -i ansible/inventory.ini ansible/bootstrap_sketch_root.yml"
)
READINESS_PLAYBOOK_COMMAND = (
    "ansible-playbook -f 1 -i ansible/inventory.ini ansible/wait_for_sketch_readiness.yml"
)
TRANSPORT_PLAYBOOK_COMMAND = (
    "ansible-playbook -f 1 -i ansible/inventory.ini ansible/install_sketch_transport.yml"
)


class SketchBootstrapValidationError(ValueError):
    """Raised when a bootstrap artifact would be unsafe or incomplete."""

    def __init__(self, errors: list[str]):
        super().__init__("sketch bootstrap workspace validation failed")
        self.errors = errors


@dataclass(frozen=True)
class SketchBootstrapCoreHost:
    """A core management hop used by the local Ansible controller."""

    name: str
    host: str
    user: str
    ssh_private_key_path: str
    host_key_alias: str = ""


@dataclass(frozen=True)
class SketchBootstrapNode:
    """A sketch middle or edge node.

    ``public_ip`` is reached from its preceding sketch hop; it is never a
    controller-side destination.  ``private_ip`` is retained in the rendered
    manifest as topology evidence for the caller, but is intentionally not
    published to sketch hosts.
    """

    name: str
    public_ip: str
    private_ip: str = ""


@dataclass(frozen=True)
class SketchBootstrapSpec:
    homebase: SketchBootstrapCoreHost
    proxy: SketchBootstrapCoreHost
    middle: SketchBootstrapNode
    edges: tuple[SketchBootstrapNode, ...]
    admin_private_key_path: str
    admin_public_key_path: str
    transport_public_key_path: str
    ssh_config_path: str
    upstream_root_playbook_path: str
    host_policies: Mapping[str, Mapping[str, object]] | None = None
    proxy_egress_ip: str = ""
    initial_sketch_known_hosts_path: str = ""
    pinned_core_known_hosts_path: str = ""


@dataclass(frozen=True)
class RenderedSketchBootstrapArtifact:
    target: str
    content: str

    def to_dict(self) -> dict[str, str]:
        return {"target": self.target, "content": self.content}


@dataclass(frozen=True)
class SketchBootstrapExecution:
    readiness_command: tuple[str, ...]
    root_command: tuple[str, ...]
    user_readiness_command: tuple[str, ...]
    transport_command: tuple[str, ...]

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "readinessCommand": list(self.readiness_command),
            "rootCommand": list(self.root_command),
            "userReadinessCommand": list(self.user_readiness_command),
            "transportCommand": list(self.transport_command),
        }


@dataclass(frozen=True)
class SketchBootstrapWorkspace:
    inventory: RenderedSketchBootstrapArtifact
    user_inventory: RenderedSketchBootstrapArtifact
    ssh_config: RenderedSketchBootstrapArtifact
    readiness_playbook: RenderedSketchBootstrapArtifact
    user_readiness_playbook: RenderedSketchBootstrapArtifact
    root_variables: RenderedSketchBootstrapArtifact
    transport_playbook: RenderedSketchBootstrapArtifact
    manifest: RenderedSketchBootstrapArtifact
    execution: SketchBootstrapExecution
    host_vars: tuple[RenderedSketchBootstrapArtifact, ...] = ()

    def to_dict(self) -> dict[str, object]:
        result = {
            "status": "Pending Sketch Bootstrap",
            "mutation": False,
            "inventory": self.inventory.to_dict(),
            "userInventory": self.user_inventory.to_dict(),
            "sshConfig": self.ssh_config.to_dict(),
            "readinessPlaybook": self.readiness_playbook.to_dict(),
            "userReadinessPlaybook": self.user_readiness_playbook.to_dict(),
            "rootVariables": self.root_variables.to_dict(),
            "transportPlaybook": self.transport_playbook.to_dict(),
            "manifest": self.manifest.to_dict(),
            "execution": self.execution.to_dict(),
        }
        if self.host_vars:
            result["hostVars"] = [artifact.to_dict() for artifact in self.host_vars]
        return result


def render_sketch_bootstrap_workspace(spec: SketchBootstrapSpec) -> SketchBootstrapWorkspace:
    """Return controller-ready artifacts for the two-phase sketch handoff.

    Root is deliberately limited to the first play.  The second play connects
    as ``user`` and becomes root only for the restricted ``sketchssh`` account
    file operations.
    """

    _validate_spec(spec)
    workspace = SketchBootstrapWorkspace(
        inventory=RenderedSketchBootstrapArtifact("ansible/inventory.ini", _render_inventory(spec, user="root")),
        user_inventory=RenderedSketchBootstrapArtifact(
            "ansible/user_inventory.ini", _render_inventory(spec, user="user")
        ),
        ssh_config=RenderedSketchBootstrapArtifact("ansible/ssh_config", _render_ssh_config(spec)),
        readiness_playbook=RenderedSketchBootstrapArtifact(
            "ansible/wait_for_sketch_readiness.yml", _render_readiness_playbook()
        ),
        user_readiness_playbook=RenderedSketchBootstrapArtifact(
            "ansible/wait_for_sketch_user_readiness.yml", _render_user_readiness_playbook()
        ),
        root_variables=RenderedSketchBootstrapArtifact(
            "ansible/upstream-bootstrap-vars.yml", _render_root_variables(spec)
        ),
        transport_playbook=RenderedSketchBootstrapArtifact(
            "ansible/install_sketch_transport.yml", _render_transport_playbook(spec)
        ),
        manifest=RenderedSketchBootstrapArtifact("MANIFEST.json", _render_manifest(spec)),
        execution=SketchBootstrapExecution(
            readiness_command=(
                "ansible-playbook",
                "-f",
                "1",
                "-i",
                "ansible/inventory.ini",
                "ansible/wait_for_sketch_readiness.yml",
            ),
            root_command=(
                "ansible-playbook",
                "-f",
                "1",
                "-i",
                "ansible/inventory.ini",
                spec.upstream_root_playbook_path,
                "-e",
                "@ansible/upstream-bootstrap-vars.yml",
            ),
            user_readiness_command=(
                "ansible-playbook",
                "-f",
                "1",
                "-i",
                "ansible/user_inventory.ini",
                "ansible/wait_for_sketch_user_readiness.yml",
            ),
            transport_command=(
                "ansible-playbook",
                "-f",
                "1",
                "-i",
                "ansible/user_inventory.ini",
                "ansible/install_sketch_transport.yml",
            ),
        ),
        host_vars=_render_host_vars(spec),
    )
    _assert_no_private_key_material(workspace)
    return workspace


def render_strict_v2_sketch_identity_ssh_config(spec: SketchBootstrapSpec) -> str:
    """Render only the pinned user-route SSH config for read-only host proof.

    Bootstrap enrollment keeps accept-new for first contact. This separate
    proof mode requires both preexisting trust files and never enrolls a key.
    """
    _validate_spec(spec)
    if (spec.host_policies is None or not spec.initial_sketch_known_hosts_path
            or not spec.pinned_core_known_hosts_path):
        raise SketchBootstrapValidationError(["strict v2 proof requires separate pinned trust files"])
    return _render_ssh_config(spec, strict_sketch_host_keys=True)


def _render_inventory(spec: SketchBootstrapSpec, *, user: str) -> str:
    alias = _root_alias if user == "root" else _user_alias
    inventory_lines = [_inventory_line(node, alias(node), user=user) for node in _sketch_nodes(spec)]
    return "\n".join(
        [
            "# Managed by Barragan: upstream-compatible sketch bootstrap.",
            "# SSH aliases in ansible/ssh_config force homebase -> proxy -> middle -> edge.",
            "[sketch]",
            *inventory_lines,
            "",
            # The connection settings must belong to the declared sketch group.
            # An undefined ``[group:vars]`` is only a warning in some Ansible
            # versions, but it discards the SSH config and turns our aliases
            # into accidental DNS destinations.
            "[sketch:vars]",
            ("ansible_ssh_common_args='-F ansible/ssh_config -o IdentitiesOnly=yes -o BatchMode=yes "
             + (f"-o UserKnownHostsFile={spec.initial_sketch_known_hosts_path} "
                if spec.initial_sketch_known_hosts_path else "")
             + "-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15'"),
            "",
        ]
    )


def _render_readiness_playbook() -> str:
    """Probe every required hop before allowing any upstream mutation.

    ``any_errors_fatal`` is intentional: an upstream sketch play assumes facts
    from every node.  A transient unavailable edge is a waiting condition, not
    permission to begin a partial root bootstrap on the reachable middle.
    """

    return "\n".join(
        [
            "---",
            "- name: Wait for serial sketch management readiness",
            "  hosts: sketch",
            "  serial: 1",
            "  any_errors_fatal: true",
            "  gather_facts: false",
            "  tasks:",
            "    - name: Verify the approved sketch SSH hop path",
            "      ansible.builtin.wait_for_connection:",
            "        timeout: 45",
            "",
        ]
    )


def _render_user_readiness_playbook() -> str:
    """Verify the upstream root play created every normal admin identity."""

    return "\n".join(
        [
            "---",
            "- name: Verify serial post-root sketch user readiness",
            "  hosts: sketch",
            "  serial: 1",
            "  any_errors_fatal: true",
            "  gather_facts: false",
            "  tasks:",
            "    - name: Verify the upstream root-to-user identity handoff",
            "      ansible.builtin.wait_for_connection:",
            "        timeout: 45",
            "",
        ]
    )


def _render_ssh_config(spec: SketchBootstrapSpec, *, strict_sketch_host_keys: bool = False) -> str:
    homebase = _core_alias("homebase")
    proxy = _core_alias("proxy")
    enrollment = bool(spec.initial_sketch_known_hosts_path)
    core_known_hosts = spec.pinned_core_known_hosts_path if enrollment else ""
    sketch_known_hosts = spec.initial_sketch_known_hosts_path if enrollment else ""
    lines = [
        "# Managed by Barragan.  Key paths are references only; key contents are never rendered.",
        *_ssh_host_block(
            homebase,
            spec.homebase.host,
            spec.homebase.user,
            spec.homebase.ssh_private_key_path,
            known_hosts_path=core_known_hosts,
            strict_host_key_checking="yes" if enrollment else "no",
            disable_multiplexing=spec.host_policies is not None,
        ),
        "",
        *_ssh_host_block(
            proxy,
            spec.proxy.host,
            spec.proxy.user,
            spec.proxy.ssh_private_key_path,
            proxy_jump=homebase,
            known_hosts_path=core_known_hosts,
            strict_host_key_checking="yes" if enrollment else "no",
            host_key_alias=spec.proxy.host_key_alias if enrollment else "",
            disable_multiplexing=spec.host_policies is not None,
        ),
        "",
    ]
    for node in _sketch_nodes(spec):
        is_middle = node == spec.middle
        root_jump = proxy if is_middle else f"{proxy},{_root_alias(spec.middle)}"
        user_jump = proxy if is_middle else f"{proxy},{_user_alias(spec.middle)}"
        lines.extend(
            [
                *_ssh_host_block(
                    _root_alias(node),
                    node.public_ip,
                    "root",
                    spec.admin_private_key_path,
                    proxy_jump=root_jump,
                    known_hosts_path=sketch_known_hosts,
                    strict_host_key_checking="yes" if strict_sketch_host_keys else (
                        "accept-new" if enrollment else "no"),
                    host_key_alias=_sketch_known_hosts_alias(node) if enrollment else "",
                    disable_multiplexing=spec.host_policies is not None,
                ),
                "",
                *_ssh_host_block(
                    _user_alias(node),
                    node.public_ip,
                    "user",
                    spec.admin_private_key_path,
                    proxy_jump=user_jump,
                    known_hosts_path=sketch_known_hosts,
                    strict_host_key_checking="yes" if strict_sketch_host_keys else (
                        "accept-new" if enrollment else "no"),
                    host_key_alias=_sketch_known_hosts_alias(node) if enrollment else "",
                    disable_multiplexing=spec.host_policies is not None,
                ),
                "",
            ]
        )
    return "\n".join(lines)


def _ssh_host_block(alias: str, host: str, user: str, identity_file: str, *, proxy_jump: str = "",
                    known_hosts_path: str = "", strict_host_key_checking: str = "no",
                    host_key_alias: str = "", disable_multiplexing: bool = False) -> list[str]:
    # ``ProxyJump`` starts independent local SSH clients.  Command-line
    # options passed by Ansible apply only to its final SSH client, not to
    # those intermediate clients.  Keep the guarded non-interactive policy on
    # every host stanza so homebase -> proxy -> sketch works when Barragan has
    # no TTY (and does not pause on a host-key prompt halfway through a chain).
    lines = [
        f"Host {alias}",
        f"  HostName {host}",
        f"  User {user}",
        f"  IdentityFile {identity_file}",
        "  IdentitiesOnly yes",
        f"  UserKnownHostsFile {known_hosts_path or '/dev/null'}",
        f"  StrictHostKeyChecking {strict_host_key_checking}",
        "  BatchMode yes",
        "  ConnectTimeout 15",
    ]
    if disable_multiplexing:
        lines.extend(("  ControlMaster no", "  ControlPersist no"))
    if proxy_jump:
        lines.append(f"  ProxyJump {proxy_jump}")
    if host_key_alias:
        lines.append(f"  HostKeyAlias {host_key_alias}")
    return lines


def _render_root_variables(spec: SketchBootstrapSpec) -> str:
    return "\n".join(
        [
            "---",
            "# Inputs for the configured upstream external/sketch/ansible/sketch-playbook.yml.",
            f"ssh_pub_key: {spec.admin_public_key_path}",
            f"ssh_config_path: {spec.ssh_config_path}",
            "",
        ]
    )


def _render_transport_playbook(spec: SketchBootstrapSpec) -> str:
    return "\n".join(
        [
            "---",
            "# Post-bootstrap phase: connects as user, then becomes root only for sketchssh key installation.",
            "- name: Install independent sketch transport identity",
            "  hosts: sketch",
            *(["  serial: 1"] if spec.host_policies is not None else []),
            "  gather_facts: false",
            "  remote_user: user",
            "  become: true",
            "  vars:",
            "    # Inventory keeps root for the upstream phase; this higher-precedence",
            "    # play variable is the explicit post-bootstrap SSH handoff.",
            "    ansible_user: user",
            f"    bootstrap_transport_public_key_path: {spec.transport_public_key_path}",
            "  tasks:",
            "    - name: Ensure sketch transport SSH directory has restrictive permissions",
            "      ansible.builtin.file:",
            "        path: /home/sketchssh/.ssh",
            "        state: directory",
            "        owner: sketchssh",
            "        group: sketchssh",
            "        mode: '0700'",
            "    - name: Authorize only the managed transport key without removing other keys",
            "      ansible.builtin.lineinfile:",
            "        path: /home/sketchssh/.ssh/authorized_keys",
            "        line: \"{{ lookup('ansible.builtin.file', bootstrap_transport_public_key_path) | trim }}\"",
            "        create: true",
            "        owner: sketchssh",
            "        group: sketchssh",
            "        mode: '0600'",
            "        state: present",
            "    - name: Ensure OpenSSH drop-in directory exists for Barragan transport policy",
            "      ansible.builtin.file:",
            "        path: /etc/ssh/sshd_config.d",
            "        state: directory",
            "        owner: root",
            "        group: root",
            "        mode: '0755'",
            "    - name: Configure middle sketchssh forwarding for proxy jump",
            "      ansible.builtin.copy:",
            "        dest: /etc/ssh/sshd_config.d/90-barragan-sketch-forwarding.conf",
            "        owner: root",
            "        group: root",
            "        mode: '0644'",
            "        content: |",
            "          # Managed by Barragan after the upstream sketch baseline.",
            "          # Middle nodes carry only the internal direct-tcpip hop to an edge.",
            "          Match User sketchssh",
            "            AllowTcpForwarding local",
            "            GatewayPorts no",
            f"      when: inventory_hostname == {json.dumps(spec.middle.name)}",
            "    - name: Configure edge sketchssh forwarding for SOCKS and reverse listeners",
            "      ansible.builtin.copy:",
            "        dest: /etc/ssh/sshd_config.d/90-barragan-sketch-forwarding.conf",
            "        owner: root",
            "        group: root",
            "        mode: '0644'",
            "        content: |",
            "          # Managed by Barragan after the upstream sketch baseline.",
            "          # Edges serve proxy SOCKS local forwarding and Backflips remote forwarding.",
            "          Match User sketchssh",
            "            AllowTcpForwarding yes",
            "            GatewayPorts yes",
            f"      when: inventory_hostname != {json.dumps(spec.middle.name)}",
            "    - name: Ensure OpenSSH privilege-separation runtime directory exists",
            "      ansible.builtin.file:",
            "        path: /run/sshd",
            "        state: directory",
            "        owner: root",
            "        group: root",
            "        mode: '0755'",
            "    - name: Validate Barragan sketch SSH forwarding policy",
            "      ansible.builtin.command: /usr/sbin/sshd -t",
            "      changed_when: false",
            *([
                "    - name: Allow SSH policy file timestamps to precede daemon birth",
                "      ansible.builtin.pause:",
                "        seconds: 3",
                "    - name: Restart SSH with the verified sketch forwarding policy",
            ] if spec.host_policies is not None else [
                "    - name: Reload SSH after Barragan sketch forwarding policy",
            ]),
            "      ansible.builtin.service:",
            "        name: ssh",
            f"        state: {'restarted' if spec.host_policies is not None else 'reloaded'}",
            *([
                "    - name: Drop the pre-restart SSH control connection",
                "      ansible.builtin.meta: reset_connection",
                "    - name: Verify SSH over the selected management route after restart",
                "      ansible.builtin.wait_for_connection:",
                "        connect_timeout: 5",
                "        sleep: 3",
                "        timeout: 60",
            ] if spec.host_policies is not None else []),
            "",
        ]
    )


def _render_manifest(spec: SketchBootstrapSpec) -> str:
    return json.dumps(
        {
            "schemaVersion": 1,
            "purpose": "upstream-compatible sketch identity bootstrap",
            "managementPath": ["homebase", "proxy", "middle", "edge"],
            "rootPhase": {"account": "root", "scope": "configured upstream sketch-playbook only"},
            "upstreamRootPlaybook": spec.upstream_root_playbook_path,
            "postBootstrapAdministration": {"account": "user", "keyPath": spec.admin_private_key_path},
            "transport": {"account": "sketchssh", "publicKeyPath": spec.transport_public_key_path},
            "nodes": [
                {"name": node.name, "role": "middle" if node == spec.middle else "edge", "privateIp": node.private_ip}
                for node in _sketch_nodes(spec)
            ],
        },
        indent=2,
        sort_keys=True,
    ) + "\n"


def _inventory_line(node: SketchBootstrapNode, alias: str, *, user: str = "root") -> str:
    return f"{node.name} ansible_host={alias} ansible_user={user}"


def _sketch_nodes(spec: SketchBootstrapSpec) -> tuple[SketchBootstrapNode, ...]:
    return (spec.middle, *spec.edges)


def _render_host_vars(spec: SketchBootstrapSpec) -> tuple[RenderedSketchBootstrapArtifact, ...]:
    if spec.host_policies is None:
        return ()
    return tuple(
        RenderedSketchBootstrapArtifact(
            f"ansible/host_vars/{node.name}.json",
            json.dumps(spec.host_policies[node.name], sort_keys=True, indent=2) + "\n",
        )
        for node in _sketch_nodes(spec)
    )


def _core_alias(role: str) -> str:
    return f"barragan-bootstrap-{role}"


def _root_alias(node: SketchBootstrapNode) -> str:
    return f"barragan-bootstrap-root-{node.name}"


def _user_alias(node: SketchBootstrapNode) -> str:
    return f"barragan-bootstrap-user-{node.name}"


def _sketch_known_hosts_alias(node: SketchBootstrapNode) -> str:
    return f"barragan-bootstrap-sketch-{node.name}"


def _validate_spec(spec: SketchBootstrapSpec) -> None:
    errors: list[str] = []
    for role, host in (("homebase", spec.homebase), ("proxy", spec.proxy)):
        if host.name != role:
            errors.append(f"{role} host name must equal {role}")
        if not _safe_host(host.host):
            errors.append(f"{role} host is invalid")
        if not _safe_name(host.user):
            errors.append(f"{role} SSH user is invalid")
        if not _safe_path(host.ssh_private_key_path):
            errors.append(f"{role} SSH private key path is invalid")
        if host.host_key_alias and not _safe_public_ipv4(host.host_key_alias):
            errors.append(f"{role} host-key alias is invalid")
    nodes = _sketch_nodes(spec)
    if not spec.edges:
        errors.append("at least one edge is required")
    names = [node.name for node in nodes]
    if len(set(names)) != len(names):
        errors.append("sketch node names must be unique")
    for node in nodes:
        if not _safe_name(node.name):
            errors.append(f"sketch node name is invalid: {node.name!r}")
        if not _safe_ip(node.public_ip):
            errors.append(f"sketch node public IP is invalid: {node.name}")
        if node.private_ip and not _safe_ip(node.private_ip):
            errors.append(f"sketch node private IP is invalid: {node.name}")
    for label, path in (
        ("administration private key", spec.admin_private_key_path),
        ("administration public key", spec.admin_public_key_path),
        ("transport public key", spec.transport_public_key_path),
        ("bootstrap SSH config", spec.ssh_config_path),
        ("upstream sketch playbook", spec.upstream_root_playbook_path),
    ):
        if not _safe_path(path):
            errors.append(f"{label} path is invalid")
    if spec.host_policies is not None:
        errors.extend(_validate_host_policies(spec))
    enrollment = bool(spec.initial_sketch_known_hosts_path or spec.pinned_core_known_hosts_path)
    if enrollment and (spec.host_policies is None
                       or not spec.initial_sketch_known_hosts_path
                       or not spec.pinned_core_known_hosts_path
                       or spec.initial_sketch_known_hosts_path == spec.pinned_core_known_hosts_path
                       or not _safe_known_hosts_path(spec.initial_sketch_known_hosts_path)
                       or not _safe_known_hosts_path(spec.pinned_core_known_hosts_path)):
        errors.append("v2 known-hosts enrollment requires separate safe Sketch and core files")
    if enrollment and (spec.homebase.host_key_alias or not spec.proxy.host_key_alias):
        errors.append("v2 proxy requires its pinned public-IP host-key alias")
    if errors:
        raise SketchBootstrapValidationError(errors)


def _validate_host_policies(spec: SketchBootstrapSpec) -> list[str]:
    errors: list[str] = []
    policies = spec.host_policies
    nodes = _sketch_nodes(spec)
    if not isinstance(policies, Mapping) or set(policies) != {node.name for node in nodes}:
        return ["v2 host policy must cover exactly the inventory nodes"]
    if not _usable_ipv4(spec.proxy_egress_ip):
        return ["v2 host policy requires the proxy egress IPv4 address"]
    if any(not _usable_ipv4(node.public_ip) for node in nodes):
        return ["v2 host policy requires usable sketch public IPv4 addresses"]
    for node in nodes:
        policy = policies[node.name]
        if not isinstance(policy, Mapping) or set(policy) != {
            "sketch_firewall_v2_enabled", "sketch_firewall_v2_ssh_sources", "sketch_firewall_v2_rules",
        } or policy.get("sketch_firewall_v2_enabled") is not True:
            errors.append(f"v2 host policy is incomplete: {node.name}")
            continue
        sources = policy.get("sketch_firewall_v2_ssh_sources")
        predecessor = spec.proxy_egress_ip if node == spec.middle else spec.middle.public_ip
        if sources != [f"{predecessor}/32"]:
            errors.append(f"v2 SSH predecessor is invalid: {node.name}")
        rules = policy.get("sketch_firewall_v2_rules")
        if not isinstance(rules, list):
            errors.append(f"v2 route rules are invalid: {node.name}")
            continue
        for rule in rules:
            if not isinstance(rule, Mapping) or set(rule) != {"from_ip", "port", "proto"}:
                errors.append(f"v2 route rule shape is invalid: {node.name}")
                continue
            if not isinstance(rule["from_ip"], str):
                errors.append(f"v2 route source is invalid: {node.name}")
                continue
            try:
                source = ipaddress.ip_network(rule["from_ip"], strict=True)
            except (TypeError, ValueError):
                errors.append(f"v2 route source is invalid: {node.name}")
                continue
            if (source.version != 4 or type(rule["port"]) is not int
                    or not 1 <= rule["port"] <= 65535 or rule["port"] == 22
                    or not isinstance(rule["proto"], str)
                    or rule["proto"] not in ("tcp", "udp")):
                errors.append(f"v2 route rule is invalid: {node.name}")
    return errors


def _usable_ipv4(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (address.version == 4 and not address.is_unspecified
            and not address.is_loopback and not address.is_multicast)


def _safe_name(value: str) -> bool:
    return bool(_HOST_NAME.fullmatch(value))


def _safe_host(value: str) -> bool:
    return bool(_HOST_OR_IP.fullmatch(value)) and not _CONTROL_CHARS.search(value)


def _safe_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _safe_public_ipv4(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return isinstance(address, ipaddress.IPv4Address) and address.is_global


def _safe_path(value: str) -> bool:
    if not value or _CONTROL_CHARS.search(value) or any(char.isspace() for char in value):
        return False
    path = PurePosixPath(value)
    return path.is_absolute() and ".." not in path.parts


def _safe_known_hosts_path(value: str) -> bool:
    return isinstance(value, str) and bool(_KNOWN_HOSTS_PATH.fullmatch(value)) and _safe_path(value)


def _assert_no_private_key_material(workspace: SketchBootstrapWorkspace) -> None:
    rendered = "\n".join(
        artifact.content
        for artifact in (
            workspace.inventory,
            workspace.user_inventory,
            workspace.ssh_config,
            workspace.readiness_playbook,
            workspace.user_readiness_playbook,
            workspace.root_variables,
            workspace.transport_playbook,
            workspace.manifest,
            *workspace.host_vars,
        )
    )
    for marker in (
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "BEGIN PRIVATE KEY",
    ):
        if marker in rendered:
            raise SketchBootstrapValidationError(["private key material must not be rendered"])
