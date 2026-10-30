# Copyright (c) 2026, Oracle and/or its affiliates.
"""Pure consistency check for structured Sketch host-isolation evidence.

The caller must collect complete, current host evidence through the approved
management path. This module has no collector or remote execution and does
not establish that an observation came from a live host.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal, Sequence

from app.services.provider_keyed_chain_projection import ProjectedProviderKeyedChain


_FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")


class ProviderKeyedHostProofError(ValueError):
    """Structured evidence does not prove the projected host boundary."""


@dataclass(frozen=True)
class UfwRule:
    action: Literal["allow", "deny"]
    direction: Literal["in", "out", "routed"]
    protocol: Literal["tcp", "udp"]
    port: int
    source_cidr: str


@dataclass(frozen=True)
class UfwSnapshot:
    enabled: bool
    default_incoming: str
    default_routed: str
    default_outgoing: str
    rules: tuple[UfwRule, ...]
    complete: bool
    ipv6_enabled: bool
    ipv6_default_incoming: str
    ipv6_default_routed: str
    ipv6_rules: tuple[UfwRule, ...]
    ipv6_complete: bool


@dataclass(frozen=True)
class SshAccountEvidence:
    account: str
    authorized_key_sha256: frozenset[str]
    password_authentication: bool
    allow_tcp_forwarding: str
    gateway_ports: str
    complete: bool


@dataclass(frozen=True)
class ListenerEvidence:
    protocol: Literal["tcp", "udp"]
    bind_address: str
    port: int
    process: str


@dataclass(frozen=True)
class HostObservation:
    hostname: str
    terraform_address: str
    provider_instance_id: str
    public_ipv4: str
    ufw_active: UfwSnapshot
    ufw_persisted: UfwSnapshot
    ssh_accounts: tuple[SshAccountEvidence, ...]
    listeners: tuple[ListenerEvidence, ...]
    listeners_complete: bool


@dataclass(frozen=True)
class HostEvidenceValidation:
    """Validated structured observations; collection provenance is external."""

    hostnames: tuple[str, ...]
    provider_instance_ids: tuple[str, ...]


def verify_projected_host_evidence(
    projected_chains: Sequence[ProjectedProviderKeyedChain],
    observations: Sequence[HostObservation],
    *,
    admin_key_sha256: str,
    transport_key_sha256: str,
) -> HostEvidenceValidation:
    """Reject incomplete, widened, or inconsistent active/persisted host state."""
    try:
        if (not isinstance(projected_chains, Sequence) or len(projected_chains) != 2
                or any(not isinstance(item, ProjectedProviderKeyedChain) for item in projected_chains)
                or not isinstance(observations, Sequence)
                or any(not isinstance(item, HostObservation) for item in observations)
                or not isinstance(admin_key_sha256, str) or not _FINGERPRINT.fullmatch(admin_key_sha256)
                or not isinstance(transport_key_sha256, str) or not _FINGERPRINT.fullmatch(transport_key_sha256)
                or admin_key_sha256 == transport_key_sha256):
            raise ValueError("host proof input differs")
        expected: dict[str, tuple[dict, dict, str]] = {}
        all_node_ips: set[str] = set()
        for projection in projected_chains:
            rows = projection.chain.nodes
            if (projection.chain.status != "pending" or not rows
                    or len([row for row in rows if row.get("role") == "middle"]) != 1
                    or len([row for row in rows if row.get("role") == "edge"]) != len(rows) - 1
                    or set(projection.host_policies) != {row.get("hostname") for row in rows}):
                raise ValueError("projected host set differs")
            middle = next(row for row in rows if row["role"] == "middle")
            for row in rows:
                name = row.get("hostname")
                if (not isinstance(name, str) or not name or name in expected
                        or row.get("chainId") != projection.chain.chain_id
                        or row.get("assignedProxy") != projection.chain.assigned_proxy
                        or row.get("proxy") != projection.chain.assigned_proxy
                        or row.get("publicIp") in all_node_ips
                        or not row.get("providerInstanceId") or not row.get("terraformAddress")):
                    raise ValueError("projected node identity repeats or differs")
                all_node_ips.add(row["publicIp"])
                predecessor = projection.proxy_egress_ip if row["role"] == "middle" else middle["publicIp"]
                expected[name] = (row, projection.host_policies[name], predecessor)
        by_name = {observation.hostname: observation for observation in observations}
        if len(by_name) != len(observations) or set(by_name) != set(expected):
            raise ValueError("host observation coverage differs")
        if len({observation.provider_instance_id for observation in observations}) != len(observations):
            raise ValueError("host provider identity repeats")
        for name, (row, policy, predecessor) in expected.items():
            observation = by_name[name]
            if (observation.terraform_address != row["terraformAddress"]
                    or observation.provider_instance_id != row["providerInstanceId"]
                    or observation.public_ipv4 != row["publicIp"]):
                raise ValueError("host observation identity differs")
            expected_rules = _expected_rules(policy, predecessor)
            _check_ufw(observation.ufw_active, observation.ufw_persisted, expected_rules)
            _check_ssh(observation.ssh_accounts, row["role"], admin_key_sha256, transport_key_sha256)
            _check_listeners(observation.listeners, observation.listeners_complete, row["publicIp"])
        return HostEvidenceValidation(
            tuple(sorted(expected)),
            tuple(by_name[name].provider_instance_id for name in sorted(expected)),
        )
    except Exception:
        raise ProviderKeyedHostProofError("projected host evidence is incomplete or differs") from None


def _expected_rules(policy: dict, predecessor: str) -> frozenset[UfwRule]:
    if (not isinstance(policy, dict)
            or set(policy) != {"sketch_firewall_v2_enabled", "sketch_firewall_v2_ssh_sources",
                               "sketch_firewall_v2_rules"}
            or policy["sketch_firewall_v2_enabled"] is not True
            or policy["sketch_firewall_v2_ssh_sources"] != [f"{predecessor}/32"]
            or not isinstance(policy["sketch_firewall_v2_rules"], list)):
        raise ValueError("projected SSH predecessor policy differs")
    rules = {UfwRule("allow", "in", "tcp", 22, f"{predecessor}/32")}
    for route in policy["sketch_firewall_v2_rules"]:
        if (not isinstance(route, dict) or set(route) != {"from_ip", "port", "proto"}
                or type(route["port"]) is not int or not 1 <= route["port"] <= 65535
                or route["port"] == 22 or route["proto"] not in ("tcp", "udp")):
            raise ValueError("projected route rule differs")
        rules.add(UfwRule("allow", "in", route["proto"], route["port"], route["from_ip"]))
    if len(rules) != 1 + len(policy["sketch_firewall_v2_rules"]):
        raise ValueError("projected route rule repeats")
    for rule in rules:
        _check_rule(rule)
    return frozenset(rules)


def _check_ufw(active: UfwSnapshot, persisted: UfwSnapshot, expected: frozenset[UfwRule]) -> None:
    if (not isinstance(active, UfwSnapshot) or not isinstance(persisted, UfwSnapshot)
            or active != persisted or active.complete is not True or active.enabled is not True
            or (active.default_incoming, active.default_routed, active.default_outgoing)
            != ("deny", "deny", "allow")
            or active.ipv6_enabled is not True
            or (active.ipv6_default_incoming, active.ipv6_default_routed) != ("deny", "deny")
            or active.ipv6_complete is not True or active.ipv6_rules != ()
            or not isinstance(active.rules, tuple)
            or any(not isinstance(rule, UfwRule) for rule in active.rules)
            or len(set(active.rules)) != len(active.rules)):
        raise ValueError("active and persisted UFW state differs")
    for rule in active.rules:
        _check_rule(rule)
    if frozenset(active.rules) != expected:
        raise ValueError("host UFW rules differ from exact projected rules")


def _check_rule(rule: UfwRule) -> None:
    if (rule.action not in ("allow", "deny") or rule.direction not in ("in", "out", "routed")
            or rule.protocol not in ("tcp", "udp") or type(rule.port) is not int
            or not 1 <= rule.port <= 65535 or not isinstance(rule.source_cidr, str)):
        raise ValueError("host UFW rule is malformed")
    network = ipaddress.ip_network(rule.source_cidr, strict=True)
    if str(network) != rule.source_cidr or (rule.action == "allow" and network.version != 4):
        raise ValueError("host UFW rule source differs")


def _check_ssh(accounts: tuple[SshAccountEvidence, ...], role: str, admin: str, transport: str) -> None:
    if (not isinstance(accounts, tuple) or len(accounts) != 2
            or any(not isinstance(account, SshAccountEvidence) for account in accounts)):
        raise ValueError("SSH account evidence is incomplete")
    by_name = {account.account: account for account in accounts}
    if set(by_name) != {"user", "sketchssh"}:
        raise ValueError("SSH account identity differs")
    user, sketchssh = by_name["user"], by_name["sketchssh"]
    for account in accounts:
        if (account.complete is not True or account.password_authentication is not False
                or not isinstance(account.authorized_key_sha256, frozenset)
                or any(not isinstance(value, str) or not _FINGERPRINT.fullmatch(value)
                       for value in account.authorized_key_sha256)):
            raise ValueError("SSH account policy is incomplete")
    if (admin not in user.authorized_key_sha256 or transport in user.authorized_key_sha256
            or transport not in sketchssh.authorized_key_sha256
            or admin in sketchssh.authorized_key_sha256
            or sketchssh.allow_tcp_forwarding != ("local" if role == "middle" else "yes")
            or sketchssh.gateway_ports != ("no" if role == "middle" else "yes")):
        raise ValueError("SSH managed keys or forwarding differ")


def _check_listeners(listeners: tuple[ListenerEvidence, ...], complete: bool,
                     public_ipv4: str) -> None:
    if (not isinstance(listeners, tuple) or complete is not True
            or any(not isinstance(listener, ListenerEvidence) for listener in listeners)
            or len(set(listeners)) != len(listeners)):
        raise ValueError("host listener evidence is incomplete")
    ipv4_ssh_listener = False
    for listener in listeners:
        if (listener.protocol not in ("tcp", "udp") or type(listener.port) is not int
                or not 1 <= listener.port <= 65535 or not listener.process):
            raise ValueError("host listener record is malformed")
        address = ipaddress.ip_address(listener.bind_address)
        if address.is_loopback:
            continue
        if listener.port == 22:
            if listener.protocol != "tcp" or listener.process != "sshd":
                raise ValueError("management SSH listener identity differs")
            if isinstance(address, ipaddress.IPv4Address) and listener.bind_address in (
                    "0.0.0.0", public_ipv4):
                ipv4_ssh_listener = True
    if not ipv4_ssh_listener:
        raise ValueError("management SSH listener is missing or ambiguous")
