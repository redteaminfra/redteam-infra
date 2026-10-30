# Copyright (c) 2026, Oracle and/or its affiliates.
"""Pure controller-side renderer for fresh Sketch firewall v2 host variables.

The caller retains the complete topology.  Only the returned value for a
particular host should be placed in that host's Ansible inventory variables.
This does not update an already-active host's firewall.
"""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from typing import Literal


class SketchHostPolicyError(ValueError):
    """The proposed route cannot be represented as isolated host rules."""


@dataclass(frozen=True)
class Middle:
    public_ip: str
    proxy_node: str


@dataclass(frozen=True)
class Edge:
    public_ip: str
    middle_node: str


@dataclass(frozen=True)
class Topology:
    proxy_egress_ips: dict[str, str]
    middles: dict[str, Middle]
    edges: dict[str, Edge]


@dataclass(frozen=True)
class ChannelRoute:
    edge_node: str
    middle_node: str
    port: int
    protocol: Literal["tcp", "udp"]
    public_sources: tuple[str, ...]


def _address(value: str, label: str) -> IPv4Address:
    if not isinstance(value, str):
        raise SketchHostPolicyError(f"{label} must be an IPv4 address")
    try:
        parsed = ip_address(value)
    except ValueError as exc:
        raise SketchHostPolicyError(f"{label} must be an IPv4 address") from exc
    if not isinstance(parsed, IPv4Address) or parsed.is_unspecified or parsed.is_multicast or parsed.is_loopback:
        raise SketchHostPolicyError(f"{label} must be a usable IPv4 address")
    return parsed


def _source(value: str) -> IPv4Network:
    if not isinstance(value, str):
        raise SketchHostPolicyError("channel source must be a canonical IPv4 CIDR")
    try:
        parsed = ip_network(value, strict=True)
    except ValueError as exc:
        raise SketchHostPolicyError("channel source must be a canonical IPv4 CIDR") from exc
    if not isinstance(parsed, IPv4Network):
        raise SketchHostPolicyError("channel source must be an IPv4 CIDR")
    return parsed


def render_sketch_host_policy(
    topology: Topology,
    channels: tuple[ChannelRoute, ...],
) -> dict[str, dict[str, object]]:
    """Validate complete intent and return isolated per-host Ansible v2 vars.

    Public channel sources apply only at the selected edge.  Its selected
    middle admits the same port solely from that edge's public address.
    Management SSH admits only the immediate route predecessor's /32.
    """
    if not topology.middles or not topology.edges:
        raise SketchHostPolicyError("topology needs middle and edge nodes")
    if set(topology.middles) & set(topology.edges):
        raise SketchHostPolicyError("middle and edge node keys overlap")

    used_ips: set[IPv4Address] = set()
    proxy_ips = {_address(address, "proxy egress IP") for address in topology.proxy_egress_ips.values()}
    policies: dict[str, dict[str, object]] = {}
    for node, middle in topology.middles.items():
        if not node or middle.proxy_node not in topology.proxy_egress_ips:
            raise SketchHostPolicyError("middle references an unknown proxy predecessor")
        middle_ip = _address(middle.public_ip, "middle public IP")
        proxy_ip = _address(topology.proxy_egress_ips[middle.proxy_node], "proxy egress IP")
        if middle_ip in used_ips or middle_ip in proxy_ips:
            raise SketchHostPolicyError("middle IP is duplicated or is its predecessor")
        used_ips.add(middle_ip)
        policies[node] = {
            "sketch_firewall_v2_enabled": True,
            "sketch_firewall_v2_ssh_sources": [f"{proxy_ip}/32"],
            "sketch_firewall_v2_rules": [],
        }
    for node, edge in topology.edges.items():
        if not node or edge.middle_node not in topology.middles:
            raise SketchHostPolicyError("edge references an unknown middle node")
        edge_ip = _address(edge.public_ip, "edge public IP")
        if edge_ip in used_ips or edge_ip in proxy_ips:
            raise SketchHostPolicyError("Sketch node public IP is duplicated")
        used_ips.add(edge_ip)
        predecessor = _address(topology.middles[edge.middle_node].public_ip, "middle public IP")
        policies[node] = {
            "sketch_firewall_v2_enabled": True,
            "sketch_firewall_v2_ssh_sources": [f"{predecessor}/32"],
            "sketch_firewall_v2_rules": [],
        }

    rule_sets: dict[str, set[tuple[str, int, str]]] = {node: set() for node in policies}
    for channel in channels:
        edge = topology.edges.get(channel.edge_node)
        if edge is None or channel.middle_node not in topology.middles or edge.middle_node != channel.middle_node:
            raise SketchHostPolicyError("channel route does not match selected edge predecessor")
        if type(channel.port) is not int or not 1 <= channel.port <= 65535 or channel.port == 22:
            raise SketchHostPolicyError("channel port must be 1..65535 and cannot be management SSH/22")
        if channel.protocol not in ("tcp", "udp"):
            raise SketchHostPolicyError("channel protocol must be tcp or udp")
        if not channel.public_sources:
            raise SketchHostPolicyError("channel needs an explicit public source CIDR")
        for source in channel.public_sources:
            rule_sets[channel.edge_node].add((str(_source(source)), channel.port, channel.protocol))
        edge_ip = _address(edge.public_ip, "edge public IP")
        rule_sets[channel.middle_node].add((f"{edge_ip}/32", channel.port, channel.protocol))

    for node, rules in rule_sets.items():
        policies[node]["sketch_firewall_v2_rules"] = [
            {"from_ip": source, "port": port, "proto": protocol}
            for source, port, protocol in sorted(rules)
        ]
    return policies
