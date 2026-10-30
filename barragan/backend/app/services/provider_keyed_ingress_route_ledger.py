# Copyright (c) 2026, Oracle and/or its affiliates.
"""Pure selected-route projection for provider-keyed Sketch hosts.

The projection is desired policy, not evidence that a host applied it. A live
caller must authenticate each observed active/persisted firewall and provider
attachment before publishing a channel. HTTP/S uses the fixed 80/443 path.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Network, ip_network
from typing import Literal, Mapping

from app.services.provider_keyed_host_policy import (
    SketchHostPolicyError, Topology, render_sketch_host_policy,
)
from app.services.provider_keyed_ingress_plan_gate import KeyedIngressRoute


class KeyedIngressRouteError(ValueError):
    pass


@dataclass(frozen=True)
class KeyedRouteIntent:
    channel_id: str
    kind: Literal["web", "tcp", "udp"]
    edge_node: str
    middle_node: str
    external_port: int
    relay_port: int
    public_sources: tuple[str, ...]


@dataclass(frozen=True)
class KeyedRouteProjection:
    host_policies: dict[str, dict[str, object]]
    provider_routes: dict[str, tuple[KeyedIngressRoute, ...]]


def render_keyed_route_projection(
    topology: Topology, node_providers: Mapping[str, str],
    routes: tuple[KeyedRouteIntent, ...],
) -> KeyedRouteProjection:
    """Render exact host rules and raw provider-route union for all siblings.

    A web route is represented only by 80/443 host rules; those public ports
    already belong to the shared provider baseline. Raw routes use different
    external and hidden relay ports. Termination/proxy rules are separate.
    """
    try:
        policies = render_sketch_host_policy(topology, ())
    except SketchHostPolicyError as exc:
        raise KeyedIngressRouteError("keyed route topology is invalid") from exc
    if (not isinstance(node_providers, Mapping) or set(node_providers) != set(policies)
            or any(provider not in {"linode", "digitalocean"}
                   for provider in node_providers.values())
            or not isinstance(routes, tuple)):
        raise KeyedIngressRouteError("keyed route provider membership is incomplete")
    seen_ids: set[str] = set()
    raw_ports: set[tuple[str, str, int]] = set()
    host_rules: dict[str, set[tuple[str, int, str]]] = {node: set() for node in policies}
    by_provider: dict[str, list[KeyedIngressRoute]] = {
        "linode": [], "digitalocean": [],
    }
    for route in routes:
        if (not isinstance(route, KeyedRouteIntent) or not isinstance(route.channel_id, str)
                or not route.channel_id or route.channel_id in seen_ids
                or route.kind not in {"web", "tcp", "udp"}
                or route.edge_node not in topology.edges
                or route.middle_node not in topology.middles
                or topology.edges[route.edge_node].middle_node != route.middle_node
                or type(route.external_port) is not int or type(route.relay_port) is not int
                or not isinstance(route.public_sources, tuple)
                or not route.public_sources):
            raise KeyedIngressRouteError("keyed route is incomplete or not selected")
        seen_ids.add(route.channel_id)
        if route.kind == "web":
            if (route.external_port not in {80, 443}
                    or route.relay_port != route.external_port):
                raise KeyedIngressRouteError("web route must use fixed 80/443 transport")
            proto = "tcp"
        else:
            if (not 1 <= route.external_port <= 65535
                    or route.external_port in {22, 80, 443, 2222}
                    or 8000 <= route.external_port <= 8080
                    or not 8000 <= route.relay_port <= 8080
                    or route.external_port == route.relay_port):
                raise KeyedIngressRouteError("raw route port roles collide")
            proto = route.kind
            public_socket = (route.edge_node, proto, route.external_port)
            relay_socket = (route.middle_node, proto, route.relay_port)
            if public_socket in raw_ports or relay_socket in raw_ports:
                raise KeyedIngressRouteError("raw route shares a public or relay port")
            raw_ports.update({public_socket, relay_socket})
            by_provider[node_providers[route.edge_node]].append(
                KeyedIngressRoute(route.channel_id, proto, route.external_port,
                                  route.edge_node))
            by_provider[node_providers[route.middle_node]].append(
                KeyedIngressRoute(route.channel_id, proto, route.relay_port,
                                  route.middle_node))
        sources: set[str] = set()
        for source in route.public_sources:
            try:
                network = ip_network(source, strict=True)
            except (TypeError, ValueError) as exc:
                raise KeyedIngressRouteError("keyed route source is not a canonical CIDR") from exc
            if not isinstance(network, IPv4Network) or str(network) != source:
                raise KeyedIngressRouteError("keyed route source must be canonical IPv4")
            sources.add(source)
        if len(sources) != len(route.public_sources):
            raise KeyedIngressRouteError("keyed route source is duplicated")
        for source in sources:
            host_rules[route.edge_node].add((source, route.external_port, proto))
        edge_ip = topology.edges[route.edge_node].public_ip
        host_rules[route.middle_node].add((f"{edge_ip}/32", route.relay_port, proto))
    for node, rules in host_rules.items():
        policies[node]["sketch_firewall_v2_rules"] = [
            {"from_ip": source, "port": port, "proto": proto}
            for source, port, proto in sorted(rules)
        ]
    return KeyedRouteProjection(policies, {
        provider: tuple(items) for provider, items in by_provider.items()
    })
