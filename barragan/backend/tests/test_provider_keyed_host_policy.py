# Copyright (c) 2026, Oracle and/or its affiliates.
import pytest

from app.services.provider_keyed_host_policy import (
    ChannelRoute,
    Edge,
    Middle,
    SketchHostPolicyError,
    Topology,
    render_sketch_host_policy,
)


def _topology() -> Topology:
    return Topology(
        proxy_egress_ips={"proxy-a": "198.51.100.10", "proxy-b": "198.51.100.20"},
        middles={
            "middle-a": Middle("203.0.113.11", "proxy-a"),
            "middle-b": Middle("203.0.113.12", "proxy-b"),
        },
        edges={
            "edge-a": Edge("203.0.113.21", "middle-a"),
            "edge-b": Edge("203.0.113.22", "middle-b"),
        },
    )


def test_two_chains_get_only_their_immediate_ssh_predecessor_and_selected_channel():
    policies = render_sketch_host_policy(
        _topology(),
        (
            ChannelRoute("edge-a", "middle-a", 18085, "tcp", ("0.0.0.0/0",)),
            ChannelRoute("edge-b", "middle-b", 3478, "udp", ("192.0.2.0/24",)),
        ),
    )
    assert policies["middle-a"] == {
        "sketch_firewall_v2_enabled": True,
        "sketch_firewall_v2_ssh_sources": ["198.51.100.10/32"],
        "sketch_firewall_v2_rules": [{"from_ip": "203.0.113.21/32", "port": 18085, "proto": "tcp"}],
    }
    assert policies["edge-a"] == {
        "sketch_firewall_v2_enabled": True,
        "sketch_firewall_v2_ssh_sources": ["203.0.113.11/32"],
        "sketch_firewall_v2_rules": [{"from_ip": "0.0.0.0/0", "port": 18085, "proto": "tcp"}],
    }
    assert policies["middle-b"]["sketch_firewall_v2_rules"] == [
        {"from_ip": "203.0.113.22/32", "port": 3478, "proto": "udp"}
    ]
    assert policies["edge-b"]["sketch_firewall_v2_rules"] == [
        {"from_ip": "192.0.2.0/24", "port": 3478, "proto": "udp"}
    ]
    for host, vars_ in policies.items():
        assert not any(key in vars_ for key in ("middles", "edges", "channels", "proxy_node")), host


def test_append_edge_preserves_existing_host_policy():
    first = render_sketch_host_policy(
        _topology(), (ChannelRoute("edge-a", "middle-a", 18085, "tcp", ("0.0.0.0/0",)),)
    )
    topology = _topology()
    topology.edges["edge-c"] = Edge("203.0.113.23", "middle-b")
    appended = render_sketch_host_policy(
        topology, (ChannelRoute("edge-a", "middle-a", 18085, "tcp", ("0.0.0.0/0",)),)
    )
    assert appended["middle-a"] == first["middle-a"]
    assert appended["edge-a"] == first["edge-a"]
    assert appended["edge-c"]["sketch_firewall_v2_ssh_sources"] == ["203.0.113.12/32"]
    assert appended["edge-c"]["sketch_firewall_v2_rules"] == []


@pytest.mark.parametrize(
    "route,match",
    [
        (ChannelRoute("edge-a", "middle-b", 18085, "tcp", ("0.0.0.0/0",)), "predecessor"),
        (ChannelRoute("edge-missing", "middle-a", 18085, "tcp", ("0.0.0.0/0",)), "predecessor"),
        (ChannelRoute("edge-a", "middle-a", 22, "tcp", ("0.0.0.0/0",)), "SSH/22"),
        (ChannelRoute("edge-a", "middle-a", 18085, "tcp", ()), "source"),
        (ChannelRoute("edge-a", "middle-a", 18085, "tcp", ("192.0.2.7/24",)), "canonical"),
        (ChannelRoute("edge-a", "middle-a", 18085, "icmp", ("0.0.0.0/0",)), "protocol"),
    ],
)
def test_rejects_mismatched_or_unsafe_channel(route: ChannelRoute, match: str):
    with pytest.raises(SketchHostPolicyError, match=match):
        render_sketch_host_policy(_topology(), (route,))


def test_rejects_duplicate_or_invalid_predecessor_address():
    topology = _topology()
    topology.edges["edge-b"] = Edge("203.0.113.21", "middle-b")
    with pytest.raises(SketchHostPolicyError, match="duplicated"):
        render_sketch_host_policy(topology, ())
    topology = _topology()
    topology.proxy_egress_ips["proxy-a"] = "0.0.0.0"
    with pytest.raises(SketchHostPolicyError, match="usable IPv4"):
        render_sketch_host_policy(topology, ())
    topology = _topology()
    topology.middles["middle-a"] = Middle("203.0.113.11", "proxy-missing")
    with pytest.raises(SketchHostPolicyError, match="unknown proxy predecessor"):
        render_sketch_host_policy(topology, ())
