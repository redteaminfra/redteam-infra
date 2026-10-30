# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import replace
import pytest

from app.services.provider_keyed_host_policy import Edge, Middle, Topology
from app.services.provider_keyed_ingress_route_ledger import (
    KeyedIngressRouteError, KeyedRouteIntent, render_keyed_route_projection,
)


def _topology():
    topology = Topology(
        {'proxy01': '192.0.2.10', 'proxy02': '192.0.2.11'},
        {'middle01': Middle('192.0.2.20', 'proxy01'),
         'middle02': Middle('192.0.2.21', 'proxy02')},
        {'edge01': Edge('192.0.2.30', 'middle01'),
         'edge02': Edge('192.0.2.31', 'middle02')},
    )
    providers = {'middle01': 'linode', 'edge01': 'digitalocean',
                 'middle02': 'digitalocean', 'edge02': 'linode'}
    return topology, providers


def test_mixed_raw_route_projects_distinct_public_and_relay_ports():
    topology, providers = _topology()
    route = KeyedRouteIntent('one', 'udp', 'edge01', 'middle01', 53, 8001, ('0.0.0.0/0',))
    result = render_keyed_route_projection(topology, providers, (route,))
    assert [(r.node_address, r.port) for r in result.provider_routes['digitalocean']] == [('edge01', 53)]
    assert [(r.node_address, r.port) for r in result.provider_routes['linode']] == [('middle01', 8001)]
    assert result.host_policies['edge01']['sketch_firewall_v2_rules'] == [
        {'from_ip': '0.0.0.0/0', 'port': 53, 'proto': 'udp'}]
    assert result.host_policies['middle01']['sketch_firewall_v2_rules'] == [
        {'from_ip': '192.0.2.30/32', 'port': 8001, 'proto': 'udp'}]
    assert result.host_policies['edge02']['sketch_firewall_v2_rules'] == []
    assert result.host_policies['middle02']['sketch_firewall_v2_rules'] == []
    assert result.host_policies['edge01']['sketch_firewall_v2_ssh_sources'] == ['192.0.2.20/32']


def test_web_uses_shared_fixed_ports_and_keeps_sibling_hosts_denied():
    topology, providers = _topology()
    first = KeyedRouteIntent('web-one', 'web', 'edge01', 'middle01', 443, 443, ('0.0.0.0/0',))
    second = KeyedRouteIntent('web-two', 'web', 'edge01', 'middle01', 443, 443, ('0.0.0.0/0',))
    result = render_keyed_route_projection(topology, providers, (first, second))
    assert result.provider_routes == {'linode': (), 'digitalocean': ()}
    assert result.host_policies['edge01']['sketch_firewall_v2_rules'] == [
        {'from_ip': '0.0.0.0/0', 'port': 443, 'proto': 'tcp'}]
    assert result.host_policies['middle01']['sketch_firewall_v2_rules'] == [
        {'from_ip': '192.0.2.30/32', 'port': 443, 'proto': 'tcp'}]
    assert result.host_policies['edge02']['sketch_firewall_v2_rules'] == []


@pytest.mark.parametrize('field,value', [
    ('middle_node', 'middle02'), ('relay_port', 443), ('external_port', 8001),
    ('external_port', 22), ('external_port', 80), ('external_port', 2222),
    ('public_sources', ('::/0',)), ('public_sources', ('0.0.0.0/0', '0.0.0.0/0')),
])
def test_raw_route_rejects_wrong_predecessor_or_ports_or_sources(field, value):
    topology, providers = _topology()
    route = KeyedRouteIntent('one', 'tcp', 'edge01', 'middle01', 3333, 8001, ('0.0.0.0/0',))
    with pytest.raises(KeyedIngressRouteError):
        render_keyed_route_projection(topology, providers, (replace(route, **{field: value}),))


def test_same_edge_raw_public_socket_collision_rejected():
    topology, providers = _topology()
    first = KeyedRouteIntent('one', 'tcp', 'edge01', 'middle01', 3333, 8001, ('0.0.0.0/0',))
    second = KeyedRouteIntent('two', 'tcp', 'edge01', 'middle01', 3333, 8002, ('0.0.0.0/0',))
    with pytest.raises(KeyedIngressRouteError, match='shares'):
        render_keyed_route_projection(topology, providers, (first, second))


def test_two_provider_orderings_and_sibling_isolation():
    topology, providers = _topology()
    first = KeyedRouteIntent('one', 'tcp', 'edge01', 'middle01', 3333, 8001, ('0.0.0.0/0',))
    second = KeyedRouteIntent('two', 'udp', 'edge02', 'middle02', 3478, 8002, ('0.0.0.0/0',))
    result = render_keyed_route_projection(topology, providers, (first, second))
    assert [(r.channel_id, r.node_address, r.port) for r in result.provider_routes['digitalocean']] == [
        ('one', 'edge01', 3333), ('two', 'middle02', 8002)]
    assert [(r.channel_id, r.node_address, r.port) for r in result.provider_routes['linode']] == [
        ('one', 'middle01', 8001), ('two', 'edge02', 3478)]


@pytest.mark.parametrize('middle_provider,edge_provider', [('linode', 'digitalocean'), ('digitalocean', 'linode')])
@pytest.mark.parametrize('shared_middle', [False, True])
def test_five_independent_dns_routes_use_exact_host_scoped_sockets(middle_provider, edge_provider, shared_middle):
    from app.services.inbound_raw_route_plan import apply_plan_to_channel, plan_new_raw_route
    from test_inbound_raw_route_plan import _channel
    middles = {'middle0': Middle('192.0.2.20', 'proxy01')}
    if not shared_middle:
        middles.update({f'middle{i}': Middle(f'192.0.2.{20+i}', 'proxy01') for i in range(1, 5)})
    topology = Topology({'proxy01': '192.0.2.10'}, middles, {
        f'edge{i}': Edge(f'192.0.2.{30+i}', 'middle0' if shared_middle else f'middle{i}')
        for i in range(5)})
    providers = {**{name: middle_provider for name in middles},
                 **{name: edge_provider for name in topology.edges}}
    active = []
    intents = []
    for i in range(5):
        edge = f'edge{i}'
        middle = topology.edges[edge].middle_node
        channel = {**_channel('udp', external=53, internal=5300+i), 'channelId': f'dns{i}',
                   'edge': edge, 'edgeComponentId': edge, 'middle': middle, 'middleComponentId': middle}
        plan = plan_new_raw_route(channel, active)
        assert plan['public']['port'] == 53
        assert plan['termination']['port'] == 5300+i
        assert plan['middleRelay']['port'] == (8000+i if shared_middle else 8000)
        assert plan['proxyRelay']['port'] == 8000+i  # All five use the same proxy.
        active.append(apply_plan_to_channel(channel, plan))
        intents.append(KeyedRouteIntent(f'dns{i}', 'udp', edge, middle, 53,
                                       plan['middleRelay']['port'], ('0.0.0.0/0',)))
    result = render_keyed_route_projection(topology, providers, tuple(intents))
    assert len(result.provider_routes[edge_provider]) == 5
    assert len(result.provider_routes[middle_provider]) == 5
    for i, intent in enumerate(intents):
        assert result.host_policies[intent.edge_node]['sketch_firewall_v2_rules'] == [
            {'from_ip': '0.0.0.0/0', 'port': 53, 'proto': 'udp'}]
        assert {'from_ip': f'192.0.2.{30+i}/32', 'port': intent.relay_port, 'proto': 'udp'} in (
            result.host_policies[intent.middle_node]['sketch_firewall_v2_rules'])
    assert len({row['proxyRelayPort'] for row in active}) == 5
    # Adding the fifth route retains every existing sibling's complete policy.
    previous = render_keyed_route_projection(topology, providers, tuple(intents[:-1]))
    for name, policy in previous.host_policies.items():
        assert all(rule in result.host_policies[name]['sketch_firewall_v2_rules']
                   for rule in policy['sketch_firewall_v2_rules'])


def test_shared_middle_relay_socket_collision_still_rejected_on_different_edges():
    topology, providers = _topology()
    topology = replace(topology, edges={**topology.edges, 'edge03': Edge('192.0.2.32', 'middle01')})
    providers['edge03'] = 'linode'
    first = KeyedRouteIntent('one', 'udp', 'edge01', 'middle01', 53, 8000, ('0.0.0.0/0',))
    second = KeyedRouteIntent('two', 'udp', 'edge03', 'middle01', 53, 8000, ('0.0.0.0/0',))
    with pytest.raises(KeyedIngressRouteError, match='shares'):
        render_keyed_route_projection(topology, providers, (first, second))


def test_same_edge_and_middle_tcp_udp_sockets_are_independent():
    topology, providers = _topology()
    udp = KeyedRouteIntent('udp', 'udp', 'edge01', 'middle01', 53, 8000, ('0.0.0.0/0',))
    tcp = replace(udp, channel_id='tcp', kind='tcp')
    result = render_keyed_route_projection(topology, providers, (udp, tcp))
    assert {row.protocol for row in result.provider_routes['digitalocean']} == {'tcp', 'udp'}
    assert result.host_policies['edge01']['sketch_firewall_v2_rules'] == [
        {'from_ip': '0.0.0.0/0', 'port': 53, 'proto': 'tcp'},
        {'from_ip': '0.0.0.0/0', 'port': 53, 'proto': 'udp'}]
    assert result.host_policies['edge02']['sketch_firewall_v2_rules'] == []


def test_duplicate_channel_id_still_rejected_across_independent_sockets():
    topology, providers = _topology()
    first = KeyedRouteIntent('same', 'udp', 'edge01', 'middle01', 53, 8000, ('0.0.0.0/0',))
    second = replace(first, edge_node='edge02', middle_node='middle02')
    with pytest.raises(KeyedIngressRouteError, match='incomplete'):
        render_keyed_route_projection(topology, providers, (first, second))
