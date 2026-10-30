# Copyright (c) 2026, Oracle and/or its affiliates.
"""Pure projection keeps sibling Sketch routes isolated after shared apply."""

from dataclasses import replace

import pytest

from app.services.outbound_channel_artifacts import derive_pending_outbound_channels_from_sketch_rows
from app.services.provider_keyed_chain_projection import (
    ProviderKeyedChainProjectionError, project_digitalocean_initial_chains,
)
from app.services.provider_keyed_digitalocean_attachment import (
    DigitalOceanAttachmentEvidence, DigitalOceanAttachmentIntent, ExpectedDigitalOceanNode,
)
from app.services.provider_keyed_persisted_intent import compile_fresh_digitalocean_persisted_intent
from test_provider_keyed_persisted_intent import _inputs


def _fixture():
    engagement, chains, core, plan, profile = _inputs()
    reviewed = compile_fresh_digitalocean_persisted_intent(
        engagement, chains, core, plan, profile, environment="devtest",
    )
    nodes = tuple(
        ExpectedDigitalOceanNode(address, str(index), expected.name, expected.region,
                                   f"198.51.100.{index}")
        for index, (address, expected) in enumerate(sorted(reviewed.nodes.items()), 101)
    )
    attachment = DigitalOceanAttachmentIntent(
        state_sha256="a" * 64, firewall_id="11111111-2222-4333-8444-555555555555",
        firewall_name=reviewed.firewall.name, selector_tag=reviewed.selector_tag,
        trusted_ssh_cidrs=reviewed.firewall.trusted_ssh_cidrs, nodes=nodes,
        credential_record_id="connection-opaque", credential_secret_sha256="b" * 64,
        credential_updated_at="2026-10-07T00:00:00+00:00",
    )
    proof = DigitalOceanAttachmentEvidence(
        state_sha256=attachment.state_sha256, firewall_id=attachment.firewall_id,
        verified_droplet_ids=tuple(sorted(node.droplet_id for node in nodes)), attempts=2,
    )
    return reviewed, attachment, proof, chains


def test_projects_two_complete_chains_with_regional_ordinals_and_isolated_policy():
    reviewed, attachment, proof, chains = _fixture()
    projected = project_digitalocean_initial_chains(reviewed, attachment, proof, chains)
    assert len(projected) == 2
    assert [item.chain.chain_id for item in projected] == [route.chain_id for route in reviewed.chain_routes]
    assert [len(item.chain.nodes) for item in projected] == [4, 3]
    assert [chain.nodes for chain in chains] == [[], []]
    assert all(item.chain.status == "pending" and item.chain.deploy_job_id == "" for item in projected)
    assert [item.proxy_egress_ip for item in projected] == ["8.8.8.8", "9.9.9.9"]
    first, second = projected
    assert [row["terraformAddress"].split('"')[1] for row in first.chain.nodes[1:]] == [
        "sfo3-01", "nyc3-01", "sfo3-02",
    ]
    assert [row["terraformAddress"].split('"')[1] for row in second.chain.nodes[1:]] == [
        "sfo3-03", "sfo3-04",
    ]
    assert {row["providerInstanceId"] for row in first.chain.nodes}.isdisjoint(
        {row["providerInstanceId"] for row in second.chain.nodes},
    )
    assert [row["componentId"] for row in second.chain.nodes] == ["middle", "edge-01", "edge-02"]
    assert [row["edgeIndex"] for row in second.chain.nodes[1:]] == ["1", "2"]
    assert second.chain.nodes[0]["middleOrdinal"] == 2
    assert all(row["chainId"] == second.chain.chain_id and row["assignedProxy"] == "proxy02"
               and row["proxy"] == "proxy02" and row["status"] == "pending"
               for row in second.chain.nodes)
    assert set(first.host_policies).isdisjoint(second.host_policies)
    for item in projected:
        middle = item.chain.nodes[0]
        assert item.host_policies[middle["hostname"]]["sketch_firewall_v2_ssh_sources"] == [
            f"{item.proxy_egress_ip}/32",
        ]
        for edge in item.chain.nodes[1:]:
            policy = item.host_policies[edge["hostname"]]
            assert policy["sketch_firewall_v2_ssh_sources"] == [f'{middle["publicIp"]}/32']
            assert policy["sketch_firewall_v2_rules"] == []
            assert set(policy) == {"sketch_firewall_v2_enabled", "sketch_firewall_v2_ssh_sources",
                                   "sketch_firewall_v2_rules"}


def test_chain_two_outbound_channels_use_local_edge_indices_not_regional_host_ordinals():
    reviewed, attachment, proof, chains = _fixture()
    second = project_digitalocean_initial_chains(reviewed, attachment, proof, chains)[1]
    channels = derive_pending_outbound_channels_from_sketch_rows(
        reviewed.engagement_name, second.chain.chain_id, second.chain.nodes,
    )
    assert [row["hostname"].split("-")[-1] for row in second.chain.nodes[1:]] == ["03", "04"]
    assert [channel["edgeIndex"] for channel in channels] == ["1", "2"]
    assert len({channel["channelId"] for channel in channels}) == 2
    assert len({channel["port"] for channel in channels}) == 2
    assert [channel["edge"] for channel in channels] == [row["hostname"] for row in second.chain.nodes[1:]]
    assert all(channel["proxy"] == "proxy02" for channel in channels)


@pytest.mark.parametrize("drift", [
    "missing", "extra", "swapped_edge", "duplicate_id", "duplicate_ip", "duplicate_name",
    "wrong_region", "wrong_chain_region", "wrong_edge_intent", "wrong_proof",
    "wrong_firewall", "shared_edge_route", "proxy_node_ip_collision", "wrong_state_proof",
])
def test_rejects_nonbijective_or_mismatched_projection(drift):
    reviewed, attachment, proof, chains = _fixture()
    nodes = list(attachment.nodes)
    if drift == "missing":
        attachment = replace(attachment, nodes=tuple(nodes[:-1]))
    elif drift == "extra":
        attachment = replace(attachment, nodes=(*nodes, replace(nodes[0], address='digitalocean_droplet.edge["extra"]')))
    elif drift == "swapped_edge":
        edges = [index for index, node in enumerate(nodes) if '.edge[' in node.address]
        a, b = edges[0], edges[1]
        nodes[a], nodes[b] = replace(nodes[a], address=nodes[b].address), replace(nodes[b], address=nodes[a].address)
        attachment = replace(attachment, nodes=tuple(nodes))
    elif drift == "duplicate_id":
        nodes[1] = replace(nodes[1], droplet_id=nodes[0].droplet_id)
        attachment = replace(attachment, nodes=tuple(nodes))
    elif drift == "duplicate_ip":
        nodes[1] = replace(nodes[1], public_ipv4=nodes[0].public_ipv4)
        attachment = replace(attachment, nodes=tuple(nodes))
    elif drift == "duplicate_name":
        nodes[1] = replace(nodes[1], name=nodes[0].name)
        attachment = replace(attachment, nodes=tuple(nodes))
    elif drift == "wrong_region":
        nodes[0] = replace(nodes[0], region="ams3")
        attachment = replace(attachment, nodes=tuple(nodes))
    elif drift == "wrong_chain_region":
        chains = [replace(chains[0], middle_region="ams3"), chains[1]]
    elif drift == "wrong_edge_intent":
        edges = [*chains[0].edge_intents]
        edges[0] = {**edges[0], "region": "ams3"}
        chains = [replace(chains[0], edge_intents=edges), chains[1]]
    elif drift == "wrong_proof":
        proof = replace(proof, verified_droplet_ids=proof.verified_droplet_ids[:-1])
    elif drift == "wrong_firewall":
        attachment = replace(attachment, firewall_name="unreviewed")
    elif drift == "proxy_node_ip_collision":
        reviewed = replace(reviewed, proxy_egress_ips={**reviewed.proxy_egress_ips,
                                                        "proxy02": nodes[0].public_ipv4})
    elif drift == "wrong_state_proof":
        proof = replace(proof, state_sha256="c" * 64)
    else:
        first, second = reviewed.chain_routes
        reviewed = replace(reviewed, chain_routes=(first, replace(second, edge_nodes=(first.edge_nodes[0], *second.edge_nodes[1:]))))
    with pytest.raises(ProviderKeyedChainProjectionError, match="projection differs"):
        project_digitalocean_initial_chains(reviewed, attachment, proof, chains)
