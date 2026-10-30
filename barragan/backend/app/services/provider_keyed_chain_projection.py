# Copyright (c) 2026, Oracle and/or its affiliates.
"""Pure, in-memory per-chain projection of a reviewed provider-keyed apply.

The shared provider apply is not a per-chain deploy job. This projection only
prepares exact node rows and isolated host policy for a later bootstrap gate.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, replace
from typing import Mapping, Sequence

from app.services.provider_keyed_digitalocean_attachment import (
    DigitalOceanAttachmentEvidence, DigitalOceanAttachmentIntent, ExpectedDigitalOceanNode,
)
from app.services.provider_keyed_host_policy import Edge, Middle, Topology, render_sketch_host_policy
from app.services.provider_keyed_persisted_intent import ProviderKeyedPersistedIntent
from app.services.provider_keyed_sketch import SCHEMA
from app.storage.sketch_chain_repository import StoredSketchChain


_ID = re.compile(r"[1-9][0-9]*\Z")


class ProviderKeyedChainProjectionError(ValueError):
    """State-backed nodes cannot be mapped bijectively to pending chains."""


@dataclass(frozen=True)
class ProjectedProviderKeyedChain:
    chain: StoredSketchChain
    host_policies: dict[str, dict[str, object]]
    proxy_egress_ip: str


def project_digitalocean_initial_chains(
    reviewed: ProviderKeyedPersistedIntent,
    attachment: DigitalOceanAttachmentIntent,
    proof: DigitalOceanAttachmentEvidence,
    chains: Sequence[StoredSketchChain],
) -> tuple[ProjectedProviderKeyedChain, ...]:
    """Bind every reviewed route node to one exact applied Droplet, without I/O."""
    try:
        if (not isinstance(reviewed, ProviderKeyedPersistedIntent)
                or reviewed.provider != "digitalocean"
                or not isinstance(attachment, DigitalOceanAttachmentIntent)
                or not isinstance(proof, DigitalOceanAttachmentEvidence)
                or not isinstance(chains, Sequence) or len(chains) != 2
                or any(not isinstance(chain, StoredSketchChain) for chain in chains)
                or len(reviewed.chain_routes) != 2
                or reviewed.topology.get("schema") != SCHEMA
                or attachment.firewall_name != reviewed.firewall.name
                or attachment.selector_tag != reviewed.selector_tag
                or attachment.trusted_ssh_cidrs != reviewed.firewall.trusted_ssh_cidrs):
            raise ValueError("reviewed projection identity differs")
        chain_by_id = {chain.chain_id: chain for chain in chains}
        route_by_id = {route.chain_id: route for route in reviewed.chain_routes}
        if len(chain_by_id) != 2 or len(route_by_id) != 2 or set(chain_by_id) != set(route_by_id):
            raise ValueError("reviewed chain set differs")
        expected_addresses = set(reviewed.nodes)
        nodes_by_address = {node.address: node for node in attachment.nodes}
        proxy_ips = set(reviewed.proxy_egress_ips.values())
        if (len(nodes_by_address) != len(attachment.nodes)
                or set(nodes_by_address) != expected_addresses
                or len({node.droplet_id for node in attachment.nodes}) != len(attachment.nodes)
                or len({node.public_ipv4 for node in attachment.nodes}) != len(attachment.nodes)
                or len({node.name for node in attachment.nodes}) != len(attachment.nodes)
                or len(proxy_ips) != len(reviewed.proxy_egress_ips)
                or any(node.public_ipv4 in proxy_ips for node in attachment.nodes)):
            raise ValueError("applied node set is not bijective")
        for address, node in nodes_by_address.items():
            expected = reviewed.nodes[address]
            ip = ipaddress.ip_address(node.public_ipv4)
            if (not isinstance(node, ExpectedDigitalOceanNode)
                    or not _ID.fullmatch(node.droplet_id)
                    or not isinstance(ip, ipaddress.IPv4Address)
                    or not node.name or node.name != expected.name
                    or node.region != expected.region
                    or expected.firewall_selector_tag != reviewed.selector_tag):
                raise ValueError("applied node identity differs")
        if (proof.provider_membership_verified is not True
                or proof.host_policy_verified is not False
                or proof.state_sha256 != attachment.state_sha256
                or proof.firewall_id != attachment.firewall_id
                or len(proof.verified_droplet_ids) != len(attachment.nodes)
                or set(proof.verified_droplet_ids) != {node.droplet_id for node in attachment.nodes}
                or type(proof.attempts) is not int or not 1 <= proof.attempts <= 12):
            raise ValueError("provider attachment proof differs")
        middles = reviewed.topology.get("middles")
        groups = reviewed.topology.get("edge_groups")
        if not isinstance(middles, Mapping) or not isinstance(groups, Mapping):
            raise ValueError("reviewed topology is incomplete")
        topology_edges: dict[str, tuple[str, str]] = {}
        for group in groups.values():
            if (not isinstance(group, Mapping) or not isinstance(group.get("region"), str)
                    or not isinstance(group.get("middle_node"), str)
                    or not isinstance(group.get("ordinals"), list)):
                raise ValueError("reviewed edge group differs")
            for ordinal in group["ordinals"]:
                if type(ordinal) is not int or ordinal < 1:
                    raise ValueError("reviewed edge ordinal differs")
                key = f'{group["region"]}-{ordinal:02d}'
                if key in topology_edges:
                    raise ValueError("reviewed edge ordinal repeats")
                topology_edges[key] = (group["middle_node"], group["region"])
        if (set(middles) != {route.middle_node for route in reviewed.chain_routes}
                or set(topology_edges) != {key for route in reviewed.chain_routes for key in route.edge_nodes}
                or sum(1 + len(route.edge_nodes) for route in reviewed.chain_routes) != len(attachment.nodes)):
            raise ValueError("reviewed routes do not cover complete topology")
        projections = []
        for route in reviewed.chain_routes:
            chain = chain_by_id[route.chain_id]
            if (chain.engagement_id != reviewed.engagement_id or chain.status != "pending"
                    or chain.burned or chain.nodes or chain.deploy_job_id or chain.teardown_job_id
                    or chain.terraform_working_directory or chain.middle_provider != "digitalocean"
                    or chain.edge_provider != "digitalocean"
                    or chain.assigned_proxy != route.assigned_proxy
                    or route.assigned_proxy not in reviewed.proxy_egress_ips
                    or not isinstance(chain.edge_intents, list)
                    or chain.edge_count != len(route.edge_nodes)
                    or len(chain.edge_intents) != len(route.edge_nodes)
                    or not route.edge_nodes or len(set(route.edge_nodes)) != len(route.edge_nodes)):
                raise ValueError("pending chain differs from reviewed route")
            middle_topology = middles.get(route.middle_node)
            if (not isinstance(middle_topology, Mapping)
                    or middle_topology.get("region") != chain.middle_region
                    or type(middle_topology.get("ordinal")) is not int
                    or middle_topology["ordinal"] < 1):
                raise ValueError("middle region differs from reviewed chain")
            middle_address = f'digitalocean_droplet.middle["{route.middle_node}"]'
            middle = nodes_by_address[middle_address]
            if middle.region != chain.middle_region or reviewed.nodes[middle_address].size != chain.middle_size:
                raise ValueError("middle intent differs from reviewed chain")
            selected_edges = []
            edge_ids = []
            for index, key in enumerate(route.edge_nodes, 1):
                edge_intent = chain.edge_intents[index - 1]
                expected_edge = topology_edges.get(key)
                address = f'digitalocean_droplet.edge["{key}"]'
                edge = nodes_by_address[address]
                if (not isinstance(edge_intent, Mapping)
                        or edge_intent.get("id") != f"edge-{index:02d}"
                        or edge_intent.get("provider") != "digitalocean"
                        or edge_intent.get("region") != edge.region
                        or edge_intent.get("size") != chain.edge_size
                        or expected_edge != (route.middle_node, edge.region)
                        or reviewed.nodes[address].size != chain.edge_size):
                    raise ValueError("edge route differs from persisted intent")
                selected_edges.append(edge)
                edge_ids.append(edge_intent["id"])
            if chain.edge_region != selected_edges[0].region:
                raise ValueError("chain primary edge region differs")
            selected_proxy_ip = reviewed.proxy_egress_ips[route.assigned_proxy]
            policy = render_sketch_host_policy(
                Topology(
                    proxy_egress_ips={route.assigned_proxy: selected_proxy_ip},
                    middles={middle.name: Middle(middle.public_ipv4, route.assigned_proxy)},
                    edges={edge.name: Edge(edge.public_ipv4, middle.name) for edge in selected_edges},
                ),
                (),
            )
            middle_row = _node_row(middle, "middle", chain)
            middle_row.update({"componentId": "middle", "middleOrdinal": middle_topology["ordinal"]})
            rows = [middle_row]
            for index, (edge, edge_id) in enumerate(zip(selected_edges, edge_ids), 1):
                row = _node_row(edge, "edge", chain)
                row.update({"componentId": edge_id, "edgeId": edge_id,
                            "edgeIndex": str(index), "edgeCount": str(len(selected_edges))})
                rows.append(row)
            if set(policy) != {row["hostname"] for row in rows}:
                raise ValueError("host policy does not cover projected nodes")
            projections.append(ProjectedProviderKeyedChain(
                replace(chain, nodes=rows), policy, selected_proxy_ip,
            ))
        return tuple(projections)
    except Exception:
        raise ProviderKeyedChainProjectionError("reviewed chain projection differs from applied evidence") from None


def _node_row(node: ExpectedDigitalOceanNode, role: str, chain: StoredSketchChain) -> dict[str, object]:
    return {
        "chainId": chain.chain_id, "role": role, "provider": "digitalocean",
        "hostname": node.name, "terraformAddress": node.address,
        "providerInstanceId": node.droplet_id, "region": node.region, "publicIp": node.public_ipv4,
        "assignedProxy": chain.assigned_proxy, "proxy": chain.assigned_proxy,
        "status": "pending",
    }
