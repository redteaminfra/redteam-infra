# Copyright (c) 2026, Oracle and/or its affiliates.
"""Pure mixed initial chain projection for the upstream Sketch bootstrap path."""

from __future__ import annotations

import ipaddress
from dataclasses import replace
from typing import Mapping

from app.services.provider_keyed_chain_projection import ProjectedProviderKeyedChain
from app.services.provider_keyed_host_policy import (
    Edge, Middle, Topology, render_sketch_host_policy,
)


class MixedInitialProjectionError(ValueError):
    """A bound mixed node cannot be projected into an isolated host route."""


def project_mixed_initial_chains(manifest: Mapping[str, object], chains: Mapping[str, object],
                                 reviewed_policy: Mapping[str, object]
                                 ) -> tuple[ProjectedProviderKeyedChain, ...]:
    """Create two controller-only route projections from exact bound nodes."""
    try:
        if (manifest.get("schema") != "mixed-initial-host-binding-v1"
                or set(chains) != set(manifest["chainIds"])
                or set(reviewed_policy) != set(manifest["orderedProviders"])
                or len(manifest["nodes"]) != 4):
            raise ValueError("mixed projection source differs")
        projected = []
        for provider, chain_id in zip(manifest["orderedProviders"], manifest["chainIds"]):
            chain = chains[chain_id]
            policy = reviewed_policy[provider]
            selected = [node for node in manifest["nodes"] if node["chainId"] == chain_id]
            middle = [node for node in selected if node["role"] == "middle"]
            edge = [node for node in selected if node["role"] == "edge"]
            trusted = policy["trusted_ssh_cidrs"]
            if (len(selected) != 2 or len(middle) != 1 or len(edge) != 1
                    or any(node["provider"] != provider
                           or node["assignedProxy"] != chain.assigned_proxy for node in selected)
                    or chain.status != "pending" or chain.nodes
                    or type(trusted) not in (list, tuple) or len(trusted) != 1):
                raise ValueError("mixed projection chain differs")
            network = ipaddress.IPv4Network(trusted[0], strict=True)
            if network.prefixlen != 32 or not network.network_address.is_global:
                raise ValueError("mixed proxy egress is unreviewed")
            proxy_ip = str(network.network_address)
            middle_node, edge_node = middle[0], edge[0]
            host_policies = render_sketch_host_policy(
                Topology(
                    proxy_egress_ips={chain.assigned_proxy: proxy_ip},
                    middles={middle_node["hostname"]: Middle(
                        middle_node["publicIp"], chain.assigned_proxy)},
                    edges={edge_node["hostname"]: Edge(
                        edge_node["publicIp"], middle_node["hostname"])},
                ), (),
            )
            rows = []
            for node in (middle_node, edge_node):
                row = {**node, "status": "pending", "proxy": chain.assigned_proxy,
                       "componentId": "middle" if node["role"] == "middle" else "edge-01"}
                if node["role"] == "middle":
                    row["middleOrdinal"] = policy["topology"]["middles"][policy["middle_key"]]["ordinal"]
                else:
                    row.update({"edgeId": "edge-01", "edgeIndex": "1", "edgeCount": "1"})
                rows.append(row)
            projected.append(ProjectedProviderKeyedChain(replace(chain, nodes=rows),
                                                           host_policies, proxy_ip))
        return tuple(projected)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise MixedInitialProjectionError("mixed bootstrap projection differs") from exc
