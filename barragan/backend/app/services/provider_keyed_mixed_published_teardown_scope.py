# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only scope check for a published mixed initial generation.

This consumes an independently authenticated publication source and fresh,
state-backed provider observations. It does not reserve teardown, contact a
provider, or authorize destroy. The later appended six-node generation needs
its own joined publication source before it can use this boundary.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Mapping

from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_mixed_initial_host_binding import ProviderHostObservation
from app.services.provider_keyed_mixed_initial_publication_source import (
    MixedInitialPublicationSource,
)
from app.services.provider_keyed_mixed_partial_apply_source import _SHARED, _state


class MixedPublishedTeardownScopeAttention(ValueError):
    """Both exact provider scopes and published chain rows are not proved."""


def build_mixed_published_initial_teardown_scopes(
    source: MixedInitialPublicationSource, *,
    reviewed_policies: Mapping[str, dict],
    reviewed_chain_fingerprints: Mapping[str, str],
    observations: Mapping[str, ProviderHostObservation],
    workspaces: Mapping[str, Path],
    chains: Mapping[str, object],
) -> tuple[dict, dict]:
    """Require two complete retained states and four matching published nodes.

    The caller must reauthenticate ``source`` from the persisted publication
    journal and provide fresh observations under the teardown fence. These
    dictionaries are preview evidence only; a writer must recheck the source.
    """
    try:
        if type(source) is not MixedInitialPublicationSource:
            raise ValueError("mixed publication source is missing")
        order, chain_ids = source.ordered_providers, source.chain_ids
        if (len(order) != 2 or set(order) != {"linode", "digitalocean"}
                or len(chain_ids) != 2 or len(set(chain_ids)) != 2
                or set(reviewed_policies) != set(order)
                or set(reviewed_chain_fingerprints) != set(chain_ids)
                or set(observations) != set(order)
                or set(workspaces) != set(order)
                or workspaces[order[0]] == workspaces[order[1]]
                or set(chains) != set(chain_ids)
                or tuple(row.provider for row in source.provider_states) != order
                or len(source.host_rows) != 4):
            raise ValueError("mixed provider or chain membership differs")
        scopes = []
        seen_node_addresses = set()
        seen_node_ids = set()
        for provider, chain_id, published in zip(
                order, chain_ids, source.provider_states, strict=True):
            chain = chains[chain_id]
            policy = reviewed_policies[provider]
            observation = observations[provider]
            workspace = workspaces[provider]
            if (published.provider != provider
                    or type(observation) is not ProviderHostObservation
                    or type(observation.state_json) is not bytes
                    or not isinstance(workspace, Path) or not workspace.is_absolute()
                    or chain.engagement_id != source.engagement_id
                    or chain.chain_id != chain_id or chain.status != "deployed"
                    or chain.deploy_job_id != source.parent_job_id
                    or chain.teardown_job_id or chain.burned
                    or chain.middle_provider != provider
                    or chain.edge_provider != provider
                    or sketch_chain_intent_fingerprint(chain)
                    != reviewed_chain_fingerprints[chain_id]
                    or chain.terraform_working_directory != str(workspace)):
                raise ValueError("published chain or workspace differs")
            classification = observation.classification
            if (classification.provider != provider or classification.kind != "full"
                    or classification.state_sha256 != published.state_sha256
                    or classification.lineage != published.lineage
                    or classification.serial != published.serial
                    or tuple(sorted(classification.resource_ids)) != published.resource_ids
                    or hashlib.sha256(observation.state_json).hexdigest()
                    != published.state_sha256):
                raise ValueError("retained provider state differs")
            state, actual, cloud = _state(provider, policy, observation.state_json)
            if (state["lineage"] != published.lineage
                    or state["serial"] != published.serial
                    or tuple(sorted(cloud.items())) != published.resource_ids
                    or set(actual) != set(policy["nodes"]) | _SHARED[provider]):
                raise ValueError("complete reviewed resource set differs")
            expected_rows = [row for row in source.host_rows
                             if row.provider == provider and row.chain_id == chain_id]
            if (len(expected_rows) != 2
                    or {row.role for row in expected_rows} != {"middle", "edge"}
                    or type(chain.nodes) is not list or len(chain.nodes) != 2):
                raise ValueError("published host projection differs")
            projected = {(row.get("role"), row.get("terraformAddress")): row
                         for row in chain.nodes if type(row) is dict}
            if len(projected) != 2:
                raise ValueError("published host projection overlaps")
            for row in expected_rows:
                node = projected.get((row.role, row.terraform_address))
                if (node is None or node.get("status") != "deployed"
                        or node.get("chainId") != chain_id
                        or node.get("provider") != provider
                        or node.get("hostname") != row.hostname
                        or str(node.get("providerInstanceId")) != row.provider_instance_id
                        or node.get("publicIp") != row.public_ip
                        or node.get("assignedProxy") != row.assigned_proxy
                        or cloud.get(row.terraform_address) != row.provider_instance_id
                        or row.terraform_address in seen_node_addresses
                        or (provider, row.provider_instance_id) in seen_node_ids):
                    raise ValueError("published host identity differs")
                seen_node_addresses.add(row.terraform_address)
                seen_node_ids.add((provider, row.provider_instance_id))
            if chain.assigned_proxy != expected_rows[0].assigned_proxy:
                raise ValueError("published proxy binding differs")
            shared_kinds = {
                "local_file.ansible_inventory[0]": "local_file",
                "local_file.ssh_stanza[0]": "local_file",
                "linode_firewall.firewall": "firewall",
                "random_password.root_password": "random_password",
                "digitalocean_firewall.firewall": "firewall",
                "digitalocean_ssh_key.key": "ssh_key",
            }
            resource_kinds = {
                **{address: "instance" if provider == "linode" else "droplet"
                   for address in policy["nodes"]},
                **{address: shared_kinds[address] for address in _SHARED[provider]},
            }
            if set(resource_kinds) != set(actual):
                raise ValueError("published resource kind is unrecognized")
            scopes.append({
                "schema": "provider-keyed-v2", "provider": provider,
                "coreJobId": source.core_job_id, "corePlanId": source.core_plan_id,
                "revisionId": source.revision_id, "workspace": str(workspace),
                "stateSha256": published.state_sha256, "lineage": published.lineage,
                "serial": published.serial, "chainIds": [chain_id],
                "resources": [
                    {"address": address, "id": str(actual[address]["id"]),
                     "kind": resource_kinds[address]} for address in sorted(actual)
                ],
            })
        return tuple(scopes)
    except Exception:
        raise MixedPublishedTeardownScopeAttention(
            "published mixed provider scope requires exact review") from None
