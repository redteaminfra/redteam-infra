# Copyright (c) 2026, Oracle and/or its affiliates.
"""Pure reservation proposal for two opposite-provider mixed edge appends.

The current shared topology writer accepts only local middles. This module
does not write that ledger or authorize a plan. It defines the exact external
middle and engagement-wide ordinal contract the writer must adopt first.
"""

from __future__ import annotations

from dataclasses import dataclass
from copy import deepcopy
import hashlib
import json
import re
from typing import Mapping

from app.services.provider_keyed_mixed_append_intent import MixedDigitalOceanOnLinodeAppendIntent
from app.services.provider_keyed_mixed_append_linode_intent import MixedLinodeOnDigitalOceanAppendIntent
from app.services.provider_keyed_mixed_initial_publication_source import MixedInitialPublicationSource


_MIDDLE = re.compile(r'(?:digitalocean_droplet|linode_instance)\.middle\["(middle_[0-9]+)"\]\Z')
_EDGE = re.compile(r'(?:digitalocean_droplet|linode_instance)\.edge\["([a-z0-9-]+)-([0-9]+)"\]\Z')


class MixedAppendReservationAttention(ValueError):
    """The published topology cannot reserve this opposite-provider pair."""


def _retained_ids_match_published(provider, published, retained):
    """Cloud publication IDs bind the complete compiler state independently."""
    saved, complete = dict(published), dict(retained)
    noncloud = {"local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]"}
    if provider == "linode":
        noncloud.add("random_password.root_password")
    return (len(saved) == len(published) and len(complete) == len(retained)
            and set(complete) - set(saved) <= noncloud
            and all(complete.get(address) == identifier for address, identifier in saved.items()))


@dataclass(frozen=True)
class MixedExternalEdgeReservation:
    provider: str
    chain_id: str
    edge_address: str
    edge_group_key: str
    edge_region: str
    edge_ordinal: int
    foreign_middle_provider: str
    foreign_middle_address: str
    foreign_middle_id: str
    foreign_middle_key: str
    prior_topology_sha256: str
    proposed_topology: dict


@dataclass(frozen=True)
class MixedAppendReservationProposal:
    reviewed_provider_order: tuple[str, str]
    original_high_water_sha256: str
    original_high_water: dict[str, int]
    original_topologies: dict[str, dict]
    proposed_high_water: dict[str, int]
    reservations: tuple[MixedExternalEdgeReservation, MixedExternalEdgeReservation]


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def propose_mixed_external_append_reservations(
    *, source: MixedInitialPublicationSource,
    binding_manifest: Mapping[str, object],
    digitalocean_intent: MixedDigitalOceanOnLinodeAppendIntent,
    linode_intent: MixedLinodeOnDigitalOceanAppendIntent,
    current_topologies: Mapping[str, Mapping[str, object]],
    regional_high_water: Mapping[str, int],
    reviewed_provider_order: tuple[str, str],
) -> MixedAppendReservationProposal:
    """Describe, without persisting, the only two legal external-middle additions.

    A future shared writer must atomically compare the original ledger and
    topology digests under its regional lock, then persist both proposals.
    Until it supports ``external_middles``, plan production remains closed.
    """
    try:
        intents = {"digitalocean": digitalocean_intent, "linode": linode_intent}
        if (type(source) is not MixedInitialPublicationSource
                or type(binding_manifest) is not dict
                or _digest(binding_manifest) != source.binding_manifest_sha256
                or binding_manifest.get("schema") != "mixed-initial-host-binding-v1"
                or binding_manifest.get("engagementId") != source.engagement_id
                or binding_manifest.get("coreJobId") != source.core_job_id
                or type(reviewed_provider_order) is not tuple
                or len(reviewed_provider_order) != 2
                or set(reviewed_provider_order) != set(intents)
                or set(current_topologies) != set(intents)
                or type(regional_high_water) is not dict
                or any(type(region) is not str or not region or type(value) is not int
                       or value < 0 for region, value in regional_high_water.items())
                or any(intent.engagement_id != source.engagement_id
                       or intent.core_job_id != source.core_job_id for intent in intents.values())
                or digitalocean_intent.digitalocean_state_sha256
                   != linode_intent.digitalocean_state_sha256
                or digitalocean_intent.linode_state_sha256
                   != linode_intent.linode_state_sha256
                or digitalocean_intent.retained_digitalocean_ids
                   != linode_intent.retained_digitalocean_ids
                or digitalocean_intent.retained_linode_ids
                   != linode_intent.retained_linode_ids):
            raise ValueError("mixed original generation differs")
        states = {row.provider: row for row in source.provider_states}
        if (set(states) != set(intents)
                or states["digitalocean"].state_sha256
                   != digitalocean_intent.digitalocean_state_sha256
                or states["linode"].state_sha256 != digitalocean_intent.linode_state_sha256
                or not _retained_ids_match_published("digitalocean",
                    states["digitalocean"].resource_ids, digitalocean_intent.retained_digitalocean_ids)
                or not _retained_ids_match_published("linode",
                    states["linode"].resource_ids, digitalocean_intent.retained_linode_ids)):
            raise ValueError("mixed provider states differ")
        rows = binding_manifest["nodes"]
        if type(rows) is not list or len(rows) != 4:
            raise ValueError("mixed published nodes differ")
        by_identity = {(row["chainId"], row["provider"], row["role"]): row for row in rows}
        if len(by_identity) != 4:
            raise ValueError("mixed published node identity collides")
        high_water = dict(regional_high_water)
        reservations = []
        for provider in reviewed_provider_order:
            intent = intents[provider]
            foreign = "linode" if provider == "digitalocean" else "digitalocean"
            local_chain = next((chain for chain, member in
                                zip(source.chain_ids, source.ordered_providers, strict=True)
                                if member == provider), None)
            local_middle = by_identity[(local_chain, provider, "middle")]
            local_edge = by_identity[(local_chain, provider, "edge")]
            selected = by_identity[(intent.chain_id, foreign, "middle")]
            foreign_address = (intent.linode_middle_address if provider == "digitalocean"
                               else intent.digitalocean_middle_address)
            foreign_id = (intent.linode_middle_id if provider == "digitalocean"
                          else intent.digitalocean_middle_id)
            foreign_match = _MIDDLE.fullmatch(foreign_address)
            edge_match = _EDGE.fullmatch(intent.new_edge_address)
            if (selected["terraformAddress"] != foreign_address
                    or selected["providerInstanceId"] != foreign_id
                    or foreign_match is None or edge_match is None
                    or intent.new_edge_ordinal != int(edge_match.group(2))
                    or not foreign_address.startswith(
                        "linode_instance." if foreign == "linode" else "digitalocean_droplet.")
                    or not intent.new_edge_address.startswith(
                        "digitalocean_droplet." if provider == "digitalocean" else "linode_instance.")):
                raise ValueError("selected foreign middle or new edge differs")
            region, ordinal = edge_match.group(1), int(edge_match.group(2))
            if ordinal != high_water.get(region, 0) + 1:
                raise ValueError("engagement-wide edge ordinal differs")
            prior = current_topologies[provider]
            if (type(prior) is not dict or prior.get("schema") != "provider-keyed-v2"
                    or set(prior) != {"schema", "middles", "edge_groups", "regional_high_water"}
                    or type(prior["middles"]) is not dict or len(prior["middles"]) != 1
                    or type(prior["edge_groups"]) is not dict or len(prior["edge_groups"]) != 1):
                raise ValueError("retained provider topology differs")
            local_middle_match = _MIDDLE.fullmatch(local_middle["terraformAddress"])
            local_edge_match = _EDGE.fullmatch(local_edge["terraformAddress"])
            if (local_middle_match is None or local_edge_match is None
                    or set(prior["middles"]) != {local_middle_match.group(1)}
                    or prior["middles"][local_middle_match.group(1)]
                       != {"region": local_middle["region"],
                           "ordinal": int(local_middle_match.group(1).rsplit("_", 1)[1])}
                    or type(prior["regional_high_water"]) is not dict
                    or any(type(value) is not int or value < 0
                           or value > regional_high_water.get(key, -1)
                           for key, value in prior["regional_high_water"].items())
                    or not any(group == {"region": local_edge["region"],
                                         "middle_node": local_middle_match.group(1),
                                         "ordinals": [int(local_edge_match.group(2))]}
                               for group in prior["edge_groups"].values())):
                raise ValueError("retained local middle or edge differs")
            requested = intent.nonsecret_varfile
            groups = requested.get("edge_groups")
            if (requested.get("middles") != prior["middles"]
                    or type(groups) is not dict
                    or len(groups) != len(prior["edge_groups"]) + 1
                    or any(groups.get(key) != value for key, value in prior["edge_groups"].items())
                    or requested.get("external_middle_nodes") != [foreign_match.group(1)]):
                raise ValueError("external middle input differs")
            new_keys = set(groups) - set(prior["edge_groups"])
            if len(new_keys) != 1:
                raise ValueError("new edge group differs")
            group_key = new_keys.pop()
            if groups[group_key] != {"region": region, "middle_node": foreign_match.group(1),
                                     "ordinals": [ordinal]}:
                raise ValueError("new edge group or ordinal differs")
            high_water[region] = ordinal
            proposed = {**prior,
                        "edge_groups": {**prior["edge_groups"], group_key: groups[group_key]},
                        "external_middles": {foreign_match.group(1): {
                            "provider": foreign, "chain_id": intent.chain_id,
                            "terraform_address": foreign_address,
                            "provider_instance_id": foreign_id}},
                        "regional_high_water": dict(high_water)}
            reservations.append(MixedExternalEdgeReservation(
                provider, intent.chain_id, intent.new_edge_address, group_key, region,
                ordinal, foreign, foreign_address, foreign_id, foreign_match.group(1),
                _digest(prior), proposed))
        return MixedAppendReservationProposal(
            reviewed_provider_order, _digest(regional_high_water),
            deepcopy(dict(regional_high_water)), deepcopy(dict(current_topologies)),
            high_water,
            tuple(reservations))
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise MixedAppendReservationAttention(
            "mixed external append needs an exact durable reservation") from exc
