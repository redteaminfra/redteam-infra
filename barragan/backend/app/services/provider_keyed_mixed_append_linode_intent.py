# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only intent for one Linode edge attached to a published DO middle.

The caller must authenticate the mixed initial publication first. This module
rechecks both retained raw provider states; it cannot authorize Terraform GO.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Mapping

from app.services.provider_keyed_linode_initial_plan_gate import LinodeNodeCreate
from app.services.provider_keyed_mixed_append_intent import (
    MixedAppendIntentError, _DO_NODE, _LINODE_MIDDLE, _SHARED_DO,
    _SHARED_LINODE, _read_state,
)


_LINODE_EDGE = re.compile(r'linode_instance\.edge\["([a-z0-9_-]+)"\]\Z')


@dataclass(frozen=True)
class MixedLinodeOnDigitalOceanAppendIntent:
    engagement_id: str
    core_job_id: str
    chain_id: str
    digitalocean_middle_address: str
    digitalocean_middle_id: str
    digitalocean_state_sha256: str
    linode_state_sha256: str
    retained_digitalocean_ids: tuple[tuple[str, str], ...]
    retained_linode_ids: tuple[tuple[str, str], ...]
    prior_trusted_ssh_cidrs: tuple[str, ...]
    trusted_ssh_cidrs: tuple[str, ...]
    new_edge_address: str
    new_edge: LinodeNodeCreate
    new_edge_ordinal: int
    nonsecret_varfile: dict


def compile_mixed_linode_on_digitalocean_append_intent(
    *, published_binding: Mapping[str, object], provider_states: Mapping[str, bytes],
    provider_state_sha256: Mapping[str, str],
    provider_resource_ids: Mapping[str, Mapping[str, str]],
    retained_linode_varfile: Mapping[str, object], selected_chain_id: str,
    edge_region: str, edge_type: str, edge_image: str, engagement_tag: str,
    admin_public_key: str,
) -> MixedLinodeOnDigitalOceanAppendIntent:
    """Compile an immutable one-edge delta from the exact published 2+2 state."""
    try:
        binding = published_binding
        if (not isinstance(binding, Mapping)
                or binding.get("schema") != "mixed-initial-host-binding-v1"
                or not isinstance(binding.get("engagementId"), str)
                or not isinstance(binding.get("coreJobId"), str)
                or not binding["engagementId"] or not binding["coreJobId"]
                or set(provider_states) != {"digitalocean", "linode"}
                or set(provider_state_sha256) != set(provider_states)
                or set(provider_resource_ids) != set(provider_states)
                or not isinstance(binding.get("nodes"), list)
                or len(binding["nodes"]) != 4
                or not isinstance(binding.get("providerStates"), list)
                or len(binding["providerStates"]) != 2
                or not isinstance(binding.get("chainIds"), list)
                or len(binding["chainIds"]) != 2
                or selected_chain_id not in binding["chainIds"]
                or set(binding.get("orderedProviders", [])) != set(provider_states)
                or not re.fullmatch(r"[a-z0-9-]+", edge_region)
                or not edge_type or not edge_image or not engagement_tag
                or not isinstance(admin_public_key, str) or not admin_public_key.strip()
                or not isinstance(retained_linode_varfile, Mapping)):
            raise ValueError("mixed append input")
        rows = binding["nodes"]
        if (len({(row["provider"], row["terraformAddress"]) for row in rows}) != 4
                or len({(row["provider"], row["providerInstanceId"]) for row in rows}) != 4):
            raise ValueError("mixed identities collide")
        provider_rows = {provider: [row for row in rows if row["provider"] == provider]
                         for provider in provider_states}
        receipts = {row["provider"]: row for row in binding["providerStates"]}
        if (any(len(provider_rows[provider]) != 2 for provider in provider_states)
                or len(receipts) != 2
                or any({row["chainId"] for row in provider_rows[provider]} != {chain_id}
                       or {row["role"] for row in provider_rows[provider]} != {"middle", "edge"}
                       for provider, chain_id in zip(binding["orderedProviders"],
                                                     binding["chainIds"], strict=True))):
            raise ValueError("mixed pairs differ")
        resources = {}
        for provider, shared in (("digitalocean", _SHARED_DO), ("linode", _SHARED_LINODE)):
            expected = {row["terraformAddress"] for row in provider_rows[provider]} | shared
            if receipts[provider]["stateSha256"] != provider_state_sha256[provider]:
                raise ValueError("mixed state receipt differs")
            resources[provider] = _read_state(
                provider_states[provider], provider_state_sha256[provider],
                provider_resource_ids[provider], expected, receipts[provider])
            for row in provider_rows[provider]:
                state_row = resources[provider][row["terraformAddress"]]
                ip = (state_row.get("ipv4_address") if provider == "digitalocean"
                      else state_row.get("ipv4"))
                if provider == "linode":
                    ip = ip[0] if isinstance(ip, list) and len(ip) == 1 else None
                if (str(state_row["id"]) != row["providerInstanceId"]
                        or state_row.get("name" if provider == "digitalocean" else "label")
                        != row["hostname"]
                        or state_row.get("region") != row["region"]
                        or ip != row["publicIp"]
                        or not ipaddress.IPv4Address(ip).is_global):
                    raise ValueError("mixed node differs from raw state")
        selected = [row for row in provider_rows["digitalocean"]
                    if row["chainId"] == selected_chain_id and row["role"] == "middle"]
        if len(selected) != 1 or _DO_NODE.fullmatch(selected[0]["terraformAddress"]).group(1) != "middle":
            raise ValueError("selected DO middle differs")
        middle_key = _DO_NODE.fullmatch(selected[0]["terraformAddress"]).group(2)
        tfvars = dict(retained_linode_varfile)
        trusted = tfvars.get("trusted_ssh_cidrs")
        if (not isinstance(trusted, list) or len(trusted) != 1
                or not isinstance(trusted[0], str)):
            raise ValueError("prior Linode SSH scope differs")
        original_source = ipaddress.IPv4Network(trusted[0], strict=True)
        selected_source = ipaddress.IPv4Network(selected[0]["publicIp"] + "/32", strict=True)
        if (original_source.prefixlen != 32 or not original_source.network_address.is_global
                or not selected_source.network_address.is_global
                or original_source == selected_source):
            raise ValueError("Linode SSH source is not exact")
        middles = tfvars.get("middles")
        groups = tfvars.get("edge_groups")
        if (not isinstance(middles, dict) or not isinstance(groups, dict)
                or tfvars.get("external_middle_nodes", []) != []
                or tfvars.get("linode_image") != edge_image
                or tfvars.get("edge_type") != edge_type
                or tfvars.get("engagement_name") != engagement_tag
                or not all(isinstance(group, dict)
                           and set(group) == {"region", "middle_node", "ordinals"}
                           and isinstance(group["ordinals"], list)
                           for group in groups.values())):
            raise ValueError("retained Linode topology differs")
        linode_rows = provider_rows["linode"]
        middle_matches = [row for row in linode_rows if row["role"] == "middle"]
        edge_matches = [row for row in linode_rows if row["role"] == "edge"]
        if len(middle_matches) != 1 or len(edge_matches) != 1:
            raise ValueError("retained Linode roles differ")
        middle_row, edge_row = middle_matches[0], edge_matches[0]
        retained_middle = _LINODE_MIDDLE.fullmatch(middle_row["terraformAddress"])
        retained_edge = _LINODE_EDGE.fullmatch(edge_row["terraformAddress"])
        ordinal_match = re.search(r"middle(\d+)-", middle_row["hostname"])
        if (retained_middle is None or retained_edge is None or ordinal_match is None
                or set(middles) != {retained_middle.group(1)}
                or middles[retained_middle.group(1)] != {
                    "region": middle_row["region"],
                    "ordinal": int(ordinal_match.group(1))}
                or resources["linode"][middle_row["terraformAddress"]].get("type")
                != tfvars.get("middle_type")
                or resources["linode"][edge_row["terraformAddress"]].get("type")
                != edge_type):
            raise ValueError("retained Linode node input differs")
        edge_key = retained_edge.group(1)
        covered = []
        for group in groups.values():
            if group["middle_node"] not in middles:
                raise ValueError("retained edge parent differs")
            for number in group["ordinals"]:
                if type(number) is not int or number < 1:
                    raise ValueError("retained ordinal differs")
                covered.append(f'{group["region"].lower()}-{number:02d}')
        if covered != [edge_key]:
            raise ValueError("retained edge group coverage differs")
        for row in linode_rows:
            state_row = resources["linode"][row["terraformAddress"]]
            if (state_row.get("image") != edge_image
                    or state_row.get("tags") != [engagement_tag]
                    or state_row.get("authorized_keys") != [admin_public_key]):
                raise ValueError("retained Linode node input differs")
        region_ordinals = []
        for row in rows:
            if row["role"] != "edge" or row["region"].lower() != edge_region:
                continue
            match = re.fullmatch(re.escape(edge_region) + r"-(\d+)",
                                 row["terraformAddress"].split('["', 1)[-1].removesuffix('"]'))
            if match is None:
                raise ValueError("regional edge key differs")
            region_ordinals.append(int(match.group(1)))
        ordinal = max(region_ordinals, default=0) + 1
        new_address = f'linode_instance.edge["{edge_region}-{ordinal:02d}"]'
        group_key = f'mixed_{edge_region.replace("-", "_")}_{ordinal:02d}'
        if (new_address in resources["linode"] or group_key in groups
                or middle_key in middles):
            raise ValueError("new edge or external parent collides")
        new = LinodeNodeCreate(
            f"edge-{engagement_tag}-{edge_region}-{ordinal:02d}",
            edge_image, edge_type, edge_region, engagement_tag, (admin_public_key,))
        return MixedLinodeOnDigitalOceanAppendIntent(
            binding["engagementId"], binding["coreJobId"], selected_chain_id,
            selected[0]["terraformAddress"], selected[0]["providerInstanceId"],
            provider_state_sha256["digitalocean"], provider_state_sha256["linode"],
            tuple(sorted(provider_resource_ids["digitalocean"].items())),
            tuple(sorted(provider_resource_ids["linode"].items())),
            (str(original_source),), (str(original_source), str(selected_source)),
            new_address, new, ordinal,
            {**tfvars, "edge_groups": {**groups, group_key: {
                "region": edge_region, "middle_node": middle_key, "ordinals": [ordinal]}},
             "external_middle_nodes": [middle_key],
             "trusted_ssh_cidrs": [str(original_source), str(selected_source)]},
        )
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
        raise MixedAppendIntentError("Linode append differs from published provider state") from exc
