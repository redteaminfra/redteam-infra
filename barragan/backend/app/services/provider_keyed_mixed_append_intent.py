# Copyright (c) 2026, Oracle and/or its affiliates.
"""Pure intent for one DigitalOcean edge on a published Linode middle.

The caller must authenticate the full mixed publication (the small unit-test
manifest is not a publication recognizer) and collect both raw state files
independently. This module never reads mutable database rows or runs a provider
command. An adapter, post-append source audit, and teardown scope that knows
the external-middle local-file deletions are required before dispatch.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
from typing import Mapping
from uuid import UUID

from app.services.provider_keyed_initial_plan_gate import DigitalOceanNodeCreate
from app.services.provider_keyed_initial_teardown import _state_resources


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_DO_NODE = re.compile(r'digitalocean_droplet\.(middle|edge)\["([a-z0-9_-]+)"\]\Z')
_LINODE_MIDDLE = re.compile(r'linode_instance\.middle\["([a-z0-9_-]+)"\]\Z')
_SHARED_DO = {"digitalocean_firewall.firewall", "digitalocean_ssh_key.key",
              "local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]"}
_SHARED_LINODE = {"linode_firewall.firewall", "random_password.root_password",
                  "local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]"}


class MixedAppendIntentError(ValueError):
    """The published mixed identity or retained provider topology is unproved."""


@dataclass(frozen=True)
class MixedDigitalOceanOnLinodeAppendIntent:
    engagement_id: str
    core_job_id: str
    chain_id: str
    linode_middle_address: str
    linode_middle_id: str
    digitalocean_state_sha256: str
    linode_state_sha256: str
    retained_digitalocean_ids: tuple[tuple[str, str], ...]
    retained_linode_ids: tuple[tuple[str, str], ...]
    prior_trusted_ssh_cidrs: tuple[str, ...]
    trusted_ssh_cidrs: tuple[str, ...]
    new_edge_address: str
    new_edge: DigitalOceanNodeCreate
    new_edge_ordinal: int
    nonsecret_varfile: dict


def _read_state(raw: bytes, expected_sha: str, expected_ids: Mapping[str, str],
                expected_addresses: set[str], receipt: Mapping[str, object]) -> dict[str, dict]:
    if (type(raw) is not bytes or type(expected_sha) is not str
            or _SHA.fullmatch(expected_sha) is None
            or hashlib.sha256(raw).hexdigest() != expected_sha
            or not isinstance(expected_ids, Mapping)
            or set(expected_ids) != expected_addresses
            or any(type(value) is not str or not value for value in expected_ids.values())):
        raise MixedAppendIntentError("mixed append state seal differs")
    try:
        state = json.loads(raw)
        if (type(state) is not dict or state.get("version") != 4
                or state.get("terraform_version") != "1.15.5"
                or type(state.get("serial")) is not int or state["serial"] < 1
                or state["serial"] != receipt.get("serial")
                or state.get("lineage") != receipt.get("lineage")):
            raise ValueError("state envelope")
        UUID(state["lineage"])
        resources = _state_resources(state)
    except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
        raise MixedAppendIntentError("mixed append state is invalid") from exc
    if (set(resources) != expected_addresses
            or any(values.get("id") is None or type(values.get("id")) is bool
                   for values in resources.values())
            or {address: str(values["id"]) for address, values in resources.items()}
            != dict(expected_ids)):
        raise MixedAppendIntentError("mixed append state resource identity differs")
    return resources


def compile_mixed_digitalocean_on_linode_append_intent(
    *, published_binding: Mapping[str, object], provider_states: Mapping[str, bytes],
    provider_state_sha256: Mapping[str, str],
    provider_resource_ids: Mapping[str, Mapping[str, str]],
    retained_digitalocean_varfile: Mapping[str, object], selected_chain_id: str,
    edge_region: str, edge_size: str, edge_image: str, selector_tag: str,
) -> MixedDigitalOceanOnLinodeAppendIntent:
    """Derive exactly one edge while retaining both published provider states.

    ``published_binding`` must already be authenticated against the terminal
    mixed publication. Its four node rows and provider state receipts are
    rechecked here against independent raw state bytes and resource IDs.
    """
    try:
        manifest = published_binding
        if (not isinstance(manifest, Mapping)
                or manifest.get("schema") != "mixed-initial-host-binding-v1"
                or type(manifest.get("engagementId")) is not str
                or type(manifest.get("coreJobId")) is not str
                or not manifest["engagementId"] or not manifest["coreJobId"]
                or set(provider_states) != {"digitalocean", "linode"}
                or set(provider_state_sha256) != set(provider_states)
                or set(provider_resource_ids) != set(provider_states)
                or type(manifest.get("nodes")) is not list or len(manifest["nodes"]) != 4
                or type(manifest.get("providerStates")) is not list
                or len(manifest["providerStates"]) != 2
                or type(manifest.get("chainIds")) is not list
                or len(manifest["chainIds"]) != 2
                or selected_chain_id not in manifest["chainIds"]
                or set(manifest.get("orderedProviders", [])) != set(provider_states)
                or type(edge_region) is not str or not re.fullmatch(r"[a-z0-9-]+", edge_region)
                or type(edge_size) is not str or not edge_size
                or type(edge_image) is not str or not edge_image
                or type(selector_tag) is not str or not selector_tag
                or not isinstance(retained_digitalocean_varfile, Mapping)):
            raise ValueError("mixed append input")
        rows = manifest["nodes"]
        addresses = [row["terraformAddress"] for row in rows]
        if (len(set(addresses)) != 4
                or len({(row["provider"], row["providerInstanceId"]) for row in rows}) != 4):
            raise ValueError("mixed node identities collide")
        provider_rows = {provider: [row for row in rows if row["provider"] == provider]
                         for provider in provider_states}
        if any(len(provider_rows[provider]) != 2 for provider in provider_states):
            raise ValueError("mixed pair")
        receipts = {row["provider"]: row for row in manifest["providerStates"]}
        if len(receipts) != 2:
            raise ValueError("mixed state receipts")
        resources = {}
        for provider, shared in (("digitalocean", _SHARED_DO), ("linode", _SHARED_LINODE)):
            expected = {row["terraformAddress"] for row in provider_rows[provider]} | shared
            receipt = receipts[provider]
            if receipt.get("stateSha256") != provider_state_sha256[provider]:
                raise ValueError("mixed state SHA")
            # The binding records provider state hashes; independent caller
            # IDs are checked against the raw state and all four bound nodes.
            resources[provider] = _read_state(
                provider_states[provider], provider_state_sha256[provider],
                provider_resource_ids[provider], expected, receipt)
            for row in provider_rows[provider]:
                address = row["terraformAddress"]
                state_row = resources[provider][address]
                if (str(state_row["id"]) != row["providerInstanceId"]
                        or state_row.get("label" if provider == "linode" else "name")
                        != row["hostname"]
                        or state_row.get("region") != row["region"]):
                    raise ValueError("mixed state node differs")
                ip = state_row.get("ipv4") if provider == "linode" else state_row.get("ipv4_address")
                if provider == "linode":
                    ip = ip[0] if type(ip) is list and len(ip) == 1 else None
                if ip != row["publicIp"] or not ipaddress.IPv4Address(ip).is_global:
                    raise ValueError("mixed state IP differs")
        selected = [row for row in provider_rows["linode"]
                    if row["chainId"] == selected_chain_id and row["role"] == "middle"]
        if len(selected) != 1 or _LINODE_MIDDLE.fullmatch(selected[0]["terraformAddress"]) is None:
            raise ValueError("selected Linode middle differs")
        middle_key = _LINODE_MIDDLE.fullmatch(selected[0]["terraformAddress"]).group(1)
        tfvars = dict(retained_digitalocean_varfile)
        prior_trusted = tfvars.get("trusted_ssh_cidrs")
        if (type(prior_trusted) is not list or len(prior_trusted) != 1
                or type(prior_trusted[0]) is not str):
            raise ValueError("prior DO trusted SSH scope differs")
        prior_network = ipaddress.IPv4Network(prior_trusted[0], strict=True)
        middle_network = ipaddress.IPv4Network(f'{selected[0]["publicIp"]}/32', strict=True)
        if (prior_network.prefixlen != 32 or not prior_network.network_address.is_global
                or middle_network.prefixlen != 32
                or not middle_network.network_address.is_global
                or prior_network == middle_network):
            raise ValueError("mixed SSH source is not exact")
        trusted = (str(prior_network), str(middle_network))
        groups = tfvars.get("edge_groups")
        middles = tfvars.get("middles")
        if (type(groups) is not dict or type(middles) is not dict
                or tfvars.get("external_middle_nodes", []) != []
                or tfvars.get("firewall_selector_tag") != selector_tag
                or tfvars.get("docean_image") != edge_image
                or tfvars.get("edge_size") != edge_size
                or any(type(group) is not dict or set(group) != {"region", "middle_node", "ordinals"}
                       or type(group["ordinals"]) is not list for group in groups.values())
                or any(_DO_NODE.fullmatch(row["terraformAddress"]) is None
                       for row in provider_rows["digitalocean"])):
            raise ValueError("retained DO topology differs")
        existing_keys = {address: _DO_NODE.fullmatch(address).group(2)
                         for address in (row["terraformAddress"] for row in provider_rows["digitalocean"])}
        if (set(middles) != {existing_keys[row["terraformAddress"]]
                            for row in provider_rows["digitalocean"] if row["role"] == "middle"}
                or tfvars.get("middle_size") != resources["digitalocean"][
                    next(row["terraformAddress"] for row in provider_rows["digitalocean"]
                         if row["role"] == "middle")].get("size")):
            raise ValueError("retained DO middle topology differs")
        group_edge_keys = []
        for group in groups.values():
            if group["middle_node"] not in middles:
                raise ValueError("existing DO edge parent differs")
            for ordinal in group["ordinals"]:
                if type(ordinal) is not int or ordinal < 1:
                    raise ValueError("existing DO ordinal differs")
                key = f'{group["region"].lower()}-{ordinal:02d}'
                if key not in existing_keys.values():
                    raise ValueError("existing DO edge key differs")
                group_edge_keys.append(key)
        if (len(group_edge_keys) != len(set(group_edge_keys))
                or set(group_edge_keys) != {existing_keys[row["terraformAddress"]]
                    for row in provider_rows["digitalocean"] if row["role"] == "edge"}):
            raise ValueError("retained DO edge group coverage differs")
        for row in provider_rows["digitalocean"]:
            value = resources["digitalocean"][row["terraformAddress"]]
            if (value.get("image") != edge_image
                    or value.get("size") != (tfvars["middle_size"] if row["role"] == "middle"
                                               else edge_size)
                    or value.get("tags") != [selector_tag]):
                raise ValueError("retained DO node inputs differ")
        all_edge_rows = [row for row in provider_rows["digitalocean"] if row["role"] == "edge"]
        regional = [row for row in all_edge_rows if row["region"].lower() == edge_region]
        ordinals = []
        for row in regional:
            key = row["terraformAddress"].split('["', 1)[-1].removesuffix('"]')
            match = re.fullmatch(re.escape(edge_region) + r"-(\d+)", key)
            if match is None:
                raise ValueError("regional edge key differs")
            ordinals.append(int(match.group(1)))
        ordinal = max(ordinals, default=0) + 1
        edge_key = f"{edge_region}-{ordinal:02d}"
        new_address = f'digitalocean_droplet.edge["{edge_key}"]'
        if new_address in resources["digitalocean"] or middle_key in middles:
            raise ValueError("new edge or external parent collides")
        group_key = f"mixed_{edge_region.replace('-', '_')}_{ordinal:02d}"
        if group_key in groups:
            raise ValueError("new edge group collides")
        engagement_name = tfvars.get("engagement_name")
        if type(engagement_name) is not str or not engagement_name:
            raise ValueError("engagement name missing")
        new = DigitalOceanNodeCreate(
            f"edge-{engagement_name}-{edge_region}-{ordinal:02d}",
            edge_image, edge_size, edge_region, selector_tag)
        return MixedDigitalOceanOnLinodeAppendIntent(
            manifest["engagementId"], manifest["coreJobId"], selected_chain_id,
            selected[0]["terraformAddress"], selected[0]["providerInstanceId"],
            provider_state_sha256["digitalocean"], provider_state_sha256["linode"],
            tuple(sorted(provider_resource_ids["digitalocean"].items())),
            tuple(sorted(provider_resource_ids["linode"].items())),
            tuple(prior_trusted), trusted,
            new_address, new, ordinal,
            {**tfvars, "edge_groups": {**groups, group_key: {
                "region": edge_region, "middle_node": middle_key, "ordinals": [ordinal]}},
             "external_middle_nodes": [middle_key],
             "trusted_ssh_cidrs": list(trusted)},
        )
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
        raise MixedAppendIntentError("mixed append differs from published provider state") from exc
