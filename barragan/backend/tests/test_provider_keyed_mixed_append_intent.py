# Copyright (c) 2026, Oracle and/or its affiliates.
"""Published mixed identity, both state seals, and regional append allocation."""

import copy
import hashlib
import json

import pytest

from app.services.provider_keyed_mixed_append_intent import (
    MixedAppendIntentError, compile_mixed_digitalocean_on_linode_append_intent,
)


def _raw(resources):
    grouped = {}
    for address, values in resources.items():
        kind, remainder = address.split(".", 1)
        name = remainder.split("[", 1)[0]
        key = remainder.split('["', 1)[1].removesuffix('"]') if '["' in remainder else None
        if "[0]" in remainder:
            key = 0
        grouped.setdefault((kind, name), []).append({
            **({"index_key": key} if key is not None else {}),
            "attributes": values,
        })
    return json.dumps({"version": 4, "terraform_version": "1.15.5", "serial": 1,
                       "lineage": "11111111-1111-4111-8111-111111111111",
                       "resources": [{"mode": "managed", "type": kind, "name": name,
                                      "instances": instances}
                                     for (kind, name), instances in grouped.items()]}).encode()


def mixed_fixture():
    do_nodes = {
        'digitalocean_droplet.middle["middle_01"]': {
            "id": "do-middle", "name": "middle01-e7c9a4d2", "region": "nyc3",
            "ipv4_address": "8.8.4.4", "tags": ["s12345678"], "ssh_keys": ["do-key"],
            "image": "ubuntu-24-04-x64", "size": "s-1vcpu-1gb-amd",
        },
        'digitalocean_droplet.edge["nyc3-01"]': {
            "id": "do-edge", "name": "edge-e7c9a4d2-nyc3-01", "region": "nyc3",
            "ipv4_address": "8.8.8.8", "tags": ["s12345678"], "ssh_keys": ["do-key"],
            "image": "ubuntu-24-04-x64", "size": "s-1vcpu-1gb-amd",
        },
    }
    linode_nodes = {
        'linode_instance.middle["middle_02"]': {
            "id": 1001, "label": "middle02-e7c9a4d2", "region": "us-sea",
            "ipv4": ["1.1.1.1"], "tags": ["e7c9a4d2"],
        },
        'linode_instance.edge["sfo3-01"]': {
            "id": 1002, "label": "edge-e7c9a4d2-sfo3-01", "region": "sfo3",
            "ipv4": ["1.0.0.1"], "tags": ["e7c9a4d2"],
        },
    }
    shared_do = {"digitalocean_firewall.firewall": {"id": "do-fw"},
                 "digitalocean_ssh_key.key": {"id": "do-key"},
                 "local_file.ansible_inventory[0]": {"id": "do-inventory"},
                 "local_file.ssh_stanza[0]": {"id": "do-stanza"}}
    shared_linode = {"linode_firewall.firewall": {"id": 2001},
                     "random_password.root_password": {"id": "secret"},
                     "local_file.ansible_inventory[0]": {"id": "linode-inventory"},
                     "local_file.ssh_stanza[0]": {"id": "linode-stanza"}}
    states = {"digitalocean": _raw(do_nodes | shared_do),
              "linode": _raw(linode_nodes | shared_linode)}
    ids = {provider: {address: str(value["id"]) for address, value in resources.items()}
           for provider, resources in (("digitalocean", do_nodes | shared_do),
                                       ("linode", linode_nodes | shared_linode))}
    sha = {provider: hashlib.sha256(raw).hexdigest() for provider, raw in states.items()}
    rows = []
    for provider, nodes, chain in (("digitalocean", do_nodes, "chain-do"),
                                   ("linode", linode_nodes, "chain-linode")):
        for address, value in nodes.items():
            role = "middle" if ".middle[" in address else "edge"
            rows.append({"chainId": chain, "provider": provider, "role": role,
                         "terraformAddress": address, "providerInstanceId": str(value["id"]),
                         "hostname": value["name" if provider == "digitalocean" else "label"],
                         "publicIp": value["ipv4_address"] if provider == "digitalocean"
                         else value["ipv4"][0], "region": value["region"]})
    binding = {"schema": "mixed-initial-host-binding-v1", "engagementId": "eng-one",
               "coreJobId": "job-one", "orderedProviders": ["digitalocean", "linode"],
               "chainIds": ["chain-do", "chain-linode"],
               "providerStates": [{"provider": provider, "stateSha256": digest,
                                   "lineage": "11111111-1111-4111-8111-111111111111",
                                   "serial": 1}
                                  for provider, digest in sha.items()], "nodes": rows}
    varfile = {"middles": {"middle_01": {"region": "nyc3", "ordinal": 1}},
               "edge_groups": {"group_01_nyc3": {"region": "nyc3",
                                                "middle_node": "middle_01",
                                                "ordinals": [1]}},
               "docean_image": "ubuntu-24-04-x64", "edge_size": "s-1vcpu-1gb-amd",
               "middle_size": "s-1vcpu-1gb-amd",
               "engagement_name": "e7c9a4d2", "firewall_selector_tag": "s12345678",
               "trusted_ssh_cidrs": ["9.9.9.9/32"]}
    args = {"published_binding": binding, "provider_states": states,
            "provider_state_sha256": sha, "provider_resource_ids": ids,
            "retained_digitalocean_varfile": varfile, "selected_chain_id": "chain-linode",
            "edge_region": "sfo3", "edge_size": "s-1vcpu-1gb-amd",
            "edge_image": "ubuntu-24-04-x64", "selector_tag": "s12345678"}
    return args


def test_cross_provider_edge_uses_engagement_wide_regional_ordinal():
    args = mixed_fixture()
    intent = compile_mixed_digitalocean_on_linode_append_intent(**args)
    assert intent.new_edge_address == 'digitalocean_droplet.edge["sfo3-01"]'
    assert intent.linode_middle_id == "1001"
    assert intent.nonsecret_varfile["external_middle_nodes"] == ["middle_02"]
    assert intent.prior_trusted_ssh_cidrs == ("9.9.9.9/32",)
    assert intent.trusted_ssh_cidrs == ("9.9.9.9/32", "1.1.1.1/32")
    assert intent.nonsecret_varfile["trusted_ssh_cidrs"] == ["9.9.9.9/32", "1.1.1.1/32"]
    assert intent.nonsecret_varfile["edge_groups"]["mixed_sfo3_01"] == {
        "region": "sfo3", "middle_node": "middle_02", "ordinals": [1]}
    assert args["retained_digitalocean_varfile"]["edge_groups"] == {
        "group_01_nyc3": {"region": "nyc3", "middle_node": "middle_01", "ordinals": [1]}}


def test_ordinal_counts_retained_do_edges_in_same_region_across_chains():
    args = mixed_fixture()
    args["edge_region"] = "nyc3"
    intent = compile_mixed_digitalocean_on_linode_append_intent(**args)
    assert intent.new_edge_address == 'digitalocean_droplet.edge["nyc3-02"]'


def test_provider_ids_are_scoped_to_provider_even_when_numeric_values_collide():
    args = mixed_fixture()
    do_middle = 'digitalocean_droplet.middle["middle_01"]'
    resources = json.loads(args["provider_states"]["digitalocean"])
    for resource in resources["resources"]:
        if resource["type"] == "digitalocean_droplet" and resource["name"] == "middle":
            resource["instances"][0]["attributes"]["id"] = "1001"
    raw = json.dumps(resources).encode()
    args["provider_states"]["digitalocean"] = raw
    digest = hashlib.sha256(raw).hexdigest()
    args["provider_state_sha256"]["digitalocean"] = digest
    args["provider_resource_ids"]["digitalocean"][do_middle] = "1001"
    next(row for row in args["published_binding"]["nodes"]
         if row["terraformAddress"] == do_middle)["providerInstanceId"] = "1001"
    next(row for row in args["published_binding"]["providerStates"]
         if row["provider"] == "digitalocean")["stateSha256"] = digest
    intent = compile_mixed_digitalocean_on_linode_append_intent(**args)
    assert intent.new_edge_address == 'digitalocean_droplet.edge["sfo3-01"]'
    assert intent.linode_middle_id == "1001"


@pytest.mark.parametrize("mutate", [
    lambda a: a["provider_state_sha256"].update(linode="0" * 64),
    lambda a: a["provider_resource_ids"]["digitalocean"].update(
        {'digitalocean_droplet.middle["middle_01"]': "swapped"}),
    lambda a: a["published_binding"]["nodes"][2].update(providerInstanceId="swapped"),
    lambda a: a["retained_digitalocean_varfile"].update(external_middle_nodes=["other"]),
    lambda a: a["retained_digitalocean_varfile"].update(trusted_ssh_cidrs=["0.0.0.0/0"]),
])
def test_stale_or_swapped_mixed_source_fails_closed(mutate):
    args = copy.deepcopy(mixed_fixture())
    mutate(args)
    with pytest.raises(MixedAppendIntentError):
        compile_mixed_digitalocean_on_linode_append_intent(**args)
