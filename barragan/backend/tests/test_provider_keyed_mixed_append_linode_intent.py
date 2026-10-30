# Copyright (c) 2026, Oracle and/or its affiliates.
"""Exact retained state and opposite-provider edge allocation without cloud IO."""

import copy
import hashlib
import json

import pytest

from app.services.provider_keyed_mixed_append_intent import MixedAppendIntentError
from app.services.provider_keyed_mixed_append_linode_intent import (
    compile_mixed_linode_on_digitalocean_append_intent,
)
from app.services.provider_keyed_initial_teardown import _state_resources
from test_provider_keyed_mixed_append_intent import _raw, mixed_fixture


def _case():
    args = mixed_fixture()
    args.pop("retained_digitalocean_varfile")
    args.update(selected_chain_id="chain-do", edge_region="us-sea",
                edge_type="g6-nanode-1", edge_image="linode/ubuntu24.04",
                engagement_tag="e7c9a4d2", admin_public_key="ssh-ed25519 fixture")
    args.pop("edge_size")
    args.pop("selector_tag")
    linode = {
        'linode_instance.middle["middle_02"]': {
            "id": 1001, "label": "middle02-e7c9a4d2", "region": "us-sea",
            "ipv4": ["1.1.1.1"], "tags": ["e7c9a4d2"],
            "image": "linode/ubuntu24.04", "type": "g6-nanode-1",
            "authorized_keys": ["ssh-ed25519 fixture"],
        },
        'linode_instance.edge["us-sea-01"]': {
            "id": 1002, "label": "edge-e7c9a4d2-us-sea-01", "region": "us-sea",
            "ipv4": ["1.0.0.1"], "tags": ["e7c9a4d2"],
            "image": "linode/ubuntu24.04", "type": "g6-nanode-1",
            "authorized_keys": ["ssh-ed25519 fixture"],
        },
    }
    shared = {"linode_firewall.firewall": {"id": 2001},
              "random_password.root_password": {"id": "secret"},
              "local_file.ansible_inventory[0]": {"id": "linode-inventory"},
              "local_file.ssh_stanza[0]": {"id": "linode-stanza"}}
    args["provider_states"]["linode"] = _raw(linode | shared)
    args["provider_state_sha256"]["linode"] = hashlib.sha256(
        args["provider_states"]["linode"]).hexdigest()
    args["provider_resource_ids"]["linode"] = {
        address: str(value["id"]) for address, value in (linode | shared).items()}
    receipt = next(row for row in args["published_binding"]["providerStates"]
                   if row["provider"] == "linode")
    receipt["stateSha256"] = args["provider_state_sha256"]["linode"]
    edge_row = next(row for row in args["published_binding"]["nodes"]
                    if row["provider"] == "linode" and row["role"] == "edge")
    edge_row.update(terraformAddress='linode_instance.edge["us-sea-01"]',
                    hostname="edge-e7c9a4d2-us-sea-01", region="us-sea")
    args["retained_linode_varfile"] = {
        "middles": {"middle_02": {"region": "us-sea", "ordinal": 2}},
        "edge_groups": {"group_02_us_sea": {
            "region": "us-sea", "middle_node": "middle_02", "ordinals": [1]}},
        "linode_image": "linode/ubuntu24.04", "edge_type": "g6-nanode-1",
        "middle_type": "g6-nanode-1", "engagement_name": "e7c9a4d2",
        "trusted_ssh_cidrs": ["9.9.9.9/32"],
    }
    return args


def test_linode_edge_uses_engagement_wide_ordinal_and_exact_do_middle():
    args = _case()
    intent = compile_mixed_linode_on_digitalocean_append_intent(**args)
    assert compile_mixed_linode_on_digitalocean_append_intent(**copy.deepcopy(args)) == intent
    assert intent.digitalocean_middle_id == "do-middle"
    assert intent.new_edge_address == 'linode_instance.edge["us-sea-02"]'
    assert intent.new_edge_ordinal == 2
    assert intent.nonsecret_varfile["external_middle_nodes"] == ["middle_01"]
    assert intent.trusted_ssh_cidrs == ("9.9.9.9/32", "8.8.4.4/32")
    assert intent.nonsecret_varfile["edge_groups"]["mixed_us_sea_02"] == {
        "region": "us-sea", "middle_node": "middle_01", "ordinals": [2]}
    assert args["retained_linode_varfile"]["edge_groups"] == {
        "group_02_us_sea": {"region": "us-sea", "middle_node": "middle_02", "ordinals": [1]}}


def test_linode_edge_accepts_reverse_provider_order_without_identity_change():
    args = _case()
    args["published_binding"]["orderedProviders"].reverse()
    args["published_binding"]["chainIds"].reverse()
    args["published_binding"]["providerStates"].reverse()
    intent = compile_mixed_linode_on_digitalocean_append_intent(**args)
    assert intent.new_edge_address == 'linode_instance.edge["us-sea-02"]'
    assert intent.digitalocean_middle_id == "do-middle"


def test_provider_ids_are_scoped_to_provider_even_when_numeric_values_collide():
    args = _case()
    do_resources = _state_resources(json.loads(args["provider_states"]["digitalocean"]))
    middle = 'digitalocean_droplet.middle["middle_01"]'
    do_resources[middle]["id"] = "1001"  # Linode middle also has provider ID 1001.
    args["provider_states"]["digitalocean"] = _raw(do_resources)
    args["provider_state_sha256"]["digitalocean"] = hashlib.sha256(
        args["provider_states"]["digitalocean"]).hexdigest()
    args["provider_resource_ids"]["digitalocean"][middle] = "1001"
    next(row for row in args["published_binding"]["nodes"]
         if row["provider"] == "digitalocean" and row["role"] == "middle")[
             "providerInstanceId"] = "1001"
    next(row for row in args["published_binding"]["providerStates"]
         if row["provider"] == "digitalocean")["stateSha256"] = (
             args["provider_state_sha256"]["digitalocean"])
    intent = compile_mixed_linode_on_digitalocean_append_intent(**args)
    assert intent.digitalocean_middle_id == "1001"
    assert intent.new_edge_address == 'linode_instance.edge["us-sea-02"]'


@pytest.mark.parametrize("change", [
    "state_sha", "swapped_id", "swapped_middle", "retained_parent",
    "prior_external_parent", "broad_ssh", "wrong_image", "wrong_key",
    "stale_serial", "stale_lineage",
])
def test_linode_append_rejects_stale_or_unreviewed_source(change):
    args = copy.deepcopy(_case())
    if change == "state_sha":
        args["provider_state_sha256"]["digitalocean"] = "0" * 64
    elif change == "swapped_id":
        args["provider_resource_ids"]["linode"]['linode_instance.edge["us-sea-01"]'] = "wrong"
    elif change == "swapped_middle":
        args["published_binding"]["nodes"][0]["providerInstanceId"] = "wrong"
    elif change == "retained_parent":
        args["retained_linode_varfile"]["edge_groups"]["group_02_us_sea"]["middle_node"] = "middle_01"
    elif change == "prior_external_parent":
        args["retained_linode_varfile"]["external_middle_nodes"] = ["middle_01"]
    elif change == "broad_ssh":
        args["retained_linode_varfile"]["trusted_ssh_cidrs"] = ["0.0.0.0/0"]
    elif change == "wrong_image":
        args["edge_image"] = "linode/ubuntu22.04"
    elif change == "wrong_key":
        args["admin_public_key"] = "ssh-ed25519 wrong"
    elif change == "stale_serial":
        args["published_binding"]["providerStates"][1]["serial"] = 2
    elif change == "stale_lineage":
        args["published_binding"]["providerStates"][1]["lineage"] = (
            "22222222-2222-4222-8222-222222222222")
    with pytest.raises(MixedAppendIntentError):
        compile_mixed_linode_on_digitalocean_append_intent(**args)
