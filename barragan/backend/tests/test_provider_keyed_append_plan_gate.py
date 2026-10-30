# Copyright (c) 2026, Oracle and/or its affiliates.
"""Observed Terraform 1.15.5/DO 2.103.0 one-edge append plan boundary."""

import copy
import json
import re

import pytest

import app.services.provider_keyed_append_plan_gate as gate
import app.services.provider_keyed_initial_plan_gate as initial
from app.services.terraform_plan_gate import TerraformPlanGateError
from test_provider_keyed_initial_plan_gate import workspace  # audited source fixture


TAG = "a3d9c7e1f4b6"
NEW = 'digitalocean_droplet.edge["nyc3-02"]'
INTENT = initial.DigitalOceanNodeCreate(
    "edge-e7c9a4d2-nyc3-02", "ubuntu-22-04-x64", "s-1vcpu-1gb", "nyc3", TAG,
)
POLICY = initial.DigitalOceanInitialFirewallIntent(
    "opaque-firewall", TAG, ("80", "443", "2222"), (), ("192.0.2.10/32",),
)
INVENTORY = "reviewed inventory for one additional edge\n"
REVIEWED_VARIABLES = {
    "allowed_tcp_ports": ["22", "80", "443", "2222"],
    "allowed_udp_ports": [], "docean_image": INTENT.image,
    "edge_groups": {
        "sfo": {"region": "sfo3", "middle_node": "primary", "ordinals": [1]},
        "nyc": {"region": "nyc3", "middle_node": "secondary", "ordinals": [1, 2]},
    },
    "edge_size": INTENT.size,
    "engagement_name": "e7c9a4d2",
    "firewall_selector_tag": TAG,
    "middle_size": INTENT.size,
    "middles": {"primary": {"region": "sfo3", "ordinal": 1},
                "secondary": {"region": "nyc3", "ordinal": 2}},
    "ssh_config_path": "opaque-ssh-dir", "ssh_priv_key_path": "opaque-private-path",
    "ssh_pub_key_path": "opaque-public-path",
    "trusted_ssh_cidrs": ["192.0.2.10/32"],
}
NODES = {
    'digitalocean_droplet.middle["primary"]': "198.51.100.11",
    'digitalocean_droplet.middle["secondary"]': "198.51.100.12",
    'digitalocean_droplet.edge["nyc3-01"]': "198.51.100.13",
    'digitalocean_droplet.edge["sfo3-01"]': "198.51.100.14",
}


def _change(address, actions, before, after, unknown=None, sensitive=None, **extra):
    return {**_metadata(address), "change": {
        "actions": actions, "before": copy.deepcopy(before), "after": copy.deepcopy(after),
        "after_unknown": copy.deepcopy(unknown if unknown is not None else {}),
        "before_sensitive": False if before is None else copy.deepcopy(sensitive or {}),
        "after_sensitive": copy.deepcopy(sensitive or {}), **extra,
    }}


def _metadata(address):
    if address.startswith("digitalocean_droplet."):
        kind, name, provider = "digitalocean_droplet", address.split(".")[1].split("[")[0], "registry.terraform.io/digitalocean/digitalocean"
    elif address.startswith("digitalocean_firewall."):
        kind, name, provider = "digitalocean_firewall", address.split(".")[1], "registry.terraform.io/digitalocean/digitalocean"
    elif address.startswith("digitalocean_ssh_key."):
        kind, name, provider = "digitalocean_ssh_key", "key", "registry.terraform.io/digitalocean/digitalocean"
    else:
        kind, name, provider = "local_file", address.split(".")[1].split("[")[0], "registry.terraform.io/hashicorp/local"
    match = re.search(r'\["([^"\\]+)"\]$|\[(0)\]$', address)
    index = (match.group(1) if match.group(1) is not None else 0) if match else None
    return {"address": address, "mode": "managed", "type": kind,
            "name": name, "provider_name": provider, **({"index": index} if index is not None else {})}


def _fixture():
    peers = sorted(f"{ip}/32" for ip in NODES.values())
    public = [initial._inbound("tcp", port, ["0.0.0.0/0"])
              for port in ("2222", "443", "80")]
    public.insert(0, initial._inbound("tcp", "22", ["192.0.2.10/32"]))
    before_ingress = [initial._inbound(proto, "1-65535", peers)
                      for proto in ("icmp", "tcp", "udp")] + public
    after_ingress = [initial._inbound_unknown_peer(proto)
                     for proto in ("icmp", "tcp", "udp")] + public
    outbound = [initial._outbound(proto, "" if proto == "icmp" else "1-65535", "0.0.0.0/0")
                for proto in ("icmp", "tcp", "udp")]
    firewall = {
        "created_at": "opaque-time", "droplet_ids": None, "id": "firewall-id",
        "inbound_rule": before_ingress, "name": POLICY.name,
        "outbound_rule": outbound, "pending_changes": [{}, {}, {}, {}],
        "status": "succeeded", "tags": [TAG],
    }
    retained = {
        address: {"id": f"node-{index}", "ipv4_address": ip,
                  "ssh_keys": ["key-id"], "tags": [TAG]}
        for index, (address, ip) in enumerate(NODES.items(), start=1)
    }
    retained[gate._KEY] = {"id": "key-id", "name": "opaque-key"}
    retained[gate._FIREWALL] = firewall
    for address in gate._LOCAL:
        retained[address] = {
            "content": "old rendered artifact", "content_base64": None,
            "content_base64sha256": "old-hash", "content_base64sha512": "old-hash",
            "content_md5": "old-hash", "content_sha1": "old-hash",
            "content_sha256": "old-hash", "content_sha512": "old-hash",
            "directory_permission": "0777", "file_permission": "0600",
            "filename": "opaque-artifact", "id": "artifact-id",
            "sensitive_content": None, "source": None,
        }
    resources = [_change(address, ["no-op"], values, values,
                         sensitive=gate._NODE_SENSITIVE if address in NODES else {})
                 for address, values in retained.items()]
    fw_change = next(r["change"] for r in resources if r["address"] == gate._FIREWALL)
    fw_change["actions"] = ["update"]
    fw_change["after"] = {**firewall, "inbound_rule": after_ingress}
    fw_change["after_unknown"] = {
        "inbound_rule": [
            {**initial._INBOUND_SOURCE_UNKNOWN,
             "source_addresses": True if index < 3 else [False]}
            for index in range(7)
        ],
        "outbound_rule": [{**initial._OUTBOUND_DEST_UNKNOWN,
                           "destination_addresses": [False]} for _ in range(3)],
        "pending_changes": [{}, {}, {}, {}], "tags": [False],
    }
    fw_change["after_sensitive"] = {
        "inbound_rule": [
            {**initial._INBOUND_SOURCE_UNKNOWN,
             "source_addresses": [] if index < 3 else [False]}
            for index in range(7)
        ],
        "outbound_rule": fw_change["after_unknown"]["outbound_rule"],
        "pending_changes": [{}, {}, {}, {}], "tags": [False],
    }
    fw_change["before_sensitive"] = {
        "inbound_rule": [
            {**initial._INBOUND_SOURCE_UNKNOWN,
             "source_addresses": [False] * 4 if index < 3 else [False]}
            for index in range(7)
        ],
        "outbound_rule": fw_change["after_unknown"]["outbound_rule"],
        "pending_changes": [{}, {}, {}, {}], "tags": [False],
    }
    for resource in resources:
        if resource["address"] not in gate._LOCAL:
            continue
        c = resource["change"]
        c["actions"] = ["delete", "create"]
        c["replace_paths"] = [["content"]]
        c["before_sensitive"] = {"sensitive_content": True}
        c["after_sensitive"] = {"sensitive_content": True}
        c["after"] = {key: c["before"][key] for key in (
            "content_base64", "directory_permission", "file_permission", "filename",
            "sensitive_content", "source",
        )}
        if resource["address"] == gate._INVENTORY:
            c["after"]["content"] = INVENTORY
        c["after_unknown"] = {**initial._COMPUTED_LOCAL,
                              **({"content": True} if resource["address"] == gate._SSH_STANZA else {})}
    node_after = {**initial._NODE_KNOWN_DEFAULTS, "name": INTENT.name,
                  "image": INTENT.image, "size": INTENT.size, "region": INTENT.region,
                  "ssh_keys": ["key-id"], "tags": [TAG]}
    resources.append(_change(NEW, ["create"], None, node_after,
                             {**initial._NODE_UNKNOWN, "ssh_keys": [False]},
                             gate._NODE_SENSITIVE))
    plan = {
        "format_version": "1.2", "terraform_version": "1.15.5",
        "applyable": True, "complete": True, "errored": False,
        "prior_state": {"values": {"root_module": {"resources": [
            {**_metadata(address), "values": copy.deepcopy(values)}
            for address, values in retained.items()
        ]}}},
        "resource_changes": resources,
        "variables": {name: {"value": copy.deepcopy(value)}
                      for name, value in REVIEWED_VARIABLES.items()}
                     | {name: {"value": copy.deepcopy(value)}
                        for name, value in gate._DEFAULTED_VARIABLES.items()}
                     | {"do_pat": {"value": "redacted-test-token"}},
    }
    return plan, retained


def _check(workspace, plan, retained):
    gate.require_digitalocean_keyed_edge_append_full_plan(
        json.dumps(plan), workspace=workspace, retained_resources=retained,
        new_edge_address=NEW, new_edge=INTENT, firewall=POLICY,
        expected_inventory_content=INVENTORY,
        reviewed_variables=REVIEWED_VARIABLES,
    )


def _change_for(plan, address):
    return next(item["change"] for item in plan["resource_changes"]
                if item["address"] == address)


def test_accepts_one_observed_channel_free_edge_append(workspace):
    plan, retained = _fixture()
    assert len(REVIEWED_VARIABLES) == 13
    assert set(plan["variables"]) == set(REVIEWED_VARIABLES) | set(gate._DEFAULTED_VARIABLES) | {"do_pat"}
    _check(workspace, plan, retained)


@pytest.mark.parametrize("name,unexpected", [
    ("edge_count_per_region", 2), ("edge_regions", ["nyc3"]),
    ("external_middle_nodes", ["outside"]), ("middle_count", True),
    ("middle_region", "nyc3"),
])
def test_rejects_changed_rendered_default(workspace, name, unexpected):
    plan, retained = _fixture()
    plan["variables"][name]["value"] = unexpected
    with pytest.raises(TerraformPlanGateError, match="append Terraform inputs differ"):
        _check(workspace, plan, retained)


@pytest.mark.parametrize("name", sorted(gate._DEFAULTED_VARIABLES))
def test_rejects_missing_rendered_default(workspace, name):
    plan, retained = _fixture()
    del plan["variables"][name]
    with pytest.raises(TerraformPlanGateError, match="append Terraform inputs differ"):
        _check(workspace, plan, retained)


@pytest.mark.parametrize("location", ["reviewed", "plan"])
def test_rejects_extra_variable_even_if_terraform_could_ignore_it(workspace, location):
    plan, retained = _fixture()
    if location == "plan":
        plan["variables"]["unexpected"] = {"value": "value"}
    else:
        reviewed = {**REVIEWED_VARIABLES, "unexpected": "value"}
        with pytest.raises(TerraformPlanGateError, match="reviewed Terraform variables are incomplete"):
            gate.require_digitalocean_keyed_edge_append_full_plan(
                json.dumps(plan), workspace=workspace, retained_resources=retained,
                new_edge_address=NEW, new_edge=INTENT, firewall=POLICY,
                expected_inventory_content=INVENTORY,
                reviewed_variables=reviewed,
            )
        return
    with pytest.raises(TerraformPlanGateError, match="append Terraform inputs differ"):
        _check(workspace, plan, retained)


@pytest.mark.parametrize("mutate", [
    lambda p: _change_for(p, next(iter(NODES)))["actions"].__setitem__(0, "update"),
    lambda p: _change_for(p, NEW)["after"].__setitem__("image", "ubuntu-24-04-x64"),
    lambda p: _change_for(p, NEW)["after"].__setitem__("tags", ["other-tag"]),
    lambda p: _change_for(p, NEW)["after"].__setitem__("ssh_keys", ["wrong-key"]),
    lambda p: _change_for(p, gate._FIREWALL)["after"]["inbound_rule"][3]["source_addresses"].__setitem__(0, "0.0.0.0/0"),
    lambda p: _change_for(p, gate._FIREWALL)["after"]["outbound_rule"].append(initial._outbound("tcp", "22", "0.0.0.0/0")),
    lambda p: _change_for(p, gate._FIREWALL)["after_unknown"]["inbound_rule"][3].__setitem__("source_addresses", True),
    lambda p: _change_for(p, gate._FIREWALL)["after"].__setitem__("droplet_ids", ["new-id"]),
    lambda p: _change_for(p, gate._INVENTORY)["after"].__setitem__("content", "unreviewed inventory"),
    lambda p: _change_for(p, gate._SSH_STANZA)["after"].__setitem__("filename", "other-path"),
    lambda p: p.__setitem__("resource_drift", [{"address": NEW}]),
    lambda p: p["resource_changes"].append(_change("digitalocean_firewall.other", ["create"], None, {})),
    lambda p: p["variables"]["edge_groups"]["value"]["nyc"].__setitem__("middle_node", "primary"),
    lambda p: p["variables"]["ssh_priv_key_path"].__setitem__("value", "unreviewed-private-path"),
])
def test_rejects_unreviewed_append_drift(workspace, mutate):
    plan, retained = _fixture()
    mutate(plan)
    with pytest.raises(TerraformPlanGateError):
        _check(workspace, plan, retained)


def test_rejects_changed_independent_retained_state(workspace):
    plan, retained = _fixture()
    retained[next(iter(NODES))]["id"] = "another-node"
    with pytest.raises(TerraformPlanGateError):
        _check(workspace, plan, retained)
