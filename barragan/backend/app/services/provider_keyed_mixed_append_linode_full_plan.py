# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only, pinned-source gate for one Linode edge on a published DO middle.

This validates plan JSON. The caller must still bind it to the saved binary,
recheck the published generation and worker lease, and journal one-shot Apply.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Mapping

from app.services.provider_keyed_initial_plan_gate import _same
from app.services.provider_keyed_linode_initial_plan_gate import (
    _REAL_NODE_STATIC_SHA256, _SOURCE_REVISION,
)
from app.services.provider_keyed_mixed_append_linode_intent import (
    MixedLinodeOnDigitalOceanAppendIntent,
)
from app.services.provider_keyed_mixed_append_linode_plan_preflight import (
    require_mixed_linode_append_retained_plan_preflight, _FIREWALL_BEFORE_SENSITIVE,
)
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.terraform_plan_gate import TerraformPlanGateError


_DEFAULTS = {
    "middle_region": None, "edge_regions": [], "middle_count": 1,
    "edge_count_per_region": 1,
}
_NEW_EDGE_UNKNOWN = "d2ebbe05dc7ef963232c3b91aa8ed7edd209f6b7a56d1611973f6ea4c0eea468"
_NEW_EDGE_SENSITIVE = "8fe50ab3bb4b94d1bb49ecb89ea269fdf7386232c077c5bae96aaefa98e474cd"
_FIREWALL_UNKNOWN = "06d89c8d9ce49f589f1a9b86d0fd24926787bfa14ca5acd5628eeaf797a46ea4"
_FIREWALL_AFTER_SENSITIVE = "5435a628623e2931e4edc9823b086f82a93c9b8c4f3bef7bf031603bb3a0724d"


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require_mixed_linode_append_full_plan(
    saved_plan_json: str, *, workspace: ProviderKeyedWorkspace,
    intent: MixedLinodeOnDigitalOceanAppendIntent,
    digitalocean_state_json: bytes, linode_state_json: bytes,
    reviewed_variables: Mapping[str, object],
) -> None:
    """Require an exact one-edge plan without authorizing its execution."""
    require_mixed_linode_append_retained_plan_preflight(
        saved_plan_json, workspace=workspace, intent=intent,
        digitalocean_state_json=digitalocean_state_json,
        linode_state_json=linode_state_json)
    if (not isinstance(reviewed_variables, Mapping)
            or set(reviewed_variables) != set(intent.nonsecret_varfile)
            or any(not _same(reviewed_variables[key], value)
                   for key, value in intent.nonsecret_varfile.items())
            or reviewed_variables.get("allowed_tcp_ports") != ["22", "80", "443", "2222"]
            or (workspace.source_revision == _SOURCE_REVISION
                and reviewed_variables.get("allowed_udp_ports") != [])
            or reviewed_variables.get("trusted_ssh_cidrs") != list(intent.trusted_ssh_cidrs)):
        raise TerraformPlanGateError("Linode append reviewed inputs differ")
    plan = json.loads(saved_plan_json)
    variables = plan.get("variables")
    if (type(variables) is not dict
            or set(variables) != set(reviewed_variables) | set(_DEFAULTS) | {"linode_api_token"}
            or any(not _same(variables.get(key), {"value": value})
                   for key, value in {**reviewed_variables, **_DEFAULTS}.items())
            or not isinstance(variables.get("linode_api_token"), dict)
            or set(variables["linode_api_token"]) != {"value"}
            or not isinstance(variables["linode_api_token"]["value"], str)
            or not variables["linode_api_token"]["value"]):
        raise TerraformPlanGateError("Linode append Terraform variables differ")
    changes = {row["address"]: row["change"] for row in plan["resource_changes"]}
    prior = {row["address"]: row["values"] for row in
             plan["prior_state"]["values"]["root_module"]["resources"]}
    new = changes[intent.new_edge_address]
    after = new.get("after")
    retained_edge = next(address for address in prior if address.startswith("linode_instance.edge["))
    expected_node = intent.new_edge
    if (new.get("before", object()) is not None or new.get("before_sensitive") is not False
            or type(after) is not dict
            or {key: after.get(key) for key in ("label", "image", "type", "region", "tags", "authorized_keys")}
            != {"label": expected_node.label, "image": expected_node.image,
                "type": expected_node.node_type, "region": expected_node.region,
                "tags": [expected_node.tag], "authorized_keys": list(expected_node.authorized_keys)}
            or not _same(after.get("root_pass"), prior[retained_edge].get("root_pass"))
            or _digest({key: value for key, value in after.items()
                        if key not in {"label", "image", "type", "region", "tags",
                                       "authorized_keys", "root_pass"}}) != _REAL_NODE_STATIC_SHA256
            or _digest(new.get("after_unknown")) != _NEW_EDGE_UNKNOWN
            or _digest(new.get("after_sensitive")) != _NEW_EDGE_SENSITIVE):
        raise TerraformPlanGateError("Linode append new edge differs from retained inputs")
    firewall = changes["linode_firewall.firewall"]
    before = firewall.get("before")
    after_firewall = firewall.get("after")
    if (type(before) is not dict or type(after_firewall) is not dict
            or before != prior["linode_firewall.firewall"]
            or before.get("label") != f"fw-{expected_node.tag}-firewall"
            or before.get("tags") != [expected_node.tag]
            or before.get("inbound_policy") != "DROP"
            or before.get("outbound_policy") != "ACCEPT"
            or type(before.get("inbound")) is not list or len(before["inbound"]) != 10
            or type(before.get("linodes")) is not list or len(before["linodes"]) != 2):
        raise TerraformPlanGateError("Linode append retained firewall differs")
    retained_ids = sorted(int(prior[address]["id"]) for address in prior
                          if address.startswith("linode_instance."))
    retained_ips = {f'{prior[address]["ipv4"][0]}/32' for address in prior
                    if address.startswith("linode_instance.")}
    if (sorted(before["linodes"]) != retained_ids
            or [rule.get("label") for rule in before["inbound"]]
            != ["allow-tcp-80", "allow-tcp-443", "allow-tcp-2222",
                "allow-tcp-22-trusted", *[f"allow-{expected_node.tag}-host-{proto}"
                                           for proto in ("tcp", "udp", "icmp")],
                "block-ipv6-tcp", "block-ipv6-udp", "block-ipv6-icmp"]
            or [rule.get("ipv4") for rule in before["inbound"][:4]]
            != [["0.0.0.0/0"]] * 3 + [list(intent.prior_trusted_ssh_cidrs)]
            or any(type(rule.get("ipv4")) is not list or len(rule["ipv4"]) != 2
                   or set(rule["ipv4"]) != retained_ips
                   for rule in before["inbound"][4:7])):
        raise TerraformPlanGateError("Linode append prior firewall is not the retained policy")
    expected_firewall = copy.deepcopy(before)
    for computed in ("fingerprint", "updated", "version"):
        expected_firewall.pop(computed, None)
    expected_firewall["linodes"].append(None)
    expected_firewall["inbound"][3]["ipv4"] = list(intent.trusted_ssh_cidrs)
    for rule in expected_firewall["inbound"][4:7]:
        rule.pop("ipv4", None)
    if (after_firewall != expected_firewall
            or _digest(firewall.get("after_unknown")) != _FIREWALL_UNKNOWN
            or _digest(firewall.get("before_sensitive")) != _FIREWALL_BEFORE_SENSITIVE
            or _digest(firewall.get("after_sensitive")) != _FIREWALL_AFTER_SENSITIVE):
        raise TerraformPlanGateError("Linode append firewall has unreviewed delta")
    for address in ("local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]"):
        local = changes[address]
        if (local.get("after", object()) is not None or local.get("after_unknown") != {}
                or local.get("before_sensitive") != {"sensitive_content": True}
                or local.get("after_sensitive") is not False):
            raise TerraformPlanGateError("Linode append local artifact differs")
    _require_outputs(plan, linode_state_json, intent, reviewed_variables)


def _require_outputs(
    plan: dict, state_json: bytes, intent: MixedLinodeOnDigitalOceanAppendIntent,
    reviewed_variables: Mapping[str, object],
) -> None:
    try:
        state_outputs = json.loads(state_json)["outputs"]
        prior_outputs = plan["prior_state"]["values"]["outputs"]
        changes = plan["output_changes"]
    except (ValueError, KeyError, TypeError) as exc:
        raise TerraformPlanGateError("Linode append outputs are malformed") from exc
    unchanged = {
        "good-bye", "middle_instance_ids", "middle_nodes", "middle_public_ips",
        "root-password", "root-password-retrieval",
    }
    expected = unchanged | {"edge_instance_ids", "edge_nodes", "edge_public_ips",
                            "public-key", "run-ansible"}
    if (type(state_outputs) is not dict or type(prior_outputs) is not dict
            or type(changes) is not dict or set(state_outputs) != expected
            or set(prior_outputs) != expected or set(changes) != expected):
        raise TerraformPlanGateError("Linode append output inventory differs")
    for name in expected:
        state = state_outputs[name]
        prior = prior_outputs[name]
        change = changes[name]
        if (type(state) is not dict or type(prior) is not dict or type(change) is not dict
                or (name not in {"public-key", "run-ansible"}
                    and not _same(prior.get("value"), state.get("value")))
                or not _same(change.get("before"), state.get("value"))
                or change.get("before_sensitive") != (name == "root-password")
                or change.get("after_sensitive") != (name == "root-password")):
            raise TerraformPlanGateError("Linode append prior output differs")
    for name in unchanged:
        change = changes[name]
        if (change.get("actions") != ["no-op"]
                or not _same(change.get("after"), change.get("before"))
                or change.get("after_unknown") is not False):
            raise TerraformPlanGateError("Linode append changes retained output")
    new_key = intent.new_edge_address.split('["', 1)[1].removesuffix('"]')
    old_edge_ids = state_outputs["edge_instance_ids"]["value"]
    old_edge_ips = state_outputs["edge_public_ips"]["value"]
    old_edge_nodes = state_outputs["edge_nodes"]["value"]
    prior_key = next(iter(old_edge_nodes), None) if type(old_edge_nodes) is dict else None
    external_middle = intent.digitalocean_middle_address.split('["', 1)[1].removesuffix('"]')
    if (type(old_edge_ids) is not list or len(old_edge_ids) != 1
            or type(old_edge_ips) is not list or len(old_edge_ips) != 1
            or type(old_edge_nodes) is not dict or len(old_edge_nodes) != 1
            or prior_key == new_key):
        raise TerraformPlanGateError("Linode append retained edge outputs differ")
    expected_deltas = {
        "edge_instance_ids": (old_edge_ids + [None], [False, True]),
        "edge_public_ips": (old_edge_ips + [None], [False, True]),
        "edge_nodes": ({**old_edge_nodes, new_key: {
            "label": intent.new_edge.label, "middle_node": external_middle}},
            {prior_key: {}, new_key: {"id": True, "public_ip": True}}),
    }
    for name, (after, unknown) in expected_deltas.items():
        change = changes[name]
        if (change.get("actions") != ["update"]
                or not _same(change.get("after"), after)
                or not _same(change.get("after_unknown"), unknown)):
            raise TerraformPlanGateError("Linode append edge output differs")
    pub_path = reviewed_variables.get("ssh_pub_key_path")
    config_path = reviewed_variables.get("ssh_config_path")
    engagement_name = reviewed_variables.get("engagement_name")
    if (not isinstance(pub_path, str) or not pub_path
            or not isinstance(config_path, str) or not config_path
            or not isinstance(engagement_name, str) or not engagement_name
            or not _same(changes["public-key"].get("after"), pub_path)
            or not _same(changes["run-ansible"].get("after"),
                "Run ansible to configure hosts with:\n\t"
                "ansible-playbook ../ansible/sketch-playbook.yml -i inventory.ini "
                f'-e "ssh_pub_key={pub_path}" -e "ssh_config_path={config_path}/{engagement_name}-sketch"')):
        raise TerraformPlanGateError("Linode append operator output path differs")
    for name in ("public-key", "run-ansible"):
        change = changes[name]
        action = "no-op" if change.get("after") == change.get("before") else "update"
        if (change.get("actions") != [action] or change.get("after_unknown") is not False
                or not _same(prior_outputs[name].get("value"), change.get("after"))):
            raise TerraformPlanGateError("Linode append operator output action differs")
