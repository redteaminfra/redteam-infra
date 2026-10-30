# Copyright (c) 2026, Oracle and/or its affiliates.
"""Pure, fail-closed gate for one channel-free DigitalOcean keyed edge append.

The caller supplies independently retained state and reviewed inputs. It must
bind this JSON to the saved plan file before apply and prove cloud/host state
afterward. Unknown peer IPs are accepted only with the audited v2 source.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Mapping

from app.services.provider_keyed_initial_plan_gate import (
    DigitalOceanInitialFirewallIntent,
    DigitalOceanNodeCreate,
    _COMPUTED_LOCAL,
    _INBOUND_SOURCE_UNKNOWN,
    _NODE_KNOWN_DEFAULTS,
    _NODE_UNKNOWN,
    _OUTBOUND_DEST_UNKNOWN,
    _inbound,
    _outbound,
    _same,
    _sorted_rules,
    _validate_policy_intent,
    _verify_audited_workspace,
)
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.terraform_plan_gate import TerraformPlanGateError, classify_saved_plan_actions


_NEW_EDGE = re.compile(r'^digitalocean_droplet\.edge\["[A-Za-z0-9._-]+"\]$')
_RETAINED_NODE = re.compile(r'^digitalocean_droplet\.(?:middle|edge)\["[A-Za-z0-9._-]+"\]$')
_FIREWALL = "digitalocean_firewall.firewall"
_KEY = "digitalocean_ssh_key.key"
_INVENTORY = "local_file.ansible_inventory[0]"
_SSH_STANZA = "local_file.ssh_stanza[0]"
_LOCAL = {_INVENTORY, _SSH_STANZA}
_NODE_SENSITIVE = {"backup_policy": [], "ssh_keys": [False], "tags": [False], "volume_ids": []}
_REVIEWED_VARIABLES = {
    "allowed_tcp_ports", "allowed_udp_ports", "docean_image", "edge_groups",
    "edge_size", "engagement_name", "firewall_selector_tag", "middle_size",
    "middles", "ssh_config_path", "ssh_priv_key_path",
    "ssh_pub_key_path", "trusted_ssh_cidrs",
}
_DEFAULTED_VARIABLES = {
    "edge_count_per_region": 1, "edge_regions": [], "external_middle_nodes": [],
    "middle_count": 1, "middle_region": None,
}


def require_digitalocean_keyed_edge_append_full_plan(
    saved_plan_json: str,
    *,
    workspace: ProviderKeyedWorkspace,
    retained_resources: Mapping[str, Mapping[str, object]],
    new_edge_address: str,
    new_edge: DigitalOceanNodeCreate,
    firewall: DigitalOceanInitialFirewallIntent,
    expected_inventory_content: str,
    reviewed_variables: Mapping[str, object],
) -> None:
    """Authorize only the observed Terraform 1.15.5 one-edge append shape.

    ``retained_resources`` is an independent snapshot of the owned Terraform
    state: address -> complete resource values. A caller must prove its state
    file hash/lineage, provider ownership, topology, and plan identity.
    """

    _verify_audited_workspace(workspace)
    _validate_policy_intent(firewall)
    if (not isinstance(new_edge_address, str) or not _NEW_EDGE.fullmatch(new_edge_address)
            or not isinstance(new_edge, DigitalOceanNodeCreate)
            or new_edge.firewall_selector_tag != firewall.selector_tag
            or not isinstance(expected_inventory_content, str) or not expected_inventory_content):
        raise TerraformPlanGateError("append reviewed edge or inventory intent is invalid")
    if (not isinstance(reviewed_variables, Mapping)
            or set(reviewed_variables) != _REVIEWED_VARIABLES):
        raise TerraformPlanGateError("append reviewed Terraform variables are incomplete")
    if not isinstance(retained_resources, Mapping):
        raise TerraformPlanGateError("append retained state is missing")
    prior_addresses = set(retained_resources)
    nodes = {address for address in prior_addresses if _RETAINED_NODE.fullmatch(address)}
    if (len(nodes) != 4 or sum(address.startswith("digitalocean_droplet.middle[") for address in nodes) != 2
            or sum(address.startswith("digitalocean_droplet.edge[") for address in nodes) != 2
            or prior_addresses != nodes | {_FIREWALL, _KEY} | _LOCAL
            or new_edge_address in prior_addresses
            or any(not isinstance(value, Mapping) for value in retained_resources.values())):
        raise TerraformPlanGateError("append retained resource set is not the reviewed two-chain pilot")
    key_id = retained_resources[_KEY].get("id")
    if not isinstance(key_id, str) or not key_id:
        raise TerraformPlanGateError("append retained SSH key ID is invalid")
    for address in nodes:
        node = retained_resources[address]
        if (not isinstance(node.get("id"), str) or not node["id"]
                or node.get("ssh_keys") != [key_id]
                or node.get("tags") != [firewall.selector_tag]):
            raise TerraformPlanGateError("append retained node identity or selector changed")
        _ipv4_host(node.get("ipv4_address"))
    try:
        plan = json.loads(saved_plan_json)
    except (TypeError, ValueError) as exc:
        raise TerraformPlanGateError("append saved plan is not JSON") from exc
    if (not isinstance(plan, dict) or plan.get("format_version") != "1.2"
            or plan.get("terraform_version") != "1.15.5"
            or plan.get("applyable") is not True or plan.get("complete") is not True
            or plan.get("errored") is not False or plan.get("resource_drift")
            or not isinstance(plan.get("resource_changes"), list)):
        raise TerraformPlanGateError("append saved plan version, status, or drift is invalid")
    variables = plan.get("variables")
    if (not isinstance(variables, dict)
            or set(variables) != _REVIEWED_VARIABLES | set(_DEFAULTED_VARIABLES) | {"do_pat"}
            or any(not _same(variables.get(name), {"value": reviewed_variables[name]})
                   for name in _REVIEWED_VARIABLES)
            or any(not _same(variables.get(name), {"value": value})
                   for name, value in _DEFAULTED_VARIABLES.items())):
        raise TerraformPlanGateError("append Terraform inputs differ from reviewed intent")
    prior = plan.get("prior_state")
    root = prior.get("values", {}).get("root_module") if isinstance(prior, dict) else None
    prior_items = root.get("resources") if isinstance(root, dict) else None
    if not isinstance(prior_items, list):
        raise TerraformPlanGateError("append saved plan omits retained state")
    _require_prior_state(prior_items, retained_resources)
    resources = plan["resource_changes"]
    expected = prior_addresses | {new_edge_address}
    by_address = {}
    for resource in resources:
        if (not isinstance(resource, dict) or not isinstance(resource.get("address"), str)
                or resource["address"] in by_address or resource["address"] not in expected
                or not isinstance(resource.get("change"), dict)):
            raise TerraformPlanGateError("append plan has unexpected or duplicate resource")
        by_address[resource["address"]] = resource
        _require_resource_metadata(resource)
    if set(by_address) != expected:
        raise TerraformPlanGateError("append plan omits a retained or new resource")
    for address in nodes | {_KEY}:
        change = by_address[address]["change"]
        if (classify_saved_plan_actions(change.get("actions")) != "no-op"
                or not _same(change.get("before"), dict(retained_resources[address]))
                or not _same(change.get("after"), dict(retained_resources[address]))
                or not _same(change.get("after_unknown"), {})
                or not _same(change.get("before_sensitive"),
                             _NODE_SENSITIVE if address in nodes else {})
                or not _same(change.get("after_sensitive"), change.get("before_sensitive"))):
            raise TerraformPlanGateError("append plan changes a retained node or SSH key")
    _require_new_edge(by_address[new_edge_address]["change"], new_edge, key_id)
    _require_firewall(by_address[_FIREWALL]["change"], retained_resources, firewall, nodes)
    _require_local(by_address[_INVENTORY]["change"], retained_resources[_INVENTORY],
                   expected_inventory_content, stanza=False)
    _require_local(by_address[_SSH_STANZA]["change"], retained_resources[_SSH_STANZA],
                   None, stanza=True)


def _require_prior_state(items: list, expected: Mapping[str, Mapping[str, object]]) -> None:
    seen = set()
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("address"), str):
            raise TerraformPlanGateError("append prior state resource is invalid")
        address = item["address"]
        if address in seen or address not in expected or item.get("mode") != "managed":
            raise TerraformPlanGateError("append prior state has unreviewed resource")
        _require_resource_metadata(item)
        seen.add(address)
        if not _same(item.get("values"), dict(expected[address])):
            raise TerraformPlanGateError("append prior state differs from retained state")
    if seen != set(expected):
        raise TerraformPlanGateError("append prior state omits retained resource")


def _require_resource_metadata(resource: dict) -> None:
    address = resource["address"]
    if address.startswith("digitalocean_droplet.middle["):
        kind, name, provider = "digitalocean_droplet", "middle", "registry.terraform.io/digitalocean/digitalocean"
    elif address.startswith("digitalocean_droplet.edge["):
        kind, name, provider = "digitalocean_droplet", "edge", "registry.terraform.io/digitalocean/digitalocean"
    elif address == _FIREWALL:
        kind, name, provider = "digitalocean_firewall", "firewall", "registry.terraform.io/digitalocean/digitalocean"
    elif address == _KEY:
        kind, name, provider = "digitalocean_ssh_key", "key", "registry.terraform.io/digitalocean/digitalocean"
    else:
        kind, name, provider = "local_file", "ansible_inventory" if address == _INVENTORY else "ssh_stanza", "registry.terraform.io/hashicorp/local"
    index = re.search(r'\["([^"\\]+)"\]$|\[(0)\]$', address)
    expected_index = (index.group(1) if index.group(1) is not None else 0) if index else None
    if (resource.get("mode") != "managed" or resource.get("type") != kind
            or resource.get("name") != name or resource.get("provider_name") != provider
            or resource.get("index") != expected_index):
        raise TerraformPlanGateError("append resource metadata differs from audited provider")


def _require_new_edge(change: dict, intent: DigitalOceanNodeCreate, key_id: str) -> None:
    if (classify_saved_plan_actions(change.get("actions")) != "create"
            or change.get("before", object()) is not None
            or change.get("before_sensitive") is not False
            or not _same(change.get("after_sensitive"), _NODE_SENSITIVE)):
        raise TerraformPlanGateError("append edge is not an exact create")
    if not all(isinstance(value, str) and value for value in (
        intent.name, intent.image, intent.size, intent.region, intent.firewall_selector_tag
    )):
        raise TerraformPlanGateError("append edge intent is incomplete")
    expected_after = {**_NODE_KNOWN_DEFAULTS, "name": intent.name, "image": intent.image,
                      "size": intent.size, "region": intent.region,
                      "ssh_keys": [key_id], "tags": [intent.firewall_selector_tag]}
    unknown = {**_NODE_UNKNOWN, "ssh_keys": [False]}
    if (not _same(change.get("after"), expected_after)
            or not _same(change.get("after_unknown"), unknown)):
        raise TerraformPlanGateError("append edge inputs or provider-computed fields differ")


def _require_firewall(
    change: dict, retained: Mapping[str, Mapping[str, object]],
    intent: DigitalOceanInitialFirewallIntent, node_addresses: set[str],
) -> None:
    before = change.get("before")
    after = change.get("after")
    if (classify_saved_plan_actions(change.get("actions")) != "update"
            or not _same(before, dict(retained[_FIREWALL]))
            or not isinstance(after, dict)):
        raise TerraformPlanGateError("append firewall update lacks retained identity")
    if (set(after) != set(before)
            or not _same({k: v for k, v in after.items() if k != "inbound_rule"},
                         {k: v for k, v in before.items() if k != "inbound_rule"})
            or after.get("name") != intent.name
            or after.get("tags") != [intent.selector_tag]
            or after.get("droplet_ids") is not None):
        raise TerraformPlanGateError("append firewall selector, egress, or metadata changed")
    peers = sorted({_ipv4_host(retained[address]["ipv4_address"]) for address in node_addresses})
    if len(peers) != len(node_addresses):
        raise TerraformPlanGateError("append retained peer IPs collide")
    public = [_inbound("tcp", port, ["0.0.0.0/0"]) for port in intent.public_tcp_ports]
    public += [_inbound("tcp", "22", list(intent.trusted_ssh_cidrs))]
    expected_before = [_inbound(proto, "1-65535", peers) for proto in ("icmp", "tcp", "udp")]
    expected_before += public
    if not _same(_sorted_rules(before.get("inbound_rule")), _sorted_rules(expected_before)):
        raise TerraformPlanGateError("append firewall prior ingress is not the reviewed baseline")
    expected_after = [_inbound(proto, "1-65535", []) for proto in ("icmp", "tcp", "udp")]
    for rule in expected_after:
        del rule["source_addresses"]
    expected_after += public
    if (not isinstance(after.get("inbound_rule"), list)
            or not _same(_sorted_rules(after["inbound_rule"]), _sorted_rules(expected_after))
            or not _same(after["inbound_rule"][:3], expected_after[:3])):
        raise TerraformPlanGateError("append firewall ingress is not the pinned unknown-peer expression")
    outbound = [_outbound(proto, "" if proto == "icmp" else "1-65535", "0.0.0.0/0")
                for proto in ("icmp", "tcp", "udp")]
    if not _same(_sorted_rules(after.get("outbound_rule")), _sorted_rules(outbound)):
        raise TerraformPlanGateError("append firewall egress differs from reviewed baseline")
    ingress_unknown = [
        {**_INBOUND_SOURCE_UNKNOWN, "source_addresses": True if index < 3 else [False]}
        for index in range(len(expected_after))
    ]
    outbound_known = [{**_OUTBOUND_DEST_UNKNOWN, "destination_addresses": [False]}
                      for _ in outbound]
    pending = before.get("pending_changes")
    if not isinstance(pending, list) or not all(isinstance(item, dict) for item in pending):
        raise TerraformPlanGateError("append firewall pending metadata is invalid")
    unknown = {"inbound_rule": ingress_unknown, "outbound_rule": outbound_known,
               "pending_changes": [{} for _ in pending], "tags": [False]}
    sensitive = {"inbound_rule": [
        {**_INBOUND_SOURCE_UNKNOWN, "source_addresses": [] if index < 3 else [False]}
        for index in range(len(expected_after))
    ], "outbound_rule": outbound_known, "pending_changes": [{} for _ in pending],
        "tags": [False]}
    before_sensitive = {"inbound_rule": [
        {**_INBOUND_SOURCE_UNKNOWN,
         "source_addresses": [False] * len(node_addresses) if index < 3 else [False]}
        for index in range(len(expected_after))
    ], "outbound_rule": outbound_known, "pending_changes": [{} for _ in pending],
        "tags": [False]}
    if (not _same(change.get("after_unknown"), unknown)
            or not _same(change.get("before_sensitive"), before_sensitive)
            or not _same(change.get("after_sensitive"), sensitive)):
        raise TerraformPlanGateError("append firewall unknown or sensitive policy differs")


def _require_local(change: dict, retained: Mapping[str, object], content: str | None,
                   *, stanza: bool) -> None:
    before = change.get("before")
    after = change.get("after")
    if (change.get("actions") != ["delete", "create"]
            or change.get("replace_paths") != [["content"]]
            or not _same(before, dict(retained)) or not isinstance(after, dict)
            or not _same(change.get("before_sensitive"), {"sensitive_content": True})
            or not _same(change.get("after_sensitive"), {"sensitive_content": True})):
        raise TerraformPlanGateError("append local artifact replacement differs")
    stable = {key: retained[key] for key in (
        "content_base64", "directory_permission", "file_permission", "filename",
        "sensitive_content", "source",
    ) if key in retained}
    if len(stable) != 6 or stable["file_permission"] != "0600":
        raise TerraformPlanGateError("append retained local artifact metadata is invalid")
    expected_after = stable if stanza else {**stable, "content": content}
    expected_unknown = {**_COMPUTED_LOCAL, **({"content": True} if stanza else {})}
    if (not _same(after, expected_after)
            or not _same(change.get("after_unknown"), expected_unknown)):
        raise TerraformPlanGateError("append local artifact has unreviewed content or path")


def _ipv4_host(ip: object) -> str:
    try:
        if not isinstance(ip, str):
            raise ValueError("not an IPv4 address")
        address = ipaddress.IPv4Address(ip)
    except ValueError as exc:
        raise TerraformPlanGateError("append retained peer IP is invalid") from exc
    return f"{address}/32"
