# Copyright (c) 2026, Oracle and/or its affiliates.
"""Saved-plan gate for a DO edge attached to a published Linode middle.

This checks a complete Terraform JSON plan against independent mixed state
evidence. An authentic Terraform 1.15.5 plan-only check confirms the
local-delete and firewall metadata shapes. This remains an offline gate:
the caller must bind the checked JSON to a saved binary, recheck state and
lease, and authorize one-shot Apply separately.
"""

from __future__ import annotations

import hashlib
import json
from typing import Mapping

from app.services.provider_keyed_append_plan_gate import (
    _DEFAULTED_VARIABLES, _FIREWALL, _INVENTORY, _KEY, _LOCAL,
    _NODE_SENSITIVE, _RETAINED_NODE, _REVIEWED_VARIABLES, _SSH_STANZA,
    _require_new_edge, _require_prior_state,
    _require_resource_metadata,
)
from app.services.provider_keyed_initial_plan_gate import (
    DigitalOceanInitialFirewallIntent, _INBOUND_SOURCE_UNKNOWN,
    _OUTBOUND_DEST_UNKNOWN, _inbound, _outbound, _same, _sorted_rules,
    _validate_policy_intent,
    _verify_audited_workspace,
)
from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_mixed_append_intent import (
    MixedDigitalOceanOnLinodeAppendIntent,
)
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.terraform_plan_gate import TerraformPlanGateError, classify_saved_plan_actions


def require_mixed_digitalocean_on_linode_append_full_plan(
    saved_plan_json: str, *, workspace: ProviderKeyedWorkspace,
    intent: MixedDigitalOceanOnLinodeAppendIntent,
    digitalocean_state_json: bytes, linode_state_json: bytes,
    firewall: DigitalOceanInitialFirewallIntent,
    reviewed_variables: Mapping[str, object],
) -> None:
    """Permit one edge create and the exact induced shared-resource delta.

    Both provider SHA and resource IDs are checked again, so a stale intent
    cannot authorize a plan against a different published generation.
    """
    _verify_audited_workspace(workspace)
    _validate_policy_intent(firewall)
    if (not isinstance(intent, MixedDigitalOceanOnLinodeAppendIntent)
            or type(digitalocean_state_json) is not bytes
            or type(linode_state_json) is not bytes
            or hashlib.sha256(digitalocean_state_json).hexdigest()
            != intent.digitalocean_state_sha256
            or hashlib.sha256(linode_state_json).hexdigest()
            != intent.linode_state_sha256
            or not isinstance(reviewed_variables, Mapping)
            or set(reviewed_variables) != _REVIEWED_VARIABLES | {"external_middle_nodes"}
            or any(not _same(reviewed_variables.get(key), value)
                   for key, value in intent.nonsecret_varfile.items())
            or reviewed_variables.get("external_middle_nodes") != [
                intent.linode_middle_address.split('["', 1)[1].removesuffix('"]')]
            or firewall.selector_tag != intent.new_edge.firewall_selector_tag
            or firewall.name != f"{reviewed_variables['engagement_name']}-firewall"
            or reviewed_variables.get("allowed_tcp_ports") != ["22", "80", "443", "2222"]
            or reviewed_variables.get("allowed_udp_ports") != []
            or firewall.trusted_ssh_cidrs != intent.trusted_ssh_cidrs
            or reviewed_variables.get("trusted_ssh_cidrs")
            != list(intent.trusted_ssh_cidrs)):
        raise TerraformPlanGateError("mixed append state or reviewed input changed")
    try:
        do_state = json.loads(digitalocean_state_json)
        linode_state = json.loads(linode_state_json)
        retained = _state_resources(do_state)
        linode = _state_resources(linode_state)
    except (ValueError, KeyError, TypeError) as exc:
        raise TerraformPlanGateError("mixed append retained state is invalid") from exc
    if ({key: str(value.get("id")) for key, value in retained.items()}
            != dict(intent.retained_digitalocean_ids)
            or {key: str(value.get("id")) for key, value in linode.items()}
            != dict(intent.retained_linode_ids)
            or str(linode.get(intent.linode_middle_address, {}).get("id"))
            != intent.linode_middle_id):
        raise TerraformPlanGateError("mixed append retained state identity changed")
    nodes = {address for address in retained if _RETAINED_NODE.fullmatch(address)}
    if (len(nodes) != 2 or len([a for a in nodes if ".middle[" in a]) != 1
            or len([a for a in nodes if ".edge[" in a]) != 1
            or set(retained) != nodes | {_FIREWALL, _KEY} | _LOCAL
            or intent.new_edge_address in retained):
        raise TerraformPlanGateError("mixed append retained DO topology differs")
    key_id = retained[_KEY].get("id")
    if (type(key_id) is not str or not key_id
            or any(retained[address].get("ssh_keys") != [key_id]
                   or retained[address].get("tags") != [firewall.selector_tag]
                   for address in nodes)):
        raise TerraformPlanGateError("mixed append retained key or selector differs")
    try:
        plan = json.loads(saved_plan_json)
    except (TypeError, ValueError) as exc:
        raise TerraformPlanGateError("mixed append saved plan is not JSON") from exc
    if (type(plan) is not dict or plan.get("format_version") != "1.2"
            or plan.get("terraform_version") != "1.15.5"
            or plan.get("applyable") is not True or plan.get("complete") is not True
            or plan.get("errored") is not False
            or type(plan.get("resource_changes")) is not list):
        raise TerraformPlanGateError("mixed append plan envelope or drift differs")
    effective = _require_completed_firewall_refresh(plan.get("resource_drift"), retained, nodes)
    refreshed = effective is not retained
    retained = effective
    variables = plan.get("variables")
    defaults = {**_DEFAULTED_VARIABLES,
                "external_middle_nodes": reviewed_variables["external_middle_nodes"]}
    if (type(variables) is not dict
            or set(variables) != _REVIEWED_VARIABLES | set(defaults) | {"do_pat"}
            or any(not _same(variables.get(key), {"value": reviewed_variables[key]})
                   for key in reviewed_variables)
            or any(not _same(variables.get(key), {"value": value})
                   for key, value in defaults.items())):
        raise TerraformPlanGateError("mixed append Terraform variables differ")
    prior = plan.get("prior_state")
    root = prior.get("values", {}).get("root_module") if type(prior) is dict else None
    items = root.get("resources") if type(root) is dict else None
    if type(items) is not list:
        raise TerraformPlanGateError("mixed append saved plan omits prior state")
    _require_prior_state(items, retained)
    expected = set(retained) | {intent.new_edge_address}
    by_address = {}
    for resource in plan["resource_changes"]:
        if (type(resource) is not dict or type(resource.get("address")) is not str
                or resource["address"] not in expected
                or resource["address"] in by_address
                or type(resource.get("change")) is not dict):
            raise TerraformPlanGateError("mixed append has unreviewed resource")
        _require_resource_metadata(resource)
        by_address[resource["address"]] = resource["change"]
    if set(by_address) != expected:
        raise TerraformPlanGateError("mixed append omits retained or new resource")
    for address in nodes | {_KEY}:
        change = by_address[address]
        if (classify_saved_plan_actions(change.get("actions")) != "no-op"
                or not _same(change.get("before"), retained[address])
                or not _same(change.get("after"), retained[address])
                or not _same(change.get("after_unknown"), {})
                or not _same(change.get("before_sensitive"),
                             _NODE_SENSITIVE if address in nodes else {})
                or not _same(change.get("after_sensitive"), change.get("before_sensitive"))):
            raise TerraformPlanGateError("mixed append changes retained DO node or key")
    _require_new_edge(by_address[intent.new_edge_address], intent.new_edge, key_id)
    _require_mixed_firewall(by_address[_FIREWALL], retained, firewall, nodes,
                            intent.prior_trusted_ssh_cidrs, refreshed=refreshed)
    for address in _LOCAL:
        change = by_address[address]
        if (classify_saved_plan_actions(change.get("actions")) != "delete"
                or not _same(change.get("before"), retained[address])
                or change.get("after", object()) is not None
                or not _same(change.get("after_unknown"), {})
                or not _same(change.get("before_sensitive"),
                             {"sensitive_content": True})
                or change.get("after_sensitive") is not False):
            raise TerraformPlanGateError("mixed append local artifact is not exact delete")


def _refresh_sensitive(attributes):
    return {
        "inbound_rule": [{**_INBOUND_SOURCE_UNKNOWN,
            "source_addresses": [False] * len(row["source_addresses"])}
            for row in attributes["inbound_rule"]],
        "outbound_rule": [{**_OUTBOUND_DEST_UNKNOWN,
            "destination_addresses": [False] * len(row["destination_addresses"])}
            for row in attributes["outbound_rule"]],
        "pending_changes": [{} for _ in attributes["pending_changes"]], "tags": [False],
        **({"droplet_ids": []} if attributes["droplet_ids"] == [] else {}),
    }


def _require_completed_firewall_refresh(drift, retained, nodes):
    """Accept only the observed completion of tag-selector attachment metadata."""
    if drift is None or drift == []:
        return retained
    try:
        if type(drift) is not list or len(drift) != 1 or type(drift[0]) is not dict:
            raise ValueError("unexpected drift")
        row = drift[0]
        if set(row) != {"address", "mode", "type", "name", "provider_name", "change"} or row["address"] != _FIREWALL:
            raise ValueError("unexpected drift resource")
        _require_resource_metadata(row)
        change = row["change"]
        before = retained[_FIREWALL]
        after = change["after"]
        node_ids = {int(retained[address]["id"]) for address in nodes}
        pending = before["pending_changes"]
        if (set(change) != {"actions", "before", "after", "after_unknown", "before_sensitive", "after_sensitive"}
                or change["actions"] != ["update"] or not _same(change["before"], before)
                or before["status"] != "waiting" or before["droplet_ids"] is not None
                or type(pending) is not list or len(pending) != len(node_ids)
                or any(type(item) is not dict or set(item) != {"droplet_id", "removing", "status"}
                       or type(item["droplet_id"]) is not int or item["removing"] is not False
                       or item["status"] != "waiting" for item in pending)
                or {item["droplet_id"] for item in pending} != node_ids
                or not _same(after, {**before, "droplet_ids": [], "pending_changes": [], "status": "succeeded"})
                or change["after_unknown"] != {}
                or not _same(change["before_sensitive"], _refresh_sensitive(before))
                or not _same(change["after_sensitive"], _refresh_sensitive(after))):
            raise ValueError("unreviewed firewall refresh")
        return {**retained, _FIREWALL: after}
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise TerraformPlanGateError("mixed append firewall refresh differs") from exc


def _require_mixed_firewall(
    change: dict, retained: Mapping[str, Mapping[str, object]],
    intent: DigitalOceanInitialFirewallIntent, node_addresses: set[str],
    prior_trusted_ssh_cidrs: tuple[str, ...],
    *, refreshed: bool = False,
) -> None:
    """Approve the selected Linode middle /32 as the sole new SSH source."""
    before = change.get("before")
    after = change.get("after")
    if (classify_saved_plan_actions(change.get("actions")) != "update"
            or not _same(before, retained[_FIREWALL])
            or type(after) is not dict or set(after) != set(before)
            or not _same({key: value for key, value in after.items()
                          if key != "inbound_rule"},
                         {key: value for key, value in before.items()
                          if key != "inbound_rule"})
            or after.get("name") != intent.name
            or after.get("tags") != [intent.selector_tag]
            or (after.get("droplet_ids") != [] if refreshed else after.get("droplet_ids") is not None)):
        raise TerraformPlanGateError("mixed append firewall identity or metadata changed")
    peers = sorted({f'{retained[address]["ipv4_address"]}/32' for address in node_addresses})
    if len(peers) != len(node_addresses):
        raise TerraformPlanGateError("mixed append retained peer IPs collide")
    public = [_inbound("tcp", port, ["0.0.0.0/0"]) for port in intent.public_tcp_ports]
    old_public = public + [_inbound("tcp", "22", list(prior_trusted_ssh_cidrs))]
    # DigitalOcean's provider represents source_addresses as a set and emits
    # the planned SSH rule in lexical order even when reviewed inputs differ.
    new_public = public + [_inbound("tcp", "22", sorted(intent.trusted_ssh_cidrs))]
    before_rules = [_inbound(proto, "1-65535", peers)
                    for proto in ("icmp", "tcp", "udp")] + old_public
    after_rules = [_inbound(proto, "1-65535", [])
                   for proto in ("icmp", "tcp", "udp")]
    for rule in after_rules:
        del rule["source_addresses"]
    after_rules += new_public
    if (not _same(_sorted_rules(before.get("inbound_rule")), _sorted_rules(before_rules))
            or not _same(_sorted_rules(after.get("inbound_rule")), _sorted_rules(after_rules))
            or not _same(after["inbound_rule"][:3], after_rules[:3])):
        raise TerraformPlanGateError("mixed append firewall ingress differs from exact SSH delta")
    ssh_before = [index for index, rule in enumerate(before["inbound_rule"])
                  if rule.get("protocol") == "tcp" and rule.get("port_range") == "22"]
    ssh_after = [index for index, rule in enumerate(after["inbound_rule"])
                 if rule.get("protocol") == "tcp" and rule.get("port_range") == "22"]
    if len(ssh_before) != 1 or len(ssh_after) != 1:
        raise TerraformPlanGateError("mixed append SSH rule is ambiguous")
    outbound = [_outbound(proto, "" if proto == "icmp" else "1-65535", "0.0.0.0/0")
                for proto in ("icmp", "tcp", "udp")]
    if not _same(_sorted_rules(after.get("outbound_rule")), _sorted_rules(outbound)):
        raise TerraformPlanGateError("mixed append firewall egress differs")
    pending = before.get("pending_changes")
    if type(pending) is not list or any(type(row) is not dict for row in pending):
        raise TerraformPlanGateError("mixed append firewall pending state differs")
    inbound_unknown = [
        {**_INBOUND_SOURCE_UNKNOWN,
         "source_addresses": True if index < 3 else
         [False] * (len(intent.trusted_ssh_cidrs) if index == ssh_after[0] else 1)}
        for index in range(len(after["inbound_rule"]))]
    outbound_known = [{**_OUTBOUND_DEST_UNKNOWN, "destination_addresses": [False]}
                      for _ in outbound]
    expected_unknown = {"inbound_rule": inbound_unknown,
                        "outbound_rule": outbound_known,
                        "pending_changes": [{} for _ in pending], "tags": [False]}
    expected_before_sensitive = {"inbound_rule": [
        {**_INBOUND_SOURCE_UNKNOWN,
         "source_addresses": [False] * len(node_addresses) if index < 3
         else [False] * (len(prior_trusted_ssh_cidrs) if index == ssh_before[0] else 1)}
        for index in range(len(before["inbound_rule"]))],
        "outbound_rule": outbound_known,
        "pending_changes": [{} for _ in pending], "tags": [False]}
    expected_after_sensitive = {"inbound_rule": [
        {**_INBOUND_SOURCE_UNKNOWN,
         "source_addresses": [] if index < 3
         else [False] * (len(intent.trusted_ssh_cidrs)
                         if index == ssh_after[0] else 1)}
        for index in range(len(after["inbound_rule"]))],
        "outbound_rule": outbound_known,
        "pending_changes": [{} for _ in pending], "tags": [False]}
    if refreshed:
        expected_unknown["droplet_ids"] = []
        expected_before_sensitive["droplet_ids"] = []
        expected_after_sensitive["droplet_ids"] = []
    if (not _same(change.get("after_unknown"), expected_unknown)
            or not _same(change.get("before_sensitive"), expected_before_sensitive)
            or not _same(change.get("after_sensitive"), expected_after_sensitive)):
        raise TerraformPlanGateError("mixed append firewall unknown or sensitive policy differs")
