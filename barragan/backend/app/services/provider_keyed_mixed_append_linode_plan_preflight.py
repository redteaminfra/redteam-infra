# Copyright (c) 2026, Oracle and/or its affiliates.
"""Partial, non-dispatchable Linode mixed append saved-plan preflight.

This establishes retained-node no-op and exact resource scope before a real
Terraform 1.15.5 append fixture calibrates firewall/computed-field semantics.
Passing this function must never authorize Apply.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

from app.services.provider_keyed_initial_plan_gate import _same

from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_linode_initial_plan_gate import _workspace
from app.services.provider_keyed_mixed_append_intent import _SHARED_LINODE
from app.services.provider_keyed_mixed_append_linode_intent import (
    MixedLinodeOnDigitalOceanAppendIntent,
)
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.terraform_plan_gate import TerraformPlanGateError, classify_saved_plan_actions


_NODES = re.compile(r'linode_instance\.(middle|edge)\["([a-z0-9_-]+)"\]\Z')
_LOCAL = {"local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]"}

_FIREWALL_BEFORE_SENSITIVE = "d914203d0601bd3f79f13d327ecc019550bfdb3e88e27d6fb919e3d08b0dd9ec"


def _metadata(row: dict) -> None:
    address = row.get("address")
    match = _NODES.fullmatch(address) if isinstance(address, str) else None
    if match:
        kind, name, provider, index = (
            "linode_instance", match.group(1), "registry.terraform.io/linode/linode",
            match.group(2))
    elif address == "linode_firewall.firewall":
        kind, name, provider, index = (
            "linode_firewall", "firewall", "registry.terraform.io/linode/linode", None)
    elif address == "random_password.root_password":
        kind, name, provider, index = (
            "random_password", "root_password", "registry.terraform.io/hashicorp/random", None)
    elif address in _LOCAL:
        kind, name, provider, index = (
            "local_file", address.split(".", 1)[1].split("[", 1)[0],
            "registry.terraform.io/hashicorp/local", 0)
    else:
        raise TerraformPlanGateError("Linode append has unreviewed resource")
    if (row.get("mode") != "managed" or row.get("type") != kind
            or row.get("name") != name or row.get("provider_name") != provider
            or row.get("index") != index or row.get("deposed") is not None):
        raise TerraformPlanGateError("Linode append resource metadata differs")


def _require_linode_firewall_updated_refresh(drift, retained):
    """Bind one computed UTC timestamp refresh to the exact owned predecessor.

    The pinned Linode v4.7.0 firewall schema exports updated as Computed String;
    refresh may advance it after initial attachment without changing policy.
    """
    if drift is None or drift == []:
        return retained
    try:
        if type(drift) is not list or len(drift) != 1 or type(drift[0]) is not dict:
            raise ValueError("unexpected Linode refresh scope")
        row = drift[0]
        if (set(row) != {"address", "mode", "type", "name", "provider_name", "change"}
                or row["address"] != "linode_firewall.firewall"):
            raise ValueError("unexpected Linode refresh resource")
        _metadata(row)
        change = row["change"]
        before = retained["linode_firewall.firewall"]
        after = change["after"]
        def timestamp(value):
            if type(value) is not str or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value) is None:
                raise ValueError("Linode updated timestamp differs")
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        def digest(value):
            return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if (type(change) is not dict
                or set(change) != {"actions", "before", "after", "after_unknown", "before_sensitive", "after_sensitive"}
                or change["actions"] != ["update"] or not _same(change["before"], before)
                or type(after) is not dict or set(after) != set(before)
                or not _same(after, {**before, "updated": after["updated"]})
                or timestamp(after["updated"]) <= timestamp(before["updated"])
                or change["after_unknown"] != {}
                or digest(change["before_sensitive"]) != _FIREWALL_BEFORE_SENSITIVE
                or not _same(change["after_sensitive"], change["before_sensitive"])):
            raise ValueError("unreviewed Linode firewall refresh")
        return {**retained, "linode_firewall.firewall": after}
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise TerraformPlanGateError("Linode append firewall timestamp refresh differs") from exc


def require_mixed_linode_append_retained_plan_preflight(
    saved_plan_json: str, *, workspace: ProviderKeyedWorkspace,
    intent: MixedLinodeOnDigitalOceanAppendIntent,
    digitalocean_state_json: bytes, linode_state_json: bytes,
) -> None:
    """Reject stale state, extra actions, and changes to original Linode nodes.

    This is intentionally only a preflight. The firewall, new-edge unknowns,
    Terraform variables and output delta are not yet approved. The full gate
    must call this again after source calibration and before binary-plan GO.
    """
    _workspace(workspace)
    if (not isinstance(intent, MixedLinodeOnDigitalOceanAppendIntent)
            or type(digitalocean_state_json) is not bytes
            or type(linode_state_json) is not bytes
            or hashlib.sha256(digitalocean_state_json).hexdigest()
            != intent.digitalocean_state_sha256
            or hashlib.sha256(linode_state_json).hexdigest()
            != intent.linode_state_sha256):
        raise TerraformPlanGateError("Linode append predecessor state changed")
    try:
        do = _state_resources(json.loads(digitalocean_state_json))
        retained = _state_resources(json.loads(linode_state_json))
    except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
        raise TerraformPlanGateError("Linode append predecessor state is malformed") from exc
    original_nodes = {address for address in retained if _NODES.fullmatch(address)}
    if (len(original_nodes) != 2
            or len([address for address in original_nodes if ".middle[" in address]) != 1
            or len([address for address in original_nodes if ".edge[" in address]) != 1
            or set(retained) != original_nodes | _SHARED_LINODE
            or intent.new_edge_address in retained
            or {address: str(value.get("id")) for address, value in retained.items()}
            != dict(intent.retained_linode_ids)
            or {address: str(value.get("id")) for address, value in do.items()}
            != dict(intent.retained_digitalocean_ids)
            or str(do.get(intent.digitalocean_middle_address, {}).get("id"))
            != intent.digitalocean_middle_id):
        raise TerraformPlanGateError("Linode append retained identity differs")
    try:
        plan = json.loads(saved_plan_json)
        prior = plan["prior_state"]["values"]["root_module"]["resources"]
        changes = plan["resource_changes"]
    except (ValueError, KeyError, TypeError) as exc:
        raise TerraformPlanGateError("Linode append plan is malformed") from exc
    if (type(plan) is not dict or plan.get("format_version") != "1.2"
            or plan.get("terraform_version") != "1.15.5"
            or plan.get("applyable") is not True or plan.get("complete") is not True
            or plan.get("errored") is not False
            or type(prior) is not list or type(changes) is not list):
        raise TerraformPlanGateError("Linode append plan envelope or drift differs")
    retained = _require_linode_firewall_updated_refresh(plan.get("resource_drift"), retained)
    prior_by_address = {}
    for row in prior:
        if type(row) is not dict or row.get("address") in prior_by_address:
            raise TerraformPlanGateError("Linode append prior state has duplicate resource")
        _metadata(row)
        prior_by_address[row["address"]] = row
    if set(prior_by_address) != set(retained):
        raise TerraformPlanGateError("Linode append prior inventory differs")
    for address, row in prior_by_address.items():
        values = row.get("values")
        if type(values) is not dict or values != retained[address]:
            raise TerraformPlanGateError("Linode append prior node or ID differs")
    expected = set(retained) | {intent.new_edge_address}
    by_address = {}
    for row in changes:
        if (type(row) is not dict or row.get("address") in by_address
                or row.get("address") not in expected
                or type(row.get("change")) is not dict):
            raise TerraformPlanGateError("Linode append action scope differs")
        _metadata(row)
        by_address[row["address"]] = row["change"]
    if set(by_address) != expected:
        raise TerraformPlanGateError("Linode append omits required resource")
    for address in original_nodes | {"random_password.root_password"}:
        change = by_address[address]
        if (classify_saved_plan_actions(change.get("actions")) != "no-op"
                or change.get("before") != prior_by_address[address]["values"]
                or change.get("after") != change.get("before")
                or change.get("after_unknown") not in ({}, None)
                or change.get("before_sensitive") != change.get("after_sensitive")):
            raise TerraformPlanGateError("Linode append changes retained node or password")
    if (classify_saved_plan_actions(by_address[intent.new_edge_address].get("actions")) != "create"
            or classify_saved_plan_actions(by_address["linode_firewall.firewall"].get("actions"))
            != "update"
            or not _same(by_address["linode_firewall.firewall"].get("before"),
                         retained["linode_firewall.firewall"])
            or any(classify_saved_plan_actions(by_address[address].get("actions")) != "delete"
                   for address in _LOCAL)):
        raise TerraformPlanGateError("Linode append action kinds differ")
