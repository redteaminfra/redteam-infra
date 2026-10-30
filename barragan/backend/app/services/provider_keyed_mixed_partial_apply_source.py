# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only classification of a sealed mixed provider Apply.

The caller supplies a durable command outcome and a complete fresh provider
observation. This module neither starts Terraform nor grants destroy authority.
An uncertain result always needs separate reconciliation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal, Mapping
from uuid import UUID

from app.services.provider_keyed_mixed_initial_plan_parent import (
    validate_mixed_initial_apply_seal,
)
from app.services.provider_keyed_initial_teardown import _state_resources
from app.storage.job_repository import StoredJobRun


Kind = Literal["unstarted", "full", "partial", "uncertain"]
_LOCAL = {"local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]"}
_SHARED = {
    "linode": {"linode_firewall.firewall", "random_password.root_password"} | _LOCAL,
    "digitalocean": {"digitalocean_firewall.firewall", "digitalocean_ssh_key.key"} | _LOCAL,
}


@dataclass(frozen=True)
class ApplyObservation:
    """Inputs collected by a future one-shot Apply or reconciliation worker.

    ``outcome`` is from a durable, exact command-result journal, never an
    inference from the presence of state. ``inventory`` contains complete
    provider GET rows for instances/droplets and firewalls; unrelated rows are
    allowed. ``phase`` is the retained workspace phase, if any.
    """

    outcome: Literal["not_started", "succeeded", "failed", "unknown"]
    command_intent: bool
    process_quiescent: bool
    phase: str | None
    state_json: bytes | None
    inventory_complete: bool
    inventory: tuple[Mapping[str, object], ...]
    selector_tag_exists: bool | None = None
    selector_attached_node_ids: tuple[str, ...] | None = None
    linode_firewall_attached_node_ids: tuple[str, ...] | None = None
    selector_resources_count: int | None = None


@dataclass(frozen=True)
class ProviderApplyClassification:
    provider: str
    kind: Kind
    state_sha256: str | None = None
    lineage: str | None = None
    serial: int | None = None
    resource_ids: tuple[tuple[str, str], ...] = ()


def _identity(provider: str, address: str, policy: Mapping[str, object]):
    nodes = policy["nodes"]
    if address in nodes:
        node = nodes[address]
        if provider == "linode":
            return ("node", node["label"], node["tag"])
        return ("node", node["name"], node["firewall_selector_tag"])
    if address == "linode_firewall.firewall":
        return ("firewall", f'fw-{policy["engagement_name"]}-firewall', policy["engagement_name"])
    if address == "digitalocean_firewall.firewall":
        firewall = policy["firewall"]
        return ("firewall", firewall["name"], firewall["selector_tag"])
    if address == "digitalocean_ssh_key.key":
        return ("ssh_key", policy["ssh_key_name"], None)
    raise ValueError("address has no provider identity")


def _state(provider: str, policy: Mapping[str, object], raw: bytes):
    state = json.loads(raw)
    UUID(state["lineage"])
    if (state.get("version") != 4 or state.get("terraform_version") != "1.15.5"
            or type(state.get("serial")) is not int or state["serial"] < 1
            or not isinstance(state.get("resources"), list)):
        raise ValueError("state envelope differs")
    actual = _state_resources(state)
    expected = set(policy["nodes"]) | _SHARED[provider]
    if not actual or not set(actual) <= expected:
        raise ValueError("state addresses differ")
    cloud = {}
    for address, attributes in actual.items():
        if (not isinstance(attributes.get("id"), (str, int))
                or type(attributes["id"]) is bool or not str(attributes["id"])):
            raise ValueError("state resource ID is absent")
        if address not in policy["nodes"] and address not in {
                "linode_firewall.firewall", "digitalocean_firewall.firewall",
                "digitalocean_ssh_key.key"}:
            continue
        kind, name, tag = _identity(provider, address, policy)
        if (not isinstance(attributes.get("id"), (str, int))
                or type(attributes["id"]) is bool
                or not str(attributes["id"])
                or attributes.get("tags", [] if kind == "ssh_key" else None)
                != ([] if tag is None else [tag])
                or attributes.get("label" if provider == "linode" else "name") != name
                or (kind == "ssh_key"
                    and attributes.get("public_key") != policy["admin_public_key"])):
            raise ValueError("state identity differs")
        if kind == "node":
            node = policy["nodes"][address]
            fields = (("image", "image"), ("region", "region"),
                      ("type", "node_type")) if provider == "linode" else (
                      ("image", "image"), ("region", "region"), ("size", "size"))
            if any(attributes.get(field) != node[reviewed] for field, reviewed in fields):
                raise ValueError("state node differs")
        cloud[address] = str(attributes["id"])
    identities = {(_identity(provider, address, policy)[0], resource_id)
                  for address, resource_id in cloud.items()}
    if len(identities) != len(cloud):
        raise ValueError("state cloud IDs overlap within a resource kind")
    return state, actual, cloud


def _inventory(provider: str, policy: Mapping[str, object],
               actual: Mapping[str, dict], cloud: Mapping[str, str],
               rows: tuple[Mapping[str, object], ...]) -> None:
    """Require every reviewed identity in fresh inventory to be state-backed."""
    expected_by_id = {(_identity(provider, address, policy)[0], resource_id):
                      _identity(provider, address, policy)
                      for address, resource_id in cloud.items()}
    seen_ids: set[tuple[str, str]] = set()
    matched: set[tuple[str, str]] = set()
    reviewed = {_identity(provider, address, policy)
                for address in set(policy["nodes"]) | (
                    {"linode_firewall.firewall"} if provider == "linode" else
                    {"digitalocean_firewall.firewall"})}
    reviewed_names = {name.casefold() for _, name, _ in reviewed}
    reviewed_tags = {tag.casefold() for _, _, tag in reviewed if tag is not None}
    for row in rows:
        if (not isinstance(row, Mapping) or row.get("kind") not in {"node", "firewall", "ssh_key"}
                or not isinstance(row.get("id"), (str, int)) or type(row["id"]) is bool
                or not isinstance(row.get("name"), str)
                or type(row.get("tags")) is not list
                or any(type(tag) is not str for tag in row["tags"])):
            raise ValueError("provider inventory row incomplete")
        resource_id = (row["kind"], str(row["id"]))
        if resource_id in seen_ids:
            raise ValueError("provider inventory ID repeated")
        seen_ids.add(resource_id)
        identity = expected_by_id.get(resource_id)
        if identity is not None:
            kind, name, tag = identity
            if (row["kind"] != kind or row["name"] != name
                    or row["tags"] != ([] if tag is None else [tag])
                    or (kind == "ssh_key"
                        and row.get("public_key") != policy["admin_public_key"])):
                raise ValueError("state-backed provider identity differs")
            matched.add(resource_id)
        elif (row["kind"] == "ssh_key" and provider == "digitalocean"
              and row.get("public_key") == policy["admin_public_key"]):
            # Account keys can share generic names; only the reviewed key
            # material identifies an unbacked engagement key.
            raise ValueError("reviewed identity exists outside retained state")
        elif (row["kind"] != "ssh_key"
              and (row["name"].casefold() in reviewed_names
                   or any(tag.casefold() in reviewed_tags for tag in row["tags"]))):
            raise ValueError("reviewed identity exists outside retained state")
    if matched != set(expected_by_id):
        raise ValueError("state-backed provider resource is missing")


def classify_sealed_provider_apply(
    parent: StoredJobRun, provider: str, observation: ApplyObservation,
) -> ProviderApplyClassification:
    """Classify one sealed provider without replaying an uncertain write.

    Invalid seal is rejected; uncertain local/provider evidence returns an
    explicit non-actionable result. The caller must authenticate the journal
    and collect complete provider pages before constructing the observation.
    """
    seal = validate_mixed_initial_apply_seal(parent)
    if provider not in seal["orderedProviders"] or type(observation) is not ApplyObservation:
        raise ValueError("mixed Apply provider or observation differs")
    uncertain = ProviderApplyClassification(provider, "uncertain")
    policy = seal["reviewedPolicy"][provider]
    try:
        if (observation.outcome not in {"not_started", "succeeded", "failed", "unknown"}
                or type(observation.command_intent) is not bool
                or type(observation.process_quiescent) is not bool
                or observation.process_quiescent is not True
                or observation.inventory_complete is not True
                or type(observation.inventory) is not tuple):
            return uncertain
        if observation.state_json is None:
            if (observation.outcome != "not_started" or observation.command_intent
                    or observation.phase is not None):
                return uncertain
            if provider == "digitalocean" and (observation.selector_tag_exists is not False
                                                 or observation.selector_attached_node_ids != ()
                                                 or observation.selector_resources_count != 0):
                return uncertain
            if provider == "linode" and observation.linode_firewall_attached_node_ids != ():
                return uncertain
            _inventory(provider, policy, {}, {}, observation.inventory)
            return ProviderApplyClassification(provider, "unstarted")
        if (not observation.command_intent or observation.outcome not in {"succeeded", "failed"}
                or observation.phase not in {"apply_started", "applied"}
                or type(observation.state_json) is not bytes):
            return uncertain
        state, actual, cloud = _state(provider, policy, observation.state_json)
        _inventory(provider, policy, actual, cloud, observation.inventory)
        if provider == "linode":
            attached = observation.linode_firewall_attached_node_ids
            nodes = {resource_id for address, resource_id in cloud.items()
                     if address in policy["nodes"]}
            if (type(attached) is not tuple or any(type(value) is not str for value in attached)
                    or len(set(attached)) != len(attached) or not set(attached) <= nodes
                    or ("linode_firewall.firewall" not in cloud and attached)):
                return uncertain
        if provider == "digitalocean":
            nodes = {resource_id for address, resource_id in cloud.items()
                     if address in policy["nodes"]}
            if (observation.selector_tag_exists is not True
                    or type(observation.selector_attached_node_ids) is not tuple
                    or type(observation.selector_resources_count) is not int
                    or observation.selector_resources_count != len(nodes)
                    or len(set(observation.selector_attached_node_ids))
                    != len(observation.selector_attached_node_ids)
                    or set(observation.selector_attached_node_ids) != nodes):
                return uncertain
        expected = set(policy["nodes"]) | _SHARED[provider]
        if set(actual) == expected and observation.outcome == "succeeded" and observation.phase == "applied":
            if provider == "linode" and set(observation.linode_firewall_attached_node_ids) != nodes:
                # A just-created firewall may still be attaching; the caller
                # can take another fresh GET snapshot under the same claim.
                return uncertain
            kind: Kind = "full"
        elif (set(actual) < expected and observation.outcome == "failed"
              and observation.phase == "apply_started"):
            kind = "partial"
        else:
            return uncertain
        return ProviderApplyClassification(
            provider, kind, hashlib.sha256(observation.state_json).hexdigest(),
            state["lineage"], state["serial"], tuple(sorted(cloud.items())),
        )
    except (KeyError, TypeError, ValueError, UnicodeError):
        return uncertain
