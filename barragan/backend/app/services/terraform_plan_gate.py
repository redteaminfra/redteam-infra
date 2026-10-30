# Copyright (c) 2026, Oracle and/or its affiliates.
"""Fail-closed inspection of Terraform's machine-readable plan events."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Iterable


class TerraformPlanGateError(ValueError):
    pass


_SAVED_PLAN_ACTIONS = {
    ("no-op",): "no-op",
    ("create",): "create",
    ("read",): "read",
    ("update",): "update",
    ("delete",): "delete",
    ("forget",): "forget",
    ("delete", "create"): "replace",
    ("create", "delete"): "replace",
}

# Provider-owned fields whose values are computed asynchronously and do not
# authorize a firewall policy mutation.  Capture reuses this exact boundary
# when classifying refresh-only drift; runtime apply authorization remains in
# require_provider_firewall_ingress_update.
PROVIDER_FIREWALL_COMPUTED_ATTRIBUTES = MappingProxyType({
    "linode": frozenset({"created", "fingerprint", "status", "updated", "version"}),
    "digitalocean": frozenset({"created_at", "pending_changes", "status"}),
})


@dataclass(frozen=True)
class PlannedResourceChange:
    address: str
    action: str


@dataclass(frozen=True, order=True)
class FirewallIngressPort:
    """One public listener admitted by a provider firewall projection."""

    protocol: str
    port: int


@dataclass(frozen=True)
class FirewallIngressDelta:
    """The complete provider-ingress change authorized by one operation."""

    added: frozenset[FirewallIngressPort] = frozenset()
    removed: frozenset[FirewallIngressPort] = frozenset()


def planned_resource_changes(plan_json_lines: str) -> list[PlannedResourceChange]:
    """Extract resource actions from ``terraform plan -json`` output.

    Terraform emits one JSON object per line. Unknown or malformed lines are a
    rejection rather than an opportunity to silently skip a change.
    """
    changes: list[PlannedResourceChange] = []
    for raw_line in str(plan_json_lines or "").splitlines():
        if not raw_line.strip():
            continue
        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise TerraformPlanGateError("terraform plan output was not machine-readable JSON") from exc
        if not isinstance(event, dict):
            raise TerraformPlanGateError("terraform plan emitted an invalid event")
        if "resource_changes" in event:
            if changes:
                raise TerraformPlanGateError("terraform plan mixed incompatible machine-readable formats")
            return _saved_plan_resource_changes(event)
        if event.get("type") != "planned_change":
            continue
        resource = event.get("change", {}).get("resource", {})
        address = str(resource.get("addr") or "").strip()
        action = str(event.get("change", {}).get("action") or "").strip()
        if not address or action not in {"create", "update", "delete", "replace", "read", "no-op"}:
            raise TerraformPlanGateError("terraform plan emitted an incomplete resource change")
        if action != "no-op":
            changes.append(PlannedResourceChange(address, action))
    return changes


def _saved_plan_resource_changes(plan: dict) -> list[PlannedResourceChange]:
    resources = plan.get("resource_changes")
    if not isinstance(resources, list):
        raise TerraformPlanGateError("saved Terraform plan omitted resource changes")
    changes: list[PlannedResourceChange] = []
    for resource in resources:
        if not isinstance(resource, dict):
            raise TerraformPlanGateError("saved Terraform plan emitted an invalid resource change")
        address = str(resource.get("address") or "").strip()
        raw_actions = resource.get("change", {}).get("actions")
        if not address:
            raise TerraformPlanGateError("saved Terraform plan emitted an incomplete resource change")
        action = classify_saved_plan_actions(raw_actions)
        if action != "no-op":
            changes.append(PlannedResourceChange(address, action))
    return changes


def classify_saved_plan_actions(raw_actions: Any) -> str:
    """Validate one exact Terraform saved-plan action sequence.

    Order is semantic for replacement actions. Unknown combinations fail closed
    so a new Terraform action cannot be normalized into an older contract.
    """

    if not isinstance(raw_actions, list) or not raw_actions or not all(
        isinstance(action, str) for action in raw_actions
    ):
        raise TerraformPlanGateError("saved Terraform plan emitted an unsupported resource action")
    action = _SAVED_PLAN_ACTIONS.get(tuple(raw_actions))
    if action is None:
        raise TerraformPlanGateError("saved Terraform plan emitted an unsupported resource action")
    return action


def saved_plan_resource_changes(plan_json: str) -> list[PlannedResourceChange]:
    """Parse the single JSON document emitted by ``terraform show -json``."""

    try:
        plan = json.loads(str(plan_json or ""))
    except json.JSONDecodeError as exc:
        raise TerraformPlanGateError("saved Terraform plan was not machine-readable JSON") from exc
    if not isinstance(plan, dict):
        raise TerraformPlanGateError("saved Terraform plan emitted an invalid document")
    return _saved_plan_resource_changes(plan)


def require_provider_firewall_ingress_update(
    plan_json: str,
    *,
    provider: str,
    expected_delta: FirewallIngressDelta,
) -> list[PlannedResourceChange]:
    """Allow only an exact public TCP/UDP ingress projection change.

    ``plan_json`` must be the document emitted by ``terraform show -json``.
    The caller describes every public listener rule that the operation may add
    or remove.  All other firewall semantics, including provider attachments,
    identity, metadata, policies, sibling/SSH ingress, and outbound rules, must
    be identical before and after the update.
    """

    normalized_provider = str(provider or "").strip().lower()
    provider_contract = {
        "linode": ("linode_firewall.firewall", "inbound"),
        "digitalocean": ("digitalocean_firewall.firewall", "inbound_rule"),
    }.get(normalized_provider)
    if provider_contract is None:
        raise TerraformPlanGateError("unsupported provider firewall plan")
    if not isinstance(expected_delta, FirewallIngressDelta):
        raise TerraformPlanGateError("provider firewall ingress delta was invalid")
    expected_address, ingress_attribute = provider_contract
    added = _validated_firewall_ports(expected_delta.added)
    removed = _validated_firewall_ports(expected_delta.removed)
    if added & removed:
        raise TerraformPlanGateError("provider firewall ingress delta cannot add and remove the same listener")

    plan = _saved_plan_document(plan_json)
    changes = _saved_plan_resource_changes(plan)
    if not changes:
        if added or removed:
            raise TerraformPlanGateError("Terraform plan omitted the expected provider firewall ingress change")
        return []
    if len(changes) != 1 or changes[0] != PlannedResourceChange(expected_address, "update"):
        rendered = ", ".join(f"{change.action} {change.address}" for change in changes)
        raise TerraformPlanGateError(f"Terraform plan contains unapproved resource changes: {rendered}")

    raw_changes = plan.get("resource_changes")
    resource = (
        next(
            (
                item
                for item in raw_changes
                if isinstance(item, dict)
                and item.get("address") == expected_address
                and isinstance(item.get("change"), dict)
                and item.get("change", {}).get("actions") == ["update"]
            ),
            None,
        )
        if isinstance(raw_changes, list)
        else None
    )
    change = resource.get("change") if isinstance(resource, dict) else None
    before = change.get("before") if isinstance(change, dict) else None
    after = change.get("after") if isinstance(change, dict) else None
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise TerraformPlanGateError("saved Terraform firewall change omitted before/after semantics")

    ignored_computed_attributes = PROVIDER_FIREWALL_COMPUTED_ATTRIBUTES[normalized_provider]
    after_unknown = change.get("after_unknown", {})
    if not isinstance(after_unknown, dict):
        raise TerraformPlanGateError("saved Terraform firewall change emitted invalid unknown-value metadata")
    unknown_paths = _unknown_value_paths(after_unknown)
    unsafe_unknown_paths = [
        path for path in unknown_paths if not path or path[0] not in ignored_computed_attributes
    ]
    if unsafe_unknown_paths:
        rendered = ", ".join(".".join(path) or "<root>" for path in unsafe_unknown_paths)
        raise TerraformPlanGateError(
            f"Terraform plan leaves protected provider firewall values unknown: {rendered}"
        )

    before_ingress = before.get(ingress_attribute)
    after_ingress = after.get(ingress_attribute)
    if not isinstance(before_ingress, list) or not isinstance(after_ingress, list):
        raise TerraformPlanGateError("saved Terraform firewall change omitted provider ingress rules")

    expected_added = Counter(
        _freeze(_public_ingress_rule(normalized_provider, listener)) for listener in added
    )
    expected_removed = Counter(
        _freeze(_public_ingress_rule(normalized_provider, listener)) for listener in removed
    )
    before_rules = Counter(_freeze(rule) for rule in _validated_rule_list(before_ingress))
    after_rules = Counter(_freeze(rule) for rule in _validated_rule_list(after_ingress))
    actual_added = after_rules - before_rules
    actual_removed = before_rules - after_rules
    if actual_added != expected_added or actual_removed != expected_removed:
        raise TerraformPlanGateError("Terraform plan contains an unapproved provider ingress rule change")

    excluded_attributes = ignored_computed_attributes | {ingress_attribute}
    before_remainder = {
        key: value for key, value in before.items() if key not in excluded_attributes
    }
    after_remainder = {
        key: value for key, value in after.items() if key not in excluded_attributes
    }
    if _freeze(before_remainder) != _freeze(after_remainder):
        raise TerraformPlanGateError("Terraform plan changes provider firewall identity, attachments, policy, or metadata")
    return changes


def _saved_plan_document(plan_json: str) -> dict[str, Any]:
    try:
        plan = json.loads(str(plan_json or ""))
    except json.JSONDecodeError as exc:
        raise TerraformPlanGateError("saved Terraform plan was not machine-readable JSON") from exc
    if not isinstance(plan, dict):
        raise TerraformPlanGateError("saved Terraform plan emitted an invalid document")
    return plan


def _validated_firewall_ports(values: Iterable[FirewallIngressPort]) -> frozenset[FirewallIngressPort]:
    validated: set[FirewallIngressPort] = set()
    for value in values:
        if not isinstance(value, FirewallIngressPort):
            raise TerraformPlanGateError("provider firewall ingress delta contained an invalid listener")
        protocol = str(value.protocol or "").strip().lower()
        if (
            protocol not in {"tcp", "udp"}
            or isinstance(value.port, bool)
            or not isinstance(value.port, int)
            or not 1 <= value.port <= 65535
        ):
            raise TerraformPlanGateError("provider firewall ingress delta contained an invalid TCP/UDP port")
        if protocol == "tcp" and value.port == 22:
            raise TerraformPlanGateError("provider firewall ingress delta cannot modify SSH ingress")
        validated.add(FirewallIngressPort(protocol, value.port))
    return frozenset(validated)


def _validated_rule_list(rules: list[Any]) -> list[dict[str, Any]]:
    if not all(isinstance(rule, dict) for rule in rules):
        raise TerraformPlanGateError("saved Terraform firewall change emitted an invalid ingress rule")
    return rules


def _public_ingress_rule(provider: str, listener: FirewallIngressPort) -> dict[str, Any]:
    if provider == "linode":
        protocol = listener.protocol.upper()
        return {
            "action": "ACCEPT",
            "description": "",
            "ipv4": ["0.0.0.0/0"],
            "ipv6": None,
            "label": f"allow-{listener.protocol}-{listener.port}",
            "ports": str(listener.port),
            "protocol": protocol,
        }
    return {
        "port_range": str(listener.port),
        "protocol": listener.protocol,
        "source_addresses": ["0.0.0.0/0"],
        "source_droplet_ids": [],
        "source_kubernetes_ids": [],
        "source_load_balancer_uids": [],
        "source_tags": [],
    }


def _freeze(value: Any) -> Any:
    """Produce an order-independent, hashable representation of plan values."""

    if isinstance(value, dict):
        return tuple(sorted((str(key), _freeze(item)) for key, item in value.items()))
    if isinstance(value, list):
        return tuple(sorted((_freeze(item) for item in value), key=repr))
    return value


def _unknown_value_paths(value: Any, path: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    """Return all values Terraform marks unknown in an ``after_unknown`` tree."""

    if value is True:
        return [path]
    if value is False or value is None:
        return []
    if isinstance(value, dict):
        return [
            unknown_path
            for key, item in value.items()
            for unknown_path in _unknown_value_paths(item, (*path, str(key)))
        ]
    if isinstance(value, list):
        return [
            unknown_path
            for index, item in enumerate(value)
            for unknown_path in _unknown_value_paths(item, (*path, str(index)))
        ]
    return [path]


def require_exact_resource_changes(
    plan_json_lines: str,
    *,
    expected: set[tuple[str, str]],
) -> list[PlannedResourceChange]:
    changes = planned_resource_changes(plan_json_lines)
    actual = {(change.address, change.action) for change in changes}
    if actual != expected:
        rendered = ", ".join(f"{action} {address}" for address, action in sorted(actual)) or "no changes"
        raise TerraformPlanGateError(f"Terraform plan contains unapproved resource changes: {rendered}")
    return changes


def require_only_in_place_resource_update(
    plan_json_lines: str,
    *,
    expected_address: str,
) -> list[PlannedResourceChange]:
    """Allow no changes or in-place updates to one exact resource address."""

    changes = saved_plan_resource_changes(plan_json_lines)
    for change in changes:
        if change.address != expected_address or change.action != "update":
            raise TerraformPlanGateError(
                f"Terraform plan contains unapproved resource change: {change.action} {change.address}"
            )
    return changes


def require_edge_transition_changes(
    plan_json_lines: str,
    *,
    provider: str,
    edge_address: str,
    edge_action: str,
) -> list[PlannedResourceChange]:
    """Accept one count-indexed edge change and its known safe dependents.

    The stock Redteam-infra sketch modules keep a single firewall and two local
    render artifacts in the same state as the middle and count-indexed edges.
    Changing the final edge therefore *must* update those dependents.  This
    gate explicitly permits only that narrow set and rejects every other
    provider resource, particularly middle or retained-edge changes.
    """

    expected_firewall = (
        "linode_firewall.firewall" if provider == "linode" else "digitalocean_firewall.firewall"
        if provider == "digitalocean"
        else ""
    )
    if not expected_firewall:
        raise TerraformPlanGateError("unsupported sketch provider for edge transition")
    if edge_action not in {"create", "delete"}:
        raise TerraformPlanGateError("edge transition action must be create or delete")

    changes = planned_resource_changes(plan_json_lines)
    actual = {(change.address, change.action) for change in changes}
    required = (edge_address, edge_action)
    if required not in actual:
        raise TerraformPlanGateError("Terraform plan did not contain the expected final-edge change")
    for change in changes:
        if (change.address, change.action) == required:
            continue
        if change.address == expected_firewall and change.action == "update":
            continue
        if change.address in {"local_file.ssh_stanza[0]", "local_file.ansible_inventory[0]"} and change.action == "update":
            continue
        raise TerraformPlanGateError(
            f"Terraform plan contains unapproved resource change: {change.action} {change.address}"
        )
    return changes
