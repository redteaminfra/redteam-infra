# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline, fail-closed review of a keyed provider firewall ingress update.

This is not an Apply adapter. The caller must derive the retained state, route
ledger, host-policy observations, and reviewed variables independently; bind
this JSON to the exact saved binary plan; and recheck them under the engagement
mutation lease immediately before a one-shot provider write. A plan gate cannot
prove a live host firewall or an account-wide selector attachment by itself.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Mapping

from app.services.provider_keyed_initial_plan_gate import _same
from app.services.provider_keyed_linode_initial_plan_gate import _workspace as require_linode_workspace
from app.services.provider_keyed_linode_udp_source_gate import (
    _CANDIDATE_SOURCE_REVISION,
    require_candidate_linode_udp_workspace,
)
from app.services.provider_keyed_initial_plan_gate import _verify_audited_workspace as require_digitalocean_workspace
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.terraform_plan_gate import TerraformPlanGateError, classify_saved_plan_actions
from app.services.terraform_plan_gate import PROVIDER_FIREWALL_COMPUTED_ATTRIBUTES, _unknown_value_paths

_BASELINE_TCP = frozenset({80, 443, 2222})
_BASELINE_TCP_VARIABLE = ["22", "80", "443", "2222"]
_FIREWALL = {"linode": "linode_firewall.firewall", "digitalocean": "digitalocean_firewall.firewall"}
_NODE_PREFIX = {"linode": "linode_instance.", "digitalocean": "digitalocean_droplet."}
# Both audited keyed roots retain these unused legacy variables. Terraform
# includes their defaults in show JSON even when absent from the reviewed file.
_DEFAULTED_VARIABLES = {
    "edge_count_per_region": 1, "edge_regions": [], "middle_count": 1, "middle_region": None,
}


@dataclass(frozen=True)
class KeyedIngressRoute:
    channel_id: str
    protocol: str
    port: int
    node_address: str


def require_keyed_ingress_saved_plan(
    saved_plan_json: str, *, workspace: ProviderKeyedWorkspace,
    retained_resources: Mapping[str, Mapping[str, object]],
    prior_routes: tuple[KeyedIngressRoute, ...],
    next_routes: tuple[KeyedIngressRoute, ...],
    selected_channel_id: str,
    attached_node_addresses: tuple[str, ...],
    observed_host_ports: Mapping[str, tuple[tuple[str, int], ...]],
    reviewed_variables: Mapping[str, object],
) -> None:
    """Accept only a selected-route provider ingress union with isolated hosts.

    ``observed_host_ports`` is a complete, independently authenticated host
    policy projection for *every* attached node, excluding baseline web and
    Backflips ports. The caller must check host receipt provenance and
    freshness; caller-supplied booleans are deliberately not accepted here.
    """
    provider = workspace.provider if isinstance(workspace, ProviderKeyedWorkspace) else ""
    linode_udp_source = False
    if provider == "linode":
        linode_udp_source = workspace.source_revision == _CANDIDATE_SOURCE_REVISION
        if linode_udp_source:
            require_candidate_linode_udp_workspace(workspace)
        else:
            require_linode_workspace(workspace)
    elif provider == "digitalocean":
        require_digitalocean_workspace(workspace)
    else:
        raise TerraformPlanGateError("keyed ingress provider is unsupported")
    firewall_address = _FIREWALL[provider]
    if (not isinstance(retained_resources, Mapping) or firewall_address not in retained_resources
            or not isinstance(retained_resources[firewall_address], Mapping)
            or not isinstance(attached_node_addresses, tuple)
            or not attached_node_addresses or len(set(attached_node_addresses)) != len(attached_node_addresses)
            or any(not isinstance(address, str) or not address.startswith(_NODE_PREFIX[provider])
                   or address not in retained_resources for address in attached_node_addresses)):
        raise TerraformPlanGateError("keyed ingress retained provider scope is invalid")
    all_nodes = {address for address in retained_resources if address.startswith(_NODE_PREFIX[provider])}
    if all_nodes != set(attached_node_addresses):
        raise TerraformPlanGateError("keyed ingress attached node set differs from retained state")
    prior = _route_ports(prior_routes, all_nodes)
    desired = _route_ports(next_routes, all_nodes)
    unchanged_union = _union(prior) == _union(desired)
    selected_before = tuple(route for route in prior_routes if route.channel_id == selected_channel_id)
    selected_after = tuple(route for route in next_routes if route.channel_id == selected_channel_id)
    if (not isinstance(selected_channel_id, str) or not selected_channel_id
            or selected_before == selected_after):
        raise TerraformPlanGateError("keyed ingress must change exactly one selected channel")
    prior_others = tuple(route for route in prior_routes if route.channel_id != selected_channel_id)
    next_others = tuple(route for route in next_routes if route.channel_id != selected_channel_id)
    if prior_others != next_others:
        raise TerraformPlanGateError("keyed ingress changes a sibling route")
    if (not isinstance(observed_host_ports, Mapping)
            or set(observed_host_ports) != all_nodes
            or any(not isinstance(ports, tuple) or len(ports) != len(set(ports))
                   or set(ports) != desired[address]
                   for address, ports in observed_host_ports.items())):
        raise TerraformPlanGateError("keyed ingress selected and sibling host isolation is unproved")
    try:
        plan = json.loads(saved_plan_json)
    except (TypeError, ValueError) as exc:
        raise TerraformPlanGateError("keyed ingress saved plan is not JSON") from exc
    expected_variables = ({name: {"value": value} for name, value in reviewed_variables.items()}
                          if isinstance(reviewed_variables, Mapping) else {})
    variables = plan.get("variables") if isinstance(plan, dict) else None
    if isinstance(variables, dict):
        expected_variables.update({name: {"value": value} for name, value in _DEFAULTED_VARIABLES.items()
                                   if name in variables and name not in expected_variables})
    if (not isinstance(plan, dict) or plan.get("format_version") != "1.2"
            or plan.get("terraform_version") != "1.15.5"
            or plan.get("applyable") is not (not unchanged_union) or plan.get("complete") is not True
            or plan.get("errored") is not False or plan.get("resource_drift", []) != []
            or not isinstance(plan.get("resource_changes"), list)
            or not isinstance(reviewed_variables, Mapping)
            or not _same(variables, expected_variables)):
        raise TerraformPlanGateError("keyed ingress plan status or reviewed inputs differ")
    expected_tcp, expected_udp = _union(desired)
    expected_tcp_variable = _BASELINE_TCP_VARIABLE + [
        str(port) for port in sorted(expected_tcp - _BASELINE_TCP)
    ]
    if (not _same(reviewed_variables.get("allowed_tcp_ports"), expected_tcp_variable)
            or (provider == "digitalocean" and
                not _same(reviewed_variables.get("allowed_udp_ports"),
                          [str(port) for port in sorted(expected_udp)]))
            or (provider == "linode" and not linode_udp_source and
                ("allowed_udp_ports" in reviewed_variables or expected_udp))
            or (provider == "linode" and linode_udp_source and
                not _same(reviewed_variables.get("allowed_udp_ports"),
                          [str(port) for port in sorted(expected_udp)]))):
        raise TerraformPlanGateError("keyed ingress Terraform ports differ from route union")
    prior_items = ((plan.get("prior_state") or {}).get("values") or {}).get("root_module", {}).get("resources")
    if not isinstance(prior_items, list):
        raise TerraformPlanGateError("keyed ingress prior state is missing")
    _exact_resources(prior_items, retained_resources, prior=True)
    changes = plan["resource_changes"]
    _exact_resources(changes, retained_resources, prior=False)
    by_address = {row["address"]: row for row in changes}
    firewall = by_address[firewall_address]["change"]
    if unchanged_union:
        _require_exact_noop(plan, retained_resources)
    before = dict(retained_resources[firewall_address])
    field = "inbound" if provider == "linode" else "inbound_rule"
    # Linode status enables/disables policy; it is not completion metadata.
    computed = PROVIDER_FIREWALL_COMPUTED_ATTRIBUTES[provider] - ({"status"} if provider == "linode" else set())
    excluded = computed | {field}
    if (classify_saved_plan_actions(firewall.get("actions")) != ("no-op" if unchanged_union else "update")
            or not _same(firewall.get("before"), before)
            or not isinstance(firewall.get("after"), dict)
            or firewall.get("replace_paths") not in (None, [])
            or not _same({k: v for k, v in firewall["after"].items() if k not in excluded},
                         {k: v for k, v in before.items() if k not in excluded})):
        raise TerraformPlanGateError("keyed ingress firewall changes attachment, egress, or identity")
    before_public, fixed_before = _public_rules(provider, before.get(field))
    after_public, fixed_after = _public_rules(provider, firewall["after"].get(field))
    prior_tcp, prior_udp = _union(prior)
    if (before_public != _public_ports(prior_tcp, prior_udp)
            or after_public != _public_ports(expected_tcp, expected_udp)
            or not _same(fixed_after, fixed_before)):
        raise TerraformPlanGateError("keyed ingress firewall public or fixed rules differ")
    unknown = firewall.get("after_unknown")
    if (unknown is not None and (
            not isinstance(unknown, dict)
            or any(not path or path[0] not in computed for path in _unknown_value_paths(unknown)))):
        raise TerraformPlanGateError("keyed ingress firewall policy is provider-unknown")
    if (not _no_sensitive_fields(firewall.get("before_sensitive"))
            or not _no_sensitive_fields(firewall.get("after_sensitive"))):
        raise TerraformPlanGateError("keyed ingress firewall contains unreviewed sensitive policy")
    for address, row in by_address.items():
        if address == firewall_address:
            continue
        change = row["change"]
        if (classify_saved_plan_actions(change.get("actions")) != "no-op"
                or not _same(change.get("before"), dict(retained_resources[address]))
                or not _same(change.get("after"), dict(retained_resources[address]))
                or change.get("after_unknown") not in ({}, None)
                or change.get("replace_paths") not in (None, [])
                or change.get("before_sensitive") != change.get("after_sensitive")):
            raise TerraformPlanGateError("keyed ingress changes a retained non-firewall resource")



def _require_exact_noop(plan: Mapping[str, object], retained: Mapping[str, Mapping[str, object]]) -> None:
    """An unchanged public union permits no resource or output mutation."""
    for row in plan["resource_changes"]:
        change = row["change"]
        if (change.get("actions") != ["no-op"]
                or not _same(change.get("before"), dict(retained[row["address"]]))
                or not _same(change.get("after"), change.get("before"))
                or _unknown_value_paths(change.get("after_unknown", {}))
                or change.get("replace_paths") not in (None, [])
                or change.get("before_sensitive") != change.get("after_sensitive")):
            raise TerraformPlanGateError("keyed ingress unchanged union has resource changes")
    outputs = plan.get("output_changes", {})
    if not isinstance(outputs, dict):
        raise TerraformPlanGateError("keyed ingress unchanged union outputs differ")
    for change in outputs.values():
        if (not isinstance(change, dict) or change.get("actions") != ["no-op"]
                or "before" not in change or "after" not in change
                or not _same(change["before"], change["after"])
                or _unknown_value_paths(change.get("after_unknown", {}))
                or change.get("before_sensitive") != change.get("after_sensitive")):
            raise TerraformPlanGateError("keyed ingress unchanged union has output changes")


def _route_ports(routes: tuple[KeyedIngressRoute, ...], nodes: set[str]) -> dict[str, set[tuple[str, int]]]:
    if not isinstance(routes, tuple):
        raise TerraformPlanGateError("keyed ingress route ledger is invalid")
    result: dict[str, set[tuple[str, int]]] = {node: set() for node in nodes}
    claimed_nodes: set[tuple[str, str]] = set()
    claimed: set[tuple[str, str, int]] = set()
    for route in routes:
        if (not isinstance(route, KeyedIngressRoute) or not isinstance(route.channel_id, str)
                or not route.channel_id or (route.channel_id, route.node_address) in claimed_nodes
                or route.node_address not in nodes or route.protocol not in {"tcp", "udp"}
                or type(route.port) is not int or not 1 <= route.port <= 65535
                or (route.protocol == "tcp" and route.port in _BASELINE_TCP)
                or (route.protocol == "tcp" and route.port == 22)):
            raise TerraformPlanGateError("keyed ingress route is invalid or collides with baseline")
        port = (route.protocol, route.port)
        socket = (route.node_address, *port)
        if socket in claimed:
            raise TerraformPlanGateError("keyed ingress public port has multiple owners")
        claimed_nodes.add((route.channel_id, route.node_address))
        claimed.add(socket)
        result[route.node_address].add(port)
    return result


def _union(by_node: Mapping[str, set[tuple[str, int]]]) -> tuple[set[int], set[int]]:
    ports = set().union(*by_node.values()) if by_node else set()
    return ({*_BASELINE_TCP, *(port for proto, port in ports if proto == "tcp")},
            {port for proto, port in ports if proto == "udp"})


def _public_ports(tcp: set[int], udp: set[int]) -> set[tuple[str, int]]:
    return {*(('tcp', port) for port in tcp), *(('udp', port) for port in udp)}


def _public_rules(provider: str, rules: object) -> tuple[set[tuple[str, int]], list[dict]]:
    if not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
        raise TerraformPlanGateError("keyed ingress firewall rules are invalid")
    public: set[tuple[str, int]] = set()
    fixed: list[dict] = []
    for rule in rules:
        if provider == "digitalocean":
            is_public = rule.get("action") == "allow" and rule.get("source_addresses") == ["0.0.0.0/0"]
            protocol, port = rule.get("protocol"), rule.get("port_range")
        else:
            is_public = rule.get("action") == "ACCEPT" and rule.get("ipv4") == ["0.0.0.0/0"]
            protocol, port = str(rule.get("protocol", "")).lower(), rule.get("ports")
        if is_public:
            if protocol not in {"tcp", "udp"} or not isinstance(port, str) or not port.isdecimal() or str(int(port)) != port or not 1 <= int(port) <= 65535:
                raise TerraformPlanGateError("keyed ingress has unreviewed public rule")
            if provider == "linode":
                canonical = {"action": "ACCEPT", "protocol": protocol.upper(),
                             "label": f"allow-{protocol}-{port}", "ports": port,
                             "ipv4": ["0.0.0.0/0"], "ipv6": None}
                # Terraform's saved-plan rendering includes the provider's
                # empty description; the offline fixture omits that default.
                if rule not in (canonical, {**canonical, "description": ""}):
                    raise TerraformPlanGateError("keyed ingress public Linode rule differs")
            if provider == "digitalocean" and rule != {"action": "allow", "protocol": protocol, "port_range": port,
                    "source_addresses": ["0.0.0.0/0"], "source_droplet_ids": [], "source_kubernetes_ids": [],
                    "source_load_balancer_uids": [], "source_tags": []}:
                raise TerraformPlanGateError("keyed ingress public DigitalOcean rule differs")
            key = (protocol, int(port))
            if key in public:
                raise TerraformPlanGateError("keyed ingress public rule is duplicated")
            public.add(key)
        else:
            if rule.get("action") in {"allow", "ACCEPT"} and ("0.0.0.0/0" in (rule.get("source_addresses") or []) or "::/0" in (rule.get("source_addresses") or []) or "0.0.0.0/0" in (rule.get("ipv4") or []) or "::/0" in (rule.get("ipv6") or [])):
                raise TerraformPlanGateError("keyed ingress has unreviewed broad ingress")
            fixed.append(rule)
    return public, fixed


def _exact_resources(rows: list, retained: Mapping[str, Mapping[str, object]], *, prior: bool) -> None:
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("address"), str) or row["address"] in seen or row["address"] not in retained or row.get("mode") != "managed":
            raise TerraformPlanGateError("keyed ingress plan has extra or duplicate resource")
        address = row["address"]
        seen.add(address)
        if prior:
            if not _same(row.get("values"), dict(retained[address])):
                raise TerraformPlanGateError("keyed ingress prior state differs")
        elif not isinstance(row.get("change"), dict):
            raise TerraformPlanGateError("keyed ingress resource change is incomplete")
    if seen != set(retained):
        raise TerraformPlanGateError("keyed ingress plan omits retained resource")


def _no_sensitive_fields(value: object) -> bool:
    if value is False:
        return True
    if isinstance(value, dict):
        return all(_no_sensitive_fields(child) for child in value.values())
    if isinstance(value, list):
        return all(_no_sensitive_fields(child) for child in value)
    return False
