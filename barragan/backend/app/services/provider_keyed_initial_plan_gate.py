# Copyright (c) 2026, Oracle and/or its affiliates.
"""Fail-closed inspection of a DigitalOcean keyed *initial* saved plan.

This is a pure plan check, not a dispatcher. Provider-computed values are
accepted only for the exact audited upstream source and exact observed plan
schema. Configuration references alone are not proof of an expression.
"""

from __future__ import annotations

import ipaddress
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping
from app.services.provider_keyed_sketch import (
    ProviderKeyedWorkspace,
    ProviderKeyedSketchError,
    SCHEMA,
    _source_files,
    _terraform_loadable,
)
from app.services.terraform_plan_gate import TerraformPlanGateError, classify_saved_plan_actions


_FIREWALL = "digitalocean_firewall.firewall"
_KEY = "digitalocean_ssh_key.key"
_ARTIFACTS = {"local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]"}
_NODE_ADDRESS = re.compile(r'^digitalocean_droplet\.(middle|edge)\["[A-Za-z0-9._-]+"\]$')
# New keyed workspaces are DevTest-only; historical audits retain their pin.
_SOURCE_REVISION = "cae68e63b8495f0e6d31dfa4a991f4024f18e58b"
_LEGACY_SOURCE_REVISION = "90b6895d9eccc0cf19524396b528a289f5f22fb1"
_SOURCE_SHA256 = "0fcadb0560b4f765ae521788e0d2db55cdba0147d6eacc5a933235ee23c98f60"
_KEY_UNKNOWN = {"fingerprint": True, "id": True}
_NODE_UNKNOWN = {
    "backup_policy": [], "created_at": True, "disk": True, "id": True,
    "ipv4_address": True, "ipv4_address_private": True,
    "ipv6_address": True, "locked": True, "memory": True,
    "price_hourly": True, "price_monthly": True,
    "private_networking": True, "public_networking": True,
    "ssh_keys": True, "status": True, "tags": [False], "urn": True,
    "vcpus": True, "volume_ids": True, "vpc_uuid": True,
}
_NODE_KNOWN_DEFAULTS = {
    "backup_policy": [], "backups": False, "droplet_agent": None,
    "gpu_partition_mode": None, "graceful_shutdown": False,
    "ipv6": False, "monitoring": False, "resize_disk": True,
    "timeouts": None, "user_data": None,
}
_COMPUTED_FIREWALL = {"created_at": True, "id": True, "pending_changes": True,
                      "status": True, "tags": [False]}
_COMPUTED_LOCAL = {f"content_{suffix}": True for suffix in
                   ("base64sha256", "base64sha512", "md5", "sha1", "sha256", "sha512")}
_COMPUTED_LOCAL["id"] = True
_INBOUND_SOURCE_UNKNOWN = {"source_droplet_ids": [], "source_kubernetes_ids": [],
                           "source_load_balancer_uids": [], "source_tags": []}
_OUTBOUND_DEST_UNKNOWN = {"destination_droplet_ids": [], "destination_kubernetes_ids": [],
                          "destination_load_balancer_uids": [], "destination_tags": []}


@dataclass(frozen=True)
class DigitalOceanNodeCreate:
    name: str
    image: str
    size: str
    region: str
    firewall_selector_tag: str


@dataclass(frozen=True)
class DigitalOceanInitialFirewallIntent:
    """Controller-reviewed inputs, supplied independently of plan output."""

    name: str
    selector_tag: str
    public_tcp_ports: tuple[str, ...]
    public_udp_ports: tuple[str, ...]
    trusted_ssh_cidrs: tuple[str, ...]
    peer_cidrs: tuple[str, ...] = ()


def require_digitalocean_keyed_initial_full_plan(
    saved_plan_json: str,
    *,
    workspace: ProviderKeyedWorkspace,
    expected_nodes: Mapping[str, DigitalOceanNodeCreate],
    expected_ssh_key_name: str,
    expected_ssh_public_key: str,
    expected_firewall: DigitalOceanInitialFirewallIntent,
    expected_local_files: Mapping[str, Mapping[str, object]],
) -> None:
    """Require exact initial creates, values, ingress, egress, and artifacts.

    The caller must still bind this JSON to the same saved plan file, inspect
    account-wide selector ownership, and verify attachments after apply.
    """

    _verify_audited_workspace(workspace)
    if (not isinstance(expected_nodes, Mapping) or not expected_nodes
            or any(not isinstance(a, str) or not _NODE_ADDRESS.fullmatch(a)
                   or not isinstance(v, DigitalOceanNodeCreate)
                   for a, v in expected_nodes.items())):
        raise TerraformPlanGateError("initial plan node intent is invalid")
    if (not isinstance(expected_ssh_key_name, str) or not expected_ssh_key_name
            or not isinstance(expected_ssh_public_key, str)
            or not expected_ssh_public_key.strip()):
        raise TerraformPlanGateError("initial plan SSH key intent is invalid")
    _validate_policy_intent(expected_firewall)
    if any(node.firewall_selector_tag != expected_firewall.selector_tag
           for node in expected_nodes.values()):
        raise TerraformPlanGateError("initial plan selector differs across nodes")
    if (not isinstance(expected_local_files, Mapping)
            or set(expected_local_files) != _ARTIFACTS
            or any(not isinstance(v, Mapping) for v in expected_local_files.values())):
        raise TerraformPlanGateError("initial plan local artifact intent is invalid")
    try:
        plan = json.loads(saved_plan_json)
    except (TypeError, ValueError) as exc:
        raise TerraformPlanGateError("initial saved plan is not JSON") from exc
    if (not isinstance(plan, dict) or not isinstance(plan.get("resource_changes"), list)
            or plan.get("resource_drift")):
        raise TerraformPlanGateError("initial saved plan is incomplete or has drift")
    prior = plan.get("prior_state")
    values = prior.get("values") if isinstance(prior, dict) else None
    if (plan.get("format_version") != "1.2" or plan.get("terraform_version") != "1.15.5"
            or plan.get("applyable") is not True or plan.get("complete") is not True
            or plan.get("errored") is not False or not isinstance(values, dict)
            or values.get("root_module") != {}):
        raise TerraformPlanGateError("initial saved plan version, status, or empty state is unproved")
    expected = set(expected_nodes) | {_KEY, _FIREWALL} | _ARTIFACTS
    seen: set[str] = set()
    for resource in plan["resource_changes"]:
        if not isinstance(resource, dict) or not isinstance(resource.get("address"), str):
            raise TerraformPlanGateError("initial plan contains invalid resource")
        address = resource["address"]
        if address in seen:
            raise TerraformPlanGateError("initial plan repeats a resource")
        seen.add(address)
        change = resource.get("change")
        if address not in expected or not isinstance(change, dict):
            raise TerraformPlanGateError("initial plan contains unapproved resource")
        if classify_saved_plan_actions(change.get("actions")) != "create" or change.get("before", object()) is not None:
            raise TerraformPlanGateError("initial plan resource is not a pure create")
        if address in expected_nodes:
            _require_node(change, expected_nodes[address])
        elif address == _KEY:
            _require_key(change, expected_ssh_key_name, expected_ssh_public_key)
        elif address == _FIREWALL:
            _require_firewall(change, expected_firewall)
        else:
            _require_local(address, change, expected_local_files[address])
        _require_exact_sensitivity(address, change)
    if seen != expected:
        raise TerraformPlanGateError("initial plan omits expected resources")


def _require_exact_sensitivity(address: str, change: dict) -> None:
    if change.get("before_sensitive") is not False:
        raise TerraformPlanGateError("initial plan before-sensitive metadata is invalid")
    if _NODE_ADDRESS.fullmatch(address):
        expected = {"backup_policy": [], "ssh_keys": [], "tags": [False], "volume_ids": []}
    elif address == _KEY:
        expected = {}
    elif address in _ARTIFACTS:
        expected = {"sensitive_content": True}
    else:
        after = change.get("after")
        inbound = after.get("inbound_rule") if isinstance(after, dict) else None
        outbound = after.get("outbound_rule") if isinstance(after, dict) else None
        if not isinstance(inbound, list) or not isinstance(outbound, list):
            raise TerraformPlanGateError("initial firewall sensitivity shape is invalid")
        expected = {
            "inbound_rule": [
                {**_INBOUND_SOURCE_UNKNOWN,
                 "source_addresses": [] if isinstance(rule, dict) and "source_addresses" not in rule else [False]}
                for rule in inbound
            ],
            "outbound_rule": [
                {**_OUTBOUND_DEST_UNKNOWN, "destination_addresses": [False]}
                for _ in outbound
            ],
            "pending_changes": [], "tags": [False],
        }
    if not _same(change.get("after_sensitive"), expected):
        raise TerraformPlanGateError("initial plan contains unreviewed sensitivity metadata")


def _verify_audited_workspace(workspace: ProviderKeyedWorkspace) -> None:
    if (not isinstance(workspace, ProviderKeyedWorkspace)
            or workspace.schema != SCHEMA or workspace.provider != "digitalocean"
            or workspace.source_revision not in {_SOURCE_REVISION, _LEGACY_SOURCE_REVISION}
            or workspace.source_sha256 != _SOURCE_SHA256):
        raise TerraformPlanGateError("initial plan source revision is not audited")
    root = workspace.path
    marker = root / ".barragan-provider-keyed-state.json"
    try:
        if root.is_symlink() or marker.is_symlink() or not root.is_dir():
            raise ValueError("unsafe source path")
        ownership = json.loads(marker.read_text(encoding="utf-8"))
        if not isinstance(ownership, dict) or any(ownership.get(k) != v for k, v in {
            "schema": SCHEMA, "provider": "digitalocean",
            "provider_connection_id": workspace.provider_connection_id,
            "connection_fingerprint": workspace.connection_fingerprint,
            "source_revision": workspace.source_revision,
        }.items()):
            raise ValueError("ownership changed")
        source_files = ownership["source_files"]
        rendered_files = ownership["rendered_files"]
        if not isinstance(source_files, dict) or not isinstance(rendered_files, dict):
            raise ValueError("source inventory missing")
        expected_render = dict(source_files)
        expected_render["providers.tf"] = source_files["barragan-v2/providers.tf"]
        expected_render["firewall.tf"] = source_files["barragan-v2/firewall.tf"]
        expected_render[".terraform.lock.hcl"] = source_files["barragan-v2/.terraform.lock.hcl"]
        if (not isinstance(source_files, dict) or not isinstance(rendered_files, dict)
                or hashlib.sha256(json.dumps(source_files, sort_keys=True).encode()).hexdigest() != _SOURCE_SHA256
                or rendered_files != expected_render
                or _source_files(root, tuple(rendered_files)) != rendered_files):
            raise ValueError("rendered source changed")
        # Terraform auto-loads tfvars as well as configuration files. An
        # unlisted file could change the provider token or firewall inputs
        # without changing any audited source digest.
        allowed = set(rendered_files)
        if any(path.relative_to(root).as_posix() not in allowed or path.is_symlink()
               for path in root.rglob("*") if _terraform_loadable(path.name)
               and (path.is_file() or path.is_symlink())):
            raise ValueError("additional Terraform source or input")
    except (OSError, ValueError, KeyError, TypeError, ProviderKeyedSketchError) as exc:
        raise TerraformPlanGateError("initial plan audited source verification failed") from exc


def _validate_policy_intent(intent: DigitalOceanInitialFirewallIntent) -> None:
    if not isinstance(intent, DigitalOceanInitialFirewallIntent):
        raise TerraformPlanGateError("initial firewall intent is invalid")
    if (not isinstance(intent.name, str) or not intent.name
            or not isinstance(intent.selector_tag, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{7,62}", intent.selector_tag)
            or not all(isinstance(x, tuple) for x in (
                intent.public_tcp_ports, intent.public_udp_ports,
                intent.trusted_ssh_cidrs, intent.peer_cidrs))):
        raise TerraformPlanGateError("initial firewall intent is incomplete")
    for ports in (intent.public_tcp_ports, intent.public_udp_ports):
        if len(set(ports)) != len(ports) or any(
            not isinstance(port, str) or not port.isdecimal()
            or str(int(port)) != port or not 1 <= int(port) <= 65535 for port in ports
        ):
            raise TerraformPlanGateError("initial public port intent is invalid")
    if "22" in intent.public_tcp_ports:
        raise TerraformPlanGateError("initial public SSH is forbidden")
    # A selector firewall attaches before fresh hosts have their per-node UFW
    # policy. Channel-specific union ports can be added only after every
    # attached node has an active, verified host policy.
    if set(intent.public_tcp_ports) != {"80", "443", "2222"} or intent.public_udp_ports:
        raise TerraformPlanGateError("initial firewall must use baseline public ports only")
    if not intent.trusted_ssh_cidrs or intent.peer_cidrs:
        raise TerraformPlanGateError("initial trusted SSH is required; peer CIDRs are provider-computed")
    for cidrs in (intent.trusted_ssh_cidrs,):
        if len(set(cidrs)) != len(cidrs):
            raise TerraformPlanGateError("initial CIDR intent repeats a source")
        try:
            if any(not isinstance(cidr, str) or ipaddress.ip_network(cidr, strict=True).version != 4
                   or not cidr.endswith("/32") for cidr in cidrs):
                raise ValueError("not an IPv4 host")
        except ValueError as exc:
            raise TerraformPlanGateError("initial CIDR intent is invalid") from exc


def _require_node(change: dict, intent: DigitalOceanNodeCreate) -> None:
    # The audited middle/edge source fixes ssh_keys to the resource key ID;
    # the exact observed unknown shape is accepted only with that source.
    unknown = change.get("after_unknown")
    if not all(isinstance(value, str) and value for value in (
        intent.name, intent.image, intent.size, intent.region, intent.firewall_selector_tag
    )):
        raise TerraformPlanGateError("initial node intent is incomplete")
    if not _same(unknown, _NODE_UNKNOWN):
        raise TerraformPlanGateError("initial node has unproved unknown SSH key, IP, or inputs")
    expected = {**_NODE_KNOWN_DEFAULTS, "name": intent.name, "image": intent.image,
                "size": intent.size, "region": intent.region,
                "tags": [intent.firewall_selector_tag]}
    if not _same(change.get("after"), expected):
        raise TerraformPlanGateError("initial node differs from reviewed intent")


def _require_key(change: dict, name: str, public_key: str) -> None:
    if not _same(change.get("after_unknown"), _KEY_UNKNOWN):
        raise TerraformPlanGateError("initial SSH key has unreviewed unknown values")
    if not _same(change.get("after"), {"name": name, "public_key": public_key,
                                        "timeouts": None}):
        raise TerraformPlanGateError("initial SSH key differs from reviewed intent")


def _require_firewall(change: dict, intent: DigitalOceanInitialFirewallIntent) -> None:
    unknown = change.get("after_unknown")
    if not isinstance(unknown, dict) or not _same(
        {k: v for k, v in unknown.items() if k not in {"inbound_rule", "outbound_rule"}},
        _COMPUTED_FIREWALL,
    ):
        raise TerraformPlanGateError("initial firewall has unproved unknown policy values")
    after = change.get("after")
    if not isinstance(after, dict) or set(after) != {"name", "tags", "droplet_ids", "inbound_rule", "outbound_rule"}:
        raise TerraformPlanGateError("initial firewall shape differs from reviewed policy")
    if not _same({k: after[k] for k in ("name", "tags", "droplet_ids")},
                 {"name": intent.name, "tags": [intent.selector_tag], "droplet_ids": None}):
        raise TerraformPlanGateError("initial firewall selector or attachments differ")
    inbound = []
    inbound.extend(_inbound("tcp", port, ["0.0.0.0/0"]) for port in intent.public_tcp_ports)
    inbound.extend(_inbound("udp", port, ["0.0.0.0/0"]) for port in intent.public_udp_ports)
    inbound.append(_inbound("tcp", "22", list(intent.trusted_ssh_cidrs)))
    inbound.extend(_inbound_unknown_peer(proto) for proto in ("tcp", "udp", "icmp"))
    if isinstance(after["inbound_rule"], list) and any(
        isinstance(rule, dict) and rule.get("source_addresses") == ["::/0"]
        for rule in after["inbound_rule"]
    ):
        raise TerraformPlanGateError("initial firewall permits broad IPv6 ingress")
    if not _same(_sorted_rules(after["inbound_rule"]), _sorted_rules(inbound)):
        raise TerraformPlanGateError("initial firewall ingress differs from reviewed policy")
    expected_ingress_unknown = [
        {**_INBOUND_SOURCE_UNKNOWN, "source_addresses":
         True if "source_addresses" not in rule else [False]}
        for rule in after["inbound_rule"]
    ]
    if not _same(unknown.get("inbound_rule"), expected_ingress_unknown):
        raise TerraformPlanGateError("initial firewall has unproved unknown ingress")
    outbound = [_outbound(proto, "1-65535" if proto != "icmp" else "", "0.0.0.0/0")
                for proto in ("tcp", "udp", "icmp")]
    if not _same(_sorted_rules(after["outbound_rule"]), _sorted_rules(outbound)):
        raise TerraformPlanGateError("initial firewall egress differs from reviewed policy")
    if not _same(unknown.get("outbound_rule"), [
        {**_OUTBOUND_DEST_UNKNOWN, "destination_addresses": [False]}
        for _ in outbound
    ]):
        raise TerraformPlanGateError("initial firewall has unproved unknown egress")


def _inbound_unknown_peer(proto: str) -> dict:
    rule = _inbound(proto, "1-65535", [])
    del rule["source_addresses"]
    return rule


def _inbound(proto: str, port: str, addresses: list[str]) -> dict:
    return {"action": "allow", "protocol": proto, "port_range": port,
            "source_addresses": addresses, "source_droplet_ids": [],
            "source_kubernetes_ids": [], "source_load_balancer_uids": [], "source_tags": []}


def _outbound(proto: str, port: str, address: str) -> dict:
    return {"action": "allow", "protocol": proto, "port_range": port,
            "destination_addresses": [address], "destination_droplet_ids": [],
            "destination_kubernetes_ids": [], "destination_load_balancer_uids": [],
            "destination_tags": []}


def _sorted_rules(value: object) -> object:
    if not isinstance(value, list) or not all(isinstance(rule, dict) for rule in value):
        return value
    return sorted(value, key=lambda rule: json.dumps(rule, sort_keys=True))


def _require_local(address: str, change: dict, expected: Mapping[str, object]) -> None:
    unknown = {**_COMPUTED_LOCAL, **({"content": True} if address == "local_file.ssh_stanza[0]" else {})}
    if not _same(change.get("after_unknown"), unknown):
        raise TerraformPlanGateError("initial local artifact has unproved content")
    if not _same(change.get("after"), dict(expected)):
        raise TerraformPlanGateError("initial local artifact differs from reviewed intent")


def _same(actual: Any, expected: Any) -> bool:
    """Compare JSON values without Python's bool/int coercion."""

    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(
            _same(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _same(left, right) for left, right in zip(actual, expected)
        )
    return actual == expected
