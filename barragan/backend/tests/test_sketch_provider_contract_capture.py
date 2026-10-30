# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import copy
from contextlib import contextmanager, ExitStack
from dataclasses import replace
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from app.integrations.terraform_runner import TerraformCommandResult
from app.integrations.terraform_runner import LocalTerraformCommandRunner
from app.integrations.oci_deployment_targets import BARRAGAN_TESTING_TARGET
from app.services import sketch_provider_contract_capture_safe as capture
from app.services import template_compatibility
from app.services import terraform_plan_gate
from app.services.sketch_provider_contract_capture_safe import (
    CaptureRequest,
    PlanOnlyRunner as _PlanOnlyRunner,
    SketchProviderContractCaptureError,
    canonical_firewall_semantics,
    clone_required_workspace as _clone_workspace,
    capture_sketch_provider_contract,
    classify_capture_output_changes,
    classify_capture_noop_plan,
    export_firewall_contract,
    load_capture_state,
    require_scenario_fidelity,
    runtime_roles,
    validate_devtest_scope,
    validate_terraform_version,
)
from app.services.terraform_plan_gate import (
    FirewallIngressDelta,
    FirewallIngressPort,
    require_provider_firewall_ingress_update,
    PlannedResourceChange,
)
from app.storage.engagement_repository import StoredEngagement
from app.storage.job_repository import StoredJobRun
from app.storage.sketch_chain_repository import StoredSketchChain
from app.services.sketch_state_workspaces import MaterializedSketchKeys


def _linode_noop_plan() -> dict:
    firewall = {
        "id": 87654321,
        "label": "opaque-firewall",
        "devices": [{"entity_id": 1234567, "id": 7654321, "label": "secret-node", "type": "linode", "url": "/v4/linode/instances/1234567"}],
        "inbound": [
            {"action": "ACCEPT", "description": "", "ipv4": ["0.0.0.0/0"], "ipv6": None, "label": "allow-tcp-22", "ports": "22", "protocol": "TCP"},
            {"action": "ACCEPT", "description": "", "ipv4": ["0.0.0.0/0"], "ipv6": None, "label": "allow-tcp-80", "ports": "80", "protocol": "TCP"},
            {"action": "ACCEPT", "description": "", "ipv4": ["0.0.0.0/0"], "ipv6": None, "label": "allow-tcp-443", "ports": "443", "protocol": "TCP"},
            {"action": "ACCEPT", "description": "", "ipv4": ["0.0.0.0/0"], "ipv6": None, "label": "allow-tcp-2222", "ports": "2222", "protocol": "TCP"},
            {"action": "ACCEPT", "description": "", "ipv4": ["0.0.0.0/0"], "ipv6": None, "label": "allow-udp-53", "ports": "53", "protocol": "UDP"},
        ],
        "inbound_policy": "DROP",
        "linodes": [1234567],
        "nodebalancers": [],
        "outbound": [],
        "outbound_policy": "ACCEPT",
        "status": "enabled",
        "tags": ["barragan-owned"],
    }
    compute = {
        "address": "linode_instance.edge[0]", "mode": "managed", "type": "linode_instance",
        "name": "edge", "provider_name": "registry.terraform.io/linode/linode", "schema_version": 0,
        "values": {
            "id": 1234567, "ip_address": "198.51.100.40", "label": "LINODE-NODE-NAME-SECRET",
            "user_data": "LINODE-USERDATA-SECRET", "authorized_keys": ["LINODE-AUTHKEY-SECRET"],
            "root_pass": "LINODE-ROOTPASS-SECRET",
        },
        "sensitive_values": {"id": False, "ip_address": False, "label": False, "user_data": True,
                             "authorized_keys": [True], "root_pass": True},
    }
    return {
        "format_version": "1.2", "terraform_version": "1.15.5",
        "planned_values": {"root_module": {"resources": [{
            "address": "linode_firewall.firewall", "mode": "managed", "type": "linode_firewall",
            "name": "firewall", "provider_name": "registry.terraform.io/linode/linode", "schema_version": 0,
            "values": firewall,
            "sensitive_values": {"id": False, "label": False, "inbound": []},
        }, compute]}},
        "resource_changes": [],
        "resource_drift": [{**compute, "change": {
            "actions": ["update"],
            "before": {"user_data": "LINODE-DRIFT-BEFORE-SECRET"},
            "after": {"user_data": "LINODE-DRIFT-AFTER-SECRET"},
            "before_sensitive": {"user_data": True}, "after_sensitive": {"user_data": True},
            "after_unknown": {"user_data": False},
        }}],
        "output_changes": {"edge_ip": {"actions": ["update"], "before": "198.51.100.40",
                                           "after": "198.51.100.41", "before_sensitive": False,
                                           "after_sensitive": False}},
        "prior_state": {"format_version": "1.0", "values": {"outputs": {
            "secret": {"sensitive": True, "value": "LINODE-PRIOR-SECRET"}}}},
        "configuration": {"root_module": {"variables": {
            "root_pass": {"default": "LINODE-CONFIG-SECRET"}}}},
        "variables": {"root_pass": {"value": "LINODE-VARIABLE-SECRET"}},
        "checks": [{"address": {"kind": "resource", "to_display": "linode_firewall.firewall"},
                    "status": "pass"}],
        "relevant_attributes": [{"resource": "linode_instance.edge[0]", "attribute": ["user_data"]}],
        "deferred_changes": [{"reason": "LINODE-DEFERRED-SECRET", "resource_change": {
            "address": "linode_instance.edge[0]", "mode": "managed", "type": "linode_instance",
            "name": "edge", "provider_name": "registry.terraform.io/linode/linode",
            "change": {"actions": ["no-op"], "importing": {"id": "LINODE-IMPORT-ID-SECRET"}}}}],
    }


def _upstream_linode_rule_plan() -> dict:
    """Model all rule-label families emitted by the authoritative Linode source."""
    document = _linode_noop_plan()
    firewall = document["planned_values"]["root_module"]["resources"][0]["values"]
    firewall["inbound"].extend([
        {
            "action": "ACCEPT", "description": "", "ipv4": ["198.51.100.40/32"],
            "ipv6": None, "label": "allow-ENGAGEMENT-LABEL-SECRET-host-tcp",
            "ports": None, "protocol": "TCP",
        },
        {
            "action": "ACCEPT", "description": "", "ipv4": ["198.51.100.40/32"],
            "ipv6": None, "label": "allow-ENGAGEMENT-LABEL-SECRET-host-udp",
            "ports": None, "protocol": "UDP",
        },
        {
            "action": "ACCEPT", "description": "", "ipv4": ["198.51.100.40/32"],
            "ipv6": None, "label": "allow-ENGAGEMENT-LABEL-SECRET-host-icmp",
            "ports": None, "protocol": "ICMP",
        },
        {
            "action": "DROP", "description": "", "ipv4": None, "ipv6": ["::/0"],
            "label": "block-ipv6-tcp", "ports": None, "protocol": "TCP",
        },
        {
            "action": "DROP", "description": "", "ipv4": None, "ipv6": ["::/0"],
            "label": "block-ipv6-udp", "ports": None, "protocol": "UDP",
        },
        {
            "action": "DROP", "description": "", "ipv4": None, "ipv6": ["::/0"],
            "label": "block-ipv6-icmp", "ports": None, "protocol": "ICMP",
        },
        {
            "action": "ACCEPT", "description": "manual", "ipv4": ["192.0.2.0/24"],
            "ipv6": None, "label": "MANUAL-RULE-LABEL-SECRET", "ports": "8443",
            "protocol": "TCP",
        },
    ])
    firewall["outbound"] = [
        {
            "action": "DROP", "description": "", "ipv4": None, "ipv6": ["::/0"],
            "label": f"block-ipv6-{protocol.lower()}", "ports": None, "protocol": protocol,
        }
        for protocol in ("TCP", "UDP", "ICMP")
    ]
    return document


def _literal_linode_listener_transport_tuples(firewall: dict) -> list[tuple]:
    """Project listener transport facts without calling capture sanitizer helpers."""
    result = []
    for direction in ("inbound", "outbound"):
        for rule in firewall.get(direction, []):
            if isinstance(rule, dict) and isinstance(rule.get("label"), str) \
                    and re.fullmatch(r"allow-(?:tcp|udp)-\d+", rule["label"]):
                result.append((
                    direction,
                    rule.get("action"),
                    rule.get("protocol"),
                    rule.get("ports"),
                    tuple(rule["ipv4"]) if isinstance(rule.get("ipv4"), list) else rule.get("ipv4"),
                    tuple(rule["ipv6"]) if isinstance(rule.get("ipv6"), list) else rule.get("ipv6"),
                ))
    return result


def _linode_rule_transport_semantics(firewall: dict) -> list[tuple]:
    """Compare transport meaning while treating non-public addresses as identities."""
    def addresses(value, public):
        if value is None:
            return None
        return tuple(item if item == public else "<identity>" for item in value)

    return [
        (
            direction,
            rule.get("action"),
            rule.get("protocol"),
            rule["ports"] if "ports" in rule else "<missing>",
            addresses(rule.get("ipv4"), "0.0.0.0/0"),
            addresses(rule.get("ipv6"), "::/0"),
        )
        for direction in ("inbound", "outbound")
        for rule in firewall.get(direction, [])
    ]


def _digitalocean_full_plan() -> dict:
    firewall = {
        "id": "DO-FIREWALL-ID-SECRET", "name": "DO-FIREWALL-NAME-SECRET",
        "droplet_ids": [201, 202], "tags": ["OWNER-TAG-SECRET"],
        "inbound_rule": [{
            "port_range": "22", "protocol": "tcp", "source_addresses": ["0.0.0.0/0"],
            "source_droplet_ids": [], "source_kubernetes_ids": [],
            "source_load_balancer_uids": [], "source_tags": [],
        }],
        "outbound_rule": [{
            "port_range": "1-65535", "protocol": "tcp", "destination_addresses": ["0.0.0.0/0"],
            "destination_droplet_ids": [], "destination_kubernetes_ids": [],
            "destination_load_balancer_uids": [], "destination_tags": [],
        }],
        "created_at": "CREATED-SECRET", "pending_changes": [], "status": "succeeded",
    }
    compute = {
        "address": "digitalocean_droplet.edge[0]", "mode": "managed", "type": "digitalocean_droplet",
        "name": "edge", "provider_name": "registry.terraform.io/digitalocean/digitalocean", "schema_version": 0,
        "values": {"user_data": "DO-USERDATA-SECRET", "authorized_keys": ["DO-AUTHKEY-SECRET"], "root_pass": "DO-ROOTPASS-SECRET"},
        "sensitive_values": {"user_data": True, "authorized_keys": [True], "root_pass": True},
    }
    return {
        "format_version": "1.2", "terraform_version": "1.15.5",
        "planned_values": {"root_module": {"resources": [{
            "address": "digitalocean_firewall.firewall", "mode": "managed", "type": "digitalocean_firewall",
            "name": "firewall", "provider_name": "registry.terraform.io/digitalocean/digitalocean",
            "schema_version": 0, "values": firewall, "sensitive_values": {"id": False, "name": False},
        }, compute]}},
        "resource_changes": [{
            "address": "digitalocean_firewall.firewall", "mode": "managed", "type": "digitalocean_firewall",
            "name": "firewall", "provider_name": "registry.terraform.io/digitalocean/digitalocean",
            "change": {"actions": ["no-op"], "before": firewall, "after": firewall,
                       "before_sensitive": {"id": False}, "after_sensitive": {"id": False},
                       "after_unknown": {"status": False}},
        }],
        "resource_drift": [{**compute, "change": {"actions": ["update"], "before": {"user_data": "DRIFT-BEFORE-SECRET"}, "after": {"user_data": "DRIFT-AFTER-SECRET"}, "before_sensitive": {"user_data": True}, "after_sensitive": {"user_data": True}, "after_unknown": {"user_data": False}}}],
        "output_changes": {"edge_ip": {"actions": ["update"], "before": "198.51.100.1", "after": "198.51.100.2", "before_sensitive": False, "after_sensitive": False}},
        "prior_state": {"format_version": "1.0", "values": {"outputs": {"secret": {"sensitive": True, "value": "PRIOR-SECRET"}}}},
        "configuration": {"root_module": {"variables": {"root_pass": {"default": "CONFIG-SECRET"}}}},
        "variables": {"root_pass": {"value": "VARIABLE-SECRET"}},
        "checks": [{"address": {"kind": "resource", "to_display": "digitalocean_firewall.firewall"}, "status": "pass"}],
        "relevant_attributes": [{"resource": "digitalocean_droplet.edge[0]", "attribute": ["user_data"]}],
        "deferred_changes": [{"reason": "DEFERRED-SECRET", "resource_change": {
            "address": "digitalocean_droplet.edge[0]", "mode": "managed", "type": "digitalocean_droplet",
            "name": "edge", "provider_name": "registry.terraform.io/digitalocean/digitalocean",
            "change": {"actions": ["no-op"], "importing": {"id": "IMPORT-ID-SECRET"}}}}],
    }


def _clean_linode_capture_noop_plan() -> dict:
    document = _linode_noop_plan()
    document["resource_drift"] = []
    document["output_changes"] = {}
    document["deferred_changes"] = []
    return document


def _digitalocean_computed_drift_noop_plan() -> dict:
    document = _digitalocean_full_plan()
    document["output_changes"] = {}
    document["deferred_changes"] = []
    firewall = document["planned_values"]["root_module"]["resources"][0]["values"]
    before = copy.deepcopy(firewall)
    before["pending_changes"] = [{"droplet_id": 201, "status": "waiting"}]
    before["status"] = "waiting"
    after = copy.deepcopy(firewall)
    after["pending_changes"] = []
    after["status"] = "succeeded"
    document["resource_drift"] = [{
        "address": "digitalocean_firewall.firewall",
        "mode": "managed",
        "type": "digitalocean_firewall",
        "name": "firewall",
        "provider_name": "registry.terraform.io/digitalocean/digitalocean",
        "change": {
            "actions": ["update"],
            "before": before,
            "after": after,
            "before_sensitive": {"id": False, "name": False},
            "after_sensitive": {"id": False, "name": False},
            "after_unknown": {"pending_changes": False, "status": False},
        },
    }]
    return document


def _linode_computed_drift_noop_plan() -> dict:
    document = _clean_linode_capture_noop_plan()
    resource = document["planned_values"]["root_module"]["resources"][0]
    after = copy.deepcopy(resource["values"])
    after["updated"] = "2026-09-15T15:30:00Z"
    before = copy.deepcopy(after)
    before["updated"] = "2026-09-15T15:29:00Z"
    resource["values"] = copy.deepcopy(after)
    sensitive = copy.deepcopy(resource["sensitive_values"])
    document["resource_drift"] = [{
        "address": "linode_firewall.firewall",
        "mode": "managed",
        "type": "linode_firewall",
        "name": "firewall",
        "provider_name": "registry.terraform.io/linode/linode",
        "change": {
            "actions": ["update"],
            "before": before,
            "after": after,
            "before_sensitive": copy.deepcopy(sensitive),
            "after_sensitive": copy.deepcopy(sensitive),
            "after_unknown": {"updated": False},
        },
    }]
    return document


def _shape(value):
    if isinstance(value, dict): return ("dict", tuple((key, _shape(item)) for key, item in value.items()))
    if isinstance(value, list): return ("list", tuple(_shape(item) for item in value))
    if value is None: return ("null",)
    if isinstance(value, bool): return ("bool", value)
    return (type(value).__name__,)


def _shape_equivalent(raw, exported):
    if isinstance(raw, dict) and isinstance(exported, dict):
        if list(raw) == list(exported):
            return all(_shape_equivalent(raw[key], exported[key]) for key in raw)
        if len(raw) != len(exported):
            return False
        common = set(raw) & set(exported)
        if not all(_shape_equivalent(raw[key], exported[key]) for key in common):
            return False
        raw_only = [item for key, item in raw.items() if key not in common]
        exported_only = [(key, item) for key, item in exported.items() if key not in common]
        allowed = re.compile(r"^(?:data_key|module|provider_alias|output|var)_\d{3}$")
        if len(raw_only) != len(exported_only) or not all(allowed.fullmatch(str(key)) for key, _item in exported_only):
            return False
        raw_shapes = sorted(repr(_shape_without_map_keys(item)) for item in raw_only)
        exported_shapes = sorted(repr(_shape_without_map_keys(item)) for _key, item in exported_only)
        return raw_shapes == exported_shapes
    if isinstance(raw, list) and isinstance(exported, list):
        return len(raw) == len(exported) and all(_shape_equivalent(left, right) for left, right in zip(raw, exported))
    if raw is None or exported is None:
        return raw is None and exported is None
    if isinstance(raw, bool) or isinstance(exported, bool):
        return type(raw) is type(exported) and raw == exported
    return type(raw) is type(exported)


def _shape_without_map_keys(value):
    if isinstance(value, dict):
        return ("dict", tuple(sorted(repr(_shape_without_map_keys(item)) for item in value.values())))
    if isinstance(value, list):
        return ("list", tuple(_shape_without_map_keys(item) for item in value))
    if value is None: return ("null",)
    if isinstance(value, bool): return ("bool", value)
    return (type(value).__name__,)


def _correlated_value(raw_map, exported_map, raw_key):
    position = list(raw_map).index(raw_key)
    return list(exported_map.values())[position]


class FakeRunner:
    def __init__(self, document: dict):
        self.document = document
        self.calls = []

    def run(self, command, **kwargs):
        self.calls.append((command, kwargs))
        if command == "version":
            stdout = json.dumps({"terraform_version": "1.15.5", "platform": "linux_amd64", "provider_selections": {
                "registry.terraform.io/linode/linode": "4.5.0",
                "registry.terraform.io/hashicorp/local": "2.9.1",
                "registry.terraform.io/hashicorp/random": "3.9.1",
            }, "terraform_outdated": False})
        elif command == "plan":
            Path(kwargs["saved_plan_path"]).write_bytes(b"opaque plan")
            stdout = "{}\n"
        elif command == "show":
            stdout = json.dumps(self.document)
        else:
            stdout = ""
        return TerraformCommandResult(
            command,
            2 if command == "plan" and self.document.get("output_changes") else 0,
            stdout,
            "",
        )


class FailingPhaseRunner(FakeRunner):
    def __init__(self, document: dict, failure_command: str):
        super().__init__(document)
        self.failure_command = failure_command

    def run(self, command, **kwargs):
        if command == self.failure_command:
            self.calls.append((command, kwargs))
            return TerraformCommandResult(
                command,
                1,
                f"PRIVATE-{command}-STDOUT-SECRET",
                f"PRIVATE-{command}-STDERR-SECRET",
            )
        return super().run(command, **kwargs)


class Repo:
    def __init__(self, value): self.value = value
    def get(self, *_args): return self.value
    def list_for_engagement(self, *_args): return []


class Lease:
    def __init__(self): self.acquired = []; self.released = []
    def acquire(self, engagement, owner, operation): self.acquired.append((engagement, owner, operation)); return True
    def release(self, engagement, owner): self.released.append((engagement, owner))


def _records(workspace: Path):
    engagement = StoredEngagement(
        "eng-test", "opaque-engagement", "active", "owner", "dev", None,
        {"deploymentTarget": {
            "provider": "oci",
            "name": BARRAGAN_TESTING_TARGET.name,
            "compartmentId": BARRAGAN_TESTING_TARGET.compartment_id,
            "region": BARRAGAN_TESTING_TARGET.region,
        }},
    )
    chain = StoredSketchChain(
        "chain-test", "eng-test", "proxy01", "linode", "us-sea", "small", "linode", "us-sea", "small",
        "deployed", False, "", "job-deploy", "", str(workspace), [
            {"chainId": "chain-test", "hostname": "middle-01", "componentId": "middle-component", "role": "middle", "provider": "linode"},
            {"chainId": "chain-test", "hostname": "edge-01", "componentId": "edge-component", "role": "edge", "provider": "linode"},
        ], "now", "now",
    )
    job = StoredJobRun(
        "job-deploy", "linode_sketch_deploy", "succeeded", "engagement:eng-test", "engagement", "eng-test", "operator",
        {"engagementId": "eng-test", "chainId": "chain-test", "provider": "linode", "edgeCredentialAlias": "default", "terraformWorkingDirectory": str(workspace),
         "terraformEngagementName": "opaque-engagement",
         "edgeRegion": "us-sea", "middleRegion": "us-sea", "edgeCount": 1, "middleCount": 1,
         "edgeSize": "small", "middleSize": "small", "resourceNameSuffix": "opaque"},
        [], "now", "now", "now", [],
    )
    return engagement, chain, job


def _channel(edge_component="edge-component"):
    return {
        "channelId": "channel-test", "chainId": "chain-test",
        "edge": "edge-01", "edgeComponentId": edge_component,
        "middle": "middle-01", "middleComponentId": "middle-component",
        "protocol": "udp", "externalPort": "53", "relayPort": "8053",
        "status": "Validated",
    }


_OUTPUT_NAMES = {
    "digitalocean": (
        "public-key", "run-ansible", "middle_public_ips", "middle_instance_ids",
        "edge_public_ips", "edge_instance_ids", "good-bye",
    ),
    "linode": (
        "root-password", "root-password-retrieval", "public-key", "run-ansible",
        "middle_public_ips", "middle_instance_ids", "edge_public_ips",
        "edge_instance_ids", "good-bye",
    ),
}


def _source_faithful_output_tf(provider: str) -> str:
    prefix = "linode_instance" if provider == "linode" else "digitalocean_droplet"
    ip_field = "ip_address" if provider == "linode" else "ipv4_address"
    provider_only = (
        'output "root-password" {\n  value = random_password.root_password.result\n  sensitive = true\n}\n'
        'output "root-password-retrieval" {\n  value = "retrieve separately"\n}\n'
        if provider == "linode" else ""
    )
    return (
        'resource "local_file" "ssh_stanza" {\n'
        '  content = templatefile("templates/ssh-stanza.tftpl", {})\n}\n'
        'resource "local_file" "ansible_inventory" {\n'
        '  content = templatefile("templates/inventory.tftpl", {})\n}\n'
        f'{provider_only}'
        'output "public-key" {\n  value = local.ssh_pub_key_path\n}\n'
        'output "run-ansible" {\n'
        '  value      = "Run ansible to configure hosts with:\\n\\tansible-playbook ../ansible/sketch-playbook.yml -i inventory.ini -e \\"ssh_pub_key=${local.ssh_pub_key_path}\\" -e \\"ssh_config_path=${local.abs_ssh_config_path}\\""\n}\n'
        f'output "middle_public_ips" {{\n  value = [for ip in {prefix}.middle : ip.{ip_field}]\n}}\n'
        f'output "middle_instance_ids" {{\n  value = [for instance in {prefix}.middle : instance.id]\n}}\n'
        f'output "edge_public_ips" {{\n  value = [for ip in {prefix}.edge : ip.{ip_field}]\n}}\n'
        f'output "edge_instance_ids" {{\n  value = [for instance in {prefix}.edge : instance.id]\n}}\n'
        'output "good-bye" {\n  value = "Have a nice day!"\n}\n'
    )


def _retained_outputs(provider: str) -> dict:
    values = {
        "public-key": "/tmp/retained-keys/admin.pub",
        "run-ansible": (
            "Run ansible to configure hosts with:\n\tansible-playbook ../ansible/sketch-playbook.yml "
            '-i inventory.ini -e "ssh_pub_key=/tmp/retained-keys/admin.pub" '
            '-e "ssh_config_path=/tmp/retained-home/.ssh/opaque-engagement-sketch"'
        ),
        "middle_public_ips": ["192.0.2.10"],
        "middle_instance_ids": ["1001"],
        "edge_public_ips": ["198.51.100.10"],
        "edge_instance_ids": ["2001"],
        "good-bye": "Have a nice day!",
        "root-password": "RETAINED-ROOT-PASSWORD-SECRET",
        "root-password-retrieval": "Root password is available separately",
    }
    return {
        name: {
            "value": copy.deepcopy(values[name]),
            "type": "string" if isinstance(values[name], str) else ["tuple", ["string"]],
            "sensitive": name == "root-password",
        }
        for name in _OUTPUT_NAMES[provider]
    }


def _capture_output_changes(
    provider: str, retained: dict, public_path: Path, ssh_config_path: Path,
) -> dict:
    run_ansible = (
        "Run ansible to configure hosts with:\n\tansible-playbook ../ansible/sketch-playbook.yml "
        f'-i inventory.ini -e "ssh_pub_key={public_path}" '
        f'-e "ssh_config_path={ssh_config_path}"'
    )
    result = {}
    for name in _OUTPUT_NAMES[provider]:
        changed = name in {"public-key", "run-ansible"}
        after = str(public_path) if name == "public-key" else run_ansible if name == "run-ansible" else retained[name]["value"]
        result[name] = {
            "actions": ["update"] if changed else ["no-op"],
            "before": copy.deepcopy(retained[name]["value"]),
            "after": copy.deepcopy(after),
            "before_sensitive": retained[name]["sensitive"],
            "after_sensitive": retained[name]["sensitive"],
            "after_unknown": False,
        }
    return result


def _prepare_capture_outputs(
    document: dict, provider: str, public_path: Path, runtime_home: Path,
    engagement_name: str = "opaque-engagement",
) -> None:
    retained = _retained_outputs(provider)
    document["output_changes"] = _capture_output_changes(
        provider, retained, public_path,
        runtime_home / ".ssh" / f"{engagement_name}-sketch",
    )


def _write_template_closure(workspace: Path, provider: str = "linode") -> None:
    (workspace / "output.tf").write_text(_source_faithful_output_tf(provider))
    (workspace / "templates").mkdir()
    (workspace / "templates" / "ssh-stanza.tftpl").write_text("ssh ${host}\n")
    (workspace / "templates" / "inventory.tftpl").write_text("inventory ${host}\n")


def _workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "state" / "eng-test" / "chain-test" / "linode"
    workspace.mkdir(parents=True)
    (workspace / ".barragan-sketch-state").write_text("marker")
    (workspace / ".terraform.lock.hcl").write_text("locked")
    (workspace / "variables.tf").write_text('variable "allowed_tcp_ports" {}\nvariable "allowed_udp_ports" {}\n')
    (workspace / "firewall.tf").write_text("resource firewall")
    _write_template_closure(workspace)
    (workspace / "terraform.tfstate").write_text(json.dumps({
        "version": 4,
        "terraform_version": "1.15.5",
        "serial": 1,
        "lineage": "00000000-0000-0000-0000-000000000000",
        "outputs": _retained_outputs("linode"),
        "resources": [{
            "mode": "managed",
            "type": "linode_firewall",
            "name": "firewall",
            "provider": 'provider["registry.terraform.io/linode/linode"]',
            "instances": [{
                "schema_version": 0,
                "attributes": {"id": "100", "label": "opaque-firewall", "linodes": ["200"], "tags": []},
                "sensitive_attributes": [],
            }],
        }],
    }))
    return workspace


def _provider_workspace(tmp_path: Path, provider: str) -> Path:
    workspace = tmp_path / "state" / "eng-test" / "chain-test" / provider
    workspace.mkdir(parents=True)
    (workspace / ".barragan-sketch-state").write_text("marker")
    (workspace / ".terraform.lock.hcl").write_text("locked")
    (workspace / "variables.tf").write_text(
        'variable "allowed_tcp_ports" {}\nvariable "allowed_udp_ports" {}\n'
    )
    (workspace / "firewall.tf").write_text("resource firewall")
    _write_template_closure(workspace, provider)
    resource_type = "linode_firewall" if provider == "linode" else "digitalocean_firewall"
    provider_address = (
        "registry.terraform.io/linode/linode"
        if provider == "linode" else "registry.terraform.io/digitalocean/digitalocean"
    )
    (workspace / "terraform.tfstate").write_text(json.dumps({
        "version": 4, "terraform_version": "1.15.5", "serial": 1,
        "lineage": f"00000000-0000-0000-0000-{provider:0<12}"[:36],
        "outputs": _retained_outputs(provider),
        "resources": [{
            "mode": "managed", "type": resource_type, "name": "firewall",
            "provider": f'provider["{provider_address}"]',
            "instances": [{"schema_version": 0, "attributes": {"id": "100"}, "sensitive_attributes": []}],
        }],
    }))
    return workspace


def test_plan_only_runner_rejects_every_provider_write_command():
    runner = _PlanOnlyRunner(FakeRunner(_linode_noop_plan()))
    for command in ("apply", "destroy", "import", "state", "providers"):
        with pytest.raises(SketchProviderContractCaptureError, match="not allowed"):
            runner.run(command, working_directory="/tmp", env={})


def test_clone_rejects_links_and_never_hardlinks(tmp_path: Path):
    source = tmp_path / "source"; source.mkdir()
    (source / "regular.tf").write_text("content")
    (source / ".terraform.lock.hcl").write_text("lock")
    (source / "terraform.tfstate").write_text("{}")
    _write_template_closure(source)
    os.symlink(source / "regular.tf", source / "linked.tf")
    with pytest.raises(SketchProviderContractCaptureError, match="link or special"):
        _clone_workspace(source, tmp_path / "copy")
    (source / "linked.tf").unlink()
    (source / ".terraform").mkdir()
    (source / ".terraform" / "provider-cache").write_text("do not clone")
    (source / "prior.tfplan").write_text("do not clone")
    (source / "README.md").write_text("do not clone")
    (source / "provider.log").write_text("do not clone")
    (source / "templates" / "unused.tftpl").write_text("do not clone")
    target = tmp_path / "copy"
    _clone_workspace(source, target)
    source_stat = (source / "regular.tf").stat()
    target_stat = (target / "regular.tf").stat()
    assert (source_stat.st_dev, source_stat.st_ino) != (target_stat.st_dev, target_stat.st_ino)
    assert oct((target / "regular.tf").stat().st_mode & 0o777) == "0o600"
    assert not (target / ".terraform").exists()
    assert not (target / "prior.tfplan").exists()
    assert not (target / "README.md").exists()
    assert not (target / "provider.log").exists()
    assert not (target / "templates" / "unused.tftpl").exists()


def test_schema_export_preserves_types_array_order_null_and_gate_semantics():
    document = _linode_noop_plan()
    sanitized = export_firewall_contract(document, "linode")
    text = json.dumps(sanitized, sort_keys=True)
    assert "opaque-firewall" not in text
    assert "87654321" not in text
    assert "1234567" not in text
    assert "secret-node" not in text
    assert "/v4/linode" not in text
    inbound = sanitized["planned_values"]["root_module"]["resources"][0]["values"]["inbound"]
    assert [row["ports"] for row in inbound] == ["22", "80", "443", "2222", "53"]
    assert inbound[0]["ipv6"] is None
    assert require_provider_firewall_ingress_update(json.dumps(document), provider="linode", expected_delta=FirewallIngressDelta()) == []
    assert require_provider_firewall_ingress_update(json.dumps(sanitized), provider="linode", expected_delta=FirewallIngressDelta()) == []


@pytest.mark.parametrize("direction", ["add", "remove"])
def test_schema_export_preserves_changed_plan_gate_and_canonical_firewall_semantics(direction: str):
    planned = _linode_noop_plan()
    with_udp = copy.deepcopy(planned["planned_values"]["root_module"]["resources"][0]["values"])
    without_udp = copy.deepcopy(with_udp)
    without_udp["inbound"] = [rule for rule in without_udp["inbound"] if rule["ports"] != "53"]
    before, after = (without_udp, with_udp) if direction == "add" else (with_udp, without_udp)
    planned["planned_values"]["root_module"]["resources"][0]["values"] = after
    planned["resource_changes"] = [{
        "address": "linode_firewall.firewall", "mode": "managed", "type": "linode_firewall",
        "name": "firewall", "provider_name": "registry.terraform.io/linode/linode",
        "change": {"actions": ["update"], "before": before, "after": after, "after_unknown": {}},
    }]
    port = FirewallIngressPort("udp", 53)
    delta = FirewallIngressDelta(
        added=frozenset({port}) if direction == "add" else frozenset(),
        removed=frozenset({port}) if direction == "remove" else frozenset(),
    )
    raw = require_provider_firewall_ingress_update(json.dumps(planned), provider="linode", expected_delta=delta)
    sanitized = export_firewall_contract(planned, "linode")
    clean = require_provider_firewall_ingress_update(json.dumps(sanitized), provider="linode", expected_delta=delta)
    assert clean == raw
    before_rules = sanitized["resource_changes"][0]["change"]["before"]["inbound"]
    after_rules = sanitized["resource_changes"][0]["change"]["after"]["inbound"]
    assert [rule["ports"] for rule in before_rules] == [rule["ports"] for rule in before["inbound"]]
    assert [rule["ports"] for rule in after_rules] == [rule["ports"] for rule in after["inbound"]]
    assert canonical_firewall_semantics(planned, "linode", redact=True) == canonical_firewall_semantics(sanitized, "linode", redact=False)


@pytest.mark.parametrize("direction", ["add", "no-op", "remove"])
def test_upstream_linode_rule_labels_are_confidential_correlated_and_gate_equivalent(direction: str):
    document = _upstream_linode_rule_plan()
    resource = document["planned_values"]["root_module"]["resources"][0]
    without_listener = copy.deepcopy(resource["values"])
    listener = {
        "action": "ACCEPT", "description": "", "ipv4": ["0.0.0.0/0"],
        "ipv6": None, "label": "allow-udp-3478", "ports": "3478", "protocol": "UDP",
    }
    with_listener = copy.deepcopy(without_listener)
    with_listener["inbound"].append(listener)
    if direction == "add":
        before, after = without_listener, with_listener
    elif direction == "remove":
        before, after = with_listener, without_listener
    else:
        before = after = without_listener
    resource["values"] = copy.deepcopy(after)
    actions = ["no-op"] if direction == "no-op" else ["update"]
    envelope = {
        "address": "linode_firewall.firewall", "mode": "managed",
        "type": "linode_firewall", "name": "firewall",
        "provider_name": "registry.terraform.io/linode/linode", "schema_version": 0,
    }
    change = {
        "actions": actions, "before": copy.deepcopy(before), "after": copy.deepcopy(after),
        "before_sensitive": {"inbound": [{"label": False, "ports": False} for _ in before["inbound"]]},
        "after_sensitive": {"inbound": [{"label": False, "ports": False} for _ in after["inbound"]]},
        "after_unknown": {"inbound": [{"label": False, "ports": False} for _ in after["inbound"]]},
    }
    document["resource_changes"] = [{**envelope, "change": copy.deepcopy(change)}]
    document["resource_drift"].append({**envelope, "change": copy.deepcopy(change)})
    document["deferred_changes"].append({
        "reason": "provider", "resource_change": {**envelope, "change": copy.deepcopy(change)},
    })
    document["prior_state"]["values"]["root_module"] = {
        "resources": [{**envelope, "values": copy.deepcopy(before), "sensitive_values": {}}],
    }

    port = FirewallIngressPort("udp", 3478)
    delta = FirewallIngressDelta(
        added=frozenset({port}) if direction == "add" else frozenset(),
        removed=frozenset({port}) if direction == "remove" else frozenset(),
    )
    raw_decision = require_provider_firewall_ingress_update(
        json.dumps(document), provider="linode", expected_delta=delta,
    )
    exported = export_firewall_contract(document, "linode")
    clean_decision = require_provider_firewall_ingress_update(
        json.dumps(exported), provider="linode", expected_delta=delta,
    )
    assert clean_decision == raw_decision
    clean_values = exported["planned_values"]["root_module"]["resources"][0]["values"]
    assert _literal_linode_listener_transport_tuples(after) == \
        _literal_linode_listener_transport_tuples(clean_values)
    assert _linode_rule_transport_semantics(after) == \
        _linode_rule_transport_semantics(clean_values)
    assert canonical_firewall_semantics(document, "linode", redact=True) == \
        canonical_firewall_semantics(exported, "linode", redact=False)

    clean_change = exported["resource_changes"][0]["change"]
    raw_labels = [rule["label"] for rule in before["inbound"]]
    clean_before_labels = [rule["label"] for rule in clean_change["before"]["inbound"]]
    clean_drift_labels = [
        rule["label"] for rule in exported["resource_drift"][-1]["change"]["before"]["inbound"]
    ]
    clean_prior_labels = [
        rule["label"]
        for rule in exported["prior_state"]["values"]["root_module"]["resources"][0]["values"]["inbound"]
    ]
    for raw_label, clean_label, drift_label, prior_label in zip(
        raw_labels, clean_before_labels, clean_drift_labels, clean_prior_labels,
    ):
        if re.fullmatch(r"allow-(?:tcp|udp)-\d+", raw_label):
            assert clean_label == raw_label
        else:
            assert re.fullmatch(r"rule_label_\d{3}", clean_label)
            assert clean_label != raw_label
        assert drift_label == clean_label == prior_label
    if direction in {"add", "remove"}:
        labels = [
            rule["label"]
            for rule in clean_change["after" if direction == "add" else "before"]["inbound"]
        ]
        assert "allow-udp-3478" in labels
    serialized = json.dumps(exported)
    for secret in (
        "ENGAGEMENT-LABEL-SECRET", "MANUAL-RULE-LABEL-SECRET",
        "block-ipv6-tcp", "block-ipv6-udp", "block-ipv6-icmp",
    ):
        assert secret not in serialized
    assert clean_change["before_sensitive"]["inbound"][0]["label"] is False
    assert clean_change["before_sensitive"]["inbound"][0]["ports"] is False
    assert clean_change["after_unknown"]["inbound"][0]["label"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        "outbound", "drop", "protocol", "port", "range", "nonpublic",
        "missing-ipv6", "ipv6-public", "extra-field", "label-range",
        "label-nonnumeric", "label-leading-zero", "null-port", "missing-port",
    ],
)
def test_linode_unproven_listener_shaped_labels_are_pseudonymized(mutation: str):
    document = _linode_noop_plan()
    firewall = document["planned_values"]["root_module"]["resources"][0]["values"]
    rule = copy.deepcopy(firewall["inbound"][1])
    if mutation == "outbound":
        firewall["inbound"].remove(firewall["inbound"][1])
        firewall["outbound"].append(rule)
    elif mutation == "drop": rule["action"] = "DROP"
    elif mutation == "protocol": rule["protocol"] = "UDP"
    elif mutation == "port": rule["ports"] = "81"
    elif mutation == "range": rule["ports"] = "80-81"
    elif mutation == "nonpublic": rule["ipv4"] = ["192.0.2.0/24"]
    elif mutation == "missing-ipv6": rule.pop("ipv6")
    elif mutation == "ipv6-public": rule["ipv6"] = ["::/0"]
    elif mutation == "extra-field": rule["provider_extension"] = "value"
    elif mutation == "label-range": rule["label"] = "allow-tcp-80-81"
    elif mutation == "label-nonnumeric": rule["label"] = "allow-tcp-http"
    elif mutation == "label-leading-zero":
        rule["label"] = "allow-tcp-080"
        rule["ports"] = "080"
    elif mutation == "null-port": rule["ports"] = None
    elif mutation == "missing-port": rule.pop("ports")
    if mutation != "outbound":
        firewall["inbound"][1] = rule
    exported = export_firewall_contract(document, "linode")
    clean_firewall = exported["planned_values"]["root_module"]["resources"][0]["values"]
    clean_rule = clean_firewall["outbound"][-1] if mutation == "outbound" else clean_firewall["inbound"][1]
    assert re.fullmatch(r"rule_label_\d{3}", clean_rule["label"])
    assert clean_rule["label"] != rule["label"]
    assert rule["label"] not in json.dumps(exported)
    if mutation == "extra-field":
        assert "provider_extension" not in clean_rule
        assert "provider_extension" not in json.dumps(exported)


def test_linode_public_listener_label_decision_is_exact_and_independent_of_export():
    sanitizer = capture.TerraformShowSanitizer({}, "linode")
    listener = copy.deepcopy(_linode_noop_plan()["planned_values"]["root_module"]["resources"][0]["values"]["inbound"][1])
    manual = copy.deepcopy(listener)
    manual["label"] = "MANUAL-IDENTITY-LABEL"
    assert sanitizer._linode_public_listener_label(
        listener, public_ingress=True,
    ) == "allow-tcp-80"
    assert sanitizer._linode_public_listener_label(
        manual, public_ingress=True,
    ) is None
    assert sanitizer._linode_public_listener_label(
        listener, public_ingress=False,
    ) is None


def test_linode_null_and_missing_rule_labels_preserve_their_distinction():
    null_document = _upstream_linode_rule_plan()
    null_rule = null_document["planned_values"]["root_module"]["resources"][0]["values"]["inbound"][-1]
    null_rule["label"] = None
    missing_document = copy.deepcopy(null_document)
    missing_document["planned_values"]["root_module"]["resources"][0]["values"]["inbound"][-1].pop("label")
    clean_null = export_firewall_contract(null_document, "linode")
    clean_missing = export_firewall_contract(missing_document, "linode")
    null_clean_rule = clean_null["planned_values"]["root_module"]["resources"][0]["values"]["inbound"][-1]
    missing_clean_rule = clean_missing["planned_values"]["root_module"]["resources"][0]["values"]["inbound"][-1]
    assert "label" in null_clean_rule and null_clean_rule["label"] is None
    assert "label" not in missing_clean_rule


def test_linode_optional_ports_preserve_null_missing_empty_single_and_range():
    document = _upstream_linode_rule_plan()
    inbound = document["planned_values"]["root_module"]["resources"][0]["values"]["inbound"]
    prototype = copy.deepcopy(inbound[-1])
    cases = [("null", None), ("missing", None), ("empty", ""), ("single", "8443"), ("range", "8000-8100")]
    for name, ports in cases:
        rule = copy.deepcopy(prototype)
        rule["label"] = f"MANUAL-{name}-PORTS-SECRET"
        if name == "missing":
            rule.pop("ports")
        else:
            rule["ports"] = ports
        inbound.append(rule)
    exported = export_firewall_contract(document, "linode")
    clean = exported["planned_values"]["root_module"]["resources"][0]["values"]["inbound"][-5:]
    assert clean[0]["ports"] is None
    assert "ports" not in clean[1]
    assert [rule["ports"] for rule in clean[2:]] == ["", "8443", "8000-8100"]
    assert _linode_rule_transport_semantics(
        {"inbound": inbound[-5:], "outbound": []},
    ) == _linode_rule_transport_semantics({"inbound": clean, "outbound": []})


@pytest.mark.parametrize("ports", [True, 80, [], {}])
def test_linode_optional_ports_reject_non_string_non_null_values(ports):
    document = _upstream_linode_rule_plan()
    document["planned_values"]["root_module"]["resources"][0]["values"]["inbound"][-1]["ports"] = ports
    with pytest.raises(SketchProviderContractCaptureError, match="port expression was invalid"):
        export_firewall_contract(document, "linode")


def test_digitalocean_port_range_does_not_accept_linode_null_compatibility():
    document = _digitalocean_full_plan()
    document["planned_values"]["root_module"]["resources"][0]["values"]["inbound_rule"][0]["port_range"] = None
    with pytest.raises(SketchProviderContractCaptureError, match="port expression was invalid"):
        export_firewall_contract(document, "digitalocean")


@pytest.mark.parametrize("label", [True, 3, [], {}])
def test_linode_rule_label_requires_a_string(label):
    document = _upstream_linode_rule_plan()
    document["planned_values"]["root_module"]["resources"][0]["values"]["inbound"][-1]["label"] = label
    with pytest.raises(SketchProviderContractCaptureError, match="rule label was invalid"):
        export_firewall_contract(document, "linode")


def test_digitalocean_unrelated_label_values_remain_generic_and_confidential():
    document = _digitalocean_full_plan()
    compute = document["planned_values"]["root_module"]["resources"][1]
    compute["values"]["label"] = "DO-UNRELATED-LABEL-SECRET"
    compute["sensitive_values"]["label"] = False
    exported = export_firewall_contract(document, "digitalocean")
    serialized = json.dumps(exported)
    assert "DO-UNRELATED-LABEL-SECRET" not in serialized
    clean_compute = exported["planned_values"]["root_module"]["resources"][1]
    assert _correlated_value(compute["values"], clean_compute["values"], "label").startswith("<redacted-")


@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
def test_unknown_firewall_keys_are_pseudonymized_and_correlate_with_masks(provider: str):
    document = _linode_noop_plan() if provider == "linode" else _digitalocean_full_plan()
    firewall_resource = document["planned_values"]["root_module"]["resources"][0]
    firewall = firewall_resource["values"]
    unknown_key = "PAYLOAD.BAD"
    nested_key = "SECRET.KEY.SENTINEL"
    rule_key = "RULE.PAYLOAD.BAD"
    device_key = "DEVICE.PAYLOAD.BAD"
    ingress_key = "inbound" if provider == "linode" else "inbound_rule"
    if provider == "linode":
        # Unknown provider-owned keys stay generic; exact public-listener rules
        # deliberately reject an expanded shape.
        firewall[ingress_key][0]["label"] = "MANUAL-UNKNOWN-FIELD-RULE"
    firewall[unknown_key] = {nested_key: "FIREWALL-SECRET-VALUE"}
    firewall[ingress_key][0][rule_key] = "RULE-SECRET-VALUE"
    if provider == "linode":
        firewall["devices"][0][device_key] = "DEVICE-SECRET-VALUE"
    firewall_resource["sensitive_values"][unknown_key] = {nested_key: True}
    firewall_resource["sensitive_values"][ingress_key] = [
        {rule_key: True}, *({} for _item in firewall[ingress_key][1:])
    ]
    if provider == "linode":
        firewall_resource["sensitive_values"]["devices"] = [{device_key: True}]
    if not document["resource_changes"]:
        document["resource_changes"].append({
            "address": "linode_firewall.firewall", "mode": "managed", "type": "linode_firewall",
            "name": "firewall", "provider_name": "registry.terraform.io/linode/linode",
            "change": {"actions": ["no-op"], "before": copy.deepcopy(firewall),
                       "after": copy.deepcopy(firewall), "before_sensitive": {},
                       "after_sensitive": {}, "after_unknown": {}},
        })
    change = document["resource_changes"][0]["change"]
    for field in ("before", "after"):
        change[field][unknown_key] = {nested_key: "FIREWALL-SECRET-VALUE"}
    for field in ("before_sensitive", "after_sensitive", "after_unknown"):
        change[field][unknown_key] = {nested_key: field != "after_unknown"}
        change[field][ingress_key] = [
            {rule_key: field != "after_unknown"}, *({} for _item in firewall[ingress_key][1:])
        ]

    sanitizer = capture.TerraformShowSanitizer(document, provider)
    sanitizer.prepare()
    exported = sanitizer.sanitize(document, ())
    clean_resource = exported["planned_values"]["root_module"]["resources"][0]
    clean_change = exported["resource_changes"][0]["change"]
    pairs = [
        (firewall, clean_resource["values"]),
        (firewall_resource["sensitive_values"], clean_resource["sensitive_values"]),
        *((change[field], clean_change[field]) for field in (
            "before", "after", "before_sensitive", "after_sensitive", "after_unknown",
        )),
    ]
    root_known = capture._LINODE_FIREWALL_KEYS["root"] if provider == "linode" else capture._DIGITALOCEAN_FIREWALL_KEYS["root"]
    rule_known = capture._LINODE_FIREWALL_KEYS["rule"] if provider == "linode" else capture._DIGITALOCEAN_FIREWALL_KEYS["rule"]
    for raw_map, clean_map in pairs:
        assert set(clean_map) == {
            key if key in root_known else sanitizer.data_key_names[key]
            for key in raw_map
        }
        assert set(clean_map[sanitizer.data_key_names[unknown_key]]) == {
            sanitizer.data_key_names[nested_key]
        }
        if ingress_key in raw_map:
            assert ingress_key in clean_map
            assert set(clean_map[ingress_key][0]) == {
                key if key in rule_known else sanitizer.data_key_names[key]
                for key in raw_map[ingress_key][0]
            }
    assert ingress_key in clean_resource["values"]
    clean_rule = clean_resource["values"][ingress_key][0]
    mapped_rule_key = sanitizer.data_key_names[rule_key]
    assert mapped_rule_key in clean_rule
    clean_mask = clean_resource["sensitive_values"]
    assert mapped_rule_key in clean_mask[ingress_key][0]
    if provider == "linode":
        clean_device = clean_resource["values"]["devices"][0]
        mapped_device_key = sanitizer.data_key_names[device_key]
        assert mapped_device_key in clean_device
        assert mapped_device_key in clean_mask["devices"][0]
    serialized = json.dumps(exported)
    for sentinel in (
        unknown_key, nested_key, rule_key, device_key, "FIREWALL-SECRET-VALUE",
        "RULE-SECRET-VALUE", "DEVICE-SECRET-VALUE", "MANUAL-UNKNOWN-FIELD-RULE",
    ):
        assert sentinel not in serialized


def test_schema_export_never_copies_secret_bearing_compute_resources():
    document = _linode_noop_plan()
    document["planned_values"]["root_module"]["resources"].append({
        "address": "linode_instance.edge[0]", "mode": "managed", "type": "linode_instance",
        "name": "edge", "provider_name": "registry.terraform.io/linode/linode", "schema_version": 0,
        "values": {
            "user_data": "USERDATA-SECRET-XYZ", "authorized_keys": ["AUTHORIZED-SECRET-XYZ"],
            "root_pass": "ROOTPASS-SECRET-XYZ", "private_key": "PRIVATE-SECRET-XYZ", "public_key": "PUBLIC-SECRET-XYZ", "token": "TOKEN-SECRET-XYZ",
        },
    })
    exported = json.dumps(export_firewall_contract(document, "linode"))
    for secret in ("USERDATA-SECRET-XYZ", "AUTHORIZED-SECRET-XYZ", "ROOTPASS-SECRET-XYZ", "PRIVATE-SECRET-XYZ", "PUBLIC-SECRET-XYZ", "TOKEN-SECRET-XYZ"):
        assert secret not in exported


@pytest.mark.parametrize("provider,document,secrets", [
    ("linode", _linode_noop_plan(), (
        "opaque-firewall", "secret-node", "/v4/linode/instances/1234567",
        "LINODE-NODE-NAME-SECRET", "LINODE-USERDATA-SECRET", "LINODE-AUTHKEY-SECRET",
        "LINODE-ROOTPASS-SECRET", "LINODE-DRIFT-BEFORE-SECRET", "LINODE-DRIFT-AFTER-SECRET",
        "LINODE-PRIOR-SECRET", "LINODE-CONFIG-SECRET", "LINODE-VARIABLE-SECRET",
        "LINODE-DEFERRED-SECRET", "LINODE-IMPORT-ID-SECRET",
    )),
    ("digitalocean", _digitalocean_full_plan(), (
        "DO-FIREWALL-ID-SECRET", "DO-FIREWALL-NAME-SECRET", "DO-USERDATA-SECRET",
        "DO-AUTHKEY-SECRET", "DO-ROOTPASS-SECRET", "DRIFT-BEFORE-SECRET",
        "DRIFT-AFTER-SECRET", "PRIOR-SECRET", "CONFIG-SECRET", "VARIABLE-SECRET",
        "DEFERRED-SECRET", "IMPORT-ID-SECRET",
    )),
])
def test_full_show_export_preserves_complete_shape_and_leaks_no_secrets(provider, document, secrets):
    exported = export_firewall_contract(document, provider)
    assert _shape_equivalent(document, exported)
    text = json.dumps(exported)
    for secret in secrets: assert secret not in text
    assert exported["format_version"] == document["format_version"]
    assert exported["terraform_version"] == document["terraform_version"]
    if document["resource_changes"]:
        assert exported["resource_changes"][0]["change"]["actions"] == document["resource_changes"][0]["change"]["actions"]
    expected = FirewallIngressDelta()
    assert require_provider_firewall_ingress_update(json.dumps(document), provider=provider, expected_delta=expected) == \
        require_provider_firewall_ingress_update(json.dumps(exported), provider=provider, expected_delta=expected)
    assert canonical_firewall_semantics(document, provider, redact=True) == \
        canonical_firewall_semantics(exported, provider, redact=False)
    if provider == "digitalocean":
        assert _shape_equivalent(
            document["resource_changes"][0]["change"]["before_sensitive"],
            exported["resource_changes"][0]["change"]["before_sensitive"],
        )
        assert _shape_equivalent(
            document["resource_changes"][0]["change"]["after_unknown"],
            exported["resource_changes"][0]["change"]["after_unknown"],
        )
        assert exported["resource_drift"][0]["address"] == "digitalocean_droplet.resource_001[0]"
        output_change = next(iter(exported["output_changes"].values()))
        assert output_change["actions"] == document["output_changes"]["edge_ip"]["actions"]


@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
def test_document_address_map_pseudonymizes_modules_for_each_keys_and_correlated_references(provider):
    document = _linode_noop_plan() if provider == "linode" else _digitalocean_full_plan()
    resource_type = "linode_instance" if provider == "linode" else "digitalocean_droplet"
    provider_name = (
        "registry.terraform.io/linode/linode"
        if provider == "linode"
        else "registry.terraform.io/digitalocean/digitalocean"
    )
    module_address = 'module.MODULE-NAME-SECRET["TENANT.KEY.SECRET"].module.INNER-MODULE-SECRET[2]'
    address = f'{module_address}.{resource_type}.RESOURCE-NAME-SECRET["EDGE.KEY.SECRET"]'
    resource = {
        "address": address,
        "module_address": module_address,
        "mode": "managed",
        "type": resource_type,
        "name": "RESOURCE-NAME-SECRET",
        "index": "EDGE.KEY.SECRET",
        "provider_name": provider_name,
        "schema_version": 0,
        "values": {
            "self_reference": address,
            "attribute_reference": f"{address}.network_interface[0].ip_address",
            "secret": "PLAN-VALUE-SECRET",
        },
        "sensitive_values": {"self_reference": False, "attribute_reference": False, "secret": True},
    }
    document["planned_values"]["root_module"].setdefault("child_modules", []).append({
        "address": module_address,
        "resources": [resource],
    })
    document.setdefault("resource_changes", []).append({
        key: copy.deepcopy(value) for key, value in resource.items()
        if key not in {"values", "sensitive_values"}
    } | {"change": {"actions": ["no-op"], "before": {}, "after": {}, "after_unknown": {}}})
    document.setdefault("resource_drift", []).append({
        key: copy.deepcopy(value) for key, value in resource.items()
        if key not in {"values", "sensitive_values"}
    } | {"change": {"actions": ["update"], "before": {"reference": address}, "after": {"reference": address}}})
    document.setdefault("checks", []).append({"address": {"kind": "resource", "to_display": address}, "status": "pass"})
    document.setdefault("relevant_attributes", []).append({
        "resource": address,
        "attribute": ["network_interface", 0, "ip_address"],
    })
    document["configuration"]["root_module"]["outputs"] = {
        "cross_reference": {"expression": {"references": [f"{address}.id"]}}
    }

    exported = export_firewall_contract(document, provider)
    child = exported["planned_values"]["root_module"]["child_modules"][-1]
    mapped = child["resources"][0]["address"]
    assert _shape_equivalent(document, exported)
    assert mapped == exported["resource_changes"][-1]["address"]
    assert mapped == exported["resource_drift"][-1]["address"]
    assert mapped == exported["checks"][-1]["address"]["to_display"]
    assert mapped == exported["relevant_attributes"][-1]["resource"]
    exported_output = next(iter(exported["configuration"]["root_module"]["outputs"].values()))
    assert exported_output["expression"]["references"][0] == f"{mapped}.id"
    cleaned_values = child["resources"][0]["values"]
    self_reference = _correlated_value(resource["values"], cleaned_values, "self_reference")
    attribute_reference = _correlated_value(resource["values"], cleaned_values, "attribute_reference")
    assert self_reference != mapped and self_reference.startswith("<redacted-")
    assert attribute_reference.startswith("<redacted-")
    assert child["resources"][0]["index"].startswith("key_")
    assert ".module_" in mapped and "[2]" in mapped
    serialized = json.dumps(exported)
    for sentinel in (
        "MODULE-NAME-SECRET", "TENANT.KEY.SECRET", "INNER-MODULE-SECRET",
        "RESOURCE-NAME-SECRET", "EDGE.KEY.SECRET", "PLAN-VALUE-SECRET",
    ):
        assert sentinel not in serialized


def test_all_pseudonym_namespaces_skip_raw_fixed_points_and_remain_deterministic():
    document = _linode_noop_plan()
    module_address = 'module.module_001["key_001"].module.module_002["key_002"]'
    child_resources = []
    for ordinal in (1, 2):
        name = f"resource_{ordinal:03d}"
        index = f"key_{ordinal:03d}"
        child_resources.append({
            "address": f'{module_address}.linode_instance.{name}["{index}"]',
            "module_address": module_address,
            "mode": "managed", "type": "linode_instance", "name": name, "index": index,
            "provider_name": "registry.terraform.io/linode/linode", "schema_version": 0,
            "values": {f"data_key_{ordinal:03d}": f"DATA-SECRET-{ordinal}"},
            "sensitive_values": {f"data_key_{ordinal:03d}": True},
        })
    document["planned_values"]["root_module"].setdefault("child_modules", []).append({
        "address": module_address,
        "resources": child_resources,
    })
    configuration = document["configuration"]
    configuration["provider_config"] = {
        f"provider_alias_{ordinal:03d}": {
            "name": "linode", "full_name": "registry.terraform.io/linode/linode",
        }
        for ordinal in (1, 2)
    }
    configuration["root_module"]["module_calls"] = {
        f"module_{ordinal:03d}": {} for ordinal in (1, 2)
    }
    for ordinal in (1, 2):
        variable = f"var_{ordinal:03d}"
        output = f"output_{ordinal:03d}"
        check = f"check_{ordinal:03d}"
        document["variables"][variable] = {"value": ordinal}
        configuration["root_module"]["variables"][variable] = {"default": ordinal}
        document["output_changes"][output] = {
            "actions": ["no-op"], "before": ordinal, "after": ordinal,
        }
        document["checks"].extend([
            {"address": {"kind": "var", "to_display": f"var.{variable}"}, "status": "pass"},
            {"address": {"kind": "output", "to_display": f"output.{output}"}, "status": "pass"},
            {"address": {"kind": "check", "to_display": f"check.{check}"}, "status": "pass"},
        ])

    first = export_firewall_contract(copy.deepcopy(document), "linode")
    second = export_firewall_contract(copy.deepcopy(document), "linode")
    assert first == second

    raw_tokens = {
        *(f"module_{ordinal:03d}" for ordinal in (1, 2)),
        *(f"resource_{ordinal:03d}" for ordinal in (1, 2)),
        *(f"key_{ordinal:03d}" for ordinal in (1, 2)),
        *(f"provider_alias_{ordinal:03d}" for ordinal in (1, 2)),
        *(f"data_key_{ordinal:03d}" for ordinal in (1, 2)),
        *(f"var_{ordinal:03d}" for ordinal in (1, 2)),
        *(f"output_{ordinal:03d}" for ordinal in (1, 2)),
        *(f"check_{ordinal:03d}" for ordinal in (1, 2)),
    }
    clean_child = first["planned_values"]["root_module"]["child_modules"][-1]
    emitted_addresses = [resource["address"] for resource in clean_child["resources"]]
    for address in emitted_addresses:
        capture.parse_terraform_address(address)
    emitted_tokens = set(re.findall(
        r"(?:module|resource|key|provider_alias|data_key|var|output|check)_\d{3}",
        json.dumps(first),
    ))
    assert not raw_tokens & emitted_tokens
    assert len(emitted_addresses) == len(set(emitted_addresses))
    assert all(re.fullmatch(r"provider_alias_\d{3}", key) for key in first["configuration"]["provider_config"])
    assert all(re.fullmatch(r"module_\d{3}", key) for key in first["configuration"]["root_module"]["module_calls"])


@pytest.mark.parametrize("mutation", ["malformed", "metadata", "unmapped-reference", "provider-conflict"])
def test_document_address_map_rejects_malformed_unmappable_or_inconsistent_metadata(mutation):
    document = _linode_noop_plan()
    compute = document["planned_values"]["root_module"]["resources"][1]
    if mutation == "malformed":
        compute["address"] = 'module.bad["unterminated].linode_instance.edge[0]'
    elif mutation == "metadata":
        compute["name"] = "other"
    elif mutation == "unmapped-reference":
        document["relevant_attributes"].append({"resource": "linode_instance.ghost[0]", "attribute": ["id"]})
    else:
        document["resource_changes"].append({
            "address": compute["address"], "mode": compute["mode"], "type": compute["type"],
            "name": compute["name"], "provider_name": "registry.terraform.io/hashicorp/local",
            "schema_version": 0, "change": {"actions": ["no-op"], "before": {}, "after": {}},
        })
    with pytest.raises(SketchProviderContractCaptureError):
        export_firewall_contract(document, "linode")


@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
def test_configuration_firewall_metadata_uses_provider_config_key_and_pseudonymizes_schema_keys(provider):
    document = _linode_noop_plan() if provider == "linode" else _digitalocean_full_plan()
    resource_type = "linode_firewall" if provider == "linode" else "digitalocean_firewall"
    full_name = (
        "registry.terraform.io/linode/linode"
        if provider == "linode"
        else "registry.terraform.io/digitalocean/digitalocean"
    )
    alias = "PROVIDER-ALIAS-SECRET"
    module_call = "MODULE-CALL-SECRET"
    configuration = document.setdefault("configuration", {})
    configuration["provider_config"] = {
        alias: {
            "name": provider, "full_name": full_name, "alias": "ALIAS-VALUE-SECRET",
            "module_address": f"module.{module_call}",
        },
    }
    root = configuration.setdefault("root_module", {})
    root["resources"] = [{
        "address": f"{resource_type}.firewall", "mode": "managed",
        "type": resource_type, "name": "firewall", "provider_config_key": alias,
        "expressions": {
            "name": {"constant_value": "CONFIG-FIREWALL-NAME-SECRET"},
            "count_probe": {"references": ["count.index"]},
        },
    }]
    root["module_calls"] = {
        module_call: {"source": "MODULE-SOURCE-SECRET", "expressions": {}, "providers": {alias: alias}},
    }

    exported = export_firewall_contract(document, provider)
    provider_keys = list(exported["configuration"]["provider_config"])
    module_keys = list(exported["configuration"]["root_module"]["module_calls"])
    config_resource = exported["configuration"]["root_module"]["resources"][0]
    assert provider_keys == ["provider_alias_001"]
    assert module_keys == ["module_001"]
    assert config_resource["provider_config_key"] == provider_keys[0]
    assert exported["configuration"]["provider_config"][provider_keys[0]]["module_address"] == f"module.{module_keys[0]}"
    module_provider_map = exported["configuration"]["root_module"]["module_calls"][module_keys[0]]["providers"]
    assert module_provider_map == {provider_keys[0]: provider_keys[0]}
    assert config_resource["address"] == f"{resource_type}.firewall"
    count_expression = next(
        item for item in config_resource["expressions"].values() if "references" in item
    )
    assert count_expression["references"] == ["count.index"]
    serialized = json.dumps(exported)
    for sentinel in (alias, module_call, "ALIAS-VALUE-SECRET", "MODULE-SOURCE-SECRET", "CONFIG-FIREWALL-NAME-SECRET"):
        assert sentinel not in serialized
    assert require_provider_firewall_ingress_update(
        json.dumps(exported), provider=provider, expected_delta=FirewallIngressDelta()
    ) == require_provider_firewall_ingress_update(
        json.dumps(document), provider=provider, expected_delta=FirewallIngressDelta()
    )


def test_nested_configuration_resource_expression_uses_owning_module_local_scope():
    document = _linode_noop_plan()
    configuration = document["configuration"]
    configuration["provider_config"] = {
        "linode": {"name": "linode", "full_name": "registry.terraform.io/linode/linode"},
    }
    configuration["root_module"]["module_calls"] = {
        "child": {"module": {"resources": [{
            "address": "module.child.linode_instance.nested", "mode": "managed",
            "type": "linode_instance", "name": "nested", "provider_config_key": "linode",
            "expressions": {"probe": {"references": ["local.shared", "count.index"]}},
        }]}},
    }
    configuration["root_module"]["outputs"] = {
        "root": {"expression": {"references": ["local.shared"]}},
    }
    exported = export_firewall_contract(document, "linode")
    root_reference = next(iter(exported["configuration"]["root_module"]["outputs"].values()))["expression"]["references"][0]
    child = next(iter(exported["configuration"]["root_module"]["module_calls"].values()))
    nested_expression = next(iter(child["module"]["resources"][0]["expressions"].values()))
    nested_references = nested_expression["references"]
    assert nested_references[0].startswith("local.local_")
    assert nested_references[0] != root_reference
    assert nested_references[1] == "count.index"


@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
def test_provider_payload_key_mimics_remain_generic_redacted_payload(provider):
    document = _linode_noop_plan() if provider == "linode" else _digitalocean_full_plan()
    compute = document["planned_values"]["root_module"]["resources"][1]
    resource_mimic = {
        "address": "PAYLOAD-ADDRESS-SECRET", "mode": "PAYLOAD-MODE-SECRET",
        "type": "PAYLOAD-TYPE-SECRET", "name": "PAYLOAD-NAME-SECRET",
    }
    check_mimic = {"kind": "PAYLOAD-KIND-SECRET", "to_display": "PAYLOAD-DISPLAY-SECRET"}
    compute["values"]["resource_mimic"] = resource_mimic
    compute["values"]["check_mimic"] = check_mimic
    document["resource_drift"][0]["change"]["before"]["resource_mimic"] = copy.deepcopy(resource_mimic)
    document["resource_drift"][0]["change"]["after"]["check_mimic"] = copy.deepcopy(check_mimic)

    exported = export_firewall_contract(document, provider)
    payload = exported["planned_values"]["root_module"]["resources"][1]["values"]
    cleaned_resource = _correlated_value(compute["values"], payload, "resource_mimic")
    cleaned_check = _correlated_value(compute["values"], payload, "check_mimic")
    assert _shape_equivalent(resource_mimic, cleaned_resource)
    assert _shape_equivalent(check_mimic, cleaned_check)
    assert _shape_equivalent(document, exported)
    serialized = json.dumps(exported)
    for sentinel in (*resource_mimic.values(), *check_mimic.values()):
        assert sentinel not in serialized


@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
@pytest.mark.parametrize("location", [
    "values", "before", "after", "before_sensitive", "after_sensitive", "after_unknown",
])
def test_structural_collection_names_inside_provider_payloads_never_invoke_parsers(provider, location):
    document = _linode_noop_plan() if provider == "linode" else _digitalocean_full_plan()
    payload = {
        "actions": ["PAYLOAD-ACTION-SECRET"],
        "module_calls": {"fixture": {"source": "PAYLOAD-MODULE-SECRET"}},
        "child_modules": [{"address": "PAYLOAD-CHILD-ADDRESS-SECRET"}],
        "expressions": {"token": {"references": ["PAYLOAD-REFERENCE-SECRET"]}},
        "PAYLOAD.BAD": {"SECRET-KEY-SENTINEL": "SECRET-KEY-VALUE"},
    }
    if location == "values":
        target = document["planned_values"]["root_module"]["resources"][1]["values"]
    else:
        target = document["resource_drift"][0]["change"].setdefault(location, {})
    target["structural_mimic"] = copy.deepcopy(payload)

    exported = export_firewall_contract(document, provider)
    if location == "values":
        cleaned_target = exported["planned_values"]["root_module"]["resources"][1]["values"]
    else:
        cleaned_target = exported["resource_drift"][0]["change"][location]
    cleaned = _correlated_value(target, cleaned_target, "structural_mimic")
    assert _shape_equivalent(payload, cleaned)
    serialized = json.dumps(cleaned)
    for sentinel in (
        "PAYLOAD-ACTION-SECRET", "PAYLOAD-MODULE-SECRET", "PAYLOAD-CHILD-ADDRESS-SECRET",
        "PAYLOAD-REFERENCE-SECRET", "PAYLOAD.BAD", "SECRET-KEY-SENTINEL", "SECRET-KEY-VALUE",
    ):
        assert sentinel not in serialized


def test_real_action_module_call_and_child_module_collections_use_structural_parsers():
    document = _linode_noop_plan()
    compute = copy.deepcopy(document["planned_values"]["root_module"]["resources"][1])
    document["resource_changes"] = [{
        key: copy.deepcopy(value) for key, value in compute.items()
        if key not in {"values", "sensitive_values"}
    } | {"change": {"actions": ["no-op"], "before": {}, "after": {}}}]
    document["resource_drift"][0]["change"]["actions"] = ["update"]
    document["deferred_changes"][0]["resource_change"]["change"]["actions"] = ["no-op"]
    root = document["configuration"]["root_module"]
    root["module_calls"] = {
        "OUTER-MODULE-SECRET": {"module": {"module_calls": {
            "INNER-MODULE-SECRET": {"module": {"resources": []}},
        }}},
    }
    planned_child = {
        "address": "module.PLANNED-MODULE-SECRET",
        "resources": [],
    }
    document["planned_values"]["root_module"].setdefault("child_modules", []).append(planned_child)
    document["prior_state"]["values"]["root_module"] = {
        "resources": [],
        "child_modules": [{"address": "module.PRIOR-MODULE-SECRET", "resources": []}],
    }

    exported = export_firewall_contract(document, "linode")
    assert exported["resource_changes"][0]["change"]["actions"] == ["no-op"]
    assert exported["resource_drift"][0]["change"]["actions"] == ["update"]
    assert exported["deferred_changes"][0]["resource_change"]["change"]["actions"] == ["no-op"]
    outer_key = next(iter(exported["configuration"]["root_module"]["module_calls"]))
    inner_calls = exported["configuration"]["root_module"]["module_calls"][outer_key]["module"]["module_calls"]
    assert outer_key.startswith("module_") and next(iter(inner_calls)).startswith("module_")
    assert exported["planned_values"]["root_module"]["child_modules"][-1]["address"].startswith("module.module_")
    assert exported["prior_state"]["values"]["root_module"]["child_modules"][0]["address"].startswith("module.module_")
    serialized = json.dumps(exported)
    for sentinel in ("OUTER-MODULE-SECRET", "INNER-MODULE-SECRET", "PLANNED-MODULE-SECRET", "PRIOR-MODULE-SECRET"):
        assert sentinel not in serialized


@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
def test_generic_value_and_mask_keys_share_one_document_namespace(provider):
    document = _linode_noop_plan() if provider == "linode" else _digitalocean_full_plan()
    key = "PAYLOAD.BAD"
    compute = document["planned_values"]["root_module"]["resources"][1]
    compute["values"][key] = {"SECRET-KEY-SENTINEL": "VALUE-SECRET"}
    compute["sensitive_values"][key] = {"SECRET-KEY-SENTINEL": True}
    change = document["resource_drift"][0]["change"]
    for field, value in (
        ("before", "BEFORE-SECRET"), ("after", "AFTER-SECRET"),
        ("before_sensitive", True), ("after_sensitive", True), ("after_unknown", False),
    ):
        change.setdefault(field, {})[key] = {"SECRET-KEY-SENTINEL": value}
    deferred_change = document["deferred_changes"][0]["resource_change"]["change"]
    deferred_change["importing"][key] = {"SECRET-KEY-SENTINEL": "DEFERRED-SECRET-VALUE"}

    exported = export_firewall_contract(document, provider)
    clean_compute = exported["planned_values"]["root_module"]["resources"][1]
    correlated_keys = []
    for raw_map, clean_map in (
        (compute["values"], clean_compute["values"]),
        (compute["sensitive_values"], clean_compute["sensitive_values"]),
        *((change[field], exported["resource_drift"][0]["change"][field]) for field in (
            "before", "after", "before_sensitive", "after_sensitive", "after_unknown",
        )),
        (deferred_change["importing"], exported["deferred_changes"][0]["resource_change"]["change"]["importing"]),
    ):
        position = list(raw_map).index(key)
        correlated_keys.append(list(clean_map)[position])
    assert len(set(correlated_keys)) == 1
    assert correlated_keys[0].startswith("data_key_")
    serialized = json.dumps(exported)
    for sentinel in (key, "SECRET-KEY-SENTINEL", "VALUE-SECRET", "BEFORE-SECRET", "AFTER-SECRET", "DEFERRED-SECRET-VALUE"):
        assert sentinel not in serialized


def test_dynamic_variable_and_output_keys_correlate_with_symbol_addresses():
    document = _linode_noop_plan()
    variable_name = "VARIABLE-KEY-SECRET"
    output_name = "OUTPUT-KEY-SECRET"
    document["variables"][variable_name] = {"value": {"SECRET-KEY-SENTINEL": "VARIABLE-VALUE-SECRET"}}
    document["configuration"]["root_module"].setdefault("variables", {})[variable_name] = {
        "default": {"SECRET-KEY-SENTINEL": "VARIABLE-DEFAULT-SECRET"},
    }
    document["output_changes"][output_name] = {
        "actions": ["update"], "before": {"SECRET-KEY-SENTINEL": "OUTPUT-BEFORE-SECRET"},
        "after": {"SECRET-KEY-SENTINEL": "OUTPUT-AFTER-SECRET"},
    }
    document["checks"].extend([
        {"address": {"kind": "var", "to_display": f"var.{variable_name}"}, "status": "pass"},
        {"address": {"kind": "output", "to_display": f"output.{output_name}"}, "status": "pass"},
    ])
    exported = export_firewall_contract(document, "linode")
    variable_key = list(exported["variables"])[list(document["variables"]).index(variable_name)]
    config_variable_key = list(exported["configuration"]["root_module"]["variables"])[
        list(document["configuration"]["root_module"]["variables"]).index(variable_name)
    ]
    output_key = list(exported["output_changes"])[list(document["output_changes"]).index(output_name)]
    assert variable_key == config_variable_key
    assert exported["checks"][-2]["address"]["to_display"] == f"var.{variable_key}"
    assert exported["checks"][-1]["address"]["to_display"] == f"output.{output_key}"
    serialized = json.dumps(exported)
    for sentinel in (
        variable_name, output_name, "SECRET-KEY-SENTINEL", "VARIABLE-VALUE-SECRET",
        "VARIABLE-DEFAULT-SECRET", "OUTPUT-BEFORE-SECRET", "OUTPUT-AFTER-SECRET",
    ):
        assert sentinel not in serialized


@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
def test_configuration_constant_value_keys_correlate_with_runtime_and_mask_data(provider):
    document = _linode_noop_plan() if provider == "linode" else _digitalocean_full_plan()
    shared_key = "CONSTANT.SHARED.KEY"
    nested_key = "CONSTANT.NESTED.KEY"
    deep_key = "CONSTANT.DEEP.KEY"
    value = {
        shared_key: {
            nested_key: ["CONSTANT-VALUE-SECRET", None, True],
            deep_key: {shared_key: 73},
        },
    }
    mask = {shared_key: {nested_key: [True, False, False], deep_key: {shared_key: False}}}
    compute = document["planned_values"]["root_module"]["resources"][1]
    compute["values"].update(copy.deepcopy(value))
    compute["sensitive_values"].update(copy.deepcopy(mask))
    change = document["resource_drift"][0]["change"]
    for field in ("before", "after"):
        change[field].update(copy.deepcopy(value))
    for field in ("before_sensitive", "after_sensitive", "after_unknown"):
        change[field].update(copy.deepcopy(mask))
    output_name = "constant_fixture"
    document["prior_state"]["values"]["outputs"][output_name] = {
        "sensitive": True, "value": copy.deepcopy(value),
    }
    document["configuration"]["root_module"]["module_calls"] = {
        "constant_fixture": {
            "expressions": {"input": {"constant_value": copy.deepcopy(value)}},
        },
    }
    provider_name = (
        "registry.terraform.io/linode/linode"
        if provider == "linode"
        else "registry.terraform.io/digitalocean/digitalocean"
    )
    provider_alias = "constant_fixture"
    document["configuration"]["provider_config"] = {
        provider_alias: {"name": provider, "full_name": provider_name},
    }
    document["configuration"]["root_module"]["resources"] = [{
        "address": compute["address"], "mode": compute["mode"], "type": compute["type"],
        "name": compute["name"], "index": 0, "provider_config_key": provider_alias,
        "expressions": {"input": {"constant_value": copy.deepcopy(value)}},
    }]
    configuration_output = "constant_output"
    document["configuration"]["root_module"]["outputs"] = {
        configuration_output: {"expression": {"constant_value": copy.deepcopy(value)}},
    }

    sanitizer = capture.TerraformShowSanitizer(document, provider)
    sanitizer.prepare()
    exported = sanitizer.sanitize(document, ())
    mapped_shared = sanitizer.data_key_names[shared_key]
    mapped_nested = sanitizer.data_key_names[nested_key]
    mapped_deep = sanitizer.data_key_names[deep_key]
    clean_compute = exported["planned_values"]["root_module"]["resources"][1]
    clean_change = exported["resource_drift"][0]["change"]
    clean_output = exported["prior_state"]["values"]["outputs"][sanitizer.symbol_names["output"][output_name]]["value"]
    clean_module = exported["configuration"]["root_module"]["module_calls"][sanitizer.module_names["constant_fixture"]]
    mapped_input = sanitizer.data_key_names["input"]
    clean_constant = clean_module["expressions"][mapped_input]["constant_value"]
    clean_resource_constant = exported["configuration"]["root_module"]["resources"][0]["expressions"][mapped_input]["constant_value"]
    clean_output_constant = exported["configuration"]["root_module"]["outputs"][sanitizer.symbol_names["output"][configuration_output]]["expression"]["constant_value"]
    for clean_map in (
        clean_compute["values"], clean_compute["sensitive_values"],
        *(clean_change[field] for field in (
            "before", "after", "before_sensitive", "after_sensitive", "after_unknown",
        )),
        clean_output, clean_constant, clean_resource_constant, clean_output_constant,
    ):
        assert set(clean_map) >= {mapped_shared}
        assert set(clean_map[mapped_shared]) == {mapped_nested, mapped_deep}
        assert set(clean_map[mapped_shared][mapped_deep]) == {mapped_shared}
    constant_list = clean_constant[mapped_shared][mapped_nested]
    assert len(constant_list) == 3
    assert isinstance(constant_list[0], str) and constant_list[0] != "CONSTANT-VALUE-SECRET"
    assert constant_list[1] is None
    assert constant_list[2] is True
    serialized = json.dumps(exported)
    for sentinel in (shared_key, nested_key, deep_key, "CONSTANT-VALUE-SECRET"):
        assert sentinel not in serialized


@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
def test_configuration_expression_member_keys_are_private_and_correlated(provider):
    document = _linode_noop_plan() if provider == "linode" else _digitalocean_full_plan()
    compute = document["planned_values"]["root_module"]["resources"][1]
    full_name = (
        "registry.terraform.io/linode/linode"
        if provider == "linode"
        else "registry.terraform.io/digitalocean/digitalocean"
    )
    alias = "EXPRESSION-PROVIDER-ALIAS"
    shared = "token"
    collision_key = "data_key_001"
    expression_keys = {
        shared, "public_key", "authorized_keys", "root_pass", "user_data", collision_key,
    }
    generic = {"expressions": {shared: "GENERIC-PAYLOAD-SECRET"}}
    compute["values"].update(copy.deepcopy(generic))
    compute["sensitive_values"].update({"expressions": {shared: True}})
    document["configuration"]["provider_config"] = {
        alias: {
            "name": provider,
            "full_name": full_name,
            "expressions": {shared: {"constant_value": "PROVIDER-TOKEN-SECRET"}},
        },
    }
    root = document["configuration"]["root_module"]
    root["resources"] = [{
        "address": compute["address"], "mode": compute["mode"], "type": compute["type"],
        "name": compute["name"], "index": 0, "provider_config_key": alias,
        "expressions": {
            "public_key": {"references": ["local.shared"]},
            "authorized_keys": {"constant_value": {shared: "RESOURCE-CONSTANT-SECRET"}},
            collision_key: {"constant_value": "COLLISION-KEY-SECRET"},
            shared: {"constant_value": "RESOURCE-TOKEN-SECRET"},
        },
    }]
    nested_type = compute["type"]
    root["module_calls"] = {
        "child": {
            "expressions": {
                "user_data": {"references": ["local.shared"]},
                shared: {"constant_value": {shared: "MODULE-CONSTANT-SECRET"}},
            },
            "module": {
                "resources": [{
                    "address": f"module.child.{nested_type}.nested", "mode": "managed",
                    "type": nested_type, "name": "nested", "provider_config_key": alias,
                    "expressions": {"root_pass": {"references": ["local.shared"]}},
                }],
                "module_calls": {
                    "grandchild": {
                        "expressions": {shared: {"constant_value": "NESTED-MODULE-SECRET"}},
                    },
                },
            },
        },
    }

    sanitizer = capture.TerraformShowSanitizer(document, provider)
    sanitizer.prepare()
    exported = sanitizer.sanitize(document, ())
    mapped = {key: sanitizer.data_key_names[key] for key in expression_keys}
    provider_config = next(iter(exported["configuration"]["provider_config"].values()))
    config_resource = exported["configuration"]["root_module"]["resources"][0]
    child = next(iter(exported["configuration"]["root_module"]["module_calls"].values()))
    nested_resource = child["module"]["resources"][0]
    grandchild = next(iter(child["module"]["module_calls"].values()))
    assert set(provider_config["expressions"]) == {mapped[shared]}
    assert set(config_resource["expressions"]) == {
        mapped["public_key"], mapped["authorized_keys"], mapped[collision_key], mapped[shared],
    }
    assert set(child["expressions"]) == {mapped["user_data"], mapped[shared]}
    assert set(nested_resource["expressions"]) == {mapped["root_pass"]}
    assert set(grandchild["expressions"]) == {mapped[shared]}
    assert config_resource["expressions"][mapped["public_key"]]["references"][0].startswith("local.local_")
    assert child["expressions"][mapped["user_data"]]["references"][0].startswith("local.local_")
    assert nested_resource["expressions"][mapped["root_pass"]]["references"][0].startswith("local.local_")
    assert set(config_resource["expressions"][mapped["authorized_keys"]]["constant_value"]) == {mapped[shared]}
    assert set(child["expressions"][mapped[shared]]["constant_value"]) == {mapped[shared]}
    assert mapped[collision_key] != collision_key
    clean_compute = exported["planned_values"]["root_module"]["resources"][1]
    mapped_expressions = sanitizer.data_key_names["expressions"]
    assert set(clean_compute["values"][mapped_expressions]) == {mapped[shared]}
    assert set(clean_compute["sensitive_values"][mapped_expressions]) == {mapped[shared]}
    serialized = json.dumps(exported)
    for sentinel in (*expression_keys, "GENERIC-PAYLOAD-SECRET", "PROVIDER-TOKEN-SECRET",
                     "RESOURCE-CONSTANT-SECRET", "RESOURCE-TOKEN-SECRET",
                     "COLLISION-KEY-SECRET", "MODULE-CONSTANT-SECRET", "NESTED-MODULE-SECRET"):
        assert f'"{sentinel}"' not in serialized
    assert _shape_equivalent(document, exported)


def test_configuration_expression_map_classifier_is_exact_and_recursive():
    valid = [
        ("configuration", "provider_config", "alias", "expressions"),
        ("configuration", "root_module", "resources", "0", "expressions"),
        ("configuration", "root_module", "module_calls", "child", "expressions"),
        ("configuration", "root_module", "module_calls", "child", "module", "resources", "0", "expressions"),
        ("configuration", "root_module", "module_calls", "child", "module", "module_calls", "grand", "expressions"),
    ]
    invalid = [
        ("configuration", "expressions"),
        ("configuration", "root_module", "expressions"),
        ("configuration", "root_module", "outputs", "out", "expressions"),
        ("planned_values", "root_module", "resources", "0", "expressions"),
        ("configuration", "root_module", "resources", "0", "values", "expressions"),
        ("configuration", "provider_config", "alias", "payload", "expressions"),
    ]
    assert all(capture.is_configuration_expression_map_path(path) for path in valid)
    assert not any(capture.is_configuration_expression_map_path(path) for path in invalid)


def test_non_resource_check_addresses_use_separate_correlated_namespaces():
    document = _linode_noop_plan()
    addresses = [
        ("output", "output.OUTPUT-NAME-SECRET"),
        ("output", "output.OUTPUT-NAME-SECRET"),
        ("var", "var.VARIABLE-NAME-SECRET"),
        ("check", 'module.MODULE-NAME-SECRET["TENANT-KEY-SECRET"].check.CHECK-NAME-SECRET'),
    ]
    document["checks"].extend(
        {"address": {"kind": kind, "to_display": address}, "status": "pass"}
        for kind, address in addresses
    )
    document["configuration"]["root_module"]["outputs"] = {
        "symbol_reference_holder": {"expression": {"references": [address for _kind, address in addresses]}}
    }
    exported = export_firewall_contract(document, "linode")
    mapped = [row["address"]["to_display"] for row in exported["checks"][-4:]]
    assert mapped[0] == mapped[1] == "output.output_001"
    assert mapped[2] == "var.var_001"
    assert mapped[3].endswith(".check.check_001")
    holder = next(iter(exported["configuration"]["root_module"]["outputs"].values()))
    assert mapped == holder["expression"]["references"]
    serialized = json.dumps(exported)
    for sentinel in ("OUTPUT-NAME-SECRET", "VARIABLE-NAME-SECRET", "MODULE-NAME-SECRET", "TENANT-KEY-SECRET", "CHECK-NAME-SECRET"):
        assert sentinel not in serialized


def _add_real_like_configuration_references(document, provider):
    root = document["configuration"]["root_module"]
    variable_names = {
        "root_pass", "engagement_name", "ssh_config_path", "ssh_priv_key_path", "ssh_pub_key_path",
    }
    root["variables"] = {name: {} for name in variable_names}
    document["variables"] = {name: {"value": f"SECRET-{name}"} for name in variable_names}
    local_refs = [
        "local.abs_ssh_config_path", "local.default_ssh_priv_key", "local.default_ssh_pub_key",
        "local.ssh_priv_key_path", "local.ssh_pub_key_path", "local.ssh_priv_key_path",
    ]
    compute = document["planned_values"]["root_module"]["resources"][1]["address"]
    references = [
        "var.engagement_name", "var.ssh_config_path", *local_refs, "count.index",
        f"{compute}.id",
    ]
    if provider == "digitalocean":
        key_resource = {
            "address": "digitalocean_ssh_key.sketch_ssh_key_id", "mode": "managed",
            "type": "digitalocean_ssh_key", "name": "sketch_ssh_key_id",
            "provider_name": "registry.terraform.io/digitalocean/digitalocean", "schema_version": 0,
            "values": {"id": "SSH-KEY-SECRET"}, "sensitive_values": {"id": False},
        }
        document["planned_values"]["root_module"]["resources"].append(key_resource)
        references.append("digitalocean_ssh_key.sketch_ssh_key_id.id")
    root["outputs"] = {
        "reference_probe": {"expression": {"references": references}},
    }
    return references


@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
def test_real_like_provider_configuration_references_are_complete_correlated_and_private(provider):
    document = _linode_noop_plan() if provider == "linode" else _digitalocean_full_plan()
    raw_references = _add_real_like_configuration_references(document, provider)
    exported = export_firewall_contract(document, provider)
    output = next(iter(exported["configuration"]["root_module"]["outputs"].values()))
    cleaned = output["expression"]["references"]
    assert len(cleaned) == len(raw_references)
    assert cleaned[8] == "count.index"
    assert cleaned[5] == cleaned[7]
    assert all(value.startswith("local.local_") for value in cleaned[2:8])
    serialized = json.dumps(exported)
    for sentinel in (
        "abs_ssh_config_path", "default_ssh_priv_key", "default_ssh_pub_key",
        "ssh_priv_key_path", "ssh_pub_key_path", "SSH-KEY-SECRET",
    ):
        assert sentinel not in serialized
    assert require_provider_firewall_ingress_update(
        json.dumps(document), provider=provider, expected_delta=FirewallIngressDelta()
    ) == require_provider_firewall_ingress_update(
        json.dumps(exported), provider=provider, expected_delta=FirewallIngressDelta()
    )
    assert canonical_firewall_semantics(document, provider, redact=True) == canonical_firewall_semantics(
        exported, provider, redact=False
    )
    assert _shape_equivalent(document, exported)


def test_configuration_local_names_are_module_scoped_and_collision_safe():
    document = _linode_noop_plan()
    root = document["configuration"]["root_module"]
    root["outputs"] = {
        "root_probe": {"expression": {"references": ["local.local_001", "local.shared"]}},
    }
    root["module_calls"] = {
        "child": {
            "expressions": {"input": {"references": ["local.shared"]}},
            "module": {"outputs": {
                "child_probe": {"expression": {"references": ["local.shared", "local.local_001"]}},
            }},
        },
    }
    exported = export_firewall_contract(document, "linode")
    root_output = next(iter(exported["configuration"]["root_module"]["outputs"].values()))
    module_call = next(iter(exported["configuration"]["root_module"]["module_calls"].values()))
    module_input = next(iter(module_call["expressions"].values()))["references"][0]
    child_output = next(iter(module_call["module"]["outputs"].values()))["expression"]["references"]
    assert root_output["expression"]["references"][1] == module_input
    assert module_input != child_output[0]
    assert all(value != "local.local_001" for value in (*root_output["expression"]["references"], *child_output))
    assert json.dumps(exported, sort_keys=True) == json.dumps(export_firewall_contract(document, "linode"), sort_keys=True)


def test_all_pseudonym_namespaces_reserve_every_other_namespace_raw_identity():
    prefixes = (
        "module", "resource", "key", "provider_alias", "check", "output", "var",
        "local", "data_key", "rule_label",
    )
    raw_identities = {f"{prefix}_{ordinal:03d}" for prefix in prefixes for ordinal in (1, 2, 9)}
    sanitizer = capture.TerraformShowSanitizer({}, "linode")
    sanitizer.module_call_names = set(raw_identities)
    sanitizer.resources = {
        ((), "managed", "linode_instance", name, None): ("registry.terraform.io/linode/linode", 0)
        for name in raw_identities
    }
    sanitizer.address_keys = set(raw_identities)
    sanitizer.provider_configs = {
        name: "registry.terraform.io/linode/linode" for name in raw_identities
    }
    sanitizer.symbol_values = {kind: set(raw_identities) for kind in ("check", "output", "var")}
    sanitizer.local_values = {((), name) for name in raw_identities}
    sanitizer.data_keys = set(raw_identities)
    sanitizer.firewall_rule_labels = set(raw_identities)
    sanitizer._allocate_identity_names()
    emitted_by_namespace = {
        "module": set(sanitizer.module_names.values()),
        "resource": set(sanitizer.resource_names.values()),
        "key": set(sanitizer.key_names.values()),
        "provider_alias": set(sanitizer.provider_alias_names.values()),
        "check": set(sanitizer.symbol_names["check"].values()),
        "output": set(sanitizer.symbol_names["output"].values()),
        "var": set(sanitizer.symbol_names["var"].values()),
        "local": set(sanitizer.local_names.values()),
        "data_key": set(sanitizer.data_key_names.values()),
        "rule_label": set(sanitizer.firewall_rule_label_names.values()),
    }
    for namespace, emitted in emitted_by_namespace.items():
        assert emitted.isdisjoint(raw_identities), namespace
        assert len(emitted) == len(raw_identities)
    all_emitted = set().union(*emitted_by_namespace.values())
    assert all_emitted.isdisjoint(raw_identities)


def test_variable_raw_local_candidate_cannot_equal_emitted_local_pseudonym():
    document = _linode_noop_plan()
    root = document["configuration"]["root_module"]
    root["variables"] = {"local_001": {}}
    document["variables"] = {"local_001": {"value": "VARIABLE-VALUE-SECRET"}}
    root["outputs"] = {
        "probe": {"expression": {"references": ["local.secret"]}},
    }
    exported = export_firewall_contract(document, "linode")
    output = next(iter(exported["configuration"]["root_module"]["outputs"].values()))
    assert output["expression"]["references"] == ["local.local_002"]
    serialized = json.dumps(exported)
    assert "local_001" not in serialized
    assert "VARIABLE-VALUE-SECRET" not in serialized
    assert exported["planned_values"]["root_module"]["resources"][0]["address"] == "linode_firewall.firewall"


@pytest.mark.parametrize("reference", [
    "local", "local.", "local.name.extra", 'local.name["secret"]',
    "count", "count.key", "count.index.extra",
    "each.key", "each.value", "path.module", "path.root", "path.cwd", "terraform.workspace",
    "unknown.value",
])
def test_configuration_reference_rejects_malformed_unknown_and_unreviewed_builtins(reference):
    document = _linode_noop_plan()
    document["configuration"]["root_module"]["outputs"] = {
        "probe": {"expression": {"references": [reference]}},
    }
    with pytest.raises(SketchProviderContractCaptureError, match="reference|unmappable|unsupported"):
        export_firewall_contract(document, "linode")


@pytest.mark.parametrize("references", [None, "local.valid", ["local.valid", 7], {"0": "local.valid"}])
def test_configuration_references_require_a_list_of_strings(references):
    document = _linode_noop_plan()
    document["configuration"]["root_module"]["outputs"] = {
        "probe": {"expression": {"references": references}},
    }
    with pytest.raises(SketchProviderContractCaptureError, match="references were invalid"):
        export_firewall_contract(document, "linode")


@pytest.mark.parametrize("location", ["values", "before", "after", "before_sensitive", "after_sensitive", "after_unknown", "constant_value"])
def test_reference_looking_provider_data_never_invokes_reference_parser(location):
    document = _linode_noop_plan()
    payload = {"references": ["local.PAYLOAD_LOCAL_SECRET", "count.key", "path.module", "UNKNOWN.VALUE"]}
    if location == "values":
        document["planned_values"]["root_module"]["resources"][1]["values"]["payload"] = payload
    elif location == "constant_value":
        document["configuration"]["root_module"].setdefault("outputs", {})["constant"] = {
            "expression": {"constant_value": payload}
        }
    else:
        document["resource_drift"][0]["change"][location] = payload
    exported = export_firewall_contract(document, "linode")
    serialized = json.dumps(exported)
    for sentinel in ("PAYLOAD_LOCAL_SECRET", "count.key", "path.module", "UNKNOWN.VALUE"):
        assert sentinel not in serialized


def test_configuration_reference_path_classifier_accepts_only_real_expression_schemas():
    valid = [
        ("configuration", "root_module", "resources", "0", "expressions", "x", "references"),
        ("configuration", "root_module", "module_calls", "child", "expressions", "x", "references"),
        ("configuration", "root_module", "outputs", "x", "expression", "references"),
        ("configuration", "root_module", "module_calls", "child", "module", "resources", "0", "expressions", "x", "references"),
        ("configuration", "root_module", "module_calls", "child", "module", "outputs", "x", "expression", "references"),
    ]
    assert all(capture.is_configuration_references_path(path) for path in valid)
    invalid = [
        ("configuration", "references"),
        ("configuration", "root_module", "references"),
        ("configuration", "root_module", "resources", "0", "values", "references"),
        ("configuration", "provider_config", "alias", "references"),
    ]
    assert not any(capture.is_configuration_references_path(path) for path in invalid)


def test_non_resource_check_address_rejects_unknown_kind():
    document = _linode_noop_plan()
    document["checks"].append({"address": {"kind": "local", "to_display": "local.secret"}, "status": "pass"})
    with pytest.raises(SketchProviderContractCaptureError, match="kind"):
        export_firewall_contract(document, "linode")


def test_explicit_null_resource_index_preserves_presence_and_null_value():
    document = _linode_noop_plan()
    document["planned_values"]["root_module"]["resources"][0]["index"] = None
    exported = export_firewall_contract(document, "linode")
    assert "index" in exported["planned_values"]["root_module"]["resources"][0]
    assert exported["planned_values"]["root_module"]["resources"][0]["index"] is None


def test_explicit_null_resource_index_rejects_indexed_address_with_domain_error():
    document = _linode_noop_plan()
    document["planned_values"]["root_module"]["resources"][1]["index"] = None
    with pytest.raises(SketchProviderContractCaptureError, match="index metadata"):
        export_firewall_contract(document, "linode")


def test_version_json_requires_exact_schema_types_platform_and_provider_selection():
    valid = json.dumps({
        "terraform_version": "1.15.5", "platform": "linux_amd64", "terraform_outdated": False,
        "provider_selections": {
            "registry.terraform.io/linode/linode": "4.5.0",
            "registry.terraform.io/hashicorp/local": "2.9.1",
            "registry.terraform.io/hashicorp/random": "3.9.1",
        },
    })
    assert validate_terraform_version(valid, "linode")["terraform_version"] == "1.15.5"
    for invalid in (
        {**json.loads(valid), "platform": "darwin_arm64"},
        {**json.loads(valid), "unexpected": "value"},
        {**json.loads(valid), "provider_selections": {"registry.terraform.io/linode/linode": "4.5.0"}},
        {**json.loads(valid), "terraform_outdated": "false"},
    ):
        with pytest.raises(SketchProviderContractCaptureError): validate_terraform_version(json.dumps(invalid), "linode")

    digitalocean = json.dumps({
        "terraform_version": "1.15.5", "platform": "linux_amd64",
        "provider_selections": {
            "registry.terraform.io/digitalocean/digitalocean": "2.68.0",
            "registry.terraform.io/hashicorp/local": "2.9.1",
        },
    })
    assert set(validate_terraform_version(digitalocean, "digitalocean")["provider_selections"]) == {
        "registry.terraform.io/digitalocean/digitalocean", "registry.terraform.io/hashicorp/local",
    }


@pytest.mark.parametrize("field,value", [
    ("mode", "data"),
    ("type", "linode_instance"),
    ("name", "other"),
    ("provider_name", "registry.terraform.io/hashicorp/local"),
    ("schema_version", 1),
])
def test_export_rejects_noncanonical_provider_firewall_metadata(field, value):
    document = _linode_noop_plan()
    document["planned_values"]["root_module"]["resources"][0][field] = value
    with pytest.raises(SketchProviderContractCaptureError, match="firewall"):
        export_firewall_contract(document, "linode")


def test_shape_export_preserves_false_and_true_unknown_trees_exactly():
    document = _linode_noop_plan()
    values = document["planned_values"]["root_module"]["resources"][0]["values"]
    document["resource_changes"] = [{
        "address": "linode_firewall.firewall", "mode": "managed", "type": "linode_firewall",
        "name": "firewall", "provider_name": "registry.terraform.io/linode/linode",
        "change": {"actions": ["update"], "before": values, "after": values,
                   "after_unknown": {"inbound": [{"ports": False}], "status": True}},
    }]
    exported = export_firewall_contract(document, "linode")
    raw_unknown = document["resource_changes"][0]["change"]["after_unknown"]
    clean_unknown = exported["resource_changes"][0]["change"]["after_unknown"]
    assert _shape_equivalent(raw_unknown, clean_unknown)
    clean_inbound = _correlated_value(raw_unknown, clean_unknown, "inbound")
    assert next(iter(clean_inbound[0].values())) is False
    document["resource_changes"][0]["change"]["after_unknown"]["inbound"][0]["ports"] = True
    exported = export_firewall_contract(document, "linode")
    clean_unknown = exported["resource_changes"][0]["change"]["after_unknown"]
    clean_inbound = _correlated_value(raw_unknown, clean_unknown, "inbound")
    assert next(iter(clean_inbound[0].values())) is True


def test_clone_rejects_source_hardlinks(tmp_path: Path):
    source = _workspace(tmp_path)
    os.link(source / "firewall.tf", source / "firewall-copy.tf")
    with pytest.raises(SketchProviderContractCaptureError, match="hardlinked"):
        _clone_workspace(source, tmp_path / "clone")


def test_clone_rejects_special_files_even_when_they_are_not_allowlisted(tmp_path: Path):
    source = _workspace(tmp_path)
    os.mkfifo(source / "provider-debug.pipe", 0o600)
    with pytest.raises(SketchProviderContractCaptureError, match="link or special"):
        _clone_workspace(source, tmp_path / "clone")


def test_runtime_role_selection_is_edge_only_for_same_provider(tmp_path: Path, monkeypatch):
    workspace = _workspace(tmp_path)
    _engagement, chain, job = _records(workspace)
    monkeypatch.setattr(capture, "validate_existing_sketch_state_workspace", lambda *_a, **_k: SimpleNamespace(path=workspace))
    roles = runtime_roles(
        CaptureRequest("eng-test", "chain-test", "channel-test", "no-op", "capture-abcd1234"),
        chain, job, _channel(), chain.nodes,
    )
    assert [(role.role, role.provider) for role in roles] == [("edge", "linode")]


def test_capture_rejects_channel_bound_to_a_different_chain(tmp_path: Path):
    workspace = _workspace(tmp_path)
    _engagement, chain, job = _records(workspace)
    with pytest.raises(SketchProviderContractCaptureError, match="not bound"):
        load_capture_state(
            CaptureRequest("eng-test", "chain-test", "channel-test", "no-op", "capture-abcd1234"),
            Repo(chain), Repo(job),
            lambda _id: {"inboundChannels": [{"channelId": "channel-test", "chainId": "other-chain", "status": "Validated"}]},
        )


def test_capture_rejects_preexisting_running_mutation_after_lease(tmp_path: Path):
    workspace = _workspace(tmp_path)
    _engagement, chain, job = _records(workspace)
    running = replace(job, id="job-running", action="mixed_provider_sketch_reconcile", status="running")
    class Jobs(Repo):
        def list_for_engagement(self, *_args): return [running]
    with pytest.raises(SketchProviderContractCaptureError, match="already running"):
        load_capture_state(
            CaptureRequest("eng-test", "chain-test", "channel-test", "no-op", "capture-abcd1234"),
            Repo(chain), Jobs(job), lambda _id: {"inboundChannels": []},
        )


def test_runtime_role_selection_is_mixed_edge_then_middle(tmp_path: Path, monkeypatch):
    edge = _workspace(tmp_path)
    middle = tmp_path / "middle"; middle.mkdir()
    chain = replace(_records(edge)[1], middle_provider="digitalocean")
    parent = _records(edge)[2]
    edge_input = {**parent.input, "provider": "linode", "middleCount": 0, "edgeCount": 1, "componentId": "edge-component"}
    middle_input = {**parent.input, "provider": "digitalocean", "middleCount": 1, "edgeCount": 0, "componentId": "middle-component", "terraformWorkingDirectory": str(middle)}
    edge_input.update({"engagementId": "eng-test", "chainId": "chain-test", "componentId": "edge-component"})
    middle_input.update({"engagementId": "eng-test", "chainId": "chain-test", "componentId": "middle-component"})
    components = [
        {"componentId": "middle-component", "role": "middle", "provider": "digitalocean"},
        {"componentId": "edge-component", "role": "edge", "provider": "linode"},
    ]
    job = replace(parent, action="mixed_provider_sketch_deploy", input={
        "engagementId": "eng-test", "chainId": "chain-test",
        "middleProvider": "digitalocean", "edgeProvider": "linode",
        "components": components,
        "childInputs": {"middle-component": middle_input, "edge-component": edge_input},
        "terraformWorkingDirectories": {"edge-component": str(edge), "middle-component": str(middle)},
    })
    chain = replace(chain, nodes=[
        {"chainId": "chain-test", "hostname": "middle-01", "componentId": "middle-component", "role": "middle", "provider": "digitalocean"},
        {"chainId": "chain-test", "hostname": "edge-01", "componentId": "edge-component", "role": "edge", "provider": "linode"},
    ])
    monkeypatch.setattr(capture, "validate_existing_sketch_state_workspace", lambda *_a, **kw: SimpleNamespace(path=middle if kw.get("component_id") == "middle-component" else edge))
    roles = runtime_roles(
        CaptureRequest("eng-test", "chain-test", "channel-test", "no-op", "capture-abcd1234"),
        chain, job, _channel(), chain.nodes,
    )
    assert [(role.role, role.provider, role.workspace) for role in roles] == [
        ("edge", "linode", edge), ("middle", "digitalocean", middle),
    ]


def test_runtime_role_selection_uses_selected_second_same_provider_edge_with_reversed_children(tmp_path: Path, monkeypatch):
    base = _workspace(tmp_path)
    middle = tmp_path / "middle-component"; middle.mkdir()
    edge_one = tmp_path / "edge-one"; edge_one.mkdir()
    edge_two = tmp_path / "edge-two"; edge_two.mkdir()
    _engagement, original_chain, parent = _records(base)
    rows = [
        {"chainId": "chain-test", "hostname": "middle-01", "componentId": "middle-component", "role": "middle", "provider": "linode"},
        {"chainId": "chain-test", "hostname": "edge-01", "componentId": "edge-one", "role": "edge", "provider": "linode"},
        {"chainId": "chain-test", "hostname": "edge-02", "componentId": "edge-two", "role": "edge", "provider": "linode"},
    ]
    chain = replace(original_chain, edge_count=2, nodes=rows)
    def child(component_id, role, workspace):
        return {
            **parent.input, "engagementId": "eng-test", "chainId": "chain-test",
            "componentId": component_id, "provider": "linode",
            "middleCount": 1 if role == "middle" else 0,
            "edgeCount": 0 if role == "middle" else 1,
            "edgeCountPerRegion": 0 if role == "middle" else 1,
            "terraformWorkingDirectory": str(workspace),
        }
    children = {
        "edge-two": child("edge-two", "edge", edge_two),
        "middle-component": child("middle-component", "middle", middle),
        "edge-one": child("edge-one", "edge", edge_one),
    }
    job = replace(parent, action="mixed_provider_sketch_deploy", input={
        "engagementId": "eng-test", "chainId": "chain-test",
        "middleProvider": "linode", "edgeProvider": "linode",
        "components": [
            {"componentId": "middle-component", "role": "middle", "provider": "linode"},
            {"componentId": "edge-one", "role": "edge", "provider": "linode"},
            {"componentId": "edge-two", "role": "edge", "provider": "linode"},
        ],
        "childInputs": children,
        "terraformWorkingDirectories": {key: value["terraformWorkingDirectory"] for key, value in children.items()},
    })
    workspaces = {"edge-two": edge_two, "edge-one": edge_one, "middle-component": middle}
    monkeypatch.setattr(
        capture,
        "validate_existing_sketch_state_workspace",
        lambda *_a, **kw: SimpleNamespace(path=workspaces[kw["component_id"]]),
    )
    channel = {**_channel("edge-two"), "edge": "edge-02"}
    roles = runtime_roles(
        CaptureRequest("eng-test", "chain-test", "channel-test", "no-op", "capture-abcd1234"),
        chain, job, channel, rows,
    )
    assert [(role.role, role.component_id, role.workspace) for role in roles] == [
        ("edge", "edge-two", edge_two),
        ("middle", "middle-component", middle),
    ]


@pytest.mark.parametrize(
    "scenario,exit_code,delta",
    [
        ("add", 0, FirewallIngressDelta()),
        ("remove", 0, FirewallIngressDelta()),
        ("no-op", 2, FirewallIngressDelta()),
    ],
)
def test_scenario_fidelity_rejects_status_labels_that_do_not_match_real_plan(scenario, exit_code, delta):
    channel = {"protocol": "udp", "externalPort": "53", "relayPort": "8000"}
    changes = [] if not delta.added and not delta.removed else [PlannedResourceChange("linode_firewall.firewall", "update")]
    with pytest.raises(SketchProviderContractCaptureError, match="did not match"):
        require_scenario_fidelity(scenario, "edge", channel, exit_code, delta, changes)


@pytest.mark.parametrize("scenario,direction", [("add", "added"), ("remove", "removed")])
def test_scenario_fidelity_accepts_exact_candidate_transition(scenario, direction):
    listener = FirewallIngressPort("udp", 53)
    delta = FirewallIngressDelta(**{direction: frozenset({listener})})
    require_scenario_fidelity(
        scenario, "edge", {"protocol": "udp", "externalPort": "53"}, 2, delta,
        [PlannedResourceChange("linode_firewall.firewall", "update")],
    )


def _output_classifier_fixture(
    tmp_path: Path, provider: str,
) -> tuple[dict, Path, Path, Path, Path]:
    source = tmp_path / provider / "output.tf"
    source.parent.mkdir()
    source.write_text(_source_faithful_output_tf(provider))
    state = source.parent / "terraform.tfstate"
    retained = _retained_outputs(provider)
    state.write_text(json.dumps({"outputs": retained}))
    public_path = tmp_path / "held-keys" / "admin.pub"
    public_path.parent.mkdir()
    public_path.write_text("PUBLIC-KEY-SENTINEL")
    ssh_config_path = tmp_path / "runtime-home" / ".ssh" / "opaque-engagement-sketch"
    document = {"output_changes": _capture_output_changes(
        provider, retained, public_path, ssh_config_path,
    )}
    return document, source, state, public_path, ssh_config_path


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize("scenario", ["add", "no-op", "remove"])
def test_capture_output_classifier_accepts_only_source_pinned_key_path_refresh(
    tmp_path: Path, provider: str, scenario: str,
):
    document, source, state, public_path, ssh_config_path = _output_classifier_fixture(
        tmp_path, provider,
    )
    # Scenario selection changes firewall expectations, not this output proof.
    assert scenario in {"add", "no-op", "remove"}
    assert classify_capture_output_changes(
        document, provider, source, state,
        materialized_public_key_path=str(public_path),
        expected_ssh_config_path=str(ssh_config_path),
    ).classification == "materialized-key-path-refresh"


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_capture_output_classifier_accepts_terraform_state_omitted_false_sensitivity(
    tmp_path: Path, provider: str,
):
    document, source, state, public_path, ssh_config_path = _output_classifier_fixture(
        tmp_path, provider,
    )
    retained = json.loads(state.read_text())
    for value in retained["outputs"].values():
        if value.get("sensitive") is False:
            del value["sensitive"]
    state.write_text(json.dumps(retained))
    assert classify_capture_output_changes(
        document, provider, source, state,
        materialized_public_key_path=str(public_path),
        expected_ssh_config_path=str(ssh_config_path),
    ).classification == "materialized-key-path-refresh"


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize("scenario", ["add", "no-op", "remove"])
def test_source_faithful_provider_gate_and_output_classifier_agree_for_every_scenario(
    tmp_path: Path, provider: str, scenario: str,
):
    document = (
        _clean_linode_capture_noop_plan()
        if provider == "linode"
        else _digitalocean_computed_drift_noop_plan()
    )
    document["resource_drift"] = []
    output_document, source, state, public_path, ssh_config_path = _output_classifier_fixture(
        tmp_path, provider,
    )
    document["output_changes"] = output_document["output_changes"]
    listener = FirewallIngressPort("udp", 34791)
    expected_delta = FirewallIngressDelta()
    if scenario != "no-op":
        resource = document["planned_values"]["root_module"]["resources"][0]
        after = copy.deepcopy(resource["values"])
        candidate = terraform_plan_gate._public_ingress_rule(provider, listener)
        collection = "inbound" if provider == "linode" else "inbound_rule"
        before = copy.deepcopy(after)
        if scenario == "add":
            after[collection].append(candidate)
            resource["values"] = copy.deepcopy(after)
            expected_delta = FirewallIngressDelta(added=frozenset({listener}))
        else:
            before[collection].append(candidate)
            expected_delta = FirewallIngressDelta(removed=frozenset({listener}))
        document["resource_changes"] = [{
            key: resource[key]
            for key in ("address", "mode", "type", "name", "provider_name")
        } | {"change": {
            "actions": ["update"], "before": before, "after": after,
            "before_sensitive": {
                collection: [_false_rule_mask(rule) for rule in before[collection]],
            },
            "after_sensitive": {
                collection: [_false_rule_mask(rule) for rule in after[collection]],
            },
            "after_unknown": {},
        }}]
        drift_before = copy.deepcopy(before)
        drift_after = copy.deepcopy(before)
        if provider == "digitalocean":
            drift_before["pending_changes"] = [{"droplet_id": 201, "status": "waiting"}]
            drift_before["status"] = "waiting"
            drift_after["pending_changes"] = []
            drift_after["status"] = "succeeded"
        else:
            drift_before["updated"] = "2026-09-15T15:29:00Z"
            drift_after["updated"] = "2026-09-15T15:30:00Z"
        document["resource_drift"] = [{
            key: resource[key]
            for key in ("address", "mode", "type", "name", "provider_name")
        } | {"change": {
            "actions": ["update"], "before": drift_before, "after": drift_after,
            "before_sensitive": copy.deepcopy(document["resource_changes"][0]["change"]["before_sensitive"]),
            "after_sensitive": copy.deepcopy(document["resource_changes"][0]["change"]["before_sensitive"]),
            "after_unknown": {
                **({"pending_changes": False, "status": False} if provider == "digitalocean" else {"updated": False}),
            },
        }}]
    decision = classify_capture_output_changes(
        document, provider, source, state,
        materialized_public_key_path=str(public_path),
        expected_ssh_config_path=str(ssh_config_path),
    )
    assert decision.classification == "materialized-key-path-refresh"
    changes = require_provider_firewall_ingress_update(
        json.dumps(document), provider=provider, expected_delta=expected_delta,
    )
    envelope_decision = capture.classify_capture_plan_envelope(
        document, provider, 2, scenario, output_decision=decision,
    )
    assert envelope_decision.classification == (
        "capture-induced-output-refresh" if scenario == "no-op" else "computed-firewall-drift"
    )
    exported = export_firewall_contract(document, provider)
    exported_changes = require_provider_firewall_ingress_update(
        json.dumps(exported), provider=provider, expected_delta=expected_delta,
    )
    assert exported_changes == changes
    sanitized_decision = capture.require_sanitized_capture_output_classification(
        document, exported, decision,
    )
    sanitized_envelope_decision = capture.classify_capture_plan_envelope(
        exported, provider, 2, scenario, output_decision=sanitized_decision,
    )
    assert sanitized_envelope_decision.semantic_identity() == envelope_decision.semantic_identity()
    require_scenario_fidelity(
        scenario, "edge", {"protocol": "udp", "externalPort": "34791"},
        2, expected_delta, changes,
        noop_classification=envelope_decision.classification if scenario == "no-op" else None,
    )


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize(
    "mutation",
    [
        "missing-output", "extra-output", "other-update", "public-after",
        "run-after", "before", "path-action", "other-action", "missing-field",
        "extra-field", "before-sensitive", "after-sensitive", "after-unknown",
        "state-missing", "state-extra", "state-shape", "state-type", "state-sensitive", "source-output",
        "source-public", "source-run",
    ],
)
def test_capture_output_classifier_rejects_unpinned_or_unrelated_changes(
    tmp_path: Path, provider: str, mutation: str,
):
    document, source, state, public_path, ssh_config_path = _output_classifier_fixture(
        tmp_path, provider,
    )
    changes = document["output_changes"]
    other = "good-bye"
    state_document = json.loads(state.read_text())
    if mutation == "missing-output":
        changes.pop(other)
    elif mutation == "extra-output":
        changes["unexpected"] = copy.deepcopy(changes[other])
    elif mutation == "other-update":
        changes[other]["actions"] = ["update"]
        changes[other]["after"] = "unrelated"
    elif mutation == "public-after":
        changes["public-key"]["after"] = str(public_path) + ".other"
    elif mutation == "run-after":
        changes["run-ansible"]["after"] += " --extra"
    elif mutation == "before":
        changes[other]["before"] = "not-retained"
    elif mutation == "path-action":
        changes["public-key"]["actions"] = ["no-op"]
    elif mutation == "other-action":
        changes[other]["actions"] = ["update"]
    elif mutation == "missing-field":
        changes["public-key"].pop("after_unknown")
    elif mutation == "extra-field":
        changes["public-key"]["replace_paths"] = []
    elif mutation == "before-sensitive":
        changes["public-key"]["before_sensitive"] = True
    elif mutation == "after-sensitive":
        changes["public-key"]["after_sensitive"] = True
    elif mutation == "after-unknown":
        changes["public-key"]["after_unknown"] = {"path": True}
    elif mutation == "state-missing":
        state_document["outputs"].pop(other)
        state.write_text(json.dumps(state_document))
    elif mutation == "state-extra":
        state_document["outputs"]["unexpected"] = copy.deepcopy(state_document["outputs"][other])
        state.write_text(json.dumps(state_document))
    elif mutation == "state-shape":
        state_document["outputs"][other]["extra"] = False
        state.write_text(json.dumps(state_document))
    elif mutation == "state-type":
        state_document["outputs"][other]["type"] = "number"
        state.write_text(json.dumps(state_document))
    elif mutation == "state-sensitive":
        state_document["outputs"][other]["sensitive"] = True
        changes[other]["before_sensitive"] = True
        changes[other]["after_sensitive"] = True
        state.write_text(json.dumps(state_document))
    elif mutation == "source-output":
        source.write_text(source.read_text().replace('output "good-bye"', 'output "unexpected"'))
    elif mutation == "source-public":
        source.write_text(source.read_text().replace(
            "value = local.ssh_pub_key_path", "value = var.ssh_pub_key_path",
        ))
    elif mutation == "source-run":
        source.write_text(source.read_text().replace("ansible-playbook", "ansible-playbook-changed"))
    with pytest.raises(SketchProviderContractCaptureError):
        classify_capture_output_changes(
            document, provider, source, state,
            materialized_public_key_path=str(public_path),
            expected_ssh_config_path=str(ssh_config_path),
        )


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_capture_output_sanitization_preserves_structure_actions_and_hides_paths(
    tmp_path: Path, provider: str,
):
    document, source, state, public_path, ssh_config_path = _output_classifier_fixture(
        tmp_path, provider,
    )
    # Supply the minimum full document needed by the sanitizer's provider schema.
    full = _digitalocean_computed_drift_noop_plan() if provider == "digitalocean" else _clean_linode_capture_noop_plan()
    full["output_changes"] = document["output_changes"]
    decision = classify_capture_output_changes(
        full, provider, source, state,
        materialized_public_key_path=str(public_path),
        expected_ssh_config_path=str(ssh_config_path),
    )
    exported = export_firewall_contract(full, provider)
    sanitized_decision = capture.require_sanitized_capture_output_classification(
        full, exported, decision,
    )
    assert sanitized_decision.provider == provider
    assert sanitized_decision.output_changes_sha256 != decision.output_changes_sha256
    assert [value["actions"] for value in exported["output_changes"].values()] == [
        value["actions"] for value in full["output_changes"].values()
    ]
    serialized = json.dumps(exported)
    assert str(public_path) not in serialized
    assert str(ssh_config_path) not in serialized
    assert set(exported["output_changes"]) != set(full["output_changes"])


@pytest.mark.parametrize("with_drift", [False, True])
def test_noop_output_authorization_rejects_tokens_wrong_bindings_and_delete(
    tmp_path: Path, with_drift: bool,
):
    document, source, state, public_path, ssh_config_path = _output_classifier_fixture(
        tmp_path, "digitalocean",
    )
    full = _digitalocean_computed_drift_noop_plan()
    full["output_changes"] = document["output_changes"]
    if not with_drift:
        full["resource_drift"] = []
    decision = classify_capture_output_changes(
        full, "digitalocean", source, state,
        materialized_public_key_path=str(public_path),
        expected_ssh_config_path=str(ssh_config_path),
    )
    expected = (
        "capture-induced-output-and-computed-firewall-drift"
        if with_drift else "capture-induced-output-refresh"
    )
    assert classify_capture_noop_plan(
        full, "digitalocean", 2, output_decision=decision,
    ).classification == expected

    with pytest.raises(SketchProviderContractCaptureError, match="classification was invalid"):
        classify_capture_noop_plan(
            full, "digitalocean", 2,
            output_decision="materialized-key-path-refresh",  # type: ignore[arg-type]
        )
    wrong_provider = replace(decision, provider="linode")
    with pytest.raises(SketchProviderContractCaptureError, match="classification was invalid"):
        classify_capture_noop_plan(
            full, "digitalocean", 2, output_decision=wrong_provider,
        )
    wrong_digest = replace(decision, output_changes_sha256="0" * 64)
    with pytest.raises(SketchProviderContractCaptureError, match="classification was invalid"):
        classify_capture_noop_plan(
            full, "digitalocean", 2, output_decision=wrong_digest,
        )

    changed = copy.deepcopy(full)
    changed["output_changes"]["public-key"]["actions"] = ["delete"]
    changed["output_changes"]["public-key"]["after"] = None
    with pytest.raises(SketchProviderContractCaptureError, match="classification was invalid"):
        classify_capture_noop_plan(
            changed, "digitalocean", 2, output_decision=decision,
        )


def test_raw_output_decision_cannot_authorize_sanitized_document(tmp_path: Path):
    document, source, state, public_path, ssh_config_path = _output_classifier_fixture(
        tmp_path, "linode",
    )
    full = _clean_linode_capture_noop_plan()
    full["output_changes"] = document["output_changes"]
    raw_decision = classify_capture_output_changes(
        full, "linode", source, state,
        materialized_public_key_path=str(public_path),
        expected_ssh_config_path=str(ssh_config_path),
    )
    exported = export_firewall_contract(full, "linode")
    with pytest.raises(SketchProviderContractCaptureError, match="classification was invalid"):
        classify_capture_noop_plan(
            exported, "linode", 2, output_decision=raw_decision,
        )
    sanitized_decision = capture.require_sanitized_capture_output_classification(
        full, exported, raw_decision,
    )
    assert classify_capture_noop_plan(
        exported, "linode", 2, output_decision=sanitized_decision,
    ).classification == "capture-induced-output-refresh"


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_authoritative_output_contract_matches_reviewed_source(provider):
    root = capture.redteam_infra_template_root() / "external" / "sketch" / provider
    capture._require_pinned_output_source(root / "output.tf", provider)


def test_capture_noop_accepts_only_exact_digitalocean_computed_firewall_drift():
    document = _digitalocean_computed_drift_noop_plan()
    exported = export_firewall_contract(document, "digitalocean")

    assert classify_capture_noop_plan(document, "digitalocean", 2).classification == "computed-firewall-drift"
    assert classify_capture_noop_plan(exported, "digitalocean", 2).classification == "computed-firewall-drift"
    require_scenario_fidelity(
        "no-op", "edge", {"protocol": "udp", "externalPort": "53"}, 2,
        FirewallIngressDelta(), [], noop_classification="computed-firewall-drift",
    )
    assert canonical_firewall_semantics(document, "digitalocean", redact=True) == \
        canonical_firewall_semantics(exported, "digitalocean", redact=False)


def _false_rule_mask(rule: dict) -> dict:
    return {
        key: ([] if isinstance(value, list) else {} if isinstance(value, dict) else False)
        for key, value in rule.items()
    }


def _capture_mutation_plan(provider: str, scenario: str, *, with_drift: bool = True) -> dict:
    assert scenario in {"add", "remove"}
    document = (
        _clean_linode_capture_noop_plan()
        if provider == "linode"
        else _digitalocean_computed_drift_noop_plan()
    )
    document["resource_drift"] = []
    document["output_changes"] = {}
    resource = document["planned_values"]["root_module"]["resources"][0]
    collection = "inbound" if provider == "linode" else "inbound_rule"
    candidate = terraform_plan_gate._public_ingress_rule(
        provider, FirewallIngressPort("udp", 34791),
    )
    after = copy.deepcopy(resource["values"])
    before = copy.deepcopy(after)
    if scenario == "add":
        after[collection].append(candidate)
        resource["values"] = copy.deepcopy(after)
    else:
        before[collection].append(candidate)
    sensitive = {
        key: copy.deepcopy(value)
        for key, value in resource["sensitive_values"].items()
        if key != collection
    }
    before_sensitive = {
        **copy.deepcopy(sensitive),
        collection: [_false_rule_mask(rule) for rule in before[collection]],
    }
    after_sensitive = {
        **copy.deepcopy(sensitive),
        collection: [_false_rule_mask(rule) for rule in after[collection]],
    }
    document["resource_changes"] = [{
        key: resource[key]
        for key in ("address", "mode", "type", "name", "provider_name")
    } | {"change": {
        "actions": ["update"], "before": before, "after": after,
        "before_sensitive": before_sensitive,
        "after_sensitive": after_sensitive, "after_unknown": {},
    }}]
    if not with_drift:
        return document
    drift_before = copy.deepcopy(before)
    drift_after = copy.deepcopy(before)
    if provider == "digitalocean":
        drift_before["pending_changes"] = [{"droplet_id": 201, "status": "waiting"}]
        drift_before["status"] = "waiting"
        drift_after["pending_changes"] = []
        drift_after["status"] = "succeeded"
        unknown = {"pending_changes": False, "status": False}
    else:
        drift_before["updated"] = "2026-09-15T15:29:00Z"
        drift_after["updated"] = "2026-09-15T15:30:00Z"
        unknown = {"updated": False}
    document["resource_drift"] = [{
        key: resource[key]
        for key in ("address", "mode", "type", "name", "provider_name")
    } | {"change": {
        "actions": ["update"], "before": drift_before, "after": drift_after,
        "before_sensitive": copy.deepcopy(before_sensitive),
        "after_sensitive": copy.deepcopy(before_sensitive), "after_unknown": unknown,
    }}]
    return document


def _append_valid_noop_sibling(document: dict) -> dict:
    sibling = {
        "address": "local_file.sibling", "mode": "managed", "type": "local_file",
        "name": "sibling", "provider_name": "registry.terraform.io/hashicorp/local",
        "change": {
            "actions": ["no-op"], "before": {"content": "opaque"},
            "after": {"content": "opaque"}, "before_sensitive": {"content": False},
            "after_sensitive": {"content": False}, "after_unknown": {"content": False},
        },
    }
    document["resource_changes"].append(sibling)
    return sibling


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize("scenario", ["add", "remove"])
def test_capture_mutation_envelope_accepts_only_selected_update_with_optional_computed_drift(
    provider: str, scenario: str,
):
    document = _capture_mutation_plan(provider, scenario)
    exported = export_firewall_contract(document, provider)
    assert capture.classify_capture_plan_envelope(document, provider, 2, scenario).classification == \
        "computed-firewall-drift"
    assert capture.classify_capture_plan_envelope(exported, provider, 2, scenario).classification == \
        "computed-firewall-drift"
    assert canonical_firewall_semantics(document, provider, redact=True) == \
        canonical_firewall_semantics(exported, provider, redact=False)

    clean = _capture_mutation_plan(provider, scenario, with_drift=False)
    assert capture.classify_capture_plan_envelope(clean, provider, 2, scenario).classification == \
        "no-refresh-drift"

    with_sibling = _capture_mutation_plan(provider, scenario)
    _append_valid_noop_sibling(with_sibling)
    assert capture.classify_capture_plan_envelope(
        with_sibling, provider, 2, scenario,
    ).classification == "computed-firewall-drift"


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize(
    "mutation",
    [
        "deposed", "moved", "module_address", "extra", "empty-address",
        "empty-type", "empty-name", "empty-provider", "nonstring-address",
        "address-mismatch", "provider-mismatch", "mode", "malformed-type",
        "malformed-name", "string-index", "bool-index", "negative-index",
        "quoted-index-address", "wrong-index-address",
    ],
)
def test_capture_plan_envelope_strictly_validates_every_noop_sibling_identity(
    provider: str, mutation: str,
):
    document = _capture_mutation_plan(provider, "add")
    sibling = _append_valid_noop_sibling(document)
    if mutation in {"deposed", "moved", "module_address", "extra"}:
        sibling[mutation] = "opaque"
    elif mutation == "empty-address":
        sibling["address"] = ""
    elif mutation == "empty-type":
        sibling["type"] = ""
    elif mutation == "empty-name":
        sibling["name"] = ""
    elif mutation == "empty-provider":
        sibling["provider_name"] = ""
    elif mutation == "nonstring-address":
        sibling["address"] = 7
    elif mutation == "address-mismatch":
        sibling["address"] = "local_file.other"
    elif mutation == "provider-mismatch":
        sibling["provider_name"] = (
            "registry.terraform.io/linode/linode" if provider == "linode"
            else "registry.terraform.io/digitalocean/digitalocean"
        )
    elif mutation == "mode":
        sibling["mode"] = "data"
    elif mutation == "malformed-type":
        sibling["type"] = "local_file[0]"
        sibling["address"] = "local_file[0].sibling"
    elif mutation == "malformed-name":
        sibling["name"] = "sibling[0]"
        sibling["address"] = "local_file.sibling[0]"
    elif mutation == "string-index":
        sibling["index"] = "0"
        sibling["address"] = "local_file.sibling[0]"
    elif mutation == "bool-index":
        sibling["index"] = True
        sibling["address"] = "local_file.sibling[1]"
    elif mutation == "negative-index":
        sibling["index"] = -1
        sibling["address"] = "local_file.sibling[-1]"
    elif mutation == "quoted-index-address":
        sibling["index"] = 0
        sibling["address"] = 'local_file.sibling["0"]'
    elif mutation == "wrong-index-address":
        sibling["index"] = 1
        sibling["address"] = "local_file.sibling[0]"
    with pytest.raises(SketchProviderContractCaptureError):
        capture.classify_capture_plan_envelope(document, provider, 2, "add")


@pytest.mark.parametrize(
    "provider,source_file,resource_type,provider_name,name",
    [
        ("digitalocean", "edge.tf", "digitalocean_droplet", "registry.terraform.io/digitalocean/digitalocean", "edge"),
        ("digitalocean", "middle.tf", "digitalocean_droplet", "registry.terraform.io/digitalocean/digitalocean", "middle"),
        ("digitalocean", "output.tf", "local_file", "registry.terraform.io/hashicorp/local", "ssh_stanza"),
        ("digitalocean", "output.tf", "local_file", "registry.terraform.io/hashicorp/local", "ansible_inventory"),
        ("linode", "edge.tf", "linode_instance", "registry.terraform.io/linode/linode", "edge"),
        ("linode", "middle.tf", "linode_instance", "registry.terraform.io/linode/linode", "middle"),
        ("linode", "output.tf", "local_file", "registry.terraform.io/hashicorp/local", "ssh_stanza"),
        ("linode", "output.tf", "local_file", "registry.terraform.io/hashicorp/local", "ansible_inventory"),
    ],
)
def test_capture_plan_envelope_accepts_source_count_indexed_siblings_raw_and_sanitized(
    provider: str, source_file: str, resource_type: str, provider_name: str, name: str,
):
    source = (
        capture.redteam_infra_template_root() / "external" / "sketch" / provider / source_file
    ).read_text()
    declaration = f'resource "{resource_type}" "{name}" {{'
    assert declaration in source
    block = source[source.index(declaration):]
    assert re.search(r"(?m)^\s*count\s*=", block[:block.index("\n}")])
    document = _capture_mutation_plan(provider, "add")
    sibling = _append_valid_noop_sibling(document)
    sibling.update({
        "address": f"{resource_type}.{name}[0]", "type": resource_type,
        "name": name, "provider_name": provider_name, "index": 0,
    })
    raw = capture.classify_capture_plan_envelope(document, provider, 2, "add")
    exported = export_firewall_contract(document, provider)
    clean = capture.classify_capture_plan_envelope(exported, provider, 2, "add")
    assert raw.semantic_identity() == clean.semantic_identity()


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize("side", ["before_sensitive", "after_sensitive"])
def test_capture_firewall_update_requires_exact_equal_sensitivity_trees(
    provider: str, side: str,
):
    document = _capture_mutation_plan(provider, "remove")
    document["resource_changes"][0]["change"][side]["inbound"] = True
    with pytest.raises(SketchProviderContractCaptureError, match="sensitivity"):
        capture.classify_capture_plan_envelope(document, provider, 2, "remove")


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize("scenario", ["add", "remove"])
@pytest.mark.parametrize(
    "mutation", ["protected-true", "ingress-true", "extra-mask", "missing-mask", "nested-malformed"],
)
def test_capture_firewall_update_rejects_unsafe_or_misaligned_sensitivity_masks(
    provider: str, scenario: str, mutation: str,
):
    document = _capture_mutation_plan(provider, scenario, with_drift=False)
    change = document["resource_changes"][0]["change"]
    ingress = "inbound" if provider == "linode" else "inbound_rule"
    if mutation == "protected-true":
        change["before_sensitive"]["name"] = True
        change["after_sensitive"]["name"] = True
    elif mutation == "ingress-true":
        change["before_sensitive"][ingress][0][next(iter(change["before_sensitive"][ingress][0]))] = True
    elif mutation == "extra-mask":
        change["after_sensitive"][ingress].append(
            copy.deepcopy(change["after_sensitive"][ingress][0])
        )
    elif mutation == "missing-mask":
        change["before_sensitive"][ingress].pop()
    elif mutation == "nested-malformed":
        rule_mask = change["after_sensitive"][ingress][0]
        list_key = next(
            key for key, value in change["after"][ingress][0].items()
            if isinstance(value, list)
        )
        rule_mask[list_key] = "false"
    with pytest.raises(SketchProviderContractCaptureError, match="sensitivity"):
        capture.classify_capture_plan_envelope(document, provider, 2, scenario)


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize("mutation", ["wrong-member-removed", "reordered-before-masks"])
def test_capture_remove_sensitivity_tracks_the_exact_rule_and_order(
    provider: str, mutation: str,
):
    document = _capture_mutation_plan(provider, "remove", with_drift=False)
    change = document["resource_changes"][0]["change"]
    ingress = "inbound" if provider == "linode" else "inbound_rule"
    # Give the first retained rule a distinct, still nonsensitive provider field
    # so moving its mask is observable rather than a swap of identical all-false maps.
    for side in ("before", "after"):
        change[side][ingress][0]["provider_marker"] = "retained"
    for side in ("before_sensitive", "after_sensitive"):
        change[side][ingress][0]["provider_marker"] = False
    if mutation == "wrong-member-removed":
        change["after_sensitive"][ingress] = copy.deepcopy(
            change["before_sensitive"][ingress][1:]
        )
    else:
        masks = change["before_sensitive"][ingress]
        masks[0], masks[-1] = masks[-1], masks[0]
    with pytest.raises(SketchProviderContractCaptureError, match="sensitivity"):
        capture.classify_capture_plan_envelope(document, provider, 2, "remove")


@pytest.mark.parametrize(
    "provider,computed", [("digitalocean", "status"), ("linode", "updated")],
)
def test_capture_update_sensitivity_does_not_exempt_computed_fields(
    provider: str, computed: str,
):
    document = _capture_mutation_plan(provider, "add", with_drift=False)
    change = document["resource_changes"][0]["change"]
    if computed not in change["before"]:
        change["before"][computed] = "before"
        change["after"][computed] = "before"
    change["before_sensitive"][computed] = False
    with pytest.raises(SketchProviderContractCaptureError, match="protected sensitivity"):
        capture.classify_capture_plan_envelope(document, provider, 2, "add")


def _false_leaf_count(value) -> int:
    if value is False:
        return 1
    if isinstance(value, dict):
        return sum(_false_leaf_count(item) for item in value.values())
    if isinstance(value, list):
        return sum(_false_leaf_count(item) for item in value)
    raise AssertionError("fixture mask was not false-only")


def test_x5_digitalocean_remove_mask_shape_is_exactly_11_to_10_and_19_to_18():
    document = _capture_mutation_plan("digitalocean", "remove", with_drift=False)
    resource = document["planned_values"]["root_module"]["resources"][0]
    change = document["resource_changes"][0]["change"]
    ingress = "inbound_rule"
    retained = copy.deepcopy(change["after"][ingress][0])
    retained_rules = []
    for ordinal in range(10):
        rule = copy.deepcopy(retained)
        rule["port_range"] = str(2200 + ordinal)
        retained_rules.append(rule)
    removed = copy.deepcopy(change["before"][ingress][-1])
    change["after"][ingress] = copy.deepcopy(retained_rules)
    change["before"][ingress] = copy.deepcopy(retained_rules) + [removed]
    resource["values"][ingress] = copy.deepcopy(retained_rules)
    after_masks = [
        ({"port_range": False, "protocol": False} if ordinal < 8 else {"port_range": False})
        for ordinal in range(10)
    ]
    before_masks = copy.deepcopy(after_masks) + [{"port_range": False}]
    change["before_sensitive"][ingress] = before_masks
    change["after_sensitive"][ingress] = after_masks

    require_provider_firewall_ingress_update(
        json.dumps(document), provider="digitalocean",
        expected_delta=FirewallIngressDelta(
            removed=frozenset({FirewallIngressPort("udp", 34791)}),
        ),
    )
    raw = capture.classify_capture_plan_envelope(document, "digitalocean", 2, "remove")
    assert (raw.before_ingress_mask_entries, raw.after_ingress_mask_entries) == (11, 10)
    assert (_false_leaf_count(before_masks), _false_leaf_count(after_masks)) == (19, 18)
    assert raw.mask_classification == "false-only-ingress-mask-aligned"
    exported = export_firewall_contract(document, "digitalocean")
    clean = capture.classify_capture_plan_envelope(exported, "digitalocean", 2, "remove")
    assert raw.semantic_identity() == clean.semantic_identity()


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_sanitized_equal_extra_mask_keys_change_bound_semantic_identity(provider: str):
    document = _capture_mutation_plan(provider, "add", with_drift=False)
    raw = capture.classify_capture_plan_envelope(document, provider, 2, "add")
    exported = export_firewall_contract(document, provider)
    clean = capture.classify_capture_plan_envelope(exported, provider, 2, "add")
    assert raw.semantic_identity() == clean.semantic_identity()
    change = exported["resource_changes"][0]["change"]
    change["before"]["unexpected_equal_key"] = "redacted"
    change["after"]["unexpected_equal_key"] = "redacted"
    change["before_sensitive"]["unexpected_equal_key"] = False
    change["after_sensitive"]["unexpected_equal_key"] = False
    tampered = capture.classify_capture_plan_envelope(exported, provider, 2, "add")
    assert tampered.semantic_identity() != raw.semantic_identity()


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize("scenario", ["add", "remove"])
@pytest.mark.parametrize("sanitized", [False, True], ids=["raw", "sanitized"])
def test_sparse_rule_mask_key_must_bind_to_an_actual_rule_field(
    provider: str, scenario: str, sanitized: bool,
):
    document = _capture_mutation_plan(provider, scenario, with_drift=False)
    if sanitized:
        document = export_firewall_contract(document, provider)
    ingress = "inbound" if provider == "linode" else "inbound_rule"
    mask = document["resource_changes"][0]["change"]["before_sensitive"][ingress][0]
    original_key = next(iter(mask))
    mask["not_a_rule_field"] = mask.pop(original_key)
    with pytest.raises(SketchProviderContractCaptureError, match="shape"):
        capture.classify_capture_plan_envelope(document, provider, 2, scenario)


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize(
    "mutation", ["nested-missing", "nested-extra", "nested-type", "list-length", "list-type"],
)
def test_sparse_rule_mask_recursively_binds_keys_types_and_list_cardinality(
    provider: str, mutation: str,
):
    document = _capture_mutation_plan(provider, "add", with_drift=False)
    change = document["resource_changes"][0]["change"]
    ingress = "inbound" if provider == "linode" else "inbound_rule"
    extension = {"child": "value", "items": ["one"]}
    extension_mask = {"child": False, "items": [False]}
    for side in ("before", "after"):
        change[side][ingress][0]["provider_extension"] = copy.deepcopy(extension)
    for side in ("before_sensitive", "after_sensitive"):
        change[side][ingress][0]["provider_extension"] = copy.deepcopy(extension_mask)
    mask = change["before_sensitive"][ingress][0]["provider_extension"]
    if mutation == "nested-missing":
        mask["not_child"] = mask.pop("child")
    elif mutation == "nested-extra":
        mask["extra"] = False
    elif mutation == "nested-type":
        mask["child"] = {}
    elif mutation == "list-length":
        mask["items"].append(False)
    elif mutation == "list-type":
        mask["items"] = {}
    with pytest.raises(SketchProviderContractCaptureError, match="shape"):
        capture.classify_capture_plan_envelope(document, provider, 2, "add")


@pytest.mark.parametrize("provider,protected_key", [("digitalocean", "name"), ("linode", "label")])
@pytest.mark.parametrize("scenario", ["add", "remove"])
@pytest.mark.parametrize("sanitized", [False, True], ids=["raw", "sanitized"])
def test_root_sensitive_mask_key_must_bind_to_protected_resource_value(
    provider: str, protected_key: str, scenario: str, sanitized: bool,
):
    document = _capture_mutation_plan(provider, scenario, with_drift=False)
    change = document["resource_changes"][0]["change"]
    change["before_sensitive"][protected_key] = False
    change["after_sensitive"][protected_key] = False
    if sanitized:
        document = export_firewall_contract(document, provider)
        change = document["resource_changes"][0]["change"]
    change["before_sensitive"]["not_a_resource_field"] = \
        change["before_sensitive"].pop(protected_key)
    change["after_sensitive"]["not_a_resource_field"] = \
        change["after_sensitive"].pop(protected_key)
    with pytest.raises(SketchProviderContractCaptureError, match="root shape"):
        capture.classify_capture_plan_envelope(document, provider, 2, scenario)


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize("scenario", ["add", "remove"])
@pytest.mark.parametrize("sanitized", [False, True], ids=["raw", "sanitized"])
@pytest.mark.parametrize("mutation", ["nested-key", "nested-type", "list-length"])
def test_protected_nested_masks_bind_to_resource_value_shape(
    provider: str, scenario: str, sanitized: bool, mutation: str,
):
    document = _capture_mutation_plan(provider, scenario, with_drift=False)
    change = document["resource_changes"][0]["change"]
    extension = {"child": "value", "items": ["one"]}
    extension_mask = {"child": False, "items": [False]}
    for side in ("before", "after"):
        change[side]["provider_extension"] = copy.deepcopy(extension)
    for side in ("before_sensitive", "after_sensitive"):
        change[side]["provider_extension"] = copy.deepcopy(extension_mask)
    raw_before_mask = change["before_sensitive"]
    if sanitized:
        document = export_firewall_contract(document, provider)
        change = document["resource_changes"][0]["change"]
        extension_key = list(change["before_sensitive"])[
            list(raw_before_mask).index("provider_extension")
        ]
    else:
        extension_key = "provider_extension"
    for side in ("before_sensitive", "after_sensitive"):
        mask = change[side][extension_key]
        if mutation == "nested-key":
            child_key = next(key for key, value in mask.items() if value is False)
            mask["not_a_nested_field"] = mask.pop(child_key)
        elif mutation == "nested-type":
            child_key = next(key for key, value in mask.items() if value is False)
            mask[child_key] = {}
        elif mutation == "list-length":
            list_key = next(key for key, value in mask.items() if isinstance(value, list))
            mask[list_key].append(False)
    with pytest.raises(SketchProviderContractCaptureError, match="root shape"):
        capture.classify_capture_plan_envelope(document, provider, 2, scenario)


@pytest.mark.parametrize("provider,scenario", [("digitalocean", "remove"), ("linode", "add")])
def test_add_remove_plan_envelope_provenance_contains_only_safe_mask_proof(
    provider: str, scenario: str,
):
    decision = capture.classify_capture_plan_envelope(
        _capture_mutation_plan(provider, scenario), provider, 2, scenario,
    )
    provenance = capture._plan_envelope_provenance(decision)
    proof = provenance["sensitivityMaskProof"]
    assert proof["classification"] == "false-only-ingress-mask-aligned"
    assert proof["beforeIngressEntries"] == decision.before_ingress_mask_entries
    assert proof["afterIngressEntries"] == decision.after_ingress_mask_entries
    assert re.fullmatch(r"[0-9a-f]{64}", proof["beforeShapeSha256"])
    assert re.fullmatch(r"[0-9a-f]{64}", proof["afterShapeSha256"])
    assert not ({"path", "value", "before", "after"} & set(proof))


def test_capture_digitalocean_drift_rejects_unobserved_created_at_even_with_observed_fields():
    document = _capture_mutation_plan("digitalocean", "add")
    change = document["resource_drift"][0]["change"]
    change["before"]["created_at"] = "before"
    change["after"]["created_at"] = "after"
    change["after_unknown"]["created_at"] = False
    with pytest.raises(SketchProviderContractCaptureError, match="computed-only|observed refresh"):
        capture.classify_capture_plan_envelope(document, "digitalocean", 2, "add")


@pytest.mark.parametrize("actions", [["delete", "create"], ["create", "delete"], "update", [], ["update", 1]])
def test_capture_mutation_envelope_rejects_replace_and_malformed_action_tuples(actions):
    document = _capture_mutation_plan("linode", "remove")
    document["resource_changes"][0]["change"]["actions"] = actions
    with pytest.raises(SketchProviderContractCaptureError):
        capture.classify_capture_plan_envelope(document, "linode", 2, "remove")


@pytest.mark.parametrize("actions", [["delete", "create"], ["create", "delete"], "update", [], ["update", 1]])
def test_capture_refresh_drift_rejects_replace_and_malformed_action_tuples(actions):
    document = _capture_mutation_plan("digitalocean", "add")
    document["resource_drift"][0]["change"]["actions"] = actions
    with pytest.raises(SketchProviderContractCaptureError):
        capture.classify_capture_plan_envelope(document, "digitalocean", 2, "add")


def test_capture_plan_envelope_decision_is_document_bound_and_sanitized_semantically_equal():
    document = _capture_mutation_plan("digitalocean", "remove")
    raw = capture.classify_capture_plan_envelope(document, "digitalocean", 2, "remove")
    exported = export_firewall_contract(document, "digitalocean")
    clean = capture.classify_capture_plan_envelope(exported, "digitalocean", 2, "remove")
    assert raw.semantic_identity() == clean.semantic_identity()
    assert raw.document_sha256 != clean.document_sha256
    changed = copy.deepcopy(document)
    changed["format_version"] = "9.9"
    changed_decision = capture.classify_capture_plan_envelope(
        changed, "digitalocean", 2, "remove",
    )
    assert changed_decision.document_sha256 != raw.document_sha256


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize("scenario", ["add", "remove"])
@pytest.mark.parametrize(
    "mutation",
    [
        "deferred", "import", "generated-config", "replace-paths",
        "sibling-generated-config",
        "extra-change-key", "extra-resource-key", "duplicate-change-address",
        "duplicate-drift", "unrelated-drift", "drift-schema", "planned-schema",
        "protected-drift", "nested-drift", "protected-unknown", "malformed-unknown",
        "drift-against-target", "unexpected-output", "wrong-exit",
    ],
)
def test_capture_mutation_envelope_rejects_unsafe_full_plan_surfaces(
    provider: str, scenario: str, mutation: str,
):
    document = _capture_mutation_plan(provider, scenario)
    update = document["resource_changes"][0]
    drift = document["resource_drift"][0]
    if mutation == "deferred":
        document["deferred_changes"] = [{"resource_change": copy.deepcopy(update)}]
    elif mutation == "import":
        update["change"]["importing"] = {"id": "opaque"}
    elif mutation == "generated-config":
        update["generated_config"] = "resource opaque {}"
    elif mutation == "sibling-generated-config":
        sibling = copy.deepcopy(update)
        sibling["address"] = f"{provider}_opaque.sibling"
        sibling["type"] = f"{provider}_opaque"
        sibling["name"] = "sibling"
        sibling["change"]["actions"] = ["no-op"]
        sibling["change"]["after"] = copy.deepcopy(sibling["change"]["before"])
        sibling["generated_config"] = "resource opaque {}"
        document["resource_changes"].append(sibling)
    elif mutation == "replace-paths":
        update["change"]["replace_paths"] = [["status"]]
    elif mutation == "extra-change-key":
        update["change"]["opaque"] = None
    elif mutation == "extra-resource-key":
        update["deposed"] = "opaque"
    elif mutation == "duplicate-change-address":
        duplicate = copy.deepcopy(update)
        duplicate["change"]["actions"] = ["no-op"]
        duplicate["change"]["after"] = copy.deepcopy(duplicate["change"]["before"])
        document["resource_changes"].append(duplicate)
    elif mutation == "duplicate-drift":
        document["resource_drift"].append(copy.deepcopy(drift))
    elif mutation == "unrelated-drift":
        drift.update({"address": f"{provider}_compute.opaque", "type": f"{provider}_compute", "name": "opaque"})
    elif mutation == "drift-schema":
        drift["schema_version"] = 0
    elif mutation == "planned-schema":
        document["planned_values"]["root_module"]["resources"][0]["schema_version"] = 1
    elif mutation == "protected-drift":
        drift["change"]["after"]["name" if provider == "digitalocean" else "label"] = "changed"
    elif mutation == "nested-drift":
        drift["change"]["before"]["opaque"] = {"updated": "before"}
        drift["change"]["after"]["opaque"] = {"updated": "after"}
    elif mutation == "protected-unknown":
        drift["change"]["after_unknown"]["inbound" if provider == "linode" else "inbound_rule"] = True
    elif mutation == "malformed-unknown":
        drift["change"]["after_unknown"]["updated" if provider == "linode" else "status"] = "false"
    elif mutation == "drift-against-target":
        target = copy.deepcopy(update["change"]["after"])
        drift["change"]["before"] = copy.deepcopy(target)
        drift["change"]["after"] = copy.deepcopy(target)
        if provider == "digitalocean":
            drift["change"]["before"]["status"] = "waiting"
            drift["change"]["after"]["status"] = "succeeded"
        else:
            drift["change"]["before"]["updated"] = "before"
            drift["change"]["after"]["updated"] = "after"
    elif mutation == "unexpected-output":
        document["output_changes"] = {"opaque": {"actions": ["delete"]}}
    exit_code = 0 if mutation == "wrong-exit" else 2
    with pytest.raises(SketchProviderContractCaptureError):
        capture.classify_capture_plan_envelope(document, provider, exit_code, scenario)


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize("scenario", ["add", "remove"])
def test_capture_mutation_rejects_direct_import_without_overmatching_provider_payload(
    provider: str, scenario: str,
):
    direct = _capture_mutation_plan(provider, scenario)
    direct["resource_changes"][0]["change"]["importing"] = {"id": "opaque"}
    with pytest.raises(SketchProviderContractCaptureError):
        capture.classify_capture_plan_envelope(direct, provider, 2, scenario)

    payload = _capture_mutation_plan(provider, scenario)
    update = payload["resource_changes"][0]["change"]
    lookalike = {"importing": "provider-owned-value"}
    for key in ("before", "after"):
        update[key]["provider_payload"] = copy.deepcopy(lookalike)
    payload["planned_values"]["root_module"]["resources"][0]["values"][
        "provider_payload"
    ] = copy.deepcopy(lookalike)
    for key in ("before", "after"):
        payload["resource_drift"][0]["change"][key]["provider_payload"] = \
            copy.deepcopy(lookalike)
    assert capture.classify_capture_plan_envelope(payload, provider, 2, scenario).classification == \
        "computed-firewall-drift"


@pytest.mark.parametrize(
    "mutation",
    [
        "output", "import", "deferred", "other-drift", "second-drift",
        "metadata", "drift-schema-present", "metadata-extra", "planned-schema-missing",
        "planned-schema-wrong", "action", "resource-action", "resource-values",
        "protected", "disconnected", "unknown", "sensitive", "replace",
    ],
)
def test_capture_noop_computed_drift_rejects_every_unsafe_plan_surface(mutation):
    document = _digitalocean_computed_drift_noop_plan()
    drift = document["resource_drift"][0]
    change = drift["change"]
    if mutation == "output":
        document["output_changes"] = {"public_ip": {"actions": ["update"]}}
    elif mutation == "import":
        change["importing"] = {"id": "opaque"}
    elif mutation == "deferred":
        document["deferred_changes"] = [{"resource_change": copy.deepcopy(drift)}]
    elif mutation == "other-drift":
        drift.update({"address": "digitalocean_droplet.edge", "type": "digitalocean_droplet", "name": "edge"})
    elif mutation == "second-drift":
        document["resource_drift"].append(copy.deepcopy(drift))
    elif mutation == "metadata":
        drift["schema_version"] = 1
    elif mutation == "drift-schema-present":
        drift["schema_version"] = 0
    elif mutation == "metadata-extra":
        drift["deposed"] = "opaque"
    elif mutation == "planned-schema-missing":
        del document["planned_values"]["root_module"]["resources"][0]["schema_version"]
    elif mutation == "planned-schema-wrong":
        document["planned_values"]["root_module"]["resources"][0]["schema_version"] = 1
    elif mutation == "action":
        change["actions"] = ["delete", "create"]
    elif mutation == "resource-action":
        document["resource_changes"][0]["change"]["actions"] = ["update"]
    elif mutation == "resource-values":
        resource_change = document["resource_changes"][0]["change"]
        resource_change["after"] = copy.deepcopy(resource_change["before"])
        resource_change["after"]["tags"] = ["changed"]
    elif mutation == "protected":
        change["after"]["droplet_ids"] = [999]
    elif mutation == "disconnected":
        change["before"]["droplet_ids"] = [999]
        change["after"]["droplet_ids"] = [999]
    elif mutation == "unknown":
        change["after_unknown"]["droplet_ids"] = True
    elif mutation == "sensitive":
        change["after_sensitive"]["name"] = True
    elif mutation == "replace":
        change["replace_paths"] = [["status"]]

    with pytest.raises(SketchProviderContractCaptureError):
        classify_capture_noop_plan(document, "digitalocean", 2)


def test_capture_noop_computed_drift_preserves_missing_null_and_list_order():
    for before_value, after_value in ((None, []), ([201, 202], [202, 201])):
        document = _digitalocean_computed_drift_noop_plan()
        change = document["resource_drift"][0]["change"]
        change["before"]["droplet_ids"] = before_value
        change["after"]["droplet_ids"] = after_value
        with pytest.raises(SketchProviderContractCaptureError, match="computed-only|protected"):
            classify_capture_noop_plan(document, "digitalocean", 2)


def test_capture_noop_computed_drift_requires_an_actual_difference():
    document = _digitalocean_computed_drift_noop_plan()
    change = document["resource_drift"][0]["change"]
    change["after"] = copy.deepcopy(change["before"])
    with pytest.raises(SketchProviderContractCaptureError, match="actual computed-only"):
        classify_capture_noop_plan(document, "digitalocean", 2)


@pytest.mark.parametrize("malformed", ["MALFORMED", 1, 0.5])
def test_capture_noop_rejects_malformed_unknown_value_metadata(malformed):
    document = _digitalocean_computed_drift_noop_plan()
    document["resource_drift"][0]["change"]["after_unknown"]["droplet_ids"] = malformed
    with pytest.raises(SketchProviderContractCaptureError, match="unknown-value metadata was malformed"):
        classify_capture_noop_plan(document, "digitalocean", 2)


@pytest.mark.parametrize("missing", ["before", "after", "before_sensitive", "after_sensitive", "after_unknown"])
def test_capture_noop_resource_change_requires_pinned_terraform_shape(missing):
    document = _digitalocean_computed_drift_noop_plan()
    del document["resource_changes"][0]["change"][missing]
    with pytest.raises(SketchProviderContractCaptureError, match="metadata was invalid"):
        classify_capture_noop_plan(document, "digitalocean", 2)


@pytest.mark.parametrize("missing", ["before", "after", "before_sensitive", "after_sensitive", "after_unknown"])
def test_capture_noop_drift_requires_exact_d9_security_shape(missing):
    document = _digitalocean_computed_drift_noop_plan()
    del document["resource_drift"][0]["change"][missing]
    with pytest.raises(SketchProviderContractCaptureError, match="drift change was invalid"):
        classify_capture_noop_plan(document, "digitalocean", 2)


def test_capture_noop_rejects_direct_import_but_not_provider_payload_lookalike():
    direct = _digitalocean_computed_drift_noop_plan()
    direct["resource_changes"][0]["change"]["importing"] = {"id": "opaque"}
    with pytest.raises(SketchProviderContractCaptureError, match="contained an import"):
        classify_capture_noop_plan(direct, "digitalocean", 2)

    payload = _digitalocean_computed_drift_noop_plan()
    change = payload["resource_changes"][0]["change"]
    lookalike = {"importing": "opaque-provider-value"}
    change["before"]["provider_payload"] = copy.deepcopy(lookalike)
    change["after"]["provider_payload"] = copy.deepcopy(lookalike)
    planned = payload["planned_values"]["root_module"]["resources"][0]["values"]
    planned["provider_payload"] = copy.deepcopy(lookalike)
    payload["resource_drift"][0]["change"]["before"]["provider_payload"] = copy.deepcopy(lookalike)
    payload["resource_drift"][0]["change"]["after"]["provider_payload"] = copy.deepcopy(lookalike)
    assert classify_capture_noop_plan(payload, "digitalocean", 2).classification == "computed-firewall-drift"


def test_capture_noop_accepts_source_faithful_linode_updated_drift():
    document = _linode_computed_drift_noop_plan()
    exported = export_firewall_contract(document, "linode")
    assert classify_capture_noop_plan(document, "linode", 2).classification == "computed-firewall-drift"
    assert classify_capture_noop_plan(exported, "linode", 2).classification == "computed-firewall-drift"
    assert canonical_firewall_semantics(document, "linode", redact=True) == \
        canonical_firewall_semantics(exported, "linode", redact=False)


@pytest.mark.parametrize("field", ["created", "fingerprint", "status", "version"])
def test_capture_noop_linode_rejects_unobserved_computed_fields(field):
    document = _linode_computed_drift_noop_plan()
    change = document["resource_drift"][0]["change"]
    change["before"] = copy.deepcopy(change["after"])
    change["before"][field] = "before"
    change["after"][field] = "after"
    change["after_unknown"] = {field: False}
    with pytest.raises(SketchProviderContractCaptureError, match="computed-only"):
        classify_capture_noop_plan(document, "linode", 2)


@pytest.mark.parametrize("before,after", [(None, "after"), ("before", None), (1, 2)])
def test_capture_noop_linode_requires_string_updated_timestamps(before, after):
    document = _linode_computed_drift_noop_plan()
    change = document["resource_drift"][0]["change"]
    change["before"]["updated"] = before
    change["after"]["updated"] = after
    with pytest.raises(SketchProviderContractCaptureError, match="updated timestamp"):
        classify_capture_noop_plan(document, "linode", 2)


@pytest.mark.parametrize(
    "mutation", ["protected", "nested", "schema", "envelope", "planned-schema"],
)
def test_capture_noop_linode_rejects_noncomputed_or_malformed_drift(mutation):
    document = _linode_computed_drift_noop_plan()
    drift = document["resource_drift"][0]
    change = drift["change"]
    if mutation == "protected":
        change["after"]["label"] = "changed"
    elif mutation == "nested":
        change["before"]["provider_payload"] = {"updated": "before"}
        change["after"]["provider_payload"] = {"updated": "after"}
    elif mutation == "schema":
        drift["schema_version"] = 0
    elif mutation == "envelope":
        drift["deposed"] = "opaque"
    elif mutation == "planned-schema":
        document["planned_values"]["root_module"]["resources"][0]["schema_version"] = 1
    with pytest.raises(SketchProviderContractCaptureError):
        classify_capture_noop_plan(document, "linode", 2)


def test_capture_is_repository_derived_readonly_and_retained_workspace_is_immutable(tmp_path: Path, monkeypatch):
    data = tmp_path / "devtest-data"; data.mkdir()
    workspace = _workspace(tmp_path)
    engagement, chain, job = _records(workspace)
    job = replace(job, input={**job.input, "materializeKeyFiles": True})
    before = capture.workspace_digest(workspace)
    document = _clean_linode_capture_noop_plan()
    _prepare_capture_outputs(
        document, "linode", tmp_path / "materialized" / "id.pub",
        data / "provider-contract-captures" / "capture-abcd1234" / "01-edge-linode" / "runtime-home",
    )
    fake = FakeRunner(document)
    lease = Lease()
    cleaned = {"value": False}
    @contextmanager
    def materialized(_engagement_id):
        key_root = tmp_path / "materialized"; key_root.mkdir()
        private = key_root / "id"; public = key_root / "id.pub"; transport = key_root / "transport.pub"
        for path in (private, public, transport): path.write_text("MATERIALIZED-KEY-VALUE")
        try:
            yield MaterializedSketchKeys(str(private), str(public), str(transport))
        finally:
            for path in (private, public, transport): path.unlink()
            key_root.rmdir(); cleaned["value"] = True
    monkeypatch.setattr(capture, "validate_existing_sketch_state_workspace", lambda *_a, **_k: SimpleNamespace(path=workspace))
    monkeypatch.setattr(capture, "retained_compute_image_for_workspace", lambda *_a, **_k: "linode/ubuntu22.04")
    monkeypatch.setattr(capture, "CANONICAL_DEVTEST_DATA_DIR", data)
    monkeypatch.setattr(capture, "adapt_clone", lambda clone, _provider: (clone / "adapter-only.tf").write_text("adapted"))
    monkeypatch.setattr(capture, "strict_git_revision", lambda _root: "a" * 40)
    source_provenance = capture.CaptureSourceProvenance(
        "a" * 40, "b" * 40, (("linode", "1" * 64),),
    )
    monkeypatch.setattr(capture, "read_capture_source_provenance", lambda *_a, **_k: source_provenance)
    monkeypatch.setattr(capture, "materialized_sketch_key_files", materialized)
    monkeypatch.setattr(capture, "_rename_directory_noreplace", _test_rename_noreplace)
    provenance_checks = []
    def record_provenance_check(expected, providers, **kwargs):
        provenance_checks.append(set(providers))
    monkeypatch.setattr(capture, "require_capture_source_provenance", record_provenance_check)
    for key in (
        "PATH", "HOME", "XDG_CONFIG_HOME", "GIT_CONFIG", "GIT_DIR", "GIT_WORK_TREE",
        "TF_CLI_ARGS", "TF_CLI_ARGS_init", "HTTPS_PROXY", "TF_PLUGIN_CACHE_DIR",
    ):
        monkeypatch.setenv(key, f"AMBIENT-POISON-{key}")

    result = capture_sketch_provider_contract(
        CaptureRequest("eng-test", "chain-test", "channel-test", "no-op", "capture-abcd1234"),
        data_dir=data, environment="devtest", engagement_repository=Repo(engagement), chain_repository=Repo(chain),
        job_repository=Repo(job), credential_resolver=lambda *_a: "secret-token-value", terraform_runner=fake,
        overview_loader=lambda _id: {"inboundChannels": [_channel()], "sketchInfrastructure": chain.nodes},
        lease_repository=lease,
    )

    assert [name for name, _kwargs in fake.calls] == ["version", "init", "plan", "show"]
    assert fake.calls[1][1]["readonly_lock"] is True and fake.calls[1][1]["backend"] is False
    assert fake.calls[0][1]["env"]["TF_DATA_DIR"].endswith("/terraform-data")
    assert fake.calls[0][1]["env"]["TF_IN_AUTOMATION"] == "1"
    assert fake.calls[0][1]["env"]["CHECKPOINT_DISABLE"] == "1"
    executed_clone = Path(fake.calls[0][1]["working_directory"])
    assert (executed_clone / "templates" / "inventory.tftpl").read_bytes() == (workspace / "templates" / "inventory.tftpl").read_bytes()
    assert (executed_clone / "templates" / "ssh-stanza.tftpl").read_bytes() == (workspace / "templates" / "ssh-stanza.tftpl").read_bytes()
    assert (executed_clone / "templates").stat().st_mode & 0o777 == 0o700
    assert all((path.stat().st_mode & 0o777) == 0o600 for path in (executed_clone / "templates").iterdir())
    for _command, kwargs in fake.calls:
        assert kwargs["env"]["PATH"] == capture.CAPTURE_SYSTEM_PATH
        assert kwargs["env"]["HOME"] == str(executed_clone.parent / "runtime-home")
        assert not any("AMBIENT-POISON" in str(value) for value in kwargs["env"].values())
        assert not ({
            "XDG_CONFIG_HOME", "GIT_CONFIG", "GIT_DIR", "GIT_WORK_TREE",
            "TF_CLI_ARGS", "TF_CLI_ARGS_init", "HTTPS_PROXY", "TF_PLUGIN_CACHE_DIR",
        } & set(kwargs["env"]))
    assert capture.workspace_digest(workspace) == before
    assert not (workspace / "adapter-only.tf").exists()
    assert lease.released and result.status == "captured"
    assert provenance_checks == [{"linode"}, {"linode"}]
    assert cleaned["value"] is True and not (tmp_path / "materialized").exists()
    assert set(result.to_dict()) == {"captureId", "status", "hashes"}
    exported = Path(result.internal_directory)
    combined = "".join(path.read_text() for path in exported.rglob("*.json"))
    assert "secret-token-value" not in combined
    assert "MATERIALIZED-KEY-VALUE" not in combined
    assert "eng-test" not in combined
    assert str(executed_clone.parent / "runtime-home") not in combined
    text_evidence = "".join(
        path.read_text()
        for path in exported.rglob("*")
        if path.is_file() and path.name != "provider-firewall.tfplan"
    )
    assert "AMBIENT-POISON" not in text_evidence
    assert all((path.stat().st_mode & 0o777) == 0o600 for path in exported.rglob("*") if path.is_file())
    raw = exported / "01-edge-linode" / "raw"
    for command in ("version", "init", "plan", "show"):
        assert (raw / f"terraform-{command}.stdout").is_file()
        assert (raw / f"terraform-{command}.stderr").is_file()
        metadata = json.loads((raw / f"terraform-{command}.result.json").read_text())
        assert metadata == {"command": command, "returnCode": 2 if command == "plan" else 0}


def test_mixed_validated_noop_accepts_do_computed_drift_then_clean_linode(tmp_path: Path, monkeypatch):
    data = tmp_path / "devtest-data"
    data.mkdir()
    edge_workspace = _provider_workspace(tmp_path, "digitalocean")
    middle_workspace = _provider_workspace(tmp_path, "linode")
    engagement, chain, job = _records(middle_workspace)
    channel = _channel()
    roles = (
        capture.RoleCapture("edge", "digitalocean", edge_workspace, "edge-component", {
            "provider": "digitalocean", "edgeCredentialAlias": "default",
            "materializeKeyFiles": True, "middleCount": 0, "edgeCount": 1,
            "terraformEngagementName": "opaque-engagement",
            "edgeRegion": "nyc3", "resourceNameSuffix": "opaque-edge",
        }),
        capture.RoleCapture("middle", "linode", middle_workspace, "middle-component", {
            "provider": "linode", "middleCredentialAlias": "default",
            "materializeKeyFiles": True, "middleCount": 1, "edgeCount": 0,
            "terraformEngagementName": "opaque-engagement",
            "middleRegion": "us-sea", "resourceNameSuffix": "opaque-middle",
        }),
    )
    do_document = _digitalocean_computed_drift_noop_plan()
    do_firewall = do_document["planned_values"]["root_module"]["resources"][0]["values"]
    for port in (80, 443, 2222):
        do_firewall["inbound_rule"].append({
            "port_range": str(port), "protocol": "tcp", "source_addresses": ["0.0.0.0/0"],
            "source_droplet_ids": [], "source_kubernetes_ids": [],
            "source_load_balancer_uids": [], "source_tags": [],
        })
    do_firewall["inbound_rule"].append({
        "port_range": "53", "protocol": "udp", "source_addresses": ["0.0.0.0/0"],
        "source_droplet_ids": [], "source_kubernetes_ids": [],
        "source_load_balancer_uids": [], "source_tags": [],
    })
    # Regenerate the refresh-only drift around the complete desired firewall.
    before = copy.deepcopy(do_firewall)
    before["pending_changes"] = [{"droplet_id": 201, "status": "waiting"}]
    before["status"] = "waiting"
    do_document["resource_drift"][0]["change"]["before"] = before
    do_document["resource_drift"][0]["change"]["after"] = copy.deepcopy(do_firewall)
    linode_document = _linode_computed_drift_noop_plan()
    linode_rule = linode_document["planned_values"]["root_module"]["resources"][0]["values"]["inbound"][-1]
    linode_rule.update({"label": "allow-udp-8053", "ports": "8053"})
    for field in ("before", "after"):
        linode_document["resource_drift"][0]["change"][field]["inbound"][-1].update({
            "label": "allow-udp-8053", "ports": "8053",
        })
    capture_root = data / "provider-contract-captures" / "capture-mixed-noop"
    materialized_public = tmp_path / "keys-0" / "id.pub"
    _prepare_capture_outputs(
        do_document, "digitalocean", materialized_public,
        capture_root / "01-edge-digitalocean" / "runtime-home",
    )
    _prepare_capture_outputs(
        linode_document, "linode", materialized_public,
        capture_root / "02-middle-linode" / "runtime-home",
    )

    class MixedRunner:
        def __init__(self): self.calls = []
        def run(self, command, **kwargs):
            provider = "digitalocean" if "TF_VAR_do_pat" in kwargs["env"] else "linode"
            self.calls.append((provider, command, kwargs))
            if command == "version":
                selections = ({
                    "registry.terraform.io/digitalocean/digitalocean": "2.100.0",
                    "registry.terraform.io/hashicorp/local": "2.9.1",
                } if provider == "digitalocean" else {
                    "registry.terraform.io/linode/linode": "4.5.0",
                    "registry.terraform.io/hashicorp/local": "2.9.1",
                    "registry.terraform.io/hashicorp/random": "3.9.1",
                })
                stdout = json.dumps({"terraform_version": "1.15.5", "platform": "linux_amd64", "provider_selections": selections})
                return TerraformCommandResult(command, 0, stdout, "")
            if command == "plan":
                Path(kwargs["saved_plan_path"]).write_bytes(b"opaque plan")
                return TerraformCommandResult(command, 2, "{}\n", "")
            if command == "show":
                return TerraformCommandResult(command, 0, json.dumps(do_document if provider == "digitalocean" else linode_document), "")
            return TerraformCommandResult(command, 0, "", "")

    @contextmanager
    def materialized(_engagement_id):
        key_root = tmp_path / f"keys-{len(list(tmp_path.glob('keys-*')))}"
        key_root.mkdir()
        paths = [key_root / name for name in ("id", "id.pub", "transport.pub")]
        for path in paths: path.write_text("PRIVATE-KEY-SENTINEL")
        try: yield MaterializedSketchKeys(*(str(path) for path in paths))
        finally:
            for path in paths: path.unlink()
            key_root.rmdir()

    runner = MixedRunner()
    monkeypatch.setattr(capture, "CANONICAL_DEVTEST_DATA_DIR", data)
    monkeypatch.setattr(capture, "runtime_roles", lambda *_a, **_k: roles)
    monkeypatch.setattr(capture, "retained_compute_image_for_workspace", lambda *_a, **_k: "retained-image")
    monkeypatch.setattr(capture, "adapt_clone", lambda *_a, **_k: None)
    monkeypatch.setattr(capture, "materialized_sketch_key_files", materialized)
    monkeypatch.setattr(capture, "_rename_directory_noreplace", _test_rename_noreplace)
    source_provenance = capture.CaptureSourceProvenance(
        "a" * 40, "b" * 40, (("digitalocean", "2" * 64), ("linode", "1" * 64)),
    )
    monkeypatch.setattr(capture, "read_capture_source_provenance", lambda *_a, **_k: source_provenance)
    monkeypatch.setattr(capture, "require_capture_source_provenance", lambda *_a, **_k: None)

    result = capture_sketch_provider_contract(
        CaptureRequest("eng-test", "chain-test", "channel-test", "no-op", "capture-mixed-noop"),
        data_dir=data, environment="devtest", engagement_repository=Repo(engagement),
        chain_repository=Repo(chain), job_repository=Repo(job), terraform_runner=runner,
        credential_resolver=lambda *_a: "PRIVATE-CREDENTIAL-SENTINEL",
        overview_loader=lambda _id: {"inboundChannels": [channel], "sketchInfrastructure": chain.nodes},
        lease_repository=Lease(),
    )

    assert result.status == "captured"
    assert [(provider, command) for provider, command, _kwargs in runner.calls] == [
        ("digitalocean", "version"), ("digitalocean", "init"),
        ("digitalocean", "plan"), ("digitalocean", "show"),
        ("linode", "version"), ("linode", "init"), ("linode", "plan"), ("linode", "show"),
    ]
    accepted = data / "provider-contract-captures" / "capture-mixed-noop" / "accepted-evidence"
    manifest = json.loads((accepted / "manifest.json").read_text())
    assert [(item["role"], item["provider"]) for item in manifest["components"]] == [
        ("edge", "digitalocean"), ("middle", "linode"),
    ]
    provenance = [
        json.loads(path.read_text())
        for path in sorted((accepted / "components").glob("*/provenance.json"))
    ]
    assert [(item["planExitCode"], item["noOpPlanClassification"]) for item in provenance] == [
        (2, "capture-induced-output-and-computed-firewall-drift"),
        (2, "capture-induced-output-and-computed-firewall-drift"),
    ]
    assert [item["planEnvelopeDecision"] for item in provenance] == [
        {
            "provider": "digitalocean", "scenario": "no-op",
            "selectedAddress": "digitalocean_firewall.firewall",
            "classification": "capture-induced-output-and-computed-firewall-drift",
            "refreshDriftChangedFields": ["pending_changes", "status"],
            "sensitivityMaskProof": None,
        },
        {
            "provider": "linode", "scenario": "no-op",
            "selectedAddress": "linode_firewall.firewall",
            "classification": "capture-induced-output-and-computed-firewall-drift",
            "refreshDriftChangedFields": ["updated"],
            "sensitivityMaskProof": None,
        },
    ]
    assert all(item["approvedChanges"] == [] for item in provenance)


@pytest.mark.parametrize("failure_command", ["version", "init", "plan", "show"])
def test_capture_persists_private_command_evidence_before_opaque_failure_and_stops(
    tmp_path: Path, monkeypatch, capsys, failure_command: str,
):
    data = tmp_path / "devtest-data"
    data.mkdir()
    workspace = _workspace(tmp_path)
    engagement, chain, job = _records(workspace)
    job = replace(job, input={**job.input, "materializeKeyFiles": True})
    before = capture.workspace_digest(workspace)
    runner = FailingPhaseRunner(_linode_noop_plan(), failure_command)
    lease = Lease()
    cleaned = {"value": False}

    @contextmanager
    def materialized(_engagement_id):
        key_root = tmp_path / "failure-materialized"
        key_root.mkdir()
        private = key_root / "id"
        public = key_root / "id.pub"
        transport = key_root / "transport.pub"
        for path in (private, public, transport):
            path.write_text("PRIVATE-MATERIALIZED-KEY-SECRET")
        try:
            yield MaterializedSketchKeys(str(private), str(public), str(transport))
        finally:
            for path in (private, public, transport):
                path.unlink()
            key_root.rmdir()
            cleaned["value"] = True

    monkeypatch.setattr(capture, "validate_existing_sketch_state_workspace", lambda *_a, **_k: SimpleNamespace(path=workspace))
    monkeypatch.setattr(capture, "retained_compute_image_for_workspace", lambda *_a, **_k: "linode/ubuntu22.04")
    monkeypatch.setattr(capture, "CANONICAL_DEVTEST_DATA_DIR", data)
    monkeypatch.setattr(capture, "adapt_clone", lambda clone, _provider: (clone / "adapter-only.tf").write_text("adapted"))
    monkeypatch.setattr(capture, "materialized_sketch_key_files", materialized)
    monkeypatch.setattr(capture, "strict_git_revision", lambda _root: "a" * 40)
    monkeypatch.setattr(
        capture, "read_capture_source_provenance",
        lambda *_a, **_k: capture.CaptureSourceProvenance(
            "a" * 40, "b" * 40, (("linode", "1" * 64),),
        ),
    )
    monkeypatch.setattr(capture, "require_capture_source_provenance", lambda *_a, **_k: None)

    with pytest.raises(SketchProviderContractCaptureError) as exc:
        capture_sketch_provider_contract(
            CaptureRequest("eng-test", "chain-test", "channel-test", "no-op", "capture-failure1"),
            data_dir=data,
            environment="devtest",
            engagement_repository=Repo(engagement),
            chain_repository=Repo(chain),
            job_repository=Repo(job),
            credential_resolver=lambda *_a: "PRIVATE-CREDENTIAL-SECRET",
            terraform_runner=runner,
            overview_loader=lambda _id: {"inboundChannels": [_channel()], "sketchInfrastructure": chain.nodes},
            lease_repository=lease,
        )

    expected_commands = ["version", "init", "plan", "show"]
    attempted = expected_commands[:expected_commands.index(failure_command) + 1]
    assert [command for command, _kwargs in runner.calls] == attempted
    assert exc.value.args == (f"terraform {failure_command} failed",)
    assert "SECRET" not in str(exc.value)
    captured = capsys.readouterr()
    assert "SECRET" not in captured.out and "SECRET" not in captured.err
    raw = data / "provider-contract-captures" / "capture-failure1" / "01-edge-linode" / "raw"
    for command in attempted:
        stdout = raw / f"terraform-{command}.stdout"
        stderr = raw / f"terraform-{command}.stderr"
        metadata = raw / f"terraform-{command}.result.json"
        assert stdout.is_file() and stderr.is_file() and metadata.is_file()
        assert all((path.stat().st_mode & 0o777) == 0o600 for path in (stdout, stderr, metadata))
        expected_returncode = (
            1 if command == failure_command
            else 2 if command == "plan"
            else 0
        )
        assert json.loads(metadata.read_text()) == {"command": command, "returnCode": expected_returncode}
    assert (raw / f"terraform-{failure_command}.stdout").read_text() == f"PRIVATE-{failure_command}-STDOUT-SECRET"
    assert (raw / f"terraform-{failure_command}.stderr").read_text() == f"PRIVATE-{failure_command}-STDERR-SECRET"
    export = raw.parent / "export"
    assert "SECRET" not in "".join(path.read_text() for path in export.rglob("*") if path.is_file())
    assert lease.released and cleaned["value"] is True
    assert capture.workspace_digest(workspace) == before
    assert not (workspace / "adapter-only.tf").exists()


@pytest.mark.parametrize("environment,name", [("production", "devtest-data"), ("devtest", "data")])
def test_capture_rejects_non_devtest_scope_before_repository_access(tmp_path: Path, environment: str, name: str):
    root = tmp_path / name; root.mkdir()
    with pytest.raises(SketchProviderContractCaptureError, match="DevTest"):
        capture_sketch_provider_contract(
            CaptureRequest("eng-test", "chain-test", "channel-test", "add", "capture-abcd1234"),
            data_dir=root, environment=environment, engagement_repository=Repo(None),
        )


def test_capture_scope_accepts_only_canonical_and_documented_legacy_testing_targets():
    canonical = {
        "provider": "oci",
        "name": BARRAGAN_TESTING_TARGET.name,
        "compartmentId": BARRAGAN_TESTING_TARGET.compartment_id,
        "region": BARRAGAN_TESTING_TARGET.region,
    }
    for parameters in (
        {},
        {"deploymentTarget": None},
        {"deploymentTarget": "barragan-testing"},
        {"deploymentTarget": canonical},
    ):
        capture.require_testing_deployment_target(parameters)


@pytest.mark.parametrize(
    "target",
    [
        "",
        " ",
        "BARRAGAN-TESTING",
        " barragan-testing ",
        [],
        1,
        True,
        {"provider": "oci", "name": "barragan-testing"},
        {"provider": "oci", "compartmentId": BARRAGAN_TESTING_TARGET.compartment_id},
        {
            "name": "barragan-testing",
            "compartmentId": BARRAGAN_TESTING_TARGET.compartment_id,
            "region": BARRAGAN_TESTING_TARGET.region,
        },
        {
            "provider": "oci",
            "compartmentId": BARRAGAN_TESTING_TARGET.compartment_id,
            "region": BARRAGAN_TESTING_TARGET.region,
        },
        {
            "provider": "oci", "name": "barragan-testing",
            "region": BARRAGAN_TESTING_TARGET.region,
        },
        {
            "provider": "oci", "name": "barragan-testing",
            "compartmentId": BARRAGAN_TESTING_TARGET.compartment_id,
        },
        {
            "provider": "digitalocean", "name": "barragan-testing",
            "compartmentId": BARRAGAN_TESTING_TARGET.compartment_id,
            "region": BARRAGAN_TESTING_TARGET.region,
        },
        {
            "provider": "oci", "name": "production-a",
            "compartmentId": "ocid1.compartment.oc1..approvedtargeta",
            "region": BARRAGAN_TESTING_TARGET.region,
        },
        {
            "provider": "oci", "name": "barragan-testing",
            "compartmentId": "ocid1.compartment.oc1..wrong",
            "region": BARRAGAN_TESTING_TARGET.region,
        },
        {
            "provider": "oci", "name": "barragan-testing",
            "compartmentId": BARRAGAN_TESTING_TARGET.compartment_id,
            "region": "us-ashburn-1",
        },
        {
            "provider": "oci", "name": "barragan-testing",
            "compartmentId": BARRAGAN_TESTING_TARGET.compartment_id,
            "region": BARRAGAN_TESTING_TARGET.region, "extra": "value",
        },
    ],
)
def test_capture_rejects_malformed_or_non_testing_target_before_lease_or_operational_access(
    tmp_path: Path, monkeypatch, target,
):
    data = tmp_path / "devtest-data"
    data.mkdir()
    monkeypatch.setattr(capture, "CANONICAL_DEVTEST_DATA_DIR", data)
    engagement = StoredEngagement(
        "eng-test", "opaque-engagement", "active", "owner", "dev", None,
        {"deploymentTarget": target},
    )
    lease = Lease()

    class ForbiddenRepository:
        def get(self, *_args):
            pytest.fail("scope rejection reached an operational repository")

        def list_for_engagement(self, *_args):
            pytest.fail("scope rejection reached an operational repository")

    class ForbiddenRunner:
        def run(self, *_args, **_kwargs):
            pytest.fail("scope rejection reached Terraform")

    with pytest.raises(SketchProviderContractCaptureError) as exc:
        capture_sketch_provider_contract(
            CaptureRequest("eng-test", "chain-test", "channel-test", "add", "capture-abcd1234"),
            data_dir=data,
            environment="devtest",
            engagement_repository=Repo(engagement),
            chain_repository=ForbiddenRepository(),
            job_repository=ForbiddenRepository(),
            credential_repository=ForbiddenRepository(),
            terraform_runner=ForbiddenRunner(),
            overview_loader=lambda _id: pytest.fail("scope rejection loaded Operations"),
            lease_repository=lease,
        )

    assert exc.value.args == ("capture is limited to barragan-testing engagements",)
    assert lease.acquired == []


def test_devtest_scope_rejects_environment_redirect_and_symlink_alias(tmp_path: Path, monkeypatch):
    canonical = tmp_path / "canonical-devtest"; canonical.mkdir()
    alias = tmp_path / "devtest-alias"; alias.symlink_to(canonical, target_is_directory=True)
    monkeypatch.setattr(capture, "CANONICAL_DEVTEST_DATA_DIR", canonical)
    assert validate_devtest_scope(canonical, "devtest") == canonical
    with pytest.raises(SketchProviderContractCaptureError, match="canonical"):
        validate_devtest_scope(alias, "devtest")
    with pytest.raises(SketchProviderContractCaptureError, match="exact DevTest"):
        validate_devtest_scope(canonical, "production")


def test_devtest_scope_rejects_symlink_in_canonical_lexical_components(tmp_path: Path, monkeypatch):
    real = tmp_path / "real"; real.mkdir(); (real / "devtest-data").mkdir()
    link = tmp_path / "linked-parent"; link.symlink_to(real, target_is_directory=True)
    canonical = link / "devtest-data"
    monkeypatch.setattr(capture, "CANONICAL_DEVTEST_DATA_DIR", canonical)
    with pytest.raises(SketchProviderContractCaptureError, match="symlink"):
        validate_devtest_scope(canonical, "devtest")


def test_cli_parser_does_not_accept_paths_variables_or_credential_aliases(monkeypatch):
    from app.cli import capture_sketch_provider_contract as cli
    assert cli.main(["--workspace", "/tmp/unsafe", "--variables", "x=y", "--credential-alias", "other"]) == 2


def test_cli_success_emits_only_opaque_status_and_hashes(monkeypatch, capsys):
    from app.cli import capture_sketch_provider_contract as cli
    @contextmanager
    def fake_context(_runtime):
        yield
    monkeypatch.setattr(cli, "initialize_runtime", lambda *_a, **_k: object())
    monkeypatch.setattr(cli, "runtime_context", fake_context)
    monkeypatch.setattr(cli, "capture_sketch_provider_contract", lambda *_a, **_k: SimpleNamespace(
        to_dict=lambda: {"captureId": "capture-abcd1234", "status": "captured", "hashes": {"manifestSha256": "a" * 64}},
        internal_directory="/var/lib/barragan/devtest-data/provider-contract-captures/capture-abcd1234",
    ))
    assert cli.main([
        "--engagement-id", "eng-test", "--chain-id", "chain-test", "--channel-id", "channel-test",
        "--scenario", "no-op", "--capture-id", "capture-abcd1234",
    ]) == 0
    output = json.loads(capsys.readouterr().out)
    assert set(output) == {"captureId", "status", "hashes"}
    assert "/var/lib" not in json.dumps(output)


def test_real_runner_uses_only_plan_only_fake_binary_commands(tmp_path: Path):
    tf_data = tmp_path / "terraform-data"
    tf_data.mkdir()
    log = tf_data / "commands.log"
    binary = tmp_path / "terraform-fake"
    binary.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$TF_DATA_DIR/commands.log\"\n"
        "if [ \"$1\" = version ]; then printf '{\"terraform_version\":\"test\"}'; fi\n"
    )
    binary.chmod(0o700)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runtime_home = tmp_path / "runtime-home"
    runtime_home.mkdir(mode=0o700)
    runner = _PlanOnlyRunner(
        LocalTerraformCommandRunner(str(binary)),
        runtime_home_path=runtime_home,
        runtime_home_identity=capture._directory_identity(runtime_home.lstat()),
    )
    env = {
        "PATH": capture.CAPTURE_SYSTEM_PATH,
        "HOME": str(runtime_home),
        "TF_DATA_DIR": str(tf_data),
        "TF_IN_AUTOMATION": "1",
        "CHECKPOINT_DISABLE": "1",
    }
    runner.run("version", working_directory=str(workspace), env=env, inherit_environment=False)
    runner.run("init", working_directory=str(workspace), env=env, readonly_lock=True, backend=False, inherit_environment=False)
    with pytest.raises(SketchProviderContractCaptureError):
        runner.run("apply", working_directory=str(tmp_path), env=env)
    assert log.read_text().splitlines() == ["version -json", "init -input=false -backend=false -lockfile=readonly"]


def test_plan_only_runner_rejects_inherited_or_cli_argument_environment(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    tf_data = tmp_path / "terraform-data"
    runtime_home = tmp_path / "runtime-home"
    runtime_home.mkdir(mode=0o700)
    safe = {
        "PATH": capture.CAPTURE_SYSTEM_PATH,
        "HOME": str(runtime_home),
        "TF_DATA_DIR": str(tf_data),
        "TF_IN_AUTOMATION": "1",
        "CHECKPOINT_DISABLE": "1",
    }
    delegate = FakeRunner(_linode_noop_plan())
    runner = _PlanOnlyRunner(
        delegate, runtime_home_path=runtime_home,
        runtime_home_identity=capture._directory_identity(runtime_home.lstat()),
    )
    with pytest.raises(SketchProviderContractCaptureError, match="isolated"):
        runner.run("version", working_directory=str(workspace), env=safe)
    with pytest.raises(SketchProviderContractCaptureError, match="allowlisted"):
        runner.run(
            "version",
            working_directory=str(workspace),
            env={**safe, "TF_CLI_ARGS_plan": "-destroy"},
            inherit_environment=False,
        )
    assert delegate.calls == []


def test_plan_only_runner_rejects_every_noncanonical_path_before_delegate(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runtime_home = tmp_path / "runtime-home"
    runtime_home.mkdir(mode=0o700)
    base = {
        "PATH": capture.CAPTURE_SYSTEM_PATH,
        "HOME": str(runtime_home),
        "TF_DATA_DIR": str(tmp_path / "terraform-data"),
        "TF_IN_AUTOMATION": "1",
        "CHECKPOINT_DISABLE": "1",
    }
    alternatives = [
        None,
        "",
        "/usr/bin",
        ":".join(reversed(capture.CAPTURE_SYSTEM_PATH.split(os.pathsep))),
        f"{capture.CAPTURE_SYSTEM_PATH}{os.pathsep}/usr/local/bin",
        str(tmp_path / "bin"),
        ".",
        "$PATH",
        7,
    ]
    delegate = FakeRunner(_linode_noop_plan())
    runner = _PlanOnlyRunner(
        delegate, runtime_home_path=runtime_home,
        runtime_home_identity=capture._directory_identity(runtime_home.lstat()),
    )
    for value in alternatives:
        if value == capture.CAPTURE_SYSTEM_PATH:
            continue
        env = dict(base)
        if value is None:
            env.pop("PATH")
        else:
            env["PATH"] = value
        with pytest.raises(SketchProviderContractCaptureError, match="environment was invalid"):
            runner.run("version", working_directory=str(workspace), env=env, inherit_environment=False)
    assert delegate.calls == []


def test_capture_fixed_path_resolves_getent_on_supported_linux_runtime():
    if not sys.platform.startswith("linux"):
        pytest.skip("getent is a supported Barragan Linux runtime prerequisite")
    resolved = shutil.which("getent", path=capture.CAPTURE_SYSTEM_PATH)
    assert resolved is not None
    assert str(Path(resolved).parent) in capture.CAPTURE_SYSTEM_PATH.split(os.pathsep)


def test_isolated_environment_linode_plan_requires_home_and_accepts_empty_private_home(tmp_path: Path):
    binary = tmp_path / "terraform-linode-home-repro"
    binary.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = plan ] && { [ -z \"${HOME+x}\" ] || [ ! -d \"$HOME\" ]; }; then\n"
        "  printf 'HOME is not defined for config path\\n'\n"
        "  exit 1\n"
        "fi\n"
        "exit 0\n"
    )
    binary.chmod(0o700)
    workspace = tmp_path / "workspace"; workspace.mkdir()
    saved_plan = tmp_path / "plan.tfplan"
    runner = LocalTerraformCommandRunner(str(binary))
    missing = runner.run(
        "plan", working_directory=str(workspace), env={}, variables={},
        saved_plan_path=saved_plan, inherit_environment=False,
    )
    assert missing.returncode == 1 and "HOME is not defined" in missing.stdout
    runtime_home = tmp_path / "runtime-home"; runtime_home.mkdir(mode=0o700)
    present = runner.run(
        "plan", working_directory=str(workspace), env={"HOME": str(runtime_home)},
        variables={}, saved_plan_path=saved_plan, inherit_environment=False,
    )
    assert present.returncode == 0


@pytest.mark.parametrize(
    "case",
    ["missing", "empty", "non-string", "relative", "outside", "symlink", "wrong-mode", "wrong-parent"],
)
def test_plan_only_runner_rejects_invalid_runtime_home_before_delegate(case, tmp_path: Path):
    component = tmp_path / "component"; component.mkdir()
    workspace = component / "workspace"; workspace.mkdir()
    tf_data = component / "terraform-data"; tf_data.mkdir()
    runtime_home = component / "runtime-home"; runtime_home.mkdir(mode=0o700)
    expected_path = runtime_home
    supplied: object = str(runtime_home)
    if case == "missing": supplied = None
    elif case == "empty": supplied = ""
    elif case == "non-string": supplied = 7
    elif case == "relative": supplied = "runtime-home"
    elif case == "outside": supplied = str(tmp_path / "outside")
    elif case == "symlink":
        alias = component / "runtime-home-alias"; alias.symlink_to(runtime_home, target_is_directory=True)
        expected_path = alias; supplied = str(alias)
    elif case == "wrong-mode": runtime_home.chmod(0o755)
    elif case == "wrong-parent":
        other = tmp_path / "other"; other.mkdir()
        runtime_home = other / "runtime-home"; runtime_home.mkdir(mode=0o700)
        expected_path = runtime_home; supplied = str(runtime_home)
    if case == "outside":
        outside = tmp_path / "outside"; outside.mkdir(mode=0o700)
        expected_path = outside
    identity = capture._directory_identity(expected_path.resolve().lstat())
    delegate = FakeRunner(_linode_noop_plan())
    runner = _PlanOnlyRunner(
        delegate, runtime_home_path=expected_path, runtime_home_identity=identity,
    )
    env = {
        "PATH": capture.CAPTURE_SYSTEM_PATH,
        "HOME": supplied,
        "TF_DATA_DIR": str(tf_data),
        "TF_IN_AUTOMATION": "1",
        "CHECKPOINT_DISABLE": "1",
    }
    if supplied is None: env.pop("HOME")
    with pytest.raises(SketchProviderContractCaptureError, match="environment was invalid|runtime home was invalid"):
        runner.run("version", working_directory=str(workspace), env=env, inherit_environment=False)
    assert delegate.calls == []


def test_plan_only_runner_rejects_runtime_home_path_replacement(tmp_path: Path):
    component = tmp_path / "component"; component.mkdir()
    workspace = component / "workspace"; workspace.mkdir()
    tf_data = component / "terraform-data"; tf_data.mkdir()
    runtime_home = component / "runtime-home"; runtime_home.mkdir(mode=0o700)
    identity = capture._directory_identity(runtime_home.lstat())
    runner = _PlanOnlyRunner(
        FakeRunner(_linode_noop_plan()), runtime_home_path=runtime_home,
        runtime_home_identity=identity,
    )
    runtime_home.rename(component / "original-home")
    runtime_home.mkdir(mode=0o700)
    env = {
        "PATH": capture.CAPTURE_SYSTEM_PATH, "HOME": str(runtime_home),
        "TF_DATA_DIR": str(tf_data), "TF_IN_AUTOMATION": "1",
        "CHECKPOINT_DISABLE": "1",
    }
    with pytest.raises(SketchProviderContractCaptureError, match="runtime home was invalid"):
        runner.run("version", working_directory=str(workspace), env=env, inherit_environment=False)
    assert runner.runner.calls == []


def test_mixed_provider_plan_only_commands_use_distinct_private_homes_through_show(tmp_path: Path):
    homes = []
    for ordinal, provider in enumerate(("digitalocean", "linode"), 1):
        component = tmp_path / f"{ordinal:02d}-{provider}"; component.mkdir()
        workspace = component / "workspace"; workspace.mkdir()
        tf_data = component / "terraform-data"; tf_data.mkdir()
        runtime_home = component / "runtime-home"; runtime_home.mkdir(mode=0o700)
        homes.append(runtime_home)
        delegate = FakeRunner(_linode_noop_plan())
        runner = _PlanOnlyRunner(
            delegate, runtime_home_path=runtime_home,
            runtime_home_identity=capture._directory_identity(runtime_home.lstat()),
        )
        env = {
            "PATH": capture.CAPTURE_SYSTEM_PATH, "HOME": str(runtime_home),
            "TF_DATA_DIR": str(tf_data), "TF_IN_AUTOMATION": "1",
            "CHECKPOINT_DISABLE": "1",
            "TF_VAR_do_pat" if provider == "digitalocean" else "TF_VAR_linode_api_token": "secret",
        }
        plan = component / "raw.tfplan"
        runner.run("version", working_directory=str(workspace), env=env, inherit_environment=False)
        runner.run("init", working_directory=str(workspace), env=env, readonly_lock=True, backend=False, inherit_environment=False)
        runner.run("plan", working_directory=str(workspace), env=env, variables={}, saved_plan_path=plan, inherit_environment=False)
        runner.run("show", working_directory=str(workspace), env=env, saved_plan_path=plan, inherit_environment=False)
        assert [command for command, _kwargs in delegate.calls] == ["version", "init", "plan", "show"]
        assert all(kwargs["env"]["HOME"] == str(runtime_home) for _command, kwargs in delegate.calls)
    assert homes[0] != homes[1]


@pytest.mark.parametrize("command,kwargs", [
    ("init", {}),
    ("init", {"readonly_lock": True}),
    ("init", {"readonly_lock": True, "backend": False, "targets": ("x.y",)}),
    ("version", {"backend": False}),
    ("plan", {}),
    ("plan", {"saved_plan_path": "plan", "refresh": False}),
    ("plan", {"saved_plan_path": "plan", "targets": ("x.y",)}),
    ("show", {}),
    ("show", {"saved_plan_path": "plan", "variables": {"x": 1}}),
    ("show", {"saved_plan_path": "plan", "unexpected": True}),
])
def test_plan_only_runner_rejects_unsafe_options_before_delegate(command, kwargs):
    class NeverCalled:
        called = False
        def run(self, *_args, **_kwargs): self.called = True
    delegate = NeverCalled()
    with pytest.raises(SketchProviderContractCaptureError):
        _PlanOnlyRunner(delegate).run(command, working_directory="/tmp", env={}, **kwargs)
    assert delegate.called is False


def test_workspace_approval_binds_approved_bytes_to_clone_and_final_verification(tmp_path: Path):
    source = _workspace(tmp_path)
    original = (source / "firewall.tf").read_bytes()
    target = tmp_path / "clone"
    with capture.approved_workspace(source) as approval:
        (source / "firewall.tf").write_bytes(b"transient unapproved bytes")
        with pytest.raises(SketchProviderContractCaptureError, match="approved source content changed"):
            approval.clone_to(target)
        (source / "firewall.tf").write_bytes(original)
        with pytest.raises(SketchProviderContractCaptureError, match="changed during capture"):
            approval.verify()


def test_workspace_approval_rejects_path_replacement_even_with_identical_bytes(tmp_path: Path):
    source = _workspace(tmp_path)
    with capture.approved_workspace(source) as approval:
        path = source / "firewall.tf"
        content = path.read_bytes()
        replacement = source / "replacement"
        replacement.write_bytes(content)
        replacement.replace(path)
        with pytest.raises(SketchProviderContractCaptureError, match="changed during capture"):
            approval.verify()


def test_operator_readable_source_is_cloned_to_private_files(tmp_path: Path):
    source = _workspace(tmp_path)
    for path in source.iterdir():
        if path.is_file():
            path.chmod(0o644)
    target = tmp_path / "clone"
    _clone_workspace(source, target)
    assert all((path.stat().st_mode & 0o777) == 0o644 for path in source.iterdir() if path.is_file())
    expected = {
        ".terraform.lock.hcl", "firewall.tf", "output.tf", "terraform.tfstate", "variables.tf",
        "templates/inventory.tftpl", "templates/ssh-stanza.tftpl",
    }
    cloned = {str(path.relative_to(target)) for path in target.rglob("*") if path.is_file()}
    assert cloned == expected
    assert (target / "templates").stat().st_mode & 0o777 == 0o700
    assert all((path.stat().st_mode & 0o777) == 0o600 for path in target.rglob("*") if path.is_file())
    for relative in expected:
        assert (source / relative).read_bytes() == (target / relative).read_bytes()
        source_stat = (source / relative).stat()
        clone_stat = (target / relative).stat()
        assert (source_stat.st_dev, source_stat.st_ino) != (clone_stat.st_dev, clone_stat.st_ino)


@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
def test_reviewed_provider_source_dependency_inventory_is_exact(provider, tmp_path: Path):
    source = _workspace(tmp_path)
    (source / "output.tf").write_text(
        f'# realistic {provider} sketch outputs\n'
        'content = templatefile("templates/ssh-stanza.tftpl", { hosts = [] })\n'
        'content = templatefile("templates/inventory.tftpl", { hosts = [] })\n'
    )
    target = tmp_path / "clone"
    _clone_workspace(source, target)
    assert (target / "output.tf").read_bytes() == (source / "output.tf").read_bytes()


@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
def test_authoritative_redteam_infra_provider_source_closure_is_exact(provider):
    root = capture.redteam_infra_template_root() / "external" / "sketch" / provider
    assert root.is_dir(), f"authoritative redteam-infra {provider} sketch root is required: {root}"
    source = "\n".join(path.read_text(encoding="utf-8") for path in sorted(root.glob("*.tf")))
    assert tuple(sorted(capture._TEMPLATEFILE_CALL.findall(source))) == tuple(sorted(capture.REQUIRED_TEMPLATE_PATHS))
    assert len(capture._TEMPLATEFILE_TOKEN.findall(source)) == len(capture.REQUIRED_TEMPLATE_PATHS)
    assert "file(local.ssh_pub_key_path)" in source
    assert "local.ssh_pub_key_path" not in capture.REQUIRED_TEMPLATE_PATHS
    assert set(re.findall(r"\blocal\.([A-Za-z_][A-Za-z0-9_-]*)", source)) == {
        "abs_ssh_config_path", "default_ssh_priv_key", "default_ssh_pub_key",
        "ssh_priv_key_path", "ssh_pub_key_path",
    }
    assert set(re.findall(r"\bcount\.([A-Za-z_][A-Za-z0-9_-]*)", source)) == {"index"}
    assert not any(value in source for value in (
        "each.key", "each.value", "path.module", "path.root", "path.cwd", "terraform.workspace",
    ))
    assert re.fullmatch(r"[0-9a-f]{64}", capture.terraform_source_digest(root))


def test_authoritative_linode_firewall_rule_label_expressions_match_reviewed_families():
    source = (
        capture.redteam_infra_template_root()
        / "external" / "sketch" / "linode" / "firewall.tf"
    ).read_text(encoding="utf-8")
    assert re.findall(r'^\s*label\s*=\s*"([^"]+)"', source, re.MULTILINE) == [
        "${var.engagement_name}-firewall",
        "allow-tcp-${inbound.value}",
        "allow-${var.engagement_name}-host-${lower(inbound.value)}",
        "block-ipv6-${lower(inbound.value)}",
        "block-ipv6-${lower(outbound.value)}",
    ]
    adapter_source = inspect.getsource(terraform_plan_gate._public_ingress_rule)
    assert '"label": f"allow-{listener.protocol}-{listener.port}"' in adapter_source
    assert terraform_plan_gate._public_ingress_rule(
        "linode", FirewallIngressPort("udp", 3478),
    )["label"] == "allow-udp-3478"
    content_blocks = re.findall(r'content\s*\{(.*?)\n\s*\}', source, re.DOTALL)
    blocks_by_label = {
        re.search(r'label\s*=\s*"([^"]+)"', block).group(1): block
        for block in content_blocks
        if re.search(r'label\s*=\s*"([^"]+)"', block)
    }
    assert "ports    = inbound.value" in blocks_by_label["allow-tcp-${inbound.value}"]
    for label in (
        "allow-${var.engagement_name}-host-${lower(inbound.value)}",
        "block-ipv6-${lower(inbound.value)}",
        "block-ipv6-${lower(outbound.value)}",
    ):
        assert not re.search(r"^\s*ports\s*=", blocks_by_label[label], re.MULTILINE)
    adapter_source = inspect.getsource(template_compatibility.ensure_sketch_udp_ingress_compatibility)
    assert 'label    = "allow-udp-${inbound.value}"' in adapter_source
    assert "ports    = inbound.value" in adapter_source
    assert "for_each = var.allowed_udp_ports" in adapter_source


def test_framed_source_closure_digest_separates_former_workspace_collision(tmp_path: Path):
    first = b'locals { collision_first = true }\n'
    second = b'locals { collision_second = true }\n'
    first_digest = hashlib.sha256(first).hexdigest()
    workspace_a = _workspace(tmp_path / "a")
    workspace_b = _workspace(tmp_path / "b")
    (workspace_a / "g.tf").write_bytes(first)
    (workspace_a / "h.tf").write_bytes(second)
    (workspace_b / f"g.tf{first_digest}h.tf").write_bytes(second)
    with capture.approved_workspace(workspace_a) as approval_a, capture.approved_workspace(workspace_b) as approval_b:
        former_a = "".join(entry.relative_path + entry.sha256 for entry in approval_a.entries)
        former_b = "".join(entry.relative_path + entry.sha256 for entry in approval_b.entries)
        assert former_a == former_b
        assert approval_a.sha256 != approval_b.sha256


@pytest.mark.parametrize("anchored", [False, True])
def test_copy_rejects_simulated_destination_hardlink_before_fstat(anchored, tmp_path: Path, monkeypatch):
    source = _workspace(tmp_path)
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    with capture.approved_workspace(source) as approval:
        entry = next(item for item in approval.entries if item.relative_path == "firewall.tf")
        real_fstat = os.fstat

        def hardlinked_destination(descriptor):
            metadata = real_fstat(descriptor)
            if descriptor != entry.descriptor and stat.S_ISREG(metadata.st_mode):
                values = list(metadata)
                values[3] = 2
                return os.stat_result(values)
            return metadata

        monkeypatch.setattr(capture.os, "fstat", hardlinked_destination)
        if anchored:
            descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            directory = capture.AnchoredPrivateDirectory(
                target, descriptor, capture._directory_identity(real_fstat(descriptor)),
                SimpleNamespace(verify=lambda: None),
            )
            try:
                with pytest.raises(SketchProviderContractCaptureError, match="changed while cloning"):
                    capture._copy_manifest_entry_to_directory(entry, directory)
            finally:
                os.close(descriptor)
        else:
            with pytest.raises(SketchProviderContractCaptureError, match="changed while cloning"):
                capture._copy_manifest_entry(entry, target)


@pytest.mark.parametrize("missing", capture.REQUIRED_TEMPLATE_PATHS)
def test_workspace_rejects_missing_required_template(missing, tmp_path: Path):
    source = _workspace(tmp_path)
    (source / missing).unlink()
    with pytest.raises(SketchProviderContractCaptureError, match="omitted required template"):
        _clone_workspace(source, tmp_path / "clone")


@pytest.mark.parametrize("bad_paths", [
    ("/templates/inventory.tftpl", "templates/ssh-stanza.tftpl"),
    ("templates/../inventory.tftpl", "templates/ssh-stanza.tftpl"),
    ("templates/./inventory.tftpl", "templates/ssh-stanza.tftpl"),
    ("templates/inventory.tftpl", "templates/inventory.tftpl"),
    ("templates/inventory.tftpl", "templates/ssh-stanza.tftpl", "templates/extra.tftpl"),
])
def test_reviewed_template_path_allowlist_rejects_noncanonical_or_extra_paths(bad_paths):
    with pytest.raises(SketchProviderContractCaptureError, match="approved template"):
        capture._validated_required_template_paths(bad_paths)


@pytest.mark.parametrize("dependency", [
    'templatefile("templates/extra.tftpl", {})',
    'templatefile(var.template_path, {})',
    'templatefile("../inventory.tftpl", {})',
])
def test_workspace_rejects_unreviewed_or_dynamic_template_dependency(dependency, tmp_path: Path):
    source = _workspace(tmp_path)
    with (source / "output.tf").open("a") as output:
        output.write(dependency + "\n")
    (source / "templates" / "extra.tftpl").write_text("not approved")
    with pytest.raises(SketchProviderContractCaptureError, match="template dependenc"):
        _clone_workspace(source, tmp_path / "clone")


def test_workspace_rejects_template_directory_and_file_links(tmp_path: Path):
    source = _workspace(tmp_path)
    templates = source / "templates"
    moved = source / "real-templates"
    templates.rename(moved)
    templates.symlink_to(moved, target_is_directory=True)
    with pytest.raises(SketchProviderContractCaptureError, match="link or special"):
        _clone_workspace(source, tmp_path / "clone-dir-link")
    templates.unlink()
    moved.rename(templates)
    inventory = templates / "inventory.tftpl"
    inventory.unlink()
    inventory.symlink_to(templates / "ssh-stanza.tftpl")
    with pytest.raises(SketchProviderContractCaptureError, match="link or special"):
        _clone_workspace(source, tmp_path / "clone-file-link")


@pytest.mark.parametrize("kind", ["hardlink", "fifo"])
def test_workspace_rejects_template_hardlink_or_special_file(kind, tmp_path: Path):
    source = _workspace(tmp_path)
    inventory = source / "templates" / "inventory.tftpl"
    inventory.unlink()
    if kind == "hardlink":
        os.link(source / "templates" / "ssh-stanza.tftpl", inventory)
        match = "hardlinked"
    else:
        os.mkfifo(inventory, 0o600)
        match = "link or special"
    with pytest.raises(SketchProviderContractCaptureError, match=match):
        _clone_workspace(source, tmp_path / "clone")


def test_workspace_approval_rejects_template_file_replace_and_restore_race(tmp_path: Path):
    source = _workspace(tmp_path)
    path = source / "templates" / "inventory.tftpl"
    original = source / "templates" / "inventory.original"
    with capture.approved_workspace(source) as approval:
        path.rename(original)
        path.write_text("transient unapproved bytes")
        approval.clone_to(tmp_path / "clone")
        assert (tmp_path / "clone" / "templates" / "inventory.tftpl").read_text() != "transient unapproved bytes"
        path.unlink()
        original.rename(path)
        with pytest.raises(SketchProviderContractCaptureError, match="directory changed"):
            approval.verify()


def test_workspace_approval_rejects_template_directory_replace_and_restore_race(tmp_path: Path):
    source = _workspace(tmp_path)
    templates = source / "templates"
    original = source / "templates.original"
    with capture.approved_workspace(source) as approval:
        templates.rename(original)
        templates.mkdir()
        (templates / "inventory.tftpl").write_text("transient inventory")
        (templates / "ssh-stanza.tftpl").write_text("transient ssh")
        approval.clone_to(tmp_path / "clone")
        assert (tmp_path / "clone" / "templates" / "inventory.tftpl").read_text() != "transient inventory"
        shutil.rmtree(templates)
        original.rename(templates)
        with pytest.raises(SketchProviderContractCaptureError, match="root changed|directory changed"):
            approval.verify()


def test_source_digest_includes_template_bytes(tmp_path: Path):
    source = _workspace(tmp_path)
    before = capture.terraform_source_digest(source)
    with (source / "templates" / "inventory.tftpl").open("a") as template:
        template.write("changed")
    assert capture.terraform_source_digest(source) != before


@pytest.mark.parametrize(
    "action,mutation,allowed",
    [
        ("outbound_channel_validation", False, True),
        ("outbound_channel_validation", None, False),
        ("outbound_channel_validation", "false", False),
        ("future_unknown_read", False, False),
        ("mixed_provider_sketch_reconcile", False, False),
    ],
)
def test_active_job_gate_is_fail_closed(action, mutation, allowed):
    job = StoredJobRun(
        "job-active", action, "running", "engagement", "engagement", "eng-test", "operator",
        {} if mutation is None else {"mutation": mutation}, [], "now", "now", "", [],
    )
    assert capture.active_job_allows_capture(job) is allowed
    assert capture.active_job_allows_capture(replace(job, status="succeeded")) is True
    assert capture.active_job_allows_capture(replace(job, status="unknown")) is False


def test_cli_parse_and_domain_failures_never_echo_arguments_or_exception(monkeypatch, capsys):
    from app.cli import capture_sketch_provider_contract as cli
    secret = "SENSITIVE-ARGUMENT-AND-PATH"
    assert cli.main(["--scenario", secret]) == 2
    assert secret not in capsys.readouterr().err

    @contextmanager
    def fake_context(_runtime):
        yield
    monkeypatch.setattr(cli, "initialize_runtime", lambda *_a, **_k: object())
    monkeypatch.setattr(cli, "runtime_context", fake_context)
    monkeypatch.setattr(
        cli,
        "capture_sketch_provider_contract",
        lambda *_a, **_k: (_ for _ in ()).throw(SketchProviderContractCaptureError(secret)),
    )
    assert cli.main([
        "--engagement-id", "eng-test", "--chain-id", "chain-test", "--channel-id", "channel-test",
        "--scenario", "no-op", "--capture-id", "capture-abcd1234",
    ]) == 1
    assert secret not in capsys.readouterr().err

    monkeypatch.setattr(cli, "initialize_runtime", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError(secret)))
    assert cli.main([
        "--engagement-id", "eng-test", "--chain-id", "chain-test", "--channel-id", "channel-test",
        "--scenario", "no-op", "--capture-id", "capture-abcd1234",
    ]) == 1
    assert secret not in capsys.readouterr().err


@pytest.mark.parametrize("schema", [None, True, False])
def test_state_schema_rejects_missing_and_boolean_values(tmp_path: Path, schema):
    state = tmp_path / "terraform.tfstate"
    resource = {
        "mode": "managed",
        "type": "linode_firewall",
        "name": "firewall",
        "provider": 'provider["registry.terraform.io/linode/linode"]',
        "instances": [{"attributes": {}, "sensitive_attributes": []}],
    }
    if schema is not None:
        resource["instances"][0]["schema_version"] = schema
    state.write_text(json.dumps({"resources": [resource]}))
    with pytest.raises(SketchProviderContractCaptureError, match="schema"):
        capture.firewall_schema_versions(state, "linode")


def test_state_and_plan_schema_reject_duplicate_firewall_resources(tmp_path: Path):
    state = tmp_path / "terraform.tfstate"
    resource = {
        "mode": "managed",
        "type": "linode_firewall",
        "name": "firewall",
        "provider": 'provider["registry.terraform.io/linode/linode"]',
        "instances": [{"schema_version": 0, "attributes": {}, "sensitive_attributes": []}],
    }
    state.write_text(json.dumps({"resources": [resource, dict(resource)]}))
    with pytest.raises(SketchProviderContractCaptureError, match="duplicated"):
        capture.firewall_schema_versions(state, "linode")

    document = _linode_noop_plan()
    resources = document["planned_values"]["root_module"]["resources"]
    resources.insert(1, copy.deepcopy(resources[0]))
    with pytest.raises(SketchProviderContractCaptureError, match="duplicated"):
        capture.plan_firewall_schema_versions(document, "linode")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda resource: resource.update(mode="data"),
        lambda resource: resource.update(name="other"),
        lambda resource: resource.update(provider='provider["registry.terraform.io/hashicorp/random"]'),
        lambda resource: resource.update(instances=[]),
        lambda resource: resource["instances"].append(copy.deepcopy(resource["instances"][0])),
        lambda resource: resource["instances"][0].update(schema_version=1),
        lambda resource: resource.update(schema_version=1),
    ],
)
def test_state_schema_rejects_noncanonical_resource_instance_and_conflicts(tmp_path: Path, mutation):
    state = tmp_path / "terraform.tfstate"
    resource = {
        "mode": "managed",
        "type": "linode_firewall",
        "name": "firewall",
        "provider": 'provider["registry.terraform.io/linode/linode"]',
        "instances": [{"schema_version": 0, "attributes": {}, "sensitive_attributes": []}],
    }
    mutation(resource)
    state.write_text(json.dumps({"version": 4, "resources": [resource]}))
    with pytest.raises(SketchProviderContractCaptureError, match="firewall|schema|instance|identity"):
        capture.firewall_schema_versions(state, "linode")


@pytest.mark.parametrize(
    "provider,resource_type,provider_reference",
    [
        ("linode", "linode_firewall", 'provider["registry.terraform.io/linode/linode"]'),
        ("digitalocean", "digitalocean_firewall", 'provider["registry.terraform.io/digitalocean/digitalocean"]'),
    ],
)
def test_state_schema_accepts_real_terraform_v4_resource_instance_shape(
    tmp_path: Path, provider: str, resource_type: str, provider_reference: str,
):
    state = tmp_path / "terraform.tfstate"
    state.write_text(json.dumps({
        "version": 4,
        "terraform_version": "1.15.5",
        "serial": 12,
        "lineage": "00000000-0000-0000-0000-000000000000",
        "outputs": {},
        "resources": [{
            "mode": "managed",
            "type": resource_type,
            "name": "firewall",
            "provider": provider_reference,
            "instances": [{
                "schema_version": 0,
                "attributes": {"id": "opaque-provider-id"},
                "sensitive_attributes": [],
            }],
        }],
    }))
    assert capture.firewall_schema_versions(state, provider) == [0]


def test_plan_schema_rejects_missing_and_boolean_values():
    for invalid in (None, True, False, 1):
        document = _linode_noop_plan()
        resource = document["planned_values"]["root_module"]["resources"][0]
        if invalid is None:
            resource.pop("schema_version")
        else:
            resource["schema_version"] = invalid
        with pytest.raises(SketchProviderContractCaptureError, match="schema"):
            capture.plan_firewall_schema_versions(document, "linode")


def test_strict_git_revision_rejects_unavailable_and_dirty_checkout(monkeypatch, tmp_path: Path):
    clean_root = SimpleNamespace(returncode=0, stdout=str(tmp_path) + "\n")
    clean_revision = SimpleNamespace(returncode=0, stdout="a" * 40 + "\n")
    clean_status = SimpleNamespace(returncode=0, stdout="")
    unavailable = SimpleNamespace(returncode=1, stdout="")
    dirty = SimpleNamespace(returncode=0, stdout=" M backend/file.py\n")
    monkeypatch.setattr(capture.subprocess, "run", lambda *a, **k: unavailable)
    with pytest.raises(SketchProviderContractCaptureError, match="unavailable"):
        capture.strict_git_revision(tmp_path)
    responses = iter((clean_root, clean_revision, dirty))
    monkeypatch.setattr(capture.subprocess, "run", lambda *a, **k: next(responses))
    with pytest.raises(SketchProviderContractCaptureError, match="not clean"):
        capture.strict_git_revision(tmp_path)


@pytest.mark.parametrize("revision", ["a" * 39, "a" * 41, "A" * 40, "g" * 40])
def test_strict_git_revision_requires_exact_lowercase_sha1(monkeypatch, tmp_path: Path, revision):
    responses = iter((
        SimpleNamespace(returncode=0, stdout=str(tmp_path) + "\n"),
        SimpleNamespace(returncode=0, stdout=revision + "\n"),
        SimpleNamespace(returncode=0, stdout=""),
    ))
    monkeypatch.setattr(capture.subprocess, "run", lambda *a, **k: next(responses))
    with pytest.raises(SketchProviderContractCaptureError, match="unavailable"):
        capture.strict_git_revision(tmp_path)


def test_strict_git_revision_uses_fixed_minimal_environment_and_exact_top_level(monkeypatch, tmp_path: Path):
    calls = []
    monkeypatch.setattr(capture.shutil, "which", lambda *_a, **_k: "/usr/bin/git")
    for key in (
        "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_CONFIG", "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_GLOBAL", "GIT_CONFIG_COUNT", "HOME", "PATH",
    ):
        monkeypatch.setenv(key, f"POISON-{key}")

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[-2:] == ["rev-parse", "--show-toplevel"]:
            return SimpleNamespace(returncode=0, stdout=str(tmp_path) + "\n")
        if argv[-3:] == ["rev-parse", "--verify", "HEAD^{commit}"]:
            return SimpleNamespace(returncode=0, stdout="a" * 40 + "\n")
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(capture.subprocess, "run", run)
    assert capture.strict_git_revision(tmp_path) == "a" * 40
    assert len(calls) == 3
    for argv, kwargs in calls:
        assert argv[0] == "/usr/bin/git"
        assert "--no-optional-locks" in argv
        assert "core.fsmonitor=false" in argv
        assert f"core.hooksPath={os.devnull}" in argv
        assert not any("safe.directory" in part for part in argv)
        assert kwargs["env"] == {
            "PATH": capture.CAPTURE_SYSTEM_PATH,
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
        assert not any("POISON" in value for value in kwargs["env"].values())
    assert calls[1][0][-1] == "HEAD^{commit}"
    assert calls[2][0][-2:] == ["--porcelain=v1", "--untracked-files=all"]


def test_strict_git_revision_rejects_symlink_and_non_top_level_roots_before_trust(monkeypatch, tmp_path: Path):
    repository = tmp_path / "repository"
    repository.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(repository, target_is_directory=True)
    monkeypatch.setattr(capture.subprocess, "run", lambda *_a, **_k: pytest.fail("Git ran for a symlink root"))
    with pytest.raises(SketchProviderContractCaptureError, match="root was invalid"):
        capture.strict_git_revision(alias)

    responses = iter((
        SimpleNamespace(returncode=0, stdout=str(tmp_path) + "\n"),
        SimpleNamespace(returncode=0, stdout="a" * 40 + "\n"),
        SimpleNamespace(returncode=0, stdout=""),
    ))
    monkeypatch.setattr(capture.subprocess, "run", lambda *_a, **_k: next(responses))
    with pytest.raises(SketchProviderContractCaptureError, match="root was invalid"):
        capture.strict_git_revision(repository)


def test_strict_git_revision_keeps_dubious_ownership_fail_closed_without_safe_directory(monkeypatch, tmp_path: Path):
    calls = []
    monkeypatch.setattr(capture.shutil, "which", lambda *_a, **_k: "/usr/bin/git")
    def rejected(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=128, stdout="", stderr="fatal: detected dubious ownership")
    monkeypatch.setattr(capture.subprocess, "run", rejected)
    with pytest.raises(SketchProviderContractCaptureError, match="unavailable"):
        capture.strict_git_revision(tmp_path)
    assert calls
    assert all(not any("safe.directory" in part for part in argv) for argv, _kwargs in calls)


@pytest.mark.parametrize(
    "target,message",
    [
        ("tool", "source revision was unavailable"),
        ("tool", "source checkout was not clean"),
        ("tool_dubious", "source revision was unavailable"),
        ("template", "source revision was unavailable"),
        ("template", "source checkout was not clean"),
        ("template_dubious", "source revision was unavailable"),
        ("template_source", "Terraform source closure was unavailable"),
    ],
)
def test_provenance_preflight_rejects_before_keys_credentials_runner_or_capture_publication(
    target, message, tmp_path: Path, monkeypatch,
):
    data = tmp_path / "devtest-data"
    data.mkdir()
    workspace = _workspace(tmp_path)
    engagement, chain, job = _records(workspace)
    template_root = tmp_path / "redteam-infra"
    template_root.mkdir()
    tool_root = Path(capture.__file__).resolve().parents[3]
    monkeypatch.setattr(capture, "CANONICAL_DEVTEST_DATA_DIR", data)
    monkeypatch.setattr(capture, "validate_existing_sketch_state_workspace", lambda *_a, **_k: SimpleNamespace(path=workspace))
    monkeypatch.setattr(capture, "redteam_infra_template_root", lambda: template_root)
    monkeypatch.setattr(capture, "terraform_source_digest", lambda _root: "1" * 64)

    def revision(root):
        if (
            (target.startswith("tool") and Path(root) == tool_root)
            or (target.startswith("template") and target != "template_source" and Path(root) == template_root)
        ):
            raise SketchProviderContractCaptureError(message)
        return "a" * 40

    monkeypatch.setattr(capture, "strict_git_revision", revision)
    if target == "template_source":
        monkeypatch.setattr(capture, "terraform_source_digest", lambda _root: (_ for _ in ()).throw(SketchProviderContractCaptureError(message)))
    monkeypatch.setattr(capture, "materialized_sketch_key_files", lambda *_a, **_k: pytest.fail("preflight reached key materialization"))
    monkeypatch.setattr(capture, "capture_role", lambda *_a, **_k: pytest.fail("preflight reached capture execution"))

    class ForbiddenRunner:
        def run(self, *_a, **_k): pytest.fail("preflight reached Terraform")

    lease = Lease()
    with pytest.raises(SketchProviderContractCaptureError, match="revision|checkout|source closure"):
        capture_sketch_provider_contract(
            CaptureRequest("eng-test", "chain-test", "channel-test", "no-op", "capture-preflight1"),
            data_dir=data, environment="devtest", engagement_repository=Repo(engagement),
            chain_repository=Repo(chain), job_repository=Repo(job),
            credential_resolver=lambda *_a: pytest.fail("preflight reached credential resolution"),
            terraform_runner=ForbiddenRunner(),
            overview_loader=lambda _id: {"inboundChannels": [_channel()], "sketchInfrastructure": chain.nodes},
            lease_repository=lease,
        )
    assert lease.released
    assert not (data / "provider-contract-captures").exists()


def test_source_provenance_fences_revision_and_mixed_provider_digest_changes(monkeypatch, tmp_path: Path):
    tool_root = Path(capture.__file__).resolve().parents[3]
    template_root = tmp_path / "redteam-infra"
    template_root.mkdir()
    provider_roots = {
        provider: template_root / "external" / "sketch" / provider
        for provider in ("linode", "digitalocean")
    }
    for root in provider_roots.values(): root.mkdir(parents=True)
    monkeypatch.setattr(capture, "redteam_infra_template_root", lambda: template_root)
    revisions = {tool_root: "a" * 40, template_root: "b" * 40}
    digests = {provider_roots["linode"]: "1" * 64, provider_roots["digitalocean"]: "2" * 64}
    monkeypatch.setattr(capture, "strict_git_revision", lambda root: revisions[Path(root)])
    monkeypatch.setattr(capture, "terraform_source_digest", lambda root: digests[Path(root)])
    baseline = capture.read_capture_source_provenance({"linode", "digitalocean"})
    assert baseline.template_sources == (("digitalocean", "2" * 64), ("linode", "1" * 64))
    digests[provider_roots["digitalocean"]] = "3" * 64
    with pytest.raises(SketchProviderContractCaptureError, match="changed during capture"):
        capture.require_capture_source_provenance(baseline, {"linode", "digitalocean"})

    digests[provider_roots["digitalocean"]] = "2" * 64
    revisions[template_root] = "c" * 40
    with pytest.raises(SketchProviderContractCaptureError, match="changed during capture"):
        capture.require_capture_source_provenance(baseline, {"linode", "digitalocean"})


@pytest.mark.parametrize("changed", ["tool", "template"])
def test_source_provenance_rejects_revision_change_while_hashing(changed, monkeypatch, tmp_path: Path):
    template_root = tmp_path / "redteam-infra"
    provider_root = template_root / "external" / "sketch" / "linode"
    template_root.mkdir(); provider_root.mkdir(parents=True)
    tool_root = Path(capture.__file__).resolve().parents[3]
    monkeypatch.setattr(capture, "redteam_infra_template_root", lambda: template_root)
    answers = iter(
        ("a" * 40, "b" * 40, "c" * 40, "b" * 40)
        if changed == "tool"
        else ("a" * 40, "b" * 40, "a" * 40, "c" * 40)
    )
    monkeypatch.setattr(capture, "strict_git_revision", lambda _root: next(answers))
    monkeypatch.setattr(capture, "terraform_source_digest", lambda _root: "1" * 64)
    with pytest.raises(SketchProviderContractCaptureError, match="changed while reading"):
        capture.read_capture_source_provenance({"linode"})


def test_postflight_change_publishes_no_provenance_or_manifest(tmp_path: Path, monkeypatch):
    data = tmp_path / "devtest-data"; data.mkdir()
    workspace = _workspace(tmp_path)
    engagement, chain, job = _records(workspace)
    job = replace(job, input={**job.input, "materializeKeyFiles": True})
    document = _clean_linode_capture_noop_plan()
    _prepare_capture_outputs(
        document, "linode", tmp_path / "keys" / "id.pub",
        data / "provider-contract-captures" / "capture-postflight1" / "01-edge-linode" / "runtime-home",
    )
    runner = FakeRunner(document)

    @contextmanager
    def materialized(_engagement_id):
        root = tmp_path / "keys"; root.mkdir()
        paths = [root / name for name in ("id", "id.pub", "transport.pub")]
        for path in paths: path.write_text("PRIVATE-KEY-SENTINEL")
        try:
            yield MaterializedSketchKeys(*(str(path) for path in paths))
        finally:
            for path in paths: path.unlink()
            root.rmdir()

    monkeypatch.setattr(capture, "CANONICAL_DEVTEST_DATA_DIR", data)
    monkeypatch.setattr(capture, "validate_existing_sketch_state_workspace", lambda *_a, **_k: SimpleNamespace(path=workspace))
    monkeypatch.setattr(capture, "retained_compute_image_for_workspace", lambda *_a, **_k: "linode/ubuntu22.04")
    monkeypatch.setattr(capture, "adapt_clone", lambda clone, _provider: (clone / "adapter-only.tf").write_text("adapted"))
    monkeypatch.setattr(capture, "strict_git_revision", lambda _root: "a" * 40)
    monkeypatch.setattr(
        capture, "read_capture_source_provenance",
        lambda *_a, **_k: capture.CaptureSourceProvenance(
            "a" * 40, "b" * 40, (("linode", "1" * 64),),
        ),
    )
    monkeypatch.setattr(capture, "materialized_sketch_key_files", materialized)
    monkeypatch.setattr(
        capture, "require_capture_source_provenance",
        lambda *_a, **_k: (_ for _ in ()).throw(SketchProviderContractCaptureError("capture source provenance changed during capture")),
    )
    with pytest.raises(SketchProviderContractCaptureError, match="provenance changed"):
        capture_sketch_provider_contract(
            CaptureRequest("eng-test", "chain-test", "channel-test", "no-op", "capture-postflight1"),
            data_dir=data, environment="devtest", engagement_repository=Repo(engagement),
            chain_repository=Repo(chain), job_repository=Repo(job), terraform_runner=runner,
            credential_resolver=lambda *_a: "PRIVATE-CREDENTIAL-SENTINEL",
            overview_loader=lambda _id: {"inboundChannels": [_channel()], "sketchInfrastructure": chain.nodes},
            lease_repository=Lease(),
        )
    assert [command for command, _kwargs in runner.calls] == ["version", "init", "plan", "show"]
    root = data / "provider-contract-captures" / "capture-postflight1"
    assert list(root.rglob("terraform-show.sanitized.json"))
    assert not list(root.rglob("provenance.json"))
    assert not list(root.rglob("manifest.json"))


@pytest.mark.parametrize("failure", ["global-third-check", "capture-root", "source-approval"])
def test_accepted_evidence_is_withheld_until_all_final_fences_pass(failure, tmp_path: Path, monkeypatch):
    root = tmp_path / "capture"
    role_export = root / "01-edge-linode" / "export"
    role_export.mkdir(parents=True)

    class Pending:
        def verify(self):
            return None

    class Directory:
        def __init__(self, path, reject=False):
            self.path = path
            self.reject = reject
        def verify(self):
            if self.reject:
                raise SketchProviderContractCaptureError("final destination integrity failed")

    class Approval:
        def verify(self):
            if failure == "source-approval":
                raise SketchProviderContractCaptureError("retained workspace changed")

    checks = []
    def source_check(*_args, **_kwargs):
        checks.append(len(checks) + 1)
        if failure == "global-third-check" and len(checks) == 3:
            raise SketchProviderContractCaptureError("global source provenance changed")
    monkeypatch.setattr(capture, "require_capture_source_provenance", source_check)
    if failure == "global-third-check":
        source_check(None, {"linode"})
        source_check(None, {"digitalocean"})

    request = CaptureRequest("eng-test", "chain-test", "channel-test", "add", "capture-final-fence")
    roles = (
        capture.RoleCapture("edge", "linode", tmp_path, "edge-1", {}),
        capture.RoleCapture("middle", "digitalocean", tmp_path, "middle-1", {}),
    )
    with pytest.raises(SketchProviderContractCaptureError):
        capture.publish_capture_evidence(
            request,
            roles,
            [Pending()],
            {"edge": Approval()},
            capture.CaptureSourceProvenance(
                "a" * 40, "b" * 40,
                (("digitalocean", "2" * 64), ("linode", "1" * 64)),
            ),
            Directory(root, reject=failure == "capture-root"),
            expected_tool_revision="a" * 40,
        )
    assert not list(root.rglob("provenance.json"))
    assert not list(root.rglob("manifest.json"))


def test_later_role_envelope_failure_leaves_first_role_diagnostics_without_accepted_evidence(tmp_path: Path, monkeypatch):
    data = tmp_path / "devtest-data"; data.mkdir()
    workspace = _workspace(tmp_path)
    engagement, chain, job = _records(workspace)
    roles = (
        capture.RoleCapture("edge", "linode", workspace, "edge-1", {}),
        capture.RoleCapture("middle", "digitalocean", workspace, "middle-1", {}),
    )
    monkeypatch.setattr(capture, "CANONICAL_DEVTEST_DATA_DIR", data)
    monkeypatch.setattr(capture, "runtime_roles", lambda *_a, **_k: roles)
    monkeypatch.setattr(
        capture, "read_capture_source_provenance",
        lambda *_a, **_k: capture.CaptureSourceProvenance(
            "a" * 40, "b" * 40,
            (("digitalocean", "2" * 64), ("linode", "1" * 64)),
        ),
    )

    # Return a pending object after retaining the diagnostic directories.
    class Pending:
        def verify(self): return None
        def publish(self): pytest.fail("publication ran after a later-role failure")
    def capture_one(*args, ordinal, capture_root, directory_stack, **kwargs):
        if ordinal == 2:
            unsafe = _digitalocean_computed_drift_noop_plan()
            unsafe["resource_drift"][0]["change"]["after"]["created_at"] = "changed"
            capture.classify_capture_plan_envelope(unsafe, "digitalocean", 2, "no-op")
            pytest.fail("unsafe later-role envelope was accepted")
        component = directory_stack.enter_context(capture_root.create_child("01-edge-linode"))
        export = directory_stack.enter_context(component.create_child("export"))
        export.write_exclusive("terraform-show.sanitized.json", "{}\n")
        return Pending()
    monkeypatch.setattr(capture, "capture_role", capture_one)

    with pytest.raises(SketchProviderContractCaptureError, match="actual computed-only|observed refresh"):
        capture_sketch_provider_contract(
            CaptureRequest("eng-test", "chain-test", "channel-test", "no-op", "capture-later-role"),
            data_dir=data, environment="devtest", engagement_repository=Repo(engagement),
            chain_repository=Repo(chain), job_repository=Repo(job),
            overview_loader=lambda _id: {"inboundChannels": [_channel()], "sketchInfrastructure": chain.nodes},
            lease_repository=Lease(),
        )
    root = data / "provider-contract-captures" / "capture-later-role"
    assert list(root.rglob("terraform-show.sanitized.json"))
    assert not list(root.rglob("provenance.json"))
    assert not list(root.rglob("manifest.json"))


@contextmanager
def _publication_fixture(tmp_path: Path, monkeypatch):
    data = tmp_path / "devtest-data"
    data.mkdir()
    monkeypatch.setattr(capture, "CANONICAL_DEVTEST_DATA_DIR", data)
    monkeypatch.setattr(capture, "_rename_directory_noreplace", _test_rename_noreplace)
    with capture.anchored_devtest_destination(data, "devtest") as destination:
        with capture.private_umask(), ExitStack() as stack:
            base = stack.enter_context(destination.open_or_create_private_child("provider-contract-captures"))
            root = stack.enter_context(base.create_child("capture-publication"))
            pending = []
            for ordinal, (role, provider) in enumerate((("edge", "linode"), ("middle", "digitalocean")), 1):
                name = f"{ordinal:02d}-{role}-{provider}"
                component = stack.enter_context(root.create_child(name))
                export = stack.enter_context(component.create_child("export"))
                runtime_home = stack.enter_context(component.create_child("runtime-home"))
                contract_bytes = f'{{"role":"{role}"}}\n'.encode()
                contract_path = export.write_exclusive_bytes("terraform-show.sanitized.json", contract_bytes)
                contract_sha256 = hashlib.sha256(contract_bytes).hexdigest()
                pending.append(capture.PendingRoleCapture(
                    name, role, provider, contract_path, contract_sha256,
                    {
                        "provider": provider, "role": role, "gateResult": "accepted",
                        "exportSha256": contract_sha256,
                    },
                    export, runtime_home, (component, export, runtime_home),
                ))
            yield root, pending


def _test_rename_noreplace(parent_descriptor, source, destination):
    try:
        os.stat(destination, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise SketchProviderContractCaptureError("accepted evidence already exists")
    os.rename(
        source, destination,
        src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor,
    )


def _publication_roles(tmp_path: Path):
    return (
        capture.RoleCapture("edge", "linode", tmp_path, "edge-1", {}),
        capture.RoleCapture("middle", "digitalocean", tmp_path, "middle-1", {}),
    )


def _publish_fixture(root, pending, roles, monkeypatch):
    monkeypatch.setattr(capture, "require_capture_source_provenance", lambda *_a, **_k: None)
    return capture.publish_capture_evidence(
        CaptureRequest("eng-test", "chain-test", "channel-test", "add", "capture-publication"),
        roles,
        pending,
        {"edge": SimpleNamespace(verify=lambda: None), "middle": SimpleNamespace(verify=lambda: None)},
        capture.CaptureSourceProvenance(
            "a" * 40, "b" * 40,
            (("digitalocean", "2" * 64), ("linode", "1" * 64)),
        ),
        root,
        expected_tool_revision="a" * 40,
    )


@pytest.mark.parametrize("outcome,entry_kind", [("zero", "file"), ("nonzero", "directory"), ("exception", "symlink")])
def test_provider_created_runtime_home_content_blocks_all_acceptance(
    outcome, entry_kind, tmp_path: Path, monkeypatch,
):
    with _publication_fixture(tmp_path, monkeypatch) as (root, pending):
        role = pending[0]
        component = role.export.parent
        with ExitStack() as stack:
            workspace = stack.enter_context(component.create_child("audit-workspace"))
            tf_data = stack.enter_context(component.create_child("terraform-data"))
            raw = stack.enter_context(component.create_child("raw-runtime-audit"))

            class WritesHome:
                def run(self, _command, **_kwargs):
                    path = role.runtime_home.path / "PRIVATE-HOME-CONTENT-SENTINEL"
                    if entry_kind == "directory": path.mkdir()
                    elif entry_kind == "symlink": path.symlink_to("missing-private-target")
                    else: path.write_text("PRIVATE-RUNTIME-HOME-SECRET")
                    if outcome == "exception":
                        raise RuntimeError("provider execution failed")
                    return TerraformCommandResult(
                        "version", 0 if outcome == "zero" else 1, "", "",
                    )

            runner = _PlanOnlyRunner(
                WritesHome(), runtime_home_path=role.runtime_home.path,
                runtime_home_identity=role.runtime_home.identity,
            )
            env = {
                "PATH": capture.CAPTURE_SYSTEM_PATH,
                "HOME": str(role.runtime_home.path),
                "TF_DATA_DIR": str(tf_data.path),
                "TF_IN_AUTOMATION": "1",
                "CHECKPOINT_DISABLE": "1",
            }
            with pytest.raises(SketchProviderContractCaptureError) as error:
                capture.run_terraform_attempt(
                    runner, "version", raw, role.runtime_home,
                    working_directory=str(workspace.path), env=env,
                    inherit_environment=False,
                )
            assert "SENTINEL" not in str(error.value)
            if outcome != "exception":
                assert (raw.path / "terraform-version.result.json").is_file()
        assert not (root.path / "accepted-evidence").exists()
        assert not list(root.path.rglob("provenance.json"))


def test_atomic_accepted_evidence_uses_exact_in_memory_serialization_and_hashes(tmp_path: Path, monkeypatch):
    real_sha256_file = capture.sha256_file
    def reject_published_reopen(path):
        if {"accepted-evidence", "pending-accepted-evidence"} & set(Path(path).parts):
            pytest.fail("an accepted or staged published path was reopened for an authoritative hash")
        return real_sha256_file(path)
    monkeypatch.setattr(capture, "sha256_file", reject_published_reopen)
    with _publication_fixture(tmp_path, monkeypatch) as (root, pending):
        manifest_hash = _publish_fixture(root, pending, _publication_roles(tmp_path), monkeypatch)
        accepted = root.path / "accepted-evidence"
        assert accepted.is_dir()
        assert not (root.path / "pending-accepted-evidence").exists()
        manifest_bytes = (accepted / "manifest.json").read_bytes()
        assert manifest_hash == hashlib.sha256(manifest_bytes).hexdigest()
        manifest = json.loads(manifest_bytes)
        for component, role_capture in zip(manifest["components"], pending, strict=True):
            provenance_bytes = (
                accepted / "components" / role_capture.component_name / "provenance.json"
            ).read_bytes()
            assert provenance_bytes == capture._deterministic_json_bytes(role_capture.provenance)
            assert component["hashes"]["provenance"] == hashlib.sha256(provenance_bytes).hexdigest()
            assert component["hashes"]["contract"] == role_capture.contract_sha256


@pytest.mark.parametrize("failure", ["role-1", "role-2", "manifest"])
def test_accepted_evidence_file_write_failure_never_creates_final_subtree(failure, tmp_path: Path, monkeypatch):
    real_write = capture.AnchoredPrivateDirectory.write_exclusive_bytes_held
    def fail_selected(directory, name, value):
        selected = (
            (failure == "role-1" and directory.path.name == "01-edge-linode")
            or (failure == "role-2" and directory.path.name == "02-middle-digitalocean")
            or (failure == "manifest" and name == "manifest.json")
        )
        if selected:
            raise SketchProviderContractCaptureError("injected accepted evidence write failure")
        return real_write(directory, name, value)
    monkeypatch.setattr(capture.AnchoredPrivateDirectory, "write_exclusive_bytes_held", fail_selected)
    with _publication_fixture(tmp_path, monkeypatch) as (root, pending):
        with pytest.raises(SketchProviderContractCaptureError, match="injected"):
            _publish_fixture(root, pending, _publication_roles(tmp_path), monkeypatch)
        assert not (root.path / "accepted-evidence").exists()


def test_accepted_evidence_rename_failure_leaves_only_nonaccepted_stage(tmp_path: Path, monkeypatch):
    with _publication_fixture(tmp_path, monkeypatch) as (root, pending):
        monkeypatch.setattr(
            capture, "_rename_directory_noreplace",
            lambda *_a, **_k: (_ for _ in ()).throw(OSError("injected rename failure")),
        )
        with pytest.raises(SketchProviderContractCaptureError, match="publication failed"):
            _publish_fixture(root, pending, _publication_roles(tmp_path), monkeypatch)
        assert not (root.path / "accepted-evidence").exists()
        assert (root.path / "pending-accepted-evidence").is_dir()


def test_destination_inserted_after_precheck_is_not_replaced_or_accepted(tmp_path: Path, monkeypatch):
    with _publication_fixture(tmp_path, monkeypatch) as (root, pending):
        def competing_destination(parent_descriptor, _source, destination):
            os.mkdir(destination, 0o700, dir_fd=parent_descriptor)
            descriptor = os.open(destination, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0), dir_fd=parent_descriptor)
            try:
                marker = os.open("competitor", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=descriptor)
                os.close(marker)
            finally:
                os.close(descriptor)
            raise SketchProviderContractCaptureError("accepted evidence already exists")
        monkeypatch.setattr(capture, "_rename_directory_noreplace", competing_destination)
        with pytest.raises(SketchProviderContractCaptureError, match="already exists"):
            _publish_fixture(root, pending, _publication_roles(tmp_path), monkeypatch)
        assert (root.path / "accepted-evidence" / "competitor").is_file()
        assert not (root.path / "accepted-evidence" / "manifest.json").exists()


def test_fsync_failure_before_commit_leaves_no_final_accepted_subtree(tmp_path: Path, monkeypatch):
    with _publication_fixture(tmp_path, monkeypatch) as (root, pending):
        real_fsync = capture.os.fsync
        calls = {"count": 0}
        def fail_first_publication_fsync(descriptor):
            calls["count"] += 1
            if calls["count"] == 1:
                raise OSError("injected fsync failure")
            return real_fsync(descriptor)
        monkeypatch.setattr(capture.os, "fsync", fail_first_publication_fsync)
        with pytest.raises(OSError, match="injected fsync"):
            _publish_fixture(root, pending, _publication_roles(tmp_path), monkeypatch)
        assert not (root.path / "accepted-evidence").exists()


@pytest.mark.skipif(sys.platform != "linux", reason="renameat2 is the Linux production primitive")
def test_linux_renameat2_noreplace_is_real_and_never_replaces(tmp_path: Path):
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir(); destination.mkdir()
    (destination / "competitor").write_text("preserved")
    descriptor = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        with pytest.raises(SketchProviderContractCaptureError, match="already exists"):
            capture._rename_directory_noreplace(descriptor, "source", "destination")
        assert source.is_dir()
        assert (destination / "competitor").read_text() == "preserved"
        (destination / "competitor").unlink()
        destination.rmdir()
        capture._rename_directory_noreplace(descriptor, "source", "destination")
        assert destination.is_dir() and not source.exists()
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("error", [capture.errno.ENOSYS, capture.errno.EINVAL])
def test_renameat2_unavailable_kernel_errors_fail_closed(error, monkeypatch):
    class RenameAt2:
        argtypes = None
        restype = None
        def __call__(self, *_args):
            capture.ctypes.set_errno(error)
            return -1
    monkeypatch.setattr(capture.ctypes, "CDLL", lambda *_a, **_k: SimpleNamespace(renameat2=RenameAt2()))
    with pytest.raises(SketchProviderContractCaptureError, match="unavailable"):
        capture._rename_directory_noreplace(4, "source", "destination")


def test_missing_renameat2_symbol_fails_closed(monkeypatch):
    monkeypatch.setattr(capture.ctypes, "CDLL", lambda *_a, **_k: SimpleNamespace())
    with pytest.raises(SketchProviderContractCaptureError, match="unavailable"):
        capture._rename_directory_noreplace(4, "source", "destination")


def test_existing_final_accepted_subtree_is_never_replaced(tmp_path: Path, monkeypatch):
    with _publication_fixture(tmp_path, monkeypatch) as (root, pending):
        accepted = root.path / "accepted-evidence"
        accepted.mkdir(mode=0o700)
        marker = accepted / "existing"
        marker.write_text("do-not-replace")
        with pytest.raises(SketchProviderContractCaptureError, match="already exists"):
            _publish_fixture(root, pending, _publication_roles(tmp_path), monkeypatch)
        assert marker.read_text() == "do-not-replace"


def test_same_uid_staged_file_replacement_is_rejected_before_atomic_publish(tmp_path: Path, monkeypatch):
    real_write = capture.AnchoredPrivateDirectory.write_exclusive_bytes_held
    replaced = {"value": False}
    def replace_after_write(directory, name, value):
        written = real_write(directory, name, value)
        if not replaced["value"] and name == "provenance.json":
            path = directory.path / name
            path.unlink()
            path.write_bytes(b"SAME-UID-REPLACEMENT-SENTINEL")
            path.chmod(0o600)
            replaced["value"] = True
        return written
    monkeypatch.setattr(capture.AnchoredPrivateDirectory, "write_exclusive_bytes_held", replace_after_write)
    with _publication_fixture(tmp_path, monkeypatch) as (root, pending):
        with pytest.raises(SketchProviderContractCaptureError, match="published file changed"):
            _publish_fixture(root, pending, _publication_roles(tmp_path), monkeypatch)
        assert not (root.path / "accepted-evidence").exists()


def test_offline_verifier_accepts_only_complete_final_atomic_layout(tmp_path: Path, monkeypatch):
    verifier = Path(capture.__file__).resolve().parents[3] / "scripts" / "verify-sketch-provider-contract-capture.py"
    with _publication_fixture(tmp_path, monkeypatch) as (root, pending):
        _publish_fixture(root, pending, _publication_roles(tmp_path), monkeypatch)
        valid = subprocess.run(
            [sys.executable, str(verifier), str(root.path)],
            check=False, capture_output=True, text=True,
        )
        assert valid.returncode == 0
        assert json.loads(valid.stdout)["status"] == "verified"
        runtime_secret = root.path / "01-edge-linode" / "runtime-home" / "PRIVATE-NONACCEPTED-SENTINEL"
        runtime_secret.write_bytes(b"\xff\x00private")
        ignored_runtime_home = subprocess.run(
            [sys.executable, str(verifier), str(root.path)],
            check=False, capture_output=True, text=True,
        )
        assert ignored_runtime_home.returncode == 0
        (root.path / "pending-accepted-evidence").mkdir(mode=0o700)
        pending_result = subprocess.run(
            [sys.executable, str(verifier), str(root.path)],
            check=False, capture_output=True, text=True,
        )
        assert pending_result.returncode != 0
        assert "non-final" in pending_result.stderr

    partial = tmp_path / "partial"
    accepted = partial / "accepted-evidence"
    accepted.mkdir(parents=True)
    (accepted / "manifest.json").write_text(json.dumps({
        "components": [{"role": "edge", "provider": "linode", "hashes": {}}],
    }))
    partial_result = subprocess.run(
        [sys.executable, str(verifier), str(partial)],
        check=False, capture_output=True, text=True,
    )
    assert partial_result.returncode != 0
    assert "component directory" in partial_result.stderr


@pytest.mark.parametrize(
    "section,actions",
    [
        ("resource_drift", []),
        ("resource_drift", ["update", "delete"]),
        ("resource_drift", ["create", "create"]),
        ("deferred_changes", ["delete", "create", "read"]),
        ("deferred_changes", [True]),
    ],
)
def test_contract_export_uses_shared_action_grammar_for_drift_and_deferred(section, actions):
    document = _linode_noop_plan()
    envelope = document[section][0]["resource_change"] if section == "deferred_changes" else document[section][0]
    envelope["change"]["actions"] = actions
    with pytest.raises(SketchProviderContractCaptureError, match="actions were invalid"):
        export_firewall_contract(document, "linode")


@pytest.mark.parametrize("actions", [["delete", "create"], ["create", "delete"]])
def test_contract_export_preserves_valid_replacement_action_order(actions):
    document = _linode_noop_plan()
    document["resource_drift"][0]["change"]["actions"] = actions
    exported = export_firewall_contract(document, "linode")
    assert exported["resource_drift"][0]["change"]["actions"] == actions


def test_destination_anchor_rejects_lexical_root_replacement_before_any_child_write(tmp_path: Path, monkeypatch):
    canonical = tmp_path / "devtest-data"
    canonical.mkdir()
    monkeypatch.setattr(capture, "CANONICAL_DEVTEST_DATA_DIR", canonical)
    moved = tmp_path / "moved-devtest-data"
    with pytest.raises(SketchProviderContractCaptureError, match="destination path changed"):
        with capture.anchored_devtest_destination(canonical, "devtest") as destination:
            canonical.rename(moved)
            canonical.mkdir()
            destination.open_or_create_private_child("provider-contract-captures")
    assert list(canonical.iterdir()) == []


def test_destination_anchor_rejects_ancestor_replacement_before_any_child_write(tmp_path: Path, monkeypatch):
    ancestor = tmp_path / "canonical-parent"
    canonical = ancestor / "devtest-data"
    canonical.mkdir(parents=True)
    monkeypatch.setattr(capture, "CANONICAL_DEVTEST_DATA_DIR", canonical)
    moved = tmp_path / "moved-parent"
    with pytest.raises(SketchProviderContractCaptureError, match="destination path changed"):
        with capture.anchored_devtest_destination(canonical, "devtest") as destination:
            ancestor.rename(moved)
            canonical.mkdir(parents=True)
            destination.open_or_create_private_child("provider-contract-captures")
    assert list(canonical.iterdir()) == []
