# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Callable, Mapping

from app.core.command_environment import barragan_subprocess_env
from app.integrations.managed_host_images import ManagedHostImageProfile, managed_host_image_profile
from app.integrations.ansible_disposable_validation import (
    ANSIBLE_PLAYBOOK_OVERRIDE_VARIABLES,
    ANSIBLE_OVERRIDE_VARIABLES,
    DEFAULT_SSH_USER,
    SSH_CONNECT_TIMEOUT_SECONDS,
    SSH_KNOWN_HOSTS_RELATIVE_PATH,
    SSH_PRIVATE_KEY_ENV,
    SSH_PUBLIC_KEY_ENV,
    SSH_READINESS_SLEEP_SECONDS,
    SSH_SOURCE_CIDR_ENV,
    resolve_ansible,
    resolve_ansible_playbook,
)
from app.integrations.oci_disposable_terraform import (
    CleanupVerificationResult,
    DisposableCommandResult,
    EXECUTION_CONFIRMATION,
    resolve_terraform,
)
from app.integrations.oci_read_validation import (
    CommandRunner as OciReadCommandRunner,
    DEFAULT_REGION,
    OciDevelopmentTarget,
    OciReadValidationResult,
    OciSafetyError,
    resolve_oci_cli,
    run_read_validation,
)
from app.integrations.oci_compute_profiles import OciComputeProfile, resolve_oci_compute_profile
from app.services.catalog import is_single_proxy_template, template_allows_elk
from app.services.outbound_channel_artifacts import CoreHost, render_core_hosts_content
from app.services.capability_execution import (
    build_core_capability_role_apply_plan,
    copy_core_capability_roles,
    render_core_capability_apply_playbook,
)
from app.services.managed_host_image_continuity import (
    retained_oci_source_image,
)


WORKSPACE_NAME = "barragan-pilot-standard-rti"
DESTROY_AFTER_VALIDATION = "destroy_after_validation"
HOLD_FOR_REVIEW = "hold_for_review"
SSH_SOURCE_CIDRS_ENV = "BARRAGAN_VALIDATION_SSH_SOURCE_CIDRS"
CORE_MANAGEMENT_SSH_USER = "user"
DEFAULT_OPERATOR_SSH_SOURCE_CIDRS = [
    "159.54.185.107/32",
    "160.34.86.0/23",
    "160.34.88.0/21",
    "160.34.104.0/21",
    "160.34.112.0/20",
]
PILOT_VCN_NAME = "pilot-vcn"
PILOT_HOMEBASE_SUBNET_NAME = "pilot-homebase-subnet"
PILOT_PROXY_SUBNET_NAME = "pilot-proxy-subnet"
PILOT_UTILITY_SUBNET_NAME = "pilot-utility-subnet"
PILOT_INTERNET_GATEWAY_NAME = "pilot-igw"
PILOT_ROUTE_TABLE_NAME = "pilot-route"
PILOT_SECURITY_LIST_NAME = "pilot-ssh-only"
PILOT_HOMEBASE_NAME = "homebase-pilot"
PILOT_PROXY_NAME = "proxy01-pilot"
PILOT_PROXY02_NAME = "proxy02-pilot"
PILOT_ELK_NAME = "elk-pilot"
PILOT_CIDR = "192.168.0.0/16"
PILOT_HOMEBASE_CIDR = "192.168.0.0/24"
PILOT_PROXY_CIDR = "192.168.2.0/24"
PILOT_UTILITY_CIDR = "192.168.1.0/24"
PILOT_HOMEBASE_PRIVATE_IP = "192.168.0.10"
PILOT_PROXY_PRIVATE_IP = "192.168.2.11"
PILOT_PROXY02_PRIVATE_IP = "192.168.2.12"
PILOT_ELK_PRIVATE_IP = "192.168.1.13"
ENGAGEMENT_PATH = "/engagement"
CAPABILITY_PLAYBOOK_PATH = "ansible/apply_capabilities.yml"
BOOTSTRAP_VALIDATE_PLAYBOOK_PATH = "ansible/bootstrap_validate.yml"
DESTROY_COMMAND_INDEX = 7
DEFAULT_COMMAND_TIMEOUT_SECONDS = 240
TERRAFORM_MUTATION_TIMEOUT_SECONDS = 1800
STANDARD_RTI_SSH_READINESS_TIMEOUT_SECONDS = 600
SSH_READINESS_COMMAND_TIMEOUT_SECONDS = 660
# Fresh Ubuntu images can download ~87 MB for python3-pip's recommended build
# dependencies at 20–50 KB/s from the regional mirror. Keep a finite window
# for the complete selected core role sequence; do not retry package work.
CAPABILITY_APPLY_TIMEOUT_SECONDS = 5400
BOOTSTRAP_VALIDATE_TIMEOUT_SECONDS = 1800
COMMAND_OUTPUT_LOG_DIR = "logs"
COMMAND_FAILURE_EXCERPT_CHARS = 65536
COMMAND_FAILURE_EXCERPT_EDGE_CHARS = COMMAND_FAILURE_EXCERPT_CHARS // 2
COMMAND_HEARTBEAT_SECONDS = 20.0
COMMAND_OBSERVATION_SECONDS = 1.0
COMMAND_PROGRESS_EVENT_LIMIT = 120
COMMAND_HEARTBEAT_EVENT_LIMIT = 90
ANSIBLE_TASK_EVENT_LIMIT = COMMAND_PROGRESS_EVENT_LIMIT - COMMAND_HEARTBEAT_EVENT_LIMIT
ANSIBLE_TASK_EVENT_THROTTLE_SECONDS = 2.0
ANSIBLE_PROGRESS_FIELD_CHARS = 240
OCI_CORE_INSTANCE_AGENT_POLICY = {
    "are_all_plugins_disabled": True,
    "is_monitoring_disabled": True,
    "plugins_config": {
        "name": "Compute Instance Monitoring",
        "desired_state": "DISABLED",
    },
}
OCI_CORE_PROXY_SKIP_SOURCE_DEST_CHECK = True
OCI_CORE_DISABLED_AGENT_UNITS = (
    "snap.oracle-cloud-agent.oracle-cloud-agent-updater.service",
    "snap.oracle-cloud-agent.oracle-cloud-agent.service",
)
OCI_CORE_AGENT_PROCESS_PATTERN = "([o]racle-cloud-agent|[g]omon|[o]ci-wlp|[u]nifiedmonitoring)"
OCI_CORE_ROLE_NAME = "oci"
# These values are deliberately pinned to the verified upstream OCI Terraform
# DHCP policy. The copied upstream OCI role is the effective host resolver
# policy and is validated before a workspace can be rendered.
OCI_CORE_DHCP_DNS_SERVERS = ("8.8.8.8", "1.1.1.1")
OCI_CORE_RESOLV_CONF_DNS_SERVERS = ("1.1.1.1", "8.8.8.8")
OCI_CORE_INSTANCE_BASELINE_FINGERPRINT = hashlib.sha256(
    json.dumps(
        {
            "agentConfig": OCI_CORE_INSTANCE_AGENT_POLICY,
            "agentProcessPattern": OCI_CORE_AGENT_PROCESS_PATTERN,
            "dhcpDnsServers": OCI_CORE_DHCP_DNS_SERVERS,
            "disabledAgentUnits": OCI_CORE_DISABLED_AGENT_UNITS,
            "proxySkipSourceDestCheck": OCI_CORE_PROXY_SKIP_SOURCE_DEST_CHECK,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
).hexdigest()

CommandRunner = Callable[[list[str], Path | None], subprocess.CompletedProcess[str]]
ProgressCallback = Callable[[dict[str, Any]], None]

COMMAND_PHASES = {
    "terraform_init": ("Initialize Terraform workspace", "terraform"),
    "terraform_apply": ("Create core infrastructure", "terraform"),
    "terraform_output": ("Read core infrastructure outputs", "terraform"),
    "ssh_readiness": ("Wait for core SSH readiness", "ansible"),
    "ansible_ping": ("Validate core host access", "ansible"),
    "ansible_bootstrap": ("Configure RTI base layout", "ansible_playbook"),
    "ansible_capabilities": ("Apply selected RTI capabilities", "ansible_playbook"),
    "terraform_destroy": ("Destroy core infrastructure", "terraform"),
    "cleanup_verification": ("Verify infrastructure cleanup", "provider_cli"),
}


@dataclass(frozen=True)
class PilotStandardRtiNames:
    engagement_name: str
    vcn_name: str
    homebase_subnet_name: str
    proxy_subnet_name: str
    utility_subnet_name: str
    internet_gateway_name: str
    route_table_name: str
    utility_route_table_name: str
    nat_gateway_name: str
    security_list_name: str
    homebase_name: str
    proxy_name: str
    proxy02_name: str
    elk_name: str
    dns_label: str


@dataclass(frozen=True)
class PilotStandardRtiArtifact:
    path: str
    content: str

    def to_dict(self, include_content: bool = False) -> dict[str, Any]:
        body: dict[str, Any] = {"path": self.path}
        if include_content:
            body["content"] = self.content
        return body


@dataclass(frozen=True)
class PilotStandardRtiWorkspace:
    target: OciDevelopmentTarget
    names: PilotStandardRtiNames
    proxy_count: int
    elk_enabled: bool
    compute_profile: OciComputeProfile
    resources: list[dict[str, Any]]
    cleanup: dict[str, Any]
    artifacts: list[PilotStandardRtiArtifact]

    def to_dict(self, include_content: bool = False) -> dict[str, Any]:
        validate_pilot_target(self.target)
        return {
            "ok": True,
            "workspace": WORKSPACE_NAME,
            "mode": "pilot_standard_rti_render_preview",
            "mutation": False,
            "notice": (
                f"This preview renders a disposable {1 + self.proxy_count + int(self.elk_enabled)}-node "
                f"{_template_display_name(self.compute_profile.template_id)} pilot only. "
                "It does not run Terraform, create OCI resources, run Ansible, or destroy resources."
            ),
            "target": _target_dict(self.target),
            "topology": pilot_topology(
                self.names,
                proxy_count=self.proxy_count,
                elk_enabled=self.elk_enabled,
                template_id=self.compute_profile.template_id,
            ),
            "computeProfile": self.compute_profile.to_dict(),
            "resources": self.resources,
            "cleanup": self.cleanup,
            "artifacts": [artifact.to_dict(include_content) for artifact in self.artifacts],
        }


@dataclass(frozen=True)
class PilotStandardRtiExecutionResult:
    target: OciDevelopmentTarget
    workspace: PilotStandardRtiWorkspace
    workspace_dir: Path
    preflight: OciReadValidationResult
    commands_planned: list[list[str]]
    commands_run: list[DisposableCommandResult]
    created_resources: list[dict[str, Any]]
    destroyed_resources: list[dict[str, Any]]
    cleanup_verification: CleanupVerificationResult | None
    mutation_status: str
    ansible_status: str
    final_cleanup_status: str
    deployment_mode: str = HOLD_FOR_REVIEW
    connection_details: list[dict[str, Any]] | None = None
    outbound_channels: list[dict[str, Any]] | None = None
    inbound_channels: list[dict[str, Any]] | None = None

    @property
    def ok(self) -> bool:
        if self.deployment_mode == HOLD_FOR_REVIEW:
            return (
                self.mutation_status == "deployed"
                and self.ansible_status == "validated"
                and self.final_cleanup_status == "pending_operator_teardown"
            )
        return (
            self.mutation_status == "destroyed"
            and self.ansible_status == "validated"
            and self.final_cleanup_status == "verified_clean"
        )

    @property
    def did_mutate(self) -> bool:
        return self.mutation_status not in {
            "preflight_failed",
            "terraform_binary_unresolved",
            "ansible_binary_unresolved",
            "ansible_playbook_binary_unresolved",
            "ssh_key_unresolved",
            "ssh_source_cidr_unsafe",
            "terraform_init_failed",
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "workspace": WORKSPACE_NAME,
            "mode": "pilot_standard_rti_guarded_execute",
            "deploymentMode": self.deployment_mode,
            "mutation": self.did_mutate,
            "target": _target_dict(self.target, mutation=self.did_mutate),
            "topology": pilot_topology(
                self.workspace.names,
                proxy_count=self.workspace.proxy_count,
                elk_enabled=self.workspace.elk_enabled,
                template_id=self.workspace.compute_profile.template_id,
            ),
            "workspaceDir": str(self.workspace_dir),
            "preflight": self.preflight.to_dict(),
            "commandsPlanned": self.commands_planned,
            "commandsRun": [command.to_dict() for command in self.commands_run],
            "createdResources": self.created_resources,
            "destroyedResources": self.destroyed_resources,
            "cleanupVerification": (
                self.cleanup_verification.to_dict()
                if self.cleanup_verification is not None
                else None
            ),
            "connectionDetails": self.connection_details or [],
            "mutationStatus": self.mutation_status,
            "ansibleStatus": self.ansible_status,
            "finalCleanupStatus": self.final_cleanup_status,
            "outboundChannels": self.outbound_channels or [],
            "inboundChannels": self.inbound_channels or [],
        }


def pilot_names(engagement_name: str | None = None) -> PilotStandardRtiNames:
    slug = _engagement_slug(engagement_name or "pilot")
    dns_label = re.sub(r"[^a-z0-9]", "", f"b{slug}")[:15] or "bpilot"
    return PilotStandardRtiNames(
        engagement_name=slug,
        vcn_name=f"{slug}-vcn",
        homebase_subnet_name=f"{slug}-homebase-subnet",
        proxy_subnet_name=f"{slug}-proxy-subnet",
        utility_subnet_name=f"{slug}-utility-subnet",
        internet_gateway_name=f"{slug}-igw",
        route_table_name=f"{slug}-route",
        utility_route_table_name=f"{slug}-utility-route",
        nat_gateway_name=f"{slug}-nat",
        security_list_name=f"{slug}-ssh-only",
        homebase_name=f"homebase-{slug}",
        proxy_name=f"proxy01-{slug}",
        proxy02_name=f"proxy02-{slug}",
        elk_name=f"elk-{slug}",
        dns_label=dns_label,
    )


def _validate_proxy_count(proxy_count: int) -> None:
    if proxy_count not in {1, 2}:
        raise ValueError("pilot Standard RTI renderer supports only 1 or 2 proxies")


def _proxy_specs(names: PilotStandardRtiNames, proxy_count: int) -> list[dict[str, str]]:
    _validate_proxy_count(proxy_count)
    specs = [
        {"id": "proxy01", "display_name": names.proxy_name, "private_ip": PILOT_PROXY_PRIVATE_IP},
        {"id": "proxy02", "display_name": names.proxy02_name, "private_ip": PILOT_PROXY02_PRIVATE_IP},
    ]
    return specs[:proxy_count]


def _engagement_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9-]+", "-", value.strip().lower())
    slug = re.sub(r"-+", "-", slug).strip("-")
    if not slug:
        raise ValueError("engagement name is required for Standard RTI deployment naming")
    return slug


def pilot_topology(
    names: PilotStandardRtiNames | None = None,
    *,
    proxy_count: int = 2,
    elk_enabled: bool = False,
    template_id: str | None = None,
) -> dict[str, Any]:
    resolved_names = names or pilot_names()
    proxies = _proxy_specs(resolved_names, proxy_count)
    resolved_template_id = template_id or ("dev-infra" if proxy_count == 1 else "standard-rti")
    return {
        "template": _template_display_name(resolved_template_id),
        "engagementName": resolved_names.engagement_name,
        "vcnCidr": PILOT_CIDR,
        "subnets": [
            {
                "role": "homebase",
                "cidr": PILOT_HOMEBASE_CIDR,
                "privateIp": PILOT_HOMEBASE_PRIVATE_IP,
            },
            *[
            {
                "role": "proxy",
                "cidr": PILOT_PROXY_CIDR,
                "privateIp": proxy["private_ip"],
            }
            for proxy in proxies
            ],
            *([{"role": "utility", "cidr": PILOT_UTILITY_CIDR, "privateIp": PILOT_ELK_PRIVATE_IP}] if elk_enabled else []),
        ],
        "nodes": [
            {
                "role": "homebase",
                "displayName": resolved_names.homebase_name,
                "privateIp": PILOT_HOMEBASE_PRIVATE_IP,
            },
            *[
            {
                "role": "proxy",
                "displayName": proxy["display_name"],
                "privateIp": proxy["private_ip"],
            }
            for proxy in proxies
            ],
            *([{"role": "elk", "displayName": resolved_names.elk_name, "privateIp": PILOT_ELK_PRIVATE_IP}] if elk_enabled else []),
        ],
        "deferred": [
            "real routes",
            "DNS",
            "certificates",
            "reverse channels",
            "live proxy-stack services",
            "sketch middle/edge nodes",
        ],
    }


def _template_display_name(template_id: str) -> str:
    return {
        "standard-rti": "Standard RTI",
        "dev-infra": "Dev Infra",
        "small-dev-infra": "Small Dev Infra",
    }.get(template_id, template_id)


def pilot_channel_rows(
    names: PilotStandardRtiNames | None = None,
    *,
    region: str = DEFAULT_REGION,
    proxy_count: int = 2,
) -> dict[str, list[dict[str, Any]]]:
    resolved_names = names or pilot_names()
    proxy_name = _proxy_specs(resolved_names, proxy_count)[0]["display_name"]
    return {
        "outboundChannels": [
            {
                "channelId": "chain-1",
                "chainId": "chain-1",
                "proxy": proxy_name,
                "middle": "Not Deployed",
                "edge": "Not Deployed",
                "port": "3333",
                "region": region,
                "provider": "N/A",
                "domain": "Not Deployed",
                "purpose": "named sketch egress route intent",
                "status": "Not Ready",
            }
        ],
        "inboundChannels": [],
    }


def build_pilot_standard_rti_workspace(
    target: OciDevelopmentTarget | None = None,
    *,
    engagement_name: str | None = None,
    oci_executable: str = "oci",
    proxy_count: int = 2,
    template_id: str | None = None,
    elk_enabled: bool = False,
    compute_profile: OciComputeProfile | None = None,
    host_image_profile: ManagedHostImageProfile | None = None,
    retained_oci_source_image_id: str = "",
) -> PilotStandardRtiWorkspace:
    resolved_target = target or OciDevelopmentTarget()
    validate_pilot_target(resolved_target)
    _validate_proxy_count(proxy_count)
    resolved_template_id = template_id or ("dev-infra" if proxy_count == 1 else "standard-rti")
    if is_single_proxy_template(resolved_template_id) and proxy_count != 1:
        raise ValueError(f"{resolved_template_id} requires exactly 1 OCI proxy")
    if not template_allows_elk(resolved_template_id) and elk_enabled:
        raise ValueError("small-dev-infra does not support an ELK node")
    profile = compute_profile or resolve_oci_compute_profile(resolved_template_id)
    if profile.template_id != resolved_template_id:
        raise ValueError("OCI compute profile template does not match the selected template")
    names = pilot_names(engagement_name)
    proxies = _proxy_specs(names, proxy_count)
    resources = [
        _resource("oci_core_vcn", "pilot_vcn", names.vcn_name, resolved_target),
        _resource("oci_core_subnet", "homebase_subnet", names.homebase_subnet_name, resolved_target),
        _resource("oci_core_subnet", "proxy_subnet", names.proxy_subnet_name, resolved_target),
        *([_resource("oci_core_subnet", "utility_subnet", names.utility_subnet_name, resolved_target)] if elk_enabled else []),
        _resource("oci_core_internet_gateway", "pilot_gateway", names.internet_gateway_name, resolved_target),
        _resource("oci_core_route_table", "pilot_route", names.route_table_name, resolved_target),
        *([
            _resource("oci_core_nat_gateway", "utility_nat", names.nat_gateway_name, resolved_target),
            _resource("oci_core_route_table", "utility_route", names.utility_route_table_name, resolved_target),
        ] if elk_enabled else []),
        _resource("oci_core_security_list", "pilot_security", names.security_list_name, resolved_target),
        _resource("oci_core_security_list", "proxy_ingress_security", f"{names.security_list_name}-proxy-ingress", resolved_target),
        _resource("oci_core_security_list", "homebase_nfs_security", f"{names.security_list_name}-homebase-nfs", resolved_target),
        _resource("oci_core_instance", "homebase", names.homebase_name, resolved_target),
        *[
            _resource("oci_core_instance", proxy["id"], proxy["display_name"], resolved_target)
            for proxy in proxies
        ],
        *([_resource("oci_core_instance", "elk", names.elk_name, resolved_target)] if elk_enabled else []),
    ]
    cleanup = {
        "expectedDestroyBehavior": (
            "terraform destroy must remove all pilot homebase/proxy/ELK compute nodes, "
            "subnets, gateway, route table, security list, and VCN immediately after validation."
        ),
        "verificationCommands": _cleanup_commands(resolved_target, names, oci_executable, proxy_count=proxy_count, elk_enabled=elk_enabled),
        "successCriteria": (
            "Cleanup verification must find no live pilot compute, subnet, gateway, "
        f"route table, security list, or VCN resources in {resolved_target.name}."
        ),
    }
    artifacts = [
        PilotStandardRtiArtifact("versions.tf", _versions_tf()),
        PilotStandardRtiArtifact(
            "variables.tf",
            _variables_tf(resolved_target, host_image_profile, retained_oci_source_image_id),
        ),
        PilotStandardRtiArtifact("main.tf", _main_tf(names, profile, proxy_count=proxy_count, elk_enabled=elk_enabled)),
        PilotStandardRtiArtifact("terraform.tfvars.json", _tfvars_json(resolved_target, profile)),
        PilotStandardRtiArtifact("ansible/inventory.ini", _inventory_ini(proxy_count=proxy_count, elk_enabled=elk_enabled)),
        PilotStandardRtiArtifact(
            "ansible/bootstrap_validate.yml",
            _validation_playbook(names, proxy_count=proxy_count, elk_enabled=elk_enabled),
        ),
        PilotStandardRtiArtifact(
            "MANIFEST.md",
            _manifest(resolved_target, names, resources, cleanup, proxy_count=proxy_count, template_id=resolved_template_id),
        ),
    ]
    return PilotStandardRtiWorkspace(
        target=resolved_target,
        names=names,
        proxy_count=proxy_count,
        elk_enabled=elk_enabled,
        compute_profile=profile,
        resources=resources,
        cleanup=cleanup,
        artifacts=artifacts,
    )


def render_pilot_standard_rti_workspace(
    destination: Path,
    target: OciDevelopmentTarget | None = None,
    *,
    engagement_name: str | None = None,
    engagement_id: str | None = None,
    engagement_repos_root: Path = Path("/opt/engagements"),
    oci_executable: str = "oci",
    proxy_count: int = 2,
    template_id: str | None = None,
    elk_enabled: bool = False,
    compute_profile: OciComputeProfile | None = None,
    host_image_profile: ManagedHostImageProfile | None = None,
    retained_oci_source_image_id: str = "",
) -> PilotStandardRtiWorkspace:
    workspace = build_pilot_standard_rti_workspace(
        target,
        engagement_name=engagement_name,
        oci_executable=oci_executable,
        proxy_count=proxy_count,
        template_id=template_id,
        elk_enabled=elk_enabled,
        compute_profile=compute_profile,
        host_image_profile=host_image_profile,
        retained_oci_source_image_id=retained_oci_source_image_id,
    )
    destination.mkdir(parents=True, exist_ok=True)
    for artifact in workspace.artifacts:
        artifact_path = destination / artifact.path
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(artifact.content, encoding="utf-8")
    capability_plan = build_core_capability_role_apply_plan(
        engagement_id=engagement_id,
        engagement_repos_root=engagement_repos_root,
        validate_selected_core_capabilities=bool(engagement_id),
        elk_enabled=workspace.elk_enabled,
    )
    _validate_upstream_oci_role(capability_plan.source.ansible_role_path(OCI_CORE_ROLE_NAME))
    copy_core_capability_roles(destination, capability_plan)
    capability_playbook = destination / CAPABILITY_PLAYBOOK_PATH
    capability_playbook.parent.mkdir(parents=True, exist_ok=True)
    capability_playbook.write_text(render_core_capability_apply_playbook(capability_plan), encoding="utf-8")
    (destination / "ansible" / "capability-plan.json").write_text(
        json.dumps(capability_plan.to_summary(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return workspace


def _validate_upstream_oci_role(role_source: Path) -> None:
    """Reject a source checkout that cannot preserve the verified OCI DNS contract."""
    import yaml

    defaults_path = role_source / "defaults" / "main.yml"
    tasks_path = role_source / "tasks" / "main.yml"
    try:
        defaults = yaml.safe_load(defaults_path.read_text(encoding="utf-8")) or {}
        tasks = yaml.safe_load(tasks_path.read_text(encoding="utf-8")) or []
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError("Redteam-infra OCI resolver role is unreadable") from exc
    dns_servers = defaults.get("dns_servers") if isinstance(defaults, dict) else None
    if not isinstance(dns_servers, list) or tuple(str(value) for value in dns_servers) != OCI_CORE_RESOLV_CONF_DNS_SERVERS:
        raise ValueError("Redteam-infra OCI resolver defaults do not match the pinned resolver contract")
    try:
        for server in dns_servers:
            ip_address(str(server))
    except ValueError as exc:
        raise ValueError("Redteam-infra OCI resolver defaults contain an invalid address") from exc
    if not isinstance(tasks, list) or not all(isinstance(task, dict) for task in tasks):
        raise ValueError("Redteam-infra OCI role does not enforce the required resolver lifecycle")
    if not (
        _oci_role_has_systemd_policy(tasks, "state", "stopped")
        and _oci_role_has_systemd_policy(tasks, "enabled", False)
        and _oci_role_has_systemd_policy(tasks, "masked", True)
        and _oci_role_writes_resolv_conf(tasks)
        and _oci_role_blocks_vcn_resolver(tasks)
        and _oci_role_persists_firewall(tasks)
    ):
        raise ValueError("Redteam-infra OCI role does not enforce the required resolver lifecycle")


def _oci_role_module(task: Mapping[str, object], name: str) -> object | None:
    return task.get(name, task.get(f"ansible.builtin.{name}"))


def _oci_role_has_systemd_policy(tasks: list[Mapping[str, object]], field: str, value: object) -> bool:
    return any(
        isinstance((config := _oci_role_module(task, "systemd")), Mapping)
        and config.get("name") == "systemd-resolved.service"
        and config.get(field) == value
        for task in tasks
    )


def _oci_role_writes_resolv_conf(tasks: list[Mapping[str, object]]) -> bool:
    return any(
        isinstance((config := _oci_role_module(task, "template")), Mapping)
        and config.get("dest") == "/etc/resolv.conf"
        for task in tasks
    )


def _oci_role_blocks_vcn_resolver(tasks: list[Mapping[str, object]]) -> bool:
    for task in tasks:
        config = _oci_role_module(task, "iptables")
        protocols = task.get("with_items", task.get("loop", []))
        if not isinstance(config, Mapping) or not isinstance(protocols, list):
            continue
        if (
            config.get("action") == "insert"
            and config.get("chain") == "OUTPUT"
            and config.get("destination") == "169.254.169.254/32"
            and config.get("protocol") == "{{ item }}"
            and str(config.get("destination_port")) == "53"
            and config.get("jump") == "DROP"
            and config.get("state") == "present"
            and {str(protocol).lower() for protocol in protocols} >= {"tcp", "udp"}
        ):
            return True
    return False


def _oci_role_persists_firewall(tasks: list[Mapping[str, object]]) -> bool:
    for task in tasks:
        command = _oci_role_module(task, "command")
        if isinstance(command, str) and command.strip() == "iptables-save -f /etc/iptables/rules.v4":
            return True
        if isinstance(command, Mapping) and str(command.get("cmd", command.get("_raw_params", ""))).strip() == "iptables-save -f /etc/iptables/rules.v4":
            return True
    return False


def build_pilot_execution_commands(
    workspace: PilotStandardRtiWorkspace,
    *,
    terraform_executable: str = "terraform",
    ansible_executable: str = "ansible",
    ansible_playbook_executable: str = "ansible-playbook",
    ssh_private_key_path: str = "$BARRAGAN_VALIDATION_SSH_PRIVATE_KEY",
    ssh_public_key_path: str = "$BARRAGAN_VALIDATION_SSH_PUBLIC_KEY",
    ssh_source_cidr: str | None = None,
    ssh_source_cidrs: list[str] | None = None,
    known_hosts_path: str = SSH_KNOWN_HOSTS_RELATIVE_PATH,
    inventory_path: str = "ansible/inventory.ini",
    terraform_state_path: str | Path | None = None,
    terraform_data_dir: str | Path | None = None,
    saved_plan_path: str | Path | None = None,
) -> list[list[str]]:
    validate_pilot_target(workspace.target)
    ssh_common_args = _ansible_ssh_common_args(known_hosts_path)
    rendered_ssh_source_cidrs = _terraform_cidr_list(
        ssh_source_cidrs or ([ssh_source_cidr] if ssh_source_cidr else [f"${SSH_SOURCE_CIDRS_ENV}"])
    )
    state_args = [f"-state={terraform_state_path}"] if terraform_state_path else []
    commands = [
        [terraform_executable, "init", "-input=false"],
        (
            [terraform_executable, "apply", "-input=false", "-auto-approve", *state_args, str(saved_plan_path)]
            if saved_plan_path
            else [
                terraform_executable,
                "apply",
                "-input=false",
                "-auto-approve",
                *state_args,
                "-var",
                f"region={workspace.target.region}",
                "-var",
                f"compartment_ocid={workspace.target.compartment_id}",
                "-var",
                f"ssh_public_key_path={ssh_public_key_path}",
                "-var",
                f"ssh_source_cidrs={rendered_ssh_source_cidrs}",
            ]
        ),
        [terraform_executable, "output", "-json", *state_args],
        [
            ansible_executable,
            "pilot_rti",
            "-i",
            inventory_path,
            "-u",
            DEFAULT_SSH_USER,
            "--private-key",
            ssh_private_key_path,
            f"--ssh-common-args={ssh_common_args}",
            "-m",
            "ansible.builtin.wait_for_connection",
            "-a",
            (
                f"timeout={STANDARD_RTI_SSH_READINESS_TIMEOUT_SECONDS} "
                f"sleep={SSH_READINESS_SLEEP_SECONDS} "
                f"connect_timeout={SSH_CONNECT_TIMEOUT_SECONDS}"
            ),
        ],
        [
            ansible_executable,
            "pilot_rti",
            "-i",
            inventory_path,
            "-u",
            DEFAULT_SSH_USER,
            "--private-key",
            ssh_private_key_path,
            f"--ssh-common-args={ssh_common_args}",
            "-m",
            "ping",
        ],
        [
            ansible_playbook_executable,
            "-i",
            inventory_path,
            "ansible/bootstrap_validate.yml",
            "-u",
            DEFAULT_SSH_USER,
            "--private-key",
            ssh_private_key_path,
            f"--ssh-common-args={ssh_common_args}",
        ],
        [
            ansible_playbook_executable,
            "-i",
            inventory_path,
            CAPABILITY_PLAYBOOK_PATH,
            "-u",
            DEFAULT_SSH_USER,
            "--private-key",
            ssh_private_key_path,
            f"--ssh-common-args={ssh_common_args}",
        ],
        [
            terraform_executable,
            "destroy",
            "-input=false",
            "-auto-approve",
            *state_args,
            "-var",
            f"region={workspace.target.region}",
            "-var",
            f"compartment_ocid={workspace.target.compartment_id}",
            "-var",
            f"ssh_public_key_path={ssh_public_key_path}",
            "-var",
            f"ssh_source_cidrs={rendered_ssh_source_cidrs}",
        ],
        *workspace.cleanup["verificationCommands"],
    ]
    if terraform_data_dir:
        commands = [
            ["env", f"TF_DATA_DIR={terraform_data_dir}", *command]
            if command and command[0] == terraform_executable
            else command
            for command in commands
        ]
    return commands


def execute_pilot_standard_rti(
    workspace_dir: Path,
    target: OciDevelopmentTarget | None = None,
    *,
    runner: CommandRunner | None = None,
    preflight_runner: OciReadCommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    ssh_private_key_path: str | None = None,
    ssh_public_key_path: str | None = None,
    ssh_source_cidr: str | None = None,
    ssh_source_cidrs: list[str] | None = None,
    deployment_mode: str = HOLD_FOR_REVIEW,
    engagement_name: str | None = None,
    engagement_id: str | None = None,
    engagement_repos_root: Path = Path("/opt/engagements"),
    terraform_state_path: str | Path | None = None,
    terraform_data_dir: str | Path | None = None,
    proxy_count: int = 2,
    template_id: str | None = None,
    elk_enabled: bool = False,
    compute_profile: OciComputeProfile | None = None,
    progress_callback: ProgressCallback | None = None,
    prepared_plan_path: str | Path | None = None,
) -> PilotStandardRtiExecutionResult:
    resolved_target = target or OciDevelopmentTarget()
    validate_pilot_target(resolved_target)
    terraform_resolution = resolve_terraform(env=env)
    oci_resolution = resolve_oci_cli(env=env)
    ansible_resolution = resolve_ansible(env=env)
    ansible_playbook_resolution = resolve_ansible_playbook(env=env)
    private_key = _path_from_value_or_env(ssh_private_key_path, SSH_PRIVATE_KEY_ENV, env)
    public_key = _path_from_value_or_env(ssh_public_key_path, SSH_PUBLIC_KEY_ENV, env)
    source_cidrs = _cidrs_from_values_or_env(ssh_source_cidrs, ssh_source_cidr, env)
    resolved_deployment_mode = _deployment_mode(deployment_mode)
    workspace = (
        build_pilot_standard_rti_workspace(
            resolved_target,
            engagement_name=engagement_name,
            oci_executable=oci_resolution.command or "oci",
            proxy_count=proxy_count,
            template_id=template_id,
            elk_enabled=elk_enabled,
            compute_profile=compute_profile,
        )
        if prepared_plan_path
        else render_pilot_standard_rti_workspace(
            workspace_dir,
            resolved_target,
            engagement_name=engagement_name,
            engagement_id=engagement_id,
            engagement_repos_root=engagement_repos_root,
            oci_executable=oci_resolution.command or "oci",
            proxy_count=proxy_count,
            template_id=template_id,
            elk_enabled=elk_enabled,
            compute_profile=compute_profile,
        )
    )
    known_hosts_path = workspace_dir / SSH_KNOWN_HOSTS_RELATIVE_PATH
    _ensure_private_known_hosts_directory(known_hosts_path.parent)
    commands_planned = build_pilot_execution_commands(
        workspace,
        terraform_executable=terraform_resolution.command or "terraform",
        ansible_executable=ansible_resolution.command or "ansible",
        ansible_playbook_executable=ansible_playbook_resolution.command or "ansible-playbook",
        ssh_private_key_path=private_key or f"${SSH_PRIVATE_KEY_ENV}",
        ssh_public_key_path=public_key or f"${SSH_PUBLIC_KEY_ENV}",
        ssh_source_cidrs=source_cidrs or [f"${SSH_SOURCE_CIDRS_ENV}"],
        known_hosts_path=str(known_hosts_path),
        terraform_state_path=terraform_state_path,
        terraform_data_dir=terraform_data_dir,
        saved_plan_path=prepared_plan_path,
    )
    command_runner = runner or _run_command
    read_runner = preflight_runner or (lambda command: command_runner(command, None))
    commands_run: list[DisposableCommandResult] = []

    preflight = run_read_validation(resolved_target, runner=read_runner, env=env)
    _emit_progress(
        progress_callback,
        "info" if preflight.ok else "error",
        "OCI read preflight completed",
        {"ok": preflight.ok, "status": "succeeded" if preflight.ok else "failed"},
    )
    if not preflight.ok:
        return _result(
            resolved_target,
            workspace,
            workspace_dir,
            preflight,
            commands_planned,
            commands_run,
            mutation_status="preflight_failed",
            ansible_status="not_started",
            final_cleanup_status="not_started",
        )

    unresolved = _first_unresolved(
        [
            ("terraform_binary_unresolved", terraform_resolution),
            ("ansible_binary_unresolved", ansible_resolution),
            ("ansible_playbook_binary_unresolved", ansible_playbook_resolution),
        ]
    )
    if unresolved is not None:
        status, resolution = unresolved
        commands_run.append(
            DisposableCommandResult.from_error(
                commands_planned[0],
                workspace_dir,
                RuntimeError(resolution.error or "required executable was not resolved"),
            )
        )
        _emit_command_progress(
            progress_callback,
            "terraform_init",
            "Terraform init completed",
            commands_run[-1],
        )
        return _result(
            resolved_target,
            workspace,
            workspace_dir,
            preflight,
            commands_planned,
            commands_run,
            mutation_status=status,
            ansible_status="not_started",
            final_cleanup_status="not_started",
        )

    if private_key is None or public_key is None or not source_cidrs:
        missing = []
        if private_key is None:
            missing.append(SSH_PRIVATE_KEY_ENV)
        if public_key is None:
            missing.append(SSH_PUBLIC_KEY_ENV)
        if not source_cidrs:
            missing.append(SSH_SOURCE_CIDRS_ENV)
        _emit_progress(
            progress_callback,
            "error",
            "SSH validation key configuration unresolved",
            {
                "step": "ssh_validation_configuration",
                "status": "failed",
                "missing": missing,
                "workspaceDir": str(workspace_dir),
            },
        )
        return _result(
            resolved_target,
            workspace,
            workspace_dir,
            preflight,
            commands_planned,
            commands_run,
            mutation_status="ssh_key_unresolved",
            ansible_status="not_started",
            final_cleanup_status="not_started",
        )
    if _unsafe_cidrs(source_cidrs):
        commands_run.append(
            DisposableCommandResult.from_error(
                commands_planned[0],
                workspace_dir,
                RuntimeError(f"{SSH_SOURCE_CIDRS_ENV} must contain valid CIDRs and must not include 0.0.0.0/0"),
            )
        )
        _emit_command_progress(
            progress_callback,
            "terraform_init",
            "Terraform init completed",
            commands_run[-1],
        )
        return _result(
            resolved_target,
            workspace,
            workspace_dir,
            preflight,
            commands_planned,
            commands_run,
            mutation_status="ssh_source_cidr_unsafe",
            ansible_status="not_started",
            final_cleanup_status="not_started",
        )

    terraform_steps = ((1, "apply_failed"),) if prepared_plan_path else ((0, "terraform_init_failed"), (1, "apply_failed"))
    for index, failure_status in terraform_steps:
        command_result = _run_guarded_command(
            commands_planned[index],
            workspace_dir,
            command_runner,
            step="terraform_init" if index == 0 else "terraform_apply",
            progress_callback=progress_callback,
        )
        commands_run.append(command_result)
        _emit_command_progress(
            progress_callback,
            "terraform_init" if index == 0 else "terraform_apply",
            "Terraform init completed" if index == 0 else "Terraform apply completed",
            command_result,
        )
        if not command_result.ok:
            if index == 1:
                return _destroy_and_verify_after_failure(
                    resolved_target,
                    workspace,
                    workspace_dir,
                    preflight,
                    commands_planned,
                    commands_run,
                    command_runner,
                    mutation_status=failure_status,
                    ansible_status="not_started",
                    progress_callback=progress_callback,
                )
            return _result(
                resolved_target,
                workspace,
                workspace_dir,
                preflight,
                commands_planned,
                commands_run,
                mutation_status=failure_status,
                ansible_status="not_started",
                final_cleanup_status="not_started",
            )

    output_result = _run_guarded_command(
        commands_planned[2], workspace_dir, command_runner, step="terraform_output", progress_callback=progress_callback
    )
    commands_run.append(output_result)
    _emit_command_progress(
        progress_callback,
        "terraform_output",
        "Terraform output completed",
        output_result,
    )
    public_ips = _terraform_public_ips(output_result)
    if not output_result.ok or public_ips is None:
        return _destroy_and_verify_after_failure(
            resolved_target,
            workspace,
            workspace_dir,
            preflight,
            commands_planned,
            commands_run,
            command_runner,
            mutation_status="output_failed",
            ansible_status="not_started",
            progress_callback=progress_callback,
        )

    runtime_inventory_path = workspace_dir / "ansible" / "runtime_inventory.ini"
    runtime_inventory_path.write_text(
        _runtime_inventory_ini(
            public_ips,
            names=workspace.names,
            proxy_count=workspace.proxy_count,
            elk_enabled=workspace.elk_enabled,
            ssh_private_key_path=private_key,
            known_hosts_path=str(known_hosts_path),
        ),
        encoding="utf-8",
    )
    ansible_commands = build_pilot_execution_commands(
        workspace,
        terraform_executable=terraform_resolution.command or "terraform",
        ansible_executable=ansible_resolution.command or "ansible",
        ansible_playbook_executable=ansible_playbook_resolution.command or "ansible-playbook",
        ssh_private_key_path=private_key,
        ssh_public_key_path=public_key,
        ssh_source_cidrs=source_cidrs,
        known_hosts_path=str(known_hosts_path),
        inventory_path=str(runtime_inventory_path),
        terraform_state_path=terraform_state_path,
    )
    ansible_step_messages = {
        3: ("ssh_readiness", "SSH readiness validation completed"),
        4: ("ansible_ping", "Ansible ping validation completed"),
        5: ("ansible_bootstrap", "Ansible bootstrap validation completed"),
        6: ("ansible_capabilities", "Ansible selected capabilities apply completed"),
    }
    for index in (3, 4, 5, 6):
        step, message = ansible_step_messages[index]
        ansible_result = _run_guarded_command(
            ansible_commands[index], workspace_dir, command_runner, step=step, progress_callback=progress_callback
        )
        commands_run.append(ansible_result)
        _emit_command_progress(progress_callback, step, message, ansible_result)
        if not ansible_result.ok:
            return _destroy_and_verify_after_failure(
                resolved_target,
                workspace,
                workspace_dir,
                preflight,
                commands_planned,
                commands_run,
                command_runner,
                mutation_status="ansible_failed",
                ansible_status="failed",
                progress_callback=progress_callback,
            )

    if resolved_deployment_mode == HOLD_FOR_REVIEW:
        connection_details = _connection_details(
            public_ips, workspace.names, resolved_target.region,
            proxy_count=workspace.proxy_count, elk_enabled=workspace.elk_enabled,
        )
        channel_rows = pilot_channel_rows(workspace.names, region=resolved_target.region, proxy_count=workspace.proxy_count)
        _emit_progress(
            progress_callback,
            "info",
            "core infrastructure deployed; preparing continuous Inspector",
            {
                "status": "deployed",
                "workspaceDir": str(workspace_dir),
                "connectionDetails": connection_details,
                "outboundChannels": channel_rows["outboundChannels"],
                "inboundChannels": channel_rows["inboundChannels"],
            },
        )
        return _result(
            resolved_target,
            workspace,
            workspace_dir,
            preflight,
            commands_planned,
            commands_run,
            created_resources=_summarize_resources(workspace, "created"),
            mutation_status="deployed",
            ansible_status="validated",
            final_cleanup_status="pending_operator_teardown",
            deployment_mode=resolved_deployment_mode,
            connection_details=connection_details,
            outbound_channels=channel_rows["outboundChannels"],
            inbound_channels=channel_rows["inboundChannels"],
        )

    destroy_result = _run_guarded_command(
        commands_planned[DESTROY_COMMAND_INDEX],
        workspace_dir,
        command_runner,
        step="terraform_destroy",
        progress_callback=progress_callback,
    )
    commands_run.append(destroy_result)
    _emit_command_progress(
        progress_callback,
        "terraform_destroy",
        "Terraform destroy completed",
        destroy_result,
    )
    if not destroy_result.ok:
        return _result(
            resolved_target,
            workspace,
            workspace_dir,
            preflight,
            commands_planned,
            commands_run,
            created_resources=_summarize_resources(workspace, "created"),
            mutation_status="destroy_failed",
            ansible_status="validated",
            final_cleanup_status="cleanup_not_verified",
        )

    cleanup = _verify_cleanup(workspace, command_runner)
    if cleanup.result is not None:
        commands_run.append(cleanup.result)
    _emit_cleanup_progress(progress_callback, cleanup)
    return _result(
        resolved_target,
        workspace,
        workspace_dir,
        preflight,
        commands_planned,
        commands_run,
        created_resources=_summarize_resources(workspace, "created"),
        destroyed_resources=_summarize_resources(workspace, "destroyed"),
        cleanup_verification=cleanup,
        mutation_status="destroyed",
        ansible_status="validated",
        final_cleanup_status="verified_clean" if cleanup.ok else "cleanup_not_verified",
        deployment_mode=resolved_deployment_mode,
        connection_details=_connection_details(
            public_ips, workspace.names, resolved_target.region,
            proxy_count=workspace.proxy_count, elk_enabled=workspace.elk_enabled,
        ),
        outbound_channels=pilot_channel_rows(workspace.names, region=resolved_target.region, proxy_count=workspace.proxy_count)["outboundChannels"],
        inbound_channels=pilot_channel_rows(workspace.names, region=resolved_target.region, proxy_count=workspace.proxy_count)["inboundChannels"],
    )


def execute_pilot_standard_rti_teardown(
    workspace_dir: Path,
    target: OciDevelopmentTarget | None = None,
    *,
    runner: CommandRunner | None = None,
    preflight_runner: OciReadCommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    ssh_public_key_path: str | None = None,
    ssh_source_cidr: str | None = None,
    ssh_source_cidrs: list[str] | None = None,
    engagement_name: str | None = None,
    engagement_id: str | None = None,
    engagement_repos_root: Path = Path("/opt/engagements"),
    terraform_state_path: str | Path | None = None,
    terraform_data_dir: str | Path | None = None,
    proxy_count: int = 2,
    template_id: str | None = None,
    elk_enabled: bool = False,
    compute_profile: OciComputeProfile | None = None,
    host_image_profile: ManagedHostImageProfile | None = None,
    progress_callback: ProgressCallback | None = None,
) -> PilotStandardRtiExecutionResult:
    resolved_target = target or OciDevelopmentTarget()
    validate_pilot_target(resolved_target)
    retained_source_image_id = ""
    state_path = Path(terraform_state_path).expanduser() if terraform_state_path is not None else None
    if state_path is not None and state_path.exists():
        retained_source_image_id = retained_oci_source_image(state_path)
    terraform_resolution = resolve_terraform(env=env)
    oci_resolution = resolve_oci_cli(env=env)
    public_key = _path_from_value_or_env(ssh_public_key_path, SSH_PUBLIC_KEY_ENV, env)
    source_cidrs = _cidrs_from_values_or_env(ssh_source_cidrs, ssh_source_cidr, env)
    workspace = render_pilot_standard_rti_workspace(
        workspace_dir,
        resolved_target,
        engagement_name=engagement_name,
        engagement_id=engagement_id,
        engagement_repos_root=engagement_repos_root,
        oci_executable=oci_resolution.command or "oci",
        proxy_count=proxy_count,
        template_id=template_id,
        elk_enabled=elk_enabled,
        compute_profile=compute_profile,
        host_image_profile=host_image_profile,
        retained_oci_source_image_id=retained_source_image_id,
    )
    commands_planned = build_pilot_execution_commands(
        workspace,
        terraform_executable=terraform_resolution.command or "terraform",
        ssh_public_key_path=public_key or f"${SSH_PUBLIC_KEY_ENV}",
        ssh_source_cidrs=source_cidrs or [f"${SSH_SOURCE_CIDRS_ENV}"],
        terraform_state_path=terraform_state_path,
        terraform_data_dir=terraform_data_dir,
    )
    command_runner = runner or _run_command
    read_runner = preflight_runner or (lambda command: command_runner(command, None))
    commands_run: list[DisposableCommandResult] = []
    preflight = run_read_validation(resolved_target, runner=read_runner, env=env)
    _emit_progress(
        progress_callback,
        "info" if preflight.ok else "error",
        "OCI read preflight completed",
        {"ok": preflight.ok, "status": "succeeded" if preflight.ok else "failed"},
    )
    if not preflight.ok:
        return _result(
            resolved_target,
            workspace,
            workspace_dir,
            preflight,
            commands_planned,
            commands_run,
            mutation_status="preflight_failed",
            ansible_status="not_started",
            final_cleanup_status="cleanup_not_verified",
            deployment_mode=DESTROY_AFTER_VALIDATION,
        )
    if not terraform_resolution.ok:
        commands_run.append(
            DisposableCommandResult.from_error(
                commands_planned[DESTROY_COMMAND_INDEX],
                workspace_dir,
                RuntimeError(terraform_resolution.error or "terraform executable was not resolved"),
            )
        )
        return _result(
            resolved_target,
            workspace,
            workspace_dir,
            preflight,
            commands_planned,
            commands_run,
            mutation_status="terraform_binary_unresolved",
            ansible_status="not_started",
            final_cleanup_status="cleanup_not_verified",
            deployment_mode=DESTROY_AFTER_VALIDATION,
        )

    init_result = _run_guarded_command(
        commands_planned[0], workspace_dir, command_runner, step="terraform_init", progress_callback=progress_callback
    )
    commands_run.append(init_result)
    _emit_command_progress(
        progress_callback,
        "terraform_init",
        "Terraform workspace initialized",
        init_result,
    )
    if not init_result.ok:
        return _result(
            resolved_target,
            workspace,
            workspace_dir,
            preflight,
            commands_planned,
            commands_run,
            mutation_status="terraform_init_failed",
            ansible_status="not_started",
            final_cleanup_status="cleanup_not_verified",
            deployment_mode=DESTROY_AFTER_VALIDATION,
        )

    destroy_result = _run_guarded_command(
        commands_planned[DESTROY_COMMAND_INDEX],
        workspace_dir,
        command_runner,
        step="terraform_destroy",
        progress_callback=progress_callback,
    )
    commands_run.append(destroy_result)
    _emit_command_progress(
        progress_callback,
        "terraform_destroy",
        "Terraform destroy completed",
        destroy_result,
    )
    cleanup = None
    if destroy_result.ok:
        cleanup = _verify_cleanup(workspace, command_runner)
        if cleanup.result is not None:
            commands_run.append(cleanup.result)
        _emit_cleanup_progress(progress_callback, cleanup)
    return _result(
        resolved_target,
        workspace,
        workspace_dir,
        preflight,
        commands_planned,
        commands_run,
        destroyed_resources=_summarize_resources(workspace, "destroyed") if destroy_result.ok else [],
        cleanup_verification=cleanup,
        mutation_status="destroyed" if destroy_result.ok else "destroy_failed",
        ansible_status="validated" if destroy_result.ok else "not_started",
        final_cleanup_status="verified_clean" if cleanup is not None and cleanup.ok else "cleanup_not_verified",
        deployment_mode=DESTROY_AFTER_VALIDATION,
    )


def validate_pilot_target(target: OciDevelopmentTarget) -> None:
    target.validate()
    if target.region != DEFAULT_REGION:
        raise OciSafetyError(f"Pilot Standard RTI validation must target only {DEFAULT_REGION}")


def _cleanup_commands(
    target: OciDevelopmentTarget,
    names: PilotStandardRtiNames,
    oci_executable: str,
    *,
    proxy_count: int = 2,
    elk_enabled: bool = False,
) -> list[list[str]]:
    base = [oci_executable, "--auth", target.auth, "--region", target.region]
    scope = ["--compartment-id", target.compartment_id, "--output", "json"]
    return [
        [*base, "compute", "instance", "list", *scope, "--display-name", names.homebase_name],
        *[
            [*base, "compute", "instance", "list", *scope, "--display-name", proxy["display_name"]]
            for proxy in _proxy_specs(names, proxy_count)
        ],
        *([[*base, "compute", "instance", "list", *scope, "--display-name", names.elk_name]] if elk_enabled else []),
        [*base, "network", "subnet", "list", *scope, "--display-name", names.homebase_subnet_name],
        [*base, "network", "subnet", "list", *scope, "--display-name", names.proxy_subnet_name],
        *([[*base, "network", "subnet", "list", *scope, "--display-name", names.utility_subnet_name]] if elk_enabled else []),
        [*base, "network", "internet-gateway", "list", *scope, "--display-name", names.internet_gateway_name],
        [*base, "network", "route-table", "list", *scope, "--display-name", names.route_table_name],
        *([[*base, "network", "route-table", "list", *scope, "--display-name", names.utility_route_table_name]] if elk_enabled else []),
        *([[*base, "network", "nat-gateway", "list", *scope, "--display-name", names.nat_gateway_name]] if elk_enabled else []),
        [*base, "network", "security-list", "list", *scope, "--display-name", names.security_list_name],
        [*base, "network", "security-list", "list", *scope, "--display-name", f"{names.security_list_name}-proxy-ingress"],
        [*base, "network", "security-list", "list", *scope, "--display-name", f"{names.security_list_name}-homebase-nfs"],
        [*base, "network", "vcn", "list", *scope, "--display-name", names.vcn_name],
    ]


def _resource(
    resource_type: str,
    name: str,
    display_name: str,
    target: OciDevelopmentTarget,
) -> dict[str, Any]:
    return {
        "provider": "oci",
        "type": resource_type,
        "name": name,
        "displayName": display_name,
        "compartmentId": target.compartment_id,
        "region": target.region,
        "expectedLifecycle": "create with terraform apply; remove with terraform destroy",
    }


def _target_dict(target: OciDevelopmentTarget, mutation: bool = False) -> dict[str, Any]:
    return {
        "name": target.name,
        "compartmentId": target.compartment_id,
        "region": target.region,
        "auth": target.auth,
        "mutation": mutation,
    }


def _versions_tf() -> str:
    return """terraform {
  required_version = ">= 1.6.0"

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 6.0.0"
    }
  }
}
"""


def _variables_tf(
    target: OciDevelopmentTarget,
    host_image_profile: ManagedHostImageProfile | None = None,
    retained_oci_source_image_id: str = "",
) -> str:
    if host_image_profile is not None:
        ubuntu_version = host_image_profile.ubuntu_version
    elif retained_oci_source_image_id:
        # Retained image identity disables the image query during teardown.
        ubuntu_version = ""
    else:
        ubuntu_version = managed_host_image_profile().ubuntu_version
    return f"""variable "region" {{
  type        = string
  description = "OCI region for the guarded Standard RTI pilot."

  validation {{
    condition     = var.region == "{DEFAULT_REGION}"
    error_message = "Pilot Standard RTI validation must target only {DEFAULT_REGION}."
  }}
}}

variable "compartment_ocid" {{
  type        = string
  description = "The pinned {target.name} compartment OCID. Do not point this workspace elsewhere."

  validation {{
    condition     = var.compartment_ocid == "{target.compartment_id}"
    error_message = "Pilot Standard RTI validation must target only the pinned {target.name} compartment."
  }}
}}

variable "ssh_public_key_path" {{
  type        = string
  description = "Path to a public SSH key used only for the disposable pilot nodes."
}}

variable "ssh_source_cidrs" {{
  type        = set(string)
  description = "Trusted source CIDRs allowed to reach SSH on pilot nodes."

  validation {{
    condition     = length(var.ssh_source_cidrs) > 0 && alltrue([for cidr in var.ssh_source_cidrs : cidr != "0.0.0.0/0" && can(cidrnetmask(cidr))])
    error_message = "Pilot Standard RTI validation requires valid non-public SSH source CIDRs."
  }}
}}

variable "homebase_shape" {{ type = string }}
variable "homebase_ocpus" {{ type = number }}
variable "homebase_memory_in_gbs" {{ type = number }}
variable "proxy_shape" {{ type = string }}
variable "proxy_ocpus" {{ type = number }}
variable "proxy_memory_in_gbs" {{ type = number }}
variable "elk_shape" {{ type = string }}
variable "elk_ocpus" {{ type = number }}
variable "elk_memory_in_gbs" {{ type = number }}
variable "boot_volume_size_in_gbs" {{
  type = number
  validation {{
    condition     = var.boot_volume_size_in_gbs >= 50
    error_message = "OCI boot volumes must be at least 50 GiB."
  }}
}}

variable "ubuntu_version" {{
  type        = string
  default     = "{ubuntu_version}"
  description = "Ubuntu version selected from OCI image metadata."
}}

variable "oci_source_image_id" {{
  type        = string
  default     = {json.dumps(retained_oci_source_image_id)}
  description = "Exact retained OCI image OCID; empty only for first provisioning."
}}
"""


def _oci_core_instance_agent_config_tf() -> str:
    policy = OCI_CORE_INSTANCE_AGENT_POLICY
    plugin = policy["plugins_config"]
    return f'''  agent_config {{
    are_all_plugins_disabled = {json.dumps(policy["are_all_plugins_disabled"])}
    is_monitoring_disabled   = {json.dumps(policy["is_monitoring_disabled"])}
    plugins_config {{
      name          = {json.dumps(plugin["name"])}
      desired_state = {json.dumps(plugin["desired_state"])}
    }}
  }}'''


def _main_tf(
    names: PilotStandardRtiNames, profile: OciComputeProfile, *, proxy_count: int = 2, elk_enabled: bool = False
) -> str:
    _validate_proxy_count(proxy_count)
    homebase_shape_config = _shape_config_tf("homebase", profile.homebase.is_flex)
    proxy_shape_config = _shape_config_tf("proxy", profile.proxy.is_flex)
    elk_shape_config = _shape_config_tf("elk", profile.elk.is_flex)
    agent_config = _oci_core_instance_agent_config_tf()
    proxy02_resource = ""
    proxy02_public_output = ""
    proxy02_private_output = ""
    if proxy_count == 2:
        proxy02_resource = f"""

resource "oci_core_instance" "proxy02" {{
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  compartment_id      = var.compartment_ocid
  display_name        = "{names.proxy02_name}"
  shape               = var.proxy_shape
  freeform_tags       = merge(local.barragan_tags, {{ barragan_role = "proxy02" }})

{proxy_shape_config}

  instance_options {{
    are_legacy_imds_endpoints_disabled = true
  }}

{agent_config}

  create_vnic_details {{
    subnet_id        = oci_core_subnet.proxy.id
    assign_public_ip = true
    private_ip       = "{PILOT_PROXY02_PRIVATE_IP}"
    display_name     = "{names.proxy02_name}-vnic"
    skip_source_dest_check = {json.dumps(OCI_CORE_PROXY_SKIP_SOURCE_DEST_CHECK)}
  }}

  metadata = {{
    ssh_authorized_keys = file(var.ssh_public_key_path)
  }}

  source_details {{
    source_type             = "image"
    source_id               = local.ubuntu_source_image_id
    boot_volume_size_in_gbs = var.boot_volume_size_in_gbs
  }}
}}
"""
        proxy02_public_output = "\n    proxy02  = oci_core_instance.proxy02.public_ip"
        proxy02_private_output = f'\n    proxy02  = "{PILOT_PROXY02_PRIVATE_IP}"'
    elk_subnet = f'''\nresource "oci_core_nat_gateway" "utility" {{
  compartment_id = var.compartment_ocid
  display_name   = "{names.nat_gateway_name}"
  vcn_id         = oci_core_vcn.pilot.id
  freeform_tags  = merge(local.barragan_tags, {{ barragan_role = "utility_nat_gateway" }})
}}

resource "oci_core_route_table" "utility" {{
  compartment_id = var.compartment_ocid
  display_name   = "{names.utility_route_table_name}"
  vcn_id         = oci_core_vcn.pilot.id
  freeform_tags  = merge(local.barragan_tags, {{ barragan_role = "utility_route_table" }})

  route_rules {{
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_nat_gateway.utility.id
  }}
}}

resource "oci_core_subnet" "utility" {{
  compartment_id             = var.compartment_ocid
  display_name               = "{names.utility_subnet_name}"
  vcn_id                     = oci_core_vcn.pilot.id
  cidr_block                 = "{PILOT_UTILITY_CIDR}"
  prohibit_public_ip_on_vnic = true
  route_table_id             = oci_core_route_table.utility.id
  security_list_ids          = [oci_core_security_list.ssh_only.id]
  freeform_tags              = merge(local.barragan_tags, {{ barragan_role = "utility_subnet" }})
}}
''' if elk_enabled else ""
    elk_resource = f'''\nresource "oci_core_instance" "elk" {{
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  compartment_id      = var.compartment_ocid
  display_name        = "{names.elk_name}"
  shape               = var.elk_shape
  freeform_tags       = merge(local.barragan_tags, {{ barragan_role = "elk" }})

{elk_shape_config}
  instance_options {{ are_legacy_imds_endpoints_disabled = true }}
{agent_config}
  create_vnic_details {{
    subnet_id        = oci_core_subnet.utility.id
    assign_public_ip = false
    private_ip       = "{PILOT_ELK_PRIVATE_IP}"
    display_name     = "{names.elk_name}-vnic"
  }}
  metadata = {{ ssh_authorized_keys = file(var.ssh_public_key_path) }}
  source_details {{
    source_type             = "image"
    source_id               = local.ubuntu_source_image_id
    boot_volume_size_in_gbs = var.boot_volume_size_in_gbs
  }}
}}
''' if elk_enabled else ""
    elk_private_output = f'\n    elk      = "{PILOT_ELK_PRIVATE_IP}"' if elk_enabled else ""
    elk_resource_outputs = '''

output "utility_network" {
  value = {
    subnet_id       = oci_core_subnet.utility.id
    route_table_id  = oci_core_route_table.utility.id
    nat_gateway_id  = oci_core_nat_gateway.utility.id
    elk_instance_id = oci_core_instance.elk.id
  }
}
''' if elk_enabled else ""
    return f"""provider "oci" {{
  region = var.region
  auth   = "InstancePrincipal"
}}

data "oci_identity_availability_domains" "ads" {{
  compartment_id = var.compartment_ocid
}}

data "oci_core_images" "ubuntu" {{
  count                    = var.oci_source_image_id == "" ? 1 : 0
  compartment_id           = var.compartment_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = var.ubuntu_version

  filter {{
    name   = "display_name"
    values = ["^Canonical-Ubuntu-${{var.ubuntu_version}}-([.0-9-]+)$"]
    regex  = true
  }}
}}

locals {{
  ubuntu_source_image_id = var.oci_source_image_id != "" ? var.oci_source_image_id : data.oci_core_images.ubuntu[0].images[0].id
  barragan_tags = {{
    barragan             = "true"
    barragan_engagement  = "{names.engagement_name}"
    barragan_environment = "barragan-testing"
    barragan_provider    = "oci"
  }}
}}

resource "oci_core_vcn" "pilot" {{
  compartment_id = var.compartment_ocid
  display_name   = "{names.vcn_name}"
  cidr_block     = "{PILOT_CIDR}"
  dns_label      = "{names.dns_label}"
  freeform_tags  = merge(local.barragan_tags, {{ barragan_role = "vcn" }})
}}

resource "oci_core_default_dhcp_options" "pilot" {{
  manage_default_resource_id = oci_core_vcn.pilot.default_dhcp_options_id
  freeform_tags              = merge(local.barragan_tags, {{ barragan_role = "default_dhcp_options" }})

  options {{
    type               = "DomainNameServer"
    server_type        = "CustomDnsServer"
    custom_dns_servers = {json.dumps(list(OCI_CORE_DHCP_DNS_SERVERS))}
  }}
}}

resource "oci_core_internet_gateway" "pilot" {{
  compartment_id = var.compartment_ocid
  display_name   = "{names.internet_gateway_name}"
  vcn_id         = oci_core_vcn.pilot.id
  enabled        = true
  freeform_tags  = merge(local.barragan_tags, {{ barragan_role = "internet_gateway" }})
}}

resource "oci_core_route_table" "pilot" {{
  compartment_id = var.compartment_ocid
  display_name   = "{names.route_table_name}"
  vcn_id         = oci_core_vcn.pilot.id
  freeform_tags  = merge(local.barragan_tags, {{ barragan_role = "route_table" }})

  route_rules {{
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.pilot.id
  }}
}}

resource "oci_core_security_list" "ssh_only" {{
  compartment_id = var.compartment_ocid
  display_name   = "{names.security_list_name}"
  vcn_id         = oci_core_vcn.pilot.id
  freeform_tags  = merge(local.barragan_tags, {{ barragan_role = "core_security_list" }})

  egress_security_rules {{
    protocol    = "all"
    destination = "0.0.0.0/0"
  }}

  ingress_security_rules {{
    protocol = "6"
    source   = "{PILOT_CIDR}"
  }}

  ingress_security_rules {{
    protocol = "17"
    source   = "{PILOT_CIDR}"
  }}

  dynamic "ingress_security_rules" {{
    for_each = var.ssh_source_cidrs

    content {{
      protocol = "6"
      source   = ingress_security_rules.value

      tcp_options {{
        min = 22
        max = 22
      }}
    }}
  }}
}}

resource "oci_core_security_list" "proxy_ingress" {{
  compartment_id = var.compartment_ocid
  display_name   = "{names.security_list_name}-proxy-ingress"
  vcn_id         = oci_core_vcn.pilot.id
  freeform_tags  = merge(local.barragan_tags, {{ barragan_role = "proxy_ingress_security_list" }})

  ingress_security_rules {{
    protocol = "6"
    source   = "0.0.0.0/0"

    tcp_options {{
      min = 80
      max = 80
    }}
  }}

  ingress_security_rules {{
    protocol = "6"
    source   = "0.0.0.0/0"

    tcp_options {{
      min = 443
      max = 443
    }}
  }}

  ingress_security_rules {{
    protocol = "6"
    source   = "0.0.0.0/0"

    tcp_options {{
      min = 2222
      max = 2222
    }}
  }}

  ingress_security_rules {{
    protocol = "6"
    source   = "0.0.0.0/0"

    tcp_options {{
      min = 8000
      max = 8080
    }}
  }}

  ingress_security_rules {{
    protocol = "17"
    source   = "0.0.0.0/0"

    udp_options {{
      min = 8000
      max = 8080
    }}
  }}
}}

resource "oci_core_security_list" "homebase_nfs" {{
  compartment_id = var.compartment_ocid
  display_name   = "{names.security_list_name}-homebase-nfs"
  vcn_id         = oci_core_vcn.pilot.id
  freeform_tags  = merge(local.barragan_tags, {{ barragan_role = "homebase_nfs_security_list" }})

  ingress_security_rules {{
    protocol = "6"
    source   = "{PILOT_PROXY_CIDR}"

    tcp_options {{
      min = 111
      max = 111
    }}
  }}

  ingress_security_rules {{
    protocol = "6"
    source   = "{PILOT_PROXY_CIDR}"

    tcp_options {{
      min = 2049
      max = 2049
    }}
  }}

  ingress_security_rules {{
    protocol = "17"
    source   = "{PILOT_PROXY_CIDR}"

    udp_options {{
      min = 111
      max = 111
    }}
  }}

  ingress_security_rules {{
    protocol = "17"
    source   = "{PILOT_PROXY_CIDR}"

    udp_options {{
      min = 2049
      max = 2049
    }}
  }}
}}

resource "oci_core_subnet" "homebase" {{
  compartment_id             = var.compartment_ocid
  display_name               = "{names.homebase_subnet_name}"
  vcn_id                     = oci_core_vcn.pilot.id
  cidr_block                 = "{PILOT_HOMEBASE_CIDR}"
  prohibit_public_ip_on_vnic = false
  route_table_id             = oci_core_route_table.pilot.id
  security_list_ids          = [oci_core_security_list.ssh_only.id, oci_core_security_list.homebase_nfs.id]
  freeform_tags              = merge(local.barragan_tags, {{ barragan_role = "homebase_subnet" }})
}}

resource "oci_core_subnet" "proxy" {{
  compartment_id             = var.compartment_ocid
  display_name               = "{names.proxy_subnet_name}"
  vcn_id                     = oci_core_vcn.pilot.id
  cidr_block                 = "{PILOT_PROXY_CIDR}"
  prohibit_public_ip_on_vnic = false
  route_table_id             = oci_core_route_table.pilot.id
  security_list_ids          = [oci_core_security_list.ssh_only.id, oci_core_security_list.proxy_ingress.id]
  freeform_tags              = merge(local.barragan_tags, {{ barragan_role = "proxy_subnet" }})
}}
{elk_subnet}

resource "oci_core_instance" "homebase" {{
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  compartment_id      = var.compartment_ocid
  display_name        = "{names.homebase_name}"
  shape               = var.homebase_shape
  freeform_tags       = merge(local.barragan_tags, {{ barragan_role = "homebase" }})

{homebase_shape_config}

  instance_options {{
    are_legacy_imds_endpoints_disabled = true
  }}

{agent_config}

  create_vnic_details {{
    subnet_id        = oci_core_subnet.homebase.id
    assign_public_ip = true
    private_ip       = "{PILOT_HOMEBASE_PRIVATE_IP}"
    display_name     = "{names.homebase_name}-vnic"
  }}

  metadata = {{
    ssh_authorized_keys = file(var.ssh_public_key_path)
  }}

  source_details {{
    source_type             = "image"
    source_id               = local.ubuntu_source_image_id
    boot_volume_size_in_gbs = var.boot_volume_size_in_gbs
  }}
}}

resource "oci_core_instance" "proxy01" {{
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  compartment_id      = var.compartment_ocid
  display_name        = "{names.proxy_name}"
  shape               = var.proxy_shape
  freeform_tags       = merge(local.barragan_tags, {{ barragan_role = "proxy01" }})

{proxy_shape_config}

  instance_options {{
    are_legacy_imds_endpoints_disabled = true
  }}

{agent_config}

  create_vnic_details {{
    subnet_id        = oci_core_subnet.proxy.id
    assign_public_ip = true
    private_ip       = "{PILOT_PROXY_PRIVATE_IP}"
    display_name     = "{names.proxy_name}-vnic"
    skip_source_dest_check = {json.dumps(OCI_CORE_PROXY_SKIP_SOURCE_DEST_CHECK)}
  }}

  metadata = {{
    ssh_authorized_keys = file(var.ssh_public_key_path)
  }}

  source_details {{
    source_type             = "image"
    source_id               = local.ubuntu_source_image_id
    boot_volume_size_in_gbs = var.boot_volume_size_in_gbs
  }}
}}

{proxy02_resource}
{elk_resource}

output "public_ips" {{
  value = {{
    homebase = oci_core_instance.homebase.public_ip
    proxy01  = oci_core_instance.proxy01.public_ip{proxy02_public_output}
  }}
}}

output "private_ips" {{
  value = {{
    homebase = "{PILOT_HOMEBASE_PRIVATE_IP}"
    proxy01  = "{PILOT_PROXY_PRIVATE_IP}"{proxy02_private_output}{elk_private_output}
  }}
}}
{elk_resource_outputs}
"""


def _tfvars_json(target: OciDevelopmentTarget, profile: OciComputeProfile) -> str:
    values = {
        "region": target.region,
        "compartment_ocid": target.compartment_id,
        "homebase_shape": profile.homebase.shape,
        "homebase_ocpus": profile.homebase.ocpus,
        "homebase_memory_in_gbs": profile.homebase.memory_in_gbs,
        "proxy_shape": profile.proxy.shape,
        "proxy_ocpus": profile.proxy.ocpus,
        "proxy_memory_in_gbs": profile.proxy.memory_in_gbs,
        "elk_shape": profile.elk.shape,
        "elk_ocpus": profile.elk.ocpus,
        "elk_memory_in_gbs": profile.elk.memory_in_gbs,
        "boot_volume_size_in_gbs": profile.boot_volume_size_in_gbs,
    }
    return json.dumps(values, indent=2, sort_keys=True) + "\n"


def _shape_config_tf(role: str, enabled: bool) -> str:
    if not enabled:
        return ""
    return f"""  shape_config {{
    ocpus         = var.{role}_ocpus
    memory_in_gbs = var.{role}_memory_in_gbs
  }}"""


def _inventory_ini(*, proxy_count: int = 2, elk_enabled: bool = False) -> str:
    proxy_lines = "\n".join(
        f"{proxy['id']} ansible_host=0.0.0.0 ansible_user={DEFAULT_SSH_USER} rti_role=proxy private_ip={proxy['private_ip']}"
        for proxy in _proxy_specs(pilot_names(), proxy_count)
    )
    elk_group = f"\n[elk]\nelk ansible_host={PILOT_ELK_PRIVATE_IP} ansible_user={DEFAULT_SSH_USER} rti_role=elk private_ip={PILOT_ELK_PRIVATE_IP}\n" if elk_enabled else ""
    return f"""[homebase]
homebase ansible_host=0.0.0.0 ansible_user={DEFAULT_SSH_USER} rti_role=homebase private_ip={PILOT_HOMEBASE_PRIVATE_IP}

[proxies]
{proxy_lines}
{elk_group}

[pilot_rti:children]
homebase
proxies
{"elk" if elk_enabled else ""}
"""


def _runtime_inventory_ini(
    public_ips: dict[str, str],
    *,
    names: PilotStandardRtiNames | None = None,
    proxy_count: int = 2,
    elk_enabled: bool = False,
    ssh_private_key_path: str = "$BARRAGAN_VALIDATION_SSH_PRIVATE_KEY",
    known_hosts_path: str = "/dev/null",
) -> str:
    resolved_names = names or pilot_names()
    proxy_lines = "\n".join(
        f"{proxy['id']} ansible_host={public_ips[proxy['id']]} ansible_user={DEFAULT_SSH_USER} rti_role=proxy private_ip={proxy['private_ip']} barragan_expected_hostname={proxy['display_name']}"
        for proxy in _proxy_specs(resolved_names, proxy_count)
    )
    proxy_command = " ".join(
        (
            "ssh",
            "-i",
            ssh_private_key_path,
            f"-o UserKnownHostsFile={known_hosts_path}",
            "-o StrictHostKeyChecking=accept-new",
            "-o IdentitiesOnly=yes",
            "-o BatchMode=yes",
            f"-o ConnectTimeout={SSH_CONNECT_TIMEOUT_SECONDS}",
            "-W %h:%p",
            f"{DEFAULT_SSH_USER}@{public_ips['homebase']}",
        )
    )
    elk_ssh_args = " ".join(
        (
            f"-o UserKnownHostsFile={known_hosts_path}",
            "-o StrictHostKeyChecking=accept-new",
            "-o IdentitiesOnly=yes",
            "-o BatchMode=yes",
            f"-o ConnectTimeout={SSH_CONNECT_TIMEOUT_SECONDS}",
            f"-o ProxyCommand='{proxy_command}'",
        )
    )
    elk_group = (
        f"\n[elk]\nelk ansible_host={PILOT_ELK_PRIVATE_IP} ansible_user={DEFAULT_SSH_USER} "
        f"ansible_ssh_private_key_file={ssh_private_key_path} "
        f"rti_role=elk private_ip={PILOT_ELK_PRIVATE_IP} barragan_expected_hostname=elk "
        f"ansible_ssh_common_args={json.dumps(elk_ssh_args)}\n"
        if elk_enabled else ""
    )
    return f"""[homebase]
homebase ansible_host={public_ips["homebase"]} ansible_user={DEFAULT_SSH_USER} rti_role=homebase private_ip={PILOT_HOMEBASE_PRIVATE_IP} barragan_expected_hostname={resolved_names.homebase_name}

[proxies]
{proxy_lines}
{elk_group}

[pilot_rti:children]
homebase
proxies
{"elk" if elk_enabled else ""}
"""


def _connection_details(
    public_ips: dict[str, str], names: PilotStandardRtiNames, region: str, *, proxy_count: int = 2, elk_enabled: bool = False
) -> list[dict[str, Any]]:
    return [
        {
            "role": "homebase",
            "displayName": names.homebase_name,
            "sshAlias": names.homebase_name,
            "publicIp": public_ips["homebase"],
            "privateIp": PILOT_HOMEBASE_PRIVATE_IP,
            "region": region,
            "sshUser": CORE_MANAGEMENT_SSH_USER,
            "sshCommand": f"ssh {names.homebase_name}",
            "services": ["SSH", "RTI base layout", "engagement workspace", "proxy config banks", "dropbox NFS export"],
        },
        *[
            {
                "role": "proxy",
                "displayName": proxy["display_name"],
                "sshAlias": proxy["display_name"],
                "publicIp": public_ips[proxy["id"]],
                "privateIp": proxy["private_ip"],
                "region": region,
                "sshUser": CORE_MANAGEMENT_SSH_USER,
                "sshCommand": f"ssh {proxy['display_name']}",
                "services": ["SSH", "RTI base layout", "dropbox NFS mount", "nmap"],
            }
            for proxy in _proxy_specs(names, proxy_count)
        ],
        *([{
            "role": "elk",
            "displayName": names.elk_name,
            "sshAlias": names.elk_name,
            "publicIp": None,
            "privateIp": PILOT_ELK_PRIVATE_IP,
            "region": region,
            "sshUser": CORE_MANAGEMENT_SSH_USER,
            "sshCommand": f"ssh -J {names.homebase_name} {DEFAULT_SSH_USER}@{PILOT_ELK_PRIVATE_IP}",
            "managementPath": f"{names.homebase_name} -> {names.elk_name}",
            "services": ["Private SSH", "ELK"],
        }] if elk_enabled else []),
    ]


def _pilot_core_hosts_content(
    names: PilotStandardRtiNames, *, proxy_count: int = 2, elk_enabled: bool = False
) -> str:
    core_hosts = [
        CoreHost("homebase", PILOT_HOMEBASE_PRIVATE_IP),
        *[
            CoreHost(proxy["id"], proxy["private_ip"])
            for proxy in _proxy_specs(names, proxy_count)
        ],
    ]
    if proxy_count == 2:
        rendered = render_core_hosts_content(names.engagement_name, core_hosts)
        if elk_enabled:
            rendered += f"{PILOT_ELK_PRIVATE_IP} {names.elk_name}.infra.redteam {names.elk_name} elk\n"
        return rendered
    lines = [
        "# Managed by Barragan outbound channel artifacts.",
        "# Core node name resolution only; do not install on sketch nodes.",
    ]
    for host in core_hosts:
        engagement_qualified_name = f"{host.name}-{names.engagement_name}"
        lines.append(f"{host.private_ip} {engagement_qualified_name}.infra.redteam {engagement_qualified_name} {host.name}")
    if elk_enabled:
        lines.append(f"{PILOT_ELK_PRIVATE_IP} {names.elk_name}.infra.redteam {names.elk_name} elk")
    return "\n".join(lines) + "\n"


def _indent_text(text: str, spaces: int) -> str:
    prefix = " " * spaces
    return "\n".join(f"{prefix}{line}" if line else line for line in text.splitlines())


def _validation_playbook(
    names: PilotStandardRtiNames | None = None, *, proxy_count: int = 2, elk_enabled: bool = False
) -> str:
    resolved_names = names or pilot_names()
    proxy_banks = _proxy_specs(resolved_names, proxy_count)
    core_hosts_block = _indent_text(
        _pilot_core_hosts_content(resolved_names, proxy_count=proxy_count, elk_enabled=elk_enabled).rstrip(), 6
    )
    proxy_bank_block = _indent_text(
        "\n".join(
            [
                f"- name: {proxy['id']}\n"
                f"  path: /opt/{proxy['id']}\n"
                f"  proxy_private_ip: {proxy['private_ip']}"
                for proxy in proxy_banks
            ]
        ),
        6,
    )
    oci_agent_unit_block = _indent_text(
        "\n".join(f'- "{unit}"' for unit in OCI_CORE_DISABLED_AGENT_UNITS), 6
    )
    required_homebase_paths = ["engagement_path", "engagement_path + '/loot'"] + [f"'/opt/{proxy['id']}'" for proxy in proxy_banks]
    required_homebase_paths_expr = "[" + ", ".join(required_homebase_paths) + "]"
    return f"""---
- name: Barragan pilot Standard RTI base host configuration
  hosts: pilot_rti
  become: true
  gather_facts: true
  vars:
    core_management_user: "{CORE_MANAGEMENT_SSH_USER}"
    engagement_path: "{ENGAGEMENT_PATH}"
    core_hosts_block: |
{core_hosts_block}
    homebase_required_paths: "{{{{ {required_homebase_paths_expr} }}}}"
    homebase_proxy_config_banks:
{proxy_bank_block}
    oracle_cloud_agent_units:
{oci_agent_unit_block}
    oracle_cloud_agent_process_pattern: {json.dumps(OCI_CORE_AGENT_PROCESS_PATTERN)}
""" + """
  tasks:
    - name: Verify pilot SSH transport
      ansible.builtin.ping:

    - name: Read target hostname before Barragan configuration
      ansible.builtin.command: hostname --short
      register: barragan_core_hostname
      changed_when: false

    - name: Assert target belongs to the selected core deployment
      ansible.builtin.assert:
        that:
          - (barragan_core_hostname.stdout | trim) == barragan_expected_hostname
        fail_msg: >-
          Core connection identity mismatch: expected {{ barragan_expected_hostname }},
          observed {{ barragan_core_hostname.stdout | trim }}. No configuration was applied.

    - name: Install managed core host resolution
      ansible.builtin.blockinfile:
        path: /etc/hosts
        marker: "# {mark} BARRAGAN MANAGED CORE HOSTS"
        block: "{{ core_hosts_block }}"
        create: true
        owner: root
        group: root
        mode: "0644"

    - name: Ensure redteam group exists
      ansible.builtin.group:
        name: redteam
        state: present

    - name: Create Barragan core management user
      ansible.builtin.user:
        name: "{{ core_management_user }}"
        groups:
          - sudo
          - redteam
        append: true
        shell: /bin/bash
        create_home: true
        state: present

    - name: Ensure Barragan core management SSH directory exists
      ansible.builtin.file:
        path: "/home/{{ core_management_user }}/.ssh"
        state: directory
        owner: "{{ core_management_user }}"
        group: "{{ core_management_user }}"
        mode: "0700"

    - name: Install deployment key for Barragan core management user
      ansible.builtin.copy:
        src: "/home/{{ ansible_user }}/.ssh/authorized_keys"
        dest: "/home/{{ core_management_user }}/.ssh/authorized_keys"
        owner: "{{ core_management_user }}"
        group: "{{ core_management_user }}"
        mode: "0600"
        remote_src: true

    - name: Allow Barragan core management user to run sudo non-interactively
      ansible.builtin.copy:
        dest: "/etc/sudoers.d/90-barragan-core-management"
        owner: root
        group: root
        mode: "0440"
        content: |
          {{ core_management_user }} ALL=(ALL) NOPASSWD:ALL

    - name: Create homebase engagement workspace directories
      ansible.builtin.file:
        path: "{{ item }}"
        state: directory
        owner: root
        group: redteam
        mode: "0775"
      loop: "{{ homebase_required_paths }}"
      when: rti_role == "homebase"

    - name: Wait for first-boot package activity to finish
      ansible.builtin.command: cloud-init status --wait
      changed_when: false
      failed_when: false

    - name: Disable Oracle Cloud Agent framework services
      ansible.builtin.command:
        argv:
          - systemctl
          - disable
          - --now
          - "{{ item }}"
      loop: "{{ oracle_cloud_agent_units }}"

    - name: Assert Oracle Cloud Agent framework and plugins stopped
      ansible.builtin.command:
        argv:
          - pgrep
          - --full
          - --list-full
          - "{{ oracle_cloud_agent_process_pattern }}"
      register: oracle_cloud_agent_processes
      changed_when: false
      failed_when: oracle_cloud_agent_processes.rc != 1

    - name: Wait for apt and dpkg locks to clear
      ansible.builtin.shell: |
        set -eu
        for _ in $(seq 1 60); do
          if ! fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock >/dev/null 2>&1; then
            exit 0
          fi
          sleep 5
        done
        exit 1
      args:
        executable: /bin/bash
      changed_when: false

    - name: Install Ubuntu repository management tools
      ansible.builtin.apt:
        name:
          - software-properties-common
        state: present
        update_cache: true
      register: repository_tool_install
      retries: 30
      delay: 5
      until: repository_tool_install is succeeded
      when: ansible_distribution == "Ubuntu"

    - name: Enable Ubuntu universe repository for legacy RTI packages
      ansible.builtin.command:
        cmd: add-apt-repository -y universe
      register: universe_repository_enable
      changed_when: "'Adding component' in universe_repository_enable.stdout or 'enabled' in universe_repository_enable.stdout"
      when: ansible_distribution == "Ubuntu"

    - name: Refresh apt cache after enabling Ubuntu universe
      ansible.builtin.apt:
        update_cache: true
      register: universe_cache_update
      retries: 30
      delay: 5
      until: universe_cache_update is succeeded
      when: ansible_distribution == "Ubuntu"

    - name: Ensure legacy nfsnobody ACL account exists for RTI NFS role compatibility
      ansible.builtin.user:
        name: nfsnobody
        system: true
        create_home: false
        shell: /usr/sbin/nologin
        state: present
      when: rti_role == "homebase"

    - name: Create homebase proxy configuration banks
      ansible.builtin.file:
        path: "{{ item.path }}"
        state: directory
        owner: root
        group: redteam
        mode: "0775"
      loop: "{{ homebase_proxy_config_banks }}"
      when: rti_role == "homebase"

    - name: Create proxy runtime directory
      ansible.builtin.file:
        path: /opt/barragan-proxy
        state: directory
        owner: root
        group: redteam
        mode: "0775"
      when: rti_role == "proxy"

    - name: Report intended Standard RTI role
      ansible.builtin.debug:
        msg: "{{ inventory_hostname }} role={{ rti_role }} private_ip={{ private_ip }} distro={{ ansible_distribution }} {{ ansible_distribution_version }} rti_base_layout=configured"
"""


def _manifest(
    target: OciDevelopmentTarget,
    names: PilotStandardRtiNames,
    resources: list[dict[str, Any]],
    cleanup: dict[str, Any],
    *,
    proxy_count: int = 2,
    template_id: str | None = None,
) -> str:
    resource_lines = "\n".join(
        f"- `{resource['type']}.{resource['name']}` named `{resource['displayName']}`"
        for resource in resources
    )
    cleanup_command = " ".join(cleanup["verificationCommands"][0])
    proxy_shape_lines = "\n".join(
        f"- Proxy subnet: `{PILOT_PROXY_CIDR}`, node `{proxy['display_name']}` at `{proxy['private_ip']}`"
        for proxy in _proxy_specs(names, proxy_count)
    )
    proxy_names = ", ".join(proxy["id"] for proxy in _proxy_specs(names, proxy_count))
    proxy_banks = ", ".join(f"`/opt/{proxy['id']}`" for proxy in _proxy_specs(names, proxy_count))
    return f"""# Barragan Pilot Standard RTI

This workspace is scoped to a disposable {'two-node Small Dev Infra' if template_id == 'small-dev-infra' else 'two-node Dev Infra' if proxy_count == 1 else 'three-node Standard RTI'} pilot in
`barragan-testing`. It validates Barragan's ability to render and launch the
core OCI shape without configuring real RTI routes.

## Target

- Compartment: `barragan-testing`
- Compartment OCID: `{target.compartment_id}`
- Region: `{target.region}`
- Confirmation token for future mutation: `{EXECUTION_CONFIRMATION}`

## Standard RTI Pilot Shape

- VCN: `{PILOT_CIDR}`
- Engagement name: `{names.engagement_name}`
- Homebase subnet: `{PILOT_HOMEBASE_CIDR}`, node `{names.homebase_name}` at `{PILOT_HOMEBASE_PRIVATE_IP}`
{proxy_shape_lines}
- SSH ingress: only `var.ssh_source_cidrs`; `0.0.0.0/0` is rejected

## Terraform Resources

{resource_lines}

## Ansible Scope

The pilot may run SSH readiness, `ansible.builtin.ping`, fact gathering, and a
minimal Standard RTI base-layout playbook. That playbook configures `/dropbox`
as a homebase NFS export mounted by {proxy_names}, creates `/engagement`
on homebase as a `root:redteam` `2770` setgid workspace, creates the homebase
proxy config banks {proxy_banks}, creates a proxy runtime
directory, and writes marker/config files that make the host shape inspectable.
It must not start backflip listeners, configure live proxy routes, configure
DNS/certificates, or configure sketch routes.

## Cleanup Verification

After destroy, verify cleanup with:

```sh
{cleanup_command}
```
"""


def _path_from_value_or_env(
    value: str | None,
    variable: str,
    env: Mapping[str, str] | None,
) -> str | None:
    if value is not None and value.strip():
        return value.strip()
    lookup = env if env is not None else os.environ
    configured = lookup.get(variable, "").strip()
    return configured or None


def _cidrs_from_values_or_env(
    values: list[str] | None,
    legacy_value: str | None,
    env: Mapping[str, str] | None,
) -> list[str]:
    if values:
        return _normalize_cidrs(values)
    if legacy_value is not None and legacy_value.strip():
        return _normalize_cidrs([legacy_value])
    lookup = env if env is not None else os.environ
    configured = lookup.get(SSH_SOURCE_CIDRS_ENV, "").strip()
    if configured:
        return _normalize_cidrs(configured.split(","))
    legacy_configured = lookup.get(SSH_SOURCE_CIDR_ENV, "").strip()
    if legacy_configured:
        return _normalize_cidrs([legacy_configured])
    return list(DEFAULT_OPERATOR_SSH_SOURCE_CIDRS)


def _normalize_cidrs(values: list[str]) -> list[str]:
    seen = set()
    cidrs = []
    for value in values:
        cidr = str(value).strip()
        if not cidr or cidr in seen:
            continue
        seen.add(cidr)
        cidrs.append(cidr)
    return cidrs


def _unsafe_cidrs(values: list[str]) -> bool:
    for value in values:
        try:
            network = ip_network(value, strict=False)
        except ValueError:
            return True
        if str(network) == "0.0.0.0/0":
            return True
    return False


def _terraform_cidr_list(values: list[str]) -> str:
    return json.dumps(values)


def _deployment_mode(value: str | None) -> str:
    if value == DESTROY_AFTER_VALIDATION:
        return DESTROY_AFTER_VALIDATION
    return HOLD_FOR_REVIEW


def _first_unresolved(resolutions: list[tuple[str, Any]]) -> tuple[str, Any] | None:
    for status, resolution in resolutions:
        if not resolution.ok:
            return status, resolution
    return None


def _run_command(command: list[str], cwd: Path | None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=barragan_subprocess_env(),
        capture_output=True,
        text=True,
        timeout=_command_timeout_seconds(command),
        check=False,
    )


def _command_timeout_seconds(command: list[str]) -> int:
    if any(part == BOOTSTRAP_VALIDATE_PLAYBOOK_PATH for part in command):
        return BOOTSTRAP_VALIDATE_TIMEOUT_SECONDS
    if any(part == CAPABILITY_PLAYBOOK_PATH for part in command):
        return CAPABILITY_APPLY_TIMEOUT_SECONDS
    normalized = [str(part) for part in command]
    if "ansible.builtin.wait_for_connection" in normalized:
        return SSH_READINESS_COMMAND_TIMEOUT_SECONDS
    if "terraform" in Path(normalized[0]).name or any(Path(part).name == "terraform" for part in normalized):
        if "apply" in normalized or "destroy" in normalized:
            return TERRAFORM_MUTATION_TIMEOUT_SECONDS
    return DEFAULT_COMMAND_TIMEOUT_SECONDS


def _run_guarded_command(
    command: list[str],
    cwd: Path | None,
    runner: CommandRunner,
    *,
    step: str = "command",
    progress_callback: ProgressCallback | None = None,
) -> DisposableCommandResult:
    phase, command_class = COMMAND_PHASES.get(step, ("Run infrastructure command", "command"))
    started_wall = datetime.now(timezone.utc)
    started_monotonic = time.monotonic()
    _emit_progress(
        progress_callback,
        "info",
        "infrastructure command started",
        {
            "eventKind": "command_started",
            "step": step,
            "phase": phase,
            "commandClass": command_class,
            "startedAt": started_wall.isoformat(),
            "observedAt": started_wall.isoformat(),
        },
    )

    def emit_activity(event_kind: str, **extra: Any) -> None:
        observed = datetime.now(timezone.utc)
        _emit_progress(
            progress_callback,
            "info",
            "Ansible task progress" if event_kind == "ansible_task" else "infrastructure command heartbeat",
            {
                "eventKind": event_kind,
                "step": step,
                "phase": phase,
                "startedAt": started_wall.isoformat(),
                "observedAt": observed.isoformat(),
                "elapsedSeconds": max(0, int(time.monotonic() - started_monotonic)),
                **extra,
            },
        )

    try:
        if runner is _run_command:
            completed = _run_observed_command(command, cwd, command_class, emit_activity)
        else:
            completed = _run_observed_custom_runner(command, cwd, runner, emit_activity)
    except (OSError, subprocess.TimeoutExpired) as exc:
        finished_wall = datetime.now(timezone.utc)
        failed = DisposableCommandResult.from_error(command, cwd, exc)
        return DisposableCommandResult(
            failed.command,
            failed.cwd,
            failed.returncode,
            failed.stdout,
            failed.stderr,
            failed.ok,
            started_wall.isoformat(),
            finished_wall.isoformat(),
            round(max(0.0, time.monotonic() - started_monotonic), 3),
        )
    finished_wall = datetime.now(timezone.utc)
    result = DisposableCommandResult.from_completed(command, cwd, completed)
    return DisposableCommandResult(
        result.command,
        result.cwd,
        result.returncode,
        result.stdout,
        result.stderr,
        result.ok,
        started_wall.isoformat(),
        finished_wall.isoformat(),
        round(max(0.0, time.monotonic() - started_monotonic), 3),
    )


def _run_observed_custom_runner(
    command: list[str],
    cwd: Path | None,
    runner: CommandRunner,
    emit_activity: Callable[..., None],
) -> subprocess.CompletedProcess[str]:
    results: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def invoke() -> None:
        try:
            results.put((True, runner(command, cwd)))
        except BaseException as exc:  # Re-raise on the orchestrator thread.
            results.put((False, exc))

    worker = threading.Thread(target=invoke, name="barragan-command", daemon=True)
    worker.start()
    heartbeat_event_count = 0
    while True:
        try:
            ok, value = results.get(timeout=COMMAND_HEARTBEAT_SECONDS)
            worker.join()
            if ok:
                return value
            raise value
        except queue.Empty:
            if heartbeat_event_count < COMMAND_HEARTBEAT_EVENT_LIMIT:
                emit_activity("command_heartbeat")
                heartbeat_event_count += 1


def _run_observed_command(
    command: list[str],
    cwd: Path | None,
    command_class: str,
    emit_activity: Callable[..., None],
) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=barragan_subprocess_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + _command_timeout_seconds(command)
    next_heartbeat = time.monotonic() + COMMAND_HEARTBEAT_SECONDS
    heartbeat_event_count = 0
    task_event_count = 0
    last_task_event = 0.0
    parsed_output_length = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            process.kill()
            stdout, stderr = process.communicate()
            raise subprocess.TimeoutExpired(command, _command_timeout_seconds(command), output=stdout, stderr=stderr)
        try:
            stdout, stderr = process.communicate(timeout=min(COMMAND_OBSERVATION_SECONDS, remaining))
            if command_class == "ansible_playbook" and task_event_count < ANSIBLE_TASK_EVENT_LIMIT:
                _emit_ansible_progress(
                    stdout[parsed_output_length:],
                    emit_activity,
                    limit=ANSIBLE_TASK_EVENT_LIMIT - task_event_count,
                )
            return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        except subprocess.TimeoutExpired as exc:
            partial = _text_output(exc.output)
            if command_class == "ansible_playbook" and task_event_count < ANSIBLE_TASK_EVENT_LIMIT:
                now = time.monotonic()
                if now - last_task_event >= ANSIBLE_TASK_EVENT_THROTTLE_SECONDS:
                    emitted = _emit_ansible_progress(partial[parsed_output_length:], emit_activity, limit=1)
                    if emitted:
                        task_event_count += emitted
                        last_task_event = now
                parsed_output_length = max(parsed_output_length, len(partial))
            now = time.monotonic()
            if now >= next_heartbeat and heartbeat_event_count < COMMAND_HEARTBEAT_EVENT_LIMIT:
                emit_activity("command_heartbeat")
                heartbeat_event_count += 1
                next_heartbeat = now + COMMAND_HEARTBEAT_SECONDS


def _text_output(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def _emit_ansible_progress(
    output: str,
    emit_activity: Callable[..., None],
    *,
    limit: int = COMMAND_PROGRESS_EVENT_LIMIT,
) -> int:
    emitted = 0
    for raw_line in output.splitlines():
        match = re.match(r"^(PLAY|TASK) \[(.+?)\]\s+\*+\s*$", raw_line.strip())
        if not match:
            continue
        label = _safe_ansible_progress_label(match.group(2))
        if not label:
            continue
        emit_activity("ansible_task", **{"play" if match.group(1) == "PLAY" else "task": label})
        emitted += 1
        if emitted >= limit:
            break
    return emitted


def _safe_ansible_progress_label(value: str) -> str:
    if re.search(r"(?i)\b(token|secret|password|passphrase|private[_ -]?key|api[_ -]?key|credential)\b", value):
        return ""
    redacted = _redact_command_output(value)
    redacted = re.sub(r"\s+", " ", redacted).strip()
    return redacted[:ANSIBLE_PROGRESS_FIELD_CHARS]


def _ansible_ssh_common_args(known_hosts_path: str) -> str:
    return (
        f"-o UserKnownHostsFile={known_hosts_path} "
        "-o StrictHostKeyChecking=accept-new "
        "-o IdentitiesOnly=yes "
        "-o BatchMode=yes "
        f"-o ConnectTimeout={SSH_CONNECT_TIMEOUT_SECONDS}"
    )


def _ensure_private_known_hosts_directory(directory: Path) -> None:
    """Keep the SSH pin directory safe on collaborator hosts with umask 0002."""
    created = False
    try:
        directory.mkdir(mode=0o700)
        created = True
    except FileExistsError:
        pass
    try:
        path_info = directory.lstat()
        if not stat.S_ISDIR(path_info.st_mode):
            raise ValueError("core known-hosts directory is unsafe")
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ValueError("core known-hosts directory is unsafe") from exc
    try:
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_dev != path_info.st_dev
                or info.st_ino != path_info.st_ino or info.st_uid not in (os.getuid(), 0)):
            raise ValueError("core known-hosts directory is unsafe")
        if created:
            if info.st_uid != os.geteuid():
                raise ValueError("core known-hosts directory is unsafe")
            os.fchmod(fd, 0o700)
            info = os.fstat(fd)
        current_path = directory.lstat()
        if (not stat.S_ISDIR(current_path.st_mode)
                or (current_path.st_dev, current_path.st_ino) != (info.st_dev, info.st_ino)
                or info.st_mode & 0o022):
            raise ValueError("core known-hosts directory is unsafe")
    finally:
        os.close(fd)


def _terraform_public_ips(result: DisposableCommandResult) -> dict[str, str] | None:
    if not result.ok:
        return None
    try:
        body = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return None
    output = body.get("public_ips")
    if not isinstance(output, dict) or not isinstance(output.get("value"), dict):
        return None
    value = output["value"]
    homebase = value.get("homebase")
    proxy01 = value.get("proxy01")
    if isinstance(homebase, str) and isinstance(proxy01, str):
        ips = {"homebase": homebase, "proxy01": proxy01}
        proxy02 = value.get("proxy02")
        if isinstance(proxy02, str):
            ips["proxy02"] = proxy02
        return ips
    return None


def _destroy_and_verify_after_failure(
    target: OciDevelopmentTarget,
    workspace: PilotStandardRtiWorkspace,
    workspace_dir: Path,
    preflight: OciReadValidationResult,
    commands_planned: list[list[str]],
    commands_run: list[DisposableCommandResult],
    runner: CommandRunner,
    *,
    mutation_status: str,
    ansible_status: str,
    progress_callback: ProgressCallback | None = None,
) -> PilotStandardRtiExecutionResult:
    destroy_result = _run_guarded_command(
        commands_planned[DESTROY_COMMAND_INDEX],
        workspace_dir,
        runner,
        step="terraform_destroy",
        progress_callback=progress_callback,
    )
    commands_run.append(destroy_result)
    _emit_command_progress(
        progress_callback,
        "terraform_destroy",
        "Terraform destroy completed",
        destroy_result,
    )
    cleanup = None
    if destroy_result.ok:
        cleanup = _verify_cleanup(workspace, runner)
        if cleanup.result is not None:
            commands_run.append(cleanup.result)
        _emit_cleanup_progress(progress_callback, cleanup)
    return _result(
        target,
        workspace,
        workspace_dir,
        preflight,
        commands_planned,
        commands_run,
        cleanup_verification=cleanup,
        created_resources=_summarize_resources(workspace, "create_attempted"),
        destroyed_resources=(
            _summarize_resources(workspace, "destroy_attempted") if destroy_result.ok else []
        ),
        mutation_status=mutation_status,
        ansible_status=ansible_status,
        final_cleanup_status=(
            "verified_clean" if cleanup is not None and cleanup.ok else "cleanup_not_verified"
        ),
    )


def _emit_progress(
    progress_callback: ProgressCallback | None,
    level: str,
    message: str,
    data: dict[str, Any],
) -> None:
    if progress_callback is None:
        return
    progress_callback({"level": level, "message": message, "data": data})


def _emit_command_progress(
    progress_callback: ProgressCallback | None,
    step: str,
    message: str,
    result: DisposableCommandResult,
) -> None:
    output_refs = _write_command_output_artifacts(step, result)
    data: dict[str, Any] = {
        "eventKind": "command_completed",
        "step": step,
        "status": "succeeded" if result.ok else "failed",
        "returncode": result.returncode,
        "cwd": str(result.cwd) if result.cwd is not None else None,
    }
    if result.started_at:
        data["startedAt"] = result.started_at
    if result.finished_at:
        data["finishedAt"] = result.finished_at
    if result.elapsed_seconds is not None:
        data["elapsedSeconds"] = result.elapsed_seconds
    if output_refs:
        data["commandOutputArtifactRefs"] = output_refs
    if not result.ok:
        failure_output = _command_failure_output(result)
        if failure_output:
            data["failureOutputExcerpt"] = failure_output
            # Backward-compatible field for existing progress console consumers.
            data["failureOutput"] = failure_output
    _emit_progress(
        progress_callback,
        "info" if result.ok else "error",
        message,
        data,
    )


def _write_command_output_artifacts(step: str, result: DisposableCommandResult) -> list[str]:
    workspace = Path(result.cwd) if result.cwd else None
    if workspace is None:
        return []
    streams = {
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    if not any(value.strip() for value in streams.values()):
        return []
    logs_dir = workspace / COMMAND_OUTPUT_LOG_DIR
    logs_dir.mkdir(parents=True, exist_ok=True)
    refs: list[str] = []
    safe_step = _safe_log_name(step)
    for stream_name, raw_value in streams.items():
        value = _redact_command_output(raw_value)
        if not value.strip():
            continue
        path = logs_dir / f"{safe_step}.{stream_name}.log"
        path.write_text(value, encoding="utf-8")
        refs.append(f"workspace:{path}")
    return refs


def _safe_log_name(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    safe = safe.strip("._-")
    return safe or "command"


def _command_failure_output(result: DisposableCommandResult, *, max_chars: int = COMMAND_FAILURE_EXCERPT_CHARS) -> str:
    output = "\n".join(
        part.strip()
        for part in (_redact_command_output(result.stderr), _redact_command_output(result.stdout))
        if part and part.strip()
    ).strip()
    if not output:
        return ""
    if len(output) <= max_chars:
        return output
    edge_chars = max(1, max_chars // 2)
    omitted = len(output) - (edge_chars * 2)
    return (
        output[:edge_chars].rstrip()
        + f"\n\n[... truncated {omitted} characters ...]\n\n"
        + output[-edge_chars:].lstrip()
    )


def _redact_command_output(value: str) -> str:
    if not value:
        return ""
    redacted = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "[redacted private key]",
        value,
        flags=re.DOTALL,
    )
    redacted = re.sub(
        r"(?i)(token|secret|password|api[_-]?key)([\"'\s:=]+)([^\s\"']+)",
        r"\1\2[redacted]",
        redacted,
    )
    return redacted


def _emit_cleanup_progress(
    progress_callback: ProgressCallback | None,
    cleanup: CleanupVerificationResult,
) -> None:
    _emit_progress(
        progress_callback,
        "info" if cleanup.ok else "error",
        "cleanup verification completed",
        {
            "status": "verified_clean" if cleanup.ok else "cleanup_not_verified",
            "ok": cleanup.ok,
            "remainingCount": cleanup.remaining_count,
        },
    )


def _verify_cleanup(
    workspace: PilotStandardRtiWorkspace,
    runner: CommandRunner,
) -> CleanupVerificationResult:
    commands = workspace.cleanup["verificationCommands"]
    checks: list[dict[str, Any]] = []
    first_result: DisposableCommandResult | None = None
    last_result: DisposableCommandResult | None = None
    remaining_total = 0
    errors: list[str] = []

    for command in commands:
        result = _run_guarded_command(command, None, runner)
        first_result = first_result or result
        last_result = result
        resource = _cleanup_resource_label(command)
        if not result.ok:
            error = (result.stderr or result.stdout).strip() or "cleanup verification failed"
            checks.append({"resource": resource, "command": command, "ok": False, "remainingCount": None, "error": error})
            errors.append(f"{resource}: {error}")
            continue
        try:
            body = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            checks.append({"resource": resource, "command": command, "ok": False, "remainingCount": None, "error": str(exc)})
            errors.append(f"{resource}: {exc}")
            continue
        data = body.get("data", [])
        if not isinstance(data, list):
            error = "cleanup verification did not return a data array"
            checks.append({"resource": resource, "command": command, "ok": False, "remainingCount": None, "error": error})
            errors.append(f"{resource}: {error}")
            continue
        remaining = _remaining_cleanup_items(resource, data)
        remaining_total += remaining
        error = None if remaining == 0 else f"pilot {resource} resource still present"
        checks.append({"resource": resource, "command": command, "ok": remaining == 0, "remainingCount": remaining, "error": error})
        if error is not None:
            errors.append(f"{resource}: {error}")

    return CleanupVerificationResult(
        command=commands[0],
        result=last_result or first_result,
        ok=len(errors) == 0,
        remaining_count=remaining_total,
        error="; ".join(errors) or None,
        checks=checks,
    )


def _cleanup_resource_label(command: list[str]) -> str:
    if "compute" in command and "instance" in command:
        return "compute_instance"
    if "subnet" in command:
        return "subnet"
    if "internet-gateway" in command:
        return "internet_gateway"
    if "nat-gateway" in command:
        return "nat_gateway"
    if "route-table" in command:
        return "route_table"
    if "security-list" in command:
        return "security_list"
    if "vcn" in command:
        return "vcn"
    return "unknown"


def _remaining_cleanup_items(resource: str, data: list[Any]) -> int:
    if resource == "compute_instance":
        return sum(
            1
            for item in data
            if not (
                isinstance(item, dict)
                and str(item.get("lifecycle-state", "")).upper() == "TERMINATED"
            )
        )
    return len(data)


def _result(
    target: OciDevelopmentTarget,
    workspace: PilotStandardRtiWorkspace,
    workspace_dir: Path,
    preflight: OciReadValidationResult,
    commands_planned: list[list[str]],
    commands_run: list[DisposableCommandResult],
    *,
    cleanup_verification: CleanupVerificationResult | None = None,
    created_resources: list[dict[str, Any]] | None = None,
    destroyed_resources: list[dict[str, Any]] | None = None,
    mutation_status: str,
    ansible_status: str,
    final_cleanup_status: str,
    deployment_mode: str = HOLD_FOR_REVIEW,
    connection_details: list[dict[str, Any]] | None = None,
    outbound_channels: list[dict[str, Any]] | None = None,
    inbound_channels: list[dict[str, Any]] | None = None,
) -> PilotStandardRtiExecutionResult:
    channel_rows = _successful_channel_rows(
        workspace,
        target.region,
        mutation_status=mutation_status,
        ansible_status=ansible_status,
        outbound_channels=outbound_channels,
        inbound_channels=inbound_channels,
    )
    return PilotStandardRtiExecutionResult(
        target=target,
        workspace=workspace,
        workspace_dir=workspace_dir,
        preflight=preflight,
        commands_planned=commands_planned,
        commands_run=commands_run,
        created_resources=created_resources or [],
        destroyed_resources=destroyed_resources or [],
        cleanup_verification=cleanup_verification,
        mutation_status=mutation_status,
        ansible_status=ansible_status,
        final_cleanup_status=final_cleanup_status,
        deployment_mode=deployment_mode,
        connection_details=connection_details,
        outbound_channels=channel_rows["outboundChannels"],
        inbound_channels=channel_rows["inboundChannels"],
    )


def _successful_channel_rows(
    workspace: PilotStandardRtiWorkspace,
    region: str,
    *,
    mutation_status: str,
    ansible_status: str,
    outbound_channels: list[dict[str, Any]] | None,
    inbound_channels: list[dict[str, Any]] | None,
) -> dict[str, list[dict[str, Any]]]:
    if ansible_status != "validated" or mutation_status not in {"deployed", "destroyed", "destroy_failed"}:
        return {"outboundChannels": [], "inboundChannels": []}
    if outbound_channels is not None or inbound_channels is not None:
        return {
            "outboundChannels": outbound_channels or [],
            "inboundChannels": inbound_channels or [],
        }
    return pilot_channel_rows(workspace.names, region=region)


def _summarize_resources(
    workspace: PilotStandardRtiWorkspace,
    action: str,
) -> list[dict[str, Any]]:
    return [
        {
            "action": action,
            "provider": resource["provider"],
            "type": resource["type"],
            "name": resource["name"],
            "displayName": resource["displayName"],
            "compartmentId": resource["compartmentId"],
            "region": resource["region"],
        }
        for resource in workspace.resources
    ]
