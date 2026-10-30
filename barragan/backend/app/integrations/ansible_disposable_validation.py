# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from app.core.command_environment import barragan_subprocess_env
from app.integrations.command_resolution import CommandResolution, resolve_executable
from app.integrations.managed_host_images import managed_host_image_profile
from app.integrations.oci_disposable_terraform import (
    CleanupVerificationResult,
    DisposableCommandResult,
    resolve_terraform,
)
from app.integrations.oci_read_validation import (
    BARRAGAN_TESTING_COMPARTMENT_ID,
    CommandRunner as OciReadCommandRunner,
    DEFAULT_REGION,
    OciDevelopmentTarget,
    OciReadValidationResult,
    OciSafetyError,
    resolve_oci_cli,
    run_read_validation,
)


WORKSPACE_NAME = "barragan-disposable-ansible-validation"
VALIDATION_INSTANCE_NAME = "barragan-disposable-ansible-validation"
VALIDATION_VCN_NAME = "barragan-disposable-ansible-vcn"
VALIDATION_SUBNET_NAME = "barragan-disposable-ansible-subnet"
VALIDATION_INTERNET_GATEWAY_NAME = "barragan-disposable-ansible-validation-igw"
VALIDATION_ROUTE_TABLE_NAME = "barragan-disposable-ansible-validation-route"
VALIDATION_SECURITY_LIST_NAME = "barragan-disposable-ansible-validation-ssh-only"
VALIDATION_CIDR = "10.255.241.0/24"
DEFAULT_SHAPE = "VM.Standard.E4.Flex"
DEFAULT_SSH_USER = "ubuntu"
SSH_PUBLIC_KEY_ENV = "BARRAGAN_VALIDATION_SSH_PUBLIC_KEY"
SSH_PRIVATE_KEY_ENV = "BARRAGAN_VALIDATION_SSH_PRIVATE_KEY"
SSH_SOURCE_CIDR_ENV = "BARRAGAN_VALIDATION_SSH_SOURCE_CIDR"
SSH_KNOWN_HOSTS_RELATIVE_PATH = "ssh/known_hosts"
SSH_READINESS_TIMEOUT_SECONDS = 180
SSH_READINESS_SLEEP_SECONDS = 5
SSH_CONNECT_TIMEOUT_SECONDS = 10
ANSIBLE_OVERRIDE_VARIABLES = ("ANSIBLE_BIN", "ANSIBLE_PATH")
ANSIBLE_PLAYBOOK_OVERRIDE_VARIABLES = ("ANSIBLE_PLAYBOOK_BIN", "ANSIBLE_PLAYBOOK_PATH")

CommandRunner = Callable[[list[str], Path | None], subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class AnsibleValidationArtifact:
    path: str
    content: str

    def to_dict(self, include_content: bool = False) -> dict[str, Any]:
        body: dict[str, Any] = {"path": self.path}
        if include_content:
            body["content"] = self.content
        return body


@dataclass(frozen=True)
class AnsibleValidationWorkspace:
    target: OciDevelopmentTarget
    resources: list[dict[str, Any]]
    cleanup: dict[str, Any]
    artifacts: list[AnsibleValidationArtifact]

    def to_dict(self, include_content: bool = False) -> dict[str, Any]:
        validate_ansible_validation_target(self.target)
        return {
            "ok": True,
            "workspace": WORKSPACE_NAME,
            "mode": "ansible_validation_render_preview",
            "mutation": False,
            "notice": (
                "This preview renders Terraform and Ansible validation artifacts only. "
                "It does not create OCI compute, open SSH, run Ansible, or destroy resources."
            ),
            "target": _target_dict(self.target),
            "resources": self.resources,
            "cleanup": self.cleanup,
            "artifacts": [artifact.to_dict(include_content) for artifact in self.artifacts],
        }


@dataclass(frozen=True)
class AnsibleValidationExecutionResult:
    target: OciDevelopmentTarget
    workspace: AnsibleValidationWorkspace
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

    @property
    def ok(self) -> bool:
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
            "mode": "ansible_guarded_execute",
            "mutation": self.did_mutate,
            "target": _target_dict(self.target, mutation=self.did_mutate),
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
            "mutationStatus": self.mutation_status,
            "ansibleStatus": self.ansible_status,
            "finalCleanupStatus": self.final_cleanup_status,
        }


def resolve_ansible(
    *,
    env: Mapping[str, str] | None = None,
    fallback_paths: list[str | Path] | None = None,
) -> CommandResolution:
    return resolve_executable(
        "ansible",
        override_variables=ANSIBLE_OVERRIDE_VARIABLES,
        fallback_paths=fallback_paths or (),
        env=env,
        display_name="Ansible",
    )


def resolve_ansible_playbook(
    *,
    env: Mapping[str, str] | None = None,
    fallback_paths: list[str | Path] | None = None,
) -> CommandResolution:
    return resolve_executable(
        "ansible-playbook",
        override_variables=ANSIBLE_PLAYBOOK_OVERRIDE_VARIABLES,
        fallback_paths=fallback_paths or (),
        env=env,
        display_name="ansible-playbook",
    )


def build_ansible_validation_workspace(
    target: OciDevelopmentTarget | None = None,
    *,
    oci_executable: str = "oci",
) -> AnsibleValidationWorkspace:
    resolved_target = target or OciDevelopmentTarget()
    validate_ansible_validation_target(resolved_target)
    resources = [
        _resource("oci_core_vcn", "validation_vcn", VALIDATION_VCN_NAME, resolved_target),
        _resource("oci_core_subnet", "validation_subnet", VALIDATION_SUBNET_NAME, resolved_target),
        _resource("oci_core_internet_gateway", "validation_gateway", VALIDATION_INTERNET_GATEWAY_NAME, resolved_target),
        _resource("oci_core_route_table", "validation_route", VALIDATION_ROUTE_TABLE_NAME, resolved_target),
        _resource("oci_core_security_list", "validation_security", VALIDATION_SECURITY_LIST_NAME, resolved_target),
        _resource("oci_core_instance", "validation_instance", VALIDATION_INSTANCE_NAME, resolved_target),
    ]
    cleanup = {
        "expectedDestroyBehavior": (
            "terraform destroy must remove the disposable compute, subnet, gateway, route, "
            "security list, and VCN immediately after Ansible validation."
        ),
        "verificationCommands": [
            [
                oci_executable,
                "--auth",
                resolved_target.auth,
                "--region",
                resolved_target.region,
                "compute",
                "instance",
                "list",
                "--compartment-id",
                resolved_target.compartment_id,
                "--display-name",
                VALIDATION_INSTANCE_NAME,
                "--output",
                "json",
            ],
            [
                oci_executable,
                "--auth",
                resolved_target.auth,
                "--region",
                resolved_target.region,
                "network",
                "subnet",
                "list",
                "--compartment-id",
                resolved_target.compartment_id,
                "--display-name",
                VALIDATION_SUBNET_NAME,
                "--output",
                "json",
            ],
            [
                oci_executable,
                "--auth",
                resolved_target.auth,
                "--region",
                resolved_target.region,
                "network",
                "internet-gateway",
                "list",
                "--compartment-id",
                resolved_target.compartment_id,
                "--display-name",
                VALIDATION_INTERNET_GATEWAY_NAME,
                "--output",
                "json",
            ],
            [
                oci_executable,
                "--auth",
                resolved_target.auth,
                "--region",
                resolved_target.region,
                "network",
                "route-table",
                "list",
                "--compartment-id",
                resolved_target.compartment_id,
                "--display-name",
                VALIDATION_ROUTE_TABLE_NAME,
                "--output",
                "json",
            ],
            [
                oci_executable,
                "--auth",
                resolved_target.auth,
                "--region",
                resolved_target.region,
                "network",
                "security-list",
                "list",
                "--compartment-id",
                resolved_target.compartment_id,
                "--display-name",
                VALIDATION_SECURITY_LIST_NAME,
                "--output",
                "json",
            ],
            [
                oci_executable,
                "--auth",
                resolved_target.auth,
                "--region",
                resolved_target.region,
                "network",
                "vcn",
                "list",
                "--compartment-id",
                resolved_target.compartment_id,
                "--display-name",
                VALIDATION_VCN_NAME,
                "--output",
                "json",
            ]
        ],
        "successCriteria": (
            "Cleanup verification must find no live disposable compute, subnet, gateway, "
            "route table, security list, or VCN resources from this validation workspace."
        ),
    }
    artifacts = [
        AnsibleValidationArtifact("versions.tf", _versions_tf()),
        AnsibleValidationArtifact("variables.tf", _variables_tf()),
        AnsibleValidationArtifact("main.tf", _main_tf()),
        AnsibleValidationArtifact("terraform.tfvars.json", _tfvars_json(resolved_target)),
        AnsibleValidationArtifact("ansible/inventory.ini", _inventory_ini()),
        AnsibleValidationArtifact("ansible/validate.yml", _validation_playbook()),
        AnsibleValidationArtifact("MANIFEST.md", _manifest(resolved_target, resources, cleanup)),
    ]
    return AnsibleValidationWorkspace(
        target=resolved_target,
        resources=resources,
        cleanup=cleanup,
        artifacts=artifacts,
    )


def render_ansible_validation_workspace(
    destination: Path,
    target: OciDevelopmentTarget | None = None,
    *,
    oci_executable: str = "oci",
) -> AnsibleValidationWorkspace:
    workspace = build_ansible_validation_workspace(target, oci_executable=oci_executable)
    destination.mkdir(parents=True, exist_ok=True)
    for artifact in workspace.artifacts:
        artifact_path = destination / artifact.path
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(artifact.content, encoding="utf-8")
    return workspace


def build_ansible_validation_commands(
    workspace: AnsibleValidationWorkspace,
    *,
    terraform_executable: str = "terraform",
    ansible_executable: str = "ansible",
    ansible_playbook_executable: str = "ansible-playbook",
    ssh_private_key_path: str = "$BARRAGAN_VALIDATION_SSH_PRIVATE_KEY",
    ssh_public_key_path: str = "$BARRAGAN_VALIDATION_SSH_PUBLIC_KEY",
    ssh_source_cidr: str = f"${SSH_SOURCE_CIDR_ENV}",
    host: str = "${terraform output public_ip}",
    known_hosts_path: str = SSH_KNOWN_HOSTS_RELATIVE_PATH,
) -> list[list[str]]:
    validate_ansible_validation_target(workspace.target)
    ssh_common_args = _ansible_ssh_common_args(known_hosts_path)
    return [
        [terraform_executable, "init", "-input=false"],
        [
            terraform_executable,
            "apply",
            "-input=false",
            "-auto-approve",
            "-var",
            f"region={workspace.target.region}",
            "-var",
            f"compartment_ocid={workspace.target.compartment_id}",
            "-var",
            f"ssh_public_key_path={ssh_public_key_path}",
            "-var",
            f"ssh_source_cidr={ssh_source_cidr}",
        ],
        [terraform_executable, "output", "-json"],
        [
            ansible_executable,
            "validation_target",
            "-i",
            "ansible/inventory.ini",
            "-u",
            DEFAULT_SSH_USER,
            "--private-key",
            ssh_private_key_path,
            f"--ssh-common-args={ssh_common_args}",
            "-e",
            f"ansible_host={host}",
            "-m",
            "ansible.builtin.wait_for_connection",
            "-a",
            (
                f"timeout={SSH_READINESS_TIMEOUT_SECONDS} "
                f"sleep={SSH_READINESS_SLEEP_SECONDS} "
                f"connect_timeout={SSH_CONNECT_TIMEOUT_SECONDS}"
            ),
        ],
        [
            ansible_executable,
            "validation_target",
            "-i",
            "ansible/inventory.ini",
            "-u",
            DEFAULT_SSH_USER,
            "--private-key",
            ssh_private_key_path,
            f"--ssh-common-args={ssh_common_args}",
            "-e",
            f"ansible_host={host}",
            "-m",
            "ping",
        ],
        [
            ansible_playbook_executable,
            "-i",
            "ansible/inventory.ini",
            "ansible/validate.yml",
            "-u",
            DEFAULT_SSH_USER,
            "--private-key",
            ssh_private_key_path,
            f"--ssh-common-args={ssh_common_args}",
            "-e",
            f"ansible_host={host}",
        ],
        [
            terraform_executable,
            "destroy",
            "-input=false",
            "-auto-approve",
            "-var",
            f"region={workspace.target.region}",
            "-var",
            f"compartment_ocid={workspace.target.compartment_id}",
            "-var",
            f"ssh_public_key_path={ssh_public_key_path}",
            "-var",
            f"ssh_source_cidr={ssh_source_cidr}",
        ],
        *workspace.cleanup["verificationCommands"],
    ]


def execute_disposable_ansible_validation(
    workspace_dir: Path,
    target: OciDevelopmentTarget | None = None,
    *,
    runner: CommandRunner | None = None,
    preflight_runner: OciReadCommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    ssh_private_key_path: str | None = None,
    ssh_public_key_path: str | None = None,
    ssh_source_cidr: str | None = None,
) -> AnsibleValidationExecutionResult:
    resolved_target = target or OciDevelopmentTarget()
    validate_ansible_validation_target(resolved_target)
    terraform_resolution = resolve_terraform(env=env)
    oci_resolution = resolve_oci_cli(env=env)
    ansible_resolution = resolve_ansible(env=env)
    ansible_playbook_resolution = resolve_ansible_playbook(env=env)
    private_key = _path_from_value_or_env(ssh_private_key_path, SSH_PRIVATE_KEY_ENV, env)
    public_key = _path_from_value_or_env(ssh_public_key_path, SSH_PUBLIC_KEY_ENV, env)
    source_cidr = _path_from_value_or_env(ssh_source_cidr, SSH_SOURCE_CIDR_ENV, env)
    workspace = render_ansible_validation_workspace(
        workspace_dir,
        resolved_target,
        oci_executable=oci_resolution.command or "oci",
    )
    known_hosts_path = workspace_dir / SSH_KNOWN_HOSTS_RELATIVE_PATH
    known_hosts_path.parent.mkdir(parents=True, exist_ok=True)
    commands_planned = build_ansible_validation_commands(
        workspace,
        terraform_executable=terraform_resolution.command or "terraform",
        ansible_executable=ansible_resolution.command or "ansible",
        ansible_playbook_executable=ansible_playbook_resolution.command or "ansible-playbook",
        ssh_private_key_path=private_key or f"${SSH_PRIVATE_KEY_ENV}",
        ssh_public_key_path=public_key or f"${SSH_PUBLIC_KEY_ENV}",
        ssh_source_cidr=source_cidr or f"${SSH_SOURCE_CIDR_ENV}",
        known_hosts_path=str(known_hosts_path),
    )
    command_runner = runner or _run_command
    read_runner = preflight_runner or (lambda command: command_runner(command, None))
    commands_run: list[DisposableCommandResult] = []

    preflight = run_read_validation(resolved_target, runner=read_runner, env=env)
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

    if private_key is None or public_key is None or source_cidr is None:
        missing = []
        if private_key is None:
            missing.append(SSH_PRIVATE_KEY_ENV)
        if public_key is None:
            missing.append(SSH_PUBLIC_KEY_ENV)
        if source_cidr is None:
            missing.append(SSH_SOURCE_CIDR_ENV)
        commands_run.append(
            DisposableCommandResult.from_error(
                commands_planned[0],
                workspace_dir,
                RuntimeError(f"Missing SSH validation configuration: {', '.join(missing)}"),
            )
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
    if source_cidr == "0.0.0.0/0":
        commands_run.append(
            DisposableCommandResult.from_error(
                commands_planned[0],
                workspace_dir,
                RuntimeError(f"{SSH_SOURCE_CIDR_ENV} must not be 0.0.0.0/0"),
            )
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

    init_result = _run_guarded_command(commands_planned[0], workspace_dir, command_runner)
    commands_run.append(init_result)
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
            final_cleanup_status="not_started",
        )

    apply_result = _run_guarded_command(commands_planned[1], workspace_dir, command_runner)
    commands_run.append(apply_result)
    if not apply_result.ok:
        return _destroy_and_verify_after_failure(
            resolved_target,
            workspace,
            workspace_dir,
            preflight,
            commands_planned,
            commands_run,
            command_runner,
            mutation_status="apply_failed",
            ansible_status="not_started",
        )

    output_result = _run_guarded_command(commands_planned[2], workspace_dir, command_runner)
    commands_run.append(output_result)
    host = _terraform_output_value(output_result, "public_ip")
    if not output_result.ok or host is None:
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
        )

    ansible_commands = build_ansible_validation_commands(
        workspace,
        terraform_executable=terraform_resolution.command or "terraform",
        ansible_executable=ansible_resolution.command or "ansible",
        ansible_playbook_executable=ansible_playbook_resolution.command or "ansible-playbook",
        ssh_private_key_path=private_key,
        ssh_public_key_path=public_key,
        ssh_source_cidr=source_cidr,
        host=host,
        known_hosts_path=str(known_hosts_path),
    )
    for index in (3, 4, 5):
        ansible_result = _run_guarded_command(ansible_commands[index], workspace_dir, command_runner)
        commands_run.append(ansible_result)
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
            )

    destroy_result = _run_guarded_command(commands_planned[6], workspace_dir, command_runner)
    commands_run.append(destroy_result)
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
    )


def validate_ansible_validation_target(target: OciDevelopmentTarget) -> None:
    target.validate()
    if target.region != DEFAULT_REGION:
        raise OciSafetyError(f"Disposable Ansible validation must target only {DEFAULT_REGION}")


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


def _variables_tf() -> str:
    return f"""variable "region" {{
  type        = string
  description = "OCI region for the disposable Barragan Ansible validation."

  validation {{
    condition     = var.region == "{DEFAULT_REGION}"
    error_message = "Disposable Ansible validation must target only {DEFAULT_REGION}."
  }}
}}

variable "compartment_ocid" {{
  type        = string
  description = "The barragan-testing compartment OCID. Do not point this workspace elsewhere."

  validation {{
    condition     = var.compartment_ocid == "{BARRAGAN_TESTING_COMPARTMENT_ID}"
    error_message = "Disposable Ansible validation must target only barragan-testing."
  }}
}}

variable "ssh_public_key_path" {{
  type        = string
  description = "Path to a public SSH key used only for the disposable validation instance."
}}

variable "ssh_source_cidr" {{
  type        = string
  description = "Single trusted source CIDR allowed to reach SSH on the disposable validation instance."

  validation {{
    condition     = var.ssh_source_cidr != "0.0.0.0/0" && can(cidrnetmask(var.ssh_source_cidr))
    error_message = "Disposable Ansible validation requires a valid non-public SSH source CIDR."
  }}
}}

variable "shape" {{
  type        = string
  default     = "{DEFAULT_SHAPE}"
  description = "Small disposable shape for one Ansible validation target."
}}

variable "ubuntu_version" {{
  type        = string
  default     = "{managed_host_image_profile().ubuntu_version}"
  description = "Ubuntu version selected from OCI image metadata."
}}
"""


def _main_tf() -> str:
    return f"""provider "oci" {{
  region = var.region
  auth   = "InstancePrincipal"
}}

data "oci_identity_availability_domains" "ads" {{
  compartment_id = var.compartment_ocid
}}

data "oci_core_images" "ubuntu" {{
  compartment_id           = var.compartment_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = var.ubuntu_version

  filter {{
    name   = "display_name"
    values = ["^Canonical-Ubuntu-${{var.ubuntu_version}}-([.0-9-]+)$"]
    regex  = true
  }}
}}

resource "oci_core_vcn" "validation" {{
  compartment_id = var.compartment_ocid
  display_name   = "{VALIDATION_VCN_NAME}"
  cidr_block     = "{VALIDATION_CIDR}"
  dns_label      = "bagansible"
}}

resource "oci_core_internet_gateway" "validation" {{
  compartment_id = var.compartment_ocid
  display_name   = "{VALIDATION_INTERNET_GATEWAY_NAME}"
  vcn_id         = oci_core_vcn.validation.id
  enabled        = true
}}

resource "oci_core_route_table" "validation" {{
  compartment_id = var.compartment_ocid
  display_name   = "{VALIDATION_ROUTE_TABLE_NAME}"
  vcn_id         = oci_core_vcn.validation.id

  route_rules {{
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.validation.id
  }}
}}

resource "oci_core_security_list" "validation" {{
  compartment_id = var.compartment_ocid
  display_name   = "{VALIDATION_SECURITY_LIST_NAME}"
  vcn_id         = oci_core_vcn.validation.id

  egress_security_rules {{
    protocol    = "all"
    destination = "0.0.0.0/0"
  }}

  ingress_security_rules {{
    protocol = "6"
    source   = var.ssh_source_cidr

    tcp_options {{
      min = 22
      max = 22
    }}
  }}
}}

resource "oci_core_subnet" "validation" {{
  compartment_id             = var.compartment_ocid
  display_name               = "{VALIDATION_SUBNET_NAME}"
  vcn_id                     = oci_core_vcn.validation.id
  cidr_block                 = "{VALIDATION_CIDR}"
  prohibit_public_ip_on_vnic = false
  route_table_id             = oci_core_route_table.validation.id
  security_list_ids          = [oci_core_security_list.validation.id]
}}

resource "oci_core_instance" "validation" {{
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  compartment_id      = var.compartment_ocid
  display_name        = "{VALIDATION_INSTANCE_NAME}"
  shape               = var.shape

  shape_config {{
    ocpus         = 1
    memory_in_gbs = 8
  }}

  instance_options {{
    are_legacy_imds_endpoints_disabled = true
  }}

  create_vnic_details {{
    subnet_id        = oci_core_subnet.validation.id
    assign_public_ip = true
    display_name     = "{VALIDATION_INSTANCE_NAME}-vnic"
  }}

  metadata = {{
    ssh_authorized_keys = file(var.ssh_public_key_path)
  }}

  source_details {{
    source_type = "image"
    source_id   = data.oci_core_images.ubuntu.images[0].id
  }}
}}

output "public_ip" {{
  value = oci_core_instance.validation.public_ip
}}

"""


def _tfvars_json(target: OciDevelopmentTarget) -> str:
    return (
        "{\n"
        f'  "region": "{target.region}",\n'
        f'  "compartment_ocid": "{target.compartment_id}"\n'
        "}\n"
    )


def _inventory_ini() -> str:
    return """[barragan_validation]
validation_target ansible_host=0.0.0.0 ansible_user=ubuntu
"""


def _validation_playbook() -> str:
    return """---
- name: Barragan disposable Ansible validation
  hosts: barragan_validation
  gather_facts: true
  tasks:
    - name: Verify Ansible transport
      ansible.builtin.ping:

    - name: Report harmless fact sample
      ansible.builtin.debug:
        msg: "{{ ansible_distribution }} {{ ansible_distribution_version }}"
"""


def _manifest(
    target: OciDevelopmentTarget,
    resources: list[dict[str, Any]],
    cleanup: dict[str, Any],
) -> str:
    resource_lines = "\n".join(
        f"- `{resource['type']}.{resource['name']}` named `{resource['displayName']}`"
        for resource in resources
    )
    cleanup_command = " ".join(cleanup["verificationCommands"][0])
    return f"""# Barragan Disposable Ansible Validation

This workspace is scoped to one disposable OCI compute target in `barragan-testing`.
It exists only to validate Barragan's guarded Ansible execution boundary.

## Target

- Compartment: `barragan-testing`
- Compartment OCID: `{target.compartment_id}`
- Region: `{target.region}`
- Instance display name: `{VALIDATION_INSTANCE_NAME}`

## Terraform Resources

{resource_lines}

## Ansible Scope

The validation may run only `ansible.builtin.ping` and fact gathering/setup
against the disposable target. It must not install packages, write files, start
services, or configure RTI roles.

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


def _first_unresolved(
    resolutions: list[tuple[str, CommandResolution]],
) -> tuple[str, CommandResolution] | None:
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
        timeout=240,
        check=False,
    )


def _run_guarded_command(
    command: list[str],
    cwd: Path | None,
    runner: CommandRunner,
) -> DisposableCommandResult:
    try:
        completed = runner(command, cwd)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return DisposableCommandResult.from_error(command, cwd, exc)
    return DisposableCommandResult.from_completed(command, cwd, completed)


def _ansible_ssh_common_args(known_hosts_path: str) -> str:
    return (
        f"-o UserKnownHostsFile={known_hosts_path} "
        "-o StrictHostKeyChecking=accept-new "
        "-o IdentitiesOnly=yes "
        "-o BatchMode=yes "
        f"-o ConnectTimeout={SSH_CONNECT_TIMEOUT_SECONDS}"
    )


def _terraform_output_value(result: DisposableCommandResult, key: str) -> str | None:
    if not result.ok:
        return None
    try:
        body = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return None
    output = body.get(key)
    if isinstance(output, dict) and isinstance(output.get("value"), str):
        return output["value"]
    return None


def _destroy_and_verify_after_failure(
    target: OciDevelopmentTarget,
    workspace: AnsibleValidationWorkspace,
    workspace_dir: Path,
    preflight: OciReadValidationResult,
    commands_planned: list[list[str]],
    commands_run: list[DisposableCommandResult],
    runner: CommandRunner,
    *,
    mutation_status: str,
    ansible_status: str,
) -> AnsibleValidationExecutionResult:
    destroy_result = _run_guarded_command(commands_planned[6], workspace_dir, runner)
    commands_run.append(destroy_result)
    cleanup = None
    if destroy_result.ok:
        cleanup = _verify_cleanup(
            workspace,
            runner,
        )
        if cleanup.result is not None:
            commands_run.append(cleanup.result)
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


def _verify_cleanup(
    workspace: AnsibleValidationWorkspace,
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
            checks.append(
                {
                    "resource": resource,
                    "command": command,
                    "ok": False,
                    "remainingCount": None,
                    "error": error,
                }
            )
            errors.append(f"{resource}: {error}")
            continue
        try:
            body = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            checks.append(
                {
                    "resource": resource,
                    "command": command,
                    "ok": False,
                    "remainingCount": None,
                    "error": str(exc),
                }
            )
            errors.append(f"{resource}: {exc}")
            continue
        data = body.get("data", [])
        if not isinstance(data, list):
            error = "cleanup verification did not return a data array"
            checks.append(
                {
                    "resource": resource,
                    "command": command,
                    "ok": False,
                    "remainingCount": None,
                    "error": error,
                }
            )
            errors.append(f"{resource}: {error}")
            continue
        remaining = _remaining_cleanup_items(resource, data)
        remaining_total += remaining
        error = None if remaining == 0 else f"disposable {resource} resource still present"
        checks.append(
            {
                "resource": resource,
                "command": command,
                "ok": remaining == 0,
                "remainingCount": remaining,
                "error": error,
            }
        )
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
    workspace: AnsibleValidationWorkspace,
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
) -> AnsibleValidationExecutionResult:
    return AnsibleValidationExecutionResult(
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
    )


def _summarize_resources(
    workspace: AnsibleValidationWorkspace,
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
