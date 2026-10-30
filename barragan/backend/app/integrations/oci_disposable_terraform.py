# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from typing import Mapping

from app.integrations.command_resolution import CommandResolution, resolve_executable
from app.integrations.oci_read_validation import (
    BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID,
    BARRAGAN_TESTING_COMPARTMENT_ID,
    CommandRunner as OciReadCommandRunner,
    DEFAULT_REGION,
    OciDevelopmentTarget,
    OciReadValidationResult,
    OciSafetyError,
    resolve_oci_cli,
    run_read_validation,
)


WORKSPACE_NAME = "barragan-disposable-oci-validation"
VALIDATION_VCN_NAME = "barragan-disposable-validation-vcn"
VALIDATION_VCN_CIDR = "10.255.240.0/24"
EXECUTION_CONFIRMATION = "mutate-barragan-testing"
TERRAFORM_OVERRIDE_VARIABLES = ("TERRAFORM_BIN", "TERRAFORM_PATH")
TERRAFORM_FALLBACK_PATHS = (
    Path.home() / ".local/bin/terraform",
    Path.home() / "bin/terraform",
)

TerraformCommandRunner = Callable[
    [list[str], Path | None],
    subprocess.CompletedProcess[str],
]


@dataclass(frozen=True)
class DisposableTerraformArtifact:
    path: str
    content: str

    def to_dict(self, include_content: bool = False) -> dict[str, Any]:
        body = {"path": self.path}
        if include_content:
            body["content"] = self.content
        return body


@dataclass(frozen=True)
class DisposableTerraformWorkspace:
    target: OciDevelopmentTarget
    resources: list[dict[str, Any]]
    cleanup: dict[str, Any]
    artifacts: list[DisposableTerraformArtifact]

    def to_dict(self, include_content: bool = False) -> dict[str, Any]:
        validate_disposable_terraform_target(self.target)
        return {
            "ok": True,
            "workspace": WORKSPACE_NAME,
            "mode": "terraform_render_preview",
            "mutation": False,
            "notice": (
                "This preview only renders local Terraform and runbook artifacts. "
                "It does not run terraform init, plan, apply, destroy, or OCI write commands."
            ),
            "target": _render_target_dict(self.target),
            "resources": self.resources,
            "cleanup": self.cleanup,
            "artifacts": [artifact.to_dict(include_content) for artifact in self.artifacts],
        }


@dataclass(frozen=True)
class DisposableCommandResult:
    command: list[str]
    cwd: str | None
    returncode: int
    stdout: str
    stderr: str
    ok: bool
    started_at: str = ""
    finished_at: str = ""
    elapsed_seconds: float | None = None

    @classmethod
    def from_completed(
        cls,
        command: list[str],
        cwd: Path | None,
        completed: subprocess.CompletedProcess[str],
    ) -> "DisposableCommandResult":
        return cls(
            command=command,
            cwd=str(cwd) if cwd is not None else None,
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            ok=completed.returncode == 0,
        )

    @classmethod
    def from_error(
        cls,
        command: list[str],
        cwd: Path | None,
        error: BaseException,
    ) -> "DisposableCommandResult":
        return cls(
            command=command,
            cwd=str(cwd) if cwd is not None else None,
            returncode=1,
            stdout="",
            stderr=str(error),
            ok=False,
        )

    def to_dict(self) -> dict[str, Any]:
        body = {
            "command": self.command,
            "cwd": self.cwd,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "ok": self.ok,
        }
        if self.started_at:
            body["startedAt"] = self.started_at
        if self.finished_at:
            body["finishedAt"] = self.finished_at
        if self.elapsed_seconds is not None:
            body["elapsedSeconds"] = self.elapsed_seconds
        return body


@dataclass(frozen=True)
class CleanupVerificationResult:
    command: list[str]
    result: DisposableCommandResult | None
    ok: bool
    remaining_count: int | None
    error: str | None
    checks: list[dict[str, Any]] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "result": self.result.to_dict() if self.result is not None else None,
            "ok": self.ok,
            "remainingCount": self.remaining_count,
            "error": self.error,
            "checks": self.checks or [],
        }


@dataclass(frozen=True)
class DisposableTerraformExecutionResult:
    target: OciDevelopmentTarget
    workspace: DisposableTerraformWorkspace
    workspace_dir: Path
    preflight: OciReadValidationResult
    commands_planned: list[list[str]]
    commands_run: list[DisposableCommandResult]
    created_resources: list[dict[str, Any]]
    destroyed_resources: list[dict[str, Any]]
    cleanup_verification: CleanupVerificationResult | None
    mutation_status: str
    final_cleanup_status: str

    @property
    def ok(self) -> bool:
        return self.mutation_status == "destroyed" and self.final_cleanup_status == "verified_clean"

    @property
    def did_mutate(self) -> bool:
        return self.mutation_status not in {
            "preflight_failed",
            "terraform_binary_unresolved",
            "terraform_init_failed",
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "workspace": WORKSPACE_NAME,
            "mode": "terraform_guarded_execute",
            "mutation": self.did_mutate,
            "target": _render_target_dict(self.target, mutation=self.did_mutate),
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
            "finalCleanupStatus": self.final_cleanup_status,
        }


def build_disposable_terraform_workspace(
    target: OciDevelopmentTarget | None = None,
    oci_executable: str = "oci",
) -> DisposableTerraformWorkspace:
    resolved_target = target or OciDevelopmentTarget()
    validate_disposable_terraform_target(resolved_target)
    resources = [
        {
            "provider": "oci",
            "type": "oci_core_vcn",
            "name": "barragan_disposable_validation",
            "displayName": VALIDATION_VCN_NAME,
            "cidrBlock": VALIDATION_VCN_CIDR,
            "compartmentId": resolved_target.compartment_id,
            "region": resolved_target.region,
            "expectedLifecycle": "create with terraform apply; remove with terraform destroy",
        }
    ]
    cleanup = {
        "expectedDestroyBehavior": "terraform destroy should remove the disposable VCN completely.",
        "verificationCommands": [
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
            "The verification command returns an empty data array for "
            f"{VALIDATION_VCN_NAME} after terraform destroy."
        ),
    }
    artifacts = [
        DisposableTerraformArtifact("versions.tf", _render_versions_tf()),
        DisposableTerraformArtifact("variables.tf", _render_variables_tf()),
        DisposableTerraformArtifact("main.tf", _render_main_tf()),
        DisposableTerraformArtifact("terraform.tfvars.json", _render_tfvars_json(resolved_target)),
        DisposableTerraformArtifact("MANIFEST.md", _render_manifest(resolved_target, resources, cleanup)),
    ]
    return DisposableTerraformWorkspace(
        target=resolved_target,
        resources=resources,
        cleanup=cleanup,
        artifacts=artifacts,
    )


def render_disposable_terraform_workspace(
    destination: Path,
    target: OciDevelopmentTarget | None = None,
    oci_executable: str = "oci",
) -> DisposableTerraformWorkspace:
    workspace = build_disposable_terraform_workspace(target, oci_executable=oci_executable)
    destination.mkdir(parents=True, exist_ok=True)
    for artifact in workspace.artifacts:
        artifact_path = destination / artifact.path
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(artifact.content, encoding="utf-8")
    return workspace


def execute_disposable_terraform_validation(
    workspace_dir: Path,
    target: OciDevelopmentTarget | None = None,
    runner: TerraformCommandRunner | None = None,
    preflight_runner: OciReadCommandRunner | None = None,
    env: Mapping[str, str] | None = None,
) -> DisposableTerraformExecutionResult:
    resolved_target = target or OciDevelopmentTarget()
    validate_disposable_terraform_target(resolved_target)
    terraform_resolution = resolve_terraform(env=env)
    oci_resolution = resolve_oci_cli(env=env)
    workspace = render_disposable_terraform_workspace(
        workspace_dir,
        resolved_target,
        oci_executable=oci_resolution.command or "oci",
    )
    commands_planned = build_disposable_execution_commands(
        workspace,
        terraform_executable=terraform_resolution.command or "terraform",
    )
    command_runner = runner or _run_command
    read_runner = preflight_runner or (lambda command: command_runner(command, None))
    commands_run: list[DisposableCommandResult] = []

    preflight = run_read_validation(resolved_target, runner=read_runner, env=env)
    if not preflight.ok:
        return DisposableTerraformExecutionResult(
            target=resolved_target,
            workspace=workspace,
            workspace_dir=workspace_dir,
            preflight=preflight,
            commands_planned=commands_planned,
            commands_run=commands_run,
            created_resources=[],
            destroyed_resources=[],
            cleanup_verification=None,
            mutation_status="preflight_failed",
            final_cleanup_status="not_started",
        )

    if not terraform_resolution.ok:
        commands_run.append(
            DisposableCommandResult.from_error(
                commands_planned[0],
                workspace_dir,
                RuntimeError(terraform_resolution.error or "Terraform executable was not resolved"),
            )
        )
        return _execution_result(
            resolved_target,
            workspace,
            workspace_dir,
            preflight,
            commands_planned,
            commands_run,
            mutation_status="terraform_binary_unresolved",
            final_cleanup_status="not_started",
        )

    init_result = _run_guarded_command(commands_planned[0], workspace_dir, command_runner)
    commands_run.append(init_result)
    if not init_result.ok:
        return _execution_result(
            resolved_target,
            workspace,
            workspace_dir,
            preflight,
            commands_planned,
            commands_run,
            mutation_status="terraform_init_failed",
            final_cleanup_status="not_started",
        )

    apply_result = _run_guarded_command(commands_planned[1], workspace_dir, command_runner)
    commands_run.append(apply_result)
    if not apply_result.ok:
        destroy_after_failed_apply = _run_guarded_command(
            commands_planned[2],
            workspace_dir,
            command_runner,
        )
        commands_run.append(destroy_after_failed_apply)
        cleanup = None
        if destroy_after_failed_apply.ok:
            cleanup = _verify_disposable_cleanup(workspace, command_runner)
            if cleanup.result is not None:
                commands_run.append(cleanup.result)
        return _execution_result(
            resolved_target,
            workspace,
            workspace_dir,
            preflight,
            commands_planned,
            commands_run,
            cleanup_verification=cleanup,
            created_resources=_summarize_resources(workspace, "create_attempted"),
            destroyed_resources=(
                _summarize_resources(workspace, "destroy_attempted")
                if destroy_after_failed_apply.ok
                else []
            ),
            mutation_status="apply_failed",
            final_cleanup_status=(
                "verified_clean" if cleanup is not None and cleanup.ok else "cleanup_not_verified"
            ),
        )

    destroy_result = _run_guarded_command(commands_planned[2], workspace_dir, command_runner)
    commands_run.append(destroy_result)
    if not destroy_result.ok:
        return _execution_result(
            resolved_target,
            workspace,
            workspace_dir,
            preflight,
            commands_planned,
            commands_run,
            created_resources=_summarize_resources(workspace, "created"),
            mutation_status="destroy_failed",
            final_cleanup_status="cleanup_not_verified",
        )

    cleanup = _verify_disposable_cleanup(workspace, command_runner)
    if cleanup.result is not None:
        commands_run.append(cleanup.result)

    return _execution_result(
        resolved_target,
        workspace,
        workspace_dir,
        preflight,
        commands_planned,
        commands_run,
        cleanup_verification=cleanup,
        created_resources=_summarize_resources(workspace, "created"),
        destroyed_resources=_summarize_resources(workspace, "destroyed"),
        mutation_status="destroyed",
        final_cleanup_status="verified_clean" if cleanup.ok else "cleanup_not_verified",
    )


def build_disposable_execution_commands(
    workspace: DisposableTerraformWorkspace,
    terraform_executable: str = "terraform",
) -> list[list[str]]:
    validate_disposable_terraform_target(workspace.target)
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
        ],
    ]


def resolve_terraform(
    *,
    env: Mapping[str, str] | None = None,
    fallback_paths: list[str | Path] | None = None,
) -> CommandResolution:
    return resolve_executable(
        "terraform",
        override_variables=TERRAFORM_OVERRIDE_VARIABLES,
        fallback_paths=fallback_paths if fallback_paths is not None else TERRAFORM_FALLBACK_PATHS,
        env=env,
        display_name="Terraform",
    )


def validate_disposable_terraform_target(target: OciDevelopmentTarget) -> None:
    target.validate()
    if target.region != DEFAULT_REGION:
        raise OciSafetyError(
            f"Disposable Barragan Terraform validation must target only {DEFAULT_REGION}"
        )


def _render_versions_tf() -> str:
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


def _render_target_dict(target: OciDevelopmentTarget, mutation: bool = False) -> dict[str, Any]:
    return {
        "name": target.name,
        "compartmentId": target.compartment_id,
        "region": target.region,
        "auth": target.auth,
        "mutation": mutation,
    }


def _render_variables_tf() -> str:
    return f"""variable "region" {{
  type        = string
  description = "OCI region for the disposable Barragan validation."

  validation {{
    condition     = var.region == "{DEFAULT_REGION}"
    error_message = "Disposable Barragan validation must target only {DEFAULT_REGION}."
  }}
}}

variable "compartment_ocid" {{
  type        = string
  description = "The barragan-testing compartment OCID. Do not point this workspace elsewhere."

  validation {{
    condition     = var.compartment_ocid == "{BARRAGAN_TESTING_COMPARTMENT_ID}"
    error_message = "Disposable Barragan validation must target only barragan-testing."
  }}
}}
"""


def _render_main_tf() -> str:
    return f"""provider "oci" {{
  region = var.region
  auth   = "InstancePrincipal"
}}

resource "oci_core_vcn" "barragan_disposable_validation" {{
  compartment_id = var.compartment_ocid
  display_name   = "{VALIDATION_VCN_NAME}"
  cidr_block     = "{VALIDATION_VCN_CIDR}"
  dns_label      = "barraganval"
}}

output "validation_vcn_id" {{
  value = oci_core_vcn.barragan_disposable_validation.id
}}
"""


def _render_tfvars_json(target: OciDevelopmentTarget) -> str:
    return (
        "{\n"
        f'  "region": "{target.region}",\n'
        f'  "compartment_ocid": "{target.compartment_id}"\n'
        "}\n"
    )


def _render_manifest(
    target: OciDevelopmentTarget,
    resources: list[dict[str, Any]],
    cleanup: dict[str, Any],
) -> str:
    command = " ".join(cleanup["verificationCommands"][0])
    resource_lines = "\n".join(
        (
            f"- `{resource['type']}.{resource['name']}` named "
            f"`{resource['displayName']}` in `{resource['region']}`"
        )
        for resource in resources
    )
    return f"""# Barragan Disposable OCI Terraform Validation

This workspace is a render/preview artifact only. Rendering it does not run
`terraform init`, `terraform plan`, `terraform apply`, `terraform destroy`, or
any OCI write command.

## Target

- Compartment: `barragan-testing`
- Compartment OCID: `{target.compartment_id}`
- Region: `{target.region}`
- Auth mode for future execution: OCI Instance Principal

## Expected Create

{resource_lines}

## Expected Destroy

Future explicit `terraform destroy` execution should remove every resource listed
above. The workspace is intentionally limited to one disposable VCN so cleanup is
easy to inspect.

## Cleanup Verification

After a future explicit destroy, verify cleanup with:

```sh
{command}
```

Cleanup is successful when the command returns an empty `data` array for
`{VALIDATION_VCN_NAME}`.
"""


def rendered_artifacts_contain_no_no_touch_compartment_ids(
    workspace: DisposableTerraformWorkspace,
) -> bool:
    no_touch_ids = {BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID}
    return not any(
        no_touch_id in artifact.content
        for artifact in workspace.artifacts
        for no_touch_id in no_touch_ids
    )


def _run_command(command: list[str], cwd: Path | None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _run_guarded_command(
    command: list[str],
    cwd: Path | None,
    runner: TerraformCommandRunner,
) -> DisposableCommandResult:
    try:
        completed = runner(command, cwd)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return DisposableCommandResult.from_error(command, cwd, exc)
    return DisposableCommandResult.from_completed(command, cwd, completed)


def _verify_disposable_cleanup(
    workspace: DisposableTerraformWorkspace,
    runner: TerraformCommandRunner,
) -> CleanupVerificationResult:
    command = workspace.cleanup["verificationCommands"][0]
    result = _run_guarded_command(command, None, runner)
    if not result.ok:
        return CleanupVerificationResult(
            command=command,
            result=result,
            ok=False,
            remaining_count=None,
            error=(result.stderr or result.stdout).strip() or "cleanup verification failed",
        )

    try:
        body = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        return CleanupVerificationResult(
            command=command,
            result=result,
            ok=False,
            remaining_count=None,
            error=str(exc),
        )

    data = body.get("data", [])
    if not isinstance(data, list):
        return CleanupVerificationResult(
            command=command,
            result=result,
            ok=False,
            remaining_count=None,
            error="cleanup verification did not return a data array",
        )

    return CleanupVerificationResult(
        command=command,
        result=result,
        ok=len(data) == 0,
        remaining_count=len(data),
        error=None if len(data) == 0 else "disposable resources still present",
    )


def _execution_result(
    target: OciDevelopmentTarget,
    workspace: DisposableTerraformWorkspace,
    workspace_dir: Path,
    preflight: OciReadValidationResult,
    commands_planned: list[list[str]],
    commands_run: list[DisposableCommandResult],
    *,
    cleanup_verification: CleanupVerificationResult | None = None,
    created_resources: list[dict[str, Any]] | None = None,
    destroyed_resources: list[dict[str, Any]] | None = None,
    mutation_status: str,
    final_cleanup_status: str,
) -> DisposableTerraformExecutionResult:
    return DisposableTerraformExecutionResult(
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
        final_cleanup_status=final_cleanup_status,
    )


def _summarize_resources(
    workspace: DisposableTerraformWorkspace,
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
