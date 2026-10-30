# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from typing import Mapping

from app.integrations.command_resolution import CommandResolution, resolve_executable


from app.integrations.oci_deployment_targets import (
    BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID,
    BARRAGAN_TESTING_COMPARTMENT_ID,
    BARRAGAN_TESTING_TARGET,
    DEFAULT_OCI_REGION,
    NO_TOUCH_COMPARTMENT_IDS,
    NO_TOUCH_COMPARTMENT_NAMES,
)


DEFAULT_REGION = DEFAULT_OCI_REGION
DEFAULT_AUTH = "instance_principal"
OCI_CLI_OVERRIDE_VARIABLE = "OCI_CLI_PATH"
OCI_CLI_FALLBACK_PATH = Path.home() / ".local/bin/oci"

class OciSafetyError(ValueError):
    pass


@dataclass(frozen=True)
class OciDevelopmentTarget:
    name: str = BARRAGAN_TESTING_TARGET.name
    compartment_id: str = BARRAGAN_TESTING_TARGET.compartment_id
    parent_compartment_id: str = BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID
    region: str = DEFAULT_REGION
    auth: str = DEFAULT_AUTH

    def validate(self) -> None:
        validate_barragan_testing_target(self.compartment_id, self.name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "compartmentId": self.compartment_id,
            "parentCompartmentId": self.parent_compartment_id,
            "region": self.region,
            "auth": self.auth,
            "mutation": False,
        }
@dataclass(frozen=True)
class OciReadCheck:
    id: str
    service: str
    operation: str
    command: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "service": self.service,
            "operation": self.operation,
            "command": self.command,
        }


@dataclass(frozen=True)
class OciReadCheckResult:
    check: OciReadCheck
    ok: bool
    count: int | None
    error: str | None

    def to_dict(self) -> dict[str, Any]:
        body = self.check.to_dict()
        body.update({"ok": self.ok, "count": self.count, "error": self.error})
        return body


@dataclass(frozen=True)
class OciReadValidationResult:
    target: OciDevelopmentTarget
    checks: list[OciReadCheckResult]
    command_resolution: CommandResolution

    @property
    def ok(self) -> bool:
        return all(check.ok for check in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "mode": "read_only",
            "mutation": False,
            "target": self.target.to_dict(),
            "commandResolution": _command_resolution_dict(self.command_resolution),
            "checks": [check.to_dict() for check in self.checks],
        }


CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def validate_barragan_testing_target(compartment_id: str, name: str | None = None) -> None:
    if name in NO_TOUCH_COMPARTMENT_NAMES:
        raise OciSafetyError(f"refusing OCI validation against no-touch compartment {name}")
    if compartment_id in NO_TOUCH_COMPARTMENT_IDS:
        raise OciSafetyError("refusing OCI validation against parent RedTeam compartment")
    if name is not None and name != BARRAGAN_TESTING_TARGET.name:
        raise OciSafetyError("Barragan OCI validation target name must be barragan-testing")
    if compartment_id != BARRAGAN_TESTING_COMPARTMENT_ID:
        raise OciSafetyError("Barragan OCI validation must target only barragan-testing")


def resolve_oci_cli(
    *,
    env: Mapping[str, str] | None = None,
    fallback_paths: list[str | Path] | None = None,
) -> CommandResolution:
    return resolve_executable(
        "oci",
        override_variables=[OCI_CLI_OVERRIDE_VARIABLE],
        fallback_paths=fallback_paths if fallback_paths is not None else [OCI_CLI_FALLBACK_PATH],
        env=env,
        display_name="OCI CLI",
    )


def build_read_checks(
    target: OciDevelopmentTarget,
    oci_executable: str = "oci",
) -> list[OciReadCheck]:
    target.validate()
    base = [oci_executable, "--auth", target.auth, "--region", target.region]
    scope = ["--compartment-id", target.compartment_id, "--all", "--output", "json"]
    return [
        OciReadCheck(
            id="oci.core.vcn.list",
            service="core-network",
            operation="list VCNs",
            command=[*base, "network", "vcn", "list", *scope],
        ),
        OciReadCheck(
            id="oci.core.boot-volume.list",
            service="core-volume",
            operation="list boot volumes",
            command=[*base, "bv", "boot-volume", "list", *scope],
        ),
    ]


def run_read_validation(
    target: OciDevelopmentTarget | None = None,
    runner: CommandRunner | None = None,
    env: Mapping[str, str] | None = None,
) -> OciReadValidationResult:
    resolved_target = target or OciDevelopmentTarget()
    oci_resolution = resolve_oci_cli(env=env)
    checks = build_read_checks(resolved_target, oci_resolution.command or "oci")
    if not oci_resolution.ok:
        return OciReadValidationResult(
            target=resolved_target,
            command_resolution=oci_resolution,
            checks=[
                OciReadCheckResult(
                    check=check,
                    ok=False,
                    count=None,
                    error=oci_resolution.error,
                )
                for check in checks
            ],
        )
    command_runner = runner or _run_command
    results = [_run_check(check, command_runner) for check in checks]
    return OciReadValidationResult(
        target=resolved_target,
        checks=results,
        command_resolution=oci_resolution,
    )


def _run_check(check: OciReadCheck, runner: CommandRunner) -> OciReadCheckResult:
    try:
        completed = runner(check.command)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return OciReadCheckResult(check=check, ok=False, count=None, error=str(exc))
    if completed.returncode != 0:
        return OciReadCheckResult(
            check=check,
            ok=False,
            count=None,
            error=(completed.stderr or completed.stdout).strip() or "OCI command failed",
        )
    try:
        body = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        return OciReadCheckResult(check=check, ok=False, count=None, error=str(exc))

    data = body.get("data", [])
    count = len(data) if isinstance(data, list) else None
    return OciReadCheckResult(check=check, ok=True, count=count, error=None)


def _run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)


def _command_resolution_dict(resolution: CommandResolution) -> dict[str, Any]:
    return {
        "binaryName": resolution.binary_name,
        "command": resolution.command,
        "source": resolution.source,
        "overrideVariables": list(resolution.override_variables),
        "ok": resolution.ok,
        "error": resolution.error,
    }
