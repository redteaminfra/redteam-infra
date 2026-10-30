# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class TerraformCommandResult:
    command: str
    returncode: int
    stdout: str
    stderr: str


class TerraformCommandRunner(Protocol):
    def run(
        self,
        command: str,
        *,
        working_directory: str,
        env: dict[str, str],
        variables: dict[str, Any] | None = None,
        targets: tuple[str, ...] = (),
        refresh: bool = True,
        saved_plan_path: str | Path | None = None,
        readonly_lock: bool = False,
        backend: bool = True,
        inherit_environment: bool = True,
    ) -> TerraformCommandResult:
        ...


MAX_TERRAFORM_DIAGNOSTIC_CHARS = 4000
SECRETISH_KEY_PARTS = (
    "api_key",
    "apikey",
    "do_pat",
    "linode_api_token",
    "password",
    "private_key",
    "privatekey",
    "secret",
    "token",
)
SECRETISH_VALUE_PATTERNS = (
    re.compile(r"\b(api[_ -]?key|apikey|do[_ -]?pat|linode[_ -]?api[_ -]?token|password|passwd|private[_ -]?key|secret|token)\s*[:=]\s*['\"]?[^'\"\s,]+", re.IGNORECASE),
    re.compile(r"\bbearer\s+[a-z0-9._~+/=-]+", re.IGNORECASE),
)
ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
RESOURCE_HINT_PATTERNS = (
    re.compile(r"\bwith\s+([A-Za-z0-9_]+\.[A-Za-z0-9_.\-[\]\"']+)"),
    re.compile(r"^([A-Za-z0-9_]+\.[A-Za-z0-9_.-]+):", re.MULTILINE),
)


class LocalTerraformCommandRunner:
    def __init__(self, binary: str = "terraform"):
        self.binary = binary

    def run(
        self,
        command: str,
        *,
        working_directory: str,
        env: dict[str, str],
        variables: dict[str, Any] | None = None,
        targets: tuple[str, ...] = (),
        refresh: bool = True,
        saved_plan_path: str | Path | None = None,
        readonly_lock: bool = False,
        backend: bool = True,
        inherit_environment: bool = True,
    ) -> TerraformCommandResult:
        args = [self.binary, command]
        if command == "init":
            if variables or targets or saved_plan_path is not None or not refresh:
                raise ValueError("terraform init does not accept planning options")
            args.append("-input=false")
            if not backend:
                args.append("-backend=false")
            if readonly_lock:
                args.append("-lockfile=readonly")
        elif command == "version":
            if variables or targets or saved_plan_path is not None or not refresh or readonly_lock or not backend:
                raise ValueError("terraform version does not accept planning options")
            args.append("-json")
        elif command == "plan":
            if readonly_lock or not backend:
                raise ValueError("terraform plan does not accept init options")
            # Terraform returns 2 when -detailed-exitcode finds changes.  The
            # caller must inspect that result and decide whether the change
            # set is acceptable before it invokes apply.
            args.extend(["-input=false", "-detailed-exitcode", "-json"])
            if not refresh:
                args.append("-refresh=false")
            if saved_plan_path is not None:
                args.append(f"-out={saved_plan_path}")
            args.extend(f"-target={target}" for target in targets)
            args.extend(_variable_args(variables or {}))
        elif command == "apply":
            if readonly_lock or not backend:
                raise ValueError("terraform apply does not accept init options")
            args.extend(["-input=false", "-auto-approve"])
            if saved_plan_path is not None:
                if variables or targets or not refresh:
                    raise ValueError("saved Terraform plans must be applied without variables, targets, or refresh options")
                args.append(str(saved_plan_path))
            else:
                if not refresh:
                    args.append("-refresh=false")
                args.extend(f"-target={target}" for target in targets)
                args.extend(_variable_args(variables or {}))
        elif command == "destroy":
            if readonly_lock or not backend:
                raise ValueError("terraform destroy does not accept init options")
            args.extend(["-input=false", "-auto-approve", *_variable_args(variables or {})])
        elif command == "show":
            if readonly_lock or not backend:
                raise ValueError("terraform show does not accept init options")
            if saved_plan_path is None:
                raise ValueError("terraform show requires a saved plan path")
            args.extend(["-json", str(saved_plan_path)])
        elif command == "output":
            if readonly_lock or not backend:
                raise ValueError("terraform output does not accept init options")
            args.append("-json")
        else:
            raise ValueError(f"unsupported terraform command: {command}")

        process = subprocess.run(
            args,
            cwd=Path(working_directory),
            env={**os.environ, **env} if inherit_environment else dict(env),
            check=False,
            capture_output=True,
            text=True,
        )
        return TerraformCommandResult(
            command=command,
            returncode=process.returncode,
            stdout=process.stdout,
            stderr=process.stderr,
        )


def _variable_args(variables: dict[str, Any]) -> list[str]:
    args = []
    for key, value in sorted(variables.items()):
        args.extend(["-var", f"{key}={_variable_value(value)}"])
    return args


def _variable_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value)


def terraform_failure_diagnostic(
    result: TerraformCommandResult,
    *,
    provider: str,
    env: dict[str, str] | None = None,
    variables: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a bounded, redacted Terraform failure summary for job event data."""

    sensitive_values = _sensitive_values(env or {}, variables or {})
    stdout = _sanitize_terraform_output(result.stdout, sensitive_values)
    stderr = _sanitize_terraform_output(result.stderr, sensitive_values)
    combined = "\n".join(part for part in (stderr, stdout) if part.strip())
    diagnostic: dict[str, Any] = {
        "provider": provider,
        "command": result.command,
        "returnCode": result.returncode,
        "errorClass": _classify_terraform_failure(combined),
        "summary": _diagnostic_summary(combined),
        "resourceHints": _resource_hints(combined),
    }
    if stderr.strip():
        diagnostic["stderrExcerpt"] = _truncate(stderr, MAX_TERRAFORM_DIAGNOSTIC_CHARS)
    if stdout.strip():
        diagnostic["stdoutExcerpt"] = _truncate(stdout, MAX_TERRAFORM_DIAGNOSTIC_CHARS)
    return diagnostic


def _sensitive_values(env: dict[str, str], variables: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key, value in {**env, **{key: _variable_value(value) for key, value in variables.items()}}.items():
        lowered = str(key).lower()
        if any(marker in lowered for marker in SECRETISH_KEY_PARTS):
            text = str(value or "").strip()
            if len(text) >= 6:
                values.append(text)
    return sorted(set(values), key=len, reverse=True)


def _sanitize_terraform_output(value: str, sensitive_values: list[str]) -> str:
    redacted = ANSI_ESCAPE_PATTERN.sub("", str(value or ""))
    for secret in sensitive_values:
        redacted = redacted.replace(secret, "[REDACTED]")
    for pattern in SECRETISH_VALUE_PATTERNS:
        redacted = pattern.sub(lambda match: _redact_assignment(match.group(0)), redacted)
    return _truncate(redacted.strip(), MAX_TERRAFORM_DIAGNOSTIC_CHARS)


def _redact_assignment(value: str) -> str:
    if value.lower().startswith("bearer "):
        return "Bearer [REDACTED]"
    separator_index = -1
    for separator in (":", "="):
        candidate = value.find(separator)
        if candidate >= 0 and (separator_index < 0 or candidate < separator_index):
            separator_index = candidate
    if separator_index < 0:
        return "[REDACTED]"
    return value[: separator_index + 1] + " [REDACTED]"


def _diagnostic_summary(value: str) -> str:
    lines = _meaningful_lines(value)
    if not lines:
        return "Terraform command failed without stdout or stderr."
    selected = []
    for line in lines:
        lowered = line.lower()
        if "error:" in lowered or lowered.startswith("error ") or "failed" in lowered:
            selected.append(line)
        if len(selected) >= 4:
            break
    if not selected:
        selected = lines[:4]
    return _truncate(" | ".join(selected), 1000)


def _resource_hints(value: str) -> list[str]:
    hints: list[str] = []
    for pattern in RESOURCE_HINT_PATTERNS:
        for match in pattern.finditer(value):
            hint = match.group(1).strip(" ,")
            if hint and hint not in hints:
                hints.append(hint)
            if len(hints) >= 8:
                return hints
    return hints


def _classify_terraform_failure(value: str) -> str:
    lowered = value.lower()
    if any(marker in lowered for marker in ("unauthorized", "forbidden", "invalid token", "authentication", "permission denied", "access denied")):
        return "auth_failed"
    if "quota" in lowered or "limit exceeded" in lowered or "too many" in lowered:
        return "quota_exceeded"
    if any(marker in lowered for marker in ("capacity", "insufficient", "out of stock")):
        return "capacity_exhausted"
    if "region" in lowered and any(marker in lowered for marker in ("invalid", "unsupported", "not available")):
        return "invalid_region"
    if any(marker in lowered for marker in ("invalid", "validation", "malformed", "bad request", "exceeds maximum", "must be")):
        return "provider_api_permanent"
    if any(marker in lowered for marker in ("timeout", "temporarily", "rate limit", "try again", "connection reset")):
        return "provider_api_transient"
    return "terraform_failed"


def _meaningful_lines(value: str) -> list[str]:
    lines = []
    for raw_line in value.splitlines():
        line = raw_line.strip(" │╷╵")
        if line:
            lines.append(line)
    return lines


def _truncate(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    return value[:max_chars] + "\n[truncated]"
