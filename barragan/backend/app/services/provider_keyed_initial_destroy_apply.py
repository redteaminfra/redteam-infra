# Copyright (c) 2026, Oracle and/or its affiliates.
"""DevTest-only exact saved-plan destroy boundary for a complete keyed DO state.

There is deliberately no runtime caller. Terraform's success is not provider
absence proof, and the returned result must not mark an engagement cleaned up.
"""

from __future__ import annotations

import fcntl
import json
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping
from uuid import UUID

from app.services.provider_keyed_initial_plan_gate import _verify_audited_workspace
from app.services.provider_keyed_initial_teardown import (
    DigitalOceanTeardownIntent,
    DigitalOceanTeardownPreview,
    _require_exact_state,
    require_exact_digitalocean_destroy_plan,
)
from app.services.provider_keyed_saved_plan_runner import (
    _ENV_ALLOWLIST,
    _credential_snapshot,
    _hash_file,
    _ordinal_lock,
    _require_canonical_workspace_paths,
    _require_nodes_match_topology,
    _require_plan_topology_variables,
    _topology_hash,
    _unsafe_keyed_workspace,
    _verify_input_hashes,
)
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, SCHEMA, _write_json
from app.storage.credential_repository import CredentialRepository


CommandRunner = Callable[[list[str], Path, Mapping[str, str]], subprocess.CompletedProcess[str]]
_PLAN_NAME = ".barragan-initial-destroy.tfplan"
_PHASE_NAME = ".barragan-apply-phase.json"


class ProviderKeyedInitialDestroyApplyError(ValueError):
    """Redacted failure; inspect the retained plan, phase and state."""


class ProviderKeyedInitialDestroyApplyUncertainError(ProviderKeyedInitialDestroyApplyError):
    """The command or phase outcome is unproved; retain files for reconciliation."""


@dataclass(frozen=True)
class ProviderKeyedInitialDestroyApplyResult:
    state_sha256: str
    provider_absence_proof_pending: bool = True


def apply_digitalocean_keyed_initial_destroy_plan(
    workspace: ProviderKeyedWorkspace,
    preview: DigitalOceanTeardownPreview,
    intent: DigitalOceanTeardownIntent,
    *,
    environment: str,
    deployment_target: str,
    expected_terraform_sha256: str,
    credential_repository: CredentialRepository,
    command_environment: Mapping[str, str],
    command_runner: CommandRunner | None = None,
    phase_write_intent: Callable[[Path, str], None] | None = None,
    expected_topology_path: Path | None = None,
    expected_topology_sha256: str | None = None,
) -> ProviderKeyedInitialDestroyApplyResult:
    """Apply one exact reviewed full-state destroy plan under both locks."""

    if environment != "devtest" or deployment_target != "barragan-testing":
        raise ProviderKeyedInitialDestroyApplyError("destroy apply requires disposable DevTest scope")
    if (not isinstance(workspace, ProviderKeyedWorkspace)
            or workspace.provider != "digitalocean" or workspace.schema != SCHEMA
            or not isinstance(preview, DigitalOceanTeardownPreview)
            or not isinstance(intent, DigitalOceanTeardownIntent)
            or any(key.upper().startswith("TF_") for key in command_environment)):
        raise ProviderKeyedInitialDestroyApplyError("destroy apply scope or evidence is invalid")
    root = workspace.path
    if expected_topology_path is not None or expected_topology_sha256 is not None:
        canonical_append = (root.parents[1] / ".plan-material" / "digitalocean"
                            / "append-inputs.json")
        if (not isinstance(expected_topology_path, Path)
                or type(expected_topology_sha256) is not str
                or len(preview.input_sha256) != 1
                or expected_topology_path != canonical_append
                or preview.input_sha256[0]
                   != (str(expected_topology_path), expected_topology_sha256)):
            raise ProviderKeyedInitialDestroyApplyError(
                "destroy append topology differs from reviewed input")
    if root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise ProviderKeyedInitialDestroyApplyError("destroy workspace path is unsafe")
    try:
        _require_canonical_workspace_paths(workspace)
        lock_path = root / ".barragan-initial-full-plan.lock"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "r+b") as lock:
            info = os.fstat(lock.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise ValueError("workspace lock is unsafe")
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                # The preview takes workspace then ordinal; never reverse it.
                with _ordinal_lock(workspace):
                    return _apply_locked(
                        workspace, preview, intent, expected_terraform_sha256,
                        credential_repository, command_environment,
                        command_runner or _run_command, phase_write_intent,
                        expected_topology_path, expected_topology_sha256,
                    )
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except ProviderKeyedInitialDestroyApplyUncertainError:
        raise ProviderKeyedInitialDestroyApplyUncertainError(
            "keyed destroy apply outcome unproved; inspect retained plan, phase and state"
        ) from None
    except Exception:
        raise ProviderKeyedInitialDestroyApplyError(
            "keyed destroy apply failed; inspect retained plan, phase and state"
        ) from None


def _apply_locked(
    workspace: ProviderKeyedWorkspace,
    preview: DigitalOceanTeardownPreview,
    intent: DigitalOceanTeardownIntent,
    expected_terraform_sha256: str,
    repository: CredentialRepository,
    command_environment: Mapping[str, str],
    run: CommandRunner, phase_write_intent: Callable[[Path, str], None] | None,
    expected_topology_path: Path | None, expected_topology_sha256: str | None,
) -> ProviderKeyedInitialDestroyApplyResult:
    root = workspace.path
    plan_path = root / _PLAN_NAME
    phase_path = root / _PHASE_NAME
    _verify_audited_workspace(workspace)
    if _unsafe_keyed_workspace(root):
        raise ValueError("workspace is not private")
    if (preview.plan_path != plan_path or plan_path.is_symlink() or not plan_path.is_file()
            or plan_path.stat().st_mode & 0o077
            or _hash_file(plan_path) != preview.plan_sha256):
        raise ValueError("saved destroy plan changed")
    if (preview.source_sha256 != workspace.source_sha256
            or _topology_hash(workspace) != preview.topology_sha256
            or _hash_file(root / ".barragan-provider-keyed-state.json") != preview.marker_sha256
            or _hash_file(root / ".terraform.lock.hcl") != preview.lockfile_sha256):
        raise ValueError("reviewed source or topology changed")
    if (phase_path.is_symlink() or json.loads(phase_path.read_text(encoding="utf-8"))
            != {"schema": SCHEMA, "phase": "applied"}
            or _hash_file(phase_path) != preview.phase_sha256):
        raise ValueError("destroy phase changed")
    if (intent.state_sha256 != preview.state_sha256
            or intent.credential_record_id != preview.credential_record_id
            or intent.credential_secret_sha256 != preview.credential_secret_sha256
            or intent.credential_updated_at != preview.credential_updated_at
            or intent.credential_record_id != workspace.provider_connection_id):
        raise ValueError("independent teardown intent differs from preview")
    _require_nodes_match_topology(
        workspace, intent.nodes, intent.firewall,
        expected_topology_path=expected_topology_path,
        expected_topology_sha256=expected_topology_sha256)
    state = _require_exact_state(workspace, intent)
    _verify_input_hashes(preview.input_sha256)
    digest, updated_at, _ = _credential_snapshot(intent.credential_record_id, repository)
    if (digest, updated_at) != (intent.credential_secret_sha256, intent.credential_updated_at):
        raise ValueError("provider credential changed")
    terraform_path = preview.terraform_binary_path
    if (not terraform_path.is_absolute() or not os.access(terraform_path, os.X_OK)
            or expected_terraform_sha256 != preview.terraform_binary_sha256
            or _hash_file(terraform_path) != expected_terraform_sha256):
        raise ValueError("Terraform binary changed")
    env = {key: value for key, value in command_environment.items() if key in _ENV_ALLOWLIST}
    env["TF_DATA_DIR"] = str(workspace.terraform_data_dir)
    env["TF_CLI_CONFIG_FILE"] = "/dev/null"
    terraform = str(terraform_path)
    shown = run([terraform, "show", "-json", str(plan_path)], root, env)
    if shown.returncode or _hash_file(plan_path) != preview.plan_sha256:
        raise ValueError("saved destroy plan inspection failed")
    require_exact_digitalocean_destroy_plan(
        shown.stdout, expected_resource_ids=intent.resource_ids, state=state,
    )
    _require_plan_topology_variables(
        shown.stdout, workspace,
        expected_topology_path=expected_topology_path,
        expected_topology_sha256=expected_topology_sha256)
    # No mutation, including a phase write, precedes this last validation.
    _verify_audited_workspace(workspace)
    _require_exact_state(workspace, intent)
    _verify_input_hashes(preview.input_sha256)
    if (_hash_file(plan_path) != preview.plan_sha256
            or _topology_hash(workspace) != preview.topology_sha256
            or _hash_file(root / ".barragan-provider-keyed-state.json") != preview.marker_sha256
            or _hash_file(root / ".terraform.lock.hcl") != preview.lockfile_sha256
            or _hash_file(phase_path) != preview.phase_sha256
            or _hash_file(terraform_path) != expected_terraform_sha256):
        raise ValueError("reviewed destroy inputs changed")
    digest, updated_at, _ = _credential_snapshot(intent.credential_record_id, repository)
    if (digest, updated_at) != (intent.credential_secret_sha256, intent.credential_updated_at):
        raise ValueError("provider credential changed")
    if phase_write_intent is not None:
        phase_write_intent(phase_path, "destroy_started")
    _write_json(phase_path, {"schema": SCHEMA, "phase": "destroy_started"})
    applied = run(
        [terraform, "apply", "-input=false", "-lock=true", "-no-color", str(plan_path)],
        root, env,
    )
    if applied.returncode or _hash_file(plan_path) != preview.plan_sha256:
        raise ValueError("Terraform destroy failed or plan changed; reconciliation required")
    state_sha = _require_empty_retained_state(workspace, state)
    if phase_write_intent is not None:
        phase_write_intent(phase_path, "destroy_applied")
    _write_json(phase_path, {"schema": SCHEMA, "phase": "destroy_applied"})
    return ProviderKeyedInitialDestroyApplyResult(state_sha)


def _require_empty_retained_state(workspace: ProviderKeyedWorkspace, before: Mapping[str, object]) -> str:
    path = workspace.state_path
    if path.is_symlink() or not path.is_file():
        raise ValueError("destroy returned without retained state")
    after = json.loads(path.read_text(encoding="utf-8"))
    UUID(after["lineage"])
    if (after.get("version") != 4 or after.get("terraform_version") != "1.15.5"
            or after.get("lineage") != before.get("lineage")
            or type(after.get("serial")) is not int
            or after["serial"] <= before["serial"]
            or after.get("resources") != []):
        raise ValueError("destroy retained partial or unrelated state")
    return _hash_file(path)


def _run_command(args: list[str], cwd: Path, env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, env=dict(env), capture_output=True, text=True, check=False)
