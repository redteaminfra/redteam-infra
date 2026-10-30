# Copyright (c) 2026, Oracle and/or its affiliates.
"""Non-applying saved-plan runner for one keyed DigitalOcean edge append.

The active four-node topology and ordinal ledger stay untouched. The caller
must independently audit the published source, proposed edge and inputs; this
runner only binds a durable binary plan to the retained state and pure gate.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from app.services.credentials import decrypt_secret_value
from app.services.provider_keyed_append_plan_gate import require_digitalocean_keyed_edge_append_full_plan
from app.services.provider_keyed_initial_plan_gate import (
    DigitalOceanInitialFirewallIntent, DigitalOceanNodeCreate, _verify_audited_workspace,
)
from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_saved_plan_runner import (
    _ENV_ALLOWLIST, _check_inputs, _credential_snapshot, _hash_file,
    _ordinal_lock, _remove_owned_plan, _require_canonical_workspace_paths,
    _require_provider_lock, _resolve_terraform, _run_command,
    _stage_credential, _stage_var_files, _topology_hash, _verify_input_hashes,
    _unsafe_keyed_workspace,
)
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.terraform_plan_gate import TerraformPlanGateError
from app.storage.credential_repository import CredentialRepository


class ProviderKeyedAppendPlanPreparationError(ValueError):
    """The retained-state append plan could not be safely saved."""

    def __init__(self, stage: str, reason_code: str | None = None):
        self.stage = stage
        self.reason_code = (reason_code if stage == "saved_plan_gate"
                            and reason_code in _APPEND_GATE_REASON_CODES.values() else None)
        super().__init__("saved append plan preparation failed; no apply was attempted")


# Only fixed text raised by the pure append gate is safe for the job journal.
# Never persist Terraform output or arbitrary exception messages.
_APPEND_GATE_REASON_CODES = {
    "append Terraform inputs differ from reviewed intent": "terraform_inputs_differ",
    "append edge inputs or provider-computed fields differ": "edge_fields_differ",
    "append edge intent is incomplete": "edge_intent_incomplete",
    "append edge is not an exact create": "edge_create_differs",
    "append firewall egress differs from reviewed baseline": "firewall_egress_differs",
    "append firewall ingress is not the pinned unknown-peer expression": "firewall_ingress_expression_differs",
    "append firewall pending metadata is invalid": "firewall_pending_metadata_invalid",
    "append firewall prior ingress is not the reviewed baseline": "firewall_prior_ingress_differs",
    "append firewall selector, egress, or metadata changed": "firewall_identity_or_metadata_changed",
    "append firewall unknown or sensitive policy differs": "firewall_unknown_or_sensitive_differs",
    "append firewall update lacks retained identity": "firewall_update_identity_differs",
    "append local artifact has unreviewed content or path": "local_artifact_content_or_path_differs",
    "append local artifact replacement differs": "local_artifact_replacement_differs",
    "append plan changes a retained node or SSH key": "retained_node_or_key_changed",
    "append plan has unexpected or duplicate resource": "unexpected_or_duplicate_resource",
    "append plan omits a retained or new resource": "resource_omitted",
    "append prior state differs from retained state": "prior_state_differs",
    "append prior state has unreviewed resource": "prior_state_unreviewed_resource",
    "append prior state omits retained resource": "prior_state_resource_omitted",
    "append prior state resource is invalid": "prior_state_resource_invalid",
    "append resource metadata differs from audited provider": "resource_metadata_differs",
    "append retained SSH key ID is invalid": "retained_key_id_invalid",
    "append retained local artifact metadata is invalid": "retained_local_artifact_invalid",
    "append retained node identity or selector changed": "retained_node_identity_changed",
    "append retained peer IP is invalid": "retained_peer_ip_invalid",
    "append retained peer IPs collide": "retained_peer_ips_collide",
    "append retained resource set is not the reviewed two-chain pilot": "retained_resource_set_differs",
    "append retained state is missing": "retained_state_missing",
    "append reviewed Terraform variables are incomplete": "reviewed_variables_incomplete",
    "append reviewed edge or inventory intent is invalid": "reviewed_edge_or_inventory_invalid",
    "append saved plan is not JSON": "saved_plan_invalid_json",
    "append saved plan omits retained state": "saved_plan_prior_state_missing",
    "append saved plan version, status, or drift is invalid": "saved_plan_status_or_drift_invalid",
}


@dataclass(frozen=True)
class ProviderKeyedAppendPlanEvidence:
    plan_path: Path
    plan_sha256: str
    state_sha256: str
    topology_sha256: str
    source_sha256: str
    lockfile_sha256: str
    input_sha256: tuple[tuple[str, str], ...]
    credential_record_id: str
    credential_secret_sha256: str
    credential_updated_at: str
    terraform_binary_path: Path
    terraform_binary_sha256: str


def prepare_digitalocean_keyed_edge_append_plan(
    workspace: ProviderKeyedWorkspace, *,
    retained_state_sha256: str,
    retained_resources: Mapping[str, Mapping[str, object]],
    new_edge_address: str,
    new_edge: DigitalOceanNodeCreate,
    firewall: DigitalOceanInitialFirewallIntent,
    expected_inventory_content: str,
    reviewed_variables: Mapping[str, object],
    input_sha256: Mapping[Path, str], var_files: Sequence[Path],
    credential_repository: CredentialRepository,
    command_environment: Mapping[str, str],
    expected_terraform_sha256: str,
    environment: str, deployment_target: str,
    terraform: str = "terraform",
    command_runner: Callable[[list[str], Path, Mapping[str, str]], subprocess.CompletedProcess[str]] | None = None,
) -> ProviderKeyedAppendPlanEvidence:
    """Save one exact append plan against unchanged, already-owned state.

    No API calls this helper yet. The caller must keep its engagement lease
    while it runs and prove provider membership before a future live plan.
    """
    if (environment != "devtest" or deployment_target != "barragan-testing"
            or not isinstance(workspace, ProviderKeyedWorkspace)
            or workspace.provider != "digitalocean"
            or any(key.upper().startswith("TF_") for key in command_environment)):
        raise ProviderKeyedAppendPlanPreparationError("boundary")
    root = workspace.path
    if root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise ProviderKeyedAppendPlanPreparationError("workspace")
    plan_path = root / ".barragan-edge-append.tfplan"
    stage = "preflight"
    try:
        _require_canonical_workspace_paths(workspace)
        inputs = _check_inputs(root, input_sha256, var_files)
        lock_path = root / ".barragan-initial-full-plan.lock"
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(lock_fd, "r+b") as lock:
            info = os.fstat(lock.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise ValueError("append workspace plan lock is unsafe")
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                with _ordinal_lock(workspace):
                    stage = "saved_plan"
                    return _prepare_locked(
                        workspace, plan_path, retained_state_sha256,
                        retained_resources, new_edge_address, new_edge, firewall,
                        expected_inventory_content, reviewed_variables,
                        inputs, var_files, credential_repository,
                        command_environment, expected_terraform_sha256,
                        terraform, command_runner or _run_command,
                    )
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except Exception as exc:
        if isinstance(exc, ProviderKeyedAppendPlanPreparationError):
            raise
        raise ProviderKeyedAppendPlanPreparationError(stage) from None


def _prepare_locked(
    workspace, plan_path, retained_state_sha256, retained_resources,
    new_edge_address, new_edge, firewall, expected_inventory_content,
    reviewed_variables, inputs, var_files, credential_repository,
    command_environment, expected_terraform_sha256, terraform, run,
) -> ProviderKeyedAppendPlanEvidence:
    root = workspace.path
    identity: tuple[int, int] | None = None
    descriptor: int | None = None
    staging: Path | None = None
    stage = "workspace_and_inputs"
    try:
        _verify_audited_workspace(workspace)
        if _unsafe_keyed_workspace(root):
            raise ValueError("append workspace is not private")
        if plan_path.exists() or plan_path.is_symlink():
            raise ValueError("append plan already exists")
        raw = workspace.state_path.read_bytes()
        state_hash = hashlib.sha256(raw).hexdigest()
        state = json.loads(raw)
        resources = _state_resources(state)
        if (state_hash != retained_state_sha256
                or resources != dict(retained_resources)):
            raise ValueError("retained state differs from reviewed source")
        topology_hash = _topology_hash(workspace)
        marker_hash = _hash_file(root / ".barragan-provider-keyed-state.json")
        lock_hash = _hash_file(root / ".terraform.lock.hcl")
        _require_provider_lock(root / ".terraform.lock.hcl")
        _verify_input_hashes(inputs)
        secret_hash, secret_updated_at, encrypted = _credential_snapshot(
            workspace.provider_connection_id, credential_repository)
        terraform_path = _resolve_terraform(terraform, command_environment)
        binary_hash = _hash_file(terraform_path)
        if binary_hash != expected_terraform_sha256:
            raise ValueError("pinned Terraform release differs")
        stage = "credential_and_staging"
        staging, staged_files, _staged_hashes = _stage_var_files(
            root, inputs, var_files, prefix=".barragan-append-inputs-")
        token = decrypt_secret_value(encrypted)
        if not token:
            raise ValueError("provider credential is empty")
        credential_file, _ = _stage_credential(staging, token)
        del token
        env = {key: value for key, value in command_environment.items()
               if key in _ENV_ALLOWLIST}
        env["TF_DATA_DIR"] = str(workspace.terraform_data_dir)
        env["TF_CLI_CONFIG_FILE"] = "/dev/null"
        stage = "terraform_init"
        version = _checked(run([str(terraform_path), "version", "-json"], root, env))
        if json.loads(version.stdout).get("terraform_version") != "1.15.5":
            raise ValueError("Terraform version differs")
        _checked(run([str(terraform_path), "init", "-input=false",
                      "-lockfile=readonly", "-no-color"], root, env))
        _require_unchanged(workspace, inputs, state_hash, topology_hash,
                           marker_hash, lock_hash)
        descriptor = os.open(plan_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        plan_info = os.fstat(descriptor)
        identity = (plan_info.st_dev, plan_info.st_ino)
        os.fchmod(descriptor, 0o600)
        args = [str(terraform_path), "plan", "-input=false", "-lock=true",
                "-refresh=false", "-no-color", f"-out={plan_path}"]
        args.extend(f"-var-file={path}" for path in staged_files)
        args.append(f"-var-file={credential_file}")
        stage = "terraform_plan"
        _checked(run(args, root, env))
        saved_info = plan_path.lstat()
        if (not stat.S_ISREG(saved_info.st_mode)
                or saved_info.st_uid != os.geteuid()
                or stat.S_IMODE(saved_info.st_mode) & 0o077
                or (saved_info.st_dev, saved_info.st_ino) != identity):
            raise ValueError("saved append plan identity differs")
        plan_hash = _hash_file(plan_path)
        stage = "saved_plan_gate"
        shown = _checked(run([str(terraform_path), "show", "-json", str(plan_path)], root, env))
        require_digitalocean_keyed_edge_append_full_plan(
            shown.stdout, workspace=workspace, retained_resources=retained_resources,
            new_edge_address=new_edge_address, new_edge=new_edge,
            firewall=firewall, expected_inventory_content=expected_inventory_content,
            reviewed_variables=reviewed_variables,
        )
        stage = "postflight"
        _require_unchanged(workspace, inputs, state_hash, topology_hash,
                           marker_hash, lock_hash)
        if (_hash_file(plan_path) != plan_hash
                or (plan_path.stat().st_dev, plan_path.stat().st_ino) != identity
                or _credential_snapshot(workspace.provider_connection_id,
                                        credential_repository)[:2]
                != (secret_hash, secret_updated_at)
                or _hash_file(terraform_path) != binary_hash):
            raise ValueError("append plan inputs changed during inspection")
        return ProviderKeyedAppendPlanEvidence(
            plan_path, plan_hash, state_hash, topology_hash,
            workspace.source_sha256, lock_hash, inputs,
            workspace.provider_connection_id, secret_hash,
            secret_updated_at, terraform_path, binary_hash,
        )
    except Exception as exc:
        _remove_owned_plan(plan_path, identity)
        if isinstance(exc, ProviderKeyedAppendPlanPreparationError):
            raise
        reason_code = (_APPEND_GATE_REASON_CODES.get(str(exc)) if stage == "saved_plan_gate"
                       and isinstance(exc, TerraformPlanGateError) else None)
        raise ProviderKeyedAppendPlanPreparationError(stage, reason_code) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if staging is not None:
            shutil.rmtree(staging)


def _require_unchanged(workspace, inputs, state_hash, topology_hash, marker_hash, lock_hash):
    _verify_audited_workspace(workspace)
    if (workspace.state_path.is_symlink()
            or _hash_file(workspace.state_path) != state_hash
            or _topology_hash(workspace) != topology_hash
            or _hash_file(workspace.path / ".barragan-provider-keyed-state.json") != marker_hash
            or _hash_file(workspace.path / ".terraform.lock.hcl") != lock_hash):
        raise ValueError("retained append workspace changed")
    _verify_input_hashes(inputs)


def _checked(result: subprocess.CompletedProcess[str]) -> subprocess.CompletedProcess[str]:
    if result.returncode != 0:
        raise ValueError("Terraform append plan command failed")
    return result
