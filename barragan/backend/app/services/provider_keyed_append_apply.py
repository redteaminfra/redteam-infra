# Copyright (c) 2026, Oracle and/or its affiliates.
"""One-shot saved-plan Apply for a reviewed, channel-free DigitalOcean edge.

The caller owns the durable command journal and the engagement mutation lease.
This helper cannot reserve a job or replay an interrupted Terraform command.
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

from app.services.provider_keyed_append_plan_gate import require_digitalocean_keyed_edge_append_full_plan
from app.services.provider_keyed_append_plan_runner import ProviderKeyedAppendPlanEvidence
from app.services.provider_keyed_initial_apply import _require_retained_state
from app.services.provider_keyed_initial_plan_gate import (
    DigitalOceanInitialFirewallIntent, DigitalOceanNodeCreate, _verify_audited_workspace,
)
from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_saved_plan_runner import (
    _ENV_ALLOWLIST, _credential_snapshot, _hash_file, _ordinal_lock,
    _require_canonical_workspace_paths, _topology_hash, _unsafe_keyed_workspace,
    _verify_input_hashes,
)
from app.services.provider_keyed_sketch import (
    ProviderKeyedWorkspace, SCHEMA, mark_provider_keyed_applied,
    mark_provider_keyed_apply_started,
)
from app.storage.credential_repository import CredentialRepository


class ProviderKeyedAppendApplyError(ValueError):
    """The append may have changed provider state and requires reconciliation."""


@dataclass(frozen=True)
class ProviderKeyedAppendApplyResult:
    state_sha256: str
    new_edge_address: str
    new_edge_provider_id: str
    new_edge_public_ip: str


def apply_digitalocean_keyed_edge_append_saved_plan(
    workspace: ProviderKeyedWorkspace,
    evidence: ProviderKeyedAppendPlanEvidence,
    *,
    retained_resources: Mapping[str, Mapping[str, object]],
    expected_nodes: Mapping[str, DigitalOceanNodeCreate],
    new_edge_address: str,
    expected_firewall: DigitalOceanInitialFirewallIntent,
    expected_inventory_content: str,
    reviewed_variables: Mapping[str, object],
    credential_repository: CredentialRepository,
    command_environment: Mapping[str, str],
    before_go_provider_check: Callable[[], None],
    command_runner: Callable[[list[str], Path, Mapping[str, str]], subprocess.CompletedProcess[str]],
    environment: str = "devtest",
    deployment_target: str = "barragan-testing",
) -> ProviderKeyedAppendApplyResult:
    """Recheck the exact reviewed binary and apply it once after fresh GET proof.

    `command_runner` must durably journal intent and process identity before
    releasing its GO gate. An uncertain command leaves `apply_started` intact.
    """
    if (environment != "devtest" or deployment_target != "barragan-testing"
            or not isinstance(workspace, ProviderKeyedWorkspace)
            or workspace.provider != "digitalocean" or workspace.schema != SCHEMA
            or not isinstance(evidence, ProviderKeyedAppendPlanEvidence)
            or not callable(before_go_provider_check) or not callable(command_runner)
            or any(key.upper().startswith("TF_") for key in command_environment)):
        raise ProviderKeyedAppendApplyError("reviewed append Apply boundary differs")
    root = workspace.path
    if root.is_symlink() or not root.is_dir() or root.resolve(strict=True) != root:
        raise ProviderKeyedAppendApplyError("append workspace path differs")
    lock_path = root / ".barragan-initial-full-plan.lock"
    try:
        descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "r+b") as lock:
            info = os.fstat(lock.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise ValueError("append workspace lock differs")
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                with _ordinal_lock(workspace):
                    return _apply_locked(
                        workspace, evidence, retained_resources, expected_nodes,
                        new_edge_address, expected_firewall, expected_inventory_content,
                        reviewed_variables, credential_repository, command_environment,
                        before_go_provider_check, command_runner,
                    )
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except Exception:
        raise ProviderKeyedAppendApplyError(
            "saved append Apply stopped; inspect phase, state, and provider before recovery"
        ) from None


def _apply_locked(
    workspace, evidence, retained_resources, expected_nodes, new_edge_address,
    expected_firewall, expected_inventory_content, reviewed_variables,
    credentials, command_environment, before_go_provider_check, run,
) -> ProviderKeyedAppendApplyResult:
    root = workspace.path
    _require_canonical_workspace_paths(workspace)
    _verify_audited_workspace(workspace)
    if _unsafe_keyed_workspace(root):
        raise ValueError("append workspace is unsafe")
    phase = root / ".barragan-apply-phase.json"
    if (phase.is_symlink() or json.loads(phase.read_text()) !=
            {"schema": SCHEMA, "phase": "applied"}):
        raise ValueError("append Apply phase is not the retained applied generation")
    if (_hash_file(workspace.state_path) != evidence.state_sha256
            or _state_resources(json.loads(workspace.state_path.read_bytes())) != dict(retained_resources)
            or workspace.source_sha256 != evidence.source_sha256
            or _topology_hash(workspace) != evidence.topology_sha256
            or _hash_file(root / ".terraform.lock.hcl") != evidence.lockfile_sha256):
        raise ValueError("retained append source differs")
    if (new_edge_address in retained_resources or new_edge_address not in expected_nodes
            or len(expected_nodes) != 5
            or set(expected_nodes) - {new_edge_address} != {
                address for address in retained_resources
                if address.startswith("digitalocean_droplet.")
            }):
        raise ValueError("append node set differs")
    input_path = root.parents[1] / ".plan-material" / "digitalocean" / "append-inputs.json"
    if (evidence.input_sha256 != ((str(input_path), _hash_file(input_path)),)
            or input_path.is_symlink() or input_path.stat().st_mode & 0o077):
        raise ValueError("reviewed append varfile differs")
    _verify_input_hashes(evidence.input_sha256)
    plan_path = root / ".barragan-edge-append.tfplan"
    binary = evidence.terraform_binary_path
    if (evidence.plan_path != plan_path or plan_path.is_symlink()
            or plan_path.stat().st_mode & 0o077
            or _hash_file(plan_path) != evidence.plan_sha256
            or not binary.is_absolute() or binary.is_symlink() or not os.access(binary, os.X_OK)
            or _hash_file(binary) != evidence.terraform_binary_sha256):
        raise ValueError("reviewed append binary or plan differs")
    digest, updated_at, _ = _credential_snapshot(evidence.credential_record_id, credentials)
    if (evidence.credential_record_id != workspace.provider_connection_id
            or (digest, updated_at) != (evidence.credential_secret_sha256,
                                         evidence.credential_updated_at)):
        raise ValueError("reviewed append credential differs")
    env = {key: value for key, value in command_environment.items() if key in _ENV_ALLOWLIST}
    env["TF_DATA_DIR"] = str(workspace.terraform_data_dir)
    env["TF_CLI_CONFIG_FILE"] = "/dev/null"
    shown = run([str(binary), "show", "-json", str(plan_path)], root, env)
    if shown.returncode:
        raise ValueError("saved append plan inspection failed")
    require_digitalocean_keyed_edge_append_full_plan(
        shown.stdout, workspace=workspace, retained_resources=retained_resources,
        new_edge_address=new_edge_address, new_edge=expected_nodes[new_edge_address],
        firewall=expected_firewall,
        expected_inventory_content=expected_inventory_content,
        reviewed_variables=reviewed_variables,
    )
    before_go_provider_check()
    # The final local checks follow provider GET, immediately before the
    # irreversible phase fence. A failed or uncertain Apply is never replayed.
    if (_hash_file(workspace.state_path) != evidence.state_sha256
            or _hash_file(plan_path) != evidence.plan_sha256
            or _topology_hash(workspace) != evidence.topology_sha256
            or _hash_file(root / ".terraform.lock.hcl") != evidence.lockfile_sha256
            or _hash_file(binary) != evidence.terraform_binary_sha256):
        raise ValueError("reviewed append inputs changed before GO")
    _verify_input_hashes(evidence.input_sha256)
    if _credential_snapshot(evidence.credential_record_id, credentials)[:2] != (
            evidence.credential_secret_sha256, evidence.credential_updated_at):
        raise ValueError("reviewed append credential changed before GO")
    mark_provider_keyed_apply_started(workspace)
    applied = run([str(binary), "apply", "-input=false", "-lock=true", "-no-color",
                   str(plan_path)], root, env)
    if applied.returncode:
        raise ValueError("saved append Apply failed")
    if _hash_file(plan_path) != evidence.plan_sha256:
        raise ValueError("saved append plan changed during Apply")
    state_sha = _require_retained_state(workspace, expected_nodes, expected_firewall)
    after = _state_resources(json.loads(workspace.state_path.read_bytes()))
    retained_nodes = {address for address in expected_nodes if address != new_edge_address}
    if (len(after) != len(retained_resources) + 1
            or any(after[address] != retained_resources[address]
                   for address in retained_nodes | {"digitalocean_ssh_key.key"})
            or after["digitalocean_firewall.firewall"].get("id") !=
               retained_resources["digitalocean_firewall.firewall"].get("id")):
        raise ValueError("retained provider identities changed during append")
    new = after[new_edge_address]
    if (not isinstance(new.get("id"), str) or not new["id"]
            or not isinstance(new.get("ipv4_address"), str) or not new["ipv4_address"]):
        raise ValueError("new edge identity is unavailable")
    mark_provider_keyed_applied(workspace)
    return ProviderKeyedAppendApplyResult(
        state_sha, new_edge_address, new["id"], new["ipv4_address"])
