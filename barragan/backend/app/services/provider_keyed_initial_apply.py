# Copyright (c) 2026, Oracle and/or its affiliates.
"""DevTest-only exact saved-plan apply boundary for fresh DigitalOcean Sketch.

This helper has no runtime caller. A successful Terraform command does not
prove provider attachments, host firewall policy, or route reachability.
"""

from __future__ import annotations

import fcntl
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from app.services.provider_keyed_initial_plan_gate import (
    DigitalOceanInitialFirewallIntent,
    DigitalOceanNodeCreate,
    _verify_audited_workspace,
    require_digitalocean_keyed_initial_full_plan,
)
from app.services.provider_keyed_saved_plan_runner import (
    ProviderKeyedInitialPlanEvidence,
    ProviderKeyedPlanPreparationError,
    _ENV_ALLOWLIST,
    _credential_snapshot,
    _hash_file,
    _ordinal_lock,
    _require_canonical_workspace_paths,
    _require_absent_initial_state,
    _unsafe_keyed_workspace,
    _require_nodes_match_topology,
    _require_plan_topology_variables,
    _topology_hash,
    _verify_input_hashes,
)
from app.services.provider_keyed_selector_preflight import (
    SelectorPreflightEvidence, require_new_digitalocean_selector_available,
)
from app.services.provider_keyed_sketch import (
    ProviderKeyedWorkspace,
    mark_provider_keyed_applied,
    mark_provider_keyed_apply_started,
)
from app.services.terraform_plan_gate import TerraformPlanGateError
from app.storage.credential_repository import CredentialRepository
from app.services.provider_catalog import ProviderCatalogTransport


CommandRunner = Callable[[list[str], Path, Mapping[str, str]], subprocess.CompletedProcess[str]]


class ProviderKeyedInitialApplyError(ValueError):
    """Redacted failure. Existing state and uncertain resources need review."""


_HASH = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ProviderKeyedInitialApplyResult:
    state_sha256: str
    selector: str
    attachment_proof_pending: bool = True


def apply_digitalocean_keyed_initial_saved_plan(
    workspace: ProviderKeyedWorkspace,
    evidence: ProviderKeyedInitialPlanEvidence,
    *,
    environment: str,
    deployment_target: str,
    expected_terraform_sha256: str,
    expected_nodes: Mapping[str, DigitalOceanNodeCreate],
    expected_ssh_key_name: str,
    expected_ssh_public_key: str,
    expected_firewall: DigitalOceanInitialFirewallIntent,
    expected_local_files: Mapping[str, Mapping[str, object]],
    engagement_tag: str,
    credential_repository: CredentialRepository,
    command_environment: Mapping[str, str],
    selector_transport: ProviderCatalogTransport | None = None,
    command_runner: CommandRunner | None = None,
    selector_absence_callback: Callable[[SelectorPreflightEvidence], None] | None = None,
    selector_reservation_callback: Callable[[], None] | None = None,
) -> ProviderKeyedInitialApplyResult:
    """Revalidate and apply only the previously reviewed full binary plan.

    A failed or interrupted apply leaves its phase fence and any Terraform
    state intact; normal deployment must stop for reconciliation.
    A future runtime caller must supply intents from the same independently
    persisted engagement draft/profile reviewed at plan time, including the
    name, selector, image, sizes, SSH key, and trusted-source policy.
    """

    if environment != "devtest" or deployment_target != "barragan-testing":
        raise ProviderKeyedInitialApplyError("keyed apply requires DevTest disposable scope")
    if (not isinstance(workspace, ProviderKeyedWorkspace) or workspace.provider != "digitalocean"
            or not isinstance(evidence, ProviderKeyedInitialPlanEvidence)):
        raise ProviderKeyedInitialApplyError("keyed apply evidence is invalid")
    root = workspace.path
    if root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise ProviderKeyedInitialApplyError("keyed apply workspace path is unsafe")
    try:
        _require_canonical_workspace_paths(workspace)
    except ValueError:
        raise ProviderKeyedInitialApplyError("provider-keyed Terraform paths are not canonical") from None
    if any(key.upper().startswith("TF_") for key in command_environment):
        raise ProviderKeyedInitialApplyError("Terraform environment inputs are forbidden at apply")
    lock_path = root / ".barragan-initial-full-plan.lock"
    try:
        descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ProviderKeyedInitialApplyError("saved-plan workspace lock is missing or unsafe") from None
    with os.fdopen(descriptor, "r+b") as lock:
        lock_info = os.fstat(lock.fileno())
        if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.getuid()
                or stat.S_IMODE(lock_info.st_mode) & 0o077):
            raise ProviderKeyedInitialApplyError("saved-plan workspace lock is unsafe")
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            # Same order as plan preparation: workspace lock, then ordinal lock.
            try:
                with _ordinal_lock(workspace):
                    return _apply_locked(
                        workspace, evidence, expected_terraform_sha256, expected_nodes,
                        expected_ssh_key_name, expected_ssh_public_key, expected_firewall,
                        expected_local_files, engagement_tag, credential_repository,
                        command_environment, selector_transport, command_runner or _run_command,
                        selector_absence_callback,
                        selector_reservation_callback,
                    )
            except ProviderKeyedPlanPreparationError:
                raise ProviderKeyedInitialApplyError("keyed apply lock or evidence is invalid") from None
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _apply_locked(
    workspace: ProviderKeyedWorkspace,
    evidence: ProviderKeyedInitialPlanEvidence,
    expected_terraform_sha256: str,
    expected_nodes: Mapping[str, DigitalOceanNodeCreate],
    expected_ssh_key_name: str,
    expected_ssh_public_key: str,
    expected_firewall: DigitalOceanInitialFirewallIntent,
    expected_local_files: Mapping[str, Mapping[str, object]],
    engagement_tag: str,
    repository: CredentialRepository,
    command_environment: Mapping[str, str],
    selector_transport: ProviderCatalogTransport | None,
    run: CommandRunner,
    selector_absence_callback: Callable[[SelectorPreflightEvidence], None] | None,
    selector_reservation_callback: Callable[[], None] | None,
) -> ProviderKeyedInitialApplyResult:
    root = workspace.path
    try:
        _verify_audited_workspace(workspace)
        if _unsafe_keyed_workspace(root):
            raise ProviderKeyedInitialApplyError("keyed workspace is not private")
        _require_absent_initial_state(workspace)
        phase = root / ".barragan-apply-phase.json"
        if phase.exists() or phase.is_symlink():
            raise ProviderKeyedInitialApplyError("keyed apply has already started")
        if evidence.source_sha256 != workspace.source_sha256:
            raise ProviderKeyedInitialApplyError("reviewed source differs from workspace")
        _require_reviewed_inputs(root, evidence.input_sha256)
        if _topology_hash(workspace) != evidence.topology_sha256:
            raise ProviderKeyedInitialApplyError("reviewed topology changed since plan")
        _require_nodes_match_topology(workspace, expected_nodes, expected_firewall)
        if (_hash_file(root / ".barragan-provider-keyed-state.json") != evidence.marker_sha256
                or _hash_file(root / ".terraform.lock.hcl") != evidence.lockfile_sha256):
            raise ProviderKeyedInitialApplyError("reviewed source or lockfile changed")
        plan_path = root / ".barragan-initial-full.tfplan"
        if evidence.plan_path != plan_path or _hash_file(plan_path) != evidence.plan_sha256:
            raise ProviderKeyedInitialApplyError("exact saved plan changed")
        if plan_path.stat().st_mode & 0o077:
            raise ProviderKeyedInitialApplyError("saved plan is not private")
        if evidence.state_sha256 is not None or evidence.terraform_version != "1.15.5":
            raise ProviderKeyedInitialApplyError("initial state or Terraform version differs")
        if (expected_terraform_sha256 != evidence.terraform_binary_sha256
                or _hash_file(evidence.terraform_binary_path) != expected_terraform_sha256
                or not evidence.terraform_binary_path.is_absolute()
                or not os.access(evidence.terraform_binary_path, os.X_OK)):
            raise ProviderKeyedInitialApplyError("Terraform binary differs from reviewed release")
        digest, updated_at, _ = _credential_snapshot(evidence.credential_record_id, repository)
        if (evidence.credential_record_id != workspace.provider_connection_id
                or digest != evidence.credential_secret_sha256
                or updated_at != evidence.credential_updated_at):
            raise ProviderKeyedInitialApplyError("provider credential changed since plan")
        env = {key: value for key, value in command_environment.items() if key in _ENV_ALLOWLIST}
        env["TF_DATA_DIR"] = str(workspace.terraform_data_dir)
        env["TF_CLI_CONFIG_FILE"] = "/dev/null"
        terraform = str(evidence.terraform_binary_path)
        shown = run([terraform, "show", "-json", str(plan_path)], root, env)
        if shown.returncode:
            raise ProviderKeyedInitialApplyError("saved-plan inspection failed")
        require_digitalocean_keyed_initial_full_plan(
            shown.stdout, workspace=workspace, expected_nodes=expected_nodes,
            expected_ssh_key_name=expected_ssh_key_name,
            expected_ssh_public_key=expected_ssh_public_key,
            expected_firewall=expected_firewall,
            expected_local_files=expected_local_files,
        )
        _require_plan_topology_variables(shown.stdout, workspace)
        if not isinstance(engagement_tag, str) or not engagement_tag or expected_firewall.selector_tag == engagement_tag:
            raise ProviderKeyedInitialApplyError("selector and engagement tag are invalid")
        selector_evidence = _recheck_preflight(
            expected_firewall.selector_tag, engagement_tag,
            evidence.credential_record_id, repository, selector_transport,
        )
        _verify_audited_workspace(workspace)
        _require_absent_initial_state(workspace)
        if (_hash_file(plan_path) != evidence.plan_sha256
                or _topology_hash(workspace) != evidence.topology_sha256
                or _hash_file(root / ".barragan-provider-keyed-state.json") != evidence.marker_sha256
                or _hash_file(root / ".terraform.lock.hcl") != evidence.lockfile_sha256
                or _hash_file(evidence.terraform_binary_path) != expected_terraform_sha256):
            raise ProviderKeyedInitialApplyError("reviewed saved-plan inputs changed")
        digest, updated_at, _ = _credential_snapshot(evidence.credential_record_id, repository)
        if (digest, updated_at) != (evidence.credential_secret_sha256, evidence.credential_updated_at):
            raise ProviderKeyedInitialApplyError("provider credential changed since plan")
        _require_reviewed_inputs(root, evidence.input_sha256)
        if (selector_absence_callback is None or selector_reservation_callback is None
                or not isinstance(selector_evidence, SelectorPreflightEvidence)):
            raise ProviderKeyedInitialApplyError("selector reservation journal is unavailable")
        selector_absence_callback(selector_evidence)
        selector_reservation_callback()
        # A provider POST happened inside the callback. No apply may follow a
        # credential swap, even when the callback itself reported success.
        digest, updated_at, _ = _credential_snapshot(evidence.credential_record_id, repository)
        if (digest, updated_at) != (evidence.credential_secret_sha256, evidence.credential_updated_at):
            raise ProviderKeyedInitialApplyError("provider credential changed after selector reservation")
        mark_provider_keyed_apply_started(workspace)
        applied = run([terraform, "apply", "-input=false", "-lock=true", "-no-color", str(plan_path)], root, env)
        if applied.returncode:
            raise ProviderKeyedInitialApplyError("Terraform apply failed; reconciliation required")
        if _hash_file(plan_path) != evidence.plan_sha256:
            raise ProviderKeyedInitialApplyError("saved plan changed during apply; reconciliation required")
        state_hash = _require_retained_state(workspace, expected_nodes, expected_firewall)
        mark_provider_keyed_applied(workspace)
        # The binary may contain the provider token. Delete only the precise
        # reviewed file after successful state retention and phase transition.
        try:
            plan_path.unlink()
        except OSError:
            # The retained 0600 plan remains available for controlled cleanup.
            pass
        return ProviderKeyedInitialApplyResult(state_hash, expected_firewall.selector_tag)
    except (OSError, ValueError, subprocess.SubprocessError, TerraformPlanGateError):
        raise ProviderKeyedInitialApplyError("keyed initial apply failed; inspect phase and state before retry") from None


def _require_reviewed_inputs(root: Path, inputs: tuple[tuple[str, str], ...]) -> None:
    """Accept only the plan job's canonical retained var file."""

    if not isinstance(inputs, tuple) or len(inputs) != 1:
        raise ProviderKeyedInitialApplyError("reviewed plan input manifest is invalid")
    entry = inputs[0]
    if not isinstance(entry, tuple) or len(entry) != 2:
        raise ProviderKeyedInitialApplyError("reviewed plan input manifest is invalid")
    name, digest = entry
    if not isinstance(name, str) or not isinstance(digest, str) or not _HASH.fullmatch(digest):
        raise ProviderKeyedInitialApplyError("reviewed plan input manifest is invalid")
    path = root.parents[1] / ".plan-material" / "digitalocean" / "inputs.json"
    if name != str(path) or path.is_symlink():
        raise ProviderKeyedInitialApplyError("reviewed plan input path is invalid")
    try:
        canonical = path.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ProviderKeyedInitialApplyError("reviewed plan input path is invalid") from None
    if canonical != path:
        raise ProviderKeyedInitialApplyError("reviewed plan input path is invalid")
    if path.stat().st_mode & 0o077:
        raise ProviderKeyedInitialApplyError("reviewed plan input is not private")
    _verify_input_hashes(inputs)


def _recheck_preflight(
    selector: str, engagement_tag: str, connection_id: str,
    repository: CredentialRepository, transport: ProviderCatalogTransport | None,
) -> SelectorPreflightEvidence:
    try:
        return require_new_digitalocean_selector_available(
            selector, engagement_tag, connection_id,
            repository=repository, transport=transport,
        )
    except Exception:
        raise ProviderKeyedInitialApplyError("selector availability is unverified") from None


def _require_retained_state(
    workspace: ProviderKeyedWorkspace,
    expected_nodes: Mapping[str, DigitalOceanNodeCreate],
    expected_firewall: DigitalOceanInitialFirewallIntent,
) -> str:
    """Require the expected managed resource identities before marking applied.

    This is local state validation, not confirmation of actual provider
    attachments. That remains a separate post-apply gate.
    """

    path = workspace.state_path
    if path.is_symlink() or not path.is_file():
        raise ProviderKeyedInitialApplyError("Terraform apply returned without retained state")
    try:
        import json
        from uuid import UUID

        state = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(state, dict) or not isinstance(state.get("lineage"), str):
            raise ValueError("lineage missing")
        UUID(state["lineage"])
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise ProviderKeyedInitialApplyError("retained Terraform state is invalid") from None
    if (not isinstance(state, dict) or type(state.get("version")) is not int
            or state["version"] != 4 or type(state.get("serial")) is not int
            or state["serial"] < 1 or state.get("terraform_version") != "1.15.5"
            or not isinstance(state.get("resources"), list)):
        raise ProviderKeyedInitialApplyError("retained Terraform state is invalid")
    expected = set(expected_nodes) | {
        "digitalocean_ssh_key.key", "digitalocean_firewall.firewall",
        "local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]",
    }
    actual: dict[str, dict] = {}
    for resource in state["resources"]:
        if (not isinstance(resource, dict) or resource.get("mode") != "managed"
                or not isinstance(resource.get("type"), str)
                or not isinstance(resource.get("name"), str)
                or not isinstance(resource.get("instances"), list)):
            raise ProviderKeyedInitialApplyError("retained Terraform resource is invalid")
        base = f'{resource["type"]}.{resource["name"]}'
        for instance in resource["instances"]:
            if not isinstance(instance, dict) or not isinstance(instance.get("attributes"), dict):
                raise ProviderKeyedInitialApplyError("retained Terraform instance is invalid")
            key = instance.get("index_key")
            if isinstance(key, str):
                import json
                address = f"{base}[{json.dumps(key)}]"
            elif type(key) is int:
                address = f"{base}[{key}]"
            elif key is None:
                address = base
            else:
                raise ProviderKeyedInitialApplyError("retained Terraform instance key is invalid")
            if address in actual:
                raise ProviderKeyedInitialApplyError("retained Terraform resource is duplicated")
            actual[address] = instance["attributes"]
    if set(actual) != expected:
        raise ProviderKeyedInitialApplyError("retained Terraform resources differ from plan")
    for address, intent in expected_nodes.items():
        attributes = actual[address]
        if (not isinstance(attributes.get("id"), str) or not attributes["id"]
                or attributes.get("name") != intent.name
                or attributes.get("region") != intent.region
                or attributes.get("tags") != [intent.firewall_selector_tag]):
            raise ProviderKeyedInitialApplyError("retained Terraform node differs from plan")
    node_ids = [actual[address]["id"] for address in expected_nodes]
    if len(set(node_ids)) != len(node_ids):
        raise ProviderKeyedInitialApplyError("retained Terraform node IDs overlap")
    firewall = actual["digitalocean_firewall.firewall"]
    if (not isinstance(firewall.get("id"), str) or not firewall["id"]
            or firewall.get("name") != expected_firewall.name
            or firewall.get("tags") != [expected_firewall.selector_tag]):
        raise ProviderKeyedInitialApplyError("retained Terraform firewall differs from plan")
    if any(not isinstance(actual[address].get("id"), str) or not actual[address]["id"]
           for address in expected - set(expected_nodes) - {"digitalocean_firewall.firewall"}):
        raise ProviderKeyedInitialApplyError("retained Terraform shared resource is invalid")
    return _hash_file(path)


def _run_command(args: list[str], cwd: Path, env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, env=dict(env), capture_output=True, text=True, check=False)
