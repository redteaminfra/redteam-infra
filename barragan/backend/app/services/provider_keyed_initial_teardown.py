# Copyright (c) 2026, Oracle and/or its affiliates.
"""Non-executing, DevTest-only preview of a complete keyed DO teardown.

The returned binary is review evidence, never an authorization to apply.  In
particular a caller must separately establish provider inventory and a safe
cleanup execution/reconciliation protocol before destroying anything.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence
from uuid import UUID

from app.services.credentials import decrypt_secret_value
from app.services.provider_keyed_initial_plan_gate import (
    DigitalOceanInitialFirewallIntent, DigitalOceanNodeCreate, _verify_audited_workspace,
)
from app.services.provider_keyed_saved_plan_runner import (
    _ENV_ALLOWLIST, _check_inputs, _credential_snapshot, _hash_file,
    _ordinal_lock, _require_canonical_workspace_paths, _require_nodes_match_topology,
    _require_plan_topology_variables, _require_provider_lock, _resolve_terraform,
    _stage_credential, _stage_var_files,
    _topology_hash, _verify_input_hashes,
    _unsafe_keyed_workspace, _remove_owned_plan,
)
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, SCHEMA
from app.storage.credential_repository import CredentialRepository


CommandRunner = Callable[[list[str], Path, Mapping[str, str]], subprocess.CompletedProcess[str]]
_HASH = re.compile(r"^[0-9a-f]{64}$")
_PLAN = ".barragan-initial-destroy.tfplan"
_FAILURE_STAGES = frozenset({
    "other", "plan_integrity", "show_command", "exact_delete",
    "topology_variables", "unchanged_inputs", "cleanup", "post_preview_evidence",
})
_DELETE_PREDICATES = frozenset({
    "envelope", "state_prior_inventory", "action_before", "output", "planned_remainder",
})
_SHARED = frozenset({
    "digitalocean_ssh_key.key", "digitalocean_firewall.firewall",
    "local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]",
})


class ProviderKeyedTeardownPreviewError(ValueError):
    """Redacted preview failure; Terraform/provider output is never included."""

    def __init__(self, message: str, *, stage: str = "other",
                 predicate_category: str | None = None) -> None:
        super().__init__(message)
        self.stage = stage if type(stage) is str and stage in _FAILURE_STAGES else "other"
        self.predicate_category = (predicate_category
                                   if self.stage == "exact_delete"
                                   and type(predicate_category) is str
                                   and predicate_category in _DELETE_PREDICATES else None)


class ProviderKeyedTeardownPreviewUncertainError(ProviderKeyedTeardownPreviewError):
    """A command or cleanup outcome is unproved; retained files need reconciliation."""


@dataclass(frozen=True)
class DigitalOceanTeardownIntent:
    """Independently persisted identities; do not derive these from state."""

    nodes: Mapping[str, DigitalOceanNodeCreate]
    firewall: DigitalOceanInitialFirewallIntent
    resource_ids: Mapping[str, str]
    state_sha256: str
    credential_record_id: str
    credential_secret_sha256: str
    credential_updated_at: str


@dataclass(frozen=True)
class DigitalOceanTeardownPreview:
    plan_path: Path
    plan_sha256: str
    state_sha256: str
    source_sha256: str
    marker_sha256: str
    lockfile_sha256: str
    topology_sha256: str
    phase_sha256: str
    input_sha256: tuple[tuple[str, str], ...]
    credential_record_id: str
    credential_secret_sha256: str
    credential_updated_at: str
    terraform_binary_path: Path
    terraform_binary_sha256: str


def require_exact_digitalocean_destroy_plan(
    payload: str, *, expected_resource_ids: Mapping[str, str], state: Mapping[str, object],
) -> None:
    """Require every and only managed resource to be deleted, with exact IDs."""

    predicate_category = "envelope"
    try:
        plan = json.loads(payload)
        changes = plan["resource_changes"]
        prior = plan["prior_state"]["values"]["root_module"]["resources"]
        if (plan["format_version"] != "1.2" or plan["terraform_version"] != "1.15.5"
                or plan["applyable"] is not True or plan["complete"] is not True
                or plan["errored"] is not False or plan.get("resource_drift")
                or not isinstance(changes, list) or not isinstance(prior, list)):
            raise ValueError("invalid plan envelope")
        predicate_category = "state_prior_inventory"
        state_values = _state_resources(state)
        if set(state_values) != set(expected_resource_ids):
            raise ValueError("unexpected state resource")
        prior_values = _plan_resource_values(prior)
        if (set(prior_values) != set(expected_resource_ids)
                or any(str(values.get("id")) != expected_resource_ids[address]
                       or str(state_values[address].get("id")) != expected_resource_ids[address]
                       for address, values in prior_values.items())):
            raise ValueError("prior state differs")
        predicate_category = "action_before"
        seen: set[str] = set()
        for item in changes:
            address = item["address"]
            change = item["change"]
            if (not isinstance(address, str) or address in seen
                    or address not in expected_resource_ids
                    or change["actions"] != ["delete"]
                    or change.get("after", "missing") is not None
                    or not isinstance(change.get("before"), dict)
                    or str(change["before"].get("id")) != expected_resource_ids[address]
                    or change.get("after_unknown") not in ({}, None)
                    or item.get("deposed") is not None):
                raise ValueError("unapproved change")
            # Terraform's prior_state is provider-normalized; raw tfstate can
            # encode complex values differently (as confirmed with 1.15.5).
            if change["before"] != prior_values[address]:
                raise ValueError("changed resource before destroy")
            seen.add(address)
        if seen != set(expected_resource_ids):
            raise ValueError("incomplete destroy")
        predicate_category = "output"
        outputs = plan.get("output_changes", {})
        # Terraform 1.15.5 has emitted top-level output actions in an
        # isolated destroy plan, while the published JSON format documents
        # output_changes[name].change.actions. Accept either exact shape,
        # but never an ambiguous entry containing both forms.
        if not isinstance(outputs, dict) or any(
            not _approved_destroy_output_change(value)
            for value in outputs.values()
        ):
            raise ValueError("unexpected output action")
        predicate_category = "planned_remainder"
        planned = plan.get("planned_values")
        if not isinstance(planned, dict) or planned.get("root_module", {}) not in ({}, {"resources": []}):
            raise ValueError("destroy leaves managed resources")
    except (KeyError, TypeError, ValueError, AttributeError, json.JSONDecodeError):
        raise ProviderKeyedTeardownPreviewError(
            "saved destroy plan differs from complete owned state",
            stage="exact_delete", predicate_category=predicate_category,
        ) from None


def _approved_destroy_output_change(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    if "change" in value:
        if set(value) != {"change"} or not isinstance(value["change"], dict):
            return False
        change = value["change"]
    else:
        change = value
    return change.get("actions") in (["delete"], ["no-op"])


def prepare_digitalocean_keyed_initial_teardown_preview(
    workspace: ProviderKeyedWorkspace, intent: DigitalOceanTeardownIntent, *,
    environment: str, deployment_target: str, input_sha256: Mapping[Path, str],
    var_files: Sequence[Path], credential_repository: CredentialRepository,
    command_environment: Mapping[str, str], expected_terraform_sha256: str,
    terraform: str = "terraform", command_runner: CommandRunner | None = None,
    staging_path: Path | None = None,
    authority_check: Callable[[], None] | None = None,
    expected_topology_path: Path | None = None,
) -> DigitalOceanTeardownPreview:
    """Create a full destroy plan under the provider workspace/ordinal locks."""

    if environment != "devtest" or deployment_target != "barragan-testing":
        raise ProviderKeyedTeardownPreviewError("teardown preview requires disposable DevTest scope")
    if (not isinstance(workspace, ProviderKeyedWorkspace) or workspace.provider != "digitalocean"
            or workspace.schema != SCHEMA or not isinstance(intent, DigitalOceanTeardownIntent)
            or intent.credential_record_id != workspace.provider_connection_id
            or not input_sha256 or not var_files
            or any(key.upper().startswith("TF_") for key in command_environment)):
        raise ProviderKeyedTeardownPreviewError("teardown preview scope or inputs are invalid")
    root = workspace.path
    if root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise ProviderKeyedTeardownPreviewError("teardown workspace path is unsafe")
    if staging_path is not None and (not _valid_preselected_staging(root, staging_path)
                                     or not callable(authority_check)):
        raise ProviderKeyedTeardownPreviewError("preselected teardown staging boundary is unsafe")
    try:
        _require_canonical_workspace_paths(workspace)
        inputs = _check_inputs(root, input_sha256, var_files)
        if expected_topology_path is not None and (
                expected_topology_path != root.parents[1] / ".plan-material" / "digitalocean" / "append-inputs.json"
                or inputs != ((str(expected_topology_path), input_sha256.get(expected_topology_path)),)):
            raise ProviderKeyedTeardownPreviewError("reviewed append topology input differs")
        lock_path = root / ".barragan-initial-full-plan.lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "r+b") as lock:
            info = os.fstat(lock.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise ProviderKeyedTeardownPreviewError("teardown workspace lock is unsafe")
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                with _ordinal_lock(workspace):
                    return _prepare_locked(workspace, intent, inputs, var_files,
                                           credential_repository, command_environment,
                                           expected_terraform_sha256, terraform,
                                           command_runner or _run_command, staging_path,
                                           authority_check, expected_topology_path)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except Exception as exc:
        if isinstance(exc, ProviderKeyedTeardownPreviewError):
            raise
        raise ProviderKeyedTeardownPreviewError("teardown preview failed; no destroy was executed") from None


def _prepare_locked(
    workspace: ProviderKeyedWorkspace, intent: DigitalOceanTeardownIntent,
    inputs: tuple[tuple[str, str], ...], var_files: Sequence[Path],
    repository: CredentialRepository, command_environment: Mapping[str, str],
    expected_terraform_sha256: str, terraform: str, run: CommandRunner,
    staging_path: Path | None, authority_check: Callable[[], None] | None,
    expected_topology_path: Path | None,
) -> DigitalOceanTeardownPreview:
    root = workspace.path
    plan_path = root / _PLAN
    staging: Path | None = None
    staging_identity: tuple[int, int] | None = None
    staged_names: frozenset[str] = frozenset()
    uncertain = False
    owned_plan_identity: tuple[int, int] | None = None
    owned_plan_descriptor: int | None = None
    failure_stage = "other"
    try:
        _verify_audited_workspace(workspace)
        if _unsafe_keyed_workspace(root):
            raise ValueError("workspace permissions")
        phase_path = root / ".barragan-apply-phase.json"
        if phase_path.is_symlink() or json.loads(phase_path.read_text()) != {"schema": SCHEMA, "phase": "applied"}:
            raise ValueError("phase is not applied")
        if plan_path.exists() or plan_path.is_symlink():
            raise ValueError("previous destroy preview exists")
        topology_sha = dict(inputs)[str(expected_topology_path)] if expected_topology_path is not None else None
        _require_nodes_match_topology(
            workspace, intent.nodes, intent.firewall,
            **({"expected_topology_path": expected_topology_path,
                "expected_topology_sha256": topology_sha}
               if expected_topology_path is not None else {}))
        state = _require_exact_state(workspace, intent)
        _verify_input_hashes(inputs)
        digest, updated_at, encrypted = _credential_snapshot(intent.credential_record_id, repository)
        if (digest, updated_at) != (intent.credential_secret_sha256, intent.credential_updated_at):
            raise ValueError("credential changed")
        if staging_path is None:
            staging, staged_var_files, staged_hashes = _stage_var_files(root, inputs, var_files)
        else:
            if not _valid_preselected_staging(root, staging_path):
                raise ValueError("preselected staging path changed")
            staging, staged_var_files, staged_hashes, staging_identity = _stage_at_reviewed_path(
                root, inputs, var_files, staging_path, authority_check,
            )
            staged_names = frozenset(path.name for path in staged_var_files)
        token = decrypt_secret_value(encrypted)
        if not token:
            raise ValueError("credential unavailable")
        if authority_check is not None:
            authority_check()
        credential_file, credential_hash = _stage_credential(staging, token)
        if staging_path is not None:
            staged_names = staged_names | {credential_file.name}
        del token
        staged_hashes = (*staged_hashes, (str(credential_file), credential_hash))
        terraform_path = _resolve_terraform(terraform, command_environment)
        if not _HASH.fullmatch(expected_terraform_sha256) or _hash_file(terraform_path) != expected_terraform_sha256:
            raise ValueError("Terraform binary changed")
        _require_provider_lock(root / ".terraform.lock.hcl")
        marker_hash = _hash_file(root / ".barragan-provider-keyed-state.json")
        lock_hash = _hash_file(root / ".terraform.lock.hcl")
        topology_hash = _topology_hash(workspace)
        phase_hash = _hash_file(phase_path)
        env = {key: value for key, value in command_environment.items() if key in _ENV_ALLOWLIST}
        env["TF_DATA_DIR"] = str(workspace.terraform_data_dir)
        env["TF_CLI_CONFIG_FILE"] = "/dev/null"
        binary = str(terraform_path)
        version = _checked(run([binary, "version", "-json"], root, env))
        if json.loads(version.stdout).get("terraform_version") != "1.15.5":
            raise ValueError("Terraform version changed")
        _checked(run([binary, "init", "-input=false", "-lockfile=readonly", "-no-color"], root, env))
        _require_unchanged(workspace, intent, repository, inputs, staged_hashes, marker_hash,
                           lock_hash, topology_hash, phase_hash, expected_terraform_sha256, terraform_path)
        args = [binary, "plan", "-destroy", "-input=false", "-lock=true", "-no-color", f"-out={plan_path}"]
        args.extend(f"-var-file={path}" for path in staged_var_files)
        args.append(f"-var-file={credential_file}")
        if authority_check is not None:
            authority_check()
        owned_plan_descriptor = os.open(plan_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        plan_info = os.fstat(owned_plan_descriptor)
        owned_plan_identity = (plan_info.st_dev, plan_info.st_ino)
        os.fchmod(owned_plan_descriptor, 0o600)
        _checked(run(args, root, env))
        failure_stage = "plan_integrity"
        if plan_path.is_symlink() or not plan_path.is_file():
            raise ValueError("destroy plan missing")
        fd = os.open(plan_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            plan_info = os.fstat(fd)
            if (not stat.S_ISREG(plan_info.st_mode) or plan_info.st_uid != os.geteuid()
                    or (plan_info.st_dev, plan_info.st_ino) != owned_plan_identity
                    or stat.S_IMODE(plan_info.st_mode) & 0o077):
                raise ValueError("destroy plan unsafe")
        finally:
            os.close(fd)
        plan_hash = _hash_file(plan_path)
        failure_stage = "show_command"
        shown = _checked(run([binary, "show", "-json", str(plan_path)], root, env))
        failure_stage = "plan_integrity"
        if _hash_file(plan_path) != plan_hash:
            raise ValueError("destroy plan changed")
        failure_stage = "exact_delete"
        require_exact_digitalocean_destroy_plan(shown.stdout, expected_resource_ids=intent.resource_ids, state=state)
        failure_stage = "topology_variables"
        _require_plan_topology_variables(
            shown.stdout, workspace,
            **({"expected_topology_path": expected_topology_path,
                "expected_topology_sha256": topology_sha}
               if expected_topology_path is not None else {}))
        failure_stage = "unchanged_inputs"
        _require_unchanged(workspace, intent, repository, inputs, staged_hashes, marker_hash,
                           lock_hash, topology_hash, phase_hash, expected_terraform_sha256, terraform_path)
        return DigitalOceanTeardownPreview(
            plan_path, plan_hash, intent.state_sha256, workspace.source_sha256,
            marker_hash, lock_hash, topology_hash, phase_hash, inputs,
            intent.credential_record_id, digest, updated_at, terraform_path,
            expected_terraform_sha256,
        )
    except ProviderKeyedTeardownPreviewUncertainError:
        uncertain = True
        raise
    except Exception as error:
        if staging_path is None:
            _remove_owned_plan(plan_path, owned_plan_identity)
        else:
            try:
                _remove_owned_plan_checked(plan_path, owned_plan_identity)
            except ProviderKeyedTeardownPreviewUncertainError:
                uncertain = True
                raise
        raise ProviderKeyedTeardownPreviewError(
            "teardown preview failed; no destroy was executed", stage=failure_stage,
            predicate_category=(error.predicate_category
                                if isinstance(error, ProviderKeyedTeardownPreviewError) else None),
        ) from None
    finally:
        if owned_plan_descriptor is not None:
            os.close(owned_plan_descriptor)
        if staging is not None and not uncertain:
            if staging_path is None:
                shutil.rmtree(staging)
            else:
                _remove_staging_checked(staging, staging_identity, staged_names)


_STAGING_NAME = re.compile(r"\.barragan-destroy-inputs-[0-9a-f]{32}\Z")


def _valid_preselected_staging(root: Path, path: Path) -> bool:
    """A future claimed caller must journal this exact absent path first."""
    return (isinstance(path, Path) and path.is_absolute() and path.parent == root
            and _STAGING_NAME.fullmatch(path.name) is not None
            and not os.path.lexists(path))


def _stage_at_reviewed_path(
    root: Path, inputs: tuple[tuple[str, str], ...], var_files: Sequence[Path], path: Path,
    authority_check: Callable[[], None] | None = None,
) -> tuple[Path, tuple[Path, ...], tuple[tuple[str, str], ...], tuple[int, int]]:
    """Atomically create only the caller-audited directory under the held locks."""
    if not _valid_preselected_staging(root, path):
        raise ProviderKeyedTeardownPreviewError("preselected teardown staging path changed")
    if authority_check is not None:
        authority_check()
    os.mkdir(path, 0o700)  # mkdir fails atomically if the audited name appeared.
    try:
        info = path.lstat()
    except OSError:
        raise ProviderKeyedTeardownPreviewUncertainError(
            "teardown staging identity unproved; retained path needs reconciliation"
        ) from None
    identity = (info.st_dev, info.st_ino)
    staged: list[Path] = []
    hashes: list[tuple[str, str]] = []
    names: set[str] = set()
    try:
        # A trusted collaborator workspace may carry setgid. Linux inherits that
        # bit on mkdir even when the requested mode is 0700. Normalize only the
        # inode we just created, before staging any credential or input bytes.
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISDIR(opened.st_mode) or opened.st_uid != os.geteuid()
                    or (opened.st_dev, opened.st_ino) != identity):
                raise ValueError("staging directory identity changed")
            os.fchmod(fd, 0o700)
            info = os.fstat(fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or (info.st_dev, info.st_ino) != identity
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError("staging directory permissions changed")
        finally:
            os.close(fd)
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or (info.st_dev, info.st_ino) != identity
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("staging directory permissions changed")
        expected = dict(inputs)
        for index, source in enumerate(var_files):
            name = f"input-{index}{'.json' if source.name.endswith('.json') else '.input'}"
            data = source.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if digest != expected[str(source)]:
                raise ValueError("reviewed input changed")
            destination = path / name
            if authority_check is not None:
                authority_check()
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            names.add(name)
            with os.fdopen(fd, "wb") as target:
                target.write(data)
                target.flush()
                os.fsync(target.fileno())
            if _hash_file(destination) != digest:
                raise ValueError("staged input changed")
            staged.append(destination)
            hashes.append((str(destination), digest))
        return path, tuple(staged), tuple(hashes), identity
    except Exception:
        _remove_staging_checked(path, identity, frozenset(names))
        raise


def _remove_staging_checked(
    path: Path, identity: tuple[int, int] | None, expected_names: frozenset[str],
) -> None:
    """Remove only this private directory and its exact owned staging files."""
    try:
        info = path.lstat()
        if (identity is None or not stat.S_ISDIR(info.st_mode)
                or (info.st_dev, info.st_ino) != identity or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("staging directory ownership changed")
        children = list(path.iterdir())
        if {entry.name for entry in children} != expected_names:
            raise ValueError("staging directory contents changed")
        for entry in children:
            child = entry.lstat()
            if (not stat.S_ISREG(child.st_mode) or child.st_uid != os.geteuid()
                    or child.st_nlink != 1 or stat.S_IMODE(child.st_mode) & 0o077):
                raise ValueError("staged file ownership changed")
            entry.unlink()
        path.rmdir()
        if os.path.lexists(path):
            raise ValueError("staging removal unproved")
    except Exception:
        raise ProviderKeyedTeardownPreviewUncertainError(
            "teardown staging cleanup unproved; retained files need reconciliation"
        ) from None


def _remove_owned_plan_checked(path: Path, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or (info.st_dev, info.st_ino) != identity
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError("owned destroy plan changed")
        path.unlink()
        if os.path.lexists(path):
            raise ValueError("destroy plan removal unproved")
    except Exception:
        raise ProviderKeyedTeardownPreviewUncertainError(
            "destroy plan cleanup unproved; retained files need reconciliation"
        ) from None


def _require_exact_state(workspace: ProviderKeyedWorkspace, intent: DigitalOceanTeardownIntent) -> dict:
    path = workspace.state_path
    if not _HASH.fullmatch(intent.state_sha256) or _hash_file(path) != intent.state_sha256:
        raise ValueError("state hash changed")
    state = json.loads(path.read_text())
    UUID(state["lineage"])
    if (state.get("version") != 4 or state.get("terraform_version") != "1.15.5"
            or type(state.get("serial")) is not int or state["serial"] < 1):
        raise ValueError("state version changed")
    resources = _state_resources(state)
    expected = set(intent.nodes) | _SHARED
    if set(resources) != expected or set(intent.resource_ids) != expected:
        raise ValueError("state resources differ")
    if any(not isinstance(value, str) or not value or str(resources[address].get("id")) != value
           for address, value in intent.resource_ids.items()):
        raise ValueError("state ID differs")
    if len({intent.resource_ids[address] for address in intent.nodes}) != len(intent.nodes):
        raise ValueError("node IDs overlap")
    for address, node in intent.nodes.items():
        attrs = resources[address]
        if (attrs.get("name") != node.name or attrs.get("region") != node.region
                or attrs.get("image") != node.image or attrs.get("size") != node.size
                or attrs.get("tags") != [node.firewall_selector_tag]):
            raise ValueError("node identity differs")
    firewall = resources["digitalocean_firewall.firewall"]
    if firewall.get("name") != intent.firewall.name or firewall.get("tags") != [intent.firewall.selector_tag]:
        raise ValueError("firewall identity differs")
    return state


def _state_resources(state: Mapping[str, object]) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for item in state["resources"]:
        if (item.get("mode") != "managed" or item.get("module") is not None
                or not isinstance(item.get("instances"), list)):
            raise ValueError("unexpected resource mode")
        base = f'{item["type"]}.{item["name"]}'
        for instance in item["instances"]:
            key = instance.get("index_key")
            if (key is not None and not isinstance(key, str) and type(key) is not int
                    or instance.get("status") is not None
                    or instance.get("deposed_key") is not None):
                raise ValueError("unexpected resource instance")
            suffix = f"[{json.dumps(key)}]" if isinstance(key, str) or type(key) is int else ""
            address = base + suffix
            if address in result or not isinstance(instance.get("attributes"), dict):
                raise ValueError("duplicate or malformed resource")
            result[address] = instance["attributes"]
    return result


def _plan_resource_values(resources: list) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for resource in resources:
        address = resource["address"]
        if address in result or resource.get("mode") != "managed":
            raise ValueError("unexpected prior resource")
        values = resource["values"]
        if not isinstance(values, dict):
            raise ValueError("unexpected prior values")
        result[address] = values
    return result


def _require_unchanged(
    workspace: ProviderKeyedWorkspace, intent: DigitalOceanTeardownIntent,
    repository: CredentialRepository, inputs: tuple[tuple[str, str], ...],
    staged: tuple[tuple[str, str], ...],
    marker: str, lock: str, topology: str, phase: str, terraform_sha: str,
    terraform_path: Path,
) -> None:
    _verify_audited_workspace(workspace)
    _require_exact_state(workspace, intent)
    _verify_input_hashes(inputs)
    _verify_input_hashes(staged)
    if (_hash_file(workspace.path / ".barragan-provider-keyed-state.json") != marker
            or _hash_file(workspace.path / ".terraform.lock.hcl") != lock
            or _topology_hash(workspace) != topology
            or _hash_file(workspace.path / ".barragan-apply-phase.json") != phase
            or _hash_file(terraform_path) != terraform_sha):
        raise ValueError("reviewed teardown inputs changed")
    digest, updated_at, _ = _credential_snapshot(intent.credential_record_id, repository)
    if (digest, updated_at) != (intent.credential_secret_sha256, intent.credential_updated_at):
        raise ValueError("provider credential changed")


def _checked(result: subprocess.CompletedProcess[str]) -> subprocess.CompletedProcess[str]:
    if result.returncode:
        raise ValueError("Terraform command failed")
    return result


def _run_command(args: list[str], cwd: Path, env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, env=dict(env), capture_output=True, text=True,
                          check=False, umask=0o077)
