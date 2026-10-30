# Copyright (c) 2026, Oracle and/or its affiliates.
"""Prepare an audited, non-applying DigitalOcean keyed initial saved plan.

This experimental DevTest helper has no runtime caller. In particular, an
accepted plan is evidence for review, not permission to apply it.
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
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence
from typing import Iterator

from app.services.provider_keyed_initial_plan_gate import (
    DigitalOceanInitialFirewallIntent,
    DigitalOceanNodeCreate,
    _verify_audited_workspace,
    require_digitalocean_keyed_initial_full_plan,
)
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.sketch_state_workspaces import _collaborator_group_gid, _unsafe_private_directory
from app.services.credentials import decrypt_secret_value
from app.services.terraform_plan_gate import TerraformPlanGateError
from app.storage.credential_repository import CredentialRepository


CommandRunner = Callable[[list[str], Path, Mapping[str, str]], subprocess.CompletedProcess[str]]
_HASH = re.compile(r"^[0-9a-f]{64}$")
_PLAN_NAME = ".barragan-initial-full.tfplan"
_ENV_ALLOWLIST = frozenset({
    "PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
})


class ProviderKeyedPlanPreparationError(ValueError):
    """A redacted preparation failure; command output is never included."""


@dataclass(frozen=True)
class ProviderKeyedInitialPlanEvidence:
    plan_path: Path
    plan_sha256: str
    source_sha256: str
    marker_sha256: str
    topology_sha256: str
    lockfile_sha256: str
    state_sha256: None
    input_sha256: tuple[tuple[str, str], ...]
    credential_record_id: str
    credential_secret_sha256: str
    credential_updated_at: str
    terraform_version: str
    terraform_binary_path: Path
    terraform_binary_sha256: str


def prepare_digitalocean_keyed_initial_full_plan(
    workspace: ProviderKeyedWorkspace,
    *,
    environment: str,
    deployment_target: str,
    expected_connection_id: str,
    input_sha256: Mapping[Path, str],
    var_files: Sequence[Path],
    expected_nodes: Mapping[str, DigitalOceanNodeCreate],
    expected_ssh_key_name: str,
    expected_ssh_public_key: str,
    expected_firewall: DigitalOceanInitialFirewallIntent,
    expected_local_files: Mapping[str, Mapping[str, object]],
    credential_repository: CredentialRepository,
    command_environment: Mapping[str, str],
    expected_terraform_sha256: str,
    terraform: str = "terraform",
    command_runner: CommandRunner | None = None,
) -> ProviderKeyedInitialPlanEvidence:
    """Build and inspect one full saved plan while holding the workspace lock.

    ``input_sha256`` must come from the caller's independently reviewed files.
    Secret var-files belong outside the Terraform root so they cannot be
    auto-loaded without the explicit ``-var-file`` argument.

    A future runtime caller must bind the independently reviewed engagement
    draft/profile to the supplied name, selector, image, sizes, SSH key,
    trusted-source policy, and input hashes. This helper does not select that
    product source of truth on its own.
    """

    if environment != "devtest" or deployment_target != "barragan-testing":
        raise ProviderKeyedPlanPreparationError("keyed plan requires DevTest disposable scope")
    if not isinstance(workspace, ProviderKeyedWorkspace) or workspace.provider != "digitalocean":
        raise ProviderKeyedPlanPreparationError("keyed plan workspace is invalid")
    if not expected_connection_id or expected_connection_id != workspace.provider_connection_id:
        raise ProviderKeyedPlanPreparationError("provider connection differs from workspace")
    root = workspace.path
    if root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise ProviderKeyedPlanPreparationError("keyed plan workspace path is unsafe")
    _require_canonical_workspace_paths(workspace)
    if not input_sha256 or not var_files:
        raise ProviderKeyedPlanPreparationError("independent plan inputs are missing")
    if any(key.upper().startswith("TF_") for key in command_environment):
        raise ProviderKeyedPlanPreparationError("Terraform environment inputs must be supplied as reviewed var files")
    canonical_inputs = _check_inputs(root, input_sha256, var_files)
    lock_path = root / ".barragan-initial-full-plan.lock"
    try:
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    except OSError as exc:
        raise ProviderKeyedPlanPreparationError("keyed plan lock is unsafe") from exc
    with os.fdopen(descriptor, "r+b") as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise ProviderKeyedPlanPreparationError("keyed plan lock is unsafe")
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            # Lock order is workspace plan lock, then engagement ordinal lock.
            # reserve_provider_topology takes only the latter.
            with _ordinal_lock(workspace):
                return _prepare_locked(
                    workspace, canonical_inputs, var_files, expected_connection_id,
                    expected_nodes, expected_ssh_key_name, expected_ssh_public_key,
                    expected_firewall, expected_local_files, credential_repository, command_environment,
                    expected_terraform_sha256, terraform, command_runner or _run_command,
                )
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _prepare_locked(
    workspace: ProviderKeyedWorkspace,
    inputs: tuple[tuple[str, str], ...],
    var_files: Sequence[Path],
    connection_id: str,
    nodes: Mapping[str, DigitalOceanNodeCreate],
    ssh_key_name: str,
    ssh_public_key: str,
    firewall: DigitalOceanInitialFirewallIntent,
    local_files: Mapping[str, Mapping[str, object]],
    credential_repository: CredentialRepository,
    command_environment: Mapping[str, str],
    expected_terraform_sha256: str,
    terraform: str,
    run: CommandRunner,
) -> ProviderKeyedInitialPlanEvidence:
    root = workspace.path
    plan_path = root / _PLAN_NAME
    owned_plan_identity: tuple[int, int] | None = None
    owned_plan_descriptor: int | None = None
    staging: Path | None = None
    try:
        credential_digest, credential_updated_at, encrypted_secret = _credential_snapshot(
            connection_id, credential_repository,
        )
        _verify_audited_workspace(workspace)
        if _unsafe_keyed_workspace(root):
            raise ProviderKeyedPlanPreparationError("keyed workspace is not private")
        _require_absent_initial_state(workspace)
        if plan_path.exists() or plan_path.is_symlink():
            raise ProviderKeyedPlanPreparationError("an initial saved plan already exists")
        _verify_input_hashes(inputs)
        staging, staged_var_files, staged_inputs = _stage_var_files(root, inputs, var_files)
        try:
            token = decrypt_secret_value(encrypted_secret)
        except Exception:
            raise ProviderKeyedPlanPreparationError("provider credential cannot be decrypted") from None
        if not token:
            raise ProviderKeyedPlanPreparationError("provider credential is empty")
        credential_var_file, credential_file_hash = _stage_credential(staging, token)
        del token
        staged_inputs = (*staged_inputs, (str(credential_var_file), credential_file_hash))
        marker_hash = _hash_file(root / ".barragan-provider-keyed-state.json")
        topology_hash = _topology_hash(workspace)
        _require_nodes_match_topology(workspace, nodes, firewall)
        lock_hash = _hash_file(root / ".terraform.lock.hcl")
        _require_provider_lock(root / ".terraform.lock.hcl")
        terraform_path = _resolve_terraform(terraform, command_environment)
        terraform_hash = _hash_file(terraform_path)
        if not isinstance(expected_terraform_sha256, str) or not _HASH.fullmatch(expected_terraform_sha256) or terraform_hash != expected_terraform_sha256:
            raise ProviderKeyedPlanPreparationError("Terraform binary differs from reviewed release")
        env = {key: value for key, value in command_environment.items() if key in _ENV_ALLOWLIST}
        env["TF_DATA_DIR"] = str(workspace.terraform_data_dir)
        # Ignore ambient ~/.terraformrc provider dev_overrides and plugin
        # installation policy; the audited lockfile controls provider bytes.
        env["TF_CLI_CONFIG_FILE"] = "/dev/null"
        version = _checked(run([str(terraform_path), "version", "-json"], root, env))
        try:
            parsed = json.loads(version.stdout)
        except (TypeError, ValueError) as exc:
            raise ProviderKeyedPlanPreparationError("Terraform version is unverified") from exc
        if not isinstance(parsed, dict) or parsed.get("terraform_version") != "1.15.5":
            raise ProviderKeyedPlanPreparationError("Terraform version is unverified")
        _checked(run([str(terraform_path), "init", "-input=false", "-lockfile=readonly", "-no-color"], root, env))
        _verify_static_evidence(workspace, staged_inputs, marker_hash, lock_hash)
        if _topology_hash(workspace) != topology_hash:
            raise ProviderKeyedPlanPreparationError("reviewed topology changed during plan preparation")
        args = [str(terraform_path), "plan", "-input=false", "-lock=true", "-no-color", f"-out={plan_path}"]
        args.extend(f"-var-file={path}" for path in staged_var_files)
        args.append(f"-var-file={credential_var_file}")
        owned_plan_descriptor = os.open(plan_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        plan_info = os.fstat(owned_plan_descriptor)
        owned_plan_identity = (plan_info.st_dev, plan_info.st_ino)
        os.fchmod(owned_plan_descriptor, 0o600)
        _checked(run(args, root, env))
        if plan_path.is_symlink() or not plan_path.is_file():
            raise ProviderKeyedPlanPreparationError("saved plan binary is missing")
        plan_descriptor = os.open(plan_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            plan_info = os.fstat(plan_descriptor)
            if (not stat.S_ISREG(plan_info.st_mode) or plan_info.st_uid != os.geteuid()
                    or (plan_info.st_dev, plan_info.st_ino) != owned_plan_identity
                    or stat.S_IMODE(plan_info.st_mode) & 0o077):
                raise ProviderKeyedPlanPreparationError("saved plan binary is unsafe")
        finally:
            os.close(plan_descriptor)
        plan_hash = _hash_file(plan_path)
        shown = _checked(run([str(terraform_path), "show", "-json", str(plan_path)], root, env))
        if _hash_file(plan_path) != plan_hash:
            raise ProviderKeyedPlanPreparationError("saved plan changed during inspection")
        require_digitalocean_keyed_initial_full_plan(
            shown.stdout,
            workspace=workspace,
            expected_nodes=nodes,
            expected_ssh_key_name=ssh_key_name,
            expected_ssh_public_key=ssh_public_key,
            expected_firewall=firewall,
            expected_local_files=local_files,
        )
        _require_plan_topology_variables(shown.stdout, workspace)
        _verify_static_evidence(workspace, staged_inputs, marker_hash, lock_hash)
        if _topology_hash(workspace) != topology_hash:
            raise ProviderKeyedPlanPreparationError("reviewed topology changed during plan preparation")
        current_digest, current_updated_at, _ = _credential_snapshot(connection_id, credential_repository)
        if (current_digest, current_updated_at) != (credential_digest, credential_updated_at):
            raise ProviderKeyedPlanPreparationError("provider credential rotated during plan preparation")
        if _hash_file(plan_path) != plan_hash:
            raise ProviderKeyedPlanPreparationError("saved plan changed during inspection")
        if _hash_file(terraform_path) != expected_terraform_sha256:
            raise ProviderKeyedPlanPreparationError("Terraform binary changed during inspection")
        return ProviderKeyedInitialPlanEvidence(
            plan_path, plan_hash, workspace.source_sha256, marker_hash,
            topology_hash, lock_hash, None, inputs, connection_id, credential_digest,
            credential_updated_at, "1.15.5", terraform_path,
            terraform_hash,
        )
    except (OSError, ValueError, subprocess.SubprocessError, TerraformPlanGateError) as exc:
        _remove_owned_plan(plan_path, owned_plan_identity)
        if isinstance(exc, ProviderKeyedPlanPreparationError):
            raise
        raise ProviderKeyedPlanPreparationError("keyed saved-plan preparation failed") from None
    finally:
        if owned_plan_descriptor is not None:
            os.close(owned_plan_descriptor)
        if staging is not None:
            shutil.rmtree(staging)


def _check_inputs(
    root: Path, expected: Mapping[Path, str], var_files: Sequence[Path]
) -> tuple[tuple[str, str], ...]:
    if any(not isinstance(path, Path) or not path.is_absolute() or not isinstance(digest, str)
           or not _HASH.fullmatch(digest) for path, digest in expected.items()):
        raise ProviderKeyedPlanPreparationError("independent input manifest is invalid")
    if any(not isinstance(path, Path) or not path.is_absolute() or path not in expected
           or path == root or root in path.parents for path in var_files):
        raise ProviderKeyedPlanPreparationError("var files must be reviewed outside the Terraform workspace")
    if len(set(var_files)) != len(var_files):
        raise ProviderKeyedPlanPreparationError("var files are duplicated")
    if set(var_files) != set(expected):
        raise ProviderKeyedPlanPreparationError("every reviewed input must be an explicit var file")
    if any(path.stat().st_mode & 0o077 for path in var_files):
        raise ProviderKeyedPlanPreparationError("reviewed var files must be private")
    result = tuple(sorted((str(path), digest) for path, digest in expected.items()))
    _verify_input_hashes(result)
    return result


def _credential_snapshot(connection_id: str, repository: CredentialRepository) -> tuple[str, str, str]:
    try:
        credential = repository.get(connection_id)
        default = repository.get_default("digitalocean")
    except Exception:
        raise ProviderKeyedPlanPreparationError("active provider connection is unavailable") from None
    if (credential is None or default is None
            or credential.id != connection_id or default.id != connection_id
            or credential.provider != "digitalocean" or default.provider != "digitalocean"
            or credential.status != "active" or default.status != "active"
            or credential.is_default is not True or default.is_default is not True
            or credential.encrypted_secret != default.encrypted_secret
            or credential.updated_at != default.updated_at
            or not isinstance(credential.encrypted_secret, str)
            or not credential.encrypted_secret):
        raise ProviderKeyedPlanPreparationError("active provider connection differs from workspace")
    return (
        hashlib.sha256(credential.encrypted_secret.encode("utf-8")).hexdigest(),
        credential.updated_at, credential.encrypted_secret,
    )


def _require_canonical_workspace_paths(workspace: ProviderKeyedWorkspace) -> None:
    root = workspace.path
    if (workspace.state_path != root / "terraform.tfstate"
            or workspace.terraform_data_dir != root / ".terraform-data"
            or workspace.state_path.is_symlink()
            or workspace.terraform_data_dir.is_symlink()
            or not workspace.terraform_data_dir.is_dir()):
        raise ProviderKeyedPlanPreparationError("provider-keyed Terraform paths are not canonical")


def _wrong_collaborator_group(gid: int, mode: int) -> bool:
    if not mode & 0o070:
        return False
    collaborator_gid = _collaborator_group_gid()
    return collaborator_gid is None or gid != collaborator_gid


def _unsafe_keyed_workspace(path: Path) -> bool:
    if _unsafe_private_directory(path):
        return True
    info = path.stat()
    return _wrong_collaborator_group(info.st_gid, stat.S_IMODE(info.st_mode))


def _remove_owned_plan(path: Path, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    try:
        info = path.lstat()
        if stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == identity:
            path.unlink()
    except FileNotFoundError:
        pass


def _topology_hash(workspace: ProviderKeyedWorkspace) -> str:
    path = workspace.path / ".barragan-topology.json"
    try:
        topology = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ProviderKeyedPlanPreparationError("reviewed provider topology is missing") from None
    if (path.is_symlink() or not isinstance(topology, dict)
            or topology.get("schema") != workspace.schema
            or not isinstance(topology.get("middles"), dict)
            or not topology["middles"]):
        raise ProviderKeyedPlanPreparationError("reviewed provider topology is invalid")
    return _hash_file(path)


def _reviewed_topology(
    workspace: ProviderKeyedWorkspace, *, expected_topology_path: Path | None,
    expected_topology_sha256: str | None,
) -> dict:
    if expected_topology_path is None:
        if expected_topology_sha256 is not None:
            raise ProviderKeyedPlanPreparationError("reviewed topology input is invalid")
        path = workspace.path / ".barragan-topology.json"
        try:
            payload = path.read_bytes()
        except OSError:
            raise ProviderKeyedPlanPreparationError("reviewed provider topology is invalid") from None
    else:
        path = workspace.path.parents[1] / ".plan-material" / "digitalocean" / "append-inputs.json"
        if (expected_topology_path != path or type(expected_topology_sha256) is not str
                or not _HASH.fullmatch(expected_topology_sha256)):
            raise ProviderKeyedPlanPreparationError("reviewed append topology input is invalid")
        try:
            info = path.lstat()
            payload = path.read_bytes()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) & 0o077
                    or hashlib.sha256(payload).hexdigest() != expected_topology_sha256):
                raise ProviderKeyedPlanPreparationError("reviewed append topology input differs")
        except OSError:
            raise ProviderKeyedPlanPreparationError("reviewed append topology input is missing") from None
    try:
        topology = json.loads(payload.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise ProviderKeyedPlanPreparationError("reviewed provider topology is invalid") from None
    if not isinstance(topology, dict):
        raise ProviderKeyedPlanPreparationError("reviewed provider topology is invalid")
    return topology


def _require_nodes_match_topology(
    workspace: ProviderKeyedWorkspace,
    nodes: Mapping[str, DigitalOceanNodeCreate],
    firewall: DigitalOceanInitialFirewallIntent,
    *, expected_topology_path: Path | None = None,
    expected_topology_sha256: str | None = None,
) -> None:
    """Bind plan node intent to reserved logical keys and regional ordinals."""

    topology = _reviewed_topology(
        workspace, expected_topology_path=expected_topology_path,
        expected_topology_sha256=expected_topology_sha256)
    if (not isinstance(topology, dict) or not isinstance(firewall, DigitalOceanInitialFirewallIntent)
            or not firewall.name.endswith("-firewall")):
        raise ProviderKeyedPlanPreparationError("reviewed topology or firewall intent is invalid")
    engagement_name = firewall.name.removesuffix("-firewall")
    if not engagement_name:
        raise ProviderKeyedPlanPreparationError("reviewed firewall name is invalid")
    expected: dict[str, tuple[str, str]] = {}
    middles = topology.get("middles")
    groups = topology.get("edge_groups")
    if not isinstance(middles, dict) or not middles or not isinstance(groups, dict):
        raise ProviderKeyedPlanPreparationError("reviewed provider topology is invalid")
    for key, item in middles.items():
        if (not isinstance(key, str) or not isinstance(item, dict)
                or not isinstance(item.get("region"), str)
                or type(item.get("ordinal")) is not int or item["ordinal"] < 1):
            raise ProviderKeyedPlanPreparationError("reviewed middle topology is invalid")
        expected[f'digitalocean_droplet.middle[{json.dumps(key)}]'] = (
            f'middle{item["ordinal"]:02d}-{engagement_name}', item["region"],
        )
    for group in groups.values():
        if (not isinstance(group, dict) or not isinstance(group.get("region"), str)
                or group.get("middle_node") not in middles
                or not isinstance(group.get("ordinals"), list)):
            raise ProviderKeyedPlanPreparationError("reviewed edge topology is invalid")
        region = group["region"]
        for ordinal in group["ordinals"]:
            if type(ordinal) is not int or ordinal < 1:
                raise ProviderKeyedPlanPreparationError("reviewed edge ordinal is invalid")
            identity = f"{region.lower()}-{ordinal:02d}"
            address = f'digitalocean_droplet.edge[{json.dumps(identity)}]'
            if address in expected:
                raise ProviderKeyedPlanPreparationError("reviewed edge identity repeats")
            expected[address] = (f"edge-{engagement_name}-{region}-{ordinal:02d}", region)
    if set(nodes) != set(expected) or any(
        not isinstance(intent, DigitalOceanNodeCreate)
        or (intent.name, intent.region) != expected[address]
        or intent.firewall_selector_tag != firewall.selector_tag
        for address, intent in nodes.items()
    ):
        raise ProviderKeyedPlanPreparationError("reviewed nodes differ from reserved topology")


def _require_plan_topology_variables(
    saved_plan_json: str, workspace: ProviderKeyedWorkspace, *,
    expected_topology_path: Path | None = None,
    expected_topology_sha256: str | None = None,
) -> None:
    """Compare actual saved-plan inputs with the reserved controller topology.

    Inspect only the two non-secret topology variables. In particular, never
    serialize or report the plan's `do_pat` value.
    """

    try:
        plan = json.loads(saved_plan_json)
        variables = plan["variables"]
        middles = variables["middles"]["value"]
        groups = variables["edge_groups"]["value"]
    except (OSError, ValueError, TypeError, KeyError):
        raise ProviderKeyedPlanPreparationError("saved plan topology variables are missing") from None
    topology = _reviewed_topology(
        workspace, expected_topology_path=expected_topology_path,
        expected_topology_sha256=expected_topology_sha256)
    reserved_middles = topology.get("middles") if isinstance(topology, dict) else None
    reserved_groups = topology.get("edge_groups") if isinstance(topology, dict) else None
    if (not isinstance(middles, dict) or not isinstance(groups, dict)
            or not isinstance(reserved_middles, dict)
            or not isinstance(reserved_groups, dict)
            or set(middles) != set(reserved_middles)
            or set(groups) != set(reserved_groups)):
        raise ProviderKeyedPlanPreparationError("saved plan topology differs from reservation")
    for key, actual in middles.items():
        expected = reserved_middles[key]
        if (not isinstance(actual, dict) or set(actual) != {"region", "ordinal"}
                or not isinstance(expected, dict)
                or actual.get("region") != expected.get("region")
                or type(actual.get("ordinal")) is not int
                or actual["ordinal"] != expected.get("ordinal")):
            raise ProviderKeyedPlanPreparationError("saved plan middle topology differs from reservation")
    for key, actual in groups.items():
        expected = reserved_groups[key]
        if (not isinstance(actual, dict) or not isinstance(expected, dict)
                or set(actual) - {"region", "middle_node", "count", "ordinal_start", "ordinals"}
                or actual.get("region") != expected.get("region")
                or actual.get("middle_node") != expected.get("middle_node")):
            raise ProviderKeyedPlanPreparationError("saved plan edge group differs from reservation")
        ordinals = actual.get("ordinals")
        count = actual.get("count")
        start = actual.get("ordinal_start", 1)
        if type(start) is not int or start < 1 or (count is None) == (ordinals is None):
            raise ProviderKeyedPlanPreparationError("saved plan edge allocation is invalid")
        if ordinals is not None:
            if (not isinstance(ordinals, list)
                    or any(type(value) is not int or value < 1 for value in ordinals)
                    or len(set(ordinals)) != len(ordinals)):
                raise ProviderKeyedPlanPreparationError("saved plan edge ordinals are invalid")
            allocated = sorted(ordinals)
        else:
            if type(count) is not int or count < 0:
                raise ProviderKeyedPlanPreparationError("saved plan edge count is invalid")
            allocated = list(range(start, start + count))
        if allocated != expected.get("ordinals"):
            raise ProviderKeyedPlanPreparationError("saved plan edge allocation differs from reservation")


@contextmanager
def _ordinal_lock(workspace: ProviderKeyedWorkspace) -> Iterator[None]:
    root = workspace.path
    schema_root = root.parents[1]
    if (schema_root.name != workspace.schema or root.parent.name != workspace.provider
            or root.name != workspace.connection_fingerprint):
        raise ProviderKeyedPlanPreparationError("provider-keyed workspace layout is invalid")
    path = schema_root / ".regional-ordinals.lock"
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ProviderKeyedPlanPreparationError("regional ordinal lock is missing or unsafe") from None
    with os.fdopen(descriptor, "r+b") as lock:
        info = os.fstat(lock.fileno())
        mode = stat.S_IMODE(info.st_mode)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or mode & 0o600 != 0o600 or mode & 0o027
                or _wrong_collaborator_group(info.st_gid, mode)):
            raise ProviderKeyedPlanPreparationError("regional ordinal lock is unsafe")
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _stage_credential(directory: Path, token: str) -> tuple[Path, str]:
    destination = directory / "credential.json"
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        json.dump({"do_pat": token}, target)
        target.write("\n")
        target.flush()
        os.fsync(target.fileno())
    return destination, _hash_file(destination)


def _stage_var_files(
    root: Path, inputs: tuple[tuple[str, str], ...], var_files: Sequence[Path],
    *, prefix: str = ".barragan-plan-inputs-",
) -> tuple[Path, tuple[Path, ...], tuple[tuple[str, str], ...]]:
    """Make private immutable-for-this-plan copies under the workspace lock.

    Terraform only receives these paths. The staged names are not `.tfvars`
    or `.auto.tfvars`, so Terraform cannot load them except by `-var-file`.
    JSON var files keep a `.json` suffix for Terraform's parser.
    """

    expected = dict(inputs)
    if prefix not in {".barragan-plan-inputs-", ".barragan-append-inputs-"}:
        raise ProviderKeyedPlanPreparationError("unrecognized staged plan input owner")
    directory = Path(tempfile.mkdtemp(prefix=prefix, dir=root))
    staged: list[Path] = []
    hashes: list[tuple[str, str]] = []
    try:
        for index, source in enumerate(var_files):
            content = source.read_bytes()
            digest = hashlib.sha256(content).hexdigest()
            if digest != expected[str(source)]:
                raise ProviderKeyedPlanPreparationError("reviewed plan input changed")
            suffix = ".json" if source.name.endswith(".json") else ".input"
            destination = directory / f"input-{index}{suffix}"
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as target:
                target.write(content)
                target.flush()
                os.fsync(target.fileno())
            if _hash_file(destination) != digest:
                raise ProviderKeyedPlanPreparationError("staged plan input changed")
            staged.append(destination)
            hashes.append((str(destination), digest))
        return directory, tuple(staged), tuple(hashes)
    except Exception:
        shutil.rmtree(directory)
        raise


def _verify_input_hashes(inputs: tuple[tuple[str, str], ...]) -> None:
    for name, expected in inputs:
        path = Path(name)
        if path.is_symlink() or not path.is_file() or _hash_file(path) != expected:
            raise ProviderKeyedPlanPreparationError("reviewed plan input changed")


def _verify_static_evidence(
    workspace: ProviderKeyedWorkspace, inputs: tuple[tuple[str, str], ...],
    marker_hash: str, lock_hash: str,
) -> None:
    _verify_audited_workspace(workspace)
    _require_absent_initial_state(workspace)
    if (_hash_file(workspace.path / ".barragan-provider-keyed-state.json") != marker_hash
            or _hash_file(workspace.path / ".terraform.lock.hcl") != lock_hash):
        raise ProviderKeyedPlanPreparationError("keyed workspace source changed")
    _verify_input_hashes(inputs)


def _require_absent_initial_state(workspace: ProviderKeyedWorkspace) -> None:
    if workspace.state_path.exists() or workspace.state_path.is_symlink() or any(
        workspace.path.glob("terraform.tfstate*")
    ):
        raise ProviderKeyedPlanPreparationError("initial plan requires absent Terraform state")


def _require_provider_lock(path: Path) -> None:
    content = path.read_text(encoding="utf-8")
    if not re.search(r'provider "registry\.terraform\.io/digitalocean/digitalocean"\s*\{\s*version\s*=\s*"2\.103\.0"', content):
        raise ProviderKeyedPlanPreparationError("DigitalOcean provider lock is unverified")


def _resolve_terraform(terraform: str, environment: Mapping[str, str]) -> Path:
    if not isinstance(terraform, str) or not terraform:
        raise ProviderKeyedPlanPreparationError("Terraform executable is unavailable")
    located = terraform if Path(terraform).is_absolute() else shutil.which(
        terraform, path=environment.get("PATH", ""),
    )
    if not located:
        raise ProviderKeyedPlanPreparationError("Terraform executable is unavailable")
    path = Path(located).resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ProviderKeyedPlanPreparationError("Terraform executable is unavailable")
    return path


def _hash_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ProviderKeyedPlanPreparationError("reviewed artifact is missing")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _checked(result: subprocess.CompletedProcess[str]) -> subprocess.CompletedProcess[str]:
    if result.returncode:
        raise ProviderKeyedPlanPreparationError("Terraform command failed")
    return result


def _run_command(args: list[str], cwd: Path, env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, env=dict(env), capture_output=True, text=True,
                          check=False, umask=0o077)
