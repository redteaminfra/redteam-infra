# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private, durable Terraform workspaces for live Sketch-chain state.

The operator-visible engagement workspace intentionally contains rendered
source and provenance only.  Sketch Terraform state is provider-sensitive and
must remain in a Barragan-owned private directory so later lifecycle operations
can use the same ownership boundary without exposing it to engagement users.
"""

from __future__ import annotations

import os
import grp
import re
import shutil
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from app.core.runtime import runtime_value
from app.services.managed_host_image_continuity import (
    ManagedHostImageContinuityError,
    retained_managed_compute_image,
)
from app.services.sketch_ssh_keys import write_existing_sketch_ssh_key_files
from app.services.sketch_transport_ssh_keys import write_existing_sketch_transport_ssh_key_files

FALLBACK_SKETCH_STATE_ROOT = Path("/var/lib/barragan/sketch-state")
_SAFE_TOKEN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,119}$")
_PROVIDERS = {"linode", "digitalocean"}


class SketchStateWorkspaceError(ValueError):
    pass


@dataclass(frozen=True)
class PreparedSketchStateWorkspace:
    path: Path
    state_path: Path
    terraform_data_dir: Path
    locator: str


@dataclass(frozen=True)
class MaterializedSketchKeys:
    administration_private_key_path: str
    administration_public_key_path: str
    transport_public_key_path: str


def prepare_sketch_state_workspace(
    engagement_id: str,
    chain_id: str,
    provider: str,
    *,
    template_directory: Path,
    root: Path | None = None,
    component_id: str | None = None,
) -> PreparedSketchStateWorkspace:
    """Copy a pinned provider template once into a private chain state root.

    The state boundary is one engagement/chain/provider.  A second call for
    the same identity returns the same location only when its ownership marker
    is present; never adopt an arbitrary directory merely because its path
    matches a requested chain.
    """

    safe_engagement = _token(engagement_id, "engagement id")
    safe_chain = _token(chain_id, "chain id")
    safe_component = _token(component_id, "component id") if component_id else None
    if provider not in _PROVIDERS:
        raise SketchStateWorkspaceError("unsupported sketch provider")
    template = template_directory.resolve(strict=True)
    if not template.is_dir():
        raise SketchStateWorkspaceError("sketch template directory is unavailable")

    private_root = _private_root(root or _default_state_root())
    target = _workspace_path(private_root, safe_engagement, safe_chain, provider, safe_component)
    marker = target / ".barragan-sketch-state"
    if target.exists():
        _validate_sketch_state_workspace(
            safe_engagement,
            safe_chain,
            provider,
            target,
            root=private_root,
            component_id=safe_component,
            require_state=False,
        )
        _grant_collaborator_access(
            safe_engagement,
            safe_chain,
            provider,
            target,
            root=private_root,
            component_id=safe_component,
            require_state=False,
        )
    else:
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _chmod_tree_parent(target.parent, private_root)
        shutil.copytree(template, target)
        _chmod_tree(target)
        marker.write_text(_marker(safe_engagement, safe_chain, provider, safe_component), encoding="utf-8")
        _set_private_file_access(marker)

    terraform_data_dir = target / ".terraform-data"
    terraform_data_dir.mkdir(exist_ok=True, mode=0o700)
    _set_private_directory_access(terraform_data_dir)
    return PreparedSketchStateWorkspace(
        path=target,
        state_path=target / "terraform.tfstate",
        terraform_data_dir=terraform_data_dir,
        locator=_locator(safe_engagement, safe_chain, provider, safe_component),
    )


def validate_existing_sketch_state_workspace(
    engagement_id: str,
    chain_id: str,
    provider: str,
    workspace: Path,
    *,
    root: Path | None = None,
    component_id: str | None = None,
) -> PreparedSketchStateWorkspace:
    """Validate retained state without creating or changing any path."""

    return _validate_sketch_state_workspace(
        engagement_id,
        chain_id,
        provider,
        workspace,
        root=root,
        component_id=component_id,
        require_state=True,
    )


def grant_collaborator_access_to_existing_sketch_state_workspace(
    engagement_id: str,
    chain_id: str,
    provider: str,
    workspace: Path,
    *,
    root: Path | None = None,
    component_id: str | None = None,
) -> PreparedSketchStateWorkspace:
    """Grant the Barragan host group read access after strict retained validation."""

    return _grant_collaborator_access(
        engagement_id,
        chain_id,
        provider,
        workspace,
        root=root,
        component_id=component_id,
        require_state=True,
    )


def _validate_sketch_state_workspace(
    engagement_id: str,
    chain_id: str,
    provider: str,
    workspace: Path,
    *,
    root: Path | None,
    component_id: str | None,
    require_state: bool,
) -> PreparedSketchStateWorkspace:
    """Validate a canonical workspace, optionally before Terraform creates state."""

    safe_engagement = _token(engagement_id, "engagement id")
    safe_chain = _token(chain_id, "chain id")
    safe_component = _token(component_id, "component id") if component_id else None
    if provider not in _PROVIDERS:
        raise SketchStateWorkspaceError("unsupported sketch provider")
    private_root = _read_only_private_root(root or _default_state_root())
    expected = _workspace_path(private_root, safe_engagement, safe_chain, provider, safe_component)
    supplied = workspace.expanduser()
    if not supplied.is_absolute():
        supplied = Path.cwd() / supplied
    if _path_has_symlink(supplied):
        raise SketchStateWorkspaceError("retained sketch state supplied path must not contain symlinks")
    if supplied.resolve(strict=False) != expected.resolve(strict=False):
        raise SketchStateWorkspaceError("retained sketch state path does not match its canonical workspace")
    descendants = list(expected.rglob("*"))
    if _contains_symlink(private_root, expected) or any(path.is_symlink() for path in descendants):
        raise SketchStateWorkspaceError("retained sketch state workspace must not contain symlinks")
    if any(
        _unsafe_workspace_descendant(path)
        for path in descendants
        if path != expected / "terraform.tfstate"
    ):
        raise SketchStateWorkspaceError("retained sketch state workspace ownership or file permissions are unsafe")
    marker = expected / ".barragan-sketch-state"
    if (
        not marker.is_file()
        or marker.is_symlink()
        or marker.read_text(encoding="utf-8")
        != _marker(safe_engagement, safe_chain, provider, safe_component)
    ):
        raise SketchStateWorkspaceError("retained sketch state ownership marker is invalid")
    engagement_root = private_root / safe_engagement
    chain_root = engagement_root / safe_chain
    private_paths = [("root", private_root), ("engagement", engagement_root), ("chain", chain_root)]
    relative_workspace = expected.relative_to(chain_root)
    current = chain_root
    for part in relative_workspace.parts[:-1]:
        current = current / part
        private_paths.append(("workspace ancestor", current))
    private_paths.append(("workspace", expected))
    for label, path in private_paths:
        if not path.is_dir() or _unsafe_private_directory(path):
            raise SketchStateWorkspaceError(f"retained sketch state {label} permissions are unsafe")
    state_path = expected / "terraform.tfstate"
    if state_path.is_symlink():
        raise SketchStateWorkspaceError("retained sketch Terraform state must not contain symlinks")
    if require_state and (not state_path.is_file() or not os.access(state_path, os.R_OK)):
        raise SketchStateWorkspaceError("retained sketch Terraform state is unavailable")
    if state_path.exists() and (
        not state_path.is_file()
        or not os.access(state_path, os.R_OK)
        or _unsafe_private_file(state_path)
    ):
        raise SketchStateWorkspaceError("retained sketch Terraform state permissions are unsafe")
    terraform_data_dir = expected / ".terraform-data"
    if terraform_data_dir.exists() and (
        not terraform_data_dir.is_dir()
        or terraform_data_dir.is_symlink()
        or _unsafe_private_directory(terraform_data_dir)
    ):
        raise SketchStateWorkspaceError("retained sketch Terraform data directory is unsafe")
    return PreparedSketchStateWorkspace(
        path=expected,
        state_path=state_path,
        terraform_data_dir=terraform_data_dir,
        locator=_locator(safe_engagement, safe_chain, provider, safe_component),
    )


def _grant_collaborator_access(
    engagement_id: str,
    chain_id: str,
    provider: str,
    workspace: Path,
    *,
    root: Path | None,
    component_id: str | None,
    require_state: bool,
) -> PreparedSketchStateWorkspace:
    """Transition one fully validated workspace without adopting unsafe paths."""

    prepared = _validate_sketch_state_workspace(
        engagement_id,
        chain_id,
        provider,
        workspace,
        root=root,
        component_id=component_id,
        require_state=require_state,
    )
    group_gid = _collaborator_group_gid()
    if group_gid is None:
        raise SketchStateWorkspaceError("barragan collaborator group is unavailable")
    if os.geteuid() != 0 and group_gid not in {os.getgid(), *os.getgroups()}:
        raise SketchStateWorkspaceError("process is not a member of the barragan collaborator group")

    private_root = _read_only_private_root(root or _default_state_root())
    relative = prepared.path.relative_to(private_root)
    ancestors = [private_root]
    current = private_root
    for part in relative.parts:
        current = current / part
        ancestors.append(current)
    candidates = ancestors + list(prepared.path.rglob("*"))

    # Repeat the ownership/type/write-bit preflight over every mutation target.
    # No chmod/chown occurs until every candidate passes.
    for path in candidates:
        if path.is_symlink() or _unsafe_workspace_descendant(path):
            raise SketchStateWorkspaceError(
                "sketch state collaborator access target ownership or permissions are unsafe"
            )

    for path in candidates:
        metadata = path.stat()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            target_mode = 0o2750
        elif mode & 0o100:
            target_mode = 0o750
        elif mode & 0o004:
            target_mode = 0o644
        else:
            target_mode = 0o640
        if metadata.st_gid != group_gid:
            os.chown(path, -1, group_gid)
        if mode != target_mode:
            os.chmod(path, target_mode)
    return prepared


def retained_compute_image_for_workspace(
    engagement_id: str,
    chain_id: str,
    provider: str,
    workspace: Path,
    *,
    root: Path | None = None,
    component_id: str | None = None,
) -> str:
    """Return the one image identity used by managed compute in retained state."""

    prepared = validate_existing_sketch_state_workspace(
        engagement_id,
        chain_id,
        provider,
        workspace,
        root=root,
        component_id=component_id,
    )
    try:
        return retained_managed_compute_image(prepared.path, provider)
    except ManagedHostImageContinuityError as exc:
        raise SketchStateWorkspaceError(
            f"retained sketch Terraform state has missing or conflicting compute image identity: {exc}"
        ) from exc


@contextmanager
def materialized_sketch_key_files(engagement_id: str):
    """Materialize existing durable identities outside Terraform state.

    Terraform evaluates ``file()`` paths during every plan, apply, and
    destroy.  The encrypted engagement key records are durable; plaintext
    files are not.  This context therefore supplies a private, per-command
    staging directory and removes it on every outcome.
    """

    root = Path(tempfile.mkdtemp(prefix="barragan-sketch-keys-"))
    os.chmod(root, 0o700)
    try:
        administration_private, administration_public = write_existing_sketch_ssh_key_files(engagement_id, root)
        _transport_private, transport_public = write_existing_sketch_transport_ssh_key_files(engagement_id, root)
        yield MaterializedSketchKeys(
            administration_private_key_path=administration_private,
            administration_public_key_path=administration_public,
            transport_public_key_path=transport_public,
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _private_root(root: Path) -> Path:
    raw = root.expanduser()
    if raw.exists():
        if raw.is_symlink() or not raw.is_dir():
            raise SketchStateWorkspaceError("sketch state root must be a directory without symlinks")
        path = raw.resolve(strict=True)
        if _unsafe_private_directory(path):
            raise SketchStateWorkspaceError("existing sketch state root ownership or permissions are unsafe")
        return path
    path = raw.resolve(strict=False)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    _set_private_directory_access(path)
    return path


def _read_only_private_root(root: Path) -> Path:
    raw = root.expanduser()
    if not raw.is_absolute():
        raw = Path.cwd() / raw
    if not raw.is_dir() or raw.is_symlink():
        raise SketchStateWorkspaceError("sketch state root is unavailable or unsafe")
    return raw.resolve(strict=True)


def _default_state_root() -> Path:
    configured = os.environ.get("BARRAGAN_SKETCH_STATE_ROOT", "").strip()
    if configured:
        return Path(configured)
    try:
        return Path(runtime_value("DATA_DIR")) / "sketch-state"
    except RuntimeError:
        return FALLBACK_SKETCH_STATE_ROOT


def _token(value: str, label: str) -> str:
    text = str(value).strip()
    if not _SAFE_TOKEN.fullmatch(text):
        raise SketchStateWorkspaceError(f"{label} must be a safe filesystem token")
    return text


def _marker(engagement_id: str, chain_id: str, provider: str, component_id: str | None = None) -> str:
    suffix = f"{component_id}\n" if component_id else ""
    return f"barragan-sketch-state-v1\n{engagement_id}\n{chain_id}\n{provider}\n{suffix}"


def _workspace_path(root: Path, engagement_id: str, chain_id: str, provider: str, component_id: str | None) -> Path:
    if component_id:
        return root / engagement_id / chain_id / "components" / component_id / provider
    return root / engagement_id / chain_id / provider


def _locator(engagement_id: str, chain_id: str, provider: str, component_id: str | None) -> str:
    middle = f"components/{component_id}/{provider}" if component_id else provider
    return f"sketch/{engagement_id}/{chain_id}/{middle}/terraform.tfstate"


def _contains_symlink(root: Path, target: Path) -> bool:
    try:
        relative = target.relative_to(root)
    except ValueError:
        return True
    current = root
    if current.is_symlink():
        return True
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _path_has_symlink(path: Path) -> bool:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _unsafe_private_directory(path: Path) -> bool:
    metadata = path.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    return (
        metadata.st_uid != os.geteuid()
        or not stat.S_ISDIR(metadata.st_mode)
        or mode & 0o700 != 0o700
        or bool(mode & 0o027)
    )


def _unsafe_private_file(path: Path) -> bool:
    metadata = path.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    return (
        metadata.st_uid != os.geteuid()
        or not stat.S_ISREG(metadata.st_mode)
        or mode & 0o600 != 0o600
        or bool(mode & 0o022)
    )


def _unsafe_workspace_descendant(path: Path) -> bool:
    metadata = path.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid != os.geteuid():
        return True
    if stat.S_ISDIR(metadata.st_mode):
        return bool(mode & 0o022)
    if stat.S_ISREG(metadata.st_mode):
        return mode & 0o600 != 0o600 or bool(mode & 0o022)
    return True


def _chmod_tree(path: Path) -> None:
    for child in path.rglob("*"):
        if child.is_symlink():
            raise SketchStateWorkspaceError("sketch template must not contain symlinks")
        if child.is_dir():
            _set_private_directory_access(child)
        else:
            _set_private_file_access(child, executable=bool(child.stat().st_mode & 0o111))
    _set_private_directory_access(path)


def _chmod_tree_parent(path: Path, root: Path) -> None:
    current = path
    while True:
        _set_private_directory_access(current)
        if current == root:
            return
        current = current.parent


def _collaborator_group_gid() -> int | None:
    try:
        return grp.getgrnam("barragan").gr_gid
    except KeyError:
        return None


def _set_private_directory_access(path: Path) -> None:
    group_gid = _collaborator_group_gid()
    if group_gid is None:
        os.chmod(path, 0o700)
        return
    os.chown(path, -1, group_gid)
    os.chmod(path, 0o2750)


def _set_private_file_access(path: Path, *, executable: bool = False) -> None:
    group_gid = _collaborator_group_gid()
    if group_gid is None:
        os.chmod(path, 0o700 if executable else 0o600)
        return
    os.chown(path, -1, group_gid)
    os.chmod(path, 0o750 if executable else 0o640)
