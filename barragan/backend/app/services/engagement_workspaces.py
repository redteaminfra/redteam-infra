# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from app.services.engagements import get_engagement
from app.services.managed_host_image_continuity import (
    resolve_or_pin_profile_for_new_managed_host,
    retained_oci_source_image,
)
from app.services.redteam_infra_template import RedteamInfraTemplateSource, resolve_redteam_infra_template_source
from app.storage.engagement_workspace_repository import (
    EngagementWorkspaceRepository,
    SqlAlchemyEngagementWorkspaceRepository,
    StoredEngagementWorkspace,
)


DEFAULT_PROFILE_ID = "standard-rti"
WORKSPACE_MARKER_RELATIVE_PATH = Path("barragan") / "workspace-manifest.json"
CORE_RUNS_RELATIVE_PATH = Path("barragan") / "runs"
DEFAULT_TERRAFORM_STATE_ROOT = Path(os.environ.get("BARRAGAN_TERRAFORM_STATE_ROOT", "/var/lib/barragan/terraform-state"))
SAFE_SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,119}$")
GitRunner = Callable[[Path, list[str]], str]


class EngagementWorkspaceValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("engagement workspace validation failed")
        self.errors = errors


@dataclass(frozen=True)
class PreparedEngagementWorkspace:
    workspace: StoredEngagementWorkspace
    created: bool

    def to_dict(self) -> dict[str, object]:
        return {"workspace": self.workspace.to_dict(), "created": self.created}


@dataclass(frozen=True)
class PreparedCoreDeploymentRun:
    """A durable, non-secret render location plus private Terraform state path."""

    workspace: StoredEngagementWorkspace
    run_directory: Path
    state_path: Path
    terraform_data_dir: Path
    state_locator: str
    managed_host_image_profile_name: str
    retained_oci_source_image_id: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "workspace": self.workspace.to_dict(),
            "runDirectory": str(self.run_directory),
            "statePolicy": "private-local-state-v1",
            "stateLocator": self.state_locator,
            "managedHostImageProfile": self.managed_host_image_profile_name,
            "retainedOciSourceImageId": self.retained_oci_source_image_id,
        }


def get_engagement_workspace(
    engagement_id: str,
    *,
    root: Path | None = None,
    repository: EngagementWorkspaceRepository | None = None,
) -> dict[str, object] | None:
    if get_engagement(engagement_id) is None:
        return None
    stored = (repository or SqlAlchemyEngagementWorkspaceRepository()).get(engagement_id)
    if stored is not None and root is not None:
        _assert_existing_workspace_is_owned(stored, _safe_root(root))
    return {"workspace": stored.to_dict()} if stored is not None else {"workspace": None}


def load_prepared_engagement_workspace(
    engagement_id: str,
    *,
    root: Path,
    repository: EngagementWorkspaceRepository | None = None,
) -> StoredEngagementWorkspace | None:
    if get_engagement(engagement_id) is None:
        return None
    stored = (repository or SqlAlchemyEngagementWorkspaceRepository()).get(engagement_id)
    if stored is None:
        raise EngagementWorkspaceValidationError(["engagement workspace must be prepared before rendering capability artifacts"])
    _assert_existing_workspace_is_owned(stored, _safe_root(root))
    return stored


def prepare_engagement_workspace(
    engagement_id: str,
    *,
    root: Path,
    profile_id: str = DEFAULT_PROFILE_ID,
    repository: EngagementWorkspaceRepository | None = None,
    source: RedteamInfraTemplateSource | None = None,
    git_runner: GitRunner | None = None,
) -> PreparedEngagementWorkspace | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    repo = repository or SqlAlchemyEngagementWorkspaceRepository()
    existing = repo.get(engagement_id)
    root_path = _safe_root(root)
    if existing is not None:
        _assert_existing_workspace_is_owned(existing, root_path)
        return PreparedEngagementWorkspace(existing, created=False)

    resolved_source = source or resolve_redteam_infra_template_source()
    slug = workspace_slug(engagement.name, engagement.id)
    target = _safe_child(root_path, slug)
    _assert_target_can_be_created(target)
    _copy_template_source(resolved_source.root, target)
    # The copied Redteam-infra checkout can carry group-readable modes.  The
    # per-engagement tree contains deployment provenance and rendered inputs,
    # so make its ownership boundary explicit before adding Barragan metadata.
    os.chmod(target, 0o700)
    template_source = _template_source_metadata(resolved_source, git_runner=git_runner)
    manifest = _workspace_manifest(
        engagement_id=engagement.id,
        engagement_name=engagement.name,
        slug=slug,
        profile_id=profile_id,
        workspace_path=target,
        template_source=template_source,
    )
    marker = target / WORKSPACE_MARKER_RELATIVE_PATH
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(marker.parent, 0o700)
    os.chmod(marker, 0o600)
    stored = repo.save(
        StoredEngagementWorkspace(
            engagement_id=engagement.id,
            slug=slug,
            path=str(target),
            status="prepared",
            profile_id=profile_id,
            template_source=template_source,
            metadata={
                "markerPath": str(WORKSPACE_MARKER_RELATIVE_PATH),
                "createdBy": "barragan",
                "createdAt": manifest["createdAt"],
            },
        )
    )
    return PreparedEngagementWorkspace(stored, created=True)


def prepare_core_deployment_run(
    engagement_id: str,
    *,
    root: Path,
    run_id: str,
    state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    repository: EngagementWorkspaceRepository | None = None,
    provider_resource_repository: object | None = None,
    job_repository: object | None = None,
    sketch_chain_repository: object | None = None,
) -> PreparedCoreDeploymentRun:
    """Allocate a protected core run only for an explicitly prepared workspace.

    The engagement tree stores only sanitized rendered IaC and provenance.  The
    Terraform state path deliberately lives under the app-private state root;
    it is never copied into the engagement source tree or returned to users.
    """
    workspace = load_prepared_engagement_workspace(engagement_id, root=root, repository=repository)
    if workspace is None:  # defensive; load currently raises for a missing row
        raise EngagementWorkspaceValidationError(["engagement workspace must be prepared before core deployment"])
    private_root = _safe_root(state_root)
    prospective_state_path = _safe_child(private_root, workspace.slug) / "core" / "terraform.tfstate"
    retained_source_image_id = ""
    try:
        if prospective_state_path.exists():
            retained_source_image_id = retained_oci_source_image(
                prospective_state_path,
                allow_no_compute=True,
            )
        selected_image_profile = resolve_or_pin_profile_for_new_managed_host(
            engagement_id,
            repository=repository or SqlAlchemyEngagementWorkspaceRepository(),
            provider_resource_repository=provider_resource_repository,
            retained_state_exists=prospective_state_path.exists(),
        )
        if prospective_state_path.exists() and not retained_source_image_id:
            from app.services.engagement_lifecycle import resolve_engagement_lifecycle

            lifecycle = resolve_engagement_lifecycle(
                engagement_id,
                job_repository=job_repository,
                provider_resource_repository=provider_resource_repository,
                sketch_chain_repository=sketch_chain_repository,
                use_runtime_repositories=True,
            )
            if lifecycle.state != "destroyed":
                raise ValueError(
                    "empty retained core state requires authoritative verified-clean lifecycle evidence"
                )
        workspace = (repository or SqlAlchemyEngagementWorkspaceRepository()).get(engagement_id) or workspace
    except ValueError as exc:
        raise EngagementWorkspaceValidationError([str(exc)]) from exc
    safe_run_id = _safe_run_id(run_id)
    workspace_root = Path(workspace.path).resolve(strict=False)
    run_directory = _safe_workspace_child(workspace_root, CORE_RUNS_RELATIVE_PATH / safe_run_id)
    run_directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    os.chmod(run_directory, 0o700)

    state_directory = _safe_child(private_root, workspace.slug) / "core"
    state_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_directory, 0o700)
    state_path = state_directory / "terraform.tfstate"
    # Do not create an empty state file: Terraform treats it as malformed.
    # Terraform creates the state on first apply; its protected parent already
    # exists, and TF_DATA_DIR is kept private as well.
    terraform_data_dir = _safe_child(state_directory, f"data-{safe_run_id}")
    terraform_data_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    os.chmod(terraform_data_dir, 0o700)
    locator = f"engagement/{workspace.engagement_id}/core/terraform.tfstate"
    run_manifest = {
        "schema": "barragan/core-deployment-run/v1",
        "managedBy": "barragan",
        "engagementId": workspace.engagement_id,
        "workspacePath": workspace.path,
        "runId": safe_run_id,
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "templateSource": workspace.template_source,
        "managedHostImageProfile": selected_image_profile.name,
        "terraformState": {
            "policy": "private-local-state-v1",
            "locator": locator,
            "storedOutsideEngagementWorkspace": True,
            "mode": "0600",
        },
        "secrets": {"persistedInRunWorkspace": False, "note": "Credentials and private keys are supplied at runtime only."},
    }
    run_manifest_path = run_directory / "run-manifest.json"
    run_manifest_path.write_text(json.dumps(run_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(run_manifest_path, 0o600)
    return PreparedCoreDeploymentRun(
        workspace,
        run_directory,
        state_path,
        terraform_data_dir,
        locator,
        selected_image_profile.name,
        retained_source_image_id,
    )


def core_deployment_state_path(
    engagement_id: str,
    *,
    root: Path,
    state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    repository: EngagementWorkspaceRepository | None = None,
) -> Path:
    """Resolve (but never expose) the protected state path for a prepared core."""
    workspace = load_prepared_engagement_workspace(engagement_id, root=root, repository=repository)
    if workspace is None:
        raise EngagementWorkspaceValidationError(["engagement workspace must be prepared before core deployment"])
    return _safe_child(_safe_root(state_root), workspace.slug) / "core" / "terraform.tfstate"


def workspace_slug(engagement_name: str, engagement_id: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", engagement_name.strip().lower())
    base = re.sub(r"-+", "-", base).strip("-")
    if not base or base.startswith("."):
        base = "engagement"
    base = base[:96].strip("-") or "engagement"
    suffix = _safe_id_suffix(engagement_id)
    slug = f"{base}-{suffix}"
    if not SAFE_SLUG_PATTERN.match(slug):
        raise EngagementWorkspaceValidationError(["derived workspace slug is not safe"])
    return slug


def _safe_id_suffix(engagement_id: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "", engagement_id.strip().lower())
    if not cleaned:
        return "unknown"
    return cleaned[-12:]


def _safe_root(root: Path) -> Path:
    root_path = root.expanduser().resolve(strict=False)
    if not root_path.is_absolute():
        raise EngagementWorkspaceValidationError(["engagement workspace root must be absolute"])
    if root_path.exists() and root_path.is_symlink():
        raise EngagementWorkspaceValidationError(["engagement workspace root must not be a symlink"])
    try:
        root_path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise EngagementWorkspaceValidationError([f"engagement workspace root is not writable: {root_path}"]) from exc
    return root_path


def _safe_child(root: Path, slug: str) -> Path:
    candidate = root / slug
    if candidate.is_symlink():
        raise EngagementWorkspaceValidationError(["engagement workspace target must not be a symlink"])
    target = candidate.resolve(strict=False)
    if target == root or root not in target.parents:
        raise EngagementWorkspaceValidationError(["engagement workspace path escapes configured root"])
    if target.name != slug or "/" in slug or "\\" in slug or ".." in slug:
        raise EngagementWorkspaceValidationError(["engagement workspace slug is not safe"])
    return target


def _assert_target_can_be_created(target: Path) -> None:
    if target.is_symlink():
        raise EngagementWorkspaceValidationError(["engagement workspace target must not be a symlink"])
    if target.exists():
        marker = target / WORKSPACE_MARKER_RELATIVE_PATH
        if not marker.is_file() or marker.is_symlink():
            raise EngagementWorkspaceValidationError(["engagement workspace target already exists and is not Barragan-owned"])


def _assert_existing_workspace_is_owned(workspace: StoredEngagementWorkspace, root: Path) -> None:
    path = Path(workspace.path).resolve(strict=False)
    if path == root or root not in path.parents:
        raise EngagementWorkspaceValidationError(["stored engagement workspace path escapes configured root"])
    marker = path / WORKSPACE_MARKER_RELATIVE_PATH
    if path.is_symlink() or not path.is_dir() or not marker.is_file() or marker.is_symlink():
        raise EngagementWorkspaceValidationError(["stored engagement workspace is missing a valid Barragan ownership marker"])
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EngagementWorkspaceValidationError(["stored engagement workspace marker is not valid JSON"]) from exc
    if payload.get("engagementId") != workspace.engagement_id or payload.get("managedBy") != "barragan":
        raise EngagementWorkspaceValidationError(["stored engagement workspace marker does not match Barragan metadata"])


def _copy_template_source(source_root: Path, target: Path) -> None:
    source = source_root.resolve(strict=True)
    if source.is_symlink():
        raise EngagementWorkspaceValidationError(["template source root must not be a symlink"])
    _assert_tree_has_no_symlinks(source)
    shutil.copytree(
        source,
        target,
        ignore=shutil.ignore_patterns(
            ".git", "__pycache__", ".terraform", ".terraform.lock.hcl",
            "*.tfstate", "*.tfstate.*", "*.tfvars", "*.tfvars.json",
            ".env", ".env.*", "credentials", "credentials.*", "*.log",
            "id_rsa", "id_ed25519", "*.pem", "*.key",
        ),
    )


def _assert_tree_has_no_symlinks(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            raise EngagementWorkspaceValidationError([f"template source contains unsupported symlink: {_relative_path(root, path)}"])


def _template_source_metadata(source: RedteamInfraTemplateSource, *, git_runner: GitRunner | None = None) -> dict[str, object]:
    return {
        "path": str(source.root),
        "kind": source.source,
        "warning": source.warning,
        "git": _git_metadata(source.root, git_runner=git_runner),
    }


def _git_metadata(root: Path, *, git_runner: GitRunner | None = None) -> dict[str, object]:
    if not (root / ".git").exists():
        return {"isCheckout": False}
    runner = git_runner or _run_git
    status = _git_value(root, ["status", "--porcelain"], runner)
    return {
        "isCheckout": True,
        "branch": _git_value(root, ["branch", "--show-current"], runner),
        "commit": _git_value(root, ["rev-parse", "HEAD"], runner),
        "dirty": bool(status.strip()),
    }


def _git_value(root: Path, args: list[str], runner: GitRunner) -> str:
    try:
        return runner(root, args).strip()
    except Exception:
        return ""


def _run_git(root: Path, args: list[str]) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], check=False, capture_output=True, text=True)
    if result.returncode != 0:
        return ""
    return result.stdout


def _workspace_manifest(
    *,
    engagement_id: str,
    engagement_name: str,
    slug: str,
    profile_id: str,
    workspace_path: Path,
    template_source: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "barragan/engagement-workspace/v1",
        "managedBy": "barragan",
        "engagementId": engagement_id,
        "engagementName": engagement_name,
        "slug": slug,
        "profileId": profile_id,
        "workspacePath": str(workspace_path),
        "templateSource": template_source,
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "mutation": False,
        "notes": "Prepared workspace only. Terraform, Ansible, Git push, and provider operations are not executed by this action.",
    }


def _relative_path(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _safe_workspace_child(workspace_root: Path, relative: Path) -> Path:
    candidate = (workspace_root / relative).resolve(strict=False)
    if workspace_root not in candidate.parents:
        raise EngagementWorkspaceValidationError(["core deployment run path escapes engagement workspace"])
    return candidate


def _safe_run_id(run_id: str) -> str:
    value = str(run_id).strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,119}", value):
        raise EngagementWorkspaceValidationError(["core deployment run id is not safe"])
    return value
