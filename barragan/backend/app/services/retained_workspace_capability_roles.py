# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

from app.services.capability_catalog import DEFAULT_CAPABILITY_MANIFEST_ROOT, SUPPORTED_API_VERSION
from app.services.engagement_workspaces import (
    WORKSPACE_MARKER_RELATIVE_PATH,
    EngagementWorkspaceValidationError,
)
from app.services.redteam_infra_template import (
    RedteamInfraTemplateSource,
    resolve_redteam_infra_template_source,
)
from app.storage.engagement_workspace_repository import EngagementWorkspaceRepository, StoredEngagementWorkspace


CAPABILITY_ROLE_IMPORTS_METADATA_KEY = "capabilityRoleImports"
CAPABILITY_ROLE_IMPORTS_MARKER_KEY = "capabilityRoleImports"
CAPABILITY_ROLE_IMPORT_JOURNAL = "capability-role-import-pending.json"
CAPABILITY_ROLE_IMPORT_JOURNAL_SCHEMA = "barragan/capability-role-import-transaction/v1"
ROLE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
GitRunner = Callable[[Path, list[str]], str]


@dataclass(frozen=True)
class _PackagedOptionalRole:
    capability_id: str
    role: str
    allowed_host_classes: tuple[str, ...]


@dataclass(frozen=True)
class _GitProvenance:
    commit: str
    tree: str
    role_trees: dict[str, str]


def import_selected_optional_capability_roles(
    workspace: StoredEngagementWorkspace,
    selected_optionals: list[dict[str, str]],
    *,
    repository: EngagementWorkspaceRepository,
    template_source: RedteamInfraTemplateSource | None = None,
    manifest_root: Path | None = None,
    git_runner: GitRunner | None = None,
) -> StoredEngagementWorkspace:
    """Import missing, explicitly selected packaged roles into a retained tree.

    Existing role directories are immutable from this workflow. The configured
    Redteam-infra checkout is consulted only when at least one selected role is
    absent, and only the packaged manifest's exact role plus declared Ansible
    dependencies may be copied.
    """

    workspace_root = Path(workspace.path)
    roles_root = _safe_workspace_roles_root(workspace_root)
    metadata_root = _safe_workspace_metadata_root(workspace_root)
    journal_path = metadata_root / CAPABILITY_ROLE_IMPORT_JOURNAL
    if journal_path.exists() or journal_path.is_symlink():
        workspace = _recover_pending_import(
            workspace,
            repository=repository,
            roles_root=roles_root,
            metadata_root=metadata_root,
            source=template_source or resolve_redteam_infra_template_source(),
            git_runner=git_runner or _run_git,
        )
    requested = _requested_packaged_roles(selected_optionals, manifest_root=manifest_root)
    if not requested:
        return workspace
    missing_requests: list[_PackagedOptionalRole] = []
    for item in requested:
        destination = roles_root / item.role
        if destination.is_symlink():
            raise EngagementWorkspaceValidationError(
                [f"retained Ansible role path must not be a symlink: ansible/roles/{item.role}"]
            )
        if destination.exists():
            if not destination.is_dir():
                raise EngagementWorkspaceValidationError(
                    [f"retained Ansible role path is not a directory: ansible/roles/{item.role}"]
                )
            continue
        missing_requests.append(item)
    if not missing_requests:
        return workspace

    source = template_source or resolve_redteam_infra_template_source()
    source_root = _validate_source_root(source)
    runner = git_runner or _run_git
    commit, tree = _clean_source_revision(source_root, runner)

    ordered_roles: list[str] = []
    role_dependencies: dict[str, list[str]] = {}
    for item in missing_requests:
        _collect_role_and_dependencies(
            source_root,
            item.role,
            ordered=ordered_roles,
            dependencies=role_dependencies,
        )

    role_trees = {
        role: _required_git_value(source_root, ["rev-parse", f"HEAD:ansible/roles/{role}"], runner,
                                  f"selected Ansible role is not tracked in the configured Redteam-infra revision: {role}")
        for role in ordered_roles
    }
    _assert_source_revision_unchanged(source_root, runner, commit=commit, tree=tree)
    provenance = _GitProvenance(commit=commit, tree=tree, role_trees=role_trees)

    missing_roles: list[str] = []
    preserved_roles: list[str] = []
    for role in ordered_roles:
        destination = roles_root / role
        if destination.is_symlink():
            raise EngagementWorkspaceValidationError(
                [f"retained Ansible role path must not be a symlink: ansible/roles/{role}"]
            )
        if destination.exists():
            if not destination.is_dir():
                raise EngagementWorkspaceValidationError(
                    [f"retained Ansible role path is not a directory: ansible/roles/{role}"]
                )
            preserved_roles.append(role)
        else:
            missing_roles.append(role)

    if not missing_roles:
        return workspace

    imported_at = datetime.now(timezone.utc).isoformat()
    records = _provenance_records(
        missing_requests,
        ordered_roles=ordered_roles,
        missing_roles=missing_roles,
        preserved_roles=preserved_roles,
        dependencies=role_dependencies,
        provenance=provenance,
        source_kind=source.source,
        imported_at=imported_at,
    )
    for role in missing_roles:
        _assert_tree_has_no_symlinks(source_root / "ansible" / "roles" / role, label=f"Ansible role {role}")
    _assert_source_revision_unchanged(source_root, runner, commit=commit, tree=tree)
    _write_json_atomically(
        journal_path,
        {
            "schema": CAPABILITY_ROLE_IMPORT_JOURNAL_SCHEMA,
            "engagementId": workspace.engagement_id,
            "source": {
                "kind": source.source,
                "commit": commit,
                "tree": tree,
                "roleTrees": role_trees,
            },
            "roles": missing_roles,
            "records": records,
        },
    )
    return _recover_pending_import(
        workspace,
        repository=repository,
        roles_root=roles_root,
        metadata_root=metadata_root,
        source=source,
        git_runner=runner,
    )


def _recover_pending_import(
    workspace: StoredEngagementWorkspace,
    *,
    repository: EngagementWorkspaceRepository,
    roles_root: Path,
    metadata_root: Path,
    source: RedteamInfraTemplateSource,
    git_runner: GitRunner,
) -> StoredEngagementWorkspace:
    """Finish a journaled role import after success, failure, or restart."""

    journal_path = metadata_root / CAPABILITY_ROLE_IMPORT_JOURNAL
    journal = _load_import_journal(journal_path, workspace.engagement_id)
    source_root = _validate_source_root(source)
    commit, tree = _clean_source_revision(source_root, git_runner)
    recorded_source = journal["source"]
    if commit != recorded_source["commit"] or tree != recorded_source["tree"]:
        raise EngagementWorkspaceValidationError(
            ["configured Redteam-infra source no longer matches the pending capability role import"]
        )

    roles = journal["roles"]
    for role in roles:
        expected_tree = _required_git_value(
            source_root,
            ["rev-parse", f"HEAD:ansible/roles/{role}"],
            git_runner,
            f"pending Ansible role is not tracked in the configured Redteam-infra revision: {role}",
        )
        if expected_tree != recorded_source["roleTrees"].get(role):
            raise EngagementWorkspaceValidationError(
                [f"configured Redteam-infra role no longer matches the pending import: {role}"]
            )
        source_role = source_root / "ansible" / "roles" / role
        _assert_tree_has_no_symlinks(source_role, label=f"Ansible role {role}")
        destination = roles_root / role
        if destination.is_symlink():
            raise EngagementWorkspaceValidationError(
                [f"retained Ansible role path must not be a symlink: ansible/roles/{role}"]
            )
        if destination.exists():
            if not destination.is_dir() or not _directory_trees_equal(source_role, destination):
                raise EngagementWorkspaceValidationError(
                    [f"retained Ansible role conflicts with the pending import: ansible/roles/{role}"]
                )
            continue
        stage = Path(tempfile.mkdtemp(prefix=".capability-role-recovery-", dir=metadata_root))
        try:
            staged_role = stage / role
            shutil.copytree(source_role, staged_role)
            _assert_source_revision_unchanged(source_root, git_runner, commit=commit, tree=tree)
            if destination.exists() or destination.is_symlink():
                raise EngagementWorkspaceValidationError(
                    [f"retained Ansible role appeared during import and was not overwritten: ansible/roles/{role}"]
                )
            os.replace(staged_role, destination)
        finally:
            shutil.rmtree(stage, ignore_errors=True)

    marker_path = metadata_root / WORKSPACE_MARKER_RELATIVE_PATH.name
    marker = _load_workspace_marker(marker_path, workspace.engagement_id)
    records = journal["records"]
    updated_marker = dict(marker)
    updated_marker[CAPABILITY_ROLE_IMPORTS_MARKER_KEY] = _merge_provenance_records(
        marker.get(CAPABILITY_ROLE_IMPORTS_MARKER_KEY), records
    )
    _write_json_atomically(marker_path, updated_marker)

    updated_metadata = dict(workspace.metadata)
    updated_metadata[CAPABILITY_ROLE_IMPORTS_METADATA_KEY] = _merge_provenance_records(
        updated_metadata.get(CAPABILITY_ROLE_IMPORTS_METADATA_KEY), records
    )
    updated_workspace = repository.save(replace(workspace, metadata=updated_metadata))
    journal_path.unlink()
    return updated_workspace


def _load_import_journal(path: Path, engagement_id: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise EngagementWorkspaceValidationError(["pending capability role import journal is invalid"])
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EngagementWorkspaceValidationError(["pending capability role import journal is invalid JSON"]) from exc
    source = payload.get("source") if isinstance(payload, dict) else None
    roles = payload.get("roles") if isinstance(payload, dict) else None
    records = payload.get("records") if isinstance(payload, dict) else None
    role_trees = source.get("roleTrees") if isinstance(source, dict) else None
    valid_roles = (
        isinstance(roles, list)
        and bool(roles)
        and len(roles) == len(set(roles))
        and all(isinstance(role, str) and ROLE_NAME_PATTERN.fullmatch(role) for role in roles)
    )
    valid_records = isinstance(records, list) and bool(records) and all(isinstance(item, dict) for item in records)
    valid_source = (
        isinstance(source, dict)
        and isinstance(source.get("commit"), str)
        and bool(source.get("commit"))
        and isinstance(source.get("tree"), str)
        and bool(source.get("tree"))
        and isinstance(role_trees, dict)
        and all(isinstance(role_trees.get(role), str) and role_trees.get(role) for role in roles or [])
    )
    if not (
        isinstance(payload, dict)
        and payload.get("schema") == CAPABILITY_ROLE_IMPORT_JOURNAL_SCHEMA
        and payload.get("engagementId") == engagement_id
        and valid_roles
        and valid_records
        and valid_source
    ):
        raise EngagementWorkspaceValidationError(["pending capability role import journal is invalid"])
    return payload


def _directory_trees_equal(left: Path, right: Path) -> bool:
    def snapshot(root: Path) -> list[tuple[str, str, bytes]]:
        rows: list[tuple[str, str, bytes]] = []
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                return []
            relative = path.relative_to(root).as_posix()
            if path.is_dir():
                rows.append((relative, "directory", b""))
            elif path.is_file():
                rows.append((relative, "file", path.read_bytes()))
            else:
                return []
        return rows

    return snapshot(left) == snapshot(right)


def _merge_provenance_records(existing: Any, additions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged = _existing_records(existing)
    identities = {_provenance_identity(record) for record in merged}
    for record in additions:
        identity = _provenance_identity(record)
        if identity not in identities:
            merged.append(dict(record))
            identities.add(identity)
    return merged


def _provenance_identity(record: dict[str, Any]) -> tuple[str, str, str, str]:
    source = record.get("source") if isinstance(record.get("source"), dict) else {}
    return (
        str(record.get("schema") or ""),
        str(record.get("capabilityId") or ""),
        str(record.get("role") or ""),
        str(source.get("commit") or ""),
    )


def importable_packaged_optional_role_selections(
    selected_optionals: list[dict[str, str]],
    *,
    manifest_root: Path | None = None,
) -> set[tuple[str, str]]:
    """Return validated host/capability pairs eligible for retained import."""

    manifests = _packaged_optional_role_manifests(manifest_root=manifest_root)
    importable: set[tuple[str, str]] = set()
    for row in selected_optionals:
        capability_id = str(row.get("id") or "").strip()
        host_class = str(row.get("hostClass") or "").strip()
        manifest = manifests.get(capability_id)
        if manifest is None:
            continue
        if host_class not in manifest.allowed_host_classes:
            raise EngagementWorkspaceValidationError(
                [f"packaged optional capability {capability_id} is not allowed on host class {host_class}"]
            )
        importable.add((host_class, capability_id))
    return importable


def _requested_packaged_roles(
    selected_optionals: list[dict[str, str]],
    *,
    manifest_root: Path | None,
) -> list[_PackagedOptionalRole]:
    manifests = _packaged_optional_role_manifests(manifest_root=manifest_root)
    requested: list[_PackagedOptionalRole] = []
    seen: set[tuple[str, str]] = set()
    for row in selected_optionals:
        capability_id = str(row.get("id") or "").strip()
        host_class = str(row.get("hostClass") or "").strip()
        manifest = manifests.get(capability_id)
        if manifest is None:
            continue
        if host_class not in manifest.allowed_host_classes:
            raise EngagementWorkspaceValidationError(
                [f"packaged optional capability {capability_id} is not allowed on host class {host_class}"]
            )
        key = (host_class, capability_id)
        if key not in seen:
            seen.add(key)
            requested.append(manifest)
    return requested


def _packaged_optional_role_manifests(*, manifest_root: Path | None) -> dict[str, _PackagedOptionalRole]:
    root = (manifest_root or DEFAULT_CAPABILITY_MANIFEST_ROOT).resolve(strict=False)
    capabilities_root = root / "capabilities"
    if not capabilities_root.is_dir() or capabilities_root.is_symlink():
        return {}
    manifests: dict[str, _PackagedOptionalRole] = {}
    for path in sorted(capabilities_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".json", ".yaml", ".yml"}:
            continue
        if path.is_symlink():
            raise EngagementWorkspaceValidationError(["packaged capability manifests must not be symlinks"])
        try:
            raw = path.read_text(encoding="utf-8")
            payload = json.loads(raw) if path.suffix.lower() == ".json" else yaml.safe_load(raw)
        except Exception as exc:
            raise EngagementWorkspaceValidationError(
                [f"packaged capability manifest could not be parsed: {path.name}"]
            ) from exc
        if not isinstance(payload, dict):
            continue
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        capability_id = str(metadata.get("id") or "").strip()
        if not capability_id:
            continue
        implementation = payload.get("implementation") if isinstance(payload.get("implementation"), dict) else {}
        if str(implementation.get("type") or "").strip() != "role":
            continue
        role = str(implementation.get("role") or "").strip()
        expected_path = f"ansible/roles/{role}"
        operator = payload.get("operator") if isinstance(payload.get("operator"), dict) else {}
        placement = payload.get("placement") if isinstance(payload.get("placement"), dict) else {}
        allowed = tuple(
            str(value).strip()
            for value in placement.get("allowedHostClasses", [])
            if isinstance(value, str) and value.strip()
        )
        valid = (
            payload.get("apiVersion") == SUPPORTED_API_VERSION
            and payload.get("kind") in {"Capability", "AnsibleCapability"}
            and payload.get("classification") == "optional"
            and operator.get("visible") is True
            and operator.get("selectable") is True
            and bool(allowed)
            and bool(ROLE_NAME_PATTERN.fullmatch(role))
            and implementation.get("path") == expected_path
        )
        if not valid:
            raise EngagementWorkspaceValidationError(
                [f"packaged optional role capability manifest is invalid: {capability_id}"]
            )
        if capability_id in manifests:
            raise EngagementWorkspaceValidationError(
                [f"duplicate packaged optional role capability manifest: {capability_id}"]
            )
        manifests[capability_id] = _PackagedOptionalRole(capability_id, role, allowed)
    return manifests


def _safe_workspace_roles_root(workspace_root: Path) -> Path:
    raw_root = workspace_root.expanduser()
    if raw_root.is_symlink():
        raise EngagementWorkspaceValidationError(["retained engagement workspace must not be a symlink"])
    resolved_root = raw_root.resolve(strict=True)
    ansible_root = resolved_root / "ansible"
    if ansible_root.is_symlink():
        raise EngagementWorkspaceValidationError(["retained Ansible path must not be a symlink"])
    ansible_root.mkdir(exist_ok=True)
    if ansible_root.resolve(strict=True).parent != resolved_root:
        raise EngagementWorkspaceValidationError(["retained Ansible path escapes engagement workspace"])
    roles_root = ansible_root / "roles"
    if roles_root.is_symlink():
        raise EngagementWorkspaceValidationError(["retained Ansible roles path must not be a symlink"])
    roles_root.mkdir(exist_ok=True)
    resolved_roles = roles_root.resolve(strict=True)
    if resolved_root not in resolved_roles.parents:
        raise EngagementWorkspaceValidationError(["retained Ansible roles path escapes engagement workspace"])
    return resolved_roles


def _safe_workspace_metadata_root(workspace_root: Path) -> Path:
    resolved_root = workspace_root.expanduser().resolve(strict=True)
    metadata_root = resolved_root / "barragan"
    if metadata_root.is_symlink():
        raise EngagementWorkspaceValidationError(["retained Barragan metadata path must not be a symlink"])
    metadata_root.mkdir(exist_ok=True)
    resolved_metadata = metadata_root.resolve(strict=True)
    if resolved_metadata.parent != resolved_root:
        raise EngagementWorkspaceValidationError(["retained Barragan metadata path escapes engagement workspace"])
    return resolved_metadata


def _validate_source_root(source: RedteamInfraTemplateSource) -> Path:
    raw_root = Path(source.root).expanduser()
    if source.source == "missing" or not raw_root.exists():
        raise EngagementWorkspaceValidationError(
            [source.warning or "configured Redteam-infra source is missing; cannot import selected capability role"]
        )
    if raw_root.is_symlink():
        raise EngagementWorkspaceValidationError(["configured Redteam-infra source must not be a symlink"])
    root = raw_root.resolve(strict=True)
    roles_root = root / "ansible" / "roles"
    if roles_root.is_symlink() or not roles_root.is_dir():
        raise EngagementWorkspaceValidationError(
            ["configured Redteam-infra source is missing its Ansible roles directory"]
        )
    return root


def _clean_source_revision(root: Path, runner: GitRunner) -> tuple[str, str]:
    inside = _required_git_value(
        root,
        ["rev-parse", "--is-inside-work-tree"],
        runner,
        "configured Redteam-infra source must be a Git checkout",
    )
    if inside != "true":
        raise EngagementWorkspaceValidationError(["configured Redteam-infra source must be a Git checkout"])
    status = _git_value(root, ["status", "--porcelain", "--untracked-files=all"], runner)
    if status is None:
        raise EngagementWorkspaceValidationError(["configured Redteam-infra source Git status could not be read"])
    if status.strip():
        raise EngagementWorkspaceValidationError(
            ["configured Redteam-infra source is dirty; commit or clean it before importing capability roles"]
        )
    commit = _required_git_value(root, ["rev-parse", "HEAD"], runner, "configured Redteam-infra source has no commit")
    tree = _required_git_value(
        root,
        ["rev-parse", "HEAD^{tree}"],
        runner,
        "configured Redteam-infra source has no committed tree",
    )
    return commit, tree


def _collect_role_and_dependencies(
    source_root: Path,
    role: str,
    *,
    ordered: list[str],
    dependencies: dict[str, list[str]],
) -> None:
    if role in dependencies:
        return
    if not ROLE_NAME_PATTERN.fullmatch(role):
        raise EngagementWorkspaceValidationError([f"Ansible role dependency name is not safe: {role}"])
    role_root = source_root / "ansible" / "roles" / role
    if role_root.is_symlink() or not role_root.is_dir():
        raise EngagementWorkspaceValidationError(
            [f"selected capability role or dependency is missing from Redteam-infra: ansible/roles/{role}"]
        )
    _assert_tree_has_no_symlinks(role_root, label=f"Ansible role {role}")
    declared = _role_dependencies(role_root)
    dependencies[role] = declared
    ordered.append(role)
    for dependency in declared:
        _collect_role_and_dependencies(source_root, dependency, ordered=ordered, dependencies=dependencies)


def _role_dependencies(role_root: Path) -> list[str]:
    meta = role_root / "meta" / "main.yml"
    if not meta.exists():
        return []
    if meta.is_symlink() or not meta.is_file():
        raise EngagementWorkspaceValidationError([f"Ansible role metadata is not a regular file: {role_root.name}"])
    try:
        payload = yaml.safe_load(meta.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EngagementWorkspaceValidationError(
            [f"Ansible role dependencies could not be parsed: {role_root.name}"]
        ) from exc
    if payload is None:
        return []
    if not isinstance(payload, dict):
        raise EngagementWorkspaceValidationError([f"Ansible role metadata must be an object: {role_root.name}"])
    raw_dependencies = payload.get("dependencies", [])
    if raw_dependencies is None:
        return []
    if not isinstance(raw_dependencies, list):
        raise EngagementWorkspaceValidationError([f"Ansible role dependencies must be a list: {role_root.name}"])
    dependencies: list[str] = []
    for item in raw_dependencies:
        if isinstance(item, str):
            dependency = item.strip()
        elif isinstance(item, dict):
            dependency = str(item.get("role") or "").strip()
        else:
            dependency = ""
        if not dependency or not ROLE_NAME_PATTERN.fullmatch(dependency):
            raise EngagementWorkspaceValidationError(
                [f"Ansible role declares an unsupported dependency: {role_root.name}"]
            )
        if dependency not in dependencies:
            dependencies.append(dependency)
    return dependencies


def _assert_tree_has_no_symlinks(root: Path, *, label: str) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            raise EngagementWorkspaceValidationError(
                [f"{label} contains unsupported symlink: {path.relative_to(root)}"]
            )


def _assert_source_revision_unchanged(
    root: Path,
    runner: GitRunner,
    *,
    commit: str,
    tree: str,
) -> None:
    current_commit, current_tree = _clean_source_revision(root, runner)
    if current_commit != commit or current_tree != tree:
        raise EngagementWorkspaceValidationError(
            ["configured Redteam-infra source changed during capability role import; retry is required"]
        )


def _required_git_value(root: Path, args: list[str], runner: GitRunner, error: str) -> str:
    value = _git_value(root, args, runner)
    if not value:
        raise EngagementWorkspaceValidationError([error])
    return value


def _git_value(root: Path, args: list[str], runner: GitRunner) -> str | None:
    try:
        return runner(root, args).strip()
    except Exception:
        return None


def _run_git(root: Path, args: list[str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git command failed")
    return result.stdout


def _load_workspace_marker(path: Path, engagement_id: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise EngagementWorkspaceValidationError(["retained workspace ownership marker is missing"])
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EngagementWorkspaceValidationError(["retained workspace ownership marker is invalid JSON"]) from exc
    if not isinstance(payload, dict) or payload.get("managedBy") != "barragan" or payload.get("engagementId") != engagement_id:
        raise EngagementWorkspaceValidationError(["retained workspace ownership marker does not match engagement"])
    return payload


def _provenance_records(
    requests: list[_PackagedOptionalRole],
    *,
    ordered_roles: list[str],
    missing_roles: list[str],
    preserved_roles: list[str],
    dependencies: dict[str, list[str]],
    provenance: _GitProvenance,
    source_kind: str,
    imported_at: str,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for request in requests:
        closure: list[str] = []

        def visit(role: str) -> None:
            if role in closure:
                return
            closure.append(role)
            for dependency in dependencies.get(role, []):
                visit(dependency)

        visit(request.role)
        records.append(
            {
                "schema": "barragan/capability-role-import/v1",
                "capabilityId": request.capability_id,
                "role": request.role,
                "importedAt": imported_at,
                "source": {
                    "kind": source_kind,
                    "commit": provenance.commit,
                    "tree": provenance.tree,
                    "roleTrees": {role: provenance.role_trees[role] for role in closure},
                },
                "roles": [role for role in ordered_roles if role in closure],
                "importedRoles": [role for role in missing_roles if role in closure],
                "preservedExistingRoles": [role for role in preserved_roles if role in closure],
            }
        )
    return records


def _existing_records(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _write_json_atomically(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
