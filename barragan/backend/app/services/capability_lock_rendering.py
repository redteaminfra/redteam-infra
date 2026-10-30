# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from app.services.capability_profile_resolution import resolve_standard_rti_profile
from app.services.engagement_capabilities import (
    apply_capability_overrides_to_resolution,
    capability_overrides_for_workspace,
    engagement_core_provider,
)
from app.services.engagements import get_engagement
from app.services.engagement_workspaces import (
    EngagementWorkspaceValidationError,
    load_prepared_engagement_workspace,
)
from app.services.redteam_infra_template import RedteamInfraTemplateSource
from app.storage.engagement_workspace_repository import (
    EngagementWorkspaceRepository,
    SqlAlchemyEngagementWorkspaceRepository,
    StoredEngagementWorkspace,
)
from app.storage.service_repository import EngagementServiceRepository
from app.services.static_web_capability_state import static_web_capability_state, with_implied_static_web_selection


CAPABILITY_LOCK_RELATIVE_PATH = Path("barragan") / "capability-lock.yml"
LOCK_SCHEMA = "barragan/capability-lock/v1"
SECRET_MARKERS = (
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "api_token",
    "apiToken",
    "password:",
    "secret:",
)


@dataclass(frozen=True)
class RenderedCapabilityLock:
    workspace: StoredEngagementWorkspace
    path: Path
    relative_path: str
    content: str
    lock: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "workspace": self.workspace.to_dict(),
            "capabilityLock": {
                "path": str(self.path),
                "relativePath": self.relative_path,
                "schema": LOCK_SCHEMA,
                "status": self.lock["status"],
                "profileId": self.lock["metadata"]["profileId"],
                "summary": self.lock["summary"],
                "warnings": self.lock["warnings"],
                "content": self.content,
            },
        }


def render_capability_lock(
    engagement_id: str,
    *,
    root: Path,
    repository: EngagementWorkspaceRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
) -> RenderedCapabilityLock | None:
    repo = repository or SqlAlchemyEngagementWorkspaceRepository()
    workspace = load_prepared_engagement_workspace(engagement_id, root=root, repository=repo)
    if workspace is None:
        return None

    workspace_root = Path(workspace.path).resolve(strict=False)
    output_path = _safe_workspace_child(workspace_root, CAPABILITY_LOCK_RELATIVE_PATH)
    workspace_source = RedteamInfraTemplateSource(workspace_root, "engagement-workspace")
    resolution = resolve_standard_rti_profile(
        source=workspace_source,
        core_provider=engagement_core_provider(get_engagement(engagement_id)),
    ).to_dict()
    overrides, _ = with_implied_static_web_selection(
        capability_overrides_for_workspace(workspace),
        static_web_capability_state(engagement_id, repository=service_repository),
    )
    resolution = apply_capability_overrides_to_resolution(resolution, overrides)
    lock = _capability_lock_payload(workspace, resolution)
    content = yaml.safe_dump(lock, sort_keys=False, allow_unicode=True)
    _assert_no_secret_material(content)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")

    updated_metadata = dict(workspace.metadata)
    updated_metadata.update(
        {
            "capabilityLockPath": str(CAPABILITY_LOCK_RELATIVE_PATH),
            "capabilityLockRenderedAt": lock["metadata"]["generatedAt"],
            "capabilityLockStatus": lock["status"],
        }
    )
    updated_workspace = repo.save(
        StoredEngagementWorkspace(
            engagement_id=workspace.engagement_id,
            slug=workspace.slug,
            path=workspace.path,
            status="capability-lock-rendered",
            profile_id=workspace.profile_id,
            template_source=workspace.template_source,
            metadata=updated_metadata,
            created_at=workspace.created_at,
            updated_at=workspace.updated_at,
        )
    )
    return RenderedCapabilityLock(
        workspace=updated_workspace,
        path=output_path,
        relative_path=str(CAPABILITY_LOCK_RELATIVE_PATH),
        content=content,
        lock=lock,
    )


def _capability_lock_payload(workspace: StoredEngagementWorkspace, resolution: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": LOCK_SCHEMA,
        "kind": "CapabilityLock",
        "metadata": {
            "engagementId": workspace.engagement_id,
            "workspaceSlug": workspace.slug,
            "profileId": workspace.profile_id,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "generatedBy": "barragan",
        },
        "templateSource": workspace.template_source,
        "profile": resolution["profile"],
        "status": resolution["status"],
        "summary": resolution["summary"],
        "selection": resolution["selection"],
        "capabilities": _capability_groups(resolution["hostClasses"]),
        "renderedArtifacts": {
            "playbooks": ["ansible/apply_capabilities.yml"],
            "note": (
                "Core deployment renders a Barragan-composed capability playbook "
                "from selected executable role-backed capabilities. Capabilities "
                "without manifests remain visible in the lock but non-executable."
            ),
        },
        "executionPolicy": {
            "terraform": False,
            "ansible": True,
            "providerMutation": False,
            "reason": "Selected executable Ansible role capabilities are applied during core infrastructure deployment.",
        },
        "warnings": resolution["warnings"],
    }


def _capability_groups(host_classes: dict[str, Any]) -> dict[str, Any]:
    grouped: dict[str, Any] = {}
    for host_class, classifications in host_classes.items():
        grouped[host_class] = {}
        for classification, entries in classifications.items():
            grouped[host_class][classification] = [_locked_entry(entry) for entry in entries]
    return grouped


def _locked_entry(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": entry["id"],
        "name": entry["name"],
        "description": entry.get("description", ""),
        "classification": entry["classification"],
        "resolution": entry["resolution"],
        "executable": bool(entry.get("executable")),
        "implementation": entry.get("implementation", {}),
        "operator": entry.get("operator", {}),
        "selected": bool(entry.get("selected", False)),
        "locked": bool(entry.get("locked", False)),
    }


def _safe_workspace_child(root: Path, relative_path: Path) -> Path:
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise EngagementWorkspaceValidationError(["capability lock path is not safe"])
    target = (root / relative_path).resolve(strict=False)
    if target == root or root not in target.parents:
        raise EngagementWorkspaceValidationError(["capability lock path escapes engagement workspace"])
    if target.is_symlink() or target.parent.is_symlink():
        raise EngagementWorkspaceValidationError(["capability lock path must not be a symlink"])
    return target


def _assert_no_secret_material(content: str) -> None:
    lower = content.lower()
    for marker in SECRET_MARKERS:
        haystack = lower if marker == marker.lower() else content
        if marker in haystack:
            raise EngagementWorkspaceValidationError(["capability lock content appears to include secret material"])
