# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from pathlib import Path

from app.services.capability_lock_rendering import RenderedCapabilityLock, render_capability_lock
from app.services.engagement_capabilities import (
    EngagementCapabilityValidationError,
    capability_overrides_for_workspace,
    update_engagement_capability_selection,
)
from app.services.engagement_workspaces import load_prepared_engagement_workspace
from app.services.static_web_capability_state import with_implied_static_web_selection
from app.storage.engagement_workspace_repository import EngagementWorkspaceRepository, SqlAlchemyEngagementWorkspaceRepository
from app.storage.service_repository import EngagementServiceRepository


def ensure_static_web_capability_lock(
    engagement_id: str,
    *,
    root: Path,
    workspace_repository: EngagementWorkspaceRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
) -> RenderedCapabilityLock:
    repo = workspace_repository or SqlAlchemyEngagementWorkspaceRepository()
    workspace = load_prepared_engagement_workspace(engagement_id, root=root, repository=repo)
    if workspace is None:
        raise EngagementCapabilityValidationError(
            ["prepare the engagement workspace before applying the Static Web capability"]
        )
    requested, _ = with_implied_static_web_selection(
        capability_overrides_for_workspace(workspace),
        {"claimed": True},
    )
    updated = update_engagement_capability_selection(
        engagement_id,
        requested,
        root=root,
        repository=repo,
        service_repository=service_repository,
    )
    if updated is None:
        raise EngagementCapabilityValidationError(["engagement not found"])
    rendered = render_capability_lock(
        engagement_id,
        root=root,
        repository=repo,
        service_repository=service_repository,
    )
    if rendered is None:
        raise EngagementCapabilityValidationError(["engagement capability lock could not be rendered"])
    return rendered
