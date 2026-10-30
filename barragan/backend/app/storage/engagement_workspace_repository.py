# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


MANAGED_HOST_IMAGE_PROFILE_METADATA_KEY = "managedHostImageProfile"


class EngagementWorkspaceImageProfileConflict(ValueError):
    """A stored managed-host image pin cannot be changed implicitly."""


@dataclass(frozen=True)
class StoredEngagementWorkspace:
    engagement_id: str
    slug: str
    path: str
    status: str
    profile_id: str
    template_source: dict[str, Any]
    metadata: dict[str, Any]
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagementId": self.engagement_id,
            "slug": self.slug,
            "path": self.path,
            "status": self.status,
            "profileId": self.profile_id,
            "templateSource": self.template_source,
            "metadata": self.metadata,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        }


class EngagementWorkspaceRepository(Protocol):
    def get(self, engagement_id: str) -> StoredEngagementWorkspace | None:
        ...

    def save(self, workspace: StoredEngagementWorkspace) -> StoredEngagementWorkspace:
        ...


class SqlAlchemyEngagementWorkspaceRepository:
    def get(self, engagement_id: str) -> StoredEngagementWorkspace | None:
        from app.storage.models import EngagementWorkspaceModel

        row = EngagementWorkspaceModel.query.get(engagement_id)
        if row is None:
            return None
        return _from_model(row)

    def save(self, workspace: StoredEngagementWorkspace) -> StoredEngagementWorkspace:
        from app.storage.database import db
        from app.storage.models import EngagementWorkspaceModel

        row = EngagementWorkspaceModel.query.populate_existing().get(workspace.engagement_id)
        if row is None:
            row = EngagementWorkspaceModel(engagement_id=workspace.engagement_id)
            db.session.add(row)
            row.slug = workspace.slug
            row.path = workspace.path
            row.status = workspace.status
            row.profile_id = workspace.profile_id
            row.template_source = workspace.template_source
            row.workspace_metadata = workspace.metadata
            db.session.commit()
            return self.get(workspace.engagement_id) or workspace

        # The image selection is a durable infrastructure identity. Merge it
        # from the current row so a stale whole-record save cannot erase it,
        # and use the metadata value as a compare-and-swap guard so two app
        # workers cannot establish different first pins.
        current_metadata = dict(row.workspace_metadata or {})
        merged_metadata = _merge_managed_host_image_pin(current_metadata, workspace.metadata)
        updated = (
            EngagementWorkspaceModel.query.filter_by(engagement_id=workspace.engagement_id)
            .filter(EngagementWorkspaceModel.workspace_metadata == current_metadata)
            .update(
                {
                    EngagementWorkspaceModel.slug: workspace.slug,
                    EngagementWorkspaceModel.path: workspace.path,
                    EngagementWorkspaceModel.status: workspace.status,
                    EngagementWorkspaceModel.profile_id: workspace.profile_id,
                    EngagementWorkspaceModel.template_source: workspace.template_source,
                    EngagementWorkspaceModel.workspace_metadata: merged_metadata,
                },
                synchronize_session=False,
            )
        )
        if updated != 1:
            db.session.rollback()
            latest = EngagementWorkspaceModel.query.populate_existing().get(workspace.engagement_id)
            if latest is None:
                raise RuntimeError("engagement workspace disappeared during save")
            latest_metadata = dict(latest.workspace_metadata or {})
            merged_metadata = _merge_managed_host_image_pin(latest_metadata, workspace.metadata)
            updated = (
                EngagementWorkspaceModel.query.filter_by(engagement_id=workspace.engagement_id)
                .filter(EngagementWorkspaceModel.workspace_metadata == latest_metadata)
                .update(
                    {
                        EngagementWorkspaceModel.slug: workspace.slug,
                        EngagementWorkspaceModel.path: workspace.path,
                        EngagementWorkspaceModel.status: workspace.status,
                        EngagementWorkspaceModel.profile_id: workspace.profile_id,
                        EngagementWorkspaceModel.template_source: workspace.template_source,
                        EngagementWorkspaceModel.workspace_metadata: merged_metadata,
                    },
                    synchronize_session=False,
                )
            )
            if updated != 1:
                db.session.rollback()
                raise RuntimeError("engagement workspace changed concurrently; retry the operation")
        db.session.commit()
        return self.get(workspace.engagement_id) or workspace


def _merge_managed_host_image_pin(
    current: dict[str, Any],
    incoming: dict[str, Any],
) -> dict[str, Any]:
    merged = dict(incoming)
    if MANAGED_HOST_IMAGE_PROFILE_METADATA_KEY not in current:
        return merged
    stored_pin = current[MANAGED_HOST_IMAGE_PROFILE_METADATA_KEY]
    incoming_pin = incoming.get(MANAGED_HOST_IMAGE_PROFILE_METADATA_KEY)
    if incoming_pin is not None and incoming_pin != "" and incoming_pin != stored_pin:
        raise EngagementWorkspaceImageProfileConflict(
            "managed-host image profile is immutable once pinned"
        )
    merged[MANAGED_HOST_IMAGE_PROFILE_METADATA_KEY] = stored_pin
    return merged


def _from_model(row: Any) -> StoredEngagementWorkspace:
    return StoredEngagementWorkspace(
        engagement_id=row.engagement_id,
        slug=row.slug,
        path=row.path,
        status=row.status,
        profile_id=row.profile_id,
        template_source=dict(row.template_source or {}),
        metadata=dict(row.workspace_metadata or {}),
        created_at=_format_datetime(getattr(row, "created_at", None)),
        updated_at=_format_datetime(getattr(row, "updated_at", None)),
    )


def _format_datetime(value: Any) -> str:
    return value.isoformat() if value is not None else ""
