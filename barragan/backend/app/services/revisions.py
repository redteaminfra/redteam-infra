# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from app.storage.engagement_repository import (
    EngagementRepository,
    SqlAlchemyEngagementRepository,
)
from app.services.revision_compiler import RevisionCompileError, compile_standard_rti_revision
from app.storage.revision_repository import (
    RevisionRepository,
    SqlAlchemyRevisionRepository,
    StoredDeploymentRevision,
)


class RevisionNotFoundError(LookupError):
    pass


def list_revisions(
    engagement_id: str,
    revision_repository: RevisionRepository | None = None,
) -> list[dict]:
    return [revision.to_dict() for revision in _revision_repository(revision_repository).list_for_engagement(engagement_id)]


def get_revision(
    revision_id: str,
    revision_repository: RevisionRepository | None = None,
) -> dict | None:
    revision = _revision_repository(revision_repository).get(revision_id)
    if revision is None:
        return None
    return revision.to_dict()


def create_revision(
    engagement_id: str,
    revision_repository: RevisionRepository | None = None,
    engagement_repository: EngagementRepository | None = None,
) -> dict:
    revisions = _revision_repository(revision_repository)
    engagements = _engagement_repository(engagement_repository)
    engagement = engagements.get(engagement_id)
    if engagement is None:
        raise RevisionNotFoundError("engagement not found")

    existing_count = revisions.count_for_engagement(engagement_id)
    plan = compile_standard_rti_revision(
        engagement_id=engagement_id,
        input_parameters=engagement.input_parameters,
        revision_number=existing_count + 1,
        template_id=engagement.template_id or "standard-rti",
    )
    body = plan.to_dict()
    revision = StoredDeploymentRevision(
        id=body["id"],
        engagement_id=engagement_id,
        revision_number=body["revisionNumber"],
        status=body["status"],
        template_id=body["templateId"],
        input_parameters=body["inputParameters"],
        resolved_topology=body["resolvedTopology"],
        run_intent=body["runIntent"],
        validation_gates=body["validationGates"],
    )
    saved_revision = revisions.save(revision)
    next_status = "planned" if engagement.status == "draft" else engagement.status
    engagements.update_revision_state(engagement_id, saved_revision.id, next_status)
    return saved_revision.to_dict()


def _revision_repository(repository: RevisionRepository | None) -> RevisionRepository:
    return repository or SqlAlchemyRevisionRepository()


def _engagement_repository(repository: EngagementRepository | None) -> EngagementRepository:
    return repository or SqlAlchemyEngagementRepository()
