# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol


@dataclass(frozen=True)
class StoredEngagementLifecycle:
    engagement_id: str
    state: str
    evidence_fingerprint: str
    evidence: list[dict[str, Any]]
    reconciled_at: str


@dataclass(frozen=True)
class StoredEngagementLifecycleEvent:
    id: int | None
    engagement_id: str
    previous_state: str
    state: str
    evidence_fingerprint: str
    evidence: list[dict[str, Any]]
    reason: str
    created_at: str


class EngagementLifecycleRepository(Protocol):
    def get(self, engagement_id: str) -> StoredEngagementLifecycle | None: ...
    def save_transition(
        self,
        lifecycle: StoredEngagementLifecycle,
        event: StoredEngagementLifecycleEvent,
    ) -> tuple[StoredEngagementLifecycle, StoredEngagementLifecycleEvent]: ...
    def list_events(self, engagement_id: str) -> list[StoredEngagementLifecycleEvent]: ...


class SqlAlchemyEngagementLifecycleRepository:
    def list_for_engagements(self, engagement_ids: list[str]) -> list[StoredEngagementLifecycle]:
        from app.storage.models import EngagementLifecycleModel

        if not engagement_ids:
            return []
        rows = EngagementLifecycleModel.query.filter(EngagementLifecycleModel.engagement_id.in_(engagement_ids)).all()
        return [_lifecycle_from_model(row) for row in rows]

    def get(self, engagement_id: str) -> StoredEngagementLifecycle | None:
        from app.storage.models import EngagementLifecycleModel

        row = EngagementLifecycleModel.query.get(engagement_id)
        return _lifecycle_from_model(row) if row is not None else None

    def save_transition(
        self,
        lifecycle: StoredEngagementLifecycle,
        event: StoredEngagementLifecycleEvent,
    ) -> tuple[StoredEngagementLifecycle, StoredEngagementLifecycleEvent]:
        from app.storage.database import db
        from app.storage.models import EngagementLifecycleEventModel, EngagementLifecycleModel

        try:
            row = EngagementLifecycleModel.query.get(lifecycle.engagement_id)
            if row is None:
                row = EngagementLifecycleModel(engagement_id=lifecycle.engagement_id)
                db.session.add(row)
            row.state = lifecycle.state
            row.evidence_fingerprint = lifecycle.evidence_fingerprint
            row.evidence = lifecycle.evidence
            row.reconciled_at = _parse_datetime(lifecycle.reconciled_at)
            event_row = EngagementLifecycleEventModel(
                engagement_id=event.engagement_id,
                previous_state=event.previous_state,
                state=event.state,
                evidence_fingerprint=event.evidence_fingerprint,
                evidence=event.evidence,
                reason=event.reason,
                created_at=_parse_datetime(event.created_at),
            )
            db.session.add(event_row)
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return _lifecycle_from_model(row), _event_from_model(event_row)

    def list_events(self, engagement_id: str) -> list[StoredEngagementLifecycleEvent]:
        from app.storage.models import EngagementLifecycleEventModel

        rows = (
            EngagementLifecycleEventModel.query.filter_by(engagement_id=engagement_id)
            .order_by(EngagementLifecycleEventModel.created_at.asc(), EngagementLifecycleEventModel.id.asc())
            .all()
        )
        return [_event_from_model(row) for row in rows]


def _lifecycle_from_model(row: Any) -> StoredEngagementLifecycle:
    return StoredEngagementLifecycle(
        engagement_id=row.engagement_id,
        state=row.state,
        evidence_fingerprint=row.evidence_fingerprint,
        evidence=list(row.evidence or []),
        reconciled_at=row.reconciled_at.isoformat(),
    )


def _event_from_model(row: Any) -> StoredEngagementLifecycleEvent:
    return StoredEngagementLifecycleEvent(
        id=row.id,
        engagement_id=row.engagement_id,
        previous_state=row.previous_state,
        state=row.state,
        evidence_fingerprint=row.evidence_fingerprint,
        evidence=list(row.evidence or []),
        reason=row.reason,
        created_at=row.created_at.isoformat(),
    )


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else datetime.now(timezone.utc)
