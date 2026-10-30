# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol


@dataclass(frozen=True)
class StoredInspectionRun:
    id: str
    engagement_id: str
    job_id: str
    trigger_type: str
    mode: str
    status: str
    provider: str
    region: str
    host: dict[str, Any]
    targets: dict[str, Any]
    evidence: dict[str, Any]
    findings: list[dict[str, Any]]
    created_at: str
    started_at: str | None
    finished_at: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "engagementId": self.engagement_id,
            "jobId": self.job_id,
            "triggerType": self.trigger_type,
            "mode": self.mode,
            "status": self.status,
            "provider": self.provider,
            "region": self.region,
            "host": dict(self.host),
            "targets": dict(self.targets),
            "evidence": dict(self.evidence),
            "findings": list(self.findings),
            "createdAt": self.created_at,
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
        }


class InspectionRunRepository(Protocol):
    def get(self, run_id: str) -> StoredInspectionRun | None:
        ...

    def list_for_engagement(self, engagement_id: str) -> list[StoredInspectionRun]:
        ...

    def save(self, run: StoredInspectionRun) -> StoredInspectionRun:
        ...


class SqlAlchemyInspectionRunRepository:
    def list_for_engagements(self, engagement_ids: list[str]) -> list[StoredInspectionRun]:
        from app.storage.models import InspectionRunModel

        if not engagement_ids:
            return []
        rows = (
            InspectionRunModel.query.filter(InspectionRunModel.engagement_id.in_(engagement_ids))
            .order_by(InspectionRunModel.engagement_id.asc(), InspectionRunModel.created_at.desc())
            .all()
        )
        return [_from_model(row) for row in rows]

    def get(self, run_id: str) -> StoredInspectionRun | None:
        from app.storage.models import InspectionRunModel

        row = InspectionRunModel.query.get(run_id)
        return _from_model(row) if row is not None else None

    def list_for_engagement(self, engagement_id: str) -> list[StoredInspectionRun]:
        from app.storage.models import InspectionRunModel

        rows = (
            InspectionRunModel.query.filter_by(engagement_id=engagement_id)
            .order_by(InspectionRunModel.created_at.desc())
            .all()
        )
        return [_from_model(row) for row in rows]

    def save(self, run: StoredInspectionRun) -> StoredInspectionRun:
        from app.storage.database import db
        from app.storage.models import InspectionRunModel

        row = InspectionRunModel.query.get(run.id)
        if row is None:
            row = InspectionRunModel(id=run.id)
            db.session.add(row)
        row.engagement_id = run.engagement_id
        row.job_id = run.job_id
        row.trigger_type = run.trigger_type
        row.mode = run.mode
        row.status = run.status
        row.provider = run.provider
        row.region = run.region
        row.host_json = dict(run.host)
        row.targets_json = dict(run.targets)
        row.evidence_json = dict(run.evidence)
        row.findings_json = list(run.findings)
        row.created_at = _parse_datetime(run.created_at)
        row.started_at = _parse_datetime(run.started_at) if run.started_at else None
        row.finished_at = _parse_datetime(run.finished_at) if run.finished_at else None
        db.session.commit()
        return self.get(run.id) or run


def _from_model(row) -> StoredInspectionRun:
    return StoredInspectionRun(
        id=row.id,
        engagement_id=row.engagement_id,
        job_id=row.job_id,
        trigger_type=row.trigger_type,
        mode=row.mode,
        status=row.status,
        provider=row.provider,
        region=row.region,
        host=dict(row.host_json or {}),
        targets=dict(row.targets_json or {}),
        evidence=dict(row.evidence_json or {}),
        findings=list(row.findings_json or []),
        created_at=row.created_at.isoformat(),
        started_at=row.started_at.isoformat() if row.started_at else None,
        finished_at=row.finished_at.isoformat() if row.finished_at else None,
    )


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
