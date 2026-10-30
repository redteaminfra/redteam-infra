# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol


TERMINAL_RECORD_STATUSES = {"destroyed", "deleted", "retired", "absent"}
LEGACY_BARRAGAN_OWNED_SOURCES = {
    "barragan",
    "inspector",
    "observer",
    "barragan_inspector",
    "barragan_observer",
    "barragan_inspector_job",
    "barragan_observer_job",
    "inspector_job",
    "observer_job",
}


def is_barragan_owned_record(record: Any) -> bool:
    """Classify authority without turning provider discovery into ownership."""

    metadata = record.metadata if isinstance(getattr(record, "metadata", None), dict) else {}
    if "barraganOwned" in metadata:
        return metadata.get("barraganOwned") is True
    source = str(getattr(record, "source", "") or "").strip().lower().replace("-", "_")
    return source in LEGACY_BARRAGAN_OWNED_SOURCES


@dataclass(frozen=True)
class StoredProviderResourceRecord:
    id: str
    engagement_id: str
    engagement_name: str
    provider: str
    resource_type: str
    resource_id: str
    name: str
    region: str
    lifecycle_state: str
    status: str
    source: str
    metadata: dict[str, Any]
    adoption_job_id: str
    adopted_at: str
    updated_at: str
    destroyed_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "engagementId": self.engagement_id,
            "engagementName": self.engagement_name,
            "provider": self.provider,
            "resourceType": self.resource_type,
            "resourceId": self.resource_id,
            "name": self.name,
            "region": self.region,
            "lifecycleState": self.lifecycle_state,
            "status": self.status,
            "source": self.source,
            "metadata": self.metadata,
            "adoptionJobId": self.adoption_job_id,
            "adoptedAt": self.adopted_at,
            "updatedAt": self.updated_at,
            "destroyedAt": self.destroyed_at,
        }

    def provider_resource_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "resourceType": self.resource_type,
            "resourceId": self.resource_id,
            "name": self.name,
            "region": self.region,
            "lifecycleState": self.lifecycle_state,
            "engagementId": self.engagement_id,
            "engagementName": self.engagement_name,
            "source": "provider_resource_record",
            "metadata": self.metadata,
        }


class ProviderResourceRepository(Protocol):
    def list(self) -> list[StoredProviderResourceRecord]:
        ...

    def list_for_engagement(self, engagement_id: str) -> list[StoredProviderResourceRecord]:
        ...

    def list_active(self) -> list[StoredProviderResourceRecord]:
        ...

    def get(self, record_id: str) -> StoredProviderResourceRecord | None:
        ...

    def save(self, record: StoredProviderResourceRecord) -> StoredProviderResourceRecord:
        ...


class SqlAlchemyProviderResourceRepository:
    def add_new_owned_pair_uncommitted(
        self, host: StoredProviderResourceRecord, firewall: StoredProviderResourceRecord,
    ) -> None:
        """Stage two new rows in the caller's transaction; never upsert or commit."""
        from app.storage.database import db
        from app.storage.models import ProviderResourceRecordModel

        if host.id == firewall.id or self.get(host.id) is not None or self.get(firewall.id) is not None:
            raise ValueError("Inspector provider ownership already exists")
        for record in (host, firewall):
            db.session.add(ProviderResourceRecordModel(
                id=record.id, engagement_id=record.engagement_id,
                engagement_name=record.engagement_name, provider=record.provider,
                resource_type=record.resource_type, resource_id=record.resource_id,
                name=record.name, region=record.region,
                lifecycle_state=record.lifecycle_state, status=record.status,
                source=record.source, metadata_json=record.metadata,
                adoption_job_id=record.adoption_job_id,
                adopted_at=_parse_datetime(record.adopted_at),
                updated_at=_parse_datetime(record.updated_at),
                destroyed_at=None,
            ))
            db.session.flush()

    def list_for_engagements(self, engagement_ids: list[str]) -> list[StoredProviderResourceRecord]:
        from app.storage.models import ProviderResourceRecordModel

        if not engagement_ids:
            return []
        rows = (
            ProviderResourceRecordModel.query.filter(ProviderResourceRecordModel.engagement_id.in_(engagement_ids))
            .order_by(ProviderResourceRecordModel.engagement_id.asc(), ProviderResourceRecordModel.updated_at.desc())
            .all()
        )
        return [_from_model(row) for row in rows]

    def list(self) -> list[StoredProviderResourceRecord]:
        from app.storage.models import ProviderResourceRecordModel

        rows = ProviderResourceRecordModel.query.order_by(ProviderResourceRecordModel.updated_at.desc()).all()
        return [_from_model(row) for row in rows]

    def list_for_engagement(self, engagement_id: str) -> list[StoredProviderResourceRecord]:
        from app.storage.models import ProviderResourceRecordModel

        rows = (
            ProviderResourceRecordModel.query.filter_by(engagement_id=engagement_id)
            .order_by(ProviderResourceRecordModel.updated_at.desc())
            .all()
        )
        return [_from_model(row) for row in rows]

    def list_active(self) -> list[StoredProviderResourceRecord]:
        return [record for record in self.list() if record.status.lower() not in TERMINAL_RECORD_STATUSES]

    def get(self, record_id: str) -> StoredProviderResourceRecord | None:
        from app.storage.models import ProviderResourceRecordModel

        row = ProviderResourceRecordModel.query.get(record_id)
        return _from_model(row) if row is not None else None

    def save(self, record: StoredProviderResourceRecord) -> StoredProviderResourceRecord:
        from app.storage.database import db
        from app.storage.models import ProviderResourceRecordModel

        row = ProviderResourceRecordModel.query.get(record.id)
        if row is None:
            row = ProviderResourceRecordModel(id=record.id)
            db.session.add(row)

        row.engagement_id = record.engagement_id
        row.engagement_name = record.engagement_name
        row.provider = record.provider
        row.resource_type = record.resource_type
        row.resource_id = record.resource_id
        row.name = record.name
        row.region = record.region
        row.lifecycle_state = record.lifecycle_state
        row.status = record.status
        row.source = record.source
        row.metadata_json = record.metadata
        row.adoption_job_id = record.adoption_job_id
        row.adopted_at = _parse_datetime(record.adopted_at)
        row.updated_at = _parse_datetime(record.updated_at)
        row.destroyed_at = _parse_datetime(record.destroyed_at) if record.destroyed_at else None
        db.session.commit()
        return self.get(record.id) or record


def _from_model(row) -> StoredProviderResourceRecord:
    return StoredProviderResourceRecord(
        id=row.id,
        engagement_id=row.engagement_id,
        engagement_name=row.engagement_name or "",
        provider=row.provider,
        resource_type=row.resource_type,
        resource_id=row.resource_id or "",
        name=row.name or "",
        region=row.region or "",
        lifecycle_state=row.lifecycle_state or "unknown",
        status=row.status or "tracked",
        source=row.source or "provider_inventory",
        metadata=dict(row.metadata_json or {}),
        adoption_job_id=row.adoption_job_id or "",
        adopted_at=row.adopted_at.isoformat(),
        updated_at=row.updated_at.isoformat(),
        destroyed_at=row.destroyed_at.isoformat() if row.destroyed_at else None,
    )


def _parse_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
