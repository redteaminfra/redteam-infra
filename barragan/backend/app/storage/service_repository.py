# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Protocol


@dataclass(frozen=True)
class StoredEngagementService:
    engagement_id: str
    service_id: str
    service_type: str
    name: str
    proxy_id: str
    status: str
    config: dict[str, Any]
    apply_job_id: str = ""
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagementId": self.engagement_id,
            "serviceId": self.service_id,
            "serviceType": self.service_type,
            "name": self.name,
            "proxyId": self.proxy_id,
            "status": self.status,
            "config": self.config,
            "applyJobId": self.apply_job_id,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        }


class EngagementServiceRepository(Protocol):
    def list_for_engagement(self, engagement_id: str) -> list[StoredEngagementService]:
        ...

    def list_for_engagement_and_proxy(self, engagement_id: str, proxy_id: str) -> list[StoredEngagementService]:
        ...

    def get(self, engagement_id: str, service_id: str) -> StoredEngagementService | None:
        ...

    def save(self, service: StoredEngagementService) -> StoredEngagementService:
        ...


class SqlAlchemyEngagementServiceRepository:
    def list_for_engagements(self, engagement_ids: list[str]) -> list[StoredEngagementService]:
        from app.storage.models import EngagementServiceModel

        if not engagement_ids:
            return []
        rows = (
            EngagementServiceModel.query.filter(EngagementServiceModel.engagement_id.in_(engagement_ids))
            .order_by(EngagementServiceModel.engagement_id.asc(), EngagementServiceModel.created_at.asc(), EngagementServiceModel.service_id.asc())
            .all()
        )
        return [_from_model(row) for row in rows]

    def list_for_engagement(self, engagement_id: str) -> list[StoredEngagementService]:
        from app.storage.models import EngagementServiceModel

        rows = (
            EngagementServiceModel.query.filter_by(engagement_id=engagement_id)
            .order_by(EngagementServiceModel.created_at.asc(), EngagementServiceModel.service_id.asc())
            .all()
        )
        return [_from_model(row) for row in rows]

    def list_for_engagement_and_proxy(self, engagement_id: str, proxy_id: str) -> list[StoredEngagementService]:
        return [service for service in self.list_for_engagement(engagement_id) if service.proxy_id == proxy_id]

    def get(self, engagement_id: str, service_id: str) -> StoredEngagementService | None:
        from app.storage.models import EngagementServiceModel

        row = EngagementServiceModel.query.filter_by(engagement_id=engagement_id, service_id=service_id).first()
        if row is None:
            return None
        return _from_model(row)

    def save(self, service: StoredEngagementService) -> StoredEngagementService:
        from app.storage.database import db
        from app.storage.models import EngagementServiceModel

        row = EngagementServiceModel.query.filter_by(
            engagement_id=service.engagement_id,
            service_id=service.service_id,
        ).first()
        if row is None:
            row = EngagementServiceModel(engagement_id=service.engagement_id, service_id=service.service_id)
            db.session.add(row)

        row.service_type = service.service_type
        row.name = service.name
        row.proxy_id = service.proxy_id
        row.status = service.status
        row.config = service.config
        row.apply_job_id = service.apply_job_id
        db.session.commit()
        return self.get(service.engagement_id, service.service_id) or service


def service_with_status(service: StoredEngagementService, status: str, apply_job_id: str = "") -> StoredEngagementService:
    return replace(service, status=status, apply_job_id=apply_job_id or service.apply_job_id)


def _from_model(row) -> StoredEngagementService:
    return StoredEngagementService(
        engagement_id=row.engagement_id,
        service_id=row.service_id,
        service_type=row.service_type,
        name=row.name,
        proxy_id=row.proxy_id or "",
        status=row.status or "pending",
        config=dict(row.config or {}),
        apply_job_id=row.apply_job_id or "",
        created_at=row.created_at.isoformat(),
        updated_at=row.updated_at.isoformat(),
    )
