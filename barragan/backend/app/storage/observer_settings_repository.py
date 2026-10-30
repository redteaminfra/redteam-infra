# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


DEFAULT_INSPECTOR_CHECK_FAMILIES = ["inbound", "dns", "tls", "forbidden_tcp"]
DEFAULT_INSPECTOR_MODE = "continuous"
DEFAULT_INSPECTOR_SCHEDULE_WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
DEFAULT_INSPECTOR_SCHEDULE_TIME_UTC = "00:00"
LEGACY_DEFAULT_FORBIDDEN_TCP_PORTS = [22, 2222, 5000, 5173, 5900]


@dataclass(frozen=True)
class StoredInspectorSettings:
    engagement_id: str
    enabled: bool
    provider: str
    region: str
    size: str
    mode: str
    schedule_weekdays: list[str]
    schedule_time_utc: str
    check_families: list[str]
    forbidden_tcp_ports: list[int]
    port_scan_profiles: list[dict[str, Any]]
    current_host: dict[str, Any]
    idle_retention_until: str
    last_scheduled_slot: str
    last_mutation_job_inspected: str
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, object]:
        return {
            "engagementId": self.engagement_id,
            "enabled": self.enabled,
            "provider": self.provider,
            "region": self.region,
            "size": self.size,
            "mode": self.mode,
            "scheduleWeekdays": list(self.schedule_weekdays),
            "scheduleTimeUtc": self.schedule_time_utc,
            "checkFamilies": list(self.check_families),
            "forbiddenTcpPorts": [str(port) for port in self.forbidden_tcp_ports],
            "portScanProfiles": list(self.port_scan_profiles),
            "currentHost": dict(self.current_host),
            "idleRetentionUntil": self.idle_retention_until,
            "lastScheduledSlot": self.last_scheduled_slot,
            "lastMutationJobInspected": self.last_mutation_job_inspected,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        }


StoredObserverSettings = StoredInspectorSettings


class ObserverSettingsRepository(Protocol):
    def get(self, engagement_id: str) -> StoredInspectorSettings | None:
        ...

    def save(self, settings: StoredInspectorSettings) -> StoredInspectorSettings:
        ...


InspectorSettingsRepository = ObserverSettingsRepository


class SqlAlchemyObserverSettingsRepository:
    def get(self, engagement_id: str) -> StoredInspectorSettings | None:
        from app.storage.models import EngagementObserverSettingsModel

        row = EngagementObserverSettingsModel.query.get(engagement_id)
        return _from_model(row) if row is not None else None

    def save(self, settings: StoredInspectorSettings) -> StoredInspectorSettings:
        from app.storage.database import db
        from app.storage.models import EngagementObserverSettingsModel

        row = EngagementObserverSettingsModel.query.get(settings.engagement_id)
        if row is None:
            row = EngagementObserverSettingsModel(engagement_id=settings.engagement_id)
            db.session.add(row)
        row.enabled = bool(settings.enabled)
        row.provider = settings.provider
        row.region = settings.region
        row.size = settings.size
        row.mode = settings.mode
        row.schedule_weekdays = list(settings.schedule_weekdays)
        row.schedule_time_utc = settings.schedule_time_utc
        row.check_families = list(settings.check_families)
        row.forbidden_tcp_ports = list(settings.forbidden_tcp_ports)
        row.port_scan_profiles = list(settings.port_scan_profiles)
        row.current_host = dict(settings.current_host)
        row.idle_retention_until = settings.idle_retention_until
        row.last_scheduled_slot = settings.last_scheduled_slot
        row.last_mutation_job_inspected = settings.last_mutation_job_inspected
        db.session.commit()
        return self.get(settings.engagement_id) or settings


SqlAlchemyInspectorSettingsRepository = SqlAlchemyObserverSettingsRepository


def _from_model(row) -> StoredInspectorSettings:
    return StoredInspectorSettings(
        engagement_id=row.engagement_id,
        enabled=bool(getattr(row, "enabled", True)),
        provider=row.provider or "",
        region=row.region or "",
        size=row.size or "",
        mode=getattr(row, "mode", "") or DEFAULT_INSPECTOR_MODE,
        schedule_weekdays=list(getattr(row, "schedule_weekdays", None) or DEFAULT_INSPECTOR_SCHEDULE_WEEKDAYS),
        schedule_time_utc=getattr(row, "schedule_time_utc", "") or DEFAULT_INSPECTOR_SCHEDULE_TIME_UTC,
        check_families=list(getattr(row, "check_families", None) or DEFAULT_INSPECTOR_CHECK_FAMILIES),
        forbidden_tcp_ports=_stored_forbidden_ports(row.forbidden_tcp_ports or []),
        port_scan_profiles=list(getattr(row, "port_scan_profiles", None) or []),
        current_host=dict(getattr(row, "current_host", None) or {}),
        idle_retention_until=getattr(row, "idle_retention_until", "") or "",
        last_scheduled_slot=getattr(row, "last_scheduled_slot", "") or "",
        last_mutation_job_inspected=getattr(row, "last_mutation_job_inspected", "") or "",
        created_at=row.created_at.isoformat(),
        updated_at=row.updated_at.isoformat(),
    )


def _stored_forbidden_ports(raw_ports: list[int | str]) -> list[int]:
    ports = [int(port) for port in raw_ports]
    if ports == LEGACY_DEFAULT_FORBIDDEN_TCP_PORTS:
        return [port for port in ports if port != 22]
    return ports
