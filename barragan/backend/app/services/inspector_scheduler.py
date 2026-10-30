# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import os
import logging
import threading
import time
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

from app.core.runtime import RuntimeState, runtime_context, runtime_value
from app.services.credentials import resolve_credential_secret, resolve_default_credential_alias
from app.services.observer_checks import _provider_for, start_inspection
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository, StoredObserverSettings


MUTATION_ACTIONS = {
    "pilot_standard_rti_run",
    "linode_sketch_deploy",
    "digitalocean_sketch_deploy",
    "linode_sketch_teardown",
    "digitalocean_sketch_teardown",
    "engagement_channels_update",
    "inbound_channel_apply",
    "inbound_channel_remove",
    "inbound_channel_validate",
    "outbound_channel_apply",
    "engagement_dns_apply",
    "web_static_service_apply",
    "web_static_service_remove",
    "backflips_service_apply",
}


_PROCESS_SCHEDULER_STARTED = False


def start_inspector_scheduler(runtime: RuntimeState) -> None:
    global _PROCESS_SCHEDULER_STARTED
    if runtime_value("TESTING", False, state=runtime):
        return
    enabled = os.environ.get("BARRAGAN_INSPECTOR_SCHEDULER_ENABLED", "1").strip().lower()
    if enabled in {"0", "false", "no", "off"}:
        return
    if _PROCESS_SCHEDULER_STARTED:
        return
    _PROCESS_SCHEDULER_STARTED = True

    def run() -> None:
        while True:
            try:
                with runtime_context(runtime):
                    tick()
            except Exception:
                logging.getLogger("barragan.inspector_scheduler").exception(
                    "Inspector scheduler tick failed"
                )
            time.sleep(int(os.environ.get("BARRAGAN_INSPECTOR_SCHEDULER_INTERVAL_SECONDS", "60")))

    threading.Thread(target=run, name="barragan-inspector-scheduler", daemon=True).start()


def tick(now: datetime | None = None) -> None:
    from app.storage.models import EngagementObserverSettingsModel

    now = now or datetime.now(timezone.utc)
    settings_repo = SqlAlchemyObserverSettingsRepository()
    for row in EngagementObserverSettingsModel.query.all():
        settings = settings_repo.get(row.engagement_id)
        if settings is None or not settings.enabled:
            continue
        _cleanup_expired_once_host(settings, settings_repo, now)
        updated = settings_repo.get(settings.engagement_id) or settings
        _run_due_scheduled_inspection(updated, settings_repo, now)
        fresh = settings_repo.get(settings.engagement_id) or updated
        _run_due_mutation_inspection(fresh, settings_repo)


def _run_due_scheduled_inspection(
    settings: StoredObserverSettings,
    settings_repo: SqlAlchemyObserverSettingsRepository,
    now: datetime,
) -> None:
    if settings.mode not in {"regular", "continuous"}:
        return
    if running_inspection(settings.engagement_id) is not None:
        return
    slot = scheduled_slot(settings, now)
    if not slot or slot == settings.last_scheduled_slot:
        return
    if not _inspection_mutation_allowed(settings.engagement_id):
        return
    settings_repo.save(replace(settings, last_scheduled_slot=slot))
    start_inspection(settings.engagement_id, {"triggerType": "scheduled"}, requested_by="inspector-scheduler")


def _run_due_mutation_inspection(
    settings: StoredObserverSettings,
    settings_repo: SqlAlchemyObserverSettingsRepository,
) -> None:
    if settings.mode != "continuous":
        return
    if running_inspection(settings.engagement_id) is not None:
        return
    latest = latest_completed_mutation(settings.engagement_id)
    if latest is None or latest.id == settings.last_mutation_job_inspected:
        return
    if not _inspection_mutation_allowed(settings.engagement_id):
        return
    settings_repo.save(replace(settings, last_mutation_job_inspected=latest.id))
    start_inspection(settings.engagement_id, {"triggerType": "mutation", "sourceJobId": latest.id}, requested_by="inspector-scheduler")


def _inspection_mutation_allowed(engagement_id: str) -> bool:
    from app.services.engagement_teardown import EngagementTeardownValidationError, assert_engagement_mutation_allowed

    try:
        assert_engagement_mutation_allowed(engagement_id)
        return True
    except EngagementTeardownValidationError:
        logging.getLogger("barragan.inspector_scheduler").info(
            "Skipping Inspector start while comprehensive engagement teardown is active",
            extra={"engagementId": engagement_id},
        )
        return False


def scheduled_slot(settings: StoredObserverSettings, now: datetime) -> str:
    weekday = now.strftime("%a").lower()[:3]
    if weekday not in settings.schedule_weekdays:
        return ""
    try:
        hour = int(settings.schedule_time_utc[:2])
        minute = int(settings.schedule_time_utc[3:5])
    except ValueError:
        return ""
    if now.hour < hour or (now.hour == hour and now.minute < minute):
        return ""
    return f"{now.date().isoformat()}T{hour:02d}:{minute:02d}Z"


def latest_completed_mutation(engagement_id: str) -> StoredJobRun | None:
    for job in SqlAlchemyJobRepository().list():
        if job.target_id != engagement_id:
            continue
        if job.action not in MUTATION_ACTIONS:
            continue
        if job.status in {"queued", "running"}:
            continue
        if job.action == "inspector_inspection":
            continue
        return job
    return None


def running_inspection(engagement_id: str) -> StoredJobRun | None:
    for job in SqlAlchemyJobRepository().list_for_engagement(engagement_id):
        if job.action == "inspector_inspection" and job.status in {"queued", "running"}:
            return job
    return None


def _cleanup_expired_once_host(
    settings: StoredObserverSettings,
    settings_repo: SqlAlchemyObserverSettingsRepository,
    now: datetime,
) -> None:
    if settings.mode == "continuous" or not settings.current_host or not settings.idle_retention_until:
        return
    try:
        expires_at = datetime.fromisoformat(settings.idle_retention_until.replace("Z", "+00:00"))
    except ValueError:
        expires_at = datetime.min.replace(tzinfo=timezone.utc)
    if expires_at > now:
        return
    alias = resolve_default_credential_alias(settings.provider)
    if not alias:
        return
    try:
        token = resolve_credential_secret(settings.provider, alias)
        host = _host_from_settings(settings.current_host)
        if host is not None and _provider_for(settings.provider).destroy(token=token, host=host):
            settings_repo.save(replace(settings, current_host={}, idle_retention_until=""))
    except Exception:
        return


def _host_from_settings(value: dict[str, Any]):
    from app.services.observer_checks import ObserverHost

    if not value.get("resourceId") or not value.get("publicIp"):
        return None
    return ObserverHost(
        provider=str(value.get("provider") or ""),
        resource_type=str(value.get("resourceType") or "instance"),
        resource_id=str(value.get("resourceId") or ""),
        name=str(value.get("name") or ""),
        region=str(value.get("region") or ""),
        public_ip=str(value.get("publicIp") or ""),
        ssh_user=str(value.get("sshUser") or "root"),
        status=str(value.get("status") or "running"),
        metadata=dict(value.get("metadata") or {}),
    )
