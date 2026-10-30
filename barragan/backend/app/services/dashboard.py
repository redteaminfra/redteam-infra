# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from app.services.catalog import list_templates
from app.services.engagement_operations import get_operations_overview, load_operations_read_snapshot
from app.services.provider_resource_reporting import reported_provider_resource
from app.services import provider_reconciliation
from app.storage.engagement_repository import EngagementRepository, SqlAlchemyEngagementRepository, StoredEngagement
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.provider_resource_repository import TERMINAL_RECORD_STATUSES
from app.storage.database import db
from app.storage.models import JobRunModel

INACTIVE_ENGAGEMENT_STATUSES = {"archived", "retired"}
DESTROYED_STATUSES = {"destroyed", "removed", "disabled"}
ATTENTION_STATUSES = {"attention", "cleanup_not_verified", "failed", "validation failed", "apply failed"}
HISTORICAL_DASHBOARD_STATES = {"destroyed", "not_deployed"}
RECENT_DAYS = 30
DASHBOARD_JOBS_PER_ENGAGEMENT = 250
DISK_WARNING_USED_PERCENT = 80
DISK_CRITICAL_USED_PERCENT = 90


def get_dashboard_inventory(
    engagement_repository: EngagementRepository | None = None,
    job_repository: JobRepository | None = None,
    include_provider_reconciliation: bool = False,
) -> dict[str, Any]:
    engagement_repo = engagement_repository or SqlAlchemyEngagementRepository()
    job_repo = job_repository or SqlAlchemyJobRepository()
    engagements = engagement_repo.list()
    operational_engagements = [engagement for engagement in engagements if engagement.status not in INACTIVE_ENGAGEMENT_STATUSES]
    operational_ids = [engagement.id for engagement in operational_engagements]
    read_snapshot = load_operations_read_snapshot(
        operational_ids,
        job_repo,
        recent_limit=DASHBOARD_JOBS_PER_ENGAGEMENT,
    )
    jobs_by_engagement = read_snapshot.jobs
    operational_jobs = _unique_jobs(jobs_by_engagement)
    job_count = (
        read_snapshot.total_job_count
        if read_snapshot.total_job_count is not None
        else _job_count(job_repo)
    )
    provider_records = [
        record
        for record in read_snapshot.all_provider_records
        if record.status.lower() not in TERMINAL_RECORD_STATUSES
    ]
    reported_resources = [reported_provider_resource(record, jobs_by_engagement.get(record.engagement_id, []))
                          for record in provider_records]
    retained_inventory_rows = []

    for engagement in operational_engagements:
        overview = get_operations_overview(
            engagement.id,
            _CachedEngagementRepository(engagements),
            _CachedJobRepository(jobs_by_engagement.get(engagement.id, []), authority_repository=job_repo),
            include_provider_findings=False,
            read_snapshot=read_snapshot,
        )
        if overview is None:
            continue
        retained_inventory_rows.append(_inventory_row(engagement, overview))

    now = datetime.now(timezone.utc)
    generated_at = now.isoformat()
    inventory_rows = [row for row in retained_inventory_rows if _show_on_global_dashboard(row)]
    active_rows = [row for row in inventory_rows if row["lifecycleState"] == "active"]
    attention_rows = [row for row in inventory_rows if row["lifecycleState"] in {"attention", "cleanup_not_verified"}]
    destroyed_rows = [row for row in inventory_rows if row["lifecycleState"] == "destroyed"]
    last_known_rows = [row for row in inventory_rows if row["lastKnown"]]
    discovery = provider_reconciliation.discover_provider_inventory() if include_provider_reconciliation else provider_reconciliation.unchecked_provider_inventory()
    live_provider_resources = discovery["resources"]
    reconciliation = provider_reconciliation.reconcile_provider_inventory(
        engagements,
        operational_jobs,
        provider_resources=live_provider_resources,
        local_provider_resources=reported_resources,
    )

    engagement_overview = _engagement_overview(engagements, retained_inventory_rows, operational_jobs, now)

    return {
        "generatedAt": generated_at,
        "summary": {
            "templates": len(list_templates()),
            "engagements": len(operational_engagements),
            "activeEngagements": len(active_rows),
            "jobRuns": job_count,
            "activeInfrastructure": len(active_rows),
            "attention": len(attention_rows),
            "destroyed": len(destroyed_rows),
            "lastKnown": len(last_known_rows),
            "orphanCandidates": len(reconciliation.orphan_candidates),
            "recentTeardowns": len(engagement_overview["recentlyEnded"]),
            "recentArchives": len(engagement_overview["recentlyArchived"]),
        },
        "engagementOverview": engagement_overview,
        "systemHealth": _system_health(
            reconciliation,
            include_provider_reconciliation,
            generated_at,
            seed_job_exists=read_snapshot.seed_job_exists,
            discovery_evidence=discovery["evidence"],
        ),
        "inventory": inventory_rows,
        "orphanCandidates": reconciliation.orphan_candidates,
        "providerDiscovery": discovery["evidence"],
        "providerInventory": provider_reconciliation.provider_inventory_rows(
            engagements, operational_jobs, live_provider_resources,
            reported_resources, discovery["evidence"]),
        "reconciliation": {
            "status": reconciliation.status if discovery["evidence"]["status"] in {"checked", "not_checked"} else discovery["evidence"]["status"],
            "detail": reconciliation.detail if discovery["evidence"]["status"] in {"checked", "not_checked"} else "Provider discovery is " + discovery["evidence"]["status"] + ". " + discovery["evidence"]["detail"],
        },
    }


def _engagement_overview(
    engagements: list[StoredEngagement],
    inventory_rows: list[dict[str, Any]],
    jobs: list[StoredJobRun],
    now: datetime,
) -> dict[str, Any]:
    rows_by_engagement = {row["engagementId"]: row for row in inventory_rows}
    jobs_by_engagement = _jobs_by_engagement(jobs)
    active: list[dict[str, Any]] = []
    recently_ended: list[dict[str, Any]] = []
    recently_archived: list[dict[str, Any]] = []

    for engagement in engagements:
        row = rows_by_engagement.get(engagement.id)
        timeline = _engagement_timeline(jobs_by_engagement.get(engagement.id, []))
        if row and row["lifecycleState"] in {"active", "attention", "cleanup_not_verified"}:
            active.append(_activity_row(engagement, row, timeline, now))
            continue
        archived_at = _parse_datetime(engagement.updated_at)
        if engagement.status in INACTIVE_ENGAGEMENT_STATUSES and _within_recent(archived_at, now):
            recently_archived.append(_activity_row(engagement, row, timeline, now, archived_at=archived_at))
            continue
        ended_at = timeline.get("endedAt")
        if row and row["lifecycleState"] == "destroyed" and _within_recent(ended_at, now):
            recently_ended.append(_activity_row(engagement, row, timeline, now, ended_at=ended_at))

    return {
        "active": sorted(active, key=lambda item: str(item.get("engagementName") or "")),
        "recentlyEnded": sorted(recently_ended, key=lambda item: str(item.get("endedAt") or ""), reverse=True),
        "recentlyArchived": sorted(recently_archived, key=lambda item: str(item.get("archivedAt") or ""), reverse=True),
        "windowDays": RECENT_DAYS,
    }


def _activity_row(
    engagement: StoredEngagement,
    row: dict[str, Any] | None,
    timeline: dict[str, datetime | None],
    now: datetime,
    ended_at: datetime | None = None,
    archived_at: datetime | None = None,
) -> dict[str, Any]:
    active_since = timeline.get("activeSince")
    if row is None:
        lifecycle_state = "archived" if engagement.status in INACTIVE_ENGAGEMENT_STATUSES else "not_deployed"
        health_status = lifecycle_state
        detail = "Engagement is archived." if lifecycle_state == "archived" else "No infrastructure records are available."
        providers: list[str] = []
        regions: list[str] = []
        last_checked_at = None
    else:
        lifecycle_state = row["lifecycleState"]
        health_status = row["healthStatus"]
        detail = row["detail"]
        providers = row["providers"]
        regions = row["regions"]
        last_checked_at = row["lastCheckedAt"]
    return {
        "engagementId": engagement.id,
        "engagementName": engagement.name,
        "engagementStatus": engagement.status,
        "lifecycleState": lifecycle_state,
        "healthStatus": health_status,
        "healthDetail": detail,
        "activeSince": _format_optional_datetime(active_since),
        "activeDurationDays": _duration_days(active_since, now),
        "activeDurationLabel": _duration_label(active_since, now),
        "endedAt": _format_optional_datetime(ended_at),
        "archivedAt": _format_optional_datetime(archived_at),
        "providers": providers,
        "regions": regions,
        "lastCheckedAt": last_checked_at,
    }


def _inventory_row(engagement: Any, overview: dict[str, Any]) -> dict[str, Any]:
    health = _dict(overview.get("healthSummary"))
    core_hosts = [_dict(row) for row in _list(overview.get("coreInfrastructure"))]
    sketch_hosts = [_dict(row) for row in _list(overview.get("sketchInfrastructure"))]
    active_core_hosts = [host for host in core_hosts if not bool(host.get("lastKnown")) and _status(host) not in DESTROYED_STATUSES]
    active_sketch_hosts = [host for host in sketch_hosts if _real_public_ip(str(host.get("publicIp") or "")) and _status(host) not in DESTROYED_STATUSES]
    lifecycle_state = _dashboard_lifecycle(health, core_hosts, sketch_hosts, active_core_hosts, active_sketch_hosts)
    # Retained connection details describe the last deployment. A verified
    # terminal lifecycle supersedes those historical host observations.
    lifecycle = _dict(overview.get("lifecycle"))
    if lifecycle.get("state") == "destroyed" and lifecycle.get("terminal"):
        lifecycle_state = "destroyed"
        active_core_hosts = []
        active_sketch_hosts = []
        health = {**health, "status": "destroyed", "activeHostCount": 0,
                  "detail": "Infrastructure teardown verified; retained host details are historical."}
    elif lifecycle.get("state") in {"cleanup_required", "unknown"}:
        lifecycle_state = "cleanup_not_verified" if lifecycle["state"] == "cleanup_required" or lifecycle_state == "cleanup_not_verified" else "attention"
        health = {**health, "status": "attention",
                  "detail": "Infrastructure cleanup or current state needs verification; retained host observations do not prove current provider presence."}
    regions = _ordered_values([str(host.get("region") or "") for host in core_hosts + sketch_hosts])
    providers = _ordered_values(["oci" for _host in core_hosts] + [str(host.get("provider") or "") for host in sketch_hosts])
    last_checked_at = str(health.get("lastCheckedAt") or "") or None

    return {
        "engagementId": engagement.id,
        "engagementName": engagement.name,
        "engagementStatus": engagement.status,
        "lifecycleState": lifecycle_state,
        "healthStatus": _dashboard_health(health, lifecycle_state),
        "coreHostCount": len(core_hosts),
        "activeCoreHostCount": int(health.get("activeHostCount") or len(active_core_hosts)),
        "sketchHostCount": len(sketch_hosts),
        "activeSketchHostCount": len(active_sketch_hosts),
        "outboundChannelCount": len(_list(overview.get("outboundChannels"))),
        "inboundChannelCount": len(_list(overview.get("inboundChannels"))),
        "providers": providers,
        "regions": regions,
        "lastCheckedAt": last_checked_at,
        "lastKnown": lifecycle_state == "destroyed" or bool(health.get("lastKnown")) or any(bool(host.get("lastKnown")) for host in core_hosts),
        "attention": lifecycle_state in {"attention", "cleanup_not_verified"},
        "detail": _dashboard_detail(health, lifecycle_state),
    }


def _dashboard_lifecycle(
    health: dict[str, Any],
    core_hosts: list[dict[str, Any]],
    sketch_hosts: list[dict[str, Any]],
    active_core_hosts: list[dict[str, Any]],
    active_sketch_hosts: list[dict[str, Any]],
) -> str:
    health_status = str(health.get("status") or "").lower()
    host_statuses = {_status(host) for host in core_hosts + sketch_hosts}
    if health_status == "destroyed" or (core_hosts and not active_core_hosts and not active_sketch_hosts and host_statuses <= DESTROYED_STATUSES):
        return "destroyed"
    if health_status in ATTENTION_STATUSES or host_statuses.intersection(ATTENTION_STATUSES):
        return "cleanup_not_verified" if "cleanup_not_verified" in host_statuses or health_status == "cleanup_not_verified" else "attention"
    if active_core_hosts or active_sketch_hosts:
        return "active"
    if core_hosts or sketch_hosts:
        return "last_known"
    return "not_deployed"


def _dashboard_health(health: dict[str, Any], lifecycle_state: str) -> str:
    if lifecycle_state in {"destroyed", "not_deployed", "last_known"}:
        return lifecycle_state
    status = str(health.get("status") or "").strip()
    return status or lifecycle_state


def _dashboard_detail(health: dict[str, Any], lifecycle_state: str) -> str:
    detail = str(health.get("detail") or "").strip()
    if detail:
        return detail
    if lifecycle_state == "active":
        return "Barragan has runtime records for active infrastructure."
    if lifecycle_state == "destroyed":
        return "Infrastructure is torn down; displayed values are historical last-known records."
    if lifecycle_state == "not_deployed":
        return "No deployed infrastructure is recorded for this engagement."
    return "Infrastructure state needs operator review."


def _jobs_by_engagement(jobs: list[StoredJobRun]) -> dict[str, list[StoredJobRun]]:
    grouped: dict[str, list[StoredJobRun]] = {}
    for job in jobs:
        engagement_id = str(
            job.input.get("engagementId")
            or (job.target_id if job.target_type == "engagement" else "")
            or (job.target.removeprefix("engagement:") if job.target.startswith("engagement:") else "")
        ).strip()
        if engagement_id:
            grouped.setdefault(engagement_id, []).append(job)
    return grouped


def _unique_jobs(jobs_by_engagement: dict[str, list[StoredJobRun]]) -> list[StoredJobRun]:
    jobs: dict[str, StoredJobRun] = {}
    for engagement_jobs in jobs_by_engagement.values():
        for job in engagement_jobs:
            jobs.setdefault(job.id, job)
    return list(jobs.values())


def _bounded_engagement_jobs(repository: JobRepository, engagement_id: str) -> list[StoredJobRun]:
    semantic = getattr(repository, "list_semantic_for_engagement", None)
    if callable(semantic):
        return semantic(engagement_id, recent_limit=DASHBOARD_JOBS_PER_ENGAGEMENT)
    try:
        return repository.list_for_engagement(engagement_id, limit=DASHBOARD_JOBS_PER_ENGAGEMENT)
    except TypeError:
        # Compatibility for lightweight test and extension repositories that
        # predate the optional repository-side limit.
        return repository.list_for_engagement(engagement_id)[:DASHBOARD_JOBS_PER_ENGAGEMENT]


def _job_count(repository: JobRepository) -> int:
    count = getattr(repository, "count", None)
    if callable(count):
        return count()
    return len(repository.list())


def _engagement_timeline(jobs: list[StoredJobRun]) -> dict[str, datetime | None]:
    active_since: datetime | None = None
    ended_at: datetime | None = None
    for job in jobs:
        job_time = _job_time(job)
        for event in job.events:
            data = event.data if isinstance(event.data, dict) else {}
            mutation_status = str(data.get("mutationStatus") or "").lower()
            cleanup_status = str(data.get("finalCleanupStatus") or data.get("status") or "").lower()
            if mutation_status == "deployed" and cleanup_status == "pending_operator_teardown":
                active_since = _latest_datetime(active_since, job_time)
            if mutation_status == "destroyed" and cleanup_status == "verified_clean":
                ended_at = _latest_datetime(ended_at, job_time)
    return {"activeSince": active_since, "endedAt": ended_at}


def _job_time(job: StoredJobRun) -> datetime | None:
    for value in (job.finished_at, job.started_at, job.created_at):
        parsed = _parse_datetime(value)
        if parsed is not None:
            return parsed
    return None


def _latest_datetime(current: datetime | None, candidate: datetime | None) -> datetime | None:
    if candidate is None:
        return current
    if current is None or candidate > current:
        return candidate
    return current


def _within_recent(value: datetime | None, now: datetime) -> bool:
    return value is not None and now - value <= timedelta(days=RECENT_DAYS)


def _duration_days(started_at: datetime | None, now: datetime) -> int | None:
    if started_at is None:
        return None
    return max(0, (now - started_at).days)


def _duration_label(started_at: datetime | None, now: datetime) -> str:
    days = _duration_days(started_at, now)
    if days is None:
        return "not recorded"
    if days == 0:
        return "<1 day"
    if days < 60:
        return f"{days} day" if days == 1 else f"{days} days"
    months = max(1, days // 30)
    return f"{months} month" if months == 1 else f"{months} months"


def _format_optional_datetime(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _system_health(
    reconciliation: provider_reconciliation.ProviderReconciliation,
    live_provider_reconciliation: bool,
    generated_at: str,
    *,
    seed_job_exists: bool | None = None,
    discovery_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    database = _database_health(seed_job_exists=seed_job_exists)
    return {
        "api": {
            "status": "ok",
            "detail": "Barragan API is responding.",
            "checkedAt": generated_at,
        },
        "database": database,
        "disk": _disk_health(database.get("path")),
        "providers": _provider_health(reconciliation, live_provider_reconciliation, generated_at, discovery_evidence),
    }


def _database_health(*, seed_job_exists: bool | None = None) -> dict[str, Any]:
    uri = db.uri
    parsed = urlparse(uri)
    try:
        status = "ok"
        detail = "Database query succeeded."
        if seed_job_exists is None:
            seed_job_exists = JobRunModel.query.filter_by(id="job-seed-001").first() is not None
        seed_status = "seeded" if seed_job_exists else "not_seeded"
    except Exception as exc:
        status = "degraded"
        detail = f"Database query failed: {exc}"
        seed_status = "unknown"
    return {
        "status": status,
        "detail": detail,
        "uriScheme": parsed.scheme or "unknown",
        "path": _safe_database_path(parsed),
        "seedStatus": seed_status,
    }


def _disk_health(database_path: Any) -> dict[str, Any]:
    target = Path(str(database_path or "."))
    if str(database_path or "") in {"", ":memory:", "configured-external-database"}:
        target = Path.cwd()
    elif not target.is_dir():
        target = target.parent
    try:
        usage = shutil.disk_usage(str(target))
    except Exception as exc:
        return {"status": "unknown", "detail": f"Disk usage check failed: {exc}", "path": str(target)}
    used_percent = round(((usage.total - usage.free) / usage.total) * 100, 1) if usage.total else 0.0
    status = "ok"
    if used_percent >= DISK_CRITICAL_USED_PERCENT:
        status = "critical"
    elif used_percent >= DISK_WARNING_USED_PERCENT:
        status = "warning"
    return {
        "status": status,
        "detail": f"{used_percent}% disk used at {target}.",
        "path": str(target),
        "freeBytes": usage.free,
        "totalBytes": usage.total,
        "usedPercent": used_percent,
    }


def _provider_health(
    reconciliation: provider_reconciliation.ProviderReconciliation,
    live_provider_reconciliation: bool,
    generated_at: str,
    discovery_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not live_provider_reconciliation:
        return {
            "status": "not checked",
            "detail": "Provider connectivity has not been checked in this dashboard render. Refresh provider inventory to run read-only provider reconciliation.",
            "checkedAt": None,
        }
    if discovery_evidence is not None:
        discovery_status = discovery_evidence["status"]
        status = "ok" if discovery_status == "checked" else "not checked" if discovery_status == "disabled" else "attention"
        if reconciliation.orphan_candidates:
            status = "attention"
        return {"status": status,
                "detail": f"Provider discovery: {discovery_status}. " + discovery_evidence["detail"],
                "checkedAt": discovery_evidence["observedAt"],
                "orphanCandidates": len(reconciliation.orphan_candidates)}
    if reconciliation.orphan_candidates:
        status = "attention"
    else:
        status = "ok"
    return {
        "status": status,
        "detail": reconciliation.detail,
        "checkedAt": generated_at,
        "orphanCandidates": len(reconciliation.orphan_candidates),
    }


def _safe_database_path(parsed: Any) -> str:
    if parsed.scheme != "sqlite":
        return "configured-external-database"
    if parsed.path == "/:memory:":
        return ":memory:"
    return str(Path(unquote(parsed.path)).resolve())


def _show_on_global_dashboard(row: dict[str, Any]) -> bool:
    lifecycle_state = row["lifecycleState"]
    if lifecycle_state in {"active", "attention", "cleanup_not_verified"}:
        return True
    if lifecycle_state in HISTORICAL_DASHBOARD_STATES:
        return False
    if row["lastKnown"]:
        return False
    return True


def _status(row: dict[str, Any]) -> str:
    value = str(row.get("lifecycleState") or row.get("status") or "").strip().lower()
    return value or "unknown"


def _real_public_ip(value: str) -> bool:
    normalized = value.strip().lower()
    return bool(normalized and normalized not in {"not deployed", "n/a", "unknown", "not recorded"})


def _ordered_values(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        normalized = value.strip()
        if not normalized or normalized.lower() in {"n/a", "unknown", "not recorded"} or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


class _CachedEngagementRepository:
    def __init__(self, engagements: list[StoredEngagement]):
        self._engagements = engagements
        self._by_id = {engagement.id: engagement for engagement in engagements}

    def list(self) -> list[StoredEngagement]:
        return self._engagements

    def get(self, engagement_id: str) -> StoredEngagement | None:
        return self._by_id.get(engagement_id)


class _CachedJobRepository:
    def __init__(self, jobs: list[StoredJobRun], *, authority_repository=None):
        self._jobs = jobs
        self._by_id = {job.id: job for job in jobs}
        self.authority_repository = authority_repository or self

    def list(self) -> list[StoredJobRun]:
        return self._jobs

    def list_for_engagement(self, engagement_id: str, *, limit: int | None = None) -> list[StoredJobRun]:
        if limit is not None:
            return self._jobs[:limit]
        return self._jobs

    def get(self, job_id: str) -> StoredJobRun | None:
        return self._by_id.get(job_id)

    def save(self, job: StoredJobRun) -> StoredJobRun:
        raise NotImplementedError("dashboard inventory uses a read-only cached job repository")
