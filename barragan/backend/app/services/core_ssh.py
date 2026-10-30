# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from pathlib import Path
from typing import Any

from app.storage.job_repository import JobRepository

CORE_DEPLOYMENT_ACTION = "pilot_standard_rti_guarded_execute"


def latest_core_connection_details(repository: JobRepository, engagement_id: str) -> tuple[str, list[dict[str, Any]]]:
    for job in repository.list_for_engagement(engagement_id):
        if job.action != CORE_DEPLOYMENT_ACTION:
            continue
        if str(job.input.get("engagementId") or "") != engagement_id:
            continue
        for event in reversed(job.events):
            details = event.data.get("connectionDetails")
            if isinstance(details, list):
                return job.id, [entry for entry in details if isinstance(entry, dict)]
    return "", []


def active_core_connection_details(repository: JobRepository, engagement_id: str) -> tuple[str, list[dict[str, Any]]]:
    """Return connection data for the current deployed core generation only."""
    for job in repository.list_for_engagement(engagement_id):
        if job.action != CORE_DEPLOYMENT_ACTION:
            continue
        if str(job.input.get("engagementId") or "") != engagement_id:
            continue
        details = _job_connection_details(job)
        if not details or not _core_job_is_active(job):
            continue
        return job.id, details
    return "", []


def core_proxy_identity(details: list[dict[str, Any]], proxy_id: str) -> dict[str, str]:
    row = next(
        (
            entry
            for entry in details
            if str(entry.get("displayName") or "").startswith(f"{proxy_id}-")
            or str(entry.get("sshAlias") or "") == proxy_id
            or (str(entry.get("role") or "") == "proxy" and str(entry.get("name") or "") == proxy_id)
        ),
        None,
    )
    if row is None:
        return {}
    return {
        "displayName": str(row.get("displayName") or row.get("name") or ""),
        "publicIp": str(row.get("publicIp") or ""),
        "privateIp": str(row.get("privateIp") or ""),
        "sshAlias": str(row.get("sshAlias") or proxy_id),
    }


def _job_connection_details(job: Any) -> list[dict[str, Any]]:
    for event in reversed(job.events):
        details = event.data.get("connectionDetails")
        if isinstance(details, list):
            return [entry for entry in details if isinstance(entry, dict)]
    return []


def _core_job_is_active(job: Any) -> bool:
    if job.status in {"queued", "running"}:
        return True
    mutation_status = ""
    cleanup_status = ""
    for event in reversed(job.events):
        mutation_status = mutation_status or str(event.data.get("mutationStatus") or "")
        cleanup_status = cleanup_status or str(event.data.get("finalCleanupStatus") or "")
    if cleanup_status == "verified_clean":
        return False
    if mutation_status:
        return job.status == "succeeded" and mutation_status == "deployed"
    # Compatibility for pre-lifecycle jobs that already persisted connection
    # details but no explicit mutation marker.
    return job.status == "succeeded"


def deployment_known_hosts_file(root: Path, engagement_id: str, deployment_id: str) -> str:
    safe_engagement = _safe_file_token(engagement_id)
    safe_deployment = _safe_file_token(deployment_id or "unknown-core")
    return str(root / f"{safe_engagement}-{safe_deployment}.known_hosts")


def ensure_known_hosts_file(path: str) -> None:
    known_hosts_path = Path(path)
    known_hosts_path.parent.mkdir(parents=True, exist_ok=True)
    known_hosts_path.touch(mode=0o600, exist_ok=True)


def _safe_file_token(value: str) -> str:
    safe = "".join(character if character.isalnum() or character in {"-", "_"} else "_" for character in str(value or ""))
    return safe or "unknown"
