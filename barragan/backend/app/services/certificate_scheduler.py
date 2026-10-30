# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import os
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from app.core.runtime import RuntimeState, runtime_context, runtime_value
from app.services.certificate_manager import start_certificate_renew
from app.storage.certificate_repository import SqlAlchemyCertificateRepository


_PROCESS_SCHEDULER_STARTED = False
_PROCESS_LOCK_HANDLE = None


def start_certificate_scheduler(runtime: RuntimeState) -> None:
    global _PROCESS_SCHEDULER_STARTED, _PROCESS_LOCK_HANDLE
    if runtime_value("TESTING", False, state=runtime):
        return
    if os.environ.get("BARRAGAN_CERTIFICATE_SCHEDULER_ENABLED", "1").strip().lower() in {"0", "false", "no", "off"}:
        return
    if _PROCESS_SCHEDULER_STARTED:
        return
    lock_handle = _scheduler_lock()
    if lock_handle is None:
        return
    _PROCESS_SCHEDULER_STARTED = True
    _PROCESS_LOCK_HANDLE = lock_handle

    def run() -> None:
        # Retain the process lock for the thread lifetime. This prevents every
        # web worker or CLI-created app from launching a competing scheduler.
        _ = _PROCESS_LOCK_HANDLE
        while True:
            try:
                with runtime_context(runtime):
                    tick()
            except Exception:
                logging.getLogger("barragan.certificate_scheduler").exception(
                    "Certificate scheduler tick failed"
                )
            time.sleep(int(os.environ.get("BARRAGAN_CERTIFICATE_SCHEDULER_INTERVAL_SECONDS", "21600")))

    threading.Thread(target=run, name="barragan-certificate-scheduler", daemon=True).start()


def tick(now: datetime | None = None) -> None:
    from app.storage.models import EngagementModel

    now = now or datetime.now(timezone.utc)
    repository = SqlAlchemyCertificateRepository()
    for row in EngagementModel.query.all():
        for asset in repository.list_assets(row.id):
            if asset.source != "letsencrypt" or asset.status != "active" or not asset.current_version_id:
                continue
            version = repository.get_version(asset.current_version_id)
            if version is None or not _due(version.to_dict(), now):
                continue
            try:
                start_certificate_renew(
                    row.id,
                    asset.id,
                    {},
                    requested_by="certificate-scheduler",
                )
            except Exception as exc:
                # The next tick retries; the active job and certificate services
                # record detailed failures without killing the scheduler thread.
                logging.getLogger("barragan.certificate_scheduler").warning(
                    "Certificate scheduler could not start renewal for %s/%s: %s",
                    row.id,
                    asset.id,
                    type(exc).__name__,
                )
                continue


def _due(value, now: datetime) -> bool:
    if not isinstance(value, dict):
        return False
    # The type/manager fields are accepted for compatibility with pre-WI-0150
    # scheduler tests and migrated channel metadata. New callers pass a
    # CertificateVersion dictionary after filtering the owning asset.
    if value.get("type") and str(value.get("type")).lower() != "letsencrypt":
        return False
    if value.get("managedBy") and str(value.get("managedBy")).lower() != "barragan":
        return False
    if str(value.get("status") or "").lower() in {"issuing", "renewing", "revoking", "revoked"}:
        return False
    try:
        issued = datetime.fromisoformat(str(value.get("issuedAt") or "").replace("Z", "+00:00"))
        expires = datetime.fromisoformat(str(value.get("expiresAt") or "").replace("Z", "+00:00"))
    except ValueError:
        return False
    if issued.tzinfo is None:
        issued = issued.replace(tzinfo=timezone.utc)
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    threshold = expires - (expires - issued) / 3
    return now >= threshold


def _scheduler_lock():
    import fcntl

    path = Path(os.environ.get("BARRAGAN_CERTIFICATE_SCHEDULER_LOCK", "/tmp/barragan-certificate-scheduler.lock"))
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        return None
    return handle
