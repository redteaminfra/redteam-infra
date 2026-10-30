# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import re
import threading

from app.storage.job_repository import JobRepository, StoredJobRun


SHARED_PROXY_STACK_MUTATION_ACTIONS = frozenset(
    {
        "web_static_service_apply",
        "web_static_service_remove",
        "inbound_channel_apply",
        "inbound_channel_remove",
        "inbound_request_header_gate_apply",
        "certificate_asset_bind",
        "certificate_asset_unbind",
        "inbound_channel_certificate_issue",
        "inbound_channel_certificate_renew",
        "inbound_channel_certificate_revoke",
    }
)
_SHARED_PROXY_STACK_LOCK = threading.Lock()


class SharedProxyStackMutationConflict(ValueError):
    def __init__(self, job: StoredJobRun):
        super().__init__("shared proxy stack mutation already running")
        self.job = job


def reserve_shared_proxy_stack_mutation(
    repository: JobRepository,
    job: StoredJobRun,
    *,
    engagement_id: str,
    proxy_id: str,
) -> StoredJobRun:
    """Atomically reject a same-process conflicting mutation and save this job."""
    candidate_proxy = canonical_proxy_id(proxy_id)
    with _SHARED_PROXY_STACK_LOCK:
        list_for_engagement = getattr(repository, "list_for_engagement", None)
        jobs = list_for_engagement(engagement_id) if callable(list_for_engagement) else repository.list()
        for current in jobs:
            if current.status not in {"queued", "running"} or current.action not in SHARED_PROXY_STACK_MUTATION_ACTIONS:
                continue
            if str(current.input.get("engagementId") or current.target_id or "") != engagement_id:
                continue
            current_proxy = _job_proxy_id(current)
            if not current_proxy or canonical_proxy_id(current_proxy) == candidate_proxy:
                raise SharedProxyStackMutationConflict(current)
        return repository.save(job)


def canonical_proxy_id(value: str) -> str:
    match = re.match(r"^(proxy[0-9]+)(?:-|$)", value.strip())
    return match.group(1) if match else value.strip()


def _job_proxy_id(job: StoredJobRun) -> str:
    direct = str(job.input.get("proxyId") or job.input.get("targetProxyId") or "").strip()
    if direct:
        return direct
    for event in reversed(job.events):
        selected = str(event.data.get("selectedProxy") or event.data.get("proxyId") or "").strip()
        if selected:
            return selected
    return ""
