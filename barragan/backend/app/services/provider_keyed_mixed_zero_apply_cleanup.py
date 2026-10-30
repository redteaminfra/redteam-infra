# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private reservation for a mixed generation stopped before Sketch Apply.

This only fences the engagement. It does not establish cloud absence or issue a
destroy command; a later worker must prove those facts before OCI GO.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from app.domain import JobEvent
from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.services.provider_keyed_mixed_zero_apply_teardown_source import (
    MixedZeroApplySource, audit_mixed_zero_apply_teardown_source,
)
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun


ACTION = "provider_keyed_mixed_zero_apply_cleanup"
_PHASE = "awaiting_inspector_preflight"


def _parent_id(core_job_id: str) -> str:
    return f"job-provider-keyed-mixed-zero-apply-cleanup-{core_job_id.removeprefix('job-')}"


def _proposal(source: MixedZeroApplySource, requested_by: str) -> StoredJobRun:
    from app.services.engagement_teardown import _fingerprint

    sealed = json.loads(json.dumps(asdict(source), sort_keys=True))
    digest = _fingerprint(sealed)
    now = datetime.now(timezone.utc).isoformat()
    return StoredJobRun(
        id=_parent_id(source.core_job_id), action=ACTION, status="queued",
        target=f"engagement:{source.engagement_id}", target_type="engagement",
        target_id=source.engagement_id, requested_by=requested_by,
        input={"schema": "mixed-zero-apply-cleanup-v1",
               "engagementId": source.engagement_id, "coreJobId": source.core_job_id,
               "corePlanId": source.core_plan_id, "source": sealed,
               "sourceSha256": digest, "phase": _PHASE, "mutation": True},
        artifact_refs=[], created_at=now, started_at=None, finished_at=None,
        events=[JobEvent(1, "info", "mixed zero-Apply cleanup fenced",
                         {"sourceSha256": digest})],
    )


def reserve_mixed_zero_apply_cleanup(
    engagement_id: str, core_job_id: str, *, requested_by: str,
    environment: str, state_root: Path, core_state_root: Path,
    job_repository: SqlAlchemyJobRepository | None = None,
) -> StoredJobRun:
    """Reserve a deterministic private parent; duplicate calls recognize its seal."""
    if (environment != "devtest" or state_root != _default_state_root()
            or core_state_root != DEFAULT_TERRAFORM_STATE_ROOT):
        raise ValueError("mixed zero-Apply cleanup requires configured DevTest roots")
    jobs = job_repository or SqlAlchemyJobRepository()
    existing = jobs.get(_parent_id(core_job_id))
    if existing is not None:
        raw = existing.input.get("source") if isinstance(existing.input, dict) else None
        try:
            if not isinstance(raw, dict):
                raise ValueError
            source = MixedZeroApplySource(**raw)
        except (TypeError, ValueError):
            raise ValueError("mixed zero-Apply cleanup parent differs") from None
        if source.engagement_id != engagement_id or source.core_job_id != core_job_id:
            raise ValueError("mixed zero-Apply cleanup parent differs")
    else:
        core = jobs.get(core_job_id)
        if core is None or core.input.get("corePlanId") is None:
            raise ValueError("reviewed mixed core job is missing")
        lease_owner = str(core.input["corePlanId"])
        source = audit_mixed_zero_apply_teardown_source(
            engagement_id, core_job_id, environment=environment,
            state_root=state_root, core_state_root=core_state_root,
            lease_owner=lease_owner, job_repository=jobs,
        )
    return jobs.reserve_mixed_zero_apply_cleanup_parent(
        _proposal(source, requested_by), reviewed_source=source,
        state_root=state_root, core_state_root=core_state_root,
    )
