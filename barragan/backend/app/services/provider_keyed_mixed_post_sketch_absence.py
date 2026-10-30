# Copyright (c) 2026, Oracle and/or its affiliates.
"""Typed authority for the OCI/Inspector tail of mixed cleanup.

The zero-Apply constructor deliberately retains its original no-GO source
audit. An interrupted Apply cannot use this constructor: it needs a separate
sealed review and exact provider-absence receipts before OCI destruction.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_mixed_zero_apply_teardown_source import (
    MixedZeroApplySource, audit_mixed_zero_apply_teardown_source,
)
from app.storage.job_repository import StoredJobRun


@dataclass(frozen=True)
class PostSketchAbsenceAuthority:
    parent: StoredJobRun
    source: MixedZeroApplySource
    kind: str

    @property
    def engagement_id(self) -> str:
        return self.source.engagement_id

    @property
    def core_job_id(self) -> str:
        return self.source.core_job_id

    @property
    def core_plan_id(self) -> str:
        return self.source.core_plan_id

    @property
    def core_state_sha256(self) -> str:
        return self.source.core_state_sha256

    @property
    def core_inventory_sha256(self) -> str:
        return self.source.core_inventory_sha256


def audit_zero_apply_post_sketch_absence(
    parent: StoredJobRun, engagement_id: str, core_job_id: str, *,
    environment: str, state_root: Path, core_state_root: Path,
    lease_owner: str, lease_operation: str, **dependencies,
) -> PostSketchAbsenceAuthority:
    """Recheck the existing zero-Apply source without changing its criteria."""
    source = audit_mixed_zero_apply_teardown_source(
        engagement_id, core_job_id, environment=environment,
        state_root=state_root, core_state_root=core_state_root,
        lease_owner=lease_owner, lease_operation=lease_operation,
        **dependencies,
    )
    if (parent.action != "provider_keyed_mixed_zero_apply_cleanup"
            or parent.status != "queued"
            or parent.target_id != engagement_id
            or parent.input.get("coreJobId") != core_job_id
            or _fingerprint(parent.input.get("source")) != _fingerprint(asdict(source))
            or parent.input.get("sourceSha256") != _fingerprint(asdict(source))):
        raise ValueError("zero-Apply cleanup parent differs")
    return PostSketchAbsenceAuthority(parent, source, "zero_apply")
