# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


DEPLOYMENT_PLAN_STATUSES = {
    "preparing",
    "ready",
    "no_changes",
    "failed",
    "invalidated",
    "applying",
    "applied",
    "reconciliation_required",
}


@dataclass(frozen=True)
class DeploymentPlan:
    id: str
    engagement_id: str
    revision_id: str
    status: str
    stage: str
    review: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    prepared_at: str = ""
    created_at: str = ""
    updated_at: str = ""
    apply_job_id: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        review = dict(self.review)
        return {
            "id": self.id,
            "engagementId": self.engagement_id,
            "revisionId": self.revision_id,
            "status": self.status,
            "stage": self.stage,
            "counts": dict(review.get("counts") or {}),
            "resourceChanges": list(review.get("resourceChanges") or []),
            "target": dict(review.get("target") or {}),
            "preparedAt": self.prepared_at or None,
            "ageWarningAt": review.get("ageWarningAt"),
            "sanitizedText": str(review.get("sanitizedText") or ""),
            "sanitizedTextKind": str(review.get("sanitizedTextKind") or "summary"),
            "terraformFiles": list(review.get("terraformFiles") or []),
            "sshSourceCidrs": list(review.get("sshSourceCidrs") or []),
            "inputFingerprint": str(review.get("inputFingerprint") or ""),
            "reviewedConfiguration": dict(review.get("reviewedConfiguration") or {}),
            "postCoreScope": dict(review.get("postCoreScope") or {}),
            "error": self.error or None,
            "applyJobId": self.apply_job_id or None,
        }
