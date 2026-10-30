# Copyright (c) 2026, Oracle and/or its affiliates.
"""Immutable checkpoint for one interrupted mixed-generation teardown.

This module does not reserve the teardown lease or authorize a provider write.
One repository CAS saves the reviewed source while fencing the engagement;
another seals both plans before the first destroy GO. OCI and Inspector remain
closed until both provider absences are terminally authenticated.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json

from app.domain import JobEvent
from app.services.provider_keyed_mixed_initial_plan_parent import validate_mixed_initial_apply_seal
from app.services.provider_keyed_mixed_interrupted_destroy_plan import (
    MixedInterruptedDestroyPlanSet, _digest as plan_digest, _scope_sha,
)
from app.services.provider_keyed_mixed_interrupted_source import (
    MixedInterruptedReview, _digest as review_digest,
)
from app.storage.job_repository import StoredJobRun, job_event_digest


ACTION = "provider_keyed_mixed_interrupted_cleanup"
SCHEMA = "mixed-interrupted-cleanup-v1"


def _parent_id(core_job_id: str) -> str:
    return f"job-provider-keyed-mixed-interrupted-cleanup-{core_job_id.removeprefix('job-')}"


def _canonical(value):
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _review_scope_input(scope: dict | None) -> dict:
    if scope is None:
        return {}
    if (type(scope) is not dict or set(scope) != {
            "jobId", "planId", "stateSha256", "inventorySha256",
            "proxyCount", "targets", "ownedInspectorRecordIds"}
            or type(scope["jobId"]) is not str or not scope["jobId"]
            or type(scope["planId"]) is not str or not scope["planId"]
            or any(type(scope[key]) is not str or len(scope[key]) != 64
                   or any(ch not in "0123456789abcdef" for ch in scope[key])
                   for key in ("stateSha256", "inventorySha256"))
            or type(scope["proxyCount"]) is not int or scope["proxyCount"] < 0
            or type(scope["targets"]) is not list
            or len(scope["targets"]) != scope["proxyCount"] + 1
            or type(scope["ownedInspectorRecordIds"]) is not list
            or len(scope["ownedInspectorRecordIds"]) != 2
            or len(set(scope["ownedInspectorRecordIds"])) != 2
            or any(type(value) is not str or not value
                   for value in scope["ownedInspectorRecordIds"])):
        raise ValueError("mixed interrupted reviewed core scope differs")
    canonical = _canonical(scope)
    return {"reviewScope": canonical,
            "reviewScopeSha256": hashlib.sha256(json.dumps(
                canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}


def _validate_boundary(initial: StoredJobRun, review: MixedInterruptedReview,
                       plans: MixedInterruptedDestroyPlanSet | None = None) -> tuple[str, str]:
    seal = validate_mixed_initial_apply_seal(initial)
    order = tuple(seal["orderedProviders"])
    if (review.engagement_id != initial.target_id
            or review.core_job_id != initial.input["coreJobId"]
            or review.seal_journal_sha256 != job_event_digest(initial.events[:6])
            or review.ordered_providers != order
            or tuple(scope.provider for scope in review.scopes) != order):
        raise ValueError("mixed interrupted review or plan set differs")
    review_payload = {"engagementId": review.engagement_id,
                      "coreJobId": review.core_job_id,
                      "sealJournalSha256": review.seal_journal_sha256,
                      "orderedProviders": order,
                      "scopes": [scope.__dict__ for scope in review.scopes]}
    if review.review_sha256 != review_digest(review_payload):
        raise ValueError("mixed interrupted checkpoint digest differs")
    if plans is not None:
        if (plans.review_sha256 != review.review_sha256
                or plans.ordered_providers != order
                or tuple(plan.provider for plan in plans.plans) != order
                or any(plan.scope_sha256 != _scope_sha(scope)
                       for scope, plan in zip(review.scopes, plans.plans, strict=True))):
            raise ValueError("mixed interrupted plan set differs")
        plan_payload = {"reviewSha256": review.review_sha256,
                        "orderedProviders": order,
                        "plans": [plan.__dict__ for plan in plans.plans]}
        if plans.plan_set_sha256 != plan_digest(plan_payload):
            raise ValueError("mixed interrupted plan digest differs")
    return review.engagement_id, review.core_job_id


def propose_mixed_interrupted_cleanup(
    initial: StoredJobRun, review: MixedInterruptedReview, *, requested_by: str,
    review_scope: dict | None = None,
) -> StoredJobRun:
    """Build the exact one-action checkpoint; no lease or provider write."""
    engagement_id, core_job_id = _validate_boundary(initial, review)
    if type(requested_by) is not str or not requested_by:
        raise ValueError("mixed interrupted requester is unavailable")
    source = _canonical(asdict(review))
    digest = review.review_sha256
    now = datetime.now(timezone.utc).isoformat()
    scope_input = _review_scope_input(review_scope)
    return StoredJobRun(
        id=_parent_id(core_job_id), action=ACTION, status="queued",
        target=f"engagement:{engagement_id}", target_type="engagement",
        target_id=engagement_id, requested_by=requested_by,
        input={"schema": SCHEMA, "engagementId": engagement_id,
               "coreJobId": core_job_id, "corePlanId": initial.input["corePlanId"],
               "source": source, "sourceSha256": digest,
               "phase": "awaiting_both_destroy_plans", "mutation": True,
               **scope_input},
        artifact_refs=[], created_at=now, started_at=None, finished_at=None,
        events=[JobEvent(1, "info", "mixed interrupted cleanup fenced",
                         {"sourceSha256": digest,
                          **({"reviewScopeSha256": scope_input["reviewScopeSha256"]}
                             if scope_input else {})})],
    )


def recognize_mixed_interrupted_cleanup_checkpoint(
    parent: StoredJobRun, initial: StoredJobRun,
    review: MixedInterruptedReview,
) -> StoredJobRun:
    """Read-only exact fenced review recognizer, before plan seal."""
    engagement_id, core_job_id = _validate_boundary(initial, review)
    source = _canonical(asdict(review))
    digest = review.review_sha256
    scope_input = _review_scope_input(parent.input.get("reviewScope"))
    if (parent.id != _parent_id(core_job_id) or parent.action != ACTION
            or parent.status != "queued" or parent.started_at is not None
            or parent.finished_at is not None or parent.artifact_refs != []
            or parent.target != f"engagement:{engagement_id}"
            or parent.target_type != "engagement" or parent.target_id != engagement_id
            or type(parent.requested_by) is not str or not parent.requested_by
            or parent.input != {
                "schema": SCHEMA, "engagementId": engagement_id,
                "coreJobId": core_job_id, "corePlanId": initial.input["corePlanId"],
                "source": source, "sourceSha256": digest,
                "phase": "awaiting_both_destroy_plans", "mutation": True,
                **scope_input}
            or parent.events != [JobEvent(1, "info", "mixed interrupted cleanup fenced",
                                          {"sourceSha256": digest,
                                           **({"reviewScopeSha256": scope_input["reviewScopeSha256"]}
                                              if scope_input else {})})]):
        raise ValueError("mixed interrupted cleanup checkpoint differs")
    if (scope_input and (parent.input.get("reviewScopeSha256")
                         != scope_input["reviewScopeSha256"]
                         or scope_input["reviewScope"]["jobId"] != core_job_id
                         or scope_input["reviewScope"]["planId"]
                         != initial.input["corePlanId"])):
        raise ValueError("mixed interrupted cleanup checkpoint differs")
    return parent


def recognize_mixed_interrupted_sealed_plans(
    parent: StoredJobRun, initial: StoredJobRun,
    review: MixedInterruptedReview, plans: MixedInterruptedDestroyPlanSet,
) -> StoredJobRun:
    """Read-only exact two-plan checkpoint, still not provider GO authority."""
    _validate_boundary(initial, review, plans)
    baseline = propose_mixed_interrupted_cleanup(
        initial, review, requested_by=parent.requested_by,
        review_scope=parent.input.get("reviewScope"))
    expected_input = {**baseline.input, "phase": "plans_sealed"}
    expected_events = baseline.events + [
        JobEvent(2, "info", "both mixed destroy plans sealed",
                 {"planSet": _canonical(asdict(plans)),
                  "planSetSha256": plans.plan_set_sha256})]
    if (parent.id != baseline.id or parent.action != ACTION or parent.status != "queued"
            or parent.target != baseline.target or parent.target_type != baseline.target_type
            or parent.target_id != baseline.target_id
            or parent.requested_by != baseline.requested_by
            or parent.input != expected_input or parent.events != expected_events
            or parent.started_at is not None or parent.finished_at is not None
            or parent.artifact_refs != []):
        raise ValueError("mixed interrupted sealed plans differ")
    return parent
