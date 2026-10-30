# Copyright (c) 2026, Oracle and/or its affiliates.
"""One-shot journal grammar for a published mixed provider destroy child.

This module proposes and recognizes durable events only. It never calls
Terraform or a provider. An intent without a complete fenced result is
uncertain and must not be replayed by a later worker.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import re

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_mixed_published_destroy_plan import PublishedMixedDestroyPlanSet
from app.services.provider_keyed_mixed_published_teardown_authority import PublishedMixedInitialTeardownReview
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    recognize_published_mixed_plans_sealed,
)
from app.storage.job_repository import StoredJobRun, job_event_digest


ACTION = "provider_keyed_mixed_published_destroy_apply"
_CLAIM_KEYS = {"claimOwner", "claimToken", "claimClaimedAt", "claimHeartbeatAt",
               "claimExpiresAt"}
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class PublishedMixedDestroyChildAttention(ValueError):
    """The saved one-shot command journal differs or is uncertain."""


def child_id(core_job_id: str, provider: str) -> str:
    return (f"job-provider-keyed-mixed-published-destroy-"
            f"{core_job_id.removeprefix('job-')}-{provider}")


def _base(parent: StoredJobRun, review: PublishedMixedInitialTeardownReview,
          plans: PublishedMixedDestroyPlanSet, provider: str,
          core_inspector_scope: dict, engagement_name: str,
          prior_absence_receipt_sha256: str | None) -> dict:
    recognize_published_mixed_plans_sealed(
        parent, review, plans, core_inspector_scope, engagement_name)
    order = review.source.ordered_providers
    if (type(plans) is not PublishedMixedDestroyPlanSet
            or plans.ordered_providers != order
            or plans.published_parent_journal_sha256
               != review.published_parent_journal_sha256
            or tuple(plan.provider for plan in plans.plans) != order
            or plans.plan_set_sha256 != _fingerprint({
                "publishedParentJournalSha256": plans.published_parent_journal_sha256,
                "orderedProviders": order,
                "plans": [asdict(plan) for plan in plans.plans],
            })
            or provider not in order):
        raise ValueError("published mixed destroy plan set differs")
    index = order.index(provider)
    scope, plan = review.provider_scopes[index], plans.plans[index]
    expected_ids = tuple(sorted((row["address"], row["id"])
                                for row in scope["resources"]))
    if (plan.scope_sha256 != _fingerprint(scope)
            or plan.before_state_sha256 != scope["stateSha256"]
            or plan.state_lineage != scope["lineage"]
            or plan.state_serial != scope["serial"]
            or plan.resource_ids != expected_ids
            or (index == 0 and prior_absence_receipt_sha256 is not None)
            or (index == 1 and (type(prior_absence_receipt_sha256) is not str
                                or _HEX64.fullmatch(prior_absence_receipt_sha256) is None))):
        raise ValueError("published mixed destroy provider order or source differs")
    return {
        "engagementId": review.source.engagement_id,
        "coreJobId": review.source.core_job_id,
        "corePlanId": review.source.core_plan_id,
        "cleanupParentId": parent.id,
        "cleanupJournalSha256": job_event_digest(parent.events),
        "planSetSha256": plans.plan_set_sha256,
        "provider": provider,
        "providerIndex": index,
        "scopeSha256": plan.scope_sha256,
        "beforeStateSha256": plan.before_state_sha256,
        "planPath": plan.plan_path,
        "planSha256": plan.plan_sha256,
        "showSha256": plan.show_json_sha256,
        "priorAbsenceReceiptSha256": prior_absence_receipt_sha256,
        "mutation": True,
    }


def propose_published_mixed_destroy_child(
    parent: StoredJobRun, review: PublishedMixedInitialTeardownReview,
    plans: PublishedMixedDestroyPlanSet, provider: str,
    core_inspector_scope: dict, engagement_name: str, *,
    prior_absence_receipt_sha256: str | None = None,
) -> StoredJobRun:
    base = _base(parent, review, plans, provider, core_inspector_scope,
                 engagement_name, prior_absence_receipt_sha256)
    return StoredJobRun(
        id=child_id(base["coreJobId"], provider), action=ACTION, status="queued",
        target=f"engagement:{base['engagementId']}", target_type="engagement",
        target_id=base["engagementId"], requested_by=parent.requested_by,
        input=base, artifact_refs=[],
        created_at=datetime.now(timezone.utc).isoformat(),
        started_at=None, finished_at=None,
        events=[JobEvent(1, "info", "published mixed provider destroy queued", {
            "planSetSha256": plans.plan_set_sha256,
            "provider": provider,
        })],
    )


def recognize_published_mixed_destroy_child(
    child: StoredJobRun, parent: StoredJobRun,
    review: PublishedMixedInitialTeardownReview,
    plans: PublishedMixedDestroyPlanSet, provider: str,
    core_inspector_scope: dict, engagement_name: str,
) -> str:
    """Return command phase; `uncertain` is a hard no-replay state."""
    try:
        base = _base(parent, review, plans, provider, core_inspector_scope,
                     engagement_name, child.input.get("priorAbsenceReceiptSha256"))
        events = child.events
        messages = (
            "published mixed provider destroy queued",
            "published mixed provider destroy started",
            "published mixed provider destroy show proved",
            "published mixed provider destroy command intended",
            "published mixed provider destroy command started before GO",
            "published mixed provider destroy result fenced",
            "published mixed provider awaiting exact absence",
            "published mixed provider exact absence proved",
        )
        if (child.id != child_id(base["coreJobId"], provider)
                or child.action != ACTION
                or {key: value for key, value in child.input.items()
                    if key not in _CLAIM_KEYS} != base
                or child.target != f"engagement:{base['engagementId']}"
                or child.target_type != "engagement"
                or child.target_id != base["engagementId"]
                or child.requested_by != parent.requested_by
                or child.artifact_refs != []
                or not 1 <= len(events) <= len(messages)
                or [(event.sequence, event.level, event.message) for event in events]
                   != [(number, "info", message)
                       for number, message in enumerate(messages[:len(events)], 1)]
                or events[0].data != {
                    "planSetSha256": plans.plan_set_sha256, "provider": provider}):
            raise ValueError("published mixed destroy journal boundary differs")
        if len(events) == 1:
            if (child.status != "queued" or child.input != base
                    or child.started_at is not None or child.finished_at is not None):
                raise ValueError("published mixed destroy queued child differs")
            return "queued"
        if (child.started_at is None or events[1].data != {}
                or (len(events) == 8 and (
                    child.status != "succeeded" or child.finished_at is None
                    or any(key in child.input for key in _CLAIM_KEYS)))
                or (len(events) != 8 and (
                    child.status != "running" or child.finished_at is not None))):
            raise ValueError("published mixed destroy running child differs")
        if len(events) == 2:
            return "started"
        plan = plans.plans[base["providerIndex"]]
        if events[2].data != {
            "planSha256": plan.plan_sha256,
            "showSha256": plan.show_json_sha256,
            "beforeStateSha256": plan.before_state_sha256,
        }:
            raise ValueError("published mixed destroy show journal differs")
        if len(events) == 3:
            return "show_proved"
        intent = events[3].data
        if (type(intent) is not dict
                or set(intent) != {"invocationId", "argvSha256", "showJournalSha256"}
                or type(intent["invocationId"]) is not str or not intent["invocationId"]
                or intent["argvSha256"] != hashlib.sha256(json.dumps([
                    plan.terraform_path, "apply", "-input=false", "-lock=true",
                    "-no-color", plan.plan_path],
                    separators=(",", ":")).encode()).hexdigest()
                or intent["showJournalSha256"] != job_event_digest(events[:3])):
            raise ValueError("published mixed destroy intent differs")
        if len(events) < 6:
            return "uncertain"
        started, result = events[4].data, events[5].data
        if (type(started) is not dict
                or set(started) != {"invocationId", "bootId", "pid", "pgid", "startTicks"}
                or started["invocationId"] != intent["invocationId"]
                or type(started["bootId"]) is not str or not started["bootId"]
                or any(type(started[key]) is not int or started[key] <= 0
                       for key in ("pid", "pgid", "startTicks"))
                or started["pid"] != started["pgid"]
                or type(result) is not dict
                or set(result) != {"invocationId", "returnCode", "stdoutBytes",
                                   "stderrBytes", "stdoutTruncated", "stderrTruncated"}
                or result["invocationId"] != intent["invocationId"]
                or type(result["returnCode"]) is not int
                or any(type(result[key]) is not int or result[key] < 0
                       for key in ("stdoutBytes", "stderrBytes"))
                or result["stdoutTruncated"] is not False
                or result["stderrTruncated"] is not False):
            raise ValueError("published mixed destroy result differs")
        if result["returnCode"] != 0:
            if len(events) != 6:
                raise ValueError("failed published destroy has an absence phase")
            return "failed_result"
        if len(events) == 6:
            return "result"
        if events[6].data != {"commandResultSequence": 6}:
            raise ValueError("published mixed absence phase differs")
        if len(events) == 7:
            return "awaiting_absence"
        evidence = events[7].data
        if (type(evidence) is not dict
                or set(evidence) != {"receipt", "receiptSha256"}
                or type(evidence["receipt"]) is not dict
                or evidence["receiptSha256"] != _fingerprint({
                    key: value for key, value in evidence["receipt"].items()
                    if key != "receipt_sha256"})
                or evidence["receipt"].get("receipt_sha256")
                   != evidence["receiptSha256"]
                or evidence["receipt"].get("provider") != provider
                or evidence["receipt"].get("plan_set_sha256")
                   != plans.plan_set_sha256
                or evidence["receipt"].get("destroy_child_id") != child.id
                or evidence["receipt"].get("destroy_child_journal_sha256")
                   != job_event_digest(events[:7])):
            raise ValueError("published mixed persisted absence receipt differs")
        return "absence_proved"
    except Exception:
        raise PublishedMixedDestroyChildAttention(
            "published mixed destroy journal requires exact one-shot review") from None
