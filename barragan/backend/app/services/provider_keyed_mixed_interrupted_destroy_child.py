# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant one-shot journal contract for a mixed interrupted provider destroy.

Proposal and recognition only. No Terraform Apply or provider call is wired.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from app.domain import JobEvent
from app.services.provider_keyed_mixed_interrupted_cleanup import recognize_mixed_interrupted_sealed_plans
from app.services.provider_keyed_mixed_interrupted_destroy_plan import MixedInterruptedDestroyPlanSet, _scope_sha
from app.services.provider_keyed_mixed_interrupted_destroy_source import MixedInterruptedDestroyShow
from app.services.provider_keyed_mixed_interrupted_source import MixedInterruptedReview
from app.storage.job_repository import StoredJobRun, job_event_digest


ACTION = "provider_keyed_mixed_interrupted_destroy_apply"
_CLAIM_KEYS = {"claimOwner", "claimToken", "claimClaimedAt", "claimHeartbeatAt",
               "claimExpiresAt"}


class MixedInterruptedDestroyChildAttention(ValueError):
    """A one-shot command or its saved journal is uncertain."""


def _child_id(core_job_id: str, provider: str) -> str:
    return ("job-provider-keyed-mixed-interrupted-destroy-"
            f"{core_job_id.removeprefix('job-')}-{provider}")


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()


def _base(initial: StoredJobRun, cleanup: StoredJobRun,
          review: MixedInterruptedReview, plans: MixedInterruptedDestroyPlanSet,
          bound: MixedInterruptedDestroyShow) -> dict:
    recognize_mixed_interrupted_sealed_plans(cleanup, initial, review, plans)
    index = plans.ordered_providers.index(bound.provider)
    scope, plan = review.scopes[index], plans.plans[index]
    if (scope.kind not in {"partial", "full"} or plan.plan_path != bound.plan_path
            or plan.plan_sha256 != bound.plan_sha256
            or plan.before_state_sha256 != bound.before_state_sha256
            or plan.show_json_sha256 != bound.show_sha256
            or plan.scope_sha256 != _scope_sha(scope)
            or not Path(bound.terraform_path).is_absolute()
            or bound.argv_sha256 != _digest((bound.terraform_path, "show", "-json",
                                              bound.plan_path))):
        raise MixedInterruptedDestroyChildAttention("mixed destroy source differs")
    return {
        "engagementId": initial.target_id, "coreJobId": initial.input["coreJobId"],
        "corePlanId": initial.input["corePlanId"], "cleanupParentId": cleanup.id,
        "cleanupJournalSha256": job_event_digest(cleanup.events),
        "sourceSha256": review.review_sha256, "planSetSha256": plans.plan_set_sha256,
        "provider": bound.provider, "providerIndex": index,
        "scopeSha256": plan.scope_sha256, "beforeStateSha256": plan.before_state_sha256,
        "planPath": bound.plan_path, "planSha256": bound.plan_sha256,
        "showSha256": bound.show_sha256, "terraformPath": bound.terraform_path,
        "terraformSha256": bound.terraform_sha256, "mutation": True,
    }


def propose_mixed_interrupted_destroy_child(
    initial: StoredJobRun, cleanup: StoredJobRun,
    review: MixedInterruptedReview, plans: MixedInterruptedDestroyPlanSet,
    bound: MixedInterruptedDestroyShow,
) -> StoredJobRun:
    base = _base(initial, cleanup, review, plans, bound)
    return StoredJobRun(
        id=_child_id(base["coreJobId"], bound.provider), action=ACTION, status="queued",
        target=f"engagement:{initial.target_id}", target_type="engagement",
        target_id=initial.target_id, requested_by=cleanup.requested_by,
        input=base, artifact_refs=[], created_at=datetime.now(timezone.utc).isoformat(),
        started_at=None, finished_at=None,
        events=[JobEvent(1, "info", "mixed provider destroy queued", {})])


def recognize_mixed_interrupted_destroy_child(
    child: StoredJobRun, initial: StoredJobRun, cleanup: StoredJobRun,
    review: MixedInterruptedReview, plans: MixedInterruptedDestroyPlanSet,
    bound: MixedInterruptedDestroyShow,
) -> str:
    """Read exact prefixes; intent without a result always needs attention."""
    try:
        base = _base(initial, cleanup, review, plans, bound)
        events = child.events
        messages = (
            "mixed provider destroy queued", "mixed provider destroy started",
            "mixed provider destroy show proved", "mixed provider destroy command intended",
            "mixed provider destroy command started before GO",
            "mixed provider phase destroy_started", "mixed provider destroy result fenced",
            "mixed provider phase destroy_applied", "mixed provider awaiting exact absence",
        )
        if (child.id != _child_id(base["coreJobId"], bound.provider)
                or child.action != ACTION
                or {key: value for key, value in child.input.items()
                    if key not in _CLAIM_KEYS} != base
                or child.target != f"engagement:{initial.target_id}"
                or child.target_type != "engagement" or child.target_id != initial.target_id
                or child.requested_by != cleanup.requested_by or child.artifact_refs != []
                or not 1 <= len(events) <= len(messages)
                or [(row.sequence, row.level, row.message) for row in events]
                != [(number, "info", message)
                    for number, message in enumerate(messages[:len(events)], 1)]
                or events[0].data != {}):
            raise ValueError("mixed destroy child boundary differs")
        if len(events) == 1:
            if (child.status != "queued" or child.input != base
                    or child.started_at is not None or child.finished_at is not None):
                raise ValueError("mixed destroy queue differs")
            return "queued"
        if child.status != "running" or child.started_at is None or child.finished_at is not None:
            raise ValueError("mixed destroy running child differs")
        if events[1].data != {}:
            raise ValueError("mixed destroy start differs")
        if len(events) == 2:
            return "started"
        show_data = {
                "showSha256": bound.show_sha256, "planSha256": bound.plan_sha256,
                "terraformSha256": bound.terraform_sha256,
                "beforeStateSha256": bound.before_state_sha256,
                "showArgvSha256": bound.argv_sha256}
        if base["providerIndex"] == 1:
            prior = events[2].data
            if (type(prior) is not dict
                    or set(prior) != set(show_data) | {
                        "priorAbsenceObservationSha256", "priorAbsenceReceiptSha256"}
                    or any(type(prior[key]) is not str or len(prior[key]) != 64
                           or any(char not in "0123456789abcdef" for char in prior[key])
                           for key in ("priorAbsenceObservationSha256", "priorAbsenceReceiptSha256"))):
                raise ValueError("prior provider absence journal differs")
            show_data.update({key: prior[key] for key in (
                "priorAbsenceObservationSha256", "priorAbsenceReceiptSha256")})
        if events[2].data != show_data:
            raise ValueError("mixed destroy show journal differs")
        if len(events) == 3:
            return "show_proved"
        intent = events[3].data
        apply_argv = (bound.terraform_path, "apply", "-input=false", "-lock=true",
                      "-no-color", bound.plan_path)
        if (type(intent) is not dict
                or set(intent) != {"invocationId", "argvSha256", "showJournalSha256",
                                   "beforeStateSha256", "planSha256"}
                or type(intent["invocationId"]) is not str or not intent["invocationId"]
                or intent["argvSha256"] != _digest(apply_argv)
                or intent["showJournalSha256"] != job_event_digest(events[:3])
                or intent["beforeStateSha256"] != bound.before_state_sha256
                or intent["planSha256"] != bound.plan_sha256):
            raise ValueError("mixed destroy command intent differs")
        if len(events) < 7:
            raise ValueError("one-shot destroy intent has no exact result")
        started, phase, result = [row.data for row in events[4:7]]
        if (type(started) is not dict
                or set(started) != {"invocationId", "bootId", "pid", "pgid", "startTicks"}
                or started["invocationId"] != intent["invocationId"]
                or type(started["bootId"]) is not str or not started["bootId"]
                or any(type(started[key]) is not int or started[key] <= 0
                       for key in ("pid", "pgid", "startTicks"))
                or started["pid"] != started["pgid"]
                or phase != {"commandStartSequence": 5}
                or type(result) is not dict
                or set(result) != {"invocationId", "returnCode", "stdoutBytes",
                                   "stderrBytes", "stdoutTruncated", "stderrTruncated"}
                or result["invocationId"] != intent["invocationId"]
                or type(result["returnCode"]) is not int
                or any(type(result[key]) is not int or result[key] < 0
                       for key in ("stdoutBytes", "stderrBytes"))
                or result["stdoutTruncated"] is not False
                or result["stderrTruncated"] is not False):
            raise ValueError("mixed destroy command result differs")
        if result["returnCode"] != 0:
            if len(events) != 7:
                raise ValueError("failed destroy has an applied phase")
            return "failed_result"
        if len(events) == 7:
            return "result"
        if events[7].data != {"commandResultSequence": 7}:
            raise ValueError("mixed destroy applied phase differs")
        if len(events) == 8:
            return "phase_applied"
        if events[8].data != {"commandResultSequence": 7}:
            raise ValueError("mixed destroy absence wait differs")
        return "awaiting_absence"
    except Exception:
        raise MixedInterruptedDestroyChildAttention(
            "mixed destroy child journal requires exact one-shot review") from None
