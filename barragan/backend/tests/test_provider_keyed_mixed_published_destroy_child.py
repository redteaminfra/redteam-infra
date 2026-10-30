# Copyright (c) 2026, Oracle and/or its affiliates.
"""One-shot published mixed destroy journal stops on uncertain intent."""

from dataclasses import replace
import hashlib
import json

import pytest

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_mixed_published_destroy_child import (
    PublishedMixedDestroyChildAttention, propose_published_mixed_destroy_child,
    recognize_published_mixed_destroy_child,
)
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    propose_published_mixed_initial_cleanup, propose_published_mixed_plans_sealed,
    saved_published_mixed_destroy_plans,
)
from app.storage.job_repository import job_event_digest
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_destroy_plan import _bind, _saved
from test_provider_keyed_mixed_published_teardown_checkpoint import _core_scope


def _setup(ready, tmp_path):
    review, initial, states, paths, shows = _saved(ready, tmp_path)
    plans = _bind(initial, review, states, paths, shows, tmp_path,
                  fence=lambda: "stable")
    scope = _core_scope(review)
    queued = propose_published_mixed_initial_cleanup(
        review, scope, "Opaque", requested_by="operator")
    parent = propose_published_mixed_plans_sealed(
        queued, review, plans, scope, "Opaque")
    return review, plans, scope, parent


def _event(job, message, data):
    return replace(job, events=[*job.events, JobEvent(
        len(job.events) + 1, "info", message, data)])


def test_both_orders_require_first_absence_before_second_child(client, ready, tmp_path):
    with client.application.storage_context():
        review, plans, scope, parent = _setup(ready, tmp_path)
        assert saved_published_mixed_destroy_plans(parent) == plans
        first, second = review.source.ordered_providers
        first_child = propose_published_mixed_destroy_child(
            parent, review, plans, first, scope, "Opaque")
        assert recognize_published_mixed_destroy_child(
            first_child, parent, review, plans, first, scope, "Opaque") == "queued"
        with pytest.raises(ValueError):
            propose_published_mixed_destroy_child(
                parent, review, plans, second, scope, "Opaque")
        second_child = propose_published_mixed_destroy_child(
            parent, review, plans, second, scope, "Opaque",
            prior_absence_receipt_sha256="a" * 64)
        assert second_child.input["priorAbsenceReceiptSha256"] == "a" * 64
        assert recognize_published_mixed_destroy_child(
            second_child, parent, review, plans, second, scope, "Opaque") == "queued"


def test_intent_without_fenced_result_is_uncertain_and_never_replayable(
        client, ready, tmp_path):
    with client.application.storage_context():
        review, plans, scope, parent = _setup(ready, tmp_path)
        provider = review.source.ordered_providers[0]
        child = propose_published_mixed_destroy_child(
            parent, review, plans, provider, scope, "Opaque")
        recognize = lambda job: recognize_published_mixed_destroy_child(
            job, parent, review, plans, provider, scope, "Opaque")
        child = _event(replace(child, status="running", started_at=child.created_at),
                       "published mixed provider destroy started", {})
        assert recognize(child) == "started"
        plan = plans.plans[0]
        child = _event(child, "published mixed provider destroy show proved", {
            "planSha256": plan.plan_sha256,
            "showSha256": plan.show_json_sha256,
            "beforeStateSha256": plan.before_state_sha256,
        })
        assert recognize(child) == "show_proved"
        invocation = "one-command-only"
        child = _event(child, "published mixed provider destroy command intended", {
            "invocationId": invocation,
            "argvSha256": hashlib.sha256(json.dumps([
                plan.terraform_path, "apply", "-input=false", "-lock=true",
                "-no-color", plan.plan_path], separators=(",", ":")).encode()).hexdigest(),
            "showJournalSha256": job_event_digest(child.events),
        })
        assert recognize(child) == "uncertain"
        started = _event(child, "published mixed provider destroy command started before GO", {
            "invocationId": invocation, "bootId": "boot", "pid": 10,
            "pgid": 10, "startTicks": 20,
        })
        assert recognize(started) == "uncertain"
        child = _event(started, "published mixed provider destroy result fenced", {
            "invocationId": invocation, "returnCode": 0,
            "stdoutBytes": 2, "stderrBytes": 0,
            "stdoutTruncated": False, "stderrTruncated": False,
        })
        assert recognize(child) == "result"
        child = _event(child, "published mixed provider awaiting exact absence", {
            "commandResultSequence": 6})
        assert recognize(child) == "awaiting_absence"
        with pytest.raises(PublishedMixedDestroyChildAttention):
            recognize(replace(child, events=[*child.events[:-2], replace(
                child.events[-2], data={**child.events[-2].data,
                                        "returnCode": "0"}), child.events[-1]]))
