# Copyright (c) 2026, Oracle and/or its affiliates.
"""One-shot mixed destroy journal is read-only until a lease-fenced runner exists."""

from dataclasses import replace
import hashlib

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_mixed_interrupted_destroy_child import (
    MixedInterruptedDestroyChildAttention, _digest, propose_mixed_interrupted_destroy_child,
    recognize_mixed_interrupted_destroy_child,
)
from app.services.provider_keyed_mixed_interrupted_destroy_source import bind_mixed_interrupted_destroy_show
from app.storage.job_repository import job_event_digest
from test_provider_keyed_mixed_interrupted_destroy_source import _release, saved
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case


def _boundary(saved):
    initial, cleanup, review, plans, provider, raw, binary, shown, _ = saved
    bound = bind_mixed_interrupted_destroy_show(
        initial, cleanup, review, plans, provider, raw, binary,
        hashlib.sha256(binary.read_bytes()).hexdigest(),
        show_runner=lambda command, cwd: shown, fence=lambda: "stable",
        release_validator=lambda: _release(binary))
    child = propose_mixed_interrupted_destroy_child(initial, cleanup, review, plans, bound)
    return initial, cleanup, review, plans, bound, child


def test_both_orders_queued_child_binds_sealed_review_and_plan(saved):
    initial, cleanup, review, plans, bound, child = _boundary(saved)
    assert recognize_mixed_interrupted_destroy_child(
        child, initial, cleanup, review, plans, bound) == "queued"
    assert child.input["sourceSha256"] == review.review_sha256
    assert child.input["planSetSha256"] == plans.plan_set_sha256
    assert child.input["provider"] == initial.input["orderedProviders"][0]


def test_lost_intent_or_started_command_never_becomes_result(saved):
    initial, cleanup, review, plans, bound, child = _boundary(saved)
    prefix = child.events + [
        JobEvent(2, "info", "mixed provider destroy started", {}),
        JobEvent(3, "info", "mixed provider destroy show proved", {
            "showSha256": bound.show_sha256, "planSha256": bound.plan_sha256,
            "terraformSha256": bound.terraform_sha256,
            "beforeStateSha256": bound.before_state_sha256,
            "showArgvSha256": bound.argv_sha256}),
    ]
    running = replace(child, status="running", started_at="2026-10-15T00:00:00+00:00",
                      events=prefix)
    assert recognize_mixed_interrupted_destroy_child(
        running, initial, cleanup, review, plans, bound) == "show_proved"
    # Any saved intent could precede a command whose result was lost. A
    # restarted worker may inspect it, but may never rerun Terraform Apply.
    intent = JobEvent(4, "info", "mixed provider destroy command intended",
                      {"invocationId": "once", "argvSha256": _digest((
                          bound.terraform_path, "apply", "-input=false", "-lock=true",
                          "-no-color", bound.plan_path)),
                       "showJournalSha256": job_event_digest(prefix),
                       "beforeStateSha256": bound.before_state_sha256,
                       "planSha256": bound.plan_sha256})
    started = JobEvent(5, "info", "mixed provider destroy command started before GO",
                       {"invocationId": "once", "bootId": "boot", "pid": 10,
                        "pgid": 10, "startTicks": 1})
    for rows in (prefix + [intent], prefix + [intent, started],
                 prefix + [intent, started,
                           JobEvent(6, "info", "mixed provider phase destroy_started",
                                    {"commandStartSequence": 5})]):
        with pytest.raises(MixedInterruptedDestroyChildAttention):
            recognize_mixed_interrupted_destroy_child(
                replace(running, events=rows), initial, cleanup, review, plans, bound)
    result = JobEvent(7, "info", "mixed provider destroy result fenced",
                      {"invocationId": "once", "returnCode": 0, "stdoutBytes": 0,
                       "stderrBytes": 0, "stdoutTruncated": False,
                       "stderrTruncated": False})
    assert recognize_mixed_interrupted_destroy_child(
        replace(running, events=prefix + [intent, started,
                JobEvent(6, "info", "mixed provider phase destroy_started",
                         {"commandStartSequence": 5}), result]),
        initial, cleanup, review, plans, bound) == "result"


def test_forged_result_or_plan_set_is_rejected(saved):
    initial, cleanup, review, plans, bound, child = _boundary(saved)
    with pytest.raises(MixedInterruptedDestroyChildAttention):
        recognize_mixed_interrupted_destroy_child(
            replace(child, input={**child.input, "planSetSha256": "0" * 64}),
            initial, cleanup, review, plans, bound)
    with pytest.raises(MixedInterruptedDestroyChildAttention):
        recognize_mixed_interrupted_destroy_child(
            replace(child, status="succeeded"), initial, cleanup, review, plans, bound)
