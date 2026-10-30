# Copyright (c) 2026, Oracle and/or its affiliates.
"""Both provider scopes and plans are immutable before interrupted destroy GO."""

from dataclasses import replace

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_mixed_interrupted_cleanup import (
    ACTION, propose_mixed_interrupted_cleanup,
    recognize_mixed_interrupted_cleanup_checkpoint,
    recognize_mixed_interrupted_sealed_plans, _canonical,
)
from app.services.provider_keyed_mixed_interrupted_destroy_plan import (
    bind_mixed_interrupted_destroy_plans,
)
from app.services.provider_keyed_mixed_interrupted_source import (
    review_mixed_interrupted_source,
)
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_interrupted_source import _snapshot


def _boundary(ready):
    initial = ready.parent
    order = tuple(initial.input["orderedProviders"])
    review = review_mixed_interrupted_source(
        initial, {provider: None for provider in order},
        {provider: _snapshot(provider) for provider in order},
        fence=lambda: "stable", process_quiescent=lambda identity: True)
    plans = bind_mixed_interrupted_destroy_plans(
        initial, review, {provider: None for provider in order},
        {provider: None for provider in order},
        {provider: None for provider in order}, fence=lambda: "one-teardown-generation")
    return initial, review, plans


def test_both_orders_review_then_both_plan_checkpoint(ready):
    initial, review, plans = _boundary(ready)
    parent = propose_mixed_interrupted_cleanup(initial, review, requested_by="operator")
    assert parent.action == ACTION and parent.status == "queued"
    assert parent.input["sourceSha256"] == review.review_sha256
    assert recognize_mixed_interrupted_cleanup_checkpoint(parent, initial, review) == parent
    sealed = replace(
        parent, input={**parent.input, "phase": "plans_sealed"},
        events=parent.events + [JobEvent(2, "info", "both mixed destroy plans sealed",
                                         {"planSet": _canonical(plans.__dict__ | {
                                             "plans": [plan.__dict__ for plan in plans.plans]}),
                                          "planSetSha256": plans.plan_set_sha256})])
    assert recognize_mixed_interrupted_sealed_plans(sealed, initial, review, plans) == sealed
    with pytest.raises(ValueError):
        recognize_mixed_interrupted_sealed_plans(parent, initial, review, plans)


def test_checkpoint_rejects_review_plan_and_journal_drift(ready):
    initial, review, plans = _boundary(ready)
    parent = propose_mixed_interrupted_cleanup(initial, review, requested_by="operator")
    with pytest.raises(ValueError):
        recognize_mixed_interrupted_cleanup_checkpoint(
            replace(parent, input={**parent.input, "sourceSha256": "0" * 64}), initial, review)
    with pytest.raises(ValueError):
        recognize_mixed_interrupted_cleanup_checkpoint(
            replace(parent, events=[JobEvent(1, "info", "different", {})]), initial, review)
    with pytest.raises(ValueError):
        recognize_mixed_interrupted_sealed_plans(
            parent, initial, review,
            replace(plans, plan_set_sha256="0" * 64))
