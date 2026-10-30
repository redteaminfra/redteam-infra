# Copyright (c) 2026, Oracle and/or its affiliates.
"""Provider 2 gets a fresh post-first source, never the initial full/full review."""

from dataclasses import replace
from pathlib import Path

import pytest

from app.services.provider_keyed_mixed_published_second_transition import (
    PublishedMixedSecondTransitionAttention,
    review_published_mixed_second_transition,
)
from app.services.provider_keyed_mixed_published_absence import (
    prove_published_mixed_provider_absence,
    propose_published_mixed_first_absence_event,
)
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    propose_published_mixed_initial_cleanup, propose_published_mixed_plans_sealed,
)
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_absence import _awaiting, _empty_snapshot
from test_provider_keyed_mixed_published_destroy_plan import _bind, _saved
from test_provider_keyed_mixed_published_teardown_checkpoint import _core_scope


@pytest.mark.parametrize("drift", [None, "second_state", "core", "bindings",
                                   "historical", "fence", "first_absence",
                                   "missing_receipt"])
def test_post_first_review_requires_first_absent_second_full_and_unchanged_core(
        client, ready, tmp_path, drift):
    with client.application.storage_context():
        review, initial, states, paths, shows, observations = _saved(
            ready, tmp_path, with_observations=True)
        plans = _bind(initial, review, states, paths, shows, tmp_path,
                      fence=lambda: "stable")
        scope = _core_scope(review)
        queued = propose_published_mixed_initial_cleanup(
            review, scope, "Opaque", requested_by="operator")
        parent = propose_published_mixed_plans_sealed(
            queued, review, plans, scope, "Opaque")
        first, second = review.source.ordered_providers
        first_child = _awaiting(parent, review, plans, scope, first)
        first_snapshot = _empty_snapshot(plans.plans[0])
        receipt = prove_published_mixed_provider_absence(
            initial, parent, review, plans, first, first_child,
            first_snapshot, scope, "Opaque", fence=lambda: "stable",
            process_quiescent=lambda identity: True)
        if drift != "missing_receipt":
            first_child = replace(first_child, status="succeeded",
                                  finished_at=first_child.started_at, events=[
                *first_child.events,
                propose_published_mixed_first_absence_event(first_child, receipt)])
        Path(review.provider_scopes[0]["workspace"]).joinpath(
            "terraform.tfstate").write_bytes(first_snapshot.state_json)
        second_observation = observations[second]
        current_scope = lambda: scope
        empty = lambda: {kind: () for kind in (
            "channels", "domains", "certificates", "sites")}
        historical = lambda: True
        fence = lambda: "stable"
        if drift == "second_state":
            second_observation = replace(
                second_observation, state_json=second_observation.state_json + b" ")
        elif drift == "core":
            current_scope = lambda: {**scope, "stateSha256": "0" * 64}
        elif drift == "bindings":
            empty = lambda: {**{kind: () for kind in (
                "channels", "domains", "certificates", "sites")},
                "channels": ("active",)}
        elif drift == "historical":
            historical = lambda: False
        elif drift == "fence":
            values = iter(("first", "second", "second"))
            fence = lambda: next(values)
        elif drift == "first_absence":
            first_snapshot = replace(first_snapshot, phase="apply")
        kwargs = dict(
            fence=fence, process_quiescent=lambda identity: True,
            historical_source_unchanged=historical,
            fresh_core_inspector_scope=current_scope,
            fresh_empty_bindings=empty)
        if drift is not None:
            with pytest.raises(PublishedMixedSecondTransitionAttention):
                review_published_mixed_second_transition(
                    initial, parent, review, plans, first_child,
                    first_snapshot, second_observation, scope, "Opaque", **kwargs)
        else:
            transition = review_published_mixed_second_transition(
                initial, parent, review, plans, first_child,
                first_snapshot, second_observation, scope, "Opaque", **kwargs)
            assert transition.first_absence.provider == first
            assert transition.second_provider == second
            assert transition.second_state_sha256 == review.source.provider_states[1].state_sha256
