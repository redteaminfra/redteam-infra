# Copyright (c) 2026, Oracle and/or its affiliates.
"""One reviewed mixed Deploy stops at the strict host-proof handoff."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.services import provider_keyed_mixed_initial_deploy_continuation as service
from app.services.provider_keyed_mixed_initial_apply_child import run_mixed_initial_provider_apply
from app.services.provider_keyed_mixed_initial_coordinator import HANDOFF_PHASE
from test_provider_keyed_mixed_initial_apply_child import _terminal_first, ready
from test_provider_keyed_mixed_initial_coordinator import _finish_second, _inputs
from test_provider_keyed_mixed_initial_plan_parent import case


def _options(ready, **overrides):
    return {
        "engagement_id": "eng-opaque", "core_job_id": "job-core",
        "environment": "devtest", "state_root": ready.case.state_root,
        "selector_absence_prover": ready.args["selector_absence_prover"],
        "selector_get_transport": ready.args["selector_get_transport"],
        "selector_post_transport": ready.args["selector_post_transport"],
        "job_repository": ready.case.jobs,
        "lease_lookup": ready.case.args["lease_lookup"],
        "source_session": ready.args["source_session"],
        **overrides,
    }


def test_both_orders_join_existing_terminal_children_without_reapply(ready):
    _, _, fresh, observations = _inputs(ready)
    checkpoint = service.advance_mixed_initial_deploy_to_host_proof(
        **_options(ready, fresh_first_prover=fresh,
                   apply_runner=lambda *_a, **_k: pytest.fail("Apply replayed"),
                   proof_finisher=lambda *_a, **_k: pytest.fail("proof repeated")))
    assert checkpoint.input["phase"] == HANDOFF_PHASE
    assert len(checkpoint.events) == 7 and len(observations) == 1
    assert service.advance_mixed_initial_deploy_to_host_proof(
        **_options(ready, fresh_first_prover=lambda *_a: pytest.fail(
            "fresh inventory repeated"),
                   apply_runner=lambda *_a, **_k: pytest.fail("Apply replayed"))) == checkpoint


def test_first_terminal_then_second_runs_in_reviewed_order_before_handoff(ready):
    first = _terminal_first(ready)
    order = ready.parent.input["orderedProviders"]
    calls = []

    def run(engagement_id, core_job_id, provider, **kwargs):
        calls.append(provider)
        assert provider == order[1]
        return _finish_second(ready, first)[provider]

    def fresh(parent, child, fence):
        fence()
        proof = first.events[-2].data
        from app.services.provider_keyed_mixed_partial_apply_source import ProviderApplyClassification
        return ProviderApplyClassification(
            order[0], "full", proof["stateSha256"], proof["lineage"],
            proof["serial"], tuple(proof["resourceIds"].items()))

    checkpoint = service.advance_mixed_initial_deploy_to_host_proof(
        **_options(ready, apply_runner=run, fresh_first_prover=fresh,
                   proof_finisher=lambda *_a, **_k: pytest.fail("already terminal")))
    assert calls == [order[1]]
    assert checkpoint.input["phase"] == HANDOFF_PHASE


def test_uncertain_saved_apply_never_replays_or_publishes(ready):
    ready.state["stop"] = "intent"
    order = ready.parent.input["orderedProviders"]
    with pytest.raises(RuntimeError, match="interrupted before command start"):
        run_mixed_initial_provider_apply(provider=order[0], **ready.args)
    intents = [row for row in ready.calls if row[0] == "command-intent"]
    with pytest.raises(service.MixedInitialDeployContinuationAttention):
        service.advance_mixed_initial_deploy_to_host_proof(
            **_options(ready,
                       apply_runner=lambda engagement_id, core_job_id, provider, **_kw:
                       run_mixed_initial_provider_apply(provider=provider, **ready.args),
                       handoff_builder=lambda *_a, **_k: pytest.fail("handoff published")))
    assert [row for row in ready.calls if row[0] == "command-intent"] == intents
    assert ready.case.jobs.get(ready.parent.id).input["phase"] == "apply_sealed"


def test_only_live_child_claim_is_passed_to_proof(ready):
    child = _terminal_first(ready)
    unclaimed = replace(child, input={key: value for key, value in child.input.items()
                                      if not key.startswith("claim")})
    assert service._active_claim(unclaimed) == (None, None)
    future = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()
    claimed = replace(child, input={**child.input, "claimOwner": "worker",
                                    "claimToken": "token", "claimExpiresAt": future})
    assert service._active_claim(claimed) == ("worker", "token")
    expired = replace(claimed, input={**claimed.input,
                                     "claimExpiresAt": "2000-01-01T00:00:00+00:00"})
    assert service._active_claim(expired) == (None, None)


def test_active_core_drift_after_first_terminal_blocks_second_provider(
        ready, monkeypatch):
    _terminal_first(ready)
    actual = service.active_core_connection_details
    reads = []
    def drifting(jobs, engagement_id):
        result = actual(jobs, engagement_id)
        reads.append(result[0])
        return ("job-new-core", result[1]) if len(reads) >= 3 else result
    monkeypatch.setattr(service, "active_core_connection_details", drifting)
    with pytest.raises(service.MixedInitialDeployContinuationAttention):
        service.advance_mixed_initial_deploy_to_host_proof(
            **_options(ready,
                       apply_runner=lambda *_a, **_k: pytest.fail(
                           "second provider Apply ran after core drift"),
                       handoff_builder=lambda *_a, **_k: pytest.fail(
                           "stale core handoff persisted")))
    assert len(reads) >= 3
    assert ready.case.jobs.get(ready.parent.id).input["phase"] == "apply_sealed"
