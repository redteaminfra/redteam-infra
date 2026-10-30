# Copyright (c) 2026, Oracle and/or its affiliates.
"""The private mixed sequencer does not replay uncertain provider writes."""

import pytest

import app.services.provider_keyed_mixed_initial_dispatch as dispatch_service
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id, run_mixed_initial_provider_apply,
)
from app.services.provider_keyed_mixed_initial_coordinator import (
    prepare_or_reuse_mixed_initial_host_proof_handoff,
)
from app.services.provider_keyed_mixed_initial_dispatch import (
    MixedInitialDispatchAttention, advance_mixed_initial_provider_proofs,
)
from app.services.provider_keyed_mixed_partial_apply_source import ProviderApplyClassification
from test_provider_keyed_mixed_initial_apply_child import _terminal_first, ready
from test_provider_keyed_mixed_initial_coordinator import _finish_second
from test_provider_keyed_mixed_initial_plan_parent import case


def _args(ready, **callbacks):
    return dict(
        engagement_id="eng-opaque", core_job_id="job-core", environment="devtest",
        job_repository=ready.case.jobs, lease_lookup=ready.case.args["lease_lookup"],
        **callbacks,
    )


def _fresh_first(ready):
    first_provider = ready.parent.input["orderedProviders"][0]

    def prove(parent, child, fence):
        assert parent.id == ready.parent.id
        assert child.id == _child_id("job-core", first_provider)
        fence()
        proof = child.events[-2].data
        return ProviderApplyClassification(
            first_provider, "full", proof["stateSha256"], proof["lineage"],
            proof["serial"], tuple(proof["resourceIds"].items()))

    return prove


def test_one_sequence_respects_both_orders_and_duplicate_has_no_effects(ready):
    first, second = ready.parent.input["orderedProviders"]
    effects = []

    def apply(provider):
        effects.append(("apply", provider))
        if provider == first:
            return _terminal_first(ready)
        assert provider == second
        prior = ready.case.jobs.get(_child_id("job-core", first))
        return _finish_second(ready, prior)[second]

    def handoff():
        effects.append(("handoff", None))
        return prepare_or_reuse_mixed_initial_host_proof_handoff(
            "eng-opaque", "job-core", environment="devtest",
            fresh_first_prover=_fresh_first(ready), job_repository=ready.case.jobs,
            lease_lookup=ready.case.args["lease_lookup"])

    args = _args(ready, apply_once=apply,
                 prove_applied=lambda _: pytest.fail("already proved child re-proved"),
                 persist_handoff=handoff)
    checkpoint = advance_mixed_initial_provider_proofs(**args)
    assert checkpoint.input["phase"] == "awaiting_mixed_host_proof"
    assert effects == [("apply", first), ("apply", second), ("handoff", None)]
    assert advance_mixed_initial_provider_proofs(**args) == checkpoint
    assert effects == [("apply", first), ("apply", second), ("handoff", None)]


def test_started_write_without_terminal_result_never_replays_or_proves(ready):
    first = ready.parent.input["orderedProviders"][0]
    ready.state["stop"] = "intent"
    with pytest.raises(RuntimeError, match="interrupted before command start"):
        run_mixed_initial_provider_apply(provider=first, **ready.args)
    with pytest.raises(MixedInitialDispatchAttention):
        advance_mixed_initial_provider_proofs(**_args(
            ready, apply_once=lambda _: pytest.fail("uncertain Apply replayed"),
            prove_applied=lambda _: pytest.fail("uncertain Apply proved"),
            persist_handoff=lambda: pytest.fail("uncertain Apply handed off")))
    assert ready.case.jobs.get(_child_id("job-core", ready.parent.input["orderedProviders"][1])) is None


def test_active_core_pointer_drift_after_first_provider_blocks_second(ready, monkeypatch):
    first, second = ready.parent.input["orderedProviders"]
    pointer = {"id": "job-core"}
    monkeypatch.setattr(dispatch_service, "active_core_connection_details",
                        lambda jobs, engagement_id: (pointer["id"], {}))
    effects = []

    def apply(provider):
        effects.append(provider)
        assert provider == first
        completed = _terminal_first(ready)
        pointer["id"] = "job-foreign-core"
        return completed

    with pytest.raises(MixedInitialDispatchAttention):
        advance_mixed_initial_provider_proofs(**_args(
            ready, apply_once=apply,
            prove_applied=lambda _: pytest.fail("core drift reached provider proof"),
            persist_handoff=lambda: pytest.fail("core drift reached handoff")))
    assert effects == [first]
    assert ready.case.jobs.get(_child_id("job-core", second)) is None


def test_no_provider_write_before_both_plan_seal(ready):
    with ready.case.jobs._connect() as connection:
        connection.execute(
            "UPDATE job_runs SET input = json_set(input, '$.phase', 'both_plans_saved') "
            "WHERE id = ?", (ready.parent.id,))
    with pytest.raises(MixedInitialDispatchAttention):
        advance_mixed_initial_provider_proofs(**_args(
            ready, apply_once=lambda _: pytest.fail("unsealed Apply ran"),
            prove_applied=lambda _: pytest.fail("unsealed proof ran"),
            persist_handoff=lambda: pytest.fail("unsealed handoff ran")))
