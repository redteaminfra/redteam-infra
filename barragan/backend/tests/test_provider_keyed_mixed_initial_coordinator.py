# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline mixed initial handoff recognizes exact persisted provider journals."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import sqlite3

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id, _prior_workspace, recognize_mixed_initial_apply_result,
    recognize_mixed_initial_apply_terminal, run_mixed_initial_provider_apply,
)
from app.services import provider_keyed_mixed_initial_apply_proof as apply_proof
from app.services.provider_keyed_mixed_initial_coordinator import (
    HANDOFF_MESSAGE, HANDOFF_PHASE, MixedInitialCoordinatorAttention,
    inspect_mixed_initial_host_proof_handoff,
    prepare_or_reuse_mixed_initial_host_proof_handoff,
    recognize_mixed_initial_host_proof_handoff,
)
from app.services.provider_keyed_mixed_partial_apply_source import ProviderApplyClassification
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, SqliteJobRepository, job_event_digest
from app.storage.models import CoreMutationLeaseModel
from test_provider_keyed_mixed_initial_apply_child import _terminal_first, ready
from test_provider_keyed_mixed_initial_plan_parent import case


def _finish_second(ready, first):
    order = ready.parent.input["orderedProviders"]
    def fresh(parent, child, workspace, **kwargs):
        kwargs["fence"]()
        return ProviderApplyClassification(order[0], "full")
    running = run_mixed_initial_provider_apply(
        provider=order[1], prior_fresh_prover=fresh, **ready.args)
    result = recognize_mixed_initial_apply_result(running, ready.parent, order[1])
    proof = {
        "classifierKind": "full", "stateSha256": "d" * 64,
        "lineage": "second-lineage", "serial": 1,
        "inventorySha256": "e" * 64, "observationSha256": "f" * 64,
        "resourceIds": {"node.address": "202"},
        "selectorResourcesCount": 1 if order[1] == "digitalocean" else None,
        "selectorAttachedNodeIds": ["202"] if order[1] == "digitalocean" else None,
        "linodeFirewallAttachedNodeIds": ["202"] if order[1] == "linode" else None,
        "inventoryCount": 1,
        "commandResultJournalSha256": result["commandResultJournalSha256"],
    }
    events = [*running.events,
              JobEvent(len(running.events) + 1, "info", "mixed provider full observation proved", proof),
              JobEvent(len(running.events) + 2, "info", "mixed provider initial Apply succeeded",
                       {"observationSha256": proof["observationSha256"]})]
    terminal = replace(running, status="succeeded", finished_at=datetime.now(timezone.utc).isoformat(),
                       events=events)
    ready.case.jobs.save(terminal)
    return {order[0]: first, order[1]: ready.case.jobs.get(terminal.id)}


def _inputs(ready):
    first = _terminal_first(ready)
    children = _finish_second(ready, first)
    core = ready.case.records["core_job"]
    first_proof = first.events[-2].data
    observations = []
    def fresh(parent, child, fence):
        assert parent.id == ready.parent.id and parent.events == ready.parent.events
        assert child == first
        fence()
        observations.append(child.id)
        provider = ready.parent.input["orderedProviders"][0]
        return ProviderApplyClassification(
            provider, "full", first_proof["stateSha256"],
            first_proof["lineage"], first_proof["serial"],
            tuple(first_proof["resourceIds"].items()))
    return core, children, fresh, observations


def test_both_reviewed_orders_build_one_typed_handoff(ready):
    core, children, fresh, observations = _inputs(ready)
    fenced = []
    data = inspect_mixed_initial_host_proof_handoff(
        ready.parent, core, core.id, children,
        fresh_first_prover=fresh, fence=lambda: fenced.append(True) or "generation")
    order = ready.parent.input["orderedProviders"]
    assert data["schema"] == "mixed-initial-host-proof-handoff-v1"
    assert data["orderedProviders"] == order
    assert data["chainIds"] == ready.parent.input["chainIds"]
    assert len(data["terminalJournalSha256"]) == 2
    assert observations == [_child_id("job-core", order[0])]
    assert len(fenced) == 3
    # Recognition of a persisted checkpoint needs no second provider read.
    checkpoint = replace(ready.parent,
                         input={**ready.parent.input, "phase": HANDOFF_PHASE},
                         events=[*ready.parent.events, JobEvent(7, "info", HANDOFF_MESSAGE, data)])
    assert recognize_mixed_initial_host_proof_handoff(checkpoint, core, core.id, children) == data


def test_missing_or_partial_child_cannot_build_handoff(ready):
    core, children, fresh, observations = _inputs(ready)
    order = ready.parent.input["orderedProviders"]
    with pytest.raises(MixedInitialCoordinatorAttention):
        inspect_mixed_initial_host_proof_handoff(
            ready.parent, core, core.id, {order[0]: children[order[0]]},
            fresh_first_prover=fresh, fence=lambda: "generation")
    partial = replace(children[order[1]], status="running", finished_at=None,
                      events=children[order[1]].events[:-1])
    with pytest.raises(MixedInitialCoordinatorAttention):
        inspect_mixed_initial_host_proof_handoff(
            ready.parent, core, core.id, {**children, order[1]: partial},
            fresh_first_prover=fresh, fence=lambda: "generation")
    assert observations == []


def test_foreign_child_stale_core_and_fresh_mismatch_are_closed(ready):
    core, children, fresh, observations = _inputs(ready)
    order = ready.parent.input["orderedProviders"]
    bad = replace(children[order[1]], requested_by="foreign")
    with pytest.raises(MixedInitialCoordinatorAttention):
        inspect_mixed_initial_host_proof_handoff(
            ready.parent, core, core.id, {**children, order[1]: bad},
            fresh_first_prover=fresh, fence=lambda: "generation")
    with pytest.raises(MixedInitialCoordinatorAttention):
        inspect_mixed_initial_host_proof_handoff(
            ready.parent, core, "another-core", children,
            fresh_first_prover=fresh, fence=lambda: "generation")
    with pytest.raises(MixedInitialCoordinatorAttention):
        inspect_mixed_initial_host_proof_handoff(
            ready.parent, core, core.id, children,
            fresh_first_prover=lambda *_: ProviderApplyClassification(order[0], "partial"),
            fence=lambda: "generation")
    assert observations == []


def test_two_digitalocean_parent_is_not_selected_as_mixed(ready):
    core, children, fresh, observations = _inputs(ready)
    not_mixed = replace(ready.parent, input={
        **ready.parent.input, "orderedProviders": ["digitalocean", "digitalocean"]})
    with pytest.raises(MixedInitialCoordinatorAttention):
        inspect_mixed_initial_host_proof_handoff(
            not_mixed, core, core.id, children,
            fresh_first_prover=fresh, fence=lambda: "generation")
    assert observations == []


def test_forged_handoff_event_and_reordered_child_times_are_closed(ready):
    core, children, fresh, _ = _inputs(ready)
    order = ready.parent.input["orderedProviders"]
    data = inspect_mixed_initial_host_proof_handoff(
        ready.parent, core, core.id, children,
        fresh_first_prover=fresh, fence=lambda: "generation")
    checkpoint = replace(ready.parent,
                         input={**ready.parent.input, "phase": HANDOFF_PHASE},
                         events=[*ready.parent.events,
                                 JobEvent(7, "info", HANDOFF_MESSAGE,
                                          {**data, "terminalJournalSha256": ["0" * 64] * 2})])
    with pytest.raises(MixedInitialCoordinatorAttention):
        recognize_mixed_initial_host_proof_handoff(checkpoint, core, core.id, children)
    second = children[order[1]]
    reversed_time = replace(second, started_at="2000-01-01T00:00:00+00:00")
    with pytest.raises(MixedInitialCoordinatorAttention):
        inspect_mixed_initial_host_proof_handoff(
            ready.parent, core, core.id, {**children, order[1]: reversed_time},
            fresh_first_prover=fresh, fence=lambda: "generation")


def test_persisted_checkpoint_duplicate_and_process_restart(ready):
    core, _, fresh, observations = _inputs(ready)
    args = dict(engagement_id="eng-opaque", core_job_id="job-core", environment="devtest",
                fresh_first_prover=fresh, job_repository=ready.case.jobs,
                lease_lookup=ready.case.args["lease_lookup"])
    checkpoint = prepare_or_reuse_mixed_initial_host_proof_handoff(**args)
    assert checkpoint.input["phase"] == HANDOFF_PHASE
    assert len(checkpoint.events) == 7
    assert len(observations) == 1
    assert prepare_or_reuse_mixed_initial_host_proof_handoff(**args) == checkpoint
    assert len(observations) == 1
    reopened = SqliteJobRepository(ready.case.jobs.database_path)
    assert prepare_or_reuse_mixed_initial_host_proof_handoff(
        **{**args, "job_repository": reopened,
           "fresh_first_prover": lambda *a: pytest.fail("fresh provider read repeated")}) == checkpoint
    assert reopened.get(checkpoint.id) == checkpoint


def test_failed_fresh_proof_leaves_seal_for_read_only_retry(ready):
    core, _, fresh, observations = _inputs(ready)
    args = dict(engagement_id="eng-opaque", core_job_id="job-core", environment="devtest",
                job_repository=ready.case.jobs,
                lease_lookup=ready.case.args["lease_lookup"])
    with pytest.raises(MixedInitialCoordinatorAttention):
        prepare_or_reuse_mixed_initial_host_proof_handoff(
            **args, fresh_first_prover=lambda *_: ProviderApplyClassification("linode", "partial"))
    sealed = ready.case.jobs.get(ready.parent.id)
    assert sealed.input["phase"] == "apply_sealed" and len(sealed.events) == 6
    # The expired claim is restartable. No provider command or child journal
    # is replayed; only the fresh read-only presence proof runs again.
    with ready.case.jobs._connect() as connection:
        connection.execute(
            "UPDATE job_runs SET input = json_set(input, '$.claimExpiresAt', ?) WHERE id = ?",
            ("2000-01-01T00:00:00+00:00", ready.parent.id))
    checkpoint = prepare_or_reuse_mixed_initial_host_proof_handoff(
        **args, fresh_first_prover=fresh)
    assert checkpoint.input["phase"] == HANDOFF_PHASE
    assert len(observations) == 1


def test_sqlalchemy_handoff_cas_fences_lease_and_duplicate(ready):
    core, children, fresh, _ = _inputs(ready)
    data = inspect_mixed_initial_host_proof_handoff(
        ready.parent, core, core.id, children,
        fresh_first_prover=fresh, fence=lambda: "generation")
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        db.session.add(CoreMutationLeaseModel(
            engagement_id="eng-opaque", owner_id="plan-1",
            operation="provider_keyed_initial"))
        db.session.commit()
        repo = SqlAlchemyJobRepository()
        repo.save(ready.parent)
        for child in children.values():
            repo.save(child)
        now = datetime.now(timezone.utc)
        claimed = repo.claim_lease(
            ready.parent.id, owner="handoff-test", token="token",
            claimed_at=now.isoformat(),
            expires_at=(now + timedelta(minutes=5)).isoformat(),
            eligible_statuses={"running"}, eligible_phases={"apply_sealed"})
        assert claimed is not None
        event = JobEvent(7, "info", HANDOFF_MESSAGE, data)
        def append(row):
            return repo.append_mixed_initial_handoff_if_claimed(
                row, owner="handoff-test", token="token", lease_owner="plan-1",
                expected_event_digest=job_event_digest(row.events), event=event)
        from sqlalchemy import text
        db.session.execute(text(
            "UPDATE core_mutation_leases SET operation = 'provider_keyed_teardown_fence'"))
        db.session.commit()
        assert append(claimed) is None
        assert len(repo.get(claimed.id).events) == 6
        db.session.execute(text(
            "UPDATE core_mutation_leases SET operation = 'provider_keyed_initial'"))
        db.session.commit()
        checkpoint = append(claimed)
        assert checkpoint is not None and checkpoint.input["phase"] == HANDOFF_PHASE
        assert checkpoint.events[6] == event
        assert append(claimed) is None
        assert repo.get(claimed.id) == checkpoint


@pytest.mark.parametrize("drift", ["status", "journal"])
def test_sqlalchemy_handoff_cas_rejects_terminal_child_drift(ready, drift, tmp_path):
    core, children, fresh, _ = _inputs(ready)
    data = inspect_mixed_initial_host_proof_handoff(
        ready.parent, core, core.id, children,
        fresh_first_prover=fresh, fence=lambda: "generation")
    database_path = tmp_path / "handoff-drift.sqlite3"
    state = db.configure(f"sqlite:///{database_path}")
    with db.bind(state):
        db.create_all()
        db.session.add(CoreMutationLeaseModel(
            engagement_id="eng-opaque", owner_id="plan-1",
            operation="provider_keyed_initial"))
        db.session.commit()
        repo = SqlAlchemyJobRepository()
        repo.save(ready.parent)
        for child in children.values():
            repo.save(child)
        now = datetime.now(timezone.utc)
        claimed = repo.claim_lease(
            ready.parent.id, owner="handoff-test", token="token",
            claimed_at=now.isoformat(),
            expires_at=(now + timedelta(minutes=5)).isoformat(),
            eligible_statuses={"running"}, eligible_phases={"apply_sealed"})
        assert claimed is not None
        first_id = children[ready.parent.input["orderedProviders"][0]].id
        # Warm SQLAlchemy's identity map, then mutate through another SQLite
        # connection as a concurrent worker could between precheck and CAS.
        assert repo.get(first_id) is not None
        with sqlite3.connect(database_path) as external:
            if drift == "status":
                external.execute(
                    "UPDATE job_runs SET status = 'running', finished_at = NULL WHERE id = ?",
                    (first_id,))
            else:
                external.execute(
                    "UPDATE job_events SET data = '{}' WHERE job_id = ? "
                    "AND sequence = (SELECT max(sequence) FROM job_events WHERE job_id = ?)",
                    (first_id, first_id))
        event = JobEvent(7, "info", HANDOFF_MESSAGE, data)
        assert repo.append_mixed_initial_handoff_if_claimed(
            claimed, owner="handoff-test", token="token", lease_owner="plan-1",
            expected_event_digest=job_event_digest(claimed.events), event=event) is None
        assert repo.get(claimed.id).input["phase"] == "apply_sealed"
        assert len(repo.get(claimed.id).events) == 6


def test_sqlite_handoff_cas_rejects_terminal_child_journal_drift(ready):
    core, children, fresh, _ = _inputs(ready)
    data = inspect_mixed_initial_host_proof_handoff(
        ready.parent, core, core.id, children,
        fresh_first_prover=fresh, fence=lambda: "generation")
    repo = ready.case.jobs
    now = datetime.now(timezone.utc)
    claimed = repo.claim_lease(
        ready.parent.id, owner="handoff-test", token="token",
        claimed_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
        eligible_statuses={"running"}, eligible_phases={"apply_sealed"})
    assert claimed is not None
    first_id = children[ready.parent.input["orderedProviders"][0]].id
    with sqlite3.connect(repo.database_path) as external:
        external.execute(
            "UPDATE job_events SET data = '{}' WHERE job_id = ? "
            "AND sequence = (SELECT max(sequence) FROM job_events WHERE job_id = ?)",
            (first_id, first_id))
    event = JobEvent(7, "info", HANDOFF_MESSAGE, data)
    assert repo.append_mixed_initial_handoff_if_claimed(
        claimed, owner="handoff-test", token="token", lease_owner="plan-1",
        expected_event_digest=job_event_digest(claimed.events), event=event) is None
    assert repo.get(claimed.id).input["phase"] == "apply_sealed"


def test_real_fresh_prover_adapter_renews_during_paginated_read(ready, monkeypatch):
    _, children, _, _ = _inputs(ready)
    first_provider = ready.parent.input["orderedProviders"][0]
    first = children[first_provider]
    terminal = recognize_mixed_initial_apply_terminal(first, ready.parent, first_provider)
    workspace = _prior_workspace(ready.parent, first_provider, terminal)
    historical = terminal["proof"]
    page_fences = []

    def collected(parent, provider, retained_workspace, *, fence, **kwargs):
        assert provider == first_provider and retained_workspace == workspace
        generation = fence()
        assert type(generation) is str and generation
        for _ in range(5):  # A slow multi-page GET keeps the same generation.
            page_fences.append(fence())
            assert page_fences[-1] == generation
        return SimpleNamespace(
            phase="applied", state_json=b"retained", inventory=(),
            selector_tag_exists=first_provider == "digitalocean",
            selector_resources_count=historical["selectorResourcesCount"],
            selector_attached_node_ids=historical["selectorAttachedNodeIds"],
            linode_firewall_attached_node_ids=historical["linodeFirewallAttachedNodeIds"])

    monkeypatch.setattr(apply_proof, "collect_provider_inventory_snapshot", collected)
    monkeypatch.setattr(apply_proof, "classify_sealed_provider_apply", lambda *a, **k:
                        ProviderApplyClassification(
                            first_provider, "full", historical["stateSha256"],
                            historical["lineage"], historical["serial"],
                            tuple(historical["resourceIds"].items())))
    renewals = []
    renew = ready.case.jobs.renew_lease
    def counted_renew(*args, **kwargs):
        renewals.append(kwargs["expires_at"])
        return renew(*args, **kwargs)
    monkeypatch.setattr(ready.case.jobs, "renew_lease", counted_renew)
    checkpoint = prepare_or_reuse_mixed_initial_host_proof_handoff(
        "eng-opaque", "job-core", environment="devtest",
        job_repository=ready.case.jobs,
        lease_lookup=ready.case.args["lease_lookup"],
        fresh_first_prover=lambda parent, child, fence:
            apply_proof.prove_mixed_initial_prior_provider_fresh(
                parent, child, workspace, fence=fence,
                process_quiescent=lambda identity: True))
    assert checkpoint.input["phase"] == HANDOFF_PHASE
    assert len(page_fences) == 5 and len(set(page_fences)) == 1
    assert len(renewals) >= 9


def test_unstable_or_empty_fence_cannot_prepare_handoff(ready):
    core, children, fresh, observations = _inputs(ready)
    with pytest.raises(MixedInitialCoordinatorAttention):
        inspect_mixed_initial_host_proof_handoff(
            ready.parent, core, core.id, children,
            fresh_first_prover=fresh, fence=lambda: "")
    assert observations == []
    generations = iter(("one", "one", "two"))
    with pytest.raises(MixedInitialCoordinatorAttention):
        inspect_mixed_initial_host_proof_handoff(
            ready.parent, core, core.id, children,
            fresh_first_prover=fresh, fence=lambda: next(generations))
