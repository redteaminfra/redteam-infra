# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted two-phase mixed interrupted cleanup fence; no provider writes."""

import json
from dataclasses import replace

import pytest

from app.services.provider_keyed_mixed_interrupted_cleanup import (
    propose_mixed_interrupted_cleanup,
    recognize_mixed_interrupted_cleanup_checkpoint,
    recognize_mixed_interrupted_sealed_plans,
)
from app.services.provider_keyed_mixed_interrupted_destroy_plan import bind_mixed_interrupted_destroy_plans
from app.services.provider_keyed_mixed_interrupted_source import review_mixed_interrupted_source
import app.services.sketch_state_workspaces as state_workspaces
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.models import CoreMutationLeaseModel, DeploymentPlanModel, EngagementModel
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_interrupted_source import _snapshot


@pytest.fixture
def persisted(ready, client, monkeypatch):
    monkeypatch.setattr(state_workspaces, "_default_state_root", lambda: ready.case.state_root)
    with client.application.storage_context():
        db.session.add(EngagementModel(
            id="eng-opaque", name="opaque-fixture", status="deployed",
            owner="operator", template_id="small", input_parameters={}))
        db.session.add(DeploymentPlanModel(
            id="plan-1", engagement_id="eng-opaque", revision_id="rev-1",
            status="applied", stage="applied", apply_job_id="job-core"))
        db.session.add(CoreMutationLeaseModel(
            engagement_id="eng-opaque", owner_id="plan-1",
            operation="provider_keyed_initial"))
        db.session.commit()
        jobs = SqlAlchemyJobRepository()
        for row in ready.case.jobs.list():
            when = "2026-10-15T00:00:00+00:00"
            normalized = replace(
                row, created_at=when if row.created_at == "now" else row.created_at,
                started_at=when if row.started_at == "now" else row.started_at,
                finished_at=when if row.finished_at == "now" else row.finished_at)
            jobs.save(normalized)
        initial = jobs.get(ready.parent.id)
        order = tuple(initial.input["orderedProviders"])
        snapshots = {provider: _snapshot(provider) for provider in order}
        review = review_mixed_interrupted_source(
            initial, {provider: None for provider in order}, snapshots,
            fence=lambda: "stable", process_quiescent=lambda identity: True)
        proposal = propose_mixed_interrupted_cleanup(initial, review, requested_by="operator")
        yield ready, jobs, initial, review, proposal, snapshots


def test_reserve_and_seal_both_no_plan_scopes_atomically(persisted):
    ready, jobs, initial, review, proposal, snapshots = persisted
    reserved = jobs.reserve_mixed_interrupted_cleanup_parent(
        proposal, initial=initial, review=review, snapshots_by_provider=snapshots,
        process_quiescent=lambda identity: True, state_root=ready.case.state_root,
        review_generation="stable")
    recognize_mixed_interrupted_cleanup_checkpoint(reserved, initial, review)
    assert db.session.get(CoreMutationLeaseModel, "eng-opaque").operation == (
        "provider_keyed_teardown_fence")
    assert jobs.reserve_mixed_interrupted_cleanup_parent(
        proposal, initial=initial, review=review, snapshots_by_provider=snapshots,
        process_quiescent=lambda identity: True, state_root=ready.case.state_root,
        review_generation="stable") == reserved
    order = review.ordered_providers
    absent = {provider: None for provider in order}
    plans = bind_mixed_interrupted_destroy_plans(
        initial, review, absent, absent, absent, fence=lambda: "stable")
    sealed = jobs.seal_mixed_interrupted_destroy_plans(
        reserved, initial=initial, review=review, plan_set=plans,
        before_states=absent, plan_paths=absent, show_json=absent,
        state_root=ready.case.state_root)
    recognize_mixed_interrupted_sealed_plans(sealed, initial, review, plans)
    assert jobs.seal_mixed_interrupted_destroy_plans(
        sealed, initial=initial, review=review, plan_set=plans,
        before_states=absent, plan_paths=absent, show_json=absent,
        state_root=ready.case.state_root) == sealed
    assert len(jobs.get(sealed.id).events) == 2


def test_lease_change_rejects_reservation_without_parent(persisted):
    ready, jobs, initial, review, proposal, snapshots = persisted
    lease = db.session.get(CoreMutationLeaseModel, "eng-opaque")
    lease.operation = "provider_keyed_teardown_fence"
    db.session.commit()
    with pytest.raises(ValueError):
        jobs.reserve_mixed_interrupted_cleanup_parent(
            proposal, initial=initial, review=review, snapshots_by_provider=snapshots,
            process_quiescent=lambda identity: True, state_root=ready.case.state_root,
            review_generation="stable")
    assert jobs.get(proposal.id) is None


@pytest.mark.parametrize("marker", [
    {"schema": "wrong", "phase": None},
    {"schema": "provider-keyed-v2", "phase": None, "extra": "drift"},
])
def test_same_phase_value_with_invalid_marker_rejects_reservation(persisted, marker):
    ready, jobs, initial, review, proposal, snapshots = persisted
    provider = review.ordered_providers[0]
    workspace = next((ready.case.state_root / "eng-opaque" / "provider-keyed-v2"
                      / provider).iterdir())
    (workspace / ".barragan-apply-phase.json").write_text(json.dumps(marker))
    with pytest.raises(ValueError, match="requires fresh review"):
        jobs.reserve_mixed_interrupted_cleanup_parent(
            proposal, initial=initial, review=review, snapshots_by_provider=snapshots,
            process_quiescent=lambda identity: True, state_root=ready.case.state_root,
            review_generation="stable")
    assert jobs.get(proposal.id) is None
    assert db.session.get(CoreMutationLeaseModel, "eng-opaque").operation == (
        "provider_keyed_initial")


def test_seal_rejects_changed_plan_set_without_second_event(persisted):
    ready, jobs, initial, review, proposal, snapshots = persisted
    reserved = jobs.reserve_mixed_interrupted_cleanup_parent(
        proposal, initial=initial, review=review, snapshots_by_provider=snapshots,
        process_quiescent=lambda identity: True, state_root=ready.case.state_root,
        review_generation="stable")
    order = review.ordered_providers
    absent = {provider: None for provider in order}
    plans = bind_mixed_interrupted_destroy_plans(
        initial, review, absent, absent, absent, fence=lambda: "stable")
    with pytest.raises(ValueError):
        jobs.seal_mixed_interrupted_destroy_plans(
            reserved, initial=initial, review=review,
            plan_set=replace(plans, plan_set_sha256="0" * 64),
            before_states=absent, plan_paths=absent, show_json=absent,
            state_root=ready.case.state_root)
    assert len(jobs.get(reserved.id).events) == 1


def test_seal_rejects_alternate_workspace_root_without_second_event(persisted, tmp_path):
    ready, jobs, initial, review, proposal, snapshots = persisted
    reserved = jobs.reserve_mixed_interrupted_cleanup_parent(
        proposal, initial=initial, review=review, snapshots_by_provider=snapshots,
        process_quiescent=lambda identity: True, state_root=ready.case.state_root,
        review_generation="stable")
    absent = {provider: None for provider in review.ordered_providers}
    plans = bind_mixed_interrupted_destroy_plans(
        initial, review, absent, absent, absent, fence=lambda: "stable")
    with pytest.raises(ValueError):
        jobs.seal_mixed_interrupted_destroy_plans(
            reserved, initial=initial, review=review, plan_set=plans,
            before_states=absent, plan_paths=absent, show_json=absent,
            state_root=tmp_path)
    assert len(jobs.get(reserved.id).events) == 1
