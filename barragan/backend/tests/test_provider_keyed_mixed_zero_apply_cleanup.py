# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted SQLite fence tests; source artifact validation has its own suite."""

from dataclasses import replace

import pytest
from sqlalchemy import text

from app.domain import JobEvent
from app.services import provider_keyed_mixed_zero_apply_cleanup as cleanup
from app.services import provider_keyed_mixed_zero_apply_teardown_source as source_service
from app.storage.database import db
from app.storage.job_repository import (
    MixedZeroApplyReservationConflict, SqlAlchemyJobRepository, StoredJobRun,
)
from app.storage.models import CoreMutationLeaseModel, DeploymentPlanModel, EngagementModel


@pytest.fixture(params=[("linode", "digitalocean"),
                        ("digitalocean", "linode")],
                ids=["linode-first", "digitalocean-first"])
def case(client, monkeypatch, tmp_path, request):
    with client.application.storage_context():
        engagement_id = "eng-mixed-fence"
        db.session.add(EngagementModel(
            id=engagement_id, name="opaque", status="deployed", owner="operator",
            template_id="small", input_parameters={},
        ))
        db.session.add(DeploymentPlanModel(
            id="plan-mixed", engagement_id=engagement_id, revision_id="rev-1",
            status="applied", stage="applied", apply_job_id="job-core-mixed",
        ))
        db.session.add(CoreMutationLeaseModel(
            engagement_id=engagement_id, owner_id="plan-mixed",
            operation="provider_keyed_initial",
        ))
        db.session.commit()
        jobs = SqlAlchemyJobRepository()
        jobs.save(StoredJobRun(
            "job-core-mixed", "pilot_standard_rti_guarded_execute", "succeeded",
            "oci-compartment:testing", "oci_compartment", "compartment-1",
            "operator", {"engagementId": engagement_id, "corePlanId": "plan-mixed"},
            [], "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:00+00:00",
            "2026-10-15T00:00:00+00:00", [JobEvent(1, "info", "core complete", {})],
        ))
        source = source_service.MixedZeroApplySource(
            engagement_id, "job-core-mixed", "plan-mixed", "job-mixed-plan",
            "a" * 64, "b" * 64, request.param, ("c" * 64, "d" * 64),
            "e" * 64, "f" * 64, ("linode:inspector:100", "linode:inspector-firewall:200"),
        )
        roots = (tmp_path / "sketch", tmp_path / "core")
        monkeypatch.setattr(cleanup, "_default_state_root", lambda: roots[0])
        monkeypatch.setattr(cleanup, "DEFAULT_TERRAFORM_STATE_ROOT", roots[1])
        observed = []
        current = [source]

        def audit(*args, **kwargs):
            lease = db.session.get(CoreMutationLeaseModel, engagement_id)
            observed.append((args, kwargs, lease.operation))
            assert kwargs["lease_owner"] == "plan-mixed"
            assert lease.operation == "provider_keyed_initial"
            return current[1] if len(current) > 1 and len(observed) >= 2 else current[0]

        monkeypatch.setattr(cleanup, "audit_mixed_zero_apply_teardown_source", audit)
        monkeypatch.setattr(source_service, "audit_mixed_zero_apply_teardown_source", audit)
        yield jobs, source, current, roots, observed


def _reserve(case):
    jobs, source, _current, roots, _observed = case
    return cleanup.reserve_mixed_zero_apply_cleanup(
        source.engagement_id, source.core_job_id, requested_by="operator",
        environment="devtest", state_root=roots[0], core_state_root=roots[1],
        job_repository=jobs,
    )


def test_reserves_one_exact_parent_and_reuses_after_restart(case):
    jobs, source, _current, _roots, observed = case
    first = _reserve(case)
    assert first.action == cleanup.ACTION and first.status == "queued"
    assert first.input["source"]["ordered_providers"] == list(source.ordered_providers)
    assert first.input["phase"] == "awaiting_inspector_preflight"
    lease = db.session.get(CoreMutationLeaseModel, source.engagement_id)
    assert (lease.owner_id, lease.operation) == (source.core_plan_id, "provider_keyed_teardown_fence")
    assert len(observed) == 2
    second = _reserve(case)
    assert second == first
    assert len(observed) == 2
    assert len(jobs.get(first.id).events) == 1


def test_stale_source_cannot_insert_or_retag(case):
    jobs, source, current, _roots, observed = case
    current.append(replace(source, core_state_sha256="0" * 64))
    with pytest.raises(MixedZeroApplyReservationConflict):
        _reserve(case)
    assert len(observed) == 2
    assert jobs.get(cleanup._parent_id(source.core_job_id)) is None
    assert db.session.get(CoreMutationLeaseModel, source.engagement_id).operation == "provider_keyed_initial"


def test_insert_then_failed_lease_retag_rolls_back_parent(case):
    jobs, source, _current, _roots, _observed = case
    db.session.execute(text("""
        CREATE TRIGGER deny_mixed_fence BEFORE UPDATE OF operation ON core_mutation_leases
        BEGIN SELECT RAISE(ABORT, 'test retag failure'); END
    """))
    db.session.commit()
    with pytest.raises(MixedZeroApplyReservationConflict):
        _reserve(case)
    assert jobs.get(cleanup._parent_id(source.core_job_id)) is None
    assert db.session.get(CoreMutationLeaseModel, source.engagement_id).operation == "provider_keyed_initial"


def test_wrong_or_half_fence_cannot_be_recognized(case):
    jobs, source, _current, _roots, _observed = case
    first = _reserve(case)
    db.session.execute(text("""
        UPDATE core_mutation_leases SET operation = 'provider_keyed_initial'
        WHERE engagement_id = :engagement
    """), {"engagement": source.engagement_id})
    db.session.commit()
    with pytest.raises(MixedZeroApplyReservationConflict):
        _reserve(case)
    assert jobs.get(first.id) == first


def test_changed_parent_seal_cannot_be_recognized(case):
    jobs, source, _current, _roots, _observed = case
    first = _reserve(case)
    jobs.save(replace(first, input={**first.input, "sourceSha256": "0" * 64}))
    with pytest.raises(MixedZeroApplyReservationConflict):
        _reserve(case)
    assert db.session.get(CoreMutationLeaseModel, source.engagement_id).operation == (
        "provider_keyed_teardown_fence")


def test_wrong_initial_lease_owner_cannot_create_parent(case):
    jobs, source, _current, _roots, _observed = case
    db.session.execute(text("""
        UPDATE core_mutation_leases SET owner_id = 'other-plan'
        WHERE engagement_id = :engagement
    """), {"engagement": source.engagement_id})
    db.session.commit()
    with pytest.raises(MixedZeroApplyReservationConflict):
        _reserve(case)
    assert jobs.get(cleanup._parent_id(source.core_job_id)) is None


def test_active_inspector_operation_blocks_fence(case):
    jobs, source, _current, _roots, _observed = case
    jobs.save(StoredJobRun(
        "job-inspector-active", "inspector_readiness", "running",
        f"engagement:{source.engagement_id}", "engagement", source.engagement_id,
        "operator", {}, [], "2026-10-15T00:00:00+00:00",
        "2026-10-15T00:00:00+00:00", None, [],
    ))
    with pytest.raises(MixedZeroApplyReservationConflict):
        _reserve(case)
    assert jobs.get(cleanup._parent_id(source.core_job_id)) is None
