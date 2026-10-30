# Copyright (c) 2026, Oracle and/or its affiliates.
"""Injected DevTest first-phase coordinator; no outbound/provider calls."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.services import engagement_teardown as teardown
from app.services import provider_keyed_comprehensive_teardown as service
from app.services import provider_keyed_teardown_handoff as handoff_service
from app.domain import JobEvent
from app.storage.job_repository import SqliteJobRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.domain.deployment_plan import DeploymentPlan
from app.storage.database import db
from test_provider_keyed_teardown_handoff import _fixture
from test_provider_keyed_published_teardown_reservation import _case as published_reservation_case


def _options(tmp_path):
    jobs, _old, queued, scope, plans, handoff_options = _fixture(tmp_path)
    clock = [datetime(2026, 10, 8, 0, 0, tzinfo=timezone.utc)]
    tokens = iter(["b" * 32, "c" * 32, "d" * 32])

    def handoff(parent_id, **kwargs):
        return handoff_service.handoff_terminal_provider_keyed_teardown(
            parent_id, **{**kwargs, "scope_builder": handoff_options["scope_builder"],
                          "now": lambda: clock[0], "token_factory": lambda: "a" * 32})

    options = dict(
        environment="devtest", job_repository=jobs, plan_repository=plans,
        lease_lookup=handoff_options["lease_lookup"], handoff=handoff,
        now=lambda: clock[0], token_factory=lambda: next(tokens),
    )
    return jobs, queued, scope, plans, clock, options


def test_one_claimed_handoff_stops_before_inspector_and_preserves_parent(tmp_path):
    jobs, queued, scope, plans, _clock, options = _options(tmp_path)
    child = service.run_provider_keyed_comprehensive_handoff(queued.id, **options)
    assert child.status == "running"
    assert child.input["phase"] == "awaiting_inspector_preflight"
    assert child.events[-1].message.endswith("Inspector preflight pending")
    assert jobs.get(queued.id) == queued
    assert plans.lease == (scope["corePlanId"], "provider_keyed_teardown_fence")
    again = service.run_provider_keyed_comprehensive_handoff(queued.id, **options)
    assert again == child and len([row for row in jobs.list() if row.action == service.ACTION]) == 1


def test_retag_failure_leaves_claimed_pending_and_recovers_after_expiry(tmp_path):
    jobs, queued, scope, plans, clock, options = _options(tmp_path)
    plans.reject = True
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownError):
        service.run_provider_keyed_comprehensive_handoff(queued.id, **options)
    child = jobs.get(service._child_id("job-core"))
    assert child.status == "running" and child.input["phase"] == "handoff_pending"
    assert jobs.get(queued.id) == queued
    assert plans.lease == (scope["corePlanId"], "provider_keyed_initial")
    plans.reject = False
    clock[0] += timedelta(minutes=6)
    assert teardown.recover_engagement_teardowns(
        job_repository=jobs,
        provider_keyed_coordinator=lambda pid: service.run_provider_keyed_comprehensive_handoff(pid, **options),
        provider_keyed_environment="devtest",
    ) == [queued.id]
    resumed = jobs.get(service._child_id("job-core"))
    assert resumed.input["phase"] == "awaiting_inspector_preflight"
    assert plans.lease == (scope["corePlanId"], "provider_keyed_teardown_fence")
    assert jobs.get(queued.id) == queued


def test_recovery_after_retag_before_child_phase_save_does_not_retag_twice(tmp_path):
    jobs, queued, scope, plans, clock, options = _options(tmp_path)
    original = jobs.save_if_leased

    def lose_completion(job, **kwargs):
        if job.input.get("phase") == "awaiting_inspector_preflight":
            return None
        return original(job, **kwargs)

    jobs.save_if_leased = lose_completion
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownError):
        service.run_provider_keyed_comprehensive_handoff(queued.id, **options)
    assert plans.lease == (scope["corePlanId"], "provider_keyed_teardown_fence")
    assert jobs.get(service._child_id("job-core")).input["phase"] == "handoff_pending"
    jobs.save_if_leased = original
    clock[0] += timedelta(minutes=6)
    resumed = service.run_provider_keyed_comprehensive_handoff(queued.id, **options)
    assert resumed.input["phase"] == "awaiting_inspector_preflight"
    assert len(plans.calls) == 1


def test_live_claim_and_parent_drift_fail_closed(tmp_path):
    jobs, queued, scope, plans, clock, options = _options(tmp_path)
    plans.reject = True
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownError):
        service.run_provider_keyed_comprehensive_handoff(queued.id, **options)
    assert service.run_provider_keyed_comprehensive_handoff(queued.id, **options).input["phase"] == "handoff_pending"
    jobs.save(replace(queued, input={**queued.input, "phase": "attention"}))
    clock[0] += timedelta(minutes=6)
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownError):
        service.run_provider_keyed_comprehensive_handoff(queued.id, **options)
    assert plans.lease == (scope["corePlanId"], "provider_keyed_initial")


def test_default_gate_stays_closed_and_explicit_seam_invokes_coordinator(tmp_path, monkeypatch):
    jobs, queued, scope, plans, _clock, options = _options(tmp_path)
    monkeypatch.setattr(teardown, "_current_scope_snapshot", lambda *_a, **_kw: queued.input["scopeSnapshot"])
    with pytest.raises(teardown.EngagementTeardownValidationError):
        teardown.start_engagement_teardown(
            queued.id, {"confirmation": "destroy test", "snapshotId": queued.input["scopeSnapshot"]["snapshotId"]},
            job_repository=jobs,
        )
    seen = []
    def coordinator(parent_id):
        seen.append(parent_id)
        return service.run_provider_keyed_comprehensive_handoff(parent_id, **options)
    result = teardown.start_engagement_teardown(
        queued.id, {"confirmation": "destroy test", "snapshotId": queued.input["scopeSnapshot"]["snapshotId"]},
        job_repository=jobs, provider_keyed_coordinator=coordinator,
        provider_keyed_environment="devtest",
    )
    assert result == queued and seen == [queued.id]
    assert plans.lease == (scope["corePlanId"], "provider_keyed_teardown_fence")
    assert teardown.recover_engagement_teardowns(job_repository=jobs) == []
    assert teardown.recover_engagement_teardowns(
        job_repository=jobs, provider_keyed_coordinator=coordinator,
        provider_keyed_environment="devtest") == []
    assert seen == [queued.id, queued.id]


def test_injected_start_queues_exact_parent_before_child_call(tmp_path, monkeypatch):
    source_jobs, queued, _scope, _plans, _clock, unused_options = _options(tmp_path)
    jobs = SqliteJobRepository(tmp_path / "start-jobs.sqlite")
    core = source_jobs.get("job-core")
    jobs.save(core)
    snapshot = queued.input["scopeSnapshot"]
    monkeypatch.setattr(teardown, "_current_scope_snapshot", lambda *_a, **_kw: snapshot)
    seen = []

    def coordinator(parent_id):
        current = jobs.get(parent_id)
        assert current.status == "queued" and current.started_at is None
        assert current.input["scopeSnapshot"] == snapshot
        assert current.events == queued.events
        seen.append(parent_id)
        return current

    result = teardown.start_engagement_teardown(
        core.id, {"confirmation": snapshot["confirmationPhrase"],
                  "snapshotId": snapshot["snapshotId"]},
        job_repository=jobs, provider_keyed_coordinator=coordinator,
        provider_keyed_environment="devtest",
    )
    assert result.id == queued.id and seen == [queued.id]
    assert jobs.get(queued.id) == result


def test_concurrent_winner_with_different_confirmation_never_starts_child(tmp_path, monkeypatch):
    source_jobs, queued, _scope, _plans, _clock, unused_options = _options(tmp_path)
    jobs = SqliteJobRepository(tmp_path / "race-jobs.sqlite")
    core = source_jobs.get("job-core")
    jobs.save(core)
    snapshot = queued.input["scopeSnapshot"]
    monkeypatch.setattr(teardown, "_current_scope_snapshot", lambda *_a, **_kw: snapshot)
    def concurrent_winner(candidate):
        changed = {**snapshot, "confirmationPhrase": "other-review"}
        changed["snapshotId"] = teardown._fingerprint({
            key: value for key, value in changed.items() if key != "snapshotId"})
        winner = replace(candidate, input={**candidate.input, "scopeSnapshot": changed},
                         events=[JobEvent(1, "info", "engagement teardown queued",
                                          {"snapshotId": changed["snapshotId"]})])
        return jobs.save(winner)
    monkeypatch.setattr(jobs, "insert_inspector_teardown_barrier", concurrent_winner)
    calls = []
    with pytest.raises(teardown.EngagementTeardownValidationError):
        teardown.start_engagement_teardown(
            core.id, {"confirmation": snapshot["confirmationPhrase"],
                      "snapshotId": snapshot["snapshotId"]},
            job_repository=jobs, provider_keyed_coordinator=lambda pid: calls.append(pid),
            provider_keyed_environment="devtest",
        )
    assert calls == []


def test_sqlalchemy_child_start_claim_handoff_and_phase_round_trip(tmp_path):
    source_jobs, queued, scope, _source_plans, clock, source_options = _options(tmp_path)
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        jobs = SqlAlchemyJobRepository()
        instant = clock[0].isoformat()
        for row in source_jobs.list():
            jobs.save(replace(
                row, created_at=row.created_at or instant,
                started_at=row.started_at or (instant if row.status != "queued" else None),
                finished_at=row.finished_at or (
                    instant if row.status in {"succeeded", "failed"} else None),
            ))
        queued = jobs.get(queued.id)
        plans = SqlAlchemyDeploymentPlanRepository()
        plans.save(DeploymentPlan(
            id=scope["corePlanId"], engagement_id=queued.target_id,
            revision_id="revision-1", status="applied", stage="applied",
            apply_job_id="job-core",
        ))
        plans.acquire(queued.target_id, scope["corePlanId"], "provider_keyed_initial")
        from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
        options = {**source_options, "job_repository": jobs, "plan_repository": plans,
                   "lease_lookup": _db_lease_lookup}
        child = service.run_provider_keyed_comprehensive_handoff(queued.id, **options)
        assert child == jobs.get(child.id)
        assert child.input["phase"] == "awaiting_inspector_preflight"
        assert child.input["claimExpiresAt"] == clock[0].isoformat()
        assert jobs.get(queued.id) == queued
        assert _db_lease_lookup(queued.target_id) == (
            scope["corePlanId"], "provider_keyed_teardown_fence")
        assert service.run_provider_keyed_comprehensive_handoff(queued.id, **options) == child


def _published_options(client, monkeypatch, tmp_path):
    from app.services import provider_keyed_teardown_source as source_selector
    from app.services.provider_keyed_runtime_preflight import _db_lease_lookup

    jobs, proposal, source, _audits = published_reservation_case(client, monkeypatch, tmp_path)
    parent = jobs.reserve_published_keyed_teardown_parent(proposal, reviewed_source=source)
    scope = parent.input["scopeSnapshot"]["providerScopes"][0]
    reads = []
    def audited(core_id, **kwargs):
        reads.append((core_id, kwargs["expected_teardown_parent_id"]))
        return source
    monkeypatch.setattr(source_selector, "audit_published_provider_keyed_source", audited)
    monkeypatch.setattr(source_selector, "build_digitalocean_keyed_teardown_scope",
                        lambda *_args, **_kwargs: scope)
    clock = [datetime(2026, 10, 9, tzinfo=timezone.utc)]
    options = dict(environment="devtest", job_repository=jobs,
                   plan_repository=SqlAlchemyDeploymentPlanRepository(),
                   lease_lookup=_db_lease_lookup,
                   handoff=lambda *_a, **_kw: pytest.fail("published job must not be retagged"),
                   pending_auditor=lambda *_a, **_kw: pytest.fail("published job is not pending"),
                   now=lambda: clock[0], token_factory=lambda: "c" * 32)
    return jobs, parent, source, reads, clock, options


def test_published_reserved_parent_advances_once_without_initial_retag(client, monkeypatch, tmp_path):
    with client.application.storage_context():
        jobs, parent, source, reads, _clock, options = _published_options(client, monkeypatch, tmp_path)
        initial = jobs.get(source.initial_job_id)
        child = service.run_provider_keyed_comprehensive_handoff(parent.id, **options)
        assert child.input["phase"] == "awaiting_inspector_preflight"
        assert [event.data for event in child.events] == [
            {"snapshotId": parent.input["scopeSnapshot"]["snapshotId"]}, {}, {},
            {"corePlanId": source.core_plan_id},
        ]
        assert jobs.get(source.initial_job_id) == initial
        assert jobs.get(parent.id) == parent
        assert len(reads) >= 4
        assert service.run_provider_keyed_comprehensive_handoff(parent.id, **options) == child


def test_published_fence_or_sealed_source_drift_prevents_child(client, monkeypatch, tmp_path):
    from app.storage.models import CoreMutationLeaseModel

    with client.application.storage_context():
        jobs, parent, source, _reads, _clock, options = _published_options(client, monkeypatch, tmp_path)
        tampered = replace(parent, input={**parent.input,
            "publishedSource": {**parent.input["publishedSource"], "state_sha256": "f" * 64}})
        jobs.save(tampered)
        with pytest.raises(service.ProviderKeyedComprehensiveTeardownError):
            service.run_provider_keyed_comprehensive_handoff(parent.id, **options)
        assert jobs.get(service._child_id(source.core_job_id)) is None
        jobs.save(parent)
        db.session.delete(db.session.get(CoreMutationLeaseModel, parent.target_id))
        db.session.commit()
        with pytest.raises(service.ProviderKeyedComprehensiveTeardownError):
            service.run_provider_keyed_comprehensive_handoff(parent.id, **options)
        assert jobs.get(service._child_id(source.core_job_id)) is None


def test_published_handoff_pending_restart_reproves_without_retag(client, monkeypatch, tmp_path):
    with client.application.storage_context():
        jobs, parent, source, reads, clock, options = _published_options(client, monkeypatch, tmp_path)
        original = jobs.save_if_leased
        def crash_before_ready(job, **kwargs):
            if job.input.get("phase") == "awaiting_inspector_preflight":
                return None
            return original(job, **kwargs)
        jobs.save_if_leased = crash_before_ready
        with pytest.raises(service.ProviderKeyedComprehensiveTeardownError):
            service.run_provider_keyed_comprehensive_handoff(parent.id, **options)
        pending = jobs.get(service._child_id(source.core_job_id))
        assert pending.input["phase"] == "handoff_pending"
        jobs.save_if_leased = original
        clock[0] += timedelta(minutes=6)
        ready = service.run_provider_keyed_comprehensive_handoff(parent.id, **options)
        assert ready.input["phase"] == "awaiting_inspector_preflight"
        assert len(ready.events) == 4 and len(reads) >= 5


def test_published_absence_recognizer_selects_historical_source_before_pending_boundary(client, monkeypatch, tmp_path):
    from app.services import provider_keyed_destroy_absence_preflight as absence
    from app.services import provider_keyed_teardown_source as sources
    from app.services import sketch_state_workspaces as workspaces

    with client.application.storage_context():
        jobs, parent, _source, _reads, _clock, options = _published_options(client, monkeypatch, tmp_path)
        root = tmp_path / "state"
        root.mkdir(exist_ok=True)
        monkeypatch.setattr(workspaces, "_default_state_root", lambda: root)
        monkeypatch.setattr(absence, "_read_success_boundary",
                            lambda *_a, **_kw: pytest.fail("pending history must not be read"))
        called = []
        def published_reader(*_args, **_kwargs):
            called.append("published")
            raise ValueError("fixture has no completed saved destroy")
        monkeypatch.setattr(sources, "_read_published_post_destroy_boundary", published_reader)
        for recognize in (service.recognize_provider_keyed_destroy_absence,
                          service.recognize_provider_keyed_group_retired):
            previous_calls = len(called)
            with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
                recognize(parent.id, environment="devtest", state_root=root,
                          job_repository=jobs, plan_repository=options["plan_repository"])
            assert called[previous_calls:] == ["published"]
