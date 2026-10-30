# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted private pending-group continuation; provider calls are stubbed."""

from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_pending_cleanup as service
from app.storage.job_repository import StoredJobRun
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.database import db
from app.domain.deployment_plan import DeploymentPlan
from test_provider_keyed_pending_cleanup import _ready_case


def _case(tmp_path, monkeypatch):
    jobs, parent, ready, preview_id, _calls, _sources, preview_opts = _ready_case(
        tmp_path, monkeypatch)
    service.advance_pending_keyed_cleanup_to_preview(parent.id, **preview_opts)
    core_id = parent.input["scopeSnapshot"]["coreJobId"]
    apply_id = f"job-provider-keyed-initial-destroy-apply-{core_id.removeprefix('job-')}"
    calls = []

    def source(*_args, **_kwargs):
        calls.append("source")
        return SimpleNamespace(
            variant="pending_handoff", teardown_parent_id=parent.id,
            engagement_id=parent.target_id, core_job_id=core_id,
            core_plan_id=jobs.get(core_id).input["corePlanId"],
            snapshot_id=parent.input["scopeSnapshot"]["snapshotId"],
            provider_scope_sha256=parent.input["scopeSnapshot"]["providerScopeSha256"],
        )

    def apply(*_args, **_kwargs):
        calls.append("apply_or_absence")
        if jobs.get(apply_id) is None:
            jobs.save(StoredJobRun(
                id=apply_id, action=service.APPLY_ACTION, status="succeeded",
                target=f"engagement:{parent.target_id}", target_type="engagement",
                target_id=parent.target_id, requested_by=parent.requested_by,
                input={}, artifact_refs=[], created_at=parent.created_at,
                started_at=parent.created_at, finished_at=parent.created_at,
                events=[JobEvent(1, "info", "test successful one-shot apply", {})],
            ))
        return object()

    def transition(phase, event):
        child = jobs.get(ready.id)
        jobs.save(replace(child, input={**child.input, "phase": phase},
                          events=[*child.events, JobEvent(
                              len(child.events) + 1, "info", event, {})]))

    def publish(*_args, **_kwargs):
        calls.append("publish_absence")
        transition("provider_absent", "provider_absent")

    def recognize_absent(*_args, **_kwargs):
        calls.append("recognize_absence")
        assert jobs.get(ready.id).input["phase"] == "provider_absent"
        return jobs.get(ready.id)

    def retire(*_args, **_kwargs):
        calls.append("retire")
        transition("pending_group_retired", "keyed_pending_provider_group_retired")

    def recognize_group(*_args, **_kwargs):
        calls.append("recognize_group")
        assert jobs.get(ready.id).input["phase"] == "pending_group_retired"
        return tuple(SimpleNamespace(chain_id=chain_id) for chain_id in sorted(
            parent.input["scopeSnapshot"]["providerScopes"][0]["chainIds"]))

    opts = dict(
        environment="devtest", state_root=preview_opts["state_root"],
        job_repository=jobs, plan_repository=preview_opts["plan_repository"],
        lease_lookup=preview_opts["lease_lookup"], source_loader=source,
        apply_continuation=apply, absence_publisher=publish,
        absence_recognizer=recognize_absent, group_retirer=retire,
        group_recognizer=recognize_group,
    )
    return jobs, parent, ready, preview_id, apply_id, calls, opts


def test_saved_preview_to_group_retirement_and_restart_do_not_reapply(tmp_path, monkeypatch):
    jobs, parent, ready, preview_id, apply_id, calls, opts = _case(tmp_path, monkeypatch)
    first = service.advance_pending_keyed_cleanup_through_group_retirement(parent.id, **opts)
    assert first == service.PendingKeyedGroupCleanup(
        parent.id, ready.id, apply_id, parent.input["scopeSnapshot"]["snapshotId"],
        tuple(sorted(parent.input["scopeSnapshot"]["providerScopes"][0]["chainIds"])),
    )
    assert calls == ["source", "apply_or_absence", "publish_absence",
                     "recognize_absence", "retire", "recognize_group"]
    assert jobs.get(preview_id).status == "succeeded"
    assert jobs.get(apply_id).status == "succeeded"
    calls.clear()
    assert service.advance_pending_keyed_cleanup_through_group_retirement(
        parent.id, **opts) == first
    assert calls == ["recognize_group"]


def test_restart_after_successful_apply_uses_historical_child_not_live_source(
        tmp_path, monkeypatch):
    jobs, parent, _ready, _preview_id, apply_id, calls, opts = _case(tmp_path, monkeypatch)
    opts["apply_continuation"](parent.id)
    calls.clear()
    opts["source_loader"] = lambda *_a, **_kw: pytest.fail(
        "pre-destroy source cannot be rebuilt after apply")
    result = service.advance_pending_keyed_cleanup_through_group_retirement(parent.id, **opts)
    assert result.apply_job_id == apply_id
    assert calls == ["apply_or_absence", "publish_absence", "recognize_absence",
                     "retire", "recognize_group"]
    assert len([row for row in jobs.list_for_engagement(parent.target_id)
                if row.action == service.APPLY_ACTION]) == 1


def test_restart_after_absence_does_not_reenter_apply_or_publication(tmp_path, monkeypatch):
    jobs, parent, ready, _preview_id, apply_id, calls, opts = _case(tmp_path, monkeypatch)
    opts["apply_continuation"](parent.id)
    opts["absence_publisher"](parent.id)
    calls.clear()
    result = service.advance_pending_keyed_cleanup_through_group_retirement(parent.id, **opts)
    assert result.apply_job_id == apply_id
    assert jobs.get(ready.id).input["phase"] == "pending_group_retired"
    assert calls == ["recognize_absence", "retire", "recognize_group"]


@pytest.mark.parametrize("status", ["queued", "running", "failed"])
def test_existing_incomplete_apply_requires_reconciliation(tmp_path, monkeypatch, status):
    jobs, parent, _ready, _preview_id, apply_id, calls, opts = _case(tmp_path, monkeypatch)
    opts["apply_continuation"](parent.id)
    existing = jobs.get(apply_id)
    jobs.save(replace(existing, status=status, finished_at=None))
    calls.clear()
    with pytest.raises(service.PendingKeyedCleanupAttention):
        service.advance_pending_keyed_cleanup_through_group_retirement(parent.id, **opts)
    assert calls == []


def test_changed_reviewed_scope_stops_before_apply(tmp_path, monkeypatch):
    _jobs, parent, _ready, _preview_id, _apply_id, calls, opts = _case(tmp_path, monkeypatch)
    good = opts["source_loader"]
    def changed(*args, **kwargs):
        proof = good(*args, **kwargs)
        proof.provider_scope_sha256 = "changed"
        return proof
    opts["source_loader"] = changed
    with pytest.raises(service.PendingKeyedCleanupAttention):
        service.advance_pending_keyed_cleanup_through_group_retirement(parent.id, **opts)
    assert calls == ["source"]


def test_unexpected_coordinator_phase_is_inert(tmp_path, monkeypatch):
    jobs, parent, ready, _preview_id, _apply_id, calls, opts = _case(tmp_path, monkeypatch)
    jobs.save(replace(ready, input={**ready.input, "phase": "attention"}))
    with pytest.raises(service.PendingKeyedCleanupAttention):
        service.advance_pending_keyed_cleanup_through_group_retirement(parent.id, **opts)
    assert calls == []


def test_sqlite_reopen_after_successful_apply_never_replays_provider_destroy(
        tmp_path, monkeypatch):
    source_jobs, parent, ready, _preview_id, apply_id, calls, opts = _case(
        tmp_path, monkeypatch)
    opts["apply_continuation"](parent.id)
    calls.clear()
    scope = parent.input["scopeSnapshot"]
    core = source_jobs.get(scope["coreJobId"])
    database = tmp_path / "pending-cleanup.sqlite"
    engine = db.configure(f"sqlite:///{database}")
    with db.bind(engine):
        db.create_all()
        jobs = SqlAlchemyJobRepository()
        instant = datetime.now(timezone.utc).isoformat()
        for row in source_jobs.list():
            jobs.save(replace(
                row, created_at=row.created_at or instant,
                started_at=row.started_at or (instant if row.status != "queued" else None),
                finished_at=row.finished_at or (
                    instant if row.status in {"succeeded", "failed"} else None),
            ))
        plans = SqlAlchemyDeploymentPlanRepository()
        plans.save(DeploymentPlan(
            id=core.input["corePlanId"], engagement_id=parent.target_id,
            revision_id="revision-1", status="applied", stage="applied",
            apply_job_id=core.id,
        ))
        plans.acquire(parent.target_id, core.input["corePlanId"], service._FENCE)

    with db.bind(engine):
        jobs = SqlAlchemyJobRepository()
        plans = SqlAlchemyDeploymentPlanRepository()
        from app.services.provider_keyed_runtime_preflight import _db_lease_lookup

        def on_resume_apply(*_args, **_kwargs):
            calls.append("recognize_successful_apply_and_absence")
            assert jobs.get(apply_id).status == "succeeded"

        def publish(*_args, **_kwargs):
            calls.append("publish_absence")
            child = jobs.get(ready.id)
            jobs.save(replace(child, input={**child.input, "phase": "provider_absent"},
                              events=[*child.events, JobEvent(
                                  len(child.events) + 1, "info", "provider_absent", {})]))

        def retire(*_args, **_kwargs):
            calls.append("retire")
            child = jobs.get(ready.id)
            jobs.save(replace(child, input={**child.input, "phase": "pending_group_retired"},
                              events=[*child.events, JobEvent(
                                  len(child.events) + 1, "info",
                                  "keyed_pending_provider_group_retired", {})]))

        reopened = {
            **opts, "job_repository": jobs, "plan_repository": plans,
            "lease_lookup": _db_lease_lookup,
            "source_loader": lambda *_a, **_kw: pytest.fail(
                "destroyed live state cannot be a restart source"),
            "apply_continuation": on_resume_apply,
            "absence_publisher": publish,
            "absence_recognizer": lambda *_a, **_kw: jobs.get(ready.id),
            "group_retirer": retire,
            "group_recognizer": lambda *_a, **_kw: tuple(
                SimpleNamespace(chain_id=chain_id) for chain_id in sorted(
                    scope["providerScopes"][0]["chainIds"])),
        }
        result = service.advance_pending_keyed_cleanup_through_group_retirement(
            parent.id, **reopened)
        assert result.apply_job_id == apply_id
        assert calls == ["recognize_successful_apply_and_absence", "publish_absence", "retire"]
        assert len([row for row in jobs.list_for_engagement(parent.target_id)
                    if row.action == service.APPLY_ACTION]) == 1
        calls.clear()
        assert service.advance_pending_keyed_cleanup_through_group_retirement(
            parent.id, **reopened) == result
        assert calls == []
