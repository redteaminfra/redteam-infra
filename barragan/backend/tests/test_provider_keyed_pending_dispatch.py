# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dispatcher restart tests; stage authority is covered by each service's tests.

These file-backed cases inject stage callbacks, so they prove orchestration and
one-shot skip behavior, not a live provider or canonical source composition.
"""

from dataclasses import replace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_pending_dispatch as dispatch
from app.storage.job_repository import SqliteJobRepository, StoredJobRun


def _row(identifier, action, status, engagement, data):
    return StoredJobRun(
        identifier, action, status, f"engagement:{engagement}", "engagement",
        engagement, "operator", data, [], "2026-10-09T00:00:00+00:00",
        "2026-10-09T00:00:01+00:00" if status != "queued" else None,
        "2026-10-09T00:00:02+00:00" if status == "succeeded" else None,
        [JobEvent(1, "info", "fixture boundary", {})],
    )


def _case(tmp_path, monkeypatch):
    database = tmp_path / "pending-dispatch.sqlite"
    jobs = SqliteJobRepository(database)
    engagement = "eng-disposable"
    parent = _row("job-parent", "engagement_comprehensive_teardown", "queued",
                  engagement, {"phase": "queued"})
    core = _row("job-core", "pilot_standard_rti_guarded_execute", "succeeded",
                engagement, {"engagementId": engagement})
    coordinator = _row(dispatch._child_id(core.id), "provider_keyed_comprehensive_teardown",
                       "running", engagement, {"phase": "awaiting_inspector_preflight"})
    for row in (parent, core, coordinator):
        jobs.save(row)
    snapshot = {"domainAssignments": []}

    def boundary(parent_id, saved_jobs, _plans, _lookup):
        assert parent_id == parent.id
        return (saved_jobs.get(parent.id), saved_jobs.get(core.id), snapshot,
                "provider_keyed_teardown_fence")

    monkeypatch.setattr(dispatch, "_boundary", boundary)
    return database, jobs, parent, core, coordinator


def _stages(jobs, parent, core, coordinator, calls, *, uncertain_preview=False,
            stop_after_apply=False, stop_after_selector=False):
    def phase(value):
        current = jobs.get(coordinator.id)
        jobs.save(replace(current, status="running",
                          started_at=current.started_at or "2026-10-09T00:00:01+00:00",
                          input={**current.input, "phase": value}))

    prefixes = {
        "provider_keyed_initial_destroy_apply": "provider-keyed-initial-destroy-apply",
        "provider_keyed_core_destroy_preview": "provider-keyed-core-destroy-preview",
        "provider_keyed_core_destroy_apply": "provider-keyed-core-destroy-apply",
        "provider_keyed_selector_retirement": "provider-keyed-selector-retirement",
    }

    def saved(action, status="succeeded"):
        identifier = f"job-{prefixes[action]}-{core.id.removeprefix('job-')}"
        jobs.save(_row(identifier, action, status, parent.target_id, {}))

    def stage(name, *, new_phase=None, child=None):
        def run(parent_id, **kwargs):
            assert parent_id == parent.id
            assert kwargs["environment"] == "devtest"
            calls.append(name)
            if new_phase:
                phase(new_phase)
            if child:
                saved(child, "queued" if uncertain_preview and name == "core_preview" else "succeeded")
            if uncertain_preview and name == "core_preview":
                raise RuntimeError("preview command outcome uncertain")
            if stop_after_apply and name == "core_absence":
                raise RuntimeError("process stopped after saved core apply")
            if stop_after_selector and name == "selector":
                saved("provider_keyed_selector_retirement")
                raise RuntimeError("process stopped after saved selector retirement")
            if name == "terminal":
                jobs.save(replace(jobs.get(parent.id), status="succeeded",
                                  finished_at="2026-10-09T00:00:03+00:00"))
            return jobs.get(parent.id)
        return run

    return {
        "preview_provider": stage("provider_preview", new_phase="inspector_ready"),
        "retire_group": stage("group", new_phase="pending_group_retired",
                              child="provider_keyed_initial_destroy_apply"),
        "preview_core": stage("core_preview", child="provider_keyed_core_destroy_preview"),
        "apply_core": stage("core_apply", child="provider_keyed_core_destroy_apply"),
        "prove_core_absence": stage("core_absence"),
        "prove_negative": stage("negative"),
        "retire_selector": stage("selector"),
        "recognize_selector": stage("selector_read"),
        "retire_inspector": stage("terminal"),
        "recognize_terminal": stage("terminal_read"),
    }


def test_private_dispatch_reopens_terminal_without_replaying_stage(tmp_path, monkeypatch):
    database, jobs, parent, core, coordinator = _case(tmp_path, monkeypatch)
    calls = []
    kwargs = _stages(jobs, parent, core, coordinator, calls)
    common = dict(environment="devtest", state_root=tmp_path,
                  positive_control_ipv4="4.2.2.2", plan_repository=object(),
                  lease_lookup=lambda _id: None)
    result = dispatch.advance_pending_keyed_terminal(
        parent.id, job_repository=jobs, **common, **kwargs)
    assert result.status == "succeeded"
    assert calls == ["provider_preview", "group", "core_preview", "core_apply",
                     "core_absence", "negative", "selector", "terminal"]
    reopened = SqliteJobRepository(database)
    restart_calls = []
    restart_kwargs = _stages(reopened, parent, core, coordinator, restart_calls)
    assert dispatch.advance_pending_keyed_terminal(
        parent.id, job_repository=reopened, **common, **restart_kwargs).status == "succeeded"
    assert restart_calls == ["terminal_read"]


def test_uncertain_core_preview_is_not_replayed_after_restart(tmp_path, monkeypatch):
    database, jobs, parent, core, coordinator = _case(tmp_path, monkeypatch)
    calls = []
    kwargs = _stages(jobs, parent, core, coordinator, calls, uncertain_preview=True)
    common = dict(environment="devtest", state_root=tmp_path,
                  positive_control_ipv4="4.2.2.2", plan_repository=object(),
                  lease_lookup=lambda _id: None)
    with pytest.raises(dispatch.PendingKeyedDispatchAttention):
        dispatch.advance_pending_keyed_terminal(
            parent.id, job_repository=jobs, **common, **kwargs)
    assert calls == ["provider_preview", "group", "core_preview"]
    reopened = SqliteJobRepository(database)
    restart_calls = []
    restart_kwargs = _stages(reopened, parent, core, coordinator, restart_calls)
    with pytest.raises(dispatch.PendingKeyedDispatchAttention):
        dispatch.advance_pending_keyed_terminal(
            parent.id, job_repository=reopened, **common, **restart_kwargs)
    assert restart_calls == ["group"]
    assert reopened.get(f"job-provider-keyed-core-destroy-preview-{core.id.removeprefix('job-')}").status == "queued"


def test_invalid_control_stops_before_any_stage(tmp_path, monkeypatch):
    _, jobs, parent, core, coordinator = _case(tmp_path, monkeypatch)
    calls = []
    kwargs = _stages(jobs, parent, core, coordinator, calls)
    with pytest.raises(dispatch.PendingKeyedDispatchAttention):
        dispatch.advance_pending_keyed_terminal(
            parent.id, environment="devtest", state_root=tmp_path,
            positive_control_ipv4="192.0.2.1", job_repository=jobs,
            plan_repository=object(), lease_lookup=lambda _id: None, **kwargs)
    assert calls == []


def test_queued_coordinator_after_restart_reaches_canonical_preview_stage(tmp_path, monkeypatch):
    database, jobs, parent, core, coordinator = _case(tmp_path, monkeypatch)
    jobs.save(replace(coordinator, status="queued", started_at=None,
                      input={"phase": "queued"}))
    reopened = SqliteJobRepository(database)
    calls = []
    kwargs = _stages(reopened, parent, core, coordinator, calls)
    result = dispatch.advance_pending_keyed_terminal(
        parent.id, environment="devtest", state_root=tmp_path,
        positive_control_ipv4="4.2.2.2", job_repository=reopened,
        plan_repository=object(), lease_lookup=lambda _id: None, **kwargs)
    assert result.status == "succeeded"
    assert calls[0] == "provider_preview"
    assert reopened.get(coordinator.id).status == "running"


@pytest.mark.parametrize("checkpoint", ["core_apply", "selector"])
def test_restart_uses_saved_success_without_replaying_go(tmp_path, monkeypatch, checkpoint):
    database, jobs, parent, core, coordinator = _case(tmp_path, monkeypatch)
    calls = []
    kwargs = _stages(jobs, parent, core, coordinator, calls,
                     stop_after_apply=checkpoint == "core_apply",
                     stop_after_selector=checkpoint == "selector")
    common = dict(environment="devtest", state_root=tmp_path,
                  positive_control_ipv4="4.2.2.2", plan_repository=object(),
                  lease_lookup=lambda _id: None)
    with pytest.raises(dispatch.PendingKeyedDispatchAttention):
        dispatch.advance_pending_keyed_terminal(
            parent.id, job_repository=jobs, **common, **kwargs)
    reopened = SqliteJobRepository(database)
    restart_calls = []
    restart_kwargs = _stages(reopened, parent, core, coordinator, restart_calls)
    assert dispatch.advance_pending_keyed_terminal(
        parent.id, job_repository=reopened, **common, **restart_kwargs).status == "succeeded"
    assert "core_preview" not in restart_calls
    assert "core_apply" not in restart_calls
    if checkpoint == "selector":
        assert "selector" not in restart_calls
        assert "selector_read" in restart_calls
