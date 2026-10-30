# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private pending cleanup stops after one saved destroy preview."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_pending_cleanup as service
from app.services import provider_keyed_comprehensive_teardown as coordinator
from app.services import provider_keyed_teardown_source as source_service
from app.services.provider_keyed_initial_destroy_apply_job import ACTION as APPLY_ACTION
from app.services.engagement_teardown import _known_public_targets_for_engagement
from app.storage.job_repository import StoredJobRun
from test_provider_keyed_comprehensive_teardown import _options
from test_provider_keyed_destroy_preview_from_ready import _case


def _source(parent, core, snapshot, stage):
    return SimpleNamespace(
        variant="pending_terminal" if stage == "pre_handoff" else "pending_handoff",
        teardown_parent_id=parent.id, engagement_id=parent.target_id,
        core_job_id=core.id, core_plan_id=core.input["corePlanId"],
        snapshot_id=snapshot["snapshotId"],
        provider_scope_sha256=snapshot["providerScopeSha256"],
    )


def _ready_case(tmp_path, monkeypatch):
    jobs, parent, ready, preview_id, calls, arguments = _case(tmp_path)
    plans = arguments["plan_repository"]
    scope = parent.input["scopeSnapshot"]
    core = jobs.get(scope["coreJobId"])
    # This older synthetic coordinator fixture omits homebase and seals no
    # public targets. Its stage tests isolate orchestration; the target
    # contract is exercised separately against real target derivation below.
    monkeypatch.setattr(service, "_require_diagnostic_targets", lambda *_args: None)
    source_calls = []

    def source_loader(parent_id, *, phase, **_kwargs):
        source_calls.append(phase)
        assert parent_id == parent.id
        return _source(jobs.get(parent.id), jobs.get(core.id),
                       jobs.get(parent.id).input["scopeSnapshot"], phase)

    def preview_runner(parent_id, **_kwargs):
        return coordinator.run_provider_keyed_destroy_preview_from_ready(
            parent_id, **arguments)

    options = dict(
        environment="devtest", state_root=Path(tmp_path),
        job_repository=jobs, plan_repository=plans,
        lease_lookup=arguments["lease_lookup"],
        source_loader=source_loader,
        ready_recognizer=arguments["retained_ready_recognizer"],
        preview_runner=preview_runner,
    )
    return jobs, parent, ready, preview_id, calls, source_calls, options


def test_real_snapshot_core_ssh_targets_are_admitted_but_sketch_and_routes_are_not(tmp_path, monkeypatch):
    real_guard = service._require_diagnostic_targets
    jobs, parent, _ready, _preview_id, _calls, _sources, _options = _ready_case(tmp_path, monkeypatch)
    core = jobs.get(parent.input["scopeSnapshot"]["coreJobId"])
    core = replace(core, events=[*core.events, JobEvent(
        len(core.events) + 1, "info", "core connections", {"connectionDetails": [
            {"role": "homebase", "publicIp": "1.1.1.1"},
            {"role": "proxy", "publicIp": "8.8.8.8"},
            {"role": "proxy", "publicIp": "9.9.9.9"},
        ]})])
    jobs.save(core)
    targets = _known_public_targets_for_engagement(jobs, parent.target_id)
    assert len(targets) == 3
    reviewed = {"core": {"proxyCount": 2}, "publicVerificationTargets": targets}
    real_guard(core, reviewed)
    for changed in (
        [{**targets[0], "targetGroup": "sketch-public-management"}, *targets[1:]],
        [*targets, {"id": "dns:example.invalid", "type": "dns-absent", "host": "example.invalid"}],
        [{**targets[0], "host": "203.0.113.99"}, *targets[1:]],
        [{**targets[0], "port": 443}, *targets[1:]],
    ):
        with pytest.raises(ValueError):
            real_guard(core, {**reviewed, "publicVerificationTargets": changed})
    missing_homebase = replace(core, events=[*core.events[:-1], replace(
        core.events[-1], data={"connectionDetails": [
            {"role": "proxy", "publicIp": "8.8.8.8"},
            {"role": "proxy", "publicIp": "9.9.9.9"},
        ]})])
    with pytest.raises(ValueError):
        real_guard(missing_homebase, {**reviewed, "publicVerificationTargets": targets[1:]})
    reserved = replace(core, events=[*core.events[:-1], replace(
        core.events[-1], data={"connectionDetails": [
            {"role": "homebase", "publicIp": "203.0.113.10"},
            {"role": "proxy", "publicIp": "8.8.8.8"},
            {"role": "proxy", "publicIp": "9.9.9.9"},
        ]})])
    with pytest.raises(ValueError):
        real_guard(reserved, reviewed)
    assert jobs.get(core.id) == core


def test_real_pending_source_loader_reopens_persisted_journal(tmp_path, monkeypatch):
    jobs, parent, scope, plans, _clock, handoff_options = _options(tmp_path)
    coordinator.run_provider_keyed_comprehensive_handoff(parent.id, **handoff_options)
    monkeypatch.setattr(source_service, "_db_lease_lookup", handoff_options["lease_lookup"])
    monkeypatch.setattr(source_service, "build_digitalocean_keyed_teardown_scope",
                        lambda *_a, **_kw: scope)
    source = source_service.load_keyed_teardown_source(
        parent.id, phase="pre_go", environment="devtest", state_root=Path(tmp_path),
        job_repository=jobs, plan_repository=plans)
    assert source.variant == "pending_handoff"
    assert source.initial_job_id.startswith("job-provider-keyed-initial-")
    assert source.snapshot_id == parent.input["scopeSnapshot"]["snapshotId"]


def test_persisted_ready_preview_and_restart_do_not_replay(tmp_path, monkeypatch):
    jobs, parent, ready, preview_id, calls, sources, options = _ready_case(tmp_path, monkeypatch)
    first = service.advance_pending_keyed_cleanup_to_preview(parent.id, **options)
    second = service.advance_pending_keyed_cleanup_to_preview(parent.id, **options)
    assert first == second == service.PendingKeyedDestroyPreview(
        parent.id, ready.id, preview_id, parent.input["scopeSnapshot"]["snapshotId"])
    assert [name for name, _ in calls].count("run") == 1
    assert [name for name, _ in calls].count("recognize") == 2
    assert sources == ["pre_go"] * 8
    assert jobs.get(parent.id) == parent
    assert not any(row.action == APPLY_ACTION for row in jobs.list())


@pytest.mark.parametrize("status", ["queued", "running", "failed"])
def test_incomplete_preview_never_replayed(tmp_path, monkeypatch, status):
    jobs, parent, _ready, preview_id, calls, _sources, options = _ready_case(tmp_path, monkeypatch)
    service.advance_pending_keyed_cleanup_to_preview(parent.id, **options)
    preview = jobs.get(preview_id)
    jobs.save(replace(preview, status=status, finished_at=None))
    calls.clear()
    with pytest.raises(service.PendingKeyedCleanupAttention):
        service.advance_pending_keyed_cleanup_to_preview(parent.id, **options)
    assert calls == []


def test_incomplete_destroy_child_stops_before_any_preview_or_replay(tmp_path, monkeypatch):
    jobs, parent, _ready, _preview_id, calls, _sources, options = _ready_case(tmp_path, monkeypatch)
    core_id = parent.input["scopeSnapshot"]["coreJobId"]
    stamp = parent.created_at
    jobs.save(StoredJobRun(
        id=f"job-provider-keyed-initial-destroy-apply-{core_id.removeprefix('job-')}",
        action=APPLY_ACTION, status="running", target=f"engagement:{parent.target_id}",
        target_type="engagement", target_id=parent.target_id,
        requested_by=parent.requested_by, input={}, artifact_refs=[],
        created_at=stamp, started_at=stamp, finished_at=None,
        events=[JobEvent(1, "info", "provider destroy apply queued", {})],
    ))
    with pytest.raises(service.PendingKeyedCleanupAttention):
        service.advance_pending_keyed_cleanup_to_preview(parent.id, **options)
    assert calls == []


def test_changed_inspector_or_source_stops_before_preview(tmp_path, monkeypatch):
    jobs, parent, ready, _preview_id, calls, _sources, options = _ready_case(tmp_path, monkeypatch)
    jobs.save(replace(ready, input={**ready.input, "phase": "attention"}))
    with pytest.raises(service.PendingKeyedCleanupAttention):
        service.advance_pending_keyed_cleanup_to_preview(parent.id, **options)
    assert calls == []
    jobs.save(ready)
    options["source_loader"] = lambda *_a, **_kw: _source(
        parent, jobs.get(parent.input["scopeSnapshot"]["coreJobId"]),
        {**parent.input["scopeSnapshot"], "snapshotId": "changed"}, "pre_go")
    with pytest.raises(service.PendingKeyedCleanupAttention):
        service.advance_pending_keyed_cleanup_to_preview(parent.id, **options)
    assert calls == []


def test_stale_lease_and_wrong_preview_identity_are_inert(tmp_path, monkeypatch):
    jobs, parent, _ready, preview_id, calls, _sources, options = _ready_case(tmp_path, monkeypatch)
    plans = options["plan_repository"]
    original_lease = plans.lease
    plans.lease = (original_lease[0], "provider_keyed_initial")
    with pytest.raises(service.PendingKeyedCleanupAttention):
        service.advance_pending_keyed_cleanup_to_preview(parent.id, **options)
    assert calls == []
    plans.lease = original_lease
    fake = StoredJobRun(
        id="job-different-destroy-plan", action="provider_keyed_initial_destroy_plan",
        status="succeeded", target=f"engagement:{parent.target_id}",
        target_type="engagement", target_id=parent.target_id,
        requested_by=parent.requested_by, input={}, artifact_refs=[],
        created_at=parent.created_at, started_at=parent.created_at,
        finished_at=parent.created_at, events=[],
    )
    jobs.save(fake)
    with pytest.raises(service.PendingKeyedCleanupAttention):
        service.advance_pending_keyed_cleanup_to_preview(parent.id, **options)
    assert calls == [] and jobs.get(preview_id) is None


def test_preview_child_inserted_during_inspector_recognition_blocks_runner(tmp_path, monkeypatch):
    jobs, parent, _ready, preview_id, calls, _sources, options = _ready_case(tmp_path, monkeypatch)
    recognize = options["ready_recognizer"]

    def racing_recognizer(parent_id, **kwargs):
        proof = recognize(parent_id, **kwargs)
        jobs.save(StoredJobRun(
            id=preview_id, action="provider_keyed_initial_destroy_plan",
            status="queued", target=f"engagement:{parent.target_id}",
            target_type="engagement", target_id=parent.target_id,
            requested_by=parent.requested_by, input={}, artifact_refs=[],
            created_at=parent.created_at, started_at=None, finished_at=None,
            events=[JobEvent(1, "info", "provider destroy plan queued", {})],
        ))
        return proof

    options["ready_recognizer"] = racing_recognizer
    with pytest.raises(service.PendingKeyedCleanupAttention):
        service.advance_pending_keyed_cleanup_to_preview(parent.id, **options)
    assert [name for name, _ in calls] == ["retained"]
    assert jobs.get(preview_id).status == "queued"


def test_wrong_environment_is_inert(tmp_path, monkeypatch):
    jobs, parent, _ready, _preview_id, calls, sources, options = _ready_case(tmp_path, monkeypatch)
    options["environment"] = "prod"
    with pytest.raises(service.PendingKeyedCleanupAttention):
        service.advance_pending_keyed_cleanup_to_preview(parent.id, **options)
    assert calls == sources == []
    assert jobs.get(parent.id) == parent


def test_new_pending_handoff_uses_existing_coordinator_once(tmp_path, monkeypatch):
    jobs, parent, _scope, plans, _clock, handoff_options = _options(tmp_path)
    core = jobs.get(parent.input["scopeSnapshot"]["coreJobId"])
    monkeypatch.setattr(service, "_require_diagnostic_targets", lambda *_args: None)
    calls = []

    def source_loader(parent_id, *, phase, **_kwargs):
        assert parent_id == parent.id
        calls.append(phase)
        return _source(jobs.get(parent.id), jobs.get(core.id),
                       jobs.get(parent.id).input["scopeSnapshot"], phase)

    def handoff_runner(parent_id, **_kwargs):
        return coordinator.run_provider_keyed_comprehensive_handoff(
            parent_id, **handoff_options)

    def ready_prover(parent_id, **_kwargs):
        calls.append("ready")
        child = jobs.get(coordinator._child_id(core.id))
        jobs.save(replace(child, input={**child.input, "phase": "inspector_ready"},
                          events=[*child.events, JobEvent(5, "info", "retained_inspector_ready", {})]))

    def ready_recognizer(parent_id, **_kwargs):
        calls.append("recognize")
        return SimpleNamespace(coordinator_job_id=coordinator._child_id(core.id))

    def preview_runner(parent_id, **_kwargs):
        calls.append("preview")
        child = jobs.get(coordinator._child_id(core.id))
        assert child.input["phase"] == "inspector_ready"
        preview_id = f"job-provider-keyed-initial-destroy-plan-{core.id.removeprefix('job-')}"
        row = StoredJobRun(
            id=preview_id, action="provider_keyed_initial_destroy_plan", status="succeeded",
            target=f"engagement:{parent.target_id}", target_type="engagement",
            target_id=parent.target_id, requested_by=parent.requested_by,
            input={}, artifact_refs=[], created_at=parent.created_at,
            started_at=parent.created_at, finished_at=parent.created_at, events=[])
        return jobs.save(row)

    result = service.advance_pending_keyed_cleanup_to_preview(
        parent.id, environment="devtest", state_root=Path(tmp_path),
        job_repository=jobs, plan_repository=plans,
        lease_lookup=handoff_options["lease_lookup"], source_loader=source_loader,
        handoff_runner=handoff_runner, ready_prover=ready_prover,
        ready_recognizer=ready_recognizer, preview_runner=preview_runner)
    assert result.preview_job_id == f"job-provider-keyed-initial-destroy-plan-{core.id.removeprefix('job-')}"
    assert calls == ["pre_handoff", "pre_go", "ready", "pre_go", "recognize", "preview", "pre_go"]
    assert plans.lease == (core.input["corePlanId"], "provider_keyed_teardown_fence")
