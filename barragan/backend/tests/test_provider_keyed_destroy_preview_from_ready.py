# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network private handoff from Inspector readiness to one saved preview."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_comprehensive_teardown as service
from app.services.provider_keyed_initial_destroy_plan_job import ACTION as PREVIEW_ACTION
from app.storage.job_repository import StoredJobRun
from test_provider_keyed_comprehensive_teardown import _options
from test_provider_keyed_comprehensive_teardown import _published_options


def _case(tmp_path, *, fresh=False):
    jobs, parent, scope, plans, _clock, options = _options(tmp_path)
    child = service.run_provider_keyed_comprehensive_handoff(parent.id, **options)
    ready_event = JobEvent(5, "info", "retained_inspector_ready", {})
    if fresh:
        ready_event = JobEvent(5, "info", "inspector_create_started", {})
    ready = replace(child,
                    input={**child.input, "phase": "inspector_ready"},
                    events=[*child.events, ready_event])
    jobs.save(ready)
    calls = []
    preview_id = f"job-provider-keyed-initial-destroy-plan-{scope['coreJobId'].removeprefix('job-')}"

    def preview_runner(parent_id, **kwargs):
        calls.append(("run", parent_id))
        stamp = parent.created_at
        preview = StoredJobRun(
            id=preview_id, action=PREVIEW_ACTION, status="succeeded",
            target=f"engagement:{parent.target_id}", target_type="engagement",
            target_id=parent.target_id, requested_by=parent.requested_by,
            input={}, artifact_refs=[], created_at=stamp, started_at=stamp,
            finished_at=stamp, events=[JobEvent(1, "info", "test preview", {})],
        )
        jobs.save(preview)
        return preview

    def recognize(parent_id, **kwargs):
        calls.append(("recognize", parent_id))
        return SimpleNamespace(
            teardown_parent_id=parent.id,
            core_job_id=scope["coreJobId"], core_plan_id=scope["corePlanId"],
            scope_snapshot_id=parent.input["scopeSnapshot"]["snapshotId"],
            provider_scope_sha256=parent.input["scopeSnapshot"]["providerScopeSha256"],
            preview_job_id=preview_id,
        )

    def retained_ready(parent_id, **kwargs):
        calls.append(("retained", parent_id))
        return SimpleNamespace(coordinator_job_id=ready.id)

    def fresh_ready(child_id, engagement_id, **kwargs):
        calls.append(("fresh", child_id))
        return SimpleNamespace(coordinator_job_id=ready.id)

    arguments = dict(
        environment="devtest", state_root=Path(tmp_path),
        job_repository=jobs, plan_repository=plans,
        lease_lookup=options["lease_lookup"],
        retained_ready_recognizer=retained_ready,
        fresh_ready_recognizer=fresh_ready,
        preview_runner=preview_runner, preview_recognizer=recognize,
    )
    return jobs, parent, ready, preview_id, calls, arguments


def test_one_preview_and_idempotent_success_recognition_preserve_parent(tmp_path):
    jobs, parent, ready, preview_id, calls, arguments = _case(tmp_path)
    first = service.run_provider_keyed_destroy_preview_from_ready(parent.id, **arguments)
    second = service.run_provider_keyed_destroy_preview_from_ready(parent.id, **arguments)
    assert first == second == jobs.get(preview_id)
    assert calls == [
        ("retained", parent.id), ("run", parent.id), ("recognize", parent.id),
        ("retained", parent.id), ("recognize", parent.id),
    ]
    assert jobs.get(parent.id) == parent
    assert jobs.get(ready.id) == ready
    assert len([row for row in jobs.list_for_engagement(parent.target_id)
                if row.action == PREVIEW_ACTION]) == 1


@pytest.mark.parametrize("status", ["queued", "running", "failed"])
def test_existing_incomplete_preview_never_replayed(tmp_path, status):
    jobs, parent, _ready, preview_id, calls, arguments = _case(tmp_path)
    arguments["preview_runner"](parent.id)
    preview = jobs.get(preview_id)
    jobs.save(replace(preview, status=status, finished_at=None))
    calls.clear()
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.run_provider_keyed_destroy_preview_from_ready(parent.id, **arguments)
    assert calls == [("retained", parent.id)]
    assert jobs.get(parent.id) == parent


def test_existing_success_with_bad_recognition_fails_without_replay(tmp_path):
    jobs, parent, _ready, preview_id, calls, arguments = _case(tmp_path)
    arguments["preview_runner"](parent.id)
    calls.clear()
    def bad_recognizer(parent_id, **kwargs):
        calls.append(("bad", parent_id))
        raise ValueError("artifact drift")
    arguments["preview_recognizer"] = bad_recognizer
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.run_provider_keyed_destroy_preview_from_ready(parent.id, **arguments)
    assert calls == [("retained", parent.id), ("bad", parent.id)]
    assert jobs.get(preview_id).status == "succeeded"


def test_success_recognizer_must_bind_the_confirmed_parent_and_plan(tmp_path):
    jobs, parent, _ready, preview_id, calls, arguments = _case(tmp_path)
    original = arguments["preview_recognizer"]

    def forged(parent_id, **kwargs):
        proof = original(parent_id, **kwargs)
        proof.preview_job_id = "different-preview"
        return proof

    arguments["preview_recognizer"] = forged
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.run_provider_keyed_destroy_preview_from_ready(parent.id, **arguments)
    assert jobs.get(preview_id).status == "succeeded"
    assert [name for name, _ in calls].count("run") == 1


def test_duplicate_preview_action_blocks_runner(tmp_path):
    jobs, parent, _ready, _preview_id, calls, arguments = _case(tmp_path)
    original = arguments["preview_runner"](parent.id)
    jobs.save(replace(original, id="job-unrelated-preview"))
    calls.clear()
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.run_provider_keyed_destroy_preview_from_ready(parent.id, **arguments)
    assert calls == [("retained", parent.id)]


def test_fresh_inspector_branch_uses_exact_fresh_ready_recognizer(tmp_path):
    jobs, parent, _ready, _preview_id, calls, arguments = _case(tmp_path, fresh=True)
    service.run_provider_keyed_destroy_preview_from_ready(parent.id, **arguments)
    assert calls[0][0] == "fresh"


def test_ready_or_parent_drift_prevents_preview(tmp_path):
    jobs, parent, ready, _preview_id, calls, arguments = _case(tmp_path)
    jobs.save(replace(ready, input={**ready.input, "phase": "attention"}))
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.run_provider_keyed_destroy_preview_from_ready(parent.id, **arguments)
    assert calls == []
    jobs.save(ready)
    jobs.save(replace(parent, input={**parent.input, "phase": "attention"}))
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.run_provider_keyed_destroy_preview_from_ready(parent.id, **arguments)
    assert calls == []


def test_persisted_published_parent_preview_once_and_restart_read(client, monkeypatch, tmp_path):
    with client.application.storage_context():
        from app.storage.job_repository import SqlAlchemyJobRepository

        jobs, parent, source, audits, _clock, handoff_options = _published_options(
            client, monkeypatch, tmp_path)
        coordinator = service.run_provider_keyed_comprehensive_handoff(
            parent.id, **handoff_options)
        ready = jobs.save(replace(
            coordinator, input={**coordinator.input, "phase": "inspector_ready"},
            events=[*coordinator.events, JobEvent(5, "info", "retained_inspector_ready", {})],
        ))
        preview_id = f"job-provider-keyed-initial-destroy-plan-{source.core_job_id.removeprefix('job-')}"
        calls = []

        def preview_runner(parent_id, **_kwargs):
            calls.append("preview")
            stamp = parent.created_at
            return jobs.save(StoredJobRun(
                id=preview_id, action=PREVIEW_ACTION, status="succeeded",
                target=parent.target, target_type="engagement", target_id=parent.target_id,
                requested_by=parent.requested_by, input={}, artifact_refs=[],
                created_at=stamp, started_at=stamp, finished_at=stamp,
                events=[JobEvent(1, "info", "test preview", {})],
            ))

        def preflight(parent_id, **_kwargs):
            calls.append("preflight")
            return SimpleNamespace(
                teardown_parent_id=parent_id, core_job_id=source.core_job_id,
                core_plan_id=source.core_plan_id,
                scope_snapshot_id=parent.input["scopeSnapshot"]["snapshotId"],
                provider_scope_sha256=parent.input["scopeSnapshot"]["providerScopeSha256"],
                preview_job_id=preview_id,
            )

        arguments = dict(
            environment="devtest", state_root=tmp_path,
            job_repository=SqlAlchemyJobRepository(),
            plan_repository=handoff_options["plan_repository"],
            lease_lookup=handoff_options["lease_lookup"],
            retained_ready_recognizer=lambda *_a, **_kw: SimpleNamespace(
                coordinator_job_id=ready.id),
            preview_runner=preview_runner, preview_recognizer=preflight,
        )
        first = service.run_provider_keyed_destroy_preview_from_ready(parent.id, **arguments)
        assert first.id == preview_id and calls == ["preview", "preflight"]
        assert audits and jobs.get(parent.id) == parent and jobs.get(ready.id) == ready
        restarted = SqlAlchemyJobRepository()
        arguments["job_repository"] = restarted
        second = service.run_provider_keyed_destroy_preview_from_ready(parent.id, **arguments)
        assert second == first and calls == ["preview", "preflight", "preflight"]
        assert len([row for row in restarted.list_for_engagement(parent.target_id)
                    if row.action == PREVIEW_ACTION]) == 1
        restarted.save(replace(parent, input={**parent.input,
            "publishedSource": {**parent.input["publishedSource"], "state_sha256": "f" * 64}}))
        with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
            service.run_provider_keyed_destroy_preview_from_ready(parent.id, **arguments)
        assert calls == ["preview", "preflight", "preflight"]
