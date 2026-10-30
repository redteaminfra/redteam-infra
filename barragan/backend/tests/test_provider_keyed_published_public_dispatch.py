# Copyright (c) 2026, Oracle and/or its affiliates.
"""Public-route composition over the authentic persisted published generation."""

from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from app.core.config import TestConfig
from app.core.runtime import runtime_context, runtime_value
from app.domain import JobEvent
from app.storage.database import db
from app.services import provider_keyed_published_dispatch as dispatch
from app.services.provider_keyed_initial_continuation import _job_ids
from app.services.provider_keyed_published_teardown_source import PublishedProviderKeyedSource
from app.services.provider_keyed_append_source import PublishedProviderKeyedAppendSource
from app.storage.job_repository import SqlAlchemyJobRepository, SqliteJobRepository
from test_provider_keyed_pending_dispatch import _row
from test_provider_keyed_real_core_canonical_generation import (
    test_real_keyed_core_plan_is_persisted_and_reviewed_after_restart as authentic_generation,
)


@pytest.mark.skipif(sys.platform != "linux", reason="reviewed Terraform release is Linux-only")
def test_public_post_reserves_authentic_published_generation_once(tmp_path, monkeypatch):
    """The normal real-core fixture supplies publication and terminal writers.

    Replace only its manual reservation with the actual public POST. The
    scheduled callback is captured; the fixture continues through the real
    private persisted teardown stages with injected external responses.
    """
    from app.asgi import create_app

    original = SqlAlchemyJobRepository.reserve_published_keyed_teardown_parent
    posts = []
    workers = []
    applications = []
    in_route = False

    def through_public_post(self, proposal, *, reviewed_source, state_root=None):
        nonlocal in_route
        if in_route:
            return original(self, proposal, reviewed_source=reviewed_source,
                            state_root=state_root)
        assert state_root == Path(str(state_root))
        assert reviewed_source.core_job_id == proposal.input["coreJobId"]

        class DevTest(TestConfig):
            ENVIRONMENT = "devtest"
            SQLALCHEMY_DATABASE_URI = str(db.engine.url)
            DATA_DIR = Path(runtime_value("DATA_DIR"))
            PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4 = "4.2.2.2"
            PROVIDER_KEYED_INITIAL_DISPATCH_ENABLED = False

        app = create_app(DevTest)
        applications.append(app)
        monkeypatch.setattr("app.core.runtime.start_runtime_task",
                            lambda worker, *, name, **_kw: workers.append((name, worker)))
        body = {"confirmation": proposal.input["scopeSnapshot"]["confirmationPhrase"],
                "snapshotId": proposal.input["scopeSnapshot"]["snapshotId"]}
        db.session.rollback()
        in_route = True
        try:
            stale = app.test_client().post(
                f"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/"
                f"{proposal.input['coreJobId']}/teardown",
                json={**body, "snapshotId": "stale"})
            assert stale.status_code == 409
            assert SqlAlchemyJobRepository().get(proposal.id) is None
            initial_id = _job_ids(proposal.input["coreJobId"])[0]
            initial = SqlAlchemyJobRepository().get(initial_id)
            assert initial is not None
            SqlAlchemyJobRepository().save(replace(
                initial, events=[*initial.events, JobEvent(
                    len(initial.events) + 1, "info", "unreviewed source drift", {})]))
            drifted = app.test_client().post(
                f"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/"
                f"{proposal.input['coreJobId']}/teardown", json=body)
            assert drifted.status_code == 409
            assert SqlAlchemyJobRepository().get(proposal.id) is None
            SqlAlchemyJobRepository().save(initial)
            response = app.test_client().post(
                f"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/"
                f"{proposal.input['coreJobId']}/teardown", json=body)
            repeated = app.test_client().post(
                f"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/"
                f"{proposal.input['coreJobId']}/teardown", json=body)
        finally:
            in_route = False
        posts.append(response)
        assert response.status_code == 200, response.json()
        assert response.json()["job"]["id"] == proposal.id
        assert repeated.status_code == 200
        assert repeated.json()["job"]["id"] == proposal.id
        assert [name for name, _ in workers] == [
            "barragan-keyed-published-teardown",
            "barragan-keyed-published-teardown-recovery",
        ]
        parent = SqlAlchemyJobRepository().get(proposal.id)
        assert parent.input["publishedSource"]
        return parent

    monkeypatch.setattr(SqlAlchemyJobRepository,
                        "reserve_published_keyed_teardown_parent", through_public_post)
    authentic_generation(
        tmp_path, monkeypatch, "worker_success_initial_published_fixture")
    assert len(posts) == 1
    assert len(workers) == 2
    with runtime_context(applications[0].state.runtime):
        terminal_before = SqlAlchemyJobRepository().get(posts[0].json()["job"]["id"])
        assert terminal_before.status == "succeeded"
        recognized = workers[0][1]()
        assert recognized.status == "succeeded"
        assert recognized.action == "provider_keyed_inspector_linode_cleanup"
        assert SqlAlchemyJobRepository().get(terminal_before.id) == terminal_before


def test_restart_schedules_exact_reserved_published_parent_before_handoff(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "restart.sqlite")
    source = PublishedProviderKeyedSource(
        engagement_id="eng-disposable", core_job_id="job-core", core_plan_id="plan-core",
        initial_job_id="job-initial", initial_journal_sha256="a" * 64,
        core_journal_sha256="b" * 64, scope_sha256="c" * 64,
        state_sha256="d" * 64, manifest_sha256="e" * 64,
        published_host_evidence_sha256="f" * 64,
        chain_ids=("chain-1", "chain-2"), chain_projection_sha256="1" * 64,
    )
    parent = _row("job-parent", "engagement_comprehensive_teardown", "queued",
                  source.engagement_id, {"phase": "queued", "publishedSource": {
                      **asdict(source), "chain_ids": list(source.chain_ids),
                  }})
    core = _row(source.core_job_id, "pilot_standard_rti_guarded_execute", "succeeded",
                source.engagement_id, {"engagementId": source.engagement_id})
    jobs.save(parent)
    jobs.save(core)
    snapshot = {"snapshotId": "sealed"}
    monkeypatch.setattr(dispatch, "_boundary",
                        lambda *_a: (parent, core, snapshot, "provider_keyed_teardown_fence"))
    monkeypatch.setattr(dispatch, "_require_reviewed_shape", lambda *_a: None)
    monkeypatch.setattr(dispatch, "require_prequeue_published_generation",
                        lambda *_a, **_kw: source)
    scheduled = []
    assert dispatch.recover_published_keyed_dispatches(
        environment="devtest", state_root=tmp_path,
        positive_control_ipv4="4.2.2.2", schedule=lambda *args: scheduled.append(args),
        job_repository=jobs, plan_repository=object(), lease_lookup=lambda _id: None,
    ) == [parent.id]
    assert scheduled == [(parent.id, 0.0)]


def _appended_dispatch_case(tmp_path):
    jobs = SqliteJobRepository(tmp_path / "appended-dispatch.sqlite")
    initial = PublishedProviderKeyedSource(
        engagement_id="eng-disposable", core_job_id="job-core", core_plan_id="plan-core",
        initial_job_id="job-initial", initial_journal_sha256="a" * 64,
        core_journal_sha256="b" * 64, scope_sha256="c" * 64,
        state_sha256="d" * 64, manifest_sha256="e" * 64,
        published_host_evidence_sha256="f" * 64,
        chain_ids=("chain-1", "chain-2"), chain_projection_sha256="1" * 64,
    )
    appended = PublishedProviderKeyedAppendSource(
        initial, "job-append", "2" * 64, "3" * 64,
        'digitalocean_droplet.edge["sfo3-03"]', "99001",
    )
    initial_seal = asdict(initial)
    append_seal = asdict(appended)
    initial_seal["chain_ids"] = list(initial.chain_ids)
    append_seal["initial_source"]["chain_ids"] = list(initial.chain_ids)
    parent = _row("job-parent", "engagement_comprehensive_teardown", "queued",
                  initial.engagement_id, {"phase": "queued", "publishedSource": initial_seal,
                                          "publishedAppendSource": append_seal})
    core = _row("job-core", "pilot_standard_rti_guarded_execute", "succeeded",
                initial.engagement_id, {"engagementId": initial.engagement_id})
    jobs.save(parent)
    jobs.save(core)
    snapshot = {"snapshotId": "sealed", "providerScopes": [{
        "stateSha256": appended.state_sha256,
        "resources": [{"address": f"owned-{index}"} for index in range(9)],
    }]}
    return jobs, parent, core, snapshot, appended


def test_reconciled_unapplied_append_prequeue_keeps_initial_four_node_source(
    tmp_path, monkeypatch,
):
    """The failed review receipt selects the original source, never append audit."""
    from app.services.engagement_teardown import _fingerprint
    import app.services.provider_keyed_append_source as append_source

    jobs = SqliteJobRepository(tmp_path / "reconciled-append-prequeue.sqlite")
    engagement_id = "eng-disposable"
    core = _row("job-core", "pilot_standard_rti_guarded_execute", "succeeded",
                engagement_id, {"engagementId": engagement_id})
    scope = {"corePlanId": "plan-core", "stateSha256": "d" * 64,
             "chainIds": ["chain-1", "chain-2"],
             "resources": [{"address": f"owned-{index}"} for index in range(8)]}
    source = PublishedProviderKeyedSource(
        engagement_id, core.id, "plan-core", "job-initial", "a" * 64,
        "b" * 64, _fingerprint(scope), "d" * 64, "e" * 64,
        "f" * 64, ("chain-1", "chain-2"), "1" * 64,
    )
    append = replace(_row("job-append", "provider_keyed_edge_append", "failed",
        engagement_id, {"engagementId": engagement_id, "coreJobId": "job-core",
                        "corePlanId": "plan-core",
                        "phase": "unapplied_reconciled", "planJobId": "job-append-plan"}),
        finished_at="2026-10-14T01:00:00+00:00",
        events=[JobEvent(1, "info", "append plan reconciled without mutation", {
            "stateSha256": scope["stateSha256"]})])
    child = _row("job-append-plan", "provider_keyed_edge_append_plan", "failed",
                 engagement_id, {"parentJobId": append.id, "coreJobId": "job-core",
                                 "mutation": False})
    inspector = {"ownedProviderRecordIds": ["inspector-instance", "inspector-firewall"],
                 "recordOwners": {"inspector-instance": "job-inspect-instance",
                                  "inspector-firewall": "job-inspect-firewall"}}
    for row in (core, append, child, *[
        _row(owner, "inspector_inspection", "succeeded", engagement_id, {})
        for owner in inspector["recordOwners"].values()
    ]):
        jobs.save(row)
    records = {
        record_id: SimpleNamespace(provider="linode", engagement_id=engagement_id,
            status="active", resource_type=kind, adoption_job_id=owner,
            metadata={"inspectionJobId": owner})
        for (record_id, owner), kind in zip(inspector["recordOwners"].items(),
                                            ("inspector_instance", "inspector_firewall"))
    }
    snapshot = {"engagementId": engagement_id, "coreJobId": core.id,
                "providerScopes": [scope]}
    snapshot["snapshotId"] = _fingerprint(snapshot)
    monkeypatch.setattr(dispatch, "_require_reviewed_shape", lambda *_a: inspector)
    calls = []
    monkeypatch.setattr(dispatch, "audit_published_provider_keyed_source",
        lambda *_a, **_kw: (calls.append("initial") or source))
    monkeypatch.setattr(append_source, "audit_published_provider_keyed_append_source",
        lambda *_a, **_kw: (_ for _ in ()).throw(
            ValueError("never-applied review entered five-node audit")))
    kwargs = dict(environment="devtest", state_root=tmp_path,
                  job_repository=jobs,
                  provider_resource_repository=SimpleNamespace(get=records.get))
    assert dispatch.require_prequeue_published_generation(core, snapshot, **kwargs) == source
    assert calls == ["initial"]
    for drift in ("receipt", "state", "apply_child"):
        changed = dict(snapshot)
        if drift == "receipt":
            jobs.save(replace(append, events=[JobEvent(1, "info",
                "append plan reconciled without mutation", {"stateSha256": "0" * 64})]))
        elif drift == "state":
            changed["providerScopes"] = [{**scope, "stateSha256": "0" * 64}]
            changed["snapshotId"] = _fingerprint({
                key: value for key, value in changed.items() if key != "snapshotId"})
        else:
            jobs.save(_row("job-append-apply", "provider_keyed_edge_append_apply",
                           "failed", engagement_id, {}))
        with pytest.raises(dispatch.PublishedKeyedDispatchAttention):
            dispatch.require_prequeue_published_generation(core, changed, **kwargs)
        if drift == "receipt":
            jobs.save(append)


def test_appended_restart_schedules_only_exact_sealed_parent(tmp_path, monkeypatch):
    jobs, parent, core, snapshot, appended = _appended_dispatch_case(tmp_path)
    monkeypatch.setattr(dispatch, "_boundary", lambda *_a: (
        jobs.get(parent.id), core, snapshot, "provider_keyed_teardown_fence"))
    monkeypatch.setattr(dispatch, "_require_reviewed_shape", lambda *_a: None)
    monkeypatch.setattr(dispatch, "require_prequeue_published_generation",
                        lambda *_a, **_kw: appended)
    scheduled = []
    options = dict(environment="devtest", state_root=tmp_path,
                   positive_control_ipv4="4.2.2.2",
                   schedule=lambda *args: scheduled.append(args),
                   job_repository=jobs, plan_repository=object(), lease_lookup=lambda _id: None)
    assert dispatch.recover_published_keyed_dispatches(**options) == [parent.id]
    assert scheduled == [(parent.id, 0.0)]
    scheduled.clear()
    jobs.save(replace(parent, input={**parent.input, "publishedAppendSource": {
        **parent.input["publishedAppendSource"], "state_sha256": "4" * 64}}))
    assert dispatch.recover_published_keyed_dispatches(**options) == []
    assert scheduled == []
    assert dispatch.recover_published_keyed_dispatches(
        **{**options, "environment": "prod"}) == []


def test_appended_failed_precommand_preview_waits_for_worker_quiescence(
    tmp_path, monkeypatch,
):
    from datetime import datetime, timedelta, timezone

    jobs, parent, core, snapshot, _appended = _appended_dispatch_case(tmp_path)
    coordinator = _row(dispatch._child_id(core.id), "provider_keyed_comprehensive_teardown",
                       "running", parent.target_id, {"phase": "inspector_ready",
                                                     "teardownParentId": parent.id,
                                                     "scopeSnapshotId": snapshot["snapshotId"]})
    jobs.save(coordinator)
    instant = datetime(2026, 10, 14, 20, 0, tzinfo=timezone.utc)
    preview = replace(_row("job-provider-keyed-initial-destroy-plan-core",
                           "provider_keyed_initial_destroy_plan", "failed",
                           parent.target_id, {}),
                      finished_at=instant.isoformat(), events=[
                          JobEvent(1, "info", "provider destroy preview queued", {}),
                          JobEvent(2, "info", "provider destroy preview started", {}),
                          JobEvent(3, "info", "provider destroy preview staging intended", {}),
                          JobEvent(4, "error", "provider destroy preview stopped; reconciliation required",
                                   {"failureStage": "other"}),
                      ])
    jobs.save(preview)
    monkeypatch.setattr(dispatch, "_boundary", lambda *_a: (
        jobs.get(parent.id), core, snapshot, "provider_keyed_teardown_fence"))
    monkeypatch.setattr(dispatch, "_require_reviewed_shape", lambda *_a: None)
    scheduled = []
    dispatch.recover_published_keyed_dispatches(
        environment="devtest", state_root=tmp_path,
        positive_control_ipv4="4.2.2.2", schedule=lambda *args: scheduled.append(args),
        job_repository=jobs, plan_repository=object(), lease_lookup=lambda _id: None,
        now=lambda: instant + timedelta(seconds=20),
    )
    assert scheduled == [(parent.id, 40.0)]


@pytest.mark.parametrize("show_only", [False, True])
def test_appended_failed_precommand_apply_reschedules_same_parent_after_quiescence(
    tmp_path, monkeypatch, show_only,
):
    from datetime import datetime, timedelta, timezone

    jobs, parent, core, snapshot, _appended = _appended_dispatch_case(tmp_path)
    jobs.save(_row(dispatch._child_id(core.id), "provider_keyed_comprehensive_teardown",
                   "running", parent.target_id,
                   {"phase": "inspector_ready", "teardownParentId": parent.id,
                    "scopeSnapshotId": snapshot["snapshotId"]}))
    instant = datetime(2026, 10, 14, 20, 0, tzinfo=timezone.utc)
    events = [
        JobEvent(1, "info", "provider destroy apply queued", {}),
        JobEvent(2, "info", "provider destroy apply started", {}),
        JobEvent(3, "error", "provider destroy apply stopped", {}),
    ]
    if show_only:
        events.extend([
            JobEvent(4, "info", "provider destroy apply pre-command recovery reserved", {}),
            JobEvent(5, "info", "provider destroy command intent fenced", {}),
            JobEvent(6, "info", "provider destroy command started before GO", {}),
            JobEvent(7, "info", "provider destroy command result fenced", {}),
            JobEvent(8, "error", "provider destroy apply stopped", {}),
        ])
    failed = replace(_row("job-provider-keyed-initial-destroy-apply-core",
                          "provider_keyed_initial_destroy_apply", "failed",
                          parent.target_id, {}),
                     finished_at=instant.isoformat(), events=events)
    jobs.save(failed)
    monkeypatch.setattr(dispatch, "_boundary", lambda *_a: (
        jobs.get(parent.id), core, snapshot, "provider_keyed_teardown_fence"))
    monkeypatch.setattr(dispatch, "_require_reviewed_shape", lambda *_a: None)
    scheduled = []
    options = dict(environment="devtest", state_root=tmp_path,
                   positive_control_ipv4="4.2.2.2",
                   schedule=lambda *args: scheduled.append(args),
                   job_repository=jobs, plan_repository=object(), lease_lookup=lambda _id: None,
                   now=lambda: instant + timedelta(seconds=20))
    assert dispatch.recover_published_keyed_dispatches(**options) == [parent.id]
    assert scheduled == [(parent.id, 40.0)]
    jobs.save(replace(failed, events=[*failed.events,
        JobEvent(len(events) + 1, "info", "unexpected", {})]))
    scheduled.clear()
    assert dispatch.recover_published_keyed_dispatches(**options) == []
    assert scheduled == []


@pytest.mark.parametrize("drift", ["none", "split", "uncertain_apply"])
def test_appended_dispatch_uses_one_saved_phase_and_never_replays_uncertain_go(
    tmp_path, monkeypatch, drift,
):
    jobs, parent, core, snapshot, _appended = _appended_dispatch_case(tmp_path)
    phase = "inspector_ready" if drift == "uncertain_apply" else "awaiting_inspector_preflight"
    coordinator = _row(dispatch._child_id(core.id), "provider_keyed_comprehensive_teardown",
                       "running", parent.target_id, {"phase": phase})
    jobs.save(coordinator)
    if drift == "split":
        snapshot["providerScopes"][0]["resources"].pop()
    if drift == "uncertain_apply":
        jobs.save(_row("job-provider-keyed-initial-destroy-apply-core",
                       "provider_keyed_initial_destroy_apply", "running",
                       parent.target_id, {}))
    monkeypatch.setattr(dispatch, "_boundary", lambda *_a: (
        jobs.get(parent.id), core, snapshot, "provider_keyed_teardown_fence"))
    monkeypatch.setattr(dispatch, "_require_reviewed_shape", lambda *_a: None)
    calls = []

    def next_phase(*_args, **_kwargs):
        calls.append("inspector_ready")
        raise RuntimeError("fixture stops after dispatch")

    with pytest.raises(dispatch.PublishedKeyedDispatchAttention):
        dispatch.advance_published_keyed_terminal(
            parent.id, environment="devtest", state_root=tmp_path,
            positive_control_ipv4="4.2.2.2", job_repository=jobs,
            plan_repository=object(), lease_lookup=lambda _id: None,
            prove_retained=next_phase,
            preview_provider=lambda *_a, **_kw: pytest.fail("destroy preview replayed"),
            apply_provider=lambda *_a, **_kw: pytest.fail("destroy Apply replayed"),
        )
    assert calls == (["inspector_ready"] if drift == "none" else [])


def test_uncertain_published_core_apply_stops_without_replay(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "uncertain.sqlite")
    engagement = "eng-disposable"
    parent = _row("job-parent", "engagement_comprehensive_teardown", "queued",
                  engagement, {"phase": "queued", "publishedSource": {"sealed": True}})
    core = _row("job-core", "pilot_standard_rti_guarded_execute", "succeeded",
                engagement, {"engagementId": engagement})
    coordinator = _row(dispatch._child_id(core.id), "provider_keyed_comprehensive_teardown",
                       "running", engagement, {"phase": "group_retired"})
    prefix = core.id.removeprefix("job-")
    preview = _row(f"job-provider-keyed-core-destroy-preview-{prefix}",
                   "provider_keyed_core_destroy_preview", "succeeded", engagement, {})
    uncertain = _row(f"job-provider-keyed-core-destroy-apply-{prefix}",
                     "provider_keyed_core_destroy_apply", "running", engagement, {})
    for row in (parent, core, coordinator, preview, uncertain):
        jobs.save(row)
    monkeypatch.setattr(dispatch, "_boundary", lambda *_a: (
        jobs.get(parent.id), core, {"snapshotId": "sealed"},
        "provider_keyed_teardown_fence"))
    monkeypatch.setattr(dispatch, "_require_reviewed_shape", lambda *_a: None)
    called = []
    with pytest.raises(dispatch.PublishedKeyedDispatchAttention):
        dispatch.advance_published_keyed_terminal(
            parent.id, environment="devtest", state_root=tmp_path,
            positive_control_ipv4="4.2.2.2", job_repository=jobs,
            plan_repository=object(), lease_lookup=lambda _id: None,
            apply_core=lambda *_a, **_kw: called.append("replayed"))
    assert called == []
    assert SqliteJobRepository(tmp_path / "uncertain.sqlite").get(uncertain.id) == uncertain


@pytest.mark.parametrize("phase", ["handoff_pending", "inspector_ready"])
def test_published_worker_reenters_saved_phase_without_replaying_destroy(
    tmp_path, monkeypatch, phase,
):
    jobs = SqliteJobRepository(tmp_path / "reentry.sqlite")
    engagement = "eng-disposable"
    parent = _row("job-parent", "engagement_comprehensive_teardown", "queued",
                  engagement, {"phase": "queued", "publishedSource": {"sealed": True}})
    core = _row("job-core", "pilot_standard_rti_guarded_execute", "succeeded",
                engagement, {"engagementId": engagement})
    coordinator = _row(dispatch._child_id(core.id), "provider_keyed_comprehensive_teardown",
                       "running", engagement, {"phase": phase})
    for row in (parent, core, coordinator):
        jobs.save(row)
    if phase == "inspector_ready":
        applied = _row(f"job-provider-keyed-initial-destroy-apply-{core.id.removeprefix('job-')}",
                       "provider_keyed_initial_destroy_apply", "succeeded", engagement, {})
        jobs.save(applied)
    monkeypatch.setattr(dispatch, "_boundary", lambda *_a: (
        jobs.get(parent.id), core, {"snapshotId": "sealed"},
        "provider_keyed_teardown_fence"))
    monkeypatch.setattr(dispatch, "_require_reviewed_shape", lambda *_a: None)
    calls = []

    def resume_handoff(_id, **_kw):
        calls.append("handoff")
        jobs.save(replace(jobs.get(coordinator.id), input={
            **jobs.get(coordinator.id).input, "phase": "awaiting_inspector_preflight",
        }))

    def stop_after_resume(_id, **_kw):
        calls.append("next")
        raise RuntimeError("bounded fixture stop")

    with pytest.raises(dispatch.PublishedKeyedDispatchAttention):
        dispatch.advance_published_keyed_terminal(
            parent.id, environment="devtest", state_root=tmp_path,
            positive_control_ipv4="4.2.2.2", job_repository=jobs,
            plan_repository=object(), lease_lookup=lambda _id: None,
            handoff=resume_handoff, prove_retained=stop_after_resume,
            preview_provider=lambda *_a, **_kw: pytest.fail("pre-destroy preview replayed"),
            apply_provider=lambda *_a, **_kw: pytest.fail("destroy apply replayed"),
            publish_absence=stop_after_resume,
        )
    assert calls == (["handoff", "next"] if phase == "handoff_pending" else ["next"])
