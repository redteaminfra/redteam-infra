# Copyright (c) 2026, Oracle and/or its affiliates.
"""An interrupted read-only mixed OCI SHOW may be taken over exactly once."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_mixed_zero_apply_core_apply as apply_service
from app.services import provider_keyed_mixed_zero_apply_core_absence as absence_service
from app.services import provider_keyed_mixed_interrupted_public as public_service
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, ProcessIdentity, StartedCommand,
)
from app.storage import models as _models  # noqa: F401 - register SQLAlchemy tables
from app.storage.database import db
from app.storage import job_repository as repository_module
from app.storage.job_repository import (
    SqlAlchemyJobRepository, SqliteJobRepository, StoredJobRun, job_event_digest,
)
from test_provider_keyed_mixed_interrupted_oci_tail import _interrupted_go_case, case
from test_provider_keyed_mixed_zero_apply_core_absence import _absent, _empty_state


def _four_event_child():
    old = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
    started = (datetime.now(timezone.utc) - timedelta(minutes=3)).isoformat()
    base = {
        "teardownParentId": "job-parent", "coreJobId": "job-core",
        "corePlanId": "plan-core", "sourceSha256": "a" * 64,
        "previewJobId": "job-preview", "previewJournalSha256": "b" * 64,
        "planSha256": "c" * 64, "mutation": True,
        "claimOwner": "provider-keyed-mixed-core-destroy-old", "claimToken": "old-token-1234567890",
        "claimClaimedAt": started, "claimHeartbeatAt": started, "claimExpiresAt": old,
    }
    events = [
        JobEvent(1, "info", "mixed core destroy apply queued", {}),
        JobEvent(2, "info", "mixed core destroy apply started", {}),
        JobEvent(3, "info", "core destroy command intent fenced", {
            "phase": "show", "invocationId": "old-show", "argvSha256": "d" * 64}),
        JobEvent(4, "info", "core destroy command started before GO", {
            "phase": "show", "invocationId": "old-show", "bootId": "boot",
            "pid": 123, "pgid": 123, "startTicks": 9}),
    ]
    return StoredJobRun(
        "job-provider-keyed-mixed-core-destroy-apply-core",
        apply_service.ACTION, "running", "engagement:eng-1", "engagement", "eng-1",
        "operator", base, [], started, started, None, events)


def _five_event_child():
    child = _four_event_child()
    return replace(child, events=[*child.events, JobEvent(
        5, "info", "core destroy command result fenced", {
            "phase": "show", "invocationId": "old-show", "returnCode": 0,
            "stdoutBytes": 74454, "stderrBytes": 0,
            "stdoutTruncated": False, "stderrTruncated": False,
        })])


def _takeover(repo, child):
    at = datetime.now(timezone.utc).isoformat()
    return repo.take_over_mixed_core_show(
        child, expected_event_digest=job_event_digest(child.events),
        owner="provider-keyed-mixed-core-destroy-new", token="new-token-1234567890",
        claimed_at=at, expires_at=(datetime.fromisoformat(at) + timedelta(minutes=5)).isoformat())


def test_persisted_sqlite_claim_and_marker_are_atomic_and_one_time(tmp_path, monkeypatch):
    repo = SqliteJobRepository(tmp_path / "mixed-show.sqlite")
    child = _four_event_child()
    repo.save(child)
    old = repo.get(child.id)
    real_match = repository_module._claimed_apply_journal_matches
    monkeypatch.setattr(repository_module, "_claimed_apply_journal_matches", lambda *_: False)
    assert _takeover(repo, old) is None
    assert repo.get(child.id) == old
    monkeypatch.setattr(repository_module, "_claimed_apply_journal_matches", real_match)
    taken = _takeover(repo, old)
    assert taken is not None
    assert len(taken.events) == 5
    assert taken.events[-1] == JobEvent(5, "info", "mixed core SHOW recovery claimed", {
        "originalJournalSha256": job_event_digest(old.events),
        "originalInvocationId": "old-show",
    })
    assert _takeover(repo, old) is None
    assert _takeover(repo, taken) is None
    assert repo.get(child.id) == taken


def test_sqlalchemy_claim_and_marker_are_atomic_and_one_time(monkeypatch):
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        repo = SqlAlchemyJobRepository()
        child = _four_event_child()
        repo.save(child)
        old = repo.get(child.id)
        real_match = repository_module._claimed_apply_journal_matches
        monkeypatch.setattr(repository_module, "_claimed_apply_journal_matches", lambda *_: False)
        assert _takeover(repo, old) is None
        assert repo.get(child.id) == old
        monkeypatch.setattr(repository_module, "_claimed_apply_journal_matches", real_match)
        taken = _takeover(repo, old)
        assert taken is not None
        assert taken.events[-1] == JobEvent(5, "info", "mixed core SHOW recovery claimed", {
            "originalJournalSha256": job_event_digest(old.events),
            "originalInvocationId": "old-show",
        })
        assert _takeover(repo, old) is None
        assert _takeover(repo, taken) is None
        assert repo.get(child.id) == taken


@pytest.mark.parametrize("repository", ["sqlite", "sqlalchemy"])
def test_completed_show_result_takeover_cas_and_bad_journal(tmp_path, repository):
    state = db.configure(f"sqlite:///{tmp_path / 'five-event.sqlite'}")
    context = db.bind(state)
    with context:
        if repository == "sqlalchemy":
            db.create_all()
            repo = SqlAlchemyJobRepository()
        else:
            repo = SqliteJobRepository(tmp_path / "five-event-jobs.sqlite")
        child = _five_event_child()
        repo.save(child)
        old = repo.get(child.id)
        assert _takeover(repo, replace(old, events=[
            *old.events[:4], replace(old.events[4], data={
                **old.events[4].data, "returnCode": 1})])) is None
        assert repo.get(child.id) == old
        live = replace(old, input={**old.input,
                                   "claimExpiresAt": (datetime.now(timezone.utc)
                                                       + timedelta(minutes=2)).isoformat()})
        repo.save(live)
        assert _takeover(repo, repo.get(child.id)) is None
        repo.save(old)
        taken = _takeover(repo, repo.get(child.id))
        assert taken is not None and len(taken.events) == 6
        assert taken.events[-1] == JobEvent(6, "info", "mixed core SHOW recovery claimed", {
            "originalJournalSha256": job_event_digest(old.events),
            "originalInvocationId": "old-show",
        })
        assert _takeover(repo, old) is None
        assert _takeover(repo, taken) is None
        intent_after_show = replace(old, events=[*old.events, JobEvent(
            6, "info", "core destroy command intent fenced", {
                "phase": "apply", "invocationId": "unsafe", "argvSha256": "e" * 64})])
        repo.save(intent_after_show)
        assert _takeover(repo, repo.get(child.id)) is None


def test_interrupted_worker_repeats_show_once_then_applies_same_saved_plan(case, monkeypatch):
    source, actions, options, _ = _interrupted_go_case(case, monkeypatch)
    normal = options["gated_command_runner"]
    calls = []

    def stop_show(args, *, scratch_path, intent_callback, started_callback, **kwargs):
        calls.append(args[1])
        intent = CommandIntent("abandoned-show", str(scratch_path), hashlib.sha256(
            json.dumps(args, separators=(",", ":")).encode()).hexdigest())
        intent_callback(intent)
        started_callback(StartedCommand(intent, ProcessIdentity("old-boot", 543, 543, 17)))
        raise RuntimeError("worker stopped after SHOW start")

    options["gated_command_runner"] = stop_show
    with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
        apply_service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **{**options, "interrupted": True})
    assert calls == ["show"] and actions == []
    child = case.jobs.get(apply_service._child_id(source.core_job_id))
    assert len(child.events) == 4
    case.jobs.save(replace(child, input={**child.input,
                                        "claimExpiresAt": "2020-01-01T00:00:00+00:00"}))
    options.update(gated_command_runner=normal,
                   process_quiescent=lambda _: True, terraform_quiescent=lambda: True)
    applied = apply_service.apply_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **{**options, "interrupted": True})
    assert applied.status == "succeeded"
    assert len(applied.events) == 14
    assert applied.events[4].message == "mixed core SHOW recovery claimed"
    assert actions == ["show", "apply"]
    _empty_state(case)
    monkeypatch.setattr(absence_service, "_default_state_root", lambda: case.state_root)
    monkeypatch.setattr(absence_service, "DEFAULT_TERRAFORM_STATE_ROOT",
                        case.core_state.parents[2])
    monkeypatch.setattr(absence_service, "_principal_digest", lambda _: "a" * 64)
    absent = absence_service.prove_mixed_zero_apply_oci_core_absence(
        source.engagement_id, source.core_job_id,
        environment="devtest", state_root=case.state_root,
        core_state_root=case.core_state.parents[2], job_repository=case.jobs,
        plan_repository=case.args["plan_repository"],
        lease_lookup=options["lease_lookup"], identity_reader=lambda: {},
        absence_prover=_absent, max_scans=2, poll_seconds=0, interrupted=True)
    assert absent.status == "succeeded"
    with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
        apply_service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **{**options, "interrupted": True})
    assert actions == ["show", "apply"]
    forged = list(applied.events)
    forged[2] = replace(forged[2], data={**forged[2].data, "argvSha256": "0" * 64})
    forged[4] = replace(forged[4], data={
        **forged[4].data, "originalJournalSha256": job_event_digest(forged[:4])})
    case.jobs.save(replace(applied, events=forged))
    with pytest.raises(absence_service.MixedZeroApplyCoreAbsenceAttention):
        absence_service.prove_mixed_zero_apply_oci_core_absence(
            source.engagement_id, source.core_job_id,
            environment="devtest", state_root=case.state_root,
            core_state_root=case.core_state.parents[2], job_repository=case.jobs,
            plan_repository=case.args["plan_repository"],
            lease_lookup=options["lease_lookup"], identity_reader=lambda: {},
            absence_prover=lambda *_a, **_kw: pytest.fail("OCI scan after forged SHOW"),
            max_scans=2, poll_seconds=0, interrupted=True)


def test_completed_show_result_recovers_same_child_then_proves_absence(case, monkeypatch, tmp_path):
    source, actions, options, _ = _interrupted_go_case(case, monkeypatch)
    normal = options["gated_command_runner"]

    def stop_after_show_result(args, **kwargs):
        if args[1] != "show":
            return normal(args, **kwargs)
        callbacks = dict(kwargs)
        original_intent = callbacks["intent_callback"]
        original_started = callbacks["started_callback"]
        original_heartbeat = callbacks["heartbeat_callback"]
        original_result = callbacks["result_callback"]
        saved = {}

        def intent(value):
            saved["intent"] = CommandIntent("abandoned-show", value.scratch_path,
                                             value.argv_sha256)
            original_intent(saved["intent"])

        def started(value):
            saved["started"] = StartedCommand(saved["intent"], value.identity)
            original_started(saved["started"])

        def heartbeat(_value):
            original_heartbeat(saved["started"])

        def result(value):
            original_result(CommandAuditResult(
                saved["started"], value.returncode, value.stdout_bytes,
                value.stderr_bytes, value.stdout_truncated, value.stderr_truncated))

        callbacks.update(intent_callback=intent, started_callback=started,
                         heartbeat_callback=heartbeat, result_callback=result)
        normal(args, **callbacks)
        raise RuntimeError("worker stopped after durable SHOW result")

    options["gated_command_runner"] = stop_after_show_result
    with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
        apply_service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **{**options, "interrupted": True})
    child = case.jobs.get(apply_service._child_id(source.core_job_id))
    assert len(child.events) == 5 and actions == ["show"]
    assert child.events[-1].data["returnCode"] == 0
    case.jobs.save(replace(child, input={**child.input,
                                        "claimExpiresAt": "2020-01-01T00:00:00+00:00"}))
    options.update(gated_command_runner=normal,
                   process_quiescent=lambda _: True, terraform_quiescent=lambda: True)
    parent = case.jobs.get(apply_service._interrupted_parent_id(source.core_job_id))
    preview = case.jobs.get(apply_service._preview_child_id(source.core_job_id))
    assert apply_service.interrupted_show_restartable(
        case.jobs.get(child.id), parent, preview, source.core_job_id,
        process_quiescent=lambda _: True, terraform_quiescent=lambda: True)
    monkeypatch.setattr(public_service, "_default_state_root", lambda: case.state_root)
    monkeypatch.setattr(public_service, "DEFAULT_TERRAFORM_STATE_ROOT",
                        case.core_state.parents[2])
    persisted = SqliteJobRepository(tmp_path / "recovered-jobs.sqlite")
    for row in case.jobs.list_for_engagement(source.engagement_id):
        persisted.save(row)
    expired = persisted.get(child.id)
    persisted.save(replace(expired, input={**expired.input,
                                           "claimExpiresAt": (datetime.now(timezone.utc)
                                                               + timedelta(minutes=2)).isoformat()}))
    assert public_service.recover_mixed_interrupted_dispatches(
        environment="devtest", schedule=lambda _: pytest.fail("live claim scheduled"),
        state_root=case.state_root, core_state_root=case.core_state.parents[2],
        job_repository=SqliteJobRepository(tmp_path / "recovered-jobs.sqlite"),
        lease_lookup=options["lease_lookup"],
        process_quiescent=lambda _: True, terraform_quiescent=lambda: True) == []
    persisted.save(expired)
    scheduled = []
    assert public_service.recover_mixed_interrupted_dispatches(
        environment="devtest", schedule=scheduled.append,
        state_root=case.state_root, core_state_root=case.core_state.parents[2],
        job_repository=persisted, lease_lookup=options["lease_lookup"],
        process_quiescent=lambda _: True, terraform_quiescent=lambda: True) == [parent.id]
    assert scheduled == [parent.id]
    assert public_service.recover_mixed_interrupted_dispatches(
        environment="devtest", schedule=lambda _: pytest.fail("live claim scheduled"),
        state_root=case.state_root, core_state_root=case.core_state.parents[2],
        job_repository=SqliteJobRepository(tmp_path / "recovered-jobs.sqlite"),
        lease_lookup=options["lease_lookup"],
        process_quiescent=lambda _: False, terraform_quiescent=lambda: True) == []
    applied = apply_service.apply_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **{**options, "interrupted": True})
    assert applied.id == child.id and applied.status == "succeeded"
    assert len(applied.events) == 15 and actions == ["show", "show", "apply"]
    assert applied.events[5].message == "mixed core SHOW recovery claimed"
    _empty_state(case)
    monkeypatch.setattr(absence_service, "_default_state_root", lambda: case.state_root)
    monkeypatch.setattr(absence_service, "DEFAULT_TERRAFORM_STATE_ROOT",
                        case.core_state.parents[2])
    monkeypatch.setattr(absence_service, "_principal_digest", lambda _: "a" * 64)
    absent = absence_service.prove_mixed_zero_apply_oci_core_absence(
        source.engagement_id, source.core_job_id,
        environment="devtest", state_root=case.state_root,
        core_state_root=case.core_state.parents[2], job_repository=case.jobs,
        plan_repository=case.args["plan_repository"],
        lease_lookup=options["lease_lookup"], identity_reader=lambda: {},
        absence_prover=_absent, max_scans=2, poll_seconds=0, interrupted=True)
    assert absent.status == "succeeded"
    forged = list(applied.events)
    forged[4] = replace(forged[4], data={**forged[4].data, "stdoutTruncated": True})
    forged[5] = replace(forged[5], data={
        **forged[5].data, "originalJournalSha256": job_event_digest(forged[:5])})
    case.jobs.save(replace(applied, events=forged))
    with pytest.raises(absence_service.MixedZeroApplyCoreAbsenceAttention):
        absence_service.prove_mixed_zero_apply_oci_core_absence(
            source.engagement_id, source.core_job_id,
            environment="devtest", state_root=case.state_root,
            core_state_root=case.core_state.parents[2], job_repository=case.jobs,
            plan_repository=case.args["plan_repository"],
            lease_lookup=options["lease_lookup"], identity_reader=lambda: {},
            absence_prover=lambda *_a, **_kw: pytest.fail("OCI scan after forged SHOW"),
            max_scans=2, poll_seconds=0, interrupted=True)


def test_live_or_ambiguous_show_blocks_before_second_terraform(case, monkeypatch):
    source, actions, options, _ = _interrupted_go_case(case, monkeypatch)
    normal = options["gated_command_runner"]

    def stop_show(args, *, scratch_path, intent_callback, started_callback, **kwargs):
        intent = CommandIntent("abandoned-show", str(scratch_path), hashlib.sha256(
            json.dumps(args, separators=(",", ":")).encode()).hexdigest())
        intent_callback(intent)
        started_callback(StartedCommand(intent, ProcessIdentity("old-boot", 543, 543, 17)))
        raise RuntimeError("stopped")

    options["gated_command_runner"] = stop_show
    with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
        apply_service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **{**options, "interrupted": True})
    child = case.jobs.get(apply_service._child_id(source.core_job_id))
    case.jobs.save(replace(child, input={**child.input,
                                        "claimExpiresAt": "2020-01-01T00:00:00+00:00"}))
    monkeypatch.setattr(public_service, "_default_state_root", lambda: case.state_root)
    monkeypatch.setattr(public_service, "DEFAULT_TERRAFORM_STATE_ROOT",
                        case.core_state.parents[2])
    scheduled = []
    assert public_service.recover_mixed_interrupted_dispatches(
        environment="devtest", schedule=scheduled.append,
        state_root=case.state_root, core_state_root=case.core_state.parents[2],
        job_repository=case.jobs, lease_lookup=options["lease_lookup"],
        process_quiescent=lambda _: True, terraform_quiescent=lambda: True) == [
            apply_service._interrupted_parent_id(source.core_job_id)]
    assert scheduled == [apply_service._interrupted_parent_id(source.core_job_id)]
    options.update(gated_command_runner=normal, process_quiescent=lambda _: False,
                   terraform_quiescent=lambda: True)
    with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
        apply_service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **{**options, "interrupted": True})
    assert actions == []
    options["process_quiescent"] = lambda _: True
    options["terraform_quiescent"] = lambda: True
    options["gated_command_runner"] = lambda *_a, **_kw: (_ for _ in ()).throw(
        RuntimeError("second worker stopped before SHOW intent"))
    with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
        apply_service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **{**options, "interrupted": True})
    child = case.jobs.get(apply_service._child_id(source.core_job_id))
    assert len(child.events) == 5 and child.events[-1].message == "mixed core SHOW recovery claimed"
    assert not apply_service.interrupted_show_restartable(
        child, case.jobs.get(apply_service._interrupted_parent_id(source.core_job_id)),
        case.jobs.get(apply_service._preview_child_id(source.core_job_id)),
        source.core_job_id, process_quiescent=lambda _: True,
        terraform_quiescent=lambda: True)
    scheduled.clear()
    assert public_service.recover_mixed_interrupted_dispatches(
        environment="devtest", schedule=scheduled.append,
        state_root=case.state_root, core_state_root=case.core_state.parents[2],
        job_repository=case.jobs, lease_lookup=options["lease_lookup"],
        process_quiescent=lambda _: True, terraform_quiescent=lambda: True) == []
    assert scheduled == []
    options["process_quiescent"] = lambda _: True
    options["terraform_quiescent"] = lambda: False
    with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
        apply_service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **{**options, "interrupted": True})
    assert actions == []
