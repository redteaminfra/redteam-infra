# Copyright (c) 2026, Oracle and/or its affiliates.
"""Incident continuation keeps one claim, one gated apply and an exact suffix."""

from dataclasses import replace
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services import provider_keyed_initial_destroy_pre_go_continuation as service
from app.storage import models  # noqa: F401 - register SQLAlchemy tables
from app.storage.database import db
from app.storage.job_repository import (
    SqlAlchemyJobRepository, SqliteJobRepository, job_event_digest,
)
from test_provider_keyed_initial_destroy_takeover import _child
from test_provider_keyed_initial_destroy_pre_go_recovery import _fixture


class ClaimedJobs:
    def __init__(self, rows):
        self.rows = rows
        self.takeovers = 0

    def get(self, identifier):
        return self.rows.get(identifier)

    def take_over_initial_destroy_apply_pre_go(self, original, *, owner, token,
                                                claimed_at, expires_at, **_kwargs):
        assert self.get(original.id) == original
        self.takeovers += 1
        current = replace(original, input={**original.input, "claimOwner": owner,
            "claimToken": token, "claimClaimedAt": claimed_at,
            "claimExpiresAt": expires_at})
        self.rows[original.id] = current
        return current

    def renew_lease(self, identifier, *, owner, token, heartbeat_at, expires_at):
        current = self.get(identifier)
        assert current.input["claimOwner"] == owner and current.input["claimToken"] == token
        current = replace(current, input={**current.input, "claimHeartbeatAt": heartbeat_at,
                                          "claimExpiresAt": expires_at})
        self.rows[identifier] = current
        return current

    def append_destroy_apply_event_if_running_claimed(self, current, *, event, **_kwargs):
        assert self.get(current.id) == current
        current = replace(current, events=[*current.events, event])
        self.rows[current.id] = current
        return current

    def finish_destroy_apply_if_running_claimed(self, current, *, status,
                                                 finished_at, event, **_kwargs):
        assert self.get(current.id) == current
        inputs = {key: value for key, value in current.input.items()
                  if not key.startswith("claim")}
        current = replace(current, status=status, finished_at=finished_at,
                          input=inputs, events=[*current.events, event])
        self.rows[current.id] = current
        return current


def _case(tmp_path, monkeypatch, *, drift_at=None):
    attestation, options, _calls, fixture_jobs, original, state_path, plan_path, _phase = (
        _fixture(tmp_path, monkeypatch))
    jobs = ClaimedJobs(dict(fixture_jobs.rows))
    root = options["state_root"]
    workspace = SimpleNamespace(path=root, state_path=state_path,
                                terraform_data_dir=root / ".terraform-data")
    reviewed = SimpleNamespace(nodes={}, firewall=object())
    bound = SimpleNamespace(parent_id=service._PARENT, child_id=service._CHILD,
                            child_journal_sha256=job_event_digest(original.events),
                            plan_sha256=service._hash_file(plan_path),
                            state_sha256=service._hash_file(state_path))
    monkeypatch.setattr(service, "_ORIGINAL_JOURNAL", bound.child_journal_sha256)
    monkeypatch.setattr(service, "_require_exact_state", lambda *_a: {
        "lineage": original.events[5].data["stateLineage"],
        "serial": original.events[5].data["preDestroySerial"],
    })
    monkeypatch.setattr(service, "_require_empty_retained_state", lambda *_a: "f" * 64)
    monkeypatch.setattr(service, "require_exact_digitalocean_destroy_plan", lambda *_a, **_kw: None)
    monkeypatch.setattr(service, "_require_plan_topology_variables", lambda *_a: None)
    observed = []

    def binder(_attestation, **kw):
        claimed = kw.get("claimed_child")
        if claimed is not None:
            assert jobs.get(service._CHILD) == claimed
            assert claimed.events[:9] == original.events
            kw["claim_fence"](claimed)
            observed.append(len(claimed.events))
            if drift_at == len(claimed.events):
                raise ValueError("fresh source changed")
        return bound

    def gated(argv, *, scratch_path, intent_callback, started_callback,
              heartbeat_callback, result_callback, **_kwargs):
        assert _kwargs["gate_timeout_seconds"] == service._INCIDENT_GATE_TIMEOUT
        phase = "show" if argv[1] == "show" else "apply"
        invocation = "show-new" if phase == "show" else "apply-new"
        intent = CommandIntent(invocation, str(scratch_path), service._digest_argv(argv))
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity("boot", 900 if phase == "show" else 901,
                                                         900 if phase == "show" else 901, 123))
        started_callback(started)
        heartbeat_callback(started)
        output = "{}" if phase == "show" else ""
        result_callback(CommandAuditResult(started, 0, len(output), 0, False, False))
        return CommandResult(started, 0, output, "", False, False)

    args = (attestation, original, bound, jobs.get(service._PARENT),
            {"environment": "devtest", "state_root": root}, jobs, object(),
            workspace, reviewed, gated, {}, binder)
    return args, jobs, observed


def test_incident_continuation_appends_exact_success_suffix_once(tmp_path, monkeypatch):
    args, jobs, observed = _case(tmp_path, monkeypatch)
    done = service._run_claimed(*args)
    assert done.status == "succeeded"
    assert len(done.events) == 18
    assert [event.message for event in done.events[9:]] == list(service._SUFFIX)
    assert done.events[9].data["historicalRevision"] == service._REVISION
    assert done.events[9].data["originalJournalSha256"] == service._ORIGINAL_JOURNAL
    assert observed == [9, 12, 13, 15]
    assert jobs.takeovers == 1
    assert not any(key.startswith("claim") for key in done.input)
    assert json.loads((args[7].path / ".barragan-apply-phase.json").read_text())["phase"] == "destroy_applied"
    with pytest.raises(AssertionError):
        jobs.take_over_initial_destroy_apply_pre_go(args[1], owner="again", token="again",
            claimed_at="now", expires_at="later")


def test_public_entrypoint_binds_twice_before_claim_then_runs_same_child(tmp_path, monkeypatch):
    args, jobs, observed = _case(tmp_path, monkeypatch)
    root = args[7].path
    jobs.get(service._PARENT).input = {
        "scopeSnapshot": {"providerScopes": [{"workspace": str(root)}]},
    }
    lock = root / ".barragan-initial-full-plan.lock"
    lock.write_bytes(b"")
    lock.chmod(0o600)
    monkeypatch.setattr(service, "_default_state_root", lambda: root)
    monkeypatch.setattr(service, "_ordinal_lock", lambda _workspace: nullcontext())
    monkeypatch.setattr(service, "read_applied_digitalocean_provider_for_teardown",
                        lambda *_a, **_kw: (args[8], args[7], {}, object()))
    done = service.continue_reviewed_digitalocean_destroy_pre_go(
        args[0], environment="devtest", state_root=root,
        job_repository=jobs, plan_repository=object(), credential_repository=object(),
        command_environment={}, gated_command_runner=args[9], binder=args[11],
    )
    assert done.status == "succeeded"
    assert len(done.events) == 18
    assert jobs.takeovers == 1
    assert observed == [9, 12, 13, 15]


def test_slow_provider_proof_over_one_minute_keeps_incident_claim_valid(tmp_path, monkeypatch):
    args, jobs, _observed = _case(tmp_path, monkeypatch)
    clock = iter([0.0, 75.0, 80.0, 155.0])
    monkeypatch.setattr(service.time, "monotonic", lambda: next(clock))
    done = service._run_claimed(*args)
    assert done.status == "succeeded"
    assert jobs.takeovers == 1
    now = datetime.now(timezone.utc)
    assert (datetime.fromisoformat(service._later(now.isoformat())) - now
            >= timedelta(minutes=15))


def test_go_proof_over_fifteen_minutes_never_releases_apply(tmp_path, monkeypatch):
    args, jobs, _observed = _case(tmp_path, monkeypatch)
    clock = iter([0.0, 901.0])
    monkeypatch.setattr(service.time, "monotonic", lambda: next(clock))
    with pytest.raises(ValueError, match="bounded window"):
        service._run_claimed(*args)
    assert len(jobs.get(service._CHILD).events) == 12
    assert jobs.takeovers == 1


@pytest.mark.parametrize("drift_at,expected_count", [(12, 12), (15, 15)])
def test_go_rebinder_vetoes_before_command_release(tmp_path, monkeypatch, drift_at, expected_count):
    args, jobs, observed = _case(tmp_path, monkeypatch, drift_at=drift_at)
    with pytest.raises(ValueError, match="fresh source changed"):
        service._run_claimed(*args)
    child = jobs.get(service._CHILD)
    assert child.status == "running"
    assert len(child.events) == expected_count
    assert observed[-1] == expected_count
    assert jobs.takeovers == 1
    assert json.loads((args[7].path / ".barragan-apply-phase.json").read_text())["phase"] == "destroy_started"


def test_original_prefix_and_recovery_intent_drift_are_rejected(tmp_path, monkeypatch):
    args, jobs, _observed = _case(tmp_path, monkeypatch)
    original = args[1]
    claimed = replace(original, input={**original.input,
        "claimOwner": "provider-keyed-destroy-recovery-test"})
    service._check_prefix(original, claimed, plan_sha=args[2].plan_sha256)
    wrong = replace(claimed, events=[*claimed.events,
        JobEvent(10, "info", service._SUFFIX[0], {
            "historicalRevision": service._REVISION,
            "originalJournalSha256": "0" * 64,
            "planSha256": args[2].plan_sha256,
        })])
    with pytest.raises(ValueError, match="recovery intent"):
        service._check_prefix(original, wrong, plan_sha=args[2].plan_sha256)


def test_second_incident_prefix_cannot_use_original_incident_digest(tmp_path, monkeypatch):
    args, _jobs, _observed = _case(tmp_path, monkeypatch)
    original = replace(args[1], id="job-provider-keyed-initial-destroy-apply-b4f1bceb4a7d")
    new_incident = replace(service._reviewed_incident(
        "job-engagement-teardown-b4f1bceb4a7d"),
        original_journal_sha256=job_event_digest(original.events))
    service._check_prefix(original, original, plan_sha=args[2].plan_sha256,
                          incident=new_incident)
    with pytest.raises(ValueError, match="journal changed"):
        service._check_prefix(original, original, plan_sha=args[2].plan_sha256,
                              incident=service._ORIGINAL_INCIDENT)
    with pytest.raises(ValueError, match="journal changed"):
        service._check_prefix(original, original, plan_sha=args[2].plan_sha256,
                              incident=replace(new_incident,
                                  original_journal_sha256="0" * 64))


@pytest.mark.parametrize("backend", ["sqlite", "sqlalchemy"])
def test_real_repository_claim_preserves_nine_events_and_finishes_eighteen(tmp_path, backend):
    scope = None
    if backend == "sqlite":
        jobs = SqliteJobRepository(tmp_path / "incident.sqlite")
    else:
        scope = db.bind(db.configure(f"sqlite:///{tmp_path / 'incident-sa.sqlite'}"))
        scope.__enter__()
        db.create_all()
        jobs = SqlAlchemyJobRepository()
    try:
        original = jobs.save(_child())
        owner, token = "provider-keyed-destroy-recovery-one", "f" * 32
        now = service._now()
        current = jobs.take_over_initial_destroy_apply_pre_go(
            original, expected_event_digest=job_event_digest(original.events),
            owner=owner, token=token, claimed_at=now, expires_at=service._later(now),
        )
        assert current is not None and current.events == original.events
        for message in service._SUFFIX[:-1]:
            instant = service._now()
            current = jobs.append_destroy_apply_event_if_running_claimed(
                current, owner=owner, token=token,
                expected_event_digest=job_event_digest(current.events),
                heartbeat_at=instant, expires_at=service._later(instant),
                event=JobEvent(len(current.events) + 1, "info", message, {}),
            )
            assert current is not None
        finished = jobs.finish_destroy_apply_if_running_claimed(
            current, owner=owner, token=token,
            expected_event_digest=job_event_digest(current.events),
            status="succeeded", finished_at=service._now(),
            event=JobEvent(18, "info", service._SUFFIX[-1], {
                "stateSha256": "a" * 64, "providerAbsenceProofPending": True,
            }),
        )
        assert finished is not None and len(finished.events) == 18
        assert finished.events[:9] == original.events
        assert finished.status == "succeeded"
        assert not any(key.startswith("claim") for key in finished.input)
        assert jobs.take_over_initial_destroy_apply_pre_go(
            original, expected_event_digest=job_event_digest(original.events),
            owner=owner + "-again", token="e" * 32,
            claimed_at=service._now(), expires_at=service._later(service._now()),
        ) is None
    finally:
        if scope is not None:
            scope.__exit__(None, None, None)
