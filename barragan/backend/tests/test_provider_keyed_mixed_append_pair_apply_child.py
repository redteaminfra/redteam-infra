# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline first-provider one-shot Apply and persisted claim/lease fences."""

from contextlib import nullcontext
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import text

from app.domain import JobEvent
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_mixed_append_pair_apply_child import (
    FirstApplySource, MixedAppendFirstApplyAttention, _child_id,
    run_first_mixed_append_provider_apply,
)
import app.services.provider_keyed_mixed_append_pair_apply_child as service
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.models import CoreMutationLeaseModel


@pytest.fixture
def ready(tmp_path, monkeypatch):
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        db.session.add(CoreMutationLeaseModel(
            engagement_id="eng-opaque", owner_id="plan-core",
            operation="provider_keyed_mixed_append"))
        db.session.commit()
        jobs = SqlAlchemyJobRepository()
        at = datetime.now(timezone.utc).isoformat()
        parent = StoredJobRun(
            "job-append", "provider_keyed_mixed_append", "running",
            "engagement:eng-opaque", "engagement", "eng-opaque", "operator",
            {"phase": "apply_sealed", "coreJobId": "job-core",
             "corePlanId": "plan-core", "reviewSha256": "a" * 64,
             "providerOrder": ["linode", "digitalocean"]},
            [], at, at, None, [JobEvent(1, "info", "pair approved", {})],
        )
        jobs.save(parent)
        parent = jobs.get(parent.id)
        root = tmp_path / "linode"
        root.mkdir()
        plan = root / '.barragan-mixed-append-linode-saved.tfplan'
        plan.write_bytes(b"exact-append-binary")
        (root / "terraform.tfstate").write_bytes(b"original-state")
        (root / ".barragan-apply-phase.json").write_text(
            json.dumps({"schema": "provider-keyed-v2", "phase": "applied"}))
        workspace = ProviderKeyedWorkspace(
            root, root / "terraform.tfstate", root / ".terraform-data",
            "provider-keyed-v2", "linode", "credential", "fingerprint",
            "revision", "b" * 64)
        source = FirstApplySource(
            workspace, hashlib.sha256(b"original-state").hexdigest(),
            hashlib.sha256(plan.read_bytes()).hexdigest(), "c" * 64,
            lock_fence=lambda: None)
        calls = []
        stop = {"at": None, "drift": False, "high_output": False, "failed": False}

        def pre_go(selected, saved, renew):
            assert selected == parent and saved == source
            renew()
            calls.append("pre-go")
            return "b" * 64 if stop["drift"] else "a" * 64

        def run(command, *, scratch_path, provider_keyed_v2, gate_timeout_seconds,
                max_output_bytes, env, intent_callback, started_callback, heartbeat_callback,
                result_callback):
            assert command == ["/usr/bin/terraform", "apply", "-input=false",
                               "-lock=true", "-no-color", str(plan)]
            assert provider_keyed_v2 and gate_timeout_seconds == 1200
            assert max_output_bytes == 1024 * 1024
            assert env["TF_DATA_DIR"] == str(root / ".terraform-data")
            intent = CommandIntent("d" * 32, str(root), hashlib.sha256(
                json.dumps(command, separators=(",", ":")).encode()).hexdigest())
            intent_callback(intent)
            calls.append("intent")
            if stop["at"] == "intent":
                raise RuntimeError("stopped after durable intent")
            if stop["at"] == "drift_before_started":
                stop["drift"] = True
            started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 99))
            started_callback(started)
            calls.append("start")
            if stop["at"] == "start":
                raise RuntimeError("stopped before result")
            heartbeat_callback(started)
            (root / "terraform.tfstate").write_bytes(b"new-state")
            output = "x" * 100_000 if stop["high_output"] else "ok\n"
            code, error = (1, "bounded diagnostic") if stop['failed'] else (0, "")
            result_callback(CommandAuditResult(started, code, len(output), len(error), False, False))
            calls.append("result")
            return CommandResult(started, code, output, error, False, False)

        def phase_started(selected):
            assert selected == workspace
            (root / ".barragan-apply-phase.json").write_text(
                json.dumps({"schema": "provider-keyed-v2", "phase": "apply_started"}))
            calls.append("phase-started")

        def phase_applied(selected):
            assert selected == workspace
            (root / ".barragan-apply-phase.json").write_text(
                json.dumps({"schema": "provider-keyed-v2", "phase": "applied"}))
            calls.append("phase-applied")

        monkeypatch.setattr(service, "mark_provider_keyed_apply_started", phase_started)
        monkeypatch.setattr(service, "mark_provider_keyed_applied", phase_applied)
        options = dict(
            parent_id=parent.id, environment="devtest", job_repository=jobs,
            lease_lookup=lambda engagement: (
                (row.owner_id, row.operation) if (
                    row := db.session.get(CoreMutationLeaseModel, engagement)) else None),
            source_session=lambda _parent, _provider, _renew: nullcontext(source),
            pair_preflight=lambda _parent, renew: (renew(), "a" * 64)[1],
            pre_go_check=pre_go,
            release_check=lambda **_kwargs: SimpleNamespace(
                path=Path("/usr/bin/terraform"), sha256="c" * 64),
            gated_command_runner=run, command_environment={"PATH": "/usr/bin"},
        )
        yield SimpleNamespace(jobs=jobs, parent=parent, root=root, calls=calls,
                              stop=stop, options=options)


def test_first_append_apply_is_one_shot_and_waits_for_exact_poststate(ready):
    child = run_first_mixed_append_provider_apply(**ready.options)
    assert child.events[-1].message == "mixed append first awaiting exact poststate proof"
    assert [row.message for row in child.events].count(
        "mixed append first Apply command intended") == 1
    assert ready.calls == ["pre-go", "pre-go", "intent", "pre-go", "phase-started",
                           "start", "result", "phase-applied"]
    with pytest.raises(MixedAppendFirstApplyAttention, match="intent already exists"):
        run_first_mixed_append_provider_apply(**ready.options)


def test_bounded_larger_terraform_output_does_not_force_attention(ready):
    ready.stop["high_output"] = True
    child = run_first_mixed_append_provider_apply(**ready.options)
    assert child.events[-1].message == "mixed append first awaiting exact poststate proof"
    result = next(row for row in child.events if row.message ==
                  "mixed append first Apply command result fenced")
    assert result.data["stdoutBytes"] == 100_000


@pytest.mark.parametrize("stop_at", ["intent", "start"])
def test_uncertain_command_never_replays(ready, stop_at):
    ready.stop["at"] = stop_at
    with pytest.raises(RuntimeError):
        run_first_mixed_append_provider_apply(**ready.options)
    child = ready.jobs.get(_child_id(ready.parent.id))
    assert child is not None
    assert any(row.message == "mixed append first Apply command intended"
               for row in child.events)
    before = list(ready.calls)
    with pytest.raises(MixedAppendFirstApplyAttention, match="intent already exists"):
        run_first_mixed_append_provider_apply(**ready.options)
    assert ready.calls == before


def test_stale_review_or_wrong_lease_stops_before_command(ready):
    bad = {**ready.options, "pre_go_check": lambda *_: "b" * 64}
    with pytest.raises(MixedAppendFirstApplyAttention, match="pre-GO proof"):
        run_first_mixed_append_provider_apply(**bad)
    child = ready.jobs.get(_child_id(ready.parent.id))
    assert child is not None and len(child.events) == 2
    db.session.execute(text("UPDATE core_mutation_leases SET operation = 'provider_keyed_initial'"))
    db.session.commit()
    with pytest.raises(MixedAppendFirstApplyAttention, match="authority differs"):
        run_first_mixed_append_provider_apply(**ready.options)
    assert len(ready.jobs.get(child.id).events) == 2


def test_paired_binary_preflight_fails_before_source_or_go(ready):
    entered = []

    def source(_parent, _provider, _renew):
        entered.append(True)
        raise AssertionError("source lock should not be entered")

    with pytest.raises(MixedAppendFirstApplyAttention, match="binary preflight"):
        run_first_mixed_append_provider_apply(**{
            **ready.options, "pair_preflight": lambda _parent, _renew: "b" * 64,
            "source_session": source,
        })
    assert entered == []
    assert len(ready.jobs.get(_child_id(ready.parent.id)).events) == 2


def test_changed_saved_plan_never_records_a_command_intent(ready):
    plan = ready.root / ".barragan-mixed-append-linode-saved.tfplan"
    plan.write_bytes(b"changed-plan")
    with pytest.raises(MixedAppendFirstApplyAttention, match="predecessor differs"):
        run_first_mixed_append_provider_apply(**ready.options)
    child = ready.jobs.get(_child_id(ready.parent.id))
    assert child is not None and len(child.events) == 2
    assert ready.calls == []


def test_changed_review_at_last_pre_go_stops_before_intent(ready):
    checks = []

    def changing(_parent, _source, renew):
        renew()
        checks.append(1)
        return "a" * 64 if len(checks) == 1 else "b" * 64

    with pytest.raises(MixedAppendFirstApplyAttention, match="GO inputs changed"):
        run_first_mixed_append_provider_apply(
            **{**ready.options, "pre_go_check": changing})
    child = ready.jobs.get(_child_id(ready.parent.id))
    assert child is not None and len(child.events) == 2
    assert len(checks) == 2


def test_review_drift_after_intent_is_fenced_before_go(ready):
    ready.stop["at"] = "drift_before_started"
    with pytest.raises(MixedAppendFirstApplyAttention, match="process differs"):
        run_first_mixed_append_provider_apply(**ready.options)
    child = ready.jobs.get(_child_id(ready.parent.id))
    assert child is not None
    assert child.events[-1].message == "mixed append first Apply command intended"
    assert "phase-started" not in ready.calls
    assert "start" not in ready.calls
    assert "result" not in ready.calls
    with pytest.raises(MixedAppendFirstApplyAttention, match="intent already exists"):
        run_first_mixed_append_provider_apply(**ready.options)


def test_claimed_append_writer_fences_exact_action_lease_and_journal(ready):
    child = run_first_mixed_append_provider_apply(**ready.options)
    current = ready.jobs.get(child.id)
    assert current.input["claimToken"]
    at = datetime.now(timezone.utc) + timedelta(seconds=1)
    kwargs = dict(owner=current.input["claimOwner"], token=current.input["claimToken"],
                  heartbeat_at=at.isoformat(),
                  expires_at=(at + timedelta(minutes=1)).isoformat(),
                  event=JobEvent(len(current.events) + 1, "info", "test next", {}))
    assert ready.jobs.append_event_if_running_claimed(
        current, expected_event_digest="0" * 64, **kwargs) is None
    assert ready.jobs.append_event_if_running_claimed(
        replace(current, action="provider_keyed_mixed_initial_apply_child"),
        expected_event_digest=job_event_digest(current.events), **kwargs) is None
    db.session.execute(text("UPDATE core_mutation_leases SET operation = 'provider_keyed_initial'"))
    db.session.commit()
    assert ready.jobs.append_event_if_running_claimed(
        current, expected_event_digest=job_event_digest(current.events), **kwargs) is None
    assert len(ready.jobs.get(current.id).events) == len(current.events)


def test_failed_first_apply_persists_private_output_without_replay(ready):
    ready.stop['failed'] = True
    with pytest.raises(MixedAppendFirstApplyAttention):
        run_first_mixed_append_provider_apply(**ready.options)
    path = ready.root / ('.barragan-append-first-apply-failure-' + 'd' * 32 + '.json')
    assert path.stat().st_mode & 0o777 == 0o600
    output = json.loads(path.read_text())
    assert output['stderr'] == 'bounded diagnostic' and output['returnCode'] == 1
    child = ready.jobs.get(_child_id(ready.parent.id))
    assert len(child.events) == 6 and child.events[-1].data['returnCode'] == 1
    assert not any('bounded diagnostic' in str(event.data) for event in child.events)
    before = path.read_bytes()
    with pytest.raises(MixedAppendFirstApplyAttention):
        run_first_mixed_append_provider_apply(**ready.options)
    assert path.read_bytes() == before


@pytest.mark.parametrize('prefix', ['../escape', '.barragan-unknown-apply-failure'])
def test_failed_output_rejects_unapproved_prefix_before_write(tmp_path, prefix):
    with pytest.raises(ValueError, match='prefix differs'):
        service._save_failed_apply_output(SimpleNamespace(path=tmp_path), None, prefix=prefix)
    assert list(tmp_path.iterdir()) == []
