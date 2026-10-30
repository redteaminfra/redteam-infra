# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline one-shot second Apply gates; no Terraform or provider request runs."""

from contextlib import nullcontext
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
import app.services.provider_keyed_mixed_append_second_apply_child as service
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.models import CoreMutationLeaseModel


class Jobs:
    """Strict local CAS stand-in until the second action is registered in storage."""

    def __init__(self, parent):
        self.rows = {parent.id: parent}

    def get(self, key):
        return self.rows.get(key)

    def save_if_absent(self, row):
        return self.rows.setdefault(row.id, row)

    def start_if_queued(self, row, *, started_at, event):
        if self.get(row.id) != row or row.status != "queued":
            return None
        return self._put(replace(row, status="running", started_at=started_at,
                                 events=[*row.events, event]))

    def claim_lease(self, key, *, owner, token, claimed_at, expires_at,
                    eligible_statuses):
        row = self.get(key)
        if row is None or row.status not in eligible_statuses:
            return None
        return self._put(replace(row, input={**row.input,
            "claimOwner": owner, "claimToken": token,
            "claimClaimedAt": claimed_at, "claimHeartbeatAt": claimed_at,
            "claimExpiresAt": expires_at}))

    def renew_lease(self, key, *, owner, token, heartbeat_at, expires_at):
        row = self.get(key)
        if row is None or row.input.get("claimOwner") != owner or row.input.get("claimToken") != token:
            return None
        return self._put(replace(row, input={**row.input, "claimHeartbeatAt": heartbeat_at,
                                            "claimExpiresAt": expires_at}))

    def append_event_if_running_claimed(self, row, *, owner, token,
                                        expected_event_digest, heartbeat_at,
                                        expires_at, event):
        if (self.get(row.id) != row or row.input.get("claimOwner") != owner
                or row.input.get("claimToken") != token
                or job_event_digest(row.events) != expected_event_digest
                or event.sequence != len(row.events) + 1):
            return None
        return self._put(replace(row, input={**row.input, "claimHeartbeatAt": heartbeat_at,
                                              "claimExpiresAt": expires_at},
                                 events=[*row.events, event]))

    def _put(self, row):
        self.rows[row.id] = row
        return row


@pytest.fixture(params=[("digitalocean", "linode"), ("linode", "digitalocean")])
def ready(tmp_path, monkeypatch, request):
    order = request.param
    at = datetime.now(timezone.utc).isoformat()
    parent = StoredJobRun(
        "job-append", "provider_keyed_mixed_append", "running",
        "engagement:eng-opaque", "engagement", "eng-opaque", "operator",
        {"phase": "apply_sealed", "coreJobId": "job-core", "corePlanId": "plan-core",
         "reviewSha256": "a" * 64, "providerOrder": list(order)},
        [], at, at, None, [JobEvent(1, "info", "pair approved", {})])
    jobs = Jobs(parent)
    provider = order[1]
    root = tmp_path / provider
    root.mkdir()
    plan = root / f".barragan-mixed-append-{provider}-saved.tfplan"
    plan.write_bytes(b"exact second binary")
    state = root / "terraform.tfstate"
    state.write_bytes(b"second predecessor")
    phase = root / ".barragan-apply-phase.json"
    phase.write_text(json.dumps({"schema": "provider-keyed-v2", "phase": "applied"}))
    workspace = ProviderKeyedWorkspace(
        root, state, root / ".terraform-data", "provider-keyed-v2", provider,
        "credential", "fingerprint", "revision", "b" * 64)
    source = service.SecondApplySource(
        workspace, hashlib.sha256(state.read_bytes()).hexdigest(),
        hashlib.sha256(plan.read_bytes()).hexdigest(), "c" * 64, lambda: None)
    change = {"kind": None, "lease": True, "proof": "d" * 64,
              "review": "a" * 64}
    go = []

    def first_terminal(_parent, renew):
        renew()
        return change["proof"]

    def second_preflight(_parent, proof, renew):
        renew()
        return "a" * 64 if proof == "d" * 64 else "0" * 64

    def pre_go(_parent, _source, proof, renew):
        renew()
        return change["review"] if proof == "d" * 64 else "0" * 64

    def gated(command, **options):
        intent = CommandIntent("e" * 32, str(root), hashlib.sha256(
            json.dumps(command, separators=(",", ":")).encode()).hexdigest())
        options["intent_callback"](intent)
        if change["kind"] == "interrupt":
            raise RuntimeError("process observation lost after durable intent")
        if change["kind"] == "first-proof":
            change["proof"] = "f" * 64
        elif change["kind"] == "second-state":
            state.write_bytes(b"changed before GO")
        elif change["kind"] == "lease":
            change["lease"] = False
        elif change["kind"] == "review":
            change["review"] = "0" * 64
        started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 99))
        options["started_callback"](started)
        go.append(command)
        options["heartbeat_callback"](started)
        state.write_bytes(b"new second state")
        code, error = (1, "bounded diagnostic") if change['kind'] == 'nonzero' else (0, "")
        options["result_callback"](CommandAuditResult(started, code, 2, len(error), False, False))
        return CommandResult(started, code, "ok", error, False, False)

    monkeypatch.setattr(service, "mark_provider_keyed_apply_started",
                        lambda _: phase.write_text(json.dumps({"schema": "provider-keyed-v2",
                                                             "phase": "apply_started"})))
    monkeypatch.setattr(service, "mark_provider_keyed_applied",
                        lambda _: phase.write_text(json.dumps({"schema": "provider-keyed-v2",
                                                             "phase": "applied"})))
    options = dict(
        parent_id=parent.id, environment="devtest", job_repository=jobs,
        lease_lookup=lambda _: ("plan-core", "provider_keyed_mixed_append") if change["lease"] else None,
        source_session=lambda *_: nullcontext(source),
        first_terminal_proof=first_terminal, second_preflight=second_preflight,
        pre_go_check=pre_go,
        release_check=lambda **_: SimpleNamespace(path=Path("/usr/bin/terraform"), sha256="c" * 64),
        gated_command_runner=gated, command_environment={"PATH": "/usr/bin"},
    )
    return SimpleNamespace(options=options, jobs=jobs, parent=parent, go=go,
                           change=change, provider=provider, root=root)


def test_exact_second_go_once_after_first_terminal(ready):
    child = service.run_second_mixed_append_provider_apply(**ready.options)
    assert child.input["provider"] == ready.provider
    assert child.input["providerIndex"] == 1
    assert child.events[-1].message == "mixed append second awaiting exact poststate proof"
    assert len(ready.go) == 1
    with pytest.raises(service.MixedAppendSecondApplyAttention, match="intent already exists"):
        service.run_second_mixed_append_provider_apply(**ready.options)


def test_missing_first_terminal_stops_before_command(ready):
    ready.change["proof"] = None
    with pytest.raises(service.MixedAppendSecondApplyAttention, match="preflight"):
        service.run_second_mixed_append_provider_apply(**ready.options)
    assert ready.go == []


@pytest.mark.parametrize("drift", ["first-proof", "second-state", "lease", "review"])
def test_late_drift_stops_before_second_go(ready, drift):
    ready.change["kind"] = drift
    with pytest.raises(service.MixedAppendSecondApplyAttention):
        service.run_second_mixed_append_provider_apply(**ready.options)
    assert ready.go == []
    child = ready.jobs.get(service._child_id(ready.parent.id))
    assert child.events[-1].message == "mixed append second Apply command intended"
    ready.change["lease"] = True
    with pytest.raises(service.MixedAppendSecondApplyAttention, match="intent already exists"):
        service.run_second_mixed_append_provider_apply(**ready.options)


def test_uncertain_second_intent_never_replays(ready):
    ready.change["kind"] = "interrupt"
    with pytest.raises(RuntimeError, match="observation lost"):
        service.run_second_mixed_append_provider_apply(**ready.options)
    assert ready.go == []
    with pytest.raises(service.MixedAppendSecondApplyAttention, match="intent already exists"):
        service.run_second_mixed_append_provider_apply(**ready.options)


def test_second_go_journal_persists_with_real_repository(ready):
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        db.session.add(CoreMutationLeaseModel(
            engagement_id=ready.parent.target_id, owner_id="plan-core",
            operation="provider_keyed_mixed_append"))
        db.session.commit()
        jobs = SqlAlchemyJobRepository()
        jobs.save(ready.parent)
        def lease(engagement):
            row = db.session.get(CoreMutationLeaseModel, engagement)
            return (row.owner_id, row.operation) if row else None
        options = {**ready.options, "job_repository": jobs, "lease_lookup": lease}
        child = service.run_second_mixed_append_provider_apply(**options)
        persisted = SqlAlchemyJobRepository().get(child.id)
        assert persisted == child
        assert persisted.action == service.ACTION
        assert persisted.input["providerIndex"] == 1
        assert len(ready.go) == 1
        assert persisted.events[-1].message == "mixed append second awaiting exact poststate proof"
        with pytest.raises(service.MixedAppendSecondApplyAttention, match="intent already exists"):
            service.run_second_mixed_append_provider_apply(**options)
        assert len(ready.go) == 1


def test_real_repository_retains_intent_after_late_first_proof_drift(ready):
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        db.session.add(CoreMutationLeaseModel(
            engagement_id=ready.parent.target_id, owner_id="plan-core",
            operation="provider_keyed_mixed_append"))
        db.session.commit()
        jobs = SqlAlchemyJobRepository()
        jobs.save(ready.parent)
        ready.change["kind"] = "first-proof"
        def lease(engagement):
            row = db.session.get(CoreMutationLeaseModel, engagement)
            return (row.owner_id, row.operation) if row else None
        options = {**ready.options, "job_repository": jobs, "lease_lookup": lease}
        with pytest.raises(service.MixedAppendSecondApplyAttention, match="process differs"):
            service.run_second_mixed_append_provider_apply(**options)
        child = SqlAlchemyJobRepository().get(service._child_id(ready.parent.id))
        assert child.events[-1].message == "mixed append second Apply command intended"
        assert ready.go == []
        with pytest.raises(service.MixedAppendSecondApplyAttention, match="intent already exists"):
            service.run_second_mixed_append_provider_apply(**options)
        assert ready.go == []


def test_failed_second_apply_persists_private_output_without_replay(ready):
    ready.change['kind'] = 'nonzero'
    with pytest.raises(service.MixedAppendSecondApplyAttention):
        service.run_second_mixed_append_provider_apply(**ready.options)
    path = ready.root / ('.barragan-append-second-apply-failure-' + 'e' * 32 + '.json')
    assert path.stat().st_mode & 0o777 == 0o600
    output = json.loads(path.read_text())
    assert output['stderr'] == 'bounded diagnostic' and output['returnCode'] == 1
    before = path.read_bytes()
    with pytest.raises(service.MixedAppendSecondApplyAttention):
        service.run_second_mixed_append_provider_apply(**ready.options)
    assert path.read_bytes() == before and len(ready.go) == 1
