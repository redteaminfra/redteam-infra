# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private one-shot mixed destroy GO with fake commands and no provider calls."""

from dataclasses import asdict, replace
import fcntl
import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from app.asgi import create_app
from app.core.config import TestConfig
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_mixed_interrupted_destroy_child import (
    MixedInterruptedDestroyChildAttention, _child_id, _digest,
    recognize_mixed_interrupted_destroy_child,
)
from app.services.provider_keyed_mixed_interrupted_destroy_source import MixedInterruptedDestroyShow
from app.services.provider_keyed_mixed_interrupted_destroy_source import bind_mixed_interrupted_destroy_show
from app.services.provider_keyed_mixed_interrupted_destroy_child import propose_mixed_interrupted_destroy_child
from app.services.provider_keyed_mixed_interrupted_destroy_go import (
    MixedInterruptedDestroyGoAttention, reconcile_mixed_interrupted_destroy_result,
    run_first_mixed_interrupted_provider_destroy, run_mixed_interrupted_provider_destroy,
)
from app.services.provider_keyed_mixed_initial_apply_child import _child_id as _apply_child_id
from app.services.provider_keyed_mixed_initial_apply_child import _base as _apply_base
from app.services.provider_keyed_mixed_initial_plan_parent import validate_mixed_initial_apply_seal
from app.services.provider_keyed_mixed_interrupted_cleanup import (
    _canonical, propose_mixed_interrupted_cleanup,
)
from app.services.provider_keyed_mixed_interrupted_destroy_plan import bind_mixed_interrupted_destroy_plans
from app.services.provider_keyed_mixed_interrupted_source import _digest as review_digest
from app.domain import JobEvent
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.database import db
from app.storage.models import CoreMutationLeaseModel
import app.services.provider_keyed_mixed_interrupted_destroy_go as go_service
from app.services.provider_keyed_mixed_partial_apply_source import _state
from test_provider_keyed_mixed_initial_apply_proof import _state_and_rows
from test_provider_keyed_mixed_interrupted_post_sketch_absence import _state_backed_case
from test_provider_keyed_mixed_interrupted_source import _snapshot
from test_provider_keyed_mixed_interrupted_destroy_source import _release, saved
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case


def _args(saved):
    initial, cleanup, review, plans, provider, raw, binary, shown, plan_path = saved
    root = plan_path.parent
    (root / ".barragan-apply-phase.json").write_text(json.dumps({
        "schema": "provider-keyed-v2", "phase": "applied"}))
    (root / ".terraform-data").mkdir(exist_ok=True)
    return initial, cleanup, review, plans, provider, raw, binary, shown, root


def test_read_only_saved_show_uses_owned_workspace_terraform_data(tmp_path, monkeypatch):
    command = ("/usr/bin/terraform", "show", "-json", str(tmp_path / "saved.tfplan"))
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout='{"format_version":"1.2"}', stderr="")

    monkeypatch.setattr(go_service.subprocess, "run", run)
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        go_service._real_show(command, tmp_path)
    assert calls == []

    data_dir = tmp_path / ".terraform-data"
    data_dir.mkdir()
    assert go_service._real_show(command, tmp_path) == '{"format_version":"1.2"}'
    assert len(calls) == 1
    assert calls[0][0] == command
    assert {key: calls[0][1][key] for key in ("cwd", "capture_output", "text",
                                                 "timeout", "check")} == {
        "cwd": tmp_path, "capture_output": True, "text": True,
        "timeout": 120, "check": False}
    assert calls[0][1]["env"]["TF_DATA_DIR"] == str(data_dir)
    assert calls[0][1]["env"]["TF_CLI_CONFIG_FILE"] == "/dev/null"
    assert set(calls[0][1]["env"]) <= go_service._COMMAND_ENV | {
        "TF_DATA_DIR", "TF_CLI_CONFIG_FILE"}

    data_dir.rmdir()
    data_dir.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        go_service._real_show(command, tmp_path)
    assert len(calls) == 1


def test_both_orders_one_shot_result_waits_for_external_absence(saved, ready):
    initial, cleanup, review, plans, provider, raw, binary, shown, root = _args(saved)
    jobs = ready.case.jobs
    jobs.save(cleanup)
    calls = []
    def fake_runner(command, *, scratch_path, intent_callback, started_callback,
                    heartbeat_callback, result_callback, **kwargs):
        calls.append(tuple(command))
        assert kwargs["env"]["TF_DATA_DIR"] == str(root / ".terraform-data")
        assert kwargs["env"]["TF_CLI_CONFIG_FILE"] == "/dev/null"
        assert set(kwargs["env"]) <= go_service._COMMAND_ENV | {
            "TF_DATA_DIR", "TF_CLI_CONFIG_FILE"}
        descriptor = os.open(scratch_path / f".barragan-{provider}-plan.lock", os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)
        intent = CommandIntent("once", str(scratch_path), hashlib.sha256(json.dumps(
            command, separators=(",", ":")).encode()).hexdigest())
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity("boot", 234, 234, 1))
        started_callback(started)
        before = json.loads((scratch_path / "terraform.tfstate").read_text())
        (scratch_path / "terraform.tfstate").write_text(json.dumps({
            **before, "serial": before["serial"] + 1, "resources": []}))
        heartbeat_callback(started)
        result_callback(CommandAuditResult(started, 0, 0, 0, False, False))
        return CommandResult(started, 0, "", "", False, False)
    result = run_first_mixed_interrupted_provider_destroy(
        initial, cleanup, review, plans, provider, raw, environment="devtest",
        exact_both_scope_prover=lambda fence: (fence(), review)[1], job_repository=jobs,
        credential_repository=ready.case.args["credential_repository"],
        lease_lookup=lambda engagement: ("plan-1", "provider_keyed_teardown_fence"),
        terraform_path=binary, show_runner=lambda command, cwd: shown,
        release_validator=lambda *, environment: _release(binary),
        gated_command_runner=fake_runner)
    assert result.status == "running"
    assert result.events[-1].message == "mixed provider awaiting exact absence"
    assert len(calls) == 1
    assert json.loads((root / ".barragan-apply-phase.json").read_text())["phase"] == "destroy_applied"
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        run_first_mixed_interrupted_provider_destroy(
            initial, cleanup, review, plans, provider, raw, environment="devtest",
            exact_both_scope_prover=lambda fence: (fence(), review)[1], job_repository=jobs,
            credential_repository=ready.case.args["credential_repository"],
            lease_lookup=lambda engagement: ("plan-1", "provider_keyed_teardown_fence"),
            terraform_path=binary, show_runner=lambda command, cwd: shown,
            release_validator=lambda *, environment: _release(binary),
            gated_command_runner=fake_runner)
    assert len(calls) == 1


def test_missing_terraform_data_blocks_destroy_before_child_or_go(saved, ready):
    initial, cleanup, review, plans, provider, raw, binary, shown, root = _args(saved)
    jobs = ready.case.jobs
    jobs.save(cleanup)
    (root / ".terraform-data").rmdir()
    calls = []
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        run_first_mixed_interrupted_provider_destroy(
            initial, cleanup, review, plans, provider, raw, environment="devtest",
            exact_both_scope_prover=lambda fence: (fence(), review)[1], job_repository=jobs,
            credential_repository=ready.case.args["credential_repository"],
            lease_lookup=lambda engagement: ("plan-1", "provider_keyed_teardown_fence"),
            terraform_path=binary, show_runner=lambda command, cwd: shown,
            release_validator=lambda *, environment: _release(binary),
            gated_command_runner=lambda *args, **kwargs: calls.append("GO"))
    assert jobs.get(_child_id(initial.input["coreJobId"], provider)) is None
    assert calls == []


@pytest.mark.parametrize("prequeued", [False, True])
def test_persisted_one_event_child_starts_without_replaying_go(
        saved, ready, tmp_path, prequeued):
    initial, cleanup, review, plans, provider, raw, binary, shown, root = _args(saved)

    class Config(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'destroy-child.sqlite3'}"

    app = create_app(Config)
    with app.storage_context():
        jobs = SqlAlchemyJobRepository()
        jobs.save(initial)
        jobs.save(cleanup)
        db.session.add(CoreMutationLeaseModel(
            engagement_id=initial.target_id, owner_id=initial.input["corePlanId"],
            operation="provider_keyed_teardown_fence"))
        db.session.commit()
        initial = jobs.get(initial.id)
        cleanup = jobs.get(cleanup.id)
        bound = bind_mixed_interrupted_destroy_show(
            initial, cleanup, review, plans, provider, raw, binary,
            hashlib.sha256(binary.read_bytes()).hexdigest(),
            show_runner=lambda command, cwd: shown, fence=lambda: "stable",
            release_validator=lambda: _release(binary))
        child_id = _child_id(initial.input["coreJobId"], provider)
        if prequeued:
            jobs.save(propose_mixed_interrupted_destroy_child(
                initial, cleanup, review, plans, bound))
            assert jobs.get(child_id).status == "queued"
            assert len(jobs.get(child_id).events) == 1

        calls = []
        def stop_before_intent(*args, **kwargs):
            calls.append("runner reached")
            raise RuntimeError("diagnostic stop before command intent")

        with pytest.raises(MixedInterruptedDestroyGoAttention):
            run_first_mixed_interrupted_provider_destroy(
                initial, cleanup, review, plans, provider, raw,
                environment="devtest", exact_both_scope_prover=lambda fence: (fence(), review)[1],
                job_repository=jobs,
                credential_repository=ready.case.args["credential_repository"],
                lease_lookup=lambda engagement: ("plan-1", "provider_keyed_teardown_fence"),
                terraform_path=binary, show_runner=lambda command, cwd: shown,
                release_validator=lambda *, environment: _release(binary),
                gated_command_runner=stop_before_intent)
        child = jobs.get(child_id)
        assert child.status == "running"
        assert recognize_mixed_interrupted_destroy_child(
            child, initial, cleanup, review, plans, bound) == "show_proved"
        assert [event.message for event in child.events] == [
            "mixed provider destroy queued", "mixed provider destroy started",
            "mixed provider destroy show proved"]
        assert calls == ["runner reached"]
        with pytest.raises(MixedInterruptedDestroyGoAttention):
            run_first_mixed_interrupted_provider_destroy(
                initial, cleanup, review, plans, provider, raw,
                environment="devtest", exact_both_scope_prover=lambda fence: (fence(), review)[1],
                job_repository=jobs,
                credential_repository=ready.case.args["credential_repository"],
                lease_lookup=lambda engagement: ("plan-1", "provider_keyed_teardown_fence"),
                terraform_path=binary, show_runner=lambda command, cwd: shown,
                release_validator=lambda *, environment: _release(binary),
                gated_command_runner=stop_before_intent)
        assert calls == ["runner reached"]


def test_loss_after_durable_intent_never_replays(saved, ready):
    initial, cleanup, review, plans, provider, raw, binary, shown, root = _args(saved)
    jobs = ready.case.jobs
    jobs.save(cleanup)
    attempts = []
    def stopped(command, *, scratch_path, intent_callback, **kwargs):
        attempts.append(tuple(command))
        intent_callback(CommandIntent("once", str(scratch_path), hashlib.sha256(json.dumps(
            command, separators=(",", ":")).encode()).hexdigest()))
        raise RuntimeError("crashed after durable intent")
    kwargs = dict(
        initial=initial, cleanup=cleanup, review=review, plans=plans,
        provider=provider, before_state=raw, environment="devtest",
        exact_both_scope_prover=lambda fence: (fence(), review)[1], job_repository=jobs,
        credential_repository=ready.case.args["credential_repository"],
        lease_lookup=lambda engagement: ("plan-1", "provider_keyed_teardown_fence"),
        terraform_path=binary, show_runner=lambda command, cwd: shown,
        release_validator=lambda *, environment: _release(binary),
        gated_command_runner=stopped)
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        run_first_mixed_interrupted_provider_destroy(**kwargs)
    child = jobs.get(_child_id(initial.input["coreJobId"], provider))
    assert child.events[-1].message == "mixed provider destroy command intended"
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        run_first_mixed_interrupted_provider_destroy(**kwargs)
    assert len(attempts) == 1


def test_second_provider_and_stale_both_scope_review_stop_before_child(saved, ready):
    initial, cleanup, review, plans, provider, raw, binary, shown, root = _args(saved)
    jobs = ready.case.jobs
    jobs.save(cleanup)
    calls = []
    common = dict(
        initial=initial, cleanup=cleanup, review=review, plans=plans,
        before_state=raw, environment="devtest", job_repository=jobs,
        credential_repository=ready.case.args["credential_repository"],
        lease_lookup=lambda engagement: ("plan-1", "provider_keyed_teardown_fence"),
        terraform_path=binary, show_runner=lambda command, cwd: calls.append(command) or shown,
        release_validator=lambda *, environment: _release(binary),
        gated_command_runner=lambda *args, **kwargs: calls.append("GO"))
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        run_first_mixed_interrupted_provider_destroy(
            provider=plans.ordered_providers[1],
            exact_both_scope_prover=lambda fence: (fence(), review)[1], **common)
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        run_first_mixed_interrupted_provider_destroy(
            provider=provider,
            exact_both_scope_prover=lambda fence: (fence(), replace(
                review, scopes=(replace(review.scopes[0], state_sha256="0" * 64),
                                review.scopes[1])))[1], **common)
    assert calls == []
    assert jobs.get(_child_id(initial.input["coreJobId"], provider)) is None


def test_credential_drift_stops_before_child_or_command(saved, ready):
    initial, cleanup, review, plans, provider, raw, binary, shown, root = _args(saved)
    jobs = ready.case.jobs
    jobs.save(cleanup)
    calls = []
    class MissingCredential:
        def get(self, key):
            return None
        def get_default(self, provider):
            return None
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        run_first_mixed_interrupted_provider_destroy(
            initial, cleanup, review, plans, provider, raw, environment="devtest",
            exact_both_scope_prover=lambda fence: (fence(), review)[1], job_repository=jobs,
            credential_repository=MissingCredential(),
            lease_lookup=lambda engagement: ("plan-1", "provider_keyed_teardown_fence"),
            terraform_path=binary, show_runner=lambda command, cwd: shown,
            release_validator=lambda *, environment: _release(binary),
            gated_command_runner=lambda *args, **kwargs: calls.append("GO"))
    assert calls == []
    assert jobs.get(_child_id(initial.input["coreJobId"], provider)) is None


def test_provider_drift_during_show_stops_before_command_intent(saved, ready):
    initial, cleanup, review, plans, provider, raw, binary, shown, root = _args(saved)
    jobs = ready.case.jobs
    jobs.save(cleanup)
    drifted = {"value": False}
    commands = []
    def show(command, cwd):
        drifted["value"] = True
        return shown
    def fresh(fence):
        fence()
        return (replace(review, scopes=(replace(review.scopes[0], state_sha256="0" * 64),
                                        review.scopes[1]))
                if drifted["value"] else review)
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        run_first_mixed_interrupted_provider_destroy(
            initial, cleanup, review, plans, provider, raw, environment="devtest",
            exact_both_scope_prover=fresh, job_repository=jobs,
            credential_repository=ready.case.args["credential_repository"],
            lease_lookup=lambda engagement: ("plan-1", "provider_keyed_teardown_fence"),
            terraform_path=binary, show_runner=show,
            release_validator=lambda *, environment: _release(binary),
            gated_command_runner=lambda *args, **kwargs: commands.append("GO"))
    assert commands == []
    assert jobs.get(_child_id(initial.input["coreJobId"], provider)) is None


def test_unrelated_account_inventory_row_does_not_block_owned_first_scope(saved, ready):
    initial, cleanup, review, plans, provider, raw, binary, shown, root = _args(saved)
    jobs = ready.case.jobs
    jobs.save(cleanup)
    changed = {"value": False}
    def show(command, cwd):
        changed["value"] = True
        return shown
    def fresh(fence):
        fence()
        if not changed["value"]:
            return review
        scopes = tuple(replace(scope, inventory_sha256="1" * 64,
                               observation_sha256="2" * 64) for scope in review.scopes)
        return replace(review, scopes=scopes, review_sha256="3" * 64)
    def stop_after_intent(command, *, scratch_path, intent_callback, **kwargs):
        intent_callback(CommandIntent("once", str(scratch_path), hashlib.sha256(json.dumps(
            command, separators=(",", ":")).encode()).hexdigest()))
        raise RuntimeError("stopped after durable intent")
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        run_first_mixed_interrupted_provider_destroy(
            initial, cleanup, review, plans, provider, raw, environment="devtest",
            exact_both_scope_prover=fresh, job_repository=jobs,
            credential_repository=ready.case.args["credential_repository"],
            lease_lookup=lambda engagement: ("plan-1", "provider_keyed_teardown_fence"),
            terraform_path=binary, show_runner=show,
            release_validator=lambda *, environment: _release(binary),
            gated_command_runner=stop_after_intent)
    child = jobs.get(_child_id(initial.input["coreJobId"], provider))
    assert child.events[-1].message == "mixed provider destroy command intended"


@pytest.mark.parametrize("drift", ["provider", "local_phase"])
def test_drift_between_intent_and_start_never_opens_gate(saved, ready, drift):
    initial, cleanup, review, plans, provider, raw, binary, shown, root = _args(saved)
    jobs = ready.case.jobs
    jobs.save(cleanup)
    changed = {"value": False}
    gate_opened = []
    def fresh(fence):
        fence()
        return (replace(review, scopes=(replace(review.scopes[0], state_sha256="0" * 64),
                                        review.scopes[1]))
                if changed["value"] and drift == "provider" else review)
    def fake_runner(command, *, scratch_path, intent_callback, started_callback, **kwargs):
        intent = CommandIntent("once", str(scratch_path), hashlib.sha256(json.dumps(
            command, separators=(",", ":")).encode()).hexdigest())
        intent_callback(intent)
        if drift == "provider":
            changed["value"] = True
        else:
            (root / ".barragan-apply-phase.json").write_text(json.dumps({
                "schema": "wrong", "phase": "applied"}))
        started_callback(StartedCommand(intent, ProcessIdentity("boot", 234, 234, 1)))
        gate_opened.append(True)
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        run_first_mixed_interrupted_provider_destroy(
            initial, cleanup, review, plans, provider, raw, environment="devtest",
            exact_both_scope_prover=fresh, job_repository=jobs,
            credential_repository=ready.case.args["credential_repository"],
            lease_lookup=lambda engagement: ("plan-1", "provider_keyed_teardown_fence"),
            terraform_path=binary, show_runner=lambda command, cwd: shown,
            release_validator=lambda *, environment: _release(binary),
            gated_command_runner=fake_runner)
    assert gate_opened == []
    child = jobs.get(_child_id(initial.input["coreJobId"], provider))
    assert child.events[-1].message == "mixed provider destroy command intended"


@pytest.mark.parametrize("marker_applied", [False, True])
def test_zero_result_restart_reconciles_phase_without_apply_replay(saved, ready, marker_applied):
    initial, cleanup, review, plans, provider, raw, binary, shown, root = _args(saved)
    jobs = ready.case.jobs
    jobs.save(cleanup)
    calls = []
    def stops_after_result(command, *, scratch_path, intent_callback, started_callback,
                           result_callback, **kwargs):
        calls.append(tuple(command))
        intent = CommandIntent("once", str(scratch_path), hashlib.sha256(json.dumps(
            command, separators=(",", ":")).encode()).hexdigest())
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity("boot", 234, 234, 1))
        started_callback(started)
        before = json.loads((scratch_path / "terraform.tfstate").read_text())
        (scratch_path / "terraform.tfstate").write_text(json.dumps({
            **before, "serial": before["serial"] + 1, "resources": []}))
        result_callback(CommandAuditResult(started, 0, 0, 0, False, False))
        raise RuntimeError("stopped after durable result")
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        run_first_mixed_interrupted_provider_destroy(
            initial, cleanup, review, plans, provider, raw, environment="devtest",
            exact_both_scope_prover=lambda fence: (fence(), review)[1], job_repository=jobs,
            credential_repository=ready.case.args["credential_repository"],
            lease_lookup=lambda engagement: ("plan-1", "provider_keyed_teardown_fence"),
            terraform_path=binary, show_runner=lambda command, cwd: shown,
            release_validator=lambda *, environment: _release(binary),
            gated_command_runner=stops_after_result)
    child = jobs.get(_child_id(initial.input["coreJobId"], provider))
    assert child.events[-1].message == "mixed provider destroy result fenced"
    if marker_applied:
        (root / ".barragan-apply-phase.json").write_text(json.dumps({
            "schema": "provider-keyed-v2", "phase": "destroy_applied"}))
    jobs.save(replace(child, input={**child.input,
                                    "claimExpiresAt": "2026-01-01T00:00:00+00:00"}))
    recovered = reconcile_mixed_interrupted_destroy_result(
        initial, cleanup, review, plans, provider, job_repository=jobs,
        lease_lookup=lambda engagement: ("plan-1", "provider_keyed_teardown_fence"),
        process_quiescent=lambda identity: True)
    assert recovered.events[-1].message == "mixed provider awaiting exact absence"
    assert len(calls) == 1


def _second_context(saved, ready, monkeypatch, *, first_kind="full"):
    initial, cleanup, review, plans, originals, destroys, snapshots = _state_backed_case(
        saved, both=True)
    first, second = review.ordered_providers
    jobs = ready.case.jobs
    workspace = next((ready.case.state_root / "eng-opaque" / "provider-keyed-v2" / second).iterdir())
    (workspace / ".terraform-data").mkdir(exist_ok=True)
    raw = (workspace / "terraform.tfstate").read_bytes()
    (workspace / ".barragan-apply-phase.json").write_text(json.dumps({
        "schema": "provider-keyed-v2", "phase": "applied"}))
    binary = workspace / "terraform-test"
    policy = initial.events[5].data["reviewedPolicy"][second]
    _, actual, _ = _state(second, policy, raw)
    changes = [{"address": address, "change": {"actions": ["delete"],
                "before": attrs, "after": None, "after_unknown": {}}}
               for address, attrs in actual.items()]
    shown = json.dumps({"format_version": "1.2", "terraform_version": "1.15.5",
                        "applyable": True, "complete": True, "errored": False,
                        "resource_changes": changes,
                        "prior_state": {"values": {"root_module": {"resources": [
                            {"address": address, "mode": "managed", "values": attrs}
                            for address, attrs in actual.items()]}}},
                        "output_changes": {}, "planned_values": {"root_module": {}}})
    assert hashlib.sha256(shown.encode()).hexdigest() == plans.plans[1].show_json_sha256
    if first_kind != "full":
        first_original = None
        if first_kind == "tag_only":
            assert first == "digitalocean"
            seal = validate_mixed_initial_apply_seal(initial)
            base = _apply_base(initial, seal, first, 0)
            selector = seal["reviewedPolicy"][first]["selector_tag"]
            rows = [
                JobEvent(1, "info", "mixed provider Apply queued", {}),
                JobEvent(2, "info", "mixed provider Apply started", {}),
                JobEvent(3, "info", "mixed selector absent before Apply",
                         {"absenceSha256": "a" * 64, "selectorTag": selector}),
                JobEvent(4, "info", "mixed selector POST intended",
                         {"selectorTag": selector, "absenceSha256": "a" * 64}),
                JobEvent(5, "info", "mixed selector 201 received",
                         {"selectorTag": selector, "httpStatus": 201}),
                JobEvent(6, "info", "mixed selector exclusive visibility proved",
                         {"selectorTag": selector, "visibleSha256": "b" * 64}),
            ]
            first_original = StoredJobRun(
                _apply_child_id(initial.input["coreJobId"], first),
                "provider_keyed_mixed_initial_apply_child", "running", initial.target,
                "engagement", initial.target_id, initial.requested_by, base, [],
                initial.created_at, initial.created_at, None, rows)
        first_scope = replace(
            review.scopes[0], kind=first_kind,
            child_journal_sha256=job_event_digest(first_original.events)
            if first_original is not None else None,
            state_sha256=None, lineage=None, serial=None, resource_ids=(),
            selector_retirement_pending=first_kind == "tag_only")
        scopes = (first_scope, review.scopes[1])
        payload = {"engagementId": review.engagement_id, "coreJobId": review.core_job_id,
                   "sealJournalSha256": review.seal_journal_sha256,
                   "orderedProviders": review.ordered_providers,
                   "scopes": [scope.__dict__ for scope in scopes]}
        review = replace(review, scopes=scopes, review_sha256=review_digest(payload))
        plans = bind_mixed_interrupted_destroy_plans(
            initial, review, {first: None, second: raw},
            {first: None, second: workspace / f".barragan-mixed-interrupted-destroy-{second}.tfplan"},
            {first: None, second: shown}, fence=lambda: "stable")
        cleanup = propose_mixed_interrupted_cleanup(initial, review, requested_by="operator")
        cleanup = replace(cleanup, input={**cleanup.input, "phase": "plans_sealed"},
                          events=cleanup.events + [JobEvent(
                              2, "info", "both mixed destroy plans sealed",
                              {"planSet": _canonical(asdict(plans)),
                               "planSetSha256": plans.plan_set_sha256})])
        first_workspace = next((ready.case.state_root / "eng-opaque" / "provider-keyed-v2" / first).iterdir())
        (first_workspace / "terraform.tfstate").unlink(missing_ok=True)
        (first_workspace / ".barragan-apply-phase.json").unlink(missing_ok=True)
        originals[first], destroys[first] = first_original, None
    for row in (cleanup,
                replace(originals[first], id=_apply_child_id(initial.input["coreJobId"], first))
                if originals[first] is not None else None,
                destroys[first],
                replace(originals[second], id=_apply_child_id(initial.input["coreJobId"], second))):
        if row is not None:
            jobs.save(row)
    # The source classifier and terminal absence checker have their own direct
    # tests. This test exercises their placement at every GO boundary.
    changed = {"first": False, "source": False}
    calls = []
    def collector(which, fence, mode):
        generation = fence()
        calls.append((which, mode))
        if which == first:
            if changed["first"]:
                return _snapshot(first, tag=first == "digitalocean" and first_kind != "unstarted",
                                 phase="destroy_applied" if first_kind == "full" else None,
                                 state=snapshots[first].state_json if first_kind == "full" else None,
                                 inventory=({"kind": "node", "id": review.scopes[0].resource_ids[0][1],
                                             "name": "reappeared", "tags": []},),
                                 generation=generation)
            return _snapshot(first, tag=first == "digitalocean" and first_kind != "unstarted",
                             phase="destroy_applied" if first_kind == "full" else None,
                             state=snapshots[first].state_json if first_kind == "full" else None,
                             generation=generation)
        return _snapshot(second, tag=second == "digitalocean", phase="applied",
                         state=raw, generation=generation)
    def source(*args, **kwargs):
        return replace(review.scopes[1], state_sha256="0" * 64) if changed["source"] else review.scopes[1]
    monkeypatch.setattr(go_service, "review_mixed_interrupted_provider_source", source)
    kwargs = dict(initial=initial, cleanup=cleanup, review=review, plans=plans,
                  provider=second, before_state=raw, environment="devtest",
                  inventory_collector=collector, process_quiescent=lambda identity: True,
                  job_repository=jobs,
                  credential_repository=ready.case.args["credential_repository"],
                  lease_lookup=lambda engagement: ("plan-1", "provider_keyed_teardown_fence"),
                  terraform_path=binary, show_runner=lambda command, cwd: shown,
                  release_validator=lambda *, environment: _release(binary))
    return kwargs, changed, calls


def test_second_provider_one_shot_after_fresh_first_absence_both_orders(saved, ready, monkeypatch):
    kwargs, changed, calls = _second_context(saved, ready, monkeypatch)
    writes = []
    def runner(command, *, scratch_path, intent_callback, started_callback,
               result_callback, **unused):
        writes.append(tuple(command))
        intent = CommandIntent("once", str(scratch_path), hashlib.sha256(json.dumps(
            command, separators=(",", ":")).encode()).hexdigest())
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity("boot", 345, 345, 1))
        started_callback(started)
        before = json.loads((scratch_path / "terraform.tfstate").read_text())
        (scratch_path / "terraform.tfstate").write_text(json.dumps({
            **before, "serial": before["serial"] + 1, "resources": []}))
        result_callback(CommandAuditResult(started, 0, 0, 0, False, False))
        return CommandResult(started, 0, "", "", False, False)
    child = run_mixed_interrupted_provider_destroy(
        **kwargs, gated_command_runner=runner)
    assert child.events[-1].message == "mixed provider awaiting exact absence"
    assert len(child.events[2].data["priorAbsenceObservationSha256"]) == 64
    assert len(child.events[2].data["priorAbsenceReceiptSha256"]) == 64
    assert len(writes) == 1
    assert len(calls) >= 8  # Fresh two-provider observations at each gate.
    source = child.input
    bound = MixedInterruptedDestroyShow(
        source["provider"], source["terraformPath"], source["terraformSha256"],
        source["planPath"], source["planSha256"], source["showSha256"],
        source["beforeStateSha256"], _digest((source["terraformPath"], "show",
                                            "-json", source["planPath"])))
    forged = list(child.events)
    forged[2] = replace(forged[2], data={**forged[2].data,
                                        "priorAbsenceReceiptSha256": "unsealed"})
    with pytest.raises(MixedInterruptedDestroyChildAttention):
        recognize_mixed_interrupted_destroy_child(
            replace(child, events=forged), kwargs["initial"], kwargs["cleanup"],
            kwargs["review"], kwargs["plans"], bound)
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        run_mixed_interrupted_provider_destroy(**kwargs, gated_command_runner=runner)
    assert len(writes) == 1


@pytest.mark.parametrize("first_kind", ["unstarted", "tag_only"])
def test_second_provider_accepts_explicit_no_plan_first_absence(
        saved, ready, monkeypatch, first_kind):
    if first_kind == "tag_only" and saved[4] != "digitalocean":
        pytest.skip("DigitalOcean selector is the tag-only scope")
    kwargs, _, calls = _second_context(saved, ready, monkeypatch, first_kind=first_kind)
    attempts = []
    def stop_after_intent(command, *, scratch_path, intent_callback, **unused):
        attempts.append(tuple(command))
        intent_callback(CommandIntent("once", str(scratch_path), hashlib.sha256(json.dumps(
            command, separators=(",", ":")).encode()).hexdigest()))
        raise RuntimeError("stop before command spawn")
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        run_mixed_interrupted_provider_destroy(
            **kwargs, gated_command_runner=stop_after_intent)
    child = ready.case.jobs.get(_child_id(
        kwargs["initial"].input["coreJobId"], kwargs["provider"]))
    assert child.events[-1].message == "mixed provider destroy command intended"
    assert len(attempts) == 1
    assert calls[0][1] == "destroy_applied"
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        run_mixed_interrupted_provider_destroy(
            **kwargs, gated_command_runner=stop_after_intent)
    assert len(attempts) == 1


@pytest.mark.parametrize("drift", ["first", "source", "uncertain_child"])
def test_second_provider_stale_or_uncertain_first_stops_before_intent(
        saved, ready, monkeypatch, drift):
    kwargs, changed, calls = _second_context(saved, ready, monkeypatch)
    if drift == "uncertain_child":
        first = kwargs["plans"].ordered_providers[0]
        child = ready.case.jobs.get(_child_id(kwargs["initial"].input["coreJobId"], first))
        ready.case.jobs.save(replace(child, events=child.events[:-1]))
    else:
        changed[drift] = True
    attempts = []
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        run_mixed_interrupted_provider_destroy(
            **kwargs, gated_command_runner=lambda *args, **kw: attempts.append(True))
    assert attempts == []
    assert ready.case.jobs.get(_child_id(
        kwargs["initial"].input["coreJobId"], kwargs["provider"])) is None


def test_second_provider_first_inventory_drift_during_show_stops_before_child(
        saved, ready, monkeypatch):
    kwargs, changed, calls = _second_context(saved, ready, monkeypatch)
    shown = kwargs["show_runner"]((), None)
    def drift_during_show(command, cwd):
        changed["first"] = True
        return shown
    attempts = []
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        run_mixed_interrupted_provider_destroy(
            **{**kwargs, "show_runner": drift_during_show},
            gated_command_runner=lambda *args, **kw: attempts.append(True))
    assert attempts == []
    assert ready.case.jobs.get(_child_id(
        kwargs["initial"].input["coreJobId"], kwargs["provider"])) is None


def test_second_provider_first_inventory_drift_after_intent_never_opens_go(
        saved, ready, monkeypatch):
    kwargs, changed, calls = _second_context(saved, ready, monkeypatch)
    opened = []
    def runner(command, *, scratch_path, intent_callback, started_callback, **unused):
        intent = CommandIntent("once", str(scratch_path), hashlib.sha256(json.dumps(
            command, separators=(",", ":")).encode()).hexdigest())
        intent_callback(intent)
        changed["first"] = True
        started_callback(StartedCommand(intent, ProcessIdentity("boot", 345, 345, 1)))
        opened.append(True)
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        run_mixed_interrupted_provider_destroy(**kwargs, gated_command_runner=runner)
    child = ready.case.jobs.get(_child_id(
        kwargs["initial"].input["coreJobId"], kwargs["provider"]))
    assert child.events[-1].message == "mixed provider destroy command intended"
    assert opened == []


def test_second_provider_result_only_restart_reproves_first_without_replay(
        saved, ready, monkeypatch):
    kwargs, changed, calls = _second_context(saved, ready, monkeypatch)
    writes = []
    def interrupted_after_result(command, *, scratch_path, intent_callback,
                                 started_callback, result_callback, **unused):
        writes.append(tuple(command))
        intent = CommandIntent("once", str(scratch_path), hashlib.sha256(json.dumps(
            command, separators=(",", ":")).encode()).hexdigest())
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity("boot", 345, 345, 1))
        started_callback(started)
        before = json.loads((scratch_path / "terraform.tfstate").read_text())
        (scratch_path / "terraform.tfstate").write_text(json.dumps({
            **before, "serial": before["serial"] + 1, "resources": []}))
        result_callback(CommandAuditResult(started, 0, 0, 0, False, False))
        raise RuntimeError("stopped after durable result")
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        run_mixed_interrupted_provider_destroy(
            **kwargs, gated_command_runner=interrupted_after_result)
    child_id = _child_id(kwargs["initial"].input["coreJobId"], kwargs["provider"])
    child = ready.case.jobs.get(child_id)
    assert child.events[-1].message == "mixed provider destroy result fenced"
    ready.case.jobs.save(replace(child, input={**child.input,
                    "claimExpiresAt": "2026-01-01T00:00:00+00:00"}))
    recovered = reconcile_mixed_interrupted_destroy_result(
        kwargs["initial"], kwargs["cleanup"], kwargs["review"], kwargs["plans"],
        kwargs["provider"], process_quiescent=lambda identity: True,
        inventory_collector=kwargs["inventory_collector"],
        job_repository=ready.case.jobs, lease_lookup=kwargs["lease_lookup"])
    assert recovered.events[-1].message == "mixed provider awaiting exact absence"
    assert len(writes) == 1
    changed["first"] = True
    with pytest.raises(MixedInterruptedDestroyGoAttention):
        reconcile_mixed_interrupted_destroy_result(
            kwargs["initial"], kwargs["cleanup"], kwargs["review"], kwargs["plans"],
            kwargs["provider"], process_quiescent=lambda identity: True,
            inventory_collector=kwargs["inventory_collector"],
            job_repository=ready.case.jobs, lease_lookup=kwargs["lease_lookup"])
