# Copyright (c) 2026, Oracle and/or its affiliates.
"""Mixed destroy planning seals both scopes from one claimed attempt."""

from pathlib import Path
from types import SimpleNamespace
from dataclasses import replace
import hashlib
import json
from datetime import datetime, timedelta

import pytest

import app.services.provider_keyed_mixed_interrupted_plan_worker as worker
from app.domain import JobEvent
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.models import CoreMutationLeaseModel, DeploymentPlanModel, EngagementModel
from app.services.provider_keyed_mixed_interrupted_cleanup import propose_mixed_interrupted_cleanup
from app.services.provider_keyed_mixed_interrupted_source import review_mixed_interrupted_source
from app.services.provider_keyed_mixed_interrupted_source import MixedInterruptedProviderScope
from app.services.provider_keyed_mixed_partial_apply_source import _state
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_mixed_interrupted_dispatch import _workspace
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_interrupted_source import _snapshot
from test_provider_keyed_mixed_initial_apply_proof import _state_and_rows


def _case(ready, tmp_path, monkeypatch):
    initial = ready.parent
    jobs = ready.case.jobs
    order = tuple(initial.input["orderedProviders"])
    review = review_mixed_interrupted_source(
        initial, {provider: None for provider in order},
        {provider: _snapshot(provider, generation="stable") for provider in order},
        fence=lambda: "stable", process_quiescent=lambda identity: True,
    )
    parent = propose_mixed_interrupted_cleanup(initial, review, requested_by="operator")
    jobs.save(parent)
    monkeypatch.setattr(worker, "review_mixed_interrupted_source",
                        lambda *args, **kwargs: review)
    monkeypatch.setattr(worker, "_default_state_root", lambda: ready.case.state_root)
    terraform = tmp_path / "terraform"
    terraform.write_bytes(b"pinned")
    terraform.chmod(0o755)
    monkeypatch.setattr(worker, "require_devtest_terraform_release", lambda **_: SimpleNamespace(
        path=terraform, sha256=hashlib.sha256(b"pinned").hexdigest(),
        version="1.15.5", platform="linux_amd64"))
    calls = []
    def seal(*args, **kwargs):
        assert set(kwargs["plan_paths"]) == set(order)
        assert all(value is None for value in kwargs["plan_paths"].values())
        assert all(value is None for value in kwargs["show_json"].values())
        calls.append("seal")
        return parent
    monkeypatch.setattr(worker, "seal_mixed_interrupted_cleanup_plans", seal)
    kwargs = dict(environment="devtest", state_root=ready.case.state_root,
                  job_repository=jobs,
                  lease_lookup=lambda _: (initial.input["corePlanId"],
                                          "provider_keyed_teardown_fence"),
                  snapshot_collector=lambda initial, provider, workspace, *, fence, **kwargs:
                      _snapshot(provider, generation=fence()),
                  plan_producer=lambda *a, **k: pytest.fail("absence-only scope cannot plan"))
    return initial, parent, kwargs, calls


def test_absence_only_both_orders_claim_once_and_seal(ready, tmp_path, monkeypatch):
    initial, parent, kwargs, calls = _case(ready, tmp_path, monkeypatch)
    result = worker.prepare_mixed_interrupted_destroy_plans(
        initial.target_id, initial.input["coreJobId"], **kwargs)
    assert result == parent and calls == ["seal"]
    child = ready.case.jobs.get(worker._job_id(initial.input["coreJobId"]))
    assert child.status == "succeeded"
    assert child.events[-1].message == "both mixed destroy plans saved"
    assert all(row["planPath"] is None for row in child.events[-1].data["providers"])
    # A completed receipt may resume the parent CAS, with no new commands.
    result = worker.prepare_mixed_interrupted_destroy_plans(
        initial.target_id, initial.input["coreJobId"], **kwargs)
    assert result == parent and calls == ["seal", "seal"]


def test_wrong_environment_does_not_reserve_worker(ready, tmp_path, monkeypatch):
    initial, _parent, kwargs, _calls = _case(ready, tmp_path, monkeypatch)
    with pytest.raises(worker.MixedInterruptedPlanWorkerAttention):
        worker.prepare_mixed_interrupted_destroy_plans(
            initial.target_id, initial.input["coreJobId"],
            **{**kwargs, "environment": "prod"})
    assert ready.case.jobs.get(worker._job_id(initial.input["coreJobId"])) is None


def test_expired_running_claim_resumes_without_new_worker(ready, tmp_path, monkeypatch):
    initial, parent, kwargs, calls = _case(ready, tmp_path, monkeypatch)
    original_later = worker._later
    monkeypatch.setattr(worker, "_later", lambda at: (
        datetime.fromisoformat(at) - timedelta(seconds=1)).isoformat())
    def interrupted_snapshot(*args, **kwargs):
        raise RuntimeError("inventory response lost")
    with pytest.raises(worker.MixedInterruptedPlanWorkerAttention):
        worker.prepare_mixed_interrupted_destroy_plans(
            initial.target_id, initial.input["coreJobId"],
            **{**kwargs, "snapshot_collector": interrupted_snapshot})
    child_id = worker._job_id(initial.input["coreJobId"])
    interrupted = ready.case.jobs.get(child_id)
    assert interrupted.status == "running" and len(interrupted.events) == 2
    monkeypatch.setattr(worker, "_later", original_later)
    result = worker.prepare_mixed_interrupted_destroy_plans(
        initial.target_id, initial.input["coreJobId"], **kwargs)
    assert result == parent and calls == ["seal"]
    finished = ready.case.jobs.get(child_id)
    assert finished.status == "succeeded" and len(finished.events) == 3


def _queued(initial, parent, review):
    core_id = initial.input["coreJobId"]
    return StoredJobRun(
        worker._job_id(core_id), worker.ACTION, "queued", f"engagement:{initial.target_id}",
        "engagement", initial.target_id, parent.requested_by,
        {"engagementId": initial.target_id, "coreJobId": core_id,
         "corePlanId": parent.input["corePlanId"], "cleanupParentId": parent.id,
         "reviewSha256": review.review_sha256, "mutation": False}, [],
        "2026-10-16T00:00:00+00:00", None, None,
        [JobEvent(1, "info", "mixed destroy planning queued", {})],
    )


def test_pristine_queued_worker_resumes_after_insert_crash(ready, tmp_path, monkeypatch):
    initial, parent, kwargs, calls = _case(ready, tmp_path, monkeypatch)
    queued = _queued(initial, parent, worker._saved_review(parent))
    ready.case.jobs.save(queued)
    assert worker.prepare_mixed_interrupted_destroy_plans(
        initial.target_id, initial.input["coreJobId"], **kwargs) == parent
    assert calls == ["seal"]
    finished = ready.case.jobs.get(queued.id)
    assert finished.status == "succeeded"
    assert [event.sequence for event in finished.events] == [1, 2, 3]


@pytest.mark.parametrize("artifact", ["journal", "plan"])
def test_queued_worker_with_destroy_artifact_cannot_resume(
        ready, tmp_path, monkeypatch, artifact):
    initial, parent, kwargs, calls = _case(ready, tmp_path, monkeypatch)
    review = worker._saved_review(parent)
    queued = _queued(initial, parent, review)
    ready.case.jobs.save(queued)
    provider = review.ordered_providers[0]
    root = _workspace(initial, provider, ready.case.state_root).path
    suffix = "journal.jsonl" if artifact == "journal" else "tfplan"
    (root / f".barragan-mixed-interrupted-destroy-{provider}.{suffix}").write_bytes(b"artifact")
    with pytest.raises(worker.MixedInterruptedPlanWorkerAttention):
        worker.prepare_mixed_interrupted_destroy_plans(
            initial.target_id, initial.input["coreJobId"], **kwargs)
    assert ready.case.jobs.get(queued.id).status == "queued" and calls == []


def test_sqlalchemy_sqlite_round_trip_starts_exact_queued_worker(
        ready, tmp_path, monkeypatch, client):
    initial, parent, kwargs, calls = _case(ready, tmp_path, monkeypatch)
    with client.application.storage_context():
        jobs = SqlAlchemyJobRepository()
        db.session.add(EngagementModel(
            id=initial.target_id, name="opaque-fixture", status="deployed",
            owner="operator", template_id="small", input_parameters={}))
        db.session.add(DeploymentPlanModel(
            id=parent.input["corePlanId"], engagement_id=initial.target_id,
            revision_id="rev-1", status="applied", stage="applied",
            apply_job_id=initial.input["coreJobId"]))
        db.session.add(CoreMutationLeaseModel(
            engagement_id=initial.target_id, owner_id=parent.input["corePlanId"],
            operation="provider_keyed_teardown_fence"))
        db.session.commit()
        timestamp = "2026-10-16T00:00:00+00:00"
        for row in ready.case.jobs.list():
            jobs.save(replace(row,
                created_at=timestamp if row.created_at == "now" else row.created_at,
                started_at=timestamp if row.started_at == "now" else row.started_at,
                finished_at=timestamp if row.finished_at == "now" else row.finished_at))
        result = worker.prepare_mixed_interrupted_destroy_plans(
            initial.target_id, initial.input["coreJobId"],
            **{**kwargs, "job_repository": jobs})
        assert result.id == parent.id and calls == ["seal"]
        child = jobs.get(worker._job_id(initial.input["coreJobId"]))
        assert child.status == "succeeded"
        assert [event.sequence for event in child.events] == [1, 2, 3]


@pytest.mark.parametrize("final_policy", [False, True])
@pytest.mark.parametrize("show_response_lost", [False, True])
@pytest.mark.parametrize("source_drift_before_plan", [False, True])
def test_state_backed_scope_saves_one_exact_plan_and_resumes_read_only_show(
        ready, tmp_path, monkeypatch, show_response_lost, source_drift_before_plan, final_policy):
    initial = ready.parent
    provider = initial.input["orderedProviders"][0]
    policy = initial.events[5].data["reviewedPolicy"][provider]
    workspace = _workspace(initial, provider, ready.case.state_root)
    lock_path = workspace.path / f".barragan-{provider}-plan.lock"
    lock_path.write_bytes(b"")
    lock_path.chmod(0o600)
    material = workspace.path.parents[1] / ".plan-material" / provider
    material.mkdir(parents=True, exist_ok=True)
    (material / "inputs.json").write_text(json.dumps({
        **policy["nonsecret_varfile"],
        "ssh_pub_key_path": str(material / "admin-public"),
        "ssh_priv_key_path": str(material / "admin-private"),
        "ssh_config_path": str(material / "ssh-output"),
    }, sort_keys=True) + "\n")
    initial_inputs = (material / "inputs.json").read_bytes()
    drift = {"changed": False}
    def source_gate(workspace):
        if drift["changed"]:
            raise ValueError("rendered Terraform source changed")
    monkeypatch.setattr(worker, "require_linode_workspace", source_gate)
    monkeypatch.setattr(worker, "require_do_workspace", source_gate)
    state, _, _, _ = _state_and_rows(provider, policy)
    raw = json.dumps(state).encode()
    workspace.state_path.write_bytes(raw)
    _, attributes, cloud = _state(provider, policy, raw)
    scope = MixedInterruptedProviderScope(
        provider, "full", "b" * 64, hashlib.sha256(raw).hexdigest(),
        state["lineage"], state["serial"], tuple(sorted(cloud.items())),
        "c" * 64, "d" * 64, policy.get("selector_tag"), provider == "digitalocean")
    terraform = tmp_path / "terraform"
    terraform.write_bytes(b"pinned")
    terraform.chmod(0o755)
    release = SimpleNamespace(path=terraform, sha256=hashlib.sha256(b"pinned").hexdigest())
    credentials = SimpleNamespace()
    monkeypatch.setattr(worker, "_credential", lambda *a: "token")
    monkeypatch.setattr(worker, "retrieve_sketch_ssh_key",
                        lambda *a: SimpleNamespace(public_key=policy["admin_public_key"],
                                                   private_key="private-key"))
    shown = json.dumps({
        "format_version": "1.2", "terraform_version": "1.15.5",
        "applyable": True, "complete": True, "errored": False,
        "resource_changes": [{"address": address, "change": {
            "actions": ["delete"], "before": attrs, "after": None,
            "after_unknown": {}}} for address, attrs in attributes.items()],
        "prior_state": {"values": {"root_module": {"resources": [
            {"address": address, "mode": "managed", "values": attrs}
            for address, attrs in attributes.items()]}}},
        "output_changes": {}, "planned_values": {"root_module": {}},
    })
    commands = []
    def gated(argv, *, scratch_path, provider_keyed_v2, env, max_output_bytes,
              intent_callback, started_callback, heartbeat_callback, result_callback):
        phase = argv[1]
        commands.append(phase)
        invocation = f"command-{len(commands)}"
        digest = hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest()
        intent = CommandIntent(invocation, str(scratch_path), digest)
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity("boot", 100, 100, 1))
        started_callback(started)
        heartbeat_callback(started)
        if phase == "plan":
            if final_policy:
                input_path = Path(next(arg.split("=", 1)[1] for arg in argv if arg.startswith("-var-file=")))
                assert input_path.parent.name.startswith(".barragan-published-destroy-material-")
                assert json.loads(input_path.read_bytes())["generate_inventory"] is False
                assert (material / "inputs.json").read_bytes() == initial_inputs
                assert not (input_path.stat().st_mode & 0o077)
            Path(next(arg.split("=", 1)[1] for arg in argv if arg.startswith("-out="))).write_bytes(b"plan")
        if phase == "show" and show_response_lost and commands.count("show") == 1:
            raise RuntimeError("show response lost after process start")
        stdout = ({"version": json.dumps({"terraform_version": "1.15.5"}),
                   "init": "ok", "plan": "ok", "show": shown})[phase]
        result_callback(CommandAuditResult(started, 0, len(stdout), 0, False, False))
        if phase == "init" and source_drift_before_plan:
            drift["changed"] = True
        return CommandResult(started, 0, stdout, "", False, False)
    args = dict(credentials=credentials, sketch_keys=None, release=release,
                fence=lambda: None, source_recheck=lambda: None,
                gated_command_runner=gated, command_environment={},
                process_quiescent=lambda identity: True)
    if final_policy:
        final = json.loads(json.dumps(policy))
        final["nonsecret_varfile"]["generate_inventory"] = False
        args.update(plan_variant="published", reviewed_policy=final)
    if source_drift_before_plan:
        with pytest.raises(ValueError, match="source changed"):
            worker._produce_state_backed_plan(provider, scope, initial, workspace, **args)
        assert commands == ["version", "init"]
        assert not (workspace.path / f".barragan-mixed-interrupted-destroy-{provider}.tfplan").exists()
        return
    if show_response_lost:
        with pytest.raises(RuntimeError):
            worker._produce_state_backed_plan(provider, scope, initial, workspace, **args)
        assert commands == ["version", "init", "plan", "show"]
    else:
        path, output = worker._produce_state_backed_plan(provider, scope, initial,
                                                           workspace, **args)
        assert output == shown and path.read_bytes() == b"plan"
    assert commands == ["version", "init", "plan", "show"]
    resumed_path, resumed_show = worker._produce_state_backed_plan(
        provider, scope, initial, workspace, **args)
    assert resumed_show == shown and resumed_path.read_bytes() == b"plan"
    assert commands == ["version", "init", "plan", "show", "show"]
    workspace.state_path.write_bytes(raw + b"\n")
    with pytest.raises(ValueError):
        worker._produce_state_backed_plan(
            provider, scope, initial, workspace, **args)
    assert commands == ["version", "init", "plan", "show", "show"]
