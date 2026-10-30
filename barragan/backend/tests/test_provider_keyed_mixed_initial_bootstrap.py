# Copyright (c) 2026, Oracle and/or its affiliates.
"""Mixed bootstrap is one-shot and journals every local command boundary."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.services.provider_keyed_mixed_initial_bootstrap as bootstrap_service
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_mixed_initial_bootstrap import (
    MixedInitialBootstrapAttention, run_mixed_initial_bootstrap,
)
from app.services.provider_keyed_mixed_initial_host_binding import reserve_mixed_initial_host_binding
from app.services.redteam_infra_template import TEMPLATE_ROOT_ENV
from app.services.sketch_bootstrap_apply import SketchBootstrapApplyResult
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_host_binding import _prepared
from test_provider_keyed_mixed_initial_plan_parent import case


def _inputs(ready, tmp_path, *, inert_history=False):
    checkpoint, _children, chains, observations = _prepared(ready)
    if inert_history:
        ghost = replace(next(iter(chains.values())), chain_id="old-default",
            status="aborted", deploy_job_id="", teardown_job_id="",
            terraform_working_directory="", nodes=[])
        chains[ghost.chain_id] = ghost
    sketches = SimpleNamespace(list_for_engagement=lambda _: list(chains.values()))
    def observer(parent, provider, fence):
        fence()
        return observations[provider]
    binding = reserve_mixed_initial_host_binding(
        "eng-opaque", "job-core", environment="devtest", fresh_observer=observer,
        job_repository=ready.case.jobs, sketch_repository=sketches,
        lease_lookup=ready.case.args["lease_lookup"])
    calls = []
    state = {"interrupt": False}

    def gate(command, *, scratch_path, provider_keyed_v2, env,
             intent_callback, started_callback, heartbeat_callback, result_callback, execution_timeout_seconds):
        assert execution_timeout_seconds == 1800
        assert provider_keyed_v2 is True and isinstance(env, dict)
        intent = CommandIntent("invocation-" + str(len(calls)), str(scratch_path), "a" * 64)
        intent_callback(intent)
        calls.append(("intent", command[-1]))
        if state["interrupt"]:
            raise RuntimeError("injected command interruption")
        started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 99))
        started_callback(started)
        heartbeat_callback(started)
        receipt = CommandAuditResult(started, 0, 4, 0, False, False,
                                     execution_timeout_seconds=1800, command_elapsed_seconds=0.25)
        result_callback(receipt)
        return CommandResult(started, 0, "done", "", False, False)

    def bootstrap(engagement_id, chain, *, repository, env, workspace_root,
                  host_policies, proxy_egress_ip, initial_sketch_known_hosts_path,
                  pinned_core_known_hosts_path, progress_reporter, runner,
                  required_source_root, required_source_revision):
        assert engagement_id == "eng-opaque" and chain.middle_provider == chain.edge_provider
        assert len(chain.nodes) == 2 and len(host_policies) == 2
        assert proxy_egress_ip == "8.8.8.8"
        workspace_root.mkdir(mode=0o700)
        workspace_root.chmod(0o700)
        progress_reporter("checking", {"phase": "root-management-readiness"})
        for path in ("wait_for_sketch_readiness.yml", "upstream-sketch-playbook.compat.yml",
                     "wait_for_sketch_user_readiness.yml", "install_sketch_transport.yml"):
            result = runner(["ansible-playbook", path], workspace_root, env)
            assert result.returncode == 0
        calls.append(("chain", chain.middle_provider))
        return SketchBootstrapApplyResult(0, 0, 2, 0)

    args = dict(engagement_id="eng-opaque", core_job_id="job-core", environment="devtest",
                fresh_observer=observer,
                bootstrap_env={TEMPLATE_ROOT_ENV: str(ready.case.args["template_root"])},
                job_repository=ready.case.jobs, sketch_repository=sketches,
                lease_lookup=ready.case.args["lease_lookup"],
                bootstrap_helper=bootstrap, gated_command_runner=gate,
                source_verifier=lambda **_: ready.case.args["template_root"],
                core_known_hosts_reader=lambda _: (str(tmp_path / "core-known-hosts"), "a" * 64),
                sketch_known_hosts_initializer=lambda *_args, **_kwargs: None)
    return checkpoint, binding, args, calls, state


@pytest.mark.parametrize("inert_history", [False, True])
def test_both_orders_complete_one_shot_upstream_bootstrap(ready, tmp_path, inert_history):
    checkpoint, binding, args, calls, state = _inputs(ready, tmp_path, inert_history=inert_history)
    finished = run_mixed_initial_bootstrap(**args)
    assert finished.status == "succeeded"
    assert finished.events[-1].message == "mixed bootstrap completed; strict raw proof pending"
    assert [value for kind, value in calls if kind == "chain"] == checkpoint.input["orderedProviders"]
    assert len([value for kind, value in calls if kind == "intent"]) == 8
    assert sum(event.message == "mixed bootstrap command intended" for event in finished.events) == 8
    assert sum(event.message == "mixed bootstrap command started before GO" for event in finished.events) == 8
    assert sum(event.message == "mixed bootstrap command result fenced" for event in finished.events) == 8
    with pytest.raises(MixedInitialBootstrapAttention):
        run_mixed_initial_bootstrap(**args)
    assert len([value for kind, value in calls if kind == "intent"]) == 8


def test_interrupted_command_journal_cannot_replay(ready, tmp_path):
    checkpoint, binding, args, calls, state = _inputs(ready, tmp_path)
    state["interrupt"] = True
    with pytest.raises(MixedInitialBootstrapAttention):
        run_mixed_initial_bootstrap(**args)
    assert len([value for kind, value in calls if kind == "intent"]) == 1
    with pytest.raises(MixedInitialBootstrapAttention):
        run_mixed_initial_bootstrap(**args)
    assert len([value for kind, value in calls if kind == "intent"]) == 1


def test_active_core_drift_before_contact_never_reserves_worker(ready, tmp_path, monkeypatch):
    checkpoint, binding, args, calls, state = _inputs(ready, tmp_path)
    pointer = {"id": "job-core"}
    monkeypatch.setattr(bootstrap_service, "active_core_connection_details",
                        lambda jobs, engagement_id: (pointer["id"], {}))
    seen = []
    original = args["fresh_observer"]

    def drift(parent, provider, fence):
        seen.append(provider)
        result = original(parent, provider, fence)
        pointer["id"] = "job-foreign-core"
        return result

    with pytest.raises(MixedInitialBootstrapAttention):
        run_mixed_initial_bootstrap(**{**args, "fresh_observer": drift})
    assert seen == [checkpoint.input["orderedProviders"][0]]
    assert ready.case.jobs.get("job-provider-keyed-mixed-host-worker-core") is None
    assert calls == []


@pytest.mark.parametrize("changed_field", ["path", "digest"])
def test_core_known_hosts_drift_before_first_command_blocks_contact(
        ready, tmp_path, changed_field):
    _checkpoint, _binding, args, calls, _state = _inputs(ready, tmp_path)
    pinned = (str(tmp_path / "core-known-hosts"), "a" * 64)
    observed = {"path": pinned[0], "digest": pinned[1]}
    args["core_known_hosts_reader"] = lambda _core: (observed["path"], observed["digest"])

    def change_after_worker_reservation(*_args, **_kwargs):
        observed[changed_field] = (str(tmp_path / "other-known-hosts")
                                   if changed_field == "path" else "b" * 64)

    args["sketch_known_hosts_initializer"] = change_after_worker_reservation
    with pytest.raises(MixedInitialBootstrapAttention):
        run_mixed_initial_bootstrap(**args)
    assert not [entry for entry in calls if entry[0] == "intent"]
    worker = ready.case.jobs.get("job-provider-keyed-mixed-host-worker-core")
    assert worker is not None and worker.status == "running"


def test_core_known_hosts_drift_before_second_command_blocks_replay(ready, tmp_path):
    _checkpoint, _binding, args, calls, _state = _inputs(ready, tmp_path)
    pinned = (str(tmp_path / "core-known-hosts"), "a" * 64)
    digest = {"value": pinned[1]}
    args["core_known_hosts_reader"] = lambda _core: (pinned[0], digest["value"])
    gate = args["gated_command_runner"]

    def change_after_first_command(*gate_args, **gate_kwargs):
        result = gate(*gate_args, **gate_kwargs)
        digest["value"] = "b" * 64
        return result

    args["gated_command_runner"] = change_after_first_command
    with pytest.raises(MixedInitialBootstrapAttention):
        run_mixed_initial_bootstrap(**args)
    assert len([entry for entry in calls if entry[0] == "intent"]) == 1
    assert not [entry for entry in calls if entry[0] == "chain"]


def test_timeout_records_attention_and_never_replays(ready, tmp_path):
    from app.services.sketch_bootstrap_apply import SketchBootstrapTimeoutError
    checkpoint, binding, args, calls, state = _inputs(ready, tmp_path)
    attempts = []
    def timeout(*args, **kwargs):
        attempts.append(True)
        raise SketchBootstrapTimeoutError("local bootstrap execution timed out")
    args["bootstrap_helper"] = timeout
    with pytest.raises(MixedInitialBootstrapAttention, match="timed out"):
        run_mixed_initial_bootstrap(**args)
    with pytest.raises(MixedInitialBootstrapAttention):
        run_mixed_initial_bootstrap(**args)
    assert attempts == [True]


def test_zero_exit_with_timed_out_audit_cannot_complete_or_replay(ready, tmp_path):
    checkpoint, binding, args, calls, state = _inputs(ready, tmp_path)
    gate = args["gated_command_runner"]
    def contradictory(command, **kwargs):
        callback = kwargs["result_callback"]
        kwargs["result_callback"] = lambda value: callback(replace(value, timed_out=True))
        return gate(command, **kwargs)
    args["gated_command_runner"] = contradictory
    with pytest.raises(MixedInitialBootstrapAttention):
        run_mixed_initial_bootstrap(**args)
    assert len([value for kind, value in calls if kind == "intent"]) == 1
    with pytest.raises(MixedInitialBootstrapAttention):
        run_mixed_initial_bootstrap(**args)
    assert len([value for kind, value in calls if kind == "intent"]) == 1
