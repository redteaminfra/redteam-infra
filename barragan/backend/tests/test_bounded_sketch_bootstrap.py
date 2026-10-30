# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-cloud supervision and reconciliation fences for bootstrap commands."""
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import sketch_bootstrap_apply as bootstrap
from app.services import sketch_chains as chains
from app.services import provider_keyed_gated_runner as gated
from test_sketch_bootstrap_apply import (
    _upstream, _materializer, _chain, _Repository, _provider_job, _stored_chain,
    _retained_provider_nodes, _ChainStore, _JobStore,
)

LINUX = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux process-group proof")


def _clean_owned_test_group(identities):
    if not identities:
        return
    identity = identities[0]
    try:
        current = gated.linux_process_identity(identity.pid)
    except gated.GatedRunnerError:
        return  # Already reaped; do not signal without the identity witness.
    if current == identity:
        os.killpg(identity.pgid, signal.SIGKILL)
        os.waitpid(identity.pid, 0)


@LINUX
@pytest.mark.parametrize("code", [
    "import time; time.sleep(30)",
    "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)",
    "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)']); time.sleep(30)",
])
def test_legacy_deadline_cancels_whole_group_bounded(monkeypatch, tmp_path, code):
    monkeypatch.setattr(bootstrap, "BOOTSTRAP_COMMAND_TIMEOUT_SECONDS", 0.25)
    identities = []
    reader = bootstrap.linux_process_identity
    monkeypatch.setattr(bootstrap, "linux_process_identity", lambda pid: (identities.append(reader(pid)), identities[-1])[1])
    started = time.monotonic()
    try:
        with pytest.raises(bootstrap.SketchBootstrapTimeoutError):
            bootstrap._run_command([sys.executable, "-c", code], tmp_path, os.environ)
        assert time.monotonic() - started < 3
        with pytest.raises(gated.GatedRunnerError):
            reader(identities[0].pid)  # leader was reaped only after group cancellation
    finally:
        _clean_owned_test_group(identities)


@LINUX
def test_legacy_exited_leader_pipe_holder_is_bounded_reconciliation(monkeypatch, tmp_path):
    monkeypatch.setattr(bootstrap, "BOOTSTRAP_COMMAND_TIMEOUT_SECONDS", 10)
    code = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])"
    identities = []
    reader = bootstrap.linux_process_identity
    monkeypatch.setattr(bootstrap, "linux_process_identity", lambda pid: (identities.append(reader(pid)), identities[-1])[1])
    started = time.monotonic()
    try:
        with pytest.raises(bootstrap.SketchBootstrapReconciliationRequiredError) as error:
            bootstrap._run_command([sys.executable, "-c", code], tmp_path, os.environ)
        assert not isinstance(error.value, bootstrap.SketchBootstrapTimeoutError)
        assert time.monotonic() - started < 3
    finally:
        _clean_owned_test_group(identities)


@LINUX
def test_legacy_identity_loss_is_unproved_without_unsafe_signal(monkeypatch, tmp_path):
    monkeypatch.setattr(bootstrap, "BOOTSTRAP_COMMAND_TIMEOUT_SECONDS", 0.1)
    identities = []
    reader = bootstrap.linux_process_identity
    def lost(pid):
        if not identities:
            identities.append(reader(pid))
            return identities[0]
        raise gated.GatedRunnerError("identity unavailable")
    monkeypatch.setattr(bootstrap, "linux_process_identity", lost)
    started = time.monotonic()
    try:
        with pytest.raises(bootstrap.SketchBootstrapQuiescenceUnprovedError):
            bootstrap._run_command([sys.executable, "-c", "import time; time.sleep(30)"], tmp_path, os.environ)
        assert time.monotonic() - started < 2
    finally:
        _clean_owned_test_group(identities)


@LINUX
def test_legacy_normal_nonzero_preserves_bounded_output(monkeypatch, tmp_path):
    monkeypatch.setattr(bootstrap, "BOOTSTRAP_COMMAND_TIMEOUT_SECONDS", 5)
    result = bootstrap._run_command([sys.executable, "-c", "import sys; print('x'*100000); print('failure',file=sys.stderr); sys.exit(7)"], tmp_path, os.environ)
    assert result.returncode == 7
    assert len(result.stdout) <= 65536
    assert result.stderr.strip() == "failure"


@LINUX
def test_gated_deadline_records_one_terminal_audit_before_typed_timeout(tmp_path):
    events = []
    started = time.monotonic()
    with pytest.raises(gated.GatedCommandTimeoutError):
        gated.run_gated_command(
            [sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)"],
            scratch_path=tmp_path.resolve(), provider_keyed_v2=True,
            intent_callback=lambda value: events.append(("intent", value)),
            started_callback=lambda value: events.append(("started", value)),
            heartbeat_callback=lambda value: None,
            result_callback=lambda value: events.append(("result", value)),
            execution_timeout_seconds=0.25,
        )
    assert time.monotonic() - started < 3
    assert [kind for kind, _ in events] == ["intent", "started", "result"]
    assert events[-1][1].timed_out is True
    assert events[-1][1].execution_timeout_seconds == 0.25
    assert 0.25 <= events[-1][1].command_elapsed_seconds < 3
    assert events[-1][1].returncode < 0


@pytest.mark.parametrize("error_type,retained", [
    (bootstrap.SketchBootstrapTimeoutError, False),
    (bootstrap.SketchBootstrapQuiescenceUnprovedError, True),
    (gated.UnreapedGatedCommandError, True),
    (gated.GatedCommandTimeoutError, False),
])
def test_apply_never_retries_uncertain_command_and_retains_material_when_unproved(monkeypatch, tmp_path, error_type, retained):
    monkeypatch.setattr(bootstrap, "resolve_redteam_infra_template_source", lambda **_: _upstream(tmp_path))
    monkeypatch.setattr(bootstrap, "resolve_ansible_playbook", lambda **_: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(bootstrap, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(bootstrap, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    calls = []
    def runner(command, cwd, env):
        calls.append((command, env["ANSIBLE_SSH_CONTROL_PATH_DIR"]))
        raise error_type("unsafe command detail")
    expected = bootstrap.SketchBootstrapTimeoutError if error_type is gated.GatedCommandTimeoutError else error_type
    with pytest.raises(expected):
        bootstrap.apply_sketch_bootstrap("eng-test", _chain(), repository=_Repository(),
                                         runner=runner, workspace_root=tmp_path / "workspace")
    assert len(calls) == 1
    assert (tmp_path / "workspace" / "keys").exists() is retained
    assert Path(calls[0][1]).exists() is retained
    if retained:
        shutil.rmtree(Path(calls[0][1]))  # Exact fake fixture socket directory only.


@pytest.mark.parametrize("error_type,timed_out,unproved", [
    (bootstrap.SketchBootstrapTimeoutError, True, False),
    (bootstrap.SketchBootstrapQuiescenceUnprovedError, False, True),
    (bootstrap.SketchBootstrapReconciliationRequiredError, False, False),
])
def test_legacy_uncertainty_terminal_keeps_provider_identity_and_blocks_historical_retry(monkeypatch, error_type, timed_out, unproved):
    job = _provider_job()
    job = replace(job, events=job.events + [JobEvent(2, "error", "old failure", {"bootstrap": "failed"})])
    chain = replace(_stored_chain(job.id), status="failed", nodes=_retained_provider_nodes())
    jobs, repo = _JobStore(job), _ChainStore(chain)
    # Simulate a prior retry whose old failure event must not restore eligibility.
    jobs.current = replace(job, status="running", events=job.events + [JobEvent(3, "info", "retry", {"bootstrap": "retrying"})])
    def failed(*args, **kwargs):
        raise error_type("private command data")
    monkeypatch.setattr(chains, "apply_sketch_bootstrap", failed)
    monkeypatch.setattr(chains, "SqlAlchemyJobRepository", lambda: jobs)
    monkeypatch.setattr(chains, "get_engagement", lambda _: SimpleNamespace(sketch_state_schema="split-v1"))
    chains._bootstrap_provider_job("eng-test", chain.chain_id, repo, jobs)
    assert jobs.current.status == "failed"
    assert jobs.current.input == job.input
    assert repo.chain.nodes == chain.nodes
    assert repo.chain.deploy_job_id == chain.deploy_job_id
    terminal = jobs.current.events[-1]
    assert terminal.data == {"bootstrap": "reconciliation_required", "timedOut": timed_out,
                             "localQuiescenceUnproved": unproved}
    assert "private" not in terminal.message
    assert not chains._failed_bootstrap_job(jobs.current)
    assert not chains._bootstrap_can_run(jobs.current)
    for retry_body in ({}, {"retryBootstrapOnly": True}):
        with pytest.raises(chains.SketchChainValidationError, match="sketch chain validation"):
            chains.deploy_sketch_chain("eng-test", chain.chain_id, retry_body, repository=repo)
    if unproved:
        with pytest.raises(chains.SketchChainValidationError):
            chains.teardown_sketch_chain("eng-test", chain.chain_id, {"confirmation": f"teardown-{chain.chain_id}"}, repository=repo)
        with pytest.raises(chains.SketchChainValidationError):
            chains.ensure_sketch_chain_teardown("eng-test", chain.chain_id, {}, repository=repo, job_repository=jobs)
    else:
        chains._require_bootstrap_reconciled(jobs.current, teardown=True)


@LINUX
def test_gated_deadline_identity_loss_preserves_unreaped_error_and_emits_no_result(tmp_path):
    identities, results = [], []
    def reader(pid):
        if not identities:
            identities.append(gated.linux_process_identity(pid))
            return identities[0]
        raise gated.GatedRunnerError("identity unavailable")
    started = time.monotonic()
    try:
        with pytest.raises(gated.UnreapedGatedCommandError):
            gated.run_gated_command(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                scratch_path=tmp_path.resolve(), provider_keyed_v2=True,
                intent_callback=lambda _: None, started_callback=lambda _: None,
                heartbeat_callback=lambda _: None, result_callback=results.append,
                identity_reader=reader, execution_timeout_seconds=0.1,
            )
        assert results == []
        assert time.monotonic() - started < 2
    finally:
        _clean_owned_test_group(identities)


def test_legacy_spawn_failure_is_typed_terminal_error(monkeypatch, tmp_path):
    monkeypatch.setattr(bootstrap.sys, "platform", "linux")
    def missing(*args, **kwargs):
        raise OSError("private startup details")
    monkeypatch.setattr(bootstrap.subprocess, "Popen", missing)
    with pytest.raises(bootstrap.SketchBootstrapApplyError, match="could not start") as error:
        bootstrap._run_command(["missing"], tmp_path, {})
    assert "private" not in str(error.value)
