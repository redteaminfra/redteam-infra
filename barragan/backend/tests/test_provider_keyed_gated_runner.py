# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network process supervision tests for the dormant v2 bootstrap caller."""

import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from app.services import provider_keyed_gated_runner as gated
from app.services.provider_keyed_gate_child import __file__ as CHILD_PATH
from app.services.provider_keyed_gated_runner import (
    GatedRunnerError, ProcessIdentity, UnreapedGatedCommandError,
    linux_process_identity, run_gated_command,
)


def _identity(pid):
    return ProcessIdentity("test-boot", pid, pid, 12345)


def _run(tmp_path, code, **kwargs):
    events = []
    result = run_gated_command(
        [sys.executable, "-c", code], scratch_path=tmp_path,
        intent_callback=lambda value: events.append(("intent", value)),
        started_callback=lambda value: events.append(("started", value)),
        heartbeat_callback=lambda value: events.append(("heartbeat", value)),
        result_callback=lambda value: events.append(("result", value)),
        provider_keyed_v2=True, identity_reader=_identity,
        group_members_reader=lambda _identity: set(), heartbeat_interval=0.05,
        **kwargs,
    )
    return result, events


def test_intent_precedes_spawn_and_started_identity_precedes_exec(tmp_path):
    marker = tmp_path / "executed"
    events = []
    def intent(value):
        assert not marker.exists()
        events.append(("intent", value))
    def started(value):
        assert not marker.exists()
        assert value.identity.pid == value.identity.pgid
        events.append(("started", value))
    result = run_gated_command(
        [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).write_text('done')"],
        scratch_path=tmp_path, intent_callback=intent, started_callback=started,
        heartbeat_callback=lambda value: events.append(("heartbeat", value)),
        result_callback=lambda value: events.append(("result", value)),
        provider_keyed_v2=True, identity_reader=_identity,
        group_members_reader=lambda _identity: set(), heartbeat_interval=0.05,
    )
    assert marker.read_text() == "done" and result.returncode == 0
    assert [event[0] for event in events][0:2] == ["intent", "started"]
    assert events[-1][0] == "result"
    assert result.started.intent.argv_sha256 and str(marker) not in repr(result.started.intent)


@pytest.mark.parametrize("failed_callback", ["intent", "started"])
def test_callback_failure_before_go_never_executes(tmp_path, failed_callback):
    marker = tmp_path / "must-not-exist"
    callbacks = []
    def intent(value):
        callbacks.append("intent")
        if failed_callback == "intent":
            raise RuntimeError("lost authority")
    def started(value):
        callbacks.append("started")
        if failed_callback == "started":
            raise RuntimeError("lost authority")
    with pytest.raises(GatedRunnerError):
        run_gated_command(
            [sys.executable, "-c", f"open({str(marker)!r}, 'w').write('bad')"],
            scratch_path=tmp_path, intent_callback=intent, started_callback=started,
            heartbeat_callback=lambda _value: None, result_callback=lambda _value: None,
            provider_keyed_v2=True, identity_reader=_identity,
            group_members_reader=lambda _identity: set(),
        )
    assert callbacks == (["intent"] if failed_callback == "intent" else ["intent", "started"])
    assert not marker.exists()


def test_sealed_apply_start_without_go_support_never_executes(tmp_path):
    """An eight-event-style Apply start is not evidence of a Terraform GO."""
    marker = tmp_path / "must-not-exist-after-pre-go-veto"
    journal = ["show-result", "prestate", "apply-intent"]

    def started(_value):
        journal.append("apply-started")
        assert not marker.exists()
        raise ValueError("read-only provider proof vetoed GO")

    with pytest.raises(GatedRunnerError):
        run_gated_command(
            [sys.executable, "-c", f"open({str(marker)!r}, 'w').write('executed')"],
            scratch_path=tmp_path,
            intent_callback=lambda _value: None,
            started_callback=started,
            heartbeat_callback=lambda _value: pytest.fail("heartbeat after veto"),
            result_callback=lambda _value: pytest.fail("result after veto"),
            provider_keyed_v2=True, identity_reader=_identity,
            group_members_reader=lambda _identity: set(),
            gate_timeout_seconds=1200,
        )
    assert journal == ["show-result", "prestate", "apply-intent", "apply-started"]
    assert not marker.exists()


def test_explicit_longer_gate_keeps_default_and_executes_only_after_go(tmp_path):
    marker = tmp_path / "executed-after-go"
    seen = []

    def started(_value):
        seen.append("started")
        time.sleep(0.08)
        assert not marker.exists()

    result = run_gated_command(
        [sys.executable, "-c", f"open({str(marker)!r}, 'w').write('done')"],
        scratch_path=tmp_path, intent_callback=lambda _value: seen.append("intent"),
        started_callback=started, heartbeat_callback=lambda _value: None,
        result_callback=lambda _value: seen.append("result"),
        provider_keyed_v2=True, identity_reader=_identity,
        group_members_reader=lambda _identity: set(), gate_timeout_seconds=2,
    )
    assert result.returncode == 0
    assert marker.read_text() == "done"
    assert seen == ["intent", "started", "result"]


def test_apply_sized_gate_waits_past_default_without_executing_before_go(tmp_path):
    marker = tmp_path / "executed-after-slow-proof"

    def slow_live_proof(_value):
        time.sleep(30.1)
        assert not marker.exists()

    result = run_gated_command(
        [sys.executable, "-c", f"open({str(marker)!r}, 'w').write('done')"],
        scratch_path=tmp_path, intent_callback=lambda _value: None,
        started_callback=slow_live_proof, heartbeat_callback=lambda _value: None,
        result_callback=lambda _value: None,
        provider_keyed_v2=True, identity_reader=_identity,
        group_members_reader=lambda _identity: set(), gate_timeout_seconds=1200,
    )
    assert result.returncode == 0
    assert marker.read_text() == "done"


def test_explicit_gate_timeout_cannot_execute_command(tmp_path):
    marker = tmp_path / "must-not-exist-after-timeout"
    with pytest.raises(GatedRunnerError):
        run_gated_command(
            [sys.executable, "-c", f"open({str(marker)!r}, 'w').write('bad')"],
            scratch_path=tmp_path, intent_callback=lambda _value: None,
            started_callback=lambda _value: time.sleep(1.2),
            heartbeat_callback=lambda _value: None, result_callback=lambda _value: None,
            provider_keyed_v2=True, identity_reader=_identity,
            group_members_reader=lambda _identity: set(), gate_timeout_seconds=1,
        )
    assert not marker.exists()


@pytest.mark.parametrize("timeout", [0, 1201, True, 1.5])
def test_invalid_gate_timeout_rejected_before_spawn(tmp_path, timeout):
    marker = tmp_path / "must-not-exist-invalid-timeout"
    with pytest.raises(GatedRunnerError):
        run_gated_command(
            [sys.executable, "-c", f"open({str(marker)!r}, 'w').write('bad')"],
            scratch_path=tmp_path, intent_callback=lambda _value: None,
            started_callback=lambda _value: None,
            heartbeat_callback=lambda _value: None, result_callback=lambda _value: None,
            provider_keyed_v2=True, gate_timeout_seconds=timeout,
        )
    assert not marker.exists()


@pytest.mark.parametrize("payload", [b"", b"X", b"GG"])
def test_child_rejects_eof_or_wrong_go(tmp_path, payload):
    marker = tmp_path / "must-not-exist"
    read_fd, write_fd = os.pipe()
    try:
        child = subprocess.Popen(
            [sys.executable, "-I", str(Path(CHILD_PATH).resolve()), str(read_fd), "--",
             sys.executable, "-c", f"open({str(marker)!r}, 'w').write('bad')"],
            pass_fds=(read_fd,), start_new_session=True,
        )
        os.close(read_fd)
        read_fd = -1
        if payload:
            os.write(write_fd, payload)
        os.close(write_fd)
        write_fd = -1
        assert child.wait(timeout=5) != 0
        assert not marker.exists()
    finally:
        for fd in (read_fd, write_fd):
            if fd >= 0:
                os.close(fd)


def test_silent_work_heartbeats_and_output_is_bounded(tmp_path):
    result, events = _run(tmp_path, "import sys,time; print('A'*20000); print('B'*20000,file=sys.stderr); time.sleep(.22)",
                          max_output_bytes=128)
    assert result.returncode == 0
    assert result.stdout == "A" * 127 + "\n" and result.stderr == "B" * 127 + "\n"
    assert result.stdout_truncated and result.stderr_truncated
    assert [name for name, _ in events].count("heartbeat") >= 2
    assert not hasattr(events[-1][1], "stdout") and not hasattr(events[-1][1], "stderr")


def test_bounded_output_retains_trailing_ansible_failure(tmp_path):
    code = "import sys; sys.stderr.write('x'*20000 + 'UNREACHABLE! connection refused\\n')"
    result, _events = _run(tmp_path, code, max_output_bytes=128)
    assert result.returncode == 0
    assert result.stderr_truncated and "UNREACHABLE! connection refused" in result.stderr
    assert len(result.stderr.encode()) <= 128


@pytest.mark.parametrize("mode", [0o775, 0o755])
def test_nonprivate_scratch_fails_before_intent(tmp_path, mode):
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    scratch.chmod(mode)
    events = []
    with pytest.raises(GatedRunnerError, match="owner-private"):
        run_gated_command(
            [sys.executable, "-c", "pass"], scratch_path=scratch,
            intent_callback=lambda _value: events.append("intent"),
            started_callback=lambda _value: events.append("started"),
            heartbeat_callback=lambda _value: events.append("heartbeat"),
            result_callback=lambda _value: events.append("result"),
            provider_keyed_v2=True,
        )
    assert events == []


def test_trusted_collaborator_workspace_executes_gated_command(tmp_path, monkeypatch):
    scratch = tmp_path / "reviewed-provider-workspace"
    scratch.mkdir(mode=0o700)
    scratch.chmod(0o2750)
    if (scratch.stat().st_mode & 0o7777) != 0o2750:
        pytest.skip("filesystem does not retain setgid on owner-created directories")
    monkeypatch.setattr(gated, "_collaborator_group_gid", lambda: scratch.stat().st_gid)
    result, events = _run(scratch, "print('reviewed')")
    assert result.returncode == 0 and result.stdout == "reviewed\n"
    assert [name for name, _ in events][0:2] == ["intent", "started"]
    assert events[-1][0] == "result"


def test_trusted_collaborator_mode_guard_with_synthetic_stat_on_nonlinux(tmp_path, monkeypatch):
    """Exercise the exact-mode branch where Darwin will not retain setgid."""
    scratch = tmp_path / "reviewed-provider-workspace"
    scratch.mkdir(mode=0o700)
    actual_stat = Path.stat
    real = actual_stat(scratch)
    synthetic = list(real)
    synthetic[0] = (real.st_mode & ~0o7777) | 0o2750
    def stat_with_setgid(path, *args, **kwargs):
        if path == scratch:
            return os.stat_result(synthetic)
        return actual_stat(path, *args, **kwargs)
    monkeypatch.setattr(Path, "stat", stat_with_setgid)
    monkeypatch.setattr(gated, "_collaborator_group_gid", lambda: real.st_gid)
    result, events = _run(scratch, "print('reviewed')")
    assert result.stdout == "reviewed\n" and events[-1][0] == "result"
    monkeypatch.setattr(gated, "_collaborator_group_gid", lambda: real.st_gid + 1)
    with pytest.raises(GatedRunnerError, match="trusted collaborator"):
        gated._private_scratch_path(scratch)


@pytest.mark.parametrize("trusted_gid", [None, -1])
def test_group_readable_workspace_requires_exact_trusted_gid(tmp_path, monkeypatch, trusted_gid):
    scratch = tmp_path / "untrusted-provider-workspace"
    scratch.mkdir(mode=0o700)
    scratch.chmod(0o2750)
    if (scratch.stat().st_mode & 0o7777) != 0o2750:
        pytest.skip("filesystem does not retain setgid on owner-created directories")
    monkeypatch.setattr(gated, "_collaborator_group_gid", lambda: trusted_gid)
    events = []
    with pytest.raises(GatedRunnerError, match="trusted collaborator"):
        run_gated_command(
            [sys.executable, "-c", "print('must not execute')"], scratch_path=scratch,
            intent_callback=lambda _value: events.append("intent"),
            started_callback=lambda _value: events.append("started"),
            heartbeat_callback=lambda _value: events.append("heartbeat"),
            result_callback=lambda _value: events.append("result"),
            provider_keyed_v2=True,
        )
    assert events == []


def test_shared_tmp_or_symlink_ancestor_fails_before_intent(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    for path in (Path("/tmp"), alias):
        events = []
        with pytest.raises(GatedRunnerError):
            run_gated_command(
                [sys.executable, "-c", "pass"], scratch_path=path,
                intent_callback=lambda _value: events.append("intent"),
                started_callback=lambda _value: events.append("started"),
                heartbeat_callback=lambda _value: events.append("heartbeat"),
                result_callback=lambda _value: events.append("result"),
                provider_keyed_v2=True,
            )
        assert events == []


def test_lost_heartbeat_authority_stops_process_group_and_descendant(tmp_path):
    marker = tmp_path / "descendant-executed"
    code = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable,'-c',\"import time; time.sleep(2); open({str(marker)!r},'w').write('bad')\"]); "
        "time.sleep(4)"
    )
    seen = []
    started_at = time.monotonic()
    with pytest.raises(GatedRunnerError):
        run_gated_command(
            [sys.executable, "-c", code], scratch_path=tmp_path,
            intent_callback=lambda _value: None,
            started_callback=lambda value: seen.append(value),
            heartbeat_callback=lambda _value: (_ for _ in ()).throw(RuntimeError("lease lost")),
            result_callback=lambda _value: pytest.fail("result must not be recorded"),
            provider_keyed_v2=True, identity_reader=_identity,
            group_members_reader=lambda _identity: set(), heartbeat_interval=0.05,
        )
    assert seen and time.monotonic() - started_at < 2
    time.sleep(2.1)
    assert not marker.exists()


def test_exited_leader_with_pipe_holding_descendant_remains_supervised(tmp_path):
    marker = tmp_path / "descendant-executed"
    code = (
        "import subprocess,sys; "
        f"subprocess.Popen([sys.executable,'-c',\"import time; time.sleep(2); open({str(marker)!r},'w').write('bad')\"]); "
    )
    heartbeats = []
    # On macOS CI there is no /proc. The injectable member reader supplies
    # a quiescent post-TERM observation; Linux production uses /proc instead.
    with pytest.raises(GatedRunnerError, match="aborted|descendants"):
        run_gated_command(
            [sys.executable, "-c", code], scratch_path=tmp_path,
            intent_callback=lambda _value: None,
            started_callback=lambda _value: None,
            heartbeat_callback=lambda _value: heartbeats.append(1),
            result_callback=lambda _value: pytest.fail("descendant cannot produce success"),
            provider_keyed_v2=True, identity_reader=_identity,
            group_members_reader=lambda _identity: set(), heartbeat_interval=0.05,
            post_leader_drain_grace=0.15,
        )
    assert heartbeats
    time.sleep(2.1)
    assert not marker.exists()


@pytest.mark.skipif(not Path("/proc/sys/kernel/random/boot_id").exists(),
                    reason="requires Linux /proc process-group identity")
def test_linux_default_identity_kills_term_resistant_descendant(tmp_path, monkeypatch):
    marker = tmp_path / "term-resistant-descendant-executed"
    ready = tmp_path / "term-resistant-ready"
    child_code = (
        "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"open({str(ready)!r},'w').write('ready'); "
        f"time.sleep(1.5); open({str(marker)!r},'w').write('bad')"
    )
    code = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{child_code!r}]); time.sleep(4)"
    started = []
    signals = []
    real_killpg = os.killpg
    def recorded_killpg(pgid, signum):
        signals.append(signum)
        return real_killpg(pgid, signum)
    monkeypatch.setattr(os, "killpg", recorded_killpg)
    def heartbeat(_value):
        if ready.exists():
            raise RuntimeError("lease lost after TERM-resistant child is ready")
    with pytest.raises(GatedRunnerError):
        run_gated_command(
            [sys.executable, "-c", code], scratch_path=tmp_path,
            intent_callback=lambda _value: None,
            started_callback=lambda value: started.append(value),
            heartbeat_callback=heartbeat,
            result_callback=lambda _value: pytest.fail("lost authority cannot produce result"),
            provider_keyed_v2=True, heartbeat_interval=0.2,
        )
    assert started
    assert signal.SIGTERM in signals and signal.SIGKILL in signals
    time.sleep(1.6)
    assert not marker.exists()


def test_v2_opt_in_and_linux_identity(tmp_path):
    with pytest.raises(GatedRunnerError, match="provider-keyed-v2"):
        run_gated_command([sys.executable, "-c", "pass"], scratch_path=tmp_path,
                          intent_callback=lambda _value: None, started_callback=lambda _value: None,
                          heartbeat_callback=lambda _value: None, result_callback=lambda _value: None)
    if Path("/proc/sys/kernel/random/boot_id").exists():
        result = run_gated_command(
            [sys.executable, "-c", "print('ok')"], scratch_path=tmp_path,
            intent_callback=lambda _value: None, started_callback=lambda _value: None,
            heartbeat_callback=lambda _value: None, result_callback=lambda _value: None,
            provider_keyed_v2=True, identity_reader=linux_process_identity,
        )
        assert result.stdout == "ok\n" and result.started.identity.boot_id


def test_term_esrch_after_quiescent_group_is_not_misclassified(monkeypatch):
    class Process:
        pid = 4567
        waited = False
        def wait(self, *, timeout):
            self.waited = True
    process = Process()
    identity = _identity(process.pid)
    monkeypatch.setattr(gated.os, "killpg", lambda *_args: (_ for _ in ()).throw(ProcessLookupError()))
    gated._terminate_group(process, identity, _identity, lambda _value: set())
    assert process.waited


def test_unproved_group_quiescence_has_distinct_error(monkeypatch):
    class Process:
        pid = 4567
        def wait(self, *, timeout):
            pytest.fail("unproved group must not be declared reaped")
    monkeypatch.setattr(gated.os, "killpg", lambda *_args: None)
    process = Process()
    with pytest.raises(UnreapedGatedCommandError, match="quiescence"):
        gated._terminate_group(process, _identity(process.pid), _identity,
                               lambda _value: {process.pid}, grace=0.01)


def test_optional_execution_budget_records_monotonic_success_duration(tmp_path):
    result, events = _run(tmp_path, "print('ok')", execution_timeout_seconds=2)
    audit = next(value for kind, value in events if kind == "result")
    assert result.returncode == 0 and result.stdout == "ok\n"
    assert audit.execution_timeout_seconds == 2
    assert audit.timed_out is False
    assert 0 <= audit.command_elapsed_seconds < 2


def test_unbudgeted_commands_keep_optional_audit_defaults(tmp_path):
    result, events = _run(tmp_path, "pass")
    audit = next(value for kind, value in events if kind == "result")
    assert result.returncode == 0
    assert audit.execution_timeout_seconds is None
    assert audit.command_elapsed_seconds is None
    assert audit.timed_out is False
