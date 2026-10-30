# Copyright (c) 2026, Oracle and/or its affiliates.
"""Timing evidence does not grant success, retry, or mutation authority."""
from types import SimpleNamespace
import subprocess

import pytest

from app.services.bootstrap_command_evidence import (
    bootstrap_command_timing, valid_bootstrap_result_keys,
)
from app.services import sketch_bootstrap_apply as bootstrap
from app.services import sketch_chains
from test_sketch_bootstrap_apply import _provider_job, _JobStore


@pytest.mark.parametrize("budget,elapsed,timed_out", [
    (True, 1, False), (1800, True, False), ("1800", 1, False),
    (1800, "1", False), (1800, float("nan"), False),
    (1800, float("inf"), False), (float("inf"), 0, False),
    (0, 1, False), (-1, 1, False), (1800, -1, False),
    (1800, 1, 0), (1800, 1, "false"), (1800, None, False),
    (None, 1, False), (10 ** 1000, 1, False),
])
def test_invalid_projection_fails_closed(budget, elapsed, timed_out):
    with pytest.raises(ValueError):
        bootstrap_command_timing(SimpleNamespace(execution_timeout_seconds=budget,
                                                command_elapsed_seconds=elapsed, timed_out=timed_out))


def test_exact_historical_interim_and_new_metadata_shapes():
    assert valid_bootstrap_result_keys({"returnCode": 0}, {"returnCode"}, success=True)
    assert valid_bootstrap_result_keys({"returnCode": 0, "timedOut": False}, {"returnCode"}, success=True)
    data = {"returnCode": 0, "timedOut": False, "executionTimeoutSeconds": 1800, "commandElapsedSeconds": 2.5}
    assert valid_bootstrap_result_keys(data, {"returnCode"}, success=True)
    assert not valid_bootstrap_result_keys({**data, "timedOut": True}, {"returnCode"}, success=True)
    for key in ("timedOut", "executionTimeoutSeconds", "commandElapsedSeconds"):
        assert not valid_bootstrap_result_keys({k: v for k, v in data.items() if k != key}, {"returnCode"})
    assert not valid_bootstrap_result_keys({**data, "unexpected": 1}, {"returnCode"})


def test_legacy_per_command_duration_excludes_backoff_and_times_transport(tmp_path, monkeypatch):
    monkeypatch.setattr(bootstrap, "BOOTSTRAP_READINESS_BACKOFF_SECONDS", (30,))
    clock, calls, events = [100.0], [], []
    def invoke(command, cwd, env):
        calls.append(command[0])
        clock[0] += 2.5
        if len(calls) == 1:
            return subprocess.CompletedProcess(command, 4, "", "UNREACHABLE: Connection refused")
        return subprocess.CompletedProcess(command, 0, "", "")
    result = bootstrap._run_bootstrap_phases_with_readiness(
        invoke, ["readiness"], ["root"], ["user"], ["transport"], tmp_path, {},
        reporter=lambda status, data: events.append((status, data)),
        wait=lambda seconds: clock.__setitem__(0, clock[0] + seconds), monotonic=lambda: clock[0],
    )
    assert all(row.returncode == 0 for row in result)
    terminal = [data for status, data in events if status in {"completed", "failed"}]
    assert len(terminal) == 5
    assert all(row["commandElapsedSeconds"] == 2.5 and row["executionTimeoutSeconds"] == 1800
               and row["timedOut"] is False for row in terminal)
    assert terminal[-1]["phase"] == "transport-key-install"
    assert terminal[-1]["elapsedSeconds"] == 42
    waiting = [data for status, data in events if status == "waiting"]
    assert waiting[0]["nextBackoffSeconds"] == 30
    assert "commandElapsedSeconds" not in waiting[0]


def test_legacy_timeout_reports_once_before_exception_without_next_phase(tmp_path):
    clock, calls, events = [0.0], [], []
    def invoke(command, cwd, env):
        calls.append(command)
        clock[0] += 1800.3
        raise bootstrap.SketchBootstrapTimeoutError("private command detail")
    with pytest.raises(bootstrap.SketchBootstrapTimeoutError):
        bootstrap._run_bootstrap_phases_with_readiness(
            invoke, ["readiness"], ["root"], ["user"], ["transport"], tmp_path, {},
            reporter=lambda status, data: events.append((status, data)),
            wait=lambda _: pytest.fail("timeout cannot retry"), monotonic=lambda: clock[0],
        )
    failures = [data for status, data in events if status == "failed"]
    assert len(failures) == 1 and len(calls) == 1
    assert failures[0]["commandElapsedSeconds"] == 1800.3
    assert failures[0]["executionTimeoutSeconds"] == 1800 and failures[0]["timedOut"] is True
    assert "private" not in str(events)


@pytest.mark.parametrize("timing", [
    {"executionTimeoutSeconds": True, "commandElapsedSeconds": 1, "timedOut": False},
    {"executionTimeoutSeconds": 1800, "commandElapsedSeconds": float("nan"), "timedOut": False},
    {"executionTimeoutSeconds": 1800, "commandElapsedSeconds": 1, "timedOut": "false"},
    {"executionTimeoutSeconds": 1800, "timedOut": False},
])
def test_legacy_storage_drops_invalid_group_without_partial_projection(timing):
    jobs = _JobStore(_provider_job())
    sketch_chains._record_bootstrap_readiness_progress(jobs, jobs.current.id, "completed", {
        "phase": "root-management-readiness", **timing,
    })
    assert not (set(jobs.current.events[-1].data) & {"executionTimeoutSeconds", "commandElapsedSeconds", "timedOut"})
