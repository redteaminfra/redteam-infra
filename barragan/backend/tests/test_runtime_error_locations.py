# Copyright (c) 2026, Oracle and/or its affiliates.
"""Background diagnostics preserve suppressed predicates without new payload logs."""
from contextlib import nullcontext
from types import SimpleNamespace

from app.core import error_locations, runtime


def test_background_task_logs_safe_suppressed_locations_and_keeps_legacy_log(monkeypatch):
    class SecretError(ValueError):
        def __str__(self):
            raise AssertionError("new diagnostics must not format exceptions")

        __repr__ = __str__

    namespace = {"SecretError": SecretError}
    filename = str(error_locations._APP_ROOT / "services" / "predicate.py")
    exec(compile("def fail():\n    raise SecretError('credential-secret')\n", filename, "exec"), namespace)

    def task():
        try:
            namespace["fail"]()
        except SecretError:
            raise RuntimeError("provider-payload-secret") from None

    safe_records, legacy_calls, threads = [], [], []
    logger = SimpleNamespace(
        error=lambda message, records: safe_records.append(message % records),
        exception=lambda *args: legacy_calls.append(args))

    class InlineThread:
        def __init__(self, **kwargs):
            self.target = kwargs["target"]
            threads.append(kwargs)

        def start(self):
            self.target()

    state = object()
    monkeypatch.setattr(runtime, "current_runtime", lambda: state)
    monkeypatch.setattr(runtime, "runtime_context", lambda active: nullcontext())
    monkeypatch.setattr(runtime.threading, "Thread", InlineThread)
    monkeypatch.setattr(runtime, "logging", SimpleNamespace(getLogger=lambda name: logger))
    runtime.start_runtime_task(task, name="existing-task")
    assert threads[0]["daemon"] is True
    assert threads[0]["name"] == "existing-task"
    assert legacy_calls == [("Background task %s failed", "existing-task")]
    assert len(safe_records) == 1
    assert "RuntimeError" in safe_records[0] and "SecretError" in safe_records[0]
    assert "('predicate.py', 2)" in safe_records[0]
    assert "runtime.py" in safe_records[0]
    assert "secret" not in safe_records[0]
    assert str(error_locations._APP_ROOT) not in safe_records[0]
    assert "test_runtime_error_locations.py" not in safe_records[0]


def test_shared_locations_handle_both_links_cycles_and_bounds():
    outer, cause, context = RuntimeError("a"), ValueError("b"), TypeError("c")
    outer.__cause__, outer.__context__ = cause, context
    outer.__suppress_context__ = True
    cause.__context__ = outer
    assert error_locations.sanitized_error_locations(outer) == [
        ("RuntimeError", []), ("ValueError", []), ("TypeError", [])]
    cursor = outer
    for _ in range(30):
        cursor.__cause__ = RuntimeError("not-for-logging")
        cursor = cursor.__cause__
    assert len(error_locations.sanitized_error_locations(outer)) == 16
