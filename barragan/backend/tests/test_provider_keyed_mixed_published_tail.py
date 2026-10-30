# Copyright (c) 2026, Oracle and/or its affiliates.
"""Ordering and no-replay checks for the private published mixed tail."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services import provider_keyed_mixed_published_tail as tail
from app.services.provider_keyed_mixed_zero_apply_inspector_retirement import (
    PUBLISHED_ACTION,
)


class Jobs:
    def __init__(self, rows=None):
        self.rows = rows or {}

    def get(self, identifier):
        return self.rows.get(identifier)


def _row(action, status="succeeded", **extra):
    return SimpleNamespace(action=action, status=status, **extra)


def _options(jobs):
    return dict(environment="devtest", state_root=Path("/tmp/sketch"),
                core_state_root=Path("/tmp/core"), job_repository=jobs)


def test_published_oci_tail_sequences_three_children_and_skips_completed(monkeypatch):
    jobs = Jobs()
    monkeypatch.setattr(tail, "_parent", lambda *_: _row(tail.PARENT_ACTION))
    calls = []

    def preview(*_args, **_kwargs):
        calls.append("preview")
        return _row(tail.PREVIEW_ACTION)

    def apply(*_args, **_kwargs):
        calls.append("apply")
        return _row(tail.APPLY_ACTION)

    def absent(*_args, **_kwargs):
        calls.append("absence")
        return _row(tail.ABSENCE_ACTION)

    result = tail.advance_published_mixed_oci_core(
        "eng", "core", **_options(jobs), preview_core=preview,
        apply_core=apply, prove_absence=absent)
    assert result.action == tail.ABSENCE_ACTION
    assert calls == ["preview", "apply", "absence"]

    jobs.rows[tail.preview_id("core")] = _row(tail.PREVIEW_ACTION)
    jobs.rows[tail.apply_id("core")] = _row(tail.APPLY_ACTION)
    calls.clear()
    tail.advance_published_mixed_oci_core(
        "eng", "core", **_options(jobs), preview_core=preview,
        apply_core=apply, prove_absence=absent)
    assert calls == ["absence"]


def test_published_oci_tail_stops_before_apply_if_preview_unproved(monkeypatch):
    jobs = Jobs()
    monkeypatch.setattr(tail, "_parent", lambda *_: _row(tail.PARENT_ACTION))
    calls = []
    with pytest.raises(ValueError, match="preview is unproved"):
        tail.advance_published_mixed_oci_core(
            "eng", "core", **_options(jobs),
            preview_core=lambda *_a, **_k: _row(tail.PREVIEW_ACTION, "running"),
            apply_core=lambda *_a, **_k: calls.append("apply"),
            prove_absence=lambda *_a, **_k: calls.append("absence"))
    assert calls == []


def test_published_inspector_tail_orders_proof_selector_retirement(monkeypatch):
    assert tail.RETIRE_ACTION == PUBLISHED_ACTION
    jobs = Jobs()
    parent = _row(tail.PARENT_ACTION)
    monkeypatch.setattr(tail, "_parent", lambda *_: parent)
    calls = []

    def step(name, action):
        def run(*_args, **_kwargs):
            calls.append(name)
            return _row(action)
        return run

    tail.advance_published_mixed_inspector_tail(
        "eng", "core", **_options(jobs), positive_control={"host": "1.1.1.1"},
        negative_prover=step("negative", "negative"),
        selector_retire=step("selector", "selector"),
        inspector_retire=step("retire", tail.RETIRE_ACTION))
    assert calls == ["negative", "selector", "retire"]


def test_published_inspector_terminal_uses_historical_receipt_only(monkeypatch):
    assert tail.RETIRE_ACTION == PUBLISHED_ACTION
    control = {"host": "1.1.1.1"}
    retired = _row(tail.RETIRE_ACTION, input={"negativeJobId": "negative"})
    jobs = Jobs({tail.retirement_id("core"): retired,
                 "negative": _row("negative", input={"positiveControl": control})})
    monkeypatch.setattr(tail, "_parent", lambda *_: _row(tail.PARENT_ACTION))
    calls = []

    def finish(*_args, **_kwargs):
        calls.append("retire")
        return retired

    result = tail.advance_published_mixed_inspector_tail(
        "eng", "core", **_options(jobs), positive_control=control,
        negative_prover=lambda *_a, **_k: pytest.fail("public probe replayed"),
        selector_retire=lambda *_a, **_k: pytest.fail("selector DELETE replayed"),
        inspector_retire=finish)
    assert result is retired
    assert calls == ["retire"]


def test_published_inspector_tail_stops_before_selector_if_negative_unproved(monkeypatch):
    jobs = Jobs()
    monkeypatch.setattr(tail, "_parent", lambda *_: _row(tail.PARENT_ACTION))
    calls = []
    with pytest.raises(ValueError, match="negative proof is absent"):
        tail.advance_published_mixed_inspector_tail(
            "eng", "core", **_options(jobs), positive_control={"host": "1.1.1.1"},
            negative_prover=lambda *_a, **_k: _row("negative", "running"),
            selector_retire=lambda *_a, **_k: calls.append("selector"),
            inspector_retire=lambda *_a, **_k: calls.append("retire"))
    assert calls == []
