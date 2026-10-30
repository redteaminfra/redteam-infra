# Copyright (c) 2026, Oracle and/or its affiliates.
"""A completed one-shot bootstrap is teardown evidence, not host policy proof."""

from dataclasses import replace

import pytest

from app.services.provider_keyed_mixed_initial_apply_child import _child_id
from app.services.provider_keyed_mixed_initial_host_attestation import (
    MixedHostAttestationAttention, recognize_completed_mixed_host_worker,
)
from app.services.provider_keyed_mixed_initial_bootstrap import run_mixed_initial_bootstrap
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_bootstrap import _inputs
from test_provider_keyed_mixed_initial_plan_parent import case


def test_exact_terminal_host_worker_and_unsafe_variants(ready, tmp_path):
    parent, binding, args, calls, _state = _inputs(ready, tmp_path)
    worker = run_mixed_initial_bootstrap(**args)
    core = ready.case.jobs.get("job-core")
    children = {provider: ready.case.jobs.get(_child_id("job-core", provider))
                for provider in parent.input["orderedProviders"]}
    digest = recognize_completed_mixed_host_worker(
        parent, core, children, binding, worker, core.id,
        process_quiescent=lambda _identity: True)
    assert len(digest) == 64
    assert len([value for kind, value in calls if kind == "intent"]) == 8
    for altered in (
        replace(worker, status="running", finished_at=None),
        replace(worker, status="failed"),
        replace(worker, events=worker.events[:-2] + worker.events[-1:]),
        replace(worker, input={**worker.input, "bindingManifestSha256": "0" * 64}),
    ):
        with pytest.raises(MixedHostAttestationAttention):
            recognize_completed_mixed_host_worker(
                parent, core, children, binding, altered, core.id,
                process_quiescent=lambda _identity: True)
    with pytest.raises(MixedHostAttestationAttention):
        recognize_completed_mixed_host_worker(
            parent, core, children, binding, worker, core.id,
            process_quiescent=lambda _identity: False)


@pytest.mark.parametrize("shape", ["old", "interim", "timing"])
def test_success_receipt_shapes_keep_exact_hashes_and_reject_timeout(ready, tmp_path, shape):
    from app.storage.job_repository import job_event_digest
    parent, binding, args, calls, _state = _inputs(ready, tmp_path)
    worker = run_mixed_initial_bootstrap(**args)
    core = ready.case.jobs.get("job-core")
    children = {provider: ready.case.jobs.get(_child_id("job-core", provider))
                for provider in parent.input["orderedProviders"]}
    fields = {"executionTimeoutSeconds", "commandElapsedSeconds", "timedOut"}
    rows = []
    for event in worker.events:
        if event.message == "mixed bootstrap command result fenced":
            data = {key: value for key, value in event.data.items() if key not in fields}
            if shape != "old":
                data["timedOut"] = False
            if shape == "timing":
                data.update(executionTimeoutSeconds=1800, commandElapsedSeconds=0.25)
            event = replace(event, data=data)
        rows.append(event)
    worker = replace(worker, events=rows)
    assert recognize_completed_mixed_host_worker(parent, core, children, binding, worker, core.id,
        process_quiescent=lambda _: True) == job_event_digest(worker.events)
    result_at = next(i for i, row in enumerate(rows) if row.message == "mixed bootstrap command result fenced")
    for bad in ({"timedOut": True}, {"commandElapsedSeconds": float("nan")},
                {"executionTimeoutSeconds": True}, {"timedOut": "false"}):
        altered = list(rows)
        altered[result_at] = replace(rows[result_at], data={**rows[result_at].data, **bad})
        with pytest.raises(MixedHostAttestationAttention):
            recognize_completed_mixed_host_worker(parent, core, children, binding,
                replace(worker, events=altered), core.id, process_quiescent=lambda _: True)


def test_incomplete_timeout_audit_is_not_phase_success_even_with_zero_exit(ready, tmp_path):
    from app.services.provider_keyed_mixed_initial_host_attestation import recognize_safe_incomplete_mixed_host_worker
    from app.storage.job_repository import job_event_digest
    parent, binding, args, calls, _state = _inputs(ready, tmp_path)
    worker = run_mixed_initial_bootstrap(**args)
    core = ready.case.jobs.get("job-core")
    children = {provider: ready.case.jobs.get(_child_id("job-core", provider))
                for provider in parent.input["orderedProviders"]}
    index = next(i for i, event in enumerate(worker.events) if event.message == "mixed bootstrap command result fenced")
    prefix = list(worker.events[:index + 1])
    prefix[-1] = replace(prefix[-1], data={**prefix[-1].data, "timedOut": True})
    stopped = replace(worker, status="failed", events=prefix)
    assert recognize_safe_incomplete_mixed_host_worker(parent, core, children, binding, stopped, core.id,
        process_quiescent=lambda _: True) == job_event_digest(prefix)
    # A completed phase/next command after timeout must not become cleanup proof.
    with pytest.raises(MixedHostAttestationAttention):
        recognize_safe_incomplete_mixed_host_worker(parent, core, children, binding,
            replace(stopped, events=[*prefix, worker.events[index + 1]]), core.id,
            process_quiescent=lambda _: True)


def test_actual_timeout_worker_suffix_requires_expired_claim_and_quiescent_process(ready, tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from app.services import provider_keyed_mixed_initial_host_attestation as attestation
    from app.services.provider_keyed_mixed_initial_bootstrap import MixedInitialBootstrapAttention
    from app.services.provider_keyed_gated_runner import (
        CommandAuditResult, CommandIntent, GatedCommandTimeoutError, ProcessIdentity, StartedCommand,
    )
    from app.services.sketch_bootstrap_apply import SketchBootstrapTimeoutError
    from app.storage.job_repository import job_event_digest

    parent, binding, args, calls, _state = _inputs(ready, tmp_path)
    attempts = []
    def timeout(command, *, scratch_path, intent_callback, started_callback,
                result_callback, execution_timeout_seconds, **kwargs):
        attempts.append(command)
        intent = CommandIntent("timed-command", str(scratch_path), "a" * 64)
        started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 99))
        intent_callback(intent)
        started_callback(started)
        result_callback(CommandAuditResult(started, -15, 0, 0, False, False, timed_out=True,
                                          execution_timeout_seconds=execution_timeout_seconds,
                                          command_elapsed_seconds=1800.25))
        raise GatedCommandTimeoutError("local bootstrap execution timed out")
    helper = args["bootstrap_helper"]
    def timeout_converting_helper(*values, **kwargs):
        # The real apply helper translates the supervised timeout at this boundary.
        try:
            return helper(*values, **kwargs)
        except GatedCommandTimeoutError as exc:
            raise SketchBootstrapTimeoutError("local bootstrap execution timed out") from exc
    args.update(gated_command_runner=timeout, bootstrap_helper=timeout_converting_helper)
    with pytest.raises(MixedInitialBootstrapAttention, match="timed out"):
        run_mixed_initial_bootstrap(**args)
    worker = ready.case.jobs.get("job-provider-keyed-mixed-host-worker-core")
    original_digest = job_event_digest(worker.events)
    assert worker.status == "running" and worker.finished_at is None
    assert worker.events[-1].message == "mixed bootstrap reconciliation required"
    core = ready.case.jobs.get("job-core")
    children = {provider: ready.case.jobs.get(_child_id("job-core", provider))
                for provider in parent.input["orderedProviders"]}
    def recognize(row=worker, quiescent=True):
        return attestation.recognize_safe_incomplete_mixed_host_worker(
            parent, core, children, binding, row, core.id, process_quiescent=lambda _: quiescent)
    with pytest.raises(MixedHostAttestationAttention):
        recognize()  # The actual worker claim is still active.

    class AfterClaimExpiry(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(timezone.utc) + timedelta(days=1)
    monkeypatch.setattr(attestation, "datetime", AfterClaimExpiry)
    assert recognize() == original_digest
    assert job_event_digest(worker.events) == original_digest
    with pytest.raises(MixedHostAttestationAttention):
        recognize(quiescent=False)
    for data in (
        {**worker.events[-1].data, "localQuiescenceUnproved": True},
        {**worker.events[-1].data, "timedOut": False},
        {**worker.events[-1].data, "timedOut": 1},
        {**worker.events[-1].data, "localQuiescenceUnproved": 0},
        {**worker.events[-1].data, "unexpected": True},
    ):
        forged = replace(worker, events=[*worker.events[:-1], replace(worker.events[-1], data=data)])
        with pytest.raises(MixedHostAttestationAttention):
            recognize(forged)
    with pytest.raises(MixedInitialBootstrapAttention):
        run_mixed_initial_bootstrap(**args)
    assert len(attempts) == 1
