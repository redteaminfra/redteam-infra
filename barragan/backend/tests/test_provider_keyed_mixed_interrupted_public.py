# Copyright (c) 2026, Oracle and/or its affiliates.
"""The public mixed cleanup advances one action without replaying destroy GO."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
import app.services.provider_keyed_mixed_interrupted_public as service
from app.services.provider_keyed_mixed_interrupted_cleanup import _parent_id as cleanup_id
from app.services.provider_keyed_mixed_interrupted_destroy_child import _child_id as destroy_id
from app.services.provider_keyed_mixed_interrupted_dispatch import _workspace
from app.services.provider_keyed_mixed_interrupted_post_sketch_absence import (
    MixedInterruptedPostSketchAbsenceAttention,
)
from app.services.provider_keyed_mixed_zero_apply_inspector_negative import (
    ACTION as negative_action, _child_id as negative_id,
)
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_interrupted_source import _snapshot
from test_provider_keyed_mixed_interrupted_plan_worker import _case, _queued
from app.services.provider_keyed_mixed_interrupted_destroy_child import (
    propose_mixed_interrupted_destroy_child,
)
from app.services.provider_keyed_mixed_interrupted_destroy_source import (
    bind_mixed_interrupted_destroy_show,
)
from test_provider_keyed_mixed_interrupted_destroy_source import _release, saved


@pytest.mark.parametrize("state_backed_index", [0, 1])
def test_one_action_mixed_order_no_plan_and_state_backed_restart(
        ready, tmp_path, monkeypatch, state_backed_index):
    initial, jobs = ready.parent, ready.case.jobs
    order = tuple(initial.input["orderedProviders"])
    state_backed = order[state_backed_index]
    parent = replace(initial, id=cleanup_id(initial.input["coreJobId"]),
                     action="provider_keyed_mixed_interrupted_cleanup", status="queued",
                     input={"coreJobId": initial.input["coreJobId"],
                            "corePlanId": initial.input["corePlanId"]})
    jobs.save(parent)
    review = SimpleNamespace(
        ordered_providers=order,
        scopes=tuple(SimpleNamespace(kind="full" if provider == state_backed else "unstarted")
                     for provider in order))
    plans = SimpleNamespace(
        ordered_providers=order, plan_set_sha256="a" * 64,
        plans=tuple(SimpleNamespace(plan_path=("saved" if provider == state_backed else None))
                    for provider in order))
    monkeypatch.setattr(service, "_saved_review", lambda saved: review)
    monkeypatch.setattr(service, "_saved_plans", lambda saved: plans)
    monkeypatch.setattr(service, "_default_state_root", lambda: ready.case.state_root)
    monkeypatch.setattr(service, "DEFAULT_TERRAFORM_STATE_ROOT", tmp_path)
    monkeypatch.setattr(service, "review_mixed_interrupted_source", lambda *a, **k: review)
    calls = []
    fail_absence = {"once": True}
    delayed_absence = {"once": True}
    reconcile_blocked = {"once": True}
    workspace = _workspace(initial, state_backed, ready.case.state_root)
    workspace.state_path.write_bytes(b"retained-state")
    jobs.save(replace(parent, id=destroy_id(initial.input["coreJobId"], state_backed),
                      action="provider_keyed_mixed_interrupted_destroy_apply",
                      status="queued", events=[JobEvent(
                          1, "info", "mixed provider destroy queued", {})]))
    lease = lambda _: (initial.input["corePlanId"], "provider_keyed_teardown_fence")

    def plan_worker(*args, **kwargs):
        calls.append(("plans",))
        return parent

    def collector(_initial, provider, _workspace, *, fence, **kwargs):
        assert kwargs["process_quiescent"]() is True
        # Paginated provider inventory calls the fence between slow pages.
        for _ in range(3):
            assert fence()
        calls.append(("GET", provider, kwargs["phase_mode"]))
        return _snapshot(provider, generation=fence())

    def absence(_initial, _parent, _review, _plans, provider, _original, child,
                snapshot, *, fence, process_quiescent):
        assert snapshot.provider == provider and fence()
        assert process_quiescent({"bootId": "boot", "pid": 1,
                                  "pgid": 1, "startTicks": 1})
        calls.append(("absent", provider, child is not None))
        if provider == state_backed and fail_absence["once"]:
            fail_absence["once"] = False
            raise ValueError("provider inventory still settling")
        if provider == state_backed and delayed_absence["once"]:
            delayed_absence["once"] = False
            raise MixedInterruptedPostSketchAbsenceAttention("provider GET still sees deleted ID")

    monkeypatch.setattr(service, "prove_mixed_interrupted_provider_absence", absence)

    def run_destroy(_initial, _parent, _review, _plans, provider, before, **kwargs):
        assert provider == state_backed and before == b"retained-state"
        assert kwargs["environment"] == "devtest"
        assert kwargs["process_quiescent"]({}) is True
        if state_backed_index == 0:
            renewals = []
            assert kwargs["exact_both_scope_prover"](
                lambda: renewals.append("renew")) == review
            assert len(renewals) >= 8  # both inventories renew between pages
        else:
            assert kwargs["inventory_collector"] is not None
        calls.append(("GO", provider))
        child = replace(parent, id=destroy_id(initial.input["coreJobId"], provider),
                        action="provider_keyed_mixed_interrupted_destroy_apply",
                        status="running", events=[])
        jobs.save(child)
        return child

    def reconcile(_initial, _parent, _review, _plans, provider, **kwargs):
        assert provider == state_backed
        calls.append(("reconcile", provider))
        if reconcile_blocked["once"]:
            reconcile_blocked["once"] = False
            raise ValueError("destroy result remains uncertain")
        return jobs.get(destroy_id(initial.input["coreJobId"], provider))

    def completed(stage):
        def run(*args, **kwargs):
            calls.append((stage,))
            return SimpleNamespace(status="succeeded")
        return run

    def terminal(*args, **kwargs):
        calls.append(("terminal",))
        finished = replace(parent, status="succeeded")
        jobs.save(finished)
        return finished

    monkeypatch.setattr(service, "recognize_mixed_interrupted_terminal",
                        lambda *a, **k: jobs.get(parent.id))
    common = dict(environment="devtest", positive_control_ipv4="1.1.1.1",
                  state_root=ready.case.state_root, core_state_root=tmp_path,
                  job_repository=jobs, lease_lookup=lease,
                  credential_repository=SimpleNamespace(),
                  process_quiescent=lambda identity: True,
                  snapshot_collector=collector, plan_worker=plan_worker,
                  destroy_runner=run_destroy, destroy_reconciler=reconcile,
                  release_validator=lambda **_: SimpleNamespace(path=Path("/usr/bin/terraform")),
                  oci_tail=completed("OCI"), inspector_tail=completed("Inspector"),
                  terminal=terminal, read_only_wait=lambda seconds: calls.append(("wait", seconds)))
    with pytest.raises(service.MixedInterruptedPublicAttention):
        service.advance_mixed_interrupted_cleanup(parent.id, **common)
    assert calls.count(("GO", state_backed)) == 1
    assert not any(stage in calls for stage in (("OCI",), ("Inspector",), ("terminal",)))
    with pytest.raises(service.MixedInterruptedPublicAttention):
        service.advance_mixed_interrupted_cleanup(parent.id, **common)
    assert calls.count(("GO", state_backed)) == 1
    assert not any(stage in calls for stage in (("OCI",), ("Inspector",), ("terminal",)))
    result = service.advance_mixed_interrupted_cleanup(parent.id, **common)
    assert result.status == "succeeded"
    assert calls.count(("GO", state_backed)) == 1
    assert calls.count(("reconcile", state_backed)) == 2
    assert calls.count(("wait", 5)) == 1
    assert calls.count(("GO", state_backed)) == 1
    assert calls[-3:] == [("OCI",), ("Inspector",), ("terminal",)]
    before = list(calls)
    assert service.advance_mixed_interrupted_cleanup(parent.id, **common) == result
    assert calls == before
    no_plan = next(provider for provider in order if provider != state_backed)
    assert ("absent", no_plan, False) in calls
    assert ("absent", state_backed, True) in calls
    if state_backed_index == 1:
        assert calls.index(("absent", no_plan, False)) < calls.index(("GO", state_backed))


def test_invalid_control_does_not_start_plan_worker(ready, tmp_path, monkeypatch):
    called = []
    with pytest.raises(ValueError):
        service.advance_mixed_interrupted_cleanup(
            "job-any", environment="devtest", positive_control_ipv4="127.0.0.1",
            plan_worker=lambda *a, **k: called.append("planned"))
    assert called == []


def test_startup_selector_schedules_fresh_parent_but_not_uncertain_destroy(
        ready, tmp_path, monkeypatch):
    initial, jobs = ready.parent, ready.case.jobs
    core_id = initial.input["coreJobId"]
    parent = replace(initial, id=cleanup_id(core_id),
                     action="provider_keyed_mixed_interrupted_cleanup", status="queued",
                     input={"coreJobId": core_id, "corePlanId": initial.input["corePlanId"],
                            "phase": "awaiting_both_destroy_plans"})
    jobs.save(parent)
    order = tuple(initial.input["orderedProviders"])
    review = SimpleNamespace(ordered_providers=order, scopes=(), core_job_id=core_id)
    monkeypatch.setattr(service, "_saved_review", lambda saved: review)
    monkeypatch.setattr(service, "recognize_mixed_interrupted_cleanup_checkpoint",
                        lambda *a: None)
    monkeypatch.setattr(service, "_default_state_root", lambda: ready.case.state_root)
    monkeypatch.setattr(service, "DEFAULT_TERRAFORM_STATE_ROOT", tmp_path)
    lease = lambda _: (initial.input["corePlanId"], "provider_keyed_teardown_fence")
    queued = []
    args = dict(environment="devtest", schedule=queued.append,
                state_root=ready.case.state_root, core_state_root=tmp_path,
                job_repository=jobs, lease_lookup=lease)
    assert service.recover_mixed_interrupted_dispatches(**args) == [parent.id]
    assert queued == [parent.id]
    queued.clear()
    failed_probe = replace(parent, id=negative_id(core_id), action=negative_action,
                           status="failed", started_at=parent.created_at,
                           finished_at=parent.created_at)
    jobs.save(failed_probe)
    assert service.recover_mixed_interrupted_dispatches(**args) == [parent.id]
    assert queued == [parent.id]
    queued.clear()
    jobs.save(replace(failed_probe, status="running", finished_at=None))
    assert service.recover_mixed_interrupted_dispatches(**args) == []
    assert queued == []
    jobs.save(failed_probe)
    parent = replace(parent, input={**parent.input, "phase": "plans_sealed"})
    jobs.save(parent)
    monkeypatch.setattr(service, "_saved_plans", lambda saved: SimpleNamespace())
    monkeypatch.setattr(service, "recognize_mixed_interrupted_sealed_plans",
                        lambda *a: None)
    uncertain = replace(parent, id=destroy_id(core_id, order[0]),
                        action="provider_keyed_mixed_interrupted_destroy_apply",
                        status="running", events=[])
    jobs.save(uncertain)
    assert service.recover_mixed_interrupted_dispatches(**args) == []
    assert queued == []


def test_startup_resumes_only_pristine_queued_plan_worker(ready, tmp_path, monkeypatch):
    initial, parent, _kwargs, _calls = _case(ready, tmp_path, monkeypatch)
    core_id = initial.input["coreJobId"]
    review = service._saved_review(parent)
    plan_worker = _queued(initial, parent, review)
    jobs = ready.case.jobs
    jobs.save(plan_worker)
    monkeypatch.setattr(service, "_default_state_root", lambda: ready.case.state_root)
    monkeypatch.setattr(service, "DEFAULT_TERRAFORM_STATE_ROOT", tmp_path)
    scheduled = []
    args = dict(environment="devtest", schedule=scheduled.append,
                state_root=ready.case.state_root, core_state_root=tmp_path,
                job_repository=jobs,
                lease_lookup=lambda _: (parent.input["corePlanId"],
                                        "provider_keyed_teardown_fence"))
    assert service.recover_mixed_interrupted_dispatches(**args) == [parent.id]
    assert scheduled == [parent.id]
    provider = review.ordered_providers[0]
    workspace = _workspace(initial, provider, ready.case.state_root)
    journal = workspace.path / f".barragan-mixed-interrupted-destroy-{provider}.journal.jsonl"
    journal.write_bytes(b"uncertain")
    scheduled.clear()
    assert service.recover_mixed_interrupted_dispatches(**args) == []
    assert scheduled == []


def test_startup_selector_waits_for_awaiting_absence_claim_expiry(monkeypatch):
    monkeypatch.setattr(service, "recognize_mixed_interrupted_destroy_child",
                        lambda *a: "awaiting_absence")
    identity = {"bootId": "boot", "pid": 5, "pgid": 5, "startTicks": 8}
    child = SimpleNamespace(
        input={"terraformPath": "/usr/bin/terraform", "terraformSha256": "a" * 64,
               "planPath": "/tmp/plan", "planSha256": "b" * 64,
               "showSha256": "c" * 64, "beforeStateSha256": "d" * 64,
               "claimExpiresAt": (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()},
        events=[SimpleNamespace(data={}) for _ in range(4)] + [SimpleNamespace(data=identity)])
    args = (child, object(), object(), object(), object(), "linode", lambda _: True)
    assert service._destroy_child_restartable(*args) is False
    child.input["claimExpiresAt"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    assert service._destroy_child_restartable(*args) is True


def test_startup_resumes_only_exact_queued_destroy_child(saved, ready, tmp_path, monkeypatch):
    initial, cleanup, review, plans, provider, raw, binary, shown, _plan_path = saved
    jobs = ready.case.jobs
    jobs.save(cleanup)
    bound = bind_mixed_interrupted_destroy_show(
        initial, cleanup, review, plans, provider, raw, binary,
        _release(binary).sha256, show_runner=lambda command, cwd: shown,
        fence=lambda: "stable", release_validator=lambda: _release(binary))
    queued = propose_mixed_interrupted_destroy_child(initial, cleanup, review, plans, bound)
    jobs.save(queued)
    monkeypatch.setattr(service, "_saved_review", lambda parent: review)
    monkeypatch.setattr(service, "_saved_plans", lambda parent: plans)
    monkeypatch.setattr(service, "_default_state_root", lambda: ready.case.state_root)
    monkeypatch.setattr(service, "DEFAULT_TERRAFORM_STATE_ROOT", tmp_path)
    selected = []
    args = dict(environment="devtest", schedule=selected.append,
                state_root=ready.case.state_root, core_state_root=tmp_path,
                job_repository=jobs,
                lease_lookup=lambda _: (initial.input["corePlanId"],
                                        "provider_keyed_teardown_fence"))
    assert service._destroy_child_restartable(
        queued, initial, cleanup, review, plans, provider, lambda _: True)
    assert service.recover_mixed_interrupted_dispatches(**args) == [cleanup.id]
    assert selected == [cleanup.id]

    uncertain = replace(queued, status="running", started_at=queued.created_at,
                        events=queued.events + [JobEvent(
                            2, "info", "mixed provider destroy command intended", {})])
    jobs.save(uncertain)
    selected.clear()
    assert not service._destroy_child_restartable(
        uncertain, initial, cleanup, review, plans, provider, lambda _: True)
    assert service.recover_mixed_interrupted_dispatches(**args) == []
    assert selected == []
