# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private one-action published mixed sequencing; no provider writes here."""

from types import SimpleNamespace

import pytest

from app.services import provider_keyed_mixed_published_public as public


class Jobs:
    def __init__(self, parent):
        self.rows = {parent.id: parent}

    def get(self, identifier):
        return self.rows.get(identifier)


def _setup(monkeypatch, order):
    core = "job-core-published"
    parent = SimpleNamespace(
        id=public.parent_id(core), action=public.ACTION, status="queued",
        target_id="eng", input={"coreJobId": core, "corePlanId": "plan",
                                "engagementId": "eng", "reviewScope": {},
                                "engagementName": "test"})
    jobs = Jobs(parent)
    review = SimpleNamespace(source=SimpleNamespace(ordered_providers=order))
    monkeypatch.setattr(public, "saved_published_mixed_initial_review",
                        lambda *_: review)
    monkeypatch.setattr(public, "saved_published_mixed_destroy_plans",
                        lambda *_: object())
    monkeypatch.setattr(public, "recognize_published_mixed_plans_sealed",
                        lambda *_: parent)
    monkeypatch.setattr(public, "recognize_published_mixed_destroy_child",
                        lambda child, *_: child.phase)
    return jobs, parent, core


def _run(jobs, parent, *, first_runner, first_absence, second_runner,
         second_absence, oci_tail, inspector_tail, terminal):
    return public.advance_published_mixed_cleanup(
        parent.id, environment="devtest", positive_control_ipv4="1.1.1.1",
        job_repository=jobs, lease_lookup=lambda *_: (
            "plan", "provider_keyed_teardown_fence"),
        plan_worker=lambda *_a, **_k: parent,
        first_runner=first_runner, first_absence=first_absence,
        second_runner=second_runner, second_absence=second_absence,
        oci_tail=oci_tail, inspector_tail=inspector_tail, terminal=terminal)


@pytest.mark.parametrize("order", [
    ("linode", "digitalocean"), ("digitalocean", "linode")])
def test_one_action_orders_both_absences_before_core_and_inspector(monkeypatch, order):
    jobs, parent, core = _setup(monkeypatch, order)
    calls = []

    def runner(index):
        def invoke(*_args, **_kwargs):
            provider = order[index]
            calls.append(f"{provider}:GO")
            child = SimpleNamespace(phase="result")
            jobs.rows[public.child_id(core, provider)] = child
            return child
        return invoke

    def finisher(index):
        def invoke(*_args, **_kwargs):
            provider = order[index]
            calls.append(f"{provider}:absent")
            child = SimpleNamespace(phase="absence_proved")
            jobs.rows[public.child_id(core, provider)] = child
            return child
        return invoke

    def step(name):
        def invoke(*_args, **_kwargs):
            calls.append(name)
            return SimpleNamespace(status="succeeded")
        return invoke

    def finish(*_args, **_kwargs):
        calls.append("terminal")
        return SimpleNamespace(status="succeeded")

    result = _run(
        jobs, parent, first_runner=runner(0), first_absence=finisher(0),
        second_runner=runner(1), second_absence=finisher(1),
        oci_tail=step("OCI"), inspector_tail=step("Inspector"), terminal=finish)
    assert result.status == "succeeded"
    assert calls == [f"{order[0]}:GO", f"{order[0]}:absent",
                     f"{order[1]}:GO", f"{order[1]}:absent",
                     "OCI", "Inspector", "terminal"]


def test_saved_first_result_reconciles_without_repeating_go(monkeypatch):
    order = ("linode", "digitalocean")
    jobs, parent, core = _setup(monkeypatch, order)
    jobs.rows[public.child_id(core, order[0])] = SimpleNamespace(phase="result")
    jobs.rows[public.child_id(core, order[1])] = SimpleNamespace(phase="absence_proved")
    calls = []

    def finish_first(*_args, **_kwargs):
        calls.append("first absence")
        child = SimpleNamespace(phase="absence_proved")
        jobs.rows[public.child_id(core, order[0])] = child
        return child

    _run(jobs, parent,
         first_runner=lambda *_a, **_k: pytest.fail("first GO replayed"),
         first_absence=finish_first,
         second_runner=lambda *_a, **_k: pytest.fail("second GO replayed"),
         second_absence=lambda *_a, **_k: pytest.fail("second absence replayed"),
         oci_tail=lambda *_a, **_k: SimpleNamespace(status="succeeded"),
         inspector_tail=lambda *_a, **_k: SimpleNamespace(status="succeeded"),
         terminal=lambda *_a, **_k: SimpleNamespace(status="succeeded"))
    assert calls == ["first absence"]


def test_uncertain_first_intent_blocks_second_and_tail(monkeypatch):
    order = ("linode", "digitalocean")
    jobs, parent, core = _setup(monkeypatch, order)
    jobs.rows[public.child_id(core, order[0])] = SimpleNamespace(phase="uncertain")
    with pytest.raises(public.PublishedMixedPublicAttention):
        _run(jobs, parent,
             first_runner=lambda *_a, **_k: pytest.fail("first GO replayed"),
             first_absence=lambda *_a, **_k: pytest.fail("absence assumed"),
             second_runner=lambda *_a, **_k: pytest.fail("second GO started"),
             second_absence=lambda *_a, **_k: pytest.fail("second absence assumed"),
             oci_tail=lambda *_a, **_k: pytest.fail("OCI started"),
             inspector_tail=lambda *_a, **_k: pytest.fail("Inspector started"),
             terminal=lambda *_a, **_k: pytest.fail("terminal started"))


def test_parent_fence_drift_blocks_before_first_go(monkeypatch):
    jobs, parent, _ = _setup(monkeypatch, ("linode", "digitalocean"))
    with pytest.raises(public.PublishedMixedPublicAttention):
        public.advance_published_mixed_cleanup(
            parent.id, environment="devtest", positive_control_ipv4="1.1.1.1",
            job_repository=jobs,
            lease_lookup=lambda *_: ("other", "provider_keyed_teardown_fence"),
            plan_worker=lambda *_a, **_k: pytest.fail("plan worker started"),
            first_runner=lambda *_a, **_k: pytest.fail("GO started"))


def test_terminal_restart_uses_read_only_recognizer(monkeypatch):
    jobs, parent, _ = _setup(monkeypatch, ("linode", "digitalocean"))
    parent.status = "succeeded"
    result = SimpleNamespace(status="succeeded")
    from app.services import provider_keyed_mixed_published_terminal as terminal
    monkeypatch.setattr(terminal, "recognize_published_mixed_terminal",
                        lambda *_a, **_k: result)
    assert public.advance_published_mixed_cleanup(
        parent.id, environment="devtest", positive_control_ipv4="1.1.1.1",
        job_repository=jobs, lease_lookup=lambda *_: None,
        plan_worker=lambda *_a, **_k: pytest.fail("plan worker restarted"),
        first_runner=lambda *_a, **_k: pytest.fail("GO replayed")) is result
