# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import replace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_mixed_zero_apply_dispatch as dispatch
from app.services.provider_keyed_mixed_zero_apply_teardown_source import MixedZeroApplySource
from app.storage.job_repository import StoredJobRun


def job(job_id, action, *, input=None, status="queued"):
    return StoredJobRun(
        id=job_id, action=action, status=status, target="engagement:eng-one",
        target_type="engagement", target_id="eng-one", requested_by="operator",
        input=input or {}, artifact_refs=[], created_at="2026-10-15T00:00:00+00:00",
        started_at=None, finished_at=None,
        events=[JobEvent(1, "info", "queued", {})],
    )


class Jobs:
    def __init__(self, *rows):
        self.rows = {row.id: row for row in rows}

    def get(self, row_id):
        return self.rows.get(row_id)

    def list(self):
        return list(self.rows.values())

    def list_for_engagement(self, engagement_id):
        return [row for row in self.rows.values() if row.target_id == engagement_id]


@pytest.fixture
def case(monkeypatch, tmp_path):
    core = job("job-core-one", "pilot_standard_rti_guarded_execute", input={
        "engagementId": "eng-one", "engagementName": "One", "corePlanId": "plan-one",
        "proxyCount": 2,
    }, status="succeeded")
    initial = job(dispatch.initial_parent_id(core.id), dispatch.INITIAL_ACTION,
                  input={"phase": "both_plans_saved"}, status="running")
    source = MixedZeroApplySource(
        "eng-one", core.id, "plan-one", initial.id, "a" * 64, "b" * 64,
        ("linode", "digitalocean"), ("c" * 64, "d" * 64), "e" * 64,
        "f" * 64, ("linode:inspector:10", "linode:inspector-firewall:20"),
    )
    jobs = Jobs(core, initial)
    monkeypatch.setattr(dispatch, "audit_mixed_zero_apply_teardown_source",
                        lambda *args, **kwargs: source)
    roots = (tmp_path / "sketch", tmp_path / "core")
    return jobs, core, initial, source, roots


def test_review_confirmation_and_reservation_are_one_action(case, monkeypatch):
    jobs, core, _initial, source, roots = case
    preview = dispatch.preview_mixed_zero_apply_cleanup(
        core, environment="devtest", state_root=roots[0],
        core_state_root=roots[1], job_repository=jobs)
    assert [scope["id"] for scope in preview["orderedScope"]] == [
        "sketch", "core", "inspector-verify", "inspector-cleanup"]
    assert preview["parentJobId"] is None
    assert preview["orderedScope"][2]["items"][0]["targetCount"] == 3
    reserved = job(dispatch._parent_id(core.id), dispatch.ACTION,
                   input={"source": __import__("dataclasses").asdict(source),
                          "sourceSha256": preview["snapshotId"],
                          "schema": "mixed-zero-apply-cleanup-v1",
                          "coreJobId": core.id, "corePlanId": source.core_plan_id})
    seen = []
    def reserve(*args, **kwargs):
        seen.append((args, kwargs))
        jobs.rows[reserved.id] = reserved
        return reserved
    monkeypatch.setattr(dispatch, "reserve_mixed_zero_apply_cleanup", reserve)
    with pytest.raises(dispatch.MixedZeroApplyDispatchAttention):
        dispatch.start_mixed_zero_apply_cleanup(
            core, {"snapshotId": "wrong", "confirmation": preview["confirmationPhrase"]},
            environment="devtest", state_root=roots[0], core_state_root=roots[1],
            job_repository=jobs)
    assert seen == []
    body = {"snapshotId": preview["snapshotId"],
            "confirmation": preview["confirmationPhrase"]}
    assert dispatch.start_mixed_zero_apply_cleanup(
        core, body, environment="devtest", state_root=roots[0],
        core_state_root=roots[1], job_repository=jobs) == reserved
    assert len(seen) == 1
    # After the fence the initial lease is no longer valid. Review and duplicate
    # confirmation use the exact saved parent instead of replaying pre-fence audit.
    monkeypatch.setattr(dispatch, "audit_mixed_zero_apply_teardown_source",
                        lambda *args, **kwargs: pytest.fail("pre-fence audit replayed"))
    assert dispatch.preview_mixed_zero_apply_cleanup(
        core, environment="devtest", state_root=roots[0],
        core_state_root=roots[1], job_repository=jobs)["parentJobId"] == reserved.id
    assert dispatch.start_mixed_zero_apply_cleanup(
        reserved, body, environment="devtest", state_root=roots[0],
        core_state_root=roots[1], job_repository=jobs) == reserved
    assert len(seen) == 1


def test_mixed_detection_does_not_take_over_later_published_generation(case):
    jobs, core, initial, _source, _roots = case
    assert dispatch.is_mixed_zero_apply_request(core, jobs=jobs)
    jobs.rows[initial.id] = replace(initial, input={"phase": "completed"})
    assert not dispatch.is_mixed_zero_apply_request(core, jobs=jobs)


def test_changed_saved_source_cannot_be_confirmed(case):
    jobs, core, _initial, source, roots = case
    from dataclasses import asdict
    raw = asdict(source)
    parent = job(dispatch._parent_id(core.id), dispatch.ACTION, input={
        "schema": "mixed-zero-apply-cleanup-v1", "coreJobId": core.id,
        "corePlanId": source.core_plan_id, "source": raw,
        "sourceSha256": "0" * 64,
    })
    jobs.rows[parent.id] = parent
    with pytest.raises(dispatch.MixedZeroApplyDispatchAttention):
        dispatch.preview_mixed_zero_apply_cleanup(
            core, environment="devtest", state_root=roots[0],
            core_state_root=roots[1], job_repository=jobs)


def test_driver_orders_one_shot_stages_and_never_replays_success(case, monkeypatch):
    jobs, core, _initial, source, roots = case
    from dataclasses import asdict
    parent = job(dispatch._parent_id(core.id), dispatch.ACTION, input={
        "coreJobId": core.id, "source": asdict(source),
    })
    jobs.rows[parent.id] = parent
    calls = []

    def runner(action, child_id=None):
        def run(*_args, **_kwargs):
            calls.append(action)
            completed = job(child_id or f"job-{action}", action, status="succeeded")
            jobs.rows[completed.id] = completed
            return completed
        return run

    from app.services.provider_keyed_mixed_zero_apply_core_preview import (
        ACTION as PREVIEW, _child_id as preview_id,
    )
    from app.services.provider_keyed_mixed_zero_apply_core_apply import (
        ACTION as APPLY, _child_id as apply_id,
    )
    from app.services.provider_keyed_mixed_zero_apply_core_absence import ACTION as ABSENCE
    from app.services.provider_keyed_mixed_zero_apply_inspector_negative import (
        ACTION as NEGATIVE, _child_id as negative_id,
    )
    from app.services.provider_keyed_mixed_zero_apply_inspector_retirement import (
        ACTION as RETIRE, _child_id as retire_id,
    )
    finish = lambda *_args, **_kwargs: calls.append("finish") or parent
    kwargs = dict(environment="devtest", positive_control_ipv4="1.1.1.1",
                  state_root=roots[0], core_state_root=roots[1],
                  job_repository=jobs, preview_core=runner(PREVIEW, preview_id(core.id)),
                  apply_core=runner(APPLY, apply_id(core.id)),
                  prove_absence=runner(ABSENCE),
                  prove_negative=runner(NEGATIVE, negative_id(core.id)),
                  retire_inspector=runner(RETIRE, retire_id(core.id)), finish=finish)
    assert dispatch.advance_mixed_zero_apply_cleanup(parent.id, **kwargs) == parent
    assert calls == [PREVIEW, APPLY, ABSENCE, NEGATIVE, RETIRE, "finish"]
    calls.clear()
    assert dispatch.advance_mixed_zero_apply_cleanup(parent.id, **kwargs) == parent
    assert calls == [ABSENCE, "finish"]
    jobs.rows[apply_id(core.id)] = replace(jobs.rows[apply_id(core.id)], status="running")
    calls.clear()
    with pytest.raises(dispatch.MixedZeroApplyDispatchAttention):
        dispatch.advance_mixed_zero_apply_cleanup(parent.id, **kwargs)
    assert calls == []


def test_succeeded_parent_uses_read_only_historical_recognizer(case, monkeypatch):
    jobs, core, _initial, source, roots = case
    from dataclasses import asdict
    from app.services import provider_keyed_mixed_zero_apply_terminal as terminal
    parent = job(dispatch._parent_id(core.id), dispatch.ACTION, status="succeeded",
                 input={"schema": "mixed-zero-apply-cleanup-v1",
                        "coreJobId": core.id, "corePlanId": source.core_plan_id,
                        "source": asdict(source),
                        "sourceSha256": dispatch._fingerprint(asdict(source))})
    jobs.rows[parent.id] = parent
    observed = []
    def recognize(*args, **kwargs):
        observed.append((args, kwargs))
        return parent
    monkeypatch.setattr(terminal, "recognize_mixed_zero_apply_terminal", recognize)
    assert dispatch.advance_mixed_zero_apply_cleanup(
        parent.id, environment="devtest", positive_control_ipv4="1.1.1.1",
        state_root=roots[0], core_state_root=roots[1],
        job_repository=jobs) == parent
    assert observed == [((source.engagement_id, core.id),
                         {"environment": "devtest", "job_repository": jobs})]
    preview = dispatch.preview_mixed_zero_apply_cleanup(
        parent, environment="devtest", state_root=roots[0],
        core_state_root=roots[1], job_repository=jobs)
    # Duplicate confirmation also has to recognize complete terminal history.
    assert dispatch.start_mixed_zero_apply_cleanup(
        parent, {"snapshotId": preview["snapshotId"],
                               "confirmation": preview["confirmationPhrase"]},
        environment="devtest", state_root=roots[0],
        core_state_root=roots[1], job_repository=jobs) == parent
    assert len(observed) == 2


def test_restart_selects_exact_fence_but_not_uncertain_child(case):
    jobs, core, _initial, source, _roots = case
    from dataclasses import asdict
    parent = job(dispatch._parent_id(core.id), dispatch.ACTION, input={
        "schema": "mixed-zero-apply-cleanup-v1", "coreJobId": core.id,
        "corePlanId": source.core_plan_id, "source": asdict(source),
        "sourceSha256": dispatch._fingerprint(asdict(source)),
    })
    jobs.rows[parent.id] = parent
    selected = []
    assert dispatch.recover_mixed_zero_apply_dispatches(
        environment="devtest", schedule=selected.append,
        job_repository=jobs,
        lease_lookup=lambda _engagement: (source.core_plan_id,
                                          "provider_keyed_teardown_fence")) == [parent.id]
    assert selected == [parent.id]
    from app.services.provider_keyed_mixed_zero_apply_core_apply import (
        ACTION as APPLY, _child_id as apply_id,
    )
    jobs.rows[apply_id(core.id)] = job(apply_id(core.id), APPLY, status="running")
    selected.clear()
    assert dispatch.recover_mixed_zero_apply_dispatches(
        environment="devtest", schedule=selected.append,
        job_repository=jobs,
        lease_lookup=lambda _engagement: (source.core_plan_id,
                                          "provider_keyed_teardown_fence")) == []
    assert selected == []


def test_restart_uses_private_precommand_selector_before_worker(case, monkeypatch):
    jobs, core, _initial, source, roots = case
    from dataclasses import asdict
    from app.services import provider_keyed_mixed_zero_apply_core_preview as preview_module
    from app.services import provider_keyed_mixed_zero_apply_core_apply as apply_module
    parent = job(dispatch._parent_id(core.id), dispatch.ACTION, input={
        "schema": "mixed-zero-apply-cleanup-v1", "coreJobId": core.id,
        "corePlanId": source.core_plan_id, "source": asdict(source),
        "sourceSha256": dispatch._fingerprint(asdict(source)),
    })
    jobs.rows[parent.id] = parent
    preview = job(preview_module._child_id(core.id), preview_module.ACTION)
    jobs.rows[preview.id] = preview
    accepted = []
    monkeypatch.setattr(preview_module, "queued_preview_restartable",
                        lambda child, *_args: accepted.append(child.id) or True)
    selected = []
    assert dispatch.recover_mixed_zero_apply_dispatches(
        environment="devtest", schedule=selected.append, job_repository=jobs,
        lease_lookup=lambda _engagement: (source.core_plan_id,
                                          "provider_keyed_teardown_fence")) == [parent.id]
    assert accepted == [preview.id]

    def complete_preview(*_args, **_kwargs):
        completed = replace(preview, status="succeeded")
        jobs.rows[preview.id] = completed
        return completed

    from app.services import provider_keyed_mixed_zero_apply_core_absence as absence_module
    from app.services import provider_keyed_mixed_zero_apply_inspector_negative as negative_module
    from app.services import provider_keyed_mixed_zero_apply_inspector_retirement as retire_module
    calls = []

    def complete(action, child_id):
        def run(*_args, **_kwargs):
            calls.append(action)
            completed = job(child_id, action, status="succeeded")
            jobs.rows[child_id] = completed
            return completed
        return run

    dispatch.advance_mixed_zero_apply_cleanup(
        parent.id, environment="devtest", positive_control_ipv4="1.1.1.1",
        state_root=roots[0], core_state_root=roots[1], job_repository=jobs,
        preview_core=complete_preview,
        apply_core=complete(apply_module.ACTION, apply_module._child_id(core.id)),
        prove_absence=complete(absence_module.ACTION, "job-absence"),
        prove_negative=complete(negative_module.ACTION, negative_module._child_id(core.id)),
        retire_inspector=complete(retire_module.ACTION, retire_module._child_id(core.id)),
        finish=lambda *_args, **_kwargs: parent,
    )
    assert calls == [apply_module.ACTION, absence_module.ACTION,
                     negative_module.ACTION, retire_module.ACTION]
