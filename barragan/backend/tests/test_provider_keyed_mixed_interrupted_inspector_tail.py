# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private interrupted tail keeps one ordered operator action."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.services import provider_keyed_mixed_interrupted_inspector_tail as service
from app.services import provider_keyed_mixed_zero_apply_inspector_negative as negative_service
from app.services import provider_keyed_mixed_zero_apply_inspector_retirement as retirement_service
from app.domain import JobEvent
from app.storage.database import db
from app.storage.job_repository import StoredJobRun, job_event_digest
from test_provider_keyed_mixed_zero_apply_inspector_negative import case, _proof
from test_provider_keyed_mixed_zero_apply_inspector_retirement import (
    Provider, _enter_sql, _sql_ready,
)


@pytest.mark.parametrize("pending", [False, True])
def test_private_tail_orders_negative_selector_and_inspector(monkeypatch, pending, tmp_path):
    parent = SimpleNamespace(action="provider_keyed_mixed_interrupted_cleanup",
                             target_id="eng-opaque")
    jobs = SimpleNamespace(get=lambda identifier: (
        parent if identifier == service.cleanup_id("job-core") else None))
    monkeypatch.setattr(service, "_saved_review", lambda _: SimpleNamespace(scopes=(
        SimpleNamespace(provider="linode", selector_retirement_pending=False),
        SimpleNamespace(provider="digitalocean", selector_retirement_pending=pending))))
    calls = []

    def stage(name):
        def run(*args, **kwargs):
            assert kwargs["environment"] == "devtest"
            assert kwargs["job_repository"] is jobs
            calls.append(name)
            return SimpleNamespace(status="succeeded")
        return run

    result = service.advance_mixed_interrupted_inspector_tail(
        "eng-opaque", "job-core", environment="devtest", state_root=tmp_path,
        core_state_root=tmp_path, positive_control={"id": "external"},
        job_repository=jobs, negative_prover=stage("negative"),
        selector_retire=stage("selector"), inspector_retire=stage("Inspector"))
    assert result.status == "succeeded"
    assert calls == (["negative", "selector", "Inspector"] if pending
                     else ["negative", "Inspector"])


def test_private_tail_never_retires_inspector_after_uncertain_selector(monkeypatch, tmp_path):
    parent = SimpleNamespace(action="provider_keyed_mixed_interrupted_cleanup",
                             target_id="eng-opaque")
    jobs = SimpleNamespace(get=lambda identifier: (
        parent if identifier == service.cleanup_id("job-core") else None))
    monkeypatch.setattr(service, "_saved_review", lambda _: SimpleNamespace(scopes=(
        SimpleNamespace(provider="digitalocean", selector_retirement_pending=True),)))
    with pytest.raises(ValueError, match="not retired"):
        service.advance_mixed_interrupted_inspector_tail(
            "eng-opaque", "job-core", environment="devtest", state_root=tmp_path,
            core_state_root=tmp_path, positive_control={}, job_repository=jobs,
            negative_prover=lambda *_a, **_k: SimpleNamespace(status="succeeded"),
            selector_retire=lambda *_a, **_k: SimpleNamespace(status="running"),
            inspector_retire=lambda *_a, **_k: pytest.fail("Inspector DELETE ran"))


def test_private_tail_retries_terminal_failed_read_only_probes_in_same_action(
        monkeypatch, tmp_path):
    core_id, engagement_id = "job-core", "eng-opaque"
    parent = SimpleNamespace(id=service.cleanup_id(core_id),
                             action="provider_keyed_mixed_interrupted_cleanup",
                             target_id=engagement_id)
    rows = {service.cleanup_id(core_id): parent}
    jobs = SimpleNamespace(get=rows.get, list_for_engagement=lambda _id: list(rows.values()))
    monkeypatch.setattr(service, "_saved_review", lambda _: SimpleNamespace(scopes=(
        SimpleNamespace(provider="digitalocean", selector_retirement_pending=False),)))
    calls = []

    def probe(*_args, **_kwargs):
        number = 1 + sum(row.action == negative_service.ACTION for row in rows.values()
                         if isinstance(row, StoredJobRun))
        identifier = negative_service._attempt_id(core_id, number)
        previous = rows.get(negative_service._attempt_id(core_id, number - 1))
        input_data = {"coreJobId": core_id}
        if previous is not None:
            input_data.update({"previousNegativeJobId": previous.id,
                               "previousNegativeJournalSha256": job_event_digest(previous.events)})
        failed = number < 3
        row = StoredJobRun(
            identifier, negative_service.ACTION, "failed" if failed else "succeeded",
            f"engagement:{engagement_id}", "engagement", engagement_id,
            "operator", input_data, [], "2026-10-15T00:00:00+00:00",
            "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:01+00:00",
            [JobEvent(1, "info", "mixed Inspector negative queued", {}),
             JobEvent(2, "info", "mixed Inspector negative started", {}),
             JobEvent(3, "error" if failed else "info",
                      "mixed Inspector negative unverified" if failed else
                      "mixed Inspector exact public negative proved", {})])
        rows[identifier] = row
        calls.append(("probe", number))
        if failed:
            raise negative_service.MixedZeroApplyInspectorNegativeAttention("offline failure")
        return row

    result = service.advance_mixed_interrupted_inspector_tail(
        engagement_id, core_id, environment="devtest", state_root=tmp_path,
        core_state_root=tmp_path, positive_control={"id": "external"},
        job_repository=jobs, negative_prover=probe,
        selector_retire=lambda *_a, **_k: pytest.fail("selector should not run"),
        inspector_retire=lambda *_a, **_k: (calls.append(("retire",)) or
                                          SimpleNamespace(status="succeeded")),
        read_only_wait=lambda seconds: calls.append(("wait", seconds)))
    assert result.status == "succeeded"
    assert calls == [("probe", 1), ("wait", 2), ("probe", 2), ("wait", 2),
                     ("probe", 3), ("retire",)]
    assert rows[negative_service._child_id(core_id)].status == "failed"


def test_private_tail_does_not_retry_running_probe(monkeypatch, tmp_path):
    core_id, engagement_id = "job-core", "eng-opaque"
    parent = SimpleNamespace(action="provider_keyed_mixed_interrupted_cleanup",
                             target_id=engagement_id)
    running = StoredJobRun(
        negative_service._child_id(core_id), negative_service.ACTION, "running",
        f"engagement:{engagement_id}", "engagement", engagement_id, "operator",
        {"coreJobId": core_id}, [], "2026-10-15T00:00:00+00:00",
        "2026-10-15T00:00:00+00:00", None,
        [JobEvent(1, "info", "mixed Inspector negative queued", {}),
         JobEvent(2, "info", "mixed Inspector negative started", {})])
    rows = {service.cleanup_id(core_id): parent, running.id: running}
    jobs = SimpleNamespace(get=rows.get, list_for_engagement=lambda _id: list(rows.values()))
    monkeypatch.setattr(service, "_saved_review", lambda _: SimpleNamespace(scopes=(
        SimpleNamespace(provider="digitalocean", selector_retirement_pending=False),)))
    with pytest.raises(negative_service.MixedZeroApplyInspectorNegativeAttention):
        service.advance_mixed_interrupted_inspector_tail(
            engagement_id, core_id, environment="devtest", state_root=tmp_path,
            core_state_root=tmp_path, positive_control={"id": "external"},
            job_repository=jobs,
            negative_prover=lambda *_a, **_k: (_ for _ in ()).throw(
                negative_service.MixedZeroApplyInspectorNegativeAttention("running")),
            inspector_retire=lambda *_a, **_k: pytest.fail("Inspector DELETE ran"),
            read_only_wait=lambda _seconds: pytest.fail("waited on running probe"))


@pytest.mark.parametrize("pending", [False, True])
def test_completed_retirement_revalidates_history_without_fresh_negative(
        monkeypatch, tmp_path, pending):
    core_id = "job-core"
    parent = SimpleNamespace(action="provider_keyed_mixed_interrupted_cleanup",
                             target_id="eng-opaque")
    retired = SimpleNamespace(action=service.RETIRE_ACTION, status="succeeded",
                              input={"receipt": "saved"})
    negative = SimpleNamespace(input={"positiveControl": {"id": "external"}})
    saved = {service.cleanup_id(core_id): parent,
             service.retirement_id(core_id): retired,
             service.negative_id(core_id): negative}
    jobs = SimpleNamespace(get=saved.get)
    monkeypatch.setattr(service, "_saved_review", lambda _: SimpleNamespace(scopes=(
        SimpleNamespace(provider="digitalocean", selector_retirement_pending=pending),)))
    calls = []

    def recognize(*_args, **kwargs):
        assert kwargs["interrupted"] is True
        calls.append("historical")
        return retired

    options = dict(environment="devtest", state_root=tmp_path,
                   core_state_root=tmp_path, positive_control={"id": "external"},
                   job_repository=jobs,
                   negative_prover=lambda *_a, **_k: pytest.fail("negative reprobed"),
                   selector_retire=lambda *_a, **_k: pytest.fail("selector replayed"),
                   inspector_retire=recognize)
    assert service.advance_mixed_interrupted_inspector_tail(
        "eng-opaque", core_id, **options) is retired
    assert calls == ["historical"]
    with pytest.raises(ValueError, match="positive control differs"):
        service.advance_mixed_interrupted_inspector_tail(
            "eng-opaque", core_id, **{**options, "positive_control": {"id": "other"}})
    assert calls == ["historical"]
    options["inspector_retire"] = lambda *_a, **_k: SimpleNamespace(
        action=service.RETIRE_ACTION, status="succeeded", input={"receipt": "changed"})
    with pytest.raises(ValueError, match="receipt differs"):
        service.advance_mixed_interrupted_inspector_tail(
            "eng-opaque", core_id, **options)


def test_running_retirement_still_checks_negative_before_inspector(
        monkeypatch, tmp_path):
    core_id = "job-core"
    parent = SimpleNamespace(action="provider_keyed_mixed_interrupted_cleanup",
                             target_id="eng-opaque")
    running = SimpleNamespace(action=service.RETIRE_ACTION, status="running")
    rows = {service.cleanup_id(core_id): parent,
            service.retirement_id(core_id): running}
    jobs = SimpleNamespace(get=rows.get)
    monkeypatch.setattr(service, "_saved_review", lambda _: SimpleNamespace(scopes=(
        SimpleNamespace(provider="digitalocean", selector_retirement_pending=False),)))
    calls = []

    def negative(*_args, **_kwargs):
        calls.append("negative")
        return SimpleNamespace(status="succeeded")

    def inspector(*_args, **_kwargs):
        calls.append("Inspector")
        return running

    with pytest.raises(ValueError, match="retirement is unproved"):
        service.advance_mixed_interrupted_inspector_tail(
            "eng-opaque", core_id, environment="devtest", state_root=tmp_path,
            core_state_root=tmp_path, positive_control={}, job_repository=jobs,
            negative_prover=negative, inspector_retire=inspector)
    assert calls == ["negative", "Inspector"]


def test_completed_retirement_tampering_is_rejected_by_historical_recognizer(
        case, monkeypatch, tmp_path):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    provider = Provider()
    with db.bind(state):
        kwargs, jobs, _, _ = _enter_sql(case, source, options, state, provider)
        retired = retirement_service.retire_mixed_zero_apply_inspector(
            source.engagement_id, source.core_job_id, **kwargs)
        old_parent_id = retired.input["teardownParentId"]
        jobs.save(replace(
            jobs.get(old_parent_id), id=service.cleanup_id(source.core_job_id),
            action="provider_keyed_mixed_interrupted_cleanup"))
        monkeypatch.setattr(service, "_saved_review", lambda _: SimpleNamespace(scopes=(
            SimpleNamespace(provider="digitalocean", selector_retirement_pending=False),)))
        monkeypatch.setattr(retirement_service, "_saved_review", lambda _: SimpleNamespace(
            scopes=(SimpleNamespace(provider="digitalocean",
                                    selector_retirement_pending=False),)))
        original_authority = retirement_service._authority
        monkeypatch.setattr(retirement_service, "_authority",
                            lambda *args, **_kw: original_authority(*args))
        retirement_options = dict(kwargs)
        for key in ("environment", "state_root", "core_state_root", "job_repository"):
            retirement_options.pop(key)
        tail_options = dict(
            environment="devtest", state_root=kwargs["state_root"],
            core_state_root=kwargs["core_state_root"],
            positive_control=jobs.get(service.negative_id(
                source.core_job_id)).input["positiveControl"],
            job_repository=jobs,
            negative_prover=lambda *_a, **_k: pytest.fail("negative reprobed"),
            selector_retire=lambda *_a, **_k: pytest.fail("selector replayed"),
            retirement_options=retirement_options)
        assert service.advance_mixed_interrupted_inspector_tail(
            source.engagement_id, source.core_job_id, **tail_options) == retired
        jobs.save(replace(retired, input={**retired.input,
                                          "historicalAuthoritySha256": "0" * 64}))
        with pytest.raises(retirement_service.MixedZeroApplyInspectorRetirementAttention):
            service.advance_mixed_interrupted_inspector_tail(
                source.engagement_id, source.core_job_id, **tail_options)
        assert (provider.host_deletes, provider.firewall_deletes) == (1, 1)


def test_interrupted_negative_routes_to_interrupted_historical_and_absence(
        case, monkeypatch):
    source, absent, options, seen = _proof(case, monkeypatch)
    original = negative_service._authority
    modes = []

    def historical(*args, **kwargs):
        modes.append(kwargs.get("interrupted"))
        return original(*args)

    def recognize_absence(*args, **kwargs):
        assert kwargs["interrupted"] is True
        return absent

    monkeypatch.setattr(negative_service, "_authority", historical)
    result = negative_service.prove_mixed_zero_apply_inspector_negative(
        source.engagement_id, source.core_job_id, **options,
        absence_recognizer=recognize_absence, interrupted=True)
    assert result.status == "succeeded" and len(seen) == 2
    assert modes and all(mode is True for mode in modes)


def test_interrupted_inspector_go_requires_prior_selector_terminal(
        case, monkeypatch, tmp_path):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    provider = Provider()
    with db.bind(state):
        kwargs, _, _, _ = _enter_sql(case, source, options, state, provider)
        original = retirement_service._authority
        monkeypatch.setattr(retirement_service, "_authority",
                            lambda *args, **_kw: original(*args))
        monkeypatch.setattr(retirement_service, "_saved_review", lambda _parent:
                            SimpleNamespace(scopes=(SimpleNamespace(
                                provider="digitalocean", selector_retirement_pending=True),)))
        with pytest.raises(retirement_service.MixedZeroApplyInspectorRetirementAttention):
            retirement_service.retire_mixed_zero_apply_inspector(
                source.engagement_id, source.core_job_id,
                **{**kwargs, "interrupted": True})
        assert (provider.host_deletes, provider.firewall_deletes) == (0, 0)


def test_selector_journal_drift_after_provider_get_blocks_inspector_delete(
        case, monkeypatch, tmp_path):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    with db.bind(state):
        provider = Provider()
        kwargs, jobs, _, _ = _enter_sql(case, source, options, state, provider)
        original = retirement_service._authority
        monkeypatch.setattr(retirement_service, "_authority",
                            lambda *args, **_kw: original(*args))
        monkeypatch.setattr(retirement_service, "_saved_review", lambda _parent:
                            SimpleNamespace(scopes=(SimpleNamespace(
                                provider="digitalocean", selector_retirement_pending=True),)))
        parent = jobs.get(next(
            row.input["teardownParentId"] for row in jobs.list_for_engagement(
                source.engagement_id) if row.action == retirement_service.NEGATIVE_ACTION))
        negative = jobs.get(retirement_service.negative_child_id(source.core_job_id))
        selector = StoredJobRun(
            retirement_service.interrupted_selector_id(source.core_job_id),
            retirement_service.INTERRUPTED_SELECTOR_ACTION, "succeeded",
            f"engagement:{source.engagement_id}", "engagement", source.engagement_id,
            parent.requested_by, {"teardownParentId": parent.id,
                                  "inspectorNegativeJobId": negative.id,
                                  "inspectorNegativeJournalSha256": job_event_digest(negative.events)},
            [], "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:00+00:00",
            "2026-10-15T00:00:01+00:00", [JobEvent(1, "info", "saved", {})])
        jobs.save(selector)
        def changed_request(method, path, token):
            result = provider.request(method, path, token)
            if path == "/networking/firewalls/200":
                jobs.save(StoredJobRun(
                    **{**selector.__dict__, "events": [
                        JobEvent(1, "info", "drifted", {})]}))
            return result
        kwargs["read_transport"] = SimpleNamespace(request=changed_request)
        kwargs["selector_recognizer"] = lambda *_a, **_k: selector
        with pytest.raises(retirement_service.MixedZeroApplyInspectorRetirementAttention):
            retirement_service.retire_mixed_zero_apply_inspector(
                source.engagement_id, source.core_job_id,
                **{**kwargs, "interrupted": True})
        assert (provider.host_deletes, provider.firewall_deletes) == (0, 0)
