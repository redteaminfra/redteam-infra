# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline mixed core public-negative proof through persisted teardown journals."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_mixed_zero_apply_core_absence as absence
from app.services import provider_keyed_mixed_zero_apply_inspector_negative as service
from app.services.observer_checks import ObserverHost, ObserverSshKey
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.models import CoreMutationLeaseModel, EngagementModel
from app.storage.observer_settings_repository import StoredInspectorSettings
from test_provider_keyed_mixed_zero_apply_core_absence import case, _ready, _absent


CONTROL = {"id": "inspector-external-control", "type": "tcp",
           "host": "1.1.1.1", "port": 443}


def _proof(case, monkeypatch):
    source, actions, options = _ready(case, monkeypatch)
    absent = absence.prove_mixed_zero_apply_oci_core_absence(
        source.engagement_id, source.core_job_id, **options,
        absence_prover=_absent, max_scans=2, poll_seconds=0)
    core = case.jobs.get(case.args["core_job_id"])
    events = list(core.events)
    details = [
        {"role": "homebase", "publicIp": "8.8.8.8"},
        {"role": "proxy", "publicIp": "9.9.9.9"}]
    events[-1] = replace(events[-1], data={**events[-1].data,
                                           "connectionDetails": details})
    events.insert(-2, JobEvent(events[-2].sequence, "info", "operator inspection ready",
                                {"connectionDetails": details}))
    events[-2] = replace(events[-2], sequence=events[-2].sequence + 1)
    events[-1] = replace(events[-1], sequence=events[-1].sequence + 1)
    case.jobs.save(replace(core, events=events))
    instance_owner = next(row.adoption_job_id for row in case.rows
                          if row.resource_type == "inspector_instance")
    case.rows[:] = [replace(row, metadata={**row.metadata,
        **({"publicIp": "4.4.4.4"} if row.resource_type == "inspector_instance"
           else {"inspectorHostResourceId": "100"})}, status="active",
        adoption_job_id=instance_owner)
        for row in case.rows]
    host = ObserverHost("linode", "instance", "100", "inspector", "us-east",
                        "4.4.4.4", metadata={"providerFirewall": {
                            "resourceId": "200"}})
    settings = StoredInspectorSettings(
        source.engagement_id, True, "linode", "us-east", "g6-nanode-1",
        "continuous", [], "00:00", [], [], [], host.to_dict(), "", "", "",
        "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:00+00:00")
    settings_repo = SimpleNamespace(get=lambda _: settings)
    resources = SimpleNamespace(list_for_engagement=lambda _: case.rows)
    targets_seen = []

    class Runner:
        def run(self, *, host, ssh_key, spec):
            targets_seen.append(spec["negative"])
            return {"ok": True, "results": [
                {"id": CONTROL["id"], "type": "tcp", "expected": "reachable",
                 "observed": "", "ok": True},
                *[{"id": target["id"], "type": "tcp-forbidden",
                   "expected": "closed", "observed": {
                       "status": "closed", "reason": "connection_refused"}, "ok": True}
                  for target in spec["negative"]]]}

    proof_options = dict(environment="devtest", state_root=case.state_root,
                         core_state_root=case.core_state.parents[2],
                         positive_control=CONTROL,
                         job_repository=case.jobs,
                         plan_repository=case.args["plan_repository"],
                         settings_repository=settings_repo,
                         provider_resource_repository=resources,
                         lease_lookup=options["lease_lookup"],
                         runner=Runner(),
                         ssh_key_factory=lambda _: ObserverSshKey(
                             str(Path(case.state_root) / "inspector-key"),
                             "ssh-ed25519 offline"),
                         identity_reader=lambda: {})
    return source, absent, proof_options, targets_seen


def test_both_provider_orders_persist_two_rounds_and_restart_without_probe(case, monkeypatch):
    source, absent, options, seen = _proof(case, monkeypatch)
    result = service.prove_mixed_zero_apply_inspector_negative(
        source.engagement_id, source.core_job_id, **options)
    assert result.status == "succeeded" and len(seen) == 2
    assert result.input["ociAbsenceJobId"] == absent.id
    assert {row["host"] for row in seen[0]} == {"8.8.8.8", "9.9.9.9"}
    options["runner"] = SimpleNamespace(run=lambda **_: pytest.fail("reprobed"))
    assert service.prove_mixed_zero_apply_inspector_negative(
        source.engagement_id, source.core_job_id, **options) == result


def test_bad_control_or_saved_target_stops_without_probe(case, monkeypatch):
    source, _, options, seen = _proof(case, monkeypatch)
    options["positive_control"] = {**CONTROL, "host": "8.8.8.8"}
    with pytest.raises(service.MixedZeroApplyInspectorNegativeAttention):
        service.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **options)
    assert seen == []
    options["positive_control"] = CONTROL
    core = case.jobs.get(source.core_job_id)
    events = list(core.events)
    events[-1] = replace(events[-1], data={**events[-1].data,
        "connectionDetails": [{"role": "homebase", "publicIp": "8.8.8.8"}]})
    case.jobs.save(replace(core, events=events))
    with pytest.raises(service.MixedZeroApplyInspectorNegativeAttention):
        service.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **options)
    assert seen == []


def test_inspector_itself_cannot_be_positive_control(case, monkeypatch):
    source, _, options, seen = _proof(case, monkeypatch)
    options["positive_control"] = {**CONTROL, "host": "4.4.4.4"}
    with pytest.raises(service.MixedZeroApplyInspectorNegativeAttention):
        service.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **options)
    assert seen == []


def test_inconclusive_control_seals_failed_child_and_bounded_retry(case, monkeypatch):
    source, _, options, seen = _proof(case, monkeypatch)
    options["runner"] = SimpleNamespace(run=lambda **_: {
        "ok": False, "results": []})
    with pytest.raises(service.MixedZeroApplyInspectorNegativeAttention):
        service.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **options)
    child = case.jobs.get(service._child_id(source.core_job_id))
    assert child.status == "failed"
    with pytest.raises(service.MixedZeroApplyInspectorNegativeAttention):
        service.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **options)
    assert seen == []
    second = case.jobs.get(service._attempt_id(source.core_job_id, 2))
    assert second.status == "failed"
    assert case.jobs.get(child.id) == child
    with pytest.raises(service.MixedZeroApplyInspectorNegativeAttention):
        service.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **options)
    assert case.jobs.get(service._attempt_id(source.core_job_id, 3)).status == "failed"
    with pytest.raises(service.MixedZeroApplyInspectorNegativeAttention):
        service.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **options)
    assert len([row for row in case.jobs.list_for_engagement(source.engagement_id)
                if row.action == service.ACTION]) == 3


def test_failed_probe_retries_with_exact_journal_lineage(case, monkeypatch):
    source, _, options, seen = _proof(case, monkeypatch)
    good_runner = options["runner"]
    options["runner"] = SimpleNamespace(run=lambda **_: {"ok": False, "results": []})
    with pytest.raises(service.MixedZeroApplyInspectorNegativeAttention):
        service.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **options)
    first = case.jobs.get(service._child_id(source.core_job_id))
    options["runner"] = good_runner
    second = service.prove_mixed_zero_apply_inspector_negative(
        source.engagement_id, source.core_job_id, **options)
    assert second.id == service._attempt_id(source.core_job_id, 2)
    assert second.status == "succeeded" and len(seen) == 2
    assert second.input["previousNegativeJobId"] == first.id
    assert second.input["previousNegativeJournalSha256"] == service.job_event_digest(first.events)
    assert case.jobs.get(first.id) == first
    assert service.latest_negative_attempt(case.jobs, source.engagement_id,
                                           source.core_job_id) == second
    options["runner"] = SimpleNamespace(run=lambda **_: pytest.fail("reprobed"))
    assert service.prove_mixed_zero_apply_inspector_negative(
        source.engagement_id, source.core_job_id, **options) == second
    case.jobs.save(replace(first, events=[*first.events[:2],
                            JobEvent(3, "error", "altered failed proof", {})]))
    with pytest.raises(ValueError, match="terminal failure"):
        service.latest_negative_attempt(case.jobs, source.engagement_id,
                                        source.core_job_id)


def test_failed_probe_lineage_tamper_and_running_fail_closed(case, monkeypatch):
    source, _, options, _ = _proof(case, monkeypatch)
    options["runner"] = SimpleNamespace(run=lambda **_: {"ok": False, "results": []})
    with pytest.raises(service.MixedZeroApplyInspectorNegativeAttention):
        service.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **options)
    first = case.jobs.get(service._child_id(source.core_job_id))
    case.jobs.save(replace(first, status="running", finished_at=None))
    with pytest.raises(service.MixedZeroApplyInspectorNegativeAttention):
        service.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **options)
    assert case.jobs.get(service._attempt_id(source.core_job_id, 2)) is None
    case.jobs.save(replace(first, input={**first.input, "targetCount": 999}))
    with pytest.raises(service.MixedZeroApplyInspectorNegativeAttention):
        service.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **options)
    assert case.jobs.get(service._attempt_id(source.core_job_id, 2)) is None


def test_inspector_record_drift_stops_before_probe(case, monkeypatch):
    source, _, options, seen = _proof(case, monkeypatch)
    case.rows[0] = replace(case.rows[0], status="destroyed")
    with pytest.raises(service.MixedZeroApplyInspectorNegativeAttention):
        service.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **options)
    assert seen == []


def test_missing_absence_receipt_never_starts_new_oci_scan(case, monkeypatch):
    source, absent, options, seen = _proof(case, monkeypatch)
    case.jobs.save(replace(absent, status="failed"))
    options["absence_recognizer"] = lambda *_args, **_kwargs: pytest.fail(
        "new OCI scan started")
    with pytest.raises(service.MixedZeroApplyInspectorNegativeAttention):
        service.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **options)
    assert seen == []


def test_timeout_is_classified_only_with_reachable_control(case, monkeypatch):
    source, _, options, seen = _proof(case, monkeypatch)

    def timed_out(*, spec, **_kwargs):
        seen.append(spec["negative"])
        return {"ok": False, "results": [
            {"id": CONTROL["id"], "type": "tcp", "expected": "reachable",
             "observed": "", "ok": True},
            *[{"id": target["id"], "type": "tcp-forbidden",
               "expected": "closed", "observed": {
                   "status": "inconclusive", "reason": "timed_out",
                   "errorType": "TimeoutError"}, "ok": False}
              for target in spec["negative"]]]}

    options["runner"] = SimpleNamespace(run=timed_out)
    result = service.prove_mixed_zero_apply_inspector_negative(
        source.engagement_id, source.core_job_id, **options)
    assert result.status == "succeeded" and len(seen) == 2
    assert all(row["classification"] == "non_reachable_after_provider_absence"
               for row in result.events[-1].data["classifications"][0])


@pytest.mark.parametrize("terminal_drift", [
    "none", "lease", "lease_in_transaction", "parent", "state", "inspector"])
def test_sql_job_receipt_survives_repository_restart(
        case, monkeypatch, tmp_path, terminal_drift):
    source, _, options, seen = _proof(case, monkeypatch)
    state = db.configure(f"sqlite:///{tmp_path / 'mixed-negative.sqlite'}")
    with db.bind(state):
        db.create_all()
        db.session.add(EngagementModel(
            id=source.engagement_id, name="opaque-fixture", status="active",
            owner="operator", template_id="small"))
        db.session.add(CoreMutationLeaseModel(
            engagement_id=source.engagement_id, owner_id=source.core_plan_id,
            operation="provider_keyed_teardown_fence"))
        db.session.commit()
        sql_jobs = SqlAlchemyJobRepository()
        for row in case.jobs.list_for_engagement(source.engagement_id):
            sql_jobs.save(replace(
                row,
                created_at=("2026-10-15T00:00:00+00:00" if row.created_at == "now"
                            else row.created_at),
                started_at=("2026-10-15T00:00:00+00:00" if row.started_at == "now"
                            else row.started_at),
                finished_at=("2026-10-15T00:00:00+00:00" if row.finished_at == "now"
                             else row.finished_at)))
        options["job_repository"] = sql_jobs
        original_finish = sql_jobs.finish_mixed_inspector_negative_if_running
        injected = False

        def finish_with_race(*args, **kwargs):
            nonlocal injected
            if terminal_drift != "none" and not injected:
                injected = True
                if terminal_drift == "lease_in_transaction":
                    authority_check = kwargs["authority_check"]

                    def changed_under_writer_slot():
                        db.session.query(CoreMutationLeaseModel).delete()
                        authority_check()

                    kwargs["authority_check"] = changed_under_writer_slot
                elif terminal_drift == "lease":
                    db.session.query(CoreMutationLeaseModel).delete()
                    db.session.commit()
                elif terminal_drift == "parent":
                    parent = sql_jobs.get(
                        f"job-provider-keyed-mixed-zero-apply-cleanup-"
                        f"{source.core_job_id.removeprefix('job-')}")
                    sql_jobs.save(replace(parent, requested_by="other-operator"))
                elif terminal_drift == "state":
                    case.core_state.write_bytes(case.core_state.read_bytes() + b"\n")
                else:
                    case.rows[0] = replace(case.rows[0], status="destroyed")
            return original_finish(*args, **kwargs)

        sql_jobs.finish_mixed_inspector_negative_if_running = finish_with_race
        if terminal_drift != "none":
            with pytest.raises(service.MixedZeroApplyInspectorNegativeAttention):
                service.prove_mixed_zero_apply_inspector_negative(
                    source.engagement_id, source.core_job_id, **options)
            assert injected
            assert sql_jobs.get(service._child_id(source.core_job_id)).status != "succeeded"
            return
        result = service.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **options)
        assert result.status == "succeeded" and len(seen) == 2
        options["job_repository"] = SqlAlchemyJobRepository()
        options["runner"] = SimpleNamespace(run=lambda **_: pytest.fail("reprobed"))
        assert service.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **options) == result
