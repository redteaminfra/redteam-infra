# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline exact OCI absence after a mixed one-shot Apply."""

from dataclasses import replace
import json
import subprocess

import pytest

from app.services import provider_keyed_mixed_zero_apply_core_absence as service
from app.services import provider_keyed_mixed_zero_apply_core_apply as apply_service
from app.services.provider_keyed_oci_exact_absence import (
    OciAbsencePending, OciExactWitness, _principal_digest,
)
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.models import CoreMutationLeaseModel, EngagementModel
from test_provider_keyed_mixed_zero_apply_core_apply import case, _go_case


def _empty_state(case):
    state = json.loads(case.core_state.read_text())
    state["serial"] += 1
    state["resources"] = []
    state["outputs"] = {}
    case.core_state.write_text(json.dumps(state))


def _ready(case, monkeypatch):
    source, actions, _, options = _go_case(case, monkeypatch)
    applied = apply_service.apply_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **options)
    assert applied.status == "succeeded" and actions == ["show", "apply"]
    _empty_state(case)
    monkeypatch.setattr(service, "_default_state_root", lambda: case.state_root)
    monkeypatch.setattr(service, "DEFAULT_TERRAFORM_STATE_ROOT", case.core_state.parents[2])
    monkeypatch.setattr(service, "_principal_digest", lambda _: "a" * 64)
    options = dict(environment="devtest", state_root=case.state_root,
                   core_state_root=case.core_state.parents[2], job_repository=case.jobs,
                   plan_repository=case.args["plan_repository"],
                   lease_lookup=options["lease_lookup"], identity_reader=lambda: {})
    return source, actions, options


def _absent(inventory, *, fence, pre_witness, **_kwargs):
    for _ in range(3):
        fence()
    return replace(pre_witness, phase="absent", evidence_sha256="e" * 64)


def test_both_orders_save_exact_absence_without_replaying_apply(case, monkeypatch):
    source, actions, options = _ready(case, monkeypatch)
    result = service.prove_mixed_zero_apply_oci_core_absence(
        source.engagement_id, source.core_job_id, **options,
        absence_prover=_absent, max_scans=2, poll_seconds=0)
    assert result.status == "succeeded"
    assert result.events[-1].data["ociAbsenceWitness"]["phase"] == "absent"
    assert actions == ["show", "apply"]
    assert case.jobs.get(result.input["teardownParentId"]).status == "queued"
    assert service.prove_mixed_zero_apply_oci_core_absence(
        source.engagement_id, source.core_job_id, **options,
        absence_prover=lambda *_a, **_kw: pytest.fail("absence replayed"),
        max_scans=2, poll_seconds=0) == result


def test_pending_scan_retries_only_read_only_absence(case, monkeypatch):
    source, actions, options = _ready(case, monkeypatch)

    def pending(_inventory, *, fence, **_kwargs):
        fence()
        raise OciAbsencePending("offline provider settling")

    with pytest.raises(service.MixedZeroApplyCoreAbsenceAttention):
        service.prove_mixed_zero_apply_oci_core_absence(
            source.engagement_id, source.core_job_id, **options,
            absence_prover=pending, max_scans=2, poll_seconds=0)
    first = case.jobs.get(service._child_prefix(source.core_job_id) + "-attempt-01")
    assert first.status == "failed"
    assert first.events[-1].data == {"retryablePendingTimeout": True}
    second = service.prove_mixed_zero_apply_oci_core_absence(
        source.engagement_id, source.core_job_id, **options,
        absence_prover=_absent, max_scans=2, poll_seconds=0)
    assert second.status == "succeeded" and second.input["previousAttemptId"] == first.id
    assert actions == ["show", "apply"]


def test_changed_empty_state_or_historical_seal_stops_before_oci(case, monkeypatch):
    source, _, options = _ready(case, monkeypatch)
    state = json.loads(case.core_state.read_text())
    state["serial"] -= 1
    case.core_state.write_text(json.dumps(state))
    with pytest.raises(service.MixedZeroApplyCoreAbsenceAttention):
        service.prove_mixed_zero_apply_oci_core_absence(
            source.engagement_id, source.core_job_id, **options,
            absence_prover=lambda *_a, **_kw: pytest.fail("OCI scanned"))
    assert case.jobs.get(service._child_prefix(source.core_job_id) + "-attempt-01") is None
    state["serial"] += 1
    case.core_state.write_text(json.dumps(state))
    applied = case.jobs.get(apply_service._child_id(source.core_job_id))
    events = list(applied.events)
    seal = dict(events[5].data)
    seal["resourceIdsSha256"] = "0" * 64
    events[5] = replace(events[5], data=seal)
    case.jobs.save(replace(applied, events=events))
    with pytest.raises(service.MixedZeroApplyCoreAbsenceAttention):
        service.prove_mixed_zero_apply_oci_core_absence(
            source.engagement_id, source.core_job_id, **options,
            absence_prover=lambda *_a, **_kw: pytest.fail("OCI scanned"))


@pytest.mark.parametrize("first_scan_pending", [False, True])
def test_real_exact_reader_requires_complete_lists_and_two_stable_scans(
        case, monkeypatch, first_scan_pending):
    source, _, _, apply_options = _go_case(case, monkeypatch)
    target = case.plan.evidence["target"]
    identity = {"id": "ocid1.instance.oc1..offlineprincipal",
                "compartmentId": target["compartmentId"],
                "canonicalRegionName": target["region"]}
    principal = _principal_digest(lambda: identity)

    def visible(inventory, *, compartment_id, region, **_kwargs):
        return OciExactWitness("present", inventory.inventory_sha256,
                               service._fingerprint({row.address: row.ocid
                                                     for row in inventory.resources}),
                               compartment_id, region, "instance_principal",
                               principal, "b" * 64)

    apply_options["visibility_prover"] = visible
    apply_service.apply_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **apply_options)
    _empty_state(case)
    monkeypatch.setattr(service, "_default_state_root", lambda: case.state_root)
    monkeypatch.setattr(service, "DEFAULT_TERRAFORM_STATE_ROOT", case.core_state.parents[2])
    calls = []
    vcn = case.jobs.get(apply_service._child_id(source.core_job_id)).events[5].data[
        "resourceIds"]["oci_core_vcn.pilot"]
    vcn_lists = 0

    def oci_runner(argv, _env):
        nonlocal vcn_lists
        calls.append(argv)
        if first_scan_pending and argv[10] == "list" and argv[8:10] == ("network", "vcn"):
            vcn_lists += 1
            if vcn_lists == 1:
                return subprocess.CompletedProcess(argv, 0, json.dumps({"data": [{
                    "id": vcn, "compartment-id": target["compartmentId"],
                    "lifecycle-state": "AVAILABLE",
                    "freeform-tags": {"barragan": "true",
                                      "barragan_engagement": "opaque-fixture",
                                      "barragan_environment": "barragan-testing",
                                      "barragan_provider": "oci", "barragan_role": "vcn"},
                }]}), "")
        if argv[10] == "list":
            return subprocess.CompletedProcess(argv, 0, json.dumps({"data": []}), "")
        return subprocess.CompletedProcess(
            argv, 1, "", 'ServiceError: {"status":404,"code":"NotAuthorizedOrNotFound"}')

    options = dict(environment="devtest", state_root=case.state_root,
                   core_state_root=case.core_state.parents[2], job_repository=case.jobs,
                   plan_repository=case.args["plan_repository"],
                   lease_lookup=apply_options["lease_lookup"],
                   oci_command_runner=oci_runner, identity_reader=lambda: identity,
                   pause=lambda _: None,
                   max_scans=3 if first_scan_pending else 2, poll_seconds=0)
    result = service.prove_mixed_zero_apply_oci_core_absence(
        source.engagement_id, source.core_job_id, **options)
    assert result.status == "succeeded"
    assert len([argv for argv in calls if argv[10] == "list"]) >= 2
    assert len([argv for argv in calls if argv[10] == "get"]) >= 2
    if first_scan_pending:
        assert vcn_lists == 3


def test_ambiguous_get_404_with_listed_resource_is_pending(case, monkeypatch):
    source, _, _, apply_options = _go_case(case, monkeypatch)
    target = case.plan.evidence["target"]
    identity = {"id": "ocid1.instance.oc1..offlineprincipal",
                "compartmentId": target["compartmentId"],
                "canonicalRegionName": target["region"]}
    principal = _principal_digest(lambda: identity)

    def visible(inventory, *, compartment_id, region, **_kwargs):
        return OciExactWitness("present", inventory.inventory_sha256,
                               service._fingerprint({row.address: row.ocid
                                                     for row in inventory.resources}),
                               compartment_id, region, "instance_principal",
                               principal, "b" * 64)

    apply_options["visibility_prover"] = visible
    apply_service.apply_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **apply_options)
    _empty_state(case)
    monkeypatch.setattr(service, "_default_state_root", lambda: case.state_root)
    monkeypatch.setattr(service, "DEFAULT_TERRAFORM_STATE_ROOT", case.core_state.parents[2])
    seal = case.jobs.get(apply_service._child_id(source.core_job_id)).events[5].data
    listed = seal["resourceIds"]["oci_core_vcn.pilot"]
    listed_row = {"id": listed, "compartment-id": target["compartmentId"],
                  "lifecycle-state": "AVAILABLE",
                  "freeform-tags": {"barragan": "true",
                                    "barragan_engagement": "opaque-fixture",
                                    "barragan_environment": "barragan-testing",
                                    "barragan_provider": "oci", "barragan_role": "vcn"}}

    def oci_runner(argv, _env):
        if argv[10] == "list" and argv[8:10] == ("network", "vcn"):
            return subprocess.CompletedProcess(argv, 0,
                                               json.dumps({"data": [listed_row]}), "")
        if argv[10] == "list":
            return subprocess.CompletedProcess(argv, 0, json.dumps({"data": []}), "")
        return subprocess.CompletedProcess(
            argv, 1, "", 'ServiceError: {"status":404,"code":"NotAuthorizedOrNotFound"}')

    with pytest.raises(service.MixedZeroApplyCoreAbsenceAttention):
        service.prove_mixed_zero_apply_oci_core_absence(
            source.engagement_id, source.core_job_id, environment="devtest",
            state_root=case.state_root, core_state_root=case.core_state.parents[2],
            job_repository=case.jobs, plan_repository=case.args["plan_repository"],
            lease_lookup=apply_options["lease_lookup"],
            oci_command_runner=oci_runner, identity_reader=lambda: identity,
            pause=lambda _: None, max_scans=2, poll_seconds=0)
    child = case.jobs.get(service._child_prefix(source.core_job_id) + "-attempt-01")
    assert child.status == "failed" and child.events[-1].data == {
        "retryablePendingTimeout": True}


@pytest.mark.parametrize("terminal_drift", ["none", "lease", "state", "parent", "apply", "plan"])
def test_sqlalchemy_terminal_writer_rechecks_authority_and_restart(
        case, monkeypatch, tmp_path, terminal_drift):
    source, actions, options = _ready(case, monkeypatch)
    state = db.configure(f"sqlite:///{tmp_path / 'mixed-absence.sqlite'}")
    with db.bind(state):
        db.create_all()
        db.session.add(EngagementModel(id=source.engagement_id, name="opaque-fixture",
                                       status="active", owner="operator", template_id="small"))
        db.session.add(CoreMutationLeaseModel(
            engagement_id=source.engagement_id, owner_id=source.core_plan_id,
            operation=service._FENCE))
        db.session.commit()
        jobs = SqlAlchemyJobRepository()
        for row in case.jobs.list_for_engagement(source.engagement_id):
            jobs.save(replace(row, created_at="2026-10-15T00:00:00+00:00",
                              started_at=("2026-10-15T00:00:01+00:00"
                                          if row.started_at is not None else None),
                              finished_at=("2026-10-15T00:00:02+00:00"
                                           if row.finished_at is not None else None)))
        options["job_repository"] = jobs
        original_finish = jobs.finish_mixed_core_absence_if_claimed
        injected = False

        def finish_with_race(*args, **kwargs):
            nonlocal injected
            if kwargs["status"] == "succeeded" and terminal_drift != "none" and not injected:
                injected = True
                if terminal_drift == "lease":
                    db.session.query(CoreMutationLeaseModel).delete()
                    db.session.commit()
                elif terminal_drift == "state":
                    case.core_state.write_bytes(case.core_state.read_bytes() + b"\n")
                elif terminal_drift == "parent":
                    parent = jobs.get(
                        f"job-provider-keyed-mixed-zero-apply-cleanup-{source.core_job_id.removeprefix('job-')}")
                    jobs.save(replace(parent, requested_by="other-operator"))
                elif terminal_drift == "apply":
                    applied = jobs.get(apply_service._child_id(source.core_job_id))
                    jobs.save(replace(applied, requested_by="other-operator"))
                else:
                    case.plan.evidence["terraformFingerprint"] = "changed"
            return original_finish(*args, **kwargs)

        jobs.finish_mixed_core_absence_if_claimed = finish_with_race
        if terminal_drift != "none":
            with pytest.raises(service.MixedZeroApplyCoreAbsenceAttention):
                service.prove_mixed_zero_apply_oci_core_absence(
                    source.engagement_id, source.core_job_id, **options,
                    absence_prover=_absent, max_scans=2, poll_seconds=0)
            assert injected
            assert jobs.get(service._child_prefix(source.core_job_id) + "-attempt-01").status != "succeeded"
            return
        saved = service.prove_mixed_zero_apply_oci_core_absence(
            source.engagement_id, source.core_job_id, **options,
            absence_prover=_absent, max_scans=2, poll_seconds=0)
        assert saved.status == "succeeded"
    reopened = db.configure(state.uri)
    with db.bind(reopened):
        options["job_repository"] = SqlAlchemyJobRepository()
        assert service.prove_mixed_zero_apply_oci_core_absence(
            source.engagement_id, source.core_job_id, **options,
            absence_prover=lambda *_a, **_kw: pytest.fail("absence replayed"),
            max_scans=2, poll_seconds=0).id == saved.id
        assert actions == ["show", "apply"]
