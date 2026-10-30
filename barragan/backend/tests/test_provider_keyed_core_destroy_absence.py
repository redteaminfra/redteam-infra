# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted exact OCI core absence follows only a completed saved-plan GO."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import os
import pwd
from pathlib import Path
import sqlite3
import subprocess
from types import SimpleNamespace

import pytest

from app.services import provider_keyed_core_destroy_absence as service
from app.services import provider_keyed_core_destroy_apply as apply_service
from app.services.provider_keyed_oci_core_state import parse_applied_oci_core_state
from app.services.provider_keyed_oci_exact_absence import prove_oci_core_visibility
from app.storage.job_repository import SqliteJobRepository
from test_provider_keyed_core_destroy_apply import _ready
from test_provider_keyed_oci_core_state import _ROLES


def _case(tmp_path, monkeypatch):
    fake, parent, core, coordinator, plan, preview, state_path, _, _, args = _ready(
        tmp_path, monkeypatch)
    stored = SqliteJobRepository(tmp_path / "jobs.sqlite")
    for row in (parent, core, coordinator, preview):
        stored.save(row)
    snapshot = {"providerScopes": [{"corePlanId": plan.id}], "snapshotId": "c" * 64}
    monkeypatch.setattr(apply_service, "_boundary", lambda *_: (
        stored.get(parent.id), stored.get(core.id), snapshot, apply_service._FENCE))
    args["job_repository"] = stored
    inventory = parse_applied_oci_core_state(
        state_path.read_bytes(), proxy_count=plan.evidence["proxyCount"],
        elk_enabled=plan.evidence["elkEnabled"],
        compartment_id=plan.evidence["target"]["compartmentId"],
        engagement_name=core.input["engagementName"])
    identity = {"id": "ocid1.instance.oc1..barraganapp",
                "compartmentId": plan.evidence["target"]["compartmentId"],
                "canonicalRegionName": plan.evidence["target"]["region"]}
    rows = {}
    for resource in inventory.resources:
        kind, role = _ROLES[resource.address]
        rows[resource.ocid] = {
            "id": resource.ocid,
            "compartment-id": plan.evidence["target"]["compartmentId"],
            "freeform-tags": {"barragan": "true", "barragan_engagement": "Disposable",
                              "barragan_environment": "barragan-testing",
                              "barragan_provider": "oci", "barragan_role": role},
            "lifecycle-state": "RUNNING" if kind == "instance" else "AVAILABLE",
        }
    calls = []
    mode = {"absent": False}

    def cli(argv, env):
        calls.append(argv)
        assert env == {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
                       "HOME": "/nonexistent",
                       "PYTHONUSERBASE": str(Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".local"),
                       "PYTHONWARNINGS": "ignore:The 'strict' parameter is no longer needed on Python 3+:FutureWarning:urllib3.poolmanager"}
        if argv[10] == "list":
            name = argv[9]
            kind = {"dhcp-options": "dhcpoptions", "internet-gateway": "internetgateway",
                    "nat-gateway": "natgateway", "route-table": "routetable",
                    "security-list": "securitylist"}.get(name, name)
            data = [] if mode["absent"] else [row for ocid, row in rows.items()
                                               if ocid.split(".")[1] == kind]
            return subprocess.CompletedProcess(argv, 0, json.dumps({"data": data}), "")
        if not mode["absent"]:
            return subprocess.CompletedProcess(argv, 0,
                                               json.dumps({"data": rows[argv[-1]]}), "")
        return subprocess.CompletedProcess(
            argv, 1, "", 'ServiceError: {"status":404,"code":"NotAuthorizedOrNotFound"}')

    args["oci_command_runner"] = cli
    args["visibility_prover"] = lambda observed, **kwargs: prove_oci_core_visibility(
        observed, **kwargs, identity_reader=lambda: dict(identity))
    applied = apply_service.apply_pending_keyed_oci_core_destroy(parent.id, **args)
    assert applied.status == "succeeded"
    mode["absent"] = True
    # The fake Terraform command writes an incomplete state; supply the exact
    # normal empty v4 state that the successor must prove.
    seal = next(event.data for event in applied.events
                if event.message == "core destroy prestate identity fenced")
    state_path.write_text(json.dumps({"version": 4, "terraform_version": "1.15.5",
                                      "lineage": seal["lineage"], "serial": seal["serial"] + 1,
                                      "outputs": {}, "resources": []}))
    monkeypatch.setattr(service, "_default_state_root", lambda: args["state_root"])
    monkeypatch.setattr(service, "DEFAULT_TERRAFORM_STATE_ROOT", state_path.parents[2])
    monkeypatch.setattr(service, "_boundary", lambda *_: (
        stored.get(parent.id), stored.get(core.id), snapshot, service._FENCE))
    options = dict(environment="devtest", state_root=args["state_root"],
                   job_repository=stored, plan_repository=args["plan_repository"],
                   lease_lookup=args["lease_lookup"], oci_command_runner=cli,
                   identity_reader=lambda: dict(identity), max_scans=3,
                   poll_seconds=0, pause=lambda _: None)
    return stored, parent, plan, state_path, identity, calls, cli, options


def test_persisted_exact_absence_and_restart_does_not_repeat_scans(tmp_path, monkeypatch):
    stored, parent, _, _, _, calls, _, options = _case(tmp_path, monkeypatch)
    result = service.prove_pending_keyed_oci_core_destroy_absence(parent.id, **options)
    assert result.status == "succeeded"
    assert result.events[-1].message == "core destroy exact absence proved"
    assert result.events[-1].data["ociAbsenceWitness"]["phase"] == "absent"
    assert len(calls) > 20  # two all-family lists and every exact ID GET
    fresh = SqliteJobRepository(stored.database_path)
    assert fresh.get(result.id) == result
    assert service.prove_pending_keyed_oci_core_destroy_absence(parent.id,
        **{**options, "job_repository": fresh}) == result
    assert fresh.get(result.id) == result


@pytest.mark.parametrize("variant", ["principal", "pending", "unauthorized", "malformed", "state"])
def test_ambiguous_absence_never_succeeds(tmp_path, monkeypatch, variant):
    stored, parent, plan, state_path, identity, calls, cli, options = _case(tmp_path, monkeypatch)
    if variant == "principal":
        identity["id"] = "ocid1.instance.oc1..someoneelse"
    elif variant == "pending":
        applied = next(row for row in stored.list_for_engagement(parent.target_id)
                       if row.action == apply_service.ACTION)
        selected = next(event.data["resourceIds"]["oci_core_default_dhcp_options.pilot"]
                        for event in applied.events
                        if event.message == "core destroy prestate identity fenced")
        def pending(argv, env):
            if argv[10] == "list" or argv[-1] != selected:
                return cli(argv, env)
            ocid = argv[-1]
            calls.append(argv)
            row = {"id": ocid, "compartment-id": plan.evidence["target"]["compartmentId"],
                   "freeform-tags": {"barragan": "true", "barragan_engagement": "Disposable",
                                     "barragan_environment": "barragan-testing",
                                     "barragan_provider": "oci",
                                     "barragan_role": "default_dhcp_options"},
                   "lifecycle-state": "TERMINATING"}
            return subprocess.CompletedProcess(argv, 0, json.dumps({"data": row}), "")
        options["oci_command_runner"] = pending
    elif variant == "unauthorized":
        options["oci_command_runner"] = lambda argv, env: subprocess.CompletedProcess(
            argv, 1, "", 'ServiceError: {"status":403,"code":"NotAuthorizedOrNotFound"}')
    elif variant == "malformed":
        options["oci_command_runner"] = lambda argv, env: subprocess.CompletedProcess(
            argv, 0, '{"data": {}}', "")
    else:
        state = json.loads(state_path.read_text())
        state["serial"] = 1
        state_path.write_text(json.dumps(state))
    with pytest.raises(service.KeyedCoreDestroyAbsenceAttention):
        service.prove_pending_keyed_oci_core_destroy_absence(parent.id, **options)
    children = [row for row in stored.list_for_engagement(parent.target_id)
                if row.action == service.ACTION]
    assert all(row.status != "succeeded" for row in children)
    if variant == "pending":
        assert len(calls) >= 24  # three bounded complete LIST rounds
        assert children[0].status == "failed"
        assert children[0].events[-1].message == "core destroy absence unverified"
        assert children[0].events[-1].data == {"retryablePendingTimeout": True}
    elif children:
        assert children[0].events[-1].data == {"retryablePendingTimeout": False}
    assert stored.get(parent.id).status == "queued"


def test_persisted_pending_timeout_retries_read_only_with_same_authority(tmp_path, monkeypatch):
    stored, parent, plan, _, _, calls, absent_cli, options = _case(tmp_path, monkeypatch)
    inventory = next(row for row in stored.list_for_engagement(parent.target_id)
                     if row.action == apply_service.ACTION)
    ocid = next(event.data["resourceIds"]["oci_core_default_dhcp_options.pilot"]
                for event in inventory.events
                if event.message == "core destroy prestate identity fenced")

    def pending(argv, env):
        if argv[10] != "get" or argv[-1] != ocid:
            return absent_cli(argv, env)
        calls.append(argv)
        row = {"id": ocid, "compartment-id": plan.evidence["target"]["compartmentId"],
               "freeform-tags": {"barragan": "true", "barragan_engagement": "Disposable",
                                 "barragan_environment": "barragan-testing",
                                 "barragan_provider": "oci",
                                 "barragan_role": "default_dhcp_options"},
               "lifecycle-state": "TERMINATING"}
        return subprocess.CompletedProcess(argv, 0, json.dumps({"data": row}), "")

    options["oci_command_runner"] = pending
    with pytest.raises(service.KeyedCoreDestroyAbsenceAttention):
        service.prove_pending_keyed_oci_core_destroy_absence(parent.id, **options)
    first = next(row for row in stored.list_for_engagement(parent.target_id)
                 if row.action == service.ACTION)
    assert first.status == "failed" and first.input["attempt"] == 1
    assert first.events[-1].data == {"retryablePendingTimeout": True}
    fresh = SqliteJobRepository(stored.database_path)
    options.update(job_repository=fresh, oci_command_runner=absent_cli)
    second = service.prove_pending_keyed_oci_core_destroy_absence(parent.id, **options)
    assert second.status == "succeeded" and second.input["attempt"] == 2
    assert second.input["previousAttemptId"] == first.id
    assert second.input["previousAttemptJournalSha256"]
    assert SqliteJobRepository(stored.database_path).get(first.id) == first


def test_nonretryable_ambiguity_does_not_allocate_next_attempt(tmp_path, monkeypatch):
    stored, parent, _, _, _, _, _, options = _case(tmp_path, monkeypatch)
    options["oci_command_runner"] = lambda argv, env: subprocess.CompletedProcess(
        argv, 1, "", 'ServiceError: {"status":403,"code":"NotAuthorizedOrNotFound"}')
    with pytest.raises(service.KeyedCoreDestroyAbsenceAttention):
        service.prove_pending_keyed_oci_core_destroy_absence(parent.id, **options)
    options["oci_command_runner"] = lambda argv, env: subprocess.CompletedProcess(
        argv, 0, '{"data": []}', "")
    with pytest.raises(service.KeyedCoreDestroyAbsenceAttention):
        service.prove_pending_keyed_oci_core_destroy_absence(parent.id, **options)
    assert len([row for row in stored.list_for_engagement(parent.target_id)
                if row.action == service.ACTION]) == 1


def test_prior_deployment_generation_absence_child_does_not_block_current(tmp_path, monkeypatch):
    stored, parent, _, _, _, _, _, options = _case(tmp_path, monkeypatch)
    historical = replace(parent,
                         id="job-provider-keyed-core-destroy-absence-old-core-attempt-01",
                         action=service.ACTION, status="succeeded")
    stored.save(historical)
    current = service.prove_pending_keyed_oci_core_destroy_absence(parent.id, **options)
    assert current.status == "succeeded" and current.input["attempt"] == 1
    assert stored.get(historical.id) == historical


def test_success_recognizer_rejects_principal_drift(tmp_path, monkeypatch):
    stored, parent, _, _, identity, _, _, options = _case(tmp_path, monkeypatch)
    result = service.prove_pending_keyed_oci_core_destroy_absence(parent.id, **options)
    identity["id"] = "ocid1.instance.oc1..otherhost"
    with pytest.raises(service.KeyedCoreDestroyAbsenceAttention):
        service.prove_pending_keyed_oci_core_destroy_absence(parent.id, **options)
    assert stored.get(result.id) == result


def test_local_scan_deadline_is_retryable_without_false_success(tmp_path, monkeypatch):
    stored, parent, _, _, _, _, _, options = _case(tmp_path, monkeypatch)
    monkeypatch.setattr(service, "_ATTEMPT_SECONDS", -1)
    with pytest.raises(service.KeyedCoreDestroyAbsenceAttention):
        service.prove_pending_keyed_oci_core_destroy_absence(parent.id, **options)
    first = next(row for row in stored.list_for_engagement(parent.target_id)
                 if row.action == service.ACTION)
    assert first.status == "failed"
    assert first.events[-1].data == {"retryablePendingTimeout": True}
    monkeypatch.setattr(service, "_ATTEMPT_SECONDS", 900)
    second = service.prove_pending_keyed_oci_core_destroy_absence(parent.id, **options)
    assert second.status == "succeeded" and second.input["attempt"] == 2


def test_delayed_retry_obeys_total_budget_during_scan(tmp_path, monkeypatch):
    stored, parent, _, _, _, _, _, options = _case(tmp_path, monkeypatch)
    monkeypatch.setattr(service, "_ATTEMPT_SECONDS", -1)
    with pytest.raises(service.KeyedCoreDestroyAbsenceAttention):
        service.prove_pending_keyed_oci_core_destroy_absence(parent.id, **options)
    first = next(row for row in stored.list_for_engagement(parent.target_id)
                 if row.action == service.ACTION)
    old = (datetime.now(timezone.utc) - timedelta(seconds=44 * 60)).isoformat()
    with sqlite3.connect(stored.database_path) as connection:
        connection.execute("UPDATE job_runs SET created_at = ? WHERE id = ?", (old, first.id))
    monkeypatch.setattr(service, "_ATTEMPT_SECONDS", 900)
    reads = {"count": 0}

    def clock():
        reads["count"] += 1
        return 0 if reads["count"] == 1 else 61

    monkeypatch.setattr(service, "time", SimpleNamespace(monotonic=clock))
    with pytest.raises(service.KeyedCoreDestroyAbsenceAttention):
        service.prove_pending_keyed_oci_core_destroy_absence(parent.id, **options)
    second = next(row for row in stored.list_for_engagement(parent.target_id)
                  if row.action == service.ACTION and row.input["attempt"] == 2)
    assert second.status == "failed"
    assert second.events[-1].data == {"retryablePendingTimeout": True}
    assert reads["count"] >= 2
