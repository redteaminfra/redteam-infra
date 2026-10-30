# Copyright (c) 2026, Oracle and/or its affiliates.
"""File-backed private core cleanup continuation across process restarts.

This deliberately starts *after* pending Sketch retirement. The upstream
retirement recognizer and the test Terraform source manifest are fixtures; the
saved core destroy plan check, claimed one-shot apply, positive OCI visibility,
and post-destroy exact OCI absence checks run through their real services.
There is no public teardown dispatcher or Inspector/selector cleanup here.
"""

import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from app.services import provider_keyed_core_destroy_absence as absence_service
from app.services import provider_keyed_core_destroy_apply as apply_service
from app.services import provider_keyed_core_destroy_preview as preview_service
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_oci_core_state import parse_applied_oci_core_state
from app.services.provider_keyed_oci_exact_absence import prove_oci_core_visibility
from app.storage.job_repository import SqliteJobRepository
from test_provider_keyed_core_destroy_preview import _case
from test_provider_keyed_oci_core_state import _ROLES


def _persisted_core(tmp_path, monkeypatch):
    temporary, parent, core, coordinator, plan, _, state_path, _, _, options = _case(
        tmp_path, monkeypatch)
    database = tmp_path / "core-cleanup.sqlite"
    stored = SqliteJobRepository(database)
    for row in (parent, core, coordinator):
        stored.save(row)
    snapshot = {"providerScopes": [{"corePlanId": plan.id}], "snapshotId": "c" * 64}

    def boundary(_parent_id, jobs, _plans, _lookup):
        return jobs.get(parent.id), jobs.get(core.id), snapshot, preview_service._FENCE

    monkeypatch.setattr(preview_service, "_boundary", boundary)
    monkeypatch.setattr(apply_service, "_boundary", boundary)
    monkeypatch.setattr(absence_service, "_boundary", boundary)
    monkeypatch.setattr(apply_service, "_default_state_root", lambda: options["state_root"])
    monkeypatch.setattr(absence_service, "_default_state_root", lambda: options["state_root"])
    monkeypatch.setattr(apply_service, "DEFAULT_TERRAFORM_STATE_ROOT", state_path.parents[2])
    monkeypatch.setattr(absence_service, "DEFAULT_TERRAFORM_STATE_ROOT", state_path.parents[2])
    options["job_repository"] = stored
    preview = preview_service.preview_pending_keyed_oci_core_destroy(parent.id, **options)
    assert preview.status == "succeeded"

    inventory = parse_applied_oci_core_state(
        state_path.read_bytes(), proxy_count=plan.evidence["proxyCount"],
        elk_enabled=plan.evidence["elkEnabled"],
        compartment_id=plan.evidence["target"]["compartmentId"],
        engagement_name=core.input["engagementName"],
    )
    target = plan.evidence["target"]
    identity = {"id": "ocid1.instance.oc1..barraganapp",
                "compartmentId": target["compartmentId"],
                "canonicalRegionName": target["region"]}
    rows = {}
    for resource in inventory.resources:
        kind, role = _ROLES[resource.address]
        rows[resource.ocid] = {
            "id": resource.ocid, "compartment-id": target["compartmentId"],
            "freeform-tags": {"barragan": "true", "barragan_engagement": "Disposable",
                              "barragan_environment": "barragan-testing",
                              "barragan_provider": "oci", "barragan_role": role},
            "lifecycle-state": "RUNNING" if kind == "instance" else "AVAILABLE",
        }
    mode = {"absent": False}
    provider_calls = []

    def oci(argv, env):
        provider_calls.append(argv)
        assert argv[:8] == (str(cli), "--auth", "instance_principal", "--region",
                            target["region"], "--output", "json", "--no-retry")
        assert argv[10] in {"get", "list"}
        if argv[10] == "list":
            assert argv[11:] == ("--compartment-id", target["compartmentId"], "--all")
            kind = {"dhcp-options": "dhcpoptions", "internet-gateway": "internetgateway",
                    "nat-gateway": "natgateway", "route-table": "routetable",
                    "security-list": "securitylist"}.get(argv[9], argv[9])
            data = [] if mode["absent"] else [row for ocid, row in rows.items()
                                              if ocid.split(".")[1] == kind]
            return subprocess.CompletedProcess(argv, 0, json.dumps({"data": data}), "")
        if mode["absent"]:
            return subprocess.CompletedProcess(
                argv, 1, "", 'ServiceError: {"status":404,"code":"NotAuthorizedOrNotFound"}')
        return subprocess.CompletedProcess(argv, 0,
                                           json.dumps({"data": rows[argv[-1]]}), "")

    shown = options["command_runner"](
        ["terraform", "show", "-json", "ignored"],
        Path(plan.evidence["runDirectory"]),
        {"TF_DATA_DIR": plan.evidence["terraformDataDir"]},
    ).stdout
    commands = []

    def gated(argv, *, scratch_path, intent_callback, started_callback,
              heartbeat_callback, result_callback, **_kwargs):
        commands.append(tuple(argv))
        intent = CommandIntent(
            f"invocation-{len(commands)}", str(scratch_path),
            hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest(),
        )
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 456))
        started_callback(started)
        heartbeat_callback(started)
        if argv[1] == "apply":
            assert argv[-1] == preview.events[-1].data["planPath"]
            mode["absent"] = True
            seal = next(event.data for event in SqliteJobRepository(database).get(
                f"job-provider-keyed-core-destroy-apply-{core.id.removeprefix('job-')}").events
                if event.message == "core destroy prestate identity fenced")
            state_path.write_text(json.dumps({
                "version": 4, "terraform_version": "1.15.5",
                "lineage": seal["lineage"], "serial": seal["serial"] + 1,
                "outputs": {}, "resources": [],
            }))
        audit = CommandAuditResult(started, 0, len(shown) if argv[1] == "show" else 0,
                                   0, False, False)
        result_callback(audit)
        return CommandResult(started, 0, shown if argv[1] == "show" else "", "",
                             False, False)

    cli = tmp_path / "oci"
    cli.write_text("#!/bin/sh\nexit 0\n")
    cli.chmod(0o700)
    common = dict(environment="devtest", state_root=options["state_root"],
                  plan_repository=options["plan_repository"],
                  lease_lookup=options["lease_lookup"])
    apply_options = dict(
        **common, retired_recognizer=options["retired_recognizer"],
        release_check=options["release_check"], source_check=lambda *_: None,
        gated_command_runner=gated, oci_command_runner=oci, oci_executable=cli,
        visibility_prover=lambda observed, **kwargs: prove_oci_core_visibility(
            observed, **kwargs, identity_reader=lambda: dict(identity)),
    )
    absence_options = dict(
        **common, oci_command_runner=oci, identity_reader=lambda: dict(identity),
        max_scans=3, poll_seconds=0, pause=lambda _: None,
    )
    return database, parent, core, identity, mode, commands, provider_calls, apply_options, absence_options


def test_core_preview_apply_absence_survives_two_repository_reopens(tmp_path, monkeypatch):
    (database, parent, core, _, mode, commands, provider_calls,
     apply_options, absence_options) = _persisted_core(tmp_path, monkeypatch)
    apply_options["job_repository"] = SqliteJobRepository(database)
    applied = apply_service.apply_pending_keyed_oci_core_destroy(parent.id, **apply_options)
    assert applied.status == "succeeded"
    assert [argv[1] for argv in commands] == ["show", "apply"]
    assert provider_calls and mode["absent"]
    assert SqliteJobRepository(database).get(parent.id).status == "queued"
    absence_options["job_repository"] = SqliteJobRepository(database)
    absent = absence_service.prove_pending_keyed_oci_core_destroy_absence(
        parent.id, **absence_options)
    assert absent.status == "succeeded"
    assert absent.events[-1].data["ociAbsenceWitness"]["phase"] == "absent"
    calls_before_restart = len(provider_calls)
    absence_options["job_repository"] = SqliteJobRepository(database)
    assert absence_service.prove_pending_keyed_oci_core_destroy_absence(
        parent.id, **absence_options) == absent
    assert len(provider_calls) == calls_before_restart
    assert SqliteJobRepository(database).get(parent.id).status == "queued"
    assert len([row for row in SqliteJobRepository(database).list_for_engagement(parent.target_id)
                if row.action == apply_service.ACTION]) == 1


def test_principal_drift_after_apply_stays_unverified_across_restart(tmp_path, monkeypatch):
    (database, parent, _, identity, _, commands, provider_calls,
     apply_options, absence_options) = _persisted_core(tmp_path, monkeypatch)
    apply_options["job_repository"] = SqliteJobRepository(database)
    apply_service.apply_pending_keyed_oci_core_destroy(parent.id, **apply_options)
    identity["id"] = "ocid1.instance.oc1..otherprincipal"
    absence_options["job_repository"] = SqliteJobRepository(database)
    with pytest.raises(absence_service.KeyedCoreDestroyAbsenceAttention):
        absence_service.prove_pending_keyed_oci_core_destroy_absence(
            parent.id, **absence_options)
    calls_after_failure = len(provider_calls)
    absence_options["job_repository"] = SqliteJobRepository(database)
    with pytest.raises(absence_service.KeyedCoreDestroyAbsenceAttention):
        absence_service.prove_pending_keyed_oci_core_destroy_absence(
            parent.id, **absence_options)
    assert len(commands) == 2
    assert len(provider_calls) == calls_after_failure
    assert SqliteJobRepository(database).get(parent.id).status == "queued"


def test_interrupted_apply_after_go_never_replays_on_reopen(tmp_path, monkeypatch):
    (database, parent, core, _, mode, commands, _,
     apply_options, _) = _persisted_core(tmp_path, monkeypatch)
    state_path = Path(apply_options["plan_repository"].get(
        core.input["corePlanId"]).evidence["terraformStatePath"])
    original_state = state_path.read_bytes()
    original = apply_options["gated_command_runner"]

    def interrupt_after_go(argv, **kwargs):
        if argv[1] == "apply":
            # The fake command has already changed state before result_callback.
            # Lose the result there, after GO, with no safe replay authority.
            kwargs["result_callback"] = lambda _result: (_ for _ in ()).throw(
                TimeoutError("command outcome lost after GO"))
        return original(argv, **kwargs)

    apply_options["gated_command_runner"] = interrupt_after_go
    apply_options["job_repository"] = SqliteJobRepository(database)
    with pytest.raises(apply_service.KeyedCoreDestroyApplyAttention):
        apply_service.apply_pending_keyed_oci_core_destroy(parent.id, **apply_options)
    child_id = f"job-provider-keyed-core-destroy-apply-{core.id.removeprefix('job-')}"
    persisted = SqliteJobRepository(database).get(child_id)
    assert persisted.status == "running"
    assert persisted.events[-1].message == "core destroy command started before GO"
    assert persisted.events[-1].data["phase"] == "apply"
    assert mode["absent"] is True
    assert [argv[1] for argv in commands] == ["show", "apply"]
    # Restore the reviewed prestate so a state-drift check cannot be the
    # reason for refusing a restart. The persisted running child must fence it.
    state_path.write_bytes(original_state)
    apply_options["job_repository"] = SqliteJobRepository(database)
    with pytest.raises(apply_service.KeyedCoreDestroyApplyAttention):
        apply_service.apply_pending_keyed_oci_core_destroy(parent.id, **apply_options)
    assert [argv[1] for argv in commands] == ["show", "apply"]
    assert SqliteJobRepository(database).get(parent.id).status == "queued"


def test_terraform_success_but_visible_oci_resource_never_completes_cleanup(
        tmp_path, monkeypatch):
    (database, parent, core, _, mode, commands, provider_calls,
     apply_options, absence_options) = _persisted_core(tmp_path, monkeypatch)
    apply_options["job_repository"] = SqliteJobRepository(database)
    applied = apply_service.apply_pending_keyed_oci_core_destroy(parent.id, **apply_options)
    assert applied.status == "succeeded"
    # Terraform returned success and its local state is empty, but an exact
    # OCID remains visible in the same compartment to the same principal.
    mode["absent"] = False
    absence_options["job_repository"] = SqliteJobRepository(database)
    with pytest.raises(absence_service.KeyedCoreDestroyAbsenceAttention):
        absence_service.prove_pending_keyed_oci_core_destroy_absence(
            parent.id, **absence_options)
    first_calls = len(provider_calls)
    assert first_calls > 0
    children = [row for row in SqliteJobRepository(database).list_for_engagement(parent.target_id)
                if row.action == absence_service.ACTION]
    assert len(children) == 1 and children[0].status == "failed"
    assert children[0].events[-1].data["retryablePendingTimeout"] is True
    absence_options["job_repository"] = SqliteJobRepository(database)
    with pytest.raises(absence_service.KeyedCoreDestroyAbsenceAttention):
        absence_service.prove_pending_keyed_oci_core_destroy_absence(
            parent.id, **absence_options)
    assert len(provider_calls) > first_calls  # read-only retry, no Terraform replay
    assert [argv[1] for argv in commands] == ["show", "apply"]
    assert SqliteJobRepository(database).get(parent.id).status == "queued"
