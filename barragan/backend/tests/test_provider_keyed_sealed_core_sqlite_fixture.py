# Copyright (c) 2026, Oracle and/or its affiliates.
"""One real sealed OCI core plan and teardown snapshot on a file SQLite DB.

Pending Sketch retirement is the upstream boundary. The core preview, apply,
and exact absence services use their real internal recognizers and journals.
Only Terraform, OCI, and instance-metadata transports are faked.
"""

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from app.domain import JobEvent
from app.domain.deployment_plan import DeploymentPlan
from app.services import provider_keyed_core_destroy_absence as absence
from app.services import provider_keyed_core_destroy_apply as apply
from app.services import provider_keyed_core_destroy_preview as preview
from app.services import provider_keyed_comprehensive_teardown as teardown
from app.services.core_deployment_plans import (
    KEYED_CORE_TERRAFORM_INPUT_FILES, build_keyed_core_terraform_source_manifest,
    require_keyed_core_terraform_source_manifest,
)
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_oci_core_state import parse_applied_oci_core_state
from app.services.provider_keyed_oci_exact_absence import prove_oci_core_visibility
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.database import db
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from test_provider_keyed_core_destroy_preview import _case as core_case
from test_provider_keyed_oci_core_state import _ROLES
from test_provider_keyed_teardown_handoff import _fixture as teardown_case


def sealed_core_sqlite(tmp_path, monkeypatch):
    core_dir, teardown_dir = tmp_path / "oci", tmp_path / "teardown"
    core_dir.mkdir()
    teardown_dir.mkdir()
    (_, _, source_core, _, source_plan, _, state_path, _, _, source_options) = core_case(
        core_dir, monkeypatch)
    source_jobs, _, source_parent, scope, _, _ = teardown_case(teardown_dir)
    original_core = source_jobs.get("job-core")
    assert source_core.id == original_core.id
    plan_id = scope["corePlanId"]

    run_dir = Path(source_plan.evidence["runDirectory"])
    for name in KEYED_CORE_TERRAFORM_INPUT_FILES:
        path = run_dir / name
        if not path.exists():
            path.write_text(f"# test Terraform input: {name}\n")
    evidence = {**source_plan.evidence, "keyedCoreTerraformSourceManifest":
                build_keyed_core_terraform_source_manifest(run_dir)}
    inventory = parse_applied_oci_core_state(
        state_path.read_bytes(), proxy_count=evidence["proxyCount"],
        elk_enabled=evidence["elkEnabled"],
        compartment_id=evidence["target"]["compartmentId"],
        engagement_name=source_core.input["engagementName"],
    )
    seal = {
        "schema": "applied-oci-core-state-v1",
        "corePlanEvidenceSha256": _fingerprint(evidence),
        "rawStateSha256": inventory.raw_state_sha256,
        "inventorySha256": inventory.inventory_sha256,
        "lineage": inventory.lineage, "serial": inventory.serial,
        "resourceCount": len(inventory.resources),
    }
    core = replace(
        original_core,
        input={**original_core.input, **source_core.input,
               "engagementId": source_parent.target_id, "corePlanId": plan_id,
               "sketchStateSchema": "provider-keyed-v2",
               "corePlanEvidenceSha256": _fingerprint(evidence)},
        events=[*original_core.events[:-1],
                JobEvent(len(original_core.events), "info", preview._EVENT, seal),
                JobEvent(len(original_core.events) + 1, "info",
                         "pilot Standard RTI run finished", {})],
    )
    parent = source_parent
    snapshot = parent.input["scopeSnapshot"]
    assert snapshot["coreJobId"] == core.id
    assert source_jobs.get(teardown._child_id(core.id)) is None
    coordinator = StoredJobRun(
        teardown._child_id(core.id), "provider_keyed_comprehensive_teardown",
        "running", parent.target, parent.target_type, parent.target_id,
        parent.requested_by,
        {"phase": "pending_group_retired", "coreJobId": core.id,
         "corePlanId": plan_id, "teardownParentId": parent.id,
         "scopeSnapshotId": snapshot["snapshotId"]},
        [], "", "", None, [],
    )

    state = db.configure(f"sqlite:///{tmp_path / 'one-generation.sqlite'}")
    with db.bind(state):
        db.create_all()
        jobs = SqlAlchemyJobRepository()
        stamp = datetime.now(timezone.utc).isoformat()
        for row in (core, parent, coordinator):
            jobs.save(replace(
                row, created_at=row.created_at or stamp,
                started_at=row.started_at or (stamp if row.status != "queued" else None),
                finished_at=row.finished_at or (
                    stamp if row.status in {"succeeded", "failed"} else None),
            ))
        plans = SqlAlchemyDeploymentPlanRepository()
        plans.save(DeploymentPlan(plan_id, parent.target_id, "revision-test",
                                  "applied", "applied", evidence=evidence,
                                  apply_job_id=core.id))
        plans.acquire(parent.target_id, plan_id, preview._FENCE)

    # Restore the actual validators that core_case stubs for its unit tests.
    for service in (preview, apply, absence):
        monkeypatch.setattr(service, "_boundary", teardown._boundary)
    monkeypatch.setattr(preview, "require_keyed_core_terraform_source_manifest",
                        require_keyed_core_terraform_source_manifest)
    for service in (apply, absence):
        monkeypatch.setattr(service, "_default_state_root",
                            lambda: source_options["state_root"])
        monkeypatch.setattr(service, "DEFAULT_TERRAFORM_STATE_ROOT",
                            state_path.parents[2])

    target = evidence["target"]
    identity = {"id": "ocid1.instance.oc1..barraganapp",
                "compartmentId": target["compartmentId"],
                "canonicalRegionName": target["region"]}
    resources = {}
    for resource in inventory.resources:
        kind, role = _ROLES[resource.address]
        resources[resource.ocid] = {
            "id": resource.ocid, "compartment-id": target["compartmentId"],
            "freeform-tags": {"barragan": "true", "barragan_engagement": "Disposable",
                              "barragan_environment": "barragan-testing",
                              "barragan_provider": "oci", "barragan_role": role},
            "lifecycle-state": "RUNNING" if kind == "instance" else "AVAILABLE",
        }
    mode = {"absent": False}
    provider_calls, commands = [], []

    def oci(argv, env):
        provider_calls.append(argv)
        assert argv[:8] == (str(cli), "--auth", "instance_principal", "--region",
                            target["region"], "--output", "json", "--no-retry")
        if argv[10] == "list":
            kind = {"dhcp-options": "dhcpoptions", "internet-gateway": "internetgateway",
                    "nat-gateway": "natgateway", "route-table": "routetable",
                    "security-list": "securitylist"}.get(argv[9], argv[9])
            data = [] if mode["absent"] else [row for ocid, row in resources.items()
                                              if ocid.split(".")[1] == kind]
            return subprocess.CompletedProcess(argv, 0, json.dumps({"data": data}), "")
        if mode["absent"]:
            return subprocess.CompletedProcess(
                argv, 1, "", 'ServiceError: {"status":404,"code":"NotAuthorizedOrNotFound"}')
        return subprocess.CompletedProcess(argv, 0,
                                           json.dumps({"data": resources[argv[-1]]}), "")

    shown = source_options["command_runner"](
        ["terraform", "show", "-json", "ignored"], run_dir,
        {"TF_DATA_DIR": evidence["terraformDataDir"]},
    ).stdout

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
            mode["absent"] = True
            applied = SqlAlchemyJobRepository().get(
                f"job-provider-keyed-core-destroy-apply-{core.id.removeprefix('job-')}")
            prestate = next(event.data for event in applied.events
                            if event.message == "core destroy prestate identity fenced")
            state_path.write_text(json.dumps({
                "version": 4, "terraform_version": evidence["terraformFingerprint"],
                "lineage": prestate["lineage"], "serial": prestate["serial"] + 1,
                "outputs": {}, "resources": [],
            }))
        audit = CommandAuditResult(started, 0, len(shown) if argv[1] == "show" else 0,
                                   0, False, False)
        result_callback(audit)
        return CommandResult(started, 0, shown if argv[1] == "show" else "", "",
                             False, False)

    cli = tmp_path / "oci-cli"
    cli.write_text("#!/bin/sh\nexit 0\n")
    cli.chmod(0o700)
    base = {"environment": "devtest", "state_root": source_options["state_root"],
            "lease_lookup": _db_lease_lookup,
            "retired_recognizer": lambda *_args, **_kwargs: (object(), object())}
    options = {
        "preview": {**base, "release_check": source_options["release_check"],
                    "command_runner": source_options["command_runner"]},
        "apply": {**base, "release_check": source_options["release_check"],
                  "gated_command_runner": gated, "oci_command_runner": oci,
                  "oci_executable": cli,
                  "visibility_prover": lambda observed, **kw: prove_oci_core_visibility(
                      observed, **kw, identity_reader=lambda: dict(identity))},
        "absence": {"environment": "devtest", "state_root": source_options["state_root"],
                    "lease_lookup": _db_lease_lookup, "oci_command_runner": oci,
                    "identity_reader": lambda: dict(identity),
                    "max_scans": 3, "poll_seconds": 0, "pause": lambda _: None},
    }
    return state, parent, core, identity, mode, commands, provider_calls, options


def test_one_sealed_generation_preview_apply_absence_and_restart(tmp_path, monkeypatch):
    state, parent, core, _, mode, commands, provider_calls, options = sealed_core_sqlite(
        tmp_path, monkeypatch)
    with db.bind(state):
        assert teardown._boundary(parent.id, SqlAlchemyJobRepository(),
                                  SqlAlchemyDeploymentPlanRepository(),
                                  _db_lease_lookup)[-1] == preview._FENCE
        reviewed = preview.preview_pending_keyed_oci_core_destroy(
            parent.id, **options["preview"])
        assert reviewed.status == "succeeded"
        applied = apply.apply_pending_keyed_oci_core_destroy(
            parent.id, **options["apply"])
        assert applied.status == "succeeded" and mode["absent"]
        absent = absence.prove_pending_keyed_oci_core_destroy_absence(
            parent.id, **options["absence"])
        assert absent.status == "succeeded"
        assert absent.input["coreJobId"] == core.id
        assert absent.input["scopeSnapshotId"] == parent.input["scopeSnapshot"]["snapshotId"]
        assert [cmd[1] for cmd in commands] == ["show", "apply"]
        assert provider_calls
    reopened = db.configure(state.uri)
    before = len(provider_calls)
    with db.bind(reopened):
        assert absence.prove_pending_keyed_oci_core_destroy_absence(
            parent.id, **options["absence"]) == absent
        with pytest.raises(apply.KeyedCoreDestroyApplyAttention):
            apply.apply_pending_keyed_oci_core_destroy(parent.id, **options["apply"])
    assert len(provider_calls) == before
    assert [cmd[1] for cmd in commands] == ["show", "apply"]


@pytest.mark.parametrize("drift", ["principal", "region"])
def test_core_absence_rejects_identity_drift_without_replaying_apply(
        tmp_path, monkeypatch, drift):
    state, parent, core, identity, _, commands, provider_calls, options = sealed_core_sqlite(
        tmp_path, monkeypatch)
    with db.bind(state):
        preview.preview_pending_keyed_oci_core_destroy(parent.id, **options["preview"])
        apply.apply_pending_keyed_oci_core_destroy(parent.id, **options["apply"])
        if drift == "principal":
            identity["id"] = "ocid1.instance.oc1..anotherprincipal"
        else:
            identity["canonicalRegionName"] = "us-other-1"
        count = len(provider_calls)
        with pytest.raises(absence.KeyedCoreDestroyAbsenceAttention):
            absence.prove_pending_keyed_oci_core_destroy_absence(
                parent.id, **options["absence"])
        assert len(provider_calls) == count
        children = [row for row in SqlAlchemyJobRepository().list_for_engagement(parent.target_id)
                    if row.action == absence.ACTION]
        assert len(children) == 1 and children[0].status == "failed"
        assert children[0].events[-1].data == {"retryablePendingTimeout": False}
    reopened = db.configure(state.uri)
    with db.bind(reopened):
        with pytest.raises(absence.KeyedCoreDestroyAbsenceAttention):
            absence.prove_pending_keyed_oci_core_destroy_absence(
                parent.id, **options["absence"])
    assert len(provider_calls) == count
    assert [cmd[1] for cmd in commands] == ["show", "apply"]
