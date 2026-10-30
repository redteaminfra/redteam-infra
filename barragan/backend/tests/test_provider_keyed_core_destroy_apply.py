# Copyright (c) 2026, Oracle and/or its affiliates.
"""The private OCI core destroy apply is exact, journaled, and one-shot."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import pwd
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_core_destroy_apply as service
from app.services import provider_keyed_core_destroy_preview as preview_service
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_oci_exact_absence import (
    OciExactWitness, prove_oci_core_visibility,
)
from app.services.provider_keyed_oci_core_state import parse_applied_oci_core_state
from app.storage.database import db
from app.storage.job_repository import (
    SqlAlchemyJobRepository, SqliteJobRepository, job_event_digest,
)
from test_provider_keyed_core_destroy_preview import _case
from test_provider_keyed_oci_core_state import _ROLES


def _ready(tmp_path, monkeypatch):
    jobs, parent, core, coordinator, plan, inventory, state_path, changes, _, options = _case(
        tmp_path, monkeypatch)
    preview = preview_service.preview_pending_keyed_oci_core_destroy(parent.id, **options)
    assert preview.status == "succeeded"
    monkeypatch.setattr(service, "_default_state_root", lambda: options["state_root"])
    monkeypatch.setattr(service, "DEFAULT_TERRAFORM_STATE_ROOT", state_path.parents[2])
    monkeypatch.setattr(service, "_boundary", lambda *_args: (
        jobs.get(parent.id), jobs.get(core.id),
        {"providerScopes": [{"corePlanId": plan.id}], "snapshotId": "c" * 64},
        service._FENCE,
    ))

    def claim(identifier, *, owner, token, claimed_at, expires_at, eligible_statuses):
        row = jobs.get(identifier)
        if row is None or row.status not in eligible_statuses:
            return None
        updated = replace(row, input={**row.input, "claimOwner": owner,
                                      "claimToken": token, "claimExpiresAt": expires_at,
                                      "claimClaimedAt": claimed_at})
        jobs.rows[identifier] = updated
        return updated

    def append(row, *, event, **_kwargs):
        if jobs.get(row.id) != row:
            return None
        updated = replace(row, events=[*row.events, event])
        jobs.rows[row.id] = updated
        return updated

    def renew(identifier, *, heartbeat_at, expires_at, **_kwargs):
        row = jobs.get(identifier)
        updated = replace(row, input={**row.input, "claimExpiresAt": expires_at,
                                      "claimHeartbeatAt": heartbeat_at})
        jobs.rows[identifier] = updated
        return updated

    def finish(row, *, event, status, finished_at, **_kwargs):
        if jobs.get(row.id) != row:
            return None
        updated = replace(row, status=status, finished_at=finished_at,
                          events=[*row.events, event])
        jobs.rows[row.id] = updated
        return updated

    jobs.claim_lease = claim
    jobs.append_core_destroy_apply_event_if_running_claimed = append
    jobs.renew_lease = renew
    jobs.finish_core_destroy_apply_if_running_claimed = finish
    shown = options["command_runner"](["terraform", "show", "-json", "ignored"],
                                      Path(plan.evidence["runDirectory"]),
                                      {"TF_DATA_DIR": plan.evidence["terraformDataDir"]}).stdout
    commands = []
    fail = {"stage": None}

    def gated(args, *, scratch_path, intent_callback, started_callback,
              heartbeat_callback, result_callback, **_kwargs):
        phase = args[1]
        commands.append(args)
        ident = CommandIntent(f"invocation-{len(commands)}", str(scratch_path),
                              hashlib.sha256(json.dumps(args, separators=(",", ":")).encode()).hexdigest())
        if fail["stage"] == "before_intent":
            raise TimeoutError("before intent")
        intent_callback(ident)
        if fail["stage"] == "after_intent":
            raise TimeoutError("after intent")
        started = StartedCommand(ident, ProcessIdentity("boot", 123, 123, 456))
        started_callback(started)
        if fail["stage"] == "after_start":
            raise TimeoutError("after start")
        heartbeat_callback(started)
        if phase == "apply":
            assert args == ["/usr/bin/terraform", "apply", "-input=false", "-lock=true",
                            "-no-color", f"-state={state_path}",
                            preview.events[-1].data["planPath"]]
            state_path.write_text(json.dumps({"version": 4, "resources": []}))
        audit = CommandAuditResult(started, 0, len(shown) if phase == "show" else 0,
                                   0, False, False)
        result_callback(audit)
        if fail["stage"] == "after_result":
            raise TimeoutError("after result")
        return CommandResult(started, 0, shown if phase == "show" else "", "", False, False)

    args = dict(
        environment="devtest", state_root=options["state_root"],
        job_repository=jobs, plan_repository=options["plan_repository"],
        lease_lookup=options["lease_lookup"],
        retired_recognizer=options["retired_recognizer"],
        release_check=options["release_check"],
        source_check=lambda path, manifest: None,
        gated_command_runner=gated,
    )
    oci = tmp_path / "oci"
    oci.write_text("#!/bin/sh\nexit 0\n")
    oci.chmod(0o700)
    args["oci_executable"] = oci
    args["visibility_prover"] = lambda observed, **kwargs: OciExactWitness(
        "present", observed.inventory_sha256,
        _fingerprint({row.address: row.ocid for row in observed.resources}),
        kwargs["compartment_id"], kwargs["region"], "instance_principal",
        "b" * 64, "a" * 64)
    return jobs, parent, core, coordinator, plan, preview, state_path, commands, fail, args


def test_exact_saved_core_destroy_applies_once_and_does_not_mark_clean(tmp_path, monkeypatch):
    jobs, parent, core, _, _, preview, state_path, commands, _, args = _ready(tmp_path, monkeypatch)
    receipt = preview.events[-1].data
    assert receipt["planDevice"] == Path(receipt["planPath"]).stat().st_dev
    assert receipt["planInode"] == Path(receipt["planPath"]).stat().st_ino
    result = service.apply_pending_keyed_oci_core_destroy(parent.id, **args)
    assert result.status == "succeeded"
    assert [command[1] for command in commands] == ["show", "apply"]
    assert result.events[-2].message == "core destroy command result fenced"
    assert result.events[-1].data == {
        "providerAbsenceProofPending": True,
        "preDestroyResourceIdsSha256": result.events[-5].data["resourceIdsSha256"],
    }
    assert result.events[-5].message == "core destroy prestate identity fenced"
    assert len(result.events[-5].data["resourceIds"]) > 0
    assert jobs.get(parent.id).status == "queued"
    with pytest.raises(service.KeyedCoreDestroyApplyAttention):
        service.apply_pending_keyed_oci_core_destroy(parent.id, **args)
    assert len(commands) == 2


def test_historical_generation_apply_does_not_block_new_core(tmp_path, monkeypatch):
    jobs, parent, core, _, _, _, _, commands, _, args = _ready(tmp_path, monkeypatch)
    prior = replace(parent, id="job-prior-core-apply", action=service.ACTION,
                    status="succeeded", input={"coreJobId": "job-prior-core"})
    jobs.rows[prior.id] = prior
    result = service.apply_pending_keyed_oci_core_destroy(parent.id, **args)
    assert result.status == "succeeded" and result.input["coreJobId"] == core.id
    assert [command[1] for command in commands] == ["show", "apply"]


def test_configured_service_oci_cli_is_resolved_without_path_lookup(tmp_path, monkeypatch):
    _, parent, _, _, _, _, _, commands, _, args = _ready(tmp_path, monkeypatch)
    cli = args.pop("oci_executable")
    monkeypatch.setattr(service, "resolve_oci_cli", lambda: SimpleNamespace(
        ok=True, command=str(cli)))
    result = service.apply_pending_keyed_oci_core_destroy(parent.id, **args)
    assert result.status == "succeeded"
    assert [command[1] for command in commands] == ["show", "apply"]


@pytest.mark.parametrize("tamper", ["plan_bytes", "plan_inode", "state", "lease",
                                     "preview_receipt", "source", "binary"])
def test_tamper_refuses_before_any_command(tmp_path, monkeypatch, tamper):
    jobs, parent, core, _, plan, preview, state_path, commands, _, args = _ready(
        tmp_path, monkeypatch)
    plan_path = Path(preview.events[-1].data["planPath"])
    if tamper == "plan_bytes":
        plan_path.write_bytes(b"different")
    elif tamper == "plan_inode":
        replacement = plan_path.with_suffix(".replacement")
        replacement.write_bytes(plan_path.read_bytes())
        replacement.replace(plan_path)
    elif tamper == "state":
        state_path.write_bytes(state_path.read_bytes() + b" ")
    elif tamper == "lease":
        args["lease_lookup"] = lambda _: (plan.id, "other")
    elif tamper == "preview_receipt":
        jobs.rows[preview.id] = replace(
            preview, events=[*preview.events[:-1], replace(preview.events[-1],
                data={**preview.events[-1].data, "planInode": 1})])
    elif tamper == "source":
        args["source_check"] = lambda *_: (_ for _ in ()).throw(ValueError("source changed"))
    else:
        args["release_check"] = lambda **_: SimpleNamespace(
            path=Path("/usr/bin/terraform"), sha256="b" * 64, version="1.15.5")
    with pytest.raises(service.KeyedCoreDestroyApplyAttention):
        service.apply_pending_keyed_oci_core_destroy(parent.id, **args)
    assert commands == []


@pytest.mark.parametrize("stage", ["before_intent", "after_intent", "after_start",
                                   "after_result"])
def test_interrupted_show_never_replays_or_applies(tmp_path, monkeypatch, stage):
    jobs, parent, core, _, _, _, _, commands, fail, args = _ready(tmp_path, monkeypatch)
    fail["stage"] = stage
    with pytest.raises(service.KeyedCoreDestroyApplyAttention):
        service.apply_pending_keyed_oci_core_destroy(parent.id, **args)
    child_id = f"job-provider-keyed-core-destroy-apply-{core.id.removeprefix('job-')}"
    assert jobs.get(child_id).status == "running"
    with pytest.raises(service.KeyedCoreDestroyApplyAttention):
        service.apply_pending_keyed_oci_core_destroy(parent.id, **args)
    assert len(commands) == 1


def test_post_start_apply_uncertainty_never_replays(tmp_path, monkeypatch):
    jobs, parent, core, _, _, _, state_path, commands, fail, args = _ready(tmp_path, monkeypatch)
    original = args["gated_command_runner"]

    def fail_apply(command, **kwargs):
        if command[1] == "apply":
            fail["stage"] = "after_start"
        return original(command, **kwargs)

    args["gated_command_runner"] = fail_apply
    with pytest.raises(service.KeyedCoreDestroyApplyAttention):
        service.apply_pending_keyed_oci_core_destroy(parent.id, **args)
    assert [command[1] for command in commands] == ["show", "apply"]
    child_id = f"job-provider-keyed-core-destroy-apply-{core.id.removeprefix('job-')}"
    child = jobs.get(child_id)
    assert child.status == "running"
    assert child.events[-1].message == "core destroy command started before GO"
    with pytest.raises(service.KeyedCoreDestroyApplyAttention):
        service.apply_pending_keyed_oci_core_destroy(parent.id, **args)
    assert len(commands) == 2


@pytest.mark.parametrize("variant", ["missing", "wrong_ids", "state_changed"])
def test_pre_go_positive_visibility_is_mandatory(tmp_path, monkeypatch, variant):
    jobs, parent, core, _, _, _, state_path, commands, _, args = _ready(
        tmp_path, monkeypatch)
    valid = args["visibility_prover"]
    if variant == "missing":
        args["visibility_prover"] = lambda *_args, **_kwargs: None
    elif variant == "wrong_ids":
        args["visibility_prover"] = lambda observed, **kwargs: replace(
            valid(observed, **kwargs), resource_ids_sha256="0" * 64)
    else:
        def drift(observed, **kwargs):
            state_path.write_bytes(state_path.read_bytes() + b" ")
            return valid(observed, **kwargs)
        args["visibility_prover"] = drift
    with pytest.raises(service.KeyedCoreDestroyApplyAttention):
        service.apply_pending_keyed_oci_core_destroy(parent.id, **args)
    assert [command[1] for command in commands] == ["show"]
    child_id = f"job-provider-keyed-core-destroy-apply-{core.id.removeprefix('job-')}"
    assert jobs.get(child_id).status == "running"
    assert all(event.message != "core destroy command intent fenced" or
               event.data["phase"] != "apply" for event in jobs.get(child_id).events)


def test_sqlite_claimed_core_destroy_journal_reaches_go_without_initial_apply_action(
    tmp_path, monkeypatch,
):
    fake_jobs, parent, core, coordinator, _, preview, _, commands, _, args = _ready(
        tmp_path, monkeypatch)
    stored = SqliteJobRepository(tmp_path / "core-apply.sqlite")
    for row in (parent, core, coordinator, preview):
        stored.save(row)
    monkeypatch.setattr(service, "_boundary", lambda *_args: (
        stored.get(parent.id), stored.get(core.id),
        {"providerScopes": [{"corePlanId": core.input["corePlanId"]}],
         "snapshotId": "c" * 64}, service._FENCE))
    args["job_repository"] = stored
    result = service.apply_pending_keyed_oci_core_destroy(parent.id, **args)
    assert result.status == "succeeded"
    assert [command[1] for command in commands] == ["show", "apply"]
    fresh = SqliteJobRepository(stored.database_path)
    assert fresh.get(result.id) == result
    assert fresh.get(result.id).events[-1].data["providerAbsenceProofPending"] is True
    assert fresh.get(parent.id).status == "queued"


def test_sqlite_real_visibility_gate_renews_claim_per_fake_oci_command(tmp_path, monkeypatch):
    fake_jobs, parent, core, coordinator, plan, preview, state_path, commands, _, args = _ready(
        tmp_path, monkeypatch)
    inventory = parse_applied_oci_core_state(
        state_path.read_bytes(), proxy_count=plan.evidence["proxyCount"],
        elk_enabled=plan.evidence["elkEnabled"],
        compartment_id=plan.evidence["target"]["compartmentId"],
        engagement_name=core.input["engagementName"])
    compartment = plan.evidence["target"]["compartmentId"]
    region = plan.evidence["target"]["region"]
    rows = {}
    for resource in inventory.resources:
        kind, role = _ROLES[resource.address]
        rows[resource.ocid] = {
            "id": resource.ocid, "compartment-id": compartment,
            "freeform-tags": {"barragan": "true", "barragan_engagement": "Disposable",
                              "barragan_environment": "barragan-testing",
                              "barragan_provider": "oci", "barragan_role": role},
            "lifecycle-state": "RUNNING" if kind == "instance" else "AVAILABLE",
        }
    cli_calls = []

    def fake_cli(argv, env):
        cli_calls.append(argv)
        assert env == {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
                       "HOME": "/nonexistent",
                       "PYTHONUSERBASE": str(Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".local"),
                       "PYTHONWARNINGS": "ignore:The 'strict' parameter is no longer needed on Python 3+:FutureWarning:urllib3.poolmanager"}
        assert argv[:8] == (str(args["oci_executable"]), "--auth", "instance_principal",
                            "--region", region, "--output", "json", "--no-retry")
        action = argv[10]
        if action == "list":
            assert argv[11:] == ("--compartment-id", compartment, "--all")
            name = argv[9]
            kind = {"dhcp-options": "dhcpoptions", "internet-gateway": "internetgateway",
                    "nat-gateway": "natgateway", "route-table": "routetable",
                    "security-list": "securitylist"}.get(name, name)
            data = [row for ocid, row in rows.items() if ocid.split(".")[1] == kind]
        else:
            assert action == "get"
            data = rows[argv[-1]]
        return subprocess.CompletedProcess(argv, 0, json.dumps({"data": data}), "")

    stored = SqliteJobRepository(tmp_path / "real-visibility.sqlite")
    for row in (parent, core, coordinator, preview):
        stored.save(row)
    monkeypatch.setattr(service, "_boundary", lambda *_args: (
        stored.get(parent.id), stored.get(core.id),
        {"providerScopes": [{"corePlanId": core.input["corePlanId"]}],
         "snapshotId": "c" * 64}, service._FENCE))
    renewals = []
    original_renew = stored.renew_lease

    def renewing(*values, **kwargs):
        renewals.append(kwargs["heartbeat_at"])
        return original_renew(*values, **kwargs)

    stored.renew_lease = renewing
    args["job_repository"] = stored
    args["oci_command_runner"] = fake_cli
    identity = {"id": "ocid1.instance.oc1..barraganapp",
                "compartmentId": compartment, "canonicalRegionName": region}
    args["visibility_prover"] = lambda observed, **kwargs: prove_oci_core_visibility(
        observed, **kwargs, identity_reader=lambda: dict(identity))
    result = service.apply_pending_keyed_oci_core_destroy(parent.id, **args)
    assert result.status == "succeeded"
    assert [command[1] for command in commands] == ["show", "apply"]
    assert len(cli_calls) >= len(inventory.resources) + 7
    assert len(renewals) >= len(cli_calls) * 2
    sealed = next(event.data for event in result.events
                  if event.message == "core destroy prestate identity fenced")
    assert sealed["ociVisibilityWitness"]["principal_sha256"] == hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert sealed["ociCliSha256"] == hashlib.sha256(args["oci_executable"].read_bytes()).hexdigest()


def _interrupted_pre_go(tmp_path, monkeypatch, *, repeated=False):
    fake_jobs, parent, core, coordinator, _, preview, _, commands, fail, args = _ready(
        tmp_path, monkeypatch)
    stored = SqliteJobRepository(tmp_path / "pre-go.sqlite")
    for row in (parent, core, coordinator, preview):
        stored.save(row)
    monkeypatch.setattr(service, "_boundary", lambda *_args: (
        stored.get(parent.id), stored.get(core.id),
        {"providerScopes": [{"corePlanId": core.input["corePlanId"]}],
         "snapshotId": "c" * 64}, service._FENCE))
    monkeypatch.setattr(service, "_terraform_quiescent", lambda: True)
    args["job_repository"] = stored
    fail["stage"] = "after_result"
    with pytest.raises(service.KeyedCoreDestroyApplyAttention):
        service.apply_pending_keyed_oci_core_destroy(parent.id, **args)
    fail["stage"] = None
    child_id = f"job-provider-keyed-core-destroy-apply-{core.id.removeprefix('job-')}"
    child = stored.get(child_id)
    assert child.status == "running" and len(child.events) == 5
    expired = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    stored.save(replace(child, input={**child.input, "claimExpiresAt": expired}))
    if repeated:
        fail["stage"] = "after_result"
        with pytest.raises(service.KeyedCoreDestroyApplyAttention):
            service.recover_pending_keyed_oci_core_destroy_pre_go(
                parent.id, recovery_child_id=child_id,
                reviewed_plan_sha256=preview.events[-1].data["planSha256"], **args)
        fail["stage"] = None
        child = stored.get(child_id)
        assert child.status == "running" and len(child.events) == 8
        stored.save(replace(child, input={**child.input, "claimExpiresAt": expired}))
    return stored, parent, child_id, preview.events[-1].data["planSha256"], commands, args


def test_sqlite_pre_go_recovery_reuses_exact_child_and_applies_once(tmp_path, monkeypatch):
    stored, parent, child_id, plan_sha, commands, args = _interrupted_pre_go(
        tmp_path, monkeypatch)
    result = service.recover_pending_keyed_oci_core_destroy_pre_go(
        parent.id, recovery_child_id=child_id, reviewed_plan_sha256=plan_sha, **args)
    assert result.id == child_id and result.status == "succeeded"
    assert [command[1] for command in commands] == ["show", "show", "apply"]
    assert [event.message for event in result.events].count(
        "core destroy command result fenced") == 3
    assert len([row for row in stored.list_for_engagement(parent.target_id)
                if row.action == service.ACTION]) == 1
    with pytest.raises(service.KeyedCoreDestroyApplyAttention):
        service.recover_pending_keyed_oci_core_destroy_pre_go(
            parent.id, recovery_child_id=child_id, reviewed_plan_sha256=plan_sha, **args)
    assert [command[1] for command in commands] == ["show", "show", "apply"]


def test_sqlite_two_show_pre_go_recovery_reuses_child_once(tmp_path, monkeypatch):
    stored, parent, child_id, plan_sha, commands, args = _interrupted_pre_go(
        tmp_path, monkeypatch, repeated=True)
    result = service.recover_pending_keyed_oci_core_destroy_pre_go(
        parent.id, recovery_child_id=child_id, reviewed_plan_sha256=plan_sha, **args)
    assert result.id == child_id and result.status == "succeeded"
    assert [command[1] for command in commands] == ["show", "show", "show", "apply"]
    assert len([row for row in stored.list_for_engagement(parent.target_id)
                if row.action == service.ACTION]) == 1
    with pytest.raises(service.KeyedCoreDestroyApplyAttention):
        service.recover_pending_keyed_oci_core_destroy_pre_go(
            parent.id, recovery_child_id=child_id, reviewed_plan_sha256=plan_sha, **args)
    assert [command[1] for command in commands] == ["show", "show", "show", "apply"]


def test_sqlalchemy_two_show_pre_go_recovery_applies_existing_child(
    tmp_path, monkeypatch,
):
    sqlite, parent, child_id, plan_sha, commands, args = _interrupted_pre_go(
        tmp_path, monkeypatch, repeated=True)
    state = db.configure(f"sqlite:///{tmp_path / 'sqlalchemy-two-show.sqlite'}")
    with db.bind(state):
        db.create_all()
        jobs = SqlAlchemyJobRepository()
        for row in sqlite.list_for_engagement(parent.target_id):
            jobs.save(row)
        core = next(row for row in sqlite.list_for_engagement(parent.target_id)
                    if row.action == "pilot_standard_rti_guarded_execute")
        coordinator = next(row for row in sqlite.list_for_engagement(parent.target_id)
                           if row.action == "provider_keyed_comprehensive_teardown")
        stored_coordinator = jobs.get(coordinator.id)
        monkeypatch.setattr(service, "_boundary", lambda *_args: (
            jobs.get(parent.id), jobs.get(core.id),
            {"providerScopes": [{"corePlanId": core.input["corePlanId"]}],
             "snapshotId": "c" * 64}, service._FENCE))
        args["job_repository"] = jobs
        result = service.recover_pending_keyed_oci_core_destroy_pre_go(
            parent.id, recovery_child_id=child_id, reviewed_plan_sha256=plan_sha, **args)
        assert result.id == child_id and result.status == "succeeded"
        assert jobs.get(coordinator.id) == stored_coordinator
        assert [command[1] for command in commands] == ["show", "show", "show", "apply"]


def test_sqlite_pre_go_takeover_cas_rejects_second_claim_and_journal_change(
    tmp_path, monkeypatch,
):
    stored, _, child_id, _, _, _ = _interrupted_pre_go(tmp_path, monkeypatch)
    old = stored.get(child_id)
    claimed_at = datetime.now(timezone.utc).isoformat()
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
    kwargs = dict(expected_event_digest=job_event_digest(old.events),
                  owner="provider-keyed-core-destroy-first", token="a" * 32,
                  claimed_at=claimed_at, expires_at=expiry)
    assert stored.take_over_core_destroy_apply_pre_go(old, **kwargs) is not None
    assert stored.take_over_core_destroy_apply_pre_go(
        old, **{**kwargs, "owner": "provider-keyed-core-destroy-second",
                "token": "b" * 32}) is None
    assert stored.append_core_destroy_apply_event_if_running_claimed(
        old, owner=old.input["claimOwner"], token=old.input["claimToken"],
        expected_event_digest=job_event_digest(old.events),
        heartbeat_at=datetime.now(timezone.utc).isoformat(),
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
        event=JobEvent(6, "info", "core destroy command intent fenced", {"phase": "apply"}),
    ) is None
    assert len(stored.get(child_id).events) == 5


@pytest.mark.parametrize("repeated", [False, True])
def test_sqlalchemy_pre_go_takeover_cas_requires_exact_row_and_journal(
    tmp_path, monkeypatch, repeated,
):
    sqlite, _, child_id, _, _, _ = _interrupted_pre_go(
        tmp_path, monkeypatch, repeated=repeated)
    state = db.configure(f"sqlite:///{tmp_path / 'sqlalchemy-pre-go.sqlite'}")
    with db.bind(state):
        db.create_all()
        jobs = SqlAlchemyJobRepository()
        original = jobs.save(sqlite.get(child_id))
        now = datetime.now(timezone.utc)
        kwargs = dict(expected_event_digest=job_event_digest(original.events),
                      owner="provider-keyed-core-destroy-first", token="a" * 32,
                      claimed_at=now.isoformat(),
                      expires_at=(now + timedelta(minutes=1)).isoformat())
        taken = jobs.take_over_core_destroy_apply_pre_go(original, **kwargs)
        assert taken is not None and taken.input["claimOwner"] == kwargs["owner"]
        assert taken.events == original.events
        assert jobs.take_over_core_destroy_apply_pre_go(
            original, **{**kwargs, "owner": "provider-keyed-core-destroy-second",
                    "token": "b" * 32}) is None
        assert jobs.get(child_id) == taken
        # An extra event cannot be mistaken for the pre-GO checkpoint.
        extra = replace(original, events=[*original.events, JobEvent(
            len(original.events) + 1, "info", "core destroy command intent fenced",
            {"phase": "apply"})])
        assert jobs.take_over_core_destroy_apply_pre_go(extra, **kwargs) is None


@pytest.mark.parametrize("tamper", ["sha", "child_id", "journal", "lease", "process",
                                     "sixth", "extra_claim_key"])
def test_pre_go_recovery_refuses_ambiguous_child_before_command(tmp_path, monkeypatch, tamper):
    stored, parent, child_id, plan_sha, commands, args = _interrupted_pre_go(
        tmp_path, monkeypatch)
    if tamper == "sha":
        plan_sha = "0" * 64
    elif tamper == "child_id":
        child_id = "job-other"
    elif tamper == "journal":
        row = stored.get(child_id)
        stored.save(replace(row, events=[*row.events[:-1], replace(
            row.events[-1], data={**row.events[-1].data, "returnCode": 1})]))
    elif tamper == "lease":
        row = stored.get(child_id)
        stored.save(replace(row, input={**row.input, "claimExpiresAt": (
            datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()}))
    elif tamper == "sixth":
        row = stored.get(child_id)
        stored.save(replace(row, events=[*row.events, JobEvent(
            6, "info", "core destroy command intent fenced", {"phase": "apply"})]))
    elif tamper == "extra_claim_key":
        row = stored.get(child_id)
        stored.save(replace(row, input={**row.input, "unexpectedKey": "value"}))
    else:
        monkeypatch.setattr(service, "_terraform_quiescent", lambda: False)
    with pytest.raises(service.KeyedCoreDestroyApplyAttention):
        service.recover_pending_keyed_oci_core_destroy_pre_go(
            parent.id, recovery_child_id=child_id, reviewed_plan_sha256=plan_sha, **args)
    assert [command[1] for command in commands] == ["show"]


@pytest.mark.parametrize("tamper", ["second_digest", "same_invocation", "second_phase",
                                     "second_result", "second_truncated", "ninth"])
def test_two_show_pre_go_recovery_rejects_corrupt_second_triple_before_command(
    tmp_path, monkeypatch, tamper,
):
    stored, parent, child_id, plan_sha, commands, args = _interrupted_pre_go(
        tmp_path, monkeypatch, repeated=True)
    row = stored.get(child_id)
    events = list(row.events)
    if tamper == "second_digest":
        events[5] = replace(events[5], data={**events[5].data, "argvSha256": "0" * 64})
    elif tamper == "same_invocation":
        old = events[2].data["invocationId"]
        events[5] = replace(events[5], data={**events[5].data, "invocationId": old})
        events[6] = replace(events[6], data={**events[6].data, "invocationId": old})
        events[7] = replace(events[7], data={**events[7].data, "invocationId": old})
    elif tamper == "second_phase":
        events[5] = replace(events[5], data={**events[5].data, "phase": "apply"})
    elif tamper == "second_result":
        events[7] = replace(events[7], data={**events[7].data, "returnCode": 1})
    elif tamper == "second_truncated":
        events[7] = replace(events[7], data={**events[7].data, "stdoutTruncated": True})
    else:
        events.append(JobEvent(9, "info", "core destroy command intent fenced", {"phase": "apply"}))
    stored.save(replace(row, events=events))
    with pytest.raises(service.KeyedCoreDestroyApplyAttention):
        service.recover_pending_keyed_oci_core_destroy_pre_go(
            parent.id, recovery_child_id=child_id, reviewed_plan_sha256=plan_sha, **args)
    assert [command[1] for command in commands] == ["show", "show"]
