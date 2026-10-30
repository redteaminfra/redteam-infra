# Copyright (c) 2026, Oracle and/or its affiliates.
"""Published OCI preview journals retain the exact two-provider handoff."""

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_mixed_published_tail_authority import PublishedMixedTailAuthority
from app.services.provider_keyed_mixed_published_tail_authority import audit_published_mixed_tail_authority
from app.services.provider_keyed_mixed_zero_apply_core_preview import (
    ACTION, _FENCE, _child_id, queued_preview_restartable,
    preview_mixed_zero_apply_oci_core_destroy, recognize_interrupted_core_preview,
    recognize_published_core_preview, MixedZeroApplyCorePreviewAttention,
)
from app.services.provider_keyed_core_destroy_preview import _state_data_ids
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_oci_exact_absence import OciExactWitness
from app.services.provider_keyed_oci_core_state import OciCoreStateInventory, OciCoreStateResource
from app.services.provider_keyed_oci_core_state import parse_applied_oci_core_state
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import StoredJobRun, job_event_digest
from test_provider_keyed_mixed_published_first_absence_worker import (
    _prepared_second, _worker, _snapshot_after,
)
from test_provider_keyed_mixed_published_first_destroy_go import _fake_runner
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_oci_core_state import _state
from app.services.provider_keyed_mixed_published_first_destroy_go import (
    run_published_mixed_second_provider_destroy,
)
from app.services.provider_keyed_mixed_published_second_absence_worker import (
    finish_published_mixed_second_absence,
)
import app.services.provider_keyed_mixed_published_tail_authority as tail
import app.services.provider_keyed_mixed_zero_apply_core_preview as preview_service
import app.services.provider_keyed_mixed_zero_apply_core_apply as apply_service


def _journals():
    now = datetime.now(timezone.utc).isoformat()
    core_id = "job-core"
    source = {"schema": "mixed-published-source-v1", "opaque": "two-provider-receipts"}
    parent = StoredJobRun(
        id="job-published-cleanup", action="provider_keyed_mixed_published_cleanup",
        status="running", target="engagement:eng-test", target_type="engagement",
        target_id="eng-test", requested_by="operator", created_at=now,
        started_at=now, finished_at=None, artifact_refs=[],
        input={"corePlanId": "plan-core", "publishedSource": source,
               "publishedSourceSha256": _fingerprint(source)},
        events=[JobEvent(1, "info", "published cleanup queued", {})],
    )
    authority = PublishedMixedTailAuthority(
        parent, (), core_id, "plan-core", "a" * 64, "b" * 64, (),
        ("inspector-1", "inspector-2"), False)
    child_input = {
        "schema": "mixed-published-core-preview-v1",
        "teardownParentId": parent.id, "coreJobId": core_id,
        "corePlanId": "plan-core", "sourceSha256": _fingerprint(source),
        "parentJournalSha256": job_event_digest(parent.events),
        "stateSha256": authority.core_state_sha256,
        "inventorySha256": authority.core_inventory_sha256,
        "leaseOperation": _FENCE,
        "inspectorRecordIds": list(authority.owned_inspector_record_ids),
    }
    queued = StoredJobRun(
        id=_child_id(core_id), action=ACTION, status="queued",
        target=parent.target, target_type="engagement", target_id="eng-test",
        requested_by="operator", input=child_input, artifact_refs=[],
        created_at=now, started_at=None, finished_at=None,
        events=[JobEvent(1, "info", "mixed core destroy preview queued", {})],
    )
    receipt = {
        "planPath": "/tmp/exact.tfplan", "planDevice": 1, "planInode": 2,
        "planSha256": "c" * 64, "stateSha256": authority.core_state_sha256,
        "inventorySha256": authority.core_inventory_sha256,
        "resourceCount": 1, "sourceSha256": child_input["sourceSha256"],
        "parentJournalSha256": child_input["parentJournalSha256"],
        "sourceManifestSha256": "d" * 64, "terraformBinarySha256": "e" * 64,
        "leaseOwner": "plan-core", "leaseOperation": _FENCE,
    }
    terminal = replace(
        queued, status="succeeded", started_at=now, finished_at=now,
        events=[*queued.events,
                JobEvent(2, "info", "mixed core destroy preview started", {}),
                JobEvent(3, "info", "mixed core destroy preview saved", receipt)],
    )
    return parent, authority, queued, terminal, receipt


def test_published_preview_queue_and_terminal_bind_exact_parent_and_inspectors():
    parent, authority, queued, terminal, receipt = _journals()
    assert queued_preview_restartable(queued, parent, "job-core", authority=authority)
    assert recognize_published_core_preview(terminal, parent, "job-core", authority) == receipt
    assert not queued_preview_restartable(queued, parent, "job-core", authority=None)
    assert not queued_preview_restartable(
        queued, replace(parent, events=[*parent.events, JobEvent(2, "info", "drift", {})]),
        "job-core", authority=authority)
    assert not queued_preview_restartable(
        replace(queued, input={**queued.input, "inspectorRecordIds": ["other", "inspector-2"]}),
        parent, "job-core", authority=authority)


def test_published_preview_refuses_wrong_source_mode_and_receipt():
    parent, authority, _, terminal, _ = _journals()
    with pytest.raises(ValueError):
        recognize_interrupted_core_preview(terminal, parent, "job-core", authority)
    with pytest.raises(ValueError):
        recognize_published_core_preview(
            terminal, parent, "job-core", replace(authority, core_state_sha256="0" * 64))
    with pytest.raises(ValueError):
        recognize_published_core_preview(
            terminal, replace(parent, input={**parent.input, "publishedSourceSha256": "0" * 64}),
            "job-core", authority)
    with pytest.raises(ValueError):
        recognize_published_core_preview(
            replace(terminal, events=[*terminal.events[:2],
                                      JobEvent(3, "info", "mixed core destroy preview saved",
                                               {**terminal.events[2].data, "planSha256": "invalid"})]),
            parent, "job-core", authority)


def _published_preview_case(client, ready, tmp_path, monkeypatch):
    jobs, collection, parent, provider_plans, second, root, go = _prepared_second(
        ready, tmp_path, monkeypatch)
    go["gated_command_runner"] = _fake_runner(second, root, [])
    run_published_mixed_second_provider_destroy(parent.id, **go)
    worker = _worker(ready, collection, monkeypatch)
    order = collection.review.source.ordered_providers
    worker["snapshot_collector"] = lambda initial, provider, workspace, *, fence, **kw: (
        _snapshot_after(provider_plans.plans[order.index(provider)], fence()))
    finish_published_mixed_second_absence(parent.id, **worker)
    monkeypatch.setattr(tail, "_default_state_root", lambda: ready.case.state_root)
    placeholder = OciCoreStateInventory(
        "a" * 64, "b" * 64, "123e4567-e89b-12d3-a456-426614174000", 1,
        (OciCoreStateResource("oci_core_instance.homebase",
                              "ocid1.instance.oc1.fixture", None),))
    authority = audit_published_mixed_tail_authority(
        parent.id, environment="devtest", job_repository=jobs,
        lease_lookup=worker["lease_lookup"], process_quiescent=lambda _: True,
        credential_repository=ready.case.args["credential_repository"],
        inventory_collector=worker["snapshot_collector"],
        core_inventory_reader=lambda *args: placeholder,
        inspector_record_reader=lambda *args: ("inspector-host", "inspector-firewall"))
    assert len(authority.provider_receipts) == 2
    source = collection.review.source
    core_root = tmp_path / "oci-state"
    state_path = core_root / source.engagement_id / "core" / "terraform.tfstate"
    state_path.parent.mkdir(parents=True)
    plan_repo = SqlAlchemyDeploymentPlanRepository()
    plan = plan_repo.get(source.core_plan_id)
    engagement_name = jobs.get(source.core_job_id).input["engagementName"]
    raw_state = _state(proxy_count=1, elk_enabled=False)
    for row in raw_state["resources"]:
        if row["mode"] == "managed":
            attributes = row["instances"][0]["attributes"]
            attributes["freeform_tags"]["barragan_engagement"] = engagement_name
            if "compartment_id" in attributes:
                attributes["compartment_id"] = plan.evidence["target"]["compartmentId"]
    state_path.write_bytes(json.dumps(raw_state).encode())
    inventory = parse_applied_oci_core_state(
        state_path.read_bytes(), proxy_count=1, elk_enabled=False,
        compartment_id=plan.evidence["target"]["compartmentId"],
        engagement_name=engagement_name)
    run_dir = tmp_path / "oci-run"
    run_dir.mkdir()
    data_dir = state_path.parent / "data-core-test"
    data_dir.mkdir()
    lock = run_dir / ".terraform.lock.hcl"
    lock.write_bytes(b"reviewed lock")
    public_key = run_dir / "admin.pub"
    public_key.write_bytes(b"ssh-ed25519 reviewed-test-key")
    evidence = {**plan.evidence,
                "terraformStatePath": str(state_path), "runDirectory": str(run_dir),
                "terraformDataDir": str(data_dir), "sshPublicKeyPath": str(public_key),
                "providerLockFingerprint": hashlib.sha256(lock.read_bytes()).hexdigest(),
                "publicKeyFingerprint": hashlib.sha256(public_key.read_bytes()).hexdigest(),
                "keyedCoreTerraformSourceManifest": {"schema": "offline-test"},
                "terraformFingerprint": "1.15.5", "sshSourceCidrs": ["192.0.2.1/32"],
                "proxyCount": 1, "elkEnabled": False}
    plan_repo.save(replace(plan, evidence=evidence))
    authority = replace(
        authority, core_state_sha256=inventory.raw_state_sha256,
        core_inventory_sha256=inventory.inventory_sha256,
        core_resource_ids=tuple(sorted((r.address, r.ocid) for r in inventory.resources)))
    monkeypatch.setattr(preview_service, "_default_state_root", lambda: ready.case.state_root)
    monkeypatch.setattr(preview_service, "DEFAULT_TERRAFORM_STATE_ROOT", core_root)
    monkeypatch.setattr(preview_service, "audit_published_mixed_tail_authority",
                        lambda cleanup_id, **kwargs: authority if cleanup_id == parent.id
                        else pytest.fail("wrong published cleanup"))
    monkeypatch.setattr(preview_service, "require_keyed_core_terraform_source_manifest",
                        lambda path, manifest: None if (path == run_dir and manifest == evidence[
                            "keyedCoreTerraformSourceManifest"]) else pytest.fail("source drift"))
    prior = [{"address": r.address, "mode": "managed", "type": r.address.split(".", 1)[0],
              "provider_name": "registry.terraform.io/oracle/oci", "values": {"id": r.ocid}}
             for r in inventory.resources]
    prior += [{"address": address, "mode": "data", "type": address.split(".", 2)[1],
               "provider_name": "registry.terraform.io/oracle/oci", "values": {"id": identifier}}
              for address, identifier in _state_data_ids(state_path.read_bytes()).items()]
    changes = [{"address": r.address, "mode": "managed", "type": r.address.split(".", 1)[0],
                "provider_name": "registry.terraform.io/oracle/oci",
                "change": {"actions": ["delete"], "before": {"id": r.ocid},
                           "after": None, "after_unknown": {}}} for r in inventory.resources]
    shown = json.dumps({"applyable": True, "complete": True, "resource_changes": changes,
                        "prior_state": {"values": {"root_module": {"resources": prior}}}})
    calls = []

    def runner(args, cwd, env):
        calls.append(args[1])
        assert cwd == run_dir and env["TF_DATA_DIR"] == str(data_dir)
        if args[1] == "plan":
            Path(args[5].removeprefix("-out=")).write_bytes(b"saved OCI destroy plan")
            return SimpleNamespace(returncode=2, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout=shown, stderr="")

    release = SimpleNamespace(path=Path("/usr/bin/terraform"), sha256="e" * 64,
                              version="1.15.5")
    options = dict(environment="devtest", state_root=ready.case.state_root,
                   core_state_root=core_root, job_repository=jobs,
                   plan_repository=plan_repo, lease_lookup=worker["lease_lookup"],
                   binding_check=lambda _: None, release_check=lambda **_: release,
                   command_runner=runner, published=True)
    return source, authority, jobs, calls, options


@pytest.mark.parametrize("drift", [None, "plan", "show"])
def test_published_preview_executes_once_and_vetoes_drift_during_commands(
        client, ready, tmp_path, monkeypatch, drift):
    with client.application.storage_context():
        source, authority, jobs, calls, options = _published_preview_case(
            client, ready, tmp_path, monkeypatch)
        if drift is not None:
            original = options["command_runner"]

            def runner(args, cwd, env):
                result = original(args, cwd, env)
                if args[1] == drift:
                    monkeypatch.setattr(preview_service, "audit_published_mixed_tail_authority",
                                        lambda *a, **k: replace(
                                            authority, owned_inspector_record_ids=("changed", "firewall")))
                return result

            options["command_runner"] = runner
        if drift is None:
            child = preview_mixed_zero_apply_oci_core_destroy(
                source.engagement_id, source.core_job_id, **options)
            assert child.status == "succeeded" and calls == ["plan", "show"]
            assert recognize_published_core_preview(
                child, authority.parent, source.core_job_id, authority) == child.events[2].data
            with pytest.raises(MixedZeroApplyCorePreviewAttention):
                preview_mixed_zero_apply_oci_core_destroy(
                    source.engagement_id, source.core_job_id, **options)
            assert calls == ["plan", "show"]
        else:
            with pytest.raises(MixedZeroApplyCorePreviewAttention):
                preview_mixed_zero_apply_oci_core_destroy(
                    source.engagement_id, source.core_job_id, **options)
            assert calls == (["plan"] if drift == "plan" else ["plan", "show"])
            assert jobs.get(_child_id(source.core_job_id)).status == "running"


def _published_go_case(client, ready, tmp_path, monkeypatch):
    source, authority, jobs, _, preview_options = _published_preview_case(
        client, ready, tmp_path, monkeypatch)
    preview = preview_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **preview_options)
    monkeypatch.setattr(apply_service, "_default_state_root", lambda: ready.case.state_root)
    monkeypatch.setattr(apply_service, "DEFAULT_TERRAFORM_STATE_ROOT",
                        preview_options["core_state_root"])
    active = {"authority": authority}
    monkeypatch.setattr(apply_service, "audit_published_mixed_tail_authority",
                        lambda cleanup_id, **kwargs: active["authority"])
    run_dir = Path(jobs.get(source.core_job_id).input.get("runDirectory") or
                   SqlAlchemyDeploymentPlanRepository().get(source.core_plan_id).evidence[
                       "runDirectory"])
    shown = preview_options["command_runner"](
        ["terraform", "show"], run_dir, {"TF_DATA_DIR": str(
            SqlAlchemyDeploymentPlanRepository().get(source.core_plan_id).evidence[
                "terraformDataDir"])}).stdout
    calls = []

    def runner(args, *, scratch_path, intent_callback, started_callback,
               heartbeat_callback, result_callback, **kwargs):
        phase = args[1]
        calls.append(phase)
        intent = CommandIntent(f"{phase}-{len(calls)}", str(scratch_path),
                               _fingerprint(args))
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity("offline-boot", 123, 123, 10))
        started_callback(started)
        heartbeat_callback(started)
        output = shown if phase == "show" else ""
        result_callback(CommandAuditResult(started, 0, len(output), 0, False, False))
        return CommandResult(started, 0, output, "", False, False)

    def witness(inventory, *, compartment_id, region, fence, **kwargs):
        fence()
        return OciExactWitness(
            "present", inventory.inventory_sha256,
            _fingerprint({row.address: row.ocid for row in inventory.resources}),
            compartment_id, region, "instance_principal", "a" * 64, "b" * 64)

    options = dict(
        environment="devtest", state_root=ready.case.state_root,
        core_state_root=preview_options["core_state_root"], job_repository=jobs,
        plan_repository=preview_options["plan_repository"],
        lease_lookup=preview_options["lease_lookup"],
        binding_check=lambda _: None,
        inspector_prover=lambda source, engagement, fence: (fence(), "c" * 64)[1],
        release_check=preview_options["release_check"],
        source_check=lambda path, manifest: None,
        gated_command_runner=runner, visibility_prover=witness,
        oci_executable=Path(sys.executable).resolve(strict=True),
        published=True)
    return source, authority, preview, jobs, active, calls, options


@pytest.mark.parametrize("drift", [None, "before_go"])
def test_published_oci_go_rechecks_receipts_and_never_replays(
        client, ready, tmp_path, monkeypatch, drift):
    with client.application.storage_context():
        source, authority, preview, jobs, active, calls, options = _published_go_case(
            client, ready, tmp_path, monkeypatch)
        if drift == "before_go":
            original = options["gated_command_runner"]

            def runner(args, **kwargs):
                if args[1] == "apply":
                    callback = kwargs["started_callback"]

                    def started(value):
                        active["authority"] = replace(
                            authority, owned_inspector_record_ids=("changed", "firewall"))
                        callback(value)

                    kwargs["started_callback"] = started
                return original(args, **kwargs)

            options["gated_command_runner"] = runner
            with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
                apply_service.apply_mixed_zero_apply_oci_core_destroy(
                    source.engagement_id, source.core_job_id, **options)
            assert calls == ["show", "apply"]
        else:
            child = apply_service.apply_mixed_zero_apply_oci_core_destroy(
                source.engagement_id, source.core_job_id, **options)
            assert child.status == "succeeded" and calls == ["show", "apply"]
            assert child.input["sourceSha256"] == authority.parent.input[
                "publishedSourceSha256"]
            with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
                apply_service.apply_mixed_zero_apply_oci_core_destroy(
                    source.engagement_id, source.core_job_id, **options)
            assert calls == ["show", "apply"]


def test_published_oci_inspector_drift_still_vetoes_held_go(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        source, authority, _, jobs, active, calls, options = _published_go_case(
            client, ready, tmp_path, monkeypatch)
        proofs = {"count": 0}

        def inspector(_source, _engagement, fence):
            fence()
            proofs["count"] += 1
            if proofs["count"] == 2:
                active["authority"] = replace(
                    authority, owned_inspector_record_ids=("changed", "firewall"))
                fence()
            return "c" * 64

        options["inspector_prover"] = inspector
        with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
            apply_service.apply_mixed_zero_apply_oci_core_destroy(
                source.engagement_id, source.core_job_id, **options)
        child = jobs.get(apply_service._child_id(source.core_job_id))
        assert calls == ["show", "apply"] and proofs["count"] == 2
        assert child.events[-1].message == "core destroy command started before GO"
        assert not any(event.message == "core destroy GO support rechecked"
                       for event in child.events)


def test_published_oci_visibility_drift_still_vetoes_held_go(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        source, authority, _, jobs, active, calls, options = _published_go_case(
            client, ready, tmp_path, monkeypatch)
        original_witness = options["visibility_prover"]
        scans = {"count": 0}

        def visibility(*args, fence, **kwargs):
            witness = original_witness(*args, fence=fence, **kwargs)
            scans["count"] += 1
            if scans["count"] == 2:
                active["authority"] = replace(
                    authority, owned_inspector_record_ids=("changed", "firewall"))
                fence()
            return witness

        options["visibility_prover"] = visibility
        with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
            apply_service.apply_mixed_zero_apply_oci_core_destroy(
                source.engagement_id, source.core_job_id, **options)
        child = jobs.get(apply_service._child_id(source.core_job_id))
        assert calls == ["show", "apply"] and scans["count"] == 2
        assert child.events[-1].message == "core destroy command started before GO"
        assert not any(event.message == "core destroy GO support rechecked"
                       for event in child.events)


@pytest.mark.parametrize("phase", ["show", "apply"])
def test_published_oci_pre_go_restart_uses_one_saved_plan_and_no_apply_replay(
        client, ready, tmp_path, monkeypatch, phase):
    with client.application.storage_context():
        source, _, _, jobs, _, calls, options = _published_go_case(
            client, ready, tmp_path, monkeypatch)
        normal = options["gated_command_runner"]

        def stopped(args, *, scratch_path, intent_callback, started_callback, **kwargs):
            if args[1] != phase:
                return normal(args, scratch_path=scratch_path,
                              intent_callback=intent_callback,
                              started_callback=started_callback, **kwargs)
            calls.append(args[1])
            intent = CommandIntent("abandoned", str(scratch_path), _fingerprint(args))
            intent_callback(intent)
            started_callback(StartedCommand(
                intent, ProcessIdentity("old-boot", 543, 543, 17)))
            raise RuntimeError("offline worker stopped before GO")

        if phase == "show":
            options["gated_command_runner"] = stopped
        else:
            original_append = jobs.append_core_destroy_apply_event_if_running_claimed

            def stop_after_pre_go_start(*args, **kwargs):
                saved = original_append(*args, **kwargs)
                if (kwargs["event"].message == "core destroy command started before GO"
                        and kwargs["event"].data["phase"] == "apply"):
                    raise RuntimeError("offline worker stopped before GO check")
                return saved

            monkeypatch.setattr(jobs, "append_core_destroy_apply_event_if_running_claimed",
                                stop_after_pre_go_start)
        with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
            apply_service.apply_mixed_zero_apply_oci_core_destroy(
                source.engagement_id, source.core_job_id, **options)
        child = jobs.get(apply_service._child_id(source.core_job_id))
        assert len(child.events) == (4 if phase == "show" else 8)
        jobs.save(replace(child, input={**child.input,
                                        "claimExpiresAt": "2020-01-01T00:00:00+00:00"}))
        if phase == "apply":
            monkeypatch.setattr(jobs, "append_core_destroy_apply_event_if_running_claimed",
                                original_append)
        options.update(gated_command_runner=normal,
                       process_quiescent=lambda _: True,
                       terraform_quiescent=lambda: True)
        terminal = apply_service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **options)
        assert terminal.status == "succeeded"
        assert calls == (["show", "show", "apply"] if phase == "show"
                         else ["show", "apply", "apply"])
        assert any("recovery claimed" in row.message for row in terminal.events)


def test_published_oci_apply_intent_without_result_is_never_replayed(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        source, _, _, jobs, _, calls, options = _published_go_case(
            client, ready, tmp_path, monkeypatch)
        normal = options["gated_command_runner"]

        def stopped(args, *, scratch_path, intent_callback, **kwargs):
            if args[1] == "show":
                return normal(args, scratch_path=scratch_path,
                              intent_callback=intent_callback, **kwargs)
            calls.append("apply")
            intent_callback(CommandIntent("uncertain", str(scratch_path),
                                          _fingerprint(args)))
            raise RuntimeError("result of provider command unknown")

        options["gated_command_runner"] = stopped
        for _ in range(2):
            with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
                apply_service.apply_mixed_zero_apply_oci_core_destroy(
                    source.engagement_id, source.core_job_id, **options)
        assert calls == ["show", "apply"]
        child = jobs.get(apply_service._child_id(source.core_job_id))
        assert child.status == "running" and child.events[-1].message == (
            "core destroy command intent fenced")
