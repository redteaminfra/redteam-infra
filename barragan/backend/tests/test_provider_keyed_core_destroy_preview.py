# Copyright (c) 2026, Oracle and/or its affiliates.
"""The private OCI destroy preview cannot widen or replay its sealed inventory."""

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_core_destroy_preview as service
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_oci_core_state import parse_applied_oci_core_state
from app.storage.job_repository import StoredJobRun
from test_provider_keyed_oci_core_state import _state


def _case(tmp_path, monkeypatch):
    root = tmp_path / "states"
    root.mkdir()
    core_root = tmp_path / "core-state"
    core_root.mkdir()
    state_dir = core_root / "engagement" / "core"
    state_dir.mkdir(parents=True)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    data_dir = state_dir / "data-core-test"
    data_dir.mkdir()
    lock = run_dir / ".terraform.lock.hcl"
    lock.write_text("pinned lock")
    public_key = tmp_path / "admin.pub"
    public_key.write_text("ssh-ed25519 test-key")
    target = {"name": "barragan-testing", "region": "us-test-1",
              "compartmentId": "ocid1.compartment.oc1..example", "auth": "instance-principal"}
    state = _state()
    for row in state["resources"]:
        if row["mode"] == "managed":
            attributes = row["instances"][0]["attributes"]
            attributes["freeform_tags"]["barragan_engagement"] = "Disposable"
            if "compartment_id" in attributes:
                attributes["compartment_id"] = target["compartmentId"]
    state_path = state_dir / "terraform.tfstate"
    state_path.write_bytes(json.dumps(state).encode())
    inventory = parse_applied_oci_core_state(
        state_path.read_bytes(), proxy_count=2, elk_enabled=True,
        compartment_id=target["compartmentId"], engagement_name="Disposable")
    evidence = {
        "sketchStateSchema": "provider-keyed-v2", "target": target,
        "proxyCount": 2, "elkEnabled": True, "runDirectory": str(run_dir),
        "terraformDataDir": str(data_dir), "terraformStatePath": str(state_path),
        "providerLockFingerprint": hashlib.sha256(lock.read_bytes()).hexdigest(),
        "sshPublicKeyPath": str(public_key),
        "publicKeyFingerprint": hashlib.sha256(public_key.read_bytes()).hexdigest(),
        "sshSourceCidrs": ["192.0.2.1/32"],
        "keyedCoreTerraformSourceManifest": {"schema": "test", "sha256": {}},
        "terraformFingerprint": "1.15.5",
    }
    core_plan_id = "dpl-core"
    parent_id = "job-teardown"
    core_id = "job-core"
    seal = {
        "schema": "applied-oci-core-state-v1",
        "corePlanEvidenceSha256": _fingerprint(evidence),
        "rawStateSha256": inventory.raw_state_sha256,
        "inventorySha256": inventory.inventory_sha256,
        "lineage": inventory.lineage, "serial": inventory.serial,
        "resourceCount": len(inventory.resources),
    }

    def job(identifier, action, status, data, events):
        return StoredJobRun(
            id=identifier, action=action, status=status, target="engagement:eng-test",
            target_type="engagement", target_id="eng-test", requested_by="tester",
            input=data, artifact_refs=[], created_at="2026-10-09T00:00:00+00:00",
            started_at="2026-10-09T00:00:01+00:00", finished_at=None, events=events)

    parent = job(parent_id, "engagement_teardown", "queued", {}, [])
    core = job(core_id, "pilot_standard_rti_guarded_execute", "succeeded", {
        "corePlanId": core_plan_id, "corePlanEvidenceSha256": _fingerprint(evidence),
        "target": target, "proxyCount": 2, "elkEnabled": True,
        "sshSourceCidrs": ["192.0.2.1/32"],
        "engagementName": "Disposable",
    }, [JobEvent(1, "info", service._EVENT, seal),
        JobEvent(2, "info", "pilot Standard RTI run finished", {})])
    coordinator = job(service._child_id(core_id), "provider_keyed_comprehensive_teardown",
                      "running", {"phase": "pending_group_retired"}, [])
    plan = SimpleNamespace(id=core_plan_id, engagement_id="eng-test", status="applied",
                           apply_job_id=core_id, evidence=evidence)
    snapshot = {"providerScopes": [{"corePlanId": core_plan_id}], "snapshotId": "c" * 64}

    class Jobs:
        def __init__(self):
            self.rows = {row.id: row for row in (parent, core, coordinator)}

        def get(self, identifier):
            return self.rows.get(identifier)

        def list_for_engagement(self, _engagement):
            return list(self.rows.values())

        def save_if_absent(self, row):
            if row.id in self.rows:
                return self.rows[row.id]
            self.rows[row.id] = row
            return row

        def start_if_queued(self, row, *, started_at, event):
            if self.rows.get(row.id) != row:
                return None
            new = replace(row, status="running", started_at=started_at,
                          events=[*row.events, event])
            self.rows[row.id] = new
            return new

        def finish_if_running(self, row, *, status, finished_at, event):
            if self.rows.get(row.id) != row:
                return None
            new = replace(row, status=status, finished_at=finished_at,
                          events=[*row.events, event])
            self.rows[row.id] = new
            return new

    class Plans:
        def get(self, identifier):
            return plan if identifier == core_plan_id else None

    jobs = Jobs()
    monkeypatch.setattr(service, "_default_state_root", lambda: root)
    monkeypatch.setattr(service, "DEFAULT_TERRAFORM_STATE_ROOT", core_root)
    monkeypatch.setattr(service, "_boundary", lambda *_args: (parent, core, snapshot, service._FENCE))
    monkeypatch.setattr(service, "require_keyed_core_terraform_source_manifest",
                        lambda path, value: (path == run_dir and value == evidence["keyedCoreTerraformSourceManifest"])
                        or pytest.fail("source manifest differs"))
    release = SimpleNamespace(path=Path("/usr/bin/terraform"), sha256="a" * 64, version="1.15.5")
    prior_rows = [{"address": row.address, "mode": "managed",
                   "type": row.address.split(".", 1)[0],
                   "provider_name": "registry.terraform.io/oracle/oci",
                   "values": {"id": row.ocid}} for row in inventory.resources]
    for resource in state["resources"]:
        if resource["mode"] != "data":
            continue
        for instance in resource["instances"]:
            address = f'data.{resource["type"]}.{resource["name"]}'
            if instance.get("index_key") == 0:
                address += "[0]"
            prior_rows.append({"address": address, "mode": "data",
                               "type": resource["type"],
                               "provider_name": "registry.terraform.io/oracle/oci",
                               "values": {"id": instance["attributes"]["id"]}})
    changes = [{"address": row.address, "mode": "managed",
                "type": row.address.split(".", 1)[0],
                "provider_name": "registry.terraform.io/oracle/oci",
                "change": {"actions": ["delete"], "before": {"id": row.ocid},
                           "after": None, "after_unknown": {}}}
               for row in inventory.resources]
    calls = []

    def runner(args, cwd, env):
        calls.append(args)
        assert cwd == run_dir and env["TF_DATA_DIR"] == str(data_dir)
        if args[1] == "plan":
            Path(args[5].removeprefix("-out=")).write_bytes(b"saved binary plan")
            return SimpleNamespace(returncode=2, stdout="", stderr="")
        return SimpleNamespace(returncode=0,
                               stdout=json.dumps({"applyable": True, "complete": True,
                                                  "resource_changes": changes,
                                                  "prior_state": {"values": {
                                                      "root_module": {"resources": prior_rows}}}}),
                               stderr="")

    options = dict(environment="devtest", state_root=root, job_repository=jobs,
                   plan_repository=Plans(), lease_lookup=lambda _: (core_plan_id, service._FENCE),
                   retired_recognizer=lambda *_args, **_kwargs: (object(), object()),
                   release_check=lambda **_kwargs: release, command_runner=runner)
    return jobs, parent, core, coordinator, plan, inventory, state_path, changes, calls, options


def test_exact_core_destroy_preview_is_saved_once(tmp_path, monkeypatch):
    jobs, parent, core, _, _, inventory, state_path, _, calls, options = _case(tmp_path, monkeypatch)
    result = service.preview_pending_keyed_oci_core_destroy(parent.id, **options)
    assert result.status == "succeeded" and len(calls) == 2
    assert result.events[-1].data["inventorySha256"] == inventory.inventory_sha256
    assert result.events[-1].data["stateSha256"] == hashlib.sha256(state_path.read_bytes()).hexdigest()
    assert Path(result.events[-1].data["planPath"]).parent == state_path.parent
    with pytest.raises(service.KeyedCoreDestroyPreviewAttention):
        service.preview_pending_keyed_oci_core_destroy(parent.id, **options)
    assert len(calls) == 2


def test_historical_generation_preview_does_not_block_new_core(tmp_path, monkeypatch):
    jobs, parent, core, _, _, _, _, _, calls, options = _case(tmp_path, monkeypatch)
    prior = replace(parent, id="job-prior-core-preview", action=service.ACTION,
                    status="succeeded", input={"coreJobId": "job-prior-core"})
    jobs.rows[prior.id] = prior
    result = service.preview_pending_keyed_oci_core_destroy(parent.id, **options)
    assert result.status == "succeeded" and result.input["coreJobId"] == core.id
    assert len(calls) == 2


@pytest.mark.parametrize("tamper", [
    "extra", "wrong_id", "replace", "unknown", "drift", "prior_wrong_id",
    "extra_data", "data_wrong_id", "incomplete", "planned_managed",
])
def test_non_exact_destroy_plan_is_retained_for_attention(tmp_path, monkeypatch, tamper):
    jobs, parent, core, _, _, _, _, changes, calls, options = _case(tmp_path, monkeypatch)
    if tamper == "extra":
        changes.append({**changes[0], "address": "oci_core_instance.unreviewed"})
    elif tamper == "wrong_id":
        changes[0]["change"]["before"]["id"] = "ocid1.instance.oc1..different"
    elif tamper == "replace":
        changes[0]["change"]["actions"] = ["delete", "create"]
    elif tamper == "unknown":
        changes[0]["change"]["after_unknown"] = {"id": True}
    elif tamper in {"drift", "prior_wrong_id", "extra_data", "data_wrong_id",
                    "incomplete", "planned_managed"}:
        original = options["command_runner"]
        def with_drift(args, cwd, env):
            result = original(args, cwd, env)
            if args[1] == "show":
                payload = json.loads(result.stdout)
                if tamper == "drift":
                    payload["resource_drift"] = [changes[0]]
                elif tamper == "prior_wrong_id":
                    payload["prior_state"]["values"]["root_module"]["resources"][0]["values"]["id"] = "ocid1.instance.oc1..wrong"
                elif tamper == "extra_data":
                    payload["prior_state"]["values"]["root_module"]["resources"].append({
                        "address": "data.oci_core_images.other", "mode": "data",
                        "type": "oci_core_images",
                        "provider_name": "registry.terraform.io/oracle/oci",
                        "values": {"id": "image-unreviewed"}})
                elif tamper == "data_wrong_id":
                    payload["prior_state"]["values"]["root_module"]["resources"][-1]["values"]["id"] = "image-wrong"
                elif tamper == "incomplete":
                    payload["complete"] = False
                else:
                    payload["planned_values"] = {"root_module": {"resources": [
                        payload["prior_state"]["values"]["root_module"]["resources"][0]]}}
                return replace_result(result, json.dumps(payload))
            return result
        options["command_runner"] = with_drift
    with pytest.raises(service.KeyedCoreDestroyPreviewAttention):
        service.preview_pending_keyed_oci_core_destroy(parent.id, **options)
    child_id = f"job-provider-keyed-core-destroy-preview-{core.id.removeprefix('job-')}"
    assert jobs.get(child_id).status == "running"
    with pytest.raises(service.KeyedCoreDestroyPreviewAttention):
        service.preview_pending_keyed_oci_core_destroy(parent.id, **options)
    assert len(calls) == 2


def replace_result(result, stdout):
    return SimpleNamespace(returncode=result.returncode, stdout=stdout, stderr=result.stderr)


def test_wrong_fence_or_state_drift_never_runs_command(tmp_path, monkeypatch):
    jobs, parent, _core, _coordinator, _plan, _, state_path, _, calls, options = _case(
        tmp_path, monkeypatch)
    options["lease_lookup"] = lambda _: ("dpl-core", "apply")
    with pytest.raises(service.KeyedCoreDestroyPreviewAttention):
        service.preview_pending_keyed_oci_core_destroy(parent.id, **options)
    assert calls == []
    options["lease_lookup"] = lambda _: ("dpl-core", service._FENCE)
    state_path.write_bytes(state_path.read_bytes() + b" ")
    with pytest.raises(service.KeyedCoreDestroyPreviewAttention):
        service.preview_pending_keyed_oci_core_destroy(parent.id, **options)
    assert calls == []


def test_wrong_core_state_root_or_terraform_version_never_runs_command(tmp_path, monkeypatch):
    jobs, parent, _core, _coordinator, plan, _, state_path, _, calls, options = _case(
        tmp_path, monkeypatch)
    monkeypatch.setattr(service, "DEFAULT_TERRAFORM_STATE_ROOT", state_path.parent.parent)
    with pytest.raises(service.KeyedCoreDestroyPreviewAttention):
        service.preview_pending_keyed_oci_core_destroy(parent.id, **options)
    assert calls == []
    monkeypatch.setattr(service, "DEFAULT_TERRAFORM_STATE_ROOT", state_path.parents[2])
    plan.evidence["terraformFingerprint"] = "1.14.0"
    core = jobs.get("job-core")
    digest = _fingerprint(plan.evidence)
    updated_seal = replace(core.events[-2], data={**core.events[-2].data,
                                                  "corePlanEvidenceSha256": digest})
    core = replace(core, input={**core.input, "corePlanEvidenceSha256": digest},
                   events=[updated_seal, core.events[-1]])
    jobs.rows[core.id] = core
    monkeypatch.setattr(service, "_boundary", lambda *_args: (
        jobs.get(parent.id), jobs.get(core.id),
        {"providerScopes": [{"corePlanId": plan.id}], "snapshotId": "c" * 64}, service._FENCE))
    with pytest.raises(service.KeyedCoreDestroyPreviewAttention):
        service.preview_pending_keyed_oci_core_destroy(parent.id, **options)
    assert calls == []


def test_interrupted_command_cannot_be_implicitly_replayed(tmp_path, monkeypatch):
    jobs, parent, core, _, _, _, _, _, calls, options = _case(tmp_path, monkeypatch)
    def interrupted(args, cwd, env):
        calls.append(args)
        raise TimeoutError("simulated interrupted Terraform process")
    options["command_runner"] = interrupted
    with pytest.raises(service.KeyedCoreDestroyPreviewAttention):
        service.preview_pending_keyed_oci_core_destroy(parent.id, **options)
    child_id = f"job-provider-keyed-core-destroy-preview-{core.id.removeprefix('job-')}"
    assert jobs.get(child_id).status == "running"
    with pytest.raises(service.KeyedCoreDestroyPreviewAttention):
        service.preview_pending_keyed_oci_core_destroy(parent.id, **options)
    assert len(calls) == 1


def test_symlink_state_refuses_preview_before_journal(tmp_path, monkeypatch):
    jobs, parent, core, _, _, _, state_path, _, calls, options = _case(tmp_path, monkeypatch)
    original = state_path.with_suffix(".original")
    state_path.rename(original)
    state_path.symlink_to(original)
    with pytest.raises(service.KeyedCoreDestroyPreviewAttention):
        service.preview_pending_keyed_oci_core_destroy(parent.id, **options)
    assert calls == []
    assert jobs.get(f"job-provider-keyed-core-destroy-preview-{core.id.removeprefix('job-')}") is None


@pytest.mark.parametrize("output,accepted", [
    ({"actions": ["delete"], "before": "old", "after": None,
      "after_unknown": False}, True),
    ({"change": {"actions": ["delete"], "before": "old", "after": None,
                 "after_unknown": {}}}, True),
    ({"actions": ["no-op"], "before": "same", "after": "same"}, True),
    ({"actions": ["delete"], "after": "retained"}, False),
    ({"actions": ["delete"], "after_unknown": 0}, False),
    ({"actions": ["delete"], "after_unknown": None}, False),
    ({"actions": ["delete"], "after_unknown": []}, False),
    ({"actions": ["update"], "after": None}, False),
    ({"actions": ["delete"], "change": {"actions": ["delete"]}}, False),
    ({"change": {"actions": ["delete"]}, "after_unknown": {}}, False),
])
def test_terraform_destroy_output_shapes(output, accepted):
    assert service._exact_destroy_output(output) is accepted


def _saved_case(tmp_path, monkeypatch):
    jobs, parent, core, coordinator, plan, inventory, state_path, changes, calls, options = _case(
        tmp_path, monkeypatch)
    preview = service.preview_pending_keyed_oci_core_destroy(parent.id, **options)
    child = replace(preview, status="running", finished_at=None, events=preview.events[:2])
    jobs.rows[child.id] = child
    calls.clear()
    stable_retirement = ("retired", "sealed")
    options["retired_recognizer"] = lambda *_args, **_kwargs: stable_retirement
    options["quiescence_check"] = lambda: True
    options["reviewed_plan_sha256"] = preview.events[-1].data["planSha256"]
    return jobs, parent, core, coordinator, plan, inventory, state_path, child, calls, options


def test_saved_preview_recovery_runs_only_show(tmp_path, monkeypatch):
    jobs, parent, core, _, _, _, _, child, calls, options = _saved_case(tmp_path, monkeypatch)
    result = service.recognize_saved_pending_keyed_oci_core_destroy_preview(parent.id, **options)
    assert result.status == "succeeded"
    assert result.events[-1].message == "core destroy preview saved"
    assert [argv[1] for argv in calls] == ["show"]
    with pytest.raises(service.KeyedCoreDestroyPreviewAttention):
        service.recognize_saved_pending_keyed_oci_core_destroy_preview(parent.id, **options)
    assert len(calls) == 1


def test_saved_preview_accepts_terraform_115_direct_output_deletes(tmp_path, monkeypatch):
    jobs, parent, _, _, _, _, _, _, calls, options = _saved_case(tmp_path, monkeypatch)
    original = options["command_runner"]
    def direct_outputs(args, cwd, env):
        assert args[1] == "show"
        result = original(args, cwd, env)
        payload = json.loads(result.stdout)
        payload["output_changes"] = {
            "homebase_ip": {"actions": ["delete"], "before": "192.0.2.20",
                            "after": None, "after_unknown": False,
                            "before_sensitive": False, "after_sensitive": False},
            "proxy_ip": {"actions": ["delete"], "before": "192.0.2.21",
                         "after": None, "after_unknown": {}},
        }
        return replace_result(result, json.dumps(payload))
    options["command_runner"] = direct_outputs
    result = service.recognize_saved_pending_keyed_oci_core_destroy_preview(parent.id, **options)
    assert result.status == "succeeded"
    assert [argv[1] for argv in calls] == ["show"]


@pytest.mark.parametrize("drift", ["hash", "state", "symlink", "active", "child", "lease"])
def test_saved_preview_rejects_drift_before_show(tmp_path, monkeypatch, drift):
    jobs, parent, core, _, _, _, state_path, child, calls, options = _saved_case(tmp_path, monkeypatch)
    plan_path = Path(state_path.parent / f".barragan-core-destroy-{core.id.removeprefix('job-')}.tfplan")
    if drift == "hash":
        options["reviewed_plan_sha256"] = "0" * 64
    elif drift == "state":
        state_path.write_bytes(state_path.read_bytes() + b" ")
    elif drift == "symlink":
        original = plan_path.with_suffix(".original")
        plan_path.rename(original)
        plan_path.symlink_to(original)
    elif drift == "active":
        options["quiescence_check"] = lambda: False
    elif drift == "child":
        jobs.rows[child.id] = replace(child, events=child.events + [
            JobEvent(3, "info", "unexpected", {})])
    else:
        options["lease_lookup"] = lambda _: ("dpl-core", "apply")
    with pytest.raises(service.KeyedCoreDestroyPreviewAttention):
        service.recognize_saved_pending_keyed_oci_core_destroy_preview(parent.id, **options)
    assert calls == []
    assert jobs.get(child.id).status == "running"


def test_saved_preview_rejects_state_drift_during_show(tmp_path, monkeypatch):
    jobs, parent, _, _, _, _, state_path, child, calls, options = _saved_case(tmp_path, monkeypatch)
    original = options["command_runner"]
    def changed(args, cwd, env):
        result = original(args, cwd, env)
        state_path.write_bytes(state_path.read_bytes() + b" ")
        return result
    options["command_runner"] = changed
    with pytest.raises(service.KeyedCoreDestroyPreviewAttention):
        service.recognize_saved_pending_keyed_oci_core_destroy_preview(parent.id, **options)
    assert [argv[1] for argv in calls] == ["show"]
    assert jobs.get(child.id).status == "running"


def test_saved_preview_rejects_plan_hash_drift_during_show(tmp_path, monkeypatch):
    jobs, parent, core, _, _, _, state_path, child, calls, options = _saved_case(tmp_path, monkeypatch)
    plan_path = state_path.parent / f".barragan-core-destroy-{core.id.removeprefix('job-')}.tfplan"
    original = options["command_runner"]
    def changed(args, cwd, env):
        result = original(args, cwd, env)
        plan_path.write_bytes(plan_path.read_bytes() + b"altered")
        return result
    options["command_runner"] = changed
    with pytest.raises(service.KeyedCoreDestroyPreviewAttention):
        service.recognize_saved_pending_keyed_oci_core_destroy_preview(parent.id, **options)
    assert [argv[1] for argv in calls] == ["show"]
    assert jobs.get(child.id).status == "running"


def test_saved_preview_rejects_release_drift_during_show(tmp_path, monkeypatch):
    jobs, parent, _, _, _, _, _, child, calls, options = _saved_case(tmp_path, monkeypatch)
    release = options["release_check"]()
    checks = iter([release, SimpleNamespace(path=release.path,
                                            version=release.version, sha256="b" * 64)])
    options["release_check"] = lambda **_kwargs: next(checks)
    with pytest.raises(service.KeyedCoreDestroyPreviewAttention):
        service.recognize_saved_pending_keyed_oci_core_destroy_preview(parent.id, **options)
    assert [argv[1] for argv in calls] == ["show"]
    assert jobs.get(child.id).status == "running"


def test_saved_preview_rejects_running_apply_child(tmp_path, monkeypatch):
    jobs, parent, core, _, _, _, _, child, calls, options = _saved_case(tmp_path, monkeypatch)
    jobs.rows["job-apply"] = replace(child, id="job-apply",
                                     action="provider_keyed_core_destroy_apply",
                                     input={"coreJobId": core.id})
    with pytest.raises(service.KeyedCoreDestroyPreviewAttention):
        service.recognize_saved_pending_keyed_oci_core_destroy_preview(parent.id, **options)
    assert calls == []


def test_saved_preview_rejects_worker_arriving_during_show(tmp_path, monkeypatch):
    jobs, parent, _, _, _, _, _, child, calls, options = _saved_case(tmp_path, monkeypatch)
    checks = iter([True, False])
    options["quiescence_check"] = lambda: next(checks)
    with pytest.raises(service.KeyedCoreDestroyPreviewAttention):
        service.recognize_saved_pending_keyed_oci_core_destroy_preview(parent.id, **options)
    assert [argv[1] for argv in calls] == ["show"]
    assert jobs.get(child.id).status == "running"


def test_service_uid_terraform_worker_scan(tmp_path):
    proc = tmp_path / "proc"
    proc.mkdir()
    worker = proc / "12345"
    worker.mkdir()
    exe = worker / "exe"
    exe.symlink_to("/usr/bin/terraform")
    assert service._terraform_quiescent(proc) is False
    exe.unlink()
    exe.symlink_to("/usr/bin/terraform-provider-oci")
    assert service._terraform_quiescent(proc) is False
    exe.unlink()
    exe.symlink_to("/usr/bin/python3")
    assert service._terraform_quiescent(proc) is True
    assert service._terraform_quiescent(tmp_path / "absent") is False
