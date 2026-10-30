# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted, offline mixed zero-Apply source proof with real artifact checks."""

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
import app.services.provider_keyed_mixed_zero_apply_teardown_source as source_service
import app.services.provider_keyed_mixed_zero_apply_cleanup as cleanup_service
import app.services.provider_keyed_mixed_linode_intent as linode_compiler
import app.services.provider_keyed_mixed_digitalocean_intent as do_compiler
import app.services.provider_keyed_mixed_linode_saved_plan as linode_saved
import app.services.provider_keyed_mixed_digitalocean_saved_plan as do_saved
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_mixed_initial_plan_parent import prepare_or_reuse_mixed_initial_plans, seal_mixed_initial_apply
from app.services.provider_keyed_mixed_plan_journal import _Journal
from app.services.provider_keyed_oci_core_state import parse_applied_oci_core_state
from app.services.provider_keyed_sketch import prepare_provider_keyed_workspace, reserve_provider_topology
from app.services.sketch_ssh_keys import SketchSshKeyMaterial, SketchSshKeyMetadata, _fingerprint as key_fingerprint
from app.storage.job_repository import SqliteJobRepository, StoredJobRun
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.database import db
from app.storage.models import CoreMutationLeaseModel, DeploymentPlanModel, EngagementModel
from app.storage.provider_resource_repository import StoredProviderResourceRecord
from test_provider_keyed_mixed_digitalocean_intent import _mixed_records, PUBLIC_KEY
from test_provider_keyed_oci_core_state import _state
from redteam_infra_test_fixtures import checkout_local_pinned_source


def _offline_source(tmp_path):
    from app.services.redteam_infra_template import TEMPLATE_ROOT_ENV

    upstream = Path(os.environ[TEMPLATE_ROOT_ENV]) if os.environ.get(TEMPLATE_ROOT_ENV) else (
        Path(__file__).resolve().parents[3] / "redteam-infra")
    if not upstream.is_dir():
        upstream = Path("/private/tmp/redteam-infra")
    return checkout_local_pinned_source(upstream, tmp_path / "pinned-source", linode_saved._SOURCE_REVISION)


def _journal(path):
    journal = _Journal(path)
    for phase in ("version", "init", "plan", "show"):
        identity = {"invocationId": phase, "bootId": "offline-test-boot",
                    "pid": 123, "pgid": 123, "startTicks": 10}
        journal.append(phase, "intent", {"invocationId": phase, "argvSha256": "a" * 64})
        journal.append(phase, "started", identity)
        journal.append(phase, "result", {**identity, "returnCode": 0,
                                          "stdoutBytes": 0, "stderrBytes": 0,
                                          "stdoutTruncated": False, "stderrTruncated": False})
    return journal.rows[-1]["sha256"]


@pytest.fixture(params=[True, False], ids=["linode-first", "digitalocean-first"])
def case(tmp_path, monkeypatch, request):
    records = _mixed_records(linode_first=request.param, same_region=True)
    material = SketchSshKeyMaterial(
        SketchSshKeyMetadata("eng-opaque", "private", "public",
                             key_fingerprint(PUBLIC_KEY), [], "now", "now"),
        "private-key", PUBLIC_KEY)
    for module in (linode_compiler, linode_saved, do_saved):
        monkeypatch.setattr(module, "retrieve_sketch_ssh_key", lambda *a: material)
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    upstream = _offline_source(tmp_path)
    state_root = tmp_path / "state"
    monkeypatch.setattr(source_service, "_default_state_root", lambda: state_root)
    terraform = Path(sys.executable).resolve(strict=True)
    monkeypatch.setattr(source_service, "_REVIEWED_PATH", terraform)
    monkeypatch.setattr(source_service, "_REVIEWED_SHA256", hashlib.sha256(terraform.read_bytes()).hexdigest())
    core_root = tmp_path / "core-state"
    monkeypatch.setattr(source_service, "DEFAULT_TERRAFORM_STATE_ROOT", core_root)
    core_state = core_root / "eng-opaque/core/terraform.tfstate"
    core_state.parent.mkdir(parents=True)
    state = _state(proxy_count=1, elk_enabled=False)
    target = records["core_plan"].evidence["target"]
    for row in state["resources"]:
        if row["mode"] == "managed":
            attrs = row["instances"][0]["attributes"]
            attrs["freeform_tags"]["barragan_engagement"] = "opaque-fixture"
            if "compartment_id" in attrs:
                attrs["compartment_id"] = target["compartmentId"]
    core_state.write_bytes(json.dumps(state).encode())
    inventory = parse_applied_oci_core_state(
        core_state.read_bytes(), proxy_count=1, elk_enabled=False,
        compartment_id=target["compartmentId"], engagement_name="opaque-fixture")
    plan = records["core_plan"]
    plan.evidence.update(terraformStatePath=str(core_state), proxyCount=1, elkEnabled=False)
    evidence_sha = _fingerprint(plan.evidence)
    core = records["core_job"]
    core_input = {**core.input, "corePlanEvidenceSha256": evidence_sha,
                  "proxyCount": 1, "elkEnabled": False}
    seal = {"schema": "applied-oci-core-state-v1", "corePlanEvidenceSha256": evidence_sha,
            "rawStateSha256": inventory.raw_state_sha256,
            "inventorySha256": inventory.inventory_sha256,
            "lineage": inventory.lineage, "serial": inventory.serial,
            "resourceCount": len(inventory.resources)}
    core = replace(core, input=core_input, events=[
        core.events[0], JobEvent(2, "info", "applied OCI core state sealed", seal),
        JobEvent(3, "info", "pilot Standard RTI run finished", {})])
    records["core_job"] = core
    jobs.save(core)
    inspector_jobs = []
    inspector_rows = []
    for kind, resource_id in (("inspector_instance", "100"), ("inspector_firewall", "200")):
        owner_id = f"job-inspector-{kind}"
        owner = StoredJobRun(owner_id, "inspector_inspection", "succeeded",
                             "engagement:eng-opaque", "engagement", "eng-opaque", "owner",
                             {}, [], "now", "now", "now", [])
        jobs.save(owner)
        inspector_jobs.append(owner)
        inspector_rows.append(StoredProviderResourceRecord(
            f"linode:inspector{'-firewall' if kind == 'inspector_firewall' else ''}:{resource_id}",
            "eng-opaque", "opaque-fixture", "linode", kind, resource_id,
            "inspector", "us-east", "running", "active", "barragan_inspector_job",
            {"barraganOwned": True, "role": ("inspector_firewall" if kind == "inspector_firewall"
                                               else "inspector"),
             "inspectionJobId": owner_id,
             **({"inspectorHostResourceId": "100"} if kind == "inspector_firewall" else {})},
            owner_id, "now", "now"))
    stored_receipts = {}

    def runner(provider):
        def produce(**_kwargs):
            intent = (linode_compiler.compile_mixed_linode_initial_intent if provider == "linode"
                      else do_compiler.compile_mixed_digitalocean_initial_intent)(
                          **{**records, "job_repository": jobs})
            if provider in stored_receipts:
                return stored_receipts[provider]
            module = linode_saved if provider == "linode" else do_saved
            workspace = prepare_provider_keyed_workspace(
                "eng-opaque", provider, intent.provider_connection_id,
                template_root=upstream, source_revision=module._SOURCE_REVISION,
                root=state_root, environment="devtest", deployment_target="barragan-testing")
            assert reserve_provider_topology(
                workspace, intent.topology["middles"], intent.topology["edge_groups"]) == intent.topology
            material_root = workspace.path.parents[1] / ".plan-material" / provider
            material_root.mkdir(parents=True, mode=0o700)
            material_root.parent.chmod(0o700)
            material_root.chmod(0o700)
            (material_root / "ssh-output").mkdir(mode=0o700)
            inputs = material_root / "inputs.json"
            expected_inputs = {**intent.nonsecret_varfile,
                               "ssh_pub_key_path": str(material_root / "admin-public"),
                               "ssh_priv_key_path": str(material_root / "admin-private"),
                               "ssh_config_path": str(material_root / "ssh-output")}
            inputs.write_text(json.dumps(expected_inputs, sort_keys=True) + "\n")
            inputs.chmod(0o600)
            plan_path = workspace.path / module._PLAN
            plan_path.write_bytes(b"offline-saved-plan-fixture")
            plan_path.chmod(0o600)
            journal_sha = _journal(workspace.path / module._JOURNAL)
            receipt = {**module._snapshot(intent, workspace, Path(sys.executable).resolve(strict=True), inputs),
                       "planSha256": module._sha(plan_path),
                       "showJsonSha256": "b" * 64, "journalSha256": journal_sha}
            receipt_path = workspace.path / module._RECEIPT
            receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n")
            receipt_path.chmod(0o600)
            stored_receipts[provider] = receipt
            return receipt
        return produce

    args = dict(core_job_id=core.id, engagement_id="eng-opaque", lease_owner="plan-1",
                environment="devtest", state_root=state_root, template_root=upstream,
                job_repository=jobs,
                engagement_repository=SimpleNamespace(get=lambda _: records["engagement"]),
                sketch_repository=SimpleNamespace(list_for_engagement=lambda _: records["chains"]),
                plan_repository=SimpleNamespace(get=lambda _: plan),
                credential_repository=records["credential_repository"],
                ssh_key_repository=SimpleNamespace(),
                lease_lookup=lambda _: ("plan-1", "provider_keyed_initial"),
                linode_runner=runner("linode"), digitalocean_runner=runner("digitalocean"))
    prepare_or_reuse_mixed_initial_plans(**args)
    audit_args = {key: value for key, value in args.items() if key not in {
        "template_root", "linode_runner", "digitalocean_runner"}}
    audit_args.update(core_state_root=core_root,
                      provider_resource_repository=SimpleNamespace(
                          list_for_engagement=lambda _: inspector_rows))
    return SimpleNamespace(args=audit_args, plan_args=args, jobs=jobs, core_state=core_state,
                           state_root=state_root, rows=inspector_rows,
                           receipts=stored_receipts, plan=plan)


def test_zero_apply_source_reopens_persisted_evidence_without_commands(case):
    source = source_service.audit_mixed_zero_apply_teardown_source(**case.args)
    assert source.ordered_providers in (("linode", "digitalocean"),
                                        ("digitalocean", "linode"))
    assert source.core_state_sha256 == hashlib.sha256(case.core_state.read_bytes()).hexdigest()
    assert len(source.provider_receipt_sha256) == 2
    assert len(source.owned_inspector_record_ids) == 2
    assert source_service.audit_mixed_zero_apply_teardown_source(**case.args) == source


def test_zero_apply_source_accepts_seal_only_while_no_apply_began(case):
    sealed = seal_mixed_initial_apply(**case.plan_args)
    source = source_service.audit_mixed_zero_apply_teardown_source(**case.args)
    assert sealed.input["phase"] == "apply_sealed"
    assert source.parent_journal_sha256 == source_service.job_event_digest(sealed.events)
    with case.jobs._connect() as connection:
        connection.execute("UPDATE job_events SET data = ? WHERE job_id = ? AND sequence = 6",
                           (json.dumps({**sealed.events[5].data, "sourceCredentialSnapshotSha256": "0" * 64}),
                            sealed.id))
    with pytest.raises(source_service.MixedZeroApplySourceError):
        source_service.audit_mixed_zero_apply_teardown_source(**case.args)


def test_sealed_zero_apply_source_rejects_apply_phase_marker(case):
    seal_mixed_initial_apply(**case.plan_args)
    provider = case.jobs.get("job-provider-keyed-mixed-initial-core").input["orderedProviders"][0]
    workspace = next((case.state_root / "eng-opaque" / "provider-keyed-v2" / provider).iterdir())
    (workspace / ".barragan-apply-phase.json").write_text("{}")
    with pytest.raises(source_service.MixedZeroApplySourceError):
        source_service.audit_mixed_zero_apply_teardown_source(**case.args)


def _fenced(case):
    source = source_service.audit_mixed_zero_apply_teardown_source(**case.args)
    case.jobs.save(cleanup_service._proposal(source, "operator"))
    args = {**case.args, "lease_operation": "provider_keyed_teardown_fence",
            "lease_lookup": lambda _: (source.core_plan_id, "provider_keyed_teardown_fence")}
    return source, args


def test_fenced_source_reopens_exact_saved_parent_in_both_orders(case):
    source, args = _fenced(case)
    assert source_service.audit_mixed_zero_apply_teardown_source(**args) == source
    assert source.ordered_providers in (("linode", "digitalocean"),
                                        ("digitalocean", "linode"))
    # The ordinary plan reader remains bound to the initial operation.
    with pytest.raises(source_service.MixedZeroApplySourceError):
        source_service.audit_mixed_zero_apply_teardown_source(
            **{key: value for key, value in args.items() if key != "lease_operation"})


def test_sqlalchemy_fence_reservation_reaudits_real_source_inside_writer(case, client, monkeypatch):
    from app.services.provider_keyed_runtime_preflight import _db_lease_lookup

    original = source_service.audit_mixed_zero_apply_teardown_source
    source = original(**case.args)
    with client.application.storage_context():
        db.session.add(EngagementModel(
            id=source.engagement_id, name="opaque-fixture", status="deployed",
            owner="operator", template_id="small", input_parameters={},
        ))
        db.session.add(DeploymentPlanModel(
            id=source.core_plan_id, engagement_id=source.engagement_id,
            revision_id=case.plan.revision_id, status="applied", stage="applied",
            apply_job_id=source.core_job_id,
        ))
        db.session.add(CoreMutationLeaseModel(
            engagement_id=source.engagement_id, owner_id=source.core_plan_id,
            operation="provider_keyed_initial",
        ))
        db.session.commit()
        jobs = SqlAlchemyJobRepository()
        for row in case.jobs.list():
            when = "2026-10-15T00:00:00+00:00"
            expected = replace(
                row, created_at=when if row.created_at == "now" else row.created_at,
                started_at=when if row.started_at == "now" else row.started_at,
                finished_at=when if row.finished_at == "now" else row.finished_at,
            )
            assert jobs.save(expected).id == expected.id
        from sqlalchemy import text
        original_append = jobs.append_mixed_plan_phase_if_claimed
        def fence_before_cas(*args, **kwargs):
            if kwargs.get("next_phase") == "apply_sealed":
                db.session.execute(text("""UPDATE core_mutation_leases
                    SET operation = 'provider_keyed_teardown_fence'
                    WHERE engagement_id = :engagement"""), {"engagement": source.engagement_id})
                db.session.commit()
            return original_append(*args, **kwargs)
        monkeypatch.setattr(jobs, "append_mixed_plan_phase_if_claimed", fence_before_cas)
        with pytest.raises(Exception):
            seal_mixed_initial_apply(**{**case.plan_args, "job_repository": jobs,
                                       "lease_lookup": _db_lease_lookup})
        assert len(jobs.get("job-provider-keyed-mixed-initial-core").events) == 5
        monkeypatch.setattr(jobs, "append_mixed_plan_phase_if_claimed", original_append)
        db.session.execute(text("""UPDATE core_mutation_leases
            SET operation = 'provider_keyed_initial' WHERE engagement_id = :engagement"""),
            {"engagement": source.engagement_id})
        db.session.execute(text("""UPDATE job_runs
            SET input = json_set(input, '$.claimExpiresAt', '2020-01-01T00:00:00+00:00')
            WHERE id = 'job-provider-keyed-mixed-initial-core'"""))
        db.session.commit()
        sealed = seal_mixed_initial_apply(**{**case.plan_args, "job_repository": jobs,
                                             "lease_lookup": _db_lease_lookup})
        assert sealed.input["phase"] == "apply_sealed"
        source = original(**{**case.args, "job_repository": jobs,
                             "lease_lookup": _db_lease_lookup})
        calls = []

        def bound_audit(*args, **kwargs):
            calls.append(db.session.get(CoreMutationLeaseModel, source.engagement_id).operation)
            return original(
                *args, **{**{key: value for key, value in case.args.items()
                            if key not in {"engagement_id", "core_job_id"}},
                          **kwargs, "job_repository": jobs,
                          "lease_lookup": _db_lease_lookup},
            )

        monkeypatch.setattr(source_service, "audit_mixed_zero_apply_teardown_source", bound_audit)
        parent = jobs.reserve_mixed_zero_apply_cleanup_parent(
            cleanup_service._proposal(source, "operator"), reviewed_source=source,
            state_root=case.state_root, core_state_root=case.args["core_state_root"],
        )
        assert calls == ["provider_keyed_initial"]
        assert parent.input["source"]["core_state_sha256"] == source.core_state_sha256
        assert db.session.get(CoreMutationLeaseModel, source.engagement_id).operation == (
            "provider_keyed_teardown_fence")
        assert original(**{**case.args, "job_repository": jobs,
                           "lease_lookup": _db_lease_lookup,
                           "lease_operation": "provider_keyed_teardown_fence"}) == source


@pytest.mark.parametrize("drift", ["missing-parent", "source", "source-payload",
                                  "extra-input", "event", "status", "lease",
                                  "lease-owner", "credential", "unknown-job"])
def test_fenced_source_rejects_parent_source_and_lease_drift(case, drift):
    source, args = _fenced(case)
    parent = case.jobs.get(cleanup_service._parent_id(source.core_job_id))
    if drift == "missing-parent":
        with case.jobs._connect() as connection:
            connection.execute("DELETE FROM job_events WHERE job_id = ?", (parent.id,))
            connection.execute("DELETE FROM job_runs WHERE id = ?", (parent.id,))
    elif drift == "source":
        case.jobs.save(replace(parent, input={**parent.input, "sourceSha256": "0" * 64}))
    elif drift == "source-payload":
        changed = {**parent.input["source"], "core_state_sha256": "0" * 64}
        case.jobs.save(replace(parent, input={**parent.input, "source": changed,
                                              "sourceSha256": _fingerprint(changed)},
                               events=[JobEvent(1, "info", "mixed zero-Apply cleanup fenced",
                                                {"sourceSha256": _fingerprint(changed)})]))
    elif drift == "extra-input":
        case.jobs.save(replace(parent, input={**parent.input, "unexpected": True}))
    elif drift == "event":
        case.jobs.save(replace(parent, events=[JobEvent(1, "info", "wrong", {})]))
    elif drift == "status":
        case.jobs.save(replace(parent, status="running"))
    elif drift == "lease":
        args["lease_lookup"] = lambda _: (source.core_plan_id, "provider_keyed_initial")
    elif drift == "lease-owner":
        args["lease_lookup"] = lambda _: ("other-plan", "provider_keyed_teardown_fence")
    elif drift == "credential":
        args["credential_repository"] = SimpleNamespace(get=lambda _: None)
    else:
        case.jobs.save(StoredJobRun(
            "job-extra", "provider_keyed_mixed_initial_apply", "queued",
            "engagement:eng-opaque", "engagement", "eng-opaque", "operator",
            {}, [], "now", None, None, []))
    with pytest.raises(source_service.MixedZeroApplySourceError):
        source_service.audit_mixed_zero_apply_teardown_source(**args)


def test_zero_apply_source_rejects_state_apply_or_receipt_drift(case):
    provider = next(iter(case.receipts))
    receipt = case.receipts[provider]
    plan_path = Path(receipt["planPath"])
    plan_path.write_bytes(b"changed-plan")
    with pytest.raises(source_service.MixedZeroApplySourceError):
        source_service.audit_mixed_zero_apply_teardown_source(**case.args)


@pytest.mark.parametrize("drift", ["state", "phase", "source", "inputs", "apply-job",
                                  "inspector", "core-state", "review", "credential", "key",
                                  "journal", "parent", "historical-resource", "unknown-job"])
def test_zero_apply_source_rejects_persisted_drift(case, drift, monkeypatch):
    receipt = next(iter(case.receipts.values()))
    workspace = Path(receipt["planPath"]).parent
    if drift == "state":
        (workspace / "terraform.tfstate").write_text("{}")
    elif drift == "phase":
        (workspace / ".barragan-apply-phase.json").write_text('{"phase":"apply_started"}')
    elif drift == "source":
        with (workspace / "edge.tf").open("a") as stream:
            stream.write("\n# drift\n")
    elif drift == "inputs":
        provider = "digitalocean" if "digitalocean" in receipt["schema"] else "linode"
        path = workspace.parents[1] / ".plan-material" / provider / "inputs.json"
        path.write_text("{}")
    elif drift == "apply-job":
        case.jobs.save(StoredJobRun(
            "job-mixed-apply", "provider_keyed_mixed_initial_apply", "queued",
            "engagement:eng-opaque", "engagement", "eng-opaque", "owner",
            {"mutation": True}, [], "now", None, None, []))
    elif drift == "unknown-job":
        case.jobs.save(StoredJobRun(
            "job-unknown", "unknown_future_mutation", "succeeded",
            "engagement:eng-opaque", "engagement", "eng-opaque", "owner",
            {}, [], "now", "now", "now", []))
    elif drift == "inspector":
        case.rows[1] = replace(case.rows[1], resource_id="other-firewall")
    elif drift == "historical-resource":
        case.rows.append(replace(case.rows[0], id="linode:instance:999",
                                 resource_type="instance", resource_id="999",
                                 status="destroyed"))
    elif drift == "core-state":
        case.core_state.write_bytes(b"{}")
    elif drift == "journal":
        provider = "digitalocean" if "digitalocean" in receipt["schema"] else "linode"
        module = do_saved if provider == "digitalocean" else linode_saved
        with (workspace / module._JOURNAL).open("a") as stream:
            stream.write('{"unexpected":true}\n')
    elif drift == "parent":
        with case.jobs._connect() as connection:
            connection.execute("UPDATE job_events SET data = ? WHERE job_id = ? AND sequence = 5",
                               (json.dumps({"drift": True}),
                                source_service._parent_id("job-core")))
    elif drift == "review":
        case.plan.evidence["sketchAuthorization"]["providerScopes"][0]["image"] = "other-image"
    elif drift == "credential":
        case.args["credential_repository"] = SimpleNamespace(get=lambda _: None)
    else:
        monkeypatch.setattr(linode_compiler, "retrieve_sketch_ssh_key", lambda *a: None)
    with pytest.raises(source_service.MixedZeroApplySourceError):
        source_service.audit_mixed_zero_apply_teardown_source(**case.args)


def test_truncated_show_cannot_prove_saved_receipt():
    complete = {"phase": "show", "kind": "result", "sha256": "a" * 64,
                "data": {"returnCode": 0, "stdoutTruncated": False,
                         "stderrTruncated": False}}
    assert source_service._successful_show([complete], "a" * 64)
    assert not source_service._successful_show([
        {**complete, "data": {**complete["data"], "stdoutTruncated": True}}], "a" * 64)
    assert not source_service._successful_show([
        complete, {**complete, "sha256": "b" * 64,
                   "data": {**complete["data"], "stderrTruncated": True}}], "a" * 64)
