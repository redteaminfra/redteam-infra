# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline, persisted one-shot mixed zero-Apply OCI preview boundaries."""

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services import provider_keyed_mixed_zero_apply_core_preview as service
from app.services import provider_keyed_mixed_zero_apply_teardown_source as source_service
from app.services.provider_keyed_core_destroy_preview import _state_data_ids
from app.services.provider_keyed_oci_core_state import parse_applied_oci_core_state
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.models import (
    CertificateAssetModel, CertificateBindingModel, DomainAssetModel,
    DomainAssignmentModel, DomainDnsRecordOwnershipModel, DomainDnsSnapshotModel,
    EngagementModel, EngagementServiceModel, JobRunModel,
)
from test_provider_keyed_mixed_zero_apply_teardown_source import case, _fenced


def _ready(case, monkeypatch):
    run_dir = case.core_state.parents[2] / "run"
    run_dir.mkdir()
    data_dir = case.core_state.parent / "data-core-test"
    data_dir.mkdir()
    lock = run_dir / ".terraform.lock.hcl"
    lock.write_bytes(b"reviewed lock")
    public_key = run_dir / "admin.pub"
    public_key.write_bytes(b"ssh-ed25519 reviewed-test-key")
    evidence = case.plan.evidence
    evidence.update(runDirectory=str(run_dir), terraformDataDir=str(data_dir),
                    sshPublicKeyPath=str(public_key),
                    providerLockFingerprint=hashlib.sha256(lock.read_bytes()).hexdigest(),
                    publicKeyFingerprint=hashlib.sha256(public_key.read_bytes()).hexdigest(),
                    keyedCoreTerraformSourceManifest={"schema": "offline-test"},
                    terraformFingerprint="1.15.5", sshSourceCidrs=["192.0.2.1/32"])
    old = case.jobs.get(case.args["core_job_id"])
    events = list(old.events)
    events[-2] = replace(events[-2], data={**events[-2].data,
                                          "corePlanEvidenceSha256": _fingerprint(evidence)})
    core = replace(old, input={**old.input, "corePlanEvidenceSha256": _fingerprint(evidence),
                               "sshSourceCidrs": evidence["sshSourceCidrs"]},
                   events=events)
    case.jobs.save(core)
    source, fenced_args = _fenced(case)
    monkeypatch.setattr(service, "_default_state_root", lambda: case.state_root)
    monkeypatch.setattr(service, "DEFAULT_TERRAFORM_STATE_ROOT", case.core_state.parents[2])
    monkeypatch.setattr(service, "require_keyed_core_terraform_source_manifest",
                        lambda path, manifest: path == run_dir and manifest == evidence["keyedCoreTerraformSourceManifest"]
                        or pytest.fail("source manifest changed"))
    release = SimpleNamespace(path=Path("/usr/bin/terraform"), sha256=source_service._REVIEWED_SHA256,
                              version="1.15.5")
    state_bytes = case.core_state.read_bytes()
    inventory = parse_applied_oci_core_state(
        state_bytes, proxy_count=evidence["proxyCount"], elk_enabled=evidence["elkEnabled"],
        compartment_id=evidence["target"]["compartmentId"], engagement_name=core.input["engagementName"])
    prior = [{"address": row.address, "mode": "managed",
              "type": row.address.split(".", 1)[0],
              "provider_name": "registry.terraform.io/oracle/oci", "values": {"id": row.ocid}}
             for row in inventory.resources]
    prior += [{"address": address, "mode": "data", "type": address.split(".", 2)[1],
               "provider_name": "registry.terraform.io/oracle/oci", "values": {"id": identifier}}
              for address, identifier in _state_data_ids(state_bytes).items()]
    changes = [{"address": row.address, "mode": "managed", "type": row.address.split(".", 1)[0],
                "provider_name": "registry.terraform.io/oracle/oci",
                "change": {"actions": ["delete"], "before": {"id": row.ocid},
                           "after": None, "after_unknown": {}}} for row in inventory.resources]
    calls = []

    def runner(args, cwd, env):
        calls.append(args[1])
        assert cwd == run_dir and env["TF_DATA_DIR"] == str(data_dir)
        if args[1] == "plan":
            Path(args[5].removeprefix("-out=")).write_bytes(b"saved offline OCI destroy plan")
            return SimpleNamespace(returncode=2, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout=json.dumps({
            "applyable": True, "complete": True, "resource_changes": changes,
            "prior_state": {"values": {"root_module": {"resources": prior}}}}), stderr="")

    options = dict(environment="devtest", state_root=case.state_root,
                   core_state_root=case.core_state.parents[2], job_repository=case.jobs,
                   plan_repository=case.args["plan_repository"],
                   lease_lookup=fenced_args["lease_lookup"],
                   source_dependencies={key: value for key, value in case.args.items() if key in {
                       "engagement_repository", "sketch_repository", "credential_repository",
                       "ssh_key_repository", "provider_resource_repository"}},
                   binding_check=lambda _: None, release_check=lambda **_: release,
                   command_runner=runner)
    return source, fenced_args, changes, calls, options


def test_both_reviewed_provider_orders_save_one_exact_core_preview(case, monkeypatch):
    source, fenced_args, _, calls, options = _ready(case, monkeypatch)
    assert source_service.audit_mixed_zero_apply_teardown_source(**fenced_args) == source
    result = service.preview_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **options)
    assert result.status == "succeeded" and calls == ["plan", "show"]
    assert result.events[-1].data["sourceSha256"] == _fingerprint(source.__dict__)
    assert result.events[-1].data["stateSha256"] == source.core_state_sha256
    assert source_service.audit_mixed_zero_apply_teardown_source(**fenced_args) == source
    with pytest.raises(service.MixedZeroApplyCorePreviewAttention):
        service.preview_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **options)
    assert calls == ["plan", "show"]


def test_queued_preview_restart_uses_same_child_without_prior_command(case, monkeypatch):
    source, _, _, calls, options = _ready(case, monkeypatch)
    original = case.jobs.save_if_absent

    def crash_after_reservation(child):
        original(child)
        raise RuntimeError("process stopped after queued save")

    monkeypatch.setattr(case.jobs, "save_if_absent", crash_after_reservation)
    with pytest.raises(service.MixedZeroApplyCorePreviewAttention):
        service.preview_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **options)
    assert calls == []
    queued = case.jobs.get(service._child_id(source.core_job_id))
    assert queued.status == "queued" and len(queued.events) == 1
    monkeypatch.setattr(case.jobs, "save_if_absent", original)
    resumed = service.preview_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **options)
    assert resumed.id == queued.id and resumed.created_at == queued.created_at
    assert resumed.status == "succeeded" and calls == ["plan", "show"]


def test_running_preview_without_intent_marker_remains_attention(case, monkeypatch):
    source, _, _, calls, options = _ready(case, monkeypatch)
    original = case.jobs.start_if_queued

    def crash_after_start(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("process stopped after start")

    monkeypatch.setattr(case.jobs, "start_if_queued", crash_after_start)
    with pytest.raises(service.MixedZeroApplyCorePreviewAttention):
        service.preview_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **options)
    assert calls == []
    monkeypatch.setattr(case.jobs, "start_if_queued", original)
    with pytest.raises(service.MixedZeroApplyCorePreviewAttention):
        service.preview_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **options)
    assert calls == []


def test_running_child_is_audited_but_alien_or_drifted_child_is_rejected(case, monkeypatch):
    source, fenced_args, _, _, options = _ready(case, monkeypatch)
    options["command_runner"] = lambda *a: (_ for _ in ()).throw(RuntimeError("interrupted"))
    with pytest.raises(service.MixedZeroApplyCorePreviewAttention):
        service.preview_mixed_zero_apply_oci_core_destroy(source.engagement_id, source.core_job_id, **options)
    child = case.jobs.get(service._child_id(source.core_job_id))
    assert child.status == "running"
    assert source_service.audit_mixed_zero_apply_teardown_source(**fenced_args) == source
    case.jobs.save(replace(child, events=[*child.events, JobEvent(3, "info", "alien", {})]))
    with pytest.raises(source_service.MixedZeroApplySourceError):
        source_service.audit_mixed_zero_apply_teardown_source(**fenced_args)


def test_non_exact_plan_stays_running_and_cannot_replay(case, monkeypatch):
    source, _, changes, calls, options = _ready(case, monkeypatch)
    changes[0]["change"]["actions"] = ["delete", "create"]
    with pytest.raises(service.MixedZeroApplyCorePreviewAttention):
        service.preview_mixed_zero_apply_oci_core_destroy(source.engagement_id, source.core_job_id, **options)
    assert calls == ["plan", "show"]
    assert case.jobs.get(service._child_id(source.core_job_id)).status == "running"
    with pytest.raises(service.MixedZeroApplyCorePreviewAttention):
        service.preview_mixed_zero_apply_oci_core_destroy(source.engagement_id, source.core_job_id, **options)
    assert calls == ["plan", "show"]


def test_lease_or_source_drift_stops_before_plan(case, monkeypatch):
    source, _, _, calls, options = _ready(case, monkeypatch)
    options["lease_lookup"] = lambda _: (source.core_plan_id, "provider_keyed_initial")
    with pytest.raises(service.MixedZeroApplyCorePreviewAttention):
        service.preview_mixed_zero_apply_oci_core_destroy(source.engagement_id, source.core_job_id, **options)
    assert calls == []
    options["lease_lookup"] = lambda _: (source.core_plan_id, service._FENCE)
    case.core_state.write_bytes(case.core_state.read_bytes() + b" ")
    with pytest.raises(service.MixedZeroApplyCorePreviewAttention):
        service.preview_mixed_zero_apply_oci_core_destroy(source.engagement_id, source.core_job_id, **options)
    assert calls == []


def test_plan_time_lease_drift_stops_before_show(case, monkeypatch):
    source, _, _, calls, options = _ready(case, monkeypatch)
    original = options["command_runner"]
    active = {"operation": service._FENCE}
    options["lease_lookup"] = lambda _: (source.core_plan_id, active["operation"])

    def drift_after_plan(args, cwd, env):
        result = original(args, cwd, env)
        if args[1] == "plan":
            active["operation"] = "provider_keyed_initial"
        return result

    options["command_runner"] = drift_after_plan
    with pytest.raises(service.MixedZeroApplyCorePreviewAttention):
        service.preview_mixed_zero_apply_oci_core_destroy(source.engagement_id, source.core_job_id, **options)
    assert calls == ["plan"]
    assert case.jobs.get(service._child_id(source.core_job_id)).status == "running"


def test_orphan_plan_file_cannot_start_a_new_child(case, monkeypatch):
    source, _, _, calls, options = _ready(case, monkeypatch)
    orphan = (case.core_state.parent /
              f".barragan-mixed-core-destroy-{source.core_job_id.removeprefix('job-')}.tfplan")
    orphan.write_bytes(b"unattributed prior attempt")
    with pytest.raises(service.MixedZeroApplyCorePreviewAttention):
        service.preview_mixed_zero_apply_oci_core_destroy(source.engagement_id, source.core_job_id, **options)
    assert case.jobs.get(service._child_id(source.core_job_id)) is None
    assert calls == []


@pytest.mark.parametrize("kind", ["assignment", "dns", "asset", "binding", "service"])
def test_independent_binding_tables_veto_current_rows(tmp_path, kind):
    state = db.configure(f"sqlite:///{tmp_path / 'bindings.sqlite'}")
    with db.bind(state):
        db.create_all()
        db.session.add(EngagementModel(id="eng-opaque", name="opaque-fixture", status="active",
                                       owner="operator", template_id="small"))
        db.session.add(DomainAssetModel(id="domain-1", domain_name="example.invalid"))
        db.session.add(DomainAssignmentModel(id=1, domain_id="domain-1",
                                             engagement_id="eng-opaque",
                                             status="active" if kind == "assignment" else "released"))
        db.session.add(DomainDnsSnapshotModel(id=1, domain_id="domain-1"))
        db.session.add(JobRunModel(id="job-dns", action="dns", status="succeeded",
                                   target="engagement:eng-opaque", target_type="engagement",
                                   target_id="eng-opaque", requested_by="operator", input={},
                                   artifact_refs=[]))
        db.session.flush()
        if kind == "dns":
            db.session.add(DomainDnsRecordOwnershipModel(
                domain_id="domain-1", assignment_id=1, engagement_id="eng-opaque",
                creating_job_id="job-dns", snapshot_id=1, record={"type": "A"},
                retired_at=None))
        if kind == "asset":
            db.session.add(CertificateAssetModel(
                id="cert-1", engagement_id="eng-opaque", name="cert", source="acme",
                target_proxy_id="proxy01", primary_identifier="example.invalid"))
        if kind == "binding":
            db.session.add(CertificateBindingModel(
                id="binding-1", engagement_id="eng-opaque", certificate_id="cert-1",
                service_id="site", hostname="example.invalid", status="unbound"))
        if kind == "service":
            db.session.add(EngagementServiceModel(
                engagement_id="eng-opaque", service_id="site", service_type="http",
                name="site", proxy_id="proxy01", status="stopped"))
        db.session.flush()
        with pytest.raises(ValueError, match="independent engagement binding"):
            service._require_no_independent_bindings("eng-opaque")


def test_released_domain_assignment_is_not_a_live_binding(tmp_path):
    state = db.configure(f"sqlite:///{tmp_path / 'released.sqlite'}")
    with db.bind(state):
        db.create_all()
        db.session.add(EngagementModel(id="eng-opaque", name="opaque-fixture", status="active",
                                       owner="operator", template_id="small"))
        db.session.add(DomainAssetModel(id="domain-1", domain_name="example.invalid"))
        db.session.add(DomainAssignmentModel(id=1, domain_id="domain-1",
                                             engagement_id="eng-opaque", status="released"))
        db.session.flush()
        service._require_no_independent_bindings("eng-opaque")


def test_sqlalchemy_child_reservation_round_trip_does_not_replay(case, monkeypatch, tmp_path):
    source, _, _, calls, options = _ready(case, monkeypatch)
    state = db.configure(f"sqlite:///{tmp_path / 'core-preview.sqlite'}")
    with db.bind(state):
        db.create_all()
        db.session.add(EngagementModel(id="eng-opaque", name="opaque-fixture", status="active",
                                       owner="operator", template_id="small"))
        db.session.commit()
        jobs = SqlAlchemyJobRepository()
        for row in case.jobs.list_for_engagement("eng-opaque"):
            jobs.save(replace(row, created_at="2026-10-15T00:00:00+00:00",
                              started_at=("2026-10-15T00:00:01+00:00"
                                          if row.started_at is not None else None),
                              finished_at=("2026-10-15T00:00:02+00:00"
                                           if row.finished_at is not None else None)))
        options["job_repository"] = jobs
        options.pop("binding_check")
        result = service.preview_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **options)
        assert result.status == "succeeded" and calls == ["plan", "show"]
        assert jobs.get(result.id).events == result.events
        with pytest.raises(service.MixedZeroApplyCorePreviewAttention):
            service.preview_mixed_zero_apply_oci_core_destroy(
                source.engagement_id, source.core_job_id, **options)
        assert calls == ["plan", "show"]
