# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline one-shot mixed OCI GO orchestration with persisted child journals."""

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from app.services import provider_keyed_mixed_zero_apply_core_apply as service
from app.services import provider_keyed_mixed_zero_apply_core_preview as preview_service
from app.services import provider_keyed_mixed_zero_apply_teardown_source as source_service
from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_oci_exact_absence import OciExactWitness
from app.services.observer_checks import (
    INSPECTOR_ADMIN_IDENTITY_VERSION, INSPECTOR_ADMIN_USER,
    INSPECTOR_DEFAULT_SUPPORT_PACKAGES, INSPECTOR_SUPPORT_PREPARATION_VERSION,
    ObserverHost, _record_inspector_resource,
)
from app.services.provider_keyed_inspector_provider_proof import (
    InspectorProviderPending, InspectorProviderProof,
)
from app.storage.credential_repository import StoredCredential
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.models import EngagementModel
from app.storage.observer_settings_repository import (
    SqlAlchemyObserverSettingsRepository, StoredInspectorSettings,
)
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from test_provider_keyed_mixed_zero_apply_core_preview import case, _ready


def _go_case(case, monkeypatch):
    source, _, _, _, preview_options = _ready(case, monkeypatch)
    preview = preview_service.preview_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **preview_options)
    assert preview.status == "succeeded"
    monkeypatch.setattr(service, "_default_state_root", lambda: case.state_root)
    monkeypatch.setattr(service, "DEFAULT_TERRAFORM_STATE_ROOT", case.core_state.parents[2])
    actions = []
    holds = {"heartbeat": 0}
    run_dir = Path(case.plan.evidence["runDirectory"])
    data_dir = Path(case.plan.evidence["terraformDataDir"])
    show = preview_options["command_runner"](
        ["terraform", "show"], run_dir, {"TF_DATA_DIR": str(data_dir)}).stdout

    def gated(args, *, scratch_path, provider_keyed_v2, max_output_bytes, gate_timeout_seconds, env,
              intent_callback, started_callback, heartbeat_callback, result_callback):
        phase = args[1]
        actions.append(phase)
        assert provider_keyed_v2 and scratch_path == run_dir
        assert gate_timeout_seconds == (1200 if phase == "apply" else 30)
        intent = CommandIntent(f"{phase}-{len(actions)}", str(scratch_path), hashlib.sha256(
            json.dumps(args, separators=(",", ":")).encode()).hexdigest())
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity("offline-boot", 123, 123, 10))
        started_callback(started)
        for _ in range(3 if phase == "apply" else 1):
            heartbeat_callback(started)
            holds["heartbeat"] += 1
        output = show if phase == "show" else ""
        result_callback(CommandAuditResult(started, 0, len(output), 0, False, False))
        return CommandResult(started, 0, output, "", False, False)

    def witness(inventory, *, compartment_id, region, engagement_name,
                oci_executable, runner, fence):
        fence()
        return OciExactWitness(
            "present", inventory.inventory_sha256,
            _fingerprint({row.address: row.ocid for row in inventory.resources}),
            compartment_id, region, "instance_principal", "a" * 64, "b" * 64)

    options = dict(
        environment="devtest", state_root=case.state_root,
        core_state_root=case.core_state.parents[2], job_repository=case.jobs,
        plan_repository=case.args["plan_repository"],
        lease_lookup=preview_options["lease_lookup"],
        source_dependencies=preview_options["source_dependencies"],
        binding_check=lambda _: None,
        inspector_prover=lambda source, engagement, fence: (fence(), "c" * 64)[1],
        inventory_reader=lambda engagement, core, audit_options, fence: (
            fence(), SimpleNamespace(observation_sha256="d" * 64))[1],
        release_check=preview_options["release_check"],
        source_check=lambda path, manifest: path == run_dir or pytest.fail("core source changed"),
        gated_command_runner=gated, visibility_prover=witness,
        oci_executable=Path(sys.executable).resolve(strict=True),
    )
    return source, actions, holds, options


def test_both_provider_orders_have_one_go_and_slow_heartbeat(case, monkeypatch):
    source, actions, holds, options = _go_case(case, monkeypatch)
    result = service.apply_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **options)
    assert result.status == "succeeded" and actions == ["show", "apply"]
    assert holds["heartbeat"] == 4
    assert result.events[-1].data["providerAbsenceProofPending"] is True
    assert any(event.message == "core destroy prestate identity fenced" for event in result.events)
    with pytest.raises(service.MixedZeroApplyCoreApplyAttention):
        service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **options)
    assert actions == ["show", "apply"]


def test_inspector_heartbeat_renews_claim_without_repeating_provider_audit(case, monkeypatch):
    source, actions, _, options = _go_case(case, monkeypatch)
    original_audit = service.audit_zero_apply_post_sketch_absence
    audits = {"count": 0}

    def counted_audit(*args, **kwargs):
        audits["count"] += 1
        return original_audit(*args, **kwargs)

    def slow_inspector(_source, _engagement, fence):
        before = audits["count"]
        for _ in range(4):
            fence()
        assert audits["count"] == before
        return "c" * 64

    monkeypatch.setattr(service, "audit_zero_apply_post_sketch_absence", counted_audit)
    options["inspector_prover"] = slow_inspector
    result = service.apply_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **options)
    assert result.status == "succeeded" and actions == ["show", "apply"]


def test_queued_apply_restart_preserves_child_and_runs_once(case, monkeypatch):
    source, actions, _, options = _go_case(case, monkeypatch)
    original = case.jobs.save_if_absent

    def stop_after_queue(child):
        original(child)
        raise RuntimeError("stopped after queued Apply child")

    monkeypatch.setattr(case.jobs, "save_if_absent", stop_after_queue)
    with pytest.raises(service.MixedZeroApplyCoreApplyAttention):
        service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **options)
    assert actions == []
    queued = case.jobs.get(service._child_id(source.core_job_id))
    parent = case.jobs.get(service._parent_id(source.core_job_id))
    preview = case.jobs.get(service._preview_child_id(source.core_job_id))
    assert service.precommand_apply_restartable(queued, parent, preview, source.core_job_id)
    monkeypatch.setattr(case.jobs, "save_if_absent", original)
    done = service.apply_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **options)
    assert done.id == queued.id and done.created_at == queued.created_at
    assert done.status == "succeeded" and actions == ["show", "apply"]


def test_expired_precommand_apply_claim_restarts_but_live_claim_does_not(
        case, monkeypatch):
    source, actions, _, options = _go_case(case, monkeypatch)
    original = case.jobs.claim_lease

    def stop_after_claim(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("stopped after claim before command intent")

    monkeypatch.setattr(case.jobs, "claim_lease", stop_after_claim)
    with pytest.raises(service.MixedZeroApplyCoreApplyAttention):
        service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **options)
    assert actions == []
    child = case.jobs.get(service._child_id(source.core_job_id))
    parent = case.jobs.get(service._parent_id(source.core_job_id))
    preview = case.jobs.get(service._preview_child_id(source.core_job_id))
    assert child.status == "running" and len(child.events) == 2
    assert not service.precommand_apply_restartable(child, parent, preview, source.core_job_id)
    monkeypatch.setattr(case.jobs, "claim_lease", original)
    with pytest.raises(service.MixedZeroApplyCoreApplyAttention):
        service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **options)
    assert actions == []
    case.jobs.save(replace(child, input={**child.input,
                                        "claimExpiresAt": "2020-01-01T00:00:00+00:00"}))
    assert service.precommand_apply_restartable(
        case.jobs.get(child.id), parent, preview, source.core_job_id)
    published_parent = replace(parent,
        action="provider_keyed_mixed_published_cleanup",
        input={**parent.input,
               "publishedSource": parent.input["source"],
               "publishedSourceSha256": child.input["sourceSha256"]})
    assert service.precommand_apply_restartable(
        case.jobs.get(child.id), published_parent, preview,
        source.core_job_id)
    done = service.apply_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **options)
    assert done.id == child.id and done.status == "succeeded"
    assert actions == ["show", "apply"]


def test_precommand_apply_rejects_intent_even_after_claim_expiry(case, monkeypatch):
    source, actions, _, options = _go_case(case, monkeypatch)

    def stop_after_intent(args, *, intent_callback, **_kwargs):
        actions.append(args[1])
        intent_callback(CommandIntent("saved-intent", str(Path(case.plan.evidence["runDirectory"])),
                                      hashlib.sha256(json.dumps(args, separators=(",", ":")).encode()).hexdigest()))
        raise RuntimeError("stopped after durable command intent")

    options["gated_command_runner"] = stop_after_intent
    with pytest.raises(service.MixedZeroApplyCoreApplyAttention):
        service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **options)
    child = case.jobs.get(service._child_id(source.core_job_id))
    assert child.events[-1].message == "core destroy command intent fenced"
    case.jobs.save(replace(child, input={**child.input,
                                        "claimExpiresAt": "2020-01-01T00:00:00+00:00"}))
    with pytest.raises(service.MixedZeroApplyCoreApplyAttention):
        service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **options)
    assert actions == ["show"]


def test_held_go_veto_preserves_one_running_child(case, monkeypatch):
    source, actions, holds, options = _go_case(case, monkeypatch)
    probes = {"count": 0}

    def changed_inspector(_source, _engagement, fence):
        fence()
        probes["count"] += 1
        return ("c" if probes["count"] == 1 else "e") * 64

    options["inspector_prover"] = changed_inspector
    with pytest.raises(service.MixedZeroApplyCoreApplyAttention):
        service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **options)
    child = case.jobs.get(service._child_id(source.core_job_id))
    assert child.status == "running" and actions == ["show", "apply"]
    assert child.events[-1].message == "core destroy command started before GO"
    with pytest.raises(service.MixedZeroApplyCoreApplyAttention):
        service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **options)
    assert actions == ["show", "apply"]


def test_source_or_support_drift_vetoes_before_terraform(case, monkeypatch):
    source, actions, _, options = _go_case(case, monkeypatch)
    options["lease_lookup"] = lambda _: (source.core_plan_id, "provider_keyed_initial")
    with pytest.raises(service.MixedZeroApplyCoreApplyAttention):
        service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **options)
    assert actions == []
    options["lease_lookup"] = lambda _: (source.core_plan_id, service._FENCE)
    options["inspector_prover"] = lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("not ready"))
    with pytest.raises(service.MixedZeroApplyCoreApplyAttention):
        service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **options)
    assert actions == []


def test_fenced_source_accepts_only_exact_pre_go_apply_child(case, monkeypatch):
    source, _, _, options = _go_case(case, monkeypatch)
    options["inspector_prover"] = lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("not ready"))
    with pytest.raises(service.MixedZeroApplyCoreApplyAttention):
        service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **options)
    audit_options = dict(case.args, core_state_root=case.core_state.parents[2],
                         lease_operation=service._FENCE,
                         lease_lookup=options["lease_lookup"])
    assert source_service.audit_mixed_zero_apply_teardown_source(**audit_options) == source
    child = case.jobs.get(service._child_id(source.core_job_id))
    case.jobs.save(replace(child, events=[*child.events, JobEvent(3, "info", "alien", {})]))
    with pytest.raises(source_service.MixedZeroApplySourceError):
        source_service.audit_mixed_zero_apply_teardown_source(**audit_options)


def test_fenced_source_rejects_drifted_pre_go_event_payloads(case, monkeypatch):
    source, _, _, options = _go_case(case, monkeypatch)
    completed = service.apply_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **options)
    prefix = replace(completed, status="running", finished_at=None,
                     events=completed.events[:9],
                     input={**completed.input, "claimOwner": "offline-owner",
                            "claimToken": "offline-token",
                            "claimExpiresAt": "2026-10-15T01:00:00+00:00"})
    case.jobs.save(prefix)
    audit_options = dict(case.args, core_state_root=case.core_state.parents[2],
                         lease_operation=service._FENCE,
                         lease_lookup=options["lease_lookup"])
    assert source_service.audit_mixed_zero_apply_teardown_source(**audit_options) == source
    changes = ((3, "argvSha256", "0" * 64), (4, "pid", 99),
               (5, "stdoutTruncated", True), (6, "resourceIds", {}),
               (6, "ociVisibilityWitness", {}), (6, "ociCliSha256", "0" * 64),
               (7, "argvSha256", "0" * 64),
               (9, "inspectorReadySha256", "0" * 64),
               (9, "ociVisibilityWitnessSha256", "0" * 64))
    for number, key, value in changes:
        events = list(prefix.events)
        data = dict(events[number - 1].data)
        data[key] = value
        events[number - 1] = replace(events[number - 1], data=data)
        case.jobs.save(replace(prefix, events=events))
        with pytest.raises(source_service.MixedZeroApplySourceError):
            source_service.audit_mixed_zero_apply_teardown_source(**audit_options)
    case.jobs.save(prefix)


def test_sqlalchemy_persisted_go_restart_never_replays(case, monkeypatch, tmp_path):
    source, actions, _, options = _go_case(case, monkeypatch)
    state = db.configure(f"sqlite:///{tmp_path / 'mixed-go.sqlite'}")
    with db.bind(state):
        db.create_all()
        db.session.add(EngagementModel(id=source.engagement_id, name="opaque-fixture",
                                       status="active", owner="operator", template_id="small"))
        db.session.commit()
        jobs = SqlAlchemyJobRepository()
        for row in case.jobs.list_for_engagement(source.engagement_id):
            jobs.save(replace(row, created_at="2026-10-15T00:00:00+00:00",
                              started_at=("2026-10-15T00:00:01+00:00"
                                          if row.started_at is not None else None),
                              finished_at=("2026-10-15T00:00:02+00:00"
                                           if row.finished_at is not None else None)))
        options["job_repository"] = jobs
        result = service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **options)
        assert result.status == "succeeded" and actions == ["show", "apply"]
    reopened = db.configure(state.uri)
    with db.bind(reopened):
        jobs = SqlAlchemyJobRepository()
        options["job_repository"] = jobs
        assert jobs.get(service._child_id(source.core_job_id)).status == "succeeded"
        with pytest.raises(service.MixedZeroApplyCoreApplyAttention):
            service.apply_mixed_zero_apply_oci_core_destroy(
                source.engagement_id, source.core_job_id, **options)
        assert actions == ["show", "apply"]


@pytest.mark.parametrize("saved_status,proved_status,pending_rounds", [
    ("running", "running", 0), ("offline", "running", 0),
    ("offline", "offline", 0), ("offline", "running", 2),
    ("offline", "running", 6),
])
def test_persisted_retained_inspector_uses_runtime_and_enriched_record_shapes(
        monkeypatch, tmp_path, saved_status, proved_status, pending_rounds):
    state = db.configure(f"sqlite:///{tmp_path / 'retained-inspector.sqlite'}")
    with db.bind(state):
        db.create_all()
        engagement_id = "eng-opaque"
        db.session.add(EngagementModel(id=engagement_id, name="opaque-fixture",
                                       status="active", owner="operator", template_id="small"))
        db.session.commit()
        host = ObserverHost(
            "linode", "instance", "100", "inspector-opaque", "us-east", "8.8.8.8",
            INSPECTOR_ADMIN_USER, saved_status, {
                "adminIdentityVersion": INSPECTOR_ADMIN_IDENTITY_VERSION,
                "rootLoginDisabled": True,
                "supportPreparationVersion": INSPECTOR_SUPPORT_PREPARATION_VERSION,
                "supportPreparedPackages": list(INSPECTOR_DEFAULT_SUPPORT_PACKAGES),
                "providerFirewall": {"provider": "linode", "resourceType": "firewall",
                                     "resourceId": "200", "name": "inspector-firewall-opaque",
                                     "managementSourceCidr": "8.8.8.8/32"},
            })
        settings = StoredInspectorSettings(
            engagement_id, True, "linode", "us-east", "g6-nanode-1", "continuous",
            ["mon"], "00:00", ["inbound"], [], [], host.to_dict(), "", "", "",
            "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:00+00:00")
        SqlAlchemyObserverSettingsRepository().save(settings)
        resources = SqlAlchemyProviderResourceRepository()
        _record_inspector_resource(resources, engagement_id, "opaque-fixture", host,
                                   "job-inspector-ready", status="active")
        ids = tuple(sorted(row.id for row in resources.list_for_engagement(engagement_id)))
        source = SimpleNamespace(owned_inspector_record_ids=ids)
        key = tmp_path / "inspector-key"
        key.write_text("private-fixture", encoding="utf-8")
        Path(str(key) + ".pub").write_text("ssh-ed25519 opaque-fixture", encoding="utf-8")
        credential = StoredCredential(
            "credential-1", "linode", "default", "active", "", "opaque-encrypted",
            True, "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:00+00:00")
        monkeypatch.setattr(service, "_safe_key_identity", lambda _: (str(key), "a" * 64))
        monkeypatch.setattr(service, "_verify_key_pair", lambda *_: None)
        monkeypatch.setattr(service, "SqlAlchemyCredentialRepository",
                            lambda: SimpleNamespace(get_default=lambda _: credential))
        monkeypatch.setattr(service, "decrypt_secret_value", lambda _: "opaque-token")
        reads, waits = [], []
        def provider_proof(**_):
            reads.append(1)
            if len(reads) <= pending_rounds:
                raise InspectorProviderPending("provider read settling")
            return InspectorProviderProof(
                replace(host, status=proved_status), "200", "8.8.8.8/32")
        monkeypatch.setattr(service, "prove_retained_keyed_inspector_provider", provider_proof)
        monkeypatch.setattr(service.time, "sleep", waits.append)
        verified = []
        monkeypatch.setattr(service, "SshObserverRunner",
                            lambda **_: SimpleNamespace(verify_access=lambda **kw: verified.append(kw)))
        if pending_rounds == 6:
            with pytest.raises(InspectorProviderPending):
                service._prove_retained_inspector(source, engagement_id, fence=lambda: None)
            assert len(reads) == 6 and waits == [5] * 5 and verified == []
        elif proved_status == "offline":
            with pytest.raises(ValueError, match="provider is not running"):
                service._prove_retained_inspector(source, engagement_id, fence=lambda: None)
            assert verified == []
        else:
            result = service._prove_retained_inspector(source, engagement_id, fence=lambda: None)
            assert len(result) == 64 and len(verified) == 1
            assert verified[0]["host"] == host
            assert len(reads) == pending_rounds + 1 and waits == [5] * pending_rounds
        assert resources.list_for_engagement(engagement_id)[0].status == "active"
