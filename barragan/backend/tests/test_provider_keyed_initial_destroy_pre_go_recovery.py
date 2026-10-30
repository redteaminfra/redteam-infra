# Copyright (c) 2026, Oracle and/or its affiliates.
"""The one-off read-only incident binder does not claim or run Terraform."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_gated_runner import (
    CommandIntent, ProcessIdentity, StartedCommand,
)
from app.services import provider_keyed_initial_destroy_pre_go_recovery as service
from app.storage.job_repository import SqliteJobRepository, job_event_digest
from test_provider_keyed_initial_destroy_takeover import _child


class Jobs:
    def __init__(self, *rows):
        self.rows = {row.id: row for row in rows}

    def get(self, identifier):
        return self.rows.get(identifier)


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _fixture(tmp_path, monkeypatch):
    root = tmp_path / "state"
    root.mkdir()
    marker = root / ".barragan-provider-keyed-state.json"
    lock = root / ".terraform.lock.hcl"
    state_path = root / "terraform.tfstate"
    phase = root / ".barragan-apply-phase.json"
    plan_path = root / ".barragan-initial-destroy.tfplan"
    binary = root / "terraform"
    for path, value in ((marker, "marker"), (lock, "lock"), (state_path, "state"),
                        (plan_path, "plan"), (binary, "binary")):
        path.write_text(value)
        path.chmod(0o600)
    phase.write_text(json.dumps({"schema": "provider-keyed-v2", "phase": "destroy_started"}))
    child = _child()
    now = datetime.now(timezone.utc)
    ids = child.events[5].data["resourceIds"]
    scope = {
        "provider": "digitalocean", "corePlanId": "plan-core", "workspace": str(root),
        "stateSha256": _sha(state_path), "selectorTag": "barragantest",
        "resources": [{"address": address, "id": identifier} for address, identifier in ids.items()],
    }
    snapshot = {"snapshotId": "a" * 64, "providerScopeSha256": "b" * 64,
                "providerScopes": [scope]}
    parent = SimpleNamespace(id=service._INCIDENT_PARENT, target_id=service._INCIDENT_ENGAGEMENT,
                             requested_by="operator")
    core = SimpleNamespace(id=service._INCIDENT_CORE)
    coordinator = SimpleNamespace(
        id=service._child_id(core.id), status="running", input={"phase": "inspector_ready"},
        events=[JobEvent(1, "info", "ready", {})],
    )
    pre = {**child.events[5].data, "coreJobId": core.id,
           "preDestroyStateSha256": scope["stateSha256"]}
    events = list(child.events)
    events[5] = replace(events[5], data=pre)
    events[6] = replace(events[6], data={
        "phase": "destroy_started", "path": str(phase),
    })
    child = replace(child, id=service._INCIDENT_CHILD,
                    target=f"engagement:{parent.target_id}", target_id=parent.target_id,
                    input={**child.input, "engagementId": parent.target_id,
                           "coreJobId": core.id, "teardownParentId": parent.id,
                           "destroyPlanJobId": f"job-provider-keyed-initial-destroy-plan-{core.id.removeprefix('job-')}"},
                    events=events)
    saved = {key: "x" for key in service._PREVIEW_DATA_KEYS}
    saved.update({
        "planPath": str(plan_path), "planSha256": _sha(plan_path),
        "stateSha256": scope["stateSha256"], "sourceRevision": "source-rev",
        "sourceSha256": "source-sha", "markerSha256": _sha(marker),
        "lockfileSha256": _sha(lock), "topologySha256": "topology-sha",
        "inputSha256": [], "terraformBinaryPath": str(binary),
        "terraformBinarySha256": _sha(binary),
    })
    for offset, argv in (
        (2, [str(binary), "show", "-json", str(plan_path)]),
        (7, [str(binary), "apply", "-input=false", "-lock=true", "-no-color", str(plan_path)]),
    ):
        events[offset] = replace(events[offset], data={
            **events[offset].data,
            "argvSha256": hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest(),
        })
    child = replace(child, events=events)
    child = replace(child, input={**child.input, "planSha256": saved["planSha256"]})
    preview = SimpleNamespace(
        id=child.input["destroyPlanJobId"], action="provider_keyed_initial_destroy_plan",
        status="succeeded", artifact_refs=[str(plan_path)],
        events=[JobEvent(1, "info", "reviewed full-state provider destroy plan saved", saved)],
    )
    jobs = Jobs(parent, coordinator, child, preview)
    jobs.rows[core.id] = core
    workspace = SimpleNamespace(path=root, state_path=state_path,
                                source_revision="source-rev", source_sha256="source-sha",
                                provider_connection_id="credential-do")
    intent = SimpleNamespace(nodes={}, firewall=SimpleNamespace(), selector_tag="barragantest")
    evidence = {"inputSha256": []}
    attachment = SimpleNamespace(
        state_sha256=scope["stateSha256"], credential_record_id="credential-do",
        credential_secret_sha256=pre["credentialSecretSha256"],
        credential_updated_at=pre["credentialUpdatedAt"],
    )
    attestation = service.HistoricalRuntimeAttestation(
        reviewed_by="operator", revision=service._HISTORICAL_REVISION,
        api_pid=317379, api_started_at=(now - timedelta(hours=1)).isoformat(),
        evidence_window_end=(now + timedelta(minutes=1)).isoformat(),
        parent_id=parent.id, child_id=child.id,
        child_journal_sha256=job_event_digest(child.events),
        gated_boot_id=child.events[8].data["bootId"],
        gated_pid=child.events[8].data["pid"],
        gated_pgid=child.events[8].data["pgid"],
        gated_start_ticks=child.events[8].data["startTicks"],
        evidence="systemd-journal+clean-git-worktree",
    )
    monkeypatch.setattr(service, "_default_state_root", lambda: root)
    monkeypatch.setattr(service, "_boundary", lambda *_a: (parent, core, snapshot, service._FENCE))
    monkeypatch.setattr(service, "read_applied_digitalocean_provider_for_teardown",
                        lambda *_a, **_kw: (intent, workspace, evidence, object()))
    monkeypatch.setattr(service, "derive_digitalocean_initial_attachment_intent",
                        lambda *_a, **_kw: attachment)
    monkeypatch.setattr(service, "_require_exact_state", lambda *_a: {
        "lineage": pre["stateLineage"], "serial": pre["preDestroySerial"],
    })
    monkeypatch.setattr(service, "_topology_hash", lambda *_a: "topology-sha")
    monkeypatch.setattr(service, "_audit_successful_preview_journal", lambda *_a: None)
    calls = []
    options = dict(
        environment="devtest", state_root=root, job_repository=jobs,
        plan_repository=object(), credential_repository=object(),
        lease_lookup=lambda _id: ("plan-core", service._FENCE),
        process_quiescence=lambda *_a: True,
        bootstrap_auditor=lambda *_a, **_kw: None,
        dns_checkpoint_prover=lambda *_a, **_kw: {
            key: pre[key] for key in (
                "dnsCleanupManifestSha256", "dnsCleanupHandoffJournalSha256",
                "dnsCleanupCheckpointSha256",
            )},
        attachment_prover=lambda *_a, **_kw: calls.append("attachment"),
        ssh_key_prover=lambda *_a: calls.append("key") or True,
        inspector_prover=lambda *_a, **_kw: calls.append("inspector"),
    )
    return attestation, options, calls, jobs, child, state_path, plan_path, phase


def test_read_only_binder_composes_exact_incident_proofs(tmp_path, monkeypatch):
    attestation, options, calls, jobs, child, *_ = _fixture(tmp_path, monkeypatch)
    result = service.bind_reviewed_digitalocean_destroy_pre_go(attestation, **options)
    assert result.child_id == service._INCIDENT_CHILD
    assert result.child_journal_sha256 == job_event_digest(child.events)
    assert calls == ["attachment", "key", "inspector"]
    assert jobs.get(child.id) == child


def test_claimed_rebinder_keeps_original_attestation_and_rechecks_live_child(tmp_path, monkeypatch):
    attestation, options, calls, jobs, original, *_ = _fixture(tmp_path, monkeypatch)
    claimed = replace(original, input={**original.input,
        "claimOwner": "provider-keyed-destroy-recovery-reviewed",
        "claimToken": "r" * 32})
    jobs.rows[original.id] = claimed
    observed_modes = []
    workspace = SimpleNamespace(
        path=options["state_root"],
        state_path=options["state_root"] / "terraform.tfstate",
        source_revision="source-rev", source_sha256="source-sha",
        provider_connection_id="credential-do",
    )
    monkeypatch.setattr(service, "read_applied_digitalocean_provider_for_teardown",
                        lambda *_a, **kw: (observed_modes.append(kw["mode"]),
                            (SimpleNamespace(nodes={}, firewall=object(), selector_tag="barragantest"),
                             workspace, {"inputSha256": []}, object()))[1])
    result = service.bind_reviewed_digitalocean_destroy_pre_go(
        attestation, **options, original_child=original, claimed_child=claimed,
        claim_fence=lambda expected: expected,
    )
    assert result.child_journal_sha256 == job_event_digest(original.events)
    assert observed_modes == ["destroy_started_recovery_read"]
    assert calls == ["attachment", "key", "inspector"]
    jobs.rows[original.id] = replace(claimed, input={**claimed.input, "planSha256": "0" * 64})
    with pytest.raises(service.PreGoRecoveryBoundaryError):
        service.bind_reviewed_digitalocean_destroy_pre_go(
            attestation, **options, original_child=original, claimed_child=claimed,
            claim_fence=lambda expected: expected,
        )


def test_claimed_rebinder_accepts_only_exact_pinned_original_prefix_at_go(tmp_path, monkeypatch):
    attestation, options, _calls, jobs, original, *_ = _fixture(tmp_path, monkeypatch)
    suffix = [JobEvent(10 + index, "info", message, {}) for index, message in enumerate((
        "provider destroy pre-GO recovery intended",
        "provider destroy command intent fenced",
        "provider destroy command started before GO",
        "provider destroy command result fenced",
        "provider destroy command intent fenced",
        "provider destroy command started before GO",
    ))]
    gated = StartedCommand(CommandIntent("new-apply", str(options["state_root"]), "a" * 64),
                           ProcessIdentity("current-boot", 34567, 34567, 12345))
    suffix[-1] = replace(suffix[-1], data={
        "phase": "apply", "invocationId": gated.intent.invocation_id,
        "bootId": gated.identity.boot_id, "pid": gated.identity.pid,
        "pgid": gated.identity.pgid, "startTicks": gated.identity.start_ticks,
    })
    claimed = replace(original, input={**original.input,
        "claimOwner": "provider-keyed-destroy-recovery-reviewed",
        "claimToken": "r" * 32}, events=[*original.events, *suffix])
    jobs.rows[original.id] = claimed
    result = service.bind_reviewed_digitalocean_destroy_pre_go(
        attestation, **options, original_child=original, claimed_child=claimed,
        claim_fence=lambda expected: expected, gated_started=gated,
        gated_argv=["terraform", "apply"], gated_process_prover=lambda *_a: True,
    )
    assert result.child_journal_sha256 == job_event_digest(original.events)
    tampered = replace(claimed, events=[replace(claimed.events[0], message="changed"),
                                        *claimed.events[1:]])
    jobs.rows[original.id] = tampered
    with pytest.raises(service.PreGoRecoveryBoundaryError):
        service.bind_reviewed_digitalocean_destroy_pre_go(
            attestation, **options, original_child=original, claimed_child=tampered,
            claim_fence=lambda expected: expected, gated_started=gated,
            gated_argv=["terraform", "apply"], gated_process_prover=lambda *_a: True,
        )


def test_attestation_accepts_naive_sqlite_job_utc_but_not_naive_operator_times(
    tmp_path, monkeypatch,
):
    attestation, _options, _calls, _jobs, child, *_ = _fixture(tmp_path, monkeypatch)
    persisted_child = replace(child, started_at=child.started_at.removesuffix("+00:00"))
    assert service._attestation_matches(
        replace(attestation, child_journal_sha256=job_event_digest(persisted_child.events)),
        persisted_child,
    )
    assert not service._attestation_matches(
        replace(attestation, api_started_at=attestation.api_started_at.removesuffix("+00:00")),
        persisted_child,
    )
    assert not service._attestation_matches(
        replace(attestation, evidence_window_end=attestation.evidence_window_end.removesuffix("+00:00")),
        persisted_child,
    )


def test_second_incident_is_exactly_pinned_and_cannot_borrow_old_attestation(tmp_path, monkeypatch):
    attestation, _options, _calls, _jobs, child, *_ = _fixture(tmp_path, monkeypatch)
    incident = service._reviewed_incident("job-engagement-teardown-b4f1bceb4a7d")
    assert incident.engagement_id == "eng-6ad4d5fb880e"
    assert incident.core_id == "job-b4f1bceb4a7d"
    assert incident.child_id == "job-provider-keyed-initial-destroy-apply-b4f1bceb4a7d"
    assert incident.original_journal_sha256 == (
        "36a5746659bf771f25429abfca06b76d092b1a36a9769c074a801b6fb2bc3caf")
    assert incident.state_sha256 == (
        "e71116c850d7cd56937f411bf49ef390a19b1b4241e4e7d571a9a88ebfda4df9")
    assert incident.plan_sha256 == (
        "e4b910e78bc2045a4c5e1adb734047ad94207c3ce98d6dbd6d7530e6e87aea9c")
    with pytest.raises(ValueError, match="unreviewed"):
        service._reviewed_incident("job-engagement-teardown-unreviewed")
    assert not service._attestation_matches(
        replace(attestation, parent_id=incident.parent_id, child_id=incident.child_id,
                revision=incident.revision, api_pid=incident.api_pid), child, incident)


def test_second_incident_attestation_requires_reviewed_runtime_identity(tmp_path, monkeypatch):
    attestation, _options, _calls, _jobs, child, *_ = _fixture(tmp_path, monkeypatch)
    recorded = dict(child.events[8].data)
    recorded.update(bootId="a002e341-34dd-43bc-9650-3d10a3f2cca6",
                    pid=391058, pgid=391058, startTicks=1176259684)
    events = [*child.events[:8], replace(child.events[8], data=recorded)]
    child = replace(child, events=events, started_at="2026-10-14T03:57:00+00:00")
    incident = replace(service._DEVTEST_0CC4_INCIDENT,
                       original_journal_sha256=job_event_digest(events))
    reviewed = replace(
        attestation, parent_id=incident.parent_id, child_id=incident.child_id,
        revision=incident.revision, api_pid=incident.api_pid,
        api_started_at="2026-10-14T03:54:27+00:00",
        evidence_window_end="2026-10-14T04:14:00+00:00",
        child_journal_sha256=incident.original_journal_sha256,
        gated_boot_id=recorded["bootId"], gated_pid=recorded["pid"],
        gated_pgid=recorded["pgid"], gated_start_ticks=recorded["startTicks"],
    )
    assert service._attestation_matches(reviewed, child, incident)
    for drift in (
        replace(reviewed, api_pid=317379),
        replace(reviewed, revision=service._HISTORICAL_REVISION),
        replace(reviewed, gated_start_ticks=recorded["startTicks"] + 1),
        replace(reviewed, api_started_at="2026-10-14T03:54:28+00:00"),
    ):
        assert not service._attestation_matches(drift, child, incident)


def test_second_incident_binder_rebinds_persisted_claimed_child(tmp_path, monkeypatch):
    attestation, options, calls, fixture_jobs, original, state, plan, _phase = (
        _fixture(tmp_path, monkeypatch))
    incident = replace(service._DEVTEST_0CC4_INCIDENT,
                       state_sha256=_sha(state), plan_sha256=_sha(plan))
    monkeypatch.setattr(service, "_DEVTEST_0CC4_INCIDENT", incident)
    _old_parent, _old_core, snapshot, _operation = service._boundary(None, None, None, None)
    parent = SimpleNamespace(id=incident.parent_id, target_id=incident.engagement_id,
                             requested_by="operator")
    core = SimpleNamespace(id=incident.core_id)
    coordinator = SimpleNamespace(
        id=service._child_id(core.id), status="running",
        input={"phase": "inspector_ready"}, events=[JobEvent(1, "info", "ready", {})],
    )
    events = list(original.events)
    events[5] = replace(events[5], data={**events[5].data, "coreJobId": core.id})
    events[8] = replace(events[8], data={**events[8].data,
        "bootId": "a002e341-34dd-43bc-9650-3d10a3f2cca6",
        "pid": 391058, "pgid": 391058, "startTicks": 1176259684})
    preview_id = "job-provider-keyed-initial-destroy-plan-b4f1bceb4a7d"
    child = replace(original, id=incident.child_id, target=f"engagement:{incident.engagement_id}",
                    target_id=incident.engagement_id,
                    started_at="2026-10-14T03:57:00+00:00",
                    input={**original.input, "engagementId": incident.engagement_id,
                           "coreJobId": core.id, "teardownParentId": parent.id,
                           "destroyPlanJobId": preview_id}, events=events)
    incident = replace(incident, original_journal_sha256=job_event_digest(child.events))
    monkeypatch.setattr(service, "_DEVTEST_0CC4_INCIDENT", incident)
    preview = fixture_jobs.get(original.input["destroyPlanJobId"])
    preview = SimpleNamespace(id=preview_id, action=preview.action, status=preview.status,
                              artifact_refs=preview.artifact_refs, events=preview.events)
    persisted = SqliteJobRepository(tmp_path / "claimed.sqlite")
    persisted.save(child)

    class Jobs:
        def get(self, identifier):
            return persisted.get(identifier) if identifier == child.id else {
                parent.id: parent, core.id: core, coordinator.id: coordinator,
                preview.id: preview,
            }.get(identifier)

    options["job_repository"] = Jobs()
    monkeypatch.setattr(service, "_boundary", lambda *_a: (parent, core, snapshot, service._FENCE))
    attestation = replace(
        attestation, revision=incident.revision, api_pid=incident.api_pid,
        api_started_at="2026-10-14T03:54:27+00:00",
        evidence_window_end="2026-10-14T04:14:00+00:00",
        parent_id=parent.id, child_id=child.id,
        child_journal_sha256=incident.original_journal_sha256,
        gated_boot_id=events[8].data["bootId"], gated_pid=391058, gated_pgid=391058,
        gated_start_ticks=1176259684,
    )
    first = service.bind_reviewed_digitalocean_destroy_pre_go(attestation, **options)
    assert first.child_id == incident.child_id
    now = datetime.now(timezone.utc)
    claimed = persisted.take_over_initial_destroy_apply_pre_go(
        persisted.get(child.id), expected_event_digest=incident.original_journal_sha256,
        owner="provider-keyed-destroy-recovery-reviewed", token="r" * 32,
        claimed_at=now.isoformat(), expires_at=(now + timedelta(minutes=15)).isoformat(),
    )
    assert claimed is not None
    second = service.bind_reviewed_digitalocean_destroy_pre_go(
        attestation, **options, original_child=child, claimed_child=claimed,
        claim_fence=lambda expected: expected,
    )
    assert second == first
    assert calls == ["attachment", "key", "inspector"] * 2
    with pytest.raises(service.PreGoRecoveryBoundaryError):
        service.bind_reviewed_digitalocean_destroy_pre_go(
            attestation, **options, original_child=child,
            claimed_child=replace(claimed, input={**claimed.input, "planSha256": "0" * 64}),
            claim_fence=lambda expected: expected,
        )


@pytest.mark.parametrize("drift", [
    "revision", "api_pid", "window", "journal", "show_argv", "apply_argv", "state",
    "plan", "phase", "process", "wrong_uid", "root_uid", "cloud_id",
])
def test_read_only_binder_rejects_incident_drift_before_mutation(tmp_path, monkeypatch, drift):
    attestation, options, calls, jobs, child, state, plan, phase = _fixture(tmp_path, monkeypatch)
    if drift == "revision":
        attestation = replace(attestation, revision="0" * 40)
    elif drift == "api_pid":
        attestation = replace(attestation, api_pid=999)
    elif drift == "window":
        attestation = replace(attestation, evidence_window_end=attestation.api_started_at)
    elif drift == "journal":
        jobs.rows[child.id] = replace(child, events=[*child.events[:-1], replace(
            child.events[-1], data={**child.events[-1].data, "pid": 999})])
    elif drift in {"show_argv", "apply_argv"}:
        index = 2 if drift == "show_argv" else 7
        events = list(child.events)
        events[index] = replace(events[index], data={
            **events[index].data, "argvSha256": "9" * 64,
        })
        changed = replace(child, events=events)
        jobs.rows[child.id] = changed
        attestation = replace(attestation, child_journal_sha256=job_event_digest(events))
    elif drift == "state":
        state.write_text("changed")
    elif drift == "plan":
        plan.write_text("changed")
    elif drift == "phase":
        phase.write_text(json.dumps({"schema": "provider-keyed-v2", "phase": "applied"}))
    elif drift == "process":
        options["process_quiescence"] = lambda *_a: False
    elif drift == "wrong_uid":
        monkeypatch.setattr(service.os, "geteuid", lambda: options["state_root"].stat().st_uid + 1)
    elif drift == "root_uid":
        monkeypatch.setattr(service.os, "geteuid", lambda: 0)
    elif drift == "cloud_id":
        options["attachment_prover"] = lambda *_a, **_kw: (_ for _ in ()).throw(
            ValueError("missing exact cloud ID"))
    with pytest.raises(service.PreGoRecoveryBoundaryError):
        service.bind_reviewed_digitalocean_destroy_pre_go(attestation, **options)
    assert jobs.get(child.id).status == "running"


def test_process_quiescence_rejects_recorded_pid_reuse_and_live_group(tmp_path, monkeypatch):
    monkeypatch.setattr(service, "_terraform_quiescent", lambda: True)
    proc = tmp_path / "proc"
    boot_path = proc / "sys/kernel/random/boot_id"
    boot_path.parent.mkdir(parents=True)
    boot_path.write_text("boot")
    assert service._process_quiescent("boot", 317689, 317689, 123, proc)
    pid = proc / "317689"
    pid.mkdir()
    assert not service._process_quiescent("boot", 317689, 317689, 123, proc)
    pid.rmdir()
    member = proc / "400000"
    member.mkdir()
    # Linux /proc/PID/stat fields after comm: state, ppid, pgrp, session...
    (member / "stat").write_text("400000 (terraform-provider) S 1 317689 1 " + "0 " * 20)
    assert not service._process_quiescent("boot", 317689, 317689, 123, proc)


def test_go_process_proof_requires_exact_blocked_child_and_single_group(monkeypatch):
    argv = ["/tmp/terraform", "apply", "-input=false", "/tmp/plan"]
    started = StartedCommand(CommandIntent("new", "/tmp", "a" * 64),
                             ProcessIdentity("boot", 45678, 45678, 98765))
    expected = [str(Path(service.sys.executable).resolve(strict=True)), "-I",
                str(service._GATE_CHILD), "7",
                f"--gate-timeout={service._INCIDENT_GATE_TIMEOUT}", "--", *argv]
    raw = b"\0".join(part.encode() for part in expected) + b"\0"
    original_read = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes", lambda path: raw if str(path) == "/proc/45678/cmdline"
                        else original_read(path))
    monkeypatch.setattr(service, "linux_process_identity", lambda _pid: started.identity)
    monkeypatch.setattr(service, "linux_active_group_members", lambda _id: {45678})
    assert service._gated_process_exact(started, argv)
    assert not service._gated_process_exact(started, [*argv[:-1], "/tmp/other-plan"])
    monkeypatch.setattr(service, "linux_active_group_members", lambda _id: {45678, 45679})
    assert not service._gated_process_exact(started, argv)
