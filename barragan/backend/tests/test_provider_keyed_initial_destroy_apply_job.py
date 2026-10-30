# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only, dormant preclaim boundary for a future keyed destroy apply."""

from dataclasses import replace
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, GatedRunnerError, ProcessIdentity, StartedCommand,
    UnreapedGatedCommandError,
)
from app.services.provider_keyed_initial_destroy_apply import ProviderKeyedInitialDestroyApplyResult
from test_provider_keyed_initial_destroy_apply import prepared
from app.services import provider_keyed_initial_destroy_apply_job as service
from app.services import provider_keyed_initial_destroy_plan_job as preview_service
from test_provider_keyed_initial_destroy_plan_job import _failed_prebinding_boundary, _prepared


_REAL_EXACT_STATE = service._require_exact_state


def _proved_preview(tmp_path, monkeypatch, *, failed_count=None):
    jobs, queued, scope, plans, options, _calls, workspace = _prepared(tmp_path, monkeypatch)
    if failed_count is not None:
        queued, _initial = _failed_prebinding_boundary(
            jobs, queued, scope, options, failed_count)
    monkeypatch.setattr(service, "_default_state_root", lambda: options["state_root"])
    preview = preview_service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    assert preview.status == "succeeded"
    # The adjacent fake gated runner supplies placeholder digests. Give this
    # read-only boundary the exact hashes a real gated runner would journal.
    events = list(preview.events)
    staging = events[2].data
    binary = events[-1].data["terraformBinaryPath"]
    plan_path = events[-1].data["planPath"]
    argv = (
        [binary, "version", "-json"],
        [binary, "init", "-input=false", "-lockfile=readonly", "-no-color"],
        [binary, "plan", "-destroy", "-input=false", "-lock=true", "-no-color",
         f"-out={plan_path}", f"-var-file={staging['stagedInputPath']}",
         f"-var-file={staging['credentialPath']}"],
        [binary, "show", "-json", plan_path],
    )
    for phase_index, command in enumerate(argv):
        event_index = 3 + phase_index * 3
        event = events[event_index]
        events[event_index] = replace(event, data={
            **event.data, "argvSha256": hashlib.sha256(json.dumps(
                command, separators=(",", ":")).encode()).hexdigest(),
        })
    preview = jobs.save(replace(preview, events=events))
    resources = {row["address"]: row["id"] for row in scope["resources"]}
    reviewed, _workspace, evidence, _apply = options["applied_reader"]()
    attachment = SimpleNamespace(
        state_sha256=scope["stateSha256"],
        nodes=tuple(SimpleNamespace(address=address, droplet_id=resources[address])
                    for address in reviewed.nodes),
        firewall_id=resources["digitalocean_firewall.firewall"],
        credential_record_id=workspace.provider_connection_id,
        credential_secret_sha256=evidence["credentialSecretSha256"],
        credential_updated_at=evidence["credentialUpdatedAt"],
    )
    observed = []

    def membership(*_args, **kwargs):
        observed.append("GET")
        assert kwargs["environment"] == "devtest"
        assert kwargs["deployment_target"] == "barragan-testing"

    binding_options = dict(
        environment="devtest", state_root=options["state_root"],
        job_repository=jobs, plan_repository=plans,
        sketch_repository=options["sketch_repository"],
        credential_repository=options["credential_repository"],
        lease_lookup=options["lease_lookup"], scope_builder=options["scope_builder"],
        applied_reader=options["applied_reader"],
        attachment_builder=lambda *_args: attachment,
        state_validator=options["state_validator"], membership_veto=membership,
    )
    if failed_count is not None:
        binding_options["handoff_auditor"] = options["handoff_auditor"]
    return jobs, queued, scope, plans, workspace, preview, binding_options, observed


@pytest.mark.parametrize("count,accepted", [(0, True), (2, True), (8, True), (1, False)])
def test_failed_prebinding_apply_boundary_rechecks_audited_count(
    tmp_path, monkeypatch, count, accepted,
):
    jobs, queued, _scope, _plans, _workspace, _preview, options, observed = (
        _proved_preview(tmp_path, monkeypatch, failed_count=count if count in (0, 2, 8) else 8))
    options["handoff_auditor"] = lambda *_args, **_kwargs: SimpleNamespace(
        parent_job_id="job-provider-keyed-initial-core", command_count=count)
    if accepted:
        bound = service.preflight_digitalocean_initial_destroy_apply(queued.id, **options)
        assert bound.teardown_parent_id == queued.id
        assert observed == ["GET"]
    else:
        with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
            service.preflight_digitalocean_initial_destroy_apply(queued.id, **options)
        assert observed == []
        assert not any(row.action == service.ACTION for row in jobs.list())


def test_exact_preview_and_current_membership_bind_without_mutation(tmp_path, monkeypatch):
    jobs, queued, scope, _plans, workspace, preview, options, observed = _proved_preview(tmp_path, monkeypatch)
    before = jobs.list()
    bound = service.preflight_digitalocean_initial_destroy_apply(queued.id, **options)
    assert bound.teardown_parent_id == queued.id
    assert bound.preview_job_id == preview.id
    assert bound.preview.plan_path == workspace.path / ".barragan-initial-destroy.tfplan"
    assert bound.preview.plan_sha256 == preview.events[-1].data["planSha256"]
    assert bound.teardown_intent.resource_ids == {
        row["address"]: row["id"] for row in scope["resources"]}
    assert observed == ["GET"] and jobs.list() == before
    assert not any(row.action == service.ACTION for row in jobs.list())


def test_published_saved_plan_preflight_rechecks_source_and_fake_publication_cannot_apply(tmp_path, monkeypatch):
    jobs, queued, scope, _plans, _workspace, preview, options, observed = _proved_preview(
        tmp_path, monkeypatch)
    published = jobs.save(replace(queued, input={**queued.input, "publishedSource": {"sealed": True}}))
    audited = []

    def source(parent_id, **kwargs):
        audited.append((parent_id, kwargs["phase"]))
        return SimpleNamespace(
            variant="published", core_job_id=scope["coreJobId"], core_plan_id=scope["corePlanId"],
            snapshot_id=published.input["scopeSnapshot"]["snapshotId"],
            provider_scope_sha256=published.input["scopeSnapshot"]["providerScopeSha256"],
        )

    monkeypatch.setattr(service, "load_keyed_teardown_source", source)
    options["handoff_auditor"] = lambda *_a, **_kw: pytest.fail("pending handoff audited")
    bound = service.preflight_digitalocean_initial_destroy_apply(published.id, **options)
    assert bound.preview_job_id == preview.id and observed == ["GET"]
    assert audited == [(published.id, "pre_go"), (published.id, "pre_go")]
    options["gated_command_runner"] = lambda *_a, **_kw: pytest.fail("Terraform command reached")
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.run_digitalocean_initial_destroy_apply_job(published.id, **options)
    assert observed == ["GET", "GET", "GET"]
    children = [row for row in jobs.list() if row.action == service.ACTION]
    assert len(children) == 1 and children[0].status == "failed"


def test_published_source_change_during_membership_get_vetoes(tmp_path, monkeypatch):
    jobs, queued, scope, _plans, _workspace, _preview, options, observed = _proved_preview(
        tmp_path, monkeypatch)
    published = jobs.save(replace(queued, input={**queued.input, "publishedSource": {"sealed": True}}))
    revision = [0]

    def source(_parent_id, **_kwargs):
        revision[0] += 1
        return SimpleNamespace(
            variant="published", core_job_id=scope["coreJobId"], core_plan_id=scope["corePlanId"],
            snapshot_id=published.input["scopeSnapshot"]["snapshotId"],
            provider_scope_sha256=published.input["scopeSnapshot"]["providerScopeSha256"],
            initial_journal_sha256=str(revision[0]),
        )

    monkeypatch.setattr(service, "load_keyed_teardown_source", source)
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.preflight_digitalocean_initial_destroy_apply(published.id, **options)
    assert observed == ["GET"] and revision == [2]
    assert not any(row.action == service.ACTION for row in jobs.list())


def test_published_source_drift_vetoes_before_membership_get(tmp_path, monkeypatch):
    jobs, queued, scope, _plans, _workspace, _preview, options, observed = _proved_preview(
        tmp_path, monkeypatch)
    published = jobs.save(replace(queued, input={**queued.input, "publishedSource": {"sealed": True}}))
    monkeypatch.setattr(service, "load_keyed_teardown_source", lambda *_a, **_kw: SimpleNamespace(
        variant="published", core_job_id=scope["coreJobId"], core_plan_id=scope["corePlanId"],
        snapshot_id="drift", provider_scope_sha256=published.input["scopeSnapshot"]["providerScopeSha256"],
    ))
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.preflight_digitalocean_initial_destroy_apply(published.id, **options)
    assert observed == []
    assert not any(row.action == service.ACTION for row in jobs.list())


@pytest.mark.parametrize("drift", ["plan", "parent", "lease", "preview", "membership"])
def test_drift_or_provider_veto_fails_before_any_apply_child(tmp_path, monkeypatch, drift):
    jobs, queued, scope, plans, workspace, preview, options, observed = _proved_preview(tmp_path, monkeypatch)
    if drift == "plan":
        (workspace.path / ".barragan-initial-destroy.tfplan").write_bytes(b"changed")
    elif drift == "parent":
        jobs.save(replace(queued, input={**queued.input, "phase": "attention"}))
    elif drift == "lease":
        plans.lease = (scope["corePlanId"], "provider_keyed_initial")
    elif drift == "preview":
        jobs.save(replace(preview, artifact_refs=[]))
    else:
        options["membership_veto"] = lambda *_a, **_kw: (_ for _ in ()).throw(
            RuntimeError("extra manually tagged Droplet"))
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError) as error:
        service.preflight_digitalocean_initial_destroy_apply(queued.id, **options)
    assert "Droplet" not in str(error.value)
    assert not any(row.action == service.ACTION for row in jobs.list())


def test_lease_change_during_provider_get_fails_final_reread(tmp_path, monkeypatch):
    jobs, queued, scope, plans, _workspace, _preview, options, _observed = _proved_preview(tmp_path, monkeypatch)

    def retag_during_get(*_args, **_kwargs):
        plans.lease = (scope["corePlanId"], "provider_keyed_initial")

    options["membership_veto"] = retag_during_get
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.preflight_digitalocean_initial_destroy_apply(queued.id, **options)
    assert not any(row.action == service.ACTION for row in jobs.list())


@pytest.mark.parametrize("drift", [
    "missing", "extra", "phase", "invocation", "argv", "process", "result", "staging",
])
def test_preview_requires_exact_supervised_command_journal(tmp_path, monkeypatch, drift):
    jobs, queued, _scope, _plans, _workspace, preview, options, observed = _proved_preview(
        tmp_path, monkeypatch)
    events = list(preview.events)
    if drift == "missing":
        events.pop(4)
    elif drift == "extra":
        events.append(replace(events[4], sequence=17))
    elif drift == "staging":
        events[2] = replace(events[2], data={**events[2].data, "credentialPath": "/tmp/other"})
    else:
        index, field, value = {
            "phase": (6, "phase", "show"),
            "invocation": (4, "invocationId", "other"),
            "argv": (3, "argvSha256", "not-a-digest"),
            "process": (4, "pgid", 99999),
            "result": (5, "stdoutTruncated", True),
        }[drift]
        events[index] = replace(events[index], data={**events[index].data, field: value})
    jobs.save(replace(preview, events=events))
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.preflight_digitalocean_initial_destroy_apply(queued.id, **options)
    assert observed == []
    assert not any(row.action == service.ACTION for row in jobs.list())


def test_attachment_credential_record_must_match_workspace_before_get(tmp_path, monkeypatch):
    jobs, queued, _scope, _plans, workspace, _preview, options, observed = _proved_preview(
        tmp_path, monkeypatch)
    attachment = options["attachment_builder"]()
    options["attachment_builder"] = lambda *_args: SimpleNamespace(
        **{**vars(attachment), "credential_record_id": "another-connection"})
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.preflight_digitalocean_initial_destroy_apply(queued.id, **options)
    assert observed == []
    assert workspace.provider_connection_id != "another-connection"
    assert not any(row.action == service.ACTION for row in jobs.list())


def _controller_fixture(tmp_path, monkeypatch, *, failed_count=None):
    jobs, queued, scope, plans, workspace, _preview, options, observed = _proved_preview(
        tmp_path, monkeypatch, failed_count=failed_count)
    commands = []
    workspace.state_path = workspace.path / "terraform.tfstate"
    before_state = {
        "version": 4, "terraform_version": "1.15.5",
        "lineage": "11111111-1111-4111-8111-111111111111",
        "serial": 3, "resources": [{"before": "owned"}],
    }
    workspace.state_path.write_text(json.dumps(before_state))
    workspace.state_path.chmod(0o600)
    monkeypatch.setattr(service, "_require_exact_state", lambda _workspace, _intent: before_state)
    actual_hash_file = service._hash_file
    monkeypatch.setattr(service, "_hash_file", lambda path: (
        scope["stateSha256"] if Path(path) == workspace.state_path
        and json.loads(workspace.state_path.read_text())["serial"] == 3
        else actual_hash_file(path)))

    def gated(args, *, scratch_path, provider_keyed_v2, max_output_bytes, env,
              intent_callback, started_callback, heartbeat_callback, result_callback,
              **gate_options):
        phase = "show" if args[1] == "show" else "apply"
        commands.append(phase)
        assert provider_keyed_v2 and scratch_path == workspace.path
        assert gate_options == ({"gate_timeout_seconds": 1200} if phase == "apply" else {})
        intent = CommandIntent(f"destroy-{phase}", str(scratch_path), hashlib.sha256(
            json.dumps(args, separators=(",", ":")).encode()).hexdigest())
        intent_callback(intent)
        child = next(row for row in jobs.list() if row.action == service.ACTION)
        lease_seconds = (datetime.fromisoformat(child.input["claimExpiresAt"])
                         - datetime.fromisoformat(child.input["claimHeartbeatAt"])).total_seconds()
        assert lease_seconds == (1200 if phase == "apply" else 60)
        started = StartedCommand(intent, ProcessIdentity(
            "11111111-1111-4111-8111-111111111111", 2000 + len(commands),
            2000 + len(commands), len(commands)))
        started_callback(started)
        heartbeat_callback(started)
        result_callback(CommandAuditResult(started, 0, 2, 0, False, False))
        return CommandResult(started, 0, "{}", "", False, False)

    def apply(workspace_arg, preview, intent, *, command_runner, phase_write_intent, **kwargs):
        assert workspace_arg == workspace and preview.plan_path.is_file()
        binary = str(preview.terraform_binary_path)
        plan = str(preview.plan_path)
        command_runner([binary, "show", "-json", plan], workspace.path, {})
        phase_write_intent(workspace.path / ".barragan-apply-phase.json", "destroy_started")
        (workspace.path / ".barragan-apply-phase.json").write_text(
            json.dumps({"schema": "provider-keyed-v2", "phase": "destroy_started"}))
        command_runner([binary, "apply", "-input=false", "-lock=true", "-no-color", plan],
                       workspace.path, {})
        phase_write_intent(workspace.path / ".barragan-apply-phase.json", "destroy_applied")
        (workspace.path / ".barragan-apply-phase.json").write_text(
            json.dumps({"schema": "provider-keyed-v2", "phase": "destroy_applied"}))
        workspace.state_path.write_text(json.dumps({**before_state, "serial": 4, "resources": []}))
        return ProviderKeyedInitialDestroyApplyResult(actual_hash_file(workspace.state_path))

    options.update(apply=apply, gated_command_runner=gated, command_environment={},
                   live_inspector_prover=lambda *_args, **_kwargs: None,
                   dns_checkpoint_prover=lambda snapshot, **_kwargs: {
                       "dnsCleanupManifestSha256": snapshot["dnsCleanupManifest"]["manifestSha256"],
                       "dnsCleanupHandoffJournalSha256": service.job_event_digest(
                           jobs.get(snapshot["dnsCleanupManifest"]["initialJobId"]).events),
                       "dnsCleanupCheckpointSha256": service._fingerprint({
                           "scopeSnapshotId": snapshot["snapshotId"],
                           "dnsCleanupManifestSha256": snapshot["dnsCleanupManifest"]["manifestSha256"],
                           "dnsCleanupHandoffJournalSha256": service.job_event_digest(
                               jobs.get(snapshot["dnsCleanupManifest"]["initialJobId"]).events),
                       }),
                   })
    return jobs, queued, scope, plans, workspace, options, observed, commands


def test_failed_prebinding_seals_source_before_phase_and_vetoes_coordinator_drift_at_go(
    tmp_path, monkeypatch,
):
    jobs, queued, _scope, _plans, workspace, options, observed, commands = _controller_fixture(
        tmp_path, monkeypatch, failed_count=8)
    coordinator_id = "job-provider-keyed-comprehensive-teardown-core"
    coordinator = jobs.save(replace(
        jobs.get("job-provider-keyed-initial-destroy-plan-core"),
        id=coordinator_id, action="provider_keyed_comprehensive_teardown",
        status="running", input={"phase": "inspector_ready"},
    ))
    snapshot = queued.input["scopeSnapshot"]
    source = SimpleNamespace(
        variant="failed_prebinding", core_job_id=snapshot["coreJobId"],
        core_plan_id=snapshot["providerScopes"][0]["corePlanId"],
        snapshot_id=snapshot["snapshotId"],
        provider_scope_sha256=snapshot["providerScopeSha256"],
        initial_job_id=snapshot["dnsCleanupManifest"]["initialJobId"],
        initial_journal_sha256=snapshot["dnsCleanupManifest"]["initialJournalSha256"],
    )
    source_reads = []

    def full_source(_parent_id, **_kwargs):
        source_reads.append(json.loads((workspace.path / ".barragan-apply-phase.json").read_text())["phase"])
        assert source_reads[-1] == "applied"
        return source

    monkeypatch.setattr(service, "load_keyed_teardown_source", full_source)
    original_membership = options["membership_veto"]

    def drift_at_go(*args, **kwargs):
        original_membership(*args, **kwargs)
        if len(observed) == 3:
            jobs.save(replace(coordinator, events=[*coordinator.events,
                replace(coordinator.events[-1], sequence=len(coordinator.events) + 1)]))

    options["membership_veto"] = drift_at_go
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "running" and child.events[-1].message == (
        "provider destroy command started before GO")
    assert source_reads == ["applied", "applied"]
    assert observed == ["GET", "GET", "GET"] and commands == ["show", "apply"]
    assert json.loads((workspace.path / ".barragan-apply-phase.json").read_text())["phase"] == (
        "destroy_started")


def test_claimed_destroy_apply_audits_show_phase_apply_and_absence_pending(tmp_path, monkeypatch):
    jobs, queued, scope, plans, workspace, options, observed, commands = _controller_fixture(
        tmp_path, monkeypatch)
    child = service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)
    assert child.status == "succeeded" and child.input["mutation"] is True
    assert "claimToken" not in child.input and child.artifact_refs == []
    assert commands == ["show", "apply"] and observed == ["GET", "GET", "GET"]
    assert [event.data["phase"] for event in child.events
            if event.message == "provider destroy phase write intended"] == [
                "destroy_started", "destroy_applied"]
    prestate = [event.data for event in child.events
                if event.message == "provider destroy prestate identity fenced"]
    assert len(prestate) == 1
    assert prestate[0]["stateLineage"] == "11111111-1111-4111-8111-111111111111"
    assert prestate[0]["preDestroySerial"] == 3
    bound_ids = {row["address"]: row["id"] for row in scope["resources"]}
    assert prestate[0]["resourceIds"] == bound_ids
    assert prestate[0]["resourceIdsSha256"] == service._fingerprint(bound_ids)
    assert prestate[0]["preDestroyStateSha256"] == scope["stateSha256"]
    assert prestate[0]["scopeSnapshotId"] == queued.input["scopeSnapshot"]["snapshotId"]
    assert prestate[0]["dnsCleanupManifestSha256"] == queued.input[
        "scopeSnapshot"]["dnsCleanupManifest"]["manifestSha256"]
    assert prestate[0]["dnsCleanupCheckpointSha256"] == service._fingerprint({
        "scopeSnapshotId": prestate[0]["scopeSnapshotId"],
        "dnsCleanupManifestSha256": prestate[0]["dnsCleanupManifestSha256"],
        "dnsCleanupHandoffJournalSha256": prestate[0]["dnsCleanupHandoffJournalSha256"],
    })
    assert child.events[-1].data == {
        "stateSha256": hashlib.sha256(workspace.state_path.read_bytes()).hexdigest(),
        "providerAbsenceProofPending": True}
    assert plans.lease == (scope["corePlanId"], "provider_keyed_teardown_fence")
    assert workspace.path.joinpath(".barragan-initial-destroy.tfplan").exists()
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)
    assert commands == ["show", "apply"]


def test_destroy_claim_covers_bounded_pre_go_gate():
    instant = "2026-10-13T00:00:00+00:00"
    assert (datetime.fromisoformat(service._later(instant))
            - datetime.fromisoformat(instant)).total_seconds() == 60
    assert (datetime.fromisoformat(service._later(instant, seconds=1200))
            - datetime.fromisoformat(instant)).total_seconds() == 1200


def test_dns_checkpoint_drift_fails_before_destroy_phase_or_apply_command(tmp_path, monkeypatch):
    jobs, queued, _scope, _plans, workspace, options, _observed, commands = _controller_fixture(
        tmp_path, monkeypatch)
    options["dns_checkpoint_prover"] = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        ValueError("DNS zone or receipt drift"))
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "failed"
    assert commands == ["show"]
    assert json.loads((workspace.path / ".barragan-apply-phase.json").read_text())["phase"] == "applied"
    assert not any(event.message == "provider destroy prestate identity fenced"
                   for event in child.events)
    assert not any(event.message == "provider destroy phase write intended"
                   for event in child.events)


def test_dns_checkpoint_second_read_veto_keeps_one_shot_unresolved(tmp_path, monkeypatch, caplog):
    jobs, queued, _scope, _plans, _workspace, options, _observed, commands = _controller_fixture(
        tmp_path, monkeypatch)
    original = options["dns_checkpoint_prover"]
    reads = 0
    def drift_after_phase(snapshot, **kwargs):
        nonlocal reads
        reads += 1
        if reads == 2:
            raise ValueError("zone changed before GO")
        return original(snapshot, **kwargs)
    options["dns_checkpoint_prover"] = drift_after_phase
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "running" and child.input["claimToken"]
    assert commands == ["show", "apply"] and reads == 2
    assert child.events[-1].message == "provider destroy command started before GO"
    assert len(child.events) == 9
    assert "stage=pre_go_dns exceptionClass=ValueError" in caplog.text
    assert "zone changed before GO" not in caplog.text


def test_apply_pre_go_membership_veto_leaves_one_shot_running(tmp_path, monkeypatch, caplog):
    jobs, queued, _scope, _plans, workspace, options, observed, commands = _controller_fixture(
        tmp_path, monkeypatch)
    def membership(*args, **kwargs):
        observed.append("GET")
        if len(observed) == 3:
            raise ValueError("extra selected Droplet")
    options["membership_veto"] = membership
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "running" and child.input["claimToken"]
    assert child.events[-1].message == "provider destroy command started before GO"
    assert len(child.events) == 9
    assert "stage=pre_go_membership exceptionClass=ValueError" in caplog.text
    assert "extra selected Droplet" not in caplog.text
    assert commands == ["show", "apply"] and observed == ["GET", "GET", "GET"]
    assert workspace.path.joinpath(".barragan-initial-destroy.tfplan").exists()


@pytest.mark.parametrize("unreaped", [False, True])
def test_pre_go_veto_does_not_release_gate_or_log_exception_payload(
    tmp_path, monkeypatch, caplog, unreaped,
):
    jobs, queued, _scope, _plans, workspace, options, _observed, commands = (
        _controller_fixture(tmp_path, monkeypatch))
    release_attempts = []
    gated = options["gated_command_runner"]

    def observe_gate(args, *, started_callback, **kwargs):
        def before_go(started):
            try:
                started_callback(started)
            except Exception as error:
                # The real gated runner replaces callback errors after safely
                # closing the gate; a failed reap is a distinct outcome.
                if unreaped:
                    raise UnreapedGatedCommandError("process group uncertain") from error
                raise GatedRunnerError("gated command aborted") from error
            release_attempts.append(started.intent.invocation_id)
        return gated(args, started_callback=before_go, **kwargs)

    class SecretBearingProviderError(Exception):
        pass

    membership_reads = 0
    def membership(*_args, **_kwargs):
        nonlocal membership_reads
        membership_reads += 1
        if membership_reads == 3:
            raise SecretBearingProviderError("token=never-log-this")

    options["gated_command_runner"] = observe_gate
    options["membership_veto"] = membership
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert commands == ["show", "apply"]
    assert len(release_attempts) == 1  # Show was released; apply was vetoed.
    assert child.status == "running" and len(child.events) == 9
    assert json.loads(workspace.state_path.read_text())["serial"] == 3
    category = "UnreapedGatedCommandError" if unreaped else "OtherError"
    assert f"stage=pre_go_membership exceptionClass={category}" in caplog.text
    assert "SecretBearingProviderError" not in caplog.text
    assert "never-log-this" not in caplog.text


def test_live_inspector_failure_before_go_preserves_one_shot_child(tmp_path, monkeypatch, caplog):
    jobs, queued, _scope, _plans, workspace, options, _observed, commands = _controller_fixture(
        tmp_path, monkeypatch)
    def unavailable(*_args, **_kwargs):
        raise ValueError("Inspector SSH unavailable")
    options["live_inspector_prover"] = unavailable
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "running" and child.input["claimToken"]
    assert child.events[-1].message == "provider destroy command started before GO"
    assert len(child.events) == 9
    assert "stage=pre_go_inspector exceptionClass=ValueError" in caplog.text
    assert "Inspector SSH unavailable" not in caplog.text
    assert commands == ["show", "apply"]
    assert workspace.state_path.exists()
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)


def test_expired_claim_after_slow_live_proof_cannot_release_apply(tmp_path, monkeypatch):
    jobs, queued, _scope, _plans, workspace, options, _observed, commands = _controller_fixture(
        tmp_path, monkeypatch)
    real_datetime = service.datetime

    class AfterLeaseDeadline:
        fromisoformat = staticmethod(real_datetime.fromisoformat)

        @staticmethod
        def now(tz):
            return real_datetime.now(tz) + timedelta(seconds=1201)

    def proof_finishes_after_claim(*_args, **_kwargs):
        # Model one blocking provider proof returning after the bounded lease.
        monkeypatch.setattr(service, "datetime", AfterLeaseDeadline)

    options["live_inspector_prover"] = proof_finishes_after_claim
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "running" and child.input["claimToken"]
    assert child.events[-1].message == "provider destroy command started before GO"
    assert commands == ["show", "apply"]
    assert json.loads((workspace.path / ".barragan-apply-phase.json").read_text())["phase"] == (
        "destroy_started")


def test_default_apply_path_cannot_skip_live_inspector_proof(tmp_path, monkeypatch):
    from app.services import provider_keyed_destroy_apply_continuation as continuation
    jobs, queued, _scope, _plans, _workspace, options, _observed, commands = _controller_fixture(
        tmp_path, monkeypatch)
    options.pop("live_inspector_prover")
    calls = []
    def deny(*_args, **_kwargs):
        calls.append("live")
        raise ValueError("selected source unavailable")
    monkeypatch.setattr(continuation, "prove_live_keyed_inspector_before_destroy_go", deny)
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert calls == ["live"] and commands == ["show", "apply"]
    assert child.status == "running"
    assert child.events[-1].message == "provider destroy command started before GO"


def test_result_audit_cas_loss_after_start_preserves_running_claim(tmp_path, monkeypatch, caplog):
    jobs, queued, _scope, _plans, workspace, options, _observed, commands = _controller_fixture(
        tmp_path, monkeypatch)
    original = jobs.append_destroy_apply_event_if_running_claimed
    gated = options["gated_command_runner"]

    def wrap_result(args, *, result_callback, **kwargs):
        def audited_result(value):
            try:
                result_callback(value)
            except Exception as error:
                raise GatedRunnerError("gated command aborted") from error
        return gated(args, result_callback=audited_result, **kwargs)

    options["gated_command_runner"] = wrap_result

    def lose_result(*args, **kwargs):
        if kwargs["event"].message == "provider destroy command result fenced" and kwargs["event"].data["phase"] == "apply":
            return None
        return original(*args, **kwargs)

    monkeypatch.setattr(jobs, "append_destroy_apply_event_if_running_claimed", lose_result)
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "running" and child.input["claimToken"]
    assert child.events[-1].message == "provider destroy command started before GO"
    assert len(child.events) == 9
    assert "stage=gated_result_audit exceptionClass=ValueError" in caplog.text
    assert "destroy apply journal claim changed" not in caplog.text
    assert commands == ["show", "apply"]
    assert workspace.path.joinpath(".barragan-initial-destroy.tfplan").exists()


def test_unreaped_before_durable_start_never_terminal_fails_or_replays(tmp_path, monkeypatch):
    jobs, queued, _scope, _plans, workspace, options, _observed, _commands = _controller_fixture(
        tmp_path, monkeypatch)
    def unreaped(args, *, scratch_path, intent_callback, **_kwargs):
        intent_callback(CommandIntent("uncertain-show", str(scratch_path), hashlib.sha256(
            json.dumps(args, separators=(",", ":")).encode()).hexdigest()))
        raise UnreapedGatedCommandError("leader identity unavailable")
    options["gated_command_runner"] = unreaped
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "running" and child.input["claimToken"]
    assert child.events[-1].message == "provider destroy command intent fenced"
    assert workspace.path.joinpath(".barragan-initial-destroy.tfplan").exists()
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)


@pytest.mark.parametrize("drift", ["phase", "state"])
def test_post_helper_phase_or_state_drift_cannot_terminal_succeed(tmp_path, monkeypatch, drift):
    jobs, queued, _scope, _plans, workspace, options, _observed, commands = _controller_fixture(
        tmp_path, monkeypatch)
    original = options["apply"]
    def drift_after_helper(*args, **kwargs):
        result = original(*args, **kwargs)
        if drift == "phase":
            (workspace.path / ".barragan-apply-phase.json").write_text(
                json.dumps({"schema": "provider-keyed-v2", "phase": "destroy_started"}))
        else:
            state = json.loads(workspace.state_path.read_text())
            workspace.state_path.write_text(json.dumps({**state, "resources": [{"partial": True}]}))
        return result
    options["apply"] = drift_after_helper
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "running" and child.input["claimToken"]
    assert commands == ["show", "apply"]


def test_chain_projection_drift_during_last_membership_get_blocks_go(tmp_path, monkeypatch):
    jobs, queued, _scope, _plans, _workspace, options, observed, commands = _controller_fixture(
        tmp_path, monkeypatch)
    rows = list(options["sketch_repository"].list_for_engagement(queued.target_id))
    options["sketch_repository"] = SimpleNamespace(list_for_engagement=lambda _id: rows)

    def drift_during_get(*_args, **_kwargs):
        observed.append("GET")
        if len(observed) == 3:
            rows[0] = replace(rows[0], status="failed")

    options["membership_veto"] = drift_during_get
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "running" and child.input["claimToken"]
    assert child.events[-1].message == "provider destroy command started before GO"
    assert commands == ["show", "apply"] and observed == ["GET", "GET", "GET"]


@pytest.mark.parametrize("veto", ["resource_ids", "prestate_cas"])
def test_prestate_identity_or_journal_veto_precedes_destroy_started_and_apply(
    tmp_path, monkeypatch, veto,
):
    jobs, queued, _scope, _plans, workspace, options, _observed, commands = _controller_fixture(
        tmp_path, monkeypatch)
    if veto == "resource_ids":
        bound = service.preflight_digitalocean_initial_destroy_apply(
            queued.id, **{key: value for key, value in options.items()
                          if key not in {"apply", "gated_command_runner", "command_environment",
                                         "live_inspector_prover", "dns_checkpoint_prover",
                                         "domain_repository", "dns_adapter"}})
        monkeypatch.setattr(service, "preflight_digitalocean_initial_destroy_apply",
                            lambda *_args, **_kwargs: bound)
        original_apply = options["apply"]

        def mismatch_before_phase(*args, phase_write_intent, **kwargs):
            def changed_phase(path, phase):
                if phase == "destroy_started":
                    first = next(iter(bound.teardown_intent.resource_ids))
                    bound.teardown_intent.resource_ids[first] = "wrong-confirmed-id"
                phase_write_intent(path, phase)
            return original_apply(*args, phase_write_intent=changed_phase, **kwargs)

        options["apply"] = mismatch_before_phase
    else:
        original_append = jobs.append_destroy_apply_event_if_running_claimed

        def reject_prestate(*args, **kwargs):
            if kwargs["event"].message == "provider destroy prestate identity fenced":
                return None
            return original_append(*args, **kwargs)

        monkeypatch.setattr(jobs, "append_destroy_apply_event_if_running_claimed", reject_prestate)
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
        service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "failed"
    assert commands == ["show"]
    assert json.loads((workspace.path / ".barragan-apply-phase.json").read_text())["phase"] == "applied"
    assert workspace.path.joinpath(".barragan-initial-destroy.tfplan").exists()
    assert not any(event.message == "provider destroy phase write intended" for event in child.events)
    assert not any(event.message == "provider destroy prestate identity fenced" for event in child.events)


@pytest.mark.parametrize("scenario", ["success", "partial", "phase_write_fail"])
def test_controller_composes_with_real_destroy_helper_without_network(
    tmp_path, monkeypatch, prepared, scenario,
):
    jobs, queued, _scope, _plans, _fixture_workspace, options, observed, _commands = (
        _controller_fixture(tmp_path / "controller", monkeypatch))
    workspace, preview, intent, helper_kwargs, _runner, prior_state = prepared
    original_boundary = service.preflight_digitalocean_initial_destroy_apply(
        queued.id, **{key: value for key, value in options.items()
                      if key not in {"apply", "gated_command_runner", "command_environment",
                                     "live_inspector_prover", "dns_checkpoint_prover",
                                     "domain_repository", "dns_adapter"}})
    # The helper fixture has a different synthetic provider state. Re-seal the
    # confirmed test scope to those exact IDs before substituting its workspace.
    snapshot = dict(queued.input["scopeSnapshot"])
    scope = dict(snapshot["providerScopes"][0])
    scope["resources"] = [{
        "address": address, "id": identity,
        "kind": "droplet" if address.startswith("digitalocean_droplet.") else
                "firewall" if address == "digitalocean_firewall.firewall" else
                "ssh_key" if address == "digitalocean_ssh_key.key" else "local_file",
    } for address, identity in sorted(intent.resource_ids.items())]
    scope["selectorTag"] = intent.firewall.selector_tag
    snapshot["providerScopes"] = [scope]
    snapshot["providerScopeSha256"] = service._fingerprint({"providerScopes": [scope]})
    snapshot["snapshotId"] = service._fingerprint({
        key: value for key, value in snapshot.items() if key != "snapshotId"})
    queued = jobs.save(replace(
        queued, input={**queued.input, "scopeSnapshot": snapshot},
        events=[replace(queued.events[0], data={"snapshotId": snapshot["snapshotId"]})],
    ))
    bound = replace(original_boundary, workspace=workspace, teardown_intent=intent,
                    preview=preview, attachment=SimpleNamespace(),
                    scope_snapshot_id=snapshot["snapshotId"],
                    provider_scope_sha256=snapshot["providerScopeSha256"])
    monkeypatch.setattr(service, "preflight_digitalocean_initial_destroy_apply",
                        lambda *_args, **_kwargs: bound)
    options["credential_repository"] = helper_kwargs["credential_repository"]
    options["apply"] = service.apply_digitalocean_keyed_initial_destroy_plan
    handoff_reads = []

    def pre_destroy_handoff(*_args, **_kwargs):
        # A real handoff audit binds the pre-destroy state. It cannot succeed
        # after the saved plan removes the resources from that state.
        assert json.loads(workspace.state_path.read_text())["resources"]
        handoff_reads.append("pre-destroy")
        return SimpleNamespace(parent_job_id=initial_id, chain_ids=("sealed", "two-chains"))

    initial_id = snapshot["dnsCleanupManifest"]["initialJobId"]
    options["handoff_auditor"] = pre_destroy_handoff
    options["command_environment"] = {"PATH": "/usr/bin"}
    monkeypatch.setattr(service, "_require_exact_state", _REAL_EXACT_STATE)
    monkeypatch.setattr(service, "_hash_file", lambda path: hashlib.sha256(
        Path(path).read_bytes()).hexdigest())
    if scenario == "phase_write_fail":
        def fail_after_journal(_path, payload):
            if payload == {"schema": "provider-keyed-v2", "phase": "destroy_started"}:
                raise OSError("injected phase write failure")
            raise AssertionError("unexpected phase write")
        monkeypatch.setattr(
            "app.services.provider_keyed_initial_destroy_apply._write_json",
            fail_after_journal,
        )
    commands = []

    def gated(args, *, scratch_path, provider_keyed_v2, max_output_bytes, env,
              intent_callback, started_callback, heartbeat_callback, result_callback,
              **gate_options):
        phase = args[1]
        commands.append(phase)
        assert phase in {"show", "apply"} and scratch_path == workspace.path
        assert gate_options == ({"gate_timeout_seconds": 1200} if phase == "apply" else {})
        command_intent = CommandIntent(f"real-helper-{phase}", str(scratch_path), hashlib.sha256(
            json.dumps(args, separators=(",", ":")).encode()).hexdigest())
        intent_callback(command_intent)
        started = StartedCommand(command_intent, ProcessIdentity(
            "11111111-1111-4111-8111-111111111111", 3000 + len(commands),
            3000 + len(commands), len(commands)))
        started_callback(started)
        heartbeat_callback(started)
        if phase == "apply" and scenario == "success":
            workspace.state_path.write_text(json.dumps({**prior_state, "serial": 2, "resources": []}))
        output = json.dumps(_runner.plan) if phase == "show" else ""
        result_callback(CommandAuditResult(started, 0, len(output), 0, False, False))
        return CommandResult(started, 0, output, "", False, False)

    options["gated_command_runner"] = gated
    if scenario in {"partial", "phase_write_fail"}:
        with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
            service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)
        child = next(row for row in jobs.list() if row.action == service.ACTION)
        assert child.status == "running" and child.input["claimToken"]
        assert json.loads((workspace.path / ".barragan-apply-phase.json").read_text())["phase"] == (
            "applied" if scenario == "phase_write_fail" else "destroy_started")
        assert preview.plan_path.exists()
        if scenario == "phase_write_fail":
            assert commands == ["show"]
            assert child.events[-1].message == "provider destroy phase write intended"
            assert child.events[-1].data["phase"] == "destroy_started"
            assert child.events[-2].message == "provider destroy prestate identity fenced"
            assert child.events[-2].data["stateLineage"] == prior_state["lineage"]
            assert child.events[-2].data["preDestroySerial"] == prior_state["serial"]
            assert child.events[-2].data["resourceIds"] == intent.resource_ids
            assert json.loads(workspace.state_path.read_text()) == prior_state
            with pytest.raises(service.ProviderKeyedInitialDestroyApplyJobError):
                service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)
            assert commands == ["show"]
    else:
        child = service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)
        assert child.status == "succeeded"
        assert child.events[-1].data["providerAbsenceProofPending"] is True
        assert json.loads((workspace.path / ".barragan-apply-phase.json").read_text())["phase"] == "destroy_applied"
        assert json.loads(workspace.state_path.read_text())["resources"] == []
    assert commands == (["show"] if scenario == "phase_write_fail" else ["show", "apply"])
    assert handoff_reads
    assert observed == (["GET"] if scenario == "phase_write_fail" else ["GET", "GET"])
