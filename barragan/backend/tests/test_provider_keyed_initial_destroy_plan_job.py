# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network, single-attempt full-state destroy preview child."""

from dataclasses import replace
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import engagement_teardown as teardown
from app.services import provider_keyed_initial_destroy_plan_job as service
from app.services import provider_keyed_initial_teardown as helper
from app.services import provider_keyed_teardown_handoff as handoff
from app.services.provider_keyed_initial_teardown import DigitalOceanTeardownPreview, _SHARED
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.provider_keyed_teardown_quiescence import _FAILED_PREBINDING_MESSAGES
from app.storage.job_repository import job_event_digest
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
    UnreapedGatedCommandError,
)
from test_provider_keyed_chain_projection import _fixture as projection_fixture
from test_provider_keyed_teardown_handoff import _fixture as handoff_fixture


def _prepared(tmp_path, monkeypatch):
    jobs, _bootstrap, queued, scope, plans, handoff_options = handoff_fixture(tmp_path)
    reviewed, _attachment, _proof, chains = projection_fixture()
    resources = [
        {"address": address, "id": str(number),
         "kind": "droplet" if address.startswith("digitalocean_droplet.") else
                 "firewall" if address == "digitalocean_firewall.firewall" else
                 "ssh_key" if address == "digitalocean_ssh_key.key" else "local_file"}
        for number, address in enumerate(sorted(set(reviewed.nodes) | _SHARED), 1)
    ]
    scope = {**scope, "resources": resources, "revisionId": reviewed.revision_id,
             "selectorTag": reviewed.selector_tag}
    snapshot = {**queued.input["scopeSnapshot"], "providerScopes": [scope],
                "providerScopeSha256": teardown._fingerprint({"providerScopes": [scope]})}
    dns_manifest = {**snapshot["dnsCleanupManifest"],
                    "providerScopeSha256": snapshot["providerScopeSha256"]}
    dns_manifest["manifestSha256"] = "sha256:" + teardown._fingerprint({
        key: value for key, value in dns_manifest.items() if key != "manifestSha256"})
    snapshot["dnsCleanupManifest"] = dns_manifest
    snapshot["snapshotId"] = teardown._fingerprint({key: value for key, value in snapshot.items()
                                                    if key != "snapshotId"})
    queued = jobs.save(replace(queued, requested_by="teardown-operator",
                               input={**queued.input, "scopeSnapshot": snapshot},
                               events=[JobEvent(1, "info", "engagement teardown queued",
                                                {"snapshotId": snapshot["snapshotId"]})]))
    handoff_options["scope_builder"] = lambda *_a, **_kw: scope
    handoff.handoff_terminal_provider_keyed_teardown(queued.id, **handoff_options)
    state_root = tmp_path / "state"
    monkeypatch.setattr(service, "_default_state_root", lambda: state_root)
    workspace = SimpleNamespace(
        path=Path(scope["workspace"]), provider_connection_id=scope["providerConnectionId"],
        source_revision=scope["sourceRevision"], source_sha256="c" * 64,
    )
    phase = workspace.path / ".barragan-apply-phase.json"
    phase.write_text('{"schema":"provider-keyed-v2","phase":"applied"}')
    phase.chmod(0o600)
    material = workspace.path.parents[1] / ".plan-material" / "digitalocean"
    material.mkdir(parents=True, exist_ok=True)
    inputs = material / "inputs.json"
    inputs.write_text('{"reviewed":true}')
    inputs.chmod(0o600)
    evidence = {
        "providerConnectionId": workspace.provider_connection_id,
        "sourceSha256": workspace.source_sha256, "selectorTag": reviewed.selector_tag,
        "corePlanId": scope["corePlanId"], "inputSha256": [[str(inputs), "d" * 64]],
        "markerSha256": "b" * 64, "lockfileSha256": "c" * 64,
        "topologySha256": "d" * 64,
        "terraformBinaryPath": "/usr/bin/true", "terraformBinarySha256": "e" * 64,
        "credentialSecretSha256": "f" * 64, "credentialUpdatedAt": "2026-10-08T00:00:00Z",
        "adminPublicKeyPath": str(material / "admin-public"),
        "adminPrivateKeyPath": str(material / "admin-private"),
        "adminPublicKeySha256": hashlib.sha256(b"ssh-ed25519 fixture\n").hexdigest(),
    }
    monkeypatch.setattr(service, "retrieve_sketch_ssh_key", lambda *_args: SimpleNamespace(
        public_key="ssh-ed25519 fixture\n"))
    calls = []

    def preview(workspace_arg, intent, **kwargs):
        calls.append("preview")
        child = next(row for row in jobs.list() if row.action == service.ACTION)
        assert child.status == "running" and child.input["claimToken"]
        assert child.events[-1].message == "provider destroy preview staging intended"
        assert workspace_arg is workspace
        assert intent.resource_ids == {row["address"]: row["id"] for row in resources}
        assert kwargs["input_sha256"] == {inputs: "d" * 64}
        assert kwargs["var_files"] == [inputs]
        assert kwargs["terraform"] == "/usr/bin/true"
        assert plans.lease == (scope["corePlanId"], "provider_keyed_teardown_fence")
        assert (material / "admin-public").read_text() == "ssh-ed25519 fixture\n"
        assert not (material / "admin-private").exists()
        plan = workspace.path / ".barragan-initial-destroy.tfplan"
        staging = kwargs["staging_path"]
        binary = kwargs["terraform"]
        run = kwargs["command_runner"]
        run([binary, "version", "-json"], workspace.path, {})
        run([binary, "init", "-input=false", "-lockfile=readonly", "-no-color"], workspace.path, {})
        run([binary, "plan", "-destroy", "-input=false", "-lock=true", "-no-color",
             f"-out={plan}", f"-var-file={staging / 'input-0.json'}",
             f"-var-file={staging / 'credential.json'}"], workspace.path, {})
        plan.write_bytes(b"reviewed destroy plan")
        plan.chmod(0o600)
        run([binary, "show", "-json", str(plan)], workspace.path, {})
        return DigitalOceanTeardownPreview(
            plan, hashlib.sha256(plan.read_bytes()).hexdigest(), scope["stateSha256"], workspace.source_sha256,
            "b" * 64, "c" * 64, "d" * 64, hashlib.sha256(phase.read_bytes()).hexdigest(),
            ((str(inputs), "d" * 64),), workspace.provider_connection_id,
            evidence["credentialSecretSha256"], evidence["credentialUpdatedAt"],
            Path("/usr/bin/true"), evidence["terraformBinarySha256"],
        )

    options = dict(
        environment="devtest", state_root=state_root, job_repository=jobs,
        plan_repository=plans, sketch_repository=SimpleNamespace(list_for_engagement=lambda _id: chains),
        credential_repository=object(), lease_lookup=lambda _id: plans.lease,
        scope_builder=lambda *_a, **_kw: scope,
        applied_reader=lambda *_a, **_kw: (reviewed, workspace, evidence, object()),
        state_validator=lambda _workspace, intent: calls.append(("state", intent.resource_ids)),
        release_check=lambda **_kw: SimpleNamespace(path=Path("/usr/bin/true"), sha256="e" * 64),
        preview=preview,
    )

    number = 0

    def gated(args, *, scratch_path, provider_keyed_v2, max_output_bytes, env,
              intent_callback, started_callback, heartbeat_callback, result_callback):
        nonlocal number
        number += 1
        assert provider_keyed_v2 and scratch_path == workspace.path
        intent = CommandIntent(f"preview-{number}", str(scratch_path), f"{number:064x}")
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity(
            "11111111-1111-4111-8111-111111111111", 1000 + number, 1000 + number, number))
        started_callback(started)
        heartbeat_callback(started)
        result_callback(CommandAuditResult(started, 0, 20, 0, False, False))
        return CommandResult(started, 0,
                             '{"terraform_version":"1.15.5"}' if args[1] == "version" else "{}",
                             "", False, False)

    options["gated_command_runner"] = gated
    return jobs, queued, scope, plans, options, calls, workspace


def _failed_prebinding_boundary(jobs, queued, scope, options, command_count):
    """Seal the failed source and expose only the auditor's command count seam."""
    initial = jobs.get("job-provider-keyed-initial-core")
    assert initial is not None
    if command_count == 0:
        events = [JobEvent(sequence, "info" if sequence < 8 else "error", message,
                           {"creationToken": "a" * 32} if sequence == 1 else {})
                  for sequence, message in enumerate(_FAILED_PREBINDING_MESSAGES, 1)]
    else:
        events = [*initial.events, JobEvent(len(initial.events) + 1, "error",
                                            "strict host proof stopped; reconciliation required", {})]
    initial = jobs.save(replace(
        initial, status="failed", finished_at="2026-10-12T00:00:00+00:00",
        input={**initial.input, "phase": "attention"},
        events=events,
    ))
    snapshot = queued.input["scopeSnapshot"]
    manifest = {
        "schema": "provider-keyed-empty-dns-prebinding-v1",
        "engagementId": snapshot["engagementId"], "coreJobId": scope["coreJobId"],
        "corePlanId": scope["corePlanId"],
        "providerScopeSha256": snapshot["providerScopeSha256"],
        "stateSha256": scope["stateSha256"], "initialJobId": initial.id,
        "initialJournalSha256": job_event_digest(initial.events),
        "domainAssignments": [], "domains": [],
    }
    manifest["manifestSha256"] = "sha256:" + teardown._fingerprint(manifest)
    snapshot = {**snapshot, "dnsCleanupManifest": manifest}
    snapshot["snapshotId"] = teardown._fingerprint({
        key: value for key, value in snapshot.items() if key != "snapshotId"})
    queued = jobs.save(replace(
        queued, input={**queued.input, "scopeSnapshot": snapshot},
        events=[JobEvent(1, "info", "engagement teardown queued",
                         {"snapshotId": snapshot["snapshotId"]})],
    ))

    def auditor(core_id, **kwargs):
        assert core_id == scope["coreJobId"]
        assert kwargs["confirmed_scope"] == scope
        assert kwargs["confirmed_scope_sha256"] == teardown._fingerprint(snapshot)
        return SimpleNamespace(parent_job_id=initial.id, command_count=command_count)

    options["handoff_auditor"] = auditor
    return queued, initial


@pytest.mark.parametrize("count,accepted", [(0, True), (2, True), (8, True), (1, False)])
def test_failed_prebinding_sealed_source_accepts_only_audited_terminal_counts(
    tmp_path, monkeypatch, count, accepted,
):
    jobs, queued, scope, _plans, options, calls, _workspace = _prepared(tmp_path, monkeypatch)
    queued, _initial = _failed_prebinding_boundary(jobs, queued, scope, options, count)
    if accepted:
        result = service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
        assert result.status == "succeeded" and calls.count("preview") == 1
    else:
        with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError):
            service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
        assert "preview" not in calls
        assert not any(row.action == service.ACTION for row in jobs.list())


def test_failed_prebinding_initial_journal_drift_vetoes_destroy_preview(tmp_path, monkeypatch):
    jobs, queued, scope, _plans, options, calls, _workspace = _prepared(tmp_path, monkeypatch)
    queued, initial = _failed_prebinding_boundary(jobs, queued, scope, options, 8)
    jobs.save(replace(initial, events=[*initial.events, JobEvent(
        len(initial.events) + 1, "info", "unreviewed evidence", {})]))
    with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError):
        service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    assert "preview" not in calls


def test_one_deterministic_full_state_preview_child_and_no_replay(tmp_path, monkeypatch):
    jobs, queued, scope, plans, options, calls, workspace = _prepared(tmp_path, monkeypatch)
    completed = service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    assert completed.id == "job-provider-keyed-initial-destroy-plan-core"
    assert completed.status == "succeeded" and completed.action == service.ACTION
    assert completed.requested_by == "teardown-operator"
    assert completed.artifact_refs == [str(workspace.path / ".barragan-initial-destroy.tfplan")]
    assert completed.events[-1].data["providerScopeSha256"] == queued.input["scopeSnapshot"]["providerScopeSha256"]
    assert "failureStage" not in completed.events[-1].data
    assert completed.input["mutation"] is True and "claimToken" not in completed.input
    assert [event.data.get("phase") for event in completed.events
            if event.message == "provider destroy preview command result fenced"] == [
                "version", "init", "plan", "show"]
    assert len([event for event in completed.events
                if event.message == "provider destroy preview command started before GO"]) == 4
    assert "fixture-token" not in str(completed.events)
    assert calls[0][0] == "state" and calls[-1][0] == "state"
    assert calls.count("preview") == 1
    assert not (workspace.path.parents[1] / ".plan-material" / "digitalocean" / "admin-public").exists()
    assert plans.lease == (scope["corePlanId"], "provider_keyed_teardown_fence")
    with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError):
        service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    assert calls.count("preview") == 1


def test_published_source_selects_sealed_pre_go_audit_before_preview(tmp_path, monkeypatch):
    jobs, queued, scope, plans, options, calls, _workspace = _prepared(tmp_path, monkeypatch)
    published = jobs.save(replace(queued, input={**queued.input, "publishedSource": {"sealed": True}}))
    audited = []

    def source(parent_id, **kwargs):
        audited.append((parent_id, kwargs["phase"]))
        return SimpleNamespace(
            variant="published", core_job_id=scope["coreJobId"],
            core_plan_id=scope["corePlanId"],
            snapshot_id=published.input["scopeSnapshot"]["snapshotId"],
            provider_scope_sha256=published.input["scopeSnapshot"]["providerScopeSha256"],
        )

    monkeypatch.setattr(service, "load_keyed_teardown_source", source)
    options["handoff_auditor"] = lambda *_a, **_kw: pytest.fail("pending handoff audited")
    child = service.run_digitalocean_initial_destroy_plan_job(published.id, **options)
    assert child.status == "succeeded" and calls.count("preview") == 1
    assert len(audited) >= 3 and set(audited) == {(published.id, "pre_go")}


def test_published_source_drift_vetoes_before_child(tmp_path, monkeypatch):
    jobs, queued, scope, _plans, options, calls, _workspace = _prepared(tmp_path, monkeypatch)
    published = jobs.save(replace(queued, input={**queued.input, "publishedSource": {"sealed": True}}))
    monkeypatch.setattr(service, "load_keyed_teardown_source", lambda *_a, **_kw: SimpleNamespace(
        variant="published", core_job_id=scope["coreJobId"], core_plan_id=scope["corePlanId"],
        snapshot_id="changed", provider_scope_sha256=published.input["scopeSnapshot"]["providerScopeSha256"],
    ))
    with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError):
        service.run_digitalocean_initial_destroy_plan_job(published.id, **options)
    assert "preview" not in calls
    assert not any(row.action == service.ACTION for row in jobs.list())


def test_published_source_change_after_child_start_stops_before_terraform(tmp_path, monkeypatch):
    jobs, queued, scope, _plans, options, calls, _workspace = _prepared(tmp_path, monkeypatch)
    published = jobs.save(replace(queued, input={**queued.input, "publishedSource": {"sealed": True}}))
    audits = [0]

    def source(_parent_id, **_kwargs):
        audits[0] += 1
        return SimpleNamespace(
            variant="published", core_job_id=scope["coreJobId"], core_plan_id=scope["corePlanId"],
            snapshot_id=(published.input["scopeSnapshot"]["snapshotId"]
                         if audits[0] == 1 else "changed"),
            provider_scope_sha256=published.input["scopeSnapshot"]["providerScopeSha256"],
        )

    monkeypatch.setattr(service, "load_keyed_teardown_source", source)
    with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError):
        service.run_digitalocean_initial_destroy_plan_job(published.id, **options)
    assert audits == [2] and "preview" not in calls
    assert jobs.get("job-provider-keyed-initial-destroy-plan-core").status == "failed"


@pytest.mark.parametrize("drift", ["snapshot", "scope", "lease", "handoff", "input", "credential"])
def test_drift_blocks_before_preview(tmp_path, monkeypatch, drift):
    jobs, queued, scope, plans, options, calls, _workspace = _prepared(tmp_path, monkeypatch)
    if drift == "snapshot":
        jobs.save(replace(queued, input={**queued.input, "scopeSnapshot": {
            **queued.input["scopeSnapshot"], "engagementName": "changed"}}))
    elif drift == "scope":
        options["scope_builder"] = lambda *_a, **_kw: {**scope, "selectorTag": "changed"}
    elif drift == "lease":
        plans.lease = (scope["corePlanId"], "provider_keyed_initial")
    elif drift == "handoff":
        parent = next(row for row in jobs.list() if row.input.get("phase") == "teardown_handoff_pending")
        jobs.save(replace(parent, input={**parent.input, "phase": "attention"}))
    elif drift == "input":
        original = options["applied_reader"]
        options["applied_reader"] = lambda *a, **kw: (
            lambda i, w, e, j: (i, w, {**e, "inputSha256": [["/wrong/inputs.json", "d" * 64]]}, j)
        )(*original(*a, **kw))
    else:
        original = options["applied_reader"]
        options["applied_reader"] = lambda *a, **kw: (
            lambda i, w, e, j: (i, w, {**e, "providerConnectionId": "changed"}, j)
        )(*original(*a, **kw))
    with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError):
        service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    assert "preview" not in calls
    assert not any(row.action == service.ACTION for row in jobs.list())


def test_preview_failure_is_terminal_without_destroy_or_phase_change(tmp_path, monkeypatch):
    jobs, queued, _scope, _plans, options, calls, workspace = _prepared(tmp_path, monkeypatch)
    phase = workspace.path / ".barragan-apply-phase.json"
    phase.write_text('{"schema":"provider-keyed-v2","phase":"applied"}')
    def failing_preview(*_args, **_kwargs):
        assert (workspace.path.parents[1] / ".plan-material" / "digitalocean" / "admin-public").is_file()
        raise ValueError("secret provider output")
    options["preview"] = failing_preview
    with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError) as error:
        service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    assert "secret" not in str(error.value)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "failed" and child.artifact_refs == []
    assert child.events[-1].data == {"failureStage": "other"}
    assert phase.read_text() == '{"schema":"provider-keyed-v2","phase":"applied"}'
    assert "preview" not in calls
    assert not (workspace.path.parents[1] / ".plan-material" / "digitalocean" / "admin-public").exists()


@pytest.mark.parametrize("stage", [
    "plan_integrity", "exact_delete", "topology_variables", "unchanged_inputs",
])
def test_redacted_helper_stage_is_saved_in_existing_terminal_event(tmp_path, monkeypatch, stage):
    jobs, queued, _scope, _plans, options, _calls, workspace = _prepared(tmp_path, monkeypatch)

    def failing_preview(*_args, **_kwargs):
        raise helper.ProviderKeyedTeardownPreviewError(
            "secret provider response", stage=stage,
        )

    options["preview"] = failing_preview
    with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError) as error:
        service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "failed" and child.artifact_refs == []
    assert child.events[-1].message == "provider destroy preview stopped; reconciliation required"
    assert child.events[-1].data == {"failureStage": stage}
    assert "secret" not in str(error.value) + str(child.events)
    assert not (workspace.path.parents[1] / ".plan-material" / "digitalocean" / "admin-public").exists()
    with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError):
        service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    assert len([row for row in jobs.list() if row.action == service.ACTION]) == 1


def test_exact_delete_predicate_is_bounded_in_failed_child_and_never_replayed(
    tmp_path, monkeypatch,
):
    jobs, queued, _scope, _plans, options, _calls, workspace = _prepared(
        tmp_path, monkeypatch)
    calls = []

    def rejected_preview(*_args, **_kwargs):
        calls.append("preview")
        raise helper.ProviderKeyedTeardownPreviewError(
            "secret Terraform JSON at digitalocean_droplet.edge", stage="exact_delete",
            predicate_category="action_before",
        )

    options["preview"] = rejected_preview
    with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError):
        service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "failed" and child.artifact_refs == []
    assert child.events[-1].data == {
        "failureStage": "exact_delete", "predicateCategory": "action_before",
    }
    assert "secret" not in str(child.events)
    with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError):
        service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    assert calls == ["preview"]
    assert not (workspace.path.parents[1] / ".plan-material" / "digitalocean" / "admin-public").exists()


def test_durable_public_key_drift_blocks_preview_and_staging(tmp_path, monkeypatch):
    jobs, queued, _scope, _plans, options, calls, workspace = _prepared(tmp_path, monkeypatch)
    monkeypatch.setattr(service, "retrieve_sketch_ssh_key", lambda *_args: SimpleNamespace(
        public_key="ssh-ed25519 rotated\n"))
    with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError):
        service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "failed" and child.artifact_refs == []
    assert "preview" not in calls
    assert not (workspace.path.parents[1] / ".plan-material" / "digitalocean" / "admin-public").exists()


def test_public_key_cleanup_uncertainty_is_explicit_and_never_replayed(tmp_path, monkeypatch):
    jobs, queued, _scope, _plans, options, calls, workspace = _prepared(tmp_path, monkeypatch)
    monkeypatch.setattr(service, "_remove_owned_public_key", lambda *_args: (_ for _ in ()).throw(OSError("unlink failed")))
    with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError):
        service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "running" and child.artifact_refs == []
    assert "cleanup unproved" in child.events[-1].message
    assert calls.count("preview") == 1


@pytest.mark.parametrize("uncertainty", ["unreaped", "result_audit"])
def test_started_without_durable_result_retains_public_and_running_claim(
    tmp_path, monkeypatch, uncertainty,
):
    jobs, queued, _scope, _plans, options, calls, workspace = _prepared(tmp_path, monkeypatch)
    original = options["gated_command_runner"]

    def uncertain_gate(args, **kwargs):
        if uncertainty == "result_audit":
            def reject_result(_value):
                raise RuntimeError("secret provider output")
            return original(args, **{**kwargs, "result_callback": reject_result})
        intent = CommandIntent("uncertain-1", str(kwargs["scratch_path"]), "a" * 64)
        kwargs["intent_callback"](intent)
        started = StartedCommand(intent, ProcessIdentity(
            "11111111-1111-4111-8111-111111111111", 9001, 9001, 1))
        kwargs["started_callback"](started)
        raise UnreapedGatedCommandError("unknown process group")

    options["gated_command_runner"] = uncertain_gate
    with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError) as error:
        service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    assert "secret" not in str(error.value)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "running" and child.input["claimToken"]
    assert child.events[-1].message == "provider destroy preview command started before GO"
    assert not any(event.message == "provider destroy preview command result fenced" for event in child.events)
    assert (workspace.path.parents[1] / ".plan-material" / "digitalocean" / "admin-public").is_file()
    assert calls.count("preview") == 1
    with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError):
        service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    assert calls.count("preview") == 1


def test_retagged_core_lease_drift_during_command_blocks_spawn_and_replay(tmp_path, monkeypatch):
    jobs, queued, scope, plans, options, calls, workspace = _prepared(tmp_path, monkeypatch)
    original = options["gated_command_runner"]

    def drift_before_intent(args, **kwargs):
        plans.lease = (scope["corePlanId"], "provider_keyed_initial")
        return original(args, **kwargs)

    options["gated_command_runner"] = drift_before_intent
    with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError):
        service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "running" and child.input["claimToken"]
    assert child.events[-1].message == "provider destroy preview staging intended"
    assert not any(event.message == "provider destroy preview command started before GO"
                   for event in child.events)
    assert (workspace.path.parents[1] / ".plan-material" / "digitalocean" / "admin-public").is_file()
    assert calls.count("preview") == 1
    with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError):
        service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    assert calls.count("preview") == 1


def test_sqlalchemy_style_timestamp_normalization_does_not_block_child(tmp_path, monkeypatch):
    jobs, queued, _scope, _plans, options, calls, _workspace = _prepared(tmp_path, monkeypatch)
    original_save_if_absent = jobs.save_if_absent

    def normalized_save(job):
        # SQLAlchemy's SQLite DateTime round-trip omits the original UTC suffix.
        return original_save_if_absent(replace(job, created_at=job.created_at.replace("+00:00", "")))

    jobs.save_if_absent = normalized_save
    assert service.run_digitalocean_initial_destroy_plan_job(queued.id, **options).status == "succeeded"
    assert calls.count("preview") == 1


def test_scope_drift_after_plan_leaves_failed_child_and_no_authorized_artifact(tmp_path, monkeypatch):
    jobs, queued, scope, _plans, options, calls, workspace = _prepared(tmp_path, monkeypatch)
    reads = 0

    def scope_drift(*_args, **_kwargs):
        nonlocal reads
        reads += 1
        return scope if reads < 4 else {**scope, "selectorTag": "changed"}

    options["scope_builder"] = scope_drift
    with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError):
        service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "failed" and child.artifact_refs == []
    assert calls.count("preview") == 1
    assert (workspace.path / ".barragan-initial-destroy.tfplan").exists()
    with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError):
        service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    assert calls.count("preview") == 1


def test_mismatched_saved_plan_digest_cannot_become_reviewed_artifact(tmp_path, monkeypatch):
    jobs, queued, _scope, _plans, options, calls, workspace = _prepared(tmp_path, monkeypatch)
    original_preview = options["preview"]

    def wrong_digest(*args, **kwargs):
        return replace(original_preview(*args, **kwargs), plan_sha256="0" * 64)

    options["preview"] = wrong_digest
    with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError):
        service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    child = next(row for row in jobs.list() if row.action == service.ACTION)
    assert child.status == "failed" and child.artifact_refs == []
    assert child.events[-1].data == {"failureStage": "post_preview_evidence"}
    assert calls.count("preview") == 1
    assert (workspace.path / ".barragan-initial-destroy.tfplan").is_file()


@pytest.mark.parametrize("uncertainty", [None, "result_audit", "unreaped"])
def test_controller_composes_real_staging_helper_with_fenced_fake_commands(
    tmp_path, monkeypatch, uncertainty,
):
    """No network: real helper stages files, while the gated command is synthetic."""
    jobs, queued, scope, _plans, options, calls, raw_workspace = _prepared(tmp_path, monkeypatch)
    root = raw_workspace.path
    data_dir = root / ".terraform-data"
    data_dir.mkdir(mode=0o700, exist_ok=True)
    data_dir.chmod(0o700)
    real_workspace = ProviderKeyedWorkspace(
        root, root / "terraform.tfstate", data_dir, "provider-keyed-v2", "digitalocean",
        raw_workspace.provider_connection_id, root.name,
        raw_workspace.source_revision, raw_workspace.source_sha256,
    )
    for name, content in (
        (".barragan-provider-keyed-state.json", "{}"),
        (".terraform.lock.hcl", 'provider "registry.terraform.io/digitalocean/digitalocean" { version = "2.103.0" }'),
        (".barragan-topology.json", "{}"),
        (".barragan-initial-full-plan.lock", ""),
    ):
        path = root / name
        path.write_text(content)
        path.chmod(0o600)
    old_reader = options["applied_reader"]
    inputs = root.parents[1] / ".plan-material" / "digitalocean" / "inputs.json"
    input_sha = hashlib.sha256(inputs.read_bytes()).hexdigest()
    binary_sha = hashlib.sha256(Path("/usr/bin/true").resolve().read_bytes()).hexdigest()

    def read_applied(*args, **kwargs):
        intent, _workspace, evidence, apply_job = old_reader(*args, **kwargs)
        return intent, real_workspace, {
            **evidence, "inputSha256": [[str(inputs), input_sha]],
            "terraformBinarySha256": binary_sha,
            "markerSha256": hashlib.sha256((root / ".barragan-provider-keyed-state.json").read_bytes()).hexdigest(),
            "lockfileSha256": hashlib.sha256((root / ".terraform.lock.hcl").read_bytes()).hexdigest(),
        }, apply_job

    options["applied_reader"] = read_applied
    options["release_check"] = lambda **_kw: SimpleNamespace(
        path=Path("/usr/bin/true").resolve(), sha256=binary_sha,
    )
    options["preview"] = helper.prepare_digitalocean_keyed_initial_teardown_preview
    monkeypatch.setattr(helper, "_verify_audited_workspace", lambda _ws: None)
    monkeypatch.setattr(helper, "_ordinal_lock", lambda _ws: nullcontext())
    monkeypatch.setattr(helper, "_require_nodes_match_topology", lambda *_args: None)
    monkeypatch.setattr(helper, "_require_plan_topology_variables", lambda *_args: None)
    monkeypatch.setattr(helper, "_require_unchanged", lambda *_args: None)
    monkeypatch.setattr(helper, "_topology_hash", lambda _ws: "d" * 64)
    monkeypatch.setattr(helper, "_credential_snapshot", lambda *_args: (
        "f" * 64, "2026-10-08T00:00:00Z", "encrypted-fixture"))
    monkeypatch.setattr(helper, "decrypt_secret_value", lambda _value: "opaque-test-token")
    reviewed, _workspace, _evidence, _apply = read_applied()
    ids = {item["address"]: item["id"] for item in scope["resources"]}
    state_resources = []
    prior = []
    changes = []
    for address, resource_id in ids.items():
        base, _, encoded_key = address.partition("[")
        kind, name = base.split(".", 1)
        values = {"id": resource_id}
        instance = {"attributes": values}
        if encoded_key:
            instance["index_key"] = json.loads("[" + encoded_key)[0]
        state_resources.append({"mode": "managed", "type": kind, "name": name,
                                "instances": [instance]})
        prior.append({"address": address, "mode": "managed", "values": values})
        changes.append({"address": address, "change": {
            "actions": ["delete"], "before": values, "after": None, "after_unknown": {},
        }})
    state = {"resources": state_resources}
    plan_json = json.dumps({
        "format_version": "1.2", "terraform_version": "1.15.5", "applyable": True,
        "complete": True, "errored": False,
        "prior_state": {"values": {"root_module": {"resources": prior}}},
        "planned_values": {"root_module": {}}, "resource_changes": changes,
    })
    monkeypatch.setattr(helper, "_require_exact_state", lambda _ws, _intent: state)
    original_gate = options["gated_command_runner"]
    phases = []

    def gate(args, **kwargs):
        phases.append(args[1])
        if args[1] == "plan":
            Path(next(arg.split("=", 1)[1] for arg in args if arg.startswith("-out="))).write_bytes(b"saved")
            if uncertainty == "result_audit":
                def reject_result(_value):
                    raise RuntimeError("secret transport output")
                return original_gate(args, **{**kwargs, "result_callback": reject_result})
            if uncertainty == "unreaped":
                intended = CommandIntent("plan-unreaped", str(kwargs["scratch_path"]), "b" * 64)
                kwargs["intent_callback"](intended)
                started = StartedCommand(intended, ProcessIdentity(
                    "11111111-1111-4111-8111-111111111111", 8123, 8123, 1))
                kwargs["started_callback"](started)
                raise UnreapedGatedCommandError("process group unproved")
        result = original_gate(args, **kwargs)
        if args[1] == "show":
            return replace(result, stdout=plan_json)
        return result

    options["gated_command_runner"] = gate
    if uncertainty is not None:
        with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError) as error:
            service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
        assert "secret" not in str(error.value)
        child = next(row for row in jobs.list() if row.action == service.ACTION)
        assert child.status == "running" and child.input["claimToken"]
        assert phases == ["version", "init", "plan"]
        assert child.events[-1].message == "provider destroy preview command started before GO"
        staging_event = next(event for event in child.events
                             if event.message == "provider destroy preview staging intended")
        assert (Path(staging_event.data["stagingPath"]) / "credential.json").is_file()
        assert Path(staging_event.data["publicKeyPath"]).is_file()
        assert Path(staging_event.data["planPath"]).is_file()
        with pytest.raises(service.ProviderKeyedInitialDestroyPlanJobError):
            service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
        assert phases == ["version", "init", "plan"]
        return
    completed = service.run_digitalocean_initial_destroy_plan_job(queued.id, **options)
    assert completed.status == "succeeded" and phases == ["version", "init", "plan", "show"]
    staging_event = next(event for event in completed.events
                         if event.message == "provider destroy preview staging intended")
    assert not Path(staging_event.data["stagingPath"]).exists()
    assert not Path(staging_event.data["publicKeyPath"]).exists()
    assert Path(staging_event.data["planPath"]).is_file()
    assert "opaque-test-token" not in str(completed.events)
