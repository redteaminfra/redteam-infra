# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted failed-prebinding review, handoff, and checkpoint regression."""

from dataclasses import replace
import hashlib
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services import provider_keyed_saved_plan_runner as terraform_runner
from app.services import provider_keyed_initial_plan_job as initial_plan_job
from app.services import provider_keyed_initial_apply as initial_apply
from app.services import provider_keyed_planned_state_preflight as planned_preflight
from app.services import provider_keyed_comprehensive_teardown as coordinator_service
from app.services.engagement_teardown import (
    _current_scope_snapshot, _fingerprint, preview_engagement_teardown,
    start_engagement_teardown,
)
from app.services.provider_keyed_comprehensive_teardown import run_provider_keyed_comprehensive_handoff
from app.services.provider_keyed_dns_cleanup_checkpoint import (
    ProviderKeyedDnsCleanupCheckpointError, prove_provider_keyed_dns_cleanup_checkpoint,
)
from app.services.provider_keyed_destroy_absence_preflight import _MESSAGES
from app.services import provider_keyed_destroy_absence_preflight as destroy_preflight
from app.services import provider_keyed_teardown_quiescence as quiescence
from app.services.provider_keyed_dns_cleanup_manifest import (
    ProviderKeyedDnsCleanupManifestError, build_provider_keyed_dns_cleanup_manifest,
)
from app.services.provider_keyed_initial_apply_job import run_fresh_digitalocean_initial_apply_job
from app.services.provider_keyed_initial_continuation import _job_ids, start_fresh_digitalocean_initial_continuation
from app.services.provider_keyed_initial_plan_job import _expected_inventory, _local_file
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, preflight_fresh_digitalocean_provider
from app.services.provider_keyed_pending_dispatch import (
    recover_pending_keyed_dispatches, require_prequeue_pending_diagnostic,
)
from app.services.provider_keyed_pending_cleanup import (
    PendingKeyedCleanupAttention, advance_pending_keyed_cleanup_to_preview,
)
from app.services.provider_keyed_teardown_quiescence import (
    ProviderKeyedTeardownQuiescenceError, audit_failed_prebinding_provider_bootstrap,
    audit_pending_provider_keyed_bootstrap,
)
from app.services.provider_keyed_teardown_source import (
    ProviderKeyedTeardownSourceError, load_keyed_teardown_source,
)
from app.domain import JobEvent
from app.services.provider_keyed_terraform_release import (
    ProviderKeyedTerraformRelease, _REVIEWED_SHA256,
)
from app.storage.database import db
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.models import JobRunModel
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from test_provider_keyed_canonical_pending_generation import (
    _EmptySelectorCatalog, _SelectorPost, _applied_state, _gated_terraform,
    _seed_reviewed_generation, _shown_plan,
)
from app.services.sketch_ssh_keys import ensure_sketch_ssh_key, retrieve_sketch_ssh_key
from app.storage.sketch_ssh_key_repository import SqlAlchemySketchSshKeyRepository


def test_failed_after_provider_apply_previews_and_fences_one_teardown(tmp_path, monkeypatch):
    state, state_root, upstream, engagement_id, core_id, plan_id, credential_id = (
        _seed_reviewed_generation(tmp_path, monkeypatch, core_known_hosts=True)
    )
    release = ProviderKeyedTerraformRelease(
        Path("/usr/bin/terraform"), _REVIEWED_SHA256, "1.15.5", "linux_amd64")
    monkeypatch.setattr(initial_plan_job, "require_devtest_terraform_release",
                        lambda **_kw: release)
    original_hash = terraform_runner._hash_file
    monkeypatch.setattr(terraform_runner, "_resolve_terraform",
                        lambda *_a, **_kw: release.path)
    monkeypatch.setattr(terraform_runner, "_hash_file",
                        lambda path: release.sha256 if Path(path) == release.path else original_hash(path))
    monkeypatch.setattr(planned_preflight, "_binary_digest",
                        lambda path: release.sha256 if Path(path) == release.path else original_hash(path))
    monkeypatch.setattr(initial_apply, "_hash_file",
                        lambda path: release.sha256 if Path(path) == release.path else original_hash(path))
    original_access = os.access
    monkeypatch.setattr(initial_apply.os, "access",
                        lambda path, mode: True if Path(path) == release.path else original_access(path, mode))
    with db.bind(state):
        intent = preflight_fresh_digitalocean_provider(
            engagement_id, core_id, lease_owner=plan_id,
            environment="devtest", state_root=state_root,
        )
        keys = SqlAlchemySketchSshKeyRepository()
        ensure_sketch_ssh_key(engagement_id, keys)
        material = retrieve_sketch_ssh_key(engagement_id, keys)
        import hashlib
        fingerprint = hashlib.sha256(f"digitalocean\0{credential_id}".encode()).hexdigest()
        workspace_path = state_root / engagement_id / "provider-keyed-v2" / "digitalocean" / fingerprint
        private = workspace_path.parents[1] / ".plan-material" / "digitalocean" / "admin-private"
        output = private.parent / "ssh-output"
        local_files = {
            "local_file.ansible_inventory[0]": _local_file(
                "inventory.ini", _expected_inventory(intent, private)),
            "local_file.ssh_stanza[0]": _local_file(
                str(output / f"{intent.engagement_name}-sketch"), None),
        }
        shown = json.dumps(_shown_plan(intent, None, material.public_key, local_files))
        commands = []

        def terraform_command(args, cwd, env):
            assert cwd == workspace_path and args[0] == "/usr/bin/terraform"
            phase = args[1]
            commands.append(phase)
            if phase == "version":
                return subprocess.CompletedProcess(args, 0, '{"terraform_version":"1.15.5"}', "")
            if phase == "plan":
                plan_path = Path(next(arg.split("=", 1)[1] for arg in args if arg.startswith("-out=")))
                plan_path.write_bytes(b"opaque reviewed binary plan fixture")
            return subprocess.CompletedProcess(args, 0, shown if phase == "show" else "", "")

        monkeypatch.setattr(terraform_runner, "_run_command", terraform_command)
        gated, apply_commands = _gated_terraform(shown, _applied_state(intent))

        def apply_writer(job_id, **kwargs):
            def live_regions(base_url, method, path, token):
                assert (base_url, method, path, token) == (
                    "https://api.digitalocean.com/v2", "GET", "/regions?per_page=200",
                    "fixture-token")
                return {"regions": [{"slug": region, "available": True,
                                     "sizes": sorted({node.size for node in intent.nodes.values()
                                                      if node.region == region})}
                                    for region in sorted({node.region for node in intent.nodes.values()})],
                        "links": {}, "meta": {"total": len({node.region for node in intent.nodes.values()})}}
            return run_fresh_digitalocean_initial_apply_job(
                job_id, **kwargs,
                selector_transport=_EmptySelectorCatalog(intent.selector_tag),
                selector_reservation_transport=_SelectorPost(),
                gated_command_runner=gated, release_check=lambda **_kw: release,
                catalog_transport=SimpleNamespace(request=live_regions),
            )

        parent = start_fresh_digitalocean_initial_continuation(
            core_id, environment="devtest", state_root=state_root, template_root=upstream,
            apply_runner=apply_writer,
            attachment_reconciler=lambda *_a, **_kw: (_ for _ in ()).throw(ValueError("fixture attachment unavailable")),
        )
        jobs = SqlAlchemyJobRepository()
        initial_id, plan_child_id, apply_child_id = _job_ids(core_id)
        assert parent.id == initial_id and parent.status == "failed"
        assert [jobs.get(row).status for row in (plan_child_id, apply_child_id)] == [
            "succeeded", "succeeded"]
        assert commands == ["version", "init", "plan", "show"]
        assert apply_commands == ["show", "apply"]

        applied_resources = _applied_state(intent)["resources"]
        firewall_id = next(row["instances"][0]["attributes"]["id"]
                           for row in applied_resources if row["type"] == "digitalocean_firewall")
        droplet_ids = [instance["attributes"]["id"]
                       for row in applied_resources if row["type"] == "digitalocean_droplet"
                       for instance in row["instances"]]
        attachment = JobEvent(8, "info", "provider attachment proven; host proof pending", {
            "stateSha256": hashlib.sha256((workspace_path / "terraform.tfstate").read_bytes()).hexdigest(),
            "firewallId": firewall_id, "verifiedDropletIds": droplet_ids,
            "attempts": 1, "providerMembershipVerified": True, "hostProofPending": True,
        })
        nine_event_parent = jobs.save(replace(parent, events=[
            *parent.events[:-1], attachment,
            JobEvent(9, "error", "host identity binding stopped; reconciliation required", {}),
        ]))
        assert preview_engagement_teardown(core_id)["snapshotId"]
        scope = _current_scope_snapshot(
            jobs.get(core_id), jobs=jobs, chains=SqlAlchemySketchChainRepository(),
            resources=SqlAlchemyProviderResourceRepository(), inspector_state_reader=None,
        )["providerScopes"][0]
        assert audit_failed_prebinding_provider_bootstrap(
            core_id, confirmed_scope=scope, workspace_root=workspace_path,
            job_repository=jobs,
        ).command_count == 0
        known_hosts = workspace_path / ".barragan-sketch-known-hosts"
        known_hosts.touch()
        with pytest.raises(ProviderKeyedTeardownQuiescenceError):
            audit_failed_prebinding_provider_bootstrap(
                core_id, confirmed_scope=scope, workspace_root=workspace_path,
                job_repository=jobs,
            )
        known_hosts.unlink()
        scratch = workspace_path / (".barragan-sketch-bootstrap-" + "a" * 32)
        scratch.mkdir()
        with pytest.raises(ProviderKeyedTeardownQuiescenceError):
            audit_failed_prebinding_provider_bootstrap(
                core_id, confirmed_scope=scope, workspace_root=workspace_path,
                job_repository=jobs,
            )
        scratch.rmdir()
        proof_child_id = f"job-provider-keyed-initial-host-proof-{core_id.removeprefix('job-')}"
        jobs.save(replace(nine_event_parent, id=proof_child_id))
        with pytest.raises(ProviderKeyedTeardownQuiescenceError):
            audit_failed_prebinding_provider_bootstrap(
                core_id, confirmed_scope=scope, workspace_root=workspace_path,
                job_repository=jobs,
            )
        db.session.delete(db.session.get(JobRunModel, proof_child_id))
        db.session.commit()
        for altered in (
            replace(attachment, data={**attachment.data, "firewallId": "wrong"}),
            replace(attachment, data={**attachment.data, "verifiedDropletIds": ["wrong"]}),
            replace(attachment, message="unreviewed attachment result"),
        ):
            jobs.save(replace(nine_event_parent, events=[
                *nine_event_parent.events[:7], altered, nine_event_parent.events[-1],
            ]))
            with pytest.raises(ProviderKeyedTeardownQuiescenceError):
                audit_failed_prebinding_provider_bootstrap(
                    core_id, confirmed_scope=scope, workspace_root=workspace_path,
                    job_repository=jobs,
                )
        jobs.save(parent)

        preview = preview_engagement_teardown(core_id)
        assert preview["snapshotId"]
        core = jobs.get(core_id)
        snapshot = _current_scope_snapshot(
            core, jobs=jobs, chains=SqlAlchemySketchChainRepository(),
            resources=SqlAlchemyProviderResourceRepository(), inspector_state_reader=None)
        assert snapshot["snapshotId"] == preview["snapshotId"]
        require_prequeue_pending_diagnostic(
            core, snapshot, environment="devtest", state_root=state_root,
            job_repository=jobs)
        reviewed = start_engagement_teardown(
            core_id, {"confirmation": preview["confirmationPhrase"],
                      "snapshotId": preview["snapshotId"]},
            provider_keyed_environment="devtest",
            provider_keyed_coordinator=lambda parent_id: run_provider_keyed_comprehensive_handoff(
                parent_id, environment="devtest", state_root=state_root),
        )
        assert reviewed.status == "queued"
        assert reviewed.input["scopeSnapshot"]["dnsCleanupManifest"]["schema"] == "provider-keyed-empty-dns-prebinding-v1"
        assert reviewed.input["scopeSnapshot"]["dnsCleanupManifest"]["domains"] == []
        assert jobs.get(initial_id) == parent
        assert _db_lease_lookup(engagement_id) == (plan_id, "provider_keyed_teardown_fence")
        scheduled = []
        assert recover_pending_keyed_dispatches(
            environment="devtest", state_root=state_root,
            positive_control_ipv4="4.2.2.2",
            schedule=lambda parent_id, delay: scheduled.append((parent_id, delay)),
            job_repository=jobs,
        ) == [reviewed.id]
        assert len(scheduled) == 1 and scheduled[0][0] == reviewed.id
        coordinator_id = ("job-provider-keyed-comprehensive-teardown-"
                          + core_id.removeprefix("job-"))
        awaiting = jobs.get(coordinator_id)
        ready = replace(
            awaiting, input={**awaiting.input, "phase": "inspector_ready"},
            events=[*awaiting.events, JobEvent(5, "info", "retained_inspector_ready", {})],
        )
        jobs.save(ready)
        ready_reads = []

        def read_ready(parent_id, **kwargs):
            ready_reads.append(parent_id)
            assert kwargs["environment"] == "devtest"
            assert kwargs["job_repository"] is jobs
            assert jobs.get(coordinator_id) == ready
            return SimpleNamespace(coordinator_job_id=coordinator_id)

        monkeypatch.setattr(coordinator_service, "recognize_retained_keyed_inspector_ready",
                            read_ready)
        assert load_keyed_teardown_source(
            reviewed.id, phase="pre_go", environment="devtest", state_root=state_root,
            job_repository=jobs, plan_repository=SqlAlchemyDeploymentPlanRepository(),
        ).variant == "failed_prebinding"
        assert ready_reads == [reviewed.id]
        monkeypatch.setattr(coordinator_service, "recognize_retained_keyed_inspector_ready",
                            lambda *_a, **_kw: (_ for _ in ()).throw(ValueError("ready journal drift")))
        with pytest.raises(ProviderKeyedTeardownSourceError):
            load_keyed_teardown_source(
                reviewed.id, phase="pre_go", environment="devtest", state_root=state_root,
                job_repository=jobs, plan_repository=SqlAlchemyDeploymentPlanRepository(),
            )
        with pytest.raises(PendingKeyedCleanupAttention):
            advance_pending_keyed_cleanup_to_preview(
                reviewed.id, environment="devtest", state_root=state_root,
                job_repository=jobs, plan_repository=SqlAlchemyDeploymentPlanRepository(),
                preview_runner=lambda *_a, **_kw: pytest.fail("preview ran after Inspector veto"),
            )
        monkeypatch.setattr(coordinator_service, "recognize_retained_keyed_inspector_ready",
                            read_ready)
        destroy_preview_id = ("job-provider-keyed-initial-destroy-plan-"
                              + core_id.removeprefix("job-"))
        preview_calls = []

        def reserve_preview(parent_id, **_kwargs):
            preview_calls.append(parent_id)
            assert jobs.get(destroy_preview_id) is None
            assert jobs.get("job-provider-keyed-initial-destroy-apply-"
                            + core_id.removeprefix("job-")) is None
            return jobs.save(replace(
                jobs.get(apply_child_id), id=destroy_preview_id,
                action="provider_keyed_initial_destroy_plan", status="succeeded",
                input={"teardownParentId": parent_id},
            ))

        reached = advance_pending_keyed_cleanup_to_preview(
            reviewed.id, environment="devtest", state_root=state_root,
            job_repository=jobs, plan_repository=SqlAlchemyDeploymentPlanRepository(),
            ready_recognizer=lambda *_a, **_kw: SimpleNamespace(
                coordinator_job_id=coordinator_id),
            preview_runner=reserve_preview,
        )
        assert reached.preview_job_id == destroy_preview_id
        assert preview_calls == [reviewed.id]
        assert jobs.get("job-provider-keyed-initial-destroy-apply-"
                        + core_id.removeprefix("job-")) is None
        db.session.delete(db.session.get(JobRunModel, destroy_preview_id))
        db.session.commit()
        state_before_drift = (workspace_path / "terraform.tfstate").read_bytes()
        (workspace_path / "terraform.tfstate").write_bytes(b"{}")
        with pytest.raises(PendingKeyedCleanupAttention):
            advance_pending_keyed_cleanup_to_preview(
                reviewed.id, environment="devtest", state_root=state_root,
                job_repository=jobs, plan_repository=SqlAlchemyDeploymentPlanRepository(),
                preview_runner=lambda *_a, **_kw: pytest.fail("preview ran after state drift"),
            )
        (workspace_path / "terraform.tfstate").write_bytes(state_before_drift)
        jobs.save(awaiting)
        running_destroy_id = f"job-provider-keyed-initial-destroy-apply-{core_id.removeprefix('job-')}"
        jobs.save(replace(
            jobs.get(apply_child_id), id=running_destroy_id,
            action="provider_keyed_initial_destroy_apply", status="running",
            input={"coreJobId": core_id, "teardownParentId": reviewed.id},
            finished_at=None,
        ))
        phase_path = workspace_path / ".barragan-apply-phase.json"
        applied_marker = phase_path.read_bytes()
        phase_path.write_text(json.dumps({"schema": "provider-keyed-v2",
                                          "phase": "destroy_started"}))
        checkpoint = prove_provider_keyed_dns_cleanup_checkpoint(
            reviewed.input["scopeSnapshot"], job_repository=jobs,
        )
        assert checkpoint["dnsCleanupManifestSha256"] == (
            reviewed.input["scopeSnapshot"]["dnsCleanupManifest"]["manifestSha256"])
        drifted_events = list(parent.events)
        drifted_events[-1] = replace(drifted_events[-1], data={"unexpected": True})
        jobs.save(replace(parent, events=drifted_events))
        with pytest.raises(ProviderKeyedDnsCleanupCheckpointError,
                           match="fresh confirmed DNS cleanup authority is unproved"):
            prove_provider_keyed_dns_cleanup_checkpoint(
                reviewed.input["scopeSnapshot"], job_repository=jobs,
            )
        jobs.save(parent)
        phase_path.write_bytes(applied_marker)
        scope = reviewed.input["scopeSnapshot"]["providerScopes"][0]
        original_state_sha256 = scope["stateSha256"]
        with pytest.raises(ProviderKeyedTeardownQuiescenceError):
            audit_failed_prebinding_provider_bootstrap(
                core_id, confirmed_scope=scope, workspace_root=workspace_path,
                confirmed_scope_sha256=_fingerprint(reviewed.input["scopeSnapshot"]),
                job_repository=jobs,
                post_destroy_state_sha256="0" * 64)
        empty_state = b'{"resources":[]}'
        empty_sha256 = hashlib.sha256(empty_state).hexdigest()
        original_state = (workspace_path / "terraform.tfstate").read_bytes()
        (workspace_path / "terraform.tfstate").write_bytes(empty_state)
        events = [JobEvent(sequence, "info", message, {})
                  for sequence, message in enumerate(_MESSAGES, 1)]
        events[5] = JobEvent(6, "info", _MESSAGES[5], {
            "preDestroyStateSha256": original_state_sha256})
        events[-1] = JobEvent(12, "info", "provider destroy apply completed; absence proof pending", {
            "stateSha256": empty_sha256})
        jobs.save(replace(jobs.get(running_destroy_id), status="succeeded",
                          finished_at="2026-10-10T00:02:00+00:00", events=events))
        assert audit_failed_prebinding_provider_bootstrap(
            core_id, confirmed_scope=scope, workspace_root=workspace_path,
            confirmed_scope_sha256=_fingerprint(reviewed.input["scopeSnapshot"]),
            job_repository=jobs,
            post_destroy_state_sha256=empty_sha256).command_count == 0
        initial_events = list(parent.events)
        initial_events[-1] = replace(initial_events[-1], data={"unexpected": True})
        jobs.save(replace(parent, events=initial_events))
        with pytest.raises(ProviderKeyedTeardownQuiescenceError):
            audit_failed_prebinding_provider_bootstrap(
                core_id, confirmed_scope=scope, workspace_root=workspace_path,
                confirmed_scope_sha256=_fingerprint(reviewed.input["scopeSnapshot"]),
                job_repository=jobs, post_destroy_state_sha256=empty_sha256)
        jobs.save(parent)
        (workspace_path / "terraform.tfstate").write_bytes(b"{}")
        with pytest.raises(ProviderKeyedTeardownQuiescenceError):
            audit_failed_prebinding_provider_bootstrap(
                core_id, confirmed_scope=scope, workspace_root=workspace_path,
                confirmed_scope_sha256=_fingerprint(reviewed.input["scopeSnapshot"]),
                job_repository=jobs, post_destroy_state_sha256=empty_sha256)
        (workspace_path / "terraform.tfstate").write_bytes(original_state)
        base_scope = {key: value for key, value in reviewed.input["scopeSnapshot"].items()
                      if key not in {"snapshotId", "dnsCleanupManifest"}}
        assert build_provider_keyed_dns_cleanup_manifest(
            base_scope, job_repository=jobs) == reviewed.input["scopeSnapshot"]["dnsCleanupManifest"]
        jobs.save(replace(
            jobs.get(apply_child_id), id="job-historical-web-service",
            action="web_static_service_apply", status="failed", input={},
        ))
        with pytest.raises(ProviderKeyedDnsCleanupManifestError):
            build_provider_keyed_dns_cleanup_manifest(
                base_scope, job_repository=jobs)

        # The same persisted pending source must remain auditable after this
        # incident's complete recovered destroy replaces the pre-destroy state.
        # Build an exact eighteen-event journal against the fixture's real
        # parent, snapshot, child rows, saved plan bytes, and empty state.
        preview_id = running_destroy_id.replace("initial-destroy-apply-",
                                                "initial-destroy-plan-", 1)
        plan_path = workspace_path / ".barragan-initial-destroy.tfplan"
        plan_path.write_bytes(b"reviewed incident destroy plan")
        plan_path.chmod(0o600)
        plan_sha256 = hashlib.sha256(plan_path.read_bytes()).hexdigest()
        preview_row = replace(jobs.get(apply_child_id), id=preview_id,
                              action="provider_keyed_initial_destroy_plan",
                              status="succeeded", requested_by=reviewed.requested_by,
                              events=[JobEvent(1, "info", "reviewed provider destroy plan saved", {
                                  "planPath": str(plan_path), "planSha256": plan_sha256,
                                  "terraformBinaryPath": "/usr/bin/true",
                              })])
        jobs.save(preview_row)
        binary = "/usr/bin/true"
        show = [binary, "show", "-json", str(plan_path)]
        apply = [binary, "apply", "-input=false", "-lock=true", "-no-color",
                 str(plan_path)]

        def command_data(phase, invocation, argv, pid):
            digest = hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest()
            return (
                {"phase": phase, "invocationId": invocation, "argvSha256": digest},
                {"phase": phase, "invocationId": invocation, "bootId": "test-boot",
                 "pid": pid, "pgid": pid, "startTicks": 12345},
                {"phase": phase, "invocationId": invocation, "returnCode": 0,
                 "stdoutBytes": 2, "stderrBytes": 0,
                 "stdoutTruncated": False, "stderrTruncated": False},
            )

        old_show = command_data("show", "old-show", show, 101)
        old_apply = command_data("apply", "old-apply", apply, 102)
        new_show = command_data("show", "new-show", show, 103)
        new_apply = command_data("apply", "new-apply", apply, 104)
        phase_path = workspace_path / ".barragan-apply-phase.json"
        data = [{}, {}, *old_show,
                {"preDestroyStateSha256": original_state_sha256},
                {"phase": "destroy_started", "path": str(phase_path)},
                *old_apply[:2]]
        prefix = [JobEvent(index, "info", message, item)
                  for index, (message, item) in enumerate(
                      zip(destroy_preflight._RECOVERY_MESSAGES[:9], data), 1)]
        original_digest = job_event_digest(prefix)
        monkeypatch.setattr(destroy_preflight, "_RECOVERY_ORIGINAL_JOURNAL_SHA256",
                            original_digest)
        monkeypatch.setattr(quiescence, "_INCIDENT_DESTROY_CHILD", running_destroy_id)
        data.extend([
            {"historicalRevision": destroy_preflight._RECOVERY_REVISION,
             "originalJournalSha256": original_digest, "planSha256": plan_sha256},
            *new_show, *new_apply,
            {"phase": "destroy_applied", "path": str(phase_path)},
            {"stateSha256": empty_sha256, "providerAbsenceProofPending": True},
        ])
        recovered_events = [JobEvent(index, "info", message, item)
                            for index, (message, item) in enumerate(
                                zip(destroy_preflight._RECOVERY_MESSAGES, data), 1)]
        snapshot = reviewed.input["scopeSnapshot"]
        recovered_input = {
            "engagementId": core.input["engagementId"], "coreJobId": core_id,
            "corePlanId": core.input["corePlanId"], "teardownParentId": reviewed.id,
            "scopeSnapshotId": snapshot["snapshotId"],
            "providerScopeSha256": snapshot["providerScopeSha256"],
            "destroyPlanJobId": preview_id, "planSha256": plan_sha256,
            "mutation": True,
        }
        recovered = jobs.save(replace(
            jobs.get(running_destroy_id), input=recovered_input,
            requested_by=reviewed.requested_by, events=recovered_events))
        (workspace_path / "terraform.tfstate").write_bytes(empty_state)
        assert running_destroy_id not in quiescence._INCIDENT_DESTROY_CHILDREN
        assert not quiescence._valid_recovered_destroy_journal(
            jobs, recovered, workspace_path, empty_sha256)
        monkeypatch.setattr(quiescence, "_INCIDENT_DESTROY_CHILDREN",
                            frozenset({running_destroy_id}))
        assert quiescence._valid_recovered_destroy_journal(
            jobs, recovered, workspace_path, empty_sha256)
        args = dict(confirmed_scope=scope, confirmed_scope_sha256=_fingerprint(snapshot),
                    workspace_root=workspace_path, job_repository=jobs)
        assert audit_pending_provider_keyed_bootstrap(core_id, **args).command_count == 0
        for field, drift in (("scopeSnapshotId", "0" * 64),
                             ("providerScopeSha256", "0" * 64),
                             ("destroyPlanJobId", "job-other-preview"),
                             ("mutation", False),
                             ("engagementId", "eng-other")):
            jobs.save(replace(recovered, input={**recovered_input, field: drift}))
            with pytest.raises(ProviderKeyedTeardownQuiescenceError):
                audit_pending_provider_keyed_bootstrap(core_id, **args)
            jobs.save(recovered)
        (workspace_path / "terraform.tfstate").write_bytes(b"{}")
        with pytest.raises(ProviderKeyedTeardownQuiescenceError):
            audit_pending_provider_keyed_bootstrap(core_id, **args)
