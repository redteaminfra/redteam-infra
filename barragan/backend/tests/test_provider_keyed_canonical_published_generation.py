# Copyright (c) 2026, Oracle and/or its affiliates.
"""A normally published keyed generation backed by the canonical applied state.

Only Terraform, DigitalOcean GETs, and host command transports are simulated.
Publication and source audit use the real SQLite repository and complete state.
The structured host receipt here is a fixture, not a claim of live collection.
"""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import hashlib
import json
import sys
from uuid import uuid4

import pytest

from app.domain import JobEvent
from app.services.engagement_teardown import (
    _current_scope_snapshot, _fingerprint, _parent_id, preview_engagement_teardown,
    ENGAGEMENT_TEARDOWN_ACTION,
)
from app.services.core_deployment_plans import (
    KEYED_CORE_TERRAFORM_INPUT_FILES, build_keyed_core_terraform_source_manifest,
)
from app.services import provider_keyed_core_destroy_preview as core_destroy_preview
from app.services.provider_keyed_comprehensive_teardown import (
    ProviderKeyedComprehensiveTeardownAttention,
    publish_provider_keyed_destroy_absence, recognize_provider_keyed_destroy_absence,
    retire_provider_keyed_group_after_absence, recognize_provider_keyed_group_retired,
    run_provider_keyed_comprehensive_handoff, run_provider_keyed_destroy_preview_from_ready,
)
from app.services.provider_keyed_chain_projection import project_digitalocean_initial_chains
from app.services.provider_keyed_host_binding import _digest_json
from app.services.provider_keyed_host_proof import HostEvidenceValidation
from app.services.provider_keyed_initial_attachment_adapter import derive_digitalocean_initial_attachment_intent
from app.services.provider_keyed_digitalocean_attachment import reconcile_digitalocean_initial_attachment
from app.services.provider_keyed_postapply_preflight import preflight_applied_digitalocean_provider
from app.services.provider_keyed_initial_destroy_plan_job import run_digitalocean_initial_destroy_plan_job
from app.services.provider_keyed_initial_destroy_apply_job import (
    ProviderKeyedInitialDestroyApplyJobError, preflight_digitalocean_initial_destroy_apply,
    run_digitalocean_initial_destroy_apply_job,
)
from app.services.provider_keyed_teardown_source import (
    ProviderKeyedPostDestroySourceUnavailable, load_keyed_teardown_source,
)
from app.services.provider_keyed_destroy_absence_preflight import (
    ProviderKeyedDestroyAbsencePreflightError,
    reconcile_successful_digitalocean_destroy_absence,
)
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_published_teardown_source import audit_published_provider_keyed_source
from app.services.provider_keyed_oci_core_state import parse_applied_oci_core_state
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_teardown_scope import build_digitalocean_keyed_teardown_scope
from app.storage.database import db
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.domain_repository import SqlAlchemyDomainRepository
from app.storage.provider_resource_repository import (
    SqlAlchemyProviderResourceRepository, StoredProviderResourceRecord,
)
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from test_provider_keyed_canonical_pending_generation import (
    _AbsentCatalog, _AttachmentCatalog, _canonical_applied_generation,
    _destroy_shown_plan,
)
from test_provider_keyed_oci_core_state import _state as _oci_state


def _modeled_sealed_core_artifacts(core, plan, engagement, root):
    """Model a parser-valid OCI state and seal before publication."""
    terraform_root = root / "oci-terraform-state"
    state_dir = terraform_root / engagement.id / "core"
    state_dir.mkdir(parents=True)
    data_dir = state_dir / "data-core-test"
    data_dir.mkdir()
    run_dir = root / "oci-core-run"
    run_dir.mkdir()
    for name in KEYED_CORE_TERRAFORM_INPUT_FILES:
        (run_dir / name).write_text(f"# reviewed fixture: {name}\n")
    public_key = root / "oci-admin.pub"
    public_key.write_text("ssh-ed25519 fixture-core-key\n")
    target = plan.evidence["target"]
    state = _oci_state(proxy_count=2, elk_enabled=False)
    for row in state["resources"]:
        if row["mode"] != "managed":
            continue
        attrs = row["instances"][0]["attributes"]
        attrs["freeform_tags"]["barragan_engagement"] = engagement.name
        if row["type"] != "oci_core_default_dhcp_options":
            attrs["compartment_id"] = target["compartmentId"]
    state_path = state_dir / "terraform.tfstate"
    state_path.write_text(json.dumps(state))
    evidence = {**plan.evidence,
        "proxyCount": 2, "elkEnabled": False,
        "runDirectory": str(run_dir), "terraformDataDir": str(data_dir),
        "terraformStatePath": str(state_path),
        "providerLockFingerprint": hashlib.sha256(
            (run_dir / ".terraform.lock.hcl").read_bytes()).hexdigest(),
        "sshPublicKeyPath": str(public_key),
        "publicKeyFingerprint": hashlib.sha256(public_key.read_bytes()).hexdigest(),
        "keyedCoreTerraformSourceManifest":
            build_keyed_core_terraform_source_manifest(run_dir),
        "terraformFingerprint": "1.15.5",
    }
    inventory = parse_applied_oci_core_state(
        state_path.read_bytes(), proxy_count=2, elk_enabled=False,
        compartment_id=target["compartmentId"], engagement_name=engagement.name,
    )
    seal = {
        "schema": "applied-oci-core-state-v1",
        "corePlanEvidenceSha256": _fingerprint(evidence),
        "rawStateSha256": inventory.raw_state_sha256,
        "inventorySha256": inventory.inventory_sha256,
        "lineage": inventory.lineage, "serial": inventory.serial,
        "resourceCount": len(inventory.resources),
    }
    core = replace(core, input={**core.input, "corePlanEvidenceSha256": _fingerprint(evidence),
                                "elkEnabled": False},
                   events=[*core.events, JobEvent(len(core.events) + 1, "info",
                                                  core_destroy_preview._EVENT, seal),
                           JobEvent(len(core.events) + 2, "info",
                                    "pilot Standard RTI run finished", {})])
    return core, replace(plan, evidence=evidence)


def _exact_oci_destroy_show(state_bytes, inventory):
    managed = [{
        "address": row.address, "mode": "managed",
        "type": row.address.split(".", 1)[0],
        "provider_name": "registry.terraform.io/oracle/oci",
        "values": {"id": row.ocid},
    } for row in inventory.resources]
    data = []
    for resource in json.loads(state_bytes)["resources"]:
        if resource["mode"] != "data":
            continue
        for instance in resource["instances"]:
            address = f'data.{resource["type"]}.{resource["name"]}'
            if instance.get("index_key") == 0:
                address += "[0]"
            data.append({"address": address, "mode": "data", "type": resource["type"],
                         "provider_name": "registry.terraform.io/oracle/oci",
                         "values": {"id": instance["attributes"]["id"]}})
    changes = [{
        "address": row.address, "mode": "managed",
        "type": row.address.split(".", 1)[0],
        "provider_name": "registry.terraform.io/oracle/oci",
        "change": {"actions": ["delete"], "before": {"id": row.ocid},
                   "after": None, "after_unknown": {}},
    } for row in inventory.resources]
    return json.dumps({"applyable": True, "complete": True,
                       "resource_changes": changes,
                       "prior_state": {"values": {"root_module": {
                           "resources": managed + data,
                       }}}})


@pytest.mark.skipif(sys.platform != "linux", reason="reviewed Terraform release is Linux-only")
@pytest.mark.parametrize("outcome", [
    "success", "absence_before_get_drift", "absence_during_get_drift",
    "publish_before_get_drift", "publish_during_get_drift",
    "source_drift", "uncertain",
])
def test_canonical_applied_generation_is_atomically_published_and_audited(tmp_path, monkeypatch, outcome):
    generation = _canonical_applied_generation(
        tmp_path, monkeypatch, False,
        core_artifact_hook=_modeled_sealed_core_artifacts if outcome == "success" else None,
    )
    state, state_root = generation["state"], generation["state_root"]
    engagement_id, core_id, plan_id = (
        generation[name] for name in ("engagement_id", "core_id", "plan_id")
    )
    parent_id = generation["parent_id"]
    assert generation["bootstrap"].input["phase"] == "awaiting_strict_host_proof"

    # Reopen the persisted file. The publication inputs below are rederived
    # from the retained reviewed apply and exact provider attachment evidence.
    reopened = db.configure(state.uri)
    with db.bind(reopened):
        reviewed = preflight_applied_digitalocean_provider(
            engagement_id, core_id, lease_owner=plan_id,
            environment="devtest", state_root=state_root,
        )
        attachment = derive_digitalocean_initial_attachment_intent(*reviewed)
        membership = reconcile_digitalocean_initial_attachment(
            reviewed[1], attachment, environment="devtest",
            deployment_target="barragan-testing", max_attempts=1,
            poll_interval_seconds=0, transport=_AttachmentCatalog(attachment),
            credential_repository=SqlAlchemyCredentialRepository(),
        )
        chains = SqlAlchemySketchChainRepository()
        pending = tuple(chains.list_for_engagement(engagement_id))
        projected = project_digitalocean_initial_chains(
            reviewed[0], attachment, membership, pending,
        )
        nodes = [row for item in projected for row in item.chain.nodes]
        names = tuple(sorted(row["hostname"] for row in nodes))
        host_receipt = HostEvidenceValidation(
            names,
            tuple(next(row["providerInstanceId"] for row in nodes
                       if row["hostname"] == name) for name in names),
        )
        jobs = SqlAlchemyJobRepository()
        now = datetime.now(timezone.utc)
        claim = jobs.claim_lease(
            parent_id, owner="canonical-published-fixture", token="fixture-claim",
            claimed_at=now.isoformat(),
            expires_at=(now + timedelta(minutes=30)).isoformat(),
            eligible_statuses={"running"}, eligible_phases={"awaiting_strict_host_proof"},
        )
        assert claim is not None
        # The completed bootstrap leaves its last heartbeat in the journal.
        # A new host-proof claim must advance that timestamp before publication.
        heartbeat = datetime.now(timezone.utc)
        claim = jobs.renew_lease(
            parent_id, owner="canonical-published-fixture", token="fixture-claim",
            heartbeat_at=heartbeat.isoformat(),
            expires_at=(heartbeat + timedelta(minutes=30)).isoformat(),
        )
        assert claim is not None
        manifest = generation["manifest"]
        published = chains.publish_provider_keyed_initial_chains(
            parent=claim, pending_chains=pending, projected_chains=projected,
            host_proof=host_receipt, host_evidence_sha256="e" * 64,
            state_sha256=attachment.state_sha256, manifest=manifest,
            manifest_sha256=_digest_json(manifest),
            applied_workspace_path=str(reviewed[1].path),
            expected_event_digest=job_event_digest(claim.events),
            claim_owner="canonical-published-fixture", claim_token="fixture-claim",
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        assert len(published) == 2
        assert all(chain.status == "deployed" for chain in published)
        assert jobs.get(parent_id).status == "succeeded"
        assert _db_lease_lookup(engagement_id) is None

    audited_session = db.configure(state.uri)
    with db.bind(audited_session):
        scope = build_digitalocean_keyed_teardown_scope(
            engagement_id, core_id, environment="devtest", state_root=state_root,
        )
        assert set(scope["resources"][index]["kind"] for index in range(len(scope["resources"]))) == {
            "droplet", "firewall", "ssh_key", "local_file",
        }
        proof = audit_published_provider_keyed_source(
            core_id, environment="devtest", state_root=state_root,
        )
        assert proof.initial_job_id == parent_id
        assert proof.state_sha256 == scope["stateSha256"]
        assert proof.chain_ids == tuple(scope["chainIds"])

    # The public teardown dispatcher has not yet been wired to the published
    # reservation writer. Exercise that real SQL writer directly on the same
    # reviewed snapshot; the coordinator then consumes its sealed parent.
    # Inspector readiness is a separate workflow, supplied here as a seam.
    reservation_session = db.configure(state.uri)
    with db.bind(reservation_session):
        preview = preview_engagement_teardown(core_id)
        assert preview is not None
        jobs = SqlAlchemyJobRepository()
        core = jobs.get(core_id)
        snapshot = _current_scope_snapshot(
            core, jobs=jobs, chains=SqlAlchemySketchChainRepository(),
            resources=SqlAlchemyProviderResourceRepository(),
            domain_repository=SqlAlchemyDomainRepository(),
            inspector_state_reader=None, state_root=state_root,
        )
        assert snapshot["snapshotId"] == preview["snapshotId"]
        now = datetime.now(timezone.utc).isoformat()
        proposal = StoredJobRun(
            id=_parent_id(core_id), action=ENGAGEMENT_TEARDOWN_ACTION,
            status="queued", target=f"engagement:{engagement_id}",
            target_type="engagement", target_id=engagement_id,
            requested_by=core.requested_by or "operator",
            input={"engagementId": engagement_id, "coreJobId": core_id,
                   "scopeSnapshot": snapshot, "phase": "queued", "outcomes": {},
                   "remainingOwnedResources": [], "mutation": True,
                   "confirmation": "redacted"},
            artifact_refs=[], created_at=now, started_at=None, finished_at=None,
            events=[JobEvent(1, "info", "engagement teardown queued",
                             {"snapshotId": snapshot["snapshotId"]})],
        )
        teardown = jobs.reserve_published_keyed_teardown_parent(
            proposal, reviewed_source=proof, state_root=state_root,
        )
        assert teardown is not None
        assert teardown.input["publishedSource"]
        assert teardown.input["scopeSnapshot"]["providerScopes"] == [scope]
        coordinator = run_provider_keyed_comprehensive_handoff(
            teardown.id, environment="devtest", state_root=state_root,
        )
        assert coordinator.input["phase"] == "awaiting_inspector_preflight"

        ready_at = datetime.now(timezone.utc).isoformat()
        ready = SqlAlchemyJobRepository().save(replace(
            coordinator,
            input={**coordinator.input, "phase": "inspector_ready",
                   "claimOwner": "provider-keyed-retained-inspector-ready-handoff",
                   "claimToken": uuid4().hex, "claimClaimedAt": ready_at,
                   "claimHeartbeatAt": ready_at, "claimExpiresAt": ready_at},
            events=[*coordinator.events, JobEvent(5, "info", "retained_inspector_ready", {})],
        ))
        assert ready.input["phase"] == "inspector_ready"

    preview_session = db.configure(state.uri)
    with db.bind(preview_session):
        workspace_path = generation["workspace_path"]
        shown = _destroy_shown_plan(workspace_path)
        commands = []

        def gated_command(args, *, scratch_path, provider_keyed_v2,
                          intent_callback, started_callback,
                          heartbeat_callback, result_callback, **_kwargs):
            phase = args[1]
            assert args[0] == "/usr/bin/terraform"
            assert phase in {"version", "init", "plan", "show"}
            assert scratch_path == workspace_path and provider_keyed_v2 is True
            commands.append(phase)
            invocation = CommandIntent(
                str(uuid4()), str(scratch_path),
                hashlib.sha256(json.dumps(args, separators=(",", ":")).encode()).hexdigest(),
            )
            number = 3000 + len(commands)
            started = StartedCommand(invocation, ProcessIdentity(
                str(uuid4()), number, number, number,
            ))
            intent_callback(invocation)
            started_callback(started)
            heartbeat_callback(started)
            if phase == "plan":
                plan_path = Path(next(value[5:] for value in args if value.startswith("-out=")))
                assert plan_path.is_file()
                plan_path.write_bytes(b"opaque complete destroy plan fixture")
            payload = (json.dumps({"terraform_version": "1.15.5"}) if phase == "version"
                       else shown if phase == "show" else "")
            result_callback(CommandAuditResult(started, 0, len(payload), 0, False, False))
            return CommandResult(started, 0, payload, "", False, False)

        def run_preview(parent_job_id, **options):
            return run_digitalocean_initial_destroy_plan_job(
                parent_job_id, **options, gated_command_runner=gated_command,
            )

        membership = _AttachmentCatalog(attachment)

        def read_preview(parent_job_id, **options):
            return preflight_digitalocean_initial_destroy_apply(
                parent_job_id, **options, membership_transport=membership,
            )

        options = {
            "environment": "devtest", "state_root": state_root,
            "retained_ready_recognizer": lambda *_args, **_kwargs: SimpleNamespace(
                coordinator_job_id=ready.id,
            ),
            "preview_runner": run_preview, "preview_recognizer": read_preview,
        }
        destroy_preview = run_provider_keyed_destroy_preview_from_ready(teardown.id, **options)
        assert destroy_preview.status == "succeeded"
        assert commands == ["version", "init", "plan", "show"]
        assert len(destroy_preview.events) == 16
        assert destroy_preview.events[-1].message == "reviewed full-state provider destroy plan saved"
        assert SqlAlchemyJobRepository().get(teardown.id) == teardown
        assert SqlAlchemyJobRepository().get(ready.id) == ready
        assert not any(row.action == "provider_keyed_initial_destroy_apply"
                       for row in SqlAlchemyJobRepository().list_for_engagement(engagement_id))

    reopened_preview = db.configure(state.uri)
    with db.bind(reopened_preview):
        saved = read_preview(teardown.id, environment="devtest", state_root=state_root)
        assert saved.preview_job_id == destroy_preview.id
        assert saved.preview.plan_sha256 == destroy_preview.events[-1].data["planSha256"]
        assert run_provider_keyed_destroy_preview_from_ready(teardown.id, **options) == destroy_preview
        assert commands == ["version", "init", "plan", "show"]

    apply_session = db.configure(state.uri)
    with db.bind(apply_session):
        attempted = []

        def apply_command(args, *, scratch_path, provider_keyed_v2,
                          intent_callback, started_callback, heartbeat_callback,
                          result_callback, **_kwargs):
            phase = args[1]
            assert phase in {"show", "apply"}
            assert scratch_path == workspace_path and provider_keyed_v2 is True
            attempted.append(phase)
            invocation = CommandIntent(
                str(uuid4()), str(scratch_path),
                hashlib.sha256(json.dumps(args, separators=(",", ":")).encode()).hexdigest(),
            )
            number = 4000 + len(attempted)
            started = StartedCommand(invocation, ProcessIdentity(
                str(uuid4()), number, number, number,
            ))
            intent_callback(invocation)
            if phase == "apply" and outcome == "source_drift":
                jobs = SqlAlchemyJobRepository()
                initial = jobs.get(parent_id)
                jobs.save(replace(initial, events=[*initial.events,
                    JobEvent(len(initial.events) + 1, "info", "unreviewed later event", {})]))
            started_callback(started)
            heartbeat_callback(started)
            if phase == "apply" and outcome == "uncertain":
                raise RuntimeError("simulated lost supervised result")
            if phase == "apply":
                state_path = workspace_path / "terraform.tfstate"
                before = json.loads(state_path.read_text())
                assert before["resources"]
                state_path.write_text(json.dumps({
                    **before, "serial": before["serial"] + 1, "resources": [],
                }))
            payload = shown if phase == "show" else ""
            result_callback(CommandAuditResult(started, 0, len(payload), 0, False, False))
            return CommandResult(started, 0, payload, "", False, False)

        apply_options = dict(
            environment="devtest", state_root=state_root,
            membership_transport=_AttachmentCatalog(attachment),
            live_inspector_prover=lambda *_args, **_kwargs: None,
            gated_command_runner=apply_command, command_environment={},
        )
        if outcome in {"success", "absence_before_get_drift", "absence_during_get_drift",
                       "publish_before_get_drift", "publish_during_get_drift"}:
            applied = run_digitalocean_initial_destroy_apply_job(teardown.id, **apply_options)
            assert applied.status == "succeeded" and attempted == ["show", "apply"]
            assert json.loads((workspace_path / "terraform.tfstate").read_text())["resources"] == []
        else:
            with pytest.raises(ProviderKeyedInitialDestroyApplyJobError):
                run_digitalocean_initial_destroy_apply_job(teardown.id, **apply_options)
            assert attempted == ["show", "apply"]
            assert json.loads((workspace_path / "terraform.tfstate").read_text())["resources"]
            with pytest.raises(ProviderKeyedInitialDestroyApplyJobError):
                run_digitalocean_initial_destroy_apply_job(teardown.id, **apply_options)
            assert attempted == ["show", "apply"]

    reopened_post = db.configure(state.uri)
    with db.bind(reopened_post):
        if outcome in {"success", "absence_before_get_drift", "absence_during_get_drift",
                       "publish_before_get_drift", "publish_during_get_drift"}:
            source = load_keyed_teardown_source(
                teardown.id, phase="post_destroy", environment="devtest", state_root=state_root,
            )
            assert source.variant == "published"
            assert source.initial_journal_sha256 == proof.initial_journal_sha256
            if outcome not in {"publish_before_get_drift", "publish_during_get_drift"}:
                catalog = _AbsentCatalog(scope["selectorTag"])
                injected_drift = []
                if outcome == "absence_before_get_drift":
                    jobs = SqlAlchemyJobRepository()
                    initial = jobs.get(parent_id)
                    jobs.save(replace(initial, events=[*initial.events,
                        JobEvent(len(initial.events) + 1, "info", "unreviewed later event", {})]))
                elif outcome == "absence_during_get_drift":
                    request = catalog.request
                    def drift_during_get(*args):
                        response = request(*args)
                        if len(catalog.paths) == 1:
                            jobs = SqlAlchemyJobRepository()
                            initial = jobs.get(parent_id)
                            injected_drift.append(jobs.save(replace(initial, events=[*initial.events,
                                JobEvent(len(initial.events) + 1, "info", "unreviewed later event", {})])))
                        return response
                    catalog.request = drift_during_get
                jobs = SqlAlchemyJobRepository()
                before_jobs = jobs.list_for_engagement(engagement_id)
                before_chains = SqlAlchemySketchChainRepository().list_for_engagement(engagement_id)
                before_lease = _db_lease_lookup(engagement_id)
                if outcome == "success":
                    absence = reconcile_successful_digitalocean_destroy_absence(
                        teardown.id, environment="devtest", state_root=state_root,
                        transport=catalog, max_attempts=1, poll_interval_seconds=0,
                    )
                    assert absence.selector_tag_cleanup_pending is True
                    owned_ids = {row["address"]: row["id"] for row in scope["resources"]}
                    assert absence.verified_absent_droplet_ids == tuple(sorted(
                        value for address, value in owned_ids.items()
                        if address.startswith("digitalocean_droplet.")
                    ))
                    assert absence.verified_absent_firewall_id == owned_ids[
                        "digitalocean_firewall.firewall"]
                    assert absence.verified_absent_ssh_key_id == owned_ids[
                        "digitalocean_ssh_key.key"]
                    assert len(catalog.paths) == 5
                else:
                    with pytest.raises(ProviderKeyedDestroyAbsencePreflightError):
                        reconcile_successful_digitalocean_destroy_absence(
                            teardown.id, environment="devtest", state_root=state_root,
                            transport=catalog, max_attempts=1, poll_interval_seconds=0,
                        )
                    if outcome == "absence_before_get_drift":
                        assert catalog.paths == []
                    if outcome == "absence_during_get_drift":
                        assert len(catalog.paths) == 5 and len(injected_drift) == 1
                expected_jobs = ([injected_drift[0] if row.id == parent_id else row
                                  for row in before_jobs] if injected_drift else before_jobs)
                assert jobs.list_for_engagement(engagement_id) == expected_jobs
                assert SqlAlchemySketchChainRepository().list_for_engagement(engagement_id) == before_chains
                assert _db_lease_lookup(engagement_id) == before_lease
        else:
            with pytest.raises(ProviderKeyedPostDestroySourceUnavailable):
                load_keyed_teardown_source(
                    teardown.id, phase="post_destroy", environment="devtest", state_root=state_root,
                )
            catalog = _AbsentCatalog(scope["selectorTag"])
            with pytest.raises(ProviderKeyedDestroyAbsencePreflightError):
                reconcile_successful_digitalocean_destroy_absence(
                    teardown.id, environment="devtest", state_root=state_root,
                    transport=catalog, max_attempts=1, poll_interval_seconds=0,
                )
            assert catalog.paths == []

    if outcome in {"success", "publish_before_get_drift", "publish_during_get_drift",
                   "source_drift", "uncertain"}:
        publication_session = db.configure(state.uri)
        with db.bind(publication_session):
            catalog = _AbsentCatalog(scope["selectorTag"])
            injection = []

            def alter_initial():
                jobs = SqlAlchemyJobRepository()
                initial = jobs.get(parent_id)
                injection.append(jobs.save(replace(initial, events=[*initial.events,
                    JobEvent(len(initial.events) + 1, "info", "unreviewed later event", {})])))

            if outcome == "publish_during_get_drift":
                request = catalog.request
                def drift_during_get(*args):
                    response = request(*args)
                    if len(catalog.paths) == 1:
                        alter_initial()
                    return response
                catalog.request = drift_during_get

            def prove(parent_job_id, **opts):
                if outcome == "publish_before_get_drift" and not injection:
                    alter_initial()
                return reconcile_successful_digitalocean_destroy_absence(
                    parent_job_id, **opts, transport=catalog,
                    poll_interval_seconds=0,
                )

            jobs = SqlAlchemyJobRepository()
            coordinator_before = jobs.get(ready.id)
            plan_before = jobs.get(destroy_preview.id)
            apply_before = jobs.get(
                f"job-provider-keyed-initial-destroy-apply-{core_id.removeprefix('job-')}")
            chains_before = SqlAlchemySketchChainRepository().list_for_engagement(engagement_id)
            lease_before = _db_lease_lookup(engagement_id)
            opts = dict(
                environment="devtest", state_root=state_root,
                retained_ready_recognizer=lambda *_a, **_kw: SimpleNamespace(
                    coordinator_job_id=ready.id,
                ),
                absence_preflight=prove,
            )
            if outcome == "success":
                absent = publish_provider_keyed_destroy_absence(teardown.id, **opts)
                assert absent.input["phase"] == "provider_absent"
                assert absent.events[-1].message == "provider_absent"
                assert len(catalog.paths) == 10
                assert attempted == ["show", "apply"]
            else:
                with pytest.raises(ProviderKeyedComprehensiveTeardownAttention):
                    publish_provider_keyed_destroy_absence(teardown.id, **opts)
                assert jobs.get(ready.id) == coordinator_before
                assert jobs.get(ready.id).input["phase"] == "inspector_ready"
                assert all(event.message != "provider_absent" for event in jobs.get(ready.id).events)
                if outcome in {"source_drift", "uncertain", "publish_before_get_drift"}:
                    assert catalog.paths == []
                if outcome == "publish_during_get_drift":
                    assert len(catalog.paths) == 5
                assert attempted == ["show", "apply"]
            assert jobs.get(destroy_preview.id) == plan_before
            assert jobs.get(apply_before.id) == apply_before
            assert SqlAlchemySketchChainRepository().list_for_engagement(engagement_id) == chains_before
            assert _db_lease_lookup(engagement_id) == lease_before

        if outcome == "success":
            recognition_session = db.configure(state.uri)
            with db.bind(recognition_session):
                assert recognize_provider_keyed_destroy_absence(
                    teardown.id, environment="devtest", state_root=state_root,
                ) == absent
                assert attempted == ["show", "apply"]
                assert len(catalog.paths) == 10
            retirement_session = db.configure(state.uri)
            with db.bind(retirement_session):
                retirement_catalog = _AbsentCatalog(scope["selectorTag"])
                owned_id = f"provider-record-{uuid4().hex}"
                droplet = next(row for row in scope["resources"]
                               if row["address"].startswith("digitalocean_droplet.middle["))
                recorded_at = datetime.now(timezone.utc).isoformat()
                SqlAlchemyProviderResourceRepository().save(StoredProviderResourceRecord(
                    id=owned_id, engagement_id=engagement_id,
                    engagement_name=engagement_id, provider="digitalocean",
                    resource_type="droplet", resource_id=str(droplet["id"]),
                    name="opaque", region="nyc3", lifecycle_state="active",
                    status="active", source="barragan",
                    metadata={"barraganOwned": True}, adoption_job_id=parent_id,
                    adopted_at=recorded_at, updated_at=recorded_at,
                ))

                def fresh_absence(parent_job_id, **opts):
                    return reconcile_successful_digitalocean_destroy_absence(
                        parent_job_id, **opts, transport=retirement_catalog,
                        poll_interval_seconds=0,
                    )

                retired = retire_provider_keyed_group_after_absence(
                    teardown.id, environment="devtest", state_root=state_root,
                    absence_preflight=fresh_absence,
                )
                assert len(retired) == 2
                assert all(row.status == "destroyed" and row.nodes == [] for row in retired)
                assert len(retirement_catalog.paths) == 5
                assert attempted == ["show", "apply"]
                event = SqlAlchemyJobRepository().get(absent.id).events[-1]
                assert event.message == "keyed_provider_group_retired"
                assert event.data["priorChainProjectionSha256"] == (
                    teardown.input["publishedSource"]["chain_projection_sha256"])
                assert event.data["retiredRecordIds"] == [owned_id]
            reopened_retired = db.configure(state.uri)
            with db.bind(reopened_retired):
                assert recognize_provider_keyed_group_retired(
                    teardown.id, environment="devtest", state_root=state_root,
                ) == retired
                assert attempted == ["show", "apply"]
            core_preview_session = db.configure(state.uri)
            with db.bind(core_preview_session):
                jobs = SqlAlchemyJobRepository()
                core = jobs.get(core_id)
                core_plan = SqlAlchemyDeploymentPlanRepository().get(plan_id)
                core_state_path = Path(core_plan.evidence["terraformStatePath"])
                core_state_bytes = core_state_path.read_bytes()
                core_inventory = parse_applied_oci_core_state(
                    core_state_bytes, proxy_count=core_plan.evidence["proxyCount"],
                    elk_enabled=core_plan.evidence["elkEnabled"],
                    compartment_id=core_plan.evidence["target"]["compartmentId"],
                    engagement_name=core.input["engagementName"],
                )
                shown_core = _exact_oci_destroy_show(core_state_bytes, core_inventory)
                monkeypatch.setattr(core_destroy_preview, "DEFAULT_TERRAFORM_STATE_ROOT",
                                    tmp_path / "oci-terraform-state")
                core_preview_calls = []

                def core_command(args, cwd, env):
                    core_preview_calls.append(args[1])
                    assert cwd == Path(core_plan.evidence["runDirectory"])
                    assert env["TF_DATA_DIR"] == core_plan.evidence["terraformDataDir"]
                    if args[1] == "plan":
                        output = Path(next(arg[5:] for arg in args if arg.startswith("-out=")))
                        output.write_bytes(b"reviewed OCI destroy plan")
                        return SimpleNamespace(returncode=2, stdout="", stderr="")
                    assert args[1:3] == ["show", "-json"]
                    return SimpleNamespace(returncode=0, stdout=shown_core, stderr="")

                preview_options = dict(
                    environment="devtest", state_root=state_root,
                    retired_recognizer=lambda *_a, **_kw: pytest.fail(
                        "pending recognizer substituted for published history"),
                    release_check=lambda **_kw: SimpleNamespace(
                        path=Path("/usr/bin/terraform"), sha256="a" * 64,
                        version="1.15.5"),
                    command_runner=core_command,
                )
                initial = jobs.get(parent_id)
                jobs.save(replace(initial, events=[*initial.events, JobEvent(
                    len(initial.events) + 1, "info", "unreviewed later event", {},
                )]))
                with pytest.raises(core_destroy_preview.KeyedCoreDestroyPreviewAttention):
                    core_destroy_preview.preview_pending_keyed_oci_core_destroy(
                        teardown.id, **preview_options)
                assert core_preview_calls == []
                jobs.save(initial)
                core_destroy_plan = core_destroy_preview.preview_pending_keyed_oci_core_destroy(
                    teardown.id, **preview_options)
                assert core_destroy_plan.status == "succeeded"
                assert core_destroy_plan.events[-1].message == "core destroy preview saved"
                assert core_preview_calls == ["plan", "show"]
            core_preview_reopen = db.configure(state.uri)
            with db.bind(core_preview_reopen):
                assert SqlAlchemyJobRepository().get(core_destroy_plan.id) == core_destroy_plan
                with pytest.raises(core_destroy_preview.KeyedCoreDestroyPreviewAttention):
                    core_destroy_preview.preview_pending_keyed_oci_core_destroy(
                        teardown.id, **{**preview_options,
                            "command_runner": lambda *_a, **_kw: pytest.fail(
                                "one-shot OCI preview replayed")})
                assert core_preview_calls == ["plan", "show"]
            reopened_retired = db.configure(state.uri)
            with db.bind(reopened_retired):
                resource_repo = SqlAlchemyProviderResourceRepository()
                owned = resource_repo.get(owned_id)
                assert owned.status == owned.lifecycle_state == "destroyed"
                assert datetime.fromisoformat(owned.destroyed_at).replace(tzinfo=timezone.utc) == datetime.fromisoformat(
                    SqlAlchemyJobRepository().get(absent.id).events[-1].data["observedAt"])
                for changed in (
                    {"resource_id": "unreviewed-resource"},
                    {"status": "retired"},
                    {"destroyed_at": (datetime.fromisoformat(owned.destroyed_at)
                                      + timedelta(seconds=1)).isoformat()},
                    {"metadata": {"barraganOwned": False}},
                    {"adoption_job_id": "unreviewed-job"},
                ):
                    resource_repo.save(replace(owned, **changed))
                    with pytest.raises(ProviderKeyedComprehensiveTeardownAttention):
                        recognize_provider_keyed_group_retired(
                            teardown.id, environment="devtest", state_root=state_root,
                        )
                    resource_repo.save(owned)
                jobs = SqlAlchemyJobRepository()
                saved = jobs.get(absent.id)
                receipt = saved.events[-1]
                jobs.save(replace(saved, events=[*saved.events[:-1], replace(
                    receipt, data={**receipt.data,
                                   "priorChainProjectionSha256": "0" * 64},
                )]))
                with pytest.raises(ProviderKeyedComprehensiveTeardownAttention):
                    recognize_provider_keyed_group_retired(
                        teardown.id, environment="devtest", state_root=state_root,
                    )
                jobs.save(saved)
                chain_repo = SqlAlchemySketchChainRepository()
                chain_repo.save(replace(retired[0], assigned_proxy="unreviewed-proxy"))
                with pytest.raises(ProviderKeyedComprehensiveTeardownAttention):
                    recognize_provider_keyed_group_retired(
                        teardown.id, environment="devtest", state_root=state_root,
                    )
                assert attempted == ["show", "apply"]
