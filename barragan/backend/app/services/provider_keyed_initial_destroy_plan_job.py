# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant DevTest-only, single-attempt full-state DigitalOcean destroy preview.

This child creates review evidence only. No runtime dispatcher invokes it, and
its saved binary plan is not authority to run Terraform destroy apply.
"""

from __future__ import annotations

from app.services.provider_keyed_published_initial_cleanup_authority import queued_cleanup_event_data

import os
import hashlib
import re
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from uuid import uuid4

from app.domain import JobEvent
from app.services.engagement_teardown import (
    ENGAGEMENT_TEARDOWN_ACTION, _fingerprint, _parent_id,
    _validated_parent_boundary, engagement_teardown_in_progress,
)
from app.services.provider_keyed_initial_teardown import (
    DigitalOceanTeardownIntent, _SHARED, _require_exact_state,
    _DELETE_PREDICATES, _FAILURE_STAGES, ProviderKeyedTeardownPreviewError,
    ProviderKeyedTeardownPreviewUncertainError,
    prepare_digitalocean_keyed_initial_teardown_preview,
)
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, StartedCommand,
    UnreapedGatedCommandError, run_gated_command,
)
from app.services.provider_keyed_postapply_preflight import read_applied_digitalocean_provider_for_teardown
from app.services.provider_keyed_append_destroy_targets import bind_published_append_destroy
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _inert_aborted_intent
from app.services.provider_keyed_teardown_quiescence import audit_pending_provider_keyed_bootstrap
from app.services.provider_keyed_teardown_source import load_keyed_teardown_source
from app.services.provider_keyed_teardown_scope import build_digitalocean_keyed_teardown_scope
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.services.sketch_ssh_keys import retrieve_sketch_ssh_key
from app.services.sketch_state_workspaces import _collaborator_group_gid, _default_state_root
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


ACTION = "provider_keyed_initial_destroy_plan"
_PRECOMMAND_RECOVERY = "provider destroy preview pre-command recovery reserved"
_OPERATION = "provider_keyed_teardown_fence"
_CLAIM_SECONDS = 60


class ProviderKeyedInitialDestroyPlanJobError(ValueError):
    """The full-state destroy preview could not be safely recorded."""


class _PublicKeyCleanupUnproved(ValueError):
    """An O_EXCL public-key staging file may remain."""


def _precommand_failed_preview(
    child: StoredJobRun | None, parent: StoredJobRun, core: StoredJobRun,
    snapshot: dict, root: Path, input_path: Path,
) -> bool:
    """Recognize only the completed cleanup of a failed, command-free attempt."""
    if child is None or child.action != ACTION or child.status != "failed":
        return False
    events = child.events
    if (child.id != f"job-provider-keyed-initial-destroy-plan-{core.id.removeprefix('job-')}"
            or child.target_id != parent.target_id or child.started_at is None
            or child.finished_at is None or child.artifact_refs != []
            or len(events) != 4 or [event.sequence for event in events] != [1, 2, 3, 4]
            or [(event.level, event.message) for event in events] != [
                ("info", "provider destroy preview queued"),
                ("info", "provider destroy preview started"),
                ("info", "provider destroy preview staging intended"),
                ("error", "provider destroy preview stopped; reconciliation required")]
            or events[0].data != {} or events[1].data != {}
            or events[3].data != {"failureStage": "other"}):
        return False
    base = {"engagementId": parent.target_id, "coreJobId": core.id,
            "corePlanId": core.input.get("corePlanId"), "teardownParentId": parent.id,
            "scopeSnapshotId": snapshot.get("snapshotId"),
            "providerScopeSha256": snapshot.get("providerScopeSha256"),
            "mutation": True}
    inputs = child.input
    try:
        # The terminal writer strips claim fields. Wait one full claim period
        # after its saved finish before treating the old worker as quiescent.
        finished = datetime.fromisoformat(child.finished_at)
        if finished.tzinfo is None:
            finished = finished.replace(tzinfo=timezone.utc)
        quiescent = (finished
                     <= datetime.now(timezone.utc) - timedelta(seconds=_CLAIM_SECONDS))
    except (TypeError, ValueError):
        quiescent = False
    if (not quiescent or inputs != base):
        return False
    staging = events[2].data
    if type(staging) is not dict or set(staging) != {
            "publicKeyPath", "stagingPath", "stagedInputPath", "credentialPath", "planPath"}:
        return False
    stage_path = Path(staging["stagingPath"])
    expected_public = input_path.parent / "admin-public"
    expected_plan = root / ".barragan-initial-destroy.tfplan"
    staged_name = "input-0.json" if input_path.name.endswith(".json") else "input-0.input"
    if (stage_path.parent != root
            or re.fullmatch(r"\.barragan-destroy-inputs-[0-9a-f]{32}", stage_path.name) is None
            or staging != {"publicKeyPath": str(expected_public),
                           "stagingPath": str(stage_path),
                           "stagedInputPath": str(stage_path / staged_name),
                           "credentialPath": str(stage_path / "credential.json"),
                           "planPath": str(expected_plan)}):
        return False
    return not any(os.path.lexists(path) for path in (
        expected_public, input_path.parent / "admin-private", stage_path,
        stage_path / staged_name, stage_path / "credential.json", expected_plan))


def run_digitalocean_initial_destroy_plan_job(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, sketch_repository=None,
    engagement_repository=None, credential_repository=None, ssh_key_repository=None,
    lease_lookup=None,
    scope_builder: Callable = build_digitalocean_keyed_teardown_scope,
    handoff_auditor: Callable = audit_pending_provider_keyed_bootstrap,
    applied_reader: Callable = read_applied_digitalocean_provider_for_teardown,
    state_validator: Callable = _require_exact_state,
    release_check: Callable = require_devtest_terraform_release,
    preview: Callable = prepare_digitalocean_keyed_initial_teardown_preview,
    gated_command_runner: Callable = run_gated_command,
) -> StoredJobRun:
    """Save one exact destroy plan, never apply it or replay a running child."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    current: StoredJobRun | None = None
    owned_public: tuple[Path, int, int] | None = None
    cleanup_unproved = False
    uncertain = False
    claim_owner: str | None = None
    claim_token: str | None = None
    failure_stage = "other"
    try:
        if (environment != "devtest" or not isinstance(teardown_parent_id, str)
                or not teardown_parent_id or not isinstance(state_root, Path)
                or state_root != _default_state_root()):
            raise ValueError("unsupported destroy preview boundary")

        def boundary():
            parent = jobs.get(teardown_parent_id)
            if (parent is None or parent.action != ENGAGEMENT_TEARDOWN_ACTION
                    or parent.status != "queued" or parent.started_at is not None
                    or parent.finished_at is not None or parent.input.get("phase") != "queued"
                    or parent.input.get("mutation") is not True or len(parent.events) != 1
                    or parent.events[0].message != "engagement teardown queued"):
                raise ValueError("confirmed parent differs")
            core, snapshot = _validated_parent_boundary(parent, jobs)
            if (_fingerprint({key: value for key, value in snapshot.items() if key != "snapshotId"})
                    != snapshot["snapshotId"] or parent.events[0].data != queued_cleanup_event_data(snapshot)
                    or parent.id != _parent_id(core.id)
                    or engagement_teardown_in_progress(snapshot["engagementId"], repository=jobs) != parent
                    or core.status != "succeeded" or core.input.get("sketchStateSchema") != "provider-keyed-v2"
                    or snapshot["coreJobId"] != core.id):
                raise ValueError("confirmed snapshot differs")
            scope = snapshot["providerScopes"][0]
            engagement_id, plan_id = snapshot["engagementId"], scope["corePlanId"]
            plan = plans.get(plan_id)
            if (core.input.get("corePlanId") != plan_id or plan is None or plan.id != plan_id
                    or plan.engagement_id != engagement_id or plan.status != "applied"
                    or plan.apply_job_id != core.id or lookup(engagement_id) != (plan_id, _OPERATION)):
                raise ValueError("retagged core lease differs")
            if scope_builder(
                engagement_id, core.id, environment=environment, state_root=state_root,
                allowed_teardown_parent_id=parent.id, engagement_repository=engagement_repository,
                sketch_repository=chains, job_repository=jobs, plan_repository=plans,
                credential_repository=credentials,
            ) != scope:
                raise ValueError("full provider scope changed")
            if "publishedSource" in parent.input:
                source = load_keyed_teardown_source(
                    parent.id, phase="pre_go", environment=environment, state_root=state_root,
                    job_repository=jobs, plan_repository=plans, sketch_repository=chains,
                )
                expected_variant = ("published_append" if "publishedAppendSource" in parent.input
                                    else "published")
                if (source.variant != expected_variant or source.core_job_id != core.id
                        or source.core_plan_id != plan_id
                        or source.snapshot_id != snapshot["snapshotId"]
                        or source.provider_scope_sha256 != snapshot["providerScopeSha256"]):
                    raise ValueError("published source changed")
            else:
                proof = handoff_auditor(
                    core.id, confirmed_scope=scope, confirmed_scope_sha256=_fingerprint(snapshot),
                    workspace_root=Path(scope["workspace"]), job_repository=jobs,
                )
                initial = jobs.get(proof.parent_job_id)
                failed_prebinding = snapshot["dnsCleanupManifest"].get("schema") == (
                    "provider-keyed-empty-dns-prebinding-v1")
                if (not proof.parent_job_id or initial is None
                        or (failed_prebinding and (
                            initial.status != "failed" or initial.input.get("phase") != "attention"
                            or job_event_digest(initial.events) != snapshot["dnsCleanupManifest"]["initialJournalSha256"]
                            or proof.command_count not in (0, 2, 8)))
                        or (not failed_prebinding
                            and initial.input.get("phase") != "teardown_handoff_pending")):
                    raise ValueError("sealed handoff changed")
            resources = scope["resources"]
            ids = {row["address"]: row["id"] for row in resources}
            if "publishedAppendSource" in parent.input:
                expanded = bind_published_append_destroy(
                    parent.id, environment=environment, state_root=state_root,
                    job_repository=jobs, plan_repository=plans, sketch_repository=chains,
                    engagement_repository=engagement_repository,
                    credential_repository=credentials,
                )
                workspace, teardown_intent = expanded.workspace, expanded.intent
                expected_input, input_hash = expanded.input_path, expanded.input_sha256
                evidence = {
                    "adminPublicKeySha256": expanded.admin_public_key_sha256,
                    "terraformBinaryPath": str(expanded.terraform_binary_path),
                    "terraformBinarySha256": expanded.terraform_binary_sha256,
                    "markerSha256": expanded.marker_sha256,
                    "topologySha256": expanded.topology_sha256,
                    "lockfileSha256": expanded.lockfile_sha256,
                }
                if (ids != teardown_intent.resource_ids
                        or teardown_intent.state_sha256 != scope["stateSha256"]):
                    raise ValueError("sealed appended resource identities differ")
            else:
                active = [row for row in chains.list_for_engagement(engagement_id)
                          if not _inert_aborted_intent(row, engagement_id)]
                mode = ("applied_read" if len(active) == 2 and all(row.status == "pending" and not row.nodes for row in active)
                        else "materialized_read")
                intent, workspace, evidence, apply_job = applied_reader(
                    engagement_id, core.id, environment=environment, state_root=state_root,
                    mode=mode, allowed_teardown_parent_id=parent.id,
                    engagement_repository=engagement_repository, sketch_repository=chains,
                    job_repository=jobs, plan_repository=plans, credential_repository=credentials,
                )
                if (len(ids) != len(resources) or set(ids) != set(intent.nodes) | _SHARED
                        or workspace.path != Path(scope["workspace"])
                        or workspace.provider_connection_id != scope["providerConnectionId"]
                        or workspace.source_revision != scope["sourceRevision"]
                        or intent.revision_id != scope["revisionId"]
                        or intent.selector_tag != scope["selectorTag"]
                        or intent.core_plan_id != plan_id
                        or evidence["providerConnectionId"] != workspace.provider_connection_id
                        or evidence["sourceSha256"] != workspace.source_sha256
                        or evidence["selectorTag"] != intent.selector_tag
                        or evidence["corePlanId"] != plan_id):
                    raise ValueError("sealed resource identities differ")
                manifest = evidence["inputSha256"]
                expected_input = workspace.path.parents[1] / ".plan-material" / "digitalocean" / "inputs.json"
                if (type(manifest) is not list or len(manifest) != 1 or type(manifest[0]) is not list
                        or len(manifest[0]) != 2 or manifest[0][0] != str(expected_input)
                        or evidence["adminPublicKeyPath"] != str(expected_input.parent / "admin-public")
                        or evidence["adminPrivateKeyPath"] != str(expected_input.parent / "admin-private")):
                    raise ValueError("initial reviewed input differs")
                input_hash = manifest[0][1]
                teardown_intent = DigitalOceanTeardownIntent(
                    intent.nodes, intent.firewall, ids, scope["stateSha256"],
                    workspace.provider_connection_id, evidence["credentialSecretSha256"],
                    evidence["credentialUpdatedAt"],
                )
            release = release_check(environment=environment)
            if (str(release.path) != evidence["terraformBinaryPath"]
                    or release.sha256 != evidence["terraformBinarySha256"]):
                raise ValueError("pinned Terraform release differs")
            state_validator(workspace, teardown_intent)
            if jobs.get(parent.id) != parent or lookup(engagement_id) != (plan_id, _OPERATION):
                raise ValueError("teardown boundary changed during read")
            return (parent, core, snapshot, scope, workspace, teardown_intent,
                    expected_input, input_hash, release, evidence)

        parent, core, snapshot, scope, workspace, intent, input_path, input_hash, release, evidence = boundary()
        suffix = core.id.removeprefix("job-")
        child_id = f"job-provider-keyed-initial-destroy-plan-{suffix}"
        prior = jobs.get(child_id)
        previews = [row for row in jobs.list_for_engagement(parent.target_id)
                    if row.action == ACTION]
        if prior is not None or previews:
            if ("publishedAppendSource" not in parent.input or len(previews) != 1
                    or previews[0] != prior or prior is None
                    or not isinstance(jobs, SqlAlchemyJobRepository)
                    or not _precommand_failed_preview(prior, parent, core, snapshot,
                                                      workspace.path, input_path)):
                raise ValueError("destroy preview child already exists")
            sealed = (parent, core, snapshot, scope, workspace, intent,
                      input_path, input_hash, release, evidence)
            claim_owner = f"provider-keyed-destroy-preview-{uuid4().hex}"
            claim_token = uuid4().hex
            claimed_at = _now()
            prior = jobs.rearm_exact_precommand_destroy_preview(
                prior, authority=lambda: (
                    boundary() == sealed
                    and _precommand_failed_preview(jobs.get(child_id), parent, core,
                                                   snapshot, workspace.path, input_path)),
                owner=claim_owner, token=claim_token,
                claimed_at=claimed_at, expires_at=_later(claimed_at))
            if prior is None:
                raise ValueError("destroy preview recovery authority changed")
        new = StoredJobRun(
            id=child_id, action=ACTION, status="queued", target=f"engagement:{parent.target_id}",
            target_type="engagement", target_id=parent.target_id, requested_by=parent.requested_by,
            input={"engagementId": parent.target_id, "coreJobId": core.id,
                   "corePlanId": scope["corePlanId"], "teardownParentId": parent.id,
                   "scopeSnapshotId": snapshot["snapshotId"],
                   "providerScopeSha256": snapshot["providerScopeSha256"], "mutation": True},
            artifact_refs=[], created_at=_now(), started_at=None, finished_at=None,
            events=[JobEvent(1, "info", "provider destroy preview queued", {})],
        )
        saved = prior if prior is not None else jobs.save_if_absent(new)
        if prior is None and (saved is None or saved.id != new.id or saved.action != new.action
                or saved.status != "queued" or saved.target != new.target
                or saved.target_type != new.target_type or saved.target_id != new.target_id
                or saved.requested_by != new.requested_by or saved.input != new.input
                or saved.artifact_refs != [] or saved.started_at is not None
                or saved.finished_at is not None or saved.events != new.events
                or datetime.fromisoformat(saved.created_at).replace(tzinfo=timezone.utc)
                != datetime.fromisoformat(new.created_at)
                or jobs.get(new.id) != saved):
            raise ValueError("destroy preview child creation lost")
        current = (saved if prior is not None else jobs.start_if_queued(
            saved, started_at=_now(),
            event=JobEvent(2, "info", "provider destroy preview started", {}),
        ))
        if (current is None or current.id != saved.id or current.action != ACTION
                or current.status != "running" or current.input != saved.input
                or current.artifact_refs != [] or current.finished_at is not None
                or current.events != (saved.events if prior is not None else [
                    *saved.events, JobEvent(2, "info", "provider destroy preview started", {})])
                or jobs.get(current.id) != current):
            raise ValueError("destroy preview child start lost")
        # The queued child is durable before any Terraform plan side effect.
        if boundary()[:4] != (parent, core, snapshot, scope):
            raise ValueError("destroy preview boundary changed after child start")
        if prior is None:
            claim_owner = f"provider-keyed-destroy-preview-{uuid4().hex}"
            claim_token = uuid4().hex
            claimed_at = _now()
            claimed = jobs.claim_lease(
                current.id, owner=claim_owner, token=claim_token,
                claimed_at=claimed_at, expires_at=_later(claimed_at),
                eligible_statuses={"running"},
            )
        else:
            claimed = current
        if (claimed is None or claimed.input.get("claimOwner") != claim_owner
                or claimed.input.get("claimToken") != claim_token
                or {key: value for key, value in claimed.input.items() if not key.startswith("claim")}
                != {key: value for key, value in current.input.items()
                    if not key.startswith("claim")}
                or claimed.events != current.events):
            raise ValueError("destroy preview claim changed")
        current = claimed
        if boundary()[:4] != (parent, core, snapshot, scope):
            raise ValueError("destroy preview boundary changed after claim")

        def require_authority() -> None:
            expiry = current.input.get("claimExpiresAt")
            try:
                unexpired = (isinstance(expiry, str)
                             and datetime.now(timezone.utc) < datetime.fromisoformat(expiry))
            except (TypeError, ValueError):
                unexpired = False
            if (jobs.get(parent.id) != parent
                    or lookup(parent.target_id) != (scope["corePlanId"], _OPERATION)
                    or jobs.get(current.id) != current or not unexpired):
                raise ValueError("destroy preview parent, lease or claim changed")

        def append_audit(message: str, data: dict) -> None:
            nonlocal current
            require_authority()
            instant = _now()
            saved = jobs.append_destroy_preview_event_if_running_claimed(
                current, owner=claim_owner, token=claim_token,
                expected_event_digest=job_event_digest(current.events),
                heartbeat_at=instant, expires_at=_later(instant),
                event=JobEvent(len(current.events) + 1, "info", message, data),
            )
            if saved is None:
                raise ValueError("destroy preview command audit claim changed")
            current = saved

        public = input_path.parent / "admin-public"
        plan_path = workspace.path / ".barragan-initial-destroy.tfplan"
        staging_path = workspace.path / f".barragan-destroy-inputs-{uuid4().hex}"
        credential_path = staging_path / "credential.json"
        staged_input = staging_path / ("input-0.json" if input_path.name.endswith(".json") else "input-0.input")
        require_authority()
        material = retrieve_sketch_ssh_key(parent.target_id, ssh_key_repository)
        if (material is None or type(material.public_key) is not str or not material.public_key
                or hashlib.sha256(material.public_key.encode("utf-8")).hexdigest()
                != evidence["adminPublicKeySha256"]
                or any(os.path.lexists(path) for path in
                       (public, input_path.parent / "admin-private", staging_path, plan_path))):
            raise ValueError("reviewed durable Sketch public key or staging paths differ")
        append_audit("provider destroy preview staging intended", {
            "publicKeyPath": str(public), "stagingPath": str(staging_path),
            "stagedInputPath": str(staged_input), "credentialPath": str(credential_path),
            "planPath": str(plan_path),
        })
        require_authority()
        owned_public = _stage_public_key(public, material.public_key)

        phase = "version"
        stage = "requested"
        command_intent: CommandIntent | None = None
        command_started: StartedCommand | None = None

        def intent_callback(value: CommandIntent) -> None:
            nonlocal stage, command_intent
            if (stage != "requested" or value.scratch_path != str(workspace.path)
                    or not value.invocation_id or len(value.argv_sha256) != 64):
                raise ValueError("destroy preview command intent differs")
            append_audit("provider destroy preview command intent fenced", {
                "phase": phase, "invocationId": value.invocation_id,
                "argvSha256": value.argv_sha256,
            })
            command_intent, stage = value, "intent"

        def started_callback(value: StartedCommand) -> None:
            nonlocal stage, command_started
            if stage != "intent" or value.intent != command_intent:
                raise ValueError("destroy preview command start differs")
            append_audit("provider destroy preview command started before GO", {
                "phase": phase, "invocationId": value.intent.invocation_id,
                "bootId": value.identity.boot_id, "pid": value.identity.pid,
                "pgid": value.identity.pgid, "startTicks": value.identity.start_ticks,
            })
            command_started, stage = value, "started"

        def heartbeat_callback(value: StartedCommand) -> None:
            nonlocal current
            if stage != "started" or value != command_started:
                raise ValueError("destroy preview heartbeat identity differs")
            require_authority()
            instant = _now()
            renewed = jobs.renew_lease(
                current.id, owner=claim_owner, token=claim_token,
                heartbeat_at=instant, expires_at=_later(instant),
            )
            if renewed is None or renewed.events != current.events:
                raise ValueError("destroy preview heartbeat claim changed")
            current = renewed

        def result_callback(value: CommandAuditResult) -> None:
            nonlocal stage
            if stage != "started" or value.started != command_started:
                raise ValueError("destroy preview command result differs")
            append_audit("provider destroy preview command result fenced", {
                "phase": phase, "invocationId": value.started.intent.invocation_id,
                "returnCode": value.returncode, "stdoutBytes": value.stdout_bytes,
                "stderrBytes": value.stderr_bytes,
                "stdoutTruncated": value.stdout_truncated,
                "stderrTruncated": value.stderr_truncated,
            })
            stage = "result"

        def command_runner(args, cwd, env):
            nonlocal phase, stage, command_intent, command_started
            binary = str(release.path)
            expected = {
                "version": [binary, "version", "-json"],
                "init": [binary, "init", "-input=false", "-lockfile=readonly", "-no-color"],
                "plan": [binary, "plan", "-destroy", "-input=false", "-lock=true", "-no-color",
                         f"-out={plan_path}", f"-var-file={staged_input}",
                         f"-var-file={credential_path}"],
                "show": [binary, "show", "-json", str(plan_path)],
            }
            if cwd != workspace.path or stage != "requested" or args != expected[phase]:
                raise ValueError("destroy preview command order or argv differs")
            require_authority()
            try:
                outcome = gated_command_runner(
                    args, scratch_path=workspace.path, provider_keyed_v2=True,
                    max_output_bytes=16 * 1024 * 1024 if phase == "show" else 65536,
                    env=dict(env), intent_callback=intent_callback,
                    started_callback=started_callback, heartbeat_callback=heartbeat_callback,
                    result_callback=result_callback,
                )
            except Exception as error:
                if isinstance(error, UnreapedGatedCommandError) or stage == "started":
                    raise ProviderKeyedTeardownPreviewUncertainError(
                        "destroy preview command completion unproved; retained files need reconciliation"
                    ) from None
                raise
            if stage != "result" or outcome.started != command_started:
                raise ProviderKeyedTeardownPreviewUncertainError(
                    "destroy preview result audit unproved; retained files need reconciliation"
                )
            if outcome.stdout_truncated or outcome.stderr_truncated:
                raise ValueError("bounded destroy preview command output was truncated")
            result = subprocess.CompletedProcess(args, outcome.returncode, outcome.stdout, "")
            order = {"version": "init", "init": "plan", "plan": "show", "show": "complete"}
            phase, stage = order[phase], "requested"
            command_intent, command_started = None, None
            return result

        try:
            require_authority()
            reviewed = preview(
                workspace, intent, environment=environment, deployment_target="barragan-testing",
                input_sha256={input_path: input_hash}, var_files=[input_path],
                credential_repository=credentials, command_environment=os.environ,
                expected_terraform_sha256=release.sha256, terraform=str(release.path),
                staging_path=staging_path, command_runner=command_runner,
                authority_check=require_authority,
                **({"expected_topology_path": input_path}
                   if "publishedAppendSource" in parent.input else {}),
            )
            if phase != "complete" or stage != "requested":
                raise ProviderKeyedTeardownPreviewUncertainError(
                    "destroy preview helper returned without complete command audit"
                )
        except ProviderKeyedTeardownPreviewUncertainError:
            uncertain = True
            raise
        finally:
            if phase == "complete" and not uncertain:
                failure_stage = "cleanup"
                require_authority()
                _remove_owned_public_key(owned_public)
                owned_public = None
        failure_stage = "post_preview_evidence"
        if (reviewed.plan_path != workspace.path / ".barragan-initial-destroy.tfplan"
                or not isinstance(reviewed.plan_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", reviewed.plan_sha256) is None
                or _private_file_digest(reviewed.plan_path) != reviewed.plan_sha256
                or reviewed.state_sha256 != scope["stateSha256"]
                or reviewed.source_sha256 != workspace.source_sha256
                or reviewed.marker_sha256 != evidence["markerSha256"]
                or reviewed.lockfile_sha256 != evidence["lockfileSha256"]
                or reviewed.topology_sha256 != evidence["topologySha256"]
                or _private_file_digest(workspace.path / ".barragan-apply-phase.json",
                                        allow_collaborator_group=True)
                != reviewed.phase_sha256
                or reviewed.credential_record_id != workspace.provider_connection_id
                or reviewed.credential_secret_sha256 != intent.credential_secret_sha256
                or reviewed.credential_updated_at != intent.credential_updated_at
                or reviewed.terraform_binary_path != release.path
                or reviewed.terraform_binary_sha256 != release.sha256
                or reviewed.input_sha256 != ((str(input_path), input_hash),)):
            raise ValueError("saved destroy preview evidence differs")
        failure_stage = "other"
        if boundary()[:4] != (parent, core, snapshot, scope):
            raise ValueError("destroy preview boundary changed after plan")
        require_authority()
        completed = jobs.finish_destroy_preview_if_running_claimed(
            current, owner=claim_owner, token=claim_token,
            expected_event_digest=job_event_digest(current.events),
            status="succeeded", finished_at=_now(),
            event=JobEvent(len(current.events) + 1, "info", "reviewed full-state provider destroy plan saved", {
                "planPath": str(reviewed.plan_path), "planSha256": reviewed.plan_sha256,
                "stateSha256": reviewed.state_sha256,
                "sourceRevision": workspace.source_revision,
                "sourceSha256": reviewed.source_sha256,
                "markerSha256": reviewed.marker_sha256,
                "lockfileSha256": reviewed.lockfile_sha256,
                "topologySha256": reviewed.topology_sha256,
                "phaseSha256": reviewed.phase_sha256,
                "inputSha256": [[str(input_path), input_hash]],
                "providerConnectionId": workspace.provider_connection_id,
                "credentialSecretSha256": reviewed.credential_secret_sha256,
                "credentialUpdatedAt": reviewed.credential_updated_at,
                "terraformBinaryPath": str(reviewed.terraform_binary_path),
                "terraformBinarySha256": reviewed.terraform_binary_sha256,
                "scopeSnapshotId": snapshot["snapshotId"],
                "providerScopeSha256": snapshot["providerScopeSha256"],
            }), artifact_ref=str(reviewed.plan_path),
        )
        if completed is None:
            raise ValueError("destroy preview terminal journal changed")
        return completed
    except Exception as error:
        stage = error.stage if isinstance(error, ProviderKeyedTeardownPreviewError) else failure_stage
        if type(stage) is not str or stage not in _FAILURE_STAGES:
            stage = "other"
        failure_data = {"failureStage": stage}
        category = (error.predicate_category
                    if isinstance(error, ProviderKeyedTeardownPreviewError) else None)
        if stage == "exact_delete" and type(category) is str and category in _DELETE_PREDICATES:
            failure_data["predicateCategory"] = category
        uncertain = uncertain or isinstance(error, ProviderKeyedTeardownPreviewUncertainError)
        cleanup_unproved = cleanup_unproved or isinstance(error, _PublicKeyCleanupUnproved)
        if (owned_public is not None and claim_token is not None
                and (jobs.get(current.id) != current or jobs.get(teardown_parent_id) != parent
                     or lookup(current.target_id) != (current.input["corePlanId"], _OPERATION))):
            uncertain = True
        if owned_public is not None and not cleanup_unproved and not uncertain:
            try:
                _remove_owned_public_key(owned_public)
                owned_public = None
            except Exception:
                cleanup_unproved = True
        if cleanup_unproved and current is not None and claim_token is not None:
            try:
                if (jobs.get(current.id) != current or jobs.get(teardown_parent_id) != parent
                        or lookup(current.target_id) != (current.input["corePlanId"], _OPERATION)):
                    raise ValueError("destroy preview cleanup audit authority changed")
                instant = _now()
                noted = jobs.append_destroy_preview_event_if_running_claimed(
                    current, owner=claim_owner, token=claim_token,
                    expected_event_digest=job_event_digest(current.events),
                    heartbeat_at=instant, expires_at=_later(instant),
                    event=JobEvent(len(current.events) + 1, "error",
                                   "provider destroy preview public key cleanup unproved", {}),
                )
                if noted is not None:
                    current = noted
            except Exception:
                pass
        if current is not None and not uncertain and not cleanup_unproved:
            try:
                if claim_owner is not None and claim_token is not None:
                    if (jobs.get(current.id) != current
                            or lookup(current.target_id) != (current.input["corePlanId"], _OPERATION)
                            or jobs.get(teardown_parent_id) != parent):
                        raise ValueError("destroy preview terminal authority changed")
                    jobs.finish_destroy_preview_if_running_claimed(
                        current, owner=claim_owner, token=claim_token,
                        expected_event_digest=job_event_digest(current.events),
                        status="failed", finished_at=_now(),
                        event=JobEvent(len(current.events) + 1, "error",
                                       "provider destroy preview stopped; reconciliation required",
                                       failure_data),
                    )
                else:
                    jobs.finish_if_running(
                    current,
                    status="failed", finished_at=_now(),
                    event=JobEvent(len(current.events) + 1, "error",
                                   "provider destroy preview stopped; reconciliation required",
                                   failure_data),
                    )
            except Exception:
                pass
        raise ProviderKeyedInitialDestroyPlanJobError(
            "reviewed full-state provider destroy preview stopped; no destroy was executed"
        ) from None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(instant: str) -> str:
    return (datetime.fromisoformat(instant) + timedelta(seconds=_CLAIM_SECONDS)).isoformat()


def _private_file_digest(path: Path, *, allow_collaborator_group: bool = False) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        mode = stat.S_IMODE(before.st_mode)
        collaborator_gid = _collaborator_group_gid() if allow_collaborator_group else None
        access_ok = ((mode == 0o600 or (mode == 0o640 and collaborator_gid is not None
                      and before.st_gid == collaborator_gid)) if allow_collaborator_group
                     else not mode & 0o077)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or not access_ok or before.st_nlink != 1):
            raise ValueError("saved destroy plan artifact is unsafe")
        digest = hashlib.sha256()
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_mode, before.st_uid, before.st_gid) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                after.st_mode, after.st_uid, after.st_gid):
            raise ValueError("saved destroy plan artifact changed during read")
        return digest.hexdigest()


def _stage_public_key(path: Path, content: str) -> tuple[Path, int, int]:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
    except Exception as error:
        os.close(descriptor)
        raise _PublicKeyCleanupUnproved("staged public key identity unproved") from error
    owned = (path, info.st_dev, info.st_ino)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
                raise ValueError("staged public key is unsafe")
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            return owned
    except Exception as error:
        # A failed write is still this process's exact O_EXCL inode. Keep it
        # for reconciliation if ownership cannot be proven and removed.
        try:
            _remove_owned_public_key(owned)
        except Exception as cleanup_error:
            raise _PublicKeyCleanupUnproved("staged public key cleanup unproved") from cleanup_error
        raise error


def _remove_owned_public_key(owned: tuple[Path, int, int]) -> None:
    path, device, inode = owned
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or (info.st_dev, info.st_ino) != (device, inode)
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError("staged public key ownership changed")
    path.unlink()
    if os.path.lexists(path):
        raise ValueError("staged public key removal is unproved")
