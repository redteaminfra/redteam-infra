# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant DevTest-only binder and one-shot full-state destroy controller.

No runtime dispatcher calls the controller. A saved plan and provider GET are
necessary evidence, while provider absence is proven only in a later gate.
"""

from __future__ import annotations

from app.services.provider_keyed_published_initial_cleanup_authority import queued_cleanup_event_data

import re
import hashlib
import json
import logging
import os
import subprocess
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from uuid import UUID, uuid4

from app.domain import JobEvent
from app.services.engagement_teardown import (
    ENGAGEMENT_TEARDOWN_ACTION, _fingerprint, _parent_id,
    _validated_parent_boundary, engagement_teardown_in_progress,
)
from app.services.provider_keyed_digitalocean_attachment import require_digitalocean_pre_destroy_membership
from app.services.provider_keyed_dns_cleanup_checkpoint import prove_provider_keyed_dns_cleanup_checkpoint
from app.services.provider_keyed_initial_attachment_adapter import derive_digitalocean_initial_attachment_intent
from app.services.provider_keyed_initial_destroy_apply import (
    ProviderKeyedInitialDestroyApplyResult, ProviderKeyedInitialDestroyApplyUncertainError,
    _require_empty_retained_state, apply_digitalocean_keyed_initial_destroy_plan,
)
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, StartedCommand, UnreapedGatedCommandError,
    run_gated_command,
)
from app.services.provider_keyed_initial_destroy_plan_job import (
    ACTION as PREVIEW_ACTION, _PRECOMMAND_RECOVERY, _private_file_digest,
)
from app.services.provider_keyed_initial_teardown import (
    DigitalOceanTeardownIntent, DigitalOceanTeardownPreview, _SHARED, _require_exact_state,
)
from app.services.provider_keyed_postapply_preflight import read_applied_digitalocean_provider_for_teardown
from app.services.provider_keyed_append_destroy_targets import bind_published_append_destroy
from app.services.provider_keyed_saved_plan_runner import _hash_file
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _inert_aborted_intent
from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_teardown_scope import build_digitalocean_keyed_teardown_scope
from app.services.provider_keyed_teardown_quiescence import (
    audit_pending_provider_keyed_bootstrap, audit_published_provider_keyed_bootstrap,
)
from app.services.provider_keyed_teardown_source import load_keyed_teardown_source
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


ACTION = "provider_keyed_initial_destroy_apply"
_PRECOMMAND_APPLY_RECOVERY = "provider destroy apply pre-command recovery reserved"
_SHOW_ONLY_APPLY_RECOVERY = "provider destroy apply show-only continuation reserved"
_OPERATION = "provider_keyed_teardown_fence"
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_PREVIEW_DATA_KEYS = frozenset({
    "planPath", "planSha256", "stateSha256", "sourceRevision", "sourceSha256",
    "markerSha256", "lockfileSha256", "topologySha256", "phaseSha256",
    "inputSha256", "providerConnectionId", "credentialSecretSha256",
    "credentialUpdatedAt", "terraformBinaryPath", "terraformBinarySha256",
    "scopeSnapshotId", "providerScopeSha256",
})
_PREVIEW_PHASES = ("version", "init", "plan", "show")
_LOGGER = logging.getLogger("barragan.provider_keyed_destroy")


def _sealed_cleanup_membership(parent, jobs, workspace, attachment, *, credentials,
                               transport, environment, expected_phase="applied"):
    from app.services.provider_keyed_published_initial_cleanup_authority import (
        KEY, build_cleanup_seal, validate_saved_cleanup,
    )
    snapshot = parent.input["scopeSnapshot"]
    if KEY not in snapshot:
        return False
    core = jobs.get(parent.input["coreJobId"])
    validate_saved_cleanup(parent, core, snapshot, jobs)
    if build_cleanup_seal(core, snapshot, jobs=jobs,
                          chains=SqlAlchemySketchChainRepository()) != snapshot[KEY]:
        raise ValueError("published cleanup bindings changed before GO")
    from app.services.provider_keyed_digitalocean_attachment import reconcile_digitalocean_initial_attachment
    reconcile_digitalocean_initial_attachment(
        workspace, attachment, environment=environment, deployment_target="barragan-testing",
        credential_repository=credentials, transport=transport, max_attempts=1,
        poll_interval_seconds=0, expected_phase=expected_phase)
    return True


def _precommand_failed_apply(child: StoredJobRun | None, parent: StoredJobRun,
                             bound: DestroyApplyReadBoundary) -> bool:
    """Accept only a quiescent, command-free failure before any phase write."""
    if (child is None or child.action != ACTION or child.status != "failed"
            or child.id != f"job-provider-keyed-initial-destroy-apply-{bound.core_job_id.removeprefix('job-')}"
            or child.target_id != parent.target_id or child.started_at is None
            or child.finished_at is None or child.artifact_refs != []
            or child.events != [
                JobEvent(1, "info", "provider destroy apply queued", {}),
                JobEvent(2, "info", "provider destroy apply started", {}),
                JobEvent(3, "error", "provider destroy apply stopped", {}),
            ]):
        return False
    expected = {
        "engagementId": parent.target_id, "coreJobId": bound.core_job_id,
        "corePlanId": bound.core_plan_id, "teardownParentId": parent.id,
        "scopeSnapshotId": bound.scope_snapshot_id,
        "providerScopeSha256": bound.provider_scope_sha256,
        "destroyPlanJobId": bound.preview_job_id,
        "planSha256": bound.preview.plan_sha256, "mutation": True,
    }
    if child.input != expected:
        return False
    try:
        finished = datetime.fromisoformat(child.finished_at)
        if finished.tzinfo is None:
            finished = finished.replace(tzinfo=timezone.utc)
        if finished > datetime.now(timezone.utc) - timedelta(seconds=60):
            return False
    except (TypeError, ValueError):
        return False
    return True


def _show_only_failed_apply(
    child: StoredJobRun | None, parent: StoredJobRun, bound: DestroyApplyReadBoundary,
    *, process_quiescence: Callable,
) -> bool:
    """Recognize one completed read-only show; no phase write or Apply intent."""
    if (child is None or child.status != "failed" or child.action != ACTION
            or child.id != f"job-provider-keyed-initial-destroy-apply-{bound.core_job_id.removeprefix('job-')}"
            or child.target_id != parent.target_id or child.artifact_refs != []
            or child.started_at is None or child.finished_at is None
            or len(child.events) != 8
            or [row.sequence for row in child.events] != list(range(1, 9))
            or [(row.level, row.message) for row in child.events] != [
                ("info", "provider destroy apply queued"),
                ("info", "provider destroy apply started"),
                ("error", "provider destroy apply stopped"),
                ("info", _PRECOMMAND_APPLY_RECOVERY),
                ("info", "provider destroy command intent fenced"),
                ("info", "provider destroy command started before GO"),
                ("info", "provider destroy command result fenced"),
                ("error", "provider destroy apply stopped")]
            or child.events[0].data != {} or child.events[1].data != {}
            or child.events[2].data != {} or child.events[7].data != {}):
        return False
    marker = child.events[3].data
    if (type(marker) is not dict
            or set(marker) != {"failedJournalSha256", "failedFinishedAt"}
            or marker["failedJournalSha256"] != job_event_digest(child.events[:3])
            or type(marker["failedFinishedAt"]) is not str):
        return False
    expected_input = {
        "engagementId": parent.target_id, "coreJobId": bound.core_job_id,
        "corePlanId": bound.core_plan_id, "teardownParentId": parent.id,
        "scopeSnapshotId": bound.scope_snapshot_id,
        "providerScopeSha256": bound.provider_scope_sha256,
        "destroyPlanJobId": bound.preview_job_id,
        "planSha256": bound.preview.plan_sha256, "mutation": True,
    }
    if child.input != expected_input:
        return False
    try:
        prior_finished = datetime.fromisoformat(marker["failedFinishedAt"])
        finished = datetime.fromisoformat(child.finished_at)
        if prior_finished.tzinfo is None:
            prior_finished = prior_finished.replace(tzinfo=timezone.utc)
        if finished.tzinfo is None:
            finished = finished.replace(tzinfo=timezone.utc)
        if (prior_finished > finished
                or finished > datetime.now(timezone.utc) - timedelta(seconds=60)):
            return False
    except (TypeError, ValueError):
        return False
    intent, started, result = [row.data for row in child.events[4:7]]
    argv = [str(bound.preview.terraform_binary_path), "show", "-json",
            str(bound.preview.plan_path)]
    argv_digest = hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest()
    if (type(intent) is not dict or type(started) is not dict or type(result) is not dict
            or set(intent) != {"phase", "invocationId", "argvSha256"}
            or set(started) != {"phase", "invocationId", "bootId", "pid", "pgid", "startTicks"}
            or set(result) != {"phase", "invocationId", "returnCode", "stdoutBytes",
                               "stderrBytes", "stdoutTruncated", "stderrTruncated"}
            or any(row["phase"] != "show" or row["invocationId"] != intent["invocationId"]
                   for row in (intent, started, result))
            or type(intent["invocationId"]) is not str or not intent["invocationId"]
            or intent["argvSha256"] != argv_digest
            or type(started["bootId"]) is not str or not started["bootId"]
            or type(started["pid"]) is not int or started["pid"] <= 0
            or type(started["pgid"]) is not int or started["pgid"] != started["pid"]
            or type(started["startTicks"]) is not int or started["startTicks"] <= 0
            or type(result["returnCode"]) is not int or result["returnCode"] != 0
            or any(type(result[key]) is not int or result[key] < 0
                   for key in ("stdoutBytes", "stderrBytes"))
            or result["stdoutTruncated"] is not False
            or result["stderrTruncated"] is not False):
        return False
    return process_quiescence(started["bootId"], started["pid"],
                              started["pgid"], started["startTicks"]) is True


def _diagnostic_exception_class(error: Exception) -> str:
    """Only emit fixed, message-free exception categories to operational logs."""
    if isinstance(error, TimeoutError):
        return "TimeoutError"
    if isinstance(error, PermissionError):
        return "PermissionError"
    if isinstance(error, OSError):
        return "OSError"
    if isinstance(error, ValueError):
        return "ValueError"
    if isinstance(error, UnreapedGatedCommandError):
        return "UnreapedGatedCommandError"
    return "OtherError"


def _audit_standard_successful_preview_journal(preview_job, workspace, evidence, plan_path: Path) -> None:
    """Require one complete, ordered, successful supervised preview attempt."""
    events = preview_job.events
    if len(events) != 16 or [event.sequence for event in events] != list(range(1, 17)):
        raise ValueError("destroy preview journal length differs")
    for event, message in zip(events[:3], (
        "provider destroy preview queued", "provider destroy preview started",
        "provider destroy preview staging intended",
    )):
        if event.level != "info" or event.message != message:
            raise ValueError("destroy preview journal prefix differs")
    if events[0].data != {} or events[1].data != {}:
        raise ValueError("destroy preview journal prefix data differs")
    staging = events[2].data
    staging_path = Path(staging.get("stagingPath", "")) if isinstance(staging, dict) else Path()
    input_path = Path(evidence["inputSha256"][0][0])
    staged_name = "input-0.json" if input_path.name.endswith(".json") else "input-0.input"
    if (not isinstance(staging, dict) or set(staging) != {
            "publicKeyPath", "stagingPath", "stagedInputPath", "credentialPath", "planPath"}
            or staging.get("publicKeyPath") != evidence["adminPublicKeyPath"]
            or staging_path.parent != workspace.path
            or re.fullmatch(r"\.barragan-destroy-inputs-[0-9a-f]{32}", staging_path.name) is None
            or staging.get("stagedInputPath") != str(staging_path / staged_name)
            or staging.get("credentialPath") != str(staging_path / "credential.json")
            or staging.get("planPath") != str(plan_path)):
        raise ValueError("destroy preview staging journal differs")
    invocations: set[str] = set()
    binary = preview_job.events[-1].data.get("terraformBinaryPath")
    if type(binary) is not str or not Path(binary).is_absolute():
        raise ValueError("destroy preview Terraform binary differs")
    expected_argv = {
        "version": [binary, "version", "-json"],
        "init": [binary, "init", "-input=false", "-lockfile=readonly", "-no-color"],
        "plan": [binary, "plan", "-destroy", "-input=false", "-lock=true", "-no-color",
                 f"-out={plan_path}", f"-var-file={staging_path / staged_name}",
                 f"-var-file={staging_path / 'credential.json'}"],
        "show": [binary, "show", "-json", str(plan_path)],
    }
    for index, phase in enumerate(_PREVIEW_PHASES):
        intent, started, result = events[3 + 3 * index:6 + 3 * index]
        if ([(row.level, row.message) for row in (intent, started, result)] != [
                ("info", "provider destroy preview command intent fenced"),
                ("info", "provider destroy preview command started before GO"),
                ("info", "provider destroy preview command result fenced")]):
            raise ValueError("destroy preview command journal order differs")
        intent_data, start_data, result_data = intent.data, started.data, result.data
        if (not all(isinstance(value, dict) for value in (intent_data, start_data, result_data))
                or set(intent_data) != {"phase", "invocationId", "argvSha256"}
                or set(start_data) != {"phase", "invocationId", "bootId", "pid", "pgid", "startTicks"}
                or set(result_data) != {"phase", "invocationId", "returnCode", "stdoutBytes",
                                        "stderrBytes", "stdoutTruncated", "stderrTruncated"}):
            raise ValueError("destroy preview command journal fields differ")
        invocation = intent_data["invocationId"]
        if (any(row["phase"] != phase or row["invocationId"] != invocation
                for row in (intent_data, start_data, result_data))
                or type(invocation) is not str or not invocation or invocation in invocations
                or type(intent_data["argvSha256"]) is not str
                or intent_data["argvSha256"] != hashlib.sha256(json.dumps(
                    expected_argv[phase], separators=(",", ":")).encode()).hexdigest()
                or type(start_data["bootId"]) is not str or not start_data["bootId"]
                or type(start_data["pid"]) is not int or start_data["pid"] <= 0
                or type(start_data["pgid"]) is not int or start_data["pgid"] != start_data["pid"]
                or type(start_data["startTicks"]) is not int or start_data["startTicks"] <= 0
                or type(result_data["returnCode"]) is not int or result_data["returnCode"] != 0
                or any(type(result_data[key]) is not int or result_data[key] < 0
                       for key in ("stdoutBytes", "stderrBytes"))
                or result_data["stdoutTruncated"] is not False
                or result_data["stderrTruncated"] is not False):
            raise ValueError("destroy preview command journal identity differs")
        invocations.add(invocation)
    if events[-1].level != "info" or events[-1].message != "reviewed full-state provider destroy plan saved":
        raise ValueError("destroy preview terminal journal differs")


def _audit_completed_preview_journal(preview_job, workspace, evidence, plan_path: Path) -> None:
    """Keep the normal parser intact; admit one exact failed pre-command prefix."""
    events = preview_job.events
    if len(events) == 16:
        _audit_standard_successful_preview_journal(preview_job, workspace, evidence, plan_path)
        return
    if (len(events) != 19 or [row.sequence for row in events] != list(range(1, 20))
            or [(row.level, row.message) for row in events[:5]] != [
                ("info", "provider destroy preview queued"),
                ("info", "provider destroy preview started"),
                ("info", "provider destroy preview staging intended"),
                ("error", "provider destroy preview stopped; reconciliation required"),
                ("info", _PRECOMMAND_RECOVERY)]
            or events[0].data != {} or events[1].data != {}
            or events[3].data != {"failureStage": "other"}
            or type(events[4].data) is not dict
            or set(events[4].data) != {"failedJournalSha256", "failedFinishedAt"}
            or events[4].data["failedJournalSha256"] != job_event_digest(events[:4])
            or type(events[4].data["failedFinishedAt"]) is not str
            or not events[4].data["failedFinishedAt"]):
        raise ValueError("recovered destroy preview journal differs")
    staging = events[2].data
    old = Path(staging.get("stagingPath", "")) if type(staging) is dict else Path()
    input_path = Path(evidence["inputSha256"][0][0])
    name = "input-0.json" if input_path.name.endswith(".json") else "input-0.input"
    if (type(staging) is not dict or old.parent != workspace.path
            or re.fullmatch(r"\.barragan-destroy-inputs-[0-9a-f]{32}", old.name) is None
            or staging != {"publicKeyPath": evidence["adminPublicKeyPath"],
                           "stagingPath": str(old), "stagedInputPath": str(old / name),
                           "credentialPath": str(old / "credential.json"),
                           "planPath": str(plan_path)}
            or old == Path(events[5].data.get("stagingPath", ""))):
        raise ValueError("recovered destroy preview staging differs")
    projected = [*events[:2], *events[5:]]
    projected = [replace(row, sequence=index) for index, row in enumerate(projected, 1)]
    _audit_standard_successful_preview_journal(
        replace(preview_job, events=projected), workspace, evidence, plan_path)


def _audit_successful_preview_journal(preview_job, workspace, evidence, plan_path: Path) -> None:
    """Shared preview audit used by apply and later teardown boundary readers."""
    _audit_completed_preview_journal(preview_job, workspace, evidence, plan_path)


class ProviderKeyedInitialDestroyApplyJobError(ValueError):
    """The saved plan is not a currently proven, complete destroy authority."""


@dataclass(frozen=True)
class DestroyApplyReadBoundary:
    teardown_parent_id: str
    core_job_id: str
    core_plan_id: str
    scope_snapshot_id: str
    provider_scope_sha256: str
    preview_job_id: str
    workspace: object
    teardown_intent: DigitalOceanTeardownIntent
    preview: DigitalOceanTeardownPreview
    attachment: object
    topology_input_path: Path | None = None
    topology_input_sha256: str | None = None


def preflight_digitalocean_initial_destroy_apply(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, sketch_repository=None,
    engagement_repository=None, credential_repository=None, lease_lookup=None,
    scope_builder: Callable = build_digitalocean_keyed_teardown_scope,
    applied_reader: Callable = read_applied_digitalocean_provider_for_teardown,
    attachment_builder: Callable = derive_digitalocean_initial_attachment_intent,
    handoff_auditor: Callable = audit_pending_provider_keyed_bootstrap,
    state_validator: Callable = _require_exact_state,
    membership_veto: Callable = require_digitalocean_pre_destroy_membership,
    membership_transport=None,
) -> DestroyApplyReadBoundary:
    """Bind current complete state and provider membership; perform no writes."""
    try:
        if (environment != "devtest" or not isinstance(state_root, Path)
                or state_root != _default_state_root()
                or not isinstance(teardown_parent_id, str) or not teardown_parent_id):
            raise ValueError("unsupported destroy apply boundary")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        chains = sketch_repository or SqlAlchemySketchChainRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        lookup = lease_lookup or _db_lease_lookup
        parent = jobs.get(teardown_parent_id)
        if (parent is None or parent.action != ENGAGEMENT_TEARDOWN_ACTION
                or parent.status != "queued" or parent.started_at is not None
                or parent.finished_at is not None or parent.input.get("phase") != "queued"
                or parent.input.get("mutation") is not True or len(parent.events) != 1
                or parent.events[0].message != "engagement teardown queued"):
            raise ValueError("confirmed queued parent differs")
        core, snapshot = _validated_parent_boundary(parent, jobs)
        if (snapshot.get("snapshotId") != _fingerprint({
                key: value for key, value in snapshot.items() if key != "snapshotId"})
                or parent.events[0].data != queued_cleanup_event_data(snapshot)
                or parent.id != _parent_id(core.id)
                or engagement_teardown_in_progress(snapshot["engagementId"], repository=jobs) != parent
                or core.status != "succeeded"
                or core.input.get("sketchStateSchema") != "provider-keyed-v2"
                or snapshot["coreJobId"] != core.id):
            raise ValueError("confirmed snapshot differs")
        scopes = snapshot.get("providerScopes")
        if not isinstance(scopes, list) or len(scopes) != 1 or not isinstance(scopes[0], dict):
            raise ValueError("provider scope is incomplete")
        scope = scopes[0]
        engagement_id, plan_id = snapshot["engagementId"], scope["corePlanId"]
        plan = plans.get(plan_id)
        if (core.input.get("corePlanId") != plan_id or plan is None
                or plan.engagement_id != engagement_id or plan.status != "applied"
                or plan.apply_job_id != core.id or lookup(engagement_id) != (plan_id, _OPERATION)):
            raise ValueError("retagged core mutation lease differs")
        if scope_builder(
            engagement_id, core.id, environment=environment, state_root=state_root,
            allowed_teardown_parent_id=parent.id, engagement_repository=engagement_repository,
            sketch_repository=chains, job_repository=jobs, plan_repository=plans,
            credential_repository=credentials,
        ) != scope:
            raise ValueError("full provider scope differs")
        source = None
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
                raise ValueError("published source differs")
        else:
            handoff = handoff_auditor(
                core.id, confirmed_scope=scope, confirmed_scope_sha256=_fingerprint(snapshot),
                workspace_root=Path(scope["workspace"]), job_repository=jobs,
            )
            initial = jobs.get(handoff.parent_job_id)
            failed_prebinding = snapshot["dnsCleanupManifest"].get("schema") == (
                "provider-keyed-empty-dns-prebinding-v1")
            if (not handoff.parent_job_id or initial is None
                    or (failed_prebinding and (
                        initial.status != "failed" or initial.input.get("phase") != "attention"
                        or job_event_digest(initial.events) != snapshot["dnsCleanupManifest"]["initialJournalSha256"]
                        or handoff.command_count not in (0, 2, 8)))
                    or (not failed_prebinding
                        and initial.input.get("phase") != "teardown_handoff_pending")):
                raise ValueError("sealed bootstrap handoff differs")
        resources = scope["resources"]
        ids = {row["address"]: row["id"] for row in resources}
        if "publishedAppendSource" in parent.input:
            expanded = bind_published_append_destroy(
                parent.id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans, sketch_repository=chains,
                engagement_repository=engagement_repository,
                credential_repository=credentials,
            )
            workspace, attachment, teardown_intent = (
                expanded.workspace, expanded.attachment, expanded.intent)
            evidence = {"inputSha256": [[str(expanded.input_path), expanded.input_sha256]],
                        "adminPublicKeyPath": str(expanded.input_path.parent / "admin-public")}
            if (ids != teardown_intent.resource_ids
                    or attachment.state_sha256 != scope["stateSha256"]):
                raise ValueError("current appended resource identity differs")
        else:
            active = [row for row in chains.list_for_engagement(engagement_id)
                      if not _inert_aborted_intent(row, engagement_id)]
            mode = ("applied_read" if len(active) == 2 and
                    all(row.status == "pending" and not row.nodes for row in active)
                    else "materialized_read")
            intent, workspace, evidence, apply_job = applied_reader(
                engagement_id, core.id, environment=environment, state_root=state_root,
                mode=mode, allowed_teardown_parent_id=parent.id,
                engagement_repository=engagement_repository, sketch_repository=chains,
                job_repository=jobs, plan_repository=plans, credential_repository=credentials,
            )
            attachment = attachment_builder(intent, workspace, evidence, apply_job)
            if (len(ids) != len(resources) or set(ids) != set(intent.nodes) | _SHARED
                    or workspace.path != Path(scope["workspace"])
                    or workspace.provider_connection_id != scope["providerConnectionId"]
                    or workspace.source_revision != scope["sourceRevision"]
                    or intent.revision_id != scope["revisionId"]
                    or intent.selector_tag != scope["selectorTag"]
                    or attachment.state_sha256 != scope["stateSha256"]
                    or attachment.credential_record_id != workspace.provider_connection_id
                    or {node.address: str(node.droplet_id) for node in attachment.nodes}
                    != {address: ids[address] for address in intent.nodes}
                    or str(attachment.firewall_id) != ids["digitalocean_firewall.firewall"]):
                raise ValueError("current applied resource identity differs")
            teardown_intent = DigitalOceanTeardownIntent(
                intent.nodes, intent.firewall, ids, scope["stateSha256"],
                attachment.credential_record_id, attachment.credential_secret_sha256,
                attachment.credential_updated_at,
            )
        state_validator(workspace, teardown_intent)
        preview_id = f"job-provider-keyed-initial-destroy-plan-{core.id.removeprefix('job-')}"
        preview_job = jobs.get(preview_id)
        if (preview_job is None or preview_job.action != PREVIEW_ACTION
                or preview_job.status != "succeeded" or preview_job.finished_at is None
                or preview_job.input != {
                    "engagementId": engagement_id, "coreJobId": core.id,
                    "corePlanId": plan_id, "teardownParentId": parent.id,
                    "scopeSnapshotId": snapshot["snapshotId"],
                    "providerScopeSha256": snapshot["providerScopeSha256"], "mutation": True,
                } or preview_job.target_id != engagement_id
                or preview_job.requested_by != parent.requested_by
                or len([row for row in jobs.list_for_engagement(engagement_id)
                        if row.action == PREVIEW_ACTION]) != 1
                or not preview_job.events or preview_job.events[-1].message
                != "reviewed full-state provider destroy plan saved"):
            raise ValueError("successful destroy preview differs")
        data = preview_job.events[-1].data
        plan_path = workspace.path / ".barragan-initial-destroy.tfplan"
        if (not isinstance(data, dict) or set(data) != _PREVIEW_DATA_KEYS
                or preview_job.artifact_refs != [str(plan_path)]
                or data["planPath"] != str(plan_path)
                or not isinstance(data["planSha256"], str)
                or _HASH.fullmatch(data["planSha256"]) is None
                or _private_file_digest(plan_path) != data["planSha256"]
                or data["stateSha256"] != scope["stateSha256"]
                or data["sourceRevision"] != workspace.source_revision
                or data["sourceSha256"] != workspace.source_sha256
                or data["providerConnectionId"] != workspace.provider_connection_id
                or data["scopeSnapshotId"] != snapshot["snapshotId"]
                or data["providerScopeSha256"] != snapshot["providerScopeSha256"]
                or data["credentialSecretSha256"] != teardown_intent.credential_secret_sha256
                or data["credentialUpdatedAt"] != teardown_intent.credential_updated_at):
            raise ValueError("saved destroy-plan artifact differs")
        inputs = evidence["inputSha256"]
        if data["inputSha256"] != inputs or len(inputs) != 1 or len(inputs[0]) != 2:
            raise ValueError("reviewed original plan input differs")
        _audit_completed_preview_journal(preview_job, workspace, evidence, plan_path)
        preview = DigitalOceanTeardownPreview(
            plan_path, data["planSha256"], data["stateSha256"], data["sourceSha256"],
            data["markerSha256"], data["lockfileSha256"], data["topologySha256"],
            data["phaseSha256"], ((inputs[0][0], inputs[0][1]),),
            data["providerConnectionId"], data["credentialSecretSha256"],
            data["credentialUpdatedAt"], Path(data["terraformBinaryPath"]),
            data["terraformBinarySha256"],
        )
        if (not preview.terraform_binary_path.is_absolute()
                or any(_HASH.fullmatch(value) is None for value in
                       (preview.marker_sha256, preview.lockfile_sha256,
                        preview.topology_sha256, preview.phase_sha256,
                        preview.terraform_binary_sha256, preview.input_sha256[0][1]))):
            raise ValueError("saved destroy preview evidence is malformed")
        if not _sealed_cleanup_membership(parent, jobs, workspace, attachment,
                credentials=credentials, transport=membership_transport, environment=environment):
            membership_veto(
                workspace, attachment, environment=environment,
                deployment_target="barragan-testing", credential_repository=credentials,
                transport=membership_transport,
            )
        if (jobs.get(parent.id) != parent or jobs.get(preview_id) != preview_job
                or lookup(engagement_id) != (plan_id, _OPERATION)
                or (source is not None and load_keyed_teardown_source(
                    parent.id, phase="pre_go", environment=environment, state_root=state_root,
                    job_repository=jobs, plan_repository=plans, sketch_repository=chains,
                ) != source)
                or scope_builder(
                    engagement_id, core.id, environment=environment, state_root=state_root,
                    allowed_teardown_parent_id=parent.id,
                    engagement_repository=engagement_repository, sketch_repository=chains,
                    job_repository=jobs, plan_repository=plans,
                    credential_repository=credentials,
                ) != scope or _private_file_digest(plan_path) != preview.plan_sha256):
            raise ValueError("destroy authority changed during provider GET")
        return DestroyApplyReadBoundary(
            parent.id, core.id, plan_id, snapshot["snapshotId"],
            snapshot["providerScopeSha256"], preview_id, workspace,
            teardown_intent, preview, attachment,
            expanded.input_path if "publishedAppendSource" in parent.input else None,
            expanded.input_sha256 if "publishedAppendSource" in parent.input else None,
        )
    except Exception:
        raise ProviderKeyedInitialDestroyApplyJobError(
            "reviewed full-state destroy apply preflight stopped; no destroy was executed"
        ) from None


def run_digitalocean_initial_destroy_apply_job(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, sketch_repository=None,
    engagement_repository=None, credential_repository=None, lease_lookup=None,
    scope_builder: Callable = build_digitalocean_keyed_teardown_scope,
    applied_reader: Callable = read_applied_digitalocean_provider_for_teardown,
    attachment_builder: Callable = derive_digitalocean_initial_attachment_intent,
    handoff_auditor: Callable = audit_pending_provider_keyed_bootstrap,
    state_validator: Callable = _require_exact_state,
    membership_veto: Callable = require_digitalocean_pre_destroy_membership,
    membership_transport=None,
    apply: Callable = apply_digitalocean_keyed_initial_destroy_plan,
    gated_command_runner: Callable = run_gated_command,
    live_inspector_prover: Callable | None = None,
    dns_checkpoint_prover: Callable = prove_provider_keyed_dns_cleanup_checkpoint,
    domain_repository=None, dns_adapter=None,
    command_environment=None, process_quiescence: Callable | None = None,
) -> StoredJobRun:
    """Run one reviewed destroy Apply child, with bounded DevTest recovery."""
    jobs = job_repository or SqlAlchemyJobRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    diagnostic_stage = "preflight"
    diagnostic_error_class: str | None = None
    binder_args = dict(
        environment=environment, state_root=state_root, job_repository=jobs,
        plan_repository=plan_repository, sketch_repository=sketch_repository,
        engagement_repository=engagement_repository, credential_repository=credentials,
        lease_lookup=lookup, scope_builder=scope_builder, applied_reader=applied_reader,
        attachment_builder=attachment_builder, handoff_auditor=handoff_auditor,
        state_validator=state_validator, membership_veto=membership_veto,
        membership_transport=membership_transport,
    )
    try:
        bound = preflight_digitalocean_initial_destroy_apply(teardown_parent_id, **binder_args)
        parent = jobs.get(bound.teardown_parent_id)
        published = parent is not None and "publishedSource" in parent.input
        preview_job = jobs.get(bound.preview_job_id)
        child_id = f"job-provider-keyed-initial-destroy-apply-{bound.core_job_id.removeprefix('job-')}"
        base_input = {
            "engagementId": parent.target_id, "coreJobId": bound.core_job_id,
            "corePlanId": bound.core_plan_id, "teardownParentId": parent.id,
            "scopeSnapshotId": bound.scope_snapshot_id,
            "providerScopeSha256": bound.provider_scope_sha256,
            "destroyPlanJobId": bound.preview_job_id,
            "planSha256": bound.preview.plan_sha256, "mutation": True,
        }
        prior = jobs.get(child_id)
        siblings = [row for row in jobs.list_for_engagement(parent.target_id)
                    if row.action == ACTION]
        show_only = False
        if prior is not None or siblings:
            if (environment != "devtest" or "publishedAppendSource" not in parent.input
                    or len(siblings) != 1 or siblings[0] != prior
                    or not isinstance(jobs, SqlAlchemyJobRepository)):
                raise ValueError("destroy apply child already exists")
            if not _precommand_failed_apply(prior, parent, bound):
                from app.services.provider_keyed_initial_destroy_pre_go_recovery import (
                    _process_quiescent,
                )
                show_only = _show_only_failed_apply(
                    prior, parent, bound,
                    process_quiescence=process_quiescence or _process_quiescent)
                if not show_only:
                    raise ValueError("destroy apply child already exists")
            owner = f"provider-keyed-destroy-apply-{uuid4().hex}"
            token = uuid4().hex
            claimed_at = _now()
            original_prior = prior
            def recovery_authority():
                return (
                    preflight_digitalocean_initial_destroy_apply(
                        teardown_parent_id, **binder_args) == bound
                    and jobs.get(parent.id) == parent
                    and jobs.get(preview_job.id) == preview_job
                    and (_show_only_failed_apply(
                        jobs.get(child_id), parent, bound,
                        process_quiescence=process_quiescence or _process_quiescent)
                         if show_only else _precommand_failed_apply(
                             jobs.get(child_id), parent, bound)))
            reserve = (jobs.rearm_exact_show_only_destroy_apply if show_only
                       else jobs.rearm_exact_precommand_destroy_apply)
            prior = reserve(
                original_prior, authority=recovery_authority,
                owner=owner, token=token, claimed_at=claimed_at,
                expires_at=_later(claimed_at))
            if prior is None:
                raise ValueError("destroy apply recovery authority changed")
        queued = StoredJobRun(
            id=child_id, action=ACTION, status="queued", target=f"engagement:{parent.target_id}",
            target_type="engagement", target_id=parent.target_id,
            requested_by=parent.requested_by, input=base_input, artifact_refs=[],
            created_at=_now(), started_at=None, finished_at=None,
            events=[JobEvent(1, "info", "provider destroy apply queued", {})],
        )
        saved = prior if prior is not None else jobs.save_if_absent(queued)
        # SQLAlchemy's SQLite DateTime round-trip removes the UTC suffix.
        # Continue from the persisted reservation, while checking every field
        # and the exact instant just as the core destroy-apply writer does.
        if (prior is None and (saved is None or saved.id != queued.id or saved.action != queued.action
                or saved.status != queued.status or saved.target != queued.target
                or saved.target_type != queued.target_type
                or saved.target_id != queued.target_id
                or saved.requested_by != queued.requested_by
                or saved.input != queued.input or saved.artifact_refs != queued.artifact_refs
                or saved.created_at not in {queued.created_at,
                                           queued.created_at.removesuffix("+00:00")}
                or saved.started_at is not None or saved.finished_at is not None
                or saved.events != queued.events or jobs.get(child_id) != saved)):
            raise ValueError("destroy apply child creation lost")
        current = (saved if prior is not None else jobs.start_if_queued(
            saved, started_at=_now(),
            event=JobEvent(2, "info", "provider destroy apply started", {}),
        ))
        if (current is None or current.status != "running"
                or {key: value for key, value in current.input.items()
                    if not key.startswith("claim")} != base_input
                or current.events != (saved.events if prior is not None else [
                    *saved.events, JobEvent(2, "info", "provider destroy apply started", {})])
                or jobs.get(child_id) != current):
            raise ValueError("destroy apply child start lost")
        if prior is None:
            owner = f"provider-keyed-destroy-apply-{uuid4().hex}"
            token = uuid4().hex
            claimed_at = _now()
            claimed = jobs.claim_lease(
                child_id, owner=owner, token=token, claimed_at=claimed_at,
                expires_at=_later(claimed_at), eligible_statuses={"running"},
            )
        else:
            claimed = current
        if (claimed is None or claimed.events != current.events
                or claimed.input.get("claimOwner") != owner
                or claimed.input.get("claimToken") != token):
            raise ValueError("destroy apply child claim lost")
        current = claimed
        # This complete reread must happen after claim and before any phase write.
        diagnostic_stage = "claimed_preflight"
        again = preflight_digitalocean_initial_destroy_apply(teardown_parent_id, **binder_args)
        if again != bound:
            raise ValueError("destroy authority changed after claim")
        confirmed_snapshot = parent.input["scopeSnapshot"]
        confirmed_scope = confirmed_snapshot["providerScopes"][0]
        chains = sketch_repository or SqlAlchemySketchChainRepository()
        initial_rows = deepcopy([row for row in chains.list_for_engagement(parent.target_id)
                                 if not _inert_aborted_intent(row, parent.target_id)])
        if published:
            # This is the final live applied-scope audit. After the phase
            # marker is written, Terraform may erase the nonempty state.
            published_source = load_keyed_teardown_source(
                parent.id, phase="pre_go", environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plan_repository,
                sketch_repository=chains,
            )
            expected_variant = ("published_append" if "publishedAppendSource" in parent.input
                                else "published")
            if published_source.variant != expected_variant:
                raise ValueError("published destroy source differs")
            sealed_initial = deepcopy(jobs.get(published_source.initial_job_id))
            sealed_core = deepcopy(jobs.get(bound.core_job_id))
            if expected_variant == "published_append":
                sealed_append_record = deepcopy(parent.input["publishedAppendSource"])
                append = jobs.get(parent.input["publishedAppendSource"]["append_job_id"])
                sealed_append = deepcopy(append)
                sealed_append_children = tuple(deepcopy(jobs.get(append.input[f"{kind}JobId"]))
                                               for kind in ("plan", "apply", "hostProof"))
                if any(child is None for child in sealed_append_children):
                    raise ValueError("published append child is absent")
                initial_handoff = published_source.published_source_sha256
            else:
                initial_handoff = audit_published_provider_keyed_bootstrap(
                    bound.core_job_id, confirmed_scope=confirmed_scope,
                    workspace_root=bound.workspace.path, job_repository=jobs,
                )
        else:
            initial_handoff = handoff_auditor(
                bound.core_job_id, confirmed_scope=confirmed_scope,
                confirmed_scope_sha256=_fingerprint(confirmed_snapshot),
                workspace_root=bound.workspace.path, job_repository=jobs,
            )
            sealed_unpublished_initial = deepcopy(jobs.get(initial_handoff.parent_job_id))
            if sealed_unpublished_initial is None:
                raise ValueError("unpublished initial source job is absent")
            failed_prebinding = confirmed_snapshot["dnsCleanupManifest"]["schema"] == (
                "provider-keyed-empty-dns-prebinding-v1")
            if failed_prebinding:
                from app.services.provider_keyed_comprehensive_teardown import _child_id

                failed_source = load_keyed_teardown_source(
                    parent.id, phase="pre_go", environment=environment,
                    state_root=state_root, job_repository=jobs,
                    plan_repository=plan_repository, sketch_repository=chains,
                )
                if (failed_source.variant != "failed_prebinding"
                        or failed_source.core_job_id != bound.core_job_id
                        or failed_source.core_plan_id != bound.core_plan_id
                        or failed_source.snapshot_id != bound.scope_snapshot_id
                        or failed_source.provider_scope_sha256 != bound.provider_scope_sha256
                        or failed_source.initial_job_id != initial_handoff.parent_job_id
                        or failed_source.initial_journal_sha256 != confirmed_snapshot[
                            "dnsCleanupManifest"]["initialJournalSha256"]):
                    raise ValueError("failed prebinding destroy source differs")
                coordinator_id = _child_id(bound.core_job_id)
                sealed_coordinator = deepcopy(jobs.get(coordinator_id))
                if sealed_coordinator is None:
                    raise ValueError("failed prebinding coordinator is absent")

        def phase_independent_authority(*, pre_destroy_handoff: bool = True) -> None:
            current_rows = [row for row in chains.list_for_engagement(parent.target_id)
                            if not _inert_aborted_intent(row, parent.target_id)]
            fingerprints = confirmed_scope["chainFingerprints"]
            snapshots = {row["chainId"]: row for row in confirmed_snapshot["chains"]}
            if (current_rows != initial_rows or len(current_rows) != 2
                    or {row.chain_id for row in current_rows} != set(confirmed_scope["chainIds"])
                    or (snapshots and set(snapshots) != set(confirmed_scope["chainIds"]))
                    or any(sketch_chain_intent_fingerprint(row) != fingerprints[row.chain_id]
                           or (snapshots and (
                               row.status != snapshots[row.chain_id]["status"]
                               or row.deploy_job_id != snapshots[row.chain_id]["deployJobId"]))
                           for row in current_rows)
                    or (pre_destroy_handoff and (audit_published_provider_keyed_bootstrap(
                        bound.core_job_id, confirmed_scope=confirmed_scope,
                        workspace_root=bound.workspace.path, job_repository=jobs,
                    ) != initial_handoff if published and expected_variant == "published"
                        else (parent.input.get("publishedAppendSource") != sealed_append_record
                              if published and expected_variant == "published_append"
                              else handoff_auditor(
                                  bound.core_job_id, confirmed_scope=confirmed_scope,
                                  confirmed_scope_sha256=_fingerprint(confirmed_snapshot),
                                  workspace_root=bound.workspace.path, job_repository=jobs,
                              ) != initial_handoff)))
                    or (published and expected_variant == "published_append"
                        and (jobs.get(sealed_append.id) != sealed_append
                             or any(jobs.get(child.id) != child
                                    for child in sealed_append_children)))
                    or (published and (jobs.get(published_source.initial_job_id) != sealed_initial
                                       or jobs.get(bound.core_job_id) != sealed_core
                                       or job_event_digest(sealed_initial.events)
                                          != published_source.initial_journal_sha256))
                    or (not published and jobs.get(sealed_unpublished_initial.id)
                        != sealed_unpublished_initial)
                    or (not published and failed_prebinding
                        and jobs.get(coordinator_id) != sealed_coordinator)):
                raise ValueError("confirmed chain projection or sealed handoff changed")
        command_phase = "show"
        command_stage = "requested"
        command_intent: CommandIntent | None = None
        command_started: StartedCommand | None = None
        phase_written = False
        phase_completed = False
        uncertain = False
        dns_checkpoint: dict | None = None

        def claim_expiry(instant: str) -> str:
            # Only the one-shot apply phase needs room for serial live proofs.
            # The pre-show and show claim retain their short lease.
            return _later(instant, seconds=1200 if phase_written else 60)

        def authority() -> None:
            if lookup(parent.target_id) != (bound.core_plan_id, _OPERATION):
                raise ValueError("destroy core lease changed")
            observed = jobs.get(child_id)
            expiry = datetime.fromisoformat(current.input["claimExpiresAt"])
            if (observed != current or datetime.now(timezone.utc) >= expiry
                    or jobs.get(parent.id) != parent or jobs.get(preview_job.id) != preview_job):
                raise ValueError("destroy claim or confirmed parent changed")

        def append(message: str, data: dict) -> None:
            nonlocal current
            authority()
            instant = _now()
            updated = jobs.append_destroy_apply_event_if_running_claimed(
                current, owner=owner, token=token,
                expected_event_digest=job_event_digest(current.events),
                heartbeat_at=instant, expires_at=claim_expiry(instant),
                event=JobEvent(len(current.events) + 1, "info", message, data),
            )
            if updated is None:
                raise ValueError("destroy apply journal claim changed")
            current = updated

        def renew_claim() -> None:
            nonlocal current
            authority()
            instant = _now()
            renewed = jobs.renew_lease(
                child_id, owner=owner, token=token, heartbeat_at=instant,
                expires_at=claim_expiry(instant),
            )
            if renewed is None or renewed.events != current.events:
                raise ValueError("destroy DNS checkpoint claim changed")
            current = renewed
            authority()

        def fresh_dns_checkpoint() -> dict:
            proof = dns_checkpoint_prover(
                confirmed_snapshot, job_repository=jobs,
                domain_repository=domain_repository, adapter=dns_adapter,
                fence=renew_claim,
            )
            if (type(proof) is not dict or set(proof) != {
                    "dnsCleanupManifestSha256", "dnsCleanupHandoffJournalSha256",
                    "dnsCleanupCheckpointSha256"}
                    or proof["dnsCleanupManifestSha256"] != confirmed_snapshot[
                        "dnsCleanupManifest"]["manifestSha256"]
                    or proof["dnsCleanupCheckpointSha256"] != _fingerprint({
                        "scopeSnapshotId": bound.scope_snapshot_id,
                        "dnsCleanupManifestSha256": proof["dnsCleanupManifestSha256"],
                        "dnsCleanupHandoffJournalSha256": proof["dnsCleanupHandoffJournalSha256"],
                    })):
                raise ValueError("fresh DNS cleanup checkpoint differs")
            renew_claim()
            return proof

        def phase_write_intent(path: Path, phase: str) -> None:
            nonlocal phase_written, phase_completed, command_stage, dns_checkpoint, diagnostic_stage
            diagnostic_stage = "phase_write"
            if path != bound.workspace.path / ".barragan-apply-phase.json" or phase not in {
                    "destroy_started", "destroy_applied"}:
                raise ValueError("destroy phase path differs")
            if phase == "destroy_started" and (command_stage != "show_complete" or phase_written):
                raise ValueError("destroy phase preceded reviewed show")
            if phase == "destroy_applied" and (command_stage != "apply_complete" or phase_completed):
                raise ValueError("destroy applied phase preceded supervised apply")
            if phase == "destroy_started":
                # Terraform can erase the pre-destroy state after this point.
                # Seal the exact independent identity now, so recovery never
                # needs to infer owned IDs or lineage from a partial state.
                diagnostic_stage = "prestate_authority"
                authority()
                phase_independent_authority()
                if published and load_keyed_teardown_source(
                    parent.id, phase="pre_go", environment=environment,
                    state_root=state_root, job_repository=jobs,
                    plan_repository=plan_repository, sketch_repository=chains,
                ) != published_source:
                    raise ValueError("published source changed before phase write")
                if not published and failed_prebinding and load_keyed_teardown_source(
                    parent.id, phase="pre_go", environment=environment,
                    state_root=state_root, job_repository=jobs,
                    plan_repository=plan_repository, sketch_repository=chains,
                ) != failed_source:
                    raise ValueError("failed prebinding source changed before phase write")
                prior = _require_exact_state(bound.workspace, bound.teardown_intent)
                UUID(prior["lineage"])
                if type(prior["serial"]) is not int or prior["serial"] < 1:
                    raise ValueError("reviewed pre-destroy state generation differs")
                resource_ids = dict(bound.teardown_intent.resource_ids)
                sealed_ids = {row["address"]: row["id"] for row in confirmed_scope["resources"]}
                if resource_ids != sealed_ids or len(resource_ids) != len(confirmed_scope["resources"]):
                    raise ValueError("confirmed pre-destroy resource identities differ")
                diagnostic_stage = "prestate_dns"
                dns_checkpoint = fresh_dns_checkpoint()
                append("provider destroy prestate identity fenced", {
                    "coreJobId": bound.core_job_id, "corePlanId": bound.core_plan_id,
                    "scopeSnapshotId": bound.scope_snapshot_id,
                    "providerScopeSha256": bound.provider_scope_sha256,
                    "preDestroyStateSha256": bound.teardown_intent.state_sha256,
                    "stateLineage": prior["lineage"], "preDestroySerial": prior["serial"],
                    "resourceIds": resource_ids, "resourceIdsSha256": _fingerprint(resource_ids),
                    "selectorTag": confirmed_scope["selectorTag"],
                    "credentialRecordId": bound.teardown_intent.credential_record_id,
                    "credentialSecretSha256": bound.teardown_intent.credential_secret_sha256,
                    "credentialUpdatedAt": bound.teardown_intent.credential_updated_at,
                    **dns_checkpoint,
                })
            append("provider destroy phase write intended", {"phase": phase, "path": str(path)})
            if phase == "destroy_started":
                phase_written = True
                command_stage = "requested"
            else:
                phase_completed = True

        def intent_callback(value: CommandIntent) -> None:
            nonlocal command_stage, command_intent
            if (command_stage != "requested" or value.scratch_path != str(bound.workspace.path)
                    or not value.invocation_id or not isinstance(value.argv_sha256, str)
                    or _HASH.fullmatch(value.argv_sha256) is None):
                raise ValueError("destroy command intent differs")
            append("provider destroy command intent fenced", {
                "phase": command_phase, "invocationId": value.invocation_id,
                "argvSha256": value.argv_sha256,
            })
            command_intent, command_stage = value, "intent"

        def started_callback(value: StartedCommand) -> None:
            nonlocal command_stage, command_started, diagnostic_stage
            if command_stage != "intent" or value.intent != command_intent:
                raise ValueError("destroy command start differs")
            append("provider destroy command started before GO", {
                "phase": command_phase, "invocationId": value.intent.invocation_id,
                "bootId": value.identity.boot_id, "pid": value.identity.pid,
                "pgid": value.identity.pgid, "startTicks": value.identity.start_ticks,
            })
            command_started, command_stage = value, "started"
            if command_phase == "apply":
                # The gated child remains blocked. A slow GET that loses the
                # claim must abort before GO rather than use stale membership.
                diagnostic_stage = "pre_go_membership"
                if not _sealed_cleanup_membership(jobs.get(teardown_parent_id), jobs,
                        bound.workspace, bound.attachment, credentials=credentials,
                        transport=membership_transport, environment=environment,
                        expected_phase="destroy_started"):
                    membership_veto(
                        bound.workspace, bound.attachment, environment=environment,
                        deployment_target="barragan-testing", credential_repository=credentials,
                        transport=membership_transport, expected_phase="destroy_started",
                    )
                # The Inspector-ready journal proves an earlier observation,
                # not current reachability. The gated Terraform child is still
                # waiting for GO at this point. A failed live proof cannot
                # release it or permit an automatic second apply attempt.
                if live_inspector_prover is None:
                    from app.services.provider_keyed_destroy_apply_continuation import (
                        prove_live_keyed_inspector_before_destroy_go,
                    )
                    prover = prove_live_keyed_inspector_before_destroy_go
                else:
                    prover = live_inspector_prover
                diagnostic_stage = "pre_go_inspector"
                prover(parent.id, environment=environment, job_repository=jobs,
                       plan_repository=plan_repository, lease_lookup=lookup,
                       fence=lambda: heartbeat_callback(value),
                       active_destroy_child=lambda: current)
                diagnostic_stage = "pre_go_authority"
                authority()
                phase_independent_authority()
                diagnostic_stage = "pre_go_inputs"
                if (_private_file_digest(bound.preview.plan_path) != bound.preview.plan_sha256
                        or _hash_file(bound.workspace.state_path) != bound.teardown_intent.state_sha256
                        or json.loads((bound.workspace.path / ".barragan-apply-phase.json").read_text())
                        != {"schema": "provider-keyed-v2", "phase": "destroy_started"}):
                    raise ValueError("reviewed destroy inputs changed before GO")
                diagnostic_stage = "pre_go_dns"
                if dns_checkpoint is None or fresh_dns_checkpoint() != dns_checkpoint:
                    raise ValueError("fresh DNS cleanup checkpoint changed before GO")
                # The runner owns the actual GO write. Returning from this
                # callback proves only that the final read fence passed.
                diagnostic_stage = "gated_go_or_result"

        def heartbeat_callback(value: StartedCommand) -> None:
            nonlocal current
            if command_stage != "started" or value != command_started:
                raise ValueError("destroy heartbeat identity differs")
            authority()
            instant = _now()
            renewed = jobs.renew_lease(
                child_id, owner=owner, token=token, heartbeat_at=instant,
                expires_at=claim_expiry(instant),
            )
            if renewed is None or renewed.events != current.events:
                raise ValueError("destroy heartbeat claim changed")
            current = renewed

        def result_callback(value: CommandAuditResult) -> None:
            nonlocal command_stage, diagnostic_stage
            diagnostic_stage = "gated_result_audit"
            if command_stage != "started" or value.started != command_started:
                raise ValueError("destroy command result differs")
            append("provider destroy command result fenced", {
                "phase": command_phase, "invocationId": value.started.intent.invocation_id,
                "returnCode": value.returncode, "stdoutBytes": value.stdout_bytes,
                "stderrBytes": value.stderr_bytes,
                "stdoutTruncated": value.stdout_truncated,
                "stderrTruncated": value.stderr_truncated,
            })
            command_stage = "result"

        def command_runner(args, cwd, env):
            nonlocal command_phase, command_stage, command_intent, command_started, uncertain
            nonlocal diagnostic_stage, diagnostic_error_class
            binary, plan_path = str(bound.preview.terraform_binary_path), str(bound.preview.plan_path)
            expected = ([binary, "show", "-json", plan_path] if command_phase == "show"
                        else [binary, "apply", "-input=false", "-lock=true", "-no-color", plan_path])
            if (cwd != bound.workspace.path or args != expected or command_stage != "requested"
                    or (command_phase == "apply" and not phase_written)):
                raise ValueError("destroy command order or argv differs")
            authority()
            def capture_callback_error(callback, value):
                nonlocal diagnostic_error_class
                try:
                    callback(value)
                except Exception as error:
                    # The gated runner replaces callback errors with its own
                    # bounded error. Retain only an allowlisted category.
                    diagnostic_error_class = _diagnostic_exception_class(error)
                    raise
            try:
                # The apply child waits behind current provider membership,
                # Inspector, and DNS proofs. Those serial reads can exceed the
                # runner's 30-second default without authorizing Terraform.
                # Keep show on its short default gate; only apply needs this
                # bounded wait before the final GO fence.
                gate_options = ({"gate_timeout_seconds": 1200}
                                if command_phase == "apply" else {})
                diagnostic_stage = "gated_show" if command_phase == "show" else "gated_go_or_result"
                outcome = gated_command_runner(
                    args, scratch_path=bound.workspace.path, provider_keyed_v2=True,
                    max_output_bytes=16 * 1024 * 1024 if command_phase == "show" else 65536,
                    env=dict(env),
                    intent_callback=lambda value: capture_callback_error(intent_callback, value),
                    started_callback=lambda value: capture_callback_error(started_callback, value),
                    heartbeat_callback=lambda value: capture_callback_error(heartbeat_callback, value),
                    result_callback=lambda value: capture_callback_error(result_callback, value),
                    **gate_options,
                )
            except Exception as error:
                if isinstance(error, UnreapedGatedCommandError):
                    # A callback may have failed first, but an unreaped child
                    # is the higher-risk final supervision outcome.
                    diagnostic_error_class = "UnreapedGatedCommandError"
                elif diagnostic_error_class is None:
                    diagnostic_error_class = _diagnostic_exception_class(error)
                if command_stage == "started" or isinstance(error, UnreapedGatedCommandError):
                    uncertain = True
                    raise ProviderKeyedInitialDestroyApplyUncertainError(
                        "destroy command result unproved; retained files need reconciliation") from None
                raise
            if command_stage != "result" or outcome.started != command_started:
                uncertain = True
                raise ProviderKeyedInitialDestroyApplyUncertainError(
                    "destroy command audit incomplete; retained files need reconciliation")
            if outcome.stdout_truncated or outcome.stderr_truncated:
                raise ValueError("bounded destroy command output truncated")
            completed_phase = command_phase
            command_phase, command_stage = ("apply", "show_complete") if completed_phase == "show" else ("complete", "apply_complete")
            command_intent, command_started = None, None
            return subprocess.CompletedProcess(args, outcome.returncode,
                                               outcome.stdout if completed_phase == "show" else "", "")

        authority()
        before_state = json.loads(bound.workspace.state_path.read_text(encoding="utf-8"))
        diagnostic_stage = "destroy_helper"
        result = apply(
            bound.workspace, bound.preview, bound.teardown_intent,
            environment=environment, deployment_target="barragan-testing",
            expected_terraform_sha256=bound.preview.terraform_binary_sha256,
            credential_repository=credentials,
            command_environment=os.environ if command_environment is None else command_environment,
            command_runner=command_runner, phase_write_intent=phase_write_intent,
            **({"expected_topology_path": bound.topology_input_path,
                "expected_topology_sha256": bound.topology_input_sha256}
               if bound.topology_input_path is not None else {}),
        )
        diagnostic_stage = "post_apply_result"
        if (not isinstance(result, ProviderKeyedInitialDestroyApplyResult)
                or command_phase != "complete" or command_stage != "apply_complete"
                or not phase_completed
                or result.provider_absence_proof_pending is not True
                or type(result.state_sha256) is not str
                or _HASH.fullmatch(result.state_sha256) is None):
            raise ValueError("destroy apply result or empty state is unproved")
        if (json.loads((bound.workspace.path / ".barragan-apply-phase.json").read_text())
                != {"schema": "provider-keyed-v2", "phase": "destroy_applied"}
                or _require_empty_retained_state(bound.workspace, before_state) != result.state_sha256):
            raise ValueError("retained empty state or destroy phase changed after helper")
        diagnostic_stage = "terminal_authority"
        authority()
        # The handoff auditor proves the pre-destroy state and was fenced before
        # GO. Terraform has now emptied that state, so rerunning it here would
        # reject a successful destroy. Retain the independent chain/journal
        # identity checks; the empty state and phase were verified just above.
        phase_independent_authority(pre_destroy_handoff=False)
        terminal = jobs.finish_destroy_apply_if_running_claimed(
            current, owner=owner, token=token,
            expected_event_digest=job_event_digest(current.events),
            status="succeeded", finished_at=_now(),
            event=JobEvent(len(current.events) + 1, "info", "provider destroy apply completed; absence proof pending", {
                "stateSha256": result.state_sha256, "providerAbsenceProofPending": True,
            }),
        )
        if terminal is None:
            raise ValueError("destroy apply terminal claim changed")
        return terminal
    except Exception as error:
        # An event here would invalidate the exact pre-GO recovery
        # journal. Keep diagnostics in the server log, without exception text,
        # traceback, provider data, or any secret-bearing callback arguments.
        _LOGGER.warning(
            "provider_destroy_apply_stopped jobId=%s stage=%s exceptionClass=%s",
            child_id if "child_id" in locals() else "unreserved",
            diagnostic_stage, diagnostic_error_class or _diagnostic_exception_class(error),
        )
        # A phase write or a started command is one-shot. Preserve the running
        # claim and all evidence; an independent read-only recovery must decide.
        if "current" in locals() and current.status == "running" and "owner" in locals():
            if not ("phase_written" in locals() and phase_written) and not (
                    "uncertain" in locals() and uncertain) and not (
                    "command_stage" in locals() and command_stage == "started"):
                try:
                    jobs.finish_destroy_apply_if_running_claimed(
                        current, owner=owner, token=token,
                        expected_event_digest=job_event_digest(current.events),
                        status="failed", finished_at=_now(),
                        event=JobEvent(len(current.events) + 1, "error", "provider destroy apply stopped", {}),
                    )
                except Exception:
                    pass
        raise ProviderKeyedInitialDestroyApplyJobError(
            "full-state destroy apply stopped; inspect retained plan, phase and state"
        ) from None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(instant: str, *, seconds: int = 60) -> str:
    return (datetime.fromisoformat(instant) + timedelta(seconds=seconds)).isoformat()
