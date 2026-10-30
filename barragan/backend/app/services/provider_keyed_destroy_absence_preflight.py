# Copyright (c) 2026, Oracle and/or its affiliates.
"""Success-only, read-only absence reconciliation for a keyed DO destroy.

The retained empty state cannot reconstruct what Terraform owned before apply.
Only the confirmed parent and the complete one-shot child journal can do that.
This module does not delete the selector tag or advance teardown lifecycle.
"""

from __future__ import annotations

from app.services.provider_keyed_published_initial_cleanup_authority import queued_cleanup_event_data

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from uuid import UUID

from app.services.engagement_teardown import (
    ENGAGEMENT_TEARDOWN_ACTION, _fingerprint, _parent_id,
    _validated_parent_boundary, engagement_teardown_in_progress,
)
from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_digitalocean_absence import (
    DigitalOceanAbsenceEvidence, DigitalOceanAbsenceIntent,
    _require_destroy_fence, _validate_intent,
    reconcile_digitalocean_keyed_destroy_absence,
)
from app.services.provider_keyed_initial_destroy_apply_job import (
    ACTION as APPLY_ACTION, _PREVIEW_DATA_KEYS, _audit_successful_preview_journal,
)
from app.services.provider_keyed_initial_destroy_plan_job import (
    ACTION as PLAN_ACTION, _private_file_digest,
)
from app.services.provider_keyed_planned_state_preflight import _digest
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _inert_aborted_intent
from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, SCHEMA
from app.services.provider_keyed_teardown_quiescence import audit_pending_provider_keyed_bootstrap
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


_HASH = re.compile(r"[0-9a-f]{64}\Z")
_PRESTATE = "provider destroy prestate identity fenced"
_PHASE = "provider destroy phase write intended"
_INTENT = "provider destroy command intent fenced"
_STARTED = "provider destroy command started before GO"
_RESULT = "provider destroy command result fenced"
_MESSAGES = (
    "provider destroy apply queued", "provider destroy apply started",
    _INTENT, _STARTED, _RESULT, _PRESTATE, _PHASE,
    _INTENT, _STARTED, _RESULT, _PHASE,
    "provider destroy apply completed; absence proof pending",
)
_RECOVERY_REVISION = "bc3a6990f86dcca99381e1659ec337493ddf5275"
_RECOVERY_ORIGINAL_JOURNAL_SHA256 = (
    "4a9014cec817e4bc3cc09cd954801ebdf9e91496080d21bc3094f5bc4074f4b8"
)
_RECOVERY_INCIDENT_JOURNALS = {
    "job-provider-keyed-initial-destroy-apply-db19aa91df17": _RECOVERY_ORIGINAL_JOURNAL_SHA256,
    "job-provider-keyed-initial-destroy-apply-b4f1bceb4a7d":
        "36a5746659bf771f25429abfca06b76d092b1a36a9769c074a801b6fb2bc3caf",
}
_RECOVERY_INCIDENT_REVISIONS = {
    "job-provider-keyed-initial-destroy-apply-db19aa91df17": _RECOVERY_REVISION,
    "job-provider-keyed-initial-destroy-apply-b4f1bceb4a7d":
        "e4f702c984fd8f2448288db1a005d242049362a8",
}
_RECOVERY_MESSAGES = (
    *_MESSAGES[:9], "provider destroy pre-GO recovery intended",
    _INTENT, _STARTED, _RESULT, _INTENT, _STARTED, _RESULT,
    _PHASE, _MESSAGES[-1],
)
_PRESTATE_KEYS = frozenset({
    "coreJobId", "corePlanId", "scopeSnapshotId", "providerScopeSha256",
    "preDestroyStateSha256", "stateLineage", "preDestroySerial",
    "resourceIds", "resourceIdsSha256", "selectorTag", "credentialRecordId",
    "credentialSecretSha256", "credentialUpdatedAt",
    "dnsCleanupManifestSha256", "dnsCleanupHandoffJournalSha256",
    "dnsCleanupCheckpointSha256",
})


class ProviderKeyedDestroyAbsencePreflightError(ValueError):
    """Redacted authority failure; no cleanup transition was made."""


@dataclass(frozen=True)
class DestroyAbsenceBoundary:
    parent: object
    core: object
    preview_job: object
    apply_job: object
    scope: dict
    workspace: ProviderKeyedWorkspace
    intent: DigitalOceanAbsenceIntent
    chains: tuple


def _command_journal(events, index: int, phase: str, argv: list[str]) -> None:
    intent, started, result = events[index:index + 3]
    a, b, c = intent.data, started.data, result.data
    digest = hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest()
    if (not all(type(value) is dict for value in (a, b, c))
            or set(a) != {"phase", "invocationId", "argvSha256"}
            or set(b) != {"phase", "invocationId", "bootId", "pid", "pgid", "startTicks"}
            or set(c) != {"phase", "invocationId", "returnCode", "stdoutBytes",
                              "stderrBytes", "stdoutTruncated", "stderrTruncated"}
            or any(row["phase"] != phase or row["invocationId"] != a["invocationId"]
                   for row in (a, b, c))
            or type(a["invocationId"]) is not str or not a["invocationId"]
            or a["argvSha256"] != digest
            or type(b["bootId"]) is not str or not b["bootId"]
            or type(b["pid"]) is not int or b["pid"] <= 0
            or type(b["pgid"]) is not int or b["pgid"] != b["pid"]
            or type(b["startTicks"]) is not int or b["startTicks"] <= 0
            or type(c["returnCode"]) is not int or c["returnCode"] != 0
            or any(type(c[key]) is not int or c[key] < 0 for key in ("stdoutBytes", "stderrBytes"))
            or c["stdoutTruncated"] is not False or c["stderrTruncated"] is not False):
        raise ValueError("destroy command journal differs")


def _standard_or_incident_successful_journal(events, binary: str, plan_path: Path,
                        child_id: str = "job-provider-keyed-initial-destroy-apply-db19aa91df17"
                        ) -> tuple[int, int]:
    """Recognize the ordinary journal or this incident's reviewed continuation."""
    messages = _MESSAGES if len(events) == 12 else _RECOVERY_MESSAGES
    if (len(events) not in (12, 18)
            or [row.sequence for row in events] != list(range(1, len(events) + 1))
            or [(row.level, row.message) for row in events]
            != [("info", message) for message in messages]
            or events[0].data != {} or events[1].data != {}):
        raise ValueError("successful destroy journal differs")
    show_argv = [binary, "show", "-json", str(plan_path)]
    apply_argv = [binary, "apply", "-input=false", "-lock=true", "-no-color", str(plan_path)]
    _command_journal(events, 2, "show", show_argv)
    if len(events) == 12:
        _command_journal(events, 7, "apply", apply_argv)
        if events[2].data["invocationId"] == events[7].data["invocationId"]:
            raise ValueError("destroy command identity overlaps")
        return 10, 11
    from app.services.provider_keyed_teardown_quiescence import _INCIDENT_DESTROY_CHILD
    original_digest = (_RECOVERY_ORIGINAL_JOURNAL_SHA256
                       if child_id == _INCIDENT_DESTROY_CHILD else
                       _RECOVERY_INCIDENT_JOURNALS.get(child_id))
    revision = (_RECOVERY_REVISION if child_id == _INCIDENT_DESTROY_CHILD else
                _RECOVERY_INCIDENT_REVISIONS.get(child_id))
    if original_digest is None or job_event_digest(events[:9]) != original_digest:
        raise ValueError("original pre-GO journal differs")
    old_apply_intent, old_apply_started = events[7].data, events[8].data
    old_digest = hashlib.sha256(json.dumps(apply_argv, separators=(",", ":")).encode()).hexdigest()
    if (type(old_apply_intent) is not dict or type(old_apply_started) is not dict
            or set(old_apply_intent) != {"phase", "invocationId", "argvSha256"}
            or set(old_apply_started) != {"phase", "invocationId", "bootId", "pid", "pgid", "startTicks"}
            or old_apply_intent["phase"] != "apply"
            or old_apply_intent["argvSha256"] != old_digest
            or old_apply_started["phase"] != "apply"
            or old_apply_started["invocationId"] != old_apply_intent["invocationId"]
            or type(old_apply_intent["invocationId"]) is not str
            or not old_apply_intent["invocationId"]
            or type(old_apply_started["bootId"]) is not str or not old_apply_started["bootId"]
            or type(old_apply_started["pid"]) is not int or old_apply_started["pid"] <= 0
            or type(old_apply_started["pgid"]) is not int
            or old_apply_started["pgid"] != old_apply_started["pid"]
            or type(old_apply_started["startTicks"]) is not int
            or old_apply_started["startTicks"] <= 0):
        raise ValueError("original destroy apply intent differs")
    recovery = events[9].data
    if (type(recovery) is not dict
            or set(recovery) != {"historicalRevision", "originalJournalSha256", "planSha256"}
            or recovery["historicalRevision"] != revision
            or recovery["originalJournalSha256"] != original_digest
            or recovery["planSha256"] != _private_file_digest(plan_path)):
        raise ValueError("reviewed pre-GO recovery intent differs")
    _command_journal(events, 10, "show", show_argv)
    _command_journal(events, 13, "apply", apply_argv)
    invocation_ids = [events[index].data["invocationId"] for index in (2, 7, 10, 13)]
    if len(set(invocation_ids)) != len(invocation_ids):
        raise ValueError("destroy command identity overlaps")
    return 16, 17


def _successful_journal(events, binary: str, plan_path: Path,
                        child_id: str = "job-provider-keyed-initial-destroy-apply-db19aa91df17"
                        ) -> tuple[int, int]:
    """Also admit one exact append-only pre-command Apply recovery prefix."""
    if len(events) == 19:
        from dataclasses import replace
        from app.domain import JobEvent
        from app.services.provider_keyed_initial_destroy_apply_job import (
            _PRECOMMAND_APPLY_RECOVERY, _SHOW_ONLY_APPLY_RECOVERY,
        )

        failed = [JobEvent(1, "info", "provider destroy apply queued", {}),
                  JobEvent(2, "info", "provider destroy apply started", {}),
                  JobEvent(3, "error", "provider destroy apply stopped", {})]
        first_seal = events[3].data if len(events) > 3 else None
        second_seal = events[8].data if len(events) > 8 else None
        if (child_id in _RECOVERY_INCIDENT_JOURNALS
                or [row.sequence for row in events] != list(range(1, 20))
                or events[:3] != failed
                or events[3].level != "info" or events[3].message != _PRECOMMAND_APPLY_RECOVERY
                or type(first_seal) is not dict
                or set(first_seal) != {"failedJournalSha256", "failedFinishedAt"}
                or first_seal["failedJournalSha256"] != job_event_digest(failed)
                or type(first_seal["failedFinishedAt"]) is not str
                or [(row.level, row.message) for row in events[4:8]] != [
                    ("info", _INTENT), ("info", _STARTED), ("info", _RESULT),
                    ("error", "provider destroy apply stopped")]
                or events[7].data != {}
                or events[8].level != "info" or events[8].message != _SHOW_ONLY_APPLY_RECOVERY
                or type(second_seal) is not dict
                or set(second_seal) != {"failedJournalSha256", "failedFinishedAt"}
                or second_seal["failedJournalSha256"] != job_event_digest(events[:8])
                or type(second_seal["failedFinishedAt"]) is not str):
            raise ValueError("show-only destroy Apply continuation differs")
        _command_journal(events, 4, "show", [binary, "show", "-json", str(plan_path)])
        projected = [*events[:2], *events[9:]]
        projected = [replace(row, sequence=index) for index, row in enumerate(projected, 1)]
        phase_index, terminal_index = _standard_or_incident_successful_journal(
            projected, binary, plan_path, child_id)
        return phase_index + 7, terminal_index + 7
    if len(events) != 14:
        return _standard_or_incident_successful_journal(events, binary, plan_path, child_id)
    from dataclasses import replace
    from app.domain import JobEvent
    from app.services.provider_keyed_initial_destroy_apply_job import _PRECOMMAND_APPLY_RECOVERY

    if (child_id in _RECOVERY_INCIDENT_JOURNALS
            or [row.sequence for row in events] != list(range(1, 15))
            or events[:3] != [
                JobEvent(1, "info", "provider destroy apply queued", {}),
                JobEvent(2, "info", "provider destroy apply started", {}),
                JobEvent(3, "error", "provider destroy apply stopped", {}),
            ]
            or events[3].level != "info"
            or events[3].message != _PRECOMMAND_APPLY_RECOVERY
            or type(events[3].data) is not dict
            or set(events[3].data) != {"failedJournalSha256", "failedFinishedAt"}
            or events[3].data["failedJournalSha256"] != job_event_digest(events[:3])
            or type(events[3].data["failedFinishedAt"]) is not str
            or not events[3].data["failedFinishedAt"]):
        raise ValueError("recovered pre-command destroy Apply journal differs")
    projected = [*events[:2], *events[4:]]
    projected = [replace(row, sequence=index) for index, row in enumerate(projected, 1)]
    pre_index, terminal_index = _standard_or_incident_successful_journal(
        projected, binary, plan_path, child_id)
    return pre_index + 2, terminal_index + 2


def _read_success_boundary(
    teardown_parent_id: str, *, jobs, plans, chains, credentials, lookup,
    handoff_auditor: Callable, credential_check: Callable, state_root: Path,
) -> DestroyAbsenceBoundary:
    parent = jobs.get(teardown_parent_id)
    if (parent is None or parent.action != ENGAGEMENT_TEARDOWN_ACTION
            or parent.status != "queued" or parent.started_at is not None
            or parent.finished_at is not None or parent.input.get("phase") != "queued"
            or parent.input.get("mutation") is not True or len(parent.events) != 1
            or parent.events[0].message != "engagement teardown queued"):
        raise ValueError("queued parent differs")
    core, snapshot = _validated_parent_boundary(parent, jobs)
    if (snapshot.get("snapshotId") != _fingerprint({
            key: value for key, value in snapshot.items() if key != "snapshotId"})
            or parent.events[0].data != queued_cleanup_event_data(snapshot)
            or parent.id != _parent_id(core.id)
            or engagement_teardown_in_progress(snapshot["engagementId"], repository=jobs) != parent
            or core.status != "succeeded" or core.input.get("sketchStateSchema") != SCHEMA):
        raise ValueError("confirmed parent or core differs")
    scopes = snapshot.get("providerScopes")
    if type(scopes) is not list or len(scopes) != 1 or type(scopes[0]) is not dict:
        raise ValueError("provider scope differs")
    scope = scopes[0]
    plan_id = scope["corePlanId"]
    core_plan = plans.get(plan_id)
    if (core_plan is None or core_plan.status != "applied"
            or core_plan.engagement_id != parent.target_id
            or core_plan.apply_job_id != core.id or core.input.get("corePlanId") != plan_id
            or lookup(parent.target_id) != (plan_id, "provider_keyed_teardown_fence")):
        raise ValueError("retagged core lease differs")
    root = Path(scope["workspace"])
    if (not root.is_absolute() or root.is_symlink() or not root.is_dir()
            or root.resolve(strict=True) != root or not root.is_relative_to(state_root)
            or root == state_root or root.name in {"", ".", ".."}):
        raise ValueError("retained provider workspace differs")
    failed_prebinding = (snapshot.get("dnsCleanupManifest", {}).get("schema")
                         == "provider-keyed-empty-dns-prebinding-v1")
    if not failed_prebinding:
        handoff_auditor(
            core.id, confirmed_scope=scope, confirmed_scope_sha256=_fingerprint(snapshot),
            workspace_root=root, job_repository=jobs,
        )
    current_chains = tuple(row for row in chains.list_for_engagement(parent.target_id)
                           if not _inert_aborted_intent(row, parent.target_id))
    if (len(current_chains) != 2
            or {row.chain_id for row in current_chains} != set(scope["chainIds"])
            or any(sketch_chain_intent_fingerprint(row) != scope["chainFingerprints"][row.chain_id]
                   for row in current_chains)):
        raise ValueError("confirmed chain intent differs")
    related = jobs.list_for_engagement(parent.target_id)
    previews = [row for row in related if row.action == PLAN_ACTION]
    applies = [row for row in related if row.action == APPLY_ACTION]
    preview_id = f"job-provider-keyed-initial-destroy-plan-{core.id.removeprefix('job-')}"
    apply_id = f"job-provider-keyed-initial-destroy-apply-{core.id.removeprefix('job-')}"
    if (len(previews) != 1 or len(applies) != 1
            or previews[0].id != preview_id or applies[0].id != apply_id
            or jobs.get(preview_id) != previews[0] or jobs.get(apply_id) != applies[0]):
        raise ValueError("destroy child set differs")
    preview, applied = previews[0], applies[0]
    expected_shared = {
        "engagementId": parent.target_id, "coreJobId": core.id,
        "corePlanId": plan_id, "teardownParentId": parent.id,
        "scopeSnapshotId": snapshot["snapshotId"],
        "providerScopeSha256": snapshot["providerScopeSha256"],
        "mutation": True,
    }
    if not preview.events or type(preview.events[-1].data) is not dict:
        raise ValueError("reviewed destroy preview is absent")
    preview_data = preview.events[-1].data
    if set(preview_data) != _PREVIEW_DATA_KEYS:
        raise ValueError("reviewed destroy preview data differs")
    expected_apply_input = {
        **expected_shared, "destroyPlanJobId": preview.id,
        "planSha256": preview_data["planSha256"],
    }
    if (preview.action != PLAN_ACTION or preview.status != "succeeded"
            or preview.input != expected_shared or not preview.started_at or not preview.finished_at
            or applied.action != APPLY_ACTION or applied.status != "succeeded"
            or applied.input != expected_apply_input or not applied.started_at or not applied.finished_at
            or any(row.target_type != "engagement" or row.target_id != parent.target_id
                   or row.target != f"engagement:{parent.target_id}"
                   or row.requested_by != parent.requested_by for row in (preview, applied))
            or applied.artifact_refs != []):
        raise ValueError("successful destroy child identity differs")
    plan_path = root / ".barragan-initial-destroy.tfplan"
    if (preview.artifact_refs != [str(plan_path)]
            or preview_data.get("planPath") != str(plan_path)
            or _private_file_digest(plan_path) != preview_data["planSha256"]
            or preview_data.get("stateSha256") != scope["stateSha256"]
            or preview_data.get("sourceRevision") != scope["sourceRevision"]
            or preview_data.get("providerConnectionId") != scope["providerConnectionId"]
            or preview_data.get("scopeSnapshotId") != snapshot["snapshotId"]
            or preview_data.get("providerScopeSha256") != snapshot["providerScopeSha256"]):
        raise ValueError("reviewed destroy plan differs")
    workspace = ProviderKeyedWorkspace(
        root, root / "terraform.tfstate", root / ".terraform-data", SCHEMA,
        "digitalocean", scope["providerConnectionId"], root.name,
        scope["sourceRevision"], preview_data["sourceSha256"],
    )
    # The preview's own staging event is not independent authority for where
    # the durable initial inputs and public key live.
    material = root.parents[1] / ".plan-material" / "digitalocean"
    input_path = material / ("append-inputs.json" if "publishedAppendSource" in parent.input
                             else "inputs.json")
    public_path = material / "admin-public"
    if (preview_data["inputSha256"] != [[str(input_path), _digest(input_path)]]
            or preview.events[2].data.get("publicKeyPath") != str(public_path)
            or public_path.exists() or public_path.is_symlink()):
        raise ValueError("original provider input material differs")
    _audit_successful_preview_journal(
        preview, workspace, {
            "adminPublicKeyPath": str(public_path),
            "inputSha256": preview_data["inputSha256"],
        }, plan_path,
    )
    events = applied.events
    binary = preview_data["terraformBinaryPath"]
    if type(binary) is not str or not Path(binary).is_absolute():
        raise ValueError("reviewed Terraform binary differs")
    applied_phase_index, terminal_index = _successful_journal(
        events, binary, plan_path, applied.id)
    recovery_offset = 7 if len(events) == 19 else (2 if len(events) == 14 else 0)
    pre = events[5 + recovery_offset].data
    resource_ids = {row["address"]: row["id"] for row in scope["resources"]}
    initial = jobs.get(snapshot["dnsCleanupManifest"]["initialJobId"])
    handoff_digest = job_event_digest(initial.events) if initial is not None else None
    if (type(pre) is not dict or set(pre) != _PRESTATE_KEYS
            or len(resource_ids) != len(scope["resources"])
            or pre["resourceIds"] != resource_ids
            or pre["resourceIdsSha256"] != _fingerprint(resource_ids)
            or pre["coreJobId"] != core.id or pre["corePlanId"] != plan_id
            or pre["scopeSnapshotId"] != snapshot["snapshotId"]
            or pre["providerScopeSha256"] != snapshot["providerScopeSha256"]
            or pre["preDestroyStateSha256"] != scope["stateSha256"]
            or pre["selectorTag"] != scope["selectorTag"]
            or pre["credentialRecordId"] != scope["providerConnectionId"]
            or pre["credentialSecretSha256"] != preview_data["credentialSecretSha256"]
            or pre["credentialUpdatedAt"] != preview_data["credentialUpdatedAt"]
            or pre["dnsCleanupManifestSha256"] != snapshot["dnsCleanupManifest"]["manifestSha256"]
            or pre["dnsCleanupHandoffJournalSha256"] != handoff_digest
            or pre["dnsCleanupCheckpointSha256"] != _fingerprint({
                "scopeSnapshotId": snapshot["snapshotId"],
                "dnsCleanupManifestSha256": pre["dnsCleanupManifestSha256"],
                "dnsCleanupHandoffJournalSha256": pre["dnsCleanupHandoffJournalSha256"],
            })
            or type(pre["preDestroySerial"]) is not int or pre["preDestroySerial"] < 1):
        raise ValueError("pre-destroy ownership journal differs")
    UUID(pre["stateLineage"])
    phase_path = root / ".barragan-apply-phase.json"
    if (events[6 + recovery_offset].data != {"phase": "destroy_started", "path": str(phase_path)}
            or events[applied_phase_index].data != {"phase": "destroy_applied", "path": str(phase_path)}
            or events[terminal_index].data.get("providerAbsenceProofPending") is not True
            or set(events[terminal_index].data) != {"stateSha256", "providerAbsenceProofPending"}
            or type(events[terminal_index].data["stateSha256"]) is not str
            or _HASH.fullmatch(events[terminal_index].data["stateSha256"]) is None):
        raise ValueError("post-destroy journal differs")
    intent = DigitalOceanAbsenceIntent(
        resource_ids, pre["selectorTag"], pre["preDestroyStateSha256"],
        pre["stateLineage"], pre["preDestroySerial"],
        events[terminal_index].data["stateSha256"], _private_file_digest(
            phase_path, allow_collaborator_group=True,
        ),
        pre["credentialRecordId"], pre["credentialSecretSha256"],
        pre["credentialUpdatedAt"],
    )
    # Terraform state is intentionally team-readable; reject writable drift.
    if _digest(workspace.state_path) != intent.empty_state_sha256:
        raise ValueError("retained empty state differs")
    _validate_intent(workspace, intent)
    _require_destroy_fence(workspace, intent)
    if failed_prebinding:
        from app.services.provider_keyed_teardown_quiescence import (
            audit_failed_prebinding_provider_bootstrap,
        )
        audit_failed_prebinding_provider_bootstrap(
            core.id, confirmed_scope=scope, confirmed_scope_sha256=_fingerprint(snapshot),
            workspace_root=root, job_repository=jobs,
            post_destroy_state_sha256=intent.empty_state_sha256,
        )
    digest, updated_at, _ = credential_check(intent.credential_record_id, credentials)
    if (digest, updated_at) != (intent.credential_secret_sha256, intent.credential_updated_at):
        raise ValueError("provider credential changed")
    return DestroyAbsenceBoundary(parent, core, preview, applied, scope, workspace, intent, current_chains)


def reconcile_successful_digitalocean_destroy_absence(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, sketch_repository=None,
    credential_repository=None, lease_lookup=None,
    handoff_auditor: Callable = audit_pending_provider_keyed_bootstrap,
    credential_check: Callable = _credential_snapshot,
    absence_reconciler: Callable = reconcile_digitalocean_keyed_destroy_absence,
    transport=None, max_attempts: int = 12, poll_interval_seconds: float = 5.0,
    sleeper=None, retired_published: bool = False,
) -> DigitalOceanAbsenceEvidence:
    """Return GET-only absence proof; leave the parent and selector tag untouched."""
    try:
        if (environment != "devtest" or not isinstance(state_root, Path)
                or state_root != _default_state_root()
                or state_root.resolve(strict=True) != state_root
                or not teardown_parent_id):
            raise ValueError("unsupported absence boundary")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        chains = sketch_repository or SqlAlchemySketchChainRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        lookup = lease_lookup or _db_lease_lookup
        parent = jobs.get(teardown_parent_id)
        published = parent is not None and "publishedSource" in parent.input
        if type(retired_published) is not bool or (retired_published and not published):
            raise ValueError("retired published selector differs")
        if published:
            # Local import avoids the historical selector's success-boundary
            # callback forming a module import cycle. It returns the boundary
            # it already audited, so there is no nested absence read.
            from app.services.provider_keyed_teardown_source import (
                _read_published_post_destroy_boundary,
            )
            def read():
                return _read_published_post_destroy_boundary(
                    teardown_parent_id, environment=environment, state_root=state_root,
                    job_repository=jobs, plan_repository=plans,
                    sketch_repository=chains, credential_repository=credentials,
                    lease_lookup=lookup, credential_check=credential_check,
                    retired=retired_published,
                )
        else:
            def read():
                return None, _read_success_boundary(
                    teardown_parent_id, jobs=jobs, plans=plans, chains=chains,
                    credentials=credentials, lookup=lookup,
                    handoff_auditor=handoff_auditor, credential_check=credential_check,
                    state_root=state_root,
                )
        before_source, before = read()
        kwargs = dict(
            environment=environment, deployment_target="barragan-testing",
            credential_repository=credentials, transport=transport,
            max_attempts=max_attempts, poll_interval_seconds=poll_interval_seconds,
        )
        if sleeper is not None:
            kwargs["sleeper"] = sleeper
        proof = absence_reconciler(before.workspace, before.intent, **kwargs)
        if (not isinstance(proof, DigitalOceanAbsenceEvidence)
                or proof.empty_state_sha256 != before.intent.empty_state_sha256
                or proof.verified_absent_droplet_ids != tuple(sorted(
                    value for address, value in before.intent.resource_ids.items()
                    if address.startswith("digitalocean_droplet.")))
                or proof.verified_absent_firewall_id != before.intent.resource_ids["digitalocean_firewall.firewall"]
                or proof.verified_absent_ssh_key_id != before.intent.resource_ids["digitalocean_ssh_key.key"]
                or type(proof.selector_tag_cleanup_pending) is not bool
                or type(proof.attempts) is not int or proof.attempts < 1
                or read() != (before_source, before)):
            raise ValueError("provider absence proof changed")
        return proof
    except Exception:
        raise ProviderKeyedDestroyAbsencePreflightError(
            "reviewed keyed destroy absence is unproved; no cleanup was advanced"
        ) from None
