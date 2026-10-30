# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only terminal bootstrap audit for a future shared-state teardown.

This proves only the recorded initial gated commands completed and their
staged-key paths are clear. It neither transfers a lease nor authorizes a
destroy; a future caller must fence new workers and repeat the audit.
"""

from __future__ import annotations

import os
import re
import stat
import hashlib
from datetime import datetime, timezone
from dataclasses import dataclass
from dataclasses import replace
from pathlib import Path
from typing import Mapping
from uuid import UUID

from app.services.bootstrap_command_evidence import without_bootstrap_timing
from app.services.provider_keyed_host_binding import _digest_json
from app.services.provider_keyed_initial_continuation import ACTION, CORE_ACTION, _job_ids, _same_parent
from app.services.sketch_state_workspaces import _collaborator_group_gid
from app.storage.job_repository import SqlAlchemyJobRepository, handoff_claim_digest, job_event_digest


_HASH = re.compile(r"[0-9a-f]{64}\Z")
_SCRATCH = re.compile(r"\.barragan-sketch-bootstrap-[0-9a-f]{32}\Z")
_PROOF_SCRATCH = re.compile(r"\.barragan-strict-host-proof-[0-9a-f]{32}\Z")
_PREPARED = "provider bootstrap preparation fenced"
_CONTACT = "provider bootstrap first host contact fenced"
_ROOT = "provider upstream root bootstrap start fenced"
_INTENT = "provider bootstrap command intent fenced"
_STARTED = "provider bootstrap command started before GO"
_RESULT = "provider bootstrap command result fenced"
_COMPLETE = "provider chain bootstrap completed; host proof pending"
_FINAL = "provider bootstrap completed; strict host proof pending"
_HANDOFF = "provider bootstrap claim fenced for teardown handoff"
_PHASES = frozenset({"root_management_readiness", "upstream_root_bootstrap",
                     "user_readiness", "transport_install"})
_FAILED_PREBINDING_MESSAGES = (
    "provider continuation job queued", "provider plan child starting",
    "provider plan child queued", "provider plan child succeeded",
    "provider apply preflight passed", "provider apply child queued",
    "provider attachment proof started",
    "provider continuation stopped; reconciliation required",
)
_FAILED_POST_ATTACHMENT_MESSAGES = (
    *_FAILED_PREBINDING_MESSAGES[:-1],
    "provider attachment proven; host proof pending",
    "host identity binding stopped; reconciliation required",
)
_INCIDENT_DESTROY_CHILD = "job-provider-keyed-initial-destroy-apply-db19aa91df17"
_INCIDENT_DESTROY_CHILDREN = frozenset({
    _INCIDENT_DESTROY_CHILD,
    "job-provider-keyed-initial-destroy-apply-b4f1bceb4a7d",
})


class ProviderKeyedTeardownQuiescenceError(ValueError):
    """A terminal, complete and clean initial bootstrap was not proven."""


@dataclass(frozen=True)
class ProviderKeyedBootstrapQuiescenceEvidence:
    parent_job_id: str
    manifest_sha256: str
    chain_ids: tuple[str, str]
    command_count: int
    scratch_paths: tuple[str, ...]


def audit_terminal_provider_keyed_bootstrap(
    core_job_id: str, *, confirmed_scope: Mapping[str, object],
    workspace_root: Path, job_repository=None,
) -> ProviderKeyedBootstrapQuiescenceEvidence:
    """Accept only the finished two-chain bootstrap journal; perform no writes."""
    return _audit_bootstrap(
        core_job_id, confirmed_scope=confirmed_scope, workspace_root=workspace_root,
        job_repository=job_repository, pending_scope_sha256=None,
    )


def audit_pending_provider_keyed_bootstrap(
    core_job_id: str, *, confirmed_scope: Mapping[str, object],
    confirmed_scope_sha256: str, workspace_root: Path, job_repository=None,
) -> ProviderKeyedBootstrapQuiescenceEvidence:
    """Reprove the actual persisted pending row and its sealed source journal."""
    jobs = job_repository or SqlAlchemyJobRepository()
    parent = jobs.get(_job_ids(core_job_id)[0])
    if parent is not None and parent.status == "failed":
        # This reviewed DevTest child has already destroyed its provider state.
        # The pre-destroy state hash in the snapshot is no longer the on-disk
        # hash; use its terminal journal hash only through the existing strict
        # post-destroy auditor. Other children retain the original path.
        destroyed = jobs.get("job-provider-keyed-initial-destroy-apply-"
                             + core_job_id.removeprefix("job-"))
        post_destroy_sha256 = None
        if (destroyed is not None and destroyed.id in _INCIDENT_DESTROY_CHILDREN
                and destroyed.status == "succeeded" and len(destroyed.events) == 18):
            terminal = destroyed.events[-1].data
            if (type(terminal) is not dict
                    or type(terminal.get("stateSha256")) is not str
                    or not _HASH.fullmatch(terminal["stateSha256"])):
                raise ProviderKeyedTeardownQuiescenceError(
                    "terminal failed prebinding evidence is unproved")
            post_destroy_sha256 = terminal["stateSha256"]
        return audit_failed_prebinding_provider_bootstrap(
            core_job_id, confirmed_scope=confirmed_scope,
            confirmed_scope_sha256=confirmed_scope_sha256,
            workspace_root=workspace_root, job_repository=jobs,
            post_destroy_state_sha256=post_destroy_sha256,
        )
    return _audit_bootstrap(
        core_job_id, confirmed_scope=confirmed_scope, workspace_root=workspace_root,
        job_repository=jobs, pending_scope_sha256=confirmed_scope_sha256,
    )


def audit_failed_prebinding_provider_bootstrap(
    core_job_id: str, *, confirmed_scope: Mapping[str, object],
    workspace_root: Path, job_repository=None,
    confirmed_scope_sha256: str | None = None,
    post_destroy_state_sha256: str | None = None, sketch_repository=None,
) -> ProviderKeyedBootstrapQuiescenceEvidence:
    """Prove a failed, unpublished initial generation is safe to retire."""
    try:
        jobs = job_repository or SqlAlchemyJobRepository()
        from app.services.engagement_teardown import (
            _parent_id, _fingerprint, _valid_keyed_dns_cleanup_manifest,
        )
        from app.services.provider_keyed_initial_apply_job import require_initial_selector_absence_provenance
        from app.services.provider_keyed_planned_state_preflight import _EVIDENCE_KEYS
        parent_id, plan_id, apply_id = _job_ids(core_job_id)
        core, parent, planned, applied = (
            jobs.get(core_job_id), jobs.get(parent_id), jobs.get(plan_id), jobs.get(apply_id))
        teardown = jobs.get(_parent_id(core_job_id))
        snapshot = teardown.input.get("scopeSnapshot") if teardown is not None else None
        if (core is None or parent is None or planned is None or applied is None
                or core.action != CORE_ACTION or core.status != "succeeded"
                or core.input.get("sketchStateSchema") != "provider-keyed-v2"
                or not _same_parent(parent, core, core.input["engagementId"],
                                    core.input["corePlanId"], plan_id, apply_id)
                or parent.status != "failed" or parent.input.get("phase") != "attention"
                or not parent.started_at or not parent.finished_at
                or parent.artifact_refs != []
                or planned.status != "succeeded" or not planned.finished_at
                or applied.status != "succeeded" or not applied.finished_at
                or not planned.started_at or not applied.started_at
                or planned.action != "provider_keyed_initial_plan"
                or applied.action != "provider_keyed_initial_apply"
                or any(job.target_type != "engagement"
                       or job.target != f"engagement:{core.input['engagementId']}"
                       or job.target_id != core.input["engagementId"]
                       or job.requested_by != core.requested_by
                       for job in (planned, applied))
                or planned.input != {"engagementId": core.input["engagementId"],
                                     "coreJobId": core_job_id, "mutation": False}
                or applied.input != {"engagementId": core.input["engagementId"],
                                     "coreJobId": core_job_id,
                                     "corePlanId": core.input["corePlanId"],
                                     "planJobId": plan_id, "mutation": True}
                or planned.id != parent.input["planJobId"]
                or applied.id != parent.input["applyJobId"]
                or not isinstance(confirmed_scope, Mapping)
                or confirmed_scope.get("schema") != "provider-keyed-v2"
                or confirmed_scope.get("coreJobId") != core_job_id
                or confirmed_scope.get("corePlanId") != core.input["corePlanId"]
                or confirmed_scope.get("chainIds") != core.input.get("pendingSketchChainIds")
                or confirmed_scope.get("chainFingerprints") != core.input.get("pendingSketchChainFingerprints")
                or not isinstance(workspace_root, Path)
                or str(workspace_root) != confirmed_scope.get("workspace")
                or workspace_root.is_symlink() or workspace_root.resolve(strict=True) != workspace_root
                or not _private_directory(workspace_root, collaborator_root=True)):
            raise ValueError("failed prebinding identity differs")
        if confirmed_scope_sha256 is not None and (
                teardown is None or teardown.status != "queued"
                or teardown.input.get("phase") != "queued"
                or type(snapshot) is not dict
                or not _HASH.fullmatch(confirmed_scope_sha256)
                or _fingerprint(snapshot) != confirmed_scope_sha256
                or _fingerprint({key: value for key, value in snapshot.items()
                                 if key != "snapshotId"}) != snapshot.get("snapshotId")
                or snapshot.get("providerScopes") != [confirmed_scope]
                or not _valid_keyed_dns_cleanup_manifest(snapshot)
                or snapshot.get("dnsCleanupManifest", {}).get("schema")
                   != "provider-keyed-empty-dns-prebinding-v1"
                or snapshot["dnsCleanupManifest"].get("initialJournalSha256")
                != job_event_digest(parent.events)):
            raise ValueError("failed prebinding snapshot differs")
        events = parent.events
        messages = tuple(event.message for event in events)
        early_failure = _exact_prebinding_boundary(
            events, confirmed_scope, workspace_root, jobs, core_job_id)
        partial_failure = (not early_failure and _exact_partial_root_failure(
            parent, events, confirmed_scope, workspace_root, jobs, core_job_id))
        late_failure = (not early_failure and len(events) > 1
                        and events[-1].message == "strict host proof stopped; reconciliation required"
                        and events[-1].level == "error" and events[-1].data == {})
        if not early_failure and not partial_failure and not late_failure:
            raise ValueError("failed prebinding journal differs")
        plan_events = planned.events
        apply_events = applied.events
        if (len(plan_events) != 3
                or [event.sequence for event in plan_events] != [1, 2, 3]
                or [event.level for event in plan_events] != ["info"] * 3
                or [event.message for event in plan_events] != [
                    "provider continuation job queued", "provider plan preflight started",
                    "reviewed provider plan saved"]
                or set(plan_events[0].data) != {"creationToken"}
                or plan_events[1].data != {}
                or set(plan_events[2].data) != _EVIDENCE_KEYS
                or plan_events[2].data.get("coreJobId") != core_job_id
                or plan_events[2].data.get("corePlanId") != core.input["corePlanId"]
                or apply_events[-1].message != "provider saved-plan apply completed; proof pending"
                or apply_events[-1].level != "info"
                or apply_events[-1].sequence != len(apply_events)
                or set(apply_events[-1].data) != {
                    "stateSha256", "selectorTag", "attachmentProofPending", "hostProofPending"}
                or apply_events[-1].data.get("stateSha256") != confirmed_scope.get("stateSha256")
                or apply_events[-1].data.get("selectorTag") != confirmed_scope.get("selectorTag")
                or apply_events[-1].data.get("attachmentProofPending") is not True
                or apply_events[-1].data.get("hostProofPending") is not True):
            raise ValueError("failed prebinding children differ")
        plan_evidence = plan_events[2].data
        if (plan_evidence.get("selectorTag") != confirmed_scope.get("selectorTag")
                or plan_evidence.get("sourceRevision") != confirmed_scope.get("sourceRevision")
                or plan_evidence.get("providerConnectionId") != confirmed_scope.get("providerConnectionId")):
            raise ValueError("failed prebinding plan scope differs")
        require_initial_selector_absence_provenance(
            applied, engagement_id=core.input["engagementId"], core_job_id=core_job_id,
            core_plan_id=core.input["corePlanId"], plan_job_id=plan_id,
            connection_id=plan_evidence["providerConnectionId"],
            credential_secret_sha256=plan_evidence["credentialSecretSha256"],
            credential_updated_at=plan_evidence["credentialUpdatedAt"],
            selector_tag=plan_evidence["selectorTag"],
            source_sha256=plan_evidence["sourceSha256"],
            plan_sha256=plan_evidence["planSha256"],
            plan_path=Path(plan_evidence["planPath"]),
            terraform_binary_path=Path(plan_evidence["terraformBinaryPath"]),
            terraform_binary_sha256=plan_evidence["terraformBinarySha256"],
        )
        state_path = workspace_root / "terraform.tfstate"
        expected_state_sha256 = confirmed_scope.get("stateSha256")
        if post_destroy_state_sha256 is not None:
            from app.services.provider_keyed_destroy_absence_preflight import _MESSAGES
            destroy_id = ("job-provider-keyed-initial-destroy-apply-"
                          + core_job_id.removeprefix("job-"))
            destroyed = jobs.get(destroy_id)
            events = destroyed.events if destroyed is not None else []
            recovered = (len(events) == 18 and _valid_recovered_destroy_journal(
                jobs, destroyed, workspace_root, post_destroy_state_sha256))
            ordinary = (len(events) == 12
                        and [event.sequence for event in events] == list(range(1, 13))
                        and [(event.level, event.message) for event in events]
                            == [("info", message) for message in _MESSAGES])
            if (confirmed_scope_sha256 is None or teardown is None
                    or destroyed is None or destroyed.status != "succeeded"
                    or destroyed.action != "provider_keyed_initial_destroy_apply"
                    or destroyed.input.get("teardownParentId") != teardown.id
                    or destroyed.input.get("coreJobId") != core_job_id
                    or not (ordinary or recovered)
                    or destroyed.events[5].data.get("preDestroyStateSha256") != expected_state_sha256
                    or destroyed.events[-1].message != "provider destroy apply completed; absence proof pending"
                    or destroyed.events[-1].data.get("stateSha256") != post_destroy_state_sha256
                    or not _HASH.fullmatch(post_destroy_state_sha256)):
                raise ValueError("post-destroy failed prebinding stage differs")
            if recovered:
                preview_id = destroyed.id.replace(
                    "initial-destroy-apply-", "initial-destroy-plan-", 1)
                preview = jobs.get(preview_id)
                expected_input = {
                    "engagementId": core.input["engagementId"],
                    "coreJobId": core_job_id, "corePlanId": core.input["corePlanId"],
                    "teardownParentId": teardown.id,
                    "scopeSnapshotId": snapshot["snapshotId"],
                    "providerScopeSha256": snapshot["providerScopeSha256"],
                    "destroyPlanJobId": preview_id,
                    "planSha256": preview.events[-1].data["planSha256"],
                    "mutation": True,
                }
                if (destroyed.input != expected_input
                        or destroyed.target != f"engagement:{core.input['engagementId']}"
                        or destroyed.target_type != "engagement"
                        or destroyed.target_id != core.input["engagementId"]
                        or destroyed.requested_by != teardown.requested_by
                        or destroyed.artifact_refs != []):
                    raise ValueError("recovered destroy identity differs")
            expected_state_sha256 = post_destroy_state_sha256
        if (state_path.is_symlink() or not state_path.is_file()
                or hashlib.sha256(state_path.read_bytes()).hexdigest()
                != expected_state_sha256
                or jobs.get(parent_id) != parent or jobs.get(plan_id) != planned
                or jobs.get(apply_id) != applied or jobs.get(core_job_id) != core
                or (confirmed_scope_sha256 is not None
                    and jobs.get(teardown.id) != teardown)
                or (post_destroy_state_sha256 is not None
                    and jobs.get(destroyed.id) != destroyed)):
            raise ValueError("failed prebinding state or journal changed")
        if (early_failure and messages == _FAILED_POST_ATTACHMENT_MESSAGES
                and post_destroy_state_sha256 is None):
            _prove_attachment_against_state(parent.events[7].data, state_path)
        if partial_failure and post_destroy_state_sha256 is None:
            _prove_attachment_against_state(parent.events[7].data, state_path)
        chain_ids = confirmed_scope["chainIds"]
        if type(chain_ids) is not list or len(chain_ids) != 2 or len(set(chain_ids)) != 2:
            raise ValueError("failed prebinding chains differ")
        if late_failure:
            bootstrap = _audit_bootstrap(
                core_job_id, confirmed_scope=confirmed_scope, workspace_root=workspace_root,
                job_repository=jobs, pending_scope_sha256=None, failed_host_proof=True,
            )
            _audit_failed_strict_host_child(
                core_job_id, core, parent, bootstrap, workspace_root, jobs,
                sketch_repository=sketch_repository, confirmed_scope=confirmed_scope,
                teardown=teardown, destroyed=destroyed if post_destroy_state_sha256 else None,
            )
            if jobs.get(parent_id) != parent:
                raise ValueError("failed proof parent changed")
            return ProviderKeyedBootstrapQuiescenceEvidence(
                parent_id, job_event_digest(parent.events), bootstrap.chain_ids,
                bootstrap.command_count, bootstrap.scratch_paths,
            )
        if partial_failure:
            scratch = parent.events[10].data["scratchPaths"]
            return ProviderKeyedBootstrapQuiescenceEvidence(
                parent_id, job_event_digest(parent.events),
                (chain_ids[0], chain_ids[1]), 2, (scratch[0], scratch[1]),
            )
        return ProviderKeyedBootstrapQuiescenceEvidence(
            parent_id, job_event_digest(parent.events),
            (chain_ids[0], chain_ids[1]), 0, (),
        )
    except Exception:
        raise ProviderKeyedTeardownQuiescenceError(
            "terminal failed prebinding evidence is unproved") from None


def _exact_prebinding_boundary(events, confirmed_scope, workspace_root, jobs, core_job_id) -> bool:
    messages = tuple(event.message for event in events)
    if messages not in (_FAILED_PREBINDING_MESSAGES, _FAILED_POST_ATTACHMENT_MESSAGES):
        return False
    if (len(events) not in (8, 9)
            or [event.sequence for event in events] != list(range(1, len(events) + 1))
            or [event.level for event in events] != ["info"] * (len(events) - 1) + ["error"]
            or type(events[0].data) is not dict
            or set(events[0].data) != {"creationToken"}
            or type(events[0].data["creationToken"]) is not str
            or re.fullmatch(r"[0-9a-f]{32}", events[0].data["creationToken"]) is None
            or any(event.data != {} for event in events[1:7])
            or events[-1].data != {}):
        return False
    if len(events) == 9:
        proof = events[7].data
        if (type(proof) is not dict
                or set(proof) != {"stateSha256", "firewallId", "verifiedDropletIds",
                                  "attempts", "providerMembershipVerified", "hostProofPending"}
                or proof["stateSha256"] != confirmed_scope.get("stateSha256")
                or type(proof["attempts"]) is not int or not 1 <= proof["attempts"] <= 12
                or proof["providerMembershipVerified"] is not True
                or proof["hostProofPending"] is not True):
            return False
    from app.services.provider_keyed_initial_host_publication import _child_id
    from app.services.provider_keyed_host_binding import _KNOWN_HOSTS_NAME
    if (jobs.get(_child_id(core_job_id)) is not None
            or (workspace_root / _KNOWN_HOSTS_NAME).exists()
            or (workspace_root / _KNOWN_HOSTS_NAME).is_symlink()
            or any(workspace_root.glob(".barragan-sketch-bootstrap-*"))
            or any(workspace_root.glob(".barragan-strict-host-proof-*"))):
        return False
    return True


def _exact_partial_root_failure(parent, events, scope, root, jobs, core_job_id) -> bool:
    """Recognize only a fenced failure of the first upstream root command."""
    try:
        from app.services.provider_keyed_host_binding import (
            _KNOWN_HOSTS_NAME, _regular_file_digest,
        )
        from app.services.provider_keyed_initial_host_publication import _child_id

        terminal = events[-1]
        generic = (terminal.message ==
                   "provider bootstrap stopped; manual read-only reconciliation required"
                   and terminal.data == {})
        detail = terminal.data.get("failureDetail") if type(terminal.data) is dict else None
        root_code = events[18].data.get("returnCode") if len(events) > 18 else None
        diagnosed = (type(detail) is str and len(detail) <= 4096
                     and type(root_code) is int and root_code != 0
                     and detail.startswith(f"upstream sketch bootstrap failed (exit {root_code}")
                     and terminal.message == (
                         "provider bootstrap stopped; manual read-only reconciliation required; "
                         + detail[:240]))
        attachment = events[7].data
        if (len(events) != 20
                or [event.sequence for event in events] != list(range(1, 21))
                or [event.level for event in events] != ["info"] * 19 + ["error"]
                or tuple(event.message for event in events[:8])
                   != _FAILED_POST_ATTACHMENT_MESSAGES[:-1]
                or [event.message for event in events[8:19]] != [
                    "provider host identity binding intended", "provider host identity bound",
                    _PREPARED, _CONTACT, _INTENT, _STARTED, _RESULT, _ROOT,
                    _INTENT, _STARTED, _RESULT,
                ]
                or not (generic or diagnosed)
                or type(events[0].data) is not dict
                or set(events[0].data) != {"creationToken"}
                or type(events[0].data["creationToken"]) is not str
                or re.fullmatch(r"[0-9a-f]{32}", events[0].data["creationToken"]) is None
                or any(event.data != {} for event in events[1:7])
                or type(attachment) is not dict
                or set(attachment) != {"stateSha256", "firewallId", "verifiedDropletIds",
                                          "attempts", "providerMembershipVerified", "hostProofPending"}
                or attachment["stateSha256"] != scope["stateSha256"]
                or type(attachment["attempts"]) is not int
                or not 1 <= attachment["attempts"] <= 12
                or attachment["providerMembershipVerified"] is not True
                or attachment["hostProofPending"] is not True
                or jobs.get(_child_id(core_job_id)) is not None
                or any(root.glob(".barragan-strict-host-proof-*"))):
            return False
        expiry = datetime.fromisoformat(parent.input["claimExpiresAt"])
        if (expiry.tzinfo is None or expiry > datetime.now(timezone.utc)
                or not parent.input.get("claimOwner")
                or not parent.input.get("claimToken")):
            return False
        ids = scope["chainIds"]
        manifest = events[8].data
        digest = _digest_json(manifest)
        scratch = events[10].data["scratchPaths"]
        resources = {row["address"]: str(row["id"]) for row in scope["resources"]}
        nodes = manifest.get("nodes")
        if (type(manifest) is not dict or manifest.get("schema") != "provider-keyed-v2"
                or manifest.get("engagementId") != parent.target_id
                or manifest.get("coreJobId") != core_job_id
                or manifest.get("corePlanId") != scope["corePlanId"]
                or manifest.get("stateSha256") != scope["stateSha256"]
                or manifest.get("sourceRevision") != scope["sourceRevision"]
                or manifest.get("providerConnectionId") != scope["providerConnectionId"]
                or manifest.get("chainFingerprints") != [
                    {"chainId": chain_id, "fingerprint": scope["chainFingerprints"][chain_id]}
                    for chain_id in ids]
                or type(nodes) is not list or len(nodes) != 4
                or any(len([node for node in nodes
                            if node.get("chainId") == chain_id]) != 2
                       or {node.get("role") for node in nodes
                           if node.get("chainId") == chain_id} != {"middle", "edge"}
                       for chain_id in ids)
                or {node.get("terraformAddress"): str(node.get("providerInstanceId"))
                    for node in nodes} != {
                        address: value for address, value in resources.items()
                        if address.startswith("digitalocean_droplet.")}
                or events[9].data != {"manifestSha256": digest, "hostProofPending": True}
                or events[10].data != {"manifestSha256": digest, "chainIds": ids,
                                       "scratchPaths": scratch}
                or type(scratch) is not list or len(scratch) != 2
                or len(set(scratch)) != 2
                or events[11].data != {"chainId": ids[0]}
                or events[15].data != {"chainId": ids[0]}
                or manifest.get("sketchKnownHostsPath") != str(root / _KNOWN_HOSTS_NAME)):
            return False
        _regular_file_digest(root / _KNOWN_HOSTS_NAME, require_content=False)
        _clean_scratch(Path(scratch[0]), root)
        # The second chain was never entered; its reserved path must not have
        # been materialized by an unrecorded worker.
        second = Path(scratch[1])
        if (not second.is_absolute() or second.parent != root
                or not _SCRATCH.fullmatch(second.name)
                or second.exists() or second.is_symlink()):
            return False
        for offset, phase, number, code in (
            (12, "root_management_readiness", 1, 0),
            (16, "upstream_root_bootstrap", 2, root_code),
        ):
            intent, started, result = events[offset:offset + 3]
            fields = {"chainId": ids[0], "phase": phase, "sequence": number,
                      "attempt": 1}
            invocation = intent.data.get("invocationId")
            if (type(invocation) is not str or not invocation
                    or intent.data != {**fields, "invocationId": invocation,
                                       "scratchPath": scratch[0],
                                       "argvSha256": intent.data.get("argvSha256")}
                    or type(intent.data["argvSha256"]) is not str
                    or not _HASH.fullmatch(intent.data["argvSha256"])
                    or started.data != {**fields, "invocationId": invocation,
                                        "bootId": started.data.get("bootId"),
                                        "pid": started.data.get("pid"),
                                        "pgid": started.data.get("pgid"),
                                        "startTicks": started.data.get("startTicks")}
                    or not _valid_started_identity(started.data)
                    or without_bootstrap_timing(result.data, success=code == 0) != {**fields, "invocationId": invocation,
                                       "returnCode": code,
                                       "stdoutBytes": result.data.get("stdoutBytes"),
                                       "stderrBytes": result.data.get("stderrBytes"),
                                       "stdoutTruncated": result.data.get("stdoutTruncated"),
                                       "stderrTruncated": result.data.get("stderrTruncated")}
                    or (number == 2 and (type(code) is not int or code == 0))
                    or any(type(result.data[key]) is not int or result.data[key] < 0
                           for key in ("stdoutBytes", "stderrBytes"))
                    or any(type(result.data[key]) is not bool
                           for key in ("stdoutTruncated", "stderrTruncated"))
                    or _recorded_group_active(started.data)):
                return False
        if (events[12].data["invocationId"] == events[16].data["invocationId"]
                or jobs.get(parent.id) != parent):
            return False
        _clean_scratch(Path(scratch[0]), root)
        if second.exists() or second.is_symlink():
            return False
        return True
    except Exception:
        return False


def _prove_attachment_against_state(proof, state_path: Path) -> None:
    from app.services.provider_keyed_initial_attachment_adapter import _provider_resources
    import json

    resources = _provider_resources(json.loads(state_path.read_bytes()))
    firewall = resources.get("digitalocean_firewall.firewall")
    droplet_ids = {str(row.get("id")) for address, row in resources.items()
                   if address.startswith("digitalocean_droplet.")}
    if (type(proof["verifiedDropletIds"]) is not list
            or len(proof["verifiedDropletIds"]) != len(droplet_ids)
            or not droplet_ids
            or set(proof["verifiedDropletIds"]) != droplet_ids
            or any(type(value) is not str or not value for value in proof["verifiedDropletIds"])
            or type(proof["firewallId"]) is not str
            or firewall is None or proof["firewallId"] != str(firewall.get("id"))):
        raise ValueError("recorded attachment differs from unchanged state")


def _valid_recovered_destroy_journal(jobs, destroyed, workspace_root: Path,
                                     post_destroy_state_sha256: str) -> bool:
    """Recognize only the reviewed incident's complete successful continuation."""
    try:
        from app.services.provider_keyed_destroy_absence_preflight import (
            _RECOVERY_MESSAGES, _successful_journal,
        )
        from app.services.provider_keyed_initial_destroy_plan_job import _private_file_digest
        events = destroyed.events
        if destroyed.id not in _INCIDENT_DESTROY_CHILDREN:
            return False
        preview_id = destroyed.id.replace("initial-destroy-apply-", "initial-destroy-plan-", 1)
        preview = jobs.get(preview_id)
        plan_path = workspace_root / ".barragan-initial-destroy.tfplan"
        phase_path = workspace_root / ".barragan-apply-phase.json"
        if (preview is None or preview.status != "succeeded"
                or preview.action != "provider_keyed_initial_destroy_plan"
                or not preview.events or type(preview.events[-1].data) is not dict
                or preview.events[-1].data.get("planPath") != str(plan_path)
                or preview.events[-1].data.get("planSha256") != _private_file_digest(plan_path)
                or preview.events[-1].data.get("planSha256") != destroyed.input.get("planSha256")
                or events[9].data.get("planSha256") != destroyed.input.get("planSha256")
                or events[6].data != {"phase": "destroy_started", "path": str(phase_path)}
                or events[16].data != {"phase": "destroy_applied", "path": str(phase_path)}
                or events[17].data != {"stateSha256": post_destroy_state_sha256,
                                       "providerAbsenceProofPending": True}
                or [(event.level, event.message) for event in events]
                   != [("info", message) for message in _RECOVERY_MESSAGES]):
            return False
        binary = preview.events[-1].data.get("terraformBinaryPath")
        return (type(binary) is str and Path(binary).is_absolute()
                and _successful_journal(events, binary, plan_path, destroyed.id) == (16, 17))
    except Exception:
        return False


def audit_published_provider_keyed_bootstrap(
    core_job_id: str, *, confirmed_scope: Mapping[str, object],
    workspace_root: Path, job_repository=None,
) -> ProviderKeyedBootstrapQuiescenceEvidence:
    """Validate the actual completed initial journal, including its bootstrap prefix.

    The terminal host digest is a persisted publication fact, not proof of
    independently collected host evidence.
    """
    return _audit_bootstrap(
        core_job_id, confirmed_scope=confirmed_scope, workspace_root=workspace_root,
        job_repository=job_repository, pending_scope_sha256=None, published=True,
    )


def _audit_bootstrap(
    core_job_id: str, *, confirmed_scope: Mapping[str, object],
    workspace_root: Path, job_repository, pending_scope_sha256: str | None,
    published: bool = False, failed_host_proof: bool = False,
) -> ProviderKeyedBootstrapQuiescenceEvidence:
    try:
        jobs = job_repository or SqlAlchemyJobRepository()
        parent_id, plan_job_id, apply_job_id = _job_ids(core_job_id)
        core, parent = jobs.get(core_job_id), jobs.get(parent_id)
        phase = ("attention" if failed_host_proof else
                 "teardown_handoff_pending" if pending_scope_sha256 is not None else
                 "awaiting_strict_host_proof")
        if (core is None or parent is None or core.action != CORE_ACTION
                or core.status != "succeeded" or core.input.get("sketchStateSchema") != "provider-keyed-v2"
                or not isinstance(confirmed_scope, Mapping)
                or confirmed_scope.get("schema") != "provider-keyed-v2"
                or confirmed_scope.get("coreJobId") != core_job_id
                or confirmed_scope.get("corePlanId") != core.input.get("corePlanId")
                or confirmed_scope.get("stateSha256") is None
                or not isinstance(workspace_root, Path)
                or str(workspace_root) != confirmed_scope.get("workspace")
                or workspace_root.is_symlink() or workspace_root.resolve(strict=True) != workspace_root
                or not _private_directory(workspace_root, collaborator_root=True)
                or parent.status != ("failed" if failed_host_proof else "succeeded" if published else "running")
                or parent.input.get("phase") != ("completed" if published else phase)
                or (parent.finished_at is None if (published or failed_host_proof)
                    else parent.finished_at is not None)
                or not (_published_parent_shape(parent, core, plan_job_id, apply_job_id)
                        if published else
                        (_same_parent(parent, core, core.input["engagementId"], core.input["corePlanId"],
                                      plan_job_id, apply_job_id) if pending_scope_sha256 is None
                         else _pending_parent_shape(parent, core, plan_job_id, apply_job_id)))):
            raise ValueError("terminal core, parent, or workspace differs")
        ids = confirmed_scope.get("chainIds")
        fingerprints = confirmed_scope.get("chainFingerprints")
        if (not isinstance(ids, list) or len(ids) != 2 or len(set(ids)) != 2
                or not all(isinstance(value, str) and value for value in ids)
                or not isinstance(fingerprints, dict) or set(fingerprints) != set(ids)
                or ids != core.input.get("pendingSketchChainIds")
                or fingerprints != core.input.get("pendingSketchChainFingerprints")):
            raise ValueError("reviewed chain identity differs")
        events = parent.events
        if failed_host_proof:
            if (len(events) < 2 or events[-1].sequence != len(events)
                    or events[-1].level != "error" or events[-1].data != {}
                    or events[-1].message != "strict host proof stopped; reconciliation required"):
                raise ValueError("failed strict proof terminal differs")
            events = events[:-1]
        if published:
            if (len(events) < 2 or events[-1].sequence != len(events)
                    or events[-1].level != "info"
                    or events[-1].message != "provider two-chain host proof published"
                    or sum(event.message == "provider two-chain host proof published"
                           for event in events) != 1):
                raise ValueError("published terminal event differs")
            events = events[:-1]
        if pending_scope_sha256 is not None:
            if (not _HASH.fullmatch(pending_scope_sha256) or len(events) < 2
                    or events[-1].sequence != len(events)
                    or events[-1].level != "info" or events[-1].message != _HANDOFF
                    or events[-1].data != {
                        "phase": "teardown_handoff_pending",
                        "sourceEventSha256": job_event_digest(events[:-1]),
                        "scopeSnapshotSha256": pending_scope_sha256,
                        "handoffClaimSha256": handoff_claim_digest(
                            owner=parent.input["claimOwner"], token=parent.input["claimToken"],
                            claimed_at=parent.input["claimClaimedAt"],
                            expires_at=parent.input["claimExpiresAt"],
                        ),
                    }):
                raise ValueError("sealed handoff event differs")
            events = events[:-1]
        if (not events or [event.sequence for event in events] != list(range(1, len(events) + 1))
                or events[-1].message != _FINAL or events[-1].level != "info"):
            raise ValueError("terminal event is absent or superseded")
        manifest_event = _only(events, "provider host identity binding intended")
        bound = _only(events, "provider host identity bound")
        prepared = _only(events, _PREPARED)
        host_messages = {_CONTACT, _ROOT, _INTENT, _STARTED, _RESULT, _COMPLETE, _FINAL}
        if (sum(event.message == _FINAL for event in events) != 1
                or any(event.message in host_messages and event.sequence <= prepared.sequence
                       for event in events)):
            raise ValueError("host command or final phase precedes bootstrap preparation")
        manifest = manifest_event.data
        digest = _digest_json(manifest)
        if (not isinstance(manifest, dict) or manifest.get("schema") != "provider-keyed-v2"
                or manifest.get("coreJobId") != core_job_id
                or manifest.get("corePlanId") != confirmed_scope["corePlanId"]
                or manifest.get("stateSha256") != confirmed_scope["stateSha256"]
                or manifest.get("sourceRevision") != confirmed_scope.get("sourceRevision")
                or manifest.get("providerConnectionId") != confirmed_scope.get("providerConnectionId")
                or manifest.get("chainFingerprints") != [
                    {"chainId": chain_id, "fingerprint": fingerprints[chain_id]} for chain_id in ids]
                or bound.data.get("manifestSha256") != digest
                or prepared.data.get("manifestSha256") != digest
                or events[-1].data != {"manifestSha256": digest, "chainIds": ids,
                                       "hostProofPending": True}
                or not (manifest_event.sequence < bound.sequence < prepared.sequence < events[-1].sequence)):
            raise ValueError("retained manifest or phase evidence differs")
        scratch = prepared.data.get("scratchPaths")
        if (prepared.data.get("chainIds") != ids or not isinstance(scratch, list)
                or len(scratch) != 2 or len(set(scratch)) != 2):
            raise ValueError("bootstrap scratch intent differs")
        for path in scratch:
            _clean_scratch(Path(path), workspace_root, allow_missing=published)
        count = _command_journal(events, prepared.sequence, ids, scratch)
        if failed_host_proof and any(
                _recorded_group_active(event.data) for event in events
                if event.message == _STARTED):
            raise ValueError("bootstrap command group remains active")
        if jobs.get(parent_id) != parent or jobs.get(core_job_id) != core:
            raise ValueError("bootstrap audit changed during read")
        for path in scratch:
            _clean_scratch(Path(path), workspace_root, allow_missing=published)
        return ProviderKeyedBootstrapQuiescenceEvidence(
            parent_id, digest, (ids[0], ids[1]), count, (scratch[0], scratch[1]))
    except Exception:
        raise ProviderKeyedTeardownQuiescenceError(
            "terminal keyed bootstrap process and staged-key quiescence is unproved") from None


def _audit_failed_strict_host_child(
    core_job_id, core, parent, bootstrap, workspace_root, jobs, *, sketch_repository,
    confirmed_scope=None, teardown=None, destroyed=None,
) -> None:
    """A failed interpreter is safe to retire only after every host capture ended."""
    from app.services.provider_keyed_initial_host_publication import _child_id
    from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
    from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository

    child = jobs.get(_child_id(core_job_id))
    manifest_event = _only(parent.events, "provider host identity binding intended")
    manifest = manifest_event.data
    digest = bootstrap.manifest_sha256
    ids = bootstrap.chain_ids
    nodes = manifest.get("nodes")
    rows = (sketch_repository or SqlAlchemySketchChainRepository()).list_for_engagement(
        core.input["engagementId"])
    retired = (type(rows) is list and len(rows) == 2
               and all(row.status == "destroyed" for row in rows))
    if retired:
        _audit_failed_host_retirement(
            core, teardown, destroyed, confirmed_scope, rows, jobs,
        )
    if (child is None or child.action != "provider_keyed_initial_host_proof"
            or child.status != "failed" or not child.started_at or not child.finished_at
            or child.target_type != "engagement"
            or child.target != f"engagement:{core.input['engagementId']}"
            or child.target_id != core.input["engagementId"]
            or child.requested_by != core.requested_by or child.artifact_refs != []
            or {key: value for key, value in child.input.items() if not key.startswith("claim")}
            != {"engagementId": core.input["engagementId"], "coreJobId": core_job_id,
                "corePlanId": core.input["corePlanId"], "parentJobId": parent.id,
                "manifestSha256": digest, "mutation": False}
            or type(nodes) is not list or len(nodes) != 4
            or type(rows) is not list or len(rows) != 2
            or {row.chain_id for row in rows} != set(ids)
            or any(row.status != ("destroyed" if retired else "pending")
                   or row.deploy_job_id != ""
                   or row.teardown_job_id != (destroyed.id if retired else "") or row.burned
                   or row.nodes != [] or row.edge_count != 1
                   or (retired and row.terraform_working_directory)
                   or sketch_chain_intent_fingerprint(row)
                      != core.input["pendingSketchChainFingerprints"][row.chain_id]
                   for row in rows)
            or any(len([node for node in nodes if node.get("chainId") == chain_id]) != 2
                   or {node.get("role") for node in nodes if node.get("chainId") == chain_id}
                      != {"middle", "edge"} for chain_id in ids)
            or len({node.get("terraformAddress") for node in nodes}) != 4
            or len({node.get("providerInstanceId") for node in nodes}) != 4):
        raise ValueError("failed host proof source differs")
    events = child.events
    if (len(events) != 59 or [event.sequence for event in events] != list(range(1, 60))
            or events[0].level != "info"
            or events[0].message != "strict host proof reserved"
            or events[0].data != {"manifestSha256": digest}
            or events[1].level != "info"
            or events[1].message != "strict host proof started"
            or events[1].data != {"manifestSha256": digest}
            or events[-1].level != "error"
            or events[-1].message != "strict host proof stopped; reconciliation required"
            or events[-1].data != {}):
        raise ValueError("failed host proof journal differs")
    expected = [next(node for node in nodes if node["chainId"] == chain_id
                     and node["role"] == role)
                for chain_id in ids for role in ("middle", "edge")]
    offset = 2
    invocations = set()
    for node in expected:
        fields = {"hostname": node["name"], "terraformAddress": node["terraformAddress"],
                  "providerInstanceId": node["providerInstanceId"]}
        scratch = events[offset]
        path = Path(scratch.data.get("scratchPath", ""))
        if (scratch.level != "info" or scratch.message != "strict host proof scratch intended"
                or scratch.data != {**fields, "scratchPath": str(path)}
                or not path.is_absolute() or path.parent != workspace_root
                or not _PROOF_SCRATCH.fullmatch(path.name)
                or path.exists() or path.is_symlink()):
            raise ValueError("failed host proof scratch differs")
        offset += 1
        for _ in range(4):
            intent, started, result = events[offset:offset + 3]
            offset += 3
            invocation = intent.data.get("invocationId")
            if ([(event.level, event.message) for event in (intent, started, result)] != [
                    ("info", "strict host proof command intended"),
                    ("info", "strict host proof command started before GO"),
                    ("info", "strict host proof command result fenced")]
                    or type(invocation) is not str or not invocation or invocation in invocations
                    or intent.data != {**fields, "invocationId": invocation,
                                       "scratchPath": str(path),
                                       "argvSha256": intent.data.get("argvSha256")}
                    or type(intent.data["argvSha256"]) is not str
                    or not _HASH.fullmatch(intent.data["argvSha256"])
                    or started.data != {**fields, "invocationId": invocation,
                                        "bootId": started.data.get("bootId"),
                                        "pid": started.data.get("pid"),
                                        "pgid": started.data.get("pgid"),
                                        "startTicks": started.data.get("startTicks")}
                    or not _valid_started_identity(started.data)
                    or result.data != {**fields, "invocationId": invocation,
                                       "returnCode": 0,
                                       "stdoutBytes": result.data.get("stdoutBytes"),
                                       "stderrBytes": 0,
                                       "stdoutTruncated": False, "stderrTruncated": False}
                    or type(result.data["stdoutBytes"]) is not int
                    or result.data["stdoutBytes"] < 0
                    or _recorded_group_active(started.data)):
                raise ValueError("failed host proof command differs or remains active")
            invocations.add(invocation)
        captured = events[offset]
        offset += 1
        if (captured.level != "info" or captured.message != "strict host proof capture completed"
                or captured.data != fields):
            raise ValueError("failed host proof capture differs")
    if (offset != len(events) - 1 or any(workspace_root.glob(".barragan-strict-host-proof-*"))
            or jobs.get(child.id) != child):
        raise ValueError("failed host proof changed or retained scratch")


def _audit_failed_host_retirement(core, teardown, destroyed, scope, rows, jobs) -> None:
    """Bind retired rows to the exact sealed post-absence coordinator event."""
    from datetime import timedelta

    from app.services.engagement_teardown import _fingerprint
    from app.services.provider_keyed_comprehensive_teardown import ACTION, _child_id
    from app.services.provider_keyed_pending_retirement import _EVENT_KEYS
    from app.storage.job_repository import (
        _PROVIDER_ABSENT_PROOF_KEYS, _utc_instant, _valid_provider_absent_handoff,
    )

    if teardown is None or destroyed is None or destroyed.status != "succeeded":
        raise ValueError("retired failed-host source differs")
    snapshot = teardown.input.get("scopeSnapshot")
    coordinator = jobs.get(_child_id(core.id))
    if (type(snapshot) is not dict or coordinator is None
            or coordinator.action != ACTION or coordinator.status != "running"
            or coordinator.finished_at is not None
            or coordinator.target_type != "engagement"
            or coordinator.target_id != core.input["engagementId"]
            or coordinator.target != f"engagement:{coordinator.target_id}"
            or coordinator.requested_by != teardown.requested_by
            or coordinator.input.get("coreJobId") != core.id
            or coordinator.input.get("corePlanId") != core.input["corePlanId"]
            or coordinator.input.get("teardownParentId") != teardown.id
            or coordinator.input.get("scopeSnapshotId") != snapshot.get("snapshotId")
            or coordinator.input.get("providerScopeSha256") != snapshot.get("providerScopeSha256")
            or len(coordinator.events) < 7
            or [event.sequence for event in coordinator.events]
               != list(range(1, len(coordinator.events) + 1))):
        raise ValueError("retired failed-host coordinator differs")
    prefix = coordinator.events[:7]
    absent, sealed = prefix[5], prefix[6]
    data = sealed.data
    absence = absent.data
    ready = replace(coordinator, input={**coordinator.input, "phase": "inspector_ready"},
                    events=prefix[:5])
    resource_ids = {row["address"]: row["id"] for row in scope["resources"]}
    droplets = sorted(value for address, value in resource_ids.items()
                      if address.startswith("digitalocean_droplet."))
    timestamps = (data.get("confirmationCompletedAt"),
                  data.get("observedAt"), data.get("confirmationExpiresAt")) if type(data) is dict else ()
    instants = tuple(_utc_instant(value) for value in timestamps)
    if (absent.level != "info" or absent.message != "provider_absent"
            or type(absence) is not dict
            or set(absence) != _PROVIDER_ABSENT_PROOF_KEYS | {"observedAt"}
            or not _valid_provider_absent_handoff(
                ready, job_event_digest(ready.events),
                {key: value for key, value in absence.items() if key != "observedAt"})
            or absence["applyJobId"] != destroyed.id
            or absence["resourceIdsSha256"] != _fingerprint(resource_ids)
            or sealed.level != "info" or sealed.message != "keyed_pending_provider_group_retired"
            or type(data) is not dict or set(data) != _EVENT_KEYS
            or data["sourceJournalSha256"] != job_event_digest(prefix[:6])
            or data["scopeSnapshotId"] != snapshot["snapshotId"]
            or data["providerScopeSha256"] != snapshot["providerScopeSha256"]
            or data["applyJobId"] != destroyed.id
            or data["resourceIdsSha256"] != _fingerprint(resource_ids)
            or data["verifiedAbsentDropletIds"] != droplets
            or data["verifiedAbsentFirewallId"] != resource_ids["digitalocean_firewall.firewall"]
            or data["verifiedAbsentSshKeyId"] != resource_ids["digitalocean_ssh_key.key"]
            or data["chainIds"] != sorted(scope["chainIds"])
            or data["chainFingerprints"] != {
                key: scope["chainFingerprints"][key] for key in sorted(scope["chainIds"])}
            or type(data["retiredRecordIds"]) is not list
            or data["retiredRecordIds"] != sorted(set(data["retiredRecordIds"]))
            or len(instants) != 3 or any(value is None for value in instants)
            or not (instants[0] <= instants[1] < instants[2]
                    <= instants[0] + timedelta(seconds=30))
            or any(row.chain_id not in scope["chainIds"] for row in rows)
            or jobs.get(coordinator.id) != coordinator):
        raise ValueError("retired failed-host seal differs")


def _valid_started_identity(data: dict) -> bool:
    try:
        UUID(data["bootId"])
    except (KeyError, TypeError, ValueError, AttributeError):
        return False
    return (type(data.get("pid")) is int and data["pid"] > 0
            and data.get("pgid") == data["pid"]
            and type(data.get("startTicks")) is int and data["startTicks"] > 0)


def _recorded_group_active(data: dict) -> bool:
    """Read process groups only; never signal a reused PID or old boot group."""
    boot_path = Path("/proc/sys/kernel/random/boot_id")
    if not boot_path.exists():
        raise ValueError("Linux process inventory unavailable")
    if boot_path.read_text().strip() != data["bootId"]:
        return False
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "stat").read_text()
            fields = raw[raw.rfind(")") + 2:].split()
            if int(fields[2]) == data["pgid"] and fields[0] != "Z":
                return True
        except (FileNotFoundError, ProcessLookupError):
            continue
    return False


def _pending_parent_shape(parent, core, plan_job_id: str, apply_job_id: str) -> bool:
    inputs = {key: value for key, value in parent.input.items() if not key.startswith("claim")}
    return (
        parent.action == ACTION and parent.target == f"engagement:{core.input['engagementId']}"
        and parent.target_type == "engagement" and parent.target_id == core.input["engagementId"]
        and parent.requested_by == core.requested_by
        and parent.input.get("claimOwner") == "provider-keyed-teardown-handoff"
        and all(isinstance(parent.input.get(key), str) and bool(parent.input[key])
                and parent.input[key] == parent.input[key].strip()
                for key in ("claimToken", "claimClaimedAt", "claimExpiresAt"))
        and inputs == {
            "engagementId": core.input["engagementId"], "coreJobId": core.id,
            "corePlanId": core.input["corePlanId"], "planJobId": plan_job_id,
            "applyJobId": apply_job_id, "phase": "teardown_handoff_pending", "mutation": True,
        }
    )


def _published_parent_shape(parent, core, plan_job_id: str, apply_job_id: str) -> bool:
    # Publication strips the claim and changes only phase/status/finished_at.
    # Reuse the initial continuation's exact identity and optional recheck shape.
    if any(key.startswith("claim") for key in parent.input):
        return False
    candidate = replace(parent, status="running", finished_at=None,
                        input={**parent.input, "phase": "awaiting_strict_host_proof"})
    return _same_parent(candidate, core, core.input["engagementId"],
                        core.input["corePlanId"], plan_job_id, apply_job_id)


def _only(events, message):
    matches = [event for event in events if event.message == message]
    if len(matches) != 1 or matches[0].level != "info":
        raise ValueError("event is missing or ambiguous")
    return matches[0]


def _private_directory(path: Path, *, collaborator_root: bool = False) -> bool:
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        return False
    if mode == 0o700:
        return True
    if collaborator_root and mode == 0o2750:
        trusted_gid = _collaborator_group_gid()
        return trusted_gid is not None and info.st_gid == trusted_gid
    return False


def _clean_scratch(path: Path, root: Path, *, allow_missing: bool = False) -> None:
    if (not path.is_absolute() or path.parent != root or not _SCRATCH.fullmatch(path.name)
            or path.is_symlink()):
        raise ValueError("bootstrap scratch path or staged keys are unsafe")
    # Successful deployments may later prune their empty scratch directories.
    # A pending bootstrap still requires both directories for quiescence proof.
    if allow_missing and not path.exists():
        return
    if (path.resolve(strict=True) != path or not _private_directory(path)
            or (path / "keys").exists()
            or (path / "keys").is_symlink()):
        raise ValueError("bootstrap scratch path or staged keys are unsafe")
    # V2 disables SSH multiplexing. A socket, FIFO, symlink, or foreign owner
    # in a retained scratch workspace makes control-artifact cleanup uncertain.
    visited = 0
    def walk_error(error: OSError) -> None:
        raise ValueError("bootstrap scratch inventory could not be traversed") from error

    for directory, names, files in os.walk(path, followlinks=False, onerror=walk_error):
        for name in (*names, *files):
            visited += 1
            if visited > 4096:
                raise ValueError("bootstrap scratch inventory is unbounded")
            child = Path(directory) / name
            metadata = child.lstat()
            if (metadata.st_uid != os.geteuid()
                    or not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode))
                    or (stat.S_ISDIR(metadata.st_mode) and metadata.st_mode & 0o500 != 0o500)
                    or metadata.st_mode & 0o022):
                raise ValueError("bootstrap scratch contains an unsafe artifact")


def _command_journal(events, prepared_sequence: int, ids: list[str], scratch: list[str]) -> int:
    active = 0
    sequence = [0, 0]
    contacted = [False, False]
    rooted = [False, False]
    phases: list[list[tuple[str, int]]] = [[], []]
    invocations: set[str] = set()
    pending: tuple[dict, int] | None = None
    stage = "intent"
    count = 0
    for event in events:
        if event.sequence <= prepared_sequence or event.message == _FINAL:
            continue
        if active >= 2 or event.level != "info":
            raise ValueError("host command followed terminal chain completion")
        data = event.data
        if event.message == _CONTACT:
            if pending is not None or contacted[active] or data != {"chainId": ids[active]}:
                raise ValueError("host contact differs")
            contacted[active] = True
        elif event.message == _ROOT:
            if (pending is not None or not contacted[active] or rooted[active]
                    or data != {"chainId": ids[active]}
                    or not phases[active]
                    or phases[active][-1] != ("root_management_readiness", 0)):
                raise ValueError("root start differs")
            rooted[active] = True
        elif event.message in {_INTENT, _STARTED, _RESULT}:
            if not contacted[active] or data.get("chainId") != ids[active]:
                raise ValueError("command chain differs")
            if event.message == _INTENT:
                if pending is not None or stage != "intent":
                    raise ValueError("command intent overlaps")
                phase, number, attempt = data.get("phase"), data.get("sequence"), data.get("attempt")
                invocation = data.get("invocationId")
                if (phase not in _PHASES or type(number) is not int or number != sequence[active] + 1
                        or type(attempt) is not int
                        or attempt != 1 + sum(earlier == phase for earlier, _ in phases[active])
                        or not isinstance(invocation, str) or not invocation or invocation in invocations
                        or data.get("scratchPath") != scratch[active]
                        or not isinstance(data.get("argvSha256"), str)
                        or not _HASH.fullmatch(data["argvSha256"])):
                    raise ValueError("command intent fields differ")
                if phase == "root_management_readiness" and rooted[active]:
                    raise ValueError("root readiness was replayed after root start")
                if phase == "upstream_root_bootstrap" and not rooted[active]:
                    raise ValueError("root command lacks start fence")
                if (phase in {"user_readiness", "transport_install"}
                        and (not rooted[active] or not any(
                            earlier == "upstream_root_bootstrap" and code == 0
                            for earlier, code in phases[active]))):
                    raise ValueError("post-root command lacks start fence")
                if (phase == "transport_install" and (not phases[active]
                        or phases[active][-1] != ("user_readiness", 0))):
                    raise ValueError("transport command lacks user readiness")
                invocations.add(invocation)
                pending = (data, event.sequence)
                stage = "started"
            elif event.message == _STARTED:
                if pending is None or stage != "started" or not _same_command(data, pending[0]):
                    raise ValueError("command start differs")
                try:
                    UUID(data["bootId"])
                except (KeyError, TypeError, ValueError, AttributeError):
                    raise ValueError("command boot identity differs") from None
                if (type(data.get("pid")) is not int or data["pid"] <= 0
                        or data.get("pgid") != data["pid"]
                        or type(data.get("startTicks")) is not int or data["startTicks"] <= 0):
                    raise ValueError("command process identity differs")
                stage = "result"
            else:
                if pending is None or stage != "result" or not _same_command(data, pending[0]):
                    raise ValueError("command result differs")
                if (type(data.get("returnCode")) is not int
                        or any(type(data.get(key)) is not int or data[key] < 0
                               for key in ("stdoutBytes", "stderrBytes"))
                        or any(type(data.get(key)) is not bool
                               for key in ("stdoutTruncated", "stderrTruncated"))):
                    raise ValueError("command result metadata differs")
                without_bootstrap_timing(data, success=True)
                phases[active].append((pending[0]["phase"], data["returnCode"]))
                sequence[active] += 1
                count += 1
                pending = None
                stage = "intent"
        elif event.message == _COMPLETE:
            if (pending is not None or not rooted[active] or data.get("chainId") != ids[active]
                    or type(data.get("nodeCount")) is not int or data["nodeCount"] < 2
                    or any(data.get(key) != 0 for key in (
                        "rootReturnCode", "userReadinessReturnCode", "transportReturnCode"))
                    or not _completed_phases(phases[active])):
                raise ValueError("chain completion differs from command audit")
            active += 1
        else:
            raise ValueError("unexpected post-preparation host audit event")
    if active != 2 or pending is not None or count < 8:
        raise ValueError("two complete command journals are absent")
    return count


def _same_command(data: dict, original: dict) -> bool:
    return all(data.get(key) == original.get(key) for key in (
        "chainId", "phase", "sequence", "attempt", "invocationId"))


def _completed_phases(rows: list[tuple[str, int]]) -> bool:
    phases = [phase for phase, _code in rows]
    if (not phases or phases[0] != "root_management_readiness"
            or phases.count("upstream_root_bootstrap") != 1
            or phases[-1] != "transport_install"):
        return False
    for required in _PHASES:
        if required not in phases or next(code for phase, code in reversed(rows) if phase == required) != 0:
            return False
    return True
