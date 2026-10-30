# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
from copy import deepcopy
import hashlib
import ipaddress
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol

from app.domain import JobEvent, JobRunDetail, JobRunSummary
from app.core.request_identity import current_request_identity
from app.storage.binding_history import is_independent_binding_history


class MixedAppendBindingFenceError(ValueError):
    """A binding-history writer must wait for paired append completion."""

    def __init__(self):
        super().__init__("channel and service changes are unavailable during paired edge append")


def _fence_append_binding_history(job: StoredJobRun, *, connection=None) -> None:
    """Hold the existing SQLite writer through the caller's history commit."""
    if not is_independent_binding_history(job.action):
        return
    if connection is not None:
        # Offline raw repositories may not contain the control-plane lease table.
        if not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                                  "AND name='core_mutation_leases'").fetchone():
            return
        connection.execute("UPDATE core_mutation_leases SET operation = operation "
                           "WHERE engagement_id = ?", (job.target_id,))
        held = connection.execute("SELECT 1 FROM core_mutation_leases WHERE "
            "engagement_id = ? AND operation = 'provider_keyed_mixed_append'",
            (job.target_id,)).fetchone()
    else:
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel
        CoreMutationLeaseModel.query.filter_by(engagement_id=job.target_id).update(
            {"operation": CoreMutationLeaseModel.operation}, synchronize_session=False)
        held = CoreMutationLeaseModel.query.filter_by(engagement_id=job.target_id,
            operation="provider_keyed_mixed_append").first()
    if held:
        if connection is None:
            db.session.rollback()
        raise MixedAppendBindingFenceError()


SEMANTIC_EVENT_KEYS = (
    "connectionDetails",
    "sketchInfrastructure",
    "outboundChannels",
    "inboundChannels",
    "servicePlacements",
    "capabilities",
    "mutationStatus",
    "finalCleanupStatus",
)
SEMANTIC_JOB_ACTIONS = {
    "pilot_standard_rti_guarded_execute",
    "engagement_comprehensive_teardown",
    "linode_sketch_deploy",
    "digitalocean_sketch_deploy",
    "mixed_provider_sketch_deploy",
    "linode_sketch_reconcile",
    "digitalocean_sketch_reconcile",
    "linode_sketch_teardown",
    "digitalocean_sketch_teardown",
    "mixed_provider_sketch_teardown",
    "sketch_edge_retire",
    "sketch_edge_replace",
    "engagement_channels_update",
    "outbound_channel_apply",
    "outbound_channel_validation",
    "outbound_channel_remove",
    "inbound_channel_apply",
    "inbound_channel_validation",
    "inbound_channel_remove",
    "inspector_cleanup",
}
SEMANTIC_ROWS_PER_CATEGORY = 32
DASHBOARD_EVENT_KEYS = (
    "capabilities",
    "servicePlacements",
    "createdResources",
    "connectionDetails",
    "sketchInfrastructure",
    "outboundChannels",
    "inboundChannels",
    "mutationStatus",
    "finalCleanupStatus",
    "remainingCount",
    "region",
    "target",
    "inspectorTeardownVerification",
    "inspectorCleanup",
)


def _valid_eligible_phases(phases: set[str] | None) -> bool:
    return phases is None or (
        isinstance(phases, set) and bool(phases)
        and all(isinstance(phase, str) and phase and phase.strip() == phase for phase in phases)
    )


_BOOTSTRAP_FINAL_MESSAGE = "provider bootstrap completed; strict host proof pending"
_BOOTSTRAP_HANDOFF_PHASE = "teardown_handoff_pending"
_BOOTSTRAP_HANDOFF_MESSAGE = "provider bootstrap claim fenced for teardown handoff"
_APPLY_INPUT_KEYS = frozenset({"engagementId", "coreJobId", "corePlanId", "planJobId", "mutation"})
_MIXED_INITIAL_APPLY_INPUT_KEYS = frozenset({
    "engagementId", "coreJobId", "corePlanId", "mixedParentId", "sealJournalSha256",
    "provider", "providerIndex", "chainId", "receiptSha256", "mutation",
})
_MIXED_APPEND_APPLY_INPUT_KEYS = frozenset({
    "engagementId", "coreJobId", "corePlanId", "appendParentId",
    "reviewSha256", "provider", "providerIndex", "mutation",
})
_MIXED_APPEND_APPLY_ACTIONS = frozenset({
    "provider_keyed_mixed_append_apply_child",
    "provider_keyed_mixed_append_second_apply_child",
})

_MIXED_APPEND_BOOKKEEPING_LEASE_SQL = """
(action NOT IN ('provider_keyed_mixed_append',
                'provider_keyed_mixed_append_apply_child',
                'provider_keyed_mixed_append_second_apply_child')
 OR EXISTS (SELECT 1 FROM core_mutation_leases
            WHERE engagement_id = job_runs.target_id
              AND owner_id = json_extract(job_runs.input, '$.corePlanId')
              AND operation = 'provider_keyed_mixed_append'))
"""
_MIXED_INTERRUPTED_DESTROY_INPUT_KEYS = frozenset({
    "engagementId", "coreJobId", "corePlanId", "cleanupParentId",
    "cleanupJournalSha256", "sourceSha256", "planSetSha256", "provider",
    "providerIndex", "scopeSha256", "beforeStateSha256", "planPath",
    "planSha256", "showSha256", "terraformPath", "terraformSha256", "mutation",
})
_MIXED_PUBLISHED_DESTROY_INPUT_KEYS = frozenset({
    "engagementId", "coreJobId", "corePlanId", "cleanupParentId",
    "cleanupJournalSha256", "planSetSha256", "provider", "providerIndex",
    "scopeSha256", "beforeStateSha256", "planPath", "planSha256",
    "showSha256", "priorAbsenceReceiptSha256", "mutation",
})
_MIXED_INITIAL_HOST_WORKER_INPUT_KEYS = frozenset({
    "engagementId", "coreJobId", "corePlanId", "mixedParentId",
    "handoffJournalSha256", "bindingJobId", "bindingManifestSha256", "mutation",
})
_MIXED_INITIAL_STRICT_PROOF_INPUT_KEYS = frozenset({
    "engagementId", "coreJobId", "corePlanId", "mixedParentId",
    "handoffJournalSha256", "bindingJobId", "bindingManifestSha256",
    "bootstrapJobId", "bootstrapJournalSha256", "mutation",
})
_MIXED_LINODE_DIAGNOSTIC_INPUT_KEYS = _MIXED_INITIAL_STRICT_PROOF_INPUT_KEYS
_MIXED_INTERRUPTED_PLAN_WORKER_INPUT_KEYS = frozenset({
    "engagementId", "coreJobId", "corePlanId", "cleanupParentId",
    "reviewSha256", "mutation",
})
_MIXED_INTERRUPTED_SELECTOR_INPUT_KEYS = frozenset({
    "schema", "engagementId", "coreJobId", "corePlanId", "teardownParentId",
    "reviewSha256", "planSetSha256", "doScopeSha256", "selectorTag",
    "providerConnectionId", "credentialSecretSha256", "credentialUpdatedAt",
    "ociAbsenceJobId", "ociAbsenceJournalSha256", "inspectorNegativeJobId",
    "inspectorNegativeJournalSha256", "mutation",
})
_MIXED_PUBLISHED_SELECTOR_INPUT_KEYS = (
    _MIXED_INTERRUPTED_SELECTOR_INPUT_KEYS | frozenset({
        "doAbsenceReceiptSha256", "publishedParentJournalSha256",
    })
)
_APPEND_APPLY_INPUT_KEYS = frozenset({
    "engagementId", "parentJobId", "coreJobId", "corePlanId", "planJobId", "mutation",
})
_DESTROY_PLAN_INPUT_KEYS = frozenset({
    "engagementId", "coreJobId", "corePlanId", "teardownParentId",
    "scopeSnapshotId", "providerScopeSha256", "mutation",
})
_DESTROY_APPLY_INPUT_KEYS = _DESTROY_PLAN_INPUT_KEYS | frozenset({"destroyPlanJobId", "planSha256"})
_CORE_DESTROY_APPLY_INPUT_KEYS = frozenset({
    "teardownParentId", "coreJobId", "corePlanId", "scopeSnapshotId",
    "coordinatorJournalSha256", "previewJobId", "previewJournalSha256",
    "planSha256", "mutation",
})
_MIXED_CORE_DESTROY_APPLY_INPUT_KEYS = frozenset({
    "teardownParentId", "coreJobId", "corePlanId", "sourceSha256",
    "previewJobId", "previewJournalSha256", "planSha256", "mutation",
})
_SELECTOR_RETIRE_INPUT_KEYS = frozenset({
    "engagementId", "coreJobId", "corePlanId", "teardownParentId",
    "scopeSnapshotId", "providerScopeSha256", "selectorTag",
    "providerConnectionId", "credentialSecretSha256", "credentialUpdatedAt",
    "initialApplyJobId", "initialApplyJournalSha256", "coreAbsenceJobId",
    "coreAbsenceJournalSha256", "mutation",
})
_SELECTOR_RETIRE_PUBLISHED_INPUT_KEYS = _SELECTOR_RETIRE_INPUT_KEYS | frozenset({
    "inspectorNegativeJobId", "inspectorNegativeJournalSha256",
})
_INSPECTOR_COORDINATOR_INPUT_KEYS = _DESTROY_PLAN_INPUT_KEYS | frozenset({"phase"})
_INSPECTOR_INTENT_KEYS = frozenset({
    "scopeSnapshotId", "providerScopeSha256", "provider", "region", "size",
    "credentialAlias", "credentialId", "credentialSha256", "credentialUpdatedAt",
    "resourceName", "keyFingerprintSha256",
    "managementSourceCidr", "claimGenerationSha256",
})


class KeyedDomainAssignmentConflict(ValueError):
    """Frozen keyed DNS assignments changed before teardown parent publication."""


class PublishedKeyedTeardownReservationConflict(ValueError):
    """The private published-source reservation needs fresh review or recovery."""


class MixedZeroApplyReservationConflict(ValueError):
    """The private mixed zero-Apply fence needs fresh review or recovery."""


def _mixed_absence_finish_base(job: StoredJobRun, owner: str, token: str,
                               digest: str, event: JobEvent) -> dict[str, Any] | None:
    """Validate the one private GET-only mixed absence terminal generation."""
    data = job.input
    if not isinstance(data, dict):
        return None
    base = {key: value for key, value in data.items() if key not in {
        "claimOwner", "claimToken", "claimClaimedAt", "claimHeartbeatAt", "claimExpiresAt"}}
    expected = {"teardownParentId", "coreJobId", "corePlanId", "sourceSha256",
                "previewJobId", "previewJournalSha256", "applyJobId",
                "applyJournalSha256", "preDestroyResourceIdsSha256",
                "preDestroyStateSha256", "emptyStateSha256", "principalSha256",
                "attempt", "previousAttemptId", "previousAttemptJournalSha256"}
    success_event = (event.level == "info"
                     and event.message == "mixed core exact absence proved"
                     and type(event.data) is dict
                     and set(event.data) == {"emptyStateSha256", "preDestroyResourceIdsSha256",
                                             "ociAbsenceWitness"}
                     and event.data["emptyStateSha256"] == base.get("emptyStateSha256")
                     and event.data["preDestroyResourceIdsSha256"] == base.get(
                         "preDestroyResourceIdsSha256")
                     and type(event.data["ociAbsenceWitness"]) is dict)
    failure_event = (event.level == "error"
                     and event.message == "mixed core absence unverified"
                     and event.data in ({"retryablePendingTimeout": True},
                                        {"retryablePendingTimeout": False}))
    if (job.action != "provider_keyed_mixed_zero_apply_core_destroy_absence"
            or job.status != "running" or not job.started_at or job.finished_at is not None
            or job.target != f"engagement:{job.target_id}"
            or job.target_type != "engagement" or job.artifact_refs != []
            or data.get("claimOwner") != owner or data.get("claimToken") != token
            or set(base) != expected
            or type(base["attempt"]) is not int or base["attempt"] not in (1, 2, 3)
            or any(type(base[key]) is not str or not base[key]
                   for key in ("teardownParentId", "coreJobId", "corePlanId",
                               "previewJobId", "applyJobId"))
            or any(type(base[key]) is not str or re.fullmatch(r"[0-9a-f]{64}", base[key]) is None
                   for key in ("sourceSha256", "previewJournalSha256",
                               "applyJournalSha256", "preDestroyResourceIdsSha256",
                               "preDestroyStateSha256", "emptyStateSha256",
                               "principalSha256"))
            or (base["attempt"] == 1 and (
                base["previousAttemptId"] is not None
                or base["previousAttemptJournalSha256"] is not None))
            or (base["attempt"] > 1 and (
                type(base["previousAttemptId"]) is not str
                or re.fullmatch(r"[0-9a-f]{64}",
                                base["previousAttemptJournalSha256"] or "") is None))
            or not all(isinstance(data.get(key), str) and data[key]
                       for key in ("claimClaimedAt", "claimExpiresAt"))
            or job_event_digest(job.events) != digest
            or job.events != [JobEvent(1, "info", "mixed core absence queued", {}),
                              JobEvent(2, "info", "mixed core absence started", {})]
            or event.sequence != 3 or not (success_event or failure_event)):
        return None
    return base


def inspector_claim_generation_digest(*, token: str, claimed_at: str) -> str:
    """Bind a durable intent to its original opaque claim without recording the token."""
    payload = {"token": token, "claimedAt": claimed_at}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def valid_inspector_management_source_cidr(value: object) -> bool:
    """Only a canonical, globally routable unicast IPv4 host source is safe."""
    if type(value) is not str:
        return False
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        return False
    address = network.network_address
    return (network.version == 4 and network.prefixlen == 32
            and value == f"{address}/32" and address.is_global
            and not any((address.is_private, address.is_reserved,
                         address.is_multicast, address.is_loopback,
                         address.is_link_local, address.is_unspecified)))
_INSPECTOR_CLAIM_OWNER = "provider-keyed-inspector-create"
_RETAINED_INSPECTOR_OWNER = "provider-keyed-retained-inspector-proof"
_RETAINED_READY_OWNER = "provider-keyed-retained-inspector-ready-handoff"
_PROVIDER_ABSENT_PROOF_KEYS = frozenset({
    "scopeSnapshotId", "providerScopeSha256", "readyJournalSha256",
    "previewJobId", "previewJournalSha256", "applyJobId", "applyJournalSha256",
    "emptyStateSha256", "resourceIdsSha256", "verifiedAbsentDropletIds",
    "verifiedAbsentFirewallId", "verifiedAbsentSshKeyId", "selectorTagCleanupPending",
    "confirmationCompletedAt", "confirmationExpiresAt",
})
_RETAINED_HANDOFF_MESSAGES = (
    "keyed teardown coordinator queued", "keyed teardown coordinator started",
    "keyed teardown handoff intended",
    "keyed teardown handoff verified; Inspector preflight pending",
)
_INSPECTOR_STAGE_KEYS = frozenset({
    "provider", "resourceName", "stage", "point", "resourceId", "firewallId",
    "dropletId", "tagName", "tagExclusive",
})
_INSPECTOR_BARRIER_PARENT = "engagement_comprehensive_teardown"
_INSPECTOR_BARRIER_ACTIONS = frozenset({
    "inspector_inspection", "inspector_readiness", "inspector_cleanup",
})


def _inspector_barrier_opponents(job: StoredJobRun) -> tuple[str, ...]:
    if (job.action == _INSPECTOR_BARRIER_PARENT and job.status == "queued"
            and job.started_at is None):
        opponents = tuple(sorted(_INSPECTOR_BARRIER_ACTIONS))
    elif (job.action in _INSPECTOR_BARRIER_ACTIONS and job.status == "running"
          and job.started_at is not None):
        opponents = (_INSPECTOR_BARRIER_PARENT,)
    else:
        raise ValueError("Inspector/teardown barrier requires an initial lifecycle job")
    if (job.target_type != "engagement" or not job.target_id
            or job.target != f"engagement:{job.target_id}"
            or job.finished_at is not None or job.artifact_refs != []
            or len(job.events) != 1 or job.events[0].sequence != 1):
        raise ValueError("Inspector/teardown barrier job identity is invalid")
    return opponents
_APPLY_CLAIM_KEYS = frozenset({"claimOwner", "claimToken", "claimClaimedAt", "claimExpiresAt"})
_UTC_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?\+00:00\Z")
_STORED_NAIVE_UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?\Z"
)


def _utc_instant(value: Any) -> datetime | None:
    if type(value) is not str or _UTC_TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.utcoffset() == timedelta(0) else None


def _stored_utc_instant(value: Any) -> datetime | None:
    """SQLAlchemy stores UTC timestamps as naive datetimes; SQLite keeps offsets."""
    if type(value) is not str:
        return None
    aware = _utc_instant(value)
    if aware is not None:
        return aware
    if _STORED_NAIVE_UTC_TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else None


def _valid_claimed_apply_times(job: StoredJobRun, *, at: str, next_expiry: str | None = None) -> bool:
    claimed = _utc_instant(job.input.get("claimClaimedAt"))
    prior_heartbeat = _utc_instant(job.input.get("claimHeartbeatAt")) if "claimHeartbeatAt" in job.input else claimed
    old_expiry = _utc_instant(job.input.get("claimExpiresAt"))
    moment = _utc_instant(at)
    future = _utc_instant(next_expiry) if next_expiry is not None else None
    return (claimed is not None and prior_heartbeat is not None and old_expiry is not None
            and moment is not None and claimed <= prior_heartbeat <= moment < old_expiry
            and (next_expiry is None or (future is not None and future > moment)))


def job_event_digest(events: list[JobEvent]) -> str:
    """Digest the complete ordered journal, including event payloads."""
    payload = [
        {"sequence": event.sequence, "level": event.level,
         "message": event.message, "data": event.data}
        for event in events
    ]
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


_MIXED_PLAN_PHASES = {
    "queued": ("planning", "mixed provider planning started"),
    "planning": ("first_plan_saved", "first mixed provider plan saved"),
    "first_plan_saved": ("second_plan_saved", "second mixed provider plan saved"),
    "second_plan_saved": ("both_plans_saved", "both mixed provider plans saved"),
    "both_plans_saved": ("apply_sealed", "mixed provider Apply source sealed"),
}


def _valid_mixed_plan_phase_append(
    job: StoredJobRun, *, owner: str, token: str, lease_owner: str, digest: str,
    phase: str, event: JobEvent,
) -> bool:
    """Validate the dormant mixed-plan parent before its narrow SQLite CAS."""
    prior = job.input.get("phase") if isinstance(job.input, dict) else None
    transition = _MIXED_PLAN_PHASES.get(prior)
    if (not isinstance(job.input, dict)
            or job.action != "provider_keyed_mixed_initial" or job.status not in {"queued", "running"}
            or job.finished_at is not None or job.target_type != "engagement"
            or job.target_id != job.input.get("engagementId")
            or lease_owner != job.input.get("corePlanId")
            or job.input.get("claimOwner") != owner or job.input.get("claimToken") != token
            or _utc_instant(job.input.get("claimExpiresAt")) is None
            or _utc_instant(job.input["claimExpiresAt"]) <= datetime.now(timezone.utc)
            or not isinstance(digest, str) or digest != job_event_digest(job.events)
            or transition != (phase, event.message) or event.level != "info"
            or event.sequence != len(job.events) + 1 or not isinstance(event.data, dict)):
        return False
    if phase == "planning":
        return event.data == {}
    order = job.input.get("orderedProviders")
    ids = job.input.get("chainIds")
    if (not isinstance(order, list) or len(order) != 2 or set(order) != {"linode", "digitalocean"}
            or not isinstance(ids, list) or len(ids) != 2):
        return False
    if phase in {"first_plan_saved", "second_plan_saved"}:
        index = 0 if phase == "first_plan_saved" else 1
        return (set(event.data) == {"provider", "chainId", "receiptSha256", "planSha256",
                                    "journalSha256"}
                and event.data["provider"] == order[index]
                and event.data["chainId"] == ids[index]
                and all(isinstance(event.data[key], str)
                        and re.fullmatch(r"[0-9a-f]{64}", event.data[key]) is not None
                        for key in ("receiptSha256", "planSha256", "journalSha256")))
    if phase == "apply_sealed":
        data = event.data
        return (set(data) == {"schema", "corePlanId", "reviewFingerprint", "orderedProviders",
                             "chainIds", "providerConnectionIds", "receiptSha256",
                             "intentSha256", "sourceCredentialSnapshotSha256",
                             "firstFiveJournalSha256", "reviewedPolicy"}
                and data["schema"] == "mixed-initial-apply-seal-v1"
                and data["corePlanId"] == job.input.get("corePlanId")
                and data["reviewFingerprint"] == job.input.get("reviewFingerprint")
                and data["orderedProviders"] == order and data["chainIds"] == ids
                and data["receiptSha256"] == [job.events[2].data.get("receiptSha256"),
                                              job.events[3].data.get("receiptSha256")]
                and data["firstFiveJournalSha256"] == job_event_digest(job.events)
                and isinstance(data["providerConnectionIds"], list)
                and len(data["providerConnectionIds"]) == 2
                and all(isinstance(value, str) and value for value in data["providerConnectionIds"])
                and isinstance(data["intentSha256"], list) and len(data["intentSha256"]) == 2
                and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                        for value in data["intentSha256"])
                and isinstance(data["reviewedPolicy"], dict)
                and all(isinstance(data[key], str) and re.fullmatch(r"[0-9a-f]{64}", data[key])
                        for key in ("sourceCredentialSnapshotSha256",)))
    return (set(event.data) == {"firstReceiptSha256", "secondReceiptSha256", "reviewFingerprint"}
            and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
                    for value in event.data.values()))


def _valid_mixed_initial_handoff_append(
    job: StoredJobRun, *, owner: str, token: str, lease_owner: str,
    digest: str, event: JobEvent,
) -> bool:
    """Validate the sole sealed-provider-to-host-proof parent transition."""
    inputs = job.input if isinstance(job.input, dict) else {}
    data = event.data if isinstance(event.data, dict) else {}
    fresh = data.get("firstFreshPresence")
    hashes = data.get("terminalJournalSha256")
    proofs = data.get("providerProofSha256")
    return (
        job.action == "provider_keyed_mixed_initial" and job.status == "running"
        and job.finished_at is None and inputs.get("phase") == "apply_sealed"
        and len(job.events) == 6 and inputs.get("engagementId") == job.target_id
        and lease_owner == inputs.get("corePlanId")
        and inputs.get("claimOwner") == owner and inputs.get("claimToken") == token
        and _utc_instant(inputs.get("claimExpiresAt")) is not None
        and _utc_instant(inputs["claimExpiresAt"]) > datetime.now(timezone.utc)
        and digest == job_event_digest(job.events)
        and event == JobEvent(7, "info",
                              "mixed provider Apply proofs joined; awaiting host proof", data)
        and set(data) == {"schema", "sealJournalSha256", "coreJobId", "corePlanId",
                          "orderedProviders", "chainIds", "terminalJournalSha256",
                          "providerProofSha256", "firstFreshPresence"}
        and data["schema"] == "mixed-initial-host-proof-handoff-v1"
        and data["sealJournalSha256"] == job_event_digest(job.events[:6])
        and data["coreJobId"] == inputs.get("coreJobId")
        and data["corePlanId"] == lease_owner
        and data["orderedProviders"] == inputs.get("orderedProviders")
        and data["chainIds"] == inputs.get("chainIds")
        and isinstance(hashes, list) and isinstance(proofs, list)
        and len(hashes) == len(proofs) == 2
        and all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value)
                for value in hashes + proofs)
        and isinstance(fresh, dict)
        and set(fresh) == {"stateSha256", "lineage", "serial", "resourceIds"}
        and type(fresh["stateSha256"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", fresh["stateSha256"])
        and type(fresh["lineage"]) is str and bool(fresh["lineage"])
        and type(fresh["serial"]) is int and fresh["serial"] >= 1
        and isinstance(fresh["resourceIds"], dict) and bool(fresh["resourceIds"])
        and list(fresh["resourceIds"]) == sorted(fresh["resourceIds"])
        and all(type(key) is str and key and type(value) is str and value
                for key, value in fresh["resourceIds"].items())
    )


def _mixed_initial_handoff_children_match(
    job: StoredJobRun, event: JobEvent, get_child: Callable[[str], StoredJobRun | None],
) -> bool:
    """Re-read both terminal children inside the parent writer transaction."""
    from app.services.provider_keyed_mixed_initial_apply_child import _child_id
    from app.services.provider_keyed_mixed_initial_coordinator import _handoff_data, _terminal_proofs

    try:
        order = tuple(job.input["orderedProviders"])
        children = {provider: get_child(_child_id(job.input["coreJobId"], provider))
                    for provider in order}
        terminals, _ = _terminal_proofs(job, children)
        return event.data == _handoff_data(job, terminals)
    except (KeyError, TypeError, ValueError):
        return False


def _inspector_queued_prefix(job: StoredJobRun, parent: StoredJobRun | None) -> dict | None:
    """Pure parent-bound sealed prefix; unsealed legacy bytes stay exact."""
    from app.services.provider_keyed_published_initial_cleanup_authority import (
        KEY, MARKER, queued_cleanup_event_data, seal_marker,
    )
    inputs = job.input
    if (type(inputs) is not dict or not job.events or type(job.events[0].data) is not dict
            or (parent is not None and type(parent.input) is not dict)):
        return None
    scope = parent.input.get("scopeSnapshot") if parent is not None else None
    marked = MARKER in job.events[0].data
    sealed_parent = type(scope) is dict and KEY in scope
    if not sealed_parent:
        if marked or (parent is not None and MARKER in parent.input):
            return None
        return {"snapshotId": inputs.get("scopeSnapshotId")}
    try:
        from app.services.engagement_teardown import (
            ENGAGEMENT_TEARDOWN_ACTION, _parent_boundary_fields, _parent_id, _fingerprint,
        )
        from app.services.provider_keyed_comprehensive_teardown import _child_id
        fields = _parent_boundary_fields(parent)
        if fields is None:
            return None
        engagement_id, core_id, scope = fields
        scopes = scope["providerScopes"]
        expected = queued_cleanup_event_data(scope)
        if (parent.id != _parent_id(core_id) or parent.action != ENGAGEMENT_TEARDOWN_ACTION
                or parent.status != "queued" or parent.started_at is not None
                or parent.finished_at is not None or parent.artifact_refs != []
                or parent.input.get("phase") != "queued" or parent.input.get("mutation") is not True
                or len(parent.events) != 1
                or parent.events[0] != JobEvent(1, "info", "engagement teardown queued", expected)
                or parent.input.get(MARKER) != seal_marker(scope)
                or "publishedSource" not in parent.input
                or scope["snapshotId"] != _fingerprint({k:v for k,v in scope.items() if k != "snapshotId"})
                or len(scopes) != 1 or scopes[0]["coreJobId"] != core_id
                or job.id != _child_id(core_id) or job.action != "provider_keyed_comprehensive_teardown"
                or job.target != parent.target or job.target_type != parent.target_type
                or job.target_id != engagement_id or job.requested_by != parent.requested_by
                or inputs.get("engagementId") != engagement_id or inputs.get("coreJobId") != core_id
                or inputs.get("corePlanId") != scopes[0]["corePlanId"]
                or inputs.get("teardownParentId") != parent.id
                or inputs.get("scopeSnapshotId") != scope["snapshotId"]
                or inputs.get("providerScopeSha256") != scope["providerScopeSha256"]
                or job.events[0].data != expected):
            return None
        return expected
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return None


def _inspector_prefix_boundary(job: StoredJobRun, get_parent) -> tuple[dict, StoredJobRun | None] | None:
    """Explicit repository lookup; no network or live authority collection."""
    from app.services.provider_keyed_published_initial_cleanup_authority import KEY
    if type(job.input) is not dict:
        return None
    parent = get_parent(job.input.get("teardownParentId"))
    expected = _inspector_queued_prefix(job, parent)
    if expected is None:
        return None
    # Compare the whole sealed parent again after taking the SQLite writer slot.
    scope = parent.input.get("scopeSnapshot") if parent is not None else None
    sealed = type(scope) is dict and KEY in scope
    return expected, deepcopy(parent) if sealed else None


def _inspector_prefix_still_matches(job, boundary, get_parent) -> bool:
    from app.storage.database import db
    db.session.expire_all()
    return _inspector_prefix_boundary(job, get_parent) == boundary


def _valid_retained_inspector_boundary(job: StoredJobRun, digest: str, queued_data: dict | None = None) -> bool:
    """Only the untouched four-event keyed handoff can contact a retained host."""
    inputs = job.input
    if type(inputs) is not dict:
        return False
    base = {key: value for key, value in inputs.items() if not key.startswith("claim")}
    return (
        job.action == "provider_keyed_comprehensive_teardown"
        and job.status == "running" and job.started_at is not None
        and job.finished_at is None and job.artifact_refs == []
        and type(inputs) is dict
        and set(base) == _INSPECTOR_COORDINATOR_INPUT_KEYS
        and base.get("phase") == "awaiting_inspector_preflight"
        and base.get("mutation") is True
        and all(type(base.get(key)) is str and base[key] for key in
                ("engagementId", "coreJobId", "corePlanId", "teardownParentId"))
        and all(type(base.get(key)) is str and re.fullmatch(r"[0-9a-f]{64}", base[key])
                for key in ("scopeSnapshotId", "providerScopeSha256"))
        and job.target_type == "engagement" and job.target_id == base["engagementId"]
        and job.target == f"engagement:{job.target_id}"
        and len(job.events) == 4
        and [event.sequence for event in job.events] == [1, 2, 3, 4]
        and tuple(event.message for event in job.events) == _RETAINED_HANDOFF_MESSAGES
        and [event.data for event in job.events] == [
            (queued_data if queued_data is not None else {"snapshotId": base["scopeSnapshotId"]}), {}, {},
            {"corePlanId": base["corePlanId"]},
        ]
        and all(event.level == "info" for event in job.events)
        and type(digest) is str and job_event_digest(job.events) == digest
    )


_RETAINED_READY_KEYS = frozenset({
    "scopeSnapshotId", "providerScopeSha256", "sourceJournalSha256",
    "hostRecordId", "firewallRecordId", "provider", "hostId", "firewallId",
    "publicIp", "sourceCidr", "credentialId", "credentialUpdatedAt",
    "credentialSha256", "keyFingerprintSha256", "providerProofSha256",
    "sshPolicySha256", "nmapVersionSha256", "claimGenerationSha256",
})


def _valid_retained_ready_event(job: StoredJobRun, digest: str, event: JobEvent | None) -> bool:
    if (event is None or event.sequence != 5 or event.level != "info"
            or event.message != "retained_inspector_ready" or type(event.data) is not dict
            or set(event.data) != _RETAINED_READY_KEYS):
        return False
    data = event.data
    return (
        data["scopeSnapshotId"] == job.input["scopeSnapshotId"]
        and data["providerScopeSha256"] == job.input["providerScopeSha256"]
        and data["sourceJournalSha256"] == digest
        and data["claimGenerationSha256"] == inspector_claim_generation_digest(
            token=job.input["claimToken"], claimed_at=job.input["claimClaimedAt"])
        and type(data["provider"]) is str
        and data["provider"] in {"linode", "digitalocean"}
        and valid_inspector_management_source_cidr(data["sourceCidr"])
        and all(type(data[key]) is str and bool(data[key]) and "\x00" not in data[key]
                for key in ("hostRecordId", "firewallRecordId", "hostId", "firewallId",
                            "publicIp", "credentialId", "credentialUpdatedAt"))
        and all(type(data[key]) is str and re.fullmatch(r"[0-9a-f]{64}", data[key])
                for key in ("credentialSha256", "keyFingerprintSha256",
                            "providerProofSha256", "sshPolicySha256", "nmapVersionSha256"))
    )


def _valid_provider_absent_handoff(job: StoredJobRun, digest: str, proof: dict, queued_data: dict | None = None) -> bool:
    """Check the exact action-scoped ready prefix and nonsecret absence evidence."""
    inputs = job.input
    base = {key: value for key, value in inputs.items()
            if key not in _APPLY_CLAIM_KEYS | {"claimHeartbeatAt"}}
    if (job.action != "provider_keyed_comprehensive_teardown"
            or job.status != "running" or job.finished_at is not None
            or not job.started_at or job.artifact_refs != []
            or job.target_type != "engagement" or job.target != f"engagement:{job.target_id}"
            or set(base) != _INSPECTOR_COORDINATOR_INPUT_KEYS
            or base.get("engagementId") != job.target_id
            or base.get("phase") != "inspector_ready" or base.get("mutation") is not True
            or set(inputs) != set(base) | _APPLY_CLAIM_KEYS | {"claimHeartbeatAt"}
            or inputs.get("claimOwner") != (
                _RETAINED_READY_OWNER if len(job.events) == 5
                else "provider-keyed-inspector-ready-handoff")
            or type(inputs.get("claimToken")) is not str
            or len(inputs["claimToken"]) < 16
            or any(_utc_instant(inputs.get(key)) is None for key in
                   ("claimClaimedAt", "claimHeartbeatAt", "claimExpiresAt"))
            or inputs["claimClaimedAt"] != inputs["claimHeartbeatAt"]
            or inputs["claimClaimedAt"] != inputs["claimExpiresAt"]
            or type(digest) is not str or job_event_digest(job.events) != digest
            or len(job.events) not in (5, 12, 16)
            or [e.sequence for e in job.events] != list(range(1, len(job.events) + 1))
            or [e.message for e in job.events[:4]] != list(_RETAINED_HANDOFF_MESSAGES)
            or [e.data for e in job.events[:4]] != [
                (queued_data if queued_data is not None else {"snapshotId": base["scopeSnapshotId"]}), {}, {},
                {"corePlanId": base["corePlanId"]},
            ] or any(e.level != "info" for e in job.events)
            or (job.events[-1].message != (
                "retained_inspector_ready" if len(job.events) == 5
                else "inspector selected-source proof published"))
            or type(proof) is not dict or set(proof) != _PROVIDER_ABSENT_PROOF_KEYS
            or proof["scopeSnapshotId"] != base["scopeSnapshotId"]
            or proof["providerScopeSha256"] != base["providerScopeSha256"]
            or proof["readyJournalSha256"] != digest
            or any(type(proof[key]) is not str or re.fullmatch(r"[0-9a-f]{64}", proof[key]) is None
                   for key in ("previewJournalSha256", "applyJournalSha256",
                               "emptyStateSha256", "resourceIdsSha256"))
            or any(type(proof[key]) is not str or not proof[key]
                   for key in ("previewJobId", "applyJobId",
                               "verifiedAbsentFirewallId", "verifiedAbsentSshKeyId"))
            or type(proof["verifiedAbsentDropletIds"]) is not list
            or not proof["verifiedAbsentDropletIds"]
            or proof["verifiedAbsentDropletIds"] != sorted(set(proof["verifiedAbsentDropletIds"]))
            or any(type(value) is not str or re.fullmatch(r"[1-9][0-9]*", value) is None
                   for value in proof["verifiedAbsentDropletIds"])
            or type(proof["selectorTagCleanupPending"]) is not bool):
        return False
    completed = _utc_instant(proof["confirmationCompletedAt"])
    expires = _utc_instant(proof["confirmationExpiresAt"])
    if (completed is None or expires is None or expires <= completed
            or expires > completed + timedelta(seconds=30)):
        return False
    return True


def _retained_transition_input(
    job: StoredJobRun, *, mode: str, expected_event_digest: str,
    owner: str, token: str, at: str, expires_at: str, event: JobEvent | None,
    queued_data: dict | None = None,
) -> dict[str, Any] | None:
    if not _valid_retained_inspector_boundary(job, expected_event_digest, queued_data):
        return None
    instant, expiry = _utc_instant(at), _utc_instant(expires_at)
    if (instant is None or expiry is None or type(token) is not str or len(token) < 16
            or expiry <= instant or expiry > instant + timedelta(minutes=5)
            or mode not in {"claim", "heartbeat", "ready"}):
        return None
    if mode == "claim":
        if (owner != _RETAINED_INSPECTOR_OWNER or event is not None
                or job.input.get("claimOwner") != "provider-keyed-comprehensive-handoff"):
            return None
        return {**job.input, "claimOwner": owner, "claimToken": token,
                "claimClaimedAt": at, "claimHeartbeatAt": at, "claimExpiresAt": expires_at}
    prior = _utc_instant(job.input.get("claimHeartbeatAt") or job.input.get("claimClaimedAt"))
    if (owner != _RETAINED_INSPECTOR_OWNER or job.input.get("claimOwner") != owner
            or job.input.get("claimToken") != token or prior is None or instant < prior):
        return None
    if mode == "heartbeat":
        if event is not None:
            return None
        return {**job.input, "claimHeartbeatAt": at, "claimExpiresAt": expires_at}
    if not _valid_retained_ready_event(job, expected_event_digest, event):
        return None
    return {**job.input, "phase": "inspector_ready", "claimOwner": _RETAINED_READY_OWNER,
            "claimToken": hashlib.sha256((token + at).encode()).hexdigest(),
            "claimClaimedAt": at, "claimHeartbeatAt": at, "claimExpiresAt": at}


def _claimed_apply_base(job: StoredJobRun, owner: str, token: str, *,
                        allow_mixed_append_host: bool = False) -> dict[str, Any] | None:
    inputs = job.input
    if job.action == "provider_keyed_mixed_append_pair_host_proof":
        if not allow_mixed_append_host:
            return None
        allowed = {"parentJobId", "sourceSha256", "mutation"}
        if (type(inputs) is not dict or job.status != "running" or not job.started_at
                or job.finished_at is not None or job.target_type != "engagement"
                or job.target != f"engagement:{job.target_id}" or not job.target_id
                or job.artifact_refs != []
                or set(inputs) not in (allowed | _APPLY_CLAIM_KEYS,
                                       allowed | _APPLY_CLAIM_KEYS | {"claimHeartbeatAt"})
                or inputs.get("mutation") is not True
                or type(inputs.get("parentJobId")) is not str or not inputs["parentJobId"]
                or not inputs["parentJobId"].startswith("job-provider-keyed-mixed-append-")
                or job.id != ("job-provider-keyed-mixed-append-host-proof-" +
                    inputs["parentJobId"].removeprefix("job-provider-keyed-mixed-append-"))
                or type(inputs.get("sourceSha256")) is not str
                or re.fullmatch(r"[0-9a-f]{64}", inputs["sourceSha256"]) is None
                or type(owner) is not str or not owner.startswith("mixed-append-host-proof-")
                or type(token) is not str or not token or inputs.get("claimOwner") != owner
                or inputs.get("claimToken") != token):
            return None
        # This host receipt durably binds the original claim pair for restart
        # publication; other Apply actions keep their existing stripped base.
        return dict(inputs)
    allowed = (_APPLY_INPUT_KEYS if job.action == "provider_keyed_initial_apply" else
               _APPEND_APPLY_INPUT_KEYS if job.action == "provider_keyed_edge_append_apply" else
               _MIXED_INITIAL_APPLY_INPUT_KEYS if job.action == "provider_keyed_mixed_initial_apply_child" else
               _MIXED_APPEND_APPLY_INPUT_KEYS if job.action in _MIXED_APPEND_APPLY_ACTIONS else
               _MIXED_INTERRUPTED_DESTROY_INPUT_KEYS if job.action == "provider_keyed_mixed_interrupted_destroy_apply" else
               _MIXED_PUBLISHED_DESTROY_INPUT_KEYS if job.action == "provider_keyed_mixed_published_destroy_apply" else
               _MIXED_INITIAL_HOST_WORKER_INPUT_KEYS if job.action == "provider_keyed_mixed_initial_host_worker" else
               _MIXED_INITIAL_STRICT_PROOF_INPUT_KEYS if job.action == "provider_keyed_mixed_initial_strict_host_proof" else
               _MIXED_LINODE_DIAGNOSTIC_INPUT_KEYS if job.action in {
                   "provider_keyed_mixed_linode_diagnostic",
                   "provider_keyed_mixed_linode_raw_diagnostic"} else
               _MIXED_INTERRUPTED_PLAN_WORKER_INPUT_KEYS if job.action == "provider_keyed_mixed_interrupted_plan_worker" else
               _MIXED_INTERRUPTED_SELECTOR_INPUT_KEYS if job.action == "provider_keyed_mixed_interrupted_selector_retirement" else
               _MIXED_PUBLISHED_SELECTOR_INPUT_KEYS if job.action == "provider_keyed_mixed_published_selector_retirement" else
               None)
    if allowed is None or not isinstance(inputs, dict):
        return None
    base = {key: value for key, value in inputs.items() if key not in _APPLY_CLAIM_KEYS | {"claimHeartbeatAt"}}
    if (job.status != "running"
            or not job.started_at or job.finished_at is not None
            or job.target_type != "engagement" or job.target_id != base.get("engagementId")
            or job.target != f"engagement:{job.target_id}"
            or set(base) != allowed
            or base.get("mutation") is not (
                False if job.action in {"provider_keyed_mixed_initial_strict_host_proof",
                                        "provider_keyed_mixed_linode_diagnostic",
                                        "provider_keyed_mixed_linode_raw_diagnostic",
                                        "provider_keyed_mixed_interrupted_plan_worker"} else True)
            or (job.action == "provider_keyed_mixed_interrupted_selector_retirement"
                and (base.get("schema") != "mixed-interrupted-selector-retirement-v1"
                     or any(type(base.get(key)) is not str
                            or re.fullmatch(r"[0-9a-f]{64}", base[key]) is None
                            for key in ("reviewSha256", "planSetSha256", "doScopeSha256",
                                        "credentialSecretSha256", "ociAbsenceJournalSha256",
                                        "inspectorNegativeJournalSha256"))))
            or (job.action == "provider_keyed_mixed_published_selector_retirement"
                and (base.get("schema") != "mixed-published-selector-retirement-v1"
                     or any(type(base.get(key)) is not str
                            or re.fullmatch(r"[0-9a-f]{64}", base[key]) is None
                            for key in ("reviewSha256", "planSetSha256", "doScopeSha256",
                                        "credentialSecretSha256", "ociAbsenceJournalSha256",
                                        "inspectorNegativeJournalSha256", "doAbsenceReceiptSha256",
                                        "publishedParentJournalSha256"))))
            or any(type(base[key]) is not str or not base[key] for key in
                   (("engagementId", "coreJobId", "corePlanId", "mixedParentId", "sealJournalSha256",
                     "provider", "chainId", "receiptSha256")
                    if job.action == "provider_keyed_mixed_initial_apply_child" else
                    ("engagementId", "coreJobId", "corePlanId", "appendParentId",
                     "reviewSha256", "provider")
                    if job.action in _MIXED_APPEND_APPLY_ACTIONS else
                    ("engagementId", "coreJobId", "corePlanId", "cleanupParentId",
                     "cleanupJournalSha256", "sourceSha256", "planSetSha256", "provider",
                     "scopeSha256", "beforeStateSha256", "planPath", "planSha256",
                     "showSha256", "terraformPath", "terraformSha256")
                    if job.action == "provider_keyed_mixed_interrupted_destroy_apply" else
                    ("engagementId", "coreJobId", "corePlanId", "cleanupParentId",
                     "cleanupJournalSha256", "planSetSha256", "provider",
                     "scopeSha256", "beforeStateSha256", "planPath", "planSha256",
                     "showSha256")
                    if job.action == "provider_keyed_mixed_published_destroy_apply" else
                    ("engagementId", "coreJobId", "corePlanId", "mixedParentId",
                     "handoffJournalSha256", "bindingJobId", "bindingManifestSha256")
                    if job.action == "provider_keyed_mixed_initial_host_worker" else
                    ("engagementId", "coreJobId", "corePlanId", "mixedParentId",
                     "handoffJournalSha256", "bindingJobId", "bindingManifestSha256",
                     "bootstrapJobId", "bootstrapJournalSha256")
                    if job.action in {"provider_keyed_mixed_initial_strict_host_proof",
                                       "provider_keyed_mixed_linode_diagnostic",
                                       "provider_keyed_mixed_linode_raw_diagnostic"} else
                    ("engagementId", "coreJobId", "corePlanId", "cleanupParentId", "reviewSha256")
                    if job.action == "provider_keyed_mixed_interrupted_plan_worker" else
                    ("engagementId", "coreJobId", "corePlanId", "teardownParentId",
                     "reviewSha256", "planSetSha256", "doScopeSha256", "selectorTag",
                     "providerConnectionId", "credentialSecretSha256", "credentialUpdatedAt",
                     "ociAbsenceJobId", "ociAbsenceJournalSha256",
                     "inspectorNegativeJobId", "inspectorNegativeJournalSha256")
                    if job.action == "provider_keyed_mixed_interrupted_selector_retirement" else
                    ("engagementId", "coreJobId", "corePlanId", "teardownParentId",
                     "reviewSha256", "planSetSha256", "doScopeSha256", "selectorTag",
                     "providerConnectionId", "credentialSecretSha256", "credentialUpdatedAt",
                     "ociAbsenceJobId", "ociAbsenceJournalSha256",
                     "inspectorNegativeJobId", "inspectorNegativeJournalSha256",
                     "doAbsenceReceiptSha256", "publishedParentJournalSha256")
                    if job.action == "provider_keyed_mixed_published_selector_retirement" else
                    ("engagementId", "coreJobId", "corePlanId", "planJobId")))
            or (job.action == "provider_keyed_mixed_initial_apply_child"
                and (type(base.get("providerIndex")) is not int
                     or base["providerIndex"] not in (0, 1)
                     or base["provider"] not in {"linode", "digitalocean"}))
            or (job.action in _MIXED_APPEND_APPLY_ACTIONS
                and (type(base.get("providerIndex")) is not int
                     or base["providerIndex"] != (
                         0 if job.action == "provider_keyed_mixed_append_apply_child" else 1)
                     or base["provider"] not in {"linode", "digitalocean"}
                     or re.fullmatch(r"[0-9a-f]{64}", base["reviewSha256"]) is None))
            or (job.action == "provider_keyed_mixed_interrupted_destroy_apply"
                and (type(base.get("providerIndex")) is not int
                     or base["providerIndex"] not in (0, 1)
                     or base["provider"] not in {"linode", "digitalocean"}))
            or (job.action == "provider_keyed_mixed_published_destroy_apply"
                and (type(base.get("providerIndex")) is not int
                     or base["providerIndex"] not in (0, 1)
                     or base["provider"] not in {"linode", "digitalocean"}
                     or (base["providerIndex"] == 0 and
                         base["priorAbsenceReceiptSha256"] is not None)
                     or (base["providerIndex"] == 1 and
                         (type(base["priorAbsenceReceiptSha256"]) is not str
                          or re.fullmatch(r"[0-9a-f]{64}",
                                          base["priorAbsenceReceiptSha256"]) is None))))
            or (job.action == "provider_keyed_edge_append_apply"
                and (type(base.get("parentJobId")) is not str or not base["parentJobId"]))
            or set(inputs) not in (allowed | _APPLY_CLAIM_KEYS,
                                   allowed | _APPLY_CLAIM_KEYS | {"claimHeartbeatAt"})
            or inputs.get("claimOwner") != owner or inputs.get("claimToken") != token
            or any(type(inputs.get(key)) is not str or not inputs[key] for key in
                   ("claimOwner", "claimToken", "claimClaimedAt", "claimExpiresAt"))
            or ("claimHeartbeatAt" in inputs and
                (type(inputs["claimHeartbeatAt"]) is not str or not inputs["claimHeartbeatAt"]))):
        return None
    return base


def _mixed_append_host_lease_condition(job: StoredJobRun, owner: str, token: str):
    from sqlalchemy import text
    return text("""EXISTS (
        SELECT 1 FROM job_runs AS parent JOIN core_mutation_leases AS lease
          ON lease.engagement_id = parent.target_id
         AND lease.owner_id = json_extract(parent.input, '$.corePlanId')
         AND lease.operation = 'provider_keyed_mixed_append'
        WHERE parent.id = :host_parent_id AND parent.action = 'provider_keyed_mixed_append'
          AND parent.status = 'running' AND parent.finished_at IS NULL
          AND parent.target = job_runs.target AND parent.target_type = 'engagement'
          AND parent.target_id = job_runs.target_id AND parent.requested_by = job_runs.requested_by
          AND json_extract(parent.input, '$.phase') = 'apply_sealed'
          AND json_extract(parent.input, '$.claimOwner') = :host_owner
          AND json_extract(parent.input, '$.claimToken') = :host_token
          AND julianday(json_extract(parent.input, '$.claimExpiresAt')) > julianday('now')
    )""").bindparams(host_parent_id=job.input["parentJobId"], host_owner=owner, host_token=token)


def _claimed_destroy_preview_base(job: StoredJobRun, owner: str, token: str) -> dict[str, Any] | None:
    """Validate the exact nonsecret destroy-preview claim generation."""
    inputs = job.input
    if not isinstance(inputs, dict):
        return None
    base = {key: value for key, value in inputs.items()
            if key not in _APPLY_CLAIM_KEYS | {"claimHeartbeatAt"}}
    if (job.action != "provider_keyed_initial_destroy_plan" or job.status != "running"
            or not job.started_at or job.finished_at is not None
            or set(base) != _DESTROY_PLAN_INPUT_KEYS
            or any(type(base.get(key)) is not str or not base[key]
                   or base[key] != base[key].strip()
                   for key in ("engagementId", "coreJobId", "corePlanId", "teardownParentId"))
            or any(type(base.get(key)) is not str
                   or re.fullmatch(r"[0-9a-f]{64}", base[key]) is None
                   for key in ("scopeSnapshotId", "providerScopeSha256"))
            or base.get("mutation") is not True
            or job.target_type != "engagement" or job.target_id != base["engagementId"]
            or job.target != f"engagement:{job.target_id}"
            or job.artifact_refs != []
            or set(inputs) not in (_DESTROY_PLAN_INPUT_KEYS | _APPLY_CLAIM_KEYS,
                                   _DESTROY_PLAN_INPUT_KEYS | _APPLY_CLAIM_KEYS | {"claimHeartbeatAt"})
            or inputs.get("claimOwner") != owner or inputs.get("claimToken") != token
            or any(type(inputs.get(key)) is not str or not inputs[key]
                   for key in ("claimOwner", "claimToken", "claimClaimedAt", "claimExpiresAt"))
            or ("claimHeartbeatAt" in inputs and
                (type(inputs["claimHeartbeatAt"]) is not str or not inputs["claimHeartbeatAt"]))):
        return None
    return base


def _claimed_destroy_apply_base(job: StoredJobRun, owner: str, token: str) -> dict[str, Any] | None:
    """Require one exact reviewed destroy-plan reference and claim generation."""
    inputs = job.input
    if not isinstance(inputs, dict):
        return None
    base = {key: value for key, value in inputs.items()
            if key not in _APPLY_CLAIM_KEYS | {"claimHeartbeatAt"}}
    if (job.action != "provider_keyed_initial_destroy_apply" or job.status != "running"
            or not job.started_at or job.finished_at is not None
            or set(base) != _DESTROY_APPLY_INPUT_KEYS
            or any(type(base.get(key)) is not str or not base[key]
                   or base[key] != base[key].strip()
                   for key in ("engagementId", "coreJobId", "corePlanId", "teardownParentId",
                               "destroyPlanJobId"))
            or any(type(base.get(key)) is not str
                   or re.fullmatch(r"[0-9a-f]{64}", base[key]) is None
                   for key in ("scopeSnapshotId", "providerScopeSha256", "planSha256"))
            or base.get("mutation") is not True
            or job.target_type != "engagement" or job.target_id != base["engagementId"]
            or job.target != f"engagement:{job.target_id}" or job.artifact_refs != []
            or set(inputs) not in (_DESTROY_APPLY_INPUT_KEYS | _APPLY_CLAIM_KEYS,
                                   _DESTROY_APPLY_INPUT_KEYS | _APPLY_CLAIM_KEYS | {"claimHeartbeatAt"})
            or inputs.get("claimOwner") != owner or inputs.get("claimToken") != token
            or any(type(inputs.get(key)) is not str or not inputs[key]
                   for key in ("claimOwner", "claimToken", "claimClaimedAt", "claimExpiresAt"))
            or ("claimHeartbeatAt" in inputs and
                (type(inputs["claimHeartbeatAt"]) is not str or not inputs["claimHeartbeatAt"]))):
        return None
    return base


def _claimed_core_destroy_apply_base(job: StoredJobRun, owner: str, token: str) -> dict[str, Any] | None:
    """Validate the private OCI core destroy child's exact claimed input."""
    inputs = job.input
    if type(inputs) is not dict:
        return None
    base = {key: value for key, value in inputs.items()
            if key not in _APPLY_CLAIM_KEYS | {"claimHeartbeatAt"}}
    mixed = job.action == "provider_keyed_mixed_zero_apply_core_destroy_apply"
    expected = (_MIXED_CORE_DESTROY_APPLY_INPUT_KEYS if mixed
                else _CORE_DESTROY_APPLY_INPUT_KEYS)
    if (job.action not in {"provider_keyed_core_destroy_apply",
                           "provider_keyed_mixed_zero_apply_core_destroy_apply"}
            or job.status != "running"
            or job.started_at is None or job.finished_at is not None
            or job.artifact_refs != [] or job.target_type != "engagement"
            or job.target != f"engagement:{job.target_id}"
            or set(base) != expected
            or base.get("mutation") is not True
            or any(type(base.get(key)) is not str or not base[key]
                   or base[key] != base[key].strip()
                   for key in ("teardownParentId", "coreJobId", "corePlanId", "previewJobId"))
            or any(type(base.get(key)) is not str
                   or re.fullmatch(r"[0-9a-f]{64}", base[key]) is None
                   for key in (("sourceSha256", "previewJournalSha256", "planSha256") if mixed
                               else ("scopeSnapshotId", "coordinatorJournalSha256",
                                     "previewJournalSha256", "planSha256")))
            or set(inputs) not in (expected | _APPLY_CLAIM_KEYS,
                                   expected | _APPLY_CLAIM_KEYS | {"claimHeartbeatAt"})
            or inputs.get("claimOwner") != owner or inputs.get("claimToken") != token
            or type(owner) is not str or not owner.startswith(
                "provider-keyed-mixed-core-destroy-" if mixed else "provider-keyed-core-destroy-")
            or type(token) is not str or len(token) < 16
            or any(type(inputs.get(key)) is not str or not inputs[key]
                   for key in ("claimClaimedAt", "claimExpiresAt"))
            or ("claimHeartbeatAt" in inputs and
                (type(inputs["claimHeartbeatAt"]) is not str or not inputs["claimHeartbeatAt"]))):
        return None
    return base


def _claimed_selector_retirement_base(job: StoredJobRun, owner: str, token: str) -> dict[str, Any] | None:
    inputs = job.input
    if type(inputs) is not dict:
        return None
    base = {key: value for key, value in inputs.items()
            if key not in _APPLY_CLAIM_KEYS | {"claimHeartbeatAt"}}
    keys = set(base)
    if keys not in (_SELECTOR_RETIRE_INPUT_KEYS, _SELECTOR_RETIRE_PUBLISHED_INPUT_KEYS):
        return None
    published = keys == _SELECTOR_RETIRE_PUBLISHED_INPUT_KEYS
    if (job.action != "provider_keyed_selector_retirement" or job.status != "running"
            or job.started_at is None or job.finished_at is not None
            or job.artifact_refs != [] or job.target_type != "engagement"
            or job.target_id != base.get("engagementId")
            or job.target != f"engagement:{job.target_id}"
            or base.get("mutation") is not True
            or any(type(base.get(key)) is not str or not base[key]
                   for key in ("engagementId", "coreJobId", "corePlanId", "teardownParentId",
                               "selectorTag", "providerConnectionId", "credentialUpdatedAt",
                               "initialApplyJobId", "coreAbsenceJobId"))
            or any(type(base.get(key)) is not str
                   or re.fullmatch(r"[0-9a-f]{64}", base[key]) is None
                   for key in ("scopeSnapshotId", "providerScopeSha256",
                               "credentialSecretSha256", "initialApplyJournalSha256",
                               "coreAbsenceJournalSha256"))
            or (published and (
                base.get("inspectorNegativeJobId") !=
                f"job-provider-keyed-inspector-negative-{base['coreJobId'].removeprefix('job-')}"
                or type(base.get("inspectorNegativeJournalSha256")) is not str
                or re.fullmatch(r"[0-9a-f]{64}", base["inspectorNegativeJournalSha256"]) is None))
            or set(inputs) not in (keys | _APPLY_CLAIM_KEYS,
                                   keys | _APPLY_CLAIM_KEYS | {"claimHeartbeatAt"})
            or inputs.get("claimOwner") != owner or inputs.get("claimToken") != token
            or type(owner) is not str or not owner.startswith("provider-keyed-selector-retire-")
            or type(token) is not str or len(token) < 16
            or any(type(inputs.get(key)) is not str or not inputs[key]
                   for key in ("claimClaimedAt", "claimExpiresAt"))):
        return None
    return base


def _valid_selector_retirement_event(job: StoredJobRun, event: JobEvent, *, terminal: bool) -> bool:
    base = job.input
    if (event.sequence != len(job.events) + 1 or event.level != "info"
            or type(event.data) is not dict):
        return False
    extra = ({"inspectorNegativeJobId": base["inspectorNegativeJobId"],
              "inspectorNegativeJournalSha256": base["inspectorNegativeJournalSha256"]}
             if "inspectorNegativeJobId" in base else {})
    if not terminal:
        return (event.message == "selector DELETE intended"
                and len(job.events) == 2
                and [item.message for item in job.events] == [
                    "selector retirement queued", "selector retirement started"]
                and event.data == {
                    "selectorTag": base["selectorTag"],
                    "scopeSnapshotId": base["scopeSnapshotId"],
                    "initialApplyJournalSha256": base["initialApplyJournalSha256"],
                    "coreAbsenceJournalSha256": base["coreAbsenceJournalSha256"],
                    **extra,
                })
    if (len(job.events) != 3
            or [item.message for item in job.events] != [
                "selector retirement queued", "selector retirement started",
                "selector DELETE intended"]
            or job.events[-1].data != {
                "selectorTag": base["selectorTag"],
                "scopeSnapshotId": base["scopeSnapshotId"],
                "initialApplyJournalSha256": base["initialApplyJournalSha256"],
                "coreAbsenceJournalSha256": base["coreAbsenceJournalSha256"],
                **extra,
            }):
        return False
    return ((event.message == "selector DELETE 204 received"
             and event.data == {"httpStatus": 204, "selectorTag": base["selectorTag"]})
            or (event.message == "selector absence reconciled"
                and event.data == {"selectorTag": base["selectorTag"],
                                   "exactGetStatus": 404,
                                   "completeTagListAbsent": True}))


def _valid_mixed_interrupted_selector_event(
    job: StoredJobRun, event: JobEvent, *, terminal: bool,
) -> bool:
    base = job.input
    if (job.action != "provider_keyed_mixed_interrupted_selector_retirement"
            or event.sequence != len(job.events) + 1 or event.level != "info"
            or type(event.data) is not dict
            or len(job.events) != (3 if terminal else 2)
            or [(row.sequence, row.level, row.message, row.data)
                for row in job.events[:2]] != [
                    (1, "info", "mixed interrupted selector retirement queued", {}),
                    (2, "info", "mixed interrupted selector retirement started", {})]):
        return False
    intent = {
        "selectorTag": base["selectorTag"], "doScopeSha256": base["doScopeSha256"],
        "ociAbsenceJournalSha256": base["ociAbsenceJournalSha256"],
        "inspectorNegativeJournalSha256": base["inspectorNegativeJournalSha256"],
    }
    if not terminal:
        return (event.message == "mixed interrupted selector DELETE intended"
                and event.data == intent)
    if (job.events[2].message != "mixed interrupted selector DELETE intended"
            or job.events[2].data != intent):
        return False
    return ((event.message == "mixed interrupted selector DELETE 204 received"
             and event.data == {"selectorTag": base["selectorTag"], "httpStatus": 204})
            or (event.message == "mixed interrupted selector absence reconciled"
                and event.data == {"selectorTag": base["selectorTag"],
                                   "exactGetStatus": 404,
                                   "completeTagListAbsent": True}))


def _valid_mixed_published_selector_event(
    job: StoredJobRun, event: JobEvent, *, terminal: bool,
) -> bool:
    """Bound a published child to either one DELETE or an already absent tag."""
    base = job.input
    if (job.action != "provider_keyed_mixed_published_selector_retirement"
            or event.sequence != len(job.events) + 1 or event.level != "info"
            or type(event.data) is not dict or len(job.events) not in (
                (2, 3) if terminal else (2,))
            or job.events[:2] != [
                JobEvent(1, "info", "mixed published selector retirement queued", {}),
                JobEvent(2, "info", "mixed published selector retirement started", {})]):
        return False
    intent = {
        "selectorTag": base["selectorTag"],
        "doAbsenceReceiptSha256": base["doAbsenceReceiptSha256"],
        "ociAbsenceJournalSha256": base["ociAbsenceJournalSha256"],
        "inspectorNegativeJournalSha256": base["inspectorNegativeJournalSha256"],
    }
    if not terminal:
        return (event.message == "mixed published selector DELETE intended"
                and event.data == intent)
    if len(job.events) == 2:
        return (event.message == "mixed published selector already absent"
                and event.data == {"selectorTag": base["selectorTag"],
                                   "exactGetStatus": 404})
    if job.events[2] != JobEvent(
            3, "info", "mixed published selector DELETE intended", intent):
        return False
    return ((event.message == "mixed published selector DELETE 204 received"
             and event.data == {"selectorTag": base["selectorTag"], "httpStatus": 204})
            or (event.message == "mixed published selector absence reconciled"
                and event.data == {"selectorTag": base["selectorTag"],
                                   "exactGetStatus": 404}))


def _valid_keyed_inspector_intent(
    job: StoredJobRun, *, owner: str, token: str, expected_event_digest: str,
    heartbeat_at: str, expires_at: str, event: JobEvent,
    queued_data: dict | None = None,
) -> bool:
    inputs = job.input
    if not isinstance(inputs, dict):
        return False
    base = {key: value for key, value in inputs.items()
            if key not in _APPLY_CLAIM_KEYS | {"claimHeartbeatAt"}}
    data = event.data
    return (
        job.action == "provider_keyed_comprehensive_teardown"
        and job.status == "running" and job.finished_at is None
        and job.started_at is not None and job.artifact_refs == []
        and job.target_type == "engagement" and job.target == f"engagement:{job.target_id}"
        and set(base) == _INSPECTOR_COORDINATOR_INPUT_KEYS
        and base.get("engagementId") == job.target_id
        and base.get("phase") == "awaiting_inspector_preflight"
        and base.get("mutation") is True
        and all(type(base.get(key)) is str and bool(base[key]) and base[key] == base[key].strip()
                for key in ("coreJobId", "corePlanId", "teardownParentId"))
        and all(type(base.get(key)) is str and re.fullmatch(r"[0-9a-f]{64}", base[key])
                for key in ("scopeSnapshotId", "providerScopeSha256"))
        and set(inputs) in (_INSPECTOR_COORDINATOR_INPUT_KEYS | _APPLY_CLAIM_KEYS,
                            _INSPECTOR_COORDINATOR_INPUT_KEYS | _APPLY_CLAIM_KEYS | {"claimHeartbeatAt"})
        and owner == _INSPECTOR_CLAIM_OWNER
        and inputs.get("claimOwner") == owner and inputs.get("claimToken") == token
        and type(token) is str and len(token) >= 16
        and _valid_claimed_apply_times(job, at=heartbeat_at, next_expiry=expires_at)
        and [item.sequence for item in job.events] == list(range(1, len(job.events) + 1))
        and len(job.events) == 4
        and [item.message for item in job.events] == [
            "keyed teardown coordinator queued", "keyed teardown coordinator started",
            "keyed teardown handoff intended",
            "keyed teardown handoff verified; Inspector preflight pending",
        ]
        and all(item.level == "info" for item in job.events)
        and [item.data for item in job.events] == [
            (queued_data if queued_data is not None else {"snapshotId": base["scopeSnapshotId"]}), {}, {}, {"corePlanId": base["corePlanId"]},
        ]
        and type(expected_event_digest) is str
        and job_event_digest(job.events) == expected_event_digest
        and event.sequence == 5 and event.level == "info"
        and event.message == "inspector_create_started"
        and type(data) is dict and set(data) == _INSPECTOR_INTENT_KEYS
        and data["scopeSnapshotId"] == base["scopeSnapshotId"]
        and data["providerScopeSha256"] == base["providerScopeSha256"]
        and type(data["provider"]) is str and data["provider"] in {"linode", "digitalocean"}
        and all(type(data[key]) is str
                and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", data[key]) is not None
                for key in ("region", "size", "credentialAlias"))
        and _utc_instant(data["credentialUpdatedAt"]) is not None
        and type(data["credentialId"]) is str and bool(data["credentialId"])
        and type(data["credentialSha256"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", data["credentialSha256"]) is not None
        and type(data["resourceName"]) is str
        and re.fullmatch(r"inspector-[0-9a-f]{32}", data["resourceName"]) is not None
        and type(data["keyFingerprintSha256"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", data["keyFingerprintSha256"]) is not None
        and data["claimGenerationSha256"] == inspector_claim_generation_digest(
            token=token, claimed_at=inputs["claimClaimedAt"])
        and valid_inspector_management_source_cidr(data["managementSourceCidr"])
    )


def _valid_inspector_stage_prefix(
    job: StoredJobRun, *, owner: str, token: str,
    expected_event_digest: str, heartbeat_at: str, expires_at: str,
    event: JobEvent,
    queued_data: dict | None = None,
) -> bool:
    """Validate the whole finite mutation journal, including cross-stage IDs."""
    inputs = job.input
    if type(inputs) is not dict:
        return False
    base = {key: value for key, value in inputs.items()
            if key not in _APPLY_CLAIM_KEYS | {"claimHeartbeatAt"}}
    events = job.events
    if (job.action != "provider_keyed_comprehensive_teardown"
            or job.status != "running" or job.finished_at is not None
            or job.started_at is None or job.artifact_refs != []
            or job.target_type != "engagement" or job.target != f"engagement:{job.target_id}"
            or set(base) != _INSPECTOR_COORDINATOR_INPUT_KEYS
            or base.get("engagementId") != job.target_id
            or base.get("phase") != "inspector_create_started"
            or base.get("mutation") is not True
            or any(type(base.get(key)) is not str or not base[key] or base[key] != base[key].strip()
                   for key in ("coreJobId", "corePlanId", "teardownParentId"))
            or any(type(base.get(key)) is not str or re.fullmatch(r"[0-9a-f]{64}", base[key]) is None
                   for key in ("scopeSnapshotId", "providerScopeSha256"))
            or set(inputs) not in (_INSPECTOR_COORDINATOR_INPUT_KEYS | _APPLY_CLAIM_KEYS,
                                   _INSPECTOR_COORDINATOR_INPUT_KEYS | _APPLY_CLAIM_KEYS | {"claimHeartbeatAt"})
            or owner != _INSPECTOR_CLAIM_OWNER or inputs.get("claimOwner") != owner
            or type(token) is not str or len(token) < 16 or inputs.get("claimToken") != token
            or not _valid_claimed_apply_times(job, at=heartbeat_at, next_expiry=expires_at)
            or len(events) < 5 or len(events) > 12
            or [item.sequence for item in events] != list(range(1, len(events) + 1))
            or [item.message for item in events[:5]] != [
                "keyed teardown coordinator queued", "keyed teardown coordinator started",
                "keyed teardown handoff intended",
                "keyed teardown handoff verified; Inspector preflight pending",
                "inspector_create_started",
            ]
            or [item.data for item in events[:4]] != [
                (queued_data if queued_data is not None else {"snapshotId": base["scopeSnapshotId"]}), {}, {},
                {"corePlanId": base["corePlanId"]},
            ]
            or any(item.level != "info" for item in events)
            or type(expected_event_digest) is not str
            or job_event_digest(events) != expected_event_digest
            or event.sequence != len(events) + 1 or event.level != "info"
            or event.message != "inspector_create_stage"):
        return False
    intent = events[4].data
    if (type(intent) is not dict or set(intent) != _INSPECTOR_INTENT_KEYS
            or intent["scopeSnapshotId"] != base["scopeSnapshotId"]
            or intent["providerScopeSha256"] != base["providerScopeSha256"]
            or type(intent["provider"]) is not str
            or intent["provider"] not in {"linode", "digitalocean"}
            or type(intent["resourceName"]) is not str
            or re.fullmatch(r"inspector-[0-9a-f]{32}", intent["resourceName"]) is None
            or type(intent["keyFingerprintSha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", intent["keyFingerprintSha256"]) is None
            or intent["claimGenerationSha256"] != inspector_claim_generation_digest(
                token=token, claimed_at=inputs["claimClaimedAt"])
            or not valid_inspector_management_source_cidr(intent["managementSourceCidr"])
            or any(type(intent[key]) is not str
                   or re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", intent[key]) is None
                   for key in ("region", "size", "credentialAlias"))
            or _utc_instant(intent["credentialUpdatedAt"]) is None):
        return False
    provider = intent["provider"]
    name = intent["resourceName"]
    stages = ("firewall", "instance") if provider == "linode" else (
        "tag", "firewall", "droplet", "attachment")
    if len(events) - 5 >= len(stages) * 2:
        return False
    tag = "bi-" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:20] if provider == "digitalocean" else ""
    firewall_id = ""
    droplet_id = ""
    for index, item in enumerate([*events[5:], event]):
        stage = stages[index // 2]
        point = "before_post" if index % 2 == 0 else "response_received"
        data = item.data
        if (item.sequence != index + 6 or item.level != "info"
                or item.message != "inspector_create_stage"
                or type(data) is not dict or set(data) != _INSPECTOR_STAGE_KEYS):
            return False
        resource_id = ""
        if point == "response_received" and stage in {"firewall", "instance", "droplet"}:
            resource_id = data["resourceId"]
            if (type(resource_id) is not str
                    or (re.fullmatch(r"[1-9][0-9]*", resource_id) is None
                        and not (provider == "digitalocean" and stage == "firewall"
                                 and len(resource_id) <= 128
                                 and re.fullmatch(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+", resource_id)))):
                return False
        expected_firewall = firewall_id
        expected_droplet = droplet_id
        if point == "response_received" and stage == "firewall":
            expected_firewall = resource_id if provider == "digitalocean" else ""
        if point == "response_received" and stage == "droplet":
            expected_droplet = resource_id
        expected = {
            "provider": provider, "resourceName": name, "stage": stage, "point": point,
            "resourceId": resource_id, "firewallId": expected_firewall,
            "dropletId": expected_droplet, "tagName": tag, "tagExclusive": False,
        }
        if provider == "linode":
            expected["firewallId"] = firewall_id if stage == "instance" else ""
            expected["dropletId"] = ""
        if data != expected:
            return False
        if point == "response_received" and stage == "firewall":
            firewall_id = resource_id
        if point == "response_received" and stage == "droplet":
            droplet_id = resource_id
    return True


def _valid_completed_inspector_submission_heartbeat(
    job: StoredJobRun, *, owner: str, token: str, claimed_at: str,
    expected_event_digest: str, heartbeat_at: str, expires_at: str,
    queued_data: dict | None = None,
) -> bool:
    """The last stage must close the exact finite journal, not merely be present."""
    if (type(job.input) is not dict
            or job.input.get("claimClaimedAt") != claimed_at
            or job.input.get("claimOwner") != owner
            or job.input.get("claimToken") != token
            or owner != _INSPECTOR_CLAIM_OWNER
            or type(expected_event_digest) is not str
            or job_event_digest(job.events) != expected_event_digest
            or not _valid_claimed_apply_times(job, at=heartbeat_at, next_expiry=expires_at)
            or len(job.events) < 6):
        return False
    provider = job.events[4].data.get("provider") if type(job.events[4].data) is dict else None
    if len(job.events) != (9 if provider == "linode" else 13 if provider == "digitalocean" else -1):
        return False
    prior = replace(job, events=job.events[:-1])
    prior_heartbeat = job.input.get("claimHeartbeatAt", claimed_at)
    return _valid_inspector_stage_prefix(
        prior, owner=owner, token=token,
        expected_event_digest=job_event_digest(prior.events),
        heartbeat_at=prior_heartbeat, expires_at=job.input["claimExpiresAt"],
        event=job.events[-1], queued_data=queued_data,
    )


def _valid_keyed_inspector_prepare_heartbeat(
    job: StoredJobRun, *, owner: str, token: str, claimed_at: str,
    expected_event_digest: str, heartbeat_at: str, expires_at: str,
    queued_data: dict | None = None,
) -> bool:
    """Validate the whole original-claim journal through prepare intent."""
    if (type(job.input) is not dict or job.input.get("phase") != "inspector_prepare_started"
            or owner != _INSPECTOR_CLAIM_OWNER or job.input.get("claimOwner") != owner
            or job.input.get("claimToken") != token
            or job.input.get("claimClaimedAt") != claimed_at
            or job.action != "provider_keyed_comprehensive_teardown"
            or job.status != "running" or job.finished_at is not None
            or job.started_at is None or job.artifact_refs != []
            or job.target_type != "engagement" or job.target != f"engagement:{job.target_id}"
            or job.input.get("engagementId") != job.target_id
            or job.input.get("mutation") is not True
            or set(job.input) not in (
                _INSPECTOR_COORDINATOR_INPUT_KEYS | _APPLY_CLAIM_KEYS,
                _INSPECTOR_COORDINATOR_INPUT_KEYS | _APPLY_CLAIM_KEYS | {"claimHeartbeatAt"},
            )
            or not _valid_claimed_apply_times(job, at=heartbeat_at, next_expiry=expires_at)
            or _utc_instant(expires_at) - _utc_instant(heartbeat_at) > timedelta(minutes=5)
            or type(expected_event_digest) is not str
            or job_event_digest(job.events) != expected_event_digest
            or [event.sequence for event in job.events] != list(range(1, len(job.events) + 1))
            or any(event.level != "info" for event in job.events)
            or len(job.events) not in (11, 15)):
        return False
    events = job.events
    intent = events[4].data
    if type(intent) is not dict or intent.get("claimGenerationSha256") != inspector_claim_generation_digest(
            token=token, claimed_at=claimed_at):
        return False
    provider = intent.get("provider")
    if len(events) != (11 if provider == "linode" else 15 if provider == "digitalocean" else -1):
        return False
    submitted = replace(job, input={**job.input, "phase": "inspector_create_started"},
                        events=events[:-2])
    if not _valid_completed_inspector_submission_heartbeat(
        submitted, owner=owner, token=token, claimed_at=claimed_at,
        expected_event_digest=job_event_digest(submitted.events),
        heartbeat_at=heartbeat_at, expires_at=expires_at, queued_data=queued_data,
    ):
        return False
    stages = submitted.events[5:]
    firewall_id = stages[1 if provider == "linode" else 3].data["resourceId"]
    host_id = stages[3 if provider == "linode" else 5].data["resourceId"]
    link = events[-2]
    prepare = events[-1]
    public_ip = link.data.get("publicIp") if type(link.data) is dict else None
    try:
        address = ipaddress.ip_address(public_ip)
        valid_ip = (address.version == 4 and address.is_global and not address.is_private
                    and not address.is_reserved and not address.is_multicast
                    and not address.is_loopback and not address.is_link_local
                    and not address.is_unspecified and str(address) == public_ip)
    except (ValueError, TypeError):
        valid_ip = False
    if not valid_ip or type(link.data.get("proofSha256")) is not str:
        return False
    expected_link = {
        "stageJournalSha256": job_event_digest(submitted.events),
        "proofSha256": link.data["proofSha256"],
        "hostRecordId": f"{provider}:inspector:{host_id}",
        "firewallRecordId": f"{provider}:inspector-firewall:{firewall_id}",
        "hostId": host_id, "firewallId": firewall_id, "provider": provider,
        "publicIp": public_ip, "scopeSnapshotId": job.input["scopeSnapshotId"],
        "cleanupRequired": True,
    }
    expected_prepare = {
        "scopeSnapshotId": job.input["scopeSnapshotId"],
        "providerScopeSha256": job.input["providerScopeSha256"],
        "sourceJournalSha256": job_event_digest(events[:-1]),
        "provider": provider,
        "hostRecordId": expected_link["hostRecordId"],
        "firewallRecordId": expected_link["firewallRecordId"],
        "hostId": host_id, "firewallId": firewall_id, "publicIp": public_ip,
        "keyFingerprintSha256": intent["keyFingerprintSha256"],
    }
    return (link.message == "inspector_owned_unprepared"
            and type(link.data) is dict and link.data == expected_link
            and re.fullmatch(r"[0-9a-f]{64}", link.data["proofSha256"]) is not None
            and prepare.message == "inspector_prepare_started"
            and type(prepare.data) is dict and prepare.data == expected_prepare)


def _valid_destroy_apply_finish(
    job: StoredJobRun, *, expected_event_digest: str,
    status: str, finished_at: str, event: JobEvent,
) -> bool:
    started = _stored_utc_instant(job.started_at)
    finished = _utc_instant(finished_at)
    return (status in {"succeeded", "failed"} and started is not None
            and finished is not None and finished > started
            and isinstance(expected_event_digest, str)
            and re.fullmatch(r"[0-9a-f]{64}", expected_event_digest) is not None
            and [item.sequence for item in job.events] == list(range(1, len(job.events) + 1))
            and job_event_digest(job.events) == expected_event_digest
            and event.sequence == len(job.events) + 1
            and ((status == "succeeded" and event.level == "info"
                  and isinstance(event.data, dict)
                  and set(event.data) == {"stateSha256", "providerAbsenceProofPending"}
                  and type(event.data["stateSha256"]) is str
                  and re.fullmatch(r"[0-9a-f]{64}", event.data["stateSha256"]) is not None
                  and event.data["providerAbsenceProofPending"] is True)
                 or (status == "failed" and event.level == "error" and event.data == {})))


def _valid_core_destroy_apply_finish(
    job: StoredJobRun, *, expected_event_digest: str, status: str,
    finished_at: str, event: JobEvent,
) -> bool:
    started = _stored_utc_instant(job.started_at)
    finished = _utc_instant(finished_at)
    return (status == "succeeded" and started is not None and finished is not None
            and finished > started and job_event_digest(job.events) == expected_event_digest
            and [item.sequence for item in job.events] == list(range(1, len(job.events) + 1))
            and event.sequence == len(job.events) + 1 and event.level == "info"
            and event.message == "core destroy applied; provider absence pending"
            and type(event.data) is dict
            and set(event.data) == {"providerAbsenceProofPending", "preDestroyResourceIdsSha256"}
            and event.data["providerAbsenceProofPending"] is True
            and type(event.data["preDestroyResourceIdsSha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", event.data["preDestroyResourceIdsSha256"]) is not None)


def _destroy_preview_claim_unexpired_at_write(job: StoredJobRun) -> bool:
    """Use the real clock under the writer transaction, not a supplied event time."""
    expiry = _utc_instant(job.input.get("claimExpiresAt"))
    return expiry is not None and datetime.now(timezone.utc) < expiry


def _claimed_apply_journal_matches(rows: list[Any], job: StoredJobRun, expected_digest: str) -> bool:
    events = [JobEvent(int(row[0]), row[1], row[2],
                       json.loads(row[3]) if isinstance(row[3], str) else row[3]) for row in rows]
    return (len(events) == len(job.events)
            and [event.sequence for event in events] == list(range(1, len(events) + 1))
            and job_event_digest(events) == expected_digest == job_event_digest(job.events))


def _valid_core_destroy_show_triple(events: list[JobEvent], offset: int) -> bool:
    """Require one complete successful read-only show journal, never an apply intent."""
    intent, started, result = events[offset:offset + 3]
    if ([event.message for event in (intent, started, result)] != [
            "core destroy command intent fenced",
            "core destroy command started before GO",
            "core destroy command result fenced"]
            or any(event.level != "info" for event in (intent, started, result))):
        return False
    a, b, c = intent.data, started.data, result.data
    return (
        type(a) is dict and set(a) == {"phase", "invocationId", "argvSha256"}
        and a["phase"] == "show" and type(a["invocationId"]) is str
        and bool(a["invocationId"]) and type(a["argvSha256"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", a["argvSha256"]) is not None
        and type(b) is dict and set(b) == {
            "phase", "invocationId", "bootId", "pid", "pgid", "startTicks"}
        and b["phase"] == "show" and b["invocationId"] == a["invocationId"]
        and type(b["bootId"]) is str and bool(b["bootId"])
        and all(type(b[key]) is int and b[key] > 0 for key in ("pid", "pgid", "startTicks"))
        and b["pid"] == b["pgid"]
        and type(c) is dict and set(c) == {
            "phase", "invocationId", "returnCode", "stdoutBytes", "stderrBytes",
            "stdoutTruncated", "stderrTruncated"}
        and c["phase"] == "show" and c["invocationId"] == a["invocationId"]
        and type(c["returnCode"]) is int and c["returnCode"] == 0
        and type(c["stdoutBytes"]) is int and c["stdoutBytes"] > 0
        and type(c["stderrBytes"]) is int and c["stderrBytes"] >= 0
        and c["stdoutTruncated"] is False and c["stderrTruncated"] is False
    )


def _valid_core_destroy_pre_go_takeover(
    job: StoredJobRun, *, expected_event_digest: str,
    owner: str, token: str, claimed_at: str, expires_at: str,
) -> bool:
    old_owner, old_token = job.input.get("claimOwner"), job.input.get("claimToken")
    old_expiry = _utc_instant(job.input.get("claimExpiresAt"))
    claimed, expiry = _utc_instant(claimed_at), _utc_instant(expires_at)
    events = job.events
    return (
        type(old_owner) is str and type(old_token) is str
        and _claimed_core_destroy_apply_base(job, old_owner, old_token) is not None
        and job_event_digest(events) == expected_event_digest
        and len(events) in (5, 8)
        and [event.sequence for event in events] == list(range(1, len(events) + 1))
        and events[:2] == [
            JobEvent(1, "info", "core destroy apply queued", {}),
            JobEvent(2, "info", "core destroy apply started", {}),
        ]
        and _valid_core_destroy_show_triple(events, 2)
        and (len(events) == 5 or (
            _valid_core_destroy_show_triple(events, 5)
            and events[5].data["argvSha256"] == events[2].data["argvSha256"]
            and events[5].data["invocationId"] != events[2].data["invocationId"]))
        and old_expiry is not None and claimed is not None and expiry is not None
        and old_expiry < datetime.now(timezone.utc)
        and old_expiry <= claimed <= datetime.now(timezone.utc) < expiry
        and type(owner) is str and owner.startswith("provider-keyed-core-destroy-")
        and type(token) is str and len(token) >= 16
        and (owner, token) != (old_owner, old_token)
    )


def _valid_mixed_core_show_takeover(
    job: StoredJobRun, *, expected_event_digest: str,
    owner: str, token: str, claimed_at: str, expires_at: str,
) -> bool:
    """CAS only an expired pre-GO mixed SHOW start or successful result."""
    old_owner, old_token = job.input.get("claimOwner"), job.input.get("claimToken")
    old_expiry = _utc_instant(job.input.get("claimExpiresAt"))
    claimed, expiry = _utc_instant(claimed_at), _utc_instant(expires_at)
    events = job.events
    return (
        type(old_owner) is str and type(old_token) is str
        and _claimed_core_destroy_apply_base(job, old_owner, old_token) is not None
        and job.action == "provider_keyed_mixed_zero_apply_core_destroy_apply"
        and len(events) in (4, 5)
        and [(row.sequence, row.level, row.message) for row in events[:4]] == [
            (1, "info", "mixed core destroy apply queued"),
            (2, "info", "mixed core destroy apply started"),
            (3, "info", "core destroy command intent fenced"),
            (4, "info", "core destroy command started before GO"),
        ]
        and events[0].data == {} and events[1].data == {}
        and type(events[2].data) is dict
        and set(events[2].data) == {"phase", "invocationId", "argvSha256"}
        and events[2].data["phase"] == "show"
        and type(events[2].data["invocationId"]) is str
        and bool(events[2].data["invocationId"])
        and type(events[2].data["argvSha256"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", events[2].data["argvSha256"]) is not None
        and type(events[3].data) is dict
        and set(events[3].data) == {
            "phase", "invocationId", "bootId", "pid", "pgid", "startTicks"}
        and events[3].data["phase"] == "show"
        and events[3].data["invocationId"] == events[2].data["invocationId"]
        and type(events[3].data["bootId"]) is str and bool(events[3].data["bootId"])
        and all(type(events[3].data[key]) is int and events[3].data[key] > 0
                for key in ("pid", "pgid", "startTicks"))
        and events[3].data["pid"] == events[3].data["pgid"]
        and (len(events) == 4 or (
            events[4].sequence == 5
            and _valid_core_destroy_show_triple(events, 2)))
        and job_event_digest(events) == expected_event_digest
        and old_expiry is not None and claimed is not None and expiry is not None
        and old_expiry < datetime.now(timezone.utc)
        and old_expiry <= claimed <= datetime.now(timezone.utc) < expiry
        and type(owner) is str and owner.startswith("provider-keyed-mixed-core-destroy-")
        and type(token) is str and len(token) >= 16
        and (owner, token) != (old_owner, old_token)
    )


def _mixed_core_no_go_attempts(events: list[JobEvent]) -> tuple[dict, ...]:
    """Authenticate the append-only chain of Apply starts before any GO.

    Every later attempt is preceded by a marker binding the complete prior
    journal. A GO or result is never a recoverable prefix.
    """
    if (len(events) < 8 or (len(events) - 8) % 3
            or [row.sequence for row in events] != list(range(1, len(events) + 1))
            or [(row.level, row.message) for row in events[:8]] != [
                ("info", "mixed core destroy apply queued"),
                ("info", "mixed core destroy apply started"),
                ("info", "core destroy command intent fenced"),
                ("info", "core destroy command started before GO"),
                ("info", "core destroy command result fenced"),
                ("info", "core destroy prestate identity fenced"),
                ("info", "core destroy command intent fenced"),
                ("info", "core destroy command started before GO")]
            or events[0].data != {} or events[1].data != {}
            or not _valid_core_destroy_show_triple(events, 2)):
        raise ValueError("mixed core pre-GO Apply prefix differs")

    def intent(row: JobEvent, phase: str) -> dict:
        data = row.data
        if (type(data) is not dict
                or set(data) != {"phase", "invocationId", "argvSha256"}
                or data["phase"] != phase
                or type(data["invocationId"]) is not str
                or not data["invocationId"]
                or type(data["argvSha256"]) is not str
                or re.fullmatch(r"[0-9a-f]{64}", data["argvSha256"]) is None):
            raise ValueError("mixed core pre-GO intent differs")
        return data

    def start(row: JobEvent, invocation: str, phase: str) -> dict:
        data = row.data
        if (type(data) is not dict
                or set(data) != {"phase", "invocationId", "bootId", "pid", "pgid", "startTicks"}
                or data["phase"] != phase or data["invocationId"] != invocation
                or type(data["bootId"]) is not str or not data["bootId"]
                or any(type(data[key]) is not int or data[key] <= 0
                       for key in ("pid", "pgid", "startTicks"))
                or data["pid"] != data["pgid"]):
            raise ValueError("mixed core pre-GO process identity differs")
        return data

    original = intent(events[6], "apply")
    identities = [start(events[7], original["invocationId"], "apply")]
    invocations = {original["invocationId"]}
    for index in range(8, len(events), 3):
        marker, retry_intent, retry_start = events[index:index + 3]
        if ([(row.level, row.message) for row in (marker, retry_intent, retry_start)]
                != [("info", "mixed core pre-GO Apply recovery claimed"),
                    ("info", "core destroy command intent fenced"),
                    ("info", "core destroy command started before GO")]
                or marker.data != {
                    "originalJournalSha256": job_event_digest(events[:index]),
                    "originalInvocationId": events[index - 2].data["invocationId"],
                }):
            raise ValueError("mixed core pre-GO recovery marker differs")
        retry = intent(retry_intent, "apply")
        if (retry["argvSha256"] != original["argvSha256"]
                or retry["invocationId"] in invocations):
            raise ValueError("mixed core pre-GO retry command differs")
        invocations.add(retry["invocationId"])
        identities.append(start(retry_start, retry["invocationId"], "apply"))
    return tuple(identities)


def _valid_mixed_core_apply_no_go_takeover(
    job: StoredJobRun, *, expected_event_digest: str,
    owner: str, token: str, claimed_at: str, expires_at: str,
) -> bool:
    """Claim only the one exact expired mixed Apply start without GO evidence.

    The service validates the saved plan, prestate and recorded process group;
    this predicate only makes the journal/claim transition atomic.
    """
    inputs, events = job.input, job.events
    old_owner, old_token = inputs.get("claimOwner"), inputs.get("claimToken")
    old_expiry = _utc_instant(inputs.get("claimExpiresAt"))
    claimed, expiry = _utc_instant(claimed_at), _utc_instant(expires_at)
    try:
        _mixed_core_no_go_attempts(events)
    except (ValueError, KeyError, TypeError):
        return False
    return (
        type(old_owner) is str and type(old_token) is str
        and _claimed_core_destroy_apply_base(job, old_owner, old_token) is not None
        and job.action == "provider_keyed_mixed_zero_apply_core_destroy_apply"
        and job_event_digest(events) == expected_event_digest
        and old_expiry is not None and claimed is not None and expiry is not None
        and old_expiry < datetime.now(timezone.utc)
        and old_expiry <= claimed <= datetime.now(timezone.utc) < expiry
        and type(owner) is str and owner.startswith("provider-keyed-mixed-core-destroy-")
        and type(token) is str and len(token) >= 16
        and (owner, token) != (old_owner, old_token)
    )


def _valid_initial_destroy_pre_go_takeover(
    job: StoredJobRun, *, expected_event_digest: str,
    owner: str, token: str, claimed_at: str, expires_at: str,
) -> bool:
    """Only the exact interrupted nine-event DO child may change claim owner.

    This is a journal/lease CAS, not authority to execute Terraform. The
    recovery caller must independently prove the saved plan, state, provider
    inventory, source and the historical pre-GO abort before any command.
    """
    inputs, events = job.input, job.events
    old_owner, old_token = inputs.get("claimOwner"), inputs.get("claimToken")
    old_expiry = _utc_instant(inputs.get("claimExpiresAt"))
    claimed, expiry = _utc_instant(claimed_at), _utc_instant(expires_at)
    if not (
        type(old_owner) is str and type(old_token) is str
        and _claimed_destroy_apply_base(job, old_owner, old_token) is not None
        and len(events) == 9
        and [event.sequence for event in events] == list(range(1, 10))
        and job_event_digest(events) == expected_event_digest
        and events[:2] == [
            JobEvent(1, "info", "provider destroy apply queued", {}),
            JobEvent(2, "info", "provider destroy apply started", {}),
        ]
        and old_expiry is not None and claimed is not None and expiry is not None
        and old_expiry < datetime.now(timezone.utc)
        and old_expiry <= claimed <= datetime.now(timezone.utc) < expiry
        and type(owner) is str and owner.startswith("provider-keyed-destroy-recovery-")
        and type(token) is str and len(token) >= 16
        and (owner, token) != (old_owner, old_token)
    ):
        return False
    if [(event.level, event.message) for event in events[2:]] != [
        ("info", "provider destroy command intent fenced"),
        ("info", "provider destroy command started before GO"),
        ("info", "provider destroy command result fenced"),
        ("info", "provider destroy prestate identity fenced"),
        ("info", "provider destroy phase write intended"),
        ("info", "provider destroy command intent fenced"),
        ("info", "provider destroy command started before GO"),
    ]:
        return False
    show_intent, show_start, show_result = (event.data for event in events[2:5])
    prestate, phase, apply_intent, apply_start = (event.data for event in events[5:9])
    pre_keys = {
        "coreJobId", "corePlanId", "scopeSnapshotId", "providerScopeSha256",
        "preDestroyStateSha256", "stateLineage", "preDestroySerial",
        "resourceIds", "resourceIdsSha256", "selectorTag", "credentialRecordId",
        "credentialSecretSha256", "credentialUpdatedAt", "dnsCleanupManifestSha256",
        "dnsCleanupHandoffJournalSha256", "dnsCleanupCheckpointSha256",
    }
    if (any(type(row) is not dict for row in (
            show_intent, show_start, show_result, prestate, phase,
            apply_intent, apply_start))
            or set(prestate) != pre_keys
            or any(prestate[key] != inputs[key] for key in (
                "coreJobId", "corePlanId", "scopeSnapshotId", "providerScopeSha256"))
            or type(prestate["resourceIds"]) is not dict
            or len(prestate["resourceIds"]) != 8
            or set(prestate["resourceIds"]) != {
                "digitalocean_ssh_key.key", "digitalocean_firewall.firewall",
                "local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]",
            } | {address for address in prestate["resourceIds"]
                 if re.fullmatch(r'digitalocean_droplet\.(?:middle|edge)\["[A-Za-z0-9._-]+"\]', address)}
            or sum(address.startswith("digitalocean_droplet.middle[")
                   for address in prestate["resourceIds"]) != 2
            or sum(address.startswith("digitalocean_droplet.edge[")
                   for address in prestate["resourceIds"]) != 2
            or prestate["resourceIdsSha256"] != hashlib.sha256(json.dumps(
                prestate["resourceIds"], sort_keys=True, separators=(",", ":")
            ).encode()).hexdigest()
            or type(prestate["preDestroySerial"]) is not int
            or prestate["preDestroySerial"] < 1
            or any(type(prestate[key]) is not str or not prestate[key] for key in (
                "stateLineage", "selectorTag", "credentialRecordId", "credentialUpdatedAt"))
            or any(type(prestate[key]) is not str or
                   re.fullmatch(r"[0-9a-f]{64}", prestate[key]) is None for key in (
                "preDestroyStateSha256", "resourceIdsSha256", "credentialSecretSha256",
                "dnsCleanupHandoffJournalSha256",
                "dnsCleanupCheckpointSha256"))
            or type(prestate["dnsCleanupManifestSha256"]) is not str
            or re.fullmatch(r"sha256:[0-9a-f]{64}", prestate["dnsCleanupManifestSha256"]) is None
            or phase != {"phase": "destroy_started", "path": phase.get("path")}
            or type(phase.get("path")) is not str
            or not Path(phase["path"]).is_absolute()
            or Path(phase["path"]).name != ".barragan-apply-phase.json"):
        return False
    for name, intent, started in (("show", show_intent, show_start),
                                  ("apply", apply_intent, apply_start)):
        if (set(intent) != {"phase", "invocationId", "argvSha256"}
                or intent["phase"] != name
                or type(intent["invocationId"]) is not str or not intent["invocationId"]
                or type(intent["argvSha256"]) is not str
                or re.fullmatch(r"[0-9a-f]{64}", intent["argvSha256"]) is None
                or set(started) != {"phase", "invocationId", "bootId", "pid", "pgid", "startTicks"}
                or started["phase"] != name
                or started["invocationId"] != intent["invocationId"]
                or type(started["bootId"]) is not str or not started["bootId"]
                or any(type(started[key]) is not int or started[key] <= 0
                       for key in ("pid", "pgid", "startTicks"))
                or started["pid"] != started["pgid"]):
            return False
    return (
        show_intent["invocationId"] != apply_intent["invocationId"]
        and set(show_result) == {"phase", "invocationId", "returnCode", "stdoutBytes",
                                 "stderrBytes", "stdoutTruncated", "stderrTruncated"}
        and show_result["phase"] == "show"
        and show_result["invocationId"] == show_intent["invocationId"]
        and type(show_result["returnCode"]) is int and show_result["returnCode"] == 0
        and type(show_result["stdoutBytes"]) is int and show_result["stdoutBytes"] > 0
        and type(show_result["stderrBytes"]) is int and show_result["stderrBytes"] >= 0
        and show_result["stdoutTruncated"] is False
        and show_result["stderrTruncated"] is False
    )


def _valid_keyed_destroy_finish(
    job: StoredJobRun, *, expected_event_digest: str, status: str,
    finished_at: str, event: JobEvent, artifact_ref: str | None,
) -> bool:
    started = _stored_utc_instant(job.started_at)
    finished = _utc_instant(finished_at)
    return (
        job.action == "provider_keyed_initial_destroy_plan"
        and job.status == "running" and job.finished_at is None
        and isinstance(job.input, dict) and set(job.input) == _DESTROY_PLAN_INPUT_KEYS
        and all(type(job.input[key]) is str and bool(job.input[key])
                and job.input[key] == job.input[key].strip()
                for key in ("engagementId", "coreJobId", "corePlanId", "teardownParentId"))
        and all(type(job.input[key]) is str
                and re.fullmatch(r"[0-9a-f]{64}", job.input[key]) is not None
                for key in ("scopeSnapshotId", "providerScopeSha256"))
        and job.input["mutation"] is True
        and job.target_type == "engagement"
        and job.target_id == job.input.get("engagementId")
        and job.target == f"engagement:{job.target_id}"
        and job.artifact_refs == []
        and isinstance(expected_event_digest, str)
        and re.fullmatch(r"[0-9a-f]{64}", expected_event_digest) is not None
        and [entry.sequence for entry in job.events] == list(range(1, len(job.events) + 1))
        and job_event_digest(job.events) == expected_event_digest
        and status in {"succeeded", "failed"}
        and started is not None and finished is not None and finished > started
        and event.sequence == len(job.events) + 1
        and ((status == "succeeded" and type(artifact_ref) is str
              and Path(artifact_ref).is_absolute() and "\x00" not in artifact_ref
              and ".." not in Path(artifact_ref).parts)
             or (status == "failed" and artifact_ref is None))
    )


def _claimed_apply_input_predicate(inputs: dict[str, Any]) -> tuple[str, tuple[Any, ...]]:
    """Compare the exact flat JSON input independent of json_set key ordering."""
    keys = sorted(inputs)
    predicate = "(SELECT COUNT(*) FROM json_each(input)) = ?"
    parameters: list[Any] = [len(keys)]
    for key in keys:
        value = inputs[key]
        predicate += f" AND json_type(input, '$.{key}') = ?"
        kind = ("null" if value is None else "true" if value is True else
                "false" if value is False else "integer" if type(value) is int else "text")
        parameters.append(kind)
        if value is not None:
            predicate += f" AND json_extract(input, '$.{key}') = ?"
            parameters.append(int(value) if type(value) is bool else value)
    return predicate, tuple(parameters)


def _sqlalchemy_apply_input_conditions(model: Any, inputs: dict[str, Any]) -> list[Any]:
    from sqlalchemy import func, text

    conditions = [text("(SELECT COUNT(*) FROM json_each(job_runs.input)) = :input_count")
                  .bindparams(input_count=len(inputs))]
    for key, value in sorted(inputs.items()):
        kind = ("null" if value is None else "true" if value is True else
                "false" if value is False else "integer" if type(value) is int else "text")
        conditions.append(func.json_type(model.input, f"$.{key}") == kind)
        if value is not None:
            conditions.append(func.json_extract(model.input, f"$.{key}") == (
                int(value) if type(value) is bool else value))
    return conditions


def handoff_claim_digest(*, owner: str, token: str, claimed_at: str, expires_at: str) -> str:
    """Seal the exact handoff claim generation without recording its token."""
    claim = {"owner": owner, "token": token,
             "claimedAt": claimed_at, "expiresAt": expires_at}
    return hashlib.sha256(json.dumps(claim, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _handoff_arguments_valid(
    *, old_owner: str, old_token: str, new_owner: str, new_token: str,
    claimed_at: str, expires_at: str, expected_event_count: int,
    expected_event_digest: str, expected_final_message: str,
    confirmed_scope_sha256: str,
) -> bool:
    return (
        all(isinstance(value, str) and value and value.strip() == value for value in
            (old_owner, old_token, new_owner, new_token, claimed_at, expires_at))
        and (old_owner, old_token) != (new_owner, new_token)
        and isinstance(expected_event_count, int) and expected_event_count > 0
        and isinstance(expected_event_digest, str)
        and re.fullmatch(r"[0-9a-f]{64}", expected_event_digest) is not None
        and isinstance(confirmed_scope_sha256, str)
        and re.fullmatch(r"[0-9a-f]{64}", confirmed_scope_sha256) is not None
        and expected_final_message == _BOOTSTRAP_FINAL_MESSAGE
    )


def _handoff_journal_matches(
    rows: list[Any], *, expected_event_count: int, expected_event_digest: str,
    expected_final_message: str,
) -> bool:
    events = [JobEvent(int(row[0]), row[1], row[2], json.loads(row[3])) for row in rows]
    return (
        len(events) == expected_event_count
        and [event.sequence for event in events] == list(range(1, expected_event_count + 1))
        and events[-1].message == expected_final_message
        and job_event_digest(events) == expected_event_digest
    )


@dataclass(frozen=True)
class StoredJobRun:
    id: str
    action: str
    status: str
    target: str
    target_type: str
    target_id: str
    requested_by: str
    input: dict[str, Any]
    artifact_refs: list[str]
    created_at: str
    started_at: str | None
    finished_at: str | None
    events: list[JobEvent]

    def to_summary(self) -> JobRunSummary:
        return JobRunSummary(
            id=self.id,
            action=self.action,
            status=self.status,
            target=self.target,
            created_at=self.created_at,
        )

    def to_detail(self) -> JobRunDetail:
        return JobRunDetail(
            id=self.id,
            action=self.action,
            status=self.status,
            target_type=self.target_type,
            target_id=self.target_id,
            requested_by=self.requested_by,
            input=self.input,
            artifact_refs=self.artifact_refs,
            events=self.events,
        )


@dataclass(frozen=True)
class SemanticJobBatch:
    jobs_by_engagement: dict[str, list[StoredJobRun]]
    total_job_count: int
    seed_job_exists: bool


@dataclass(frozen=True)
class DashboardSemanticJobBatch:
    jobs_by_engagement: dict[str, list[StoredJobRun]]
    total_job_count: int
    seed_job_exists: bool


class JobRepository(Protocol):
    def list(self) -> list[StoredJobRun]:
        ...

    def list_for_engagement(self, engagement_id: str, *, limit: int | None = None) -> list[StoredJobRun]:
        ...

    def list_channel_mutations_for_engagement(self, engagement_id: str) -> list[StoredJobRun]:
        ...

    def list_semantic_for_engagement(self, engagement_id: str, *, recent_limit: int = 250) -> list[StoredJobRun]:
        ...

    def list_semantic_for_engagements(
        self,
        engagement_ids: list[str],
        *,
        recent_limit: int = 250,
    ) -> SemanticJobBatch:
        ...

    def list_dashboard_semantic_for_engagements(
        self,
        engagement_ids: list[str],
        *,
        recent_limit: int = 250,
    ) -> DashboardSemanticJobBatch:
        ...

    def list_summaries(self, *, limit: int, offset: int) -> tuple[list[JobRunSummary], int]:
        ...

    def count(self) -> int:
        ...

    def get(self, job_id: str) -> StoredJobRun | None:
        ...

    def save(self, job: StoredJobRun) -> StoredJobRun:
        ...

    def save_if_absent(self, job: StoredJobRun) -> StoredJobRun:
        ...

    def insert_inspector_teardown_barrier(self, job: StoredJobRun) -> StoredJobRun | None:
        ...

    def start_if_queued(self, job: StoredJobRun, *, started_at: str, event: JobEvent) -> StoredJobRun | None:
        ...

    def finish_if_running(
        self, job: StoredJobRun, *, status: str, finished_at: str, event: JobEvent,
    ) -> StoredJobRun | None:
        ...

    def finish_if_running_with_journal_digest(
        self, job: StoredJobRun, *, expected_event_digest: str,
        status: str, finished_at: str, event: JobEvent,
        artifact_ref: str | None = None,
    ) -> StoredJobRun | None:
        ...

    def append_event_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        ...

    def finish_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, status: str, finished_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        ...

    def append_destroy_preview_event_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        ...

    def finish_destroy_preview_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, status: str, finished_at: str,
        event: JobEvent, artifact_ref: str | None = None,
    ) -> StoredJobRun | None:
        ...

    def append_destroy_apply_event_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        ...

    def append_core_destroy_apply_event_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        ...

    def append_selector_retirement_event_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        ...

    def finish_selector_retirement_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, finished_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        ...

    def finish_core_destroy_apply_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, status: str, finished_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        ...

    def take_over_mixed_core_show(
        self, job: StoredJobRun, *, expected_event_digest: str,
        owner: str, token: str, claimed_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        ...

    def take_over_mixed_core_apply_no_go(
        self, job: StoredJobRun, *, expected_event_digest: str,
        owner: str, token: str, claimed_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        ...

    def take_over_core_destroy_apply_pre_go(
        self, job: StoredJobRun, *, expected_event_digest: str,
        owner: str, token: str, claimed_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        ...

    def take_over_initial_destroy_apply_pre_go(
        self, job: StoredJobRun, *, expected_event_digest: str,
        owner: str, token: str, claimed_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        ...

    def append_keyed_inspector_create_intent_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        ...

    def append_keyed_inspector_stage_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        ...

    def heartbeat_keyed_inspector_submission_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str, claimed_at: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        ...

    def heartbeat_keyed_inspector_preparation_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str, claimed_at: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        ...

    def transition_retained_inspector_if_running(
        self, job: StoredJobRun, *, mode: str, expected_event_digest: str,
        owner: str, token: str, at: str, expires_at: str,
        event: JobEvent | None = None, authority: Callable[[], None] | None = None,
    ) -> StoredJobRun | None:
        ...

    def finish_destroy_apply_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, status: str, finished_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        ...

    def claim_lease(
        self,
        job_id: str,
        *,
        owner: str,
        token: str,
        claimed_at: str,
        expires_at: str,
        eligible_statuses: set[str],
        eligible_phases: set[str] | None = None,
    ) -> StoredJobRun | None:
        ...

    def renew_lease(
        self,
        job_id: str,
        *,
        owner: str,
        token: str,
        heartbeat_at: str,
        expires_at: str,
    ) -> StoredJobRun | None:
        ...

    def save_if_leased(
        self,
        job: StoredJobRun,
        *,
        owner: str,
        token: str,
    ) -> StoredJobRun | None:
        ...

    def append_mixed_plan_phase_if_claimed(
        self, job: StoredJobRun, *, owner: str, token: str, lease_owner: str,
        expected_event_digest: str, next_phase: str, event: JobEvent,
    ) -> StoredJobRun | None:
        ...

    def append_mixed_initial_handoff_if_claimed(
        self, job: StoredJobRun, *, owner: str, token: str, lease_owner: str,
        expected_event_digest: str, event: JobEvent,
    ) -> StoredJobRun | None:
        ...

    def fence_terminal_provider_bootstrap_handoff(
        self, job_id: str, *, old_owner: str, old_token: str,
        new_owner: str, new_token: str, claimed_at: str, expires_at: str,
        expected_event_count: int, expected_event_digest: str,
        expected_final_message: str, confirmed_scope_sha256: str,
    ) -> StoredJobRun | None:
        ...

    def mark_stale_nonterminal_attention(
        self,
        job_id: str,
        *,
        expected_status: str,
        event: JobEvent,
    ) -> bool:
        ...

    def list_by_actions_and_statuses(
        self,
        *,
        actions: set[str],
        statuses: set[str],
        limit: int,
        stale_before: str | None = None,
        lease_expired_before: str | None = None,
    ) -> list[StoredJobRun]:
        ...


class SqlAlchemyJobRepository:
    def rearm_exact_show_only_destroy_apply(
        self, failed: StoredJobRun, *, authority: Callable[[], bool],
        owner: str, token: str, claimed_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        """Append-only CAS for one settled show-only DevTest Apply failure."""
        from sqlalchemy import text

        from app.services.provider_keyed_initial_destroy_apply_job import (
            _SHOW_ONLY_APPLY_RECOVERY,
        )
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        claimed = _utc_instant(claimed_at)
        expires = _utc_instant(expires_at)
        if (db.engine.dialect.name != "sqlite" or not callable(authority)
                or type(owner) is not str
                or not owner.startswith("provider-keyed-destroy-apply-")
                or type(token) is not str or len(token) < 16
                or claimed is None or expires is None
                or not claimed <= datetime.now(timezone.utc) < expires):
            return None
        try:
            db.session.rollback()
            touched = db.session.execute(text("""
                UPDATE job_runs SET status = status
                WHERE id = :id AND action = 'provider_keyed_initial_destroy_apply'
                  AND status = 'failed'
            """), {"id": failed.id})
            if touched.rowcount != 1:
                raise ValueError("failed show-only Apply changed")
            db.session.expire_all()
            current = self.get(failed.id)
            if current != failed or not authority() or self.get(failed.id) != failed:
                raise ValueError("show-only Apply authority changed")
            row = db.session.get(JobRunModel, failed.id)
            if row is None:
                raise ValueError("show-only Apply disappeared")
            row.status = "running"
            row.finished_at = None
            row.input = {key: value for key, value in failed.input.items()
                         if key not in {"claimOwner", "claimToken", "claimClaimedAt",
                                        "claimHeartbeatAt", "claimExpiresAt"}} | {
                             "claimOwner": owner, "claimToken": token,
                             "claimClaimedAt": claimed_at, "claimExpiresAt": expires_at,
                         }
            db.session.add(JobEventModel(
                job_id=failed.id, sequence=9, level="info", message=_SHOW_ONLY_APPLY_RECOVERY,
                data={"failedJournalSha256": job_event_digest(failed.events),
                      "failedFinishedAt": failed.finished_at},
            ))
            db.session.commit()
            return self.get(failed.id)
        except Exception:
            db.session.rollback()
            return None

    def rearm_exact_precommand_destroy_apply(
        self, failed: StoredJobRun, *, authority: Callable[[], bool],
        owner: str, token: str, claimed_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        """Atomically claim one expired, command-free published append Apply."""
        from sqlalchemy import text

        from app.services.provider_keyed_initial_destroy_apply_job import (
            _PRECOMMAND_APPLY_RECOVERY,
        )
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        claimed = _utc_instant(claimed_at)
        expires = _utc_instant(expires_at)
        if (db.engine.dialect.name != "sqlite" or not callable(authority)
                or type(owner) is not str
                or not owner.startswith("provider-keyed-destroy-apply-")
                or type(token) is not str or len(token) < 16
                or claimed is None or expires is None
                or not claimed <= datetime.now(timezone.utc) < expires):
            return None
        try:
            db.session.rollback()
            touched = db.session.execute(text("""
                UPDATE job_runs SET status = status
                WHERE id = :id AND action = 'provider_keyed_initial_destroy_apply'
                  AND status = 'failed'
            """), {"id": failed.id})
            if touched.rowcount != 1:
                raise ValueError("failed Apply changed")
            db.session.expire_all()
            current = self.get(failed.id)
            if current != failed or not authority() or self.get(failed.id) != failed:
                raise ValueError("pre-command Apply boundary changed")
            row = db.session.get(JobRunModel, failed.id)
            if row is None:
                raise ValueError("failed Apply disappeared")
            row.status = "running"
            row.finished_at = None
            row.input = {key: value for key, value in failed.input.items()
                         if key not in {"claimOwner", "claimToken", "claimClaimedAt",
                                        "claimHeartbeatAt", "claimExpiresAt"}} | {
                             "claimOwner": owner, "claimToken": token,
                             "claimClaimedAt": claimed_at, "claimExpiresAt": expires_at,
                         }
            db.session.add(JobEventModel(
                job_id=failed.id, sequence=4, level="info", message=_PRECOMMAND_APPLY_RECOVERY,
                data={"failedJournalSha256": job_event_digest(failed.events),
                      "failedFinishedAt": failed.finished_at},
            ))
            db.session.commit()
            return self.get(failed.id)
        except Exception:
            db.session.rollback()
            return None

    def rearm_exact_precommand_destroy_preview(
        self, failed: StoredJobRun, *, authority: Callable[[], bool],
        owner: str, token: str, claimed_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        """Append-only SQLite CAS for one expired, command-free preview failure."""
        from sqlalchemy import text

        from app.services.provider_keyed_initial_destroy_plan_job import (
            _PRECOMMAND_RECOVERY,
        )
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        claimed = _utc_instant(claimed_at)
        expires = _utc_instant(expires_at)
        if (db.engine.dialect.name != "sqlite" or not callable(authority)
                or type(owner) is not str
                or not owner.startswith("provider-keyed-destroy-preview-")
                or type(token) is not str or len(token) < 16
                or claimed is None or expires is None
                or not claimed <= datetime.now(timezone.utc) < expires):
            return None
        try:
            db.session.rollback()
            touched = db.session.execute(text("""
                UPDATE job_runs SET status = status
                WHERE id = :id AND action = 'provider_keyed_initial_destroy_plan'
                  AND status = 'failed'
            """), {"id": failed.id})
            if touched.rowcount != 1:
                raise ValueError("failed preview changed")
            db.session.expire_all()
            current = self.get(failed.id)
            if current != failed or not authority() or self.get(failed.id) != failed:
                raise ValueError("pre-command preview boundary changed")
            row = db.session.get(JobRunModel, failed.id)
            if row is None:
                raise ValueError("failed preview disappeared")
            row.status = "running"
            row.finished_at = None
            row.input = {key: value for key, value in failed.input.items()
                         if key not in {"claimOwner", "claimToken", "claimClaimedAt",
                                        "claimHeartbeatAt", "claimExpiresAt"}} | {
                             "claimOwner": owner, "claimToken": token,
                             "claimClaimedAt": claimed_at, "claimExpiresAt": expires_at,
                         }
            db.session.add(JobEventModel(
                job_id=failed.id, sequence=5, level="info", message=_PRECOMMAND_RECOVERY,
                data={"failedJournalSha256": job_event_digest(failed.events),
                      "failedFinishedAt": failed.finished_at},
            ))
            db.session.commit()
            return self.get(failed.id)
        except Exception:
            db.session.rollback()
            return None

    def rearm_sealed_provider_keyed_append_publication(
        self, parent: StoredJobRun, *, state_root: Path,
    ) -> StoredJobRun | None:
        """CAS a stopped, already proved append back to publication only.

        The no-op UPDATE takes SQLite's writer slot before re-reading every
        authority. No child journal, Terraform state, or chain row is changed.
        """
        from sqlalchemy import text

        from app.services.provider_keyed_append_publication_recovery import (
            _CLAIM_KEYS, _SEAL, _evidence,
        )
        from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel
        from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository

        if db.engine.dialect.name != "sqlite":
            return None
        try:
            db.session.rollback()
            touched = db.session.execute(text("""
                UPDATE job_runs SET status = status
                WHERE id = :id AND action = 'provider_keyed_edge_append'
                  AND status = 'failed'
            """), {"id": parent.id})
            if touched.rowcount != 1:
                raise ValueError("stopped append parent changed")
            db.session.expire_all()
            state, current = _evidence(
                parent.id, environment="devtest", state_root=state_root,
                jobs=self, chains=SqlAlchemySketchChainRepository(),
                lease_lookup=_db_lease_lookup,
            )
            if state != "ready" or current != parent:
                raise ValueError("sealed append publication changed")
            row = db.session.get(JobRunModel, parent.id)
            if row is None:
                raise ValueError("append parent disappeared")
            row.status = "running"
            row.finished_at = None
            row.input = {**{key: value for key, value in parent.input.items()
                            if key not in _CLAIM_KEYS}, "phase": "awaiting_publication"}
            seal = parent.events[-2]
            db.session.add(JobEventModel(
                job_id=parent.id, sequence=len(parent.events) + 1,
                level="info", message=_SEAL, data=seal.data,
            ))
            db.session.commit()
            return self.get(parent.id)
        except Exception:
            db.session.rollback()
            return None

    def reserve_mixed_zero_apply_cleanup_parent(
        self, job: StoredJobRun, *, reviewed_source, state_root, core_state_root,
    ) -> StoredJobRun:
        """Atomically fence an attested zero-Apply generation without provider I/O."""
        from dataclasses import asdict
        from sqlalchemy import text
        from app.services.engagement_teardown import _fingerprint
        from app.services.provider_keyed_mixed_zero_apply_teardown_source import (
            MixedZeroApplySource, audit_mixed_zero_apply_teardown_source,
        )
        from app.services.provider_keyed_mixed_zero_apply_cleanup import (
            ACTION, _PHASE, _parent_id,
        )
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel, JobEventModel, JobRunModel

        sealed = json.loads(json.dumps(asdict(reviewed_source), sort_keys=True)) if isinstance(
            reviewed_source, MixedZeroApplySource) else None
        digest = _fingerprint(sealed) if sealed is not None else None
        if (db.engine.dialect.name != "sqlite" or sealed is None
                or job.id != _parent_id(reviewed_source.core_job_id)
                or job.action != ACTION or job.status != "queued"
                or job.target != f"engagement:{reviewed_source.engagement_id}"
                or job.target_type != "engagement"
                or job.target_id != reviewed_source.engagement_id
                or job.started_at is not None or job.finished_at is not None
                or job.artifact_refs != [] or not job.requested_by
                or not isinstance(job.input, dict)
                or job.input != {
                    "schema": "mixed-zero-apply-cleanup-v1",
                    "engagementId": reviewed_source.engagement_id,
                    "coreJobId": reviewed_source.core_job_id,
                    "corePlanId": reviewed_source.core_plan_id,
                    "source": sealed, "sourceSha256": digest,
                    "phase": _PHASE, "mutation": True,
                }
                or job.events != [JobEvent(
                    1, "info", "mixed zero-Apply cleanup fenced",
                    {"sourceSha256": digest})]):
            raise MixedZeroApplyReservationConflict("mixed zero-Apply proposal differs")
        try:
            # Discard any pre-review read transaction; obtain SQLite's writer
            # slot before reading lease, jobs, or local source evidence.
            db.session.rollback()
            locked = db.session.execute(text("""
                UPDATE deployment_plans SET status = status
                WHERE id = :plan AND engagement_id = :engagement
                  AND status = 'applied' AND apply_job_id = :core
            """), {"plan": reviewed_source.core_plan_id,
                   "engagement": reviewed_source.engagement_id,
                   "core": reviewed_source.core_job_id})
            if locked.rowcount != 1:
                raise ValueError("reviewed applied core changed")
            db.session.expire_all()
            existing = self.get(job.id)
            lease = db.session.query(CoreMutationLeaseModel).filter_by(
                engagement_id=job.target_id).one_or_none()
            if existing is not None:
                if (lease is None or lease.owner_id != reviewed_source.core_plan_id
                        or lease.operation != "provider_keyed_teardown_fence"
                        or existing.id != job.id or existing.action != job.action
                        or existing.status != "queued" or existing.target != job.target
                        or existing.target_type != job.target_type
                        or existing.target_id != job.target_id
                        or existing.started_at is not None
                        or existing.finished_at is not None
                        or existing.input != job.input or existing.events != job.events
                        or existing.artifact_refs != []):
                    raise ValueError("mixed cleanup parent or fence differs")
                db.session.commit()
                return existing
            if (lease is None or lease.owner_id != reviewed_source.core_plan_id
                    or lease.operation != "provider_keyed_initial"):
                raise ValueError("initial mixed lease differs")
            if db.session.execute(text("""
                SELECT 1 FROM job_runs WHERE target_type = 'engagement'
                  AND target_id = :engagement AND status IN ('queued', 'running')
                  AND action IN ('inspector_inspection', 'inspector_readiness', 'inspector_cleanup')
                LIMIT 1
            """), {"engagement": job.target_id}).first() is not None:
                raise ValueError("Inspector operation is active")
            current = audit_mixed_zero_apply_teardown_source(
                reviewed_source.engagement_id, reviewed_source.core_job_id,
                environment="devtest", state_root=state_root,
                core_state_root=core_state_root,
                lease_owner=reviewed_source.core_plan_id, job_repository=self,
            )
            if current != reviewed_source:
                raise ValueError("mixed source changed before fence")
            db.session.add(JobRunModel(
                id=job.id, action=job.action, status=job.status, target=job.target,
                target_type=job.target_type, target_id=job.target_id,
                requested_by=job.requested_by, input=job.input, artifact_refs=[],
                created_at=_parse_datetime(job.created_at), started_at=None,
                finished_at=None,
            ))
            db.session.add(JobEventModel(
                job_id=job.id, sequence=1, level="info",
                message="mixed zero-Apply cleanup fenced",
                data={"sourceSha256": digest},
            ))
            db.session.flush()
            updated = db.session.execute(text("""
                UPDATE core_mutation_leases SET operation = 'provider_keyed_teardown_fence'
                WHERE engagement_id = :engagement AND owner_id = :plan
                  AND operation = 'provider_keyed_initial'
            """), {"engagement": job.target_id,
                   "plan": reviewed_source.core_plan_id})
            if updated.rowcount != 1:
                raise ValueError("mixed lease changed before fence")
            db.session.commit()
            return self.get(job.id)
        except Exception:
            db.session.rollback()
            raise MixedZeroApplyReservationConflict(
                "mixed zero-Apply fence requires fresh review or recovery") from None

    def reserve_published_mixed_initial_cleanup_parent(
        self, proposal: StoredJobRun, *, collection,
        expected_snapshot_id: str,
    ) -> StoredJobRun:
        """Atomically fence one reviewed, published four-host mixed generation.

        Provider GETs precede this SQLite writer transaction. Inside it we
        reread every durable source row and exact retained state bytes before
        inserting the parent and a new teardown lease together. No Terraform
        command or provider write runs while holding the writer slot.
        """
        from sqlalchemy import text

        from app.services.core_ssh import active_core_connection_details
        from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
        from app.services.provider_keyed_mixed_initial_apply_child import _child_id
        from app.services.provider_keyed_mixed_initial_bootstrap import _worker_id
        from app.services.provider_keyed_mixed_initial_host_binding import _binding_child_id
        from app.services.provider_keyed_mixed_initial_plan_parent import _parent_id
        from app.services.provider_keyed_mixed_interrupted_dispatch import _core_inspector_scope
        from app.services.provider_keyed_mixed_published_teardown_authority import (
            review_published_mixed_initial_teardown,
        )
        from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
            recognize_published_mixed_initial_checkpoint,
        )
        from app.services.provider_keyed_mixed_published_teardown_collector import (
            PublishedMixedTeardownCollection, _empty_owned_bindings,
            recheck_published_six_collection_local, recheck_failed_append_collection_local,
        )
        from app.services.provider_keyed_mixed_strict_host_receipt import child_id as proof_child_id
        from app.storage.database import db
        from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
        from app.storage.domain_repository import SqlAlchemyDomainRepository
        from app.storage.models import CoreMutationLeaseModel, JobEventModel, JobRunModel
        from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
        from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository

        if (db.engine.dialect.name != "sqlite"
                or type(collection) is not PublishedMixedTeardownCollection
                or type(expected_snapshot_id) is not str
                or expected_snapshot_id != proposal.input.get("reviewSnapshotId")):
            raise ValueError("published mixed reservation boundary differs")
        review = collection.review
        source = review.source
        scope = collection.core_inspector_scope
        engagement_name = proposal.input.get("engagementName")
        recognize_published_mixed_initial_checkpoint(
            proposal, review, scope, engagement_name)
        try:
            db.session.rollback()
            touched = db.session.execute(text("""
                UPDATE deployment_plans SET status = status
                WHERE id = :plan AND engagement_id = :engagement
                  AND status = 'applied' AND stage = 'applied'
                  AND apply_job_id = :core
            """), {"plan": source.core_plan_id,
                   "engagement": source.engagement_id,
                   "core": source.core_job_id})
            if touched.rowcount != 1:
                raise ValueError("published mixed applied core plan changed")
            db.session.expire_all()
            lease = db.session.query(CoreMutationLeaseModel).filter_by(
                engagement_id=source.engagement_id).one_or_none()
            existing = self.get(proposal.id)
            if existing is not None:
                if (lease is None or lease.owner_id != source.core_plan_id
                        or lease.operation != "provider_keyed_teardown_fence"):
                    raise ValueError("published mixed existing fence differs")
                recognize_published_mixed_initial_checkpoint(
                    existing, review, scope, engagement_name)
            elif lease is not None and not ((review.failed_append_recovery is not None or review.unpublished_six_recovery is not None)
                    and lease.owner_id == source.core_plan_id
                    and lease.operation == "provider_keyed_mixed_append"):
                raise ValueError("another core mutation lease exists")
            if review.failed_append_recovery is not None:
                recheck_failed_append_collection_local(
                    collection, jobs=self, allow_teardown_fence=existing is not None)
            elif collection.six_collection is not None:
                recheck_published_six_collection_local(
                    collection, jobs=self, allow_teardown_fence=existing is not None)
            else:
                initial = self.get(_parent_id(source.core_job_id))
                core = self.get(source.core_job_id)
                plan = SqlAlchemyDeploymentPlanRepository().get(source.core_plan_id)
                binding = self.get(_binding_child_id(source.core_job_id))
                bootstrap = self.get(_worker_id(source.core_job_id))
                proof = self.get(proof_child_id(source.core_job_id))
                order, ids = source.ordered_providers, source.chain_ids
                children = {provider: self.get(_child_id(source.core_job_id, provider))
                            for provider in order}
                sketches = SqlAlchemySketchChainRepository()
                durable_chains = sketches.list_for_engagement(source.engagement_id)
                from app.services.provider_keyed_runtime_preflight import reviewed_mixed_chain_rows
                chains = {row.chain_id: row for row in reviewed_mixed_chain_rows(
                    durable_chains, ids, source.engagement_id)}
                domains = SqlAlchemyDomainRepository()
                resources = SqlAlchemyProviderResourceRepository()
                if (initial is None or core is None or plan is None
                        or binding is None or bootstrap is None or proof is None
                        or any(child is None for child in children.values())
                        or set(chains) != set(ids)
                        or active_core_connection_details(self, source.engagement_id)[0]
                           != source.core_job_id
                        or _empty_owned_bindings(source.engagement_id, self, domains)
                           != {kind: () for kind in (
                               "channels", "domains", "certificates", "sites")}
                        or _core_inspector_scope(
                            core, jobs=self,
                            core_state_root=DEFAULT_TERRAFORM_STATE_ROOT,
                            plan_repository=SqlAlchemyDeploymentPlanRepository(),
                            provider_resource_repository=resources) != scope):
                    raise ValueError("published mixed durable source changed")
                for provider in order:
                    workspace = collection.workspaces[provider]
                    raw = collection.observations[provider].state_json
                    state_path = workspace / "terraform.tfstate"
                    if (not workspace.is_absolute() or workspace.is_symlink()
                            or not workspace.is_dir()
                            or workspace.resolve(strict=True) != workspace
                            or state_path.is_symlink() or state_path.read_bytes() != raw):
                        raise ValueError("published mixed retained state changed")
                current_review = review_published_mixed_initial_teardown(
                    parent=initial, core=core, plan=plan, binding=binding,
                    bootstrap=bootstrap, proof_child=proof,
                    apply_children=children, chains=chains,
                    observations=collection.observations,
                    workspaces=collection.workspaces,
                    live_bindings={kind: () for kind in (
                        "channels", "domains", "certificates", "sites")},
                    mutation_lease=None,
                )
                if current_review != review:
                    raise ValueError("published mixed reviewed generation changed")
            if db.session.execute(text("""
                SELECT 1 FROM job_runs WHERE target_type = 'engagement'
                  AND target_id = :engagement AND status IN ('queued', 'running')
                  AND action IN ('inspector_inspection', 'inspector_readiness',
                                 'inspector_cleanup') LIMIT 1
            """), {"engagement": source.engagement_id}).first() is not None:
                raise ValueError("Inspector operation is active")
            if existing is not None:
                db.session.commit()
                return existing
            db.session.add(JobRunModel(
                id=proposal.id, action=proposal.action, status=proposal.status,
                target=proposal.target, target_type=proposal.target_type,
                target_id=proposal.target_id, requested_by=proposal.requested_by,
                input=proposal.input, artifact_refs=[],
                created_at=_parse_datetime(proposal.created_at),
                started_at=None, finished_at=None,
            ))
            db.session.add(JobEventModel(
                job_id=proposal.id, sequence=1, level="info",
                message=proposal.events[0].message,
                data=proposal.events[0].data,
            ))
            if review.failed_append_recovery is not None or review.unpublished_six_recovery is not None:
                changed = db.session.query(CoreMutationLeaseModel).filter_by(
                    engagement_id=source.engagement_id, owner_id=source.core_plan_id,
                    operation="provider_keyed_mixed_append").update(
                        {"operation": "provider_keyed_teardown_fence"}, synchronize_session=False)
                if changed != 1:
                    raise ValueError("failed append lease changed before teardown")
            else:
                db.session.add(CoreMutationLeaseModel(
                    engagement_id=source.engagement_id,
                    owner_id=source.core_plan_id,
                    operation="provider_keyed_teardown_fence",
                ))
            db.session.commit()
            result = self.get(proposal.id)
            recognize_published_mixed_initial_checkpoint(
                result, review, scope, engagement_name)
            return result
        except Exception:
            db.session.rollback()
            raise ValueError(
                "published mixed teardown reservation requires exact review") from None

    def seal_published_mixed_initial_destroy_plans(
        self, parent: StoredJobRun, *, collection, plan_set,
        before_states: dict[str, bytes],
    ) -> StoredJobRun:
        """Prime pure checks and read-only commands before acquiring the writer."""
        from app.services.provider_keyed_host_proof_verdicts import host_proof_verdict_scope
        from app.services.provider_keyed_readonly_verification import readonly_verification_scope
        from app.services.provider_keyed_mixed_published_teardown_collector import (
            PublishedMixedTeardownCollection, recheck_failed_append_collection_local,
            recheck_published_six_collection_local,
        )
        from app.storage.database import db
        if db.engine.dialect.name != "sqlite" or type(collection) is not PublishedMixedTeardownCollection:
            raise ValueError("published mixed seal requires SQLite review")
        source = collection.review.source
        if (set(before_states) != set(source.ordered_providers)
                or any(type(before_states[provider]) is not bytes for provider in source.ordered_providers)):
            raise ValueError("published mixed retained state set differs")
        db.session.rollback()
        try:
            with host_proof_verdict_scope() as proofs, readonly_verification_scope() as commands:
                if collection.six_collection is not None or collection.review.failed_append_recovery is not None:
                    recheck = (recheck_failed_append_collection_local
                               if collection.review.failed_append_recovery is not None
                               else recheck_published_six_collection_local)
                    recheck(collection, jobs=self, allow_teardown_fence=True)
                proofs.require_hits_only()
                commands.require_hits_only()
                return self._seal_published_mixed_initial_destroy_plans(
                    parent, collection=collection, plan_set=plan_set, before_states=before_states)
        except Exception:
            db.session.rollback()
            raise

    def _seal_published_mixed_initial_destroy_plans(
        self, parent: StoredJobRun, *, collection, plan_set,
        before_states: dict[str, bytes],
    ) -> StoredJobRun:
        """Seal both already-attested plans; never run Terraform in the writer."""
        from sqlalchemy import text, update
        from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
            propose_published_mixed_plans_sealed,
            recognize_published_mixed_initial_checkpoint,
            recognize_published_mixed_plans_sealed,
        )
        from app.services.provider_keyed_mixed_published_teardown_collector import (
            PublishedMixedTeardownCollection, _empty_owned_bindings,
            recheck_published_six_collection_local, recheck_failed_append_collection_local,
        )
        from app.services.provider_keyed_mixed_interrupted_destroy_source import _binary_sha
        from app.services.provider_keyed_mixed_interrupted_dispatch import _core_inspector_scope
        from app.services.provider_keyed_mixed_initial_apply_child import _child_id
        from app.services.provider_keyed_mixed_initial_bootstrap import _worker_id
        from app.services.provider_keyed_mixed_initial_host_binding import _binding_child_id
        from app.services.provider_keyed_mixed_published_teardown_authority import (
            review_published_mixed_initial_teardown,
        )
        from app.services.provider_keyed_mixed_strict_host_receipt import child_id as proof_child_id
        from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
        from app.services.core_ssh import active_core_connection_details
        from app.storage.database import db
        from app.storage.domain_repository import SqlAlchemyDomainRepository
        from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
        from app.storage.models import CoreMutationLeaseModel, JobEventModel, JobRunModel
        from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
        from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository

        if (db.engine.dialect.name != "sqlite"
                or type(collection) is not PublishedMixedTeardownCollection):
            raise ValueError("published mixed seal requires SQLite review")
        review = collection.review
        source = review.source
        scope = collection.core_inspector_scope
        name = parent.input.get("engagementName")
        sealed = propose_published_mixed_plans_sealed(
            parent, review, plan_set, scope, name)
        if (set(before_states) != set(source.ordered_providers)
                or any(type(before_states[p]) is not bytes
                       for p in source.ordered_providers)):
            raise ValueError("published mixed retained state set differs")
        try:
            db.session.rollback()
            touched = db.session.execute(text("""
                UPDATE deployment_plans SET status = status
                WHERE id = :plan AND engagement_id = :engagement
                  AND status = 'applied' AND stage = 'applied'
                  AND apply_job_id = :core
            """), {"plan": source.core_plan_id, "engagement": source.engagement_id,
                   "core": source.core_job_id})
            if touched.rowcount != 1:
                raise ValueError("published mixed core plan changed")
            db.session.expire_all()
            current = self.get(parent.id)
            lease = db.session.query(CoreMutationLeaseModel).filter_by(
                engagement_id=source.engagement_id).one_or_none()
            if (lease is None or lease.owner_id != source.core_plan_id
                    or lease.operation != "provider_keyed_teardown_fence"
                    or current != parent):
                raise ValueError("published mixed seal parent or fence changed")
            recognize_published_mixed_initial_checkpoint(
                current, review, scope, name)
            if collection.six_collection is not None or review.failed_append_recovery is not None:
                (recheck_failed_append_collection_local if review.failed_append_recovery is not None
                 else recheck_published_six_collection_local)(
                    collection, jobs=self, allow_teardown_fence=True)
                for artifact in plan_set.plans:
                    plan_path = Path(artifact.plan_path)
                    if (plan_path.is_symlink() or not plan_path.is_file()
                            or hashlib.sha256(plan_path.read_bytes()).hexdigest() != artifact.plan_sha256
                            or _binary_sha(Path(artifact.terraform_path)) != artifact.terraform_sha256):
                        raise ValueError("published six-node saved plan changed")
            else:
                initial = self.get(source.parent_job_id)
                core = self.get(source.core_job_id)
                plan = SqlAlchemyDeploymentPlanRepository().get(source.core_plan_id)
                binding = self.get(_binding_child_id(source.core_job_id))
                bootstrap = self.get(_worker_id(source.core_job_id))
                proof = self.get(proof_child_id(source.core_job_id))
                children = {p: self.get(_child_id(source.core_job_id, p))
                            for p in source.ordered_providers}
                durable = SqlAlchemySketchChainRepository().list_for_engagement(
                    source.engagement_id)
                from app.services.provider_keyed_runtime_preflight import reviewed_mixed_chain_rows
                chains = {row.chain_id: row for row in reviewed_mixed_chain_rows(
                    durable, source.chain_ids, source.engagement_id)}
                if (initial is None or job_event_digest(initial.events)
                        != review.published_parent_journal_sha256
                        or core is None or plan is None or binding is None
                        or bootstrap is None or proof is None
                        or any(child is None for child in children.values())
                        or set(chains) != set(source.chain_ids)
                        or active_core_connection_details(self, source.engagement_id)[0]
                           != source.core_job_id
                        or _empty_owned_bindings(source.engagement_id, self,
                                                 SqlAlchemyDomainRepository())
                           != {kind: () for kind in (
                               "channels", "domains", "certificates", "sites")}
                        or _core_inspector_scope(
                            core, jobs=self,
                            core_state_root=DEFAULT_TERRAFORM_STATE_ROOT,
                            plan_repository=SqlAlchemyDeploymentPlanRepository(),
                            provider_resource_repository=SqlAlchemyProviderResourceRepository(),
                        ) != scope):
                    raise ValueError("published mixed source or bindings changed")
                for provider, artifact in zip(
                        source.ordered_providers, plan_set.plans, strict=True):
                    workspace = collection.workspaces[provider]
                    state_path = workspace / "terraform.tfstate"
                    plan_path = Path(artifact.plan_path)
                    if (not workspace.is_absolute() or workspace.is_symlink()
                            or not workspace.is_dir()
                            or workspace.resolve(strict=True) != workspace
                            or state_path.is_symlink()
                            or state_path.read_bytes() != before_states[provider]
                            or before_states[provider]
                               != collection.observations[provider].state_json
                            or plan_path.is_symlink() or not plan_path.is_file()
                            or not 0 < plan_path.stat().st_size <= 128 * 1024 * 1024
                            or hashlib.sha256(plan_path.read_bytes()).hexdigest()
                               != artifact.plan_sha256
                            or _binary_sha(Path(artifact.terraform_path))
                               != artifact.terraform_sha256):
                        raise ValueError("published mixed retained plan bytes changed")
                current_review = review_published_mixed_initial_teardown(
                    parent=initial, core=core, plan=plan, binding=binding,
                    bootstrap=bootstrap, proof_child=proof,
                    apply_children=children, chains=chains,
                    observations=collection.observations,
                    workspaces=collection.workspaces,
                    live_bindings={kind: () for kind in (
                        "channels", "domains", "certificates", "sites")},
                    mutation_lease=(source.core_plan_id, "provider_keyed_teardown_fence"),
                    allow_teardown_fence=True,
                )
                if current_review != review:
                    raise ValueError("published mixed reviewed generation changed")
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job ORDER BY sequence
            """), {"job": parent.id}).fetchall()
            if not _claimed_apply_journal_matches(
                    rows, current, job_event_digest(current.events)):
                raise ValueError("published mixed seal journal changed")
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == parent.id,
                JobRunModel.action == parent.action,
                JobRunModel.status == "queued",
                JobRunModel.started_at.is_(None),
                JobRunModel.finished_at.is_(None),
                JobRunModel.input == parent.input,
            ).values(input=sealed.input))
            if changed.rowcount != 1:
                raise ValueError("published mixed seal CAS lost")
            event = sealed.events[-1]
            db.session.add(JobEventModel(
                job_id=parent.id, sequence=2, level=event.level,
                message=event.message, data=event.data))
            db.session.commit()
            result = self.get(parent.id)
            recognize_published_mixed_plans_sealed(
                result, review, plan_set, scope, name)
            return result
        except Exception:
            db.session.rollback()
            raise ValueError("both published mixed plans require fresh seal") from None

    def reserve_mixed_interrupted_cleanup_parent(
        self, proposal: StoredJobRun, *, initial: StoredJobRun, review,
        snapshots_by_provider, process_quiescent: Callable[[dict], bool],
        state_root: Path, review_generation: str, host_rows=None,
    ) -> StoredJobRun:
        """Atomically exchange the initial lease for one reviewed cleanup fence."""
        from sqlalchemy import text
        from app.services.provider_keyed_mixed_initial_apply_child import _child_id
        from app.services.provider_keyed_mixed_initial_host_attestation import (
            recognize_safe_incomplete_mixed_host_worker,
        )
        from app.services.provider_keyed_mixed_initial_host_binding import _binding_child_id
        from app.services.provider_keyed_mixed_initial_bootstrap import _worker_id as _host_worker_id
        from app.services.provider_keyed_mixed_initial_plan_parent import validate_mixed_initial_apply_seal
        from app.services.provider_keyed_mixed_interrupted_cleanup import (
            recognize_mixed_interrupted_cleanup_checkpoint,
        )
        from app.services.provider_keyed_mixed_interrupted_source import review_mixed_interrupted_source
        from app.services.provider_keyed_sketch import SCHEMA
        from app.services.sketch_state_workspaces import _default_state_root
        from app.services.core_ssh import active_core_connection_details
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel, JobEventModel, JobRunModel

        if (db.engine.dialect.name != "sqlite" or not isinstance(state_root, Path)
                or state_root != _default_state_root()
                or type(review_generation) is not str or not review_generation
                or not callable(process_quiescent)):
            raise ValueError("mixed interrupted reservation boundary differs")
        recognize_mixed_interrupted_cleanup_checkpoint(proposal, initial, review)
        try:
            db.session.rollback()
            touched = db.session.execute(text("""
                UPDATE deployment_plans SET status = status
                WHERE id = :plan AND engagement_id = :engagement
                  AND status = 'applied' AND apply_job_id = :core
            """), {"plan": initial.input["corePlanId"],
                   "engagement": initial.target_id,
                   "core": initial.input["coreJobId"]})
            if touched.rowcount != 1:
                raise ValueError("applied core plan changed")
            db.session.expire_all()
            lease = db.session.query(CoreMutationLeaseModel).filter_by(
                engagement_id=initial.target_id).one_or_none()
            existing = self.get(proposal.id)
            if existing is not None:
                if (lease is None or lease.owner_id != initial.input["corePlanId"]
                        or lease.operation != "provider_keyed_teardown_fence"):
                    raise ValueError("mixed interrupted fence differs")
                recognize_mixed_interrupted_cleanup_checkpoint(existing, initial, review)
                db.session.commit()
                return existing
            if (lease is None or lease.owner_id != initial.input["corePlanId"]
                    or lease.operation != "provider_keyed_initial"
                    or self.get(initial.id) != initial):
                raise ValueError("mixed initial source or lease changed")
            seal = validate_mixed_initial_apply_seal(initial)
            order = tuple(seal["orderedProviders"])
            expected = {_child_id(initial.input["coreJobId"], provider) for provider in order}
            historical = [row for row in self.list_for_engagement(initial.target_id)
                          if row.action == "provider_keyed_mixed_initial_apply_child"]
            if any(row.id not in expected for row in historical):
                raise ValueError("foreign mixed Apply child is present")
            children = {provider: self.get(_child_id(initial.input["coreJobId"], provider))
                        for provider in order}
            core_id = initial.input["coreJobId"]
            if initial.input.get("phase") == "awaiting_mixed_host_proof":
                if (type(host_rows) is not tuple or len(host_rows) != 3
                        or self.get(core_id) != host_rows[0]
                        or self.get(_binding_child_id(core_id)) != host_rows[1]
                        or self.get(_host_worker_id(core_id)) != host_rows[2]):
                    raise ValueError("mixed completed host worker changed before fence")
                active_core_id, _ = active_core_connection_details(self, initial.target_id)
                recognize_safe_incomplete_mixed_host_worker(
                    initial, host_rows[0], children, host_rows[1], host_rows[2],
                    active_core_id, process_quiescent=process_quiescent)
            elif (initial.input.get("phase") != "apply_sealed" or host_rows is not None
                    or self.get(_host_worker_id(core_id)) is not None):
                raise ValueError("mixed host phase or worker differs before fence")
            if db.session.execute(text("""
                SELECT 1 FROM job_runs WHERE target_type = 'engagement'
                  AND target_id = :engagement AND status IN ('queued', 'running')
                  AND action IN ('inspector_inspection', 'inspector_readiness', 'inspector_cleanup')
                LIMIT 1
            """), {"engagement": initial.target_id}).first() is not None:
                raise ValueError("Inspector operation is active")
            # The GET pages were already collected. Re-read only local state
            # and exact journals under the database writer slot.
            for provider in order:
                policy = seal["reviewedPolicy"][provider]
                fingerprint = hashlib.sha256(
                    f"{provider}\0{policy['provider_connection_id']}".encode()).hexdigest()
                root = (state_root / initial.target_id / "provider-keyed-v2"
                        / provider / fingerprint)
                if root.is_symlink() or not root.is_dir() or root.resolve(strict=True) != root:
                    raise ValueError("mixed provider workspace changed")
                snapshot = snapshots_by_provider[provider]
                state_path = root / "terraform.tfstate"
                phase_path = root / ".barragan-apply-phase.json"
                if state_path.is_symlink() or phase_path.is_symlink():
                    raise ValueError("mixed provider retained state changed")
                phase_marker = json.loads(phase_path.read_text()) if phase_path.exists() else None
                expected_marker = ({"schema": SCHEMA, "phase": snapshot.phase}
                                   if snapshot.phase is not None else None)
                if ((state_path.read_bytes() if state_path.exists() else None)
                        != snapshot.state_json
                        or phase_marker != expected_marker):
                    raise ValueError("mixed provider retained state changed")
            def source_fence() -> str:
                current = db.session.query(CoreMutationLeaseModel).filter_by(
                    engagement_id=initial.target_id).one_or_none()
                if (current is None or current.owner_id != initial.input["corePlanId"]
                        or current.operation != "provider_keyed_initial"):
                    raise ValueError("mixed initial lease changed during review")
                return review_generation
            current_review = review_mixed_interrupted_source(
                initial, children, snapshots_by_provider,
                fence=source_fence, process_quiescent=process_quiescent)
            if current_review != review:
                raise ValueError("mixed interrupted source changed before fence")
            if proposal.input.get("reviewScope") is not None:
                from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
                from app.services.provider_keyed_mixed_interrupted_dispatch import (
                    _core_inspector_scope, _saved_core_inspector_scope,
                )
                core = self.get(core_id)
                if core is None or _core_inspector_scope(
                        core, jobs=self,
                        core_state_root=DEFAULT_TERRAFORM_STATE_ROOT
                ) != _saved_core_inspector_scope(proposal):
                    raise ValueError("mixed reviewed core or Inspector changed before fence")
            db.session.add(JobRunModel(
                id=proposal.id, action=proposal.action, status=proposal.status,
                target=proposal.target, target_type=proposal.target_type,
                target_id=proposal.target_id, requested_by=proposal.requested_by,
                input=proposal.input, artifact_refs=[],
                created_at=_parse_datetime(proposal.created_at),
                started_at=None, finished_at=None))
            db.session.add(JobEventModel(
                job_id=proposal.id, sequence=1, level="info",
                message=proposal.events[0].message, data=proposal.events[0].data))
            db.session.flush()
            changed = db.session.execute(text("""
                UPDATE core_mutation_leases SET operation = 'provider_keyed_teardown_fence'
                WHERE engagement_id = :engagement AND owner_id = :plan
                  AND operation = 'provider_keyed_initial'
            """), {"engagement": initial.target_id,
                   "plan": initial.input["corePlanId"]})
            if changed.rowcount != 1:
                raise ValueError("mixed lease changed before reservation")
            db.session.commit()
            return self.get(proposal.id)
        except Exception:
            db.session.rollback()
            raise ValueError("mixed interrupted cleanup reservation requires fresh review") from None

    def seal_mixed_interrupted_destroy_plans(
        self, parent: StoredJobRun, *, initial: StoredJobRun, review,
        plan_set, before_states, plan_paths, show_json, state_root: Path,
    ) -> StoredJobRun:
        """Seal both exact destroy plans under the existing teardown fence."""
        from dataclasses import asdict
        from sqlalchemy import text, update
        from app.services.provider_keyed_mixed_interrupted_cleanup import (
            recognize_mixed_interrupted_cleanup_checkpoint,
            recognize_mixed_interrupted_sealed_plans,
        )
        from app.services.provider_keyed_mixed_interrupted_destroy_plan import (
            bind_mixed_interrupted_destroy_plans,
        )
        from app.services.provider_keyed_mixed_initial_plan_parent import validate_mixed_initial_apply_seal
        from app.services.sketch_state_workspaces import _default_state_root
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel, JobEventModel, JobRunModel

        if (db.engine.dialect.name != "sqlite" or not isinstance(state_root, Path)
                or state_root != _default_state_root()):
            raise ValueError("mixed destroy plan seal requires SQLite")
        try:
            db.session.rollback()
            touched = db.session.execute(text("""
                UPDATE deployment_plans SET status = status
                WHERE id = :plan AND engagement_id = :engagement
                  AND status = 'applied' AND apply_job_id = :core
            """), {"plan": initial.input["corePlanId"],
                   "engagement": initial.target_id,
                   "core": initial.input["coreJobId"]})
            if touched.rowcount != 1:
                raise ValueError("applied core plan changed")
            db.session.expire_all()
            current = self.get(parent.id)
            lease = db.session.query(CoreMutationLeaseModel).filter_by(
                engagement_id=parent.target_id).one_or_none()
            if (lease is None or lease.owner_id != initial.input["corePlanId"]
                    or lease.operation != "provider_keyed_teardown_fence"
                    or self.get(initial.id) != initial):
                raise ValueError("mixed teardown fence or seal changed")
            if current != parent:
                raise ValueError("mixed cleanup parent changed")
            if parent.input.get("phase") == "plans_sealed":
                recognize_mixed_interrupted_sealed_plans(parent, initial, review, plan_set)
                db.session.commit()
                return parent
            recognize_mixed_interrupted_cleanup_checkpoint(parent, initial, review)
            # Local read-only validation; no Terraform or provider request in
            # the database writer transaction.
            seal = validate_mixed_initial_apply_seal(initial)
            for provider in review.ordered_providers:
                policy = seal["reviewedPolicy"][provider]
                fingerprint = hashlib.sha256(
                    f"{provider}\0{policy['provider_connection_id']}".encode()).hexdigest()
                root = (state_root / initial.target_id / "provider-keyed-v2"
                        / provider / fingerprint)
                state_path = root / "terraform.tfstate"
                expected_plan = root / f".barragan-mixed-interrupted-destroy-{provider}.tfplan"
                if (root.is_symlink() or not root.is_dir()
                        or root.resolve(strict=True) != root
                        or state_path.is_symlink()
                        or (state_path.read_bytes() if state_path.exists() else None)
                        != before_states[provider]
                        or (plan_paths[provider] is not None
                            and plan_paths[provider] != expected_plan)):
                    raise ValueError("mixed destroy workspace differs")
            current_plans = bind_mixed_interrupted_destroy_plans(
                initial, review, before_states, plan_paths, show_json,
                fence=lambda: review.review_sha256)
            if current_plans != plan_set:
                raise ValueError("mixed destroy plan artifacts changed")
            event = JobEvent(2, "info", "both mixed destroy plans sealed",
                             {"planSet": json.loads(json.dumps(asdict(plan_set), sort_keys=True)),
                              "planSetSha256": plan_set.plan_set_sha256})
            updated_input = {**parent.input, "phase": "plans_sealed"}
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == parent.id, JobRunModel.action == parent.action,
                JobRunModel.status == "queued", JobRunModel.started_at.is_(None),
                JobRunModel.finished_at.is_(None), JobRunModel.input == parent.input,
            ).values(input=updated_input))
            if changed.rowcount != 1:
                raise ValueError("mixed cleanup plan seal CAS lost")
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job ORDER BY sequence
            """), {"job": parent.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, parent, job_event_digest(parent.events)):
                raise ValueError("mixed cleanup plan journal changed")
            db.session.add(JobEventModel(job_id=parent.id, sequence=2,
                                         level=event.level, message=event.message, data=event.data))
            db.session.commit()
            result = self.get(parent.id)
            recognize_mixed_interrupted_sealed_plans(result, initial, review, plan_set)
            return result
        except Exception:
            db.session.rollback()
            raise ValueError("both mixed destroy plans require fresh sealed review") from None

    def reserve_published_keyed_append_teardown_parent(
        self, job: StoredJobRun, *, reviewed_source, state_root=None,
    ) -> StoredJobRun | None:
        """Reserve the ordinary teardown parent for one channel-free appended generation.

        This is a private persisted boundary only. The expanded generation has
        no destroy dispatcher until its pre-GO and historical readers are ready.
        """
        from dataclasses import asdict
        from sqlalchemy import text
        from app.services import engagement_teardown as teardown
        from app.services.provider_keyed_append_source import (
            PublishedProviderKeyedAppendSource, audit_published_provider_keyed_append_source,
        )
        from app.services.provider_keyed_dns_cleanup_manifest import _empty_published_append_manifest
        from app.storage.database import db
        from app.storage.domain_repository import SqlAlchemyDomainRepository
        from app.storage.models import CoreMutationLeaseModel, JobEventModel, JobRunModel
        from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
        from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository

        if (db.engine.dialect.name != "sqlite"
                or not isinstance(reviewed_source, PublishedProviderKeyedAppendSource)
                or job.action != teardown.ENGAGEMENT_TEARDOWN_ACTION
                or job.status != "queued" or job.started_at is not None
                or job.finished_at is not None or job.artifact_refs != []
                or job.id != teardown._parent_id(reviewed_source.initial_source.core_job_id)
                or job.target_type != "engagement"
                or job.target_id != reviewed_source.initial_source.engagement_id
                or job.target != f"engagement:{job.target_id}"
                or type(job.input) is not dict
                or set(job.input) != {
                    "engagementId", "coreJobId", "scopeSnapshot", "phase",
                    "outcomes", "remainingOwnedResources", "mutation", "confirmation",
                }
                or job.input.get("coreJobId") != reviewed_source.initial_source.core_job_id
                or job.input.get("engagementId") != job.target_id
                or job.input.get("phase") != "queued"
                or job.input.get("mutation") is not True
                or job.input.get("outcomes") != {}
                or job.input.get("remainingOwnedResources") != []
                or job.input.get("confirmation") != "redacted"
                or type(job.input.get("scopeSnapshot")) is not dict
                or len(job.events) != 1 or job.events[0] != JobEvent(
                    1, "info", "engagement teardown queued",
                    {"snapshotId": job.input.get("scopeSnapshot", {}).get("snapshotId")},
                )):
            raise PublishedKeyedTeardownReservationConflict("invalid appended teardown proposal")
        snapshot = job.input["scopeSnapshot"]
        scope = snapshot.get("providerScopes")
        dns = snapshot.get("dnsCleanupManifest")
        if (teardown._parent_boundary_fields(job) is None
                or type(scope) is not list or len(scope) != 1
                or scope[0].get("stateSha256") != reviewed_source.state_sha256
                or scope[0].get("corePlanId") != reviewed_source.initial_source.core_plan_id
                or teardown._fingerprint({key: value for key, value in snapshot.items()
                                          if key != "snapshotId"}) != snapshot["snapshotId"]
                or type(dns) is not dict
                or dns.get("schema") != "provider-keyed-empty-dns-append-v1"
                or dns.get("appendJobId") != reviewed_source.append_job_id
                or dns.get("appendJournalSha256") != reviewed_source.append_journal_sha256):
            raise PublishedKeyedTeardownReservationConflict("reviewed appended snapshot differs")
        sealed = json.loads(json.dumps(asdict(reviewed_source), sort_keys=True))
        identity = current_request_identity()
        proposed = replace(job,
            requested_by=identity.username if identity is not None else job.requested_by,
            input={**job.input,
                   "publishedSource": json.loads(json.dumps(asdict(reviewed_source.initial_source), sort_keys=True)),
                   "publishedAppendSource": sealed})
        try:
            db.session.rollback()
            updated = db.session.execute(text("""
                UPDATE deployment_plans SET status = status
                WHERE id = :plan AND engagement_id = :engagement
                  AND status = 'applied' AND apply_job_id = :core
            """), {"plan": reviewed_source.initial_source.core_plan_id,
                   "engagement": job.target_id,
                   "core": reviewed_source.initial_source.core_job_id})
            if updated.rowcount != 1:
                raise ValueError("applied core plan changed")
            db.session.expire_all()
            existing = self.get(job.id)
            lease = db.session.query(CoreMutationLeaseModel).filter_by(
                engagement_id=job.target_id).one_or_none()
            if existing is not None:
                if (existing.id == proposed.id and existing.action == proposed.action
                        and existing.status == "queued" and existing.started_at is None
                        and existing.finished_at is None
                        and existing.target == proposed.target
                        and existing.target_type == proposed.target_type
                        and existing.target_id == proposed.target_id
                        and isinstance(existing.requested_by, str)
                        and bool(existing.requested_by.strip())
                        and existing.input == proposed.input
                        and existing.artifact_refs == []
                        and existing.events == proposed.events and lease is not None
                        and lease.owner_id == reviewed_source.initial_source.core_plan_id
                        and lease.operation == "provider_keyed_teardown_fence"):
                    db.session.commit()
                    return existing
                raise ValueError("existing appended teardown requires reconciliation")
            if lease is not None:
                raise ValueError("another core mutation lease exists")
            if db.session.execute(text("""
                SELECT 1 FROM job_runs WHERE target_type = 'engagement'
                  AND target_id = :engagement AND status IN ('queued', 'running')
                  AND action IN ('inspector_inspection', 'inspector_readiness', 'inspector_cleanup')
                LIMIT 1
            """), {"engagement": job.target_id}).first() is not None:
                raise ValueError("Inspector operation is active")
            current = audit_published_provider_keyed_append_source(
                reviewed_source.initial_source.core_job_id, state_root=state_root,
                job_repository=self)
            if current != reviewed_source:
                raise ValueError("appended publication changed")
            if (_empty_published_append_manifest(snapshot, self, SqlAlchemyDomainRepository())
                    != dns):
                raise ValueError("empty DNS boundary changed")
            core = self.get(reviewed_source.initial_source.core_job_id)
            current_snapshot = teardown._current_scope_snapshot(
                core, jobs=self, chains=SqlAlchemySketchChainRepository(),
                resources=SqlAlchemyProviderResourceRepository(),
                domain_repository=SqlAlchemyDomainRepository(),
                inspector_state_reader=None, reviewed_dns_manifest=dns,
                state_root=state_root,
            )
            if current_snapshot != snapshot or audit_published_provider_keyed_append_source(
                    core.id, state_root=state_root, job_repository=self) != reviewed_source:
                raise ValueError("reviewed appended generation changed")
            db.session.add(JobRunModel(
                id=proposed.id, action=proposed.action, status=proposed.status,
                target=proposed.target, target_type=proposed.target_type,
                target_id=proposed.target_id, requested_by=proposed.requested_by,
                input=proposed.input, artifact_refs=[],
                created_at=_parse_datetime(proposed.created_at),
                started_at=None, finished_at=None,
            ))
            db.session.add(JobEventModel(
                job_id=proposed.id, sequence=1, level="info",
                message="engagement teardown queued",
                data={"snapshotId": snapshot["snapshotId"]},
            ))
            db.session.add(CoreMutationLeaseModel(
                engagement_id=job.target_id,
                owner_id=reviewed_source.initial_source.core_plan_id,
                operation="provider_keyed_teardown_fence",
            ))
            db.session.commit()
            return self.get(proposed.id)
        except Exception:
            db.session.rollback()
            raise PublishedKeyedTeardownReservationConflict(
                "appended teardown reservation requires fresh review or recovery") from None

    def reserve_published_keyed_teardown_parent(
        self, job: StoredJobRun, *, reviewed_source,
        state_root=None,
    ) -> StoredJobRun | None:
        """Privately reserve one published keyed teardown and its lease atomically.

        The saved DNS manifest is review evidence. This transaction rereads
        only local persisted state; later DNS GO must recheck the provider zone.
        The public teardown dispatcher does not call this method yet.
        """
        from dataclasses import asdict
        from app.services.provider_keyed_published_initial_cleanup_authority import (
            MARKER, queued_cleanup_event_data, seal_marker, validate_saved_cleanup,
        )

        from sqlalchemy import text

        from app.services import engagement_teardown as teardown
        from app.services import provider_keyed_published_teardown_source as published
        from app.storage.database import db
        from app.storage.domain_repository import SqlAlchemyDomainRepository
        from app.storage.models import CoreMutationLeaseModel, JobEventModel, JobRunModel
        from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
        from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository

        if (db.engine.dialect.name != "sqlite"
                or not isinstance(reviewed_source, published.PublishedProviderKeyedSource)
                or job.action != teardown.ENGAGEMENT_TEARDOWN_ACTION
                or job.status != "queued" or job.started_at is not None
                or job.finished_at is not None or job.artifact_refs != []
                or job.id != teardown._parent_id(reviewed_source.core_job_id)
                or job.target_type != "engagement"
                or job.target_id != reviewed_source.engagement_id
                or job.target != f"engagement:{reviewed_source.engagement_id}"
                or not isinstance(job.input, dict)
                or set(job.input) != {
                    "engagementId", "coreJobId", "scopeSnapshot", "phase",
                    "outcomes", "remainingOwnedResources", "mutation", "confirmation",
                }
                or job.input.get("coreJobId") != reviewed_source.core_job_id
                or job.input.get("engagementId") != reviewed_source.engagement_id
                or job.input.get("phase") != "queued"
                or job.input.get("mutation") is not True
                or job.input.get("outcomes") != {}
                or job.input.get("remainingOwnedResources") != []
                or job.input.get("confirmation") != "redacted"
                or type(job.input.get("scopeSnapshot")) is not dict
                or len(job.events) != 1 or job.events[0] != JobEvent(
                    1, "info", "engagement teardown queued",
                    {"snapshotId": job.input.get("scopeSnapshot", {}).get("snapshotId")},
                )):
            raise PublishedKeyedTeardownReservationConflict("invalid published teardown proposal")
        snapshot = job.input.get("scopeSnapshot")
        if (teardown._parent_boundary_fields(job) is None
                or snapshot.get("providerScopes") is None
                or len(snapshot["providerScopes"]) != 1
                or snapshot["providerScopes"][0].get("corePlanId") != reviewed_source.core_plan_id
                or teardown._fingerprint({key: value for key, value in snapshot.items()
                                          if key != "snapshotId"}) != snapshot["snapshotId"]
                or teardown._fingerprint(snapshot["providerScopes"][0]) != reviewed_source.scope_sha256):
            raise PublishedKeyedTeardownReservationConflict("reviewed published snapshot differs")
        sealed = json.loads(json.dumps(asdict(reviewed_source), sort_keys=True))
        identity = current_request_identity()
        proposed = replace(
            job, requested_by=identity.username if identity is not None else job.requested_by,
            input={**job.input, "publishedSource": sealed,
                   **({MARKER: seal_marker(snapshot)} if seal_marker(snapshot) else {})},
            events=[JobEvent(1, "info", "engagement teardown queued", queued_cleanup_event_data(snapshot))],
        )
        try:
            # Discard any preview read transaction/identity map before taking
            # the writer slot. Authority is reloaded only after the UPDATE.
            db.session.rollback()
            # This conditional UPDATE obtains SQLite's writer slot before any
            # authoritative row read. The plan has no onupdate timestamp.
            updated = db.session.execute(text("""
                UPDATE deployment_plans SET status = status
                WHERE id = :plan AND engagement_id = :engagement
                  AND status = 'applied' AND apply_job_id = :core
            """), {"plan": reviewed_source.core_plan_id,
                   "engagement": reviewed_source.engagement_id,
                   "core": reviewed_source.core_job_id})
            if updated.rowcount != 1:
                raise ValueError("applied core plan changed")
            db.session.expire_all()
            existing = self.get(job.id)
            lease = db.session.query(CoreMutationLeaseModel).filter_by(
                engagement_id=job.target_id).one_or_none()
            if existing is not None:
                # A restart recognizes only the exact queued source and owned
                # fence. Missing/different lease is recovery-required.
                if (existing.id == proposed.id and existing.action == proposed.action
                        and existing.status == "queued" and existing.started_at is None
                        and existing.finished_at is None and existing.target == proposed.target
                        and existing.target_type == proposed.target_type
                        and existing.target_id == proposed.target_id
                        and isinstance(existing.requested_by, str)
                        and bool(existing.requested_by.strip())
                        and existing.input == proposed.input
                        and existing.artifact_refs == []
                        and existing.events == proposed.events and lease is not None
                        and lease.owner_id == reviewed_source.core_plan_id
                        and lease.operation == "provider_keyed_teardown_fence"):
                    db.session.commit()
                    return existing
                raise ValueError("existing published teardown needs reconciliation")
            if lease is not None:
                raise ValueError("another core mutation lease exists")
            opponents = _inspector_barrier_opponents(job)
            if db.session.execute(text("""
                SELECT 1 FROM job_runs WHERE target_type = 'engagement'
                  AND target_id = :engagement AND status IN ('queued', 'running')
                  AND action IN ('inspector_inspection', 'inspector_readiness', 'inspector_cleanup')
                LIMIT 1
            """), {"engagement": job.target_id}).first() is not None:
                raise ValueError("Inspector operation is active")
            if opponents != tuple(sorted(_INSPECTOR_BARRIER_ACTIONS)):
                raise ValueError("Inspector barrier changed")
            current = published.audit_published_provider_keyed_source(
                reviewed_source.core_job_id, state_root=state_root,
                job_repository=self,
            )
            if current != reviewed_source:
                raise ValueError("published generation changed")
            # Rebind the reviewed DNS deletion manifest to the actual terminal
            # initial journal and active owned receipts. No provider GET or
            # domain flock may run while this SQLite writer slot is held.
            from app.services.engagement_dns import DNS_APPLY_ACTION, _canonical_record
            from app.services.provider_keyed_dns_cleanup_binding import (
                bind_provider_keyed_dns_cleanup_targets,
            )

            dns_manifest = snapshot["dnsCleanupManifest"]
            initial = self.get(reviewed_source.initial_job_id)
            if (initial is None or job_event_digest(initial.events) !=
                    reviewed_source.initial_journal_sha256
                    or dns_manifest["initialJobId"] != reviewed_source.initial_job_id
                    or dns_manifest["initialJournalSha256"] !=
                    reviewed_source.initial_journal_sha256):
                raise ValueError("DNS initial journal changed")
            intents = [event for event in initial.events
                       if event.message == "provider host identity binding intended"]
            bounds = [event for event in initial.events
                      if event.message == "provider host identity bound"]
            if len(intents) != 1 or len(bounds) != 1:
                raise ValueError("DNS host binding changed")
            binding = bind_provider_keyed_dns_cleanup_targets(
                job.target_id, confirmed_scope=snapshot["providerScopes"][0],
                provider_scope_sha256=snapshot["providerScopeSha256"],
                host_binding_intent_event=intents[0], host_binding_bound_event=bounds[0],
            )
            if (dns_manifest["bindingSha256"] != binding.binding_sha256
                    or dns_manifest["providerScopeSha256"] != binding.provider_scope_sha256
                    or binding.manifest_sha256 != reviewed_source.manifest_sha256):
                raise ValueError("DNS edge binding changed")
            domains = SqlAlchemyDomainRepository()
            for entry in dns_manifest["domains"]:
                if (entry["bindingSha256"] != binding.binding_sha256
                        or entry["oldEdgeIps"] != list(binding.edge_public_ips)):
                    raise ValueError("DNS reviewed edge IPs changed")
                active = domains.list_record_ownership(entry["domainId"], active_only=True)
                if sorted(row.id for row in active) != entry["ownedReceiptIds"]:
                    raise ValueError("DNS active receipt inventory changed")
                selected = [row for row in active if row.id in entry["ownedReceiptIds"]]
                if sorted(row.id for row in selected) != entry["ownedReceiptIds"]:
                    raise ValueError("DNS owned receipt set changed")
                snapshots = {row.id: row for row in domains.list_snapshots(entry["domainId"])}
                proofs = []
                for row in selected:
                    record = _canonical_record(row.record)
                    source = self.get(row.creating_job_id)
                    source_snapshot = snapshots.get(row.snapshot_id)
                    if (row.engagement_id != job.target_id
                            or row.assignment_id != entry["assignmentId"]
                            or source is None or source.action != DNS_APPLY_ACTION
                            or source.status != "succeeded" or source.target_id != job.target_id
                            or source.input.get("domainId") != entry["domainId"]
                            or source_snapshot is None
                            or source_snapshot.sync_job_id != source.id
                            or source_snapshot.domain_id != entry["domainId"]
                            or sum(_canonical_record(item) == record
                                   for item in source_snapshot.hosts) != 1
                            or not any(event.message ==
                                       "Namecheap DNS setHosts completed with full desired host list"
                                       and event.data.get("snapshotId") == row.snapshot_id
                                       for event in source.events)):
                        raise ValueError("DNS owned receipt provenance changed")
                    proofs.append({"ownershipId": row.id, "record": record})
                proofs.sort(key=lambda row: row["ownershipId"])
                if entry["ownedRecordsSha256"] != "sha256:" + teardown._fingerprint(proofs):
                    raise ValueError("DNS reviewed owned records changed")
            core = self.get(reviewed_source.core_job_id)
            if core is None:
                raise ValueError("core vanished")
            current_snapshot = teardown._current_scope_snapshot(
                core, jobs=self, chains=SqlAlchemySketchChainRepository(),
                resources=SqlAlchemyProviderResourceRepository(),
                domain_repository=SqlAlchemyDomainRepository(),
                inspector_state_reader=None,
                reviewed_dns_manifest=snapshot["dnsCleanupManifest"],
                state_root=state_root,
            )
            validate_saved_cleanup(proposed, core, snapshot, self)
            if current_snapshot != snapshot:
                raise ValueError("reviewed DB-only scope changed")
            if published.audit_published_provider_keyed_source(
                reviewed_source.core_job_id, state_root=state_root,
                job_repository=self,
            ) != reviewed_source:
                raise ValueError("applied state changed before reservation")
            db.session.add(JobRunModel(
                id=proposed.id, action=proposed.action, status=proposed.status,
                target=proposed.target, target_type=proposed.target_type,
                target_id=proposed.target_id, requested_by=proposed.requested_by,
                input=proposed.input, artifact_refs=[],
                created_at=_parse_datetime(proposed.created_at),
                started_at=None, finished_at=None,
            ))
            db.session.add(JobEventModel(
                job_id=proposed.id, sequence=1, level="info",
                message="engagement teardown queued",
                data=queued_cleanup_event_data(snapshot),
            ))
            db.session.add(CoreMutationLeaseModel(
                engagement_id=job.target_id, owner_id=reviewed_source.core_plan_id,
                operation="provider_keyed_teardown_fence",
            ))
            db.session.commit()
            return self.get(proposed.id)
        except Exception:
            db.session.rollback()
            raise PublishedKeyedTeardownReservationConflict(
                "published keyed teardown reservation requires fresh review or recovery") from None

    def list(self) -> list[StoredJobRun]:
        from app.storage.models import JobRunModel

        rows = JobRunModel.query.order_by(JobRunModel.created_at.desc()).all()
        return _from_models(rows)

    def list_for_engagement(self, engagement_id: str, *, limit: int | None = None) -> list[StoredJobRun]:
        from sqlalchemy import or_

        from app.storage.models import JobRunModel

        query = (
            JobRunModel.query.filter(
                or_(
                    JobRunModel.target_id == engagement_id,
                    JobRunModel.target == f"engagement:{engagement_id}",
                    JobRunModel.input["engagementId"].as_string() == engagement_id,
                )
            )
            .order_by(JobRunModel.created_at.desc())
        )
        if limit is not None:
            query = query.limit(limit)
        rows = query.all()
        return _from_models(rows)

    def list_channel_mutations_for_engagement(self, engagement_id: str) -> list[StoredJobRun]:
        """Read only channel-writing jobs and jobs with raw channel snapshots."""
        from sqlalchemy import and_, exists, func, or_

        from app.storage.models import JobEventModel, JobRunModel

        channel_event = exists().where(and_(
            JobEventModel.job_id == JobRunModel.id,
            or_(
                func.json_type(JobEventModel.data, "$.inboundChannels").isnot(None),
                func.json_type(JobEventModel.data, "$.outboundChannels").isnot(None),
            ),
        ))
        rows = (JobRunModel.query.filter(
            or_(
                JobRunModel.target_id == engagement_id,
                JobRunModel.target == f"engagement:{engagement_id}",
                JobRunModel.input["engagementId"].as_string() == engagement_id,
            ),
            or_(
                JobRunModel.action == "engagement_channels_update",
                JobRunModel.action.startswith("inbound_channel_"),
                JobRunModel.action.startswith("outbound_channel_"),
                channel_event,
            ),
        ).order_by(JobRunModel.created_at.desc()).all())
        return _from_models(rows)

    def list_semantic_for_engagement(self, engagement_id: str, *, recent_limit: int = 250) -> list[StoredJobRun]:
        """Return a bounded timeline plus bounded latest semantic projections."""
        from sqlalchemy import text

        from app.storage.database import db

        rows = db.session.execute(
            text(_semantic_jobs_sql()),
            {
                "engagement_id": engagement_id,
                "engagement_target": f"engagement:{engagement_id}",
                "recent_limit": recent_limit,
                "category_limit": SEMANTIC_ROWS_PER_CATEGORY,
            },
        ).mappings().all()
        return _stored_jobs_from_mappings(rows)

    def list_semantic_for_engagements(
        self,
        engagement_ids: list[str],
        *,
        recent_limit: int = 250,
    ) -> SemanticJobBatch:
        """Preserve per-engagement ranking while batching jobs and events."""
        from sqlalchemy import text

        from app.storage.database import db

        ids = list(dict.fromkeys(value for value in engagement_ids if value))
        parameters = {f"engagement_{index}": value for index, value in enumerate(ids)}
        rows = db.session.execute(
            text(_semantic_jobs_for_engagements_sql(len(ids))),
            {
                **parameters,
                "recent_limit": recent_limit,
                "category_limit": SEMANTIC_ROWS_PER_CATEGORY,
            },
        ).mappings().all()
        metadata = rows[0]
        selected_rows = rows[1:]
        return SemanticJobBatch(
            jobs_by_engagement=_stored_jobs_by_engagement_from_mappings(selected_rows, ids),
            total_job_count=int(metadata["total_job_count"]),
            seed_job_exists=bool(metadata["seed_job_exists"]),
        )

    def list_dashboard_semantic_for_engagements(
        self,
        engagement_ids: list[str],
        *,
        recent_limit: int = 250,
    ) -> DashboardSemanticJobBatch:
        from sqlalchemy import text

        from app.storage.database import db

        ids = list(dict.fromkeys(value for value in engagement_ids if value))
        parameters = {f"engagement_{index}": value for index, value in enumerate(ids)}
        rows = db.session.execute(
            text(_semantic_jobs_for_engagements_sql(len(ids))),
            {
                **parameters,
                "recent_limit": recent_limit,
                "category_limit": SEMANTIC_ROWS_PER_CATEGORY,
            },
        ).mappings().all()
        metadata = rows[0]
        return DashboardSemanticJobBatch(
            jobs_by_engagement=_stored_dashboard_jobs_by_engagement_from_mappings(rows[1:], ids),
            total_job_count=int(metadata["total_job_count"]),
            seed_job_exists=bool(metadata["seed_job_exists"]),
        )

    def list_summaries(self, *, limit: int, offset: int) -> tuple[list[JobRunSummary], int]:
        from app.storage.models import JobRunModel

        total = JobRunModel.query.count()
        rows = JobRunModel.query.order_by(JobRunModel.created_at.desc()).offset(offset).limit(limit).all()
        return [_summary_from_model(row) for row in rows], total

    def count(self) -> int:
        from app.storage.models import JobRunModel

        return JobRunModel.query.count()

    def get(self, job_id: str) -> StoredJobRun | None:
        from app.storage.models import JobRunModel

        row = JobRunModel.query.get(job_id)
        if row is None:
            return None
        return _from_model(row)

    def save(self, job: StoredJobRun) -> StoredJobRun:
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        _fence_append_binding_history(job)
        row = JobRunModel.query.get(job.id)
        if row is None:
            request_identity = current_request_identity()
            if request_identity is not None:
                job = replace(job, requested_by=request_identity.username)
            row = JobRunModel(id=job.id)
            db.session.add(row)

        row.action = job.action
        row.status = job.status
        row.target = job.target
        row.target_type = job.target_type
        row.target_id = job.target_id
        row.requested_by = job.requested_by
        row.input = job.input
        row.artifact_refs = job.artifact_refs
        row.created_at = _parse_datetime(job.created_at)
        row.started_at = _parse_datetime(job.started_at) if job.started_at else None
        row.finished_at = _parse_datetime(job.finished_at) if job.finished_at else None

        JobEventModel.query.filter_by(job_id=job.id).delete()
        for event in job.events:
            db.session.add(
                JobEventModel(
                    job_id=job.id,
                    sequence=event.sequence,
                    level=event.level,
                    message=event.message,
                    data=event.data,
                )
            )
        db.session.commit()
        return self.get(job.id) or job

    def reserve_mixed_append_pair(self, parent: StoredJobRun,
                                  plan_child: StoredJobRun) -> StoredJobRun:
        """Atomically lease one published mixed generation and reserve pair jobs.

        A repeated identical reservation is a read of the same durable intent;
        a crash cannot leave an append lease without its planning inputs.
        """
        from app.storage.database import db
        from app.storage.models import (
            CoreMutationLeaseModel, DeploymentPlanModel, JobEventModel, JobRunModel,
            SketchChainModel,
        )

        inputs = parent.input
        if (db.engine.dialect.name != "sqlite"
                or parent.action != "provider_keyed_mixed_append"
                or plan_child.action != "provider_keyed_mixed_append_plan_child"
                or parent.status != "queued" or plan_child.status != "queued"
                or parent.started_at is not None or plan_child.started_at is not None
                or parent.finished_at is not None or plan_child.finished_at is not None
                or parent.target_type != "engagement"
                or parent.target != f"engagement:{parent.target_id}"
                or plan_child.target != parent.target
                or plan_child.target_type != parent.target_type
                or plan_child.target_id != parent.target_id
                or plan_child.requested_by != parent.requested_by
                or plan_child.input.get("appendParentId") != parent.id
                or plan_child.input.get("requestSha256") != inputs.get("requestSha256")
                or inputs.get("phase") != "planning"
                or inputs.get("engagementId") != parent.target_id
                or not isinstance(inputs.get("coreJobId"), str)
                or not isinstance(inputs.get("corePlanId"), str)
                or len(parent.events) != 1 or len(plan_child.events) != 1
                or parent.artifact_refs or plan_child.artifact_refs):
            raise ValueError("mixed append reservation identity differs")
        try:
            # Successful mixed publication released its initial lease. Take
            # SQLite's writer slot on the selected applied plan, then require
            # that normal lease-free published state before inserting a new
            # append lease and both jobs in this one transaction.
            locked = DeploymentPlanModel.query.filter_by(
                id=inputs["corePlanId"], engagement_id=parent.target_id,
                status="applied", stage="applied",
                apply_job_id=inputs["coreJobId"],
            ).update({"status": "applied"}, synchronize_session=False)
            lease = CoreMutationLeaseModel.query.filter_by(
                engagement_id=parent.target_id).one_or_none()
            plan = DeploymentPlanModel.query.filter_by(
                id=inputs["corePlanId"], engagement_id=parent.target_id,
                status="applied", stage="applied",
                apply_job_id=inputs["coreJobId"],
            ).one_or_none()
            core = JobRunModel.query.filter_by(
                id=inputs["coreJobId"], action="pilot_standard_rti_guarded_execute",
                status="succeeded",
            ).one_or_none()
            published_id = ("job-provider-keyed-mixed-initial-"
                            f"{inputs['coreJobId'].removeprefix('job-')}")
            published = JobRunModel.query.filter_by(
                id=published_id, action="provider_keyed_mixed_initial",
                status="succeeded", target_id=parent.target_id,
            ).one_or_none()
            publication_event = JobEventModel.query.filter_by(
                job_id=published_id).order_by(JobEventModel.sequence.desc()).first()
            published_chains = SketchChainModel.query.filter_by(
                engagement_id=parent.target_id).all()
            initial_ids = published.input.get("chainIds") if published else None
            from app.services.provider_keyed_runtime_preflight import reviewed_mixed_chain_rows
            from app.storage.sketch_chain_repository import _from_model as _chain_from_model
            selected = reviewed_mixed_chain_rows(
                [_chain_from_model(row) for row in published_chains],
                initial_ids, parent.target_id)
            published_chains = [row for row in published_chains
                                if row.chain_id in {chain.chain_id for chain in selected}]
            prior_parent = JobRunModel.query.filter_by(id=parent.id).one_or_none()
            prior_child = JobRunModel.query.filter_by(id=plan_child.id).one_or_none()
            if (locked != 1 or plan is None or core is None or published is None
                    or publication_event is None
                    or publication_event.message != "mixed two-provider host proof published"
                    or publication_event.level != "info"
                    or core.input.get("engagementId") != parent.target_id
                    or core.input.get("corePlanId") != plan.id
                    or published.input.get("coreJobId") != core.id
                    or published.input.get("corePlanId") != plan.id
                    or published.input.get("phase") != "completed"
                    or published.finished_at is None
                    or type(initial_ids) is not list or len(initial_ids) != 2
                    or len(set(initial_ids)) != 2
                    or set(inputs.get("providerOrder", []))
                       != {"digitalocean", "linode"}
                    or set(initial_ids) != set(inputs.get("chainOrder", []))
                    or publication_event.data.get("chainIds") != initial_ids
                    or len(published_chains) != 2
                    or {row.chain_id for row in published_chains} != set(initial_ids)
                    or {row.middle_provider for row in published_chains}
                       != {"digitalocean", "linode"}
                    or inputs.get("reviewRequest", {}).get("digitalocean", {}).get(
                        "selectedChainId") != next(
                            row.chain_id for row in published_chains
                            if row.middle_provider == "linode")
                    or inputs.get("reviewRequest", {}).get("linode", {}).get(
                        "selectedChainId") != next(
                            row.chain_id for row in published_chains
                            if row.middle_provider == "digitalocean")
                    or any(row.status != "deployed" or row.burned
                           or row.deploy_job_id != published_id
                           or row.middle_provider != row.edge_provider
                           or row.edge_count != 1 or len(row.nodes or []) != 2
                           or [node.get("role") for node in row.nodes]
                              != ["middle", "edge"]
                           or any(node.get("provider") != row.middle_provider
                                  for node in row.nodes)
                           for row in published_chains)
                    or bool(prior_parent) != bool(prior_child)
                    or (prior_parent is None and lease is not None)
                    or (prior_parent is not None and
                        (lease is None or lease.owner_id != plan.id or
                         lease.operation != "provider_keyed_mixed_append"))):
                raise ValueError("mixed append core lease or generation differs")
            if prior_parent is not None:
                saved = self.get(parent.id)
                saved_child = self.get(plan_child.id)
                if (saved is None or saved_child is None
                        or saved.action != parent.action
                        or saved.target_id != parent.target_id
                        or saved.requested_by != parent.requested_by
                        or saved.input.get("requestSha256") != inputs["requestSha256"]
                        or saved.input.get("coreJobId") != inputs["coreJobId"]
                        or saved.input.get("corePlanId") != inputs["corePlanId"]
                        or saved_child.action != plan_child.action
                        or saved_child.input.get("requestSha256")
                           != inputs["requestSha256"]):
                    raise ValueError("mixed append reservation differs from prior click")
                db.session.commit()
                return saved
            # DB-only eligibility recheck under the writer slot. A domain,
            # service or channel binding racing the front-door check must not
            # leave an append lease that its original cleanup cannot consume.
            from app.services.provider_keyed_mixed_append_availability import require_no_independent_mixed_append_bindings
            require_no_independent_mixed_append_bindings(parent.target_id, jobs=self)
            db.session.add(CoreMutationLeaseModel(
                engagement_id=parent.target_id, owner_id=plan.id,
                operation="provider_keyed_mixed_append"))
            for job in (parent, plan_child):
                db.session.add(JobRunModel(
                    id=job.id, action=job.action, status=job.status,
                    target=job.target, target_type=job.target_type,
                    target_id=job.target_id, requested_by=job.requested_by,
                    input=job.input, artifact_refs=[],
                    created_at=_parse_datetime(job.created_at),
                    started_at=None, finished_at=None,
                ))
                db.session.add(JobEventModel(
                    job_id=job.id, sequence=1, level=job.events[0].level,
                    message=job.events[0].message, data=job.events[0].data,
                ))
            db.session.commit()
            return self.get(parent.id) or parent
        except Exception:
            db.session.rollback()
            raise

    def seal_mixed_append_pair(self, parent: StoredJobRun, *,
                               plan_child_id: str, sealed_input: dict,
                               claim_owner: str, claim_token: str,
                               approved_at: str) -> StoredJobRun:
        """Commit one claimed paired approval digest and plan child atomically."""
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel, JobEventModel, JobRunModel

        if (db.engine.dialect.name != "sqlite" or parent.action != "provider_keyed_mixed_append"
                or parent.status != "running" or parent.input.get("phase") != "planning"
                or parent.input.get("claimOwner") != claim_owner
                or parent.input.get("claimToken") != claim_token
                or sealed_input.get("phase") != "apply_sealed"
                or sealed_input.get("requestSha256") != parent.input.get("requestSha256")
                or any(sealed_input.get(key) != parent.input.get(key)
                       for key in ("engagementId", "coreJobId", "corePlanId",
                                   "providerOrder", "chainOrder", "reviewRequest"))
                or type(sealed_input.get("reviewSha256")) is not str
                or len(sealed_input["reviewSha256"]) != 64
                or not plan_child_id or not approved_at):
            raise ValueError("mixed append approval input differs")
        try:
            # Acquire the SQLite writer slot and keep the lease, parent, child,
            # and approval journal in the same transaction.
            held = CoreMutationLeaseModel.query.filter_by(
                engagement_id=parent.target_id,
                owner_id=parent.input["corePlanId"],
                operation="provider_keyed_mixed_append",
            ).update({"operation": "provider_keyed_mixed_append"},
                     synchronize_session=False)
            row = JobRunModel.query.filter_by(id=parent.id).one_or_none()
            child = JobRunModel.query.filter_by(
                id=plan_child_id, action="provider_keyed_mixed_append_plan_child",
                status="succeeded", target_id=parent.target_id,
            ).one_or_none()
            child_terminal = JobEventModel.query.filter_by(
                job_id=plan_child_id).order_by(JobEventModel.sequence.desc()).first()
            if (held != 1 or row is None or child is None
                    or self.get(parent.id) != parent
                    or child.input.get("appendParentId") != parent.id
                    or child.input.get("requestSha256") != parent.input["requestSha256"]
                    or child_terminal is None
                    or child_terminal.level != "info"
                    or child_terminal.message != "mixed append pair plan reviewed"
                    or child_terminal.data != {
                        "reviewSha256": sealed_input["reviewSha256"]}
                    or datetime.fromisoformat(parent.input["claimExpiresAt"])
                       <= datetime.fromisoformat(approved_at)):
                raise ValueError("mixed append claimed approval changed")
            # The approval claim only fences the read-only seal transaction.
            # Release it with the seal so host proof can claim the parent
            # immediately after the two provider Apply proofs complete.
            row.input = {key: value for key, value in sealed_input.items()
                         if key not in {"claimOwner", "claimToken",
                                        "claimClaimedAt", "claimHeartbeatAt",
                                        "claimExpiresAt"}}
            db.session.add(JobEventModel(
                job_id=parent.id, sequence=len(parent.events) + 1,
                level="info", message="mixed append pair approved",
                data={"reviewSha256": sealed_input["reviewSha256"],
                      "planChildId": plan_child_id},
            ))
            db.session.commit()
            return self.get(parent.id) or parent
        except Exception:
            db.session.rollback()
            raise

    def finish_mixed_append_review(self, parent: StoredJobRun,
                                   child: StoredJobRun, *, status: str,
                                   event: JobEvent, finished_at: str,
                                   review_summary: dict | None = None) -> StoredJobRun:
        """Finish one reviewed plan child under the exact parent claim and lease."""
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel, JobEventModel, JobRunModel

        if (db.engine.dialect.name != "sqlite"
                or parent.action != "provider_keyed_mixed_append"
                or parent.status != "running" or parent.input.get("phase") != "planning"
                or child.action != "provider_keyed_mixed_append_plan_child"
                or child.status != "running" or child.input.get("appendParentId") != parent.id
                or child.input.get("requestSha256") != parent.input.get("requestSha256")
                or status not in {"succeeded", "failed"}
                or event.sequence != len(child.events) + 1
                or (status == "succeeded" and (
                    event.level != "info" or event.message != "mixed append pair plan reviewed"
                    or set(event.data) != {"reviewSha256"}
                    or not re.fullmatch(r"[0-9a-f]{64}", event.data["reviewSha256"])))
                or (status == "failed" and (event.level != "error"
                    or event.message != "mixed append pair plan needs reconciliation"))
                or (status == "failed" and review_summary is not None)
                or (status == "succeeded" and (
                    type(review_summary) is not dict
                    or set(review_summary) != {"schema", "providerOrder", "plans", "outcome"}
                    or review_summary["schema"] != "mixed-append-pair-review-summary-v1"
                    or review_summary["providerOrder"] != parent.input.get("providerOrder")
                    or review_summary["outcome"] != "add one edge per provider; retain all existing nodes"
                    or type(review_summary["plans"]) is not list
                    or len(review_summary["plans"]) != 2
                    or any(type(plan) is not dict or set(plan) != {
                        "provider", "selectedChainId", "edgeRegion", "edgeSizeOrType",
                        "newEdgeAddress", "savedPlanSha256"}
                        or plan["provider"] != parent.input["providerOrder"][index]
                        or plan["selectedChainId"] != parent.input["reviewRequest"][plan["provider"]]["selectedChainId"]
                        or plan["edgeRegion"] != parent.input["reviewRequest"][plan["provider"]]["edgeRegion"]
                        or plan["edgeSizeOrType"] != parent.input["reviewRequest"][plan["provider"]][
                            "edgeSize" if plan["provider"] == "digitalocean" else "edgeType"]
                        or type(plan["newEdgeAddress"]) is not str
                        or not plan["newEdgeAddress"]
                        or type(plan["savedPlanSha256"]) is not str
                        or re.fullmatch(r"[0-9a-f]{64}", plan["savedPlanSha256"]) is None
                        for index, plan in enumerate(review_summary["plans"]))))):
            raise ValueError("mixed append plan terminal differs")
        try:
            held = CoreMutationLeaseModel.query.filter_by(
                engagement_id=parent.target_id,
                owner_id=parent.input["corePlanId"],
                operation="provider_keyed_mixed_append",
            ).update({"operation": "provider_keyed_mixed_append"},
                     synchronize_session=False)
            row = JobRunModel.query.filter_by(id=child.id).one_or_none()
            parent_row = JobRunModel.query.filter_by(id=parent.id).one_or_none()
            last = JobEventModel.query.filter_by(job_id=child.id).order_by(
                JobEventModel.sequence.desc()).first()
            if (held != 1 or row is None or parent_row is None
                    or self.get(parent.id) != parent or self.get(child.id) != child
                    or last is None or last.sequence + 1 != event.sequence
                    or datetime.fromisoformat(parent.input["claimExpiresAt"])
                       <= datetime.fromisoformat(finished_at)):
                raise ValueError("mixed append plan claim changed")
            row.status = status
            row.finished_at = _parse_datetime(finished_at)
            parent_row.input = {key: value for key, value in parent.input.items()
                                if key not in {"claimOwner", "claimToken",
                                               "claimClaimedAt", "claimHeartbeatAt",
                                               "claimExpiresAt"}}
            if status == "succeeded":
                parent_row.input = {**parent_row.input, "reviewSummary": review_summary}
            db.session.add(JobEventModel(
                job_id=child.id, sequence=event.sequence, level=event.level,
                message=event.message, data=event.data))
            db.session.commit()
            return self.get(child.id) or child
        except Exception:
            db.session.rollback()
            raise

    def retry_precommand_mixed_append_review(self, parent: StoredJobRun,
                                             child: StoredJobRun, *, recheck,
                                             requested_at: str, completed_plans_only: bool = False,
                                             completed_first_provider: str | None = None) -> StoredJobRun:
        """CAS one exactly fenced failed Review back to its existing worker queue."""
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel, JobRunModel, JobEventModel
        from app.services.provider_keyed_mixed_append_review_runtime import mixed_append_retry_choices
        if (db.engine.dialect.name != "sqlite" or not callable(recheck)
                or type(completed_plans_only) is not bool
                or completed_first_provider is not None and (
                    type(completed_first_provider) is not str or completed_plans_only
                    or completed_first_provider != parent.input["providerOrder"][0])):
            raise ValueError("append retry requires its local writer fence")
        try:
            held = CoreMutationLeaseModel.query.filter_by(
                engagement_id=parent.target_id, owner_id=parent.input["corePlanId"],
                operation="provider_keyed_mixed_append").update(
                    {"operation": "provider_keyed_mixed_append"}, synchronize_session=False)
            if (held != 1 or self.get(parent.id) != parent or self.get(child.id) != child
                    or mixed_append_retry_choices(parent, child, jobs=self) is None):
                raise ValueError("append retry source or lease changed")
            recheck()
            row = db.session.get(JobRunModel, child.id)
            row.status = "queued"
            row.started_at = None
            row.finished_at = None
            db.session.add(JobEventModel(job_id=child.id, sequence=len(child.events) + 1,
                level="info", message="mixed append pair Review retry requested",
                data=({"completedPlansOnly": True} if completed_plans_only else
                      {"completedFirstProvider": completed_first_provider} if completed_first_provider is not None else {}),
                created_at=_parse_datetime(requested_at)))
            db.session.commit()
            return self.get(child.id)
        except Exception:
            db.session.rollback()
            raise

    def renew_mixed_append_review_claim(self, parent: StoredJobRun, *,
                                        heartbeat_at: str, expires_at: str) -> StoredJobRun:
        """Renew only a live paired Review claim while its plan child runs."""
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel, JobRunModel

        if (parent.action != "provider_keyed_mixed_append"
                or parent.status != "running" or parent.input.get("phase") != "planning"
                or not parent.input.get("claimOwner")
                or not parent.input.get("claimToken")
                or datetime.fromisoformat(parent.input["claimExpiresAt"])
                   <= datetime.fromisoformat(heartbeat_at)
                or datetime.fromisoformat(expires_at)
                   <= datetime.fromisoformat(heartbeat_at)):
            raise ValueError("mixed append Review renewal differs")
        try:
            held = CoreMutationLeaseModel.query.filter_by(
                engagement_id=parent.target_id, owner_id=parent.input["corePlanId"],
                operation="provider_keyed_mixed_append").update(
                    {"operation": "provider_keyed_mixed_append"}, synchronize_session=False)
            row = JobRunModel.query.filter_by(id=parent.id).one_or_none()
            child = JobRunModel.query.filter_by(
                id=f"job-provider-keyed-mixed-append-plan-{parent.id.removeprefix('job-')}",
                action="provider_keyed_mixed_append_plan_child", status="running",
                target_id=parent.target_id).one_or_none()
            if (held != 1 or row is None or child is None
                    or self.get(parent.id) != parent
                    or child.input.get("requestSha256") != parent.input.get("requestSha256")):
                raise ValueError("mixed append Review claim changed")
            row.input = {**parent.input, "claimHeartbeatAt": heartbeat_at,
                         "claimExpiresAt": expires_at}
            db.session.commit()
            updated = self.get(parent.id)
            if updated is None:
                raise ValueError("mixed append Review renewal missing")
            return updated
        except Exception:
            db.session.rollback()
            raise

    def save_if_absent(self, job: StoredJobRun) -> StoredJobRun:
        from sqlalchemy.dialects.sqlite import insert

        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        _fence_append_binding_history(job)
        if db.engine.dialect.name != "sqlite":
            existing = self.get(job.id)
            return existing or self.save(job)
        if job.action in _MIXED_APPEND_APPLY_ACTIONS | {"provider_keyed_mixed_append"}:
            from sqlalchemy import text
            # Serialize the lease test with no-Apply teardown's writer slot.
            locked = db.session.execute(text("""
                UPDATE core_mutation_leases SET operation = operation
                WHERE engagement_id = :engagement AND owner_id = :plan
                  AND operation = 'provider_keyed_mixed_append'
            """), {"engagement": job.target_id, "plan": job.input.get("corePlanId")})
            if locked.rowcount != 1:
                db.session.rollback()
                raise ValueError("append reservation lost its mutation lease")
        values = {
            "id": job.id,
            "action": job.action,
            "status": job.status,
            "target": job.target,
            "target_type": job.target_type,
            "target_id": job.target_id,
            "requested_by": job.requested_by,
            "input": job.input,
            "artifact_refs": job.artifact_refs,
            "created_at": _parse_datetime(job.created_at),
            "started_at": None,
            "finished_at": None,
        }
        result = db.session.execute(insert(JobRunModel).values(**values).on_conflict_do_nothing(index_elements=["id"]))
        if result.rowcount:
            for event in job.events:
                db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence, level=event.level, message=event.message, data=event.data))
        db.session.commit()
        return self.get(job.id) or job

    def insert_inspector_teardown_barrier(self, job: StoredJobRun) -> StoredJobRun | None:
        """Atomically insert one initial job unless its opposing lifecycle is active."""
        from sqlalchemy import text
        from app.storage.database import db
        from app.storage.models import JobEventModel

        opponents = _inspector_barrier_opponents(job)
        if db.engine.dialect.name != "sqlite":
            raise RuntimeError("Inspector/teardown insert barrier requires SQLite")
        if job.action == _INSPECTOR_BARRIER_PARENT:
            existing = self.get(job.id)
            if existing is not None:
                return existing if existing.action == job.action and existing.target_id == job.target_id else None
        identity = current_request_identity()
        if identity is not None:
            job = replace(job, requested_by=identity.username)
        binds = ", ".join(f":op{i}" for i in range(len(opponents)))
        parameters = {
            "id": job.id, "action": job.action, "status": job.status,
            "target": job.target, "target_type": job.target_type, "target_id": job.target_id,
            "requested_by": job.requested_by,
            "input": json.dumps(job.input, sort_keys=True),
            "artifact_refs": json.dumps(job.artifact_refs, sort_keys=True),
            "created_at": _parse_datetime(job.created_at).isoformat(sep=" "),
            "started_at": _parse_datetime(job.started_at).isoformat(sep=" ") if job.started_at else None,
            **{f"op{i}": action for i, action in enumerate(opponents)},
        }
        try:
            inserted = db.session.execute(text(f"""
                INSERT OR IGNORE INTO job_runs
                  (id, action, status, target, target_type, target_id, requested_by,
                   input, artifact_refs, created_at, started_at, finished_at)
                SELECT :id, :action, :status, :target, :target_type, :target_id,
                       :requested_by, :input, :artifact_refs, :created_at, :started_at, NULL
                WHERE NOT EXISTS (
                  SELECT 1 FROM job_runs
                  WHERE target_type = 'engagement' AND target_id = :target_id
                    AND action IN ({binds}) AND status IN ('queued', 'running')
                )
            """), parameters)
            if inserted.rowcount != 1:
                db.session.rollback()
                existing = self.get(job.id) if job.action == _INSPECTOR_BARRIER_PARENT else None
                return existing if existing is not None and existing.action == job.action \
                    and existing.target_id == job.target_id else None
            if job.action == _INSPECTOR_BARRIER_PARENT:
                snapshot = job.input.get("scopeSnapshot")
                core_input = db.session.execute(
                    text("SELECT input FROM job_runs WHERE id = :core_id"),
                    {"core_id": job.input.get("coreJobId")},
                ).scalar_one_or_none()
                if core_input is not None:
                    core_values = json.loads(core_input)
                    keyed_core = (type(core_values) is dict
                                  and core_values.get("sketchStateSchema") == "provider-keyed-v2")
                else:
                    keyed_core = False
                keyed_snapshot = type(snapshot) is dict and "providerScopes" in snapshot
                if keyed_core or keyed_snapshot:
                    # The successful INSERT owns SQLite's writer slot. All
                    # DomainRepository reads below use this same db.session;
                    # no assignment writer can commit between them and COMMIT.
                    from app.services.engagement_teardown import (
                        _active_keyed_domain_assignments, _valid_keyed_domain_assignments,
                    )
                    from app.storage.domain_repository import SqlAlchemyDomainRepository

                    frozen = snapshot.get("domainAssignments") if type(snapshot) is dict else None
                    try:
                        current = _active_keyed_domain_assignments(
                            job.target_id, SqlAlchemyDomainRepository(),
                        )
                    except Exception:
                        raise KeyedDomainAssignmentConflict(
                            "keyed DNS assignments changed before teardown was queued"
                        ) from None
                    if (not keyed_core or not keyed_snapshot
                            or not _valid_keyed_domain_assignments(frozen)
                            or current != frozen):
                        raise KeyedDomainAssignmentConflict(
                            "keyed DNS assignments changed before teardown was queued")
            event = job.events[0]
            db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence,
                                         level=event.level, message=event.message, data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def take_over_mixed_core_apply_no_go(
        self, job: StoredJobRun, *, expected_event_digest: str,
        owner: str, token: str, claimed_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        """Atomically replace the expired claim and seal the abandoned start."""
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        if not _valid_mixed_core_apply_no_go_takeover(
                job, expected_event_digest=expected_event_digest, owner=owner,
                token=token, claimed_at=claimed_at, expires_at=expires_at):
            return None
        next_input = {**job.input, "claimOwner": owner, "claimToken": token,
                      "claimClaimedAt": claimed_at, "claimExpiresAt": expires_at}
        next_input.pop("claimHeartbeatAt", None)
        marker = JobEvent(len(job.events) + 1, "info", "mixed core pre-GO Apply recovery claimed", {
            "originalJournalSha256": expected_event_digest,
            "originalInvocationId": job.events[-2].data["invocationId"],
        })
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id,
                JobRunModel.action == "provider_keyed_mixed_zero_apply_core_destroy_apply",
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.created_at == _parse_datetime(job.created_at),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id,
                JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == [],
            ).values(input=next_input))
            if changed.rowcount != 1:
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=job.id, sequence=marker.sequence, level=marker.level,
                                         message=marker.message, data=marker.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def finish_mixed_core_absence_if_claimed(
        self, job: StoredJobRun, *, owner: str, token: str, lease_owner: str,
        expected_event_digest: str, status: str, finished_at: str, event: JobEvent,
        authority_check: Callable[[], None],
    ) -> StoredJobRun | None:
        """Seal a GET-only absence child under its claim and core fence."""
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        base = _mixed_absence_finish_base(job, owner, token, expected_event_digest, event)
        if (base is None or status not in {"succeeded", "failed"}
                or (status == "succeeded") != (event.level == "info")
                or not _valid_claimed_apply_times(job, at=finished_at)
                or not isinstance(lease_owner, str) or not lease_owner
                or not callable(authority_check)):
            return None
        try:
            # Discard a prior read transaction, then take SQLite's writer slot
            # without changing the child. The callback rereads historical
            # authority and the empty state under that same transaction.
            db.session.rollback()
            locked = db.session.execute(text("""
                UPDATE job_runs SET status = status
                WHERE id = :job_id AND action = :action AND status = 'running'
                  AND finished_at IS NULL
            """), {"job_id": job.id, "action": job.action})
            if locked.rowcount != 1:
                db.session.rollback()
                return None
            db.session.expire_all()
            authority_check()
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id, JobRunModel.action == job.action,
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.target_id == job.target_id,
                text("julianday(json_extract(input, '$.claimExpiresAt')) > julianday('now')"),
                text("EXISTS (SELECT 1 FROM core_mutation_leases "
                     "WHERE engagement_id = job_runs.target_id AND owner_id = :lease_owner "
                     "AND operation = 'provider_keyed_teardown_fence')"),
            ).values(input=base, status=status, finished_at=_parse_datetime(finished_at)),
                {"lease_owner": lease_owner})
            if changed.rowcount != 1:
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence,
                                         level=event.level, message=event.message,
                                         data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def finish_mixed_inspector_negative_if_running(
        self, job: StoredJobRun, *, lease_owner: str,
        expected_event_digest: str, finished_at: str, event: JobEvent,
        authority_check: Callable[[], None],
    ) -> StoredJobRun | None:
        """Prime read-only evidence before the terminal writer transaction."""
        from app.services.provider_keyed_host_proof_verdicts import host_proof_verdict_scope
        from app.services.provider_keyed_readonly_verification import readonly_verification_scope
        from app.storage.database import db
        if (job.action != "provider_keyed_mixed_zero_apply_inspector_negative"
                or job.status != "running" or job.started_at is None
                or job.finished_at is not None or len(job.events) != 2
                or event != JobEvent(3, "info",
                                     "mixed Inspector exact public negative proved", event.data)
                or job_event_digest(job.events) != expected_event_digest
                or not lease_owner or not callable(authority_check)):
            return None
        db.session.rollback()
        try:
            with host_proof_verdict_scope() as proofs, readonly_verification_scope() as commands:
                authority_check()
                proofs.require_hits_only()
                commands.require_hits_only()
                return self._finish_mixed_inspector_negative_if_running(
                    job, lease_owner=lease_owner, expected_event_digest=expected_event_digest,
                    finished_at=finished_at, event=event, authority_check=authority_check)
        except Exception:
            db.session.rollback()
            raise

    def _finish_mixed_inspector_negative_if_running(
        self, job: StoredJobRun, *, lease_owner: str,
        expected_event_digest: str, finished_at: str, event: JobEvent,
        authority_check: Callable[[], None],
    ) -> StoredJobRun | None:
        """Seal the mixed Inspector result with authority under SQLite's writer slot."""
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        if (job.action != "provider_keyed_mixed_zero_apply_inspector_negative"
                or job.status != "running" or job.started_at is None
                or job.finished_at is not None or len(job.events) != 2
                or event != JobEvent(3, "info",
                                     "mixed Inspector exact public negative proved", event.data)
                or job_event_digest(job.events) != expected_event_digest
                or not lease_owner or not callable(authority_check)):
            return None
        try:
            db.session.rollback()
            locked = db.session.execute(text("""
                UPDATE job_runs SET status = status
                WHERE id = :job_id AND action = :action AND status = 'running'
                  AND finished_at IS NULL
            """), {"job_id": job.id, "action": job.action})
            if locked.rowcount != 1:
                db.session.rollback()
                return None
            db.session.expire_all()
            authority_check()
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id, JobRunModel.action == job.action,
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                JobRunModel.input == job.input,
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.target_id == job.target_id,
                text("EXISTS (SELECT 1 FROM core_mutation_leases "
                     "WHERE engagement_id = job_runs.target_id AND owner_id = :lease_owner "
                     "AND operation = 'provider_keyed_teardown_fence')"),
            ).values(status="succeeded", finished_at=_parse_datetime(finished_at)),
                {"lease_owner": lease_owner})
            if changed.rowcount != 1:
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence,
                                         level=event.level, message=event.message,
                                         data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def publish_keyed_provider_absent_if_ready(
        self, job: StoredJobRun, *, expected_event_digest: str,
        proof: dict, authority: Callable[[], None],
    ) -> StoredJobRun | None:
        """One SQLite writer transaction seals point-in-time provider absence.

        The callback rereads the parent, lease, saved apply, retained workspace,
        and desired chain intent under this transaction. It must not perform
        provider GET or any mutation.
        """
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        boundary = _inspector_prefix_boundary(job, self.get)
        if boundary is None:
            return None
        if (db.session.get_bind().dialect.name != "sqlite"
                or not callable(authority)
                or not _valid_provider_absent_handoff(job, expected_event_digest, proof, boundary[0])):
            return None
        next_input = {**job.input, "phase": "provider_absent"}
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id,
                JobRunModel.action == "provider_keyed_comprehensive_teardown",
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.created_at == _parse_datetime(job.created_at),
                JobRunModel.target == job.target,
                JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id,
                JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == [],
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                text("julianday('now') >= julianday(json_extract(job_runs.input, '$.claimExpiresAt'))"),
                text("julianday('now') >= julianday(:absence_completed) AND "
                     "julianday('now') < julianday(:absence_expires)").bindparams(
                         absence_completed=proof["confirmationCompletedAt"],
                         absence_expires=proof["confirmationExpiresAt"]),
            ).values(input=next_input))
            if changed.rowcount != 1:
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if (not _claimed_apply_journal_matches(rows, job, expected_event_digest)
                    or not _inspector_prefix_still_matches(job, boundary, self.get)):
                db.session.rollback()
                return None
            db.session.expire_all()
            authority()
            observed = db.session.execute(text(
                "SELECT strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now')"
            )).scalar_one()
            observed_in_window = db.session.execute(text(
                "SELECT julianday(:completed) <= julianday(:observed) "
                "AND julianday(:observed) < julianday(:expires)"
            ), {"completed": proof["confirmationCompletedAt"],
                "observed": observed,
                "expires": proof["confirmationExpiresAt"]}).scalar_one()
            if observed_in_window != 1:
                db.session.rollback()
                return None
            db.session.add(JobEventModel(
                job_id=job.id, sequence=len(job.events) + 1, level="info",
                message="provider_absent", data={**proof, "observedAt": observed},
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def heartbeat_keyed_inspector_preparation_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str, claimed_at: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        """Renew only the exact original prepare-intent journal and live claim."""
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobRunModel

        boundary = _inspector_prefix_boundary(job, self.get)
        if boundary is None:
            return None
        if not _valid_keyed_inspector_prepare_heartbeat(
            job, owner=owner, token=token, claimed_at=claimed_at,
            expected_event_digest=expected_event_digest,
            heartbeat_at=heartbeat_at, expires_at=expires_at,
            queued_data=boundary[0],
        ):
            return None
        updated_input = {**job.input, "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at}
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id,
                JobRunModel.action == "provider_keyed_comprehensive_teardown",
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.created_at == _parse_datetime(job.created_at),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id, JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == [],
                text("julianday('now') < julianday(json_extract(job_runs.input, '$.claimExpiresAt'))"),
                text("julianday(:new_expiry) > julianday('now') "
                     "AND julianday(:new_expiry) <= julianday('now', '+5 minutes')")
                     .bindparams(new_expiry=expires_at),
            ).values(input=updated_input))
            if changed.rowcount != 1:
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if (not _claimed_apply_journal_matches(rows, job, expected_event_digest)
                    or not _inspector_prefix_still_matches(job, boundary, self.get)):
                db.session.rollback()
                return None
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def transition_retained_inspector_if_running(
        self, job: StoredJobRun, *, mode: str, expected_event_digest: str,
        owner: str, token: str, at: str, expires_at: str,
        event: JobEvent | None = None, authority: Callable[[], None] | None = None,
    ) -> StoredJobRun | None:
        """Four-event retained-host claim, heartbeat, or one-shot ready handoff."""
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        boundary = _inspector_prefix_boundary(job, self.get)
        if boundary is None:
            return None
        next_input = _retained_transition_input(
            job, mode=mode, expected_event_digest=expected_event_digest,
            owner=owner, token=token, at=at, expires_at=expires_at, event=event, queued_data=boundary[0])
        if (next_input is None or db.session.get_bind().dialect.name != "sqlite"
                or (mode == "ready" and authority is None)):
            return None
        clock_condition = (
            "julianday('now') >= julianday(json_extract(job_runs.input, '$.claimExpiresAt'))"
            if mode == "claim" else
            "julianday('now') < julianday(json_extract(job_runs.input, '$.claimExpiresAt'))"
        )
        try:
            conditions = [
                JobRunModel.id == job.id,
                JobRunModel.action == "provider_keyed_comprehensive_teardown",
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.created_at == _parse_datetime(job.created_at),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id,
                JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == [],
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                text(clock_condition),
            ]
            if mode != "ready":
                conditions.append(text(
                    "julianday(:retained_expiry) > julianday('now') AND "
                    "julianday(:retained_expiry) <= julianday('now', '+5 minutes')"
                ).bindparams(retained_expiry=expires_at))
            changed = db.session.execute(update(JobRunModel).where(*conditions).values(input=next_input))
            if changed.rowcount != 1:
                db.session.rollback()
                return None
            if mode == "ready":
                db.session.execute(text("""
                    UPDATE job_runs SET input = json_set(
                        input,
                        '$.claimClaimedAt', strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now'),
                        '$.claimHeartbeatAt', strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now'),
                        '$.claimExpiresAt', strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now')
                    ) WHERE id = :job_id
                """), {"job_id": job.id})
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if (not _claimed_apply_journal_matches(rows, job, expected_event_digest)
                    or not _inspector_prefix_still_matches(job, boundary, self.get)):
                db.session.rollback()
                return None
            if mode == "ready":
                db.session.expire_all()
                authority()
                db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence,
                                             level=event.level, message=event.message,
                                             data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def heartbeat_keyed_inspector_submission_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str, claimed_at: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        """Renew only a complete submitted-Inspector journal under its DB-live claim."""
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobRunModel

        boundary = _inspector_prefix_boundary(job, self.get)
        if boundary is None:
            return None
        if not _valid_completed_inspector_submission_heartbeat(
            job, owner=owner, token=token, claimed_at=claimed_at,
            expected_event_digest=expected_event_digest,
            heartbeat_at=heartbeat_at, expires_at=expires_at,
            queued_data=boundary[0],
        ):
            return None
        updated_input = {**job.input, "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at}
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id,
                JobRunModel.action == "provider_keyed_comprehensive_teardown",
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.created_at == _parse_datetime(job.created_at),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id, JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == [],
                text("julianday('now') < julianday(json_extract(job_runs.input, '$.claimExpiresAt'))"),
            ).values(input=updated_input))
            if changed.rowcount != 1:
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if (not _claimed_apply_journal_matches(rows, job, expected_event_digest)
                    or not _inspector_prefix_still_matches(job, boundary, self.get)):
                db.session.rollback()
                return None
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def start_if_queued(self, job: StoredJobRun, *, started_at: str, event: JobEvent) -> StoredJobRun | None:
        """Claim an exact queued job and append its start event atomically."""
        from sqlalchemy import func, update, text

        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        if (job.status != "queued" or job.started_at is not None or job.finished_at is not None
                or not started_at or event.sequence != len(job.events) + 1):
            return None
        try:
            result = db.session.execute(
                update(JobRunModel).where(
                    JobRunModel.id == job.id, JobRunModel.action == job.action,
                    JobRunModel.input == job.input, JobRunModel.status == "queued",
                    JobRunModel.started_at.is_(None), JobRunModel.finished_at.is_(None),
                    text(_MIXED_APPEND_BOOKKEEPING_LEASE_SQL) if db.engine.dialect.name == "sqlite" else True,
                ).values(status="running", started_at=_parse_datetime(started_at))
            )
            if result.rowcount != 1:
                db.session.rollback()
                return None
            last_sequence = db.session.query(func.max(JobEventModel.sequence)).filter_by(job_id=job.id).scalar() or 0
            if last_sequence + 1 != event.sequence:
                db.session.rollback()
                return None
            db.session.add(JobEventModel(
                job_id=job.id, sequence=event.sequence, level=event.level,
                message=event.message, data=event.data,
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def append_destroy_preview_event_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        """Append one redacted v2 destroy-preview event under its exact claim."""
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        if (_claimed_destroy_preview_base(job, owner, token) is None
                or not _valid_claimed_apply_times(job, at=heartbeat_at, next_expiry=expires_at)
                or not isinstance(expected_event_digest, str)
                or event.sequence != len(job.events) + 1):
            return None
        updated_input = {**job.input, "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at}
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id, JobRunModel.action == "provider_keyed_initial_destroy_plan",
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.created_at == _parse_datetime(job.created_at),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id,
                JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == [],
            ).values(input=updated_input))
            if changed.rowcount != 1 or not _destroy_preview_claim_unexpired_at_write(job):
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence,
                                         level=event.level, message=event.message, data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def finish_destroy_preview_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, status: str, finished_at: str,
        event: JobEvent, artifact_ref: str | None = None,
    ) -> StoredJobRun | None:
        """Atomically finish the exact claim, journal and saved-plan reference."""
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        base = _claimed_destroy_preview_base(job, owner, token)
        if (base is None or not _valid_claimed_apply_times(job, at=finished_at)
                or not _valid_keyed_destroy_finish(
                    replace(job, input=base), expected_event_digest=expected_event_digest,
                    status=status, finished_at=finished_at, event=event, artifact_ref=artifact_ref)):
            return None
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id, JobRunModel.action == "provider_keyed_initial_destroy_plan",
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.created_at == _parse_datetime(job.created_at),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id,
                JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == [],
            ).values(input=base, status=status, finished_at=_parse_datetime(finished_at),
                     artifact_refs=[artifact_ref] if artifact_ref is not None else []))
            if changed.rowcount != 1 or not _destroy_preview_claim_unexpired_at_write(job):
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence,
                                         level=event.level, message=event.message, data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def append_destroy_apply_event_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        """Append one redacted v2 destroy-apply event under its exact claim."""
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        if (_claimed_destroy_apply_base(job, owner, token) is None
                or not _valid_claimed_apply_times(job, at=heartbeat_at, next_expiry=expires_at)
                or not isinstance(expected_event_digest, str)
                or event.sequence != len(job.events) + 1):
            return None
        updated_input = {**job.input, "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at}
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id, JobRunModel.action == "provider_keyed_initial_destroy_apply",
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.created_at == _parse_datetime(job.created_at),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id,
                JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == [],
            ).values(input=updated_input))
            if changed.rowcount != 1 or not _destroy_preview_claim_unexpired_at_write(job):
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence,
                                         level=event.level, message=event.message, data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def finish_destroy_apply_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, status: str, finished_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        """Atomically finish an exact claimed destroy apply and its journal."""
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        base = _claimed_destroy_apply_base(job, owner, token)
        if (base is None or not _valid_claimed_apply_times(job, at=finished_at)
                or not _valid_destroy_apply_finish(
                    job, expected_event_digest=expected_event_digest,
                    status=status, finished_at=finished_at, event=event)):
            return None
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id, JobRunModel.action == "provider_keyed_initial_destroy_apply",
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.created_at == _parse_datetime(job.created_at),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id,
                JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == [],
            ).values(input=base, status=status, finished_at=_parse_datetime(finished_at)))
            if changed.rowcount != 1 or not _destroy_preview_claim_unexpired_at_write(job):
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence,
                                         level=event.level, message=event.message, data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def take_over_initial_destroy_apply_pre_go(
        self, job: StoredJobRun, *, expected_event_digest: str,
        owner: str, token: str, claimed_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        """Atomically replace only an expired exact nine-event DO claim."""
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobRunModel

        if not _valid_initial_destroy_pre_go_takeover(
            job, expected_event_digest=expected_event_digest,
            owner=owner, token=token, claimed_at=claimed_at, expires_at=expires_at,
        ):
            return None
        next_input = {**job.input, "claimOwner": owner, "claimToken": token,
                      "claimClaimedAt": claimed_at, "claimExpiresAt": expires_at}
        next_input.pop("claimHeartbeatAt", None)
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id,
                JobRunModel.action == "provider_keyed_initial_destroy_apply",
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.created_at == _parse_datetime(job.created_at),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id,
                JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == [],
            ).values(input=next_input))
            if changed.rowcount != 1:
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                db.session.rollback()
                return None
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def take_over_mixed_core_show(
        self, job: StoredJobRun, *, expected_event_digest: str,
        owner: str, token: str, claimed_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        """CAS the expired claim and append the sole recovery marker together."""
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        if not _valid_mixed_core_show_takeover(
            job, expected_event_digest=expected_event_digest, owner=owner,
            token=token, claimed_at=claimed_at, expires_at=expires_at,
        ):
            return None
        next_input = {**job.input, "claimOwner": owner, "claimToken": token,
                      "claimClaimedAt": claimed_at, "claimExpiresAt": expires_at}
        next_input.pop("claimHeartbeatAt", None)
        marker = JobEvent(len(job.events) + 1, "info", "mixed core SHOW recovery claimed", {
            "originalJournalSha256": expected_event_digest,
            "originalInvocationId": job.events[2].data["invocationId"],
        })
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id,
                JobRunModel.action == "provider_keyed_mixed_zero_apply_core_destroy_apply",
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.created_at == _parse_datetime(job.created_at),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id,
                JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == [],
            ).values(input=next_input))
            if changed.rowcount != 1:
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=job.id, sequence=marker.sequence,
                                         level=marker.level, message=marker.message,
                                         data=marker.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def take_over_core_destroy_apply_pre_go(
        self, job: StoredJobRun, *, expected_event_digest: str,
        owner: str, token: str, claimed_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        """CAS an expired five-event show-only child into a fresh claim."""
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobRunModel

        if not _valid_core_destroy_pre_go_takeover(
            job, expected_event_digest=expected_event_digest,
            owner=owner, token=token, claimed_at=claimed_at, expires_at=expires_at,
        ):
            return None
        next_input = {**job.input, "claimOwner": owner, "claimToken": token,
                      "claimClaimedAt": claimed_at, "claimExpiresAt": expires_at}
        next_input.pop("claimHeartbeatAt", None)
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id, JobRunModel.action == "provider_keyed_core_destroy_apply",
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.created_at == _parse_datetime(job.created_at),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id,
                JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == [],
            ).values(input=next_input))
            if changed.rowcount != 1:
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                db.session.rollback()
                return None
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def append_core_destroy_apply_event_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        """Append one redacted v2 core-destroy-apply event under its exact claim."""
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        if (_claimed_core_destroy_apply_base(job, owner, token) is None
                or not _valid_claimed_apply_times(job, at=heartbeat_at, next_expiry=expires_at)
                or not isinstance(expected_event_digest, str)
                or event.sequence != len(job.events) + 1):
            return None
        updated_input = {**job.input, "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at}
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id, JobRunModel.action == job.action,
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.created_at == _parse_datetime(job.created_at),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id,
                JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == [],
            ).values(input=updated_input))
            if changed.rowcount != 1 or not _destroy_preview_claim_unexpired_at_write(job):
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence,
                                         level=event.level, message=event.message, data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def append_selector_retirement_event_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        if (_claimed_selector_retirement_base(job, owner, token) is None
                or not _valid_claimed_apply_times(job, at=heartbeat_at, next_expiry=expires_at)
                or not _valid_selector_retirement_event(job, event, terminal=False)):
            return None
        updated_input = {**job.input, "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at}
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id, JobRunModel.action == "provider_keyed_selector_retirement",
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.created_at == _parse_datetime(job.created_at),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id, JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == [],
            ).values(input=updated_input))
            if changed.rowcount != 1 or not _destroy_preview_claim_unexpired_at_write(job):
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence,
                                         level=event.level, message=event.message, data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def finish_selector_retirement_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, finished_at: str, event: JobEvent,
    ) -> StoredJobRun | None:
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        base = _claimed_selector_retirement_base(job, owner, token)
        if (base is None or not _valid_claimed_apply_times(job, at=finished_at)
                or not _valid_selector_retirement_event(job, event, terminal=True)):
            return None
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id, JobRunModel.action == "provider_keyed_selector_retirement",
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.created_at == _parse_datetime(job.created_at),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id, JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == [],
            ).values(input=base, status="succeeded", finished_at=_parse_datetime(finished_at)))
            if changed.rowcount != 1 or not _destroy_preview_claim_unexpired_at_write(job):
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence,
                                         level=event.level, message=event.message, data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def finish_core_destroy_apply_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, status: str, finished_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        """Atomically finish an exact claimed destroy apply and its journal."""
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        base = _claimed_core_destroy_apply_base(job, owner, token)
        if (base is None or not _valid_claimed_apply_times(job, at=finished_at)
                or not _valid_core_destroy_apply_finish(
                    job, expected_event_digest=expected_event_digest,
                    status=status, finished_at=finished_at, event=event)):
            return None
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id, JobRunModel.action == job.action,
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.created_at == _parse_datetime(job.created_at),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id,
                JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == [],
            ).values(input=base, status=status, finished_at=_parse_datetime(finished_at)))
            if changed.rowcount != 1 or not _destroy_preview_claim_unexpired_at_write(job):
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence,
                                         level=event.level, message=event.message, data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def append_keyed_inspector_create_intent_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        """Fence one Inspector create intent and advance the coordinator phase."""
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        boundary = _inspector_prefix_boundary(job, self.get)
        if boundary is None:
            return None
        if not _valid_keyed_inspector_intent(
            job, owner=owner, token=token, expected_event_digest=expected_event_digest,
            heartbeat_at=heartbeat_at, expires_at=expires_at, event=event,
            queued_data=boundary[0],
        ):
            return None
        updated_input = {**job.input, "phase": "inspector_create_started",
                         "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at}
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id,
                JobRunModel.action == "provider_keyed_comprehensive_teardown",
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.created_at == _parse_datetime(job.created_at),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id,
                JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == [],
                text("julianday('now') < julianday(json_extract(job_runs.input, '$.claimExpiresAt'))"),
            ).values(input=updated_input))
            if changed.rowcount != 1:
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if (not _claimed_apply_journal_matches(rows, job, expected_event_digest)
                    or not _inspector_prefix_still_matches(job, boundary, self.get)):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence,
                                         level=event.level, message=event.message, data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def append_keyed_inspector_stage_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        """Append one exact opt-in Inspector provider stage under its live claim."""
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        boundary = _inspector_prefix_boundary(job, self.get)
        if boundary is None:
            return None
        if not _valid_inspector_stage_prefix(
            job, owner=owner, token=token, expected_event_digest=expected_event_digest,
            heartbeat_at=heartbeat_at, expires_at=expires_at, event=event,
            queued_data=boundary[0],
        ):
            return None
        updated_input = {**job.input, "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at}
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id,
                JobRunModel.action == "provider_keyed_comprehensive_teardown",
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.created_at == _parse_datetime(job.created_at),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id,
                JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == [],
                text("julianday('now') < julianday(json_extract(job_runs.input, '$.claimExpiresAt'))"),
            ).values(input=updated_input))
            if changed.rowcount != 1:
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if (not _claimed_apply_journal_matches(rows, job, expected_event_digest)
                    or not _inspector_prefix_still_matches(job, boundary, self.get)):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence,
                                         level=event.level, message=event.message, data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def finish_if_running_with_journal_digest(
        self, job: StoredJobRun, *, expected_event_digest: str, status: str,
        finished_at: str, event: JobEvent, artifact_ref: str | None = None,
    ) -> StoredJobRun | None:
        """Finish only the exact keyed destroy-plan row and full prior journal."""
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        if not _valid_keyed_destroy_finish(
            job, expected_event_digest=expected_event_digest, status=status,
            finished_at=finished_at, event=event, artifact_ref=artifact_ref,
        ):
            return None
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id,
                JobRunModel.action == "provider_keyed_initial_destroy_plan",
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id,
                JobRunModel.requested_by == job.requested_by,
                JobRunModel.created_at == _parse_datetime(job.created_at),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.artifact_refs == [],
            ).values(status=status, finished_at=_parse_datetime(finished_at),
                     artifact_refs=[artifact_ref] if artifact_ref is not None else []))
            if changed.rowcount != 1:
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence,
                                         level=event.level, message=event.message, data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def finish_if_running(
        self, job: StoredJobRun, *, status: str, finished_at: str, event: JobEvent,
    ) -> StoredJobRun | None:
        """Atomically finish only the exact running job generation."""
        from sqlalchemy import func, update

        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        if (status not in {"succeeded", "failed"} or job.status != "running"
                or not job.started_at or job.finished_at is not None or not finished_at
                or event.sequence != len(job.events) + 1):
            return None
        try:
            result = db.session.execute(
                update(JobRunModel).where(
                    JobRunModel.id == job.id, JobRunModel.action == job.action,
                    JobRunModel.input == job.input, JobRunModel.status == "running",
                    JobRunModel.started_at == _parse_datetime(job.started_at),
                    JobRunModel.finished_at.is_(None),
                ).values(status=status, finished_at=_parse_datetime(finished_at))
            )
            if result.rowcount != 1:
                db.session.rollback()
                return None
            last_sequence = db.session.query(func.max(JobEventModel.sequence)).filter_by(job_id=job.id).scalar() or 0
            if last_sequence + 1 != event.sequence:
                db.session.rollback()
                return None
            db.session.add(JobEventModel(
                job_id=job.id, sequence=event.sequence, level=event.level,
                message=event.message, data=event.data,
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def append_event_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        if (_claimed_apply_base(job, owner, token, allow_mixed_append_host=True) is None
                or not _valid_claimed_apply_times(job, at=heartbeat_at, next_expiry=expires_at)
                or not isinstance(expected_event_digest, str)
                or event.sequence != len(job.events) + 1):
            return None
        updated_input = {**job.input, "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at}
        lease_condition = ([text("""EXISTS (SELECT 1 FROM core_mutation_leases
            WHERE engagement_id = job_runs.target_id AND owner_id = :mixed_lease_owner
              AND operation = :mixed_lease_operation)""").bindparams(
                mixed_lease_operation=("provider_keyed_teardown_fence"
                    if job.action in {"provider_keyed_mixed_interrupted_destroy_apply",
                                      "provider_keyed_mixed_published_destroy_apply",
                                      "provider_keyed_mixed_interrupted_plan_worker",
                                      "provider_keyed_mixed_interrupted_selector_retirement",
                                      "provider_keyed_mixed_published_selector_retirement"}
                    else "provider_keyed_mixed_append"
                    if job.action in _MIXED_APPEND_APPLY_ACTIONS
                    else "provider_keyed_initial"),
                mixed_lease_owner=job.input["corePlanId"])]
            if job.action in {"provider_keyed_mixed_initial_apply_child",
                              *_MIXED_APPEND_APPLY_ACTIONS,
                              "provider_keyed_mixed_initial_host_worker",
                              "provider_keyed_mixed_initial_strict_host_proof",
                              "provider_keyed_mixed_linode_diagnostic",
                              "provider_keyed_mixed_linode_raw_diagnostic",
                              "provider_keyed_mixed_interrupted_plan_worker",
                              "provider_keyed_mixed_interrupted_destroy_apply",
                              "provider_keyed_mixed_published_destroy_apply",
                              "provider_keyed_mixed_interrupted_selector_retirement",
                              "provider_keyed_mixed_published_selector_retirement"} else [])
        if job.action == "provider_keyed_mixed_append_pair_host_proof":
            lease_condition = [_mixed_append_host_lease_condition(job, owner, token)]
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id, JobRunModel.action == job.action,
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id, JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == job.artifact_refs,
                JobRunModel.created_at == _parse_datetime(job.created_at),
                *lease_condition,
            ).values(input=updated_input))
            if changed.rowcount != 1:
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence,
                                         level=event.level, message=event.message, data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def finish_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, status: str, finished_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        from sqlalchemy import text, update
        from app.storage.database import db
        from app.storage.models import JobEventModel, JobRunModel

        base = _claimed_apply_base(job, owner, token, allow_mixed_append_host=True)
        if (base is None or status not in {"succeeded", "failed"}
                or not _valid_claimed_apply_times(job, at=finished_at)
                or not isinstance(expected_event_digest, str)
                or event.sequence != len(job.events) + 1):
            return None
        lease_condition = ([text("""EXISTS (SELECT 1 FROM core_mutation_leases
            WHERE engagement_id = job_runs.target_id AND owner_id = :mixed_lease_owner
              AND operation = :mixed_lease_operation)""").bindparams(
                mixed_lease_operation=("provider_keyed_teardown_fence"
                    if job.action in {"provider_keyed_mixed_interrupted_destroy_apply",
                                      "provider_keyed_mixed_published_destroy_apply",
                                      "provider_keyed_mixed_interrupted_plan_worker",
                                      "provider_keyed_mixed_interrupted_selector_retirement",
                                      "provider_keyed_mixed_published_selector_retirement"}
                    else "provider_keyed_mixed_append"
                    if job.action in _MIXED_APPEND_APPLY_ACTIONS
                    else "provider_keyed_initial"),
                mixed_lease_owner=job.input["corePlanId"])]
            if job.action in {"provider_keyed_mixed_initial_apply_child",
                              *_MIXED_APPEND_APPLY_ACTIONS,
                              "provider_keyed_mixed_initial_host_worker",
                              "provider_keyed_mixed_initial_strict_host_proof",
                              "provider_keyed_mixed_linode_diagnostic",
                              "provider_keyed_mixed_linode_raw_diagnostic",
                              "provider_keyed_mixed_interrupted_plan_worker",
                              "provider_keyed_mixed_interrupted_destroy_apply",
                              "provider_keyed_mixed_published_destroy_apply",
                              "provider_keyed_mixed_interrupted_selector_retirement",
                              "provider_keyed_mixed_published_selector_retirement"} else [])
        if job.action == "provider_keyed_mixed_append_pair_host_proof":
            lease_condition = [_mixed_append_host_lease_condition(job, owner, token)]
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == job.id, JobRunModel.action == job.action,
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, job.input),
                JobRunModel.started_at == _parse_datetime(job.started_at),
                JobRunModel.target == job.target, JobRunModel.target_type == job.target_type,
                JobRunModel.target_id == job.target_id, JobRunModel.requested_by == job.requested_by,
                JobRunModel.artifact_refs == job.artifact_refs,
                JobRunModel.created_at == _parse_datetime(job.created_at),
                *lease_condition,
            ).values(input=base, status=status, finished_at=_parse_datetime(finished_at)))
            if changed.rowcount != 1:
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence,
                                         level=event.level, message=event.message, data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def append_mixed_interrupted_selector_retirement_event_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        if (_claimed_apply_base(job, owner, token) is None
                or not _valid_mixed_interrupted_selector_event(job, event, terminal=False)):
            return None
        return self.append_event_if_running_claimed(
            job, owner=owner, token=token,
            expected_event_digest=expected_event_digest,
            heartbeat_at=heartbeat_at, expires_at=expires_at, event=event)

    def finish_mixed_interrupted_selector_retirement_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, finished_at: str, event: JobEvent,
    ) -> StoredJobRun | None:
        if (_claimed_apply_base(job, owner, token) is None
                or not _valid_mixed_interrupted_selector_event(job, event, terminal=True)):
            return None
        return self.finish_if_running_claimed(
            job, owner=owner, token=token,
            expected_event_digest=expected_event_digest, status="succeeded",
            finished_at=finished_at, event=event)

    def append_mixed_published_selector_retirement_event_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        if (_claimed_apply_base(job, owner, token) is None
                or not _valid_mixed_published_selector_event(job, event, terminal=False)):
            return None
        return self.append_event_if_running_claimed(
            job, owner=owner, token=token,
            expected_event_digest=expected_event_digest,
            heartbeat_at=heartbeat_at, expires_at=expires_at, event=event)

    def finish_mixed_published_selector_retirement_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, finished_at: str, event: JobEvent,
    ) -> StoredJobRun | None:
        if (_claimed_apply_base(job, owner, token) is None
                or not _valid_mixed_published_selector_event(job, event, terminal=True)):
            return None
        return self.finish_if_running_claimed(
            job, owner=owner, token=token,
            expected_event_digest=expected_event_digest, status="succeeded",
            finished_at=finished_at, event=event)

    def approve_provider_keyed_edge_append_apply(
        self, parent: StoredJobRun, plan: StoredJobRun, *, plan_sha256: str,
        requested_by: str, requested_at: str,
    ) -> StoredJobRun | None:
        """Atomically record one operator click against the exact reviewed child.

        This is approval metadata on the existing parent, not a Terraform
        command or a second parent. A process crash after this commit can be
        resumed without treating every reviewed plan as approved.
        """
        from sqlalchemy import text
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel, JobEventModel
        from app.services.provider_keyed_append_plan_job import (
            _only_attested_historical_no_go_apply_children,
        )

        if (db.engine.dialect.name != "sqlite"
                or parent.action != "provider_keyed_edge_append"
                or parent.status != "running" or parent.input.get("phase") != "awaiting_apply"
                or parent.input.get("claimToken") is not None
                or plan.action != "provider_keyed_edge_append_plan"
                or plan.status != "succeeded" or plan.id != parent.input.get("planJobId")
                or plan.input.get("parentJobId") != parent.id
                or parent.input.get("planJournalSha256") != job_event_digest(plan.events)
                or not plan.events or plan.events[-1].message != "reviewed append plan saved"
                or plan.events[-1].data.get("planSha256") != plan_sha256
                or not isinstance(requested_by, str) or not requested_by
                or not isinstance(requested_at, str) or not requested_at):
            return None
        try:
            db.session.rollback()
            # SQLite writer lock is shared with the plan/lease and job writer.
            locked = db.session.execute(text("""
                UPDATE deployment_plans SET status = status
                WHERE id = :plan AND engagement_id = :engagement
                  AND status = 'applied' AND apply_job_id = :core
            """), {"plan": parent.input.get("corePlanId"),
                   "engagement": parent.target_id,
                   "core": parent.input.get("coreJobId")})
            db.session.expire_all()
            lease = db.session.query(CoreMutationLeaseModel).filter_by(
                engagement_id=parent.target_id,
                owner_id=parent.input.get("corePlanId"),
                operation="provider_keyed_edge_append",
            ).one_or_none()
            current = self.get(parent.id)
            current_plan = self.get(plan.id)
            if (locked.rowcount != 1 or lease is None or current != parent
                    or current_plan != plan
                    or not _only_attested_historical_no_go_apply_children(parent, self)):
                db.session.rollback()
                return None
            approved = {**parent.input,
                        "applyRequestedPlanSha256": plan_sha256,
                        "applyRequestedBy": requested_by,
                        "applyRequestedAt": requested_at}
            changed = db.session.execute(text("""
                UPDATE job_runs SET input = :approved
                WHERE id = :parent AND status = 'running'
                  AND json_extract(input, '$.phase') = 'awaiting_apply'
                  AND json_extract(input, '$.applyRequestedPlanSha256') IS NULL
            """), {"approved": json.dumps(approved, sort_keys=True),
                     "parent": parent.id})
            if changed.rowcount != 1:
                db.session.rollback()
                return None
            db.session.add(JobEventModel(
                job_id=parent.id, sequence=len(parent.events) + 1,
                level="info", message="provider append Apply requested", data={
                    "planJobId": plan.id, "planSha256": plan_sha256,
                    "requestedBy": requested_by, "requestedAt": requested_at,
                }))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(parent.id)

    def claim_lease(
        self,
        job_id: str,
        *,
        owner: str,
        token: str,
        claimed_at: str,
        expires_at: str,
        eligible_statuses: set[str],
        eligible_phases: set[str] | None = None,
    ) -> StoredJobRun | None:
        from sqlalchemy import text

        from app.storage.database import db

        if not eligible_statuses or not _valid_eligible_phases(eligible_phases):
            return None
        status_parameters = {f"status_{index}": status for index, status in enumerate(sorted(eligible_statuses))}
        placeholders = ", ".join(f":{key}" for key in status_parameters)
        phase_parameters = {f"phase_{index}": phase for index, phase in enumerate(sorted(eligible_phases or ()))}
        phase_predicate = (
            "AND json_extract(input, '$.phase') IN ("
            + ", ".join(f":{key}" for key in phase_parameters) + ")"
        ) if eligible_phases is not None else ""
        result = db.session.execute(
            text(
                f"""
                UPDATE job_runs
                SET input = json_set(
                    input,
                    '$.claimOwner', :owner,
                    '$.claimToken', :token,
                    '$.claimClaimedAt', :claimed_at,
                    '$.claimHeartbeatAt', :claimed_at,
                    '$.claimExpiresAt', :expires_at
                )
                WHERE id = :job_id
                  AND status IN ({placeholders})
                  {phase_predicate}
                  AND (
                    json_extract(input, '$.claimToken') IS NULL
                    OR json_extract(input, '$.claimExpiresAt') IS NULL
                    OR julianday(json_extract(input, '$.claimExpiresAt')) IS NULL
                    OR json_extract(input, '$.claimExpiresAt') <= :claimed_at
                    OR (
                      json_extract(input, '$.claimOwner') = :owner
                      AND json_extract(input, '$.claimToken') = :token
                    )
                  )
                """ + (" AND " + _MIXED_APPEND_BOOKKEEPING_LEASE_SQL if db.engine.dialect.name == "sqlite" else "")
            ),
            {
                "job_id": job_id,
                "owner": owner,
                "token": token,
                "claimed_at": claimed_at,
                "expires_at": expires_at,
                **status_parameters,
                **phase_parameters,
            },
        )
        db.session.commit()
        return self.get(job_id) if result.rowcount == 1 else None

    def renew_lease(
        self,
        job_id: str,
        *,
        owner: str,
        token: str,
        heartbeat_at: str,
        expires_at: str,
    ) -> StoredJobRun | None:
        from sqlalchemy import text

        from app.storage.database import db

        result = db.session.execute(
            text(
                """
                UPDATE job_runs
                SET input = json_set(
                    input,
                    '$.claimHeartbeatAt', :heartbeat_at,
                    '$.claimExpiresAt', :expires_at
                )
                WHERE id = :job_id
                  AND status IN ('queued', 'running')
                  AND json_extract(input, '$.claimOwner') = :owner
                  AND json_extract(input, '$.claimToken') = :token
                """ + (" AND " + _MIXED_APPEND_BOOKKEEPING_LEASE_SQL if db.engine.dialect.name == "sqlite" else "")
            ),
            {
                "job_id": job_id,
                "owner": owner,
                "token": token,
                "heartbeat_at": heartbeat_at,
                "expires_at": expires_at,
            },
        )
        db.session.commit()
        return self.get(job_id) if result.rowcount == 1 else None

    def save_if_leased(
        self,
        job: StoredJobRun,
        *,
        owner: str,
        token: str,
    ) -> StoredJobRun | None:
        from sqlalchemy import text

        from app.storage.database import db
        from app.storage.models import JobEventModel

        result = db.session.execute(
            text(
                """
                UPDATE job_runs
                SET action = :action, status = :status, target = :target,
                    target_type = :target_type, target_id = :target_id,
                    requested_by = :requested_by, input = :input,
                    artifact_refs = :artifact_refs, created_at = :created_at,
                    started_at = :started_at, finished_at = :finished_at
                WHERE id = :job_id
                  AND json_extract(input, '$.claimOwner') = :owner
                  AND json_extract(input, '$.claimToken') = :token
                """
            ),
            {
                "job_id": job.id,
                "owner": owner,
                "token": token,
                "action": job.action,
                "status": job.status,
                "target": job.target,
                "target_type": job.target_type,
                "target_id": job.target_id,
                "requested_by": job.requested_by,
                "input": json.dumps(job.input, sort_keys=True),
                "artifact_refs": json.dumps(job.artifact_refs, sort_keys=True),
                "created_at": _parse_datetime(job.created_at),
                "started_at": _parse_datetime(job.started_at) if job.started_at else None,
                "finished_at": _parse_datetime(job.finished_at) if job.finished_at else None,
            },
        )
        if result.rowcount != 1:
            db.session.rollback()
            return None
        JobEventModel.query.filter_by(job_id=job.id).delete()
        for event in job.events:
            db.session.add(
                JobEventModel(
                    job_id=job.id,
                    sequence=event.sequence,
                    level=event.level,
                    message=event.message,
                    data=event.data,
                )
            )
        db.session.commit()
        return self.get(job.id)

    def append_mixed_plan_phase_if_claimed(
        self, job: StoredJobRun, *, owner: str, token: str, lease_owner: str,
        expected_event_digest: str, next_phase: str, event: JobEvent,
    ) -> StoredJobRun | None:
        """Append one mixed-plan checkpoint under claim and full journal CAS."""
        from sqlalchemy import text
        from app.storage.database import db
        from app.storage.models import JobEventModel

        if not _valid_mixed_plan_phase_append(
            job, owner=owner, token=token, lease_owner=lease_owner,
            digest=expected_event_digest,
            phase=next_phase, event=event,
        ):
            return None
        now = datetime.now(timezone.utc).isoformat()
        try:
            changed = db.session.execute(text("""
                UPDATE job_runs SET status = 'running', started_at = COALESCE(started_at, :now),
                    input = json_set(input, '$.phase', :next_phase,
                                     '$.claimExpiresAt', CASE WHEN :release = 1 THEN :now
                                                              ELSE json_extract(input, '$.claimExpiresAt') END)
                WHERE id = :job_id AND action = 'provider_keyed_mixed_initial'
                  AND status = :status AND finished_at IS NULL
                  AND json_extract(input, '$.phase') = :prior_phase
                  AND json_extract(input, '$.claimOwner') = :owner
                  AND json_extract(input, '$.claimToken') = :token
                  AND julianday(json_extract(input, '$.claimExpiresAt')) > julianday('now')
                  AND EXISTS (
                    SELECT 1 FROM core_mutation_leases
                    WHERE engagement_id = :engagement_id AND owner_id = :lease_owner
                      AND operation = 'provider_keyed_initial'
                  )
            """), {"now": now, "next_phase": next_phase,
                   "release": int(next_phase in {"both_plans_saved", "apply_sealed"}), "job_id": job.id,
                   "status": job.status, "prior_phase": job.input["phase"],
                   "owner": owner, "token": token,
                   "engagement_id": job.target_id, "lease_owner": lease_owner})
            if changed.rowcount != 1:
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence,
                                         level=event.level, message=event.message, data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def append_mixed_initial_handoff_if_claimed(
        self, job: StoredJobRun, *, owner: str, token: str, lease_owner: str,
        expected_event_digest: str, event: JobEvent,
    ) -> StoredJobRun | None:
        """CAS the sole typed mixed provider-to-host-proof checkpoint."""
        from sqlalchemy import text
        from app.storage.database import db
        from app.storage.models import JobEventModel

        if not _valid_mixed_initial_handoff_append(
            job, owner=owner, token=token, lease_owner=lease_owner,
            digest=expected_event_digest, event=event,
        ):
            return None
        now = datetime.now(timezone.utc).isoformat()
        try:
            changed = db.session.execute(text("""
                UPDATE job_runs SET
                    input = json_set(input, '$.phase', 'awaiting_mixed_host_proof',
                                     '$.claimExpiresAt', :now)
                WHERE id = :job_id AND action = 'provider_keyed_mixed_initial'
                  AND status = 'running' AND finished_at IS NULL
                  AND json_extract(input, '$.phase') = 'apply_sealed'
                  AND json_extract(input, '$.claimOwner') = :owner
                  AND json_extract(input, '$.claimToken') = :token
                  AND julianday(json_extract(input, '$.claimExpiresAt')) > julianday('now')
                  AND EXISTS (
                    SELECT 1 FROM core_mutation_leases
                    WHERE engagement_id = :engagement_id AND owner_id = :lease_owner
                      AND operation = 'provider_keyed_initial'
                  )
            """), {"now": now, "job_id": job.id, "owner": owner, "token": token,
                   "engagement_id": job.target_id, "lease_owner": lease_owner})
            if changed.rowcount != 1:
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                db.session.rollback()
                return None
            db.session.expire_all()
            if not _mixed_initial_handoff_children_match(job, event, self.get):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=job.id, sequence=event.sequence,
                                         level=event.level, message=event.message,
                                         data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job.id)

    def fence_terminal_provider_bootstrap_handoff(
        self, job_id: str, *, old_owner: str, old_token: str,
        new_owner: str, new_token: str, claimed_at: str, expires_at: str,
        expected_event_count: int, expected_event_digest: str,
        expected_final_message: str, confirmed_scope_sha256: str,
    ) -> StoredJobRun | None:
        """Fence the terminal bootstrap writer and append one audit event atomically."""
        from sqlalchemy import text
        from app.storage.database import db
        from app.storage.models import JobEventModel

        if not _handoff_arguments_valid(
            old_owner=old_owner, old_token=old_token, new_owner=new_owner,
            new_token=new_token, claimed_at=claimed_at, expires_at=expires_at,
            expected_event_count=expected_event_count,
            expected_event_digest=expected_event_digest,
            expected_final_message=expected_final_message,
            confirmed_scope_sha256=confirmed_scope_sha256,
        ):
            return None
        try:
            result = db.session.execute(text("""
                UPDATE job_runs SET input = json_set(
                    input, '$.phase', :phase, '$.claimOwner', :new_owner,
                    '$.claimToken', :new_token, '$.claimClaimedAt', :claimed_at,
                    '$.claimExpiresAt', :expires_at)
                WHERE id = :job_id AND action = 'provider_keyed_initial'
                  AND status = 'running' AND finished_at IS NULL
                  AND json_extract(input, '$.phase') = 'awaiting_strict_host_proof'
                  AND json_extract(input, '$.claimOwner') = :old_owner
                  AND json_extract(input, '$.claimToken') = :old_token
            """), {
                "job_id": job_id, "phase": _BOOTSTRAP_HANDOFF_PHASE,
                "old_owner": old_owner, "old_token": old_token,
                "new_owner": new_owner, "new_token": new_token,
                "claimed_at": claimed_at, "expires_at": expires_at,
            })
            if result.rowcount != 1:
                db.session.rollback()
                return None
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": job_id}).fetchall()
            if not _handoff_journal_matches(
                rows, expected_event_count=expected_event_count,
                expected_event_digest=expected_event_digest,
                expected_final_message=expected_final_message,
            ):
                db.session.rollback()
                return None
            db.session.add(JobEventModel(
                job_id=job_id, sequence=expected_event_count + 1, level="info",
                message=_BOOTSTRAP_HANDOFF_MESSAGE,
                data={"phase": _BOOTSTRAP_HANDOFF_PHASE,
                      "sourceEventSha256": expected_event_digest,
                      "scopeSnapshotSha256": confirmed_scope_sha256,
                      "handoffClaimSha256": handoff_claim_digest(
                          owner=new_owner, token=new_token,
                          claimed_at=claimed_at, expires_at=expires_at)},
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(job_id)

    def mark_stale_nonterminal_attention(
        self,
        job_id: str,
        *,
        expected_status: str,
        event: JobEvent,
    ) -> bool:
        """Atomically annotate only the same still-nonterminal job row."""
        from sqlalchemy import text

        from app.storage.database import db

        result = db.session.execute(
            text(
                """
                UPDATE job_runs
                SET input = json_set(input, '$.lifecycleRecoveryAttention', 'stale_nonterminal')
                WHERE id = :job_id
                  AND status = :expected_status
                  AND status IN ('queued', 'running')
                  AND finished_at IS NULL
                  AND COALESCE(json_extract(input, '$.lifecycleRecoveryAttention'), '') != 'stale_nonterminal'
                """
            ),
            {"job_id": job_id, "expected_status": expected_status},
        )
        if result.rowcount != 1:
            db.session.rollback()
            return False
        db.session.execute(
            text(
                """
                INSERT INTO job_events (job_id, sequence, level, message, data)
                SELECT :job_id, COALESCE(MAX(sequence), 0) + 1, :level, :message, :data
                FROM job_events
                WHERE job_id = :job_id
                """
            ),
            {
                "job_id": job_id,
                "level": event.level,
                "message": event.message,
                "data": json.dumps(event.data, sort_keys=True),
            },
        )
        db.session.commit()
        return True

    def list_by_actions_and_statuses(
        self,
        *,
        actions: set[str],
        statuses: set[str],
        limit: int,
        stale_before: str | None = None,
        lease_expired_before: str | None = None,
    ) -> list[StoredJobRun]:
        from app.storage.models import JobRunModel

        if not actions or not statuses or limit <= 0:
            return []
        rows = (
            JobRunModel.query.filter(
                JobRunModel.action.in_(actions),
                JobRunModel.status.in_(statuses),
            )
        )
        if stale_before is not None and lease_expired_before is not None:
            from sqlalchemy import and_, func, or_

            expiry = func.json_extract(JobRunModel.input, "$.claimExpiresAt")
            rows = rows.filter(
                or_(
                    expiry <= lease_expired_before,
                    and_(expiry.is_(None), JobRunModel.created_at <= _parse_datetime(stale_before)),
                )
            )
        rows = rows.order_by(JobRunModel.created_at.asc()).limit(limit).all()
        return _from_models(rows)


class SqliteJobRepository:
    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.initialize()

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS job_runs (
                  id TEXT PRIMARY KEY,
                  action TEXT NOT NULL,
                  status TEXT NOT NULL,
                  target TEXT NOT NULL,
                  target_type TEXT NOT NULL,
                  target_id TEXT NOT NULL,
                  requested_by TEXT NOT NULL,
                  input TEXT NOT NULL,
                  artifact_refs TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  started_at TEXT,
                  finished_at TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS job_events (
                  job_id TEXT NOT NULL,
                  sequence INTEGER NOT NULL,
                  level TEXT NOT NULL,
                  message TEXT NOT NULL,
                  data TEXT NOT NULL,
                  PRIMARY KEY (job_id, sequence),
                  FOREIGN KEY (job_id) REFERENCES job_runs(id)
                )
                """
            )
            for statement in (
                "CREATE INDEX IF NOT EXISTS ix_job_runs_target_id_created_id "
                "ON job_runs (target_id, created_at DESC, id DESC)",
                "CREATE INDEX IF NOT EXISTS ix_job_runs_target_created_id "
                "ON job_runs (target, created_at DESC, id DESC)",
                "CREATE INDEX IF NOT EXISTS ix_job_runs_input_engagement_created_id "
                "ON job_runs (json_extract(input, '$.engagementId'), created_at DESC, id DESC)",
                "CREATE INDEX IF NOT EXISTS ix_job_events_job_sequence "
                "ON job_events (job_id, sequence)",
            ):
                connection.execute(statement)

    def list(self) -> list[StoredJobRun]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, action, status, target, target_type, target_id, requested_by,
                       input, artifact_refs, created_at, started_at, finished_at
                FROM job_runs
                ORDER BY created_at DESC
                """
            ).fetchall()
        return [self._from_sqlite_row(row) for row in rows]

    def list_for_engagement(self, engagement_id: str, *, limit: int | None = None) -> list[StoredJobRun]:
        with self._connect() as connection:
            query = """
                SELECT id, action, status, target, target_type, target_id, requested_by,
                       input, artifact_refs, created_at, started_at, finished_at
                FROM job_runs
                WHERE target_id = ?
                   OR target = ?
                   OR json_extract(input, '$.engagementId') = ?
                ORDER BY created_at DESC
                """
            parameters: tuple[Any, ...] = (engagement_id, f"engagement:{engagement_id}", engagement_id)
            if limit is not None:
                query += " LIMIT ?"
                parameters += (limit,)
            rows = connection.execute(query, parameters).fetchall()
        return [self._from_sqlite_row(row) for row in rows]

    def list_channel_mutations_for_engagement(self, engagement_id: str) -> list[StoredJobRun]:
        """Keep the exact channel fence without hydrating unrelated job events."""
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT j.id, j.action, j.status, j.target, j.target_type, j.target_id,
                       j.requested_by, j.input, j.artifact_refs, j.created_at,
                       j.started_at, j.finished_at
                FROM job_runs AS j
                WHERE (j.target_id = ? OR j.target = ?
                       OR json_extract(j.input, '$.engagementId') = ?)
                  AND (j.action = 'engagement_channels_update'
                       OR substr(j.action, 1, length('inbound_channel_')) = 'inbound_channel_'
                       OR substr(j.action, 1, length('outbound_channel_')) = 'outbound_channel_'
                       OR EXISTS (
                           SELECT 1 FROM job_events AS e
                           WHERE e.job_id = j.id
                             AND (json_type(e.data, '$.inboundChannels') IS NOT NULL
                                  OR json_type(e.data, '$.outboundChannels') IS NOT NULL)))
                ORDER BY j.created_at DESC
                """,
                (engagement_id, f"engagement:{engagement_id}", engagement_id),
            ).fetchall()
        return [self._from_sqlite_row(row) for row in rows]

    def list_semantic_for_engagement(self, engagement_id: str, *, recent_limit: int = 250) -> list[StoredJobRun]:
        with self._connect() as connection:
            rows = connection.execute(
                _semantic_jobs_sql(named=False),
                (engagement_id, f"engagement:{engagement_id}", engagement_id, recent_limit, SEMANTIC_ROWS_PER_CATEGORY),
            ).fetchall()
            if not rows:
                return []
            placeholders = ", ".join("?" for _ in rows)
            event_rows = connection.execute(
                f"""
                SELECT job_id, sequence, level, message, data
                FROM job_events WHERE job_id IN ({placeholders})
                ORDER BY job_id, sequence ASC
                """,
                tuple(row["id"] for row in rows),
            ).fetchall()
        events_by_job: dict[str, list[JobEvent]] = {}
        for event in event_rows:
            events_by_job.setdefault(event["job_id"], []).append(
                JobEvent(event["sequence"], event["level"], event["message"], json.loads(event["data"]))
            )
        return [_stored_job_from_mapping(row, events_by_job.get(row["id"], [])) for row in rows]

    def list_semantic_for_engagements(
        self,
        engagement_ids: list[str],
        *,
        recent_limit: int = 250,
    ) -> SemanticJobBatch:
        ids = list(dict.fromkeys(value for value in engagement_ids if value))
        with self._connect() as connection:
            rows = connection.execute(
                _semantic_jobs_for_engagements_sql(len(ids), named=False),
                (*ids, recent_limit, SEMANTIC_ROWS_PER_CATEGORY),
            ).fetchall()
            metadata = rows[0]
            selected_rows = rows[1:]
            selected_job_ids = list(dict.fromkeys(str(row["id"]) for row in selected_rows))
            if selected_job_ids:
                placeholders = ", ".join("?" for _ in selected_job_ids)
                event_rows = connection.execute(
                    f"""
                    SELECT job_id, sequence, level, message, data
                    FROM job_events WHERE job_id IN ({placeholders})
                    ORDER BY job_id, sequence ASC
                    """,
                    tuple(selected_job_ids),
                ).fetchall()
            else:
                event_rows = connection.execute(
                    "SELECT job_id, sequence, level, message, data FROM job_events WHERE 0 = 1"
                ).fetchall()
        events_by_job: dict[str, list[JobEvent]] = {}
        for event in event_rows:
            events_by_job.setdefault(event["job_id"], []).append(
                JobEvent(event["sequence"], event["level"], event["message"], json.loads(event["data"]))
            )
        grouped = {engagement_id: [] for engagement_id in ids}
        for row in selected_rows:
            grouped[str(row["matched_engagement_id"])].append(
                _stored_job_from_mapping(row, events_by_job.get(str(row["id"]), []))
            )
        return SemanticJobBatch(
            jobs_by_engagement=grouped,
            total_job_count=int(metadata["total_job_count"]),
            seed_job_exists=bool(metadata["seed_job_exists"]),
        )

    def list_dashboard_semantic_for_engagements(
        self,
        engagement_ids: list[str],
        *,
        recent_limit: int = 250,
    ) -> DashboardSemanticJobBatch:
        ids = list(dict.fromkeys(value for value in engagement_ids if value))
        with self._connect() as connection:
            rows = connection.execute(
                _semantic_jobs_for_engagements_sql(len(ids), named=False),
                (*ids, recent_limit, SEMANTIC_ROWS_PER_CATEGORY),
            ).fetchall()
            metadata = rows[0]
            selected_rows = rows[1:]
            selected_job_ids = list(dict.fromkeys(str(row["id"]) for row in selected_rows))
            event_rows = _sqlite_dashboard_event_rows(connection, selected_job_ids)
        events_by_job: dict[str, list[JobEvent]] = {}
        for event in event_rows:
            events_by_job.setdefault(event["job_id"], []).append(
                JobEvent(
                    event["sequence"],
                    event["level"],
                    event["message"],
                    _decoded_event_data(event["data"]),
                )
            )
        grouped = {engagement_id: [] for engagement_id in ids}
        for row in selected_rows:
            grouped[str(row["matched_engagement_id"])].append(
                _stored_job_from_mapping(row, events_by_job.get(str(row["id"]), []))
            )
        return DashboardSemanticJobBatch(
            jobs_by_engagement=grouped,
            total_job_count=int(metadata["total_job_count"]),
            seed_job_exists=bool(metadata["seed_job_exists"]),
        )

    def list_summaries(self, *, limit: int, offset: int) -> tuple[list[JobRunSummary], int]:
        with self._connect() as connection:
            total = int(connection.execute("SELECT COUNT(*) FROM job_runs").fetchone()[0])
            rows = connection.execute(
                """
                SELECT id, action, status, target, created_at
                FROM job_runs
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        return [
            JobRunSummary(
                id=row["id"],
                action=row["action"],
                status=row["status"],
                target=row["target"],
                created_at=row["created_at"],
            )
            for row in rows
        ], total

    def count(self) -> int:
        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM job_runs").fetchone()[0])

    def get(self, job_id: str) -> StoredJobRun | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, action, status, target, target_type, target_id, requested_by,
                       input, artifact_refs, created_at, started_at, finished_at
                FROM job_runs
                WHERE id = ?
                """,
                (job_id,),
            ).fetchone()
        if row is None:
            return None
        return self._from_sqlite_row(row)

    def save(self, job: StoredJobRun) -> StoredJobRun:
        if self.get(job.id) is None:
            request_identity = current_request_identity()
            if request_identity is not None:
                job = replace(job, requested_by=request_identity.username)
        with self._connect() as connection:
            _fence_append_binding_history(job, connection=connection)
            connection.execute(
                """
                INSERT INTO job_runs (
                  id, action, status, target, target_type, target_id, requested_by,
                  input, artifact_refs, created_at, started_at, finished_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  action = excluded.action,
                  status = excluded.status,
                  target = excluded.target,
                  target_type = excluded.target_type,
                  target_id = excluded.target_id,
                  requested_by = excluded.requested_by,
                  input = excluded.input,
                  artifact_refs = excluded.artifact_refs,
                  created_at = excluded.created_at,
                  started_at = excluded.started_at,
                  finished_at = excluded.finished_at
                """,
                (
                    job.id,
                    job.action,
                    job.status,
                    job.target,
                    job.target_type,
                    job.target_id,
                    job.requested_by,
                    json.dumps(job.input, sort_keys=True),
                    json.dumps(job.artifact_refs, sort_keys=True),
                    job.created_at,
                    job.started_at,
                    job.finished_at,
                ),
            )
            connection.execute("DELETE FROM job_events WHERE job_id = ?", (job.id,))
            for event in job.events:
                connection.execute(
                    """
                    INSERT INTO job_events (job_id, sequence, level, message, data)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        job.id,
                        event.sequence,
                        event.level,
                        event.message,
                        json.dumps(event.data, sort_keys=True),
                    ),
                )
        stored = self.get(job.id)
        if stored is None:
            raise RuntimeError("job save did not persist a readable row")
        return stored

    def save_if_absent(self, job: StoredJobRun) -> StoredJobRun:
        with self._connect() as connection:
            _fence_append_binding_history(job, connection=connection)
            if job.action in _MIXED_APPEND_APPLY_ACTIONS | {"provider_keyed_mixed_append"}:
                locked = connection.execute("""
                    UPDATE core_mutation_leases SET operation = operation
                    WHERE engagement_id = ? AND owner_id = ?
                      AND operation = 'provider_keyed_mixed_append'
                """, (job.target_id, job.input.get("corePlanId")))
                if locked.rowcount != 1:
                    raise ValueError("append reservation lost its mutation lease")
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO job_runs (
                  id, action, status, target, target_type, target_id, requested_by,
                  input, artifact_refs, created_at, started_at, finished_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job.id, job.action, job.status, job.target, job.target_type, job.target_id,
                    job.requested_by, json.dumps(job.input, sort_keys=True),
                    json.dumps(job.artifact_refs, sort_keys=True), job.created_at, job.started_at, job.finished_at,
                ),
            )
            if cursor.rowcount == 1:
                for event in job.events:
                    connection.execute(
                        "INSERT INTO job_events (job_id, sequence, level, message, data) VALUES (?, ?, ?, ?, ?)",
                        (job.id, event.sequence, event.level, event.message, json.dumps(event.data, sort_keys=True)),
                    )
        return self.get(job.id) or job

    def insert_inspector_teardown_barrier(self, job: StoredJobRun) -> StoredJobRun | None:
        """SQLite's conditional insert serializes the opposing-job decision."""
        opponents = _inspector_barrier_opponents(job)
        if job.action == _INSPECTOR_BARRIER_PARENT:
            existing = self.get(job.id)
            if existing is not None:
                return existing if existing.action == job.action and existing.target_id == job.target_id else None
        identity = current_request_identity()
        if identity is not None:
            job = replace(job, requested_by=identity.username)
        placeholders = ", ".join("?" for _ in opponents)
        with self._connect() as connection:
            cursor = connection.execute(f"""
                INSERT OR IGNORE INTO job_runs
                  (id, action, status, target, target_type, target_id, requested_by,
                   input, artifact_refs, created_at, started_at, finished_at)
                SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL
                WHERE NOT EXISTS (
                  SELECT 1 FROM job_runs
                  WHERE target_type = 'engagement' AND target_id = ?
                    AND action IN ({placeholders}) AND status IN ('queued', 'running')
                )
            """, (
                job.id, job.action, job.status, job.target, job.target_type, job.target_id,
                job.requested_by, json.dumps(job.input, sort_keys=True),
                json.dumps(job.artifact_refs, sort_keys=True), job.created_at, job.started_at,
                job.target_id, *opponents,
            ))
            if cursor.rowcount == 1:
                event = job.events[0]
                connection.execute(
                    "INSERT INTO job_events (job_id, sequence, level, message, data) VALUES (?, ?, ?, ?, ?)",
                    (job.id, event.sequence, event.level, event.message,
                     json.dumps(event.data, sort_keys=True)),
                )
        if cursor.rowcount != 1 and job.action != _INSPECTOR_BARRIER_PARENT:
            return None
        stored = self.get(job.id)
        return stored if stored is not None and stored.action == job.action \
            and stored.target_id == job.target_id else None

    def start_if_queued(self, job: StoredJobRun, *, started_at: str, event: JobEvent) -> StoredJobRun | None:
        """Use SQLite's conditional UPDATE as the single-worker claim."""
        if (job.status != "queued" or job.started_at is not None or job.finished_at is not None
                or not started_at or event.sequence != len(job.events) + 1):
            return None
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE job_runs SET status = 'running', started_at = ?
                WHERE id = ? AND action = ? AND input = ?
                  AND status = 'queued' AND started_at IS NULL AND finished_at IS NULL
                """ + (" AND " + _MIXED_APPEND_BOOKKEEPING_LEASE_SQL if job.action in _MIXED_APPEND_APPLY_ACTIONS | {"provider_keyed_mixed_append"} else ""),
                (started_at, job.id, job.action, json.dumps(job.input, sort_keys=True)),
            )
            if cursor.rowcount != 1:
                return None
            last = connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) FROM job_events WHERE job_id = ?", (job.id,),
            ).fetchone()[0]
            if last + 1 != event.sequence:
                connection.rollback()
                return None
            connection.execute(
                "INSERT INTO job_events (job_id, sequence, level, message, data) VALUES (?, ?, ?, ?, ?)",
                (job.id, event.sequence, event.level, event.message, json.dumps(event.data, sort_keys=True)),
            )
        return self.get(job.id)

    def finish_if_running(
        self, job: StoredJobRun, *, status: str, finished_at: str, event: JobEvent,
    ) -> StoredJobRun | None:
        """Use SQLite's conditional UPDATE to fence a terminal writer."""
        if (status not in {"succeeded", "failed"} or job.status != "running"
                or not job.started_at or job.finished_at is not None or not finished_at
                or event.sequence != len(job.events) + 1):
            return None
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE job_runs SET status = ?, finished_at = ?
                WHERE id = ? AND action = ? AND input = ? AND started_at = ?
                  AND status = 'running' AND finished_at IS NULL
                """,
                (status, finished_at, job.id, job.action, json.dumps(job.input, sort_keys=True), job.started_at),
            )
            if cursor.rowcount != 1:
                return None
            last = connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) FROM job_events WHERE job_id = ?", (job.id,),
            ).fetchone()[0]
            if last + 1 != event.sequence:
                connection.rollback()
                return None
            connection.execute(
                "INSERT INTO job_events (job_id, sequence, level, message, data) VALUES (?, ?, ?, ?, ?)",
                (job.id, event.sequence, event.level, event.message, json.dumps(event.data, sort_keys=True)),
            )
        return self.get(job.id)

    def finish_mixed_core_absence_if_claimed(
        self, job: StoredJobRun, *, owner: str, token: str, lease_owner: str,
        expected_event_digest: str, status: str, finished_at: str, event: JobEvent,
        authority_check: Callable[[], None],
    ) -> StoredJobRun | None:
        """Standalone SQLite test repository's exact claimed absence terminal."""
        base = _mixed_absence_finish_base(job, owner, token, expected_event_digest, event)
        if (base is None or status not in {"succeeded", "failed"}
                or (status == "succeeded") != (event.level == "info")
                or not _valid_claimed_apply_times(job, at=finished_at)
                or not isinstance(lease_owner, str) or not lease_owner
                or not callable(authority_check)):
            return None
        predicate, parameters = _claimed_apply_input_predicate(job.input)
        with self._connect() as connection:
            locked = connection.execute("""
                UPDATE job_runs SET status = status
                WHERE id = ? AND action = 'provider_keyed_mixed_zero_apply_core_destroy_absence'
                  AND status = 'running' AND finished_at IS NULL
            """, (job.id,))
            if locked.rowcount != 1:
                connection.rollback()
                return None
            authority_check()
            changed = connection.execute("""
                UPDATE job_runs SET input = ?, status = ?, finished_at = ?
                WHERE id = ? AND action = 'provider_keyed_mixed_zero_apply_core_destroy_absence'
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND target_id = ? AND """ + predicate,
                (json.dumps(base, sort_keys=True), status, finished_at,
                 job.id, job.started_at, job.target_id, *parameters))
            if changed.rowcount != 1 or not _destroy_preview_claim_unexpired_at_write(job):
                connection.rollback()
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            connection.execute("""
                INSERT INTO job_events (job_id, sequence, level, message, data)
                VALUES (?, ?, ?, ?, ?)
            """, (job.id, event.sequence, event.level, event.message,
                  json.dumps(event.data, sort_keys=True)))
        return self.get(job.id)

    def finish_mixed_inspector_negative_if_running(
        self, job: StoredJobRun, *, lease_owner: str,
        expected_event_digest: str, finished_at: str, event: JobEvent,
        authority_check: Callable[[], None],
    ) -> StoredJobRun | None:
        """Test repository's exact Inspector terminal under a writer slot."""
        if (job.action != "provider_keyed_mixed_zero_apply_inspector_negative"
                or job.status != "running" or job.started_at is None
                or job.finished_at is not None or len(job.events) != 2
                or event != JobEvent(3, "info",
                                     "mixed Inspector exact public negative proved", event.data)
                or job_event_digest(job.events) != expected_event_digest
                or not lease_owner or not callable(authority_check)):
            return None
        with self._connect() as connection:
            locked = connection.execute("""
                UPDATE job_runs SET status = status
                WHERE id = ? AND action = 'provider_keyed_mixed_zero_apply_inspector_negative'
                  AND status = 'running' AND finished_at IS NULL
            """, (job.id,))
            if locked.rowcount != 1:
                connection.rollback()
                return None
            authority_check()
            changed = connection.execute("""
                UPDATE job_runs SET status = 'succeeded', finished_at = ?
                WHERE id = ? AND action = 'provider_keyed_mixed_zero_apply_inspector_negative'
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND target_id = ? AND input = ?
            """, (finished_at, job.id, job.started_at, job.target_id,
                  json.dumps(job.input, sort_keys=True)))
            if changed.rowcount != 1:
                connection.rollback()
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            connection.execute("""
                INSERT INTO job_events (job_id, sequence, level, message, data)
                VALUES (?, ?, ?, ?, ?)
            """, (job.id, event.sequence, event.level, event.message,
                  json.dumps(event.data, sort_keys=True)))
        return self.get(job.id)

    def append_keyed_inspector_create_intent_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        """SQLite one-shot Inspector intent; UPDATE locks before journal validation."""
        if not _valid_keyed_inspector_intent(
            job, owner=owner, token=token, expected_event_digest=expected_event_digest,
            heartbeat_at=heartbeat_at, expires_at=expires_at, event=event,
        ):
            return None
        updated_input = {**job.input, "phase": "inspector_create_started",
                         "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at}
        predicate, parameters = _claimed_apply_input_predicate(job.input)
        with self._connect() as connection:
            changed = connection.execute("""
                UPDATE job_runs SET input = ?
                WHERE id = ? AND action = 'provider_keyed_comprehensive_teardown'
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND created_at = ? AND target = ?
                  AND target_type = ? AND target_id = ? AND requested_by = ?
                  AND artifact_refs = '[]' AND """ + predicate + """
                  AND julianday('now') < julianday(json_extract(input, '$.claimExpiresAt'))
            """, (json.dumps(updated_input, sort_keys=True), job.id, job.started_at,
                  job.created_at, job.target, job.target_type, job.target_id,
                  job.requested_by, *parameters))
            if changed.rowcount != 1:
                connection.rollback()
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            connection.execute("""
                INSERT INTO job_events (job_id, sequence, level, message, data)
                VALUES (?, ?, ?, ?, ?)
            """, (job.id, event.sequence, event.level, event.message,
                  json.dumps(event.data, sort_keys=True)))
        return self.get(job.id)

    def heartbeat_keyed_inspector_submission_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str, claimed_at: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        """SQLite heartbeat of one complete staged Inspector submission."""
        if not _valid_completed_inspector_submission_heartbeat(
            job, owner=owner, token=token, claimed_at=claimed_at,
            expected_event_digest=expected_event_digest,
            heartbeat_at=heartbeat_at, expires_at=expires_at,
        ):
            return None
        updated_input = {**job.input, "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at}
        predicate, parameters = _claimed_apply_input_predicate(job.input)
        with self._connect() as connection:
            changed = connection.execute("""
                UPDATE job_runs SET input = ?
                WHERE id = ? AND action = 'provider_keyed_comprehensive_teardown'
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND created_at = ? AND target = ?
                  AND target_type = ? AND target_id = ? AND requested_by = ?
                  AND artifact_refs = '[]' AND """ + predicate + """
                  AND julianday('now') < julianday(json_extract(input, '$.claimExpiresAt'))
            """, (json.dumps(updated_input, sort_keys=True), job.id, job.started_at,
                  job.created_at, job.target, job.target_type, job.target_id,
                  job.requested_by, *parameters))
            if changed.rowcount != 1:
                connection.rollback()
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
        return self.get(job.id)

    def heartbeat_keyed_inspector_preparation_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str, claimed_at: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        """SQLite heartbeat for the exact one-shot Inspector prepare journal."""
        if not _valid_keyed_inspector_prepare_heartbeat(
            job, owner=owner, token=token, claimed_at=claimed_at,
            expected_event_digest=expected_event_digest,
            heartbeat_at=heartbeat_at, expires_at=expires_at,
        ):
            return None
        updated_input = {**job.input, "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at}
        predicate, parameters = _claimed_apply_input_predicate(job.input)
        with self._connect() as connection:
            changed = connection.execute("""
                UPDATE job_runs SET input = ?
                WHERE id = ? AND action = 'provider_keyed_comprehensive_teardown'
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND created_at = ? AND target = ?
                  AND target_type = ? AND target_id = ? AND requested_by = ?
                  AND artifact_refs = '[]' AND """ + predicate + """
                  AND julianday('now') < julianday(json_extract(input, '$.claimExpiresAt'))
                  AND julianday(?) > julianday('now')
                  AND julianday(?) <= julianday('now', '+5 minutes')
            """, (json.dumps(updated_input, sort_keys=True), job.id, job.started_at,
                  job.created_at, job.target, job.target_type, job.target_id,
                  job.requested_by, *parameters, expires_at, expires_at))
            if changed.rowcount != 1:
                connection.rollback()
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
        return self.get(job.id)

    def transition_retained_inspector_if_running(
        self, job: StoredJobRun, *, mode: str, expected_event_digest: str,
        owner: str, token: str, at: str, expires_at: str,
        event: JobEvent | None = None, authority: Callable[[], None] | None = None,
    ) -> StoredJobRun | None:
        """SQLite equivalent of the exact four-event retained-host transition."""
        next_input = _retained_transition_input(
            job, mode=mode, expected_event_digest=expected_event_digest,
            owner=owner, token=token, at=at, expires_at=expires_at, event=event)
        if next_input is None or mode == "ready":
            # Cross-table authority cannot be fenced through this isolated
            # repository connection. Production publication uses SQLAlchemy.
            return None
        predicate, parameters = _claimed_apply_input_predicate(job.input)
        clock_condition = (
            "julianday('now') >= julianday(json_extract(input, '$.claimExpiresAt'))"
            if mode == "claim" else
            "julianday('now') < julianday(json_extract(input, '$.claimExpiresAt'))"
        )
        expiry_condition = (
            "" if mode == "ready" else
            " AND julianday(?) > julianday('now')"
            " AND julianday(?) <= julianday('now', '+5 minutes')"
        )
        with self._connect() as connection:
            changed = connection.execute("""
                UPDATE job_runs SET input = ?
                WHERE id = ? AND action = 'provider_keyed_comprehensive_teardown'
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND created_at = ? AND target = ?
                  AND target_type = ? AND target_id = ? AND requested_by = ?
                  AND artifact_refs = '[]' AND """ + predicate + " AND "
                + clock_condition + expiry_condition,
                (json.dumps(next_input, sort_keys=True), job.id, job.started_at,
                 job.created_at, job.target, job.target_type, job.target_id,
                 job.requested_by, *parameters,
                 *((expires_at, expires_at) if mode != "ready" else ())))
            if changed.rowcount != 1:
                connection.rollback()
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            if mode == "ready":
                connection.execute("""
                    INSERT INTO job_events (job_id, sequence, level, message, data)
                    VALUES (?, ?, ?, ?, ?)
                """, (job.id, event.sequence, event.level, event.message,
                      json.dumps(event.data, sort_keys=True)))
        return self.get(job.id)

    def append_keyed_inspector_stage_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        """SQLite append-only Inspector stage CAS under the current claim."""
        if not _valid_inspector_stage_prefix(
            job, owner=owner, token=token, expected_event_digest=expected_event_digest,
            heartbeat_at=heartbeat_at, expires_at=expires_at, event=event,
        ):
            return None
        updated_input = {**job.input, "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at}
        predicate, parameters = _claimed_apply_input_predicate(job.input)
        with self._connect() as connection:
            changed = connection.execute("""
                UPDATE job_runs SET input = ?
                WHERE id = ? AND action = 'provider_keyed_comprehensive_teardown'
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND created_at = ? AND target = ?
                  AND target_type = ? AND target_id = ? AND requested_by = ?
                  AND artifact_refs = '[]' AND """ + predicate + """
                  AND julianday('now') < julianday(json_extract(input, '$.claimExpiresAt'))
            """, (json.dumps(updated_input, sort_keys=True), job.id, job.started_at,
                  job.created_at, job.target, job.target_type, job.target_id,
                  job.requested_by, *parameters))
            if changed.rowcount != 1:
                connection.rollback()
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            connection.execute("""
                INSERT INTO job_events (job_id, sequence, level, message, data)
                VALUES (?, ?, ?, ?, ?)
            """, (job.id, event.sequence, event.level, event.message,
                  json.dumps(event.data, sort_keys=True)))
        return self.get(job.id)

    def finish_if_running_with_journal_digest(
        self, job: StoredJobRun, *, expected_event_digest: str, status: str,
        finished_at: str, event: JobEvent, artifact_ref: str | None = None,
    ) -> StoredJobRun | None:
        """Finish only the exact keyed destroy-plan row and full prior journal."""
        if not _valid_keyed_destroy_finish(
            job, expected_event_digest=expected_event_digest, status=status,
            finished_at=finished_at, event=event, artifact_ref=artifact_ref,
        ):
            return None
        input_predicate, input_parameters = _claimed_apply_input_predicate(job.input)
        with self._connect() as connection:
            changed = connection.execute(
                f"""
                UPDATE job_runs SET status = ?, finished_at = ?, artifact_refs = ?
                WHERE id = ? AND action = 'provider_keyed_initial_destroy_plan'
                  AND status = 'running' AND finished_at IS NULL
                  AND target = ? AND target_type = ? AND target_id = ?
                  AND requested_by = ? AND created_at = ? AND started_at = ?
                  AND artifact_refs = '[]' AND {input_predicate}
                """,
                (status, finished_at, json.dumps([artifact_ref] if artifact_ref else []),
                 job.id, job.target, job.target_type, job.target_id,
                 job.requested_by, job.created_at, job.started_at, *input_parameters),
            )
            if changed.rowcount != 1:
                return None
            rows = connection.execute(
                "SELECT sequence, level, message, data FROM job_events WHERE job_id = ? ORDER BY sequence",
                (job.id,),
            ).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            connection.execute(
                "INSERT INTO job_events (job_id, sequence, level, message, data) VALUES (?, ?, ?, ?, ?)",
                (job.id, event.sequence, event.level, event.message,
                 json.dumps(event.data, sort_keys=True)),
            )
        return self.get(job.id)

    def append_event_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        if (_claimed_apply_base(job, owner, token) is None
                or not _valid_claimed_apply_times(job, at=heartbeat_at, next_expiry=expires_at)
                or not isinstance(expected_event_digest, str)
                or event.sequence != len(job.events) + 1):
            return None
        updated_input = {**job.input, "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at}
        input_predicate, input_parameters = _claimed_apply_input_predicate(job.input)
        append_lease = (" AND EXISTS (SELECT 1 FROM core_mutation_leases"
                        " WHERE engagement_id = job_runs.target_id"
                        " AND owner_id = ? AND operation = 'provider_keyed_mixed_append')"
                        if job.action in _MIXED_APPEND_APPLY_ACTIONS else "")
        append_lease_parameters = ((job.input["corePlanId"],) if append_lease else ())
        with self._connect() as connection:
            cursor = connection.execute("""
                UPDATE job_runs SET input = ?
                WHERE id = ? AND action = ?
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND target = ?
                  AND target_type = ? AND target_id = ? AND requested_by = ?
                  AND artifact_refs = ? AND created_at = ?
                  AND """ + input_predicate + append_lease, (json.dumps(updated_input, sort_keys=True), job.id,
                  job.action, job.started_at, job.target,
                  job.target_type, job.target_id, job.requested_by,
                  json.dumps(job.artifact_refs, sort_keys=True), job.created_at,
                  *input_parameters, *append_lease_parameters))
            if cursor.rowcount != 1:
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            connection.execute("""
                INSERT INTO job_events (job_id, sequence, level, message, data)
                VALUES (?, ?, ?, ?, ?)
            """, (job.id, event.sequence, event.level, event.message,
                  json.dumps(event.data, sort_keys=True)))
        return self.get(job.id)

    def finish_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, status: str, finished_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        base = _claimed_apply_base(job, owner, token)
        if (base is None or status not in {"succeeded", "failed"}
                or not _valid_claimed_apply_times(job, at=finished_at)
                or not isinstance(expected_event_digest, str)
                or event.sequence != len(job.events) + 1):
            return None
        input_predicate, input_parameters = _claimed_apply_input_predicate(job.input)
        append_lease = (" AND EXISTS (SELECT 1 FROM core_mutation_leases"
                        " WHERE engagement_id = job_runs.target_id"
                        " AND owner_id = ? AND operation = 'provider_keyed_mixed_append')"
                        if job.action in _MIXED_APPEND_APPLY_ACTIONS else "")
        append_lease_parameters = ((job.input["corePlanId"],) if append_lease else ())
        with self._connect() as connection:
            cursor = connection.execute("""
                UPDATE job_runs SET input = ?, status = ?, finished_at = ?
                WHERE id = ? AND action = ?
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND target = ?
                  AND target_type = ? AND target_id = ? AND requested_by = ?
                  AND artifact_refs = ? AND created_at = ?
                  AND """ + input_predicate + append_lease,
            (json.dumps(base, sort_keys=True), status, finished_at, job.id,
                  job.action, job.started_at, job.target,
                  job.target_type, job.target_id, job.requested_by,
                  json.dumps(job.artifact_refs, sort_keys=True), job.created_at,
                  *input_parameters, *append_lease_parameters))
            if cursor.rowcount != 1:
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            connection.execute("""
                INSERT INTO job_events (job_id, sequence, level, message, data)
                VALUES (?, ?, ?, ?, ?)
            """, (job.id, event.sequence, event.level, event.message,
                  json.dumps(event.data, sort_keys=True)))
        return self.get(job.id)

    def append_destroy_preview_event_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        if (_claimed_destroy_preview_base(job, owner, token) is None
                or not _valid_claimed_apply_times(job, at=heartbeat_at, next_expiry=expires_at)
                or not isinstance(expected_event_digest, str)
                or event.sequence != len(job.events) + 1):
            return None
        updated_input = {**job.input, "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at}
        predicate, parameters = _claimed_apply_input_predicate(job.input)
        with self._connect() as connection:
            changed = connection.execute("""
                UPDATE job_runs SET input = ?
                WHERE id = ? AND action = 'provider_keyed_initial_destroy_plan'
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND created_at = ? AND target = ?
                  AND target_type = ? AND target_id = ? AND requested_by = ?
                  AND artifact_refs = '[]' AND """ + predicate,
                (json.dumps(updated_input, sort_keys=True), job.id, job.started_at,
                 job.created_at, job.target, job.target_type, job.target_id,
                 job.requested_by, *parameters))
            if changed.rowcount != 1 or not _destroy_preview_claim_unexpired_at_write(job):
                connection.rollback()
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            connection.execute("""
                INSERT INTO job_events (job_id, sequence, level, message, data)
                VALUES (?, ?, ?, ?, ?)
            """, (job.id, event.sequence, event.level, event.message,
                  json.dumps(event.data, sort_keys=True)))
        return self.get(job.id)

    def finish_destroy_preview_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, status: str, finished_at: str,
        event: JobEvent, artifact_ref: str | None = None,
    ) -> StoredJobRun | None:
        base = _claimed_destroy_preview_base(job, owner, token)
        if (base is None or not _valid_claimed_apply_times(job, at=finished_at)
                or not _valid_keyed_destroy_finish(
                    replace(job, input=base), expected_event_digest=expected_event_digest,
                    status=status, finished_at=finished_at, event=event, artifact_ref=artifact_ref)):
            return None
        predicate, parameters = _claimed_apply_input_predicate(job.input)
        with self._connect() as connection:
            changed = connection.execute("""
                UPDATE job_runs SET input = ?, status = ?, finished_at = ?, artifact_refs = ?
                WHERE id = ? AND action = 'provider_keyed_initial_destroy_plan'
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND created_at = ? AND target = ?
                  AND target_type = ? AND target_id = ? AND requested_by = ?
                  AND artifact_refs = '[]' AND """ + predicate,
                (json.dumps(base, sort_keys=True), status, finished_at,
                 json.dumps([artifact_ref] if artifact_ref is not None else []), job.id,
                 job.started_at, job.created_at, job.target, job.target_type,
                 job.target_id, job.requested_by, *parameters))
            if changed.rowcount != 1 or not _destroy_preview_claim_unexpired_at_write(job):
                connection.rollback()
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            connection.execute("""
                INSERT INTO job_events (job_id, sequence, level, message, data)
                VALUES (?, ?, ?, ?, ?)
            """, (job.id, event.sequence, event.level, event.message,
                  json.dumps(event.data, sort_keys=True)))
        return self.get(job.id)

    def append_destroy_apply_event_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        if (_claimed_destroy_apply_base(job, owner, token) is None
                or not _valid_claimed_apply_times(job, at=heartbeat_at, next_expiry=expires_at)
                or not isinstance(expected_event_digest, str)
                or event.sequence != len(job.events) + 1):
            return None
        updated_input = {**job.input, "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at}
        predicate, parameters = _claimed_apply_input_predicate(job.input)
        with self._connect() as connection:
            changed = connection.execute("""
                UPDATE job_runs SET input = ?
                WHERE id = ? AND action = 'provider_keyed_initial_destroy_apply'
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND created_at = ? AND target = ?
                  AND target_type = ? AND target_id = ? AND requested_by = ?
                  AND artifact_refs = '[]' AND """ + predicate,
                (json.dumps(updated_input, sort_keys=True), job.id, job.started_at,
                 job.created_at, job.target, job.target_type, job.target_id,
                 job.requested_by, *parameters))
            if changed.rowcount != 1 or not _destroy_preview_claim_unexpired_at_write(job):
                connection.rollback()
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            connection.execute("""
                INSERT INTO job_events (job_id, sequence, level, message, data)
                VALUES (?, ?, ?, ?, ?)
            """, (job.id, event.sequence, event.level, event.message,
                  json.dumps(event.data, sort_keys=True)))
        return self.get(job.id)

    def finish_destroy_apply_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, status: str, finished_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        base = _claimed_destroy_apply_base(job, owner, token)
        if (base is None or not _valid_claimed_apply_times(job, at=finished_at)
                or not _valid_destroy_apply_finish(
                    job, expected_event_digest=expected_event_digest,
                    status=status, finished_at=finished_at, event=event)):
            return None
        predicate, parameters = _claimed_apply_input_predicate(job.input)
        with self._connect() as connection:
            changed = connection.execute("""
                UPDATE job_runs SET input = ?, status = ?, finished_at = ?
                WHERE id = ? AND action = 'provider_keyed_initial_destroy_apply'
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND created_at = ? AND target = ?
                  AND target_type = ? AND target_id = ? AND requested_by = ?
                  AND artifact_refs = '[]' AND """ + predicate,
                (json.dumps(base, sort_keys=True), status, finished_at, job.id,
                 job.started_at, job.created_at, job.target, job.target_type,
                 job.target_id, job.requested_by, *parameters))
            if changed.rowcount != 1 or not _destroy_preview_claim_unexpired_at_write(job):
                connection.rollback()
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            connection.execute("""
                INSERT INTO job_events (job_id, sequence, level, message, data)
                VALUES (?, ?, ?, ?, ?)
            """, (job.id, event.sequence, event.level, event.message,
                  json.dumps(event.data, sort_keys=True)))
        return self.get(job.id)

    def take_over_initial_destroy_apply_pre_go(
        self, job: StoredJobRun, *, expected_event_digest: str,
        owner: str, token: str, claimed_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        if not _valid_initial_destroy_pre_go_takeover(
            job, expected_event_digest=expected_event_digest,
            owner=owner, token=token, claimed_at=claimed_at, expires_at=expires_at,
        ):
            return None
        next_input = {**job.input, "claimOwner": owner, "claimToken": token,
                      "claimClaimedAt": claimed_at, "claimExpiresAt": expires_at}
        next_input.pop("claimHeartbeatAt", None)
        predicate, parameters = _claimed_apply_input_predicate(job.input)
        with self._connect() as connection:
            changed = connection.execute("""
                UPDATE job_runs SET input = ?
                WHERE id = ? AND action = 'provider_keyed_initial_destroy_apply'
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND created_at = ? AND target = ?
                  AND target_type = ? AND target_id = ? AND requested_by = ?
                  AND artifact_refs = '[]' AND """ + predicate,
                (json.dumps(next_input, sort_keys=True), job.id, job.started_at,
                 job.created_at, job.target, job.target_type, job.target_id,
                 job.requested_by, *parameters))
            if changed.rowcount != 1:
                connection.rollback()
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
        return self.get(job.id)

    def take_over_mixed_core_show(
        self, job: StoredJobRun, *, expected_event_digest: str,
        owner: str, token: str, claimed_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        if not _valid_mixed_core_show_takeover(
            job, expected_event_digest=expected_event_digest, owner=owner,
            token=token, claimed_at=claimed_at, expires_at=expires_at,
        ):
            return None
        next_input = {**job.input, "claimOwner": owner, "claimToken": token,
                      "claimClaimedAt": claimed_at, "claimExpiresAt": expires_at}
        next_input.pop("claimHeartbeatAt", None)
        marker = JobEvent(len(job.events) + 1, "info", "mixed core SHOW recovery claimed", {
            "originalJournalSha256": expected_event_digest,
            "originalInvocationId": job.events[2].data["invocationId"],
        })
        predicate, parameters = _claimed_apply_input_predicate(job.input)
        with self._connect() as connection:
            changed = connection.execute("""
                UPDATE job_runs SET input = ?
                WHERE id = ? AND action = 'provider_keyed_mixed_zero_apply_core_destroy_apply'
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND created_at = ? AND target = ?
                  AND target_type = ? AND target_id = ? AND requested_by = ?
                  AND artifact_refs = '[]' AND """ + predicate,
                (json.dumps(next_input, sort_keys=True), job.id, job.started_at,
                 job.created_at, job.target, job.target_type, job.target_id,
                 job.requested_by, *parameters))
            if changed.rowcount != 1:
                connection.rollback()
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            connection.execute("""
                INSERT INTO job_events (job_id, sequence, level, message, data)
                VALUES (?, ?, ?, ?, ?)
            """, (job.id, marker.sequence, marker.level, marker.message,
                  json.dumps(marker.data, sort_keys=True)))
        return self.get(job.id)

    def take_over_mixed_core_apply_no_go(
        self, job: StoredJobRun, *, expected_event_digest: str,
        owner: str, token: str, claimed_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        if not _valid_mixed_core_apply_no_go_takeover(
                job, expected_event_digest=expected_event_digest, owner=owner,
                token=token, claimed_at=claimed_at, expires_at=expires_at):
            return None
        next_input = {**job.input, "claimOwner": owner, "claimToken": token,
                      "claimClaimedAt": claimed_at, "claimExpiresAt": expires_at}
        next_input.pop("claimHeartbeatAt", None)
        marker = JobEvent(len(job.events) + 1, "info", "mixed core pre-GO Apply recovery claimed", {
            "originalJournalSha256": expected_event_digest,
            "originalInvocationId": job.events[-2].data["invocationId"],
        })
        predicate, parameters = _claimed_apply_input_predicate(job.input)
        with self._connect() as connection:
            changed = connection.execute("""
                UPDATE job_runs SET input = ?
                WHERE id = ? AND action = 'provider_keyed_mixed_zero_apply_core_destroy_apply'
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND created_at = ? AND target = ?
                  AND target_type = ? AND target_id = ? AND requested_by = ?
                  AND artifact_refs = '[]' AND """ + predicate,
                (json.dumps(next_input, sort_keys=True), job.id, job.started_at,
                 job.created_at, job.target, job.target_type, job.target_id,
                 job.requested_by, *parameters))
            if changed.rowcount != 1:
                connection.rollback()
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            connection.execute("""
                INSERT INTO job_events (job_id, sequence, level, message, data)
                VALUES (?, ?, ?, ?, ?)
            """, (job.id, marker.sequence, marker.level, marker.message,
                  json.dumps(marker.data, sort_keys=True)))
        return self.get(job.id)

    def take_over_core_destroy_apply_pre_go(
        self, job: StoredJobRun, *, expected_event_digest: str,
        owner: str, token: str, claimed_at: str, expires_at: str,
    ) -> StoredJobRun | None:
        if not _valid_core_destroy_pre_go_takeover(
            job, expected_event_digest=expected_event_digest,
            owner=owner, token=token, claimed_at=claimed_at, expires_at=expires_at,
        ):
            return None
        next_input = {**job.input, "claimOwner": owner, "claimToken": token,
                      "claimClaimedAt": claimed_at, "claimExpiresAt": expires_at}
        next_input.pop("claimHeartbeatAt", None)
        predicate, parameters = _claimed_apply_input_predicate(job.input)
        with self._connect() as connection:
            changed = connection.execute("""
                UPDATE job_runs SET input = ?
                WHERE id = ? AND action = 'provider_keyed_core_destroy_apply'
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND created_at = ? AND target = ?
                  AND target_type = ? AND target_id = ? AND requested_by = ?
                  AND artifact_refs = '[]' AND """ + predicate,
                (json.dumps(next_input, sort_keys=True), job.id, job.started_at,
                 job.created_at, job.target, job.target_type, job.target_id,
                 job.requested_by, *parameters))
            if changed.rowcount != 1:
                connection.rollback()
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
        return self.get(job.id)

    def append_core_destroy_apply_event_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        if (_claimed_core_destroy_apply_base(job, owner, token) is None
                or not _valid_claimed_apply_times(job, at=heartbeat_at, next_expiry=expires_at)
                or not isinstance(expected_event_digest, str)
                or event.sequence != len(job.events) + 1):
            return None
        updated_input = {**job.input, "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at}
        predicate, parameters = _claimed_apply_input_predicate(job.input)
        with self._connect() as connection:
            changed = connection.execute("""
                UPDATE job_runs SET input = ?
                WHERE id = ? AND action = ?
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND created_at = ? AND target = ?
                  AND target_type = ? AND target_id = ? AND requested_by = ?
                  AND artifact_refs = '[]' AND """ + predicate,
                (json.dumps(updated_input, sort_keys=True), job.id, job.action, job.started_at,
                 job.created_at, job.target, job.target_type, job.target_id,
                 job.requested_by, *parameters))
            if changed.rowcount != 1 or not _destroy_preview_claim_unexpired_at_write(job):
                connection.rollback()
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            connection.execute("""
                INSERT INTO job_events (job_id, sequence, level, message, data)
                VALUES (?, ?, ?, ?, ?)
            """, (job.id, event.sequence, event.level, event.message,
                  json.dumps(event.data, sort_keys=True)))
        return self.get(job.id)

    def append_selector_retirement_event_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, heartbeat_at: str, expires_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        if (_claimed_selector_retirement_base(job, owner, token) is None
                or not _valid_claimed_apply_times(job, at=heartbeat_at, next_expiry=expires_at)
                or not _valid_selector_retirement_event(job, event, terminal=False)):
            return None
        updated_input = {**job.input, "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at}
        predicate, parameters = _claimed_apply_input_predicate(job.input)
        with self._connect() as connection:
            changed = connection.execute("""
                UPDATE job_runs SET input = ?
                WHERE id = ? AND action = 'provider_keyed_selector_retirement'
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND created_at = ? AND target = ?
                  AND target_type = ? AND target_id = ? AND requested_by = ?
                  AND artifact_refs = '[]' AND """ + predicate,
                (json.dumps(updated_input, sort_keys=True), job.id, job.started_at,
                 job.created_at, job.target, job.target_type, job.target_id,
                 job.requested_by, *parameters))
            if changed.rowcount != 1 or not _destroy_preview_claim_unexpired_at_write(job):
                connection.rollback()
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            connection.execute("""
                INSERT INTO job_events (job_id, sequence, level, message, data)
                VALUES (?, ?, ?, ?, ?)
            """, (job.id, event.sequence, event.level, event.message,
                  json.dumps(event.data, sort_keys=True)))
        return self.get(job.id)

    def finish_selector_retirement_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, finished_at: str, event: JobEvent,
    ) -> StoredJobRun | None:
        base = _claimed_selector_retirement_base(job, owner, token)
        if (base is None or not _valid_claimed_apply_times(job, at=finished_at)
                or not _valid_selector_retirement_event(job, event, terminal=True)):
            return None
        predicate, parameters = _claimed_apply_input_predicate(job.input)
        with self._connect() as connection:
            changed = connection.execute("""
                UPDATE job_runs SET input = ?, status = 'succeeded', finished_at = ?
                WHERE id = ? AND action = 'provider_keyed_selector_retirement'
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND created_at = ? AND target = ?
                  AND target_type = ? AND target_id = ? AND requested_by = ?
                  AND artifact_refs = '[]' AND """ + predicate,
                (json.dumps(base, sort_keys=True), finished_at, job.id, job.started_at,
                 job.created_at, job.target, job.target_type, job.target_id,
                 job.requested_by, *parameters))
            if changed.rowcount != 1 or not _destroy_preview_claim_unexpired_at_write(job):
                connection.rollback()
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            connection.execute("""
                INSERT INTO job_events (job_id, sequence, level, message, data)
                VALUES (?, ?, ?, ?, ?)
            """, (job.id, event.sequence, event.level, event.message,
                  json.dumps(event.data, sort_keys=True)))
        return self.get(job.id)

    def finish_core_destroy_apply_if_running_claimed(
        self, job: StoredJobRun, *, owner: str, token: str,
        expected_event_digest: str, status: str, finished_at: str,
        event: JobEvent,
    ) -> StoredJobRun | None:
        base = _claimed_core_destroy_apply_base(job, owner, token)
        if (base is None or not _valid_claimed_apply_times(job, at=finished_at)
                or not _valid_core_destroy_apply_finish(
                    job, expected_event_digest=expected_event_digest,
                    status=status, finished_at=finished_at, event=event)):
            return None
        predicate, parameters = _claimed_apply_input_predicate(job.input)
        with self._connect() as connection:
            changed = connection.execute("""
                UPDATE job_runs SET input = ?, status = ?, finished_at = ?
                WHERE id = ? AND action = ?
                  AND status = 'running' AND finished_at IS NULL
                  AND started_at = ? AND created_at = ? AND target = ?
                  AND target_type = ? AND target_id = ? AND requested_by = ?
                  AND artifact_refs = '[]' AND """ + predicate,
                (json.dumps(base, sort_keys=True), status, finished_at, job.id, job.action,
                 job.started_at, job.created_at, job.target, job.target_type,
                 job.target_id, job.requested_by, *parameters))
            if changed.rowcount != 1 or not _destroy_preview_claim_unexpired_at_write(job):
                connection.rollback()
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            connection.execute("""
                INSERT INTO job_events (job_id, sequence, level, message, data)
                VALUES (?, ?, ?, ?, ?)
            """, (job.id, event.sequence, event.level, event.message,
                  json.dumps(event.data, sort_keys=True)))
        return self.get(job.id)

    def claim_lease(
        self,
        job_id: str,
        *,
        owner: str,
        token: str,
        claimed_at: str,
        expires_at: str,
        eligible_statuses: set[str],
        eligible_phases: set[str] | None = None,
    ) -> StoredJobRun | None:
        if not eligible_statuses or not _valid_eligible_phases(eligible_phases):
            return None
        placeholders = ", ".join("?" for _ in eligible_statuses)
        phase_predicate = (
            "AND json_extract(input, '$.phase') IN ("
            + ", ".join("?" for _ in eligible_phases) + ")"
        ) if eligible_phases is not None else ""
        current = self.get(job_id)
        append_guard = (" AND " + _MIXED_APPEND_BOOKKEEPING_LEASE_SQL
            if current is not None and current.action in _MIXED_APPEND_APPLY_ACTIONS | {"provider_keyed_mixed_append"} else "")
        with self._connect() as connection:
            cursor = connection.execute(
                f"""
                UPDATE job_runs
                SET input = json_set(
                    input,
                    '$.claimOwner', ?,
                    '$.claimToken', ?,
                    '$.claimClaimedAt', ?,
                    '$.claimHeartbeatAt', ?,
                    '$.claimExpiresAt', ?
                )
                WHERE id = ?
                  AND status IN ({placeholders})
                  {phase_predicate}
                  AND (
                    json_extract(input, '$.claimToken') IS NULL
                    OR json_extract(input, '$.claimExpiresAt') IS NULL
                    OR julianday(json_extract(input, '$.claimExpiresAt')) IS NULL
                    OR json_extract(input, '$.claimExpiresAt') <= ?
                    OR (
                      json_extract(input, '$.claimOwner') = ?
                      AND json_extract(input, '$.claimToken') = ?
                    )
                  )
                """ + append_guard,
                (owner, token, claimed_at, claimed_at, expires_at, job_id, *sorted(eligible_statuses),
                 *sorted(eligible_phases or ()), claimed_at, owner, token),
            )
        return self.get(job_id) if cursor.rowcount == 1 else None

    def renew_lease(
        self,
        job_id: str,
        *,
        owner: str,
        token: str,
        heartbeat_at: str,
        expires_at: str,
    ) -> StoredJobRun | None:
        current = self.get(job_id)
        append_guard = (" AND " + _MIXED_APPEND_BOOKKEEPING_LEASE_SQL
            if current is not None and current.action in _MIXED_APPEND_APPLY_ACTIONS | {"provider_keyed_mixed_append"} else "")
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE job_runs
                SET input = json_set(input, '$.claimHeartbeatAt', ?, '$.claimExpiresAt', ?)
                WHERE id = ?
                  AND status IN ('queued', 'running')
                  AND json_extract(input, '$.claimOwner') = ?
                  AND json_extract(input, '$.claimToken') = ?
                """ + append_guard,
                (heartbeat_at, expires_at, job_id, owner, token),
            )
        return self.get(job_id) if cursor.rowcount == 1 else None

    def save_if_leased(
        self,
        job: StoredJobRun,
        *,
        owner: str,
        token: str,
    ) -> StoredJobRun | None:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE job_runs
                SET action = ?, status = ?, target = ?, target_type = ?, target_id = ?,
                    requested_by = ?, input = ?, artifact_refs = ?, created_at = ?,
                    started_at = ?, finished_at = ?
                WHERE id = ?
                  AND json_extract(input, '$.claimOwner') = ?
                  AND json_extract(input, '$.claimToken') = ?
                """,
                (
                    job.action, job.status, job.target, job.target_type, job.target_id,
                    job.requested_by, json.dumps(job.input, sort_keys=True),
                    json.dumps(job.artifact_refs, sort_keys=True), job.created_at,
                    job.started_at, job.finished_at, job.id, owner, token,
                ),
            )
            if cursor.rowcount != 1:
                return None
            connection.execute("DELETE FROM job_events WHERE job_id = ?", (job.id,))
            for event in job.events:
                connection.execute(
                    "INSERT INTO job_events (job_id, sequence, level, message, data) VALUES (?, ?, ?, ?, ?)",
                    (job.id, event.sequence, event.level, event.message, json.dumps(event.data, sort_keys=True)),
                )
        return self.get(job.id)

    def append_mixed_plan_phase_if_claimed(
        self, job: StoredJobRun, *, owner: str, token: str, lease_owner: str,
        expected_event_digest: str, next_phase: str, event: JobEvent,
    ) -> StoredJobRun | None:
        """Append one mixed-plan checkpoint under claim and full journal CAS."""
        if not _valid_mixed_plan_phase_append(
            job, owner=owner, token=token, lease_owner=lease_owner,
            digest=expected_event_digest,
            phase=next_phase, event=event,
        ):
            return None
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            changed = connection.execute("""
                UPDATE job_runs SET status = 'running', started_at = COALESCE(started_at, ?),
                    input = json_set(input, '$.phase', ?,
                                     '$.claimExpiresAt', CASE WHEN ? = 1 THEN ?
                                                              ELSE json_extract(input, '$.claimExpiresAt') END)
                WHERE id = ? AND action = 'provider_keyed_mixed_initial'
                  AND status = ? AND finished_at IS NULL
                  AND json_extract(input, '$.phase') = ?
                  AND json_extract(input, '$.claimOwner') = ?
                  AND json_extract(input, '$.claimToken') = ?
                  AND julianday(json_extract(input, '$.claimExpiresAt')) > julianday('now')
            """, (now, next_phase, int(next_phase in {"both_plans_saved", "apply_sealed"}), now, job.id,
                  job.status, job.input["phase"], owner, token))
            if changed.rowcount != 1:
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            connection.execute("""
                INSERT INTO job_events (job_id, sequence, level, message, data)
                VALUES (?, ?, ?, ?, ?)
            """, (job.id, event.sequence, event.level, event.message,
                  json.dumps(event.data, sort_keys=True)))
        return self.get(job.id)

    def append_mixed_initial_handoff_if_claimed(
        self, job: StoredJobRun, *, owner: str, token: str, lease_owner: str,
        expected_event_digest: str, event: JobEvent,
    ) -> StoredJobRun | None:
        """SQLite test-store equivalent of the one mixed handoff CAS."""
        if not _valid_mixed_initial_handoff_append(
            job, owner=owner, token=token, lease_owner=lease_owner,
            digest=expected_event_digest, event=event,
        ):
            return None
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            changed = connection.execute("""
                UPDATE job_runs SET
                    input = json_set(input, '$.phase', 'awaiting_mixed_host_proof',
                                     '$.claimExpiresAt', ?)
                WHERE id = ? AND action = 'provider_keyed_mixed_initial'
                  AND status = 'running' AND finished_at IS NULL
                  AND json_extract(input, '$.phase') = 'apply_sealed'
                  AND json_extract(input, '$.claimOwner') = ?
                  AND json_extract(input, '$.claimToken') = ?
                  AND julianday(json_extract(input, '$.claimExpiresAt')) > julianday('now')
            """, (now, job.id, owner, token))
            if changed.rowcount != 1:
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job.id,)).fetchall()
            if not _claimed_apply_journal_matches(rows, job, expected_event_digest):
                connection.rollback()
                return None
            if not _mixed_initial_handoff_children_match(job, event, self.get):
                connection.rollback()
                return None
            connection.execute("""
                INSERT INTO job_events (job_id, sequence, level, message, data)
                VALUES (?, ?, ?, ?, ?)
            """, (job.id, event.sequence, event.level, event.message,
                  json.dumps(event.data, sort_keys=True)))
        return self.get(job.id)

    def fence_terminal_provider_bootstrap_handoff(
        self, job_id: str, *, old_owner: str, old_token: str,
        new_owner: str, new_token: str, claimed_at: str, expires_at: str,
        expected_event_count: int, expected_event_digest: str,
        expected_final_message: str, confirmed_scope_sha256: str,
    ) -> StoredJobRun | None:
        if not _handoff_arguments_valid(
            old_owner=old_owner, old_token=old_token, new_owner=new_owner,
            new_token=new_token, claimed_at=claimed_at, expires_at=expires_at,
            expected_event_count=expected_event_count,
            expected_event_digest=expected_event_digest,
            expected_final_message=expected_final_message,
            confirmed_scope_sha256=confirmed_scope_sha256,
        ):
            return None
        with self._connect() as connection:
            cursor = connection.execute("""
                UPDATE job_runs SET input = json_set(
                    input, '$.phase', ?, '$.claimOwner', ?, '$.claimToken', ?,
                    '$.claimClaimedAt', ?, '$.claimExpiresAt', ?)
                WHERE id = ? AND action = 'provider_keyed_initial'
                  AND status = 'running' AND finished_at IS NULL
                  AND json_extract(input, '$.phase') = 'awaiting_strict_host_proof'
                  AND json_extract(input, '$.claimOwner') = ?
                  AND json_extract(input, '$.claimToken') = ?
            """, (_BOOTSTRAP_HANDOFF_PHASE, new_owner, new_token, claimed_at,
                  expires_at, job_id, old_owner, old_token))
            if cursor.rowcount != 1:
                return None
            rows = connection.execute("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = ? ORDER BY sequence
            """, (job_id,)).fetchall()
            if not _handoff_journal_matches(
                rows, expected_event_count=expected_event_count,
                expected_event_digest=expected_event_digest,
                expected_final_message=expected_final_message,
            ):
                connection.rollback()
                return None
            connection.execute("""
                INSERT INTO job_events (job_id, sequence, level, message, data)
                VALUES (?, ?, 'info', ?, ?)
            """, (job_id, expected_event_count + 1, _BOOTSTRAP_HANDOFF_MESSAGE,
                  json.dumps({"phase": _BOOTSTRAP_HANDOFF_PHASE,
                              "sourceEventSha256": expected_event_digest,
                              "scopeSnapshotSha256": confirmed_scope_sha256,
                              "handoffClaimSha256": handoff_claim_digest(
                                  owner=new_owner, token=new_token,
                                  claimed_at=claimed_at, expires_at=expires_at)}, sort_keys=True)))
        return self.get(job_id)

    def mark_stale_nonterminal_attention(
        self,
        job_id: str,
        *,
        expected_status: str,
        event: JobEvent,
    ) -> bool:
        """Atomically annotate only the same still-nonterminal job row."""
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE job_runs
                SET input = json_set(input, '$.lifecycleRecoveryAttention', 'stale_nonterminal')
                WHERE id = ?
                  AND status = ?
                  AND status IN ('queued', 'running')
                  AND finished_at IS NULL
                  AND COALESCE(json_extract(input, '$.lifecycleRecoveryAttention'), '') != 'stale_nonterminal'
                """,
                (job_id, expected_status),
            )
            if cursor.rowcount != 1:
                return False
            connection.execute(
                """
                INSERT INTO job_events (job_id, sequence, level, message, data)
                SELECT ?, COALESCE(MAX(sequence), 0) + 1, ?, ?, ?
                FROM job_events
                WHERE job_id = ?
                """,
                (job_id, event.level, event.message, json.dumps(event.data, sort_keys=True), job_id),
            )
        return True

    def list_by_actions_and_statuses(
        self,
        *,
        actions: set[str],
        statuses: set[str],
        limit: int,
        stale_before: str | None = None,
        lease_expired_before: str | None = None,
    ) -> list[StoredJobRun]:
        if not actions or not statuses or limit <= 0:
            return []
        action_placeholders = ", ".join("?" for _ in actions)
        status_placeholders = ", ".join("?" for _ in statuses)
        stale_clause = ""
        extra_parameters: tuple[Any, ...] = ()
        if stale_before is not None and lease_expired_before is not None:
            stale_clause = """
                AND (
                  json_extract(input, '$.claimExpiresAt') <= ?
                  OR (json_extract(input, '$.claimExpiresAt') IS NULL AND created_at <= ?)
                )
            """
            extra_parameters = (lease_expired_before, stale_before)
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT id, action, status, target, target_type, target_id, requested_by,
                       input, artifact_refs, created_at, started_at, finished_at
                FROM job_runs
                WHERE action IN ({action_placeholders}) AND status IN ({status_placeholders})
                {stale_clause}
                ORDER BY created_at ASC LIMIT ?
                """,
                (*sorted(actions), *sorted(statuses), *extra_parameters, limit),
            ).fetchall()
        return [self._from_sqlite_row(row) for row in rows]

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _from_sqlite_row(self, row: sqlite3.Row) -> StoredJobRun:
        return StoredJobRun(
            id=row["id"],
            action=row["action"],
            status=row["status"],
            target=row["target"],
            target_type=row["target_type"],
            target_id=row["target_id"],
            requested_by=row["requested_by"],
            input=json.loads(row["input"]),
            artifact_refs=json.loads(row["artifact_refs"]),
            created_at=row["created_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            events=self._events(row["id"]),
        )

    def _events(self, job_id: str) -> list[JobEvent]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT sequence, level, message, data
                FROM job_events
                WHERE job_id = ?
                ORDER BY sequence ASC
                """,
                (job_id,),
            ).fetchall()
        return [JobEvent(row["sequence"], row["level"], row["message"], json.loads(row["data"])) for row in rows]


def _from_models(rows: list[Any]) -> list[StoredJobRun]:
    from app.storage.models import JobEventModel

    if not rows:
        return []
    events = (
        JobEventModel.query.filter(JobEventModel.job_id.in_([row.id for row in rows]))
        .order_by(JobEventModel.sequence.asc())
        .all()
    )
    events_by_job: dict[str, list[Any]] = {}
    for event in events:
        events_by_job.setdefault(event.job_id, []).append(event)
    return [_from_model(row, events=events_by_job.get(row.id, [])) for row in rows]


def _semantic_jobs_sql(*, named: bool = True) -> str:
    engagement_id = ":engagement_id" if named else "?"
    engagement_target = ":engagement_target" if named else "?"
    input_engagement_id = ":engagement_id" if named else "?"
    recent_limit = ":recent_limit" if named else "?"
    category_limit = ":category_limit" if named else "?"
    return f"""
        WITH classified AS (
          SELECT j.*,
            CASE
              WHEN j.action = 'pilot_standard_rti_guarded_execute' THEN 'core'
              WHEN j.action LIKE '%sketch_deploy' OR j.action LIKE '%sketch_teardown'
                OR j.action LIKE '%sketch_reconcile' OR j.action LIKE 'sketch_edge_%' THEN 'sketch'
              WHEN j.action LIKE 'outbound_channel_%' OR j.action = 'engagement_channels_update' THEN 'outbound'
              WHEN j.action LIKE 'inbound_channel_%' THEN 'inbound'
              WHEN j.action IN ('engagement_comprehensive_teardown',
                'provider_keyed_mixed_zero_apply_cleanup', 'provider_keyed_mixed_interrupted_cleanup',
                'provider_keyed_mixed_published_cleanup') THEN 'teardown'
              WHEN j.action LIKE 'provider_keyed_mixed_%destroy%'
                OR j.action LIKE 'provider_keyed_mixed_%inspector%'
                OR j.action = 'provider_keyed_mixed_published_selector_retirement' THEN 'teardown_progress'
              WHEN EXISTS (
                SELECT 1 FROM job_events e WHERE e.job_id = j.id
                  AND (json_type(e.data, '$.capabilities') IS NOT NULL
                    OR json_type(e.data, '$.servicePlacements') IS NOT NULL)
              ) THEN 'capability'
              WHEN EXISTS (
                SELECT 1 FROM job_events e WHERE e.job_id = j.id
                  AND (json_type(e.data, '$.connectionDetails') IS NOT NULL
                    OR json_type(e.data, '$.sketchInfrastructure') IS NOT NULL)
              ) THEN 'topology'
              WHEN EXISTS (
                SELECT 1 FROM job_events e WHERE e.job_id = j.id
                  AND (json_type(e.data, '$.outboundChannels') IS NOT NULL
                    OR json_type(e.data, '$.inboundChannels') IS NOT NULL)
              ) THEN 'channel_state'
              WHEN EXISTS (
                SELECT 1 FROM job_events e WHERE e.job_id = j.id
                  AND (json_type(e.data, '$.mutationStatus') IS NOT NULL
                    OR json_type(e.data, '$.finalCleanupStatus') IS NOT NULL)
              ) THEN 'lifecycle'
              ELSE 'timeline'
            END AS semantic_category
          FROM job_runs j
          WHERE j.target_id = {engagement_id}
             OR j.target = {engagement_target}
             OR json_extract(j.input, '$.engagementId') = {input_engagement_id}
        ), ranked AS (
          SELECT classified.*,
            row_number() OVER (ORDER BY created_at DESC, id DESC) AS timeline_rank,
            row_number() OVER (
              PARTITION BY semantic_category ORDER BY created_at DESC, id DESC
            ) AS category_rank
          FROM classified
        )
        SELECT id, action, status, target, target_type, target_id, requested_by,
               input, artifact_refs, created_at, started_at, finished_at
        FROM ranked
        WHERE timeline_rank <= {recent_limit}
           OR (semantic_category != 'timeline' AND category_rank <= {category_limit})
        ORDER BY created_at DESC, id DESC
    """


def _semantic_jobs_for_engagements_sql(engagement_count: int, *, named: bool = True) -> str:
    requested = (
        "requested(engagement_id) AS (VALUES "
        + ", ".join(
            f"(:engagement_{index})" if named else "(?)"
            for index in range(engagement_count)
        )
        + ")"
        if engagement_count > 0
        else "requested(engagement_id) AS (SELECT NULL WHERE 0)"
    )
    recent_limit = ":recent_limit" if named else "?"
    category_limit = ":category_limit" if named else "?"
    return f"""
        WITH {requested},
        classified AS (
          SELECT requested.engagement_id AS matched_engagement_id, j.*,
            CASE
              WHEN j.action = 'pilot_standard_rti_guarded_execute' THEN 'core'
              WHEN j.action LIKE '%sketch_deploy' OR j.action LIKE '%sketch_teardown'
                OR j.action LIKE '%sketch_reconcile' OR j.action LIKE 'sketch_edge_%' THEN 'sketch'
              WHEN j.action LIKE 'outbound_channel_%' OR j.action = 'engagement_channels_update' THEN 'outbound'
              WHEN j.action LIKE 'inbound_channel_%' THEN 'inbound'
              WHEN j.action IN ('engagement_comprehensive_teardown',
                'provider_keyed_mixed_zero_apply_cleanup', 'provider_keyed_mixed_interrupted_cleanup',
                'provider_keyed_mixed_published_cleanup') THEN 'teardown'
              WHEN j.action LIKE 'provider_keyed_mixed_%destroy%'
                OR j.action LIKE 'provider_keyed_mixed_%inspector%'
                OR j.action = 'provider_keyed_mixed_published_selector_retirement' THEN 'teardown_progress'
              WHEN EXISTS (
                SELECT 1 FROM job_events e WHERE e.job_id = j.id
                  AND (json_type(e.data, '$.capabilities') IS NOT NULL
                    OR json_type(e.data, '$.servicePlacements') IS NOT NULL)
              ) THEN 'capability'
              WHEN EXISTS (
                SELECT 1 FROM job_events e WHERE e.job_id = j.id
                  AND (json_type(e.data, '$.connectionDetails') IS NOT NULL
                    OR json_type(e.data, '$.sketchInfrastructure') IS NOT NULL)
              ) THEN 'topology'
              WHEN EXISTS (
                SELECT 1 FROM job_events e WHERE e.job_id = j.id
                  AND (json_type(e.data, '$.outboundChannels') IS NOT NULL
                    OR json_type(e.data, '$.inboundChannels') IS NOT NULL)
              ) THEN 'channel_state'
              WHEN EXISTS (
                SELECT 1 FROM job_events e WHERE e.job_id = j.id
                  AND (json_type(e.data, '$.mutationStatus') IS NOT NULL
                    OR json_type(e.data, '$.finalCleanupStatus') IS NOT NULL)
              ) THEN 'lifecycle'
              ELSE 'timeline'
            END AS semantic_category
          FROM requested
          JOIN job_runs j
            ON j.target_id = requested.engagement_id
            OR j.target = 'engagement:' || requested.engagement_id
            OR json_extract(j.input, '$.engagementId') = requested.engagement_id
        ), ranked AS (
          SELECT classified.*,
            row_number() OVER (
              PARTITION BY matched_engagement_id ORDER BY created_at DESC, id DESC
            ) AS timeline_rank,
            row_number() OVER (
              PARTITION BY matched_engagement_id, semantic_category
              ORDER BY created_at DESC, id DESC
            ) AS category_rank
          FROM classified
        ), selected AS (
          SELECT matched_engagement_id, id, action, status, target, target_type,
                 target_id, requested_by, input, artifact_refs, created_at,
                 started_at, finished_at
          FROM ranked
          WHERE timeline_rank <= {recent_limit}
             OR (semantic_category != 'timeline' AND category_rank <= {category_limit})
        ), metadata AS (
          SELECT COUNT(*) AS total_job_count,
                 MAX(CASE WHEN id = 'job-seed-001' THEN 1 ELSE 0 END) AS seed_job_exists
          FROM job_runs
        )
        SELECT NULL AS matched_engagement_id, NULL AS id, NULL AS action,
               NULL AS status, NULL AS target, NULL AS target_type,
               NULL AS target_id, NULL AS requested_by, NULL AS input,
               NULL AS artifact_refs, NULL AS created_at, NULL AS started_at,
               NULL AS finished_at, metadata.total_job_count,
               metadata.seed_job_exists, 0 AS result_order
        FROM metadata
        UNION ALL
        SELECT selected.matched_engagement_id, selected.id, selected.action,
               selected.status, selected.target, selected.target_type,
               selected.target_id, selected.requested_by, selected.input,
               selected.artifact_refs, selected.created_at, selected.started_at,
               selected.finished_at, metadata.total_job_count,
               metadata.seed_job_exists, 1 AS result_order
        FROM selected CROSS JOIN metadata
        ORDER BY result_order, matched_engagement_id, created_at DESC, id DESC
    """


def _stored_jobs_from_mappings(rows: list[Any]) -> list[StoredJobRun]:
    from app.storage.models import JobEventModel

    if not rows:
        return []
    ids = [str(row["id"]) for row in rows]
    events = (
        JobEventModel.query.filter(JobEventModel.job_id.in_(ids))
        .order_by(JobEventModel.job_id.asc(), JobEventModel.sequence.asc())
        .all()
    )
    events_by_job: dict[str, list[JobEvent]] = {}
    for event in events:
        events_by_job.setdefault(event.job_id, []).append(
            JobEvent(event.sequence, event.level, event.message, event.data or {})
        )
    return [_stored_job_from_mapping(row, events_by_job.get(str(row["id"]), [])) for row in rows]


def _stored_jobs_by_engagement_from_mappings(
    rows: list[Any],
    engagement_ids: list[str],
) -> dict[str, list[StoredJobRun]]:
    from app.storage.models import JobEventModel

    grouped = {engagement_id: [] for engagement_id in engagement_ids}
    ids = list(dict.fromkeys(str(row["id"]) for row in rows))
    events = (
        JobEventModel.query.filter(JobEventModel.job_id.in_(ids))
        .order_by(JobEventModel.job_id.asc(), JobEventModel.sequence.asc())
        .all()
    )
    events_by_job: dict[str, list[JobEvent]] = {}
    for event in events:
        events_by_job.setdefault(event.job_id, []).append(
            JobEvent(event.sequence, event.level, event.message, event.data or {})
        )
    for row in rows:
        grouped[str(row["matched_engagement_id"])].append(
            _stored_job_from_mapping(row, events_by_job.get(str(row["id"]), []))
        )
    return grouped


def _stored_dashboard_jobs_by_engagement_from_mappings(
    rows: list[Any],
    engagement_ids: list[str],
) -> dict[str, list[StoredJobRun]]:
    from sqlalchemy import text

    from app.storage.database import db

    grouped = {engagement_id: [] for engagement_id in engagement_ids}
    ids = list(dict.fromkeys(str(row["id"]) for row in rows))
    predicates = _dashboard_event_predicates()
    if ids:
        parameters = {f"job_id_{index}": value for index, value in enumerate(ids)}
        placeholders = ", ".join(f":job_id_{index}" for index in range(len(ids)))
        statement = text(
            f"""
            SELECT job_id, sequence, level, message, data
            FROM job_events
            WHERE job_id IN ({placeholders}) AND ({predicates})
            ORDER BY job_id, sequence ASC
            """
        )
    else:
        parameters = {}
        statement = text(
            f"""
            SELECT job_id, sequence, level, message, data
            FROM job_events
            WHERE 0 = 1 AND ({predicates})
            ORDER BY job_id, sequence ASC
            """
        )
    events = db.session.execute(statement, parameters).mappings().all()
    events_by_job: dict[str, list[JobEvent]] = {}
    for event in events:
        events_by_job.setdefault(str(event["job_id"]), []).append(
            JobEvent(
                int(event["sequence"]),
                str(event["level"]),
                str(event["message"]),
                _decoded_event_data(event["data"]),
            )
        )
    for row in rows:
        grouped[str(row["matched_engagement_id"])].append(
            _stored_job_from_mapping(row, events_by_job.get(str(row["id"]), []))
        )
    return grouped


def _sqlite_dashboard_event_rows(connection: sqlite3.Connection, job_ids: list[str]) -> list[Any]:
    predicates = _dashboard_event_predicates()
    if not job_ids:
        return connection.execute(
            f"SELECT job_id, sequence, level, message, data FROM job_events WHERE 0 = 1 AND ({predicates})"
        ).fetchall()
    placeholders = ", ".join("?" for _ in job_ids)
    return connection.execute(
        f"""
        SELECT job_id, sequence, level, message, data
        FROM job_events
        WHERE job_id IN ({placeholders}) AND ({predicates})
        ORDER BY job_id, sequence ASC
        """,
        tuple(job_ids),
    ).fetchall()


def _dashboard_event_predicates() -> str:
    return " OR ".join(
        [f"json_type(data, '$.{key}') IS NOT NULL" for key in DASHBOARD_EVENT_KEYS]
        + ["lower(message) LIKE '%teardown%'"]
    )


def _decoded_event_data(value: Any) -> Any:
    decoded = json.loads(value) if isinstance(value, str) else value
    return decoded or {}


def _stored_job_from_mapping(row: Any, events: list[JobEvent]) -> StoredJobRun:
    def value(key: str):
        return row[key]

    def json_value(key: str, default):
        raw = value(key)
        if raw is None:
            return default
        return json.loads(raw) if isinstance(raw, str) else raw

    def timestamp(key: str) -> str | None:
        raw = value(key)
        return raw.isoformat() if hasattr(raw, "isoformat") else str(raw) if raw is not None else None

    return StoredJobRun(
        id=str(value("id")),
        action=str(value("action")),
        status=str(value("status")),
        target=str(value("target")),
        target_type=str(value("target_type")),
        target_id=str(value("target_id")),
        requested_by=str(value("requested_by")),
        input=json_value("input", {}),
        artifact_refs=json_value("artifact_refs", []),
        created_at=timestamp("created_at") or "",
        started_at=timestamp("started_at"),
        finished_at=timestamp("finished_at"),
        events=events,
    )


def _from_model(row: Any, *, events: list[Any] | None = None) -> StoredJobRun:
    if events is None:
        from app.storage.models import JobEventModel

        events = (
            JobEventModel.query.filter_by(job_id=row.id)
            .order_by(JobEventModel.sequence.asc())
            .all()
        )
    return StoredJobRun(
        id=row.id,
        action=row.action,
        status=row.status,
        target=row.target,
        target_type=row.target_type,
        target_id=row.target_id,
        requested_by=row.requested_by,
        input=row.input or {},
        artifact_refs=row.artifact_refs or [],
        created_at=row.created_at.isoformat(),
        started_at=row.started_at.isoformat() if row.started_at else None,
        finished_at=row.finished_at.isoformat() if row.finished_at else None,
        events=[
            JobEvent(event.sequence, event.level, event.message, event.data or {})
            for event in events
        ],
    )


def _summary_from_model(row: Any) -> JobRunSummary:
    return JobRunSummary(
        id=row.id,
        action=row.action,
        status=row.status,
        target=row.target,
        created_at=row.created_at.isoformat(),
    )


def _parse_datetime(value: str):
    from datetime import datetime

    return datetime.fromisoformat(value)
