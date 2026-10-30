# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private exact OCI absence after the one-shot mixed zero-Apply core GO.

The pre-destroy state is historical evidence here. This reader never resumes
Terraform Apply, edits the retained Inspector, or advances engagement status.
"""

from __future__ import annotations

from dataclasses import asdict, fields, replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
import time
from typing import Callable
from uuid import uuid4

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.services.provider_keyed_core_destroy_absence import (
    _ATTEMPT_SECONDS, _MAX_ATTEMPTS, _TOTAL_SECONDS, _parse_json,
    _sealed_inventory, _stored_utc,
)
from app.services.provider_keyed_core_destroy_preview import _EVENT, _read_regular
from app.services.provider_keyed_mixed_initial_plan_parent import (
    _parent_id as initial_parent_id, _validate_parent,
)
from app.services.provider_keyed_mixed_initial_coordinator import (
    recognize_mixed_initial_host_proof_handoff,
)
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id as initial_apply_child_id,
)
from app.services.provider_keyed_mixed_zero_apply_cleanup import (
    ACTION as CLEANUP_ACTION, _PHASE as CLEANUP_PHASE, _parent_id,
)
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    ACTION as PUBLISHED_ACTION, parent_id as published_parent_id,
)
from app.services.provider_keyed_mixed_published_post_oci_source import (
    PublishedMixedPostOciSource, audit_published_mixed_post_oci_source,
)
from app.services.provider_keyed_mixed_zero_apply_core_apply import (
    ACTION as APPLY_ACTION, _child_id as apply_child_id,
)
from app.services.provider_keyed_mixed_zero_apply_core_preview import (
    ACTION as PREVIEW_ACTION, _child_id as preview_child_id,
)
from app.services.provider_keyed_mixed_zero_apply_teardown_source import (
    MixedZeroApplySource, _apply_pre_go_prefix, canonical_mixed_core_apply_events,
)
from app.services.provider_keyed_oci_exact_absence import (
    OciAbsencePending, OciExactWitness, _default_identity_reader,
    _principal_digest, prove_oci_core_absence,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest


ACTION = "provider_keyed_mixed_zero_apply_core_destroy_absence"
_FENCE = "provider_keyed_teardown_fence"
_HASH = re.compile(r"[0-9a-f]{64}\Z")


class MixedZeroApplyCoreAbsenceAttention(ValueError):
    """Exact OCI absence or its retained authority is unproved."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(value: str) -> str:
    return (datetime.fromisoformat(value) + timedelta(seconds=60)).isoformat()


def _child_prefix(core_job_id: str) -> str:
    return f"job-provider-keyed-mixed-core-destroy-absence-{core_job_id.removeprefix('job-')}"


def _authority_digest(authority: tuple) -> str:
    parent, core, initial, preview, applied, plan, source, *_ = authority
    return _fingerprint({"jobs": [asdict(row) for row in (
        parent, core, initial, preview, applied)], "plan": asdict(plan),
        "source": asdict(source)})


def _authority(engagement_id, core_job_id, jobs, plans, lookup, *,
               interrupted=False, published=False,
               post_source_reader=audit_published_mixed_post_oci_source):
    """Use only immutable pre-GO seals; the OCI state may now be empty."""
    core = jobs.get(core_job_id)
    if core is None or not isinstance(core.input, dict):
        raise ValueError("mixed applied core is absent")
    plan = plans.get(core.input.get("corePlanId"))
    if published:
        parent = jobs.get(published_parent_id(core_job_id))
    elif interrupted:
        from app.services.provider_keyed_mixed_interrupted_cleanup import (
            _parent_id as interrupted_parent_id,
            recognize_mixed_interrupted_sealed_plans,
        )
        from app.services.provider_keyed_mixed_interrupted_dispatch import _saved_plans, _saved_review
        from app.services.provider_keyed_mixed_interrupted_oci_tail import InterruptedHistoricalOciSource
        parent = jobs.get(interrupted_parent_id(core_job_id))
    else:
        parent = jobs.get(_parent_id(core_job_id))
    initial = jobs.get(initial_parent_id(core_job_id))
    preview = jobs.get(preview_child_id(core_job_id))
    applied = jobs.get(apply_child_id(core_job_id))
    if (plan is None or parent is None or initial is None or preview is None
            or applied is None or plan.engagement_id != engagement_id
            or plan.status != "applied" or plan.apply_job_id != core.id
            or core.status != "succeeded"
            or core.input.get("corePlanEvidenceSha256") != _fingerprint(plan.evidence)
            or core.input.get("target") != plan.evidence.get("target")
            or plan.evidence.get("target", {}).get("name") != "barragan-testing"
            or lookup(engagement_id) != (plan.id, _FENCE)):
        raise ValueError("mixed core or fence differs")
    raw = parent.input.get("source") if isinstance(parent.input, dict) else None
    if published:
        source = post_source_reader(parent, initial, core, plan, jobs, lookup)
        if (type(source) is not PublishedMixedPostOciSource
                or parent.id != published_parent_id(core_job_id)
                or parent.action != PUBLISHED_ACTION
                or parent.target_id != engagement_id
                or parent.input.get("coreJobId") != core_job_id
                or parent.input.get("corePlanId") != plan.id
                or parent.input.get("publishedSourceSha256")
                   != _fingerprint(parent.input.get("publishedSource"))):
            raise ValueError("published historical OCI source differs")
        source_sha = parent.input["publishedSourceSha256"]
    elif interrupted:
        review, plan_set = _saved_review(parent), _saved_plans(parent)
        recognize_mixed_interrupted_sealed_plans(parent, initial, review, plan_set)
        record_ids = preview.input.get("inspectorRecordIds")
        if (type(record_ids) is not list or len(record_ids) != 2
                or len(set(record_ids)) != 2
                or any(type(value) is not str or not value for value in record_ids)
                or parent.input.get("corePlanId") != plan.id):
            raise ValueError("interrupted historical source differs")
        source = InterruptedHistoricalOciSource(
            preview.input.get("stateSha256"), preview.input.get("inventorySha256"),
            tuple(record_ids))
        source_sha = parent.input["sourceSha256"]
    else:
        if type(raw) is not dict or set(raw) != {field.name for field in fields(MixedZeroApplySource)}:
            raise ValueError("historical mixed source differs")
        source = MixedZeroApplySource(**raw)
        source_sha = _fingerprint(raw)
    if (not interrupted and not published and (
            parent.id != _parent_id(core.id) or parent.action != CLEANUP_ACTION
            or parent.status != "queued" or parent.started_at is not None
            or parent.finished_at is not None or parent.artifact_refs != []
            or parent.target != f"engagement:{engagement_id}"
            or parent.target_type != "engagement" or parent.target_id != engagement_id
            or not isinstance(parent.requested_by, str) or not parent.requested_by
            or parent.input != {"schema": "mixed-zero-apply-cleanup-v1",
                                "engagementId": engagement_id, "coreJobId": core.id,
                                "corePlanId": plan.id, "source": raw,
                                "sourceSha256": _fingerprint(raw),
                                "phase": CLEANUP_PHASE, "mutation": True}
            or parent.events != [JobEvent(1, "info", "mixed zero-Apply cleanup fenced",
                                          {"sourceSha256": _fingerprint(raw)})]
            or source.engagement_id != engagement_id or source.core_job_id != core.id
            or source.core_plan_id != plan.id or source.parent_job_id != initial.id
            or source.parent_journal_sha256 != job_event_digest(initial.events)
            or source.review_fingerprint != plan.evidence["sketchAuthorization"]["fingerprint"]
            or tuple(source.ordered_providers) != tuple(initial.input["orderedProviders"])
            or tuple(source.provider_receipt_sha256) != (
                initial.events[2].data["receiptSha256"],
                initial.events[3].data["receiptSha256"])
            or len(source.owned_inspector_record_ids) != 2)):
        raise ValueError("historical mixed source seal changed")
    if published:
        pass  # Historical published parent was rechecked by post_source_reader.
    elif interrupted:
        phase = initial.input.get("phase")
        if phase == "awaiting_mixed_host_proof":
            recognize_mixed_initial_host_proof_handoff(
                initial, core, core.id,
                {provider: jobs.get(initial_apply_child_id(core.id, provider))
                 for provider in initial.input["orderedProviders"]})
        elif phase == "apply_sealed":
            _validate_parent(initial, core, plan, initial.input["chainIds"],
                             initial.input["orderedProviders"])
        else:
            raise ValueError("interrupted mixed parent phase differs")
    else:
        _validate_parent(initial, core, plan, initial.input["chainIds"],
                         initial.input["orderedProviders"])
    seals = [event for event in core.events if event.message == _EVENT]
    if (len(seals) != 1 or core.events[-2] != seals[0]
            or core.events[-1].message != "pilot Standard RTI run finished"
            or seals[0].level != "info"):
        raise ValueError("applied core state seal differs")
    state_seal = seals[0].data
    if (type(state_seal) is not dict
            or state_seal.get("schema") != "applied-oci-core-state-v1"
            or state_seal.get("corePlanEvidenceSha256") != _fingerprint(plan.evidence)
            or state_seal.get("rawStateSha256") != source.core_state_sha256
            or state_seal.get("inventorySha256") != source.core_inventory_sha256):
        raise ValueError("historical core inventory changed")
    receipt = preview.events[-1].data if preview.events else {}
    preview_input = {
        "schema": ("mixed-published-core-preview-v1" if published
                   else "mixed-interrupted-core-preview-v1" if interrupted
                   else "mixed-zero-apply-core-preview-v1"),
        "teardownParentId": parent.id, "coreJobId": core.id,
        "corePlanId": plan.id, "sourceSha256": source_sha,
        "parentJournalSha256": job_event_digest(parent.events),
        "stateSha256": source.core_state_sha256,
        "inventorySha256": source.core_inventory_sha256,
        "leaseOperation": _FENCE,
    }
    if interrupted or published:
        preview_input["inspectorRecordIds"] = list(source.owned_inspector_record_ids)
    if (preview.id != preview_child_id(core.id) or preview.action != PREVIEW_ACTION
            or preview.status != "succeeded" or preview.target_id != engagement_id
            or preview.requested_by != parent.requested_by or len(preview.events) != 3
            or preview.events[-1].message != "mixed core destroy preview saved"
            or preview.input != preview_input
            or receipt.get("sourceSha256") != source_sha
            or receipt.get("stateSha256") != source.core_state_sha256
            or receipt.get("inventorySha256") != source.core_inventory_sha256
            or receipt.get("leaseOwner") != plan.id
            or receipt.get("leaseOperation") != _FENCE
            or not _HASH.fullmatch(receipt.get("planSha256") or "")):
        raise ValueError("reviewed mixed preview differs")
    events = canonical_mixed_core_apply_events(applied)
    seal = events[5].data
    inventory = _sealed_inventory(
        seal, state_seal, compartment_id=plan.evidence["target"]["compartmentId"],
        engagement_name=core.input["engagementName"],
        proxy_count=plan.evidence["proxyCount"],
        elk_enabled=plan.evidence["elkEnabled"])
    if (len(applied.events) in (14, 15)
            and applied.events[8].message == "mixed core SHOW recovery claimed"):
        # Authenticate the abandoned read-only SHOW before normalization drops
        # it from the logical successful journal.
        _apply_pre_go_prefix(replace(applied, events=applied.events[:len(applied.events) - 10]),
                             core=core, plan=plan, inventory=inventory,
                             preview=preview, interrupted=interrupted)
    elif (len(applied.events) == 14
          and applied.events[8].message == "mixed core pre-GO Apply recovery claimed"):
        _apply_pre_go_prefix(replace(applied, events=applied.events[:8]),
                             core=core, plan=plan, inventory=inventory,
                             preview=preview, interrupted=interrupted)
    base = {"teardownParentId": parent.id, "coreJobId": core.id,
            "corePlanId": plan.id, "sourceSha256": source_sha,
            "previewJobId": preview.id,
            "previewJournalSha256": job_event_digest(preview.events),
            "planSha256": receipt["planSha256"], "mutation": True}
    if (applied.id != apply_child_id(core.id) or applied.action != APPLY_ACTION
            or applied.status != "succeeded" or applied.input != base
            or applied.target != f"engagement:{engagement_id}"
            or applied.target_type != "engagement" or applied.target_id != engagement_id
            or applied.requested_by != parent.requested_by
            or applied.started_at is None or applied.finished_at is None
            or applied.artifact_refs != []
            or [(event.sequence, event.level, event.message) for event in events]
            != [(1, "info", "mixed core destroy apply queued"),
                (2, "info", "mixed core destroy apply started"),
                (3, "info", "core destroy command intent fenced"),
                (4, "info", "core destroy command started before GO"),
                (5, "info", "core destroy command result fenced"),
                (6, "info", "core destroy prestate identity fenced"),
                (7, "info", "core destroy command intent fenced"),
                (8, "info", "core destroy command started before GO"),
                (9, "info", "core destroy GO support rechecked"),
                (10, "info", "core destroy command result fenced"),
                (11, "info", "core destroy applied; provider absence pending")]
            or events[0].data != {} or events[1].data != {}):
        raise ValueError("completed mixed Apply differs")
    _apply_pre_go_prefix(replace(applied, events=events[:9]),
                         core=core, plan=plan, inventory=inventory, preview=preview,
                         interrupted=interrupted)
    outcome = events[9].data
    if (set(outcome) != {"phase", "invocationId", "returnCode", "stdoutBytes",
                         "stderrBytes", "stdoutTruncated", "stderrTruncated"}
            or outcome["phase"] != "apply"
            or outcome["invocationId"] != events[6].data["invocationId"]
            or outcome["returnCode"] != 0
            or any(type(outcome[key]) is not int or outcome[key] < 0
                   for key in ("stdoutBytes", "stderrBytes"))
            or outcome["stdoutTruncated"] is not False
            or outcome["stderrTruncated"] is not False
            or events[10].data != {
                "providerAbsenceProofPending": True,
                "preDestroyResourceIdsSha256": seal["resourceIdsSha256"]}):
        raise ValueError("mixed Apply completion differs")
    witness = OciExactWitness(**seal["ociVisibilityWitness"])
    if (witness.phase != "present" or witness.inventory_sha256 != inventory.inventory_sha256
            or witness.resource_ids_sha256 != seal["resourceIdsSha256"]
            or witness.compartment_id != plan.evidence["target"]["compartmentId"]
            or witness.region != plan.evidence["target"]["region"]
            or witness.auth != "instance_principal"
            or not _HASH.fullmatch(witness.principal_sha256)
            or not _HASH.fullmatch(witness.evidence_sha256)):
        raise ValueError("pre-destroy positive OCI witness differs")
    return parent, core, initial, preview, applied, plan, source, inventory, seal, witness


def prove_mixed_zero_apply_oci_core_absence(
    engagement_id: str, core_job_id: str, *, environment: str, state_root: Path,
    core_state_root: Path, job_repository=None, plan_repository=None, lease_lookup=None,
    absence_prover: Callable = prove_oci_core_absence,
    oci_command_runner=None, identity_reader=None, pause=None,
    max_scans: int = 61, poll_seconds: int = 10,
    interrupted: bool = False, published: bool = False,
    post_source_reader: Callable = audit_published_mixed_post_oci_source,
) -> StoredJobRun:
    """Save an exact read-only OCI absence receipt under the retained fence."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    lookup = lease_lookup or _db_lease_lookup
    current: StoredJobRun | None = None
    pending_timeout = False
    try:
        if (environment != "devtest" or state_root != _default_state_root()
                or state_root.is_symlink()
                or state_root.resolve(strict=True) != state_root
                or core_state_root != DEFAULT_TERRAFORM_STATE_ROOT
                or core_state_root.is_symlink()
                or type(max_scans) is not int or not 2 <= max_scans <= 61
                or type(poll_seconds) is not int or not 0 <= poll_seconds <= 10):
            raise ValueError("private mixed absence boundary differs")
        if (type(interrupted) is not bool or type(published) is not bool
                or (interrupted and published)):
            raise ValueError("mixed OCI absence mode differs")
        authority = _authority(engagement_id, core_job_id, jobs, plans, lookup,
                               interrupted=interrupted, published=published,
                               post_source_reader=post_source_reader)
        authority_digest = _authority_digest(authority)
        parent, core, initial, preview, applied, plan, source, inventory, seal, witness = authority
        state_path = Path(plan.evidence["terraformStatePath"])
        if (not state_path.is_absolute() or state_path.name != "terraform.tfstate"
                or state_path.parent.name != "core" or state_path.parents[2] != core_state_root
                or state_path.is_symlink() or state_path.parent.is_symlink()
                or state_path.parent.resolve(strict=True) != state_path.parent):
            raise ValueError("retained OCI state path differs")

        def empty_sha():
            raw = _read_regular(state_path)
            state = _parse_json(raw)
            if (type(state.get("version")) is not int or state["version"] != 4
                    or state.get("terraform_version") != plan.evidence["terraformFingerprint"]
                    or state.get("lineage") != inventory.lineage
                    or type(state.get("serial")) is not int
                    or state["serial"] <= inventory.serial
                    or state.get("resources") != [] or state.get("outputs") != {}):
                raise ValueError("retained OCI state is not exact empty state")
            return hashlib.sha256(raw).hexdigest()

        empty_state_sha = empty_sha()
        cli = Path(seal["ociCliPath"])
        if (not cli.is_absolute() or cli.is_symlink() or not cli.is_file()
                or hashlib.sha256(_read_regular(cli)).hexdigest() != seal["ociCliSha256"]):
            raise ValueError("pinned OCI CLI changed")
        base = {"teardownParentId": parent.id, "coreJobId": core.id,
                "corePlanId": plan.id,
                "sourceSha256": (parent.input["publishedSourceSha256"] if published
                                 else _fingerprint(parent.input["source"])),
                "previewJobId": preview.id,
                "previewJournalSha256": job_event_digest(preview.events),
                "applyJobId": applied.id,
                "applyJournalSha256": job_event_digest(applied.events),
                "preDestroyResourceIdsSha256": seal["resourceIdsSha256"],
                "preDestroyStateSha256": inventory.raw_state_sha256,
                "emptyStateSha256": empty_state_sha,
                "principalSha256": witness.principal_sha256}
        prefix = _child_prefix(core.id)
        previous = None
        existing = [row for row in jobs.list_for_engagement(engagement_id)
                    if row.action == ACTION and row.id.startswith(prefix + "-attempt-")]
        for number in range(1, _MAX_ATTEMPTS + 1):
            candidate = jobs.get(f"{prefix}-attempt-{number:02d}")
            if candidate is None:
                attempt = number
                break
            expected = {**base, "attempt": number,
                        "previousAttemptId": previous.id if previous else None,
                        "previousAttemptJournalSha256": (
                            job_event_digest(previous.events) if previous else None)}
            if (candidate.action != ACTION or candidate.input != expected
                    or candidate.status not in {"failed", "succeeded"}
                    or candidate.target != f"engagement:{engagement_id}"
                    or candidate.target_type != "engagement"
                    or candidate.target_id != engagement_id
                    or candidate.requested_by != parent.requested_by
                    or candidate.artifact_refs != [] or candidate.finished_at is None
                    or len(candidate.events) != 3
                    or candidate.events[:2] != [
                        JobEvent(1, "info", "mixed core absence queued", {}),
                        JobEvent(2, "info", "mixed core absence started", {})]):
                raise ValueError("prior mixed absence attempt differs")
            terminal = candidate.events[2]
            if candidate.status == "succeeded":
                data = terminal.data
                if (len(existing) != number or terminal != JobEvent(
                        3, "info", "mixed core exact absence proved", data)
                        or type(data) is not dict or set(data) != {
                            "emptyStateSha256", "preDestroyResourceIdsSha256",
                            "ociAbsenceWitness"}
                        or data["emptyStateSha256"] != empty_state_sha
                        or data["preDestroyResourceIdsSha256"] != seal["resourceIdsSha256"]
                        or type(data["ociAbsenceWitness"]) is not dict
                        or set(data["ociAbsenceWitness"]) != set(asdict(witness))):
                    raise ValueError("saved mixed absence receipt differs")
                saved = OciExactWitness(**data["ociAbsenceWitness"])
                if (saved.phase != "absent"
                        or saved.inventory_sha256 != inventory.inventory_sha256
                        or saved.resource_ids_sha256 != seal["resourceIdsSha256"]
                        or saved.compartment_id != witness.compartment_id
                        or saved.region != witness.region or saved.auth != witness.auth
                        or saved.principal_sha256 != witness.principal_sha256
                        or not _HASH.fullmatch(saved.evidence_sha256)
                        or _principal_digest(identity_reader or _default_identity_reader)
                        != witness.principal_sha256):
                    raise ValueError("saved mixed absence identity differs")
                return candidate
            if terminal != JobEvent(3, "error", "mixed core absence unverified",
                                    {"retryablePendingTimeout": True}):
                raise ValueError("prior mixed absence attempt is not retryable")
            previous = candidate
        else:
            raise ValueError("mixed absence retry budget exhausted")
        if (len(existing) != attempt - 1
                or {row.id for row in existing} != {
                    f"{prefix}-attempt-{number:02d}" for number in range(1, attempt)}):
            raise ValueError("mixed absence attempt set differs")
        first_at = _stored_utc(jobs.get(f"{prefix}-attempt-01").created_at) if previous else None
        if first_at and (datetime.now(timezone.utc) - first_at).total_seconds() >= _TOTAL_SECONDS:
            raise ValueError("mixed absence total budget expired")
        candidate_id = f"{prefix}-attempt-{attempt:02d}"
        input_data = {**base, "attempt": attempt,
                      "previousAttemptId": previous.id if previous else None,
                      "previousAttemptJournalSha256": (
                          job_event_digest(previous.events) if previous else None)}
        queued = StoredJobRun(candidate_id, ACTION, "queued", f"engagement:{engagement_id}",
                              "engagement", engagement_id, parent.requested_by, input_data, [],
                              _now(), None, None,
                              [JobEvent(1, "info", "mixed core absence queued", {})])
        saved = jobs.save_if_absent(queued)
        if (saved is None or saved.id != queued.id or saved.action != ACTION
                or saved.status != "queued" or saved.input != input_data
                or saved.events != queued.events):
            raise ValueError("mixed absence reservation lost")
        current = jobs.start_if_queued(
            saved, started_at=_now(),
            event=JobEvent(2, "info", "mixed core absence started", {}))
        if current is None:
            raise ValueError("mixed absence start lost")
        owner, token = f"mixed-core-absence-{uuid4().hex}", uuid4().hex
        at = _now()
        current = jobs.claim_lease(candidate_id, owner=owner, token=token,
                                   claimed_at=at, expires_at=_later(at),
                                   eligible_statuses={"running"})
        if current is None:
            raise ValueError("mixed absence claim lost")
        first_at = first_at or _stored_utc(current.created_at)
        elapsed = (datetime.now(timezone.utc) - first_at).total_seconds()
        if elapsed < 0 or elapsed >= _TOTAL_SECONDS:
            raise ValueError("mixed absence total budget expired")
        deadline = time.monotonic() + min(_ATTEMPT_SECONDS, _TOTAL_SECONDS - elapsed)

        def fence():
            nonlocal current, pending_timeout
            if time.monotonic() >= deadline:
                pending_timeout = True
                raise ValueError("mixed absence attempt timed out")
            if (jobs.get(parent.id) != parent or jobs.get(core.id) != core
                    or jobs.get(initial.id) != initial or jobs.get(preview.id) != preview
                    or jobs.get(applied.id) != applied or plans.get(plan.id) != plan
                    or lookup(engagement_id) != (plan.id, _FENCE)
                    or jobs.get(candidate_id) != current or empty_sha() != empty_state_sha
                    or hashlib.sha256(_read_regular(cli)).hexdigest() != seal["ociCliSha256"]):
                raise ValueError("mixed absence authority changed")
            at = _now()
            if datetime.fromisoformat(at) >= datetime.fromisoformat(
                    current.input["claimExpiresAt"]):
                raise ValueError("mixed absence claim expired")
            renewed = jobs.renew_lease(candidate_id, owner=owner, token=token,
                                       heartbeat_at=at, expires_at=_later(at))
            if (renewed is None or renewed.events != current.events
                    or renewed.input.get("claimOwner") != owner
                    or renewed.input.get("claimToken") != token):
                raise ValueError("mixed absence heartbeat lost")
            current = renewed

        def terminal_authority_check():
            # Called by the repository after taking SQLite's writer slot and
            # before the terminal child UPDATE. No cloud read or mutation.
            if (_authority_digest(_authority(
                    engagement_id, core_job_id, jobs, plans, lookup,
                    interrupted=interrupted, published=published,
                    post_source_reader=post_source_reader)) != authority_digest
                    or jobs.get(candidate_id) != current
                    or lookup(engagement_id) != (plan.id, _FENCE)
                    or empty_sha() != empty_state_sha
                    or hashlib.sha256(_read_regular(cli)).hexdigest() != seal["ociCliSha256"]):
                raise ValueError("mixed absence terminal authority changed")

        kwargs = {"compartment_id": witness.compartment_id, "region": witness.region,
                  "engagement_name": core.input["engagementName"],
                  "oci_executable": str(cli), "pre_witness": witness,
                  "max_scans": max_scans, "poll_seconds": poll_seconds, "fence": fence}
        if oci_command_runner is not None:
            kwargs["runner"] = oci_command_runner
        if identity_reader is not None:
            kwargs["identity_reader"] = identity_reader
        if pause is not None:
            kwargs["pause"] = pause
        fence()
        result = absence_prover(inventory, **kwargs)
        fence()
        if (type(result) is not OciExactWitness or result.phase != "absent"
                or result.inventory_sha256 != inventory.inventory_sha256
                or result.resource_ids_sha256 != seal["resourceIdsSha256"]
                or result.compartment_id != witness.compartment_id
                or result.region != witness.region or result.auth != witness.auth
                or result.principal_sha256 != witness.principal_sha256
                or not _HASH.fullmatch(result.evidence_sha256)):
            raise ValueError("mixed exact OCI absence witness differs")
        fence()
        finished = jobs.finish_mixed_core_absence_if_claimed(
            current, owner=owner, token=token, lease_owner=plan.id,
            expected_event_digest=job_event_digest(current.events),
            status="succeeded", finished_at=_now(),
            authority_check=terminal_authority_check,
            event=JobEvent(3, "info", "mixed core exact absence proved", {
                "emptyStateSha256": empty_state_sha,
                "preDestroyResourceIdsSha256": seal["resourceIdsSha256"],
                "ociAbsenceWitness": asdict(result)}))
        if finished is None:
            raise ValueError("mixed absence receipt changed")
        return finished
    except Exception as exc:
        if current is not None and current.status == "running":
            try:
                jobs.finish_mixed_core_absence_if_claimed(
                    current, owner=owner, token=token, lease_owner=plan.id,
                    expected_event_digest=job_event_digest(current.events),
                    status="failed", finished_at=_now(),
                    authority_check=terminal_authority_check,
                    event=JobEvent(3, "error", "mixed core absence unverified", {
                        "retryablePendingTimeout": (
                            type(exc) is OciAbsencePending or pending_timeout)}))
            except Exception:
                pass
        raise MixedZeroApplyCoreAbsenceAttention(
            "mixed core absence is unverified; reconcile retained child") from None
