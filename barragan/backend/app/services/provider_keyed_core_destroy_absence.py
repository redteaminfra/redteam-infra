# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private DevTest reconciliation of a completed keyed OCI core destroy.

Terraform's successful exit is not cloud absence. This read-only successor
binds the retained pre-destroy OCID seal to an empty state and two complete OCI
GET/list scans. No public dispatcher calls this module.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import time
from typing import Callable

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.services.provider_keyed_comprehensive_teardown import _boundary, _child_id
from app.services.provider_keyed_comprehensive_teardown import recognize_provider_keyed_group_retired
from app.services.provider_keyed_core_destroy_apply import ACTION as APPLY_ACTION
from app.services.provider_keyed_core_destroy_preview import ACTION as PREVIEW_ACTION, _EVENT, _read_regular
from app.services.provider_keyed_oci_core_state import (
    OciCoreStateInventory, OciCoreStateResource, _BASE_ROLES, _ELK_ROLES, _OCID,
)
from app.services.provider_keyed_oci_exact_absence import (
    OciAbsencePending, OciExactWitness, _default_identity_reader,
    _principal_digest, prove_oci_core_absence,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest


ACTION = "provider_keyed_core_destroy_absence"
_FENCE = "provider_keyed_teardown_fence"
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_MAX_ATTEMPTS = 3
_ATTEMPT_SECONDS = 15 * 60
_TOTAL_SECONDS = _MAX_ATTEMPTS * _ATTEMPT_SECONDS


class KeyedCoreDestroyAbsenceAttention(ValueError):
    """Exact retained state or OCI provider absence could not be proved."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stored_utc(value: str) -> datetime:
    """Interpret SQLAlchemy SQLite's timezone-stripped UTC DateTime on read."""
    parsed = datetime.fromisoformat(value)
    if parsed.utcoffset() is None:
        return parsed.replace(tzinfo=timezone.utc)
    if parsed.utcoffset().total_seconds() != 0:
        raise ValueError("OCI absence attempt timestamp is not UTC")
    return parsed


def _parse_json(raw: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate state key")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique)
    if type(value) is not dict:
        raise ValueError("retained state is not an object")
    return value


def _sealed_inventory(seal: dict, state_seal: dict, *, compartment_id: str,
                      engagement_name: str, proxy_count: int, elk_enabled: bool) -> OciCoreStateInventory:
    ids = seal.get("resourceIds")
    expected = dict(_BASE_ROLES)
    if proxy_count == 2:
        expected["oci_core_instance.proxy02"] = ("instance", "proxy02")
    if elk_enabled:
        expected.update(_ELK_ROLES)
    if (type(ids) is not dict or set(ids) != set(expected)
            or len(set(ids.values())) != len(ids)
            or seal.get("resourceIdsSha256") != _fingerprint(ids)
            or seal.get("preDestroyStateSha256") != state_seal.get("rawStateSha256")
            or seal.get("inventorySha256") != state_seal.get("inventorySha256")
            or seal.get("lineage") != state_seal.get("lineage")
            or seal.get("serial") != state_seal.get("serial")
            or state_seal.get("resourceCount") != len(ids)):
        raise ValueError("pre-destroy OCID seal differs")
    resources = []
    for address in sorted(ids):
        ocid = ids[address]
        match = _OCID.fullmatch(ocid) if isinstance(ocid, str) else None
        if match is None or match.group(1) != expected[address][0]:
            raise ValueError("pre-destroy OCID kind differs")
        resources.append(OciCoreStateResource(
            address, ocid, None if address == "oci_core_default_dhcp_options.pilot"
            else compartment_id))
    # The original inventory digest includes the DHCP compartment field. The
    # Terraform parser allows that one field to be null or explicit, so it
    # cannot be reconstructed reliably from the compact apply seal alone.
    # The sealed digest remains bound by the core job and apply event.
    return OciCoreStateInventory(state_seal["rawStateSha256"],
                                 state_seal["inventorySha256"],
                                 state_seal["lineage"], state_seal["serial"],
                                 tuple(resources))


def prove_pending_keyed_oci_core_destroy_absence(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, lease_lookup=None,
    absence_prover: Callable = prove_oci_core_absence,
    oci_command_runner=None, identity_reader=None, pause=None,
    max_scans: int = 61, poll_seconds: int = 10,
) -> StoredJobRun:
    """Persist a one-shot exact absence receipt without releasing the fence."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    lookup = lease_lookup or _db_lease_lookup
    child: StoredJobRun | None = None
    deadline_expired = False
    try:
        if (environment != "devtest" or not isinstance(state_root, Path)
                or state_root != _default_state_root() or state_root.is_symlink()
                or state_root.resolve(strict=True) != state_root):
            raise ValueError("private DevTest boundary differs")
        parent, core, snapshot, operation = _boundary(teardown_parent_id, jobs, plans, lookup)
        published = "publishedSource" in parent.input
        coordinator = jobs.get(_child_id(core.id))
        plan = plans.get(core.input["corePlanId"])
        if (operation != _FENCE
                or coordinator is None or coordinator.status != "running"
                or coordinator.input.get("phase") != (
                    "group_retired" if published else "pending_group_retired")
                or plan is None or plan.id != snapshot["providerScopes"][0]["corePlanId"]
                or plan.apply_job_id != core.id or plan.status != "applied"
                or plan.engagement_id != parent.target_id
                or plan.evidence.get("sketchStateSchema") != "provider-keyed-v2"
                or plan.evidence.get("target", {}).get("name") != "barragan-testing"
                or core.input.get("corePlanEvidenceSha256") != _fingerprint(plan.evidence)
                or core.input.get("target") != plan.evidence.get("target")):
            raise ValueError("reviewed core authority differs")
        # Published retirement is proved from its immutable historical source,
        # never from the OCI state that the completed apply has now emptied.
        retired = None
        if published:
            retired = recognize_provider_keyed_group_retired(
                parent.id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans, lease_lookup=lookup,
            )

        def historical_fence():
            if published and recognize_provider_keyed_group_retired(
                parent.id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans, lease_lookup=lookup,
            ) != retired:
                raise ValueError("published retirement changed")
        state_events = [event for event in core.events if event.message == _EVENT]
        if (len(state_events) != 1 or state_events[0].level != "info"
                or core.events[-2] != state_events[0]
                or core.events[-1].message != "pilot Standard RTI run finished"):
            raise ValueError("applied OCI state seal differs")
        state_seal = state_events[0].data
        if (type(state_seal) is not dict or state_seal.get("schema") != "applied-oci-core-state-v1"
                or state_seal.get("corePlanEvidenceSha256") != core.input["corePlanEvidenceSha256"]
                or any(_HASH.fullmatch(state_seal.get(key) or "") is None
                       for key in ("rawStateSha256", "inventorySha256"))
                or type(state_seal.get("serial")) is not int or state_seal["serial"] < 1):
            raise ValueError("applied OCI state seal is invalid")
        preview = jobs.get(f"job-provider-keyed-core-destroy-preview-{core.id.removeprefix('job-')}")
        applied = jobs.get(f"job-provider-keyed-core-destroy-apply-{core.id.removeprefix('job-')}")
        if (preview is None or preview.action != PREVIEW_ACTION or preview.status != "succeeded"
                or applied is None or applied.action != APPLY_ACTION or applied.status != "succeeded"
                or preview.target_id != parent.target_id or applied.target_id != parent.target_id
                or preview.requested_by != parent.requested_by
                or applied.requested_by != parent.requested_by
                or applied.input.get("previewJobId") != preview.id
                or applied.input.get("previewJournalSha256") != job_event_digest(preview.events)
                or applied.input.get("coreJobId") != core.id
                or applied.input.get("corePlanId") != plan.id
                or applied.input.get("teardownParentId") != parent.id
                or applied.input.get("scopeSnapshotId") != snapshot["snapshotId"]
                or applied.input.get("coordinatorJournalSha256") != job_event_digest(coordinator.events)
                or applied.input.get("planSha256") != preview.events[-1].data.get("planSha256")
                or applied.events[-1].message != "core destroy applied; provider absence pending"
                or applied.events[-1].data.get("providerAbsenceProofPending") is not True):
            raise ValueError("completed core destroy journal differs")
        seals = [event for event in applied.events if event.message == "core destroy prestate identity fenced"]
        if len(seals) != 1 or seals[0].level != "info":
            raise ValueError("pre-destroy OCID seal is missing")
        seal = seals[0].data
        if (type(seal) is not dict or seal.get("coreJobId") != core.id
                or seal.get("corePlanId") != plan.id
                or seal.get("scopeSnapshotId") != snapshot["snapshotId"]
                or seal.get("planSha256") != preview.events[-1].data["planSha256"]
                or applied.events[-1].data.get("preDestroyResourceIdsSha256")
                != seal.get("resourceIdsSha256")):
            raise ValueError("pre-destroy seal binding differs")
        target = plan.evidence["target"]
        inventory = _sealed_inventory(
            seal, state_seal, compartment_id=target["compartmentId"],
            engagement_name=core.input["engagementName"],
            proxy_count=plan.evidence["proxyCount"],
            elk_enabled=plan.evidence["elkEnabled"])
        witness = OciExactWitness(**seal["ociVisibilityWitness"])
        if (witness.phase != "present" or witness.inventory_sha256 != inventory.inventory_sha256
                or witness.resource_ids_sha256 != seal["resourceIdsSha256"]
                or witness.compartment_id != target["compartmentId"]
                or witness.region != target["region"] or witness.auth != "instance_principal"
                or not _HASH.fullmatch(witness.principal_sha256)
                or not _HASH.fullmatch(witness.evidence_sha256)):
            raise ValueError("pre-destroy OCI witness differs")
        state_path = Path(plan.evidence["terraformStatePath"])
        if (not state_path.is_absolute() or state_path.name != "terraform.tfstate"
                or state_path.parent.name != "core"
                or state_path.parents[2] != DEFAULT_TERRAFORM_STATE_ROOT
                or state_path.parent.is_symlink()
                or state_path.parent.resolve(strict=True) != state_path.parent
                or DEFAULT_TERRAFORM_STATE_ROOT.is_symlink()):
            raise ValueError("retained core state path differs")

        def empty_state_sha() -> str:
            raw = _read_regular(state_path)
            state = _parse_json(raw)
            if (type(state.get("version")) is not int or state["version"] != 4
                    or state.get("terraform_version") != plan.evidence["terraformFingerprint"]
                    or state.get("lineage") != inventory.lineage
                    or type(state.get("serial")) is not int
                    or state["serial"] <= inventory.serial
                    or state.get("resources") != [] or state.get("outputs") != {}):
                raise ValueError("retained OCI core state is not exact empty state")
            return hashlib.sha256(raw).hexdigest()

        empty_sha = empty_state_sha()
        cli = Path(seal["ociCliPath"])
        if (not cli.is_absolute() or cli.is_symlink() or not cli.is_file()
                or not os.access(cli, os.X_OK)
                or cli.resolve(strict=True) != cli
                or hashlib.sha256(_read_regular(cli)).hexdigest() != seal["ociCliSha256"]):
            raise ValueError("pinned OCI CLI changed")
        base = {"teardownParentId": parent.id, "coreJobId": core.id,
                "corePlanId": plan.id, "scopeSnapshotId": snapshot["snapshotId"],
                "previewJobId": preview.id, "previewJournalSha256": job_event_digest(preview.events),
                "applyJobId": applied.id, "applyJournalSha256": job_event_digest(applied.events),
                "preDestroyResourceIdsSha256": seal["resourceIdsSha256"],
                "preDestroyStateSha256": inventory.raw_state_sha256,
                "emptyStateSha256": empty_sha, "principalSha256": witness.principal_sha256}
        if (type(max_scans) is not int or max_scans < 2 or max_scans > 61
                or type(poll_seconds) is not int or poll_seconds < 0 or poll_seconds > 10):
            raise ValueError("OCI absence retry time budget differs")
        prefix = f"job-provider-keyed-core-destroy-absence-{core.id.removeprefix('job-')}"
        existing = [row for row in jobs.list_for_engagement(parent.target_id)
                    if row.action == ACTION and row.id.startswith(prefix + "-attempt-")]
        previous = None
        attempt = 1
        for number in range(1, _MAX_ATTEMPTS + 1):
            candidate_id = f"{prefix}-attempt-{number:02d}"
            candidate = jobs.get(candidate_id)
            if candidate is None:
                attempt = number
                break
            expected_input = {**base, "attempt": number,
                              "previousAttemptId": previous.id if previous else None,
                              "previousAttemptJournalSha256":
                              job_event_digest(previous.events) if previous else None}
            if (candidate.action != ACTION or candidate.input != expected_input
                    or candidate.target_id != parent.target_id
                    or candidate.requested_by != parent.requested_by
                    or candidate.artifact_refs != [] or len(candidate.events) != 3
                    or [event.sequence for event in candidate.events] != [1, 2, 3]
                    or [event.message for event in candidate.events[:2]] != [
                        "core destroy absence queued", "core destroy absence started"]
                    or candidate.events[0].data != {} or candidate.events[1].data != {}
                    or candidate.finished_at is None):
                raise ValueError("prior absence attempt differs")
            if candidate.status == "succeeded":
                receipt = candidate.events[-1]
                data = receipt.data
                if (len(existing) != number or receipt.level != "info"
                        or receipt.message != "core destroy exact absence proved"
                        or type(data) is not dict or set(data) != {
                            "emptyStateSha256", "preDestroyResourceIdsSha256",
                            "ociAbsenceWitness"}
                        or data["emptyStateSha256"] != empty_sha
                        or data["preDestroyResourceIdsSha256"] != seal["resourceIdsSha256"]
                        or type(data["ociAbsenceWitness"]) is not dict
                        or set(data["ociAbsenceWitness"]) != set(asdict(witness))):
                    raise ValueError("saved OCI absence receipt differs")
                saved_witness = OciExactWitness(**data["ociAbsenceWitness"])
                if (saved_witness.phase != "absent"
                        or saved_witness.inventory_sha256 != inventory.inventory_sha256
                        or saved_witness.resource_ids_sha256 != seal["resourceIdsSha256"]
                        or saved_witness.compartment_id != target["compartmentId"]
                        or saved_witness.region != target["region"]
                        or saved_witness.auth != "instance_principal"
                        or saved_witness.principal_sha256 != witness.principal_sha256
                        or not _HASH.fullmatch(saved_witness.evidence_sha256)
                        or _principal_digest(identity_reader or _default_identity_reader)
                        != witness.principal_sha256
                        or lookup(parent.target_id) != (plan.id, _FENCE)):
                    raise ValueError("saved OCI absence identity differs")
                historical_fence()
                return candidate
            if (candidate.status != "failed" or candidate.events[-1].level != "error"
                    or candidate.events[-1].message != "core destroy absence unverified"
                    or candidate.events[-1].data != {"retryablePendingTimeout": True}):
                raise ValueError("prior absence attempt is not safely retryable")
            previous = candidate
        else:
            raise ValueError("OCI absence retry budget exhausted")
        if (len(existing) != attempt - 1
                or {row.id for row in existing} != {
                    f"{prefix}-attempt-{number:02d}" for number in range(1, attempt)}):
            raise ValueError("unexpected OCI absence attempt exists")
        first_at = _stored_utc(
            jobs.get(f"{prefix}-attempt-01").created_at) if previous else None
        if (first_at is not None and (
                (datetime.now(timezone.utc) - first_at).total_seconds() >= _TOTAL_SECONDS)):
            raise ValueError("OCI absence retry time budget exhausted")
        child_id = f"{prefix}-attempt-{attempt:02d}"
        base.update({"attempt": attempt,
                     "previousAttemptId": previous.id if previous else None,
                     "previousAttemptJournalSha256":
                     job_event_digest(previous.events) if previous else None})
        child = StoredJobRun(child_id, ACTION, "queued", f"engagement:{parent.target_id}",
                             "engagement", parent.target_id, parent.requested_by, base, [],
                             _now(), None, None,
                             [JobEvent(1, "info", "core destroy absence queued", {})])
        saved = jobs.save_if_absent(child)
        if (saved is None or saved.id != child.id or saved.action != child.action
                or saved.status != child.status or saved.target != child.target
                or saved.target_type != child.target_type
                or saved.target_id != child.target_id
                or saved.requested_by != child.requested_by
                or saved.input != child.input or saved.artifact_refs != child.artifact_refs
                or saved.created_at not in {child.created_at,
                                           child.created_at.removesuffix("+00:00")}
                or saved.started_at is not None or saved.finished_at is not None
                or saved.events != child.events or jobs.get(child_id) != saved):
            raise ValueError("core absence child reservation lost")
        child = jobs.start_if_queued(saved, started_at=_now(),
                                     event=JobEvent(2, "info", "core destroy absence started", {}))
        if child is None:
            raise ValueError("core absence child start lost")
        first_at = first_at or _stored_utc(child.created_at)
        elapsed = (datetime.now(timezone.utc) - first_at).total_seconds()
        if elapsed < 0 or elapsed >= _TOTAL_SECONDS:
            raise ValueError("OCI absence total time budget expired")
        deadline = time.monotonic() + min(_ATTEMPT_SECONDS, _TOTAL_SECONDS - elapsed)

        def fence():
            nonlocal deadline_expired
            if time.monotonic() >= deadline:
                deadline_expired = True
                raise ValueError("OCI absence attempt time budget expired")
            if (jobs.get(parent.id) != parent or jobs.get(core.id) != core
                    or jobs.get(coordinator.id) != coordinator
                    or jobs.get(preview.id) != preview or jobs.get(applied.id) != applied
                    or plans.get(plan.id) != plan or lookup(parent.target_id) != (plan.id, _FENCE)
                    or jobs.get(child_id) != child or empty_state_sha() != empty_sha
                    or hashlib.sha256(_read_regular(cli)).hexdigest() != seal["ociCliSha256"]):
                raise ValueError("core absence authority changed")
            historical_fence()

        kwargs = {"compartment_id": target["compartmentId"], "region": target["region"],
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
                or result.compartment_id != target["compartmentId"]
                or result.region != target["region"] or result.auth != "instance_principal"
                or result.principal_sha256 != witness.principal_sha256
                or not _HASH.fullmatch(result.evidence_sha256)):
            raise ValueError("OCI exact absence witness differs")
        fence()
        finished = jobs.finish_if_running(
            child, status="succeeded", finished_at=_now(),
            event=JobEvent(3, "info", "core destroy exact absence proved", {
                "emptyStateSha256": empty_sha,
                "preDestroyResourceIdsSha256": seal["resourceIdsSha256"],
                "ociAbsenceWitness": asdict(result),
            }))
        if finished is None:
            raise ValueError("core absence receipt changed")
        return finished
    except Exception as exc:
        if child is not None and child.status == "running":
            try:
                jobs.finish_if_running(
                    child, status="failed", finished_at=_now(),
                    event=JobEvent(len(child.events) + 1, "error",
                                   "core destroy absence unverified", {
                                       "retryablePendingTimeout": (
                                           type(exc) is OciAbsencePending or deadline_expired),
                                   }))
            except Exception:
                pass
        raise KeyedCoreDestroyAbsenceAttention(
            "core destroy absence is unverified; reconcile retained child"
        ) from None
