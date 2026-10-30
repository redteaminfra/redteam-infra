# Copyright (c) 2026, Oracle and/or its affiliates.
"""DevTest-only first phase of comprehensive keyed teardown.

The confirmed comprehensive parent remains queued and byte-for-byte unchanged.
This deterministic child journals the existing core-lease handoff and stops
before Inspector, outbound, Terraform, or provider cleanup.
"""

from __future__ import annotations

from app.services.provider_keyed_published_initial_cleanup_authority import queued_cleanup_event_data

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Callable
from uuid import uuid4

from app.domain import JobEvent
from app.services.engagement_teardown import (
    ENGAGEMENT_TEARDOWN_ACTION, _fingerprint, _parent_id,
    _validated_parent_boundary, engagement_teardown_in_progress,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_teardown_handoff import handoff_terminal_provider_keyed_teardown
from app.services.provider_keyed_teardown_quiescence import audit_pending_provider_keyed_bootstrap
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest


ACTION = "provider_keyed_comprehensive_teardown"
_OLD = "provider_keyed_initial"
_FENCE = "provider_keyed_teardown_fence"
_OWNER = "provider-keyed-comprehensive-handoff"


class ProviderKeyedComprehensiveTeardownError(ValueError):
    """Redacted first-phase failure; no outbound/provider cleanup was run."""


class ProviderKeyedComprehensiveTeardownAttention(ProviderKeyedComprehensiveTeardownError):
    """One-shot Inspector create intent exists; recovery must not rearm it."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _boundary(parent_id: str, jobs, plans, lookup) -> tuple[StoredJobRun, object, dict, str]:
    parent = jobs.get(parent_id)
    if (parent is None or parent.action != ENGAGEMENT_TEARDOWN_ACTION
            or parent.status != "queued" or parent.started_at is not None
            or parent.finished_at is not None or parent.input.get("phase") != "queued"
            or parent.input.get("mutation") is not True or len(parent.events) != 1
            or parent.events[0].message != "engagement teardown queued"):
        raise ValueError("confirmed queued parent differs")
    core, snapshot = _validated_parent_boundary(parent, jobs)
    scope = snapshot.get("providerScopes")
    if (snapshot.get("snapshotId") != _fingerprint({
            key: value for key, value in snapshot.items() if key != "snapshotId"})
            or parent.events[0].data != queued_cleanup_event_data(snapshot)
            or parent.id != _parent_id(core.id)
            or engagement_teardown_in_progress(parent.target_id, repository=jobs) != parent
            or core.status != "succeeded" or core.input.get("sketchStateSchema") != "provider-keyed-v2"
            or type(scope) is not list or len(scope) != 1
            or snapshot.get("providerScopeSha256") != _fingerprint({"providerScopes": scope})):
        raise ValueError("confirmed keyed scope differs")
    plan_id = scope[0]["corePlanId"]
    if "publishedSource" in parent.input:
        from app.services.provider_keyed_published_initial_cleanup_authority import validate_saved_cleanup
        validate_saved_cleanup(parent, core, snapshot, jobs)
    plan = plans.get(plan_id)
    lease = lookup(parent.target_id)
    if (core.input.get("corePlanId") != plan_id or plan is None
            or plan.engagement_id != parent.target_id or plan.status != "applied"
            or plan.apply_job_id != core.id
            or lease not in ((plan_id, _OLD), (plan_id, _FENCE))):
        raise ValueError("retained core plan lease differs")
    return parent, core, snapshot, lease[1]


def _child_id(core_id: str) -> str:
    return f"job-provider-keyed-comprehensive-teardown-{core_id.removeprefix('job-')}"


def _same_child(child: StoredJobRun, parent: StoredJobRun, core, snapshot: dict) -> bool:
    expected = {
        "engagementId": parent.target_id, "coreJobId": core.id,
        "corePlanId": core.input["corePlanId"], "teardownParentId": parent.id,
        "scopeSnapshotId": snapshot["snapshotId"],
        "providerScopeSha256": snapshot["providerScopeSha256"],
        "mutation": True,
    }
    phase = child.input.get("phase")
    claim_keys = {"claimOwner", "claimToken", "claimClaimedAt", "claimExpiresAt", "claimHeartbeatAt"}
    input_base = {key: value for key, value in child.input.items() if key not in claim_keys}
    if (child.id != _child_id(core.id) or child.action != ACTION
            or child.target != f"engagement:{parent.target_id}"
            or child.target_type != "engagement" or child.target_id != parent.target_id
            or child.requested_by != parent.requested_by or child.artifact_refs != []
            or input_base != {**expected, "phase": phase}
            or phase not in {"queued", "handoff_pending", "awaiting_inspector_preflight"}
            or child.finished_at is not None):
        return False
    messages = [event.message for event in child.events]
    allowed = {
        "queued": (["keyed teardown coordinator queued"] if child.status == "queued" else
                   ["keyed teardown coordinator queued", "keyed teardown coordinator started"]),
        "handoff_pending": ["keyed teardown coordinator queued", "keyed teardown coordinator started",
                            "keyed teardown handoff intended"],
        "awaiting_inspector_preflight": [
            "keyed teardown coordinator queued", "keyed teardown coordinator started",
            "keyed teardown handoff intended", "keyed teardown handoff verified; Inspector preflight pending",
        ],
    }
    expected_data = ([queued_cleanup_event_data(snapshot)]
                     + ([{}] if child.status == "running" else [])
                     + ([{}] if phase in {"handoff_pending", "awaiting_inspector_preflight"} else [])
                     + ([{"corePlanId": core.input["corePlanId"]}]
                        if phase == "awaiting_inspector_preflight" else []))
    has_claim = "claimToken" in child.input
    permitted_owner = ({_OWNER, "provider-keyed-inspector-create",
                        "provider-keyed-retained-inspector-proof"}
                       if phase == "awaiting_inspector_preflight" else {_OWNER})
    if (has_claim and (child.input.get("claimOwner") not in permitted_owner
                       or type(child.input.get("claimToken")) is not str
                       or len(child.input["claimToken"]) < 16
                       or any(key not in child.input for key in
                              ("claimClaimedAt", "claimExpiresAt")))):
        return False
    return (child.status in ({"queued", "running"} if phase == "queued" else {"running"})
            and messages == allowed[phase]
            and [event.sequence for event in child.events] == list(range(1, len(messages) + 1))
            and [event.data for event in child.events] == expected_data
            and all(event.level == "info" for event in child.events)
            and (child.status == "queued") == (child.started_at is None))


def _verify_published_source(parent: StoredJobRun, *, environment: str,
                             state_root: Path | None, jobs, plans) -> None:
    """Reprove the completed generation and its new fence without retagging it."""
    from app.services.provider_keyed_teardown_source import load_keyed_teardown_source

    proof = load_keyed_teardown_source(
        parent.id, phase="pre_go", environment=environment, state_root=state_root,
        job_repository=jobs, plan_repository=plans,
    )
    variant = ("published_append" if "publishedAppendSource" in parent.input
               else "published")
    if (proof.variant != variant or proof.teardown_parent_id != parent.id
            or proof.snapshot_id != parent.input["scopeSnapshot"]["snapshotId"]
            or proof.published_source_sha256 is None):
        raise ValueError("published coordinator source differs")


def _published_destroy_started_inspector_boundary(
    parent: StoredJobRun, core, snapshot: dict, active_destroy_child: StoredJobRun,
    jobs, *, state_root: Path | None, failed_prebinding: bool = False,
) -> None:
    """Bind the live pre-GO child to its sealed published or pending source.

    This substitutes only the applied-phase source reread. The caller still
    proves live Inspector reachability, membership, and all final GO fences.
    """
    from app.services.provider_keyed_saved_plan_runner import _hash_file
    from app.services.sketch_state_workspaces import _default_state_root
    from app.storage.job_repository import _claimed_destroy_apply_base, _utc_instant

    scope = snapshot["providerScopes"][0]
    workspace = Path(scope["workspace"])
    phase_path = workspace / ".barragan-apply-phase.json"
    state_path = workspace / "terraform.tfstate"
    child_id = f"job-provider-keyed-initial-destroy-apply-{core.id.removeprefix('job-')}"
    preview_id = f"job-provider-keyed-initial-destroy-plan-{core.id.removeprefix('job-')}"
    child = active_destroy_child
    preview = jobs.get(preview_id)
    inputs = child.input if isinstance(child, StoredJobRun) else None
    events = child.events if isinstance(child, StoredJobRun) else []
    base = (_claimed_destroy_apply_base(child, inputs.get("claimOwner"),
                                        inputs.get("claimToken"))
            if type(inputs) is dict else None)
    expiry = _utc_instant(inputs.get("claimExpiresAt")) if type(inputs) is dict else None
    preview_data = preview.events[-1].data if preview is not None and preview.events else None
    resource_ids = {row["address"]: row["id"] for row in scope["resources"]}
    root = state_root or _default_state_root()
    appended = "publishedAppendSource" in parent.input
    if appended and len(events) in {11, 16}:
        from app.services.provider_keyed_destroy_absence_preflight import _command_journal
        from app.services.provider_keyed_initial_destroy_apply_job import (
            _PRECOMMAND_APPLY_RECOVERY, _SHOW_ONLY_APPLY_RECOVERY,
        )

        failed = [JobEvent(1, "info", "provider destroy apply queued", {}),
                  JobEvent(2, "info", "provider destroy apply started", {}),
                  JobEvent(3, "error", "provider destroy apply stopped", {})]
        seal = events[3].data
        if (events[:3] != failed or events[3].level != "info"
                or events[3].message != _PRECOMMAND_APPLY_RECOVERY
                or type(seal) is not dict
                or set(seal) != {"failedJournalSha256", "failedFinishedAt"}
                or seal["failedJournalSha256"] != job_event_digest(failed)
                or type(seal["failedFinishedAt"]) is not str
                or type(preview_data) is not dict):
            raise ValueError("recovered Inspector Apply prefix differs")
        binary = preview_data.get("terraformBinaryPath")
        plan_path = preview_data.get("planPath")
        if type(binary) is not str or type(plan_path) is not str:
            raise ValueError("recovered Inspector show authority differs")
        show_argv = [binary, "show", "-json", plan_path]
        if len(events) == 16:
            prior_seal = events[8].data
            if ([(row.level, row.message) for row in events[4:9]] != [
                    ("info", "provider destroy command intent fenced"),
                    ("info", "provider destroy command started before GO"),
                    ("info", "provider destroy command result fenced"),
                    ("error", "provider destroy apply stopped"),
                    ("info", _SHOW_ONLY_APPLY_RECOVERY)]
                    or events[7].data != {} or type(prior_seal) is not dict
                    or set(prior_seal) != {"failedJournalSha256", "failedFinishedAt"}
                    or prior_seal["failedJournalSha256"] != job_event_digest(events[:8])
                    or type(prior_seal["failedFinishedAt"]) is not str):
                raise ValueError("show-only Inspector prefix differs")
            _command_journal(events, 4, "show", show_argv)
            suffix = events[9:]
        else:
            suffix = events[4:]
        if ([row.sequence for row in events] != list(range(1, len(events) + 1))
                or [(row.level, row.message) for row in suffix[:3]] != [
                    ("info", "provider destroy command intent fenced"),
                    ("info", "provider destroy command started before GO"),
                    ("info", "provider destroy command result fenced")]):
            raise ValueError("recovered Inspector show suffix differs")
        _command_journal(suffix, 0, "show", show_argv)
        events = [*events[:2], *suffix]
        events = [replace(row, sequence=index) for index, row in enumerate(events, 1)]
    prestate = events[5].data if len(events) == 9 else None
    sealed = parent.input.get("publishedAppendSource" if appended else "publishedSource")
    if failed_prebinding:
        from app.services.provider_keyed_initial_continuation import _job_ids
        initial = jobs.get(_job_ids(core.id)[0])
        manifest = snapshot.get("dnsCleanupManifest")
        source_matches = (
            "publishedSource" not in parent.input
            and "publishedAppendSource" not in parent.input
            and type(manifest) is dict
            and manifest.get("schema") == "provider-keyed-empty-dns-prebinding-v1"
            and initial is not None and initial.status == "failed"
            and manifest.get("initialJournalSha256") == job_event_digest(initial.events)
        )
    else:
        source_matches = (
            type(sealed) is dict
            and (sealed.get("initial_source") == parent.input.get("publishedSource")
                 if appended else sealed.get("scope_sha256") == _fingerprint(scope))
            and sealed.get("state_sha256") == scope["stateSha256"]
        )
    if (not source_matches
            or not isinstance(root, Path) or root != _default_state_root()
            or root.is_symlink() or root.resolve(strict=True) != root
            or not workspace.is_relative_to(root) or workspace == root
            or child is None or child.id != child_id or jobs.get(child_id) != child
            or type(inputs) is not dict
            or preview is None or preview.id != preview_id or preview.status != "succeeded"
            or type(preview_data) is not dict
            or preview_data.get("planSha256") != inputs.get("planSha256")
            or base is None or expiry is None or expiry <= _now()
            or not inputs["claimOwner"].startswith("provider-keyed-destroy-apply-")
            or len(inputs["claimToken"]) < 16
            or base != {
                "engagementId": parent.target_id, "coreJobId": core.id,
                "corePlanId": core.input["corePlanId"], "teardownParentId": parent.id,
                "scopeSnapshotId": snapshot["snapshotId"],
                "providerScopeSha256": snapshot["providerScopeSha256"],
                "destroyPlanJobId": preview_id,
                "planSha256": preview_data["planSha256"], "mutation": True,
            } or child.requested_by != parent.requested_by
            or len(events) != 9 or [event.sequence for event in events] != list(range(1, 10))
            or [(event.level, event.message) for event in events] != [
                ("info", message) for message in (
                    "provider destroy apply queued", "provider destroy apply started",
                    "provider destroy command intent fenced",
                    "provider destroy command started before GO",
                    "provider destroy command result fenced",
                    "provider destroy prestate identity fenced",
                    "provider destroy phase write intended",
                    "provider destroy command intent fenced",
                    "provider destroy command started before GO",
                )]
            or events[0].data != {} or events[1].data != {}
            or type(prestate) is not dict or set(prestate) != {
                "coreJobId", "corePlanId", "scopeSnapshotId", "providerScopeSha256",
                "preDestroyStateSha256", "stateLineage", "preDestroySerial",
                "resourceIds", "resourceIdsSha256", "selectorTag", "credentialRecordId",
                "credentialSecretSha256", "credentialUpdatedAt",
                "dnsCleanupManifestSha256", "dnsCleanupHandoffJournalSha256",
                "dnsCleanupCheckpointSha256",
            }
            or len(resource_ids) != len(scope["resources"])
            or any(prestate.get(key) != expected for key, expected in (
                ("coreJobId", core.id), ("corePlanId", core.input["corePlanId"]),
                ("scopeSnapshotId", snapshot["snapshotId"]),
                ("providerScopeSha256", snapshot["providerScopeSha256"]),
                ("preDestroyStateSha256", scope["stateSha256"]),
                ("resourceIds", resource_ids),
                ("resourceIdsSha256", _fingerprint(resource_ids)),
                ("selectorTag", scope["selectorTag"]),
                ("credentialRecordId", scope["providerConnectionId"]),
                ("credentialSecretSha256", preview_data.get("credentialSecretSha256")),
                ("credentialUpdatedAt", preview_data.get("credentialUpdatedAt")),
                ("dnsCleanupManifestSha256", snapshot["dnsCleanupManifest"]["manifestSha256"]),
            ))
            or not all(type(events[index].data) is dict for index in (2, 3, 4, 7, 8))
            or any(events[index].data.get("phase") != phase for index, phase in (
                (2, "show"), (3, "show"), (4, "show"), (7, "apply"), (8, "apply")))
            or any(events[index].data.get("invocationId") != events[intent].data.get("invocationId")
                   for index, intent in ((3, 2), (4, 2), (8, 7)))
            or events[2].data.get("invocationId") == events[7].data.get("invocationId")
            or events[4].data.get("returnCode") != 0
            or events[6].data != {"phase": "destroy_started", "path": str(phase_path)}
            or not workspace.is_dir() or workspace.is_symlink()
            or workspace.resolve(strict=True) != workspace
            or phase_path.is_symlink()
            or state_path.is_symlink()
            or json.loads(phase_path.read_text()) != {
                "schema": "provider-keyed-v2", "phase": "destroy_started"}
            or _hash_file(state_path) != scope["stateSha256"]):
        raise ValueError("published destroy-started Inspector boundary differs")


def run_provider_keyed_comprehensive_handoff(
    teardown_parent_id: str, *, environment: str,
    job_repository=None, plan_repository=None, lease_lookup=None,
    state_root: Path | None = None,
    handoff: Callable = handoff_terminal_provider_keyed_teardown,
    pending_auditor: Callable = audit_pending_provider_keyed_bootstrap,
    now: Callable[[], datetime] = _now,
    token_factory: Callable[[], str] = lambda: uuid4().hex,
) -> StoredJobRun:
    """Claim one child, perform/verify handoff, and stop before network mutation."""
    try:
        if environment != "devtest" or not teardown_parent_id:
            raise ValueError("DevTest keyed coordinator only")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        lookup = lease_lookup or _db_lease_lookup
        parent, core, snapshot, operation = _boundary(teardown_parent_id, jobs, plans, lookup)
        published = "publishedSource" in parent.input
        failed_prebinding = snapshot.get("dnsCleanupManifest", {}).get("schema") == (
            "provider-keyed-empty-dns-prebinding-v1")
        if published:
            if operation != _FENCE:
                raise ValueError("published teardown fence differs")
            _verify_published_source(parent, environment=environment,
                                     state_root=state_root, jobs=jobs, plans=plans)
        identifier = _child_id(core.id)
        child = jobs.get(identifier)
        if child is not None and child.input.get("phase") == "inspector_ready":
            if len(child.events) == 5 and child.events[-1].message == "retained_inspector_ready":
                recognize_retained_keyed_inspector_ready(
                    parent.id, environment=environment, job_repository=jobs,
                    plan_repository=plans, lease_lookup=lookup,
                    pending_auditor=pending_auditor, state_root=state_root)
            else:
                if published:
                    raise ValueError("published fresh Inspector source is not implemented")
                from app.services.provider_keyed_inspector_readiness_publish import (
                    recognize_published_keyed_inspector_readiness,
                )
                recognize_published_keyed_inspector_readiness(
                    child.id, parent.target_id, environment=environment)
            return child
        if child is not None and child.input.get("phase") == "inspector_create_started":
            if published:
                raise ValueError("published Inspector create source is not implemented")
            from app.services.provider_keyed_inspector_create_intent import recorded_keyed_inspector_intent
            if operation != _FENCE or not recorded_keyed_inspector_intent(child, parent, core, snapshot):
                raise ValueError("Inspector create intent journal differs")
            pending_auditor(
                core.id, confirmed_scope=snapshot["providerScopes"][0],
                confirmed_scope_sha256=_fingerprint(snapshot),
                workspace_root=Path(snapshot["providerScopes"][0]["workspace"]),
                job_repository=jobs,
            )
            raise ProviderKeyedComprehensiveTeardownAttention(
                "Inspector create intent already started; explicit reconciliation is required"
            )
        if child is None:
            created = now().isoformat()
            new = StoredJobRun(
                id=identifier, action=ACTION, status="queued",
                target=f"engagement:{parent.target_id}", target_type="engagement",
                target_id=parent.target_id, requested_by=parent.requested_by,
                input={"engagementId": parent.target_id, "coreJobId": core.id,
                       "corePlanId": core.input["corePlanId"], "teardownParentId": parent.id,
                       "scopeSnapshotId": snapshot["snapshotId"],
                       "providerScopeSha256": snapshot["providerScopeSha256"],
                       "mutation": True, "phase": "queued"},
                artifact_refs=[], created_at=created, started_at=None, finished_at=None,
                events=[JobEvent(1, "info", "keyed teardown coordinator queued",
                                 queued_cleanup_event_data(snapshot))],
            )
            child = jobs.save_if_absent(new)
        if (child is None or not _same_child(child, parent, core, snapshot)
                or len([row for row in jobs.list_for_engagement(parent.target_id)
                        if row.action == ACTION]) != 1):
            raise ValueError("keyed coordinator child differs")
        if child.input["phase"] == "awaiting_inspector_preflight":
            if operation != _FENCE:
                raise ValueError("keyed handoff lease regressed")
            if published:
                _verify_published_source(parent, environment=environment,
                                         state_root=state_root, jobs=jobs, plans=plans)
            elif failed_prebinding:
                from app.services.provider_keyed_teardown_source import load_keyed_teardown_source
                source = load_keyed_teardown_source(
                    parent.id, phase="pre_go", environment=environment,
                    state_root=state_root, job_repository=jobs, plan_repository=plans)
                if source.variant != "failed_prebinding":
                    raise ValueError("failed prebinding handoff source changed")
            else:
                pending_auditor(
                    core.id, confirmed_scope=snapshot["providerScopes"][0],
                    confirmed_scope_sha256=_fingerprint(snapshot),
                    workspace_root=Path(snapshot["providerScopes"][0]["workspace"]),
                    job_repository=jobs,
                )
            return child
        # Start is its own exact CAS. Only then claim the running row; SQLite
        # json_set claim serialization is not text-identical to start's input CAS.
        if child.status == "queued":
            child = jobs.start_if_queued(
                child, started_at=now().isoformat(),
                event=JobEvent(2, "info", "keyed teardown coordinator started", {}),
            )
            if child is None:
                raise ValueError("keyed coordinator start lost")
        if child.input.get("claimToken"):
            expiry = datetime.fromisoformat(child.input["claimExpiresAt"])
            if expiry > now():
                return child
        instant = now()
        token = token_factory()
        if (instant.tzinfo is None or not isinstance(token, str) or len(token) < 16):
            raise ValueError("coordinator claim generation is invalid")
        claimed = jobs.claim_lease(
            child.id, owner=_OWNER, token=token, claimed_at=instant.isoformat(),
            expires_at=(instant + timedelta(minutes=5)).isoformat(),
            eligible_statuses={child.status}, eligible_phases={child.input["phase"]},
        )
        if claimed is None:
            raise ValueError("keyed coordinator claim lost")
        if published:
            _verify_published_source(parent, environment=environment,
                                     state_root=state_root, jobs=jobs, plans=plans)
        if claimed.input["phase"] == "queued":
            claimed = jobs.save_if_leased(
                replace(claimed, input={**claimed.input, "phase": "handoff_pending"},
                        events=[*claimed.events, JobEvent(3, "info", "keyed teardown handoff intended", {})]),
                owner=_OWNER, token=token,
            )
            if claimed is None:
                raise ValueError("keyed coordinator handoff intent lost")
        if (not _same_child(claimed, parent, core, snapshot)
                or claimed.input["phase"] != "handoff_pending"
                or jobs.get(parent.id) != parent):
            raise ValueError("keyed coordinator authority changed")
        if failed_prebinding:
            if operation != _OLD or not hasattr(plans, "fence_failed_prebinding_keyed_teardown"):
                raise ValueError("failed prebinding fence and coordinator are split")
            from app.services.provider_keyed_teardown_source import load_keyed_teardown_source
            source = load_keyed_teardown_source(
                parent.id, phase="pre_handoff", environment=environment,
                state_root=state_root, job_repository=jobs, plan_repository=plans)
            if (source.variant != "failed_prebinding"
                    or source.initial_journal_sha256 != snapshot["dnsCleanupManifest"]["initialJournalSha256"]):
                raise ValueError("failed prebinding source changed")
            completed = plans.fence_failed_prebinding_keyed_teardown(
                teardown_parent_id=parent.id, coordinator_job_id=claimed.id,
                expected_snapshot=snapshot,
                expected_coordinator_journal_sha256=job_event_digest(claimed.events),
                expected_initial_journal_sha256=source.initial_journal_sha256,
                expected_claim_token=token, fence_at=now().isoformat(),
            )
            if (completed is None or not _same_child(completed, parent, core, snapshot)
                    or completed.input.get("phase") != "awaiting_inspector_preflight"
                    or lookup(parent.target_id) != (core.input["corePlanId"], _FENCE)
                    or jobs.get(parent.id) != parent):
                raise ValueError("failed prebinding handoff commit differs")
            verified = load_keyed_teardown_source(
                parent.id, phase="pre_go", environment=environment,
                state_root=state_root, job_repository=jobs, plan_repository=plans)
            if verified.variant != "failed_prebinding":
                raise ValueError("failed prebinding handoff marker differs")
            return completed
        if operation == _OLD:
            handoff(parent.id, environment=environment, job_repository=jobs,
                    plan_repository=plans, lease_lookup=lookup)
        elif operation != _FENCE:
            raise ValueError("keyed coordinator lease changed")
        if published:
            _verify_published_source(parent, environment=environment,
                                     state_root=state_root, jobs=jobs, plans=plans)
        else:
            pending_auditor(
                core.id, confirmed_scope=snapshot["providerScopes"][0],
                confirmed_scope_sha256=_fingerprint(snapshot),
                workspace_root=Path(snapshot["providerScopes"][0]["workspace"]),
                job_repository=jobs,
            )
        if (jobs.get(parent.id) != parent
                or lookup(parent.target_id) != (core.input["corePlanId"], _FENCE)
                or jobs.get(claimed.id) != claimed
                or datetime.fromisoformat(claimed.input["claimExpiresAt"]) <= now()):
            raise ValueError("keyed coordinator handoff authority changed")
        finished = now().isoformat()
        completed = jobs.save_if_leased(
            replace(claimed,
                    input={**claimed.input, "phase": "awaiting_inspector_preflight",
                           "claimExpiresAt": finished},
                    events=[*claimed.events, JobEvent(4, "info",
                           "keyed teardown handoff verified; Inspector preflight pending",
                           {"corePlanId": core.input["corePlanId"]})]),
            owner=_OWNER, token=token,
        )
        if completed is None or jobs.get(parent.id) != parent:
            raise ValueError("keyed coordinator handoff completion lost")
        if published:
            _verify_published_source(parent, environment=environment,
                                     state_root=state_root, jobs=jobs, plans=plans)
        return completed
    except ProviderKeyedComprehensiveTeardownAttention:
        raise
    except Exception:
        raise ProviderKeyedComprehensiveTeardownError(
            "keyed teardown handoff is unproved; Inspector/outbound/provider cleanup was not started"
        ) from None


_RETAINED_OWNER = "provider-keyed-retained-inspector-proof"
_RETAINED_HANDOFF = "provider-keyed-retained-inspector-ready-handoff"


@dataclass(frozen=True)
class RetainedInspectorReady:
    coordinator_job_id: str
    host_record_id: str
    firewall_record_id: str
    provider_proof_sha256: str
    ssh_policy_sha256: str


def _retained_digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def prove_retained_keyed_inspector_ready(
    teardown_parent_id: str, *, environment: str,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, credential_repository=None,
    lease_lookup=None, pending_auditor: Callable = audit_pending_provider_keyed_bootstrap,
    key_identity_reader=None, public_key_reader=None, decrypt_secret=None,
    management_source_resolver=None, transport=None, ssh_runner=None,
    state_root: Path | None = None,
    now: Callable[[], datetime] = _now,
    token_factory: Callable[[], str] = lambda: uuid4().hex,
) -> RetainedInspectorReady:
    """Privately prove the normal retained Inspector and seal one ready phase.

    This is not a public dispatcher. It performs only exact-ID provider GET and
    five read-only selected-source SSH checks; parent/settings/owned rows stay
    unchanged. A failed or uncertain proof is never called readiness.
    """
    from app.services.credentials import decrypt_secret_value
    from app.services.observer_checks import (
        INSPECTION_ACTION, INSPECTOR_READINESS_ACTION, ObserverSshKey,
        SshObserverRunner, _inspector_host_from_settings,
        resolve_inspector_management_source_cidr,
    )
    from app.services.provider_keyed_inspector_preflight import inspect_prepared_keyed_teardown_inspector
    from app.services.provider_keyed_inspector_prepare_binder import (
        _existing_key_identity, _safe_key_identity, _verify_key_pair,
    )
    from app.services.provider_keyed_inspector_preparation_proof import verify_inspector_selected_source_ssh
    from app.services.provider_keyed_inspector_provider_proof import prove_retained_keyed_inspector_provider
    from app.services.provider_keyed_inspector_settlement import _GetOnlyTransport, _default_transport
    from app.services.provider_keyed_inspector_submit import _existing_public_key
    from app.storage.credential_repository import SqlAlchemyCredentialRepository
    from app.storage.job_repository import (
        inspector_claim_generation_digest, job_event_digest,
        valid_inspector_management_source_cidr,
    )
    from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
    from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository

    try:
        if environment != "devtest" or not teardown_parent_id:
            raise ValueError("retained Inspector proof is DevTest only")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        lookup = lease_lookup or _db_lease_lookup
        read_key = key_identity_reader or _existing_key_identity
        read_public = public_key_reader or _existing_public_key
        decrypt = decrypt_secret or decrypt_secret_value
        resolve_source = management_source_resolver or resolve_inspector_management_source_cidr
        runner = ssh_runner or SshObserverRunner()

        def authority(*, preflight: bool, refresh_source: bool = False, expected_child=None):
            parent, core, snapshot, operation = _boundary(teardown_parent_id, jobs, plans, lookup)
            child = jobs.get(_child_id(core.id))
            if (operation != _FENCE or child is None
                    or len([row for row in jobs.list_for_engagement(parent.target_id)
                            if row.action == ACTION]) != 1):
                raise ValueError("retained Inspector coordinator differs")
            scope = snapshot["providerScopes"][0]
            if "publishedSource" in parent.input:
                _verify_published_source(parent, environment=environment,
                                         state_root=state_root, jobs=jobs, plans=plans)
            else:
                pending_auditor(
                    core.id, confirmed_scope=scope,
                    confirmed_scope_sha256=_fingerprint(snapshot),
                    workspace_root=Path(scope["workspace"]), job_repository=jobs,
                )
            if preflight:
                evidence = inspect_prepared_keyed_teardown_inspector(
                    parent.id, environment=environment, job_repository=jobs,
                    plan_repository=plans, settings_repository=settings_repo,
                    provider_resource_repository=resources, lease_lookup=lookup,
                    pending_auditor=pending_auditor, state_root=state_root)
                if child.input.get("phase") != "awaiting_inspector_preflight" or not _same_child(
                        child, parent, core, snapshot):
                    raise ValueError("retained Inspector phase differs")
            else:
                if (child.id != expected_child.id or child.input.get("phase") != "inspector_ready"
                        or child.input.get("claimOwner") != _RETAINED_HANDOFF
                        or child.events != expected_child.events):
                    raise ValueError("retained Inspector publication phase differs")
                evidence = None
            settings = settings_repo.get(parent.target_id)
            rows = tuple(resources.list_for_engagement(parent.target_id))
            if (settings is None or settings.mode != "continuous" or not settings.enabled
                    or settings.current_host == {}):
                raise ValueError("retained Inspector settings differ")
            host = _inspector_host_from_settings(settings.current_host, settings=settings)
            if host is None or host.provider not in {"linode", "digitalocean"}:
                raise ValueError("retained Inspector host differs")
            from app.services.observer_checks import (
                _is_inspector_resource_record, INSPECTOR_RESOURCE_SOURCE,
            )
            from app.storage.provider_resource_repository import TERMINAL_RECORD_STATUSES
            active_hosts = [row for row in rows if _is_inspector_resource_record(row)
                            and str(row.status).lower() not in TERMINAL_RECORD_STATUSES]
            active_firewalls = [row for row in rows if (
                row.resource_type == "inspector_firewall"
                or isinstance(row.metadata, dict)
                and row.metadata.get("role") == "inspector_firewall"
            ) and str(row.status).lower() not in TERMINAL_RECORD_STATUSES]
            if (len(active_hosts) != 1 or len(active_firewalls) != 1
                    or active_hosts[0].source != INSPECTOR_RESOURCE_SOURCE
                    or active_firewalls[0].source != INSPECTOR_RESOURCE_SOURCE):
                raise ValueError("retained Inspector ownership is ambiguous")
            selected_hosts = [row for row in active_hosts
                              if row.id == f"{host.provider}:inspector:{host.resource_id}"]
            if len(selected_hosts) != 1 or not selected_hosts[0].adoption_job_id:
                raise ValueError("retained Inspector ownership differs")
            host_record = selected_hosts[0]
            adoption = jobs.get(host_record.adoption_job_id)
            if (adoption is None or adoption.action not in {INSPECTION_ACTION, INSPECTOR_READINESS_ACTION}
                    or adoption.target_id != parent.target_id or adoption.status != "succeeded"):
                raise ValueError("retained Inspector adoption job differs")
            firewall_meta = dict(host.metadata or {}).get("providerFirewall")
            if (type(firewall_meta) is not dict
                    or not valid_inspector_management_source_cidr(
                        firewall_meta.get("managementSourceCidr"))
                    or (refresh_source and firewall_meta["managementSourceCidr"] != resolve_source())):
                raise ValueError("retained Inspector source is unproved")
            firewall_rows = [row for row in active_firewalls if row.id == (
                f"{host.provider}:inspector-firewall:{firewall_meta.get('resourceId')}")]
            if len(firewall_rows) != 1 or firewall_rows[0].adoption_job_id != adoption.id:
                raise ValueError("retained Inspector firewall differs")
            defaults = [item for item in credentials.list(host.provider)
                        if item.provider == host.provider and item.status == "active"
                        and item.is_default]
            selected = credentials.get_default(host.provider)
            if (len(defaults) != 1 or selected != defaults[0] or not selected.alias
                    or not selected.updated_at or not selected.encrypted_secret):
                raise ValueError("retained Inspector credential differs")
            key_path, key_digest = _safe_key_identity(read_key)
            if preflight:
                _verify_key_pair(key_path, key_digest)
            public_key, public_digest = read_public()
            if public_digest != key_digest or not public_key.startswith("ssh-ed25519 "):
                raise ValueError("retained Inspector key differs")
            if evidence is not None and (evidence.owned_record_id != host_record.id
                                         or evidence.provider_resource_id != host.resource_id
                                         or evidence.public_ip != host.public_ip):
                raise ValueError("retained Inspector preflight differs")
            return (parent, core, snapshot, child, settings, rows, selected,
                    key_path, key_digest, public_key, host, host_record,
                    firewall_rows[0], firewall_meta)

        before = authority(preflight=True, refresh_source=True)
        child = before[3]
        instant = now()
        token = token_factory()
        expiry = instant + timedelta(minutes=4, seconds=50)
        if (instant.tzinfo is None or instant.utcoffset() != timedelta(0)
                or type(token) is not str or len(token) < 16):
            raise ValueError("retained Inspector claim differs")
        claimed = jobs.transition_retained_inspector_if_running(
            child, mode="claim", expected_event_digest=job_event_digest(child.events),
            owner=_RETAINED_OWNER, token=token, at=instant.isoformat(),
            expires_at=expiry.isoformat())
        if claimed is None:
            raise ValueError("retained Inspector claim lost")
        current = claimed
        original_claimed_at = claimed.input["claimClaimedAt"]
        original = before[:3] + before[4:]

        def fence():
            nonlocal current
            observed = authority(preflight=True)
            if (observed[:3] + observed[4:] != original or observed[3] != current
                    or current.input.get("claimOwner") != _RETAINED_OWNER
                    or current.input.get("claimToken") != token
                    or current.input.get("claimClaimedAt") != original_claimed_at):
                raise ValueError("retained Inspector authority changed")
            moment = now()
            renewed = jobs.transition_retained_inspector_if_running(
                current, mode="heartbeat", expected_event_digest=job_event_digest(current.events),
                owner=_RETAINED_OWNER, token=token, at=moment.isoformat(),
                expires_at=(moment + timedelta(minutes=4, seconds=50)).isoformat())
            if renewed is None:
                raise ValueError("retained Inspector claim heartbeat lost")
            current = renewed
            observed = authority(preflight=True)
            if observed[:3] + observed[4:] != original or observed[3] != current:
                raise ValueError("retained Inspector authority changed")

        fence()
        selected = before[6]
        secret = decrypt(selected.encrypted_secret)
        if type(secret) is not str or not secret:
            raise ValueError("retained Inspector credential is unavailable")
        host = before[10]
        firewall = before[12]
        source = before[13]["managementSourceCidr"]
        wrapped = _GetOnlyTransport(
            transport or _default_transport(host.provider), before_get=fence, after_get=fence)
        proof = prove_retained_keyed_inspector_provider(
            expected_host=host, size=before[4].size, token=secret,
            transport=wrapped, firewall_id=firewall.resource_id,
            management_cidr=source)
        fence()
        policy_digest, nmap_version = verify_inspector_selected_source_ssh(
            host, ObserverSshKey(before[7], before[9]), source, fence, runner)
        fence()
        if resolve_source() != source:
            raise ValueError("retained Inspector management source changed")
        proof_digest = _retained_digest(asdict(proof))
        evidence = {
            "scopeSnapshotId": before[2]["snapshotId"],
            "providerScopeSha256": before[2]["providerScopeSha256"],
            "sourceJournalSha256": job_event_digest(current.events),
            "hostRecordId": before[11].id, "firewallRecordId": firewall.id,
            "provider": host.provider, "hostId": host.resource_id,
            "firewallId": firewall.resource_id, "publicIp": host.public_ip,
            "sourceCidr": source, "credentialId": selected.id,
            "credentialUpdatedAt": selected.updated_at,
            "credentialSha256": hashlib.sha256(selected.encrypted_secret.encode()).hexdigest(),
            "keyFingerprintSha256": before[8], "providerProofSha256": proof_digest,
            "sshPolicySha256": policy_digest,
            "nmapVersionSha256": hashlib.sha256(nmap_version.encode()).hexdigest(),
            "claimGenerationSha256": inspector_claim_generation_digest(
                token=token, claimed_at=original_claimed_at),
        }
        event = JobEvent(5, "info", "retained_inspector_ready", evidence)

        def locked_authority():
            # The repository has the SQLite writer slot and has changed only
            # this child's phase/claim in its uncommitted transaction.
            observed = authority(preflight=False, expected_child=replace(
                current, input={**current.input, "phase": "inspector_ready",
                       "claimOwner": _RETAINED_HANDOFF}, events=current.events))
            if observed[:3] + observed[4:] != original:
                raise ValueError("retained Inspector publication authority changed")

        published = jobs.transition_retained_inspector_if_running(
            current, mode="ready", expected_event_digest=job_event_digest(current.events),
            owner=_RETAINED_OWNER, token=token, at=now().isoformat(),
            expires_at=current.input["claimExpiresAt"], event=event,
            authority=locked_authority)
        if published is None:
            raise ValueError("retained Inspector ready CAS lost")
        return RetainedInspectorReady(published.id, before[11].id, firewall.id,
                                      proof_digest, policy_digest)
    except Exception:
        raise ProviderKeyedComprehensiveTeardownAttention(
            "retained Inspector proof or readiness publication is unverified; reconcile persisted phase"
        ) from None


def recognize_retained_keyed_inspector_ready(
    teardown_parent_id: str, *, environment: str,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, credential_repository=None,
    lease_lookup=None, pending_auditor: Callable = audit_pending_provider_keyed_bootstrap,
    state_root: Path | None = None,
    active_destroy_child: StoredJobRun | None = None,
) -> RetainedInspectorReady:
    """Recognize the sealed five-event retained branch from persisted data only."""
    from app.services.observer_checks import (
        INSPECTION_ACTION, INSPECTOR_READINESS_ACTION, INSPECTOR_RESOURCE_SOURCE,
        _inspector_host_from_settings, _inspector_support_baseline_current,
        _is_inspector_resource_record, _retired_target_public_ips, _usable_inspector_host,
    )
    from app.services.provider_keyed_inspector_prepare_binder import (
        _existing_key_identity, _safe_key_identity, _verify_key_pair,
    )
    from app.storage.credential_repository import SqlAlchemyCredentialRepository
    from app.storage.job_repository import job_event_digest, valid_inspector_management_source_cidr
    from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
    from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository

    try:
        if environment != "devtest":
            raise ValueError("DevTest only")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        lookup = lease_lookup or _db_lease_lookup
        parent, core, snapshot, operation = _boundary(teardown_parent_id, jobs, plans, lookup)
        pending_audited = False
        if active_destroy_child is not None:
            if operation != _FENCE:
                raise ValueError("destroy-started lease differs")
            failed_prebinding = "publishedSource" not in parent.input
            if failed_prebinding:
                scope = snapshot["providerScopes"][0]
                pending_auditor(
                    core.id, confirmed_scope=scope,
                    confirmed_scope_sha256=_fingerprint(snapshot),
                    workspace_root=Path(scope["workspace"]), job_repository=jobs,
                )
                pending_audited = True
                _published_destroy_started_inspector_boundary(
                    parent, core, snapshot, active_destroy_child, jobs,
                    state_root=state_root, failed_prebinding=True)
            else:
                _published_destroy_started_inspector_boundary(
                    parent, core, snapshot, active_destroy_child, jobs,
                    state_root=state_root)
        elif "publishedSource" in parent.input:
            destroy_id = (f"job-provider-keyed-initial-destroy-apply-"
                          f"{core.id.removeprefix('job-')}")
            destroy = jobs.get(destroy_id)
            if destroy is not None and destroy.status == "succeeded":
                from app.services.provider_keyed_teardown_source import (
                    _read_published_post_destroy_boundary,
                )
                from app.services.sketch_state_workspaces import _default_state_root

                source, bound = _read_published_post_destroy_boundary(
                    parent.id, environment=environment,
                    state_root=state_root or _default_state_root(),
                    job_repository=jobs, plan_repository=plans,
                    sketch_repository=None, credential_repository=None,
                    lease_lookup=lookup, credential_check=None,
                )
                expected_variant = ("published_append" if "publishedAppendSource" in parent.input
                                    else "published")
                if (source.variant != expected_variant or source.teardown_parent_id != parent.id
                        or source.engagement_id != parent.target_id
                        or source.core_job_id != core.id
                        or source.core_plan_id != core.input["corePlanId"]
                        or source.snapshot_id != snapshot["snapshotId"]
                        or source.provider_scope_sha256 != snapshot["providerScopeSha256"]
                        or bound.parent != parent or bound.core != core
                        or bound.scope != snapshot["providerScopes"][0]
                        or bound.apply_job != destroy):
                    raise ValueError("published post-destroy Inspector source differs")
            else:
                _verify_published_source(parent, environment=environment,
                                         state_root=state_root, jobs=jobs, plans=plans)
        else:
            destroy_id = (f"job-provider-keyed-initial-destroy-apply-"
                          f"{core.id.removeprefix('job-')}")
            destroy = jobs.get(destroy_id)
            if (destroy is not None and destroy.status == "succeeded"
                    and snapshot.get("dnsCleanupManifest", {}).get("schema")
                    == "provider-keyed-empty-dns-prebinding-v1"):
                from app.services.provider_keyed_destroy_absence_preflight import (
                    _read_success_boundary,
                )
                from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
                from app.services.sketch_state_workspaces import _default_state_root
                from app.storage.credential_repository import SqlAlchemyCredentialRepository
                from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository

                bound = _read_success_boundary(
                    parent.id, jobs=jobs, plans=plans,
                    chains=SqlAlchemySketchChainRepository(),
                    credentials=SqlAlchemyCredentialRepository(), lookup=lookup,
                    handoff_auditor=pending_auditor,
                    credential_check=_credential_snapshot,
                    state_root=state_root or _default_state_root(),
                )
                if (bound.parent != parent or bound.core != core
                        or bound.scope != snapshot["providerScopes"][0]
                        or bound.apply_job != destroy):
                    raise ValueError("pending post-destroy Inspector source differs")
                pending_audited = True
        child = jobs.get(_child_id(core.id))
        expected_input = {
            "engagementId": parent.target_id, "coreJobId": core.id,
            "corePlanId": core.input["corePlanId"], "teardownParentId": parent.id,
            "scopeSnapshotId": snapshot["snapshotId"],
            "providerScopeSha256": snapshot["providerScopeSha256"],
            "mutation": True, "phase": "inspector_ready",
        }
        claim_keys = {"claimOwner", "claimToken", "claimClaimedAt",
                      "claimHeartbeatAt", "claimExpiresAt"}
        if (operation != _FENCE or child is None or child.action != ACTION
                or child.status != "running" or child.finished_at is not None
                or child.input.get("phase") != "inspector_ready"
                or child.input.get("claimOwner") != _RETAINED_HANDOFF
                or {key: value for key, value in child.input.items() if key not in claim_keys}
                != expected_input or set(child.input) != set(expected_input) | claim_keys
                or type(child.input.get("claimToken")) is not str
                or len(child.input["claimToken"]) < 16
                or child.input.get("claimClaimedAt") != child.input.get("claimHeartbeatAt")
                or child.input.get("claimExpiresAt") != child.input.get("claimClaimedAt")
                or datetime.fromisoformat(child.input["claimExpiresAt"]) > _now()
                or child.target != f"engagement:{parent.target_id}"
                or child.target_type != "engagement" or child.target_id != parent.target_id
                or child.requested_by != parent.requested_by
                or child.id != _child_id(core.id) or child.started_at is None
                or child.artifact_refs != []
                or len(child.events) != 5
                or [e.sequence for e in child.events] != [1, 2, 3, 4, 5]
                or [e.message for e in child.events[:4]] != [
                    "keyed teardown coordinator queued", "keyed teardown coordinator started",
                    "keyed teardown handoff intended",
                    "keyed teardown handoff verified; Inspector preflight pending",
                ]
                or [e.data for e in child.events[:4]] != [
                    queued_cleanup_event_data(snapshot), {}, {},
                    {"corePlanId": core.input["corePlanId"]},
                ] or any(e.level != "info" for e in child.events)
                or child.events[4].message != "retained_inspector_ready"
                or type(child.events[4].data) is not dict
                or len([row for row in jobs.list_for_engagement(parent.target_id)
                        if row.action == ACTION]) != 1):
            raise ValueError("retained ready journal differs")
        scope = snapshot["providerScopes"][0]
        if "publishedSource" not in parent.input and not pending_audited:
            pending_auditor(core.id, confirmed_scope=scope,
                            confirmed_scope_sha256=_fingerprint(snapshot),
                            workspace_root=Path(scope["workspace"]), job_repository=jobs)
        data = child.events[4].data
        from app.storage.job_repository import _RETAINED_READY_KEYS
        if (set(data) != _RETAINED_READY_KEYS
                or data["scopeSnapshotId"] != snapshot["snapshotId"]
                or data["providerScopeSha256"] != snapshot["providerScopeSha256"]
                or data["sourceJournalSha256"] != job_event_digest(child.events[:4])
                or not valid_inspector_management_source_cidr(data["sourceCidr"])
                or not all(type(data[key]) is str and re.fullmatch(r"[0-9a-f]{64}", data[key])
                           for key in ("credentialSha256", "keyFingerprintSha256",
                                       "providerProofSha256", "sshPolicySha256",
                                       "nmapVersionSha256", "claimGenerationSha256"))):
            raise ValueError("retained ready evidence differs")
        settings = settings_repo.get(parent.target_id)
        host = _inspector_host_from_settings(settings.current_host, settings=settings) if settings else None
        rows = tuple(resources.list_for_engagement(parent.target_id))
        from app.storage.provider_resource_repository import TERMINAL_RECORD_STATUSES
        active_hosts = [row for row in rows if _is_inspector_resource_record(row)
                        and str(row.status).lower() not in TERMINAL_RECORD_STATUSES]
        active_firewalls = [row for row in rows if (
            row.resource_type == "inspector_firewall" or
            isinstance(row.metadata, dict) and row.metadata.get("role") == "inspector_firewall"
        ) and str(row.status).lower() not in TERMINAL_RECORD_STATUSES]
        host_record = active_hosts[0] if len(active_hosts) == 1 else None
        firewall_record = active_firewalls[0] if len(active_firewalls) == 1 else None
        host_meta = host_record.metadata if host_record and isinstance(host_record.metadata, dict) else {}
        firewall_meta = (firewall_record.metadata if firewall_record
                         and isinstance(firewall_record.metadata, dict) else {})
        host_firewall = dict(host.metadata or {}).get("providerFirewall") if host else None
        if (settings is None or not settings.enabled or settings.mode != "continuous"
                or host is None or not _usable_inspector_host(host)
                or not _inspector_support_baseline_current(host)
                or host.public_ip in _retired_target_public_ips(
                    list(snapshot.get("publicVerificationTargets") or []))
                or host_record is None or firewall_record is None
                or host.provider != data["provider"] or host.resource_id != data["hostId"]
                or host.public_ip != data["publicIp"]
                or host.provider != settings.provider or host.region != settings.region
                or type(host_firewall) is not dict
                or host_firewall.get("resourceId") != data["firewallId"]
                or host_firewall.get("managementSourceCidr") != data["sourceCidr"]
                or host_record.id != data["hostRecordId"]
                or host_record.id != f"{host.provider}:inspector:{host.resource_id}"
                or host_record.source != INSPECTOR_RESOURCE_SOURCE
                or host_record.engagement_id != parent.target_id
                or host_record.provider != host.provider
                or host_record.resource_type != f"inspector_{host.resource_type}"
                or host_record.resource_id != host.resource_id
                or host_record.name != host.name or host_record.region != host.region
                or host_record.status.lower() not in {"active", "running"}
                or host_record.lifecycle_state.lower() not in {"active", "running"}
                or host_meta.get("barraganOwned") is not True
                or host_meta.get("role") != "inspector"
                or host_meta.get("publicIp") != host.public_ip
                or type(host_meta.get("publicIps")) is not list
                or host.public_ip not in host_meta["publicIps"]
                or host_meta.get("providerFirewall") != host_firewall
                or not host_record.adoption_job_id
                or host_meta.get("inspectionJobId") != host_record.adoption_job_id
                or firewall_record.id != data["firewallRecordId"]
                or firewall_record.id != f"{host.provider}:inspector-firewall:{data['firewallId']}"
                or firewall_record.source != INSPECTOR_RESOURCE_SOURCE
                or firewall_record.engagement_id != parent.target_id
                or firewall_record.provider != host.provider
                or firewall_record.resource_type != "inspector_firewall"
                or firewall_record.resource_id != data["firewallId"]
                or firewall_record.name != host_firewall.get("name")
                or firewall_record.region != host.region
                or firewall_record.status.lower() not in {"active", "running"}
                or firewall_record.lifecycle_state.lower() not in {"active", "running"}
                or firewall_record.adoption_job_id != host_record.adoption_job_id
                or firewall_meta.get("barraganOwned") is not True
                or firewall_meta.get("role") != "inspector_firewall"
                or firewall_meta.get("inspectorHostResourceId") != host.resource_id
                or firewall_meta.get("inspectionJobId") != host_record.adoption_job_id
                or firewall_meta.get("managementSourceCidr") != data["sourceCidr"]):
            raise ValueError("retained ready ownership differs")
        adoption = jobs.get(host_record.adoption_job_id)
        if (adoption is None or adoption.action not in {INSPECTION_ACTION, INSPECTOR_READINESS_ACTION}
                or adoption.target_id != parent.target_id or adoption.status != "succeeded"):
            raise ValueError("retained ready adoption differs")
        defaults = [item for item in credentials.list(host.provider)
                    if item.provider == host.provider and item.status == "active" and item.is_default]
        selected = credentials.get_default(host.provider)
        if (len(defaults) != 1 or selected != defaults[0]
                or selected.id != data["credentialId"]
                or selected.updated_at != data["credentialUpdatedAt"]
                or hashlib.sha256(selected.encrypted_secret.encode()).hexdigest()
                != data["credentialSha256"]):
            raise ValueError("retained ready credential differs")
        key_path, key_digest = _safe_key_identity(_existing_key_identity)
        if key_digest != data["keyFingerprintSha256"]:
            raise ValueError("retained ready key differs")
        _verify_key_pair(key_path, key_digest)
        return RetainedInspectorReady(child.id, data["hostRecordId"],
                                      data["firewallRecordId"],
                                      data["providerProofSha256"], data["sshPolicySha256"])
    except Exception:
        raise ProviderKeyedComprehensiveTeardownAttention(
            "retained Inspector ready phase is unverified; reconcile persisted evidence"
        ) from None


def run_provider_keyed_destroy_preview_from_ready(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, lease_lookup=None,
    retained_ready_recognizer: Callable | None = None,
    fresh_ready_recognizer: Callable | None = None,
    preview_runner: Callable | None = None,
    preview_recognizer: Callable | None = None,
) -> StoredJobRun:
    """Privately save or recognize one full-state destroy preview.

    The coordinator remains at ``inspector_ready``. The preview child is the
    durable one-shot progress journal; an existing incomplete child is never
    started again. The successful-child recognizer performs read-only apply
    preflight, including the exact saved-plan and provider-membership checks.
    This function does not authorize or execute destroy apply.
    """
    from app.services.provider_keyed_initial_destroy_apply_job import (
        preflight_digitalocean_initial_destroy_apply,
    )
    from app.services.provider_keyed_initial_destroy_plan_job import (
        ACTION as PREVIEW_ACTION, run_digitalocean_initial_destroy_plan_job,
    )
    from app.services.provider_keyed_inspector_readiness_publish import (
        recognize_published_keyed_inspector_readiness,
    )

    try:
        if environment != "devtest" or not teardown_parent_id or not isinstance(state_root, Path):
            raise ValueError("DevTest preview boundary required")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        lookup = lease_lookup or _db_lease_lookup
        parent, core, snapshot, operation = _boundary(teardown_parent_id, jobs, plans, lookup)
        published = "publishedSource" in parent.input
        if published:
            from app.services.provider_keyed_teardown_source import load_keyed_teardown_source
            source = load_keyed_teardown_source(
                parent.id, phase="pre_go", environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans,
            )
            expected_variant = ("published_append" if "publishedAppendSource" in parent.input
                                else "published")
            if (source.variant != expected_variant or source.core_job_id != core.id
                    or source.core_plan_id != core.input["corePlanId"]
                    or source.snapshot_id != snapshot["snapshotId"]
                    or source.provider_scope_sha256 != snapshot["providerScopeSha256"]):
                raise ValueError("published destroy preview source differs")
        child = jobs.get(_child_id(core.id))
        if (operation != _FENCE or child is None or child.action != ACTION
                or child.status != "running" or child.input.get("phase") != "inspector_ready"):
            raise ValueError("Inspector ready coordinator differs")
        if len(child.events) == 5 and child.events[-1].message == "retained_inspector_ready":
            recognize = retained_ready_recognizer or recognize_retained_keyed_inspector_ready
            ready = recognize(parent.id, environment=environment, job_repository=jobs,
                              plan_repository=plans, lease_lookup=lookup)
        else:
            recognize = fresh_ready_recognizer or recognize_published_keyed_inspector_readiness
            ready = recognize(child.id, parent.target_id, environment=environment,
                              job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
        if ready.coordinator_job_id != child.id or jobs.get(child.id) != child:
            raise ValueError("Inspector ready proof changed")

        preview_id = f"job-provider-keyed-initial-destroy-plan-{core.id.removeprefix('job-')}"
        previews = [row for row in jobs.list_for_engagement(parent.target_id)
                    if row.action == PREVIEW_ACTION]
        if previews or jobs.get(preview_id) is not None:
            if len(previews) != 1 or previews[0].id != preview_id:
                raise ValueError("destroy preview child set differs")
            preview = jobs.get(preview_id)
            if preview != previews[0] or preview.status != "succeeded":
                if ("publishedAppendSource" not in parent.input
                        or preview is None or preview.status != "failed"):
                    raise ValueError("existing destroy preview needs reconciliation")
                runner = preview_runner or run_digitalocean_initial_destroy_plan_job
                runner(parent.id, environment=environment, state_root=state_root,
                       job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
                preview = jobs.get(preview_id)
                if preview is None or preview.status != "succeeded":
                    raise ValueError("recovered destroy preview did not finish successfully")
        else:
            # The runner inserts the child before Terraform contact and refuses
            # any pre-existing child. A racing invocation cannot replay it.
            runner = preview_runner or run_digitalocean_initial_destroy_plan_job
            runner(parent.id, environment=environment, state_root=state_root,
                   job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
            preview = jobs.get(preview_id)
            if preview is None or preview.status != "succeeded":
                raise ValueError("destroy preview did not finish successfully")

        # This existing preflight audits the complete preview journal and
        # private plan artifact, rechecks current ownership and membership,
        # and performs no provider or Terraform mutation.
        inspect = preview_recognizer or preflight_digitalocean_initial_destroy_apply
        boundary = inspect(parent.id, environment=environment, state_root=state_root,
                           job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
        if (boundary.teardown_parent_id != parent.id
                or boundary.core_job_id != core.id
                or boundary.core_plan_id != core.input["corePlanId"]
                or boundary.scope_snapshot_id != snapshot["snapshotId"]
                or boundary.provider_scope_sha256 != snapshot["providerScopeSha256"]
                or boundary.preview_job_id != preview_id
                or jobs.get(parent.id) != parent or jobs.get(child.id) != child
                or jobs.get(preview_id) != preview
                or lookup(parent.target_id) != (core.input["corePlanId"], _FENCE)):
            raise ValueError("saved destroy preview authority changed")
        return preview
    except Exception:
        raise ProviderKeyedComprehensiveTeardownAttention(
            "keyed destroy preview is unproved or incomplete; no destroy apply was started"
        ) from None


def publish_provider_keyed_destroy_absence(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, sketch_repository=None,
    credential_repository=None, lease_lookup=None,
    retained_ready_recognizer: Callable | None = None,
    fresh_ready_recognizer: Callable | None = None,
    absence_preflight: Callable | None = None,
    boundary_reader: Callable | None = None,
) -> StoredJobRun:
    """Seal a private, point-in-time absence proof after the one-shot destroy.

    Two complete provider GET inventories happen before the SQLite writer
    transaction. The transaction rereads the exact successful apply, retained
    empty state, desired chains, parent and lease. The 30-second proof deadline
    only bounds this publication; later cleanup needs fresh provider GETs.
    This path never runs Terraform or deletes the selector tag.
    """
    from app.services.provider_keyed_destroy_absence_preflight import (
        _read_success_boundary, reconcile_successful_digitalocean_destroy_absence,
    )
    from app.services.provider_keyed_teardown_source import (
        _read_published_post_destroy_boundary,
    )
    from app.services.provider_keyed_inspector_readiness_publish import (
        recognize_published_keyed_inspector_readiness,
    )
    from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
    from app.services.sketch_state_workspaces import _default_state_root
    from app.storage.credential_repository import SqlAlchemyCredentialRepository
    from app.storage.job_repository import job_event_digest
    from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository

    try:
        if (environment != "devtest" or not teardown_parent_id
                or not isinstance(state_root, Path) or state_root != _default_state_root()
                or state_root.resolve(strict=True) != state_root):
            raise ValueError("DevTest absence handoff only")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        chains = sketch_repository or SqlAlchemySketchChainRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        lookup = lease_lookup or _db_lease_lookup
        parent, core, snapshot, operation = _boundary(teardown_parent_id, jobs, plans, lookup)
        published_source = "publishedSource" in parent.input
        if published_source and boundary_reader is not None:
            raise ValueError("published source cannot use a boundary-only reader")
        child = jobs.get(_child_id(core.id))
        if (operation != _FENCE or child is None or child.action != ACTION
                or child.status != "running" or child.input.get("phase") != "inspector_ready"):
            raise ValueError("Inspector ready coordinator differs")
        if len(child.events) == 5 and child.events[-1].message == "retained_inspector_ready":
            recognize = retained_ready_recognizer or recognize_retained_keyed_inspector_ready
            ready = recognize(parent.id, environment=environment, job_repository=jobs,
                              plan_repository=plans, lease_lookup=lookup)
        else:
            recognize = fresh_ready_recognizer or recognize_published_keyed_inspector_readiness
            ready = recognize(child.id, parent.target_id, environment=environment,
                              job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
        if ready.coordinator_job_id != child.id or jobs.get(child.id) != child:
            raise ValueError("Inspector ready authority changed")

        def read():
            if published_source:
                source, boundary = _read_published_post_destroy_boundary(
                    parent.id, environment=environment, state_root=state_root,
                    job_repository=jobs, plan_repository=plans,
                    sketch_repository=chains, credential_repository=credentials,
                    lease_lookup=lookup, credential_check=_credential_snapshot,
                )
                expected_variant = ("published_append" if "publishedAppendSource" in parent.input
                                    else "published")
                if source.variant != expected_variant or source.teardown_parent_id != parent.id:
                    raise ValueError("published absence source differs")
                return source, boundary
            if boundary_reader is not None:
                return None, boundary_reader(parent.id)
            return None, _read_success_boundary(
                parent.id, jobs=jobs, plans=plans, chains=chains,
                credentials=credentials, lookup=lookup,
                handoff_auditor=audit_pending_provider_keyed_bootstrap,
                credential_check=_credential_snapshot, state_root=state_root,
            )

        before_source, before = read()
        before_pair = (before_source, before)
        if (before.parent != parent or before.core != core
                or before.scope != snapshot["providerScopes"][0]):
            raise ValueError("saved destroy boundary changed")
        prove = absence_preflight or reconcile_successful_digitalocean_destroy_absence
        from app.services.provider_keyed_digitalocean_absence import DigitalOceanAbsenceEvidence
        def confirm(*, max_attempts: int):
            if read() != before_pair or jobs.get(child.id) != child:
                raise ValueError("absence confirmation authority changed")
            result = prove(
                parent.id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans, sketch_repository=chains,
                credential_repository=credentials, lease_lookup=lookup,
                max_attempts=max_attempts,
            )
            if (type(result) is not DigitalOceanAbsenceEvidence
                    or read() != before_pair or jobs.get(child.id) != child):
                raise ValueError("absence confirmation authority changed")
            return result

        first = confirm(max_attempts=12)
        # This is a separate provider inventory traversal. Once the first
        # settled, the second must independently see all exact IDs absent;
        # no Terraform command or child replay is involved.
        evidence = confirm(max_attempts=1)
        ids = before.intent.resource_ids
        expected_droplets = sorted(value for key, value in ids.items()
                                   if key.startswith("digitalocean_droplet."))
        expected_firewall = ids["digitalocean_firewall.firewall"]
        expected_key = ids["digitalocean_ssh_key.key"]
        if (evidence.empty_state_sha256 != before.intent.empty_state_sha256
                or (evidence.empty_state_sha256,
                    evidence.verified_absent_droplet_ids,
                    evidence.verified_absent_firewall_id,
                    evidence.verified_absent_ssh_key_id,
                    evidence.selector_tag_cleanup_pending) != (
                    first.empty_state_sha256,
                    first.verified_absent_droplet_ids,
                    first.verified_absent_firewall_id,
                    first.verified_absent_ssh_key_id,
                    first.selector_tag_cleanup_pending)
                or list(evidence.verified_absent_droplet_ids) != expected_droplets
                or evidence.verified_absent_firewall_id != expected_firewall
                or evidence.verified_absent_ssh_key_id != expected_key
                or type(evidence.selector_tag_cleanup_pending) is not bool):
            raise ValueError("exact-ID absence evidence changed")
        completed = _now()
        if completed.utcoffset() != timedelta(0):
            raise ValueError("absence confirmation clock differs")
        proof = {
            "scopeSnapshotId": snapshot["snapshotId"],
            "providerScopeSha256": snapshot["providerScopeSha256"],
            "readyJournalSha256": job_event_digest(child.events),
            "previewJobId": before.preview_job.id,
            "previewJournalSha256": job_event_digest(before.preview_job.events),
            "applyJobId": before.apply_job.id,
            "applyJournalSha256": job_event_digest(before.apply_job.events),
            "emptyStateSha256": evidence.empty_state_sha256,
            "resourceIdsSha256": _fingerprint(ids),
            "verifiedAbsentDropletIds": expected_droplets,
            "verifiedAbsentFirewallId": expected_firewall,
            "verifiedAbsentSshKeyId": expected_key,
            "selectorTagCleanupPending": evidence.selector_tag_cleanup_pending,
            "confirmationCompletedAt": completed.isoformat(),
            "confirmationExpiresAt": (completed + timedelta(seconds=30)).isoformat(),
        }

        def locked_authority():
            current = jobs.get(child.id)
            if (current != replace(child, input={**child.input, "phase": "provider_absent"})
                    or read() != before_pair
                    or jobs.get(parent.id) != parent
                    or lookup(parent.target_id) != (core.input["corePlanId"], _FENCE)):
                raise ValueError("absence publication boundary changed")

        published = jobs.publish_keyed_provider_absent_if_ready(
            child, expected_event_digest=proof["readyJournalSha256"],
            proof=proof, authority=locked_authority)
        if published is None:
            raise ValueError("absence publication CAS lost")
        return published
    except Exception:
        raise ProviderKeyedComprehensiveTeardownAttention(
            "keyed provider absence publication is unverified; reconcile persisted phase"
        ) from None


def recognize_provider_keyed_destroy_absence(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, sketch_repository=None,
    credential_repository=None, lease_lookup=None,
) -> StoredJobRun:
    """Recognize the sealed prefix without provider GET or Terraform replay.

    This only recognizes a historical observation. A later destructive step
    must obtain fresh provider absence evidence before acting.
    """
    from app.services.provider_keyed_destroy_absence_preflight import _read_success_boundary
    from app.services.provider_keyed_teardown_source import _read_published_post_destroy_boundary
    from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
    from app.services.sketch_state_workspaces import _default_state_root
    from app.storage.credential_repository import SqlAlchemyCredentialRepository
    from app.storage.job_repository import (
        _PROVIDER_ABSENT_PROOF_KEYS, _utc_instant,
        _valid_provider_absent_handoff, job_event_digest,
    )
    from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository

    try:
        if (environment != "devtest" or not teardown_parent_id
                or not isinstance(state_root, Path) or state_root != _default_state_root()
                or state_root.resolve(strict=True) != state_root):
            raise ValueError("DevTest absence recognizer only")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        chains = sketch_repository or SqlAlchemySketchChainRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        lookup = lease_lookup or _db_lease_lookup
        historical_parent = jobs.get(teardown_parent_id)
        if historical_parent is not None and "publishedSource" in historical_parent.input:
            source, bound = _read_published_post_destroy_boundary(
                teardown_parent_id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans,
                sketch_repository=chains, credential_repository=credentials,
                lease_lookup=lookup, credential_check=_credential_snapshot,
            )
            expected_variant = ("published_append" if "publishedAppendSource" in historical_parent.input
                                else "published")
            if (source.variant != expected_variant
                    or source.teardown_parent_id != historical_parent.id
                    or bound.parent != historical_parent):
                raise ValueError("published absence source differs")
        else:
            bound = _read_success_boundary(
                teardown_parent_id, jobs=jobs, plans=plans, chains=chains,
                credentials=credentials, lookup=lookup,
                handoff_auditor=audit_pending_provider_keyed_bootstrap,
                credential_check=_credential_snapshot, state_root=state_root,
            )
        child = jobs.get(_child_id(bound.core.id))
        if (child is None or child.input.get("phase") != "provider_absent"
                or child.action != ACTION or child.status != "running"
                or child.target_id != bound.parent.target_id
                or child.id != _child_id(bound.core.id)
                or child.input.get("coreJobId") != bound.core.id
                or child.input.get("corePlanId") != bound.core.input["corePlanId"]
                or child.input.get("teardownParentId") != bound.parent.id
                or child.input.get("scopeSnapshotId") != bound.parent.input[
                    "scopeSnapshot"]["snapshotId"]
                or child.input.get("providerScopeSha256") != bound.parent.input[
                    "scopeSnapshot"]["providerScopeSha256"]
                or len(child.events) not in (6, 13, 17)
                or child.events[-1].message != "provider_absent"
                or child.events[-1].level != "info"
                or child.events[-1].sequence != len(child.events)
                or len([row for row in jobs.list_for_engagement(bound.parent.target_id)
                        if row.action == ACTION]) != 1):
            raise ValueError("provider absence journal differs")
        prior = replace(child, input={**child.input, "phase": "inspector_ready"},
                        events=child.events[:-1])
        event = child.events[-1].data
        if type(event) is not dict:
            raise ValueError("provider absence event differs")
        proof = {key: value for key, value in event.items() if key != "observedAt"}
        if (set(event) != _PROVIDER_ABSENT_PROOF_KEYS | {"observedAt"}
                or _utc_instant(event["observedAt"]) is None
                or not _valid_provider_absent_handoff(
                    prior, job_event_digest(prior.events), proof,
                    queued_cleanup_event_data(bound.parent.input["scopeSnapshot"])
                    if "publishedSource" in bound.parent.input else None)
                or proof["previewJobId"] != bound.preview_job.id
                or proof["previewJournalSha256"] != job_event_digest(bound.preview_job.events)
                or proof["applyJobId"] != bound.apply_job.id
                or proof["applyJournalSha256"] != job_event_digest(bound.apply_job.events)
                or proof["emptyStateSha256"] != bound.intent.empty_state_sha256
                or proof["resourceIdsSha256"] != _fingerprint(bound.intent.resource_ids)
                or proof["verifiedAbsentDropletIds"] != sorted(
                    value for key, value in bound.intent.resource_ids.items()
                    if key.startswith("digitalocean_droplet."))
                or proof["verifiedAbsentFirewallId"] != bound.intent.resource_ids[
                    "digitalocean_firewall.firewall"]
                or proof["verifiedAbsentSshKeyId"] != bound.intent.resource_ids[
                    "digitalocean_ssh_key.key"]):
            raise ValueError("provider absence proof differs")
        return child
    except Exception:
        raise ProviderKeyedComprehensiveTeardownAttention(
            "sealed provider absence phase is unverified; obtain fresh proof before cleanup"
        ) from None


def retire_provider_keyed_group_after_absence(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, sketch_repository=None,
    credential_repository=None, provider_resource_repository=None, lease_lookup=None,
    absence_preflight: Callable | None = None,
) -> tuple:
    """Privately retire the two keyed runtime rows after a fresh exact-ID GET.

    Desired topology and the rendered workspace survive. The group apply job
    is the historical teardown job for both rows; no split chain runner runs.
    """
    from app.services.provider_keyed_destroy_absence_preflight import (
        _read_success_boundary, reconcile_successful_digitalocean_destroy_absence,
    )
    from app.services.provider_keyed_digitalocean_absence import DigitalOceanAbsenceEvidence
    from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
    from app.services.provider_keyed_teardown_source import _read_published_post_destroy_boundary
    from app.services.sketch_state_workspaces import _default_state_root
    from app.storage.credential_repository import SqlAlchemyCredentialRepository
    from app.storage.job_repository import job_event_digest
    from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
    from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository

    try:
        if (environment != "devtest" or not teardown_parent_id
                or not isinstance(state_root, Path) or state_root != _default_state_root()
                or state_root.resolve(strict=True) != state_root):
            raise ValueError("DevTest keyed retirement only")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        chains = sketch_repository or SqlAlchemySketchChainRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        lookup = lease_lookup or _db_lease_lookup
        child = recognize_provider_keyed_destroy_absence(
            teardown_parent_id, environment=environment, state_root=state_root,
            job_repository=jobs, plan_repository=plans, sketch_repository=chains,
            credential_repository=credentials, lease_lookup=lookup,
        )
        if child.action != ACTION or child.input.get("phase") != "provider_absent":
            raise ValueError("provider-absent coordinator phase differs")

        historical_parent = jobs.get(teardown_parent_id)
        published = historical_parent is not None and "publishedSource" in historical_parent.input

        def read():
            if published:
                return _read_published_post_destroy_boundary(
                    teardown_parent_id, environment=environment, state_root=state_root,
                    job_repository=jobs, plan_repository=plans, sketch_repository=chains,
                    credential_repository=credentials, lease_lookup=lookup,
                    credential_check=_credential_snapshot,
                )
            return (None, _read_success_boundary(
                teardown_parent_id, jobs=jobs, plans=plans, chains=chains,
                credentials=credentials, lookup=lookup,
                handoff_auditor=audit_pending_provider_keyed_bootstrap,
                credential_check=_credential_snapshot, state_root=state_root,
            ))

        before_pair = read()
        source, before = before_pair
        current_rows = tuple(sorted(before.chains, key=lambda row: row.chain_id))
        current_records = tuple(sorted(resources.list_for_engagement(before.parent.target_id),
                                       key=lambda row: row.id))
        ids = before.intent.resource_ids
        expected_droplets = sorted(value for key, value in ids.items()
                                   if key.startswith("digitalocean_droplet."))
        if (len(current_rows) != 2 or any(row.status != "deployed"
                or row.teardown_job_id or row.terraform_working_directory != str(before.workspace.path)
                or not row.nodes for row in current_rows)
                or {str(node.get("providerInstanceId")) for row in current_rows
                    for node in row.nodes} != set(expected_droplets)
                or jobs.get(child.id) != child):
            raise ValueError("keyed runtime projection differs")
        prove = absence_preflight or reconcile_successful_digitalocean_destroy_absence
        evidence = prove(
            teardown_parent_id, environment=environment, state_root=state_root,
            job_repository=jobs, plan_repository=plans, sketch_repository=chains,
            credential_repository=credentials, lease_lookup=lookup,
            max_attempts=12,
        )
        if (type(evidence) is not DigitalOceanAbsenceEvidence
                or evidence.empty_state_sha256 != before.intent.empty_state_sha256
                or list(evidence.verified_absent_droplet_ids) != expected_droplets
                or evidence.verified_absent_firewall_id != ids["digitalocean_firewall.firewall"]
                or evidence.verified_absent_ssh_key_id != ids["digitalocean_ssh_key.key"]
                or read() != before_pair or jobs.get(child.id) != child
                or tuple(sorted(resources.list_for_engagement(before.parent.target_id),
                                key=lambda row: row.id)) != current_records):
            raise ValueError("fresh exact-ID absence or authority changed")
        completed = _now()
        proof = {
            "scopeSnapshotId": child.input["scopeSnapshotId"],
            "providerScopeSha256": child.input["providerScopeSha256"],
            "sourceJournalSha256": job_event_digest(child.events),
            "applyJobId": before.apply_job.id,
            "resourceIdsSha256": _fingerprint(ids),
            "verifiedAbsentDropletIds": expected_droplets,
            "verifiedAbsentFirewallId": evidence.verified_absent_firewall_id,
            "verifiedAbsentSshKeyId": evidence.verified_absent_ssh_key_id,
            "confirmationCompletedAt": completed.isoformat(),
            "confirmationExpiresAt": (completed + timedelta(seconds=30)).isoformat(),
        }

        def locked_authority():
            if (read() != before_pair
                    or jobs.get(child.id) != replace(
                        child, input={**child.input, "phase": "group_retired"})
                    or tuple(sorted(resources.list_for_engagement(before.parent.target_id),
                                    key=lambda row: row.id)) != current_records):
                raise ValueError("keyed retirement authority changed")

        return chains.publish_provider_keyed_group_retired(
            coordinator=child, prior_chains=current_rows,
            prior_records=current_records, group_apply_job_id=before.apply_job.id,
            resource_ids=dict(ids), proof=proof, authority=locked_authority,
            prior_chain_projection_sha256=(
                (_fingerprint({row.chain_id: row.to_dict() for row in current_rows})
                 if source.variant == "published_append" else
                 historical_parent.input["publishedSource"]["chain_projection_sha256"])
                if source is not None else None),
        )
    except Exception:
        raise ProviderKeyedComprehensiveTeardownAttention(
            "keyed group runtime retirement is unverified; no core or Inspector cleanup advanced"
        ) from None


def recognize_provider_keyed_group_retired(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, sketch_repository=None,
    credential_repository=None, provider_resource_repository=None, lease_lookup=None,
) -> tuple:
    """Recognize the complete persisted group-retirement prefix without I/O replay."""
    from app.services.provider_keyed_destroy_absence_preflight import _read_success_boundary
    from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
    from app.services.provider_keyed_teardown_source import _read_published_post_destroy_boundary
    from app.services.sketch_state_workspaces import _default_state_root
    from app.storage.credential_repository import SqlAlchemyCredentialRepository
    from app.storage.job_repository import (
        _PROVIDER_ABSENT_PROOF_KEYS, _stored_utc_instant, _utc_instant,
        _valid_provider_absent_handoff, job_event_digest,
    )
    from app.storage.provider_resource_repository import (
        SqlAlchemyProviderResourceRepository, TERMINAL_RECORD_STATUSES,
        is_barragan_owned_record,
    )
    from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository

    try:
        if (environment != "devtest" or not teardown_parent_id
                or not isinstance(state_root, Path) or state_root != _default_state_root()
                or state_root.resolve(strict=True) != state_root):
            raise ValueError("DevTest group-retired recognizer only")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        chains = sketch_repository or SqlAlchemySketchChainRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        lookup = lease_lookup or _db_lease_lookup
        historical_parent = jobs.get(teardown_parent_id)
        published = historical_parent is not None and "publishedSource" in historical_parent.input
        if published:
            source, bound = _read_published_post_destroy_boundary(
                teardown_parent_id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans, sketch_repository=chains,
                credential_repository=credentials, lease_lookup=lookup,
                credential_check=_credential_snapshot, retired=True,
            )
            expected_variant = ("published_append" if "publishedAppendSource" in historical_parent.input
                                else "published")
            if (source.variant != expected_variant or source.teardown_parent_id != teardown_parent_id):
                raise ValueError("retired published source differs")
        else:
            bound = _read_success_boundary(
                teardown_parent_id, jobs=jobs, plans=plans, chains=chains,
                credentials=credentials, lookup=lookup,
                handoff_auditor=audit_pending_provider_keyed_bootstrap,
                credential_check=_credential_snapshot, state_root=state_root,
            )
        child = jobs.get(_child_id(bound.core.id))
        if (child is None or child.action != ACTION or child.status != "running"
                or child.input.get("phase") != "group_retired"
                or child.target_id != bound.parent.target_id
                or child.input.get("teardownParentId") != bound.parent.id
                or child.input.get("coreJobId") != bound.core.id
                or child.input.get("corePlanId") != bound.core.input["corePlanId"]
                or len(child.events) not in (7, 14, 18)
                or child.events[-1].sequence != len(child.events)
                or child.events[-1].level != "info"
                or child.events[-1].message != "keyed_provider_group_retired"
                or len([row for row in jobs.list_for_engagement(bound.parent.target_id)
                        if row.action == ACTION]) != 1):
            raise ValueError("group-retired coordinator differs")
        prior = replace(child, input={**child.input, "phase": "provider_absent"},
                        events=child.events[:-1])
        before_ready = replace(prior, input={**prior.input, "phase": "inspector_ready"},
                               events=prior.events[:-1])
        absent = prior.events[-1].data
        sealed_ids = bound.intent.resource_ids
        sealed_droplets = sorted(value for key, value in sealed_ids.items()
                                 if key.startswith("digitalocean_droplet."))
        if (type(absent) is not dict
                or prior.events[-1].sequence != len(prior.events)
                or prior.events[-1].level != "info"
                or prior.events[-1].message != "provider_absent"
                or [row.sequence for row in prior.events]
                != list(range(1, len(prior.events) + 1))
                or set(absent) != _PROVIDER_ABSENT_PROOF_KEYS | {"observedAt"}
                or _utc_instant(absent["observedAt"]) is None
                or not (_utc_instant(absent["confirmationCompletedAt"])
                        <= _utc_instant(absent["observedAt"])
                        < _utc_instant(absent["confirmationExpiresAt"]))
                or not _valid_provider_absent_handoff(
                    before_ready, job_event_digest(before_ready.events),
                    {key: value for key, value in absent.items() if key != "observedAt"},
                    queued_cleanup_event_data(bound.parent.input["scopeSnapshot"])
                    if published else None)
                or absent["previewJobId"] != bound.preview_job.id
                or absent["previewJournalSha256"] != job_event_digest(bound.preview_job.events)
                or absent["applyJobId"] != bound.apply_job.id
                or absent["applyJournalSha256"] != job_event_digest(bound.apply_job.events)
                or absent["emptyStateSha256"] != bound.intent.empty_state_sha256
                or absent["resourceIdsSha256"] != _fingerprint(sealed_ids)
                or absent["verifiedAbsentDropletIds"] != sealed_droplets
                or absent["verifiedAbsentFirewallId"] != sealed_ids[
                    "digitalocean_firewall.firewall"]
                or absent["verifiedAbsentSshKeyId"] != sealed_ids[
                    "digitalocean_ssh_key.key"]):
            raise ValueError("prior provider-absent prefix differs")
        event = child.events[-1].data
        if type(event) is not dict:
            raise ValueError("group-retired event differs")
        ids = bound.intent.resource_ids
        expected_droplets = sorted(value for key, value in ids.items()
                                   if key.startswith("digitalocean_droplet."))
        proof = {key: value for key, value in event.items()
                 if key not in {"chainIds", "retiredRecordIds", "observedAt",
                                "priorChainProjectionSha256"}}
        expected_event_keys = {
                "scopeSnapshotId", "providerScopeSha256", "sourceJournalSha256",
                "applyJobId", "resourceIdsSha256", "verifiedAbsentDropletIds",
                "verifiedAbsentFirewallId", "verifiedAbsentSshKeyId",
                "confirmationCompletedAt", "confirmationExpiresAt",
                "chainIds", "retiredRecordIds", "observedAt",
            }
        if published:
            expected_event_keys.add("priorChainProjectionSha256")
        if (set(event) != expected_event_keys
                or (published and "publishedAppendSource" not in historical_parent.input
                    and event["priorChainProjectionSha256"] !=
                    historical_parent.input["publishedSource"]["chain_projection_sha256"])
                or proof["sourceJournalSha256"] != job_event_digest(prior.events)
                or proof["scopeSnapshotId"] != child.input["scopeSnapshotId"]
                or proof["providerScopeSha256"] != child.input["providerScopeSha256"]
                or proof["applyJobId"] != bound.apply_job.id
                or proof["resourceIdsSha256"] != _fingerprint(ids)
                or proof["verifiedAbsentDropletIds"] != expected_droplets
                or proof["verifiedAbsentFirewallId"] != ids["digitalocean_firewall.firewall"]
                or proof["verifiedAbsentSshKeyId"] != ids["digitalocean_ssh_key.key"]
                or _utc_instant(proof["confirmationCompletedAt"]) is None
                or _utc_instant(proof["confirmationExpiresAt"]) is None
                or _utc_instant(proof["confirmationExpiresAt"])
                > _utc_instant(proof["confirmationCompletedAt"]) + timedelta(seconds=30)
                or _utc_instant(event["observedAt"]) is None
                or not (_utc_instant(proof["confirmationCompletedAt"])
                        <= _utc_instant(event["observedAt"])
                        < _utc_instant(proof["confirmationExpiresAt"]))
                or event["chainIds"] != sorted(bound.scope["chainIds"])
                or type(event["retiredRecordIds"]) is not list
                or event["retiredRecordIds"] != sorted(set(event["retiredRecordIds"]))):
            raise ValueError("group-retired event differs")
        current = tuple(sorted(bound.chains, key=lambda row: row.chain_id))
        snapshots = {row["chainId"]: row for row in bound.parent.input[
            "scopeSnapshot"].get("chains", [])}
        if (len(current) != 2 or any(row.status != "destroyed" or row.nodes != []
                or row.teardown_job_id != bound.apply_job.id
                or row.terraform_working_directory != str(bound.workspace.path)
                or not row.deploy_job_id
                or (snapshots and row.deploy_job_id != snapshots[row.chain_id]["deployJobId"])
                for row in current)):
            raise ValueError("retired chain projection differs")
        records = tuple(resources.list_for_engagement(bound.parent.target_id))
        if any(row.resource_type not in {"inspector", "inspector_firewall"}
               and (not isinstance(row.metadata, dict) or row.metadata.get("role") not in {
                   "inspector", "inspector_firewall"})
               and str(row.status).lower() not in TERMINAL_RECORD_STATUSES
               for row in records):
            raise ValueError("unexpected active provider resource record")
        retired = [row.id for row in records if row.id in event["retiredRecordIds"]
                   and str(row.status).lower() in TERMINAL_RECORD_STATUSES]
        if (sorted(retired) != event["retiredRecordIds"]
                or (published and any(
                    row.status != "destroyed" or row.lifecycle_state != "destroyed"
                    or row.destroyed_at is None
                    for row in records if row.id in event["retiredRecordIds"]))):
            raise ValueError("retired provider record projection differs")
        if published:
            expected_by_kind = {
                "digitalocean_droplet": set(expected_droplets),
                "digitalocean_firewall": {ids["digitalocean_firewall.firewall"]},
                "digitalocean_ssh_key": {ids["digitalocean_ssh_key.key"]},
            }
            aliases = {
                "droplet": "digitalocean_droplet",
                "firewall": "digitalocean_firewall",
                "ssh_key": "digitalocean_ssh_key",
            }
            for row in records:
                if row.id not in event["retiredRecordIds"]:
                    continue
                raw_kind = row.resource_type.lower().replace("-", "_")
                kind = aliases.get(raw_kind, raw_kind)
                if (row.engagement_id != bound.parent.target_id
                        or row.provider != "digitalocean"
                        or not is_barragan_owned_record(row)
                        or kind not in expected_by_kind
                        or row.resource_id not in expected_by_kind[kind]
                        or row.adoption_job_id != source.initial_job_id
                        or _stored_utc_instant(row.destroyed_at) !=
                           _utc_instant(event["observedAt"])):
                    raise ValueError("sealed retired provider record differs")
        return current
    except Exception:
        raise ProviderKeyedComprehensiveTeardownAttention(
            "sealed keyed group retirement is unverified; later cleanup needs fresh proof"
        ) from None
