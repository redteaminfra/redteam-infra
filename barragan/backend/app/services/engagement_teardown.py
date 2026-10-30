# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from uuid import uuid4

from app.core.runtime import current_runtime, runtime_context, start_runtime_task
from app.domain import JobEvent
from app.services.engagement_lifecycle import get_engagement_lifecycle, reconcile_engagement_lifecycle
from app.services.teardown_target_contract import canonical_teardown_targets, teardown_target_sha256
from app.storage.job_repository import (
    JobRepository, KeyedDomainAssignmentConflict, SqlAlchemyJobRepository, StoredJobRun,
)
from app.storage.deployment_plan_repository import DeploymentPlanConflictError, SqlAlchemyDeploymentPlanRepository
from app.storage.domain_repository import DomainRepository, SqlAlchemyDomainRepository
from app.storage.provider_resource_repository import (
    ProviderResourceRepository,
    SqlAlchemyProviderResourceRepository,
    TERMINAL_RECORD_STATUSES,
    is_barragan_owned_record,
)
from app.storage.sketch_chain_repository import SketchChainRepository, SqlAlchemySketchChainRepository


ENGAGEMENT_TEARDOWN_ACTION = "engagement_comprehensive_teardown"
PILOT_CORE_ACTION = "pilot_standard_rti_guarded_execute"
LEASE_SECONDS = 120
RECOVERY_INTERVAL_SECONDS = 30
POLL_SECONDS = 2.0
HEARTBEAT_START_TIMEOUT_SECONDS = 5.0

BackgroundRunner = Callable[[Callable[[], None]], None]
ChainDispatcher = Callable[[str, str, dict[str, Any]], dict[str, Any] | None]
CoreDispatcher = Callable[[str, list[dict[str, Any]]], Any]
OutboundDispatcher = Callable[[str, str, str], Any]
InspectorPreflight = Callable[[str, str, str, list[dict[str, Any]]], dict[str, Any]]
InspectorStateReader = Callable[[str], dict[str, Any]]
Waiter = Callable[[float], None]
ProviderKeyedCoordinator = Callable[[str], StoredJobRun]

_owner = f"runtime-{uuid4().hex}"
_monitor_lock = threading.Lock()
_monitor_started = False
_fallback_core_lease_lock = threading.Lock()
_fallback_core_leases: dict[str, str] = {}


class EngagementTeardownValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("engagement teardown validation failed")
        self.errors = errors


class EngagementTeardownLeaseLost(RuntimeError):
    """The fenced parent belongs to another runtime; the old worker must stop silently."""


class _FallbackCoreMutationLeases:
    """Process-local service-test substitute when no runtime database is bound."""

    def acquire(self, engagement_id: str, owner_id: str, operation: str) -> bool:
        with _fallback_core_lease_lock:
            if engagement_id in _fallback_core_leases:
                raise DeploymentPlanConflictError("another core mutation is already in progress")
            _fallback_core_leases[engagement_id] = owner_id
            return True

    def release(self, engagement_id: str, owner_id: str) -> None:
        with _fallback_core_lease_lock:
            if _fallback_core_leases.get(engagement_id) == owner_id:
                _fallback_core_leases.pop(engagement_id, None)


def _core_mutation_leases(jobs: JobRepository):
    if not isinstance(jobs, SqlAlchemyJobRepository):
        namespace = str(getattr(jobs, "_core_mutation_lease_namespace", "") or "")
        if not namespace:
            namespace = uuid4().hex
            setattr(jobs, "_core_mutation_lease_namespace", namespace)
        return _FallbackCoreMutationLeases(), f"test-{namespace}:"
    return SqlAlchemyDeploymentPlanRepository(), ""


def preview_engagement_teardown(
    job_id: str,
    *,
    job_repository: JobRepository | None = None,
    sketch_repository: SketchChainRepository | None = None,
    provider_resource_repository: ProviderResourceRepository | None = None,
    domain_repository: DomainRepository | None = None,
    inspector_state_reader: InspectorStateReader | None = None,
) -> dict[str, Any] | None:
    jobs = job_repository or SqlAlchemyJobRepository()
    existing = jobs.get(job_id)
    if existing is None:
        return None
    if is_published_mixed_initial_teardown_request(existing, jobs):
        raise EngagementTeardownValidationError(
            ["published mixed teardown requires a two-provider review and coordinator; execution is unavailable"])
    if existing.action == ENGAGEMENT_TEARDOWN_ACTION:
        core, snapshot = _validated_parent_boundary(existing, jobs)
        if "providerScopes" not in snapshot:
            snapshot = _refresh_confirmed_scope_snapshot(
                snapshot,
                _current_scope_snapshot(
                    core,
                    jobs=jobs,
                    chains=sketch_repository or SqlAlchemySketchChainRepository(),
                    resources=provider_resource_repository or SqlAlchemyProviderResourceRepository(),
                    domain_repository=domain_repository,
                    inspector_state_reader=inspector_state_reader,
                    allowed_teardown_parent_id=existing.id if existing.status in {"queued", "running"} else None,
                ),
            )
        return _preview_projection(snapshot, parent_job_id=existing.id)
    if existing.action != PILOT_CORE_ACTION:
        return None
    existing_parent = jobs.get(_parent_id(existing.id))
    if existing_parent is not None and _is_provider_keyed_v2(existing):
        parent_core, sealed = _validated_parent_boundary(existing_parent, jobs)
        if parent_core.id != existing.id:
            raise EngagementTeardownValidationError(["confirmed keyed teardown core changed"])
        return _preview_projection(sealed, parent_job_id=existing_parent.id)
    snapshot = _current_scope_snapshot(
        existing,
        jobs=jobs,
        chains=sketch_repository or SqlAlchemySketchChainRepository(),
        resources=provider_resource_repository or SqlAlchemyProviderResourceRepository(),
        domain_repository=domain_repository,
        inspector_state_reader=inspector_state_reader,
    )
    parent = jobs.get(_parent_id(existing.id))
    if parent is not None and parent.status == "failed":
        snapshot = _refresh_confirmed_scope_snapshot(
            dict(parent.input.get("scopeSnapshot") or {}),
            snapshot,
        )
    return _preview_projection(snapshot)


def start_engagement_teardown(
    job_id: str,
    body: dict[str, Any],
    *,
    job_repository: JobRepository | None = None,
    sketch_repository: SketchChainRepository | None = None,
    provider_resource_repository: ProviderResourceRepository | None = None,
    domain_repository: DomainRepository | None = None,
    inspector_state_reader: InspectorStateReader | None = None,
    chain_dispatcher: ChainDispatcher | None = None,
    outbound_dispatcher: OutboundDispatcher | None = None,
    inspector_preflight: InspectorPreflight | None = None,
    core_dispatcher: CoreDispatcher | None = None,
    background_runner: BackgroundRunner | None = None,
    wait: Waiter | None = None,
    provider_keyed_coordinator: ProviderKeyedCoordinator | None = None,
    provider_keyed_environment: str = "",
    provider_keyed_published_source=None,
    provider_keyed_state_root=None,
) -> StoredJobRun | None:
    jobs = job_repository or SqlAlchemyJobRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    requested = jobs.get(job_id)
    if requested is None:
        return None
    if is_published_mixed_initial_teardown_request(requested, jobs):
        raise EngagementTeardownValidationError(
            ["published mixed teardown requires a two-provider review and coordinator; execution is unavailable"])
    requested_core = jobs.get(str(requested.input.get("coreJobId") or "")) if requested.action == ENGAGEMENT_TEARDOWN_ACTION else requested
    keyed_request = ((requested_core is not None and _is_provider_keyed_v2(requested_core))
                     or (requested.action == ENGAGEMENT_TEARDOWN_ACTION
                         and "providerScopes" in requested.input.get("scopeSnapshot", {})))
    if keyed_request and (provider_keyed_coordinator is None or provider_keyed_environment != "devtest"):
        raise EngagementTeardownValidationError(["keyed provider teardown execution is not available; review only"])
    if requested.action == PILOT_CORE_ACTION and keyed_request:
        completed = jobs.get(_parent_id(requested.id))
        if completed is not None and completed.status in {"succeeded", "failed"}:
            prior_core, _sealed = _validated_parent_boundary(completed, jobs)
            if prior_core.id != requested.id:
                raise EngagementTeardownValidationError(["confirmed keyed teardown core changed"])
            if completed.status == "succeeded":
                return completed
            raise EngagementTeardownValidationError(
                ["failed keyed teardown requires phase-specific recovery; automatic retry is unavailable"]
            )
        if completed is not None and completed.status in {"queued", "running"}:
            prior_core, _sealed = _validated_parent_boundary(completed, jobs)
            if prior_core.id != requested.id:
                raise EngagementTeardownValidationError(["confirmed keyed teardown core changed"])
            requested = completed
    if requested.action == ENGAGEMENT_TEARDOWN_ACTION:
        parent = requested
        core, snapshot = _validated_parent_boundary(parent, jobs)
        if "providerScopes" in snapshot and parent.status == "failed":
            raise EngagementTeardownValidationError(
                ["failed keyed teardown requires phase-specific recovery; automatic retry is unavailable"]
            )
        if "providerScopes" not in snapshot:
            snapshot = _refresh_confirmed_scope_snapshot(
                snapshot,
                _current_scope_snapshot(
                    core,
                    jobs=jobs,
                    chains=chains,
                    resources=resources,
                    domain_repository=domain_repository,
                    inspector_state_reader=inspector_state_reader,
                ),
            )
    elif requested.action == PILOT_CORE_ACTION:
        core = requested
        snapshot = _current_scope_snapshot(
            core,
            jobs=jobs,
            chains=chains,
            resources=resources,
            domain_repository=domain_repository,
            inspector_state_reader=inspector_state_reader,
        )
        parent = jobs.get(_parent_id(core.id))
        if parent is not None and parent.status == "failed":
            snapshot = _refresh_confirmed_scope_snapshot(
                dict(parent.input.get("scopeSnapshot") or {}),
                snapshot,
            )
    else:
        return None
    if core is None:
        raise EngagementTeardownValidationError(["core deployment job was not found"])
    expected = str(snapshot.get("confirmationPhrase") or "")
    if str(body.get("confirmation") or "") != expected:
        raise EngagementTeardownValidationError([f'confirmation must equal "{expected}"'])
    supplied_snapshot_id = str(body.get("snapshotId") or "").strip()
    if not supplied_snapshot_id:
        raise EngagementTeardownValidationError(["snapshotId is required; review the current cleanup scope and confirm again"])
    if supplied_snapshot_id != str(snapshot.get("snapshotId") or ""):
        raise EngagementTeardownValidationError(["teardown scope changed; review the current cleanup scope and confirm again"])

    refresh_failed_parent_snapshot = parent is not None and parent.status == "failed"

    if parent is None:
        now = _now()
        try:
            proposal = StoredJobRun(
                    id=_parent_id(core.id),
                    action=ENGAGEMENT_TEARDOWN_ACTION,
                    status="queued",
                    target=f"engagement:{snapshot['engagementId']}",
                    target_type="engagement",
                    target_id=str(snapshot["engagementId"]),
                    requested_by=str(body.get("requestedBy") or core.requested_by or "operator"),
                    input={
                        "engagementId": snapshot["engagementId"],
                        "coreJobId": core.id,
                        "scopeSnapshot": snapshot,
                        "phase": "queued",
                        "outcomes": {},
                        "remainingOwnedResources": [],
                        "mutation": True,
                        "confirmation": "redacted",
                    },
                    artifact_refs=[],
                    created_at=now,
                    started_at=None,
                    finished_at=None,
                    events=[JobEvent(1, "info", "engagement teardown queued", {"snapshotId": snapshot["snapshotId"]})],
            )
            if provider_keyed_published_source is not None:
                if not keyed_request or provider_keyed_environment != "devtest":
                    raise EngagementTeardownValidationError(
                        ["published keyed teardown is unavailable"])
                from app.services.provider_keyed_append_source import (
                    PublishedProviderKeyedAppendSource,
                )
                if isinstance(provider_keyed_published_source, PublishedProviderKeyedAppendSource):
                    parent = jobs.reserve_published_keyed_append_teardown_parent(
                        proposal, reviewed_source=provider_keyed_published_source,
                        state_root=provider_keyed_state_root,
                    )
                else:
                    parent = jobs.reserve_published_keyed_teardown_parent(
                        proposal, reviewed_source=provider_keyed_published_source,
                        state_root=provider_keyed_state_root,
                    )
            else:
                parent = jobs.insert_inspector_teardown_barrier(proposal)
        except KeyedDomainAssignmentConflict:
            raise EngagementTeardownValidationError(
                ["keyed DNS assignments changed; review the current cleanup scope again"]
            ) from None
        if parent is None:
            raise EngagementTeardownValidationError(
                ["an Inspector lifecycle operation is active; review teardown after it finishes"])
    if parent.status == "succeeded":
        return parent

    if keyed_request:
        # Explicit injected DevTest seam only. The coordinator keeps this
        # confirmed parent queued for the existing keyed child contracts.
        sealed = dict(parent.input.get("scopeSnapshot") or {})
        from app.services.provider_keyed_published_initial_cleanup_authority import queued_cleanup_event_data
        if (jobs.get(parent.id) != parent
                or parent.action != ENGAGEMENT_TEARDOWN_ACTION
                or parent.status not in {"queued", "running"}
                or parent.input.get("mutation") is not True
                or parent.input.get("coreJobId") != core.id
                or parent.target_id != snapshot.get("engagementId")
                or sealed.get("snapshotId") != supplied_snapshot_id
                or sealed.get("confirmationPhrase") != expected
                or sealed.get("coreJobId") != core.id
                or sealed.get("engagementId") != parent.target_id
                or sealed.get("snapshotId") != _fingerprint({
                    key: value for key, value in sealed.items() if key != "snapshotId"})
                or not parent.events
                or parent.events[0] != JobEvent(1, "info", "engagement teardown queued",
                                                queued_cleanup_event_data(sealed))):
            raise EngagementTeardownValidationError(
                ["confirmed keyed teardown parent changed while queueing; review its scope again"])
        if parent.status == "running":
            if (parent.started_at is None or parent.finished_at is not None
                    or not _canonical_nonempty_string(parent.input.get("phase"))
                    or parent.input["phase"] == "queued"):
                raise EngagementTeardownValidationError(
                    ["running keyed teardown parent needs phase-specific recovery"]
                )
            return parent
        if (len(parent.events) != 1 or parent.started_at is not None or parent.finished_at is not None
                or parent.input.get("phase") != "queued"):
            raise EngagementTeardownValidationError(
                ["confirmed keyed teardown parent changed while queueing; review its scope again"]
            )
        provider_keyed_coordinator(parent.id)
        return jobs.get(parent.id)

    return _claim_and_launch(
        parent,
        jobs=jobs,
        chains=chains,
        resources=resources,
        chain_dispatcher=chain_dispatcher,
        outbound_dispatcher=outbound_dispatcher,
        inspector_preflight=inspector_preflight,
        inspector_state_reader=inspector_state_reader,
        core_dispatcher=core_dispatcher,
        background_runner=background_runner,
        wait=wait,
        explicit_retry=parent.status == "failed",
        confirmed_snapshot=snapshot if refresh_failed_parent_snapshot else None,
    )


def get_engagement_teardown(job_id: str, *, repository: JobRepository | None = None) -> StoredJobRun | None:
    job = (repository or SqlAlchemyJobRepository()).get(job_id)
    return job if job is not None and job.action == ENGAGEMENT_TEARDOWN_ACTION else None


def recover_engagement_teardowns(
    *,
    job_repository: JobRepository | None = None,
    sketch_repository: SketchChainRepository | None = None,
    provider_resource_repository: ProviderResourceRepository | None = None,
    chain_dispatcher: ChainDispatcher | None = None,
    outbound_dispatcher: OutboundDispatcher | None = None,
    inspector_preflight: InspectorPreflight | None = None,
    inspector_state_reader: InspectorStateReader | None = None,
    core_dispatcher: CoreDispatcher | None = None,
    background_runner: BackgroundRunner | None = None,
    wait: Waiter | None = None,
    provider_keyed_coordinator: ProviderKeyedCoordinator | None = None,
    provider_keyed_environment: str = "",
) -> list[str]:
    jobs = job_repository or SqlAlchemyJobRepository()
    recovered: list[str] = []
    for parent in jobs.list():
        if parent.action != ENGAGEMENT_TEARDOWN_ACTION or parent.status not in {"queued", "running"}:
            continue
        core = jobs.get(str(parent.input.get("coreJobId") or ""))
        keyed_parent = (core is not None and _is_provider_keyed_v2(core)) or bool(
            parent.input.get("scopeSnapshot", {}).get("providerScopes"))
        if keyed_parent:
            if (provider_keyed_coordinator is not None and provider_keyed_environment == "devtest"
                    and parent.status == "queued"):
                try:
                    child_id = ("job-provider-keyed-comprehensive-teardown-"
                                + str(parent.input.get("coreJobId") or "").removeprefix("job-"))
                    before_child = jobs.get(child_id)
                    result = provider_keyed_coordinator(parent.id)
                    after_child = jobs.get(child_id)
                    if after_child is not None and after_child == result and after_child != before_child:
                        recovered.append(parent.id)
                except Exception:
                    # The child retains its claim/journal; no generic teardown
                    # lease or per-chain dispatcher may be used as fallback.
                    pass
            continue
        if core is None:
            continue
        claimed = _claim_and_launch(
            parent,
            jobs=jobs,
            chains=sketch_repository or SqlAlchemySketchChainRepository(),
            resources=provider_resource_repository or SqlAlchemyProviderResourceRepository(),
            chain_dispatcher=chain_dispatcher,
            outbound_dispatcher=outbound_dispatcher,
            inspector_preflight=inspector_preflight,
            inspector_state_reader=inspector_state_reader,
            core_dispatcher=core_dispatcher,
            background_runner=background_runner,
            wait=wait,
            explicit_retry=False,
        )
        if claimed is not None and _lease_owned(claimed, _owner, str(claimed.input.get("claimToken") or "")):
            recovered.append(parent.id)
    return recovered


def start_engagement_teardown_recovery_monitor(*, background_runner: BackgroundRunner | None = None) -> None:
    global _monitor_started
    with _monitor_lock:
        if _monitor_started:
            return
        _monitor_started = True
    task = run_engagement_teardown_recovery_monitor
    if background_runner is not None:
        background_runner(task)
    else:
        start_runtime_task(task, name="barragan-engagement-teardown-recovery-monitor")


def run_engagement_teardown_recovery_monitor(
    *,
    wait: Callable[[float], bool] | None = None,
    interval_seconds: float = RECOVERY_INTERVAL_SECONDS,
    max_cycles: int | None = None,
) -> None:
    stop = threading.Event()
    waiter = wait or stop.wait
    cycles = 0
    while max_cycles is None or cycles < max_cycles:
        if waiter(interval_seconds):
            return
        try:
            recover_engagement_teardowns()
        except Exception:
            logging.getLogger("barragan.background").exception("Engagement teardown recovery monitor cycle failed")
        cycles += 1


def engagement_teardown_in_progress(engagement_id: str, *, repository: JobRepository | None = None) -> StoredJobRun | None:
    for job in (repository or SqlAlchemyJobRepository()).list_for_engagement(engagement_id):
        if job.action in {ENGAGEMENT_TEARDOWN_ACTION,
                          "provider_keyed_mixed_zero_apply_cleanup",
                          "provider_keyed_mixed_interrupted_cleanup",
                          "provider_keyed_mixed_published_cleanup"} and job.status in {"queued", "running"}:
            return job
    return None


def assert_engagement_mutation_allowed(engagement_id: str, *, repository: JobRepository | None = None) -> None:
    active = engagement_teardown_in_progress(engagement_id, repository=repository)
    if active is not None:
        raise EngagementTeardownValidationError(
            [f"engagement teardown {active.id} is running; wait for cleanup to finish before changing infrastructure"]
        )


def assert_core_creation_allowed(
    engagement_id: str, *, repository: JobRepository | None = None, lifecycle_state: str | None = None
) -> None:
    repo = repository or SqlAlchemyJobRepository()
    assert_engagement_mutation_allowed(engagement_id, repository=repo)
    parents = [job for job in repo.list_for_engagement(engagement_id) if job.action == ENGAGEMENT_TEARDOWN_ACTION]
    latest = max(parents, key=lambda job: (job.created_at, job.id), default=None)
    recovery_state = comprehensive_teardown_recovery_state(latest)
    if recovery_state in {"recoverable", "in_progress", "blocked"}:
        parent_id = latest.id if latest is not None else "missing"
        raise EngagementTeardownValidationError(
            [f"engagement cleanup recovery is required through comprehensive teardown {parent_id} before creating core infrastructure"]
        )
    state = lifecycle_state
    if state is None:
        state = (
            get_engagement_lifecycle(engagement_id, job_repository=repo, persist=False)["state"]
            if isinstance(repo, SqlAlchemyJobRepository)
            else "unknown"
        )
    if state in {"cleanup_required", "tearing_down"}:
        parent_id = latest.id if latest is not None else "missing"
        raise EngagementTeardownValidationError(
            [f"engagement cleanup recovery is required through comprehensive teardown {parent_id} before creating core infrastructure"]
        )


def comprehensive_teardown_recovery_state(job: StoredJobRun | None) -> str:
    if job is None:
        return "absent"
    if _parent_boundary_fields(job) is None:
        return "blocked"
    if job.status in {"queued", "running"}:
        return "in_progress"
    if job.status == "failed":
        return "recoverable"
    if job.status != "succeeded" or type(job.input.get("remainingOwnedResources")) is not list:
        return "blocked"
    if job.input.get("remainingOwnedResources"):
        return "blocked"
    terminal = job.events[-1] if job.events else None
    if terminal is None or terminal.level != "info" or terminal.message != "engagement lifecycle reconciled":
        return "blocked"
    if terminal.data != {"state": "destroyed", "finalCleanupStatus": "verified_clean"}:
        return "blocked"
    return "complete"


def _parent_boundary_fields(parent: StoredJobRun) -> tuple[str, str, dict[str, Any]] | None:
    engagement_id = parent.input.get("engagementId")
    core_job_id = parent.input.get("coreJobId")
    scope = parent.input.get("scopeSnapshot")
    if not (_canonical_nonempty_string(engagement_id) and _canonical_nonempty_string(core_job_id)):
        return None
    if parent.target != f"engagement:{engagement_id}" or parent.target_type != "engagement" or parent.target_id != engagement_id:
        return None
    if type(scope) is not dict:
        return None
    if scope.get("engagementId") != engagement_id or scope.get("coreJobId") != core_job_id:
        return None
    for key in ("snapshotId", "confirmationPhrase", "engagementName"):
        if not _canonical_nonempty_string(scope.get(key)):
            return None
    expected_containers = {
        "chains": list, "ownedProviderRecordIds": list, "excludedUnmanagedProviderRecords": list,
        "core": dict, "publicVerificationTargets": list, "inspector": dict,
    }
    if any(type(scope.get(key)) is not expected for key, expected in expected_containers.items()):
        return None
    if not _valid_snapshot_chains(scope["chains"]):
        return None
    if "providerScopes" in scope and not _valid_provider_scopes(scope["providerScopes"], core_job_id):
        return None
    if "providerScopes" in scope and scope.get("providerScopeSha256") != _fingerprint(
            {"providerScopes": scope["providerScopes"]}):
        return None
    if "providerScopes" in scope and not _valid_keyed_domain_assignments(scope.get("domainAssignments")):
        return None
    if "providerScopes" in scope and not _valid_keyed_dns_cleanup_manifest(scope):
        return None
    if not _unique_nonempty_strings(scope["ownedProviderRecordIds"]) or not _unique_nonempty_strings(scope["excludedUnmanagedProviderRecords"]):
        return None
    core = scope["core"]
    if core.get("jobId") != core_job_id or not _canonical_nonempty_string(core.get("workspace")):
        return None
    if type(core.get("proxyCount")) is not int or core["proxyCount"] < 0:
        return None
    if not _valid_scope_public_targets(scope):
        return None
    inspector = scope["inspector"]
    if type(inspector.get("tracked")) is not bool or not _unique_nonempty_strings(inspector.get("ownedProviderRecordIds")):
        return None
    owners = inspector.get("recordOwners")
    if type(owners) is not dict or not all(_canonical_nonempty_string(key) and _canonical_nonempty_string(value) for key, value in owners.items()):
        return None
    count = inspector.get("verificationTargetCount")
    if type(count) is not int or count != len(scope["publicVerificationTargets"]):
        return None
    return engagement_id, core_job_id, dict(scope)


def _unique_nonempty_strings(value: Any) -> bool:
    return type(value) is list and all(_canonical_nonempty_string(item) for item in value) and len(value) == len(set(value))


def _canonical_nonempty_string(value: Any) -> bool:
    return type(value) is str and bool(value) and value == value.strip()


def _is_provider_keyed_v2(core: StoredJobRun) -> bool:
    return core.action == PILOT_CORE_ACTION and core.input.get("sketchStateSchema") == "provider-keyed-v2"


def is_published_mixed_initial_teardown_request(job: StoredJobRun | None,
                                                jobs: JobRepository) -> bool:
    """Keep a completed mixed generation out of the DigitalOcean-only path."""
    from app.services.provider_keyed_mixed_initial_plan_parent import (
        ACTION as MIXED_INITIAL_ACTION, _parent_id as mixed_parent_id,
    )

    if job is None:
        return False
    core = (jobs.get(str(job.input.get("coreJobId") or ""))
            if job.action == ENGAGEMENT_TEARDOWN_ACTION else job)
    if core is None or core.action != PILOT_CORE_ACTION:
        return False
    initial = jobs.get(mixed_parent_id(core.id))
    return (initial is not None and initial.action == MIXED_INITIAL_ACTION
            and initial.target_id == core.input.get("engagementId")
            and initial.status == "succeeded")


def _valid_provider_scopes(value: Any, core_job_id: str) -> bool:
    if type(value) is not list or len(value) != 1 or type(value[0]) is not dict:
        return False
    scope = value[0]
    if (scope.get("schema") != "provider-keyed-v2" or scope.get("provider") != "digitalocean"
            or scope.get("coreJobId") != core_job_id
            or not all(_canonical_nonempty_string(scope.get(key)) for key in (
                "corePlanId", "revisionId", "providerConnectionId", "workspace", "sourceRevision",
                "selectorTag", "stateSha256"))
            or not _unique_nonempty_strings(scope.get("chainIds")) or len(scope["chainIds"]) != 2):
        return False
    if (not scope["workspace"].startswith("/")
            or not re.fullmatch(r"[0-9a-f]{64}", scope["stateSha256"])):
        return False
    fingerprints = scope.get("chainFingerprints")
    if type(fingerprints) is not dict or set(fingerprints) != set(scope["chainIds"]) or not all(
            _canonical_nonempty_string(value) for value in fingerprints.values()):
        return False
    resources = scope.get("resources")
    if type(resources) is not list or not resources:
        return False
    addresses = [row.get("address") for row in resources if type(row) is dict]
    if (len(addresses) != len(resources)
            or any(not _canonical_nonempty_string(address) for address in addresses)
            or addresses != sorted(set(addresses))):
        return False
    shared = {"digitalocean_ssh_key.key": "ssh_key", "digitalocean_firewall.firewall": "firewall",
              "local_file.ansible_inventory[0]": "local_file",
              "local_file.ssh_stanza[0]": "local_file"}
    if not set(shared).issubset(addresses) or len(addresses) <= len(shared):
        return False
    return all(_canonical_nonempty_string(row.get("address"))
               and _canonical_nonempty_string(row.get("id"))
               and row.get("kind") == shared.get(row["address"], "droplet")
               and (row["address"].startswith("digitalocean_droplet.")
                    or row["address"] in shared)
               for row in resources)


def _valid_keyed_domain_assignments(value: Any) -> bool:
    if type(value) is not list:
        return False
    seen_ids: set[int] = set()
    seen_assets: set[str] = set()
    seen_names: set[str] = set()
    for row in value:
        if (type(row) is not dict or set(row) != {"domainId", "assignmentId", "domainName", "registrar"}
                or type(row["assignmentId"]) is not int or row["assignmentId"] <= 0
                or not _canonical_nonempty_string(row["domainId"])
                or not _canonical_nonempty_string(row["domainName"])
                or row["domainName"] != row["domainName"].lower().strip(".")
                or row["registrar"] != "namecheap"
                or row["assignmentId"] in seen_ids or row["domainId"] in seen_assets
                or row["domainName"] in seen_names):
            return False
        seen_ids.add(row["assignmentId"])
        seen_assets.add(row["domainId"])
        seen_names.add(row["domainName"])
    return value == sorted(value, key=lambda row: (row["domainName"], row["domainId"], row["assignmentId"]))


def _valid_keyed_dns_cleanup_manifest(scope: dict[str, Any]) -> bool:
    """Check saved shape and digests; destructive children rebind live authority."""
    from app.services.provider_keyed_initial_continuation import _job_ids

    def digest(value: dict) -> str:
        return "sha256:" + _fingerprint(value)

    def sha(value: Any, *, prefixed: bool = False) -> bool:
        if type(value) is not str:
            return False
        return re.fullmatch(r"sha256:[0-9a-f]{64}" if prefixed else r"[0-9a-f]{64}", value) is not None

    try:
        manifest = scope.get("dnsCleanupManifest")
        assignments = scope["domainAssignments"]
        if type(manifest) is dict and manifest.get("schema") in {
                "provider-keyed-empty-dns-prebinding-v1", "provider-keyed-empty-dns-append-v1"}:
            provider_scopes = scope.get("providerScopes")
            expected_keys = {
                "schema", "engagementId", "coreJobId", "corePlanId",
                "providerScopeSha256", "stateSha256", "initialJobId",
                "initialJournalSha256", "domainAssignments", "domains",
                "manifestSha256",
            }
            appended = manifest["schema"] == "provider-keyed-empty-dns-append-v1"
            if appended:
                expected_keys |= {"appendJobId", "appendJournalSha256"}
            return (
                set(manifest) == expected_keys
                and assignments == [] and manifest["domainAssignments"] == []
                and manifest["domains"] == []
                and type(provider_scopes) is list and len(provider_scopes) == 1
                and manifest["engagementId"] == scope["engagementId"]
                and manifest["coreJobId"] == scope["coreJobId"]
                and manifest["corePlanId"] == provider_scopes[0].get("corePlanId")
                and manifest["providerScopeSha256"] == scope["providerScopeSha256"]
                and manifest["stateSha256"] == provider_scopes[0].get("stateSha256")
                and manifest["initialJobId"] == _job_ids(scope["coreJobId"])[0]
                and sha(manifest["stateSha256"])
                and sha(manifest["initialJournalSha256"])
                and (not appended or (
                    isinstance(manifest["appendJobId"], str)
                    and bool(manifest["appendJobId"])
                    and sha(manifest["appendJournalSha256"])))
                and manifest["manifestSha256"] == digest({
                    key: value for key, value in manifest.items() if key != "manifestSha256"})
            )
        if (type(manifest) is not dict or set(manifest) != {
                "schema", "engagementId", "coreJobId", "providerScopeSha256",
                "bindingSha256", "initialJobId", "initialJournalSha256",
                "domainAssignments", "domains", "manifestSha256"}
                or manifest["schema"] != "provider-keyed-dns-cleanup-manifest-v1"
                or manifest["engagementId"] != scope["engagementId"]
                or manifest["coreJobId"] != scope["coreJobId"]
                or manifest["providerScopeSha256"] != scope["providerScopeSha256"]
                or manifest["initialJobId"] != _job_ids(scope["coreJobId"])[0]
                or not sha(manifest["bindingSha256"])
                or not sha(manifest["initialJournalSha256"])
                or manifest["domainAssignments"] != assignments
                or type(manifest["domains"]) is not list
                or len(manifest["domains"]) != len(assignments)
                or manifest["manifestSha256"] != digest({key: value for key, value in manifest.items()
                                                         if key != "manifestSha256"})):
            return False
        for assignment, entry in zip(assignments, manifest["domains"]):
            if (type(entry) is not dict or set(entry) != {
                    "domainId", "domainName", "assignmentId", "oldEdgeIps",
                    "bindingSha256", "zoneFingerprint", "cleanupPlanSha256",
                    "ownedReceiptIds", "ownedRecordCount", "ownedRecordsSha256",
                    "maxOwnedTtl", "preservedRecordCount", "preservedRecordsSha256",
                    "blockers", "entrySha256"}
                    or any(entry[key] != assignment[value] for key, value in (
                        ("domainId", "domainId"), ("domainName", "domainName"),
                        ("assignmentId", "assignmentId")))
                    or entry["bindingSha256"] != manifest["bindingSha256"]
                    or entry["blockers"] != []
                    or not sha(entry["zoneFingerprint"], prefixed=True)
                    or not sha(entry["cleanupPlanSha256"], prefixed=True)
                    or not sha(entry["ownedRecordsSha256"], prefixed=True)
                    or not sha(entry["preservedRecordsSha256"], prefixed=True)
                    or entry["entrySha256"] != digest({key: value for key, value in entry.items()
                                                       if key != "entrySha256"})):
                return False
            ips = entry["oldEdgeIps"]
            if type(ips) is not list or not ips or len(set(ips)) != len(ips):
                return False
            for ip in ips:
                parsed = ipaddress.ip_address(ip)
                if not isinstance(parsed, ipaddress.IPv4Address) or not parsed.is_global or str(parsed) != ip:
                    return False
            if ips != sorted(ips, key=lambda value: int(ipaddress.IPv4Address(value))):
                return False
            ids = entry["ownedReceiptIds"]
            if (type(ids) is not list or any(type(value) is not int or value <= 0 for value in ids)
                    or ids != sorted(set(ids))
                    or type(entry["ownedRecordCount"]) is not int
                    or entry["ownedRecordCount"] != len(ids)
                    or type(entry["preservedRecordCount"]) is not int
                    or entry["preservedRecordCount"] < 0
                    or type(entry["maxOwnedTtl"]) is not int
                    or (entry["maxOwnedTtl"] <= 0 if ids else entry["maxOwnedTtl"] != 0)):
                return False
        return True
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def _active_keyed_domain_assignments(engagement_id: str, repository: DomainRepository | None) -> list[dict[str, Any]]:
    repo = repository or SqlAlchemyDomainRepository()
    rows: list[dict[str, Any]] = []
    try:
        assignments = repo.list_assignments(engagement_id=engagement_id)
        for assignment in assignments:
            if assignment.status != "active":
                continue
            asset = repo.get_asset(assignment.domain_id)
            if (type(assignment.id) is not int or assignment.id <= 0
                    or assignment.engagement_id != engagement_id or asset is None
                    or asset.id != assignment.domain_id or asset.registrar != "namecheap"):
                raise ValueError("active DNS assignment identity differs")
            active_for_domain = [row for row in repo.list_assignments(domain_id=assignment.domain_id)
                                 if row.status == "active"]
            if len(active_for_domain) != 1 or active_for_domain[0] != assignment:
                raise ValueError("active DNS assignment is ambiguous")
            rows.append({"domainId": asset.id, "assignmentId": assignment.id,
                         "domainName": asset.domain_name, "registrar": asset.registrar})
        rows.sort(key=lambda row: (row["domainName"], row["domainId"], row["assignmentId"]))
        if not _valid_keyed_domain_assignments(rows):
            raise ValueError("active DNS assignment set is ambiguous")
        return rows
    except Exception:
        raise EngagementTeardownValidationError(
            ["active keyed DNS assignments are unavailable or ambiguous; teardown preview is blocked"]
        ) from None


def _valid_snapshot_chains(chains: list[Any]) -> bool:
    chain_ids: list[str] = []
    for chain in chains:
        if type(chain) is not dict:
            return False
        chain_id = chain.get("chainId")
        if not _canonical_nonempty_string(chain_id):
            return False
        chain_ids.append(chain_id)
        if not _canonical_nonempty_string(chain.get("assignedProxy")) or type(chain.get("status")) is not str:
            return False
        deploy_job_id = chain.get("deployJobId")
        if type(deploy_job_id) is not str or (deploy_job_id != "" and not _canonical_nonempty_string(deploy_job_id)):
            return False
        if type(chain.get("alreadyClean")) is not bool or not _unique_nonempty_strings(chain.get("outboundChannelIds")):
            return False
        middle = chain.get("middle")
        edges = chain.get("edges")
        if type(middle) is not dict or not all(_canonical_nonempty_string(middle.get(key)) for key in ("provider", "region")):
            return False
        if type(edges) is not list or not edges:
            return False
        edge_ids: list[str] = []
        for edge in edges:
            if type(edge) is not dict or not all(_canonical_nonempty_string(edge.get(key)) for key in ("id", "provider", "region")):
                return False
            edge_ids.append(edge["id"])
        if len(edge_ids) != len(set(edge_ids)):
            return False
    return len(chain_ids) == len(set(chain_ids))


def _valid_scope_public_targets(scope: dict) -> bool:
    """Validate syntax after rebuilding exact sealed targets; retain raw bytes."""
    if type(scope) is not dict or type(scope.get("publicVerificationTargets")) is not list:
        return False
    targets = scope["publicVerificationTargets"]
    try:
        from app.services.provider_keyed_published_initial_cleanup_authority import KEY, cleanup_public_targets
        if KEY in scope:
            verified = cleanup_public_targets(scope)
            # Syntax-only adapter after exact sealed projection equality. The
            # proposal and saved targets retain their original group/bytes.
            targets = [{key: value for key, value in row.items()
                        if not (key == "targetGroup" and value == "former-public-listener")}
                       for row in verified]
    except (ValueError, TypeError, KeyError, AttributeError, IndexError):
        return False
    return _valid_public_targets(targets)


def _valid_public_targets(targets: list[Any]) -> bool:
    identities: set[tuple[Any, ...]] = set()
    ids: set[str] = set()
    for target in targets:
        if type(target) is not dict:
            return False
        target_id, target_type, host = target.get("id"), target.get("type"), target.get("host")
        if not all(type(value) is str and value and value == value.strip() for value in (target_id, target_type, host)) or target_id in ids:
            return False
        if _normalized_public_host(host) != host:
            return False
        ids.add(target_id)
        optional = set(target) - {"id", "type", "host", "port"}
        if not optional.issubset({"expectedIp", "targetGroup", "service", "purpose"}):
            return False
        if any(type(target[key]) is not str or not target[key] or target[key] != target[key].strip() for key in optional):
            return False
        if "targetGroup" in target and target["targetGroup"] not in {"core-public-management", "sketch-public-management"}:
            return False
        if target_type == "tcp-forbidden":
            port = target.get("port")
            if type(port) is not int or not 1 <= port <= 65535:
                return False
            identity = (target_type, host, port)
        elif target_type == "dns-absent":
            if "port" in target or not set(target).issubset({"id", "type", "host", "expectedIp", "service", "purpose"}):
                return False
            identity = (target_type, host, target.get("expectedIp", ""))
        else:
            return False
        if identity in identities:
            return False
        identities.add(identity)
    canonical = canonical_teardown_targets(targets)
    return len(canonical) == len(targets) and len({json.dumps(row, sort_keys=True) for row in canonical}) == len(targets)


def _validated_parent_boundary(parent: StoredJobRun, jobs: JobRepository) -> tuple[StoredJobRun, dict[str, Any]]:
    fields = _parent_boundary_fields(parent)
    if fields is None:
        raise EngagementTeardownValidationError(["comprehensive teardown recovery boundary is invalid"])
    engagement_id, core_job_id, scope = fields
    core = jobs.get(core_job_id)
    if core is None or core.action != PILOT_CORE_ACTION or core.input.get("engagementId") != engagement_id:
        raise EngagementTeardownValidationError(["comprehensive teardown recovery core boundary is invalid"])
    if _is_provider_keyed_v2(core) != ("providerScopes" in scope):
        raise EngagementTeardownValidationError(["comprehensive teardown provider scope boundary is invalid"])
    return core, scope


def _claim_and_launch(
    parent: StoredJobRun,
    *,
    jobs: JobRepository,
    chains: SketchChainRepository,
    resources: ProviderResourceRepository,
    chain_dispatcher: ChainDispatcher | None,
    outbound_dispatcher: OutboundDispatcher | None,
    inspector_preflight: InspectorPreflight | None,
    inspector_state_reader: InspectorStateReader | None,
    core_dispatcher: CoreDispatcher | None,
    background_runner: BackgroundRunner | None,
    wait: Waiter | None,
    explicit_retry: bool,
    confirmed_snapshot: dict[str, Any] | None = None,
) -> StoredJobRun | None:
    current_parent = jobs.get(parent.id)
    if (
        current_parent is not None
        and current_parent.status in {"queued", "running"}
        and _persisted_claim_is_live(current_parent)
    ):
        return current_parent
    claim_token = uuid4().hex
    core_leases, lease_prefix = _core_mutation_leases(jobs)
    lease_engagement_id = f"{lease_prefix}{parent.target_id}"
    prior_token = str((current_parent or parent).input.get("claimToken") or "")
    if prior_token and (explicit_retry or not _persisted_claim_is_live(current_parent or parent)):
        # A teardown's mutation lease uses the same opaque owner token as its
        # job lease. Once the persisted job claim has expired it is safe to
        # clear only that exact stale owner before atomically reclaiming.
        core_leases.release(lease_engagement_id, prior_token)
    try:
        core_leases.acquire(lease_engagement_id, claim_token, "teardown")
    except DeploymentPlanConflictError as exc:
        current = jobs.get(parent.id)
        if current is not None and current.status in {"queued", "running"} and _persisted_claim_is_live(current):
            return current
        raise EngagementTeardownValidationError(
            ["a core plan, apply, or teardown mutation is running; wait for it to finish"]
        ) from exc
    claimed_at = _now()
    expires_at = (datetime.fromisoformat(claimed_at) + timedelta(seconds=LEASE_SECONDS)).isoformat()
    eligible = {"queued", "running"} | ({"failed"} if explicit_retry else set())
    try:
        claimed = jobs.claim_lease(
            parent.id,
            owner=_owner,
            token=claim_token,
            claimed_at=claimed_at,
            expires_at=expires_at,
            eligible_statuses=eligible,
        )
    except Exception:
        core_leases.release(lease_engagement_id, claim_token)
        raise
    if claimed is None:
        core_leases.release(lease_engagement_id, claim_token)
        return jobs.get(parent.id)
    try:
        claimed_input = {
            **claimed.input,
            **({"scopeSnapshot": confirmed_snapshot} if confirmed_snapshot is not None else {}),
        }
        if explicit_retry:
            claimed = jobs.save_if_leased(
                replace(
                    claimed,
                    status="queued",
                    finished_at=None,
                    input={**claimed_input, "phase": "inspector_preflight"},
                    events=claimed.events
                    + [
                        JobEvent(
                            len(claimed.events) + 1,
                            "info",
                            "engagement teardown retry queued",
                            {"phase": "inspector_preflight"},
                        )
                    ],
                ),
                owner=_owner,
                token=claim_token,
            )
        elif confirmed_snapshot is not None:
            claimed = jobs.save_if_leased(
                replace(claimed, input=claimed_input),
                owner=_owner,
                token=claim_token,
            )
        if claimed is None:
            core_leases.release(lease_engagement_id, claim_token)
            return jobs.get(parent.id)
    except Exception:
        core_leases.release(lease_engagement_id, claim_token)
        raise
    def task() -> None:
        try:
            _run_parent(
                parent.id,
                owner=_owner,
                token=claim_token,
                jobs=jobs,
                chains=chains,
                resources=resources,
                chain_dispatcher=chain_dispatcher,
                outbound_dispatcher=outbound_dispatcher,
                inspector_preflight=inspector_preflight,
                inspector_state_reader=inspector_state_reader,
                core_dispatcher=core_dispatcher,
                wait=wait or _sleep,
            )
        finally:
            core_leases.release(lease_engagement_id, claim_token)
    if background_runner is not None:
        background_runner(task)
    else:
        start_runtime_task(task, name=f"barragan-engagement-teardown-{parent.target_id}", synchronous_when_testing=True)
    return jobs.get(parent.id)


def _run_parent(
    parent_id: str,
    *,
    owner: str,
    token: str,
    jobs: JobRepository,
    chains: SketchChainRepository,
    resources: ProviderResourceRepository,
    chain_dispatcher: ChainDispatcher | None,
    outbound_dispatcher: OutboundDispatcher | None,
    inspector_preflight: InspectorPreflight | None,
    inspector_state_reader: InspectorStateReader | None,
    core_dispatcher: CoreDispatcher | None,
    wait: Waiter,
) -> None:
    parent = jobs.get(parent_id)
    if parent is None or not _lease_owned(parent, owner, token):
        return
    outcomes = dict(parent.input.get("outcomes") or {})
    core_id = str(parent.input.get("coreJobId") or "")
    core = jobs.get(core_id)
    if core is None:
        return _fail(jobs, parent, outcomes, [f"core_job:{core_id}"], "core deployment job is missing")
    if _is_provider_keyed_v2(core) or parent.input.get("scopeSnapshot", {}).get("providerScopes"):
        return _fail(jobs, parent, outcomes, ["provider_keyed_v2"],
                     "keyed provider teardown execution is not available")
    confirmed_snapshot = dict(parent.input.get("scopeSnapshot") or {})
    current_snapshot = _current_scope_snapshot(
        core,
        jobs=jobs,
        chains=chains,
        resources=resources,
        inspector_state_reader=inspector_state_reader,
    )
    unexpected = _unconfirmed_destructive_targets(
        confirmed_snapshot,
        current_snapshot,
        teardown_job_id=parent.id,
    )
    unexpected.extend(_active_inspection_targets(jobs, parent.target_id))
    if unexpected:
        return _fail(
            jobs,
            parent,
            outcomes,
            unexpected,
            "current infrastructure exceeds the confirmed teardown boundary; review and confirm a new scope",
        )
    snapshot = _refresh_confirmed_scope_snapshot(confirmed_snapshot, current_snapshot)
    parent = _save_parent(
        jobs,
        parent,
        status="running",
        phase="inspector_preflight",
        outcomes=outcomes,
        message="Inspector teardown preflight started",
        level="info",
        extra_input={"scopeSnapshot": snapshot},
    )
    snapshot_targets = list(snapshot.get("publicVerificationTargets") or [])
    if snapshot_targets and not _core_verified(core, snapshot_targets):
        try:
            preflight = _run_with_lease_heartbeat(
                lambda: (inspector_preflight or _default_inspector_preflight)(
                    parent.target_id,
                    str(snapshot.get("engagementName") or parent.target_id),
                    parent.id,
                    snapshot_targets,
                ),
                jobs=jobs,
                parent_id=parent.id,
                owner=owner,
                token=token,
            )
        except EngagementTeardownLeaseLost:
            return
        except Exception as exc:
            collision = getattr(exc, "failure_class", "") == "retired_target_address_reuse"
            outcomes["inspectorPreflight"] = {
                "state": "failed",
                "failureClass": "retired_target_address_reuse" if collision else "preflight_failed",
                "targetIds": list(getattr(exc, "target_ids", [])) if collision else [],
                "nextAction": str(getattr(exc, "next_action", "")) if collision else "Review preflight failure and retry",
            }
            parent = jobs.get(parent.id) or parent
            return _fail(
                jobs,
                parent,
                outcomes,
                _remaining_resources(parent, jobs=jobs, chains=chains, resources=resources),
                f"Inspector teardown preflight failed: {_safe_error(exc)}",
            )
        if preflight.get("ok") is not True:
            outcomes["inspectorPreflight"] = {"state": "failed", "status": str(preflight.get("status") or "failed")}
            return _fail(
                jobs,
                parent,
                outcomes,
                _remaining_resources(parent, jobs=jobs, chains=chains, resources=resources),
                f"Inspector teardown preflight failed: {_preflight_error(preflight)}",
            )
        post_preflight_current = _current_scope_snapshot(
            core,
            jobs=jobs,
            chains=chains,
            resources=resources,
            inspector_state_reader=inspector_state_reader,
        )
        unexpected = _unconfirmed_destructive_targets(
            confirmed_snapshot,
            post_preflight_current,
            teardown_job_id=parent.id,
        )
        unexpected.extend(_active_inspection_targets(jobs, parent.target_id))
        if unexpected:
            return _fail(
                jobs,
                jobs.get(parent.id) or parent,
                outcomes,
                sorted(set(unexpected)),
                "Inspector preflight found infrastructure outside the confirmed teardown boundary",
            )
        refreshed = _refresh_confirmed_scope_snapshot(
            snapshot,
            post_preflight_current,
        )
        refreshed["inspector"] = {
            **dict(refreshed.get("inspector") or {}),
            "tracked": bool(preflight.get("inspectorHost")),
            "prepared": True,
            "status": str(preflight.get("status") or "ready"),
        }
        outcomes["inspectorPreflight"] = {
            "state": "ready",
            "status": str(preflight.get("status") or "ready"),
            "created": preflight.get("created") is True,
        }
        parent = _save_parent(
            jobs,
            parent,
            status="running",
            phase="inspector_preflight",
            outcomes=outcomes,
            message="Inspector teardown preflight completed",
            level="info",
            extra_input={"scopeSnapshot": refreshed},
            event_data={"inspectorPreflight": outcomes["inspectorPreflight"]},
        )

    parent = _save_parent(jobs, parent, status="running", phase="outbound_and_sketch_cleanup", outcomes=outcomes,
                          message="engagement sketch cleanup started", level="info")
    dispatch_chain = chain_dispatcher or (
        lambda engagement_id, chain_id, body: _default_chain_dispatcher(
            engagement_id,
            chain_id,
            body,
            core_mutation_lease_owner=token,
        )
    )
    dispatch_outbound = outbound_dispatcher or _default_outbound_dispatcher

    # Preserve the management path for the entire outbound phase. No provider
    # destroy is allowed until every snapshotted chain's outbound state is clean.
    for item in list(dict(parent.input.get("scopeSnapshot") or {}).get("chains") or []):
        chain_id = str(item.get("chainId") or "")
        current = chains.get(parent.target_id, chain_id)
        if current is None:
            return _fail(jobs, parent, outcomes, [f"sketch_chain:{chain_id}"], "snapshotted sketch chain is missing")
        if current.status in {"destroyed", "aborted"} or (current.status == "pending" and not current.deploy_job_id and not current.nodes):
            continue
        try:
            _run_with_lease_heartbeat(
                lambda: dispatch_outbound(parent.target_id, chain_id, parent.requested_by),
                jobs=jobs,
                parent_id=parent.id,
                owner=owner,
                token=token,
            )
        except EngagementTeardownLeaseLost:
            return
        except Exception as exc:
            return _fail(jobs, parent, outcomes, [f"outbound_configuration:{chain_id}"], _safe_error(exc))
        parent = _progress(jobs, parent, outcomes, "outbound configuration cleanup verified", {"chainId": chain_id})

    for item in list(dict(parent.input.get("scopeSnapshot") or {}).get("chains") or []):
        chain_id = str(item.get("chainId") or "")
        renewed = _renew(jobs, parent.id, owner, token)
        if renewed is None:
            return
        parent = renewed
        current = chains.get(parent.target_id, chain_id)
        if current is None:
            return _fail(jobs, parent, outcomes, [f"sketch_chain:{chain_id}"], "snapshotted sketch chain is missing")
        if current.status in {"destroyed", "aborted"}:
            outcomes[chain_id] = {"state": "verified_clean", "chainStatus": current.status, "attempts": int(dict(outcomes.get(chain_id) or {}).get("attempts") or 0)}
            parent = _progress(jobs, parent, outcomes, "sketch chain already clean", {"chainId": chain_id})
            continue
        prior = dict(outcomes.get(chain_id) or {})
        try:
            response = _run_with_lease_heartbeat(
                lambda: dispatch_chain(
                    parent.target_id,
                    chain_id,
                    {"confirmation": f"teardown-{chain_id}", "requestedBy": parent.requested_by, "outboundAlreadyRemoved": True},
                ),
                jobs=jobs,
                parent_id=parent.id,
                owner=owner,
                token=token,
            )
        except EngagementTeardownLeaseLost:
            return
        except Exception as exc:
            return _fail(jobs, parent, outcomes, [f"sketch_chain:{chain_id}"], _safe_error(exc))
        child = (response or {}).get("job") or {}
        child_id = str(child.get("id") if isinstance(child, dict) else "")
        outcomes[chain_id] = {"state": "running", "jobId": child_id, "attempts": int(prior.get("attempts") or 0) + 1}
        parent = _progress(jobs, parent, outcomes, "sketch chain teardown dispatched", {"chainId": chain_id, "childJobId": child_id})
        response_chain = (response or {}).get("chain") or {}
        if isinstance(response_chain, dict) and response_chain.get("status") in {"destroyed", "aborted"}:
            outcomes[chain_id] = {**outcomes[chain_id], "state": "verified_clean", "chainStatus": response_chain["status"]}
            parent = _progress(jobs, parent, outcomes, "sketch chain cleanup verified", {"chainId": chain_id, "childJobId": child_id})
            continue
        result = _wait_for_chain(parent, chain_id, jobs=jobs, chains=chains, owner=owner, token=token, wait=wait)
        if result is None:
            return
        parent, chain_state, child_status = result
        if chain_state != "destroyed":
            outcomes[chain_id] = {**outcomes[chain_id], "state": "failed", "chainStatus": chain_state, "childStatus": child_status}
            return _fail(jobs, parent, outcomes, [f"sketch_chain:{chain_id}"], "sketch teardown did not verify cleanup")
        outcomes[chain_id] = {**outcomes[chain_id], "state": "verified_clean", "chainStatus": chain_state, "childStatus": child_status}
        parent = _progress(jobs, parent, outcomes, "sketch chain cleanup verified", {"chainId": chain_id, "childJobId": child_id})

    parent = _save_parent(jobs, parent, status="running", phase="core_and_inspector_cleanup", outcomes=outcomes,
                          message="core and Inspector cleanup started", level="info")
    snapshot_targets = list(dict(parent.input.get("scopeSnapshot") or {}).get("publicVerificationTargets") or [])
    if not _core_verified(core, snapshot_targets):
        try:
            prior_core = dict(outcomes.get("core") or {})
            if not (prior_core.get("state") == "running" and core.status in {"queued", "running"}):
                outcomes["core"] = {"state": "running", "jobId": core_id, "attempts": int(prior_core.get("attempts") or 0) + 1}
                parent = _progress(jobs, parent, outcomes, "core cleanup dispatched", {"coreJobId": core_id})
                _run_with_lease_heartbeat(
                    lambda: (core_dispatcher or _default_core_dispatcher)(core_id, snapshot_targets),
                    jobs=jobs,
                    parent_id=parent.id,
                    owner=owner,
                    token=token,
                )
        except EngagementTeardownLeaseLost:
            return
        except Exception as exc:
            return _fail(jobs, parent, outcomes, [f"core_job:{core_id}"], _safe_error(exc))
        result = _wait_for_core(parent, core_id, jobs=jobs, owner=owner, token=token, wait=wait)
        if result is None:
            return
        parent, core = result
    if not _core_verified(core, snapshot_targets):
        return _fail(jobs, parent, outcomes, [f"core_job:{core_id}"], "core or Inspector cleanup was not verified")

    remaining = _remaining_resources(parent, jobs=jobs, chains=chains, resources=resources)
    if remaining:
        return _fail(jobs, parent, outcomes, remaining, "engagement cleanup verification found remaining owned resources")

    parent = _progress(jobs, parent, outcomes, "Inspector teardown verification completed", {"inspectorTeardownVerification": _latest(core, "inspectorTeardownVerification")})
    parent = _progress(jobs, parent, outcomes, "Inspector cleanup completed", {"inspectorCleanup": _latest(core, "inspectorCleanup")})
    parent = _save_parent(
        jobs,
        parent,
        status="running",
        phase="lifecycle_reconciliation",
        outcomes=outcomes,
        message="engagement resource cleanup gates passed",
        level="info",
        extra_input={"remainingOwnedResources": [], "claimExpiresAt": _now()},
        event_data={
            "finalCleanupStatus": "verified_clean",
            "coreJobId": core_id,
            "inspectorTeardownVerification": _latest(core, "inspectorTeardownVerification"),
            "inspectorCleanup": _latest(core, "inspectorCleanup"),
        },
        finished=False,
    )
    try:
        lifecycle = reconcile_engagement_lifecycle(parent.target_id, job_repository=jobs, sketch_chain_repository=chains, provider_resource_repository=resources, reason="comprehensive_teardown_finished")
    except Exception as exc:
        return _fail(jobs, parent, outcomes, ["engagement_lifecycle"], _safe_error(exc))
    if lifecycle["current"]["state"] != "destroyed":
        return _fail(jobs, parent, outcomes, ["engagement_lifecycle"], f"lifecycle reconciled to {lifecycle['current']['state']}")
    latest_parent = jobs.get(parent.id) or parent
    jobs.save(
        replace(
            latest_parent,
            status="succeeded",
            finished_at=_now(),
            input={**latest_parent.input, "claimExpiresAt": _now()},
            events=latest_parent.events
            + [
                JobEvent(
                    len(latest_parent.events) + 1,
                    "info",
                    "engagement lifecycle reconciled",
                    {"state": "destroyed", "finalCleanupStatus": "verified_clean"},
                )
            ],
        )
    )


def _wait_for_chain(parent: StoredJobRun, chain_id: str, *, jobs: JobRepository, chains: SketchChainRepository,
                    owner: str, token: str, wait: Waiter) -> tuple[StoredJobRun, str, str] | None:
    from app.services.sketch_chains import refresh_sketch_chain_from_job

    while True:
        renewed = _renew(jobs, parent.id, owner, token)
        if renewed is None:
            return None
        parent = renewed
        refresh_sketch_chain_from_job(parent.target_id, chain_id, repository=chains)
        chain = chains.get(parent.target_id, chain_id)
        if chain is None:
            return parent, "missing", "missing"
        child = jobs.get(chain.teardown_job_id) if chain.teardown_job_id else None
        child_status = child.status if child else "none"
        if chain.status in {"destroyed", "aborted", "failed"} or child_status in {"succeeded", "failed"}:
            refresh_sketch_chain_from_job(parent.target_id, chain_id, repository=chains)
            latest = chains.get(parent.target_id, chain_id) or chain
            return parent, latest.status, child_status
        wait(POLL_SECONDS)


def _wait_for_core(parent: StoredJobRun, core_id: str, *, jobs: JobRepository, owner: str, token: str,
                   wait: Waiter) -> tuple[StoredJobRun, StoredJobRun] | None:
    while True:
        renewed = _renew(jobs, parent.id, owner, token)
        if renewed is None:
            return None
        parent = renewed
        core = jobs.get(core_id)
        if core is None:
            return None
        if core.status not in {"queued", "running"}:
            return parent, core
        wait(POLL_SECONDS)


def _scope_snapshot(core: StoredJobRun, *, jobs: JobRepository, chains: SketchChainRepository,
                    resources: ProviderResourceRepository,
                    domain_repository: DomainRepository | None = None,
                    allowed_teardown_parent_id: str | None = None,
                    reviewed_dns_manifest: dict[str, Any] | None = None,
                    state_root=None) -> dict[str, Any]:
    engagement_id = str(core.input.get("engagementId") or core.target_id or "")
    engagement_name = str(core.input.get("engagementName") or engagement_id)
    chain_rows = []
    for chain in chains.list_for_engagement(engagement_id):
        if chain.status in {"destroyed", "aborted"}:
            continue
        edges = chain.edge_intents or [{"id": f"edge-{index + 1:02d}", "provider": chain.edge_provider, "region": chain.edge_region} for index in range(chain.edge_count)]
        chain_rows.append({
            "chainId": chain.chain_id,
            "assignedProxy": chain.assigned_proxy,
            "status": chain.status,
            "deployJobId": chain.deploy_job_id,
            "middle": {"provider": chain.middle_provider, "region": chain.middle_region},
            "edges": [{"id": str(edge.get("id") or "edge"), "provider": str(edge.get("provider") or chain.edge_provider), "region": str(edge.get("region") or chain.edge_region)} for edge in edges],
            "outboundChannelIds": _outbound_channel_ids(jobs, engagement_id, chain.chain_id),
            "alreadyClean": chain.status == "pending" and not chain.deploy_job_id and not chain.nodes,
        })
    all_active_records = [record for record in resources.list_for_engagement(engagement_id) if record.status.lower() not in TERMINAL_RECORD_STATUSES]
    active_records = [record for record in all_active_records if is_barragan_owned_record(record)]
    unmanaged_records = [record for record in all_active_records if not is_barragan_owned_record(record)]
    snapshot: dict[str, Any] = {
        "engagementId": engagement_id,
        "engagementName": engagement_name,
        "coreJobId": core.id,
        "confirmationPhrase": _confirmation_phrase(engagement_name),
        "chains": chain_rows,
        "ownedProviderRecordIds": sorted(record.id for record in active_records),
        "excludedUnmanagedProviderRecords": sorted(record.id for record in unmanaged_records),
        "core": {"jobId": core.id, "workspace": str(core.input.get("workspaceDir") or ""), "proxyCount": int(core.input.get("proxyCount") or 0)},
        "publicVerificationTargets": _known_public_targets_for_engagement(jobs, engagement_id),
        "inspector": {
            "tracked": _inspector_tracked(core, active_records),
            "ownedProviderRecordIds": _inspector_record_ids(active_records),
            "recordOwners": _inspector_record_owners(active_records),
            "verificationTargetCount": 0,
        },
    }
    snapshot["inspector"]["verificationTargetCount"] = len(snapshot["publicVerificationTargets"])
    if _is_provider_keyed_v2(core):
        from app.services.provider_keyed_dns_cleanup_manifest import (
            ProviderKeyedDnsCleanupManifestError, build_provider_keyed_dns_cleanup_manifest,
        )
        from app.services.provider_keyed_teardown_scope import (
            ProviderKeyedTeardownScopeError, build_digitalocean_keyed_teardown_scope,
        )
        try:
            snapshot["domainAssignments"] = _active_keyed_domain_assignments(
                engagement_id, domain_repository,
            )
            snapshot["providerScopes"] = [build_digitalocean_keyed_teardown_scope(
                engagement_id, core.id, sketch_repository=chains, job_repository=jobs,
                allowed_teardown_parent_id=allowed_teardown_parent_id,
                **({"state_root": state_root} if state_root is not None else {}),
            )]
        except ProviderKeyedTeardownScopeError:
            raise EngagementTeardownValidationError(
                ["complete applied keyed provider scope is unavailable; teardown preview is blocked"]
            ) from None
        snapshot["providerScopeSha256"] = _fingerprint({"providerScopes": snapshot["providerScopes"]})
        if reviewed_dns_manifest is None:
            try:
                snapshot["dnsCleanupManifest"] = build_provider_keyed_dns_cleanup_manifest(
                    snapshot, job_repository=jobs, domain_repository=domain_repository,
                )
            except ProviderKeyedDnsCleanupManifestError:
                raise EngagementTeardownValidationError(
                    ["complete owned DNS cleanup manifest is unavailable; teardown preview is blocked"]
                ) from None
        else:
            # A repository holding SQLite's writer slot may recheck the DB
            # projection, but must not call Namecheap while holding that lock.
            # The reviewed manifest remains evidence for the later fresh GO.
            snapshot["dnsCleanupManifest"] = reviewed_dns_manifest
            if not _valid_keyed_dns_cleanup_manifest(snapshot):
                raise EngagementTeardownValidationError(
                    ["reviewed keyed DNS cleanup manifest changed"])
        for row in snapshot["chains"]:
            row["alreadyClean"] = False
    if _is_provider_keyed_v2(core):
        from app.services.provider_keyed_published_initial_cleanup_authority import (
            KEY, build_cleanup_seal, has_failed_web_history,
        )
        if has_failed_web_history(jobs, engagement_id):
            try:
                seal = build_cleanup_seal(core, snapshot, jobs=jobs, chains=chains)
            except Exception:
                raise EngagementTeardownValidationError(
                    ["published initial failed-channel cleanup scope is unproved; review its owned bindings"]
                ) from None
            snapshot[KEY] = seal
            snapshot["publicVerificationTargets"] = seal["publicTargets"]["targets"]
            snapshot["inspector"]["verificationTargetCount"] = len(snapshot["publicVerificationTargets"])
    snapshot["snapshotId"] = _fingerprint(snapshot)
    return snapshot


def _current_scope_snapshot(
    core: StoredJobRun,
    *,
    jobs: JobRepository,
    chains: SketchChainRepository,
    resources: ProviderResourceRepository,
    domain_repository: DomainRepository | None = None,
    inspector_state_reader: InspectorStateReader | None,
    allowed_teardown_parent_id: str | None = None,
    reviewed_dns_manifest: dict[str, Any] | None = None,
    state_root=None,
) -> dict[str, Any]:
    snapshot = _scope_snapshot(core, jobs=jobs, chains=chains, resources=resources,
                               domain_repository=domain_repository,
                               allowed_teardown_parent_id=allowed_teardown_parent_id,
                               reviewed_dns_manifest=reviewed_dns_manifest,
                               state_root=state_root)
    state: dict[str, Any] = {}
    if inspector_state_reader is not None:
        state = inspector_state_reader(str(snapshot.get("engagementId") or ""))
    elif isinstance(jobs, SqlAlchemyJobRepository):
        state = _default_inspector_state_reader(str(snapshot.get("engagementId") or ""))
    if state:
        current = dict(snapshot.get("inspector") or {})
        snapshot["inspector"] = {
            **current,
            **state,
            "tracked": bool(current.get("tracked") or state.get("tracked")),
            "verificationTargetCount": len(snapshot.get("publicVerificationTargets") or []),
        }
        snapshot_without_id = {key: value for key, value in snapshot.items() if key != "snapshotId"}
        snapshot["snapshotId"] = _fingerprint(snapshot_without_id)
    return snapshot


def _unconfirmed_destructive_targets(
    confirmed: dict[str, Any],
    current: dict[str, Any],
    *,
    teardown_job_id: str,
) -> list[str]:
    confirmed_chains = {
        str(row.get("chainId") or "")
        for row in confirmed.get("chains") or []
        if isinstance(row, dict)
    }
    current_chains = {
        str(row.get("chainId") or "")
        for row in current.get("chains") or []
        if isinstance(row, dict)
    }
    confirmed_resources = {str(record_id) for record_id in confirmed.get("ownedProviderRecordIds") or []}
    current_inspectors = {
        str(record_id)
        for record_id in dict(current.get("inspector") or {}).get("ownedProviderRecordIds") or []
    }
    inspector_record_owners = {
        str(record_id): str(owner_id)
        for record_id, owner_id in dict(current.get("inspector") or {}).get("recordOwners", {}).items()
    }
    allowed_new_inspectors = {
        record_id
        for record_id in current_inspectors
        if inspector_record_owners.get(record_id) == teardown_job_id
    }
    current_resources = {str(record_id) for record_id in current.get("ownedProviderRecordIds") or []}
    return [
        *(["provider_scope_changed"] if (
            confirmed.get("providerScopes") != current.get("providerScopes")
            or confirmed.get("providerScopeSha256") != current.get("providerScopeSha256")) else []),
        *(["domain_assignments_changed"] if (
            "providerScopes" in confirmed and confirmed.get("domainAssignments") != current.get("domainAssignments"))
           else []),
        *(["dns_cleanup_manifest_changed"] if (
            "providerScopes" in confirmed and confirmed.get("dnsCleanupManifest") != current.get("dnsCleanupManifest"))
           else []),
        *[f"unconfirmed_sketch_chain:{chain_id}" for chain_id in sorted(current_chains - confirmed_chains)],
        *[
            f"unconfirmed_owned_provider_resource:{record_id}"
            for record_id in sorted(current_resources - confirmed_resources - allowed_new_inspectors)
        ],
    ]


def _active_inspection_targets(jobs: JobRepository, engagement_id: str) -> list[str]:
    return sorted(
        f"active_inspection_job:{job.id}"
        for job in jobs.list_for_engagement(engagement_id)
        if job.action == "inspector_inspection" and job.status in {"queued", "running"}
    )


def _refresh_confirmed_scope_snapshot(
    confirmed: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    """Refresh mutable state while preserving every confirmed cleanup target."""

    if (confirmed.get("providerScopes") != current.get("providerScopes")
            or confirmed.get("providerScopeSha256") != current.get("providerScopeSha256")):
        raise EngagementTeardownValidationError(["keyed provider scope changed; review the current cleanup scope again"])
    if ("providerScopes" in confirmed and
            confirmed.get("domainAssignments") != current.get("domainAssignments")):
        raise EngagementTeardownValidationError(["keyed DNS assignments changed; review the current cleanup scope again"])
    if ("providerScopes" in confirmed and
            confirmed.get("dnsCleanupManifest") != current.get("dnsCleanupManifest")):
        raise EngagementTeardownValidationError(["keyed DNS cleanup changed; review the current cleanup scope again"])

    refreshed = json.loads(json.dumps(confirmed))
    current_chains = {
        str(row.get("chainId") or ""): row
        for row in current.get("chains") or []
        if isinstance(row, dict)
    }
    for row in refreshed.get("chains") or []:
        chain_id = str(row.get("chainId") or "")
        latest = current_chains.get(chain_id)
        if latest is None:
            continue
        for key in ("status", "deployJobId", "alreadyClean"):
            row[key] = latest.get(key)
    refreshed["inspector"] = {
        **dict(refreshed.get("inspector") or {}),
        **dict(current.get("inspector") or {}),
        "tracked": bool(dict(current.get("inspector") or {}).get("tracked")),
        "verificationTargetCount": len(confirmed.get("publicVerificationTargets") or []),
    }
    refreshed["snapshotId"] = confirmed.get("snapshotId")
    return refreshed


def _preview_projection(snapshot: dict[str, Any], *, parent_job_id: str = "") -> dict[str, Any]:
    provider_scopes = snapshot.get("providerScopes")
    ordered_scope = [
        {"id": "outbound", "label": "Remove outbound configuration", "items": [{"chainId": row["chainId"], "channelIds": row.get("outboundChannelIds", [])} for row in snapshot.get("chains", [])]},
        {"id": "sketch", "label": "Destroy sketch chains", "items": snapshot.get("chains", [])},
        {"id": "core", "label": "Destroy core infrastructure", "items": [snapshot.get("core", {})]},
        {"id": "inspector-verify", "label": "Verify retired public endpoints", "items": [{"targetCount": snapshot.get("inspector", {}).get("verificationTargetCount", 0)}]},
        {"id": "inspector-cleanup", "label": "Destroy retained Inspector", "items": [_reviewable_inspector(snapshot)]},
    ]
    if provider_scopes is not None:
        ordered_scope[1] = {"id": "sketch", "label": "Shared provider chain membership (review only)",
                            "items": snapshot.get("chains", [])}
        ordered_scope.insert(2, {"id": "provider-keyed", "label": "Keyed provider resources (review only)",
                                 "items": provider_scopes})
        manifest = snapshot.get("dnsCleanupManifest", {})
        domains = manifest.get("domains", [])
        items = [{"domainId": row["domainId"], "domainName": row["domainName"],
                  "assignmentId": row["assignmentId"],
                  "ownedRecordCount": row["ownedRecordCount"],
                  "preservedRecordCount": row["preservedRecordCount"],
                  "maxOwnedTtl": row["maxOwnedTtl"], "blockers": row["blockers"]}
                 for row in domains]
        ordered_scope.insert(3, {"id": "dns-assignments",
                                 "label": "DNS domains for planned Barragan-owned record cleanup (manual records preserved)",
                                 "count": len(domains),
                                 "items": items if items else [{"assignedDomainCount": 0}]})
    return {
        "snapshotId": snapshot.get("snapshotId"),
        "engagementId": snapshot.get("engagementId"),
        "engagementName": snapshot.get("engagementName"),
        "confirmationPhrase": snapshot.get("confirmationPhrase"),
        "parentJobId": parent_job_id or None,
        "orderedScope": ordered_scope,
    }


def preview_published_mixed_initial_scope(review, core_inspector_scope: dict[str, Any],
                                          engagement_name: str) -> dict[str, Any]:
    """Project an authenticated two-provider review without enabling Start.

    The caller must obtain ``review`` from the published mixed authority and
    ``core_inspector_scope`` from the existing exact OCI/Inspector reader. This
    deliberately does not issue a confirmation phrase: the published mixed
    reservation and coordinator are not yet installed.
    """
    from app.services.provider_keyed_mixed_published_teardown_authority import (
        PublishedMixedInitialTeardownReview, PublishedSixTeardownSource,
    )

    if type(review) is not PublishedMixedInitialTeardownReview:
        raise EngagementTeardownValidationError(["published mixed teardown review is unavailable"])
    from dataclasses import asdict
    source = review.source
    scopes = review.provider_scopes
    six = type(source) is PublishedSixTeardownSource
    unapplied = (review.failed_append_recovery is not None
                 and review.failed_append_recovery.get("kind") == "unapplied-append-v1")
    failed_second = review.failed_append_recovery is not None and review.failed_append_recovery.get("kind") == "failed-second-v1"
    if failed_second:
        from app.services.provider_keyed_mixed_failed_second_append import failed_second_scope_resource_count
        try:
            expected_resource_count = failed_second_scope_resource_count(review)
        except (ValueError, KeyError, TypeError):
            raise EngagementTeardownValidationError(["failed second cleanup resource scope changed"]) from None
    else:
        expected_resource_count = 12 if unapplied else 10 if six or review.failed_append_recovery is not None else 12

    if (type(scopes) is not tuple or len(scopes) != 2
            or tuple(scope.get("provider") for scope in scopes) != source.ordered_providers
            or any(scope.get("coreJobId") != source.core_job_id for scope in scopes)
            or any(scope.get("corePlanId") != source.core_plan_id for scope in scopes)
            or (any(scope.get("chainIds") != list(source.chain_ids) for scope in scopes) if six else
                any(scope.get("chainIds") != [chain_id] for scope, chain_id in
                    zip(scopes, source.chain_ids, strict=True)))
            or len({scope.get("workspace") for scope in scopes}) != 2
            or sum(len(scope.get("resources", [])) for scope in scopes) != expected_resource_count
            or (not six and review.live_binding_count != 0)
            or type(core_inspector_scope) is not dict
            or core_inspector_scope.get("jobId") != source.core_job_id
            or core_inspector_scope.get("planId") != source.core_plan_id
            or type(core_inspector_scope.get("ownedInspectorRecordIds")) is not list
            or len(core_inspector_scope["ownedInspectorRecordIds"]) != 2
            or not _canonical_nonempty_string(engagement_name)):
        raise EngagementTeardownValidationError(["published mixed teardown scope changed"])
    snapshot_id = _fingerprint({
        "publication": review.published_parent_journal_sha256,
        "proof": review.published_proof_journal_sha256,
        **({"failedAppendRecovery": review.failed_append_recovery} if review.failed_append_recovery is not None else {}),
        "providers": list(scopes), "coreInspector": core_inspector_scope,
        **({"unpublishedSixRecovery": review.unpublished_six_recovery} if review.unpublished_six_recovery is not None else {}),
        **({"cleanupObservation": review.cleanup_observation} if review.cleanup_observation is not None else {}),
        **({"sixSource": asdict(source), "policies": review.reviewed_policies,
            "bindings": review.binding_manifest,
            "historicalRowsSha256": review.historical_rows_sha256} if six else {}),
    })
    return {
        "snapshotId": snapshot_id,
        "engagementId": source.engagement_id,
        "engagementName": engagement_name,
        "confirmationPhrase": "",
        "parentJobId": None,
        "startAvailable": False,
        "blockers": ["published mixed teardown execution is not yet available"],
        "orderedScope": [
            {"id": "provider-keyed", "label": "Keyed provider resources (review only)",
             "items": list(scopes)},
            {"id": "core", "label": "Core infrastructure", "items": [core_inspector_scope]},
            {"id": "inspector-cleanup", "label": "Destroy retained Inspector",
             "items": [{"ownedProviderRecordIds": core_inspector_scope["ownedInspectorRecordIds"]}]},
        ],
    }


def _reviewable_inspector(snapshot: dict[str, Any]) -> dict[str, Any]:
    inspector = dict(snapshot.get("inspector") or {})
    inspector.pop("recordOwners", None)
    return inspector


def _remaining_resources(parent: StoredJobRun, *, jobs: JobRepository, chains: SketchChainRepository,
                         resources: ProviderResourceRepository) -> list[str]:
    snapshot = dict(parent.input.get("scopeSnapshot") or {})
    snapshotted = {str(row.get("chainId") or "") for row in snapshot.get("chains", [])}
    remaining: list[str] = []
    for chain in chains.list_for_engagement(parent.target_id):
        if chain.status not in {"destroyed", "aborted"}:
            prefix = "unsnapshotted_sketch_chain" if chain.chain_id not in snapshotted else "sketch_chain"
            remaining.append(f"{prefix}:{chain.chain_id}")
    for record in resources.list_for_engagement(parent.target_id):
        if record.status.lower() not in TERMINAL_RECORD_STATUSES and is_barragan_owned_record(record):
            remaining.append(f"owned_provider_resource:{record.id}")
    core = jobs.get(str(parent.input.get("coreJobId") or ""))
    snapshot_targets = list(snapshot.get("publicVerificationTargets") or [])
    if core is None or not _core_verified(core, snapshot_targets):
        remaining.append(f"core_job:{parent.input.get('coreJobId')}")
    return sorted(set(remaining))


def _core_verified(core: StoredJobRun, snapshot_targets: list[dict[str, Any]] | None = None) -> bool:
    if core.status != "succeeded":
        return False
    if snapshot_targets is not None and (
        not isinstance(snapshot_targets, list) or not all(isinstance(target, dict) for target in snapshot_targets)
    ):
        return False
    starts = [index for index, event in enumerate(core.events) if event.message == "operator teardown requested"]
    if not starts:
        return False
    attempt = core.events[starts[-1]:]
    terminals = [event for event in attempt if event.message == "pilot Standard RTI teardown finished"]
    if len(terminals) != 1:
        return False
    terminal = terminals[0]
    if terminal.level != "info" or terminal.data.get("ok") is not True \
            or terminal.data.get("finalCleanupStatus") != "verified_clean" \
            or terminal.data.get("coreCleanupStatus") != "verified_clean" \
            or terminal.data.get("mutationStatus") != "destroyed":
        return False
    verification = terminal.data.get("inspectorTeardownVerification")
    cleanup = terminal.data.get("inspectorCleanup")
    if not (isinstance(verification, dict) and verification.get("ok") is True
            and isinstance(cleanup, dict) and cleanup.get("ok") is True
            and cleanup.get("cleanupVerified") is True and cleanup.get("currentHostCleared") is True):
        return False
    verification_targets = verification.get("targets")
    if not isinstance(verification_targets, list) or not all(isinstance(target, dict) for target in verification_targets):
        return False
    expected = canonical_teardown_targets(snapshot_targets or [])
    observed = canonical_teardown_targets(verification_targets)
    verify_host = _inspector_identity(verification.get("inspectorHost"))
    cleanup_host = _inspector_identity(cleanup.get("inspectorHost"))
    expected_digest = teardown_target_sha256(snapshot_targets or [])
    return type(verification.get("targetCount")) is int and verification.get("targetCount") == len(expected) and observed == expected \
        and (not expected or (verify_host is not None and verify_host == cleanup_host)) \
        and terminal.data.get("verificationTargetSha256") == expected_digest


def _inspector_identity(value: Any) -> tuple[str, str, str] | None:
    if not isinstance(value, dict):
        return None
    fields = tuple(value.get(key) for key in ("provider", "resourceType", "resourceId"))
    if not all(type(field) is str and field.strip() for field in fields):
        return None
    return fields


def _inspector_tracked(core: StoredJobRun, active_records: list[Any] | None = None) -> bool:
    if any(_latest(core, key) is not None for key in ("inspector", "inspectorHost", "inspectorCleanup", "inspectorTeardownVerification")):
        return True
    return any(
        is_barragan_owned_record(record)
        and (
            str(getattr(record, "resource_type", "") or "").startswith("inspector_")
            or str((getattr(record, "metadata", {}) or {}).get("role") or "").lower() == "inspector"
        )
        for record in (active_records or [])
    )


def _inspector_record_ids(active_records: list[Any]) -> list[str]:
    return sorted(
        str(record.id)
        for record in active_records
        if str(getattr(record, "resource_type", "") or "").startswith("inspector_")
        or str((getattr(record, "metadata", {}) or {}).get("role") or "").lower() == "inspector"
    )


def _inspector_record_owners(active_records: list[Any]) -> dict[str, str]:
    return {
        str(record.id): str(
            getattr(record, "adoption_job_id", "")
            or (getattr(record, "metadata", {}) or {}).get("inspectionJobId")
            or ""
        )
        for record in active_records
        if str(getattr(record, "resource_type", "") or "").startswith("inspector_")
        or str((getattr(record, "metadata", {}) or {}).get("role") or "").lower() == "inspector"
    }


def _known_public_targets(core: StoredJobRun) -> list[Any]:
    for key in ("publicVerificationTargets", "inspectorTargets", "retiredPublicEndpoints"):
        value = _latest(core, key)
        if isinstance(value, list):
            return value
    return []


def _known_public_targets_for_engagement(jobs: JobRepository, engagement_id: str) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    seen: dict[tuple[str, ...], int] = {}

    def target_identity(target: dict[str, Any]) -> tuple[str, ...]:
        target_type = str(target.get("type") or "").strip()
        host = _normalized_public_host(target.get("host"))
        if target_type == "tcp-forbidden" and host:
            try:
                port = str(int(target.get("port")))
            except (TypeError, ValueError):
                port = str(target.get("port") or "").strip()
            return (target_type, host, port)
        if target_type == "dns-absent" and host:
            return (target_type, host, str(target.get("expectedIp") or ""))
        return ("raw", json.dumps(target, sort_keys=True))

    def append_target(target: dict[str, Any]) -> None:
        key = target_identity(target)
        existing_index = seen.get(key)
        if existing_index is None:
            seen[key] = len(targets)
            targets.append(target)
            return
        existing = targets[existing_index]
        existing_group = str(existing.get("targetGroup") or "")
        incoming_group = str(target.get("targetGroup") or "")
        if incoming_group == "sketch-public-management" or not existing_group:
            if incoming_group:
                existing["targetGroup"] = incoming_group
        for metadata_key in ("expectedIp", "service", "purpose"):
            if not existing.get(metadata_key) and target.get(metadata_key):
                existing[metadata_key] = target[metadata_key]

    def add(value: Any) -> None:
        if not isinstance(value, dict):
            return
        validation = value.get("validation") if isinstance(value.get("validation"), dict) else {}
        direct_ip = _normalized_ip(value.get("edgePublicIp") or value.get("publicIp"))
        expected_ip = _normalized_ip(value.get("expectedIp") or validation.get("expectedPublicIp") or direct_ip)
        explicit_type = str(value.get("type") or "").strip()
        explicit_host = str(value.get("host") or "").strip()
        domain = str(value.get("domain") or (explicit_host if explicit_type in {"dns", "dns-absent"} else "")).strip()
        identifier = str(value.get("id") or value.get("channelId") or "").strip()
        target_group = str(value.get("targetGroup") or "").strip().lower()
        if target_group not in {"core-public-management", "sketch-public-management"}:
            target_group = ""

        if _looks_like_public_dns_name(domain):
            append_target({
                "id": identifier or f"dns:{domain}",
                "type": "dns-absent",
                "host": domain,
                **({"expectedIp": expected_ip} if expected_ip else {}),
            })

        tcp_host = direct_ip or (
            _normalized_public_host(explicit_host)
            if explicit_type in {"tcp", "tcp-forbidden"}
            else ""
        )
        port = value.get("externalPort") or value.get("port") or ""
        if tcp_host and port != "":
            append_target({
                "id": identifier or f"tcp:{tcp_host}:{port}",
                "type": "tcp-forbidden",
                "host": tcp_host,
                "port": port,
                **({"targetGroup": target_group} if target_group else {}),
            })
        elif expected_ip:
            append_target({
                "id": f"{identifier or 'edge'}:management",
                "type": "tcp-forbidden",
                "host": expected_ip,
                "port": 22,
                "targetGroup": "sketch-public-management",
            })

    for job in reversed(jobs.list_for_engagement(engagement_id)):
        for event in job.events:
            for key in ("publicVerificationTargets", "inspectorTargets", "retiredPublicEndpoints", "targets"):
                values = event.data.get(key)
                if isinstance(values, list):
                    for value in values:
                        add(value)
            for key in ("inboundChannels", "outboundChannels"):
                rows = event.data.get(key)
                if isinstance(rows, list):
                    for row in rows:
                        add(row)
            connections = event.data.get("connectionDetails")
            if isinstance(connections, list):
                for connection in connections:
                    if isinstance(connection, dict):
                        host = connection.get("publicIp") or connection.get("host")
                        if host:
                            add({"type": "tcp", "host": host, "port": 22, "targetGroup": "core-public-management"})
    hosts_with_exact_ips = {
        str(target["host"]) for target in targets
        if target.get("type") == "dns-absent" and target.get("expectedIp")
    }
    targets = [target for target in targets if not (
        target.get("type") == "dns-absent" and not target.get("expectedIp")
        and target.get("host") in hosts_with_exact_ips
    )]
    dns_by_host: dict[str, list[dict[str, Any]]] = {}
    for target in targets:
        if target.get("type") == "dns-absent":
            dns_by_host.setdefault(str(target["host"]), []).append(target)
    for host, rows in dns_by_host.items():
        if len(rows) > 1:
            # A host can point to several retired edges. Give each exact
            # host/IP proof its own stable ID, independent of event order.
            for row in rows:
                row["id"] = f"dns:{host}:{row.get('expectedIp') or 'unspecified'}"
    # One channel event can describe both DNS and its public TCP listener with
    # the same channel ID. Keep historical IDs when unique; disambiguate only
    # the colliding exact targets.
    for _ in range(3):
        id_counts: dict[str, int] = {}
        for row in targets:
            target_id = str(row["id"])
            id_counts[target_id] = id_counts.get(target_id, 0) + 1
        collisions = [row for row in targets if id_counts[str(row["id"])] > 1]
        if not collisions:
            break
        for row in collisions:
            if row["type"] == "dns-absent":
                row["id"] = f"dns:{row['host']}" + (f":{row['expectedIp']}" if row.get("expectedIp") else "")
            else:
                row["id"] = f"tcp:{row['host']}:{row['port']}"
    return targets


def _looks_like_public_dns_name(value: str) -> bool:
    candidate = value.strip().lower().rstrip(".")
    if not candidate or len(candidate) > 253 or "." not in candidate:
        return False
    try:
        ipaddress.ip_address(candidate)
        return False
    except ValueError:
        pass
    labels = candidate.split(".")
    return all(
        len(label) <= 63
        and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is not None
        for label in labels
    )


def _normalized_ip(value: Any) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ""


def _normalized_public_host(value: Any) -> str:
    candidate = str(value or "").strip()
    return _normalized_ip(candidate) or (candidate.lower().rstrip(".") if _looks_like_public_dns_name(candidate) else "")


def _canonical_teardown_targets(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return canonical_teardown_targets(targets)


def _outbound_channel_ids(jobs: JobRepository, engagement_id: str, chain_id: str) -> list[str]:
    for job in jobs.list_for_engagement(engagement_id):
        for event in reversed(job.events):
            rows = event.data.get("outboundChannels")
            if not isinstance(rows, list):
                continue
            found = [str(row.get("channelId") or "") for row in rows if isinstance(row, dict) and str(row.get("chainId") or "") == chain_id and str(row.get("status") or "") != "Removed"]
            if found:
                return [value for value in found if value]
    return []


def _default_chain_dispatcher(
    engagement_id: str,
    chain_id: str,
    body: dict[str, Any],
    *,
    core_mutation_lease_owner: str,
) -> dict[str, Any] | None:
    from app.services.sketch_chains import ensure_sketch_chain_teardown
    return ensure_sketch_chain_teardown(
        engagement_id,
        chain_id,
        body,
        core_mutation_lease_owner=core_mutation_lease_owner,
    )


def _default_outbound_dispatcher(engagement_id: str, chain_id: str, requested_by: str) -> Any:
    from app.services.sketch_chains import remove_sketch_chain_outbound_configuration
    return remove_sketch_chain_outbound_configuration(engagement_id, chain_id, requested_by=requested_by)


def _default_inspector_preflight(
    engagement_id: str, engagement_name: str, teardown_job_id: str, targets: list[dict[str, Any]],
) -> dict[str, Any]:
    from app.services.observer_checks import ensure_inspector_for_infrastructure_teardown

    return ensure_inspector_for_infrastructure_teardown(
        engagement_id, engagement_name, teardown_job_id, retired_targets=targets,
    )


def _default_inspector_state_reader(engagement_id: str) -> dict[str, Any]:
    from app.services.observer_checks import inspector_state_for_infrastructure_teardown

    return inspector_state_for_infrastructure_teardown(engagement_id)


def _default_core_dispatcher(core_job_id: str, verification_targets: list[dict[str, Any]]) -> Any:
    from app.services.guarded_test_deployment import start_guarded_pilot_standard_rti_teardown
    return start_guarded_pilot_standard_rti_teardown(core_job_id, verification_targets=verification_targets)


def _progress(jobs: JobRepository, parent: StoredJobRun, outcomes: dict[str, Any], message: str, data: dict[str, Any]) -> StoredJobRun:
    latest = jobs.get(parent.id) or parent
    return jobs.save(replace(latest, input={**latest.input, "outcomes": outcomes}, events=latest.events + [JobEvent(len(latest.events) + 1, "info", message, data)]))


def _save_parent(jobs: JobRepository, parent: StoredJobRun, *, status: str, phase: str, outcomes: dict[str, Any],
                 message: str, level: str, extra_input: dict[str, Any] | None = None, event_data: dict[str, Any] | None = None,
                 finished: bool = False) -> StoredJobRun:
    latest = jobs.get(parent.id) or parent
    return jobs.save(replace(latest, status=status, started_at=latest.started_at or _now(), finished_at=_now() if finished else None,
                             input={**latest.input, "phase": phase, "outcomes": outcomes, **(extra_input or {})},
                             events=latest.events + [JobEvent(len(latest.events) + 1, level, message, {"phase": phase, **(event_data or {})})]))


def _fail(jobs: JobRepository, parent: StoredJobRun, outcomes: dict[str, Any], remaining: list[str], detail: str) -> None:
    failed = _save_parent(jobs, parent, status="failed", phase="cleanup_required", outcomes=outcomes,
                          message="engagement teardown requires cleanup", level="error",
                          extra_input={"remainingOwnedResources": remaining, "claimExpiresAt": _now()},
                          event_data={"finalCleanupStatus": "cleanup_not_verified", "remainingOwnedResources": remaining, "detail": detail}, finished=True)
    try:
        reconcile_engagement_lifecycle(failed.target_id, reason="comprehensive_teardown_failed")
    except Exception:
        logging.getLogger("barragan.background").exception("Engagement teardown lifecycle reconciliation failed")


def _renew(jobs: JobRepository, parent_id: str, owner: str, token: str) -> StoredJobRun | None:
    claimed_at = _now()
    return jobs.claim_lease(parent_id, owner=owner, token=token, claimed_at=claimed_at,
                            expires_at=(datetime.fromisoformat(claimed_at) + timedelta(seconds=LEASE_SECONDS)).isoformat(), eligible_statuses={"running"})


def _run_with_lease_heartbeat(
    operation: Callable[[], Any],
    *,
    jobs: JobRepository,
    parent_id: str,
    owner: str,
    token: str,
) -> Any:
    """Renew a fenced parent lease while a synchronous child operation blocks."""

    stop = threading.Event()
    started = threading.Event()
    lost = threading.Event()
    try:
        state = current_runtime()
    except RuntimeError:
        state = None

    def heartbeat() -> None:
        def run() -> None:
            if _renew(jobs, parent_id, owner, token) is None:
                lost.set()
            started.set()
            while not stop.wait(max(1.0, LEASE_SECONDS / 3)):
                if _renew(jobs, parent_id, owner, token) is None:
                    lost.set()
                    return

        if state is None:
            run()
        else:
            with runtime_context(state):
                run()

    thread = threading.Thread(target=heartbeat, name=f"barragan-teardown-heartbeat-{parent_id}", daemon=True)
    thread.start()
    if not started.wait(timeout=HEARTBEAT_START_TIMEOUT_SECONDS):
        stop.set()
        thread.join()
        raise EngagementTeardownLeaseLost("engagement teardown lease renewal timed out before child dispatch")
    if lost.is_set():
        stop.set()
        thread.join()
        raise EngagementTeardownLeaseLost("engagement teardown lease was lost before child dispatch")
    operation_error: BaseException | None = None
    result: Any = None
    try:
        result = operation()
    except BaseException as exc:
        operation_error = exc
    finally:
        stop.set()
        thread.join()
    if lost.is_set() or _renew(jobs, parent_id, owner, token) is None:
        raise EngagementTeardownLeaseLost("engagement teardown lease was lost during child dispatch")
    if operation_error is not None:
        raise operation_error
    return result


def _lease_owned(job: StoredJobRun, owner: str, token: str) -> bool:
    if not token or job.input.get("claimOwner") != owner or job.input.get("claimToken") != token:
        return False
    try:
        return datetime.fromisoformat(str(job.input.get("claimExpiresAt") or "")) > datetime.now(timezone.utc)
    except ValueError:
        return False


def _persisted_claim_is_live(job: StoredJobRun) -> bool:
    if not str(job.input.get("claimToken") or ""):
        return False
    try:
        return datetime.fromisoformat(str(job.input.get("claimExpiresAt") or "")) > datetime.now(timezone.utc)
    except (TypeError, ValueError):
        return False


def _latest(job: StoredJobRun, key: str) -> Any:
    event = next((event for event in reversed(job.events) if event.data.get(key) is not None), None)
    return event.data.get(key) if event else None


def _confirmation_phrase(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return f"teardown-{slug or 'engagement'}"


def _parent_id(core_job_id: str) -> str:
    return f"job-engagement-teardown-{core_job_id.removeprefix('job-')}"


def _fingerprint(value: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _safe_error(exc: Exception) -> str:
    errors = getattr(exc, "errors", None)
    return "; ".join(str(value) for value in errors) if isinstance(errors, list) and errors else type(exc).__name__


def _preflight_error(result: dict[str, Any]) -> str:
    errors = result.get("errors")
    if isinstance(errors, list) and errors:
        return "; ".join(str(value) for value in errors)
    return str(result.get("status") or "Inspector is unavailable")


def _sleep(seconds: float) -> None:
    import time
    time.sleep(seconds)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
