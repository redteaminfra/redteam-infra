# Copyright (c) 2026, Oracle and/or its affiliates.
"""DevTest-only public composition of an exact published keyed teardown.

The private stages own their command journals. This driver creates no retry
authority and never substitutes a pending-generation recognizer.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Callable

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_comprehensive_teardown import _boundary, _child_id
from app.services.provider_keyed_pending_cleanup import _require_diagnostic_targets
from app.services.provider_keyed_pending_dispatch import require_positive_control_ipv4
from app.services.provider_keyed_published_teardown_source import (
    audit_published_provider_keyed_source,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository


class PublishedKeyedDispatchAttention(ValueError):
    """The saved phase needs review; the driver cannot infer a safe retry."""


def _require_reviewed_shape(core, snapshot: dict, jobs) -> dict:
    from app.services.provider_keyed_published_initial_cleanup_authority import KEY, seal_marker
    sealed = KEY in snapshot
    if sealed:
        seal_marker(snapshot)
    chains = snapshot.get("chains")
    scopes = snapshot.get("providerScopes")
    dns = snapshot.get("dnsCleanupManifest")
    inspector = snapshot.get("inspector")
    if (core.input.get("sketchStateSchema") != "provider-keyed-v2"
            or type(chains) is not list or len(chains) != 2
            or any(row.get("status") != "deployed"
                   or row.get("outboundChannelIds") != []
                   or row.get("middle", {}).get("provider") != "digitalocean"
                   or any(edge.get("provider") != "digitalocean"
                          for edge in row.get("edges", []))
                   for row in chains)
            or type(scopes) is not list or len(scopes) != 1
            or scopes[0].get("provider") != "digitalocean"
            or type(dns) is not dict or dns.get("domains") != []
            or snapshot.get("domainAssignments") != []
            or type(inspector) is not dict or inspector.get("tracked") is not True
            or len(inspector.get("ownedProviderRecordIds", [])) != 2
            or not sealed and any(row.action.startswith(("inbound_channel", "outbound_channel"))
                   for row in jobs.list_for_engagement(core.input["engagementId"]))):
        raise ValueError("published diagnostic scope differs")
    if not sealed:
        _require_diagnostic_targets(core, snapshot)
    return inspector


def require_prequeue_published_generation(core, snapshot: dict, *, environment: str,
                                          state_root: Path, job_repository=None,
                                          provider_resource_repository=None,
                                          expected_teardown_parent_id: str | None = None):
    """Prove the narrow published, channel-free scope before any parent insert."""
    try:
        if (environment != "devtest" or not isinstance(state_root, Path)
                or not state_root.is_absolute()):
            raise ValueError("DevTest state root required")
        jobs = job_repository or SqlAlchemyJobRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        scopes = snapshot.get("providerScopes")
        inspector = _require_reviewed_shape(core, snapshot, jobs)
        from app.services.provider_keyed_published_initial_cleanup_authority import KEY, build_cleanup_seal
        if KEY in snapshot:
            from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
            if build_cleanup_seal(core, snapshot, jobs=jobs, chains=SqlAlchemySketchChainRepository()) != snapshot[KEY]:
                raise ValueError("published initial cleanup review changed")
        inspector_ids = inspector["ownedProviderRecordIds"]
        owners = inspector.get("recordOwners")
        if (type(owners) is not dict or set(owners) != set(inspector_ids)
                or len(set(inspector_ids)) != 2):
            raise ValueError("retained Inspector identity differs")
        kinds = set()
        for record_id in inspector_ids:
            row = resources.get(record_id)
            owner_id = owners[record_id]
            adoption = jobs.get(owner_id) if type(owner_id) is str else None
            if (row is None or row.provider != "linode"
                    or row.engagement_id != snapshot["engagementId"]
                    or row.status.lower() in {"destroyed", "deleted", "retired", "absent"}
                    or row.resource_type not in {"inspector_instance", "inspector_firewall"}
                    or row.adoption_job_id != owner_id
                    or row.metadata.get("inspectionJobId") != owner_id
                    or adoption is None or adoption.action not in {
                        "inspector_inspection", "inspector_readiness",
                    } or adoption.status != "succeeded"
                    or adoption.target_id != snapshot["engagementId"]):
                raise ValueError("retained Inspector provenance differs")
            kinds.add(row.resource_type)
        if kinds != {"inspector_instance", "inspector_firewall"}:
            raise ValueError("retained Inspector record kinds differ")
        appended = [job for job in jobs.list_for_engagement(snapshot["engagementId"])
                    if job.action == "provider_keyed_edge_append"]
        from app.services.provider_keyed_teardown_scope import (
            _reconciled_unapplied_append_state_sha,
        )
        unapplied_sha = (_reconciled_unapplied_append_state_sha(
            snapshot["engagementId"], jobs,
            expected_core_job_id=core.id,
            expected_core_plan_id=scopes[0].get("corePlanId")) if appended else None)
        if appended and unapplied_sha is None:
            from app.services.provider_keyed_append_source import (
                audit_published_provider_keyed_append_source,
            )
            source = audit_published_provider_keyed_append_source(
                core.id, environment=environment, state_root=state_root,
                job_repository=jobs,
            )
            initial = source.initial_source
            if (source.state_sha256 != scopes[0].get("stateSha256")
                    or len(scopes[0].get("resources", [])) != 9):
                raise ValueError("appended source and preview differ")
        else:
            if appended and unapplied_sha != scopes[0].get("stateSha256"):
                raise ValueError("reconciled append and preview differ")
            source = audit_published_provider_keyed_source(
                core.id, environment=environment, state_root=state_root,
                job_repository=jobs,
                expected_teardown_parent_id=expected_teardown_parent_id,
            )
            initial = source
            if source.scope_sha256 != _fingerprint(scopes[0]):
                raise ValueError("published source and preview differ")
        if (initial.engagement_id != snapshot["engagementId"]
                or initial.core_job_id != core.id
                or initial.core_plan_id != scopes[0].get("corePlanId")
                or tuple(scopes[0].get("chainIds", [])) != initial.chain_ids
                or snapshot.get("snapshotId") != _fingerprint({
                    key: value for key, value in snapshot.items() if key != "snapshotId"})):
            raise ValueError("published source and preview differ")
        return source
    except Exception:
        raise PublishedKeyedDispatchAttention(
            "published keyed teardown scope is unproved; review again") from None


def _saved_child(jobs, core_id: str, prefix: str, action: str):
    child = jobs.get(f"job-{prefix}-{core_id.removeprefix('job-')}")
    if child is not None and (child.action != action or child.status != "succeeded"):
        raise PublishedKeyedDispatchAttention("one-shot child requires reconciliation")
    return child


def advance_published_keyed_terminal(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    positive_control_ipv4: str, job_repository=None, plan_repository=None,
    lease_lookup=None, handoff: Callable | None = None,
    prove_retained: Callable | None = None, preview_provider: Callable | None = None,
    apply_provider: Callable | None = None, publish_absence: Callable | None = None,
    retire_group: Callable | None = None, preview_core: Callable | None = None,
    apply_core: Callable | None = None, prove_core_absence: Callable | None = None,
    prove_negative: Callable | None = None, retire_selector: Callable | None = None,
    recognize_selector: Callable | None = None, retire_inspector: Callable | None = None,
    recognize_terminal: Callable | None = None,
):
    """Advance one persisted phase; uncertain one-shot work remains visible."""
    from app.services.provider_keyed_comprehensive_teardown import (
        prove_retained_keyed_inspector_ready, publish_provider_keyed_destroy_absence,
        retire_provider_keyed_group_after_absence,
        run_provider_keyed_comprehensive_handoff,
        run_provider_keyed_destroy_preview_from_ready,
    )
    from app.services.provider_keyed_initial_destroy_apply_job import (
        run_digitalocean_initial_destroy_apply_job,
    )
    from app.services.provider_keyed_core_destroy_preview import preview_pending_keyed_oci_core_destroy
    from app.services.provider_keyed_core_destroy_apply import apply_pending_keyed_oci_core_destroy
    from app.services.provider_keyed_core_destroy_absence import prove_pending_keyed_oci_core_destroy_absence
    from app.services.provider_keyed_inspector_negative import prove_pending_keyed_inspector_negative
    from app.services.provider_keyed_selector_retirement import (
        recognize_pending_digitalocean_selector_retired,
        retire_pending_digitalocean_selector,
    )
    from app.services.provider_keyed_inspector_linode_cleanup import (
        recognize_pending_linode_inspector_retired, retire_pending_linode_inspector,
    )

    if environment != "devtest" or not isinstance(state_root, Path) or not state_root.is_absolute():
        raise PublishedKeyedDispatchAttention("DevTest published teardown only")
    require_positive_control_ipv4(positive_control_ipv4)
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    lookup = lease_lookup or _db_lease_lookup
    common = {"environment": environment, "state_root": state_root,
              "job_repository": jobs, "plan_repository": plans, "lease_lookup": lookup}
    try:
        parent = jobs.get(teardown_parent_id)
        if parent is not None and parent.status == "succeeded":
            terminal = recognize_terminal or recognize_pending_linode_inspector_retired
            if "publishedSource" not in parent.input:
                raise ValueError("terminal source differs")
            return terminal(parent.id, environment=environment,
                            job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
        parent, core, snapshot, operation = _boundary(teardown_parent_id, jobs, plans, lookup)
        if (operation != "provider_keyed_teardown_fence"
                or "publishedSource" not in parent.input
                or parent.target_id != core.input.get("engagementId")):
            raise ValueError("published parent differs")
        if "publishedAppendSource" in parent.input:
            appended = parent.input["publishedAppendSource"]
            scopes = snapshot.get("providerScopes")
            if (type(appended) is not dict
                    or appended.get("initial_source") != parent.input["publishedSource"]
                    or type(scopes) is not list or len(scopes) != 1
                    or len(scopes[0].get("resources", [])) != 9
                    or appended.get("state_sha256") != scopes[0].get("stateSha256")):
                raise ValueError("published appended parent differs")
        _require_reviewed_shape(core, snapshot, jobs)
        from app.services.provider_keyed_published_initial_cleanup_authority import validate_saved_cleanup
        validate_saved_cleanup(parent, core, snapshot, jobs)
        coordinator = jobs.get(_child_id(core.id))
        if coordinator is None or coordinator.input.get("phase") in {"queued", "handoff_pending"}:
            (handoff or run_provider_keyed_comprehensive_handoff)(parent.id, **common)
            coordinator = jobs.get(_child_id(core.id))
        phase = coordinator.input.get("phase") if coordinator else None
        if phase == "awaiting_inspector_preflight":
            (prove_retained or prove_retained_keyed_inspector_ready)(parent.id, **common)
            coordinator = jobs.get(_child_id(core.id))
            phase = coordinator.input.get("phase")
        if phase == "inspector_ready":
            apply_id = ("job-provider-keyed-initial-destroy-apply-"
                        + core.id.removeprefix("job-"))
            applied = jobs.get(apply_id)
            if applied is not None and (applied.action != "provider_keyed_initial_destroy_apply"
                                        or applied.status not in {"failed", "succeeded"}
                                        or (applied.status == "failed"
                                            and "publishedAppendSource" not in parent.input)):
                raise PublishedKeyedDispatchAttention("one-shot child requires reconciliation")
            if applied is None or applied.status == "failed":
                (preview_provider or run_provider_keyed_destroy_preview_from_ready)(parent.id, **common)
                (apply_provider or run_digitalocean_initial_destroy_apply_job)(parent.id, **common)
                if _saved_child(jobs, core.id, "provider-keyed-initial-destroy-apply",
                                "provider_keyed_initial_destroy_apply") is None:
                    raise ValueError("provider apply has no saved success")
            # After a successful destroy apply the nonempty pre-destroy source
            # is gone. Only the saved apply receipt may advance absence.
            (publish_absence or publish_provider_keyed_destroy_absence)(parent.id, **common)
            coordinator = jobs.get(_child_id(core.id))
            phase = coordinator.input.get("phase")
        if phase == "provider_absent":
            (retire_group or retire_provider_keyed_group_after_absence)(parent.id, **common)
            coordinator = jobs.get(_child_id(core.id))
            phase = coordinator.input.get("phase")
        if phase != "group_retired":
            raise ValueError("published coordinator phase requires reconciliation")
        if _saved_child(jobs, core.id, "provider-keyed-core-destroy-preview",
                        "provider_keyed_core_destroy_preview") is None:
            (preview_core or preview_pending_keyed_oci_core_destroy)(parent.id, **common)
        if _saved_child(jobs, core.id, "provider-keyed-core-destroy-apply",
                        "provider_keyed_core_destroy_apply") is None:
            (apply_core or apply_pending_keyed_oci_core_destroy)(parent.id, **common)
        (prove_core_absence or prove_pending_keyed_oci_core_destroy_absence)(parent.id, **common)
        negative_id = f"job-provider-keyed-inspector-negative-{core.id.removeprefix('job-')}"
        negative = jobs.get(negative_id)
        if negative is not None and negative.status != "succeeded":
            raise ValueError("uncertain Inspector negative cannot replay")
        (prove_negative or prove_pending_keyed_inspector_negative)(
            parent.id, **common,
            positive_control={"id": "inspector-external-control", "type": "tcp",
                              "host": positive_control_ipv4, "port": 443})
        selector = jobs.get(f"job-provider-keyed-selector-retirement-{core.id.removeprefix('job-')}")
        if selector is not None and selector.status == "succeeded":
            (recognize_selector or recognize_pending_digitalocean_selector_retired)(parent.id, **common)
        else:
            # Its own durable DELETE intent permits only exact GET recovery.
            (retire_selector or retire_pending_digitalocean_selector)(parent.id, **common)
        return (retire_inspector or retire_pending_linode_inspector)(parent.id, **common)
    except PublishedKeyedDispatchAttention:
        raise
    except Exception:
        raise PublishedKeyedDispatchAttention(
            "published keyed cleanup stopped at its saved phase; inspect jobs") from None


def recover_published_keyed_dispatches(
    *, environment: str, state_root: Path, positive_control_ipv4: str,
    schedule: Callable[[str, float], None], job_repository=None, plan_repository=None,
    lease_lookup=None, now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> list[str]:
    """Schedule only an exact fenced published parent, never generic teardown."""
    if environment != "devtest":
        return []
    require_positive_control_ipv4(positive_control_ipv4)
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    lookup = lease_lookup or _db_lease_lookup
    selected = []
    for candidate in jobs.list():
        if (candidate.action != "engagement_comprehensive_teardown"
                or candidate.status != "queued"
                or "publishedSource" not in candidate.input):
            continue
        try:
            parent, core, snapshot, operation = _boundary(candidate.id, jobs, plans, lookup)
            coordinator = jobs.get(_child_id(core.id))
            if operation != "provider_keyed_teardown_fence":
                continue
            _require_reviewed_shape(core, snapshot, jobs)
            if coordinator is None:
                # Reservation and handoff are separate commits. A crash between
                # them is safe to resume only while the original live published
                # generation still proves the sealed source.
                source = require_prequeue_published_generation(
                    core, snapshot, environment=environment,
                    state_root=state_root, job_repository=jobs,
                    expected_teardown_parent_id=parent.id,
                )
                sealed = json.loads(json.dumps(asdict(source)))
                if "publishedAppendSource" in candidate.input:
                    if (sealed != candidate.input["publishedAppendSource"]
                            or sealed.get("initial_source") != candidate.input["publishedSource"]):
                        continue
                elif sealed != candidate.input["publishedSource"]:
                    continue
                selected.append((parent.id, 0.0))
                continue
            if (coordinator.status not in {"queued", "running"}
                    or coordinator.input.get("teardownParentId") != parent.id
                    or coordinator.input.get("scopeSnapshotId") != snapshot["snapshotId"]):
                continue
            delay = 0.0
            if coordinator.input.get("claimExpiresAt"):
                expiry = datetime.fromisoformat(coordinator.input["claimExpiresAt"])
                if expiry.tzinfo is None:
                    continue
                delay = max(0.0, (expiry - now()).total_seconds())
            if ("publishedAppendSource" in parent.input
                    and coordinator.input.get("phase") == "inspector_ready"):
                from app.services.provider_keyed_initial_destroy_plan_job import _CLAIM_SECONDS
                preview_id = ("job-provider-keyed-initial-destroy-plan-"
                              + core.id.removeprefix("job-"))
                preview = jobs.get(preview_id)
                if preview is not None and preview.status == "failed":
                    if (len(preview.events) != 4 or preview.events[-1].data != {
                            "failureStage": "other"} or preview.finished_at is None):
                        continue
                    finished = datetime.fromisoformat(preview.finished_at)
                    if finished.tzinfo is None:
                        finished = finished.replace(tzinfo=timezone.utc)
                    delay = max(delay, (finished + timedelta(seconds=_CLAIM_SECONDS)
                                        - now()).total_seconds(), 0.0)
                apply_id = ("job-provider-keyed-initial-destroy-apply-"
                            + core.id.removeprefix("job-"))
                applied = jobs.get(apply_id)
                if applied is not None and applied.status == "failed":
                    ordinary_failed = applied.events == [
                        JobEvent(1, "info", "provider destroy apply queued", {}),
                        JobEvent(2, "info", "provider destroy apply started", {}),
                        JobEvent(3, "error", "provider destroy apply stopped", {}),
                    ]
                    show_only_failed = (len(applied.events) == 8
                        and [row.sequence for row in applied.events] == list(range(1, 9))
                        and [row.message for row in applied.events] == [
                            "provider destroy apply queued",
                            "provider destroy apply started",
                            "provider destroy apply stopped",
                            "provider destroy apply pre-command recovery reserved",
                            "provider destroy command intent fenced",
                            "provider destroy command started before GO",
                            "provider destroy command result fenced",
                            "provider destroy apply stopped",
                        ])
                    if (applied.action != "provider_keyed_initial_destroy_apply"
                            or not (ordinary_failed or show_only_failed)
                            or applied.finished_at is None):
                        continue
                    finished = datetime.fromisoformat(applied.finished_at)
                    if finished.tzinfo is None:
                        finished = finished.replace(tzinfo=timezone.utc)
                    delay = max(delay, (finished + timedelta(seconds=60)
                                        - now()).total_seconds(), 0.0)
            selected.append((parent.id, delay))
        except Exception:
            continue
    for parent_id, delay in selected:
        schedule(parent_id, delay)
    return [parent_id for parent_id, _delay in selected]
