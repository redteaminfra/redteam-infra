# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private DevTest continuation for an unpublished keyed build.

The preview and provider-group destroy stages are one-shot. This module
composes their persisted boundaries through pending group retirement only;
core and Inspector removal need separate continuations.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
from typing import Callable

from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_comprehensive_teardown import (
    _FENCE, _boundary, _child_id, _same_child, prove_retained_keyed_inspector_ready,
    recognize_retained_keyed_inspector_ready,
    run_provider_keyed_comprehensive_handoff,
    run_provider_keyed_destroy_preview_from_ready,
)
from app.services.provider_keyed_initial_destroy_apply_job import ACTION as APPLY_ACTION
from app.services.provider_keyed_initial_destroy_plan_job import ACTION as PREVIEW_ACTION
from app.services.provider_keyed_destroy_apply_continuation import (
    continue_digitalocean_keyed_destroy_apply,
)
from app.services.provider_keyed_pending_retirement import (
    recognize_pending_keyed_group_retired, retire_pending_keyed_group_after_absence,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_teardown_source import load_keyed_teardown_source
from app.services.provider_keyed_teardown_quiescence import audit_pending_provider_keyed_bootstrap
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository


class PendingKeyedCleanupAttention(ValueError):
    """A persisted boundary needs review; no provider destroy was started here."""


@dataclass(frozen=True)
class PendingKeyedDestroyPreview:
    teardown_parent_id: str
    coordinator_job_id: str
    preview_job_id: str
    scope_snapshot_id: str


@dataclass(frozen=True)
class PendingKeyedGroupCleanup:
    teardown_parent_id: str
    coordinator_job_id: str
    apply_job_id: str
    scope_snapshot_id: str
    chain_ids: tuple[str, ...]


def _require_diagnostic_targets(core, snapshot: dict) -> None:
    """Allow only core SSH endpoints proven by this core job's connection rows."""
    details = next((event.data["connectionDetails"] for event in reversed(core.events)
                    if type(event.data) is dict
                    and type(event.data.get("connectionDetails")) is list), [])
    proxy_count = core.input.get("proxyCount")
    if (type(proxy_count) is not int or proxy_count not in {1, 2}
            or snapshot.get("core", {}).get("proxyCount") != proxy_count):
        raise ValueError("reviewed core topology differs")
    expected = []
    ips = set()
    homebases = 0
    proxies = 0
    for row in details:
        if type(row) is not dict:
            raise ValueError("core connection row differs")
        ip = row.get("publicIp")
        if ip is None and row.get("role") == "elk":
            continue
        if row.get("role") not in {"homebase", "proxy"} or type(ip) is not str:
            raise ValueError("core connection identity differs")
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError("core connection IP differs") from None
        if (not isinstance(address, ipaddress.IPv4Address)
                or not address.is_global
                or str(address) != ip or ip in ips):
            raise ValueError("core connection IP differs")
        ips.add(ip)
        if row["role"] == "homebase":
            homebases += 1
        else:
            proxies += 1
        expected.append({
            "id": f"tcp:{ip}:22", "type": "tcp-forbidden", "host": ip,
            "port": 22, "targetGroup": "core-public-management",
        })
    if homebases != 1 or proxies != proxy_count:
        raise ValueError("reviewed core host count differs")
    targets = snapshot.get("publicVerificationTargets")
    if (type(targets) is not list or len(targets) != len(expected)
            or any(type(row) is not dict for row in targets)
            or sorted(json.dumps(row, sort_keys=True) for row in targets)
            != sorted(json.dumps(row, sort_keys=True) for row in expected)):
        raise ValueError("diagnostic targets differ from reviewed core")


def advance_pending_keyed_cleanup_to_preview(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, lease_lookup=None,
    source_loader: Callable = load_keyed_teardown_source,
    handoff_runner: Callable = run_provider_keyed_comprehensive_handoff,
    ready_prover: Callable = prove_retained_keyed_inspector_ready,
    ready_recognizer: Callable = recognize_retained_keyed_inspector_ready,
    preview_runner: Callable = run_provider_keyed_destroy_preview_from_ready,
    pending_auditor: Callable = audit_pending_provider_keyed_bootstrap,
) -> PendingKeyedDestroyPreview:
    """Advance only the recoverable, retained-Inspector pre-destroy stages.

    Every stage reloads the exact pending source and coordinator from storage.
    Existing one-shot destroy children, even queued ones, are never invoked
    or replayed by this driver.  The lower-level preview runner owns its own
    one-shot child and exact saved-plan/provider-membership checks.
    """
    try:
        if (environment != "devtest" or not teardown_parent_id
                or not isinstance(state_root, Path) or not state_root.is_absolute()):
            raise ValueError("unsupported cleanup boundary")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        lookup = lease_lookup or _db_lease_lookup

        def read(stage: str):
            parent, core, snapshot, operation = _boundary(
                teardown_parent_id, jobs, plans, lookup)
            if "publishedSource" in parent.input:
                raise ValueError("published cleanup has a separate source")
            proof = source_loader(
                parent.id, phase=stage, environment=environment,
                state_root=state_root, job_repository=jobs, plan_repository=plans)
            failed_prebinding = snapshot.get("dnsCleanupManifest", {}).get("schema") == (
                "provider-keyed-empty-dns-prebinding-v1")
            expected_variant = ("failed_prebinding" if failed_prebinding else
                                "pending_terminal" if stage == "pre_handoff" else "pending_handoff")
            if (proof.variant != expected_variant
                    or proof.teardown_parent_id != parent.id
                    or proof.engagement_id != parent.target_id
                    or proof.core_job_id != core.id
                    or proof.core_plan_id != core.input["corePlanId"]
                    or proof.snapshot_id != snapshot["snapshotId"]
                    or proof.provider_scope_sha256 != snapshot["providerScopeSha256"]):
                raise ValueError("pending source changed")
            manifest = snapshot.get("dnsCleanupManifest")
            if (snapshot.get("domainAssignments") != []
                    or type(manifest) is not dict or manifest.get("domains") != []
                    or any(row.get("outboundChannelIds") != []
                           for row in snapshot["chains"])):
                raise ValueError("diagnostic cleanup requires no live routes or domains")
            _require_diagnostic_targets(core, snapshot)
            if stage == "pre_handoff" and operation != "provider_keyed_initial":
                raise ValueError("pre-handoff lease differs")
            if stage == "pre_go" and operation != _FENCE:
                raise ValueError("cleanup lease differs")
            apply_id = f"job-provider-keyed-initial-destroy-apply-{core.id.removeprefix('job-')}"
            if (jobs.get(apply_id) is not None or any(
                    row.action == APPLY_ACTION
                    for row in jobs.list_for_engagement(parent.target_id))):
                raise ValueError("destroy child already exists; reconcile it separately")
            return parent, core, snapshot

        parent, core, snapshot, operation = _boundary(
            teardown_parent_id, jobs, plans, lookup)
        if "publishedSource" in parent.input:
            raise ValueError("published cleanup is not supported")
        child = jobs.get(_child_id(core.id))
        if operation == "provider_keyed_initial" and child is not None and (
                child.input.get("phase") == "handoff_pending"):
            if (not _same_child(child, parent, core, snapshot)
                    or len([row for row in jobs.list_for_engagement(parent.target_id)
                            if row.action == child.action]) != 1):
                raise ValueError("pending coordinator differs")
            pending_auditor(
                core.id, confirmed_scope=snapshot["providerScopes"][0],
                confirmed_scope_sha256=_fingerprint(snapshot),
                workspace_root=Path(snapshot["providerScopes"][0]["workspace"]),
                job_repository=jobs)
            if (jobs.get(parent.id) != parent or jobs.get(child.id) != child
                    or lookup(parent.target_id) != (core.input["corePlanId"], operation)):
                raise ValueError("pending handoff changed")
        elif operation == "provider_keyed_initial":
            read("pre_handoff")
        elif operation == _FENCE:
            read("pre_go")
        else:
            raise ValueError("cleanup lease differs")
        if child is None or child.input.get("phase") in {
                "queued", "handoff_pending", "awaiting_inspector_preflight"}:
            handoff_runner(
                parent.id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
        parent, core, snapshot = read("pre_go")
        child = jobs.get(_child_id(core.id))
        if child is None or child.status != "running":
            raise ValueError("coordinator is not running")
        preview_id = f"job-provider-keyed-initial-destroy-plan-{core.id.removeprefix('job-')}"
        previews = [row for row in jobs.list_for_engagement(parent.target_id)
                    if row.action == PREVIEW_ACTION]
        if previews and (len(previews) != 1 or previews[0].id != preview_id
                         or previews[0].status != "succeeded"):
            raise ValueError("incomplete destroy preview needs reconciliation")
        if child.input.get("phase") == "awaiting_inspector_preflight":
            ready_prover(
                parent.id, environment=environment, job_repository=jobs,
                plan_repository=plans, lease_lookup=lookup)
        elif child.input.get("phase") != "inspector_ready":
            raise ValueError("coordinator phase needs reconciliation")
        parent, core, snapshot = read("pre_go")
        child = jobs.get(_child_id(core.id))
        if (child is None or child.status != "running"
                or child.input.get("phase") != "inspector_ready"
                or len(child.events) != 5
                or child.events[-1].message != "retained_inspector_ready"):
            raise ValueError("retained Inspector proof is missing")
        ready = ready_recognizer(
            parent.id, environment=environment, job_repository=jobs,
            plan_repository=plans, lease_lookup=lookup)
        if ready.coordinator_job_id != child.id or jobs.get(child.id) != child:
            raise ValueError("retained Inspector changed")
        previews = [row for row in jobs.list_for_engagement(parent.target_id)
                    if row.action == PREVIEW_ACTION]
        if previews and (len(previews) != 1 or previews[0].id != preview_id
                         or previews[0].status != "succeeded"):
            raise ValueError("incomplete destroy preview needs reconciliation")
        preview = preview_runner(
            parent.id, environment=environment, state_root=state_root,
            job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
        final_parent, final_core, final_snapshot = read("pre_go")
        if (final_parent != parent or final_core != core or final_snapshot != snapshot
                or jobs.get(child.id) != child
                or preview is None or preview.id != preview_id
                or preview.status != "succeeded" or jobs.get(preview_id) != preview):
            raise ValueError("saved preview or source changed")
        return PendingKeyedDestroyPreview(parent.id, child.id, preview.id,
                                          snapshot["snapshotId"])
    except Exception:
        raise PendingKeyedCleanupAttention(
            "pending keyed cleanup needs reconciliation; no provider destroy was started by this driver"
        ) from None


def advance_pending_keyed_cleanup_through_group_retirement(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, lease_lookup=None,
    source_loader: Callable = load_keyed_teardown_source,
    apply_continuation: Callable = continue_digitalocean_keyed_destroy_apply,
    absence_publisher: Callable = None,
    absence_recognizer: Callable = None,
    group_retirer: Callable = retire_pending_keyed_group_after_absence,
    group_recognizer: Callable = recognize_pending_keyed_group_retired,
) -> PendingKeyedGroupCleanup:
    """Resume a saved preview; never replay an existing destroy apply child.

    Only the inspector-ready phase may start the one-shot apply. Later phases
    use their full persisted historical recognizers; they do not demand a
    now-destroyed live provider workspace. No core or Inspector removal occurs.
    """
    from app.services.provider_keyed_comprehensive_teardown import (
        publish_provider_keyed_destroy_absence,
        recognize_provider_keyed_destroy_absence,
    )

    publish = absence_publisher or publish_provider_keyed_destroy_absence
    recognize_absent = absence_recognizer or recognize_provider_keyed_destroy_absence
    try:
        if (environment != "devtest" or not teardown_parent_id
                or not isinstance(state_root, Path) or not state_root.is_absolute()):
            raise ValueError("unsupported cleanup boundary")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        lookup = lease_lookup or _db_lease_lookup

        def read():
            parent, core, snapshot, operation = _boundary(
                teardown_parent_id, jobs, plans, lookup)
            child = jobs.get(_child_id(core.id))
            if ("publishedSource" in parent.input or operation != _FENCE
                    or child is None or child.status != "running"
                    or child.input.get("phase") not in {
                        "inspector_ready", "provider_absent", "pending_group_retired"}
                    or child.input.get("teardownParentId") != parent.id
                    or child.input.get("scopeSnapshotId") != snapshot["snapshotId"]
                    or child.input.get("providerScopeSha256")
                    != snapshot["providerScopeSha256"]):
                raise ValueError("pending coordinator differs")
            manifest = snapshot.get("dnsCleanupManifest")
            if (snapshot.get("domainAssignments") != []
                    or type(manifest) is not dict or manifest.get("domains") != []
                    or any(row.get("outboundChannelIds") != []
                           for row in snapshot["chains"])):
                raise ValueError("diagnostic cleanup requires no live routes or domains")
            _require_diagnostic_targets(core, snapshot)
            return parent, core, snapshot, child

        parent, core, snapshot, child = read()
        apply_id = f"job-provider-keyed-initial-destroy-apply-{core.id.removeprefix('job-')}"

        def applied():
            rows = [row for row in jobs.list_for_engagement(parent.target_id)
                    if row.action == APPLY_ACTION]
            current = jobs.get(apply_id)
            if not rows and current is None:
                return None
            if (len(rows) != 1 or rows[0].id != apply_id
                    or current != rows[0] or current.status != "succeeded"):
                raise ValueError("existing destroy apply requires reconciliation")
            return current

        current_apply = applied()
        if child.input["phase"] == "inspector_ready":
            # After a successful apply, the prior provider state is gone.
            # The one-shot continuation's successful-child auditor, rather
            # than a pre-destroy source rebuild, is the restart authority.
            if current_apply is None:
                source = source_loader(
                    parent.id, phase="pre_go", environment=environment,
                    state_root=state_root, job_repository=jobs, plan_repository=plans)
                expected_variant = ("failed_prebinding"
                                    if snapshot.get("dnsCleanupManifest", {}).get("schema")
                                       == "provider-keyed-empty-dns-prebinding-v1"
                                    else "pending_handoff")
                if (source.variant != expected_variant
                        or source.teardown_parent_id != parent.id
                        or source.engagement_id != parent.target_id
                        or source.core_job_id != core.id
                        or source.core_plan_id != core.input["corePlanId"]
                        or source.snapshot_id != snapshot["snapshotId"]
                        or source.provider_scope_sha256 != snapshot["providerScopeSha256"]):
                    raise ValueError("pending source changed")
                preview_id = f"job-provider-keyed-initial-destroy-plan-{core.id.removeprefix('job-')}"
                previews = [row for row in jobs.list_for_engagement(parent.target_id)
                            if row.action == PREVIEW_ACTION]
                if (len(previews) != 1 or previews[0].id != preview_id
                        or jobs.get(preview_id) != previews[0]
                        or previews[0].status != "succeeded"):
                    raise ValueError("saved destroy preview differs")
            # This continuation re-audits the exact saved plan and Inspector
            # before GO, and recognizes a successful preexisting child.
            apply_continuation(
                parent.id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
            if applied() is None or read() != (parent, core, snapshot, child):
                raise ValueError("destroy apply or source changed")
            publish(parent.id, environment=environment, state_root=state_root,
                    job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
            parent, core, snapshot, child = read()

        if child.input["phase"] == "provider_absent":
            if applied() is None:
                raise ValueError("successful destroy apply missing")
            recognize_absent(
                parent.id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
            group_retirer(
                parent.id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
            parent, core, snapshot, child = read()

        if child.input["phase"] != "pending_group_retired" or applied() is None:
            raise ValueError("pending group was not retired")
        rows = group_recognizer(
            parent.id, environment=environment, state_root=state_root,
            job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
        if (type(rows) is not tuple or len(rows) != 2
                or tuple(sorted(row.chain_id for row in rows))
                != tuple(sorted(snapshot["providerScopes"][0]["chainIds"]))
                or read() != (parent, core, snapshot, child)):
            raise ValueError("pending retirement changed")
        return PendingKeyedGroupCleanup(
            parent.id, child.id, apply_id, snapshot["snapshotId"],
            tuple(sorted(row.chain_id for row in rows)),
        )
    except Exception:
        raise PendingKeyedCleanupAttention(
            "pending keyed group cleanup needs reconciliation; inspect persisted destroy and absence jobs before retry"
        ) from None
