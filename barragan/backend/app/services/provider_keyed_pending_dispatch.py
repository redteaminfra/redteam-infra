# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private, phase-driven cleanup of an unpublished DevTest keyed generation.

The service journals and fences each mutation. This driver owns no separate
receipt and never retries a one-shot Terraform or provider command after its
child has been reserved. It is deliberately not wired to a public route.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from app.services.provider_keyed_comprehensive_teardown import _boundary, _child_id
from app.services.provider_keyed_initial_continuation import _job_ids
from app.services.provider_keyed_core_destroy_absence import prove_pending_keyed_oci_core_destroy_absence
from app.services.provider_keyed_core_destroy_apply import apply_pending_keyed_oci_core_destroy
from app.services.provider_keyed_core_destroy_preview import preview_pending_keyed_oci_core_destroy
from app.services.provider_keyed_inspector_linode_cleanup import (
    recognize_pending_linode_inspector_retired, retire_pending_linode_inspector,
)
from app.services.provider_keyed_inspector_negative import prove_pending_keyed_inspector_negative
from app.services.provider_keyed_pending_cleanup import (
    _require_diagnostic_targets,
    advance_pending_keyed_cleanup_through_group_retirement,
    advance_pending_keyed_cleanup_to_preview,
)
from app.services.provider_keyed_teardown_quiescence import (
    audit_failed_prebinding_provider_bootstrap,
    audit_terminal_provider_keyed_bootstrap,
)
from app.services.provider_keyed_teardown_source import load_keyed_teardown_source
from app.services.provider_keyed_selector_retirement import (
    recognize_pending_digitalocean_selector_retired,
    retire_pending_digitalocean_selector,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository


class PendingKeyedDispatchAttention(ValueError):
    """Persisted cleanup needs inspection; the dispatcher does not guess a retry."""


def require_positive_control_ipv4(value: str) -> str:
    """Require an explicitly configured, canonical public IPv4 control."""
    try:
        control = ipaddress.ip_address(value)
    except ValueError:
        raise PendingKeyedDispatchAttention("Inspector control IPv4 is required") from None
    if (not isinstance(control, ipaddress.IPv4Address) or not control.is_global
            or str(control) != value):
        raise PendingKeyedDispatchAttention("Inspector control IPv4 is required")
    return value


def _require_diagnostic_scope(core, snapshot: dict) -> None:
    manifest = snapshot.get("dnsCleanupManifest")
    chains = snapshot.get("chains")
    if (snapshot.get("domainAssignments") != [] or type(manifest) is not dict
            or manifest.get("domains") != [] or type(chains) is not list
            or len(chains) != 2 or any(type(row) is not dict
                                    or row.get("outboundChannelIds") != [] for row in chains)
            or type(snapshot.get("providerScopes")) is not list
            or len(snapshot["providerScopes"]) != 1
            or snapshot["providerScopes"][0].get("provider") != "digitalocean"):
        raise PendingKeyedDispatchAttention("only the unpublished pending diagnostic has a cleanup dispatcher")
    _require_diagnostic_targets(core, snapshot)


def require_prequeue_pending_diagnostic(
    core, snapshot: dict, *, environment: str, state_root: Path,
    job_repository=None, lease_lookup=None,
) -> None:
    """Read-only gate before the normal teardown writer inserts a parent."""
    try:
        if (environment != "devtest" or not isinstance(state_root, Path)
                or not state_root.is_absolute()
                or core.input.get("sketchStateSchema") != "provider-keyed-v2"):
            raise ValueError("pending source is unavailable")
        _require_diagnostic_scope(core, snapshot)
        jobs = job_repository or SqlAlchemyJobRepository()
        lookup = lease_lookup or _db_lease_lookup
        initial = jobs.get(_job_ids(core.id)[0])
        scope = snapshot["providerScopes"][0]
        if (initial is None or lookup(snapshot["engagementId"])
                != (core.input.get("corePlanId"), "provider_keyed_initial")):
            raise ValueError("pending source or fence differs")
        if snapshot["dnsCleanupManifest"].get("schema") == "provider-keyed-empty-dns-prebinding-v1":
            from app.services.engagement_teardown import _valid_keyed_dns_cleanup_manifest
            from app.services.provider_keyed_dns_cleanup_manifest import build_provider_keyed_dns_cleanup_manifest

            if not _valid_keyed_dns_cleanup_manifest(snapshot):
                raise ValueError("failed prebinding empty DNS manifest differs")
            audit_failed_prebinding_provider_bootstrap(
                core.id, confirmed_scope=scope, workspace_root=Path(scope["workspace"]),
                job_repository=jobs,
            )
            base_scope = {key: value for key, value in snapshot.items()
                          if key not in {"snapshotId", "dnsCleanupManifest"}}
            if build_provider_keyed_dns_cleanup_manifest(
                    base_scope, job_repository=jobs) != snapshot["dnsCleanupManifest"]:
                raise ValueError("failed prebinding ownership changed")
        else:
            if (initial.status != "running"
                    or initial.input.get("phase") != "awaiting_strict_host_proof"):
                raise ValueError("pending terminal source differs")
            audit_terminal_provider_keyed_bootstrap(
                core.id, confirmed_scope=scope, workspace_root=Path(scope["workspace"]),
                job_repository=jobs,
            )
        if (jobs.get(core.id) != core or jobs.get(initial.id) != initial
                or lookup(snapshot["engagementId"]) != (core.input.get("corePlanId"), "provider_keyed_initial")):
            raise ValueError("pending source changed")
    except Exception:
        raise PendingKeyedDispatchAttention("pending diagnostic source is unproved") from None


def recover_pending_keyed_dispatches(
    *, environment: str, state_root: Path, positive_control_ipv4: str,
    schedule: Callable[[str, float], None], job_repository=None, plan_repository=None,
    lease_lookup=None, now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> list[str]:
    """Schedule only exact queued, fenced pending parents on process restart."""
    if environment != "devtest":
        return []
    require_positive_control_ipv4(positive_control_ipv4)
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    lookup = lease_lookup or _db_lease_lookup
    selected: list[tuple[str, float]] = []
    for candidate in jobs.list():
        if (candidate.action != "engagement_comprehensive_teardown"
                or candidate.status != "queued" or candidate.input.get("phase") != "queued"
                or "publishedSource" in candidate.input):
            continue
        try:
            parent, core, snapshot, operation = _boundary(candidate.id, jobs, plans, lookup)
            _require_diagnostic_scope(core, snapshot)
            coordinator = jobs.get(_child_id(core.id))
            if coordinator is not None and (
                    coordinator.action != "provider_keyed_comprehensive_teardown"
                    or coordinator.target_id != parent.target_id
                    or coordinator.input.get("teardownParentId") != parent.id
                    or coordinator.input.get("scopeSnapshotId") != snapshot["snapshotId"]
                    or coordinator.status not in {"queued", "running"}):
                continue
            if operation == "provider_keyed_initial" and coordinator is None:
                proof = load_keyed_teardown_source(
                    parent.id, phase="pre_handoff", environment=environment,
                    state_root=state_root, job_repository=jobs, plan_repository=plans,
                )
                expected = ("failed_prebinding"
                            if snapshot.get("dnsCleanupManifest", {}).get("schema")
                               == "provider-keyed-empty-dns-prebinding-v1"
                            else "pending_terminal")
                if proof.variant != expected:
                    continue
            elif operation == "provider_keyed_teardown_fence":
                # A saved one-shot intent remains the child service's decision;
                # scheduling here does not authorize replay.
                if coordinator is None:
                    continue
            elif operation != "provider_keyed_initial":
                continue
            delay = 0.0
            if coordinator is not None and coordinator.input.get("claimExpiresAt"):
                expiry = datetime.fromisoformat(coordinator.input["claimExpiresAt"])
                instant = now()
                if expiry.tzinfo is None or instant.tzinfo is None:
                    continue
                delay = max(0.0, (expiry - instant).total_seconds())
            selected.append((parent.id, delay))
        except Exception:
            continue
    for parent_id, delay in selected:
        schedule(parent_id, delay)
    return [parent_id for parent_id, _delay in selected]


def _child(jobs, core_id: str, prefix: str):
    return jobs.get(f"job-{prefix}-{core_id.removeprefix('job-')}")


def _one_shot_status(jobs, core_id: str, prefix: str, action: str) -> str | None:
    child = _child(jobs, core_id, prefix)
    if child is None:
        return None
    if child.action != action or child.status != "succeeded":
        raise PendingKeyedDispatchAttention("one-shot cleanup child needs reconciliation")
    return child.status


def advance_pending_keyed_terminal(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    positive_control_ipv4: str, job_repository=None, plan_repository=None,
    lease_lookup=None,
    preview_provider: Callable = advance_pending_keyed_cleanup_to_preview,
    retire_group: Callable = advance_pending_keyed_cleanup_through_group_retirement,
    preview_core: Callable = preview_pending_keyed_oci_core_destroy,
    apply_core: Callable = apply_pending_keyed_oci_core_destroy,
    prove_core_absence: Callable = prove_pending_keyed_oci_core_destroy_absence,
    prove_negative: Callable = prove_pending_keyed_inspector_negative,
    retire_selector: Callable = retire_pending_digitalocean_selector,
    recognize_selector: Callable = recognize_pending_digitalocean_selector_retired,
    retire_inspector: Callable = retire_pending_linode_inspector,
    recognize_terminal: Callable = recognize_pending_linode_inspector_retired,
):
    """Advance one sealed pending teardown until terminal or visible attention.

    Existing children are consumed only through subsequent canonical services.
    A reserved but unfinished one-shot plan/apply is never invoked again. The
    negative control is supplied by an explicit reviewed caller, never guessed.
    """
    if environment != "devtest" or not isinstance(state_root, Path) or not state_root.is_absolute():
        raise PendingKeyedDispatchAttention("DevTest cleanup boundary is required")
    require_positive_control_ipv4(positive_control_ipv4)
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    lookup = lease_lookup or _db_lease_lookup
    common = {"environment": environment, "state_root": state_root,
              "job_repository": jobs, "plan_repository": plans, "lease_lookup": lookup}
    try:
        parent = jobs.get(teardown_parent_id)
        if parent is not None and parent.status == "succeeded":
            return recognize_terminal(teardown_parent_id, environment=environment,
                                      job_repository=jobs, plan_repository=plans,
                                      lease_lookup=lookup)
        parent, core, snapshot, operation = _boundary(teardown_parent_id, jobs, plans, lookup)
        coordinator = jobs.get(_child_id(core.id))
        if ("publishedSource" in parent.input or parent.target_id != core.input.get("engagementId")
                or snapshot.get("domainAssignments") != []
                or coordinator is not None and not (
                    coordinator.status == "running"
                    or coordinator.status == "queued" and coordinator.input.get("phase") == "queued"
                )):
            raise ValueError("pending diagnostic source differs")
        phase = coordinator.input.get("phase") if coordinator else None
        if phase in {None, "queued", "handoff_pending", "awaiting_inspector_preflight", "inspector_ready"}:
            # This stage refuses an existing uncertain provider apply child.
            if _one_shot_status(jobs, core.id, "provider-keyed-initial-destroy-apply",
                                "provider_keyed_initial_destroy_apply") is None:
                preview_provider(teardown_parent_id, **common)
        retire_group(teardown_parent_id, **common)
        # The core preview/apply are each one-shot. Once a child succeeds, the
        # next canonical stage validates its full journal and sealed artifact.
        if _one_shot_status(jobs, core.id, "provider-keyed-core-destroy-preview",
                            "provider_keyed_core_destroy_preview") is None:
            preview_core(teardown_parent_id, **common)
        if _one_shot_status(jobs, core.id, "provider-keyed-core-destroy-apply",
                            "provider_keyed_core_destroy_apply") is None:
            apply_core(teardown_parent_id, **common)
        prove_core_absence(teardown_parent_id, **common)
        prove_negative(
            teardown_parent_id, **common,
            positive_control={"id": "inspector-external-control", "type": "tcp",
                              "host": positive_control_ipv4, "port": 443},
        )
        selector = _child(jobs, core.id, "provider-keyed-selector-retirement")
        if selector is not None and selector.status == "succeeded":
            recognize_selector(teardown_parent_id, **common)
        else:
            # The selector service itself reconciles a durable DELETE intent
            # through GET. It never submits that DELETE a second time.
            retire_selector(teardown_parent_id, **common)
        return retire_inspector(teardown_parent_id, **common)
    except PendingKeyedDispatchAttention:
        raise
    except Exception:
        raise PendingKeyedDispatchAttention(
            "pending keyed cleanup stopped at its retained phase; inspect jobs before resuming"
        ) from None
