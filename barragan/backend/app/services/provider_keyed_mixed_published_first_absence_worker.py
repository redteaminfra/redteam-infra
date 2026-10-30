# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-replay result and exact absence handoff for published mixed provider 1.

Only the first provider is handled here. This private worker never issues a
Terraform or provider write; HTTP Start remains closed until both providers
and the core/Inspector tail have a reviewed coordinator.
"""

from __future__ import annotations

from app.services.provider_keyed_runtime_preflight import reviewed_mixed_chain_rows

from datetime import datetime, timedelta, timezone
import fcntl
import json
import os
from pathlib import Path
import stat
from uuid import uuid4

from app.domain import JobEvent
from app.services.core_ssh import active_core_connection_details
from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.services.provider_keyed_initial_destroy_pre_go_recovery import _process_quiescent
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id, _prior_workspace, recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_initial_bootstrap import _worker_id
from app.services.provider_keyed_mixed_initial_host_binding import _binding_child_id
from app.services.provider_keyed_mixed_interrupted_destroy_go import _empty_state
from app.services.provider_keyed_mixed_interrupted_dispatch import _core_inspector_scope
from app.services.provider_keyed_mixed_partial_apply_inventory import collect_provider_inventory_snapshot
from app.services.provider_keyed_mixed_published_absence import (
    propose_published_mixed_first_absence_event,
    prove_published_mixed_provider_absence,
)
from app.services.provider_keyed_mixed_published_destroy_child import (
    child_id, recognize_published_mixed_destroy_child,
)
from app.services.provider_keyed_mixed_published_teardown_authority import historical_published_mixed_rows_sha256
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    recognize_published_mixed_plans_sealed, saved_published_mixed_destroy_plans,
    saved_published_mixed_initial_review,
)
from app.services.provider_keyed_mixed_published_teardown_collector import _empty_owned_bindings
from app.services.provider_keyed_mixed_strict_host_receipt import child_id as proof_child_id
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_sketch import SCHEMA, _write_json
from app.services.provider_keyed_mixed_published_teardown_authority import (
    PublishedSixTeardownSource, six_historical_rows_sha256,
)

from app.services.provider_keyed_mixed_published_binding_manifest import require_published_bindings_unchanged

from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.domain_repository import SqlAlchemyDomainRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


class PublishedMixedFirstAbsenceAttention(ValueError):
    """First-provider result or absence needs exact review, never replay."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(at: str) -> str:
    return (datetime.fromisoformat(at) + timedelta(minutes=10)).isoformat()


def _quiescent(identity: dict) -> bool:
    return _process_quiescent(identity["bootId"], identity["pid"],
                              identity["pgid"], identity["startTicks"])


def _first_source(cleanup_id: str, *, jobs, lookup, plans_repo, sketches,
                  domains, resources, core_state_root, process_quiescent):
    cleanup = jobs.get(cleanup_id)
    review = saved_published_mixed_initial_review(cleanup)
    plans = saved_published_mixed_destroy_plans(cleanup)
    scope = cleanup.input["reviewScope"]
    name = cleanup.input["engagementName"]
    recognize_published_mixed_plans_sealed(cleanup, review, plans, scope, name)
    source = review.source
    first = source.ordered_providers[0]
    initial = jobs.get(source.parent_job_id)
    current = jobs.get(child_id(source.core_job_id, first))
    if (initial is None or current is None
            or core_state_root != DEFAULT_TERRAFORM_STATE_ROOT):
        raise ValueError("published first absence source is incomplete")
    lease = (source.core_plan_id, "provider_keyed_teardown_fence")
    generation = f"{cleanup.id}:{plans.plan_set_sha256}"

    def historical() -> bool:
        if type(source) is PublishedSixTeardownSource:
            return six_historical_rows_sha256(
                review, jobs=jobs, plans=plans_repo, sketches=sketches) == review.historical_rows_sha256
        core = jobs.get(source.core_job_id)
        plan = plans_repo.get(source.core_plan_id)
        binding = jobs.get(_binding_child_id(source.core_job_id))
        bootstrap = jobs.get(_worker_id(source.core_job_id))
        proof = jobs.get(proof_child_id(source.core_job_id))
        children = {provider: jobs.get(_child_id(source.core_job_id, provider))
                    for provider in source.ordered_providers}
        durable = sketches.list_for_engagement(source.engagement_id)
        chains = {row.chain_id: row for row in reviewed_mixed_chain_rows(
            durable, source.chain_ids, source.engagement_id)}
        if (core is None or plan is None or binding is None or bootstrap is None
                or proof is None or any(row is None for row in children.values())
                or set(chains) != set(source.chain_ids)
                or active_core_connection_details(jobs, source.engagement_id)[0]
                   != source.core_job_id):
            return False
        return historical_published_mixed_rows_sha256(
            parent=jobs.get(initial.id), core=core, plan=plan, binding=binding,
            bootstrap=bootstrap, proof_child=proof, apply_children=children,
            chains=chains, failed_append_recovery=review.failed_append_recovery, jobs=jobs) == review.historical_rows_sha256

    def fence() -> str:
        core = jobs.get(source.core_job_id)
        if (lookup(source.engagement_id) != lease
                or jobs.get(cleanup.id) != cleanup or jobs.get(initial.id) != initial
                or jobs.get(current.id) != current or not historical()
                or core is None
                or _core_inspector_scope(
                    core, jobs=jobs, core_state_root=core_state_root,
                    plan_repository=plans_repo,
                    provider_resource_repository=resources) != scope
                or require_published_bindings_unchanged(review, jobs, domains)
                   != {kind: () for kind in (
                       "channels", "domains", "certificates", "sites")}):
            raise ValueError("published first absence source fence changed")
        return generation

    first_apply = jobs.get(_child_id(source.core_job_id, first))
    terminal = recognize_mixed_initial_apply_terminal(first_apply, initial, first)
    workspace = _prior_workspace(initial, first, terminal)
    if str(workspace.path) != review.provider_scopes[0]["workspace"]:
        raise ValueError("published first absence workspace changed")
    fence()

    def set_current(value) -> None:
        nonlocal current
        current = value

    return cleanup, initial, review, plans, first, workspace, current, scope, name, fence, set_current


def _claim(jobs, current, *, set_current, fence):
    owner, token = f"mixed-published-absence-{uuid4().hex}", uuid4().hex
    at = _now()
    claimed = jobs.claim_lease(
        current.id, owner=owner, token=token, claimed_at=at,
        expires_at=_later(at), eligible_statuses={"running"})
    if claimed is None or claimed.events != current.events:
        raise ValueError("published first absence claim unavailable")
    set_current(claimed)
    fence()
    return claimed, owner, token


def _reconcile_published_mixed_provider_result(
    cleanup_id: str, *, job_repository=None, lease_lookup=None,
    plan_repository=None, sketch_repository=None, domain_repository=None,
    provider_resource_repository=None,
    core_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    process_quiescent=_quiescent,
    source_loader=_first_source,
):
    """Finish a persisted rc=0 result without issuing Terraform again."""
    jobs = job_repository or SqlAlchemyJobRepository()
    try:
        (cleanup, initial, review, plans, first, workspace, child, scope, name,
         fence, set_current) = source_loader(
            cleanup_id, jobs=jobs, lookup=lease_lookup or _db_lease_lookup,
            plans_repo=plan_repository or SqlAlchemyDeploymentPlanRepository(),
            sketches=sketch_repository or SqlAlchemySketchChainRepository(),
            domains=domain_repository or SqlAlchemyDomainRepository(),
            resources=provider_resource_repository or SqlAlchemyProviderResourceRepository(),
            core_state_root=core_state_root, process_quiescent=process_quiescent)
        phase = recognize_published_mixed_destroy_child(
            child, cleanup, review, plans, first, scope, name)
        if phase in {"awaiting_absence", "absence_proved"}:
            return child
        if phase != "result":
            raise ValueError("published first command result is not proved")
        identity = child.events[4].data
        if process_quiescent(identity) is not True:
            raise ValueError("published first command is not quiescent")
        root = workspace.path
        lock_path = root / f".barragan-{first}-plan.lock"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "r+b") as lock:
            info = os.fstat(lock.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise ValueError("published first plan lock changed")
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                if (lock_path.is_symlink() or lock_path.stat().st_ino != info.st_ino
                        or fence() != f"{cleanup.id}:{plans.plan_set_sha256}"):
                    raise ValueError("published first plan lock or source changed")
                plan = plans.plans[review.source.ordered_providers.index(first)]
                _empty_state(workspace.state_path, plan.state_lineage,
                             plan.state_serial)
                phase_path = root / ".barragan-apply-phase.json"
                marker = (json.loads(phase_path.read_text())
                          if not phase_path.is_symlink() else None)
                if marker not in ({"schema": SCHEMA, "phase": "destroy_started"},
                                  {"schema": SCHEMA, "phase": "destroy_applied"}):
                    raise ValueError("published first phase marker differs")
                child, owner, token = _claim(
                    jobs, child, set_current=set_current, fence=fence)
                if process_quiescent(identity) is not True:
                    raise ValueError("published first process changed after claim")
                if marker["phase"] == "destroy_started":
                    _write_json(phase_path, {"schema": SCHEMA,
                                             "phase": "destroy_applied"})
                fence()
                at = _now()
                updated = jobs.append_event_if_running_claimed(
                    child, owner=owner, token=token,
                    expected_event_digest=job_event_digest(child.events),
                    heartbeat_at=at, expires_at=_later(at),
                    event=JobEvent(7, "info",
                        "published mixed provider awaiting exact absence",
                        {"commandResultSequence": 6}))
                if updated is None:
                    raise ValueError("published first result CAS changed")
                set_current(updated)
                if (recognize_published_mixed_destroy_child(
                        updated, cleanup, review, plans, first, scope, name)
                        != "awaiting_absence"):
                    raise ValueError("published first result journal changed")
                handoff_at = _now()
                handed_off = jobs.renew_lease(
                    updated.id, owner=owner, token=token,
                    heartbeat_at=handoff_at, expires_at=handoff_at)
                if (handed_off is None or handed_off.events != updated.events
                        or handed_off.input.get("claimOwner") != owner
                        or handed_off.input.get("claimToken") != token):
                    raise ValueError("published first result claim handoff changed")
                set_current(handed_off)
                return handed_off
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except Exception:
        raise PublishedMixedFirstAbsenceAttention(
            "published provider rc0 result needs exact no-replay review") from None


def reconcile_published_mixed_first_result(cleanup_id: str, **kwargs):
    """Recover the first provider's saved rc0 result without replay."""
    return _reconcile_published_mixed_provider_result(
        cleanup_id, source_loader=_first_source, **kwargs)


def finish_published_mixed_first_absence(
    cleanup_id: str, *, job_repository=None, lease_lookup=None,
    plan_repository=None, sketch_repository=None, domain_repository=None,
    provider_resource_repository=None, credential_repository=None,
    core_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    process_quiescent=_quiescent,
    snapshot_collector=collect_provider_inventory_snapshot,
):
    """Persist exact provider-1 absence in event 8 under its worker claim."""
    jobs = job_repository or SqlAlchemyJobRepository()
    try:
        child = reconcile_published_mixed_first_result(
            cleanup_id, job_repository=jobs, lease_lookup=lease_lookup,
            plan_repository=plan_repository, sketch_repository=sketch_repository,
            domain_repository=domain_repository,
            provider_resource_repository=provider_resource_repository,
            core_state_root=core_state_root, process_quiescent=process_quiescent)
        (cleanup, initial, review, plans, first, workspace, current, scope, name,
         fence, set_current) = _first_source(
            cleanup_id, jobs=jobs, lookup=lease_lookup or _db_lease_lookup,
            plans_repo=plan_repository or SqlAlchemyDeploymentPlanRepository(),
            sketches=sketch_repository or SqlAlchemySketchChainRepository(),
            domains=domain_repository or SqlAlchemyDomainRepository(),
            resources=provider_resource_repository or SqlAlchemyProviderResourceRepository(),
            core_state_root=core_state_root, process_quiescent=process_quiescent)
        if current != child:
            raise ValueError("published first absence result changed")
        phase = recognize_published_mixed_destroy_child(
            current, cleanup, review, plans, first, scope, name)
        if phase == "absence_proved":
            return current
        if phase != "awaiting_absence":
            raise ValueError("published first absence phase changed")
        identity = current.events[4].data
        def quiescent() -> bool:
            return process_quiescent(identity) is True
        generation = fence()
        snapshot = snapshot_collector(
            initial, first, workspace, fence=fence, process_quiescent=quiescent,
            credential_repository=credential_repository or SqlAlchemyCredentialRepository(),
            phase_mode="destroy_applied")
        if fence() != generation or not quiescent():
            raise ValueError("published first absence changed during provider GET")
        receipt = prove_published_mixed_provider_absence(
            initial, cleanup, review, plans, first, current, snapshot,
            scope, name, fence=fence, process_quiescent=process_quiescent)
        current, owner, token = _claim(
            jobs, current, set_current=set_current, fence=fence)
        if not quiescent() or fence() != generation:
            raise ValueError("published first absence changed before finish")
        # The claim changes input, not the exact seven-event result journal.
        receipt = prove_published_mixed_provider_absence(
            initial, cleanup, review, plans, first, current, snapshot,
            scope, name, fence=fence, process_quiescent=process_quiescent)
        event = propose_published_mixed_first_absence_event(current, receipt)
        saved = jobs.finish_if_running_claimed(
            current, owner=owner, token=token,
            expected_event_digest=job_event_digest(current.events),
            status="succeeded", finished_at=_now(), event=event)
        if (saved is None or recognize_published_mixed_destroy_child(
                saved, cleanup, review, plans, first, scope, name)
                != "absence_proved"):
            raise ValueError("published first absence finish CAS changed")
        return saved
    except Exception:
        raise PublishedMixedFirstAbsenceAttention(
            "published first exact provider absence needs review") from None
