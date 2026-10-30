# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-replay provider-2 result and exact two-provider absence handoff."""

from __future__ import annotations

from pathlib import Path

from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id, _prior_workspace, recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_partial_apply_inventory import collect_provider_inventory_snapshot
from app.services.provider_keyed_mixed_published_absence import (
    propose_published_mixed_second_absence_event,
    prove_published_mixed_both_absent,
)
from app.services.provider_keyed_mixed_published_destroy_child import (
    child_id, recognize_published_mixed_destroy_child,
)
from app.services.provider_keyed_mixed_published_first_absence_worker import (
    PublishedMixedFirstAbsenceAttention, _claim, _first_source, _now,
    _quiescent, _reconcile_published_mixed_provider_result,
)
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.domain_repository import SqlAlchemyDomainRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup


class PublishedMixedSecondAbsenceAttention(ValueError):
    """Provider 2 lacks a full exact two-provider absence handoff."""


def _second_source(cleanup_id: str, *, jobs, lookup, plans_repo, sketches,
                   domains, resources, core_state_root, process_quiescent):
    (cleanup, initial, review, plans, first, first_workspace, first_child,
     scope, name, first_fence, _set_first) = _first_source(
        cleanup_id, jobs=jobs, lookup=lookup, plans_repo=plans_repo,
        sketches=sketches, domains=domains, resources=resources,
        core_state_root=core_state_root, process_quiescent=process_quiescent)
    if (recognize_published_mixed_destroy_child(
            first_child, cleanup, review, plans, first, scope, name)
            != "absence_proved"):
        raise ValueError("published second provider lacks first terminal receipt")
    first_receipt_sha = first_child.events[7].data["receiptSha256"]
    second = review.source.ordered_providers[1]
    current = jobs.get(child_id(review.source.core_job_id, second))
    if (current is None or current.input.get("priorAbsenceReceiptSha256")
            != first_receipt_sha):
        raise ValueError("published second child is not bound to first receipt")
    original = jobs.get(_child_id(review.source.core_job_id, second))
    workspace = _prior_workspace(
        initial, second, recognize_mixed_initial_apply_terminal(
            original, initial, second))
    if str(workspace.path) != review.provider_scopes[1]["workspace"]:
        raise ValueError("published second workspace changed")

    def fence() -> str:
        generation = first_fence()
        if jobs.get(current.id) != current:
            raise ValueError("published second child changed during provider GET")
        return generation

    def set_current(value) -> None:
        nonlocal current
        current = value

    fence()
    return (cleanup, initial, review, plans, second, workspace, current,
            scope, name, fence, set_current)


def reconcile_published_mixed_second_result(cleanup_id: str, **kwargs):
    """Advance a durable provider-2 rc0 result without replaying Terraform."""
    try:
        return _reconcile_published_mixed_provider_result(
            cleanup_id, source_loader=_second_source, **kwargs)
    except PublishedMixedFirstAbsenceAttention:
        raise PublishedMixedSecondAbsenceAttention(
            "published second rc0 result needs exact no-replay review") from None


def finish_published_mixed_second_absence(
    cleanup_id: str, *, job_repository=None, lease_lookup=None,
    plan_repository=None, sketch_repository=None, domain_repository=None,
    provider_resource_repository=None, credential_repository=None,
    core_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    process_quiescent=_quiescent,
    snapshot_collector=collect_provider_inventory_snapshot,
):
    """Prove both original provider IDs absent and finish provider 2 once."""
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    plan_rows = plan_repository or SqlAlchemyDeploymentPlanRepository()
    sketches = sketch_repository or SqlAlchemySketchChainRepository()
    domains = domain_repository or SqlAlchemyDomainRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    try:
        child = reconcile_published_mixed_second_result(
            cleanup_id, job_repository=jobs, lease_lookup=lookup,
            plan_repository=plan_rows, sketch_repository=sketches,
            domain_repository=domains, provider_resource_repository=resources,
            core_state_root=core_state_root, process_quiescent=process_quiescent)
        (cleanup, initial, review, plans, second, second_workspace, current,
         scope, name, fence, set_current) = _second_source(
            cleanup_id, jobs=jobs, lookup=lookup, plans_repo=plan_rows,
            sketches=sketches, domains=domains, resources=resources,
            core_state_root=core_state_root, process_quiescent=process_quiescent)
        if current != child:
            raise ValueError("published second result changed")
        phase = recognize_published_mixed_destroy_child(
            current, cleanup, review, plans, second, scope, name)
        if phase == "absence_proved":
            return current
        if phase != "awaiting_absence":
            raise ValueError("published second is not awaiting absence")
        first = review.source.ordered_providers[0]
        first_child = jobs.get(child_id(review.source.core_job_id, first))
        first_original = jobs.get(_child_id(review.source.core_job_id, first))
        first_workspace = _prior_workspace(
            initial, first, recognize_mixed_initial_apply_terminal(
                first_original, initial, first))
        if (str(first_workspace.path) != review.provider_scopes[0]["workspace"]
                or first_child.events[7].data["receiptSha256"]
                   != current.input["priorAbsenceReceiptSha256"]):
            raise ValueError("published first receipt or workspace changed")
        children = {first: first_child, second: current}
        workspaces = {first: first_workspace, second: second_workspace}
        snapshots = {}
        generation = fence()
        for provider in review.source.ordered_providers:
            identity = children[provider].events[4].data
            def quiet(identity=identity) -> bool:
                return process_quiescent(identity) is True
            snapshots[provider] = snapshot_collector(
                initial, provider, workspaces[provider],
                fence=fence, process_quiescent=quiet,
                credential_repository=credentials, phase_mode="destroy_applied")
            if fence() != generation or not quiet():
                raise ValueError("published provider absence changed during GET")
        receipts = prove_published_mixed_both_absent(
            initial, cleanup, review, plans, children, snapshots, scope, name,
            fence=fence, process_quiescent=process_quiescent)
        current, owner, token = _claim(
            jobs, current, set_current=set_current, fence=fence)
        children[second] = current
        if fence() != generation:
            raise ValueError("published two-provider absence changed before finish")
        receipts = prove_published_mixed_both_absent(
            initial, cleanup, review, plans, children, snapshots, scope, name,
            fence=fence, process_quiescent=process_quiescent)
        event = propose_published_mixed_second_absence_event(
            current, receipts[1], receipts[0])
        saved = jobs.finish_if_running_claimed(
            current, owner=owner, token=token,
            expected_event_digest=job_event_digest(current.events),
            status="succeeded", finished_at=_now(), event=event)
        if (saved is None or recognize_published_mixed_destroy_child(
                saved, cleanup, review, plans, second, scope, name)
                != "absence_proved"):
            raise ValueError("published second absence finish CAS changed")
        return saved
    except Exception:
        raise PublishedMixedSecondAbsenceAttention(
            "published exact two-provider absence needs review") from None
