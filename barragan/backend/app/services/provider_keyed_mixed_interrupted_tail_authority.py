# Copyright (c) 2026, Oracle and/or its affiliates.
"""Fresh, read-only handoff from interrupted Sketch cleanup to the OCI tail.

This is a precondition for later engines, not a Terraform or provider GO gate.
The empty DigitalOcean selector remains an explicit later retirement obligation.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from app.services.provider_keyed_mixed_initial_apply_child import _child_id as apply_child_id
from app.services.provider_keyed_mixed_interrupted_cleanup import recognize_mixed_interrupted_sealed_plans
from app.services.provider_keyed_mixed_interrupted_destroy_child import _child_id as destroy_child_id
from app.services.provider_keyed_mixed_interrupted_destroy_plan import MixedInterruptedDestroyPlanSet
from app.services.provider_keyed_mixed_interrupted_dispatch import _workspace
from app.services.provider_keyed_mixed_interrupted_post_sketch_absence import (
    MixedInterruptedPostSketchAbsence, prove_mixed_interrupted_post_sketch_absence,
)
from app.services.provider_keyed_mixed_interrupted_source import MixedInterruptedReview
from app.services.provider_keyed_mixed_partial_apply_inventory import collect_provider_inventory_snapshot
from app.services.provider_keyed_mixed_zero_apply_teardown_source import (
    _core_inventory, _owned_inspector_records,
)
from app.services.provider_keyed_oci_core_state import OciCoreStateInventory
from app.services.sketch_state_workspaces import _default_state_root
from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup


class MixedInterruptedTailAuthorityAttention(ValueError):
    """Current two-provider absence, OCI state, or Inspector ownership differs."""


@dataclass(frozen=True)
class MixedInterruptedTailAuthority:
    parent: StoredJobRun
    post_sketch_absence: MixedInterruptedPostSketchAbsence
    core_job_id: str
    core_plan_id: str
    core_state_sha256: str
    core_inventory_sha256: str
    core_resource_ids: tuple[tuple[str, str], ...]
    owned_inspector_record_ids: tuple[str, str]
    selector_retirement_pending: bool


def audit_mixed_interrupted_tail_authority(
    initial: StoredJobRun, cleanup: StoredJobRun,
    review: MixedInterruptedReview, plans: MixedInterruptedDestroyPlanSet, *,
    environment: str, state_root: Path, core_state_root: Path,
    process_quiescent: Callable[[dict], bool],
    job_repository=None, plan_repository=None, provider_resource_repository=None,
    lease_lookup=None, credential_repository=None,
    inventory_collector: Callable = collect_provider_inventory_snapshot,
    core_inventory_reader: Callable = _core_inventory,
    inspector_record_reader: Callable = _owned_inspector_records,
) -> MixedInterruptedTailAuthority:
    """Re-read both providers while the exact teardown fence remains held."""
    try:
        if (environment != "devtest" or state_root != _default_state_root()
                or not state_root.is_absolute() or state_root.is_symlink()
                or state_root.resolve(strict=True) != state_root
                or core_state_root != DEFAULT_TERRAFORM_STATE_ROOT
                or not callable(process_quiescent)):
            raise ValueError("private interrupted tail boundary differs")
        recognize_mixed_interrupted_sealed_plans(cleanup, initial, review, plans)
        jobs = job_repository or SqlAlchemyJobRepository()
        plan_store = plan_repository or SqlAlchemyDeploymentPlanRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        lookup = lease_lookup or _db_lease_lookup
        core = jobs.get(review.core_job_id)
        plan = plan_store.get(cleanup.input["corePlanId"])
        order = review.ordered_providers
        originals = {provider: jobs.get(apply_child_id(review.core_job_id, provider))
                     for provider in order}
        destroys = {provider: jobs.get(destroy_child_id(review.core_job_id, provider))
                    for provider in order}
        if (jobs.get(initial.id) != initial or jobs.get(cleanup.id) != cleanup
                or core is None or plan is None or core.status != "succeeded"
                or core.input.get("corePlanId") != plan.id
                or plan.engagement_id != cleanup.target_id or plan.status != "applied"
                or plan.apply_job_id != core.id
                or plan.evidence.get("target", {}).get("name") != "barragan-testing"
                or lookup(cleanup.target_id) != (plan.id, "provider_keyed_teardown_fence")):
            raise ValueError("interrupted tail source or lease differs")

        generation = job_event_digest(cleanup.events) + ":" + plans.plan_set_sha256

        def fence() -> str:
            if (jobs.get(initial.id) != initial or jobs.get(cleanup.id) != cleanup
                    or jobs.get(core.id) != core or plan_store.get(plan.id) != plan
                    or lookup(cleanup.target_id) != (plan.id, "provider_keyed_teardown_fence")
                    or any(jobs.get(apply_child_id(review.core_job_id, provider))
                           != originals[provider]
                           or jobs.get(destroy_child_id(review.core_job_id, provider))
                           != destroys[provider] for provider in order)):
                raise ValueError("interrupted tail changed during provider read")
            return generation

        def all_quiescent() -> bool:
            for child in (*originals.values(), *destroys.values()):
                if child is None:
                    continue
                for event in child.events:
                    if event.message in {"mixed provider Apply command started before GO",
                                         "mixed provider destroy command started before GO"}:
                        data = event.data
                        if (type(data) is not dict or not {"bootId", "pid", "pgid", "startTicks"} <= set(data)
                                or process_quiescent({key: data[key] for key in (
                                    "bootId", "pid", "pgid", "startTicks")}) is not True):
                            return False
            return True

        snapshots = {}
        for provider in order:
            workspace = _workspace(initial, provider, state_root)
            phase_mode = "destroy_applied" if next(
                scope for scope in review.scopes if scope.provider == provider).kind in {
                    "partial", "full"} else "apply"
            snapshots[provider] = inventory_collector(
                initial, provider, workspace, fence=fence,
                process_quiescent=all_quiescent,
                credential_repository=credential_repository, phase_mode=phase_mode)
        absence = prove_mixed_interrupted_post_sketch_absence(
            initial, cleanup, review, plans, originals, destroys, snapshots,
            fence=fence, process_quiescent=process_quiescent)
        inventory = core_inventory_reader(core, plan, core_state_root)
        if (type(inventory) is not OciCoreStateInventory or not inventory.resources):
            raise ValueError("retained OCI inventory differs")
        inspector_ids = inspector_record_reader(cleanup.target_id, jobs, resources)
        if (type(inspector_ids) is not tuple or len(inspector_ids) != 2
                or len(set(inspector_ids)) != 2
                or any(type(value) is not str or not value for value in inspector_ids)):
            raise ValueError("retained Inspector ownership differs")
        if (fence() != generation or core_inventory_reader(core, plan, core_state_root) != inventory
                or inspector_record_reader(cleanup.target_id, jobs, resources) != inspector_ids):
            raise ValueError("interrupted tail state changed during audit")
        return MixedInterruptedTailAuthority(
            cleanup, absence, core.id, plan.id, inventory.raw_state_sha256,
            inventory.inventory_sha256,
            tuple(sorted((row.address, row.ocid) for row in inventory.resources)),
            inspector_ids,
            any(receipt.selector_retirement_pending for receipt in absence.receipts))
    except Exception:
        raise MixedInterruptedTailAuthorityAttention(
            "interrupted tail requires fresh exact Sketch absence, OCI and Inspector evidence") from None
