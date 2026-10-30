# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only published mixed handoff after both exact provider receipts.

OCI and Inspector engines must independently reopen this authority before
their own one-shot writes. This reader itself executes GETs only.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id, _prior_workspace, recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_partial_apply_inventory import collect_provider_inventory_snapshot
from app.services.provider_keyed_mixed_published_absence import (
    PublishedMixedProviderAbsenceReceipt, prove_published_mixed_both_absent,
)
from app.services.provider_keyed_mixed_published_destroy_child import child_id
from app.services.provider_keyed_mixed_published_first_absence_worker import _quiescent
from app.services.provider_keyed_mixed_published_second_absence_worker import _second_source
from app.services.provider_keyed_mixed_zero_apply_teardown_source import (
    _core_inventory, _owned_inspector_records,
)
from app.services.provider_keyed_oci_core_state import OciCoreStateInventory
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.domain_repository import SqlAlchemyDomainRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


class PublishedMixedTailAuthorityAttention(ValueError):
    """Published provider/core/Inspector handoff is not fully authenticated."""


@dataclass(frozen=True)
class PublishedMixedTailAuthority:
    parent: StoredJobRun
    provider_receipts: tuple[PublishedMixedProviderAbsenceReceipt,
                             PublishedMixedProviderAbsenceReceipt]
    core_job_id: str
    core_plan_id: str
    core_state_sha256: str
    core_inventory_sha256: str
    core_resource_ids: tuple[tuple[str, str], ...]
    owned_inspector_record_ids: tuple[str, str]
    selector_retirement_pending: bool


def stable_published_mixed_tail_authority(value: PublishedMixedTailAuthority) -> tuple:
    """Owned identity; fresh unrelated provider account rows are observations."""
    return (value.parent, value.core_job_id, value.core_plan_id,
            value.core_state_sha256, value.core_inventory_sha256,
            value.core_resource_ids, value.owned_inspector_record_ids,
            value.selector_retirement_pending,
            tuple((receipt.provider, receipt.scope_sha256,
                   receipt.plan_set_sha256, receipt.destroy_child_id,
                   receipt.destroy_child_journal_sha256,
                   receipt.before_state_sha256, receipt.after_state_sha256,
                   receipt.lineage, receipt.before_serial,
                   receipt.after_serial, receipt.verified_absent_ids,
                   receipt.selector_retirement_pending)
                  for receipt in value.provider_receipts))


def audit_published_mixed_tail_authority(
    cleanup_id: str, *, environment: str,
    state_root: Path | None = None,
    core_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    process_quiescent=_quiescent,
    job_repository=None, plan_repository=None, sketch_repository=None,
    domain_repository=None, provider_resource_repository=None,
    credential_repository=None, lease_lookup=None,
    inventory_collector=collect_provider_inventory_snapshot,
    core_inventory_reader=_core_inventory,
    inspector_record_reader=_owned_inspector_records,
) -> PublishedMixedTailAuthority:
    """Reopen terminal two-provider receipts and retained OCI/Inspector facts."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans_repo = plan_repository or SqlAlchemyDeploymentPlanRepository()
    sketches = sketch_repository or SqlAlchemySketchChainRepository()
    domains = domain_repository or SqlAlchemyDomainRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        from app.services.provider_keyed_host_proof_verdicts import host_proof_verdict_scope
        from app.services.provider_keyed_readonly_verification import readonly_verification_scope
        with host_proof_verdict_scope() as verdicts, readonly_verification_scope() as commands:
            actual_root = _default_state_root()
            if (environment != "devtest" or state_root not in {None, actual_root}
                    or not actual_root.is_absolute() or actual_root.is_symlink()
                    or actual_root.resolve(strict=True) != actual_root
                    or core_state_root != DEFAULT_TERRAFORM_STATE_ROOT
                    or not callable(process_quiescent)):
                raise ValueError("published tail environment or root differs")
            # Prime the exact pure proof inputs before repeated GET fences. All
            # authority rows and safe bytes are still reread by every fence.
            from app.services.provider_keyed_mixed_published_teardown_checkpoint import saved_published_mixed_initial_review
            from app.services.provider_keyed_mixed_published_teardown_authority import PublishedSixTeardownSource, six_historical_rows_sha256
            saved_review = saved_published_mixed_initial_review(jobs.get(cleanup_id))
            if type(saved_review.source) is PublishedSixTeardownSource:
                if six_historical_rows_sha256(saved_review, jobs=jobs, plans=plans_repo, sketches=sketches) != saved_review.historical_rows_sha256:
                    raise ValueError("published tail historical source changed")
                verdicts.require_hits_only()
                commands.require_hits_only()
            (cleanup, initial, review, plans, second, second_workspace, second_child,
             scope, name, fence, _set_current) = _second_source(
                cleanup_id, jobs=jobs, lookup=lookup, plans_repo=plans_repo,
                sketches=sketches, domains=domains, resources=resources,
                core_state_root=core_state_root, process_quiescent=process_quiescent)
            first = review.source.ordered_providers[0]
            first_child = jobs.get(child_id(review.source.core_job_id, first))
            originals = {provider: jobs.get(_child_id(review.source.core_job_id, provider))
                         for provider in review.source.ordered_providers}
            first_workspace = _prior_workspace(
                initial, first, recognize_mixed_initial_apply_terminal(
                    originals[first], initial, first))
            if str(first_workspace.path) != review.provider_scopes[0]["workspace"]:
                raise ValueError("published tail first workspace changed")
            children = {first: first_child, second: second_child}
            workspaces = {first: first_workspace, second: second_workspace}
            generation = fence()
            snapshots = {}
            for provider in review.source.ordered_providers:
                identity = children[provider].events[4].data
                def quiet(identity=identity) -> bool:
                    return process_quiescent(identity) is True
                snapshots[provider] = inventory_collector(
                    initial, provider, workspaces[provider], fence=fence,
                    process_quiescent=quiet, credential_repository=credentials,
                    phase_mode="destroy_applied")
                if fence() != generation or not quiet():
                    raise ValueError("published tail changed during provider GET")
            receipts = prove_published_mixed_both_absent(
                initial, cleanup, review, plans, children, snapshots, scope, name,
                fence=fence, process_quiescent=process_quiescent)
            core = jobs.get(review.source.core_job_id)
            plan = plans_repo.get(review.source.core_plan_id)
            if (core is None or plan is None or core.status != "succeeded"
                    or core.input.get("corePlanId") != plan.id
                    or plan.engagement_id != cleanup.target_id
                    or plan.status != "applied" or plan.apply_job_id != core.id
                    or plan.evidence.get("target", {}).get("name") != "barragan-testing"):
                raise ValueError("published retained OCI plan changed")
            inventory = core_inventory_reader(core, plan, core_state_root)
            inspector_ids = inspector_record_reader(cleanup.target_id, jobs, resources)
            if (type(inventory) is not OciCoreStateInventory or not inventory.resources
                    or type(inspector_ids) is not tuple or len(inspector_ids) != 2
                    or len(set(inspector_ids)) != 2
                    or any(type(value) is not str or not value
                           for value in inspector_ids)
                    or fence() != generation
                    or core_inventory_reader(core, plan, core_state_root) != inventory
                    or inspector_record_reader(cleanup.target_id, jobs, resources)
                       != inspector_ids):
                raise ValueError("published OCI/Inspector inventory changed during audit")
            return PublishedMixedTailAuthority(
                cleanup, receipts, core.id, plan.id,
                inventory.raw_state_sha256, inventory.inventory_sha256,
                tuple(sorted((row.address, row.ocid) for row in inventory.resources)),
                inspector_ids, any(row.selector_retirement_pending for row in receipts))
    except Exception:
        raise PublishedMixedTailAuthorityAttention(
            "published tail requires exact provider, OCI and Inspector evidence") from None
