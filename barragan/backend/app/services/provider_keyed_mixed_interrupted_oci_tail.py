# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private OCI-tail authority bridge for a sealed interrupted mixed cleanup.

Current authority is valid only before OCI GO, while the applied core state
still exists. Post-GO absence must use the saved core Apply journal instead.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.services.provider_keyed_mixed_initial_plan_parent import _parent_id as initial_id
from app.services.provider_keyed_mixed_interrupted_cleanup import _parent_id as cleanup_id
from app.services.provider_keyed_mixed_interrupted_dispatch import (
    _default_quiescent, _saved_plans, _saved_review,
)
from app.services.provider_keyed_mixed_interrupted_tail_authority import (
    audit_mixed_interrupted_tail_authority,
)
from app.storage.job_repository import StoredJobRun


@dataclass(frozen=True)
class InterruptedHistoricalOciSource:
    core_state_sha256: str
    core_inventory_sha256: str
    owned_inspector_record_ids: tuple[str, str]


def stable_interrupted_oci_authority(value) -> tuple:
    """Identity of owned cleanup work; fresh account inventory is an observation.

    The underlying audit still performs complete fresh reads on every call.
    Unrelated account rows can change while Terraform plans or shows.
    """
    absence = value.post_sketch_absence
    return (
        value.parent, value.core_job_id, value.core_plan_id,
        value.core_state_sha256, value.core_inventory_sha256,
        value.core_resource_ids, value.owned_inspector_record_ids,
        value.selector_retirement_pending, absence.review_sha256,
        absence.plan_set_sha256,
        tuple((row.provider, row.scope_kind, row.scope_sha256,
               row.destroy_child_id, row.destroy_child_journal_sha256,
               row.before_state_sha256, row.after_state_sha256,
               row.lineage, row.before_serial, row.after_serial,
               row.verified_absent_ids, row.selector_retirement_pending)
              for row in absence.receipts),
    )


def audit_current_interrupted_oci_tail(
    engagement_id: str, core_job_id: str, *, environment: str,
    state_root: Path, core_state_root: Path, job_repository,
    plan_repository, lease_lookup, **dependencies,
):
    """Reopen the exact parent and re-read both providers under its fence."""
    initial = job_repository.get(initial_id(core_job_id))
    cleanup = job_repository.get(cleanup_id(core_job_id))
    if (initial is None or cleanup is None or initial.target_id != engagement_id
            or cleanup.target_id != engagement_id):
        raise ValueError("interrupted mixed OCI parent differs")
    review = _saved_review(cleanup)
    plans = _saved_plans(cleanup)
    return audit_mixed_interrupted_tail_authority(
        initial, cleanup, review, plans, environment=environment,
        state_root=state_root, core_state_root=core_state_root,
        process_quiescent=_default_quiescent,
        job_repository=job_repository, plan_repository=plan_repository,
        lease_lookup=lease_lookup, **dependencies)


def advance_mixed_interrupted_oci_core(
    engagement_id: str, core_job_id: str, *, environment: str,
    state_root: Path, core_state_root: Path, job_repository=None,
    plan_repository=None, lease_lookup=None, source_dependencies=None,
    preview_core=None, apply_core=None, prove_absence=None,
) -> StoredJobRun:
    """Run the existing three OCI children in order under one private action.

    A saved uncertain command child remains attention. The final absence
    reader always reopens the complete pre-GO journal and exact OCI IDs.
    """
    from app.services.provider_keyed_mixed_zero_apply_core_preview import (
        ACTION as PREVIEW_ACTION, _child_id as preview_id,
        preview_mixed_zero_apply_oci_core_destroy,
        queued_preview_restartable,
    )
    from app.services.provider_keyed_mixed_zero_apply_core_apply import (
        ACTION as APPLY_ACTION, _child_id as apply_id,
        apply_mixed_zero_apply_oci_core_destroy,
        precommand_apply_restartable, interrupted_show_restartable,
        interrupted_apply_no_go_restartable,
    )
    from app.services.provider_keyed_mixed_zero_apply_core_absence import (
        ACTION as ABSENCE_ACTION, prove_mixed_zero_apply_oci_core_absence,
    )
    from app.storage.job_repository import SqlAlchemyJobRepository
    from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
    from app.services.provider_keyed_runtime_preflight import _db_lease_lookup

    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    lookup = lease_lookup or _db_lease_lookup
    parent = jobs.get(cleanup_id(core_job_id))
    if (environment != "devtest" or parent is None
            or parent.action != "provider_keyed_mixed_interrupted_cleanup"
            or parent.target_id != engagement_id or parent.status != "queued"
            or lookup(engagement_id) != (parent.input.get("corePlanId"),
                                         "provider_keyed_teardown_fence")):
        raise ValueError("interrupted OCI cleanup fence differs")
    common = dict(environment=environment, state_root=state_root,
                  core_state_root=core_state_root, job_repository=jobs,
                  plan_repository=plans, lease_lookup=lookup, interrupted=True)
    preview = jobs.get(preview_id(core_job_id))
    if preview is None or preview.status != "succeeded":
        if preview is not None and not queued_preview_restartable(
                preview, parent, core_job_id,
                authority=audit_current_interrupted_oci_tail(
                    engagement_id, core_job_id, environment=environment,
                    state_root=state_root, core_state_root=core_state_root,
                    job_repository=jobs, plan_repository=plans,
                    lease_lookup=lookup, **dict(source_dependencies or {}))):
            raise ValueError("interrupted core preview needs exact reconciliation")
        preview = (preview_core or preview_mixed_zero_apply_oci_core_destroy)(
            engagement_id, core_job_id, **common,
            source_dependencies=source_dependencies)
    if preview.action != PREVIEW_ACTION or preview.status != "succeeded":
        raise ValueError("interrupted core preview is unproved")
    applied = jobs.get(apply_id(core_job_id))
    if applied is None or applied.status != "succeeded":
        if (applied is not None
                and not precommand_apply_restartable(
                    applied, parent, preview, core_job_id)
                and not interrupted_show_restartable(
                    applied, parent, preview, core_job_id)
                and not interrupted_apply_no_go_restartable(
                    applied, parent, preview, core_job_id)):
            raise ValueError("interrupted core Apply needs exact reconciliation")
        applied = (apply_core or apply_mixed_zero_apply_oci_core_destroy)(
            engagement_id, core_job_id, **common,
            source_dependencies=source_dependencies)
    if applied.action != APPLY_ACTION or applied.status != "succeeded":
        raise ValueError("interrupted core Apply is unproved")
    absent = (prove_absence or prove_mixed_zero_apply_oci_core_absence)(
        engagement_id, core_job_id, **common)
    if absent.action != ABSENCE_ACTION or absent.status != "succeeded":
        raise ValueError("interrupted OCI absence is unproved")
    return absent
