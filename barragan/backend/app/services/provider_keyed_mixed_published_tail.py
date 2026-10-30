# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private OCI and Inspector continuation for a published mixed teardown.

Each child owns its irreversible command and recovery journal. This module
only orders the existing children; it never retries an uncertain write.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable
import time

from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    ACTION as PARENT_ACTION, parent_id, saved_published_mixed_initial_review,
    saved_published_mixed_destroy_plans, recognize_published_mixed_plans_sealed,
)
from app.services.provider_keyed_mixed_zero_apply_core_preview import (
    ACTION as PREVIEW_ACTION, _child_id as preview_id,
    preview_mixed_zero_apply_oci_core_destroy,
)
from app.services.provider_keyed_mixed_zero_apply_core_apply import (
    ACTION as APPLY_ACTION, _child_id as apply_id,
    apply_mixed_zero_apply_oci_core_destroy,
)
from app.services.provider_keyed_mixed_zero_apply_core_absence import (
    ACTION as ABSENCE_ACTION, prove_mixed_zero_apply_oci_core_absence,
)
from app.services.provider_keyed_mixed_zero_apply_inspector_negative import (
    _MAX_ATTEMPTS as negative_max_attempts, _attempts as negative_attempts,
    latest_negative_attempt, MixedZeroApplyInspectorNegativeAttention,
    prove_mixed_zero_apply_inspector_negative,
)
from app.services.provider_keyed_mixed_published_selector_retirement import (
    retire_published_mixed_selector,
)
from app.services.provider_keyed_mixed_zero_apply_inspector_retirement import (
    PUBLISHED_ACTION as RETIRE_ACTION, _published_child_id as retirement_id,
    retire_mixed_zero_apply_inspector,
)
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun


def _parent(jobs, engagement_id: str, core_job_id: str) -> StoredJobRun:
    parent = jobs.get(parent_id(core_job_id))
    if (parent is None or parent.action != PARENT_ACTION
            or parent.target_id != engagement_id or parent.status != "queued"):
        raise ValueError("published mixed teardown parent differs")
    review = saved_published_mixed_initial_review(parent)
    plans = saved_published_mixed_destroy_plans(parent)
    recognize_published_mixed_plans_sealed(
        parent, review, plans, parent.input["reviewScope"],
        parent.input["engagementName"])
    return parent


def advance_published_mixed_oci_core(
    engagement_id: str, core_job_id: str, *, environment: str,
    state_root: Path, core_state_root: Path, job_repository=None,
    preview_core: Callable = preview_mixed_zero_apply_oci_core_destroy,
    apply_core: Callable = apply_mixed_zero_apply_oci_core_destroy,
    prove_absence: Callable = prove_mixed_zero_apply_oci_core_absence,
) -> StoredJobRun:
    """Finish the three OCI children after both sketch absence receipts."""
    if environment != "devtest":
        raise ValueError("published mixed OCI continuation is DevTest-only")
    jobs = job_repository or SqlAlchemyJobRepository()
    parent = _parent(jobs, engagement_id, core_job_id)
    common = dict(environment=environment, state_root=state_root,
                  core_state_root=core_state_root, job_repository=jobs,
                  published=True)
    bindings = {}
    if getattr(parent, "input", {}).get("sourceKind") in ("published-six-node-v1", "unpublished-six-node-cleanup-v1"):
        from app.services.provider_keyed_mixed_published_binding_manifest import require_published_bindings_unchanged
        from app.storage.domain_repository import SqlAlchemyDomainRepository
        review = saved_published_mixed_initial_review(parent)
        bindings["binding_check"] = lambda _: require_published_bindings_unchanged(
            review, jobs, SqlAlchemyDomainRepository(), require_dns_absent=True)
    preview = jobs.get(preview_id(core_job_id))
    if preview is None or preview.status != "succeeded":
        preview = preview_core(engagement_id, core_job_id, **common, **bindings)
    if preview.action != PREVIEW_ACTION or preview.status != "succeeded":
        raise ValueError("published mixed OCI preview is unproved")
    applied = jobs.get(apply_id(core_job_id))
    if applied is None or applied.status != "succeeded":
        # The Apply engine alone decides whether a pre-GO child can resume.
        # A saved GO or uncertain result remains attention, not a new Apply.
        applied = apply_core(engagement_id, core_job_id, **common, **bindings)
    if applied.action != APPLY_ACTION or applied.status != "succeeded":
        raise ValueError("published mixed OCI Apply is unproved")
    absent = prove_absence(engagement_id, core_job_id, **common)
    if absent.action != ABSENCE_ACTION or absent.status != "succeeded":
        raise ValueError("published mixed OCI absence is unproved")
    return absent


def advance_published_mixed_inspector_tail(
    engagement_id: str, core_job_id: str, *, environment: str,
    state_root: Path, core_state_root: Path, positive_control: dict,
    job_repository=None,
    negative_prover: Callable = prove_mixed_zero_apply_inspector_negative,
    selector_retire: Callable = retire_published_mixed_selector,
    inspector_retire: Callable = retire_mixed_zero_apply_inspector,
    read_only_wait: Callable[[float], None] = time.sleep,
) -> StoredJobRun:
    """Prove public absence, retire the selector, then retire Inspector."""
    if environment != "devtest":
        raise ValueError("published mixed Inspector continuation is DevTest-only")
    jobs = job_repository or SqlAlchemyJobRepository()
    parent = _parent(jobs, engagement_id, core_job_id)
    common = dict(environment=environment, state_root=state_root,
                  core_state_root=core_state_root, job_repository=jobs,
                  published=True)
    prior = jobs.get(retirement_id(core_job_id))
    if prior is not None and prior.status == "succeeded":
        negative = jobs.get(prior.input.get("negativeJobId"))
        if (prior.action != RETIRE_ACTION or negative is None
                or negative.input.get("positiveControl") != positive_control):
            raise ValueError("published Inspector terminal lineage differs")
        # The retirement recognizer uses historical receipts after the owned
        # Inspector record is gone; do not repeat a public probe.
        retired = inspector_retire(engagement_id, core_job_id, **common)
        if retired != prior:
            raise ValueError("published Inspector retirement receipt changed")
        return retired
    prior_failed = None
    for _ in range(negative_max_attempts):
        try:
            negative = negative_prover(
                engagement_id, core_job_id,
                positive_control=positive_control, **common)
            break
        except MixedZeroApplyInspectorNegativeAttention:
            failed = latest_negative_attempt(jobs, engagement_id, core_job_id)
            if (failed is None or failed.status != "failed"
                    or failed.id == prior_failed
                    or len(negative_attempts(jobs, engagement_id, core_job_id))
                       >= negative_max_attempts
                    or jobs.get(parent.id) != parent):
                raise
            prior_failed = failed.id
            read_only_wait(2)
    else:
        raise ValueError("published Inspector read-only retry budget exhausted")
    if negative.status != "succeeded":
        raise ValueError("published Inspector negative proof is absent")
    selector = selector_retire(
        engagement_id, core_job_id,
        environment=environment, state_root=state_root,
        core_state_root=core_state_root, job_repository=jobs)
    if selector.status != "succeeded":
        raise ValueError("published DigitalOcean selector is not retired")
    retired = inspector_retire(engagement_id, core_job_id, **common)
    if retired.action != RETIRE_ACTION or retired.status != "succeeded":
        raise ValueError("published Inspector retirement is unproved")
    return retired
