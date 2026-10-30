# Copyright (c) 2026, Oracle and/or its affiliates.
"""Review and reserve one published four-host mixed teardown action.

The preview is read-only. Start compares the operator's reviewed snapshot to
a fresh two-provider collection, then uses the existing atomic reservation
writer. Execution remains in the separate no-replay coordinator.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from app.services.engagement_teardown import (
    _confirmation_phrase, preview_published_mixed_initial_scope,
)
from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.services.provider_keyed_mixed_initial_plan_parent import (
    ACTION as INITIAL_ACTION, _parent_id as initial_id,
)
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    ACTION, parent_id, propose_published_mixed_initial_cleanup,
    recognize_published_mixed_initial_checkpoint,
    recognize_published_mixed_plans_sealed,
    saved_published_mixed_destroy_plans, saved_published_mixed_initial_review,
)
from app.services.provider_keyed_mixed_published_teardown_collector import (
    collect_published_mixed_initial_teardown,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun


class PublishedMixedDispatchAttention(ValueError):
    """The published review, reservation, or confirmation differs."""


def is_published_mixed_request(job: StoredJobRun | None, jobs) -> bool:
    if job is None:
        return False
    if job.action == ACTION:
        return job.id == parent_id(str(job.input.get("coreJobId") or ""))
    from app.services.engagement_teardown import (
        is_published_mixed_initial_teardown_request,
    )
    return is_published_mixed_initial_teardown_request(job, jobs)


def _core(job: StoredJobRun, jobs):
    core_id = job.input.get("coreJobId") if job.action == ACTION else job.id
    core = jobs.get(core_id)
    initial = jobs.get(initial_id(core_id))
    parent = jobs.get(parent_id(core_id))
    if (core is None or core.action != "pilot_standard_rti_guarded_execute"
            or initial is None or initial.action != INITIAL_ACTION
            or initial.status != "succeeded"
            or core.input.get("engagementId") != initial.target_id
            or job.id not in {core.id, parent.id if parent else None}):
        raise ValueError("published mixed core generation differs")
    return core, parent


def _projection(review, scope, name, parent):
    preview = preview_published_mixed_initial_scope(review, scope, name)
    return {**preview,
            "confirmationPhrase": _confirmation_phrase(name),
            "parentJobId": parent.id if parent is not None else None,
            "startAvailable": parent is None,
            "blockers": ([] if parent is None else
                         ["teardown complete"] if parent.status == "succeeded"
                         else ["teardown already reserved"]),
            "orderedScope": [
                {**item, "label": item["label"].replace(" (review only)", "")}
                for item in preview["orderedScope"]],
            }


def preview_published_mixed_cleanup(
    job: StoredJobRun, *, environment: str, job_repository=None,
    lease_lookup=None,
    collector: Callable = collect_published_mixed_initial_teardown,
) -> dict:
    """Read both live providers, or reopen a saved parent after GO."""
    if environment != "devtest":
        raise PublishedMixedDispatchAttention("published mixed review is DevTest-only")
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        core, parent = _core(job, jobs)
        name = str(core.input.get("engagementName") or core.input["engagementId"])
        if parent is not None:
            review = saved_published_mixed_initial_review(parent)
            scope = parent.input["reviewScope"]
            if parent.status == "succeeded":
                from app.services.provider_keyed_mixed_published_terminal import (
                    recognize_published_mixed_terminal,
                )
                recognize_published_mixed_terminal(
                    core.input["engagementId"], core.id,
                    environment=environment, job_repository=jobs,
                    lease_lookup=lookup)
            elif parent.input.get("phase") == "plans_sealed":
                recognize_published_mixed_plans_sealed(
                    parent, review, saved_published_mixed_destroy_plans(parent),
                    scope, name)
            elif parent.status == "queued":
                recognize_published_mixed_initial_checkpoint(parent, review, scope, name)
            else:
                raise ValueError("published mixed teardown status differs")
            if (parent.status == "queued" and lookup(core.input["engagementId"]) != (
                    core.input["corePlanId"], "provider_keyed_teardown_fence")):
                raise ValueError("published teardown lease changed")
        else:
            collection = collector(
                core.input["engagementId"], core.id,
                job_repository=jobs, lease_lookup=lookup)
            review, scope = collection.review, collection.core_inspector_scope
        return _projection(review, scope, name, parent)
    except Exception:
        raise PublishedMixedDispatchAttention(
            "published mixed cleanup needs fresh two-provider review") from None


def start_published_mixed_cleanup(
    job: StoredJobRun, body: dict, *, environment: str,
    core_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    job_repository=None, lease_lookup=None,
    collector: Callable = collect_published_mixed_initial_teardown,
) -> StoredJobRun:
    """Compare one confirmation then reserve both provider scopes atomically."""
    if environment != "devtest" or core_state_root != DEFAULT_TERRAFORM_STATE_ROOT:
        raise PublishedMixedDispatchAttention("published mixed Start is DevTest-only")
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        core, existing = _core(job, jobs)
        if existing is not None:
            if existing.status == "succeeded":
                from app.services.provider_keyed_mixed_published_terminal import (
                    recognize_published_mixed_terminal,
                )
                return recognize_published_mixed_terminal(
                    core.input["engagementId"], core.id,
                    environment=environment, job_repository=jobs,
                    lease_lookup=lookup)
            preview = preview_published_mixed_cleanup(
                job, environment=environment, job_repository=jobs,
                lease_lookup=lookup)
            if (body.get("snapshotId") != preview["snapshotId"]
                    or body.get("confirmation") != preview["confirmationPhrase"]):
                raise ValueError("published mixed saved review changed")
            return existing
        collection = collector(
            core.input["engagementId"], core.id,
            job_repository=jobs, core_state_root=core_state_root,
            lease_lookup=lookup)
        name = str(core.input.get("engagementName") or core.input["engagementId"])
        preview = _projection(collection.review,
                              collection.core_inspector_scope, name, None)
        if (body.get("snapshotId") != preview["snapshotId"]
                or body.get("confirmation") != preview["confirmationPhrase"]):
            raise ValueError("published mixed reviewed scope changed")
        proposal = propose_published_mixed_initial_cleanup(
            collection.review, collection.core_inspector_scope, name,
            requested_by=str(body.get("requestedBy") or job.requested_by or "operator"))
        return jobs.reserve_published_mixed_initial_cleanup_parent(
            proposal, collection=collection,
            expected_snapshot_id=preview["snapshotId"])
    except Exception:
        raise PublishedMixedDispatchAttention(
            "published mixed cleanup review changed; review again") from None
