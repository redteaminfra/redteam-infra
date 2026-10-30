# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private post-OCI continuation for one interrupted mixed teardown parent."""

from __future__ import annotations

from pathlib import Path
from typing import Callable
import time

from app.services.provider_keyed_mixed_interrupted_cleanup import _parent_id as cleanup_id
from app.services.provider_keyed_mixed_interrupted_dispatch import _saved_review
from app.services.provider_keyed_mixed_interrupted_selector_retirement import (
    retire_mixed_interrupted_selector,
)
from app.services.provider_keyed_mixed_zero_apply_inspector_negative import (
    _MAX_ATTEMPTS as negative_max_attempts, _attempts as negative_attempts,
    _child_id as negative_id, latest_negative_attempt,
    MixedZeroApplyInspectorNegativeAttention,
    prove_mixed_zero_apply_inspector_negative,
)
from app.services.provider_keyed_mixed_zero_apply_inspector_retirement import (
    ACTION as RETIRE_ACTION, _child_id as retirement_id,
    retire_mixed_zero_apply_inspector,
)
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun


def advance_mixed_interrupted_inspector_tail(
    engagement_id: str, core_job_id: str, *, environment: str, state_root: Path,
    core_state_root: Path, positive_control: dict, job_repository=None,
    negative_prover: Callable = prove_mixed_zero_apply_inspector_negative,
    selector_retire: Callable = retire_mixed_interrupted_selector,
    inspector_retire: Callable = retire_mixed_zero_apply_inspector,
    negative_options: dict | None = None, selector_options: dict | None = None,
    retirement_options: dict | None = None,
    read_only_wait: Callable[[float], None] = time.sleep,
) -> StoredJobRun:
    """One private action: public-negative, optional selector, Inspector retirement.

    Each engine independently reopens the saved OCI/Inspector authority. An
    uncertain one-shot child raises attention; this continuation never infers
    completion or replays a DELETE.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    parent = jobs.get(cleanup_id(core_job_id))
    if (environment != "devtest" or parent is None
            or parent.action != "provider_keyed_mixed_interrupted_cleanup"
            or parent.target_id != engagement_id):
        raise ValueError("interrupted mixed Inspector parent differs")
    review = _saved_review(parent)
    pending = next(row for row in review.scopes
                   if row.provider == "digitalocean").selector_retirement_pending
    common = dict(environment=environment, state_root=state_root,
                  core_state_root=core_state_root, job_repository=jobs,
                  interrupted=True)
    previous = jobs.get(retirement_id(core_job_id))
    if previous is not None and previous.status == "succeeded":
        saved_negative = jobs.get(previous.input.get("negativeJobId", negative_id(core_job_id)))
        if previous.action != RETIRE_ACTION:
            raise ValueError("Inspector retirement action differs")
        if (saved_negative is None
                or saved_negative.input.get("positiveControl") != positive_control):
            raise ValueError("Inspector positive control differs")
        # Its historical recognizer validates saved negative/selector lineage
        # after the Inspector binding is cleared. A fresh public probe cannot
        # run once the owned Inspector has been retired.
        retired = inspector_retire(engagement_id, core_job_id, **common,
                                   **(retirement_options or {}))
        if retired != previous:
            raise ValueError("Inspector retirement receipt differs")
        return retired
    previous_failure_id = None
    for _ in range(negative_max_attempts):
        try:
            negative = negative_prover(engagement_id, core_job_id,
                                       positive_control=positive_control, **common,
                                       **(negative_options or {}))
            break
        except MixedZeroApplyInspectorNegativeAttention:
            failed = latest_negative_attempt(jobs, engagement_id, core_job_id)
            if (failed is None or failed.status != "failed"
                    or failed.id == previous_failure_id
                    or len(negative_attempts(jobs, engagement_id, core_job_id))
                    >= negative_max_attempts
                    or jobs.get(parent.id) != parent):
                raise
            previous_failure_id = failed.id
            read_only_wait(2)
    else:
        raise ValueError("Inspector read-only retry budget exhausted")
    if negative.status != "succeeded":
        raise ValueError("Inspector public-negative is unproved")
    if pending:
        selector = selector_retire(
            engagement_id, core_job_id,
            **{key: value for key, value in common.items() if key != "interrupted"},
            **(selector_options or {}))
        if selector.status != "succeeded":
            raise ValueError("DigitalOcean selector is not retired")
    retired = inspector_retire(engagement_id, core_job_id, **common,
                               **(retirement_options or {}))
    if retired.status != "succeeded":
        raise ValueError("Inspector retirement is unproved")
    return retired
