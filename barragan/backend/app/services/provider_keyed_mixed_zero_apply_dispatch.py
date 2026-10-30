# Copyright (c) 2026, Oracle and/or its affiliates.
"""One operator review and action for a mixed generation stopped before Apply.

The private stages retain their own one-shot journals. This module supplies no
authority to retry a command whose outcome is uncertain.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Callable

from app.services.engagement_teardown import _confirmation_phrase, _fingerprint
from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.services.provider_keyed_mixed_initial_plan_parent import (
    ACTION as INITIAL_ACTION, _parent_id as initial_parent_id,
)
from app.services.provider_keyed_mixed_zero_apply_cleanup import (
    ACTION, _parent_id, reserve_mixed_zero_apply_cleanup,
)
from app.services.provider_keyed_mixed_zero_apply_teardown_source import (
    MixedZeroApplySource, audit_mixed_zero_apply_teardown_source,
)
from app.services.sketch_state_workspaces import _default_state_root
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun


class MixedZeroApplyDispatchAttention(ValueError):
    """The reviewed zero-Apply boundary or saved phase needs attention."""


def is_mixed_zero_apply_request(job: StoredJobRun | None, *, jobs=None) -> bool:
    if job is None:
        return False
    jobs = jobs or SqlAlchemyJobRepository()
    if job.action == ACTION:
        return True
    if job.action != "pilot_standard_rti_guarded_execute":
        return False
    if jobs.get(_parent_id(job.id)) is not None:
        return True
    initial = jobs.get(initial_parent_id(job.id))
    return (initial is not None and initial.action == INITIAL_ACTION
            and initial.input.get("phase") == "both_plans_saved")


def _core_and_parent(job: StoredJobRun, jobs):
    core = jobs.get(str(job.input.get("coreJobId") or "")) if job.action == ACTION else job
    if core is None or core.action != "pilot_standard_rti_guarded_execute":
        raise MixedZeroApplyDispatchAttention("mixed core job differs")
    parent = jobs.get(_parent_id(core.id))
    if job.action == ACTION and (parent is None or parent.id != job.id):
        raise MixedZeroApplyDispatchAttention("mixed cleanup parent differs")
    return core, parent


def _source(core, parent, *, jobs, state_root, core_state_root) -> MixedZeroApplySource:
    if parent is not None:
        raw = parent.input.get("source") if isinstance(parent.input, dict) else None
        try:
            source = MixedZeroApplySource(**raw) if isinstance(raw, dict) else None
        except (TypeError, ValueError):
            source = None
        if (source is None or parent.action != ACTION or parent.target_id != source.engagement_id
                or parent.input.get("schema") != "mixed-zero-apply-cleanup-v1"
                or parent.input.get("coreJobId") != core.id
                or parent.input.get("corePlanId") != source.core_plan_id
                or parent.input.get("sourceSha256") != _fingerprint(asdict(source))
                or parent.status not in {"queued", "succeeded"}):
            raise MixedZeroApplyDispatchAttention("saved mixed cleanup boundary differs")
        return source
    initial = jobs.get(initial_parent_id(core.id))
    if (initial is None or initial.action != INITIAL_ACTION
            or initial.input.get("phase") != "both_plans_saved"
            or initial.status not in {"queued", "running"}):
        raise MixedZeroApplyDispatchAttention("mixed zero-Apply checkpoint is unavailable")
    plan_id = core.input.get("corePlanId")
    if not isinstance(plan_id, str) or not plan_id:
        raise MixedZeroApplyDispatchAttention("mixed core plan is unavailable")
    try:
        return audit_mixed_zero_apply_teardown_source(
            str(core.input.get("engagementId") or ""), core.id,
            environment="devtest", state_root=state_root,
            core_state_root=core_state_root, lease_owner=plan_id,
            job_repository=jobs,
        )
    except Exception:
        raise MixedZeroApplyDispatchAttention(
            "mixed zero-Apply source is unproved; review current infrastructure") from None


def preview_mixed_zero_apply_cleanup(
    job: StoredJobRun, *, environment: str, state_root: Path | None = None,
    core_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT, job_repository=None,
) -> dict:
    """Return the normal teardown preview shape from an exact mixed source."""
    if environment != "devtest":
        raise MixedZeroApplyDispatchAttention("mixed cleanup is DevTest-only")
    jobs = job_repository or SqlAlchemyJobRepository()
    state_root = state_root or _default_state_root()
    core, parent = _core_and_parent(job, jobs)
    source = _source(core, parent, jobs=jobs, state_root=state_root,
                     core_state_root=core_state_root)
    if source.core_job_id != core.id or source.engagement_id != core.input.get("engagementId"):
        raise MixedZeroApplyDispatchAttention("mixed cleanup source differs")
    name = str(core.input.get("engagementName") or source.engagement_id)
    proxy_count = core.input.get("proxyCount")
    if type(proxy_count) is not int or proxy_count < 0:
        raise MixedZeroApplyDispatchAttention("reviewed core proxy count differs")
    return {
        "snapshotId": _fingerprint(asdict(source)),
        "engagementId": source.engagement_id,
        "engagementName": name,
        "confirmationPhrase": _confirmation_phrase(name),
        "parentJobId": parent.id if parent is not None else None,
        "orderedScope": [
            {"id": "sketch", "label": "Confirm no Sketch Apply occurred",
             "items": [{"provider": provider, "savedPlanReceiptSha256": receipt}
                       for provider, receipt in zip(source.ordered_providers,
                                                    source.provider_receipt_sha256)]},
            {"id": "core", "label": "Destroy core infrastructure",
             "items": [{"jobId": core.id, "planId": source.core_plan_id,
                        "stateSha256": source.core_state_sha256,
                        "proxyCount": proxy_count}]},
            {"id": "inspector-verify", "label": "Verify retired public endpoints",
             "items": [{"coreJobId": core.id, "targetCount": proxy_count + 1}]},
            {"id": "inspector-cleanup", "label": "Destroy retained Inspector",
             "items": [{"tracked": True,
                        "ownedProviderRecordIds": list(source.owned_inspector_record_ids)}]},
        ],
    }


def start_mixed_zero_apply_cleanup(
    job: StoredJobRun, body: dict, *, environment: str,
    state_root: Path | None = None,
    core_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    job_repository=None,
) -> StoredJobRun:
    """Compare one reviewed source, then reserve its deterministic parent."""
    jobs = job_repository or SqlAlchemyJobRepository()
    state_root = state_root or _default_state_root()
    preview = preview_mixed_zero_apply_cleanup(
        job, environment=environment, state_root=state_root,
        core_state_root=core_state_root, job_repository=jobs)
    if (body.get("snapshotId") != preview["snapshotId"]
            or body.get("confirmation") != preview["confirmationPhrase"]):
        raise MixedZeroApplyDispatchAttention("mixed cleanup review changed; review again")
    core, parent = _core_and_parent(job, jobs)
    if parent is not None:
        if parent.status == "succeeded":
            from app.services.provider_keyed_mixed_zero_apply_terminal import (
                recognize_mixed_zero_apply_terminal,
            )
            return recognize_mixed_zero_apply_terminal(
                preview["engagementId"], core.id, environment=environment,
                job_repository=jobs)
        return parent
    try:
        return reserve_mixed_zero_apply_cleanup(
            preview["engagementId"], core.id,
            requested_by=str(body.get("requestedBy") or core.requested_by or "operator"),
            environment=environment, state_root=state_root,
            core_state_root=core_state_root, job_repository=jobs,
        )
    except Exception:
        raise MixedZeroApplyDispatchAttention(
            "mixed cleanup source changed before reservation; review again") from None


def advance_mixed_zero_apply_cleanup(
    parent_id: str, *, environment: str, positive_control_ipv4: str,
    state_root: Path | None = None,
    core_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    job_repository=None, preview_core: Callable | None = None,
    apply_core: Callable | None = None, prove_absence: Callable | None = None,
    prove_negative: Callable | None = None, retire_inspector: Callable | None = None,
    finish: Callable | None = None,
) -> StoredJobRun:
    """Advance exact saved children in order; an unfinished child is attention."""
    from app.services.provider_keyed_pending_dispatch import require_positive_control_ipv4
    from app.services.provider_keyed_mixed_zero_apply_core_preview import (
        ACTION as PREVIEW_ACTION, _child_id as preview_id,
        preview_mixed_zero_apply_oci_core_destroy, queued_preview_restartable,
    )
    from app.services.provider_keyed_mixed_zero_apply_core_apply import (
        ACTION as APPLY_ACTION, _child_id as apply_id,
        apply_mixed_zero_apply_oci_core_destroy, precommand_apply_restartable,
    )
    from app.services.provider_keyed_mixed_zero_apply_core_absence import (
        ACTION as ABSENCE_ACTION,
        prove_mixed_zero_apply_oci_core_absence,
    )
    from app.services.provider_keyed_mixed_zero_apply_inspector_negative import (
        ACTION as NEGATIVE_ACTION, _child_id as negative_id,
        prove_mixed_zero_apply_inspector_negative,
    )
    from app.services.provider_keyed_mixed_zero_apply_inspector_retirement import (
        ACTION as RETIRE_ACTION, _child_id as retire_id,
        retire_mixed_zero_apply_inspector,
    )
    from app.services.provider_keyed_mixed_zero_apply_terminal import (
        finish_mixed_zero_apply_terminal, recognize_mixed_zero_apply_terminal,
    )
    if environment != "devtest":
        raise MixedZeroApplyDispatchAttention("mixed cleanup is DevTest-only")
    control = require_positive_control_ipv4(positive_control_ipv4)
    jobs = job_repository or SqlAlchemyJobRepository()
    state_root = state_root or _default_state_root()
    parent = jobs.get(parent_id)
    if parent is None or parent.action != ACTION or parent.status not in {"queued", "succeeded"}:
        raise MixedZeroApplyDispatchAttention("mixed cleanup parent differs")
    core_id = parent.input.get("coreJobId")
    engagement_id = parent.target_id
    if parent.status == "succeeded":
        return recognize_mixed_zero_apply_terminal(
            engagement_id, core_id, environment=environment,
            job_repository=jobs)
    common = dict(environment=environment, state_root=state_root,
                  core_state_root=core_state_root, job_repository=jobs)

    def stage(child_id: str, action: str, runner: Callable,
              restartable: Callable | None = None, **kwargs):
        child = jobs.get(child_id)
        if child is not None and (child.action != action or (
                child.status != "succeeded" and not (
                    restartable is not None and restartable(child)))):
            raise MixedZeroApplyDispatchAttention(
                f"{action} requires exact one-shot reconciliation")
        if child is not None and child.status == "succeeded":
            return child
        result = runner(engagement_id, core_id, **common, **kwargs)
        if result.action != action or result.status != "succeeded":
            raise MixedZeroApplyDispatchAttention(f"{action} did not prove completion")
        return result

    stage(preview_id(core_id), PREVIEW_ACTION,
          preview_core or preview_mixed_zero_apply_oci_core_destroy,
          restartable=lambda child: queued_preview_restartable(child, parent, core_id))
    stage(apply_id(core_id), APPLY_ACTION,
          apply_core or apply_mixed_zero_apply_oci_core_destroy,
          restartable=lambda child: precommand_apply_restartable(
              child, parent, jobs.get(preview_id(core_id)), core_id))
    absence = (prove_absence or prove_mixed_zero_apply_oci_core_absence)(
        engagement_id, core_id, **common)
    if absence.action != ABSENCE_ACTION or absence.status != "succeeded":
        raise MixedZeroApplyDispatchAttention("exact OCI absence did not prove completion")
    stage(negative_id(core_id), NEGATIVE_ACTION,
          prove_negative or prove_mixed_zero_apply_inspector_negative,
          positive_control={"id": "inspector-external-control", "type": "tcp",
                            "host": control, "port": 443})
    stage(retire_id(core_id), RETIRE_ACTION,
          retire_inspector or retire_mixed_zero_apply_inspector)
    return (finish or finish_mixed_zero_apply_terminal)(
        engagement_id, core_id, **common)


def recover_mixed_zero_apply_dispatches(
    *, environment: str, schedule: Callable[[str], None],
    job_repository=None, lease_lookup=None,
) -> list[str]:
    """Select exact queued fences, including proved pre-command restarts."""
    if environment != "devtest":
        return []
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    selected = []
    for parent in jobs.list():
        if parent.action != ACTION or parent.status != "queued":
            continue
        try:
            core, saved = _core_and_parent(parent, jobs)
            source = _source(core, saved, jobs=jobs, state_root=None,
                             core_state_root=None)
            if (saved != parent or core.input.get("engagementId") != source.engagement_id
                    or lookup(source.engagement_id) != (
                        source.core_plan_id, "provider_keyed_teardown_fence")):
                continue
            from app.services.provider_keyed_mixed_zero_apply_core_preview import (
                ACTION as PREVIEW_ACTION, _child_id as preview_id,
                queued_preview_restartable,
            )
            from app.services.provider_keyed_mixed_zero_apply_core_apply import (
                ACTION as APPLY_ACTION, precommand_apply_restartable,
            )
            preview = jobs.get(preview_id(core.id))
            # The private workers repeat the source/file audit and win a claim
            # before any command. This selector only recognizes their exact
            # pre-command journals; all uncertain work remains attention.
            active = [row for row in jobs.list_for_engagement(source.engagement_id)
                      if row.action in {
                          PREVIEW_ACTION, APPLY_ACTION,
                          "provider_keyed_mixed_zero_apply_inspector_negative",
                          "provider_keyed_mixed_zero_apply_inspector_retirement",
                      } and row.status != "succeeded"]
            if any(not (
                    row.action == PREVIEW_ACTION and queued_preview_restartable(
                        row, parent, core.id)
                    or row.action == APPLY_ACTION and precommand_apply_restartable(
                        row, parent, preview, core.id)) for row in active):
                continue
            selected.append(parent.id)
        except Exception:
            continue
    for parent_id in selected:
        schedule(parent_id)
    return selected
