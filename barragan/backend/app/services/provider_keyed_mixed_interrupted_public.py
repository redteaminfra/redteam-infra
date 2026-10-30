# Copyright (c) 2026, Oracle and/or its affiliates.
"""One operator teardown action for an interrupted mixed initial deployment.

The private engines own each irreversible command and its journal. This
coordinator advances only from their exact saved receipts; an uncertain
provider write is never retried.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable
from datetime import datetime, timezone
import time

from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.services.provider_keyed_mixed_initial_apply_child import _child_id as apply_child_id
from app.services.provider_keyed_mixed_initial_plan_parent import _parent_id as initial_id
from app.services.provider_keyed_mixed_interrupted_cleanup import (
    _parent_id as cleanup_id, recognize_mixed_interrupted_cleanup_checkpoint,
    recognize_mixed_interrupted_sealed_plans,
)
from app.services.provider_keyed_mixed_interrupted_destroy_child import _child_id as destroy_child_id
from app.services.provider_keyed_mixed_interrupted_destroy_child import (
    _digest as destroy_digest, recognize_mixed_interrupted_destroy_child,
)
from app.services.provider_keyed_mixed_interrupted_destroy_go import (
    reconcile_mixed_interrupted_destroy_result, run_first_mixed_interrupted_provider_destroy,
)
from app.services.provider_keyed_mixed_interrupted_dispatch import (
    _default_quiescent, _quiescent_child, _saved_plans, _saved_review, _workspace,
)
from app.services.provider_keyed_mixed_interrupted_inspector_tail import (
    advance_mixed_interrupted_inspector_tail,
)
from app.services.provider_keyed_mixed_interrupted_oci_tail import (
    advance_mixed_interrupted_oci_core,
)
from app.services.provider_keyed_mixed_interrupted_plan_worker import (
    _job_id as plan_worker_id, _pristine_queued_worker,
    prepare_mixed_interrupted_destroy_plans,
)
from app.services.provider_keyed_mixed_plan_journal import _Journal
from app.services.provider_keyed_mixed_interrupted_post_sketch_absence import (
    MixedInterruptedPostSketchAbsenceAttention, prove_mixed_interrupted_provider_absence,
)
from app.services.provider_keyed_mixed_interrupted_source import review_mixed_interrupted_source
from app.services.provider_keyed_mixed_interrupted_terminal import (
    finish_mixed_interrupted_terminal, recognize_mixed_interrupted_terminal,
)
from app.services.provider_keyed_mixed_interrupted_destroy_source import (
    MixedInterruptedDestroyShow,
)
from app.services.provider_keyed_mixed_partial_apply_inventory import (
    collect_provider_inventory_snapshot,
)
from app.services.provider_keyed_pending_dispatch import require_positive_control_ipv4
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest


class MixedInterruptedPublicAttention(ValueError):
    """The one-action cleanup stopped at an exact reconciliation boundary."""


def _expired(job: StoredJobRun) -> bool:
    try:
        value = datetime.fromisoformat(job.input["claimExpiresAt"])
        return value.tzinfo is not None and value <= datetime.now(timezone.utc)
    except (KeyError, TypeError, ValueError):
        return False


def _plan_worker_restartable(worker: StoredJobRun | None, parent: StoredJobRun,
                             initial: StoredJobRun, review, state_root: Path,
                             process_quiescent: Callable[[dict], bool]) -> bool:
    if worker is None:
        return True
    if (worker.id != plan_worker_id(review.core_job_id)
            or worker.action != "provider_keyed_mixed_interrupted_plan_worker"
            or worker.target_id != parent.target_id
            or worker.input.get("reviewSha256") != review.review_sha256):
        return False
    if worker.status == "queued":
        return _pristine_queued_worker(worker, parent, initial, review, state_root)
    if worker.status == "succeeded":
        return worker.events[-1].message == "both mixed destroy plans saved"
    if worker.status != "running" or not _expired(worker):
        return False
    if (len(worker.events) != 2
            or worker.events[-1].message != "mixed destroy planning started"):
        return False
    for scope in review.scopes:
        root = _workspace(initial, scope.provider, state_root).path
        journal = _Journal(root / f".barragan-mixed-interrupted-destroy-{scope.provider}.journal.jsonl")
        plan = root / f".barragan-mixed-interrupted-destroy-{scope.provider}.tfplan"
        if scope.kind not in {"partial", "full"}:
            if journal.rows or plan.exists() or plan.is_symlink():
                return False
            continue
        if not journal.rows:
            if plan.exists() or plan.is_symlink():
                return False
            continue
        commands = journal._commands()
        if not any(command[0]["phase"] == "plan"
                   and command[-1]["kind"] == "result"
                   and command[-1]["data"]["returnCode"] == 0
                   and not command[-1]["data"]["stdoutTruncated"]
                   and not command[-1]["data"]["stderrTruncated"]
                   for command in commands):
            return False
        if not plan.is_file() or plan.is_symlink():
            return False
        pending = journal.pending()
        if pending is not None:
            if (pending[0]["phase"] != "show" or len(pending) < 2
                    or pending[-1]["kind"] not in {"started", "heartbeat"}):
                return False
            identity = pending[1]["data"]
            if process_quiescent({"bootId": identity["bootId"], "pid": identity["pid"],
                                  "pgid": identity["pgid"],
                                  "startTicks": identity["startTicks"]}) is not True:
                return False
    return True


def _destroy_child_restartable(child: StoredJobRun | None, initial: StoredJobRun,
                               parent: StoredJobRun, review, plans, provider: str,
                               process_quiescent: Callable[[dict], bool]) -> bool:
    if child is None:
        return True
    try:
        inputs = child.input
        bound = MixedInterruptedDestroyShow(
            provider, inputs["terraformPath"], inputs["terraformSha256"],
            inputs["planPath"], inputs["planSha256"], inputs["showSha256"],
            inputs["beforeStateSha256"],
            destroy_digest((inputs["terraformPath"], "show", "-json", inputs["planPath"])))
        stage = recognize_mixed_interrupted_destroy_child(
            child, initial, parent, review, plans, bound)
        if stage == "queued":
            return True
        if stage not in {"awaiting_absence", "result", "phase_applied"}:
            return False
        if not _expired(child):
            return False
        identity = child.events[4].data
        return process_quiescent({key: identity[key] for key in (
            "bootId", "pid", "pgid", "startTicks")}) is True
    except Exception:
        return False


def advance_mixed_interrupted_cleanup(
    parent_id: str, *, environment: str, positive_control_ipv4: str,
    state_root: Path | None = None,
    core_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    job_repository=None, credential_repository=None, lease_lookup=None,
    process_quiescent: Callable[[dict], bool] = _default_quiescent,
    snapshot_collector: Callable = collect_provider_inventory_snapshot,
    plan_worker: Callable = prepare_mixed_interrupted_destroy_plans,
    destroy_runner: Callable = run_first_mixed_interrupted_provider_destroy,
    destroy_reconciler: Callable = reconcile_mixed_interrupted_destroy_result,
    oci_tail: Callable = advance_mixed_interrupted_oci_core,
    inspector_tail: Callable = advance_mixed_interrupted_inspector_tail,
    terminal: Callable = finish_mixed_interrupted_terminal,
    release_validator: Callable = require_devtest_terraform_release,
    read_only_wait: Callable[[float], None] = time.sleep,
) -> StoredJobRun:
    """Plan, destroy in reviewed order, prove absence, and finish one teardown."""
    if environment != "devtest":
        raise MixedInterruptedPublicAttention("interrupted mixed cleanup is DevTest-only")
    state_root = state_root or _default_state_root()
    if state_root != _default_state_root() or core_state_root != DEFAULT_TERRAFORM_STATE_ROOT:
        raise MixedInterruptedPublicAttention("interrupted mixed cleanup roots differ")
    # The control is validated before any Terraform or provider action.
    control = require_positive_control_ipv4(positive_control_ipv4)
    jobs = job_repository or SqlAlchemyJobRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        parent = jobs.get(parent_id)
        if (parent is None or parent.id != cleanup_id(parent.input.get("coreJobId", ""))
                or parent.action != "provider_keyed_mixed_interrupted_cleanup"
                or parent.status not in {"queued", "succeeded"}):
            raise ValueError("interrupted mixed parent differs")
        engagement_id, core_job_id = parent.target_id, parent.input["coreJobId"]
        if parent.status == "succeeded":
            return recognize_mixed_interrupted_terminal(
                engagement_id, core_job_id, environment=environment,
                job_repository=jobs, lease_lookup=lookup)
        parent = plan_worker(
            engagement_id, core_job_id, environment=environment,
            state_root=state_root, job_repository=jobs,
            credential_repository=credentials, lease_lookup=lookup)
        initial = jobs.get(initial_id(core_job_id))
        if initial is None or parent != jobs.get(parent_id):
            raise ValueError("sealed mixed parent changed")
        review, plans = _saved_review(parent), _saved_plans(parent)
        order = review.ordered_providers
        originals = {provider: jobs.get(apply_child_id(core_job_id, provider))
                     for provider in order}
        expected_lease = (parent.input["corePlanId"], "provider_keyed_teardown_fence")
        generation = job_event_digest(parent.events) + ":" + plans.plan_set_sha256

        def fence() -> str:
            if (jobs.get(initial.id) != initial or jobs.get(parent.id) != parent
                    or lookup(engagement_id) != expected_lease
                    or any(jobs.get(apply_child_id(core_job_id, provider)) != originals[provider]
                           for provider in order)):
                raise ValueError("interrupted mixed source changed")
            return generation

        def all_quiescent() -> bool:
            for provider in order:
                if not _quiescent_child(originals[provider], process_quiescent):
                    return False
                child = jobs.get(destroy_child_id(core_job_id, provider))
                if child is None:
                    continue
                for event in child.events:
                    if event.message == "mixed provider destroy command started before GO":
                        data = event.data
                        identity = {key: data[key] for key in (
                            "bootId", "pid", "pgid", "startTicks")}
                        if process_quiescent(identity) is not True:
                            return False
            return True

        def inventory(provider: str, source_fence: Callable[[], str],
                      phase_mode: str = "apply"):
            fence()
            snapshot = snapshot_collector(
                initial, provider, _workspace(initial, provider, state_root),
                fence=source_fence, process_quiescent=all_quiescent,
                credential_repository=credentials, phase_mode=phase_mode)
            fence()
            return snapshot

        def fresh_both(check: Callable[[], None]):
            def claimed_fence() -> str:
                check()
                return fence()
            claimed_fence()
            snapshots = {provider: inventory(provider, claimed_fence) for provider in order}
            current = review_mixed_interrupted_source(
                initial, originals, snapshots, fence=claimed_fence,
                process_quiescent=process_quiescent)
            claimed_fence()
            return current

        def proved_absence(provider: str) -> None:
            index = order.index(provider)
            scope = review.scopes[index]
            destroy_id = destroy_child_id(core_job_id, provider)
            destroy = jobs.get(destroy_id)
            mode = "destroy_applied" if scope.kind in {"partial", "full"} else "apply"
            attempts = 12 if scope.kind in {"partial", "full"} else 1
            for attempt in range(attempts):
                if jobs.get(destroy_id) != destroy:
                    raise ValueError("mixed destroy journal changed during absence observation")
                fence()
                snapshot = inventory(provider, fence, mode)
                if jobs.get(destroy_id) != destroy:
                    raise ValueError("mixed destroy journal changed during absence observation")
                try:
                    prove_mixed_interrupted_provider_absence(
                        initial, parent, review, plans, provider, originals[provider],
                        destroy, snapshot, fence=fence, process_quiescent=process_quiescent)
                    return
                except MixedInterruptedPostSketchAbsenceAttention:
                    if attempt + 1 == attempts:
                        raise
                    fence()
                    if jobs.get(destroy_id) != destroy:
                        raise ValueError("mixed destroy journal changed during absence observation")
                    read_only_wait(5)

        for provider in order:
            fence()
            index = order.index(provider)
            scope, plan = review.scopes[index], plans.plans[index]
            if plan.plan_path is None:
                proved_absence(provider)
                continue
            if scope.kind not in {"partial", "full"}:
                raise ValueError("state-backed mixed plan scope differs")
            existing = jobs.get(destroy_child_id(core_job_id, provider))
            if existing is None or existing.status == "queued":
                release = release_validator(environment=environment)
                state_path = _workspace(initial, provider, state_root).state_path
                if state_path.is_symlink():
                    raise ValueError("reviewed retained state is unsafe")
                destroy_runner(
                    initial, parent, review, plans, provider, state_path.read_bytes(),
                    environment=environment,
                    exact_both_scope_prover=fresh_both if index == 0 else None,
                    inventory_collector=inventory if index == 1 else None,
                    process_quiescent=process_quiescent,
                    job_repository=jobs, lease_lookup=lookup,
                    credential_repository=credentials, terraform_path=release.path,
                    release_validator=lambda **_: release)
            else:
                destroy_reconciler(
                    initial, parent, review, plans, provider,
                    process_quiescent=process_quiescent,
                    inventory_collector=inventory if index == 1 else None,
                    job_repository=jobs, lease_lookup=lookup)
            proved_absence(provider)

        oci = oci_tail(
            engagement_id, core_job_id, environment=environment,
            state_root=state_root, core_state_root=core_state_root,
            job_repository=jobs, lease_lookup=lookup)
        if oci.status != "succeeded":
            raise ValueError("interrupted mixed OCI absence is unproved")
        inspector = inspector_tail(
            engagement_id, core_job_id, environment=environment,
            state_root=state_root, core_state_root=core_state_root,
            positive_control={"id": "inspector-external-control", "type": "tcp",
                              "host": control, "port": 443}, job_repository=jobs,
            read_only_wait=read_only_wait)
        if inspector.status != "succeeded":
            raise ValueError("interrupted mixed Inspector retirement is unproved")
        return terminal(
            engagement_id, core_job_id, environment=environment,
            state_root=state_root, core_state_root=core_state_root,
            job_repository=jobs, lease_lookup=lookup)
    except Exception:
        raise MixedInterruptedPublicAttention(
            "interrupted mixed cleanup needs exact one-action reconciliation") from None


def recover_mixed_interrupted_dispatches(
    *, environment: str, schedule: Callable[[str], None],
    state_root: Path | None = None,
    core_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    job_repository=None, lease_lookup=None,
    process_quiescent: Callable[[dict], bool] = _default_quiescent,
    terraform_quiescent: Callable[[], bool] | None = None,
) -> list[str]:
    """Schedule only parents whose saved children have a safe continuation.

    This is a read-only selector. Every selected parent is revalidated by the
    private workers before a command; any uncertain write stays attention.
    """
    if environment != "devtest":
        return []
    state_root = state_root or _default_state_root()
    if state_root != _default_state_root() or core_state_root != DEFAULT_TERRAFORM_STATE_ROOT:
        return []
    from app.services.provider_keyed_mixed_zero_apply_core_preview import (
        ACTION as OCI_PREVIEW, _child_id as oci_preview_id,
        queued_preview_restartable,
    )
    from app.services.provider_keyed_mixed_zero_apply_core_apply import (
        ACTION as OCI_APPLY, _child_id as oci_apply_id,
        precommand_apply_restartable, interrupted_show_restartable,
        interrupted_apply_no_go_restartable,
    )
    from app.services.provider_keyed_core_destroy_preview import _terraform_quiescent
    from app.services.provider_keyed_mixed_interrupted_oci_tail import (
        audit_current_interrupted_oci_tail,
    )
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    selected = []
    for parent in jobs.list():
        if parent.action != "provider_keyed_mixed_interrupted_cleanup" or parent.status != "queued":
            continue
        try:
            core_job_id = parent.input["coreJobId"]
            initial = jobs.get(initial_id(core_job_id))
            if (initial is None or parent.id != cleanup_id(core_job_id)
                    or parent.target_id != initial.target_id
                    or lookup(parent.target_id) != (parent.input["corePlanId"],
                                                        "provider_keyed_teardown_fence")):
                continue
            review = _saved_review(parent)
            if parent.input.get("phase") == "plans_sealed":
                plans = _saved_plans(parent)
                recognize_mixed_interrupted_sealed_plans(parent, initial, review, plans)
            else:
                plans = None
                recognize_mixed_interrupted_cleanup_checkpoint(parent, initial, review)
            if not _plan_worker_restartable(
                    jobs.get(plan_worker_id(core_job_id)), parent, initial, review,
                    state_root, process_quiescent):
                continue
            if plans is None:
                if any(jobs.get(destroy_child_id(core_job_id, provider)) is not None
                       for provider in review.ordered_providers):
                    continue
            elif any(not _destroy_child_restartable(
                    jobs.get(destroy_child_id(core_job_id, provider)), initial, parent,
                    review, plans, provider, process_quiescent)
                    for provider in review.ordered_providers):
                continue
            preview = jobs.get(oci_preview_id(core_job_id))
            applied = jobs.get(oci_apply_id(core_job_id))
            if preview is not None and preview.status != "succeeded":
                authority = audit_current_interrupted_oci_tail(
                    parent.target_id, core_job_id, environment=environment,
                    state_root=state_root, core_state_root=core_state_root,
                    job_repository=jobs, lease_lookup=lookup)
                if not queued_preview_restartable(
                        preview, parent, core_job_id, authority=authority):
                    continue
            if (applied is not None and applied.status != "succeeded"
                    and not precommand_apply_restartable(
                        applied, parent, preview, core_job_id)
                    and not interrupted_show_restartable(
                        applied, parent, preview, core_job_id,
                        process_quiescent=process_quiescent,
                        terraform_quiescent=(terraform_quiescent or _terraform_quiescent))
                    and not interrupted_apply_no_go_restartable(
                        applied, parent, preview, core_job_id,
                        process_quiescent=process_quiescent,
                        terraform_quiescent=(terraform_quiescent or _terraform_quiescent))):
                continue
            active = [row for row in jobs.list_for_engagement(parent.target_id)
                      if row.status not in {"succeeded"} and row.action in {
                          "provider_keyed_mixed_zero_apply_inspector_negative",
                          "provider_keyed_mixed_interrupted_selector_retirement",
                          "provider_keyed_mixed_zero_apply_inspector_retirement",
                      }]
            if active:
                from app.services.provider_keyed_mixed_zero_apply_inspector_negative import (
                    ACTION as negative_action, _attempts as negative_attempts,
                    _MAX_ATTEMPTS as negative_max_attempts, latest_negative_attempt,
                )
                latest = latest_negative_attempt(jobs, parent.target_id, core_job_id)
                if (latest is not None and latest.status == "failed"
                        and len(negative_attempts(jobs, parent.target_id, core_job_id))
                        < negative_max_attempts
                        and all(row.action == negative_action and row.status == "failed"
                                for row in active)):
                    active = []
            if active:
                continue
            selected.append(parent.id)
        except Exception:
            continue
    for parent_id in selected:
        schedule(parent_id)
    return selected
