# Copyright (c) 2026, Oracle and/or its affiliates.
"""One private operator action for a published mixed-generation teardown.

The child engines own their exact provider writes and restart rules. This
coordinator only advances from authenticated saved receipts, preserving the
engagement's desired configuration for later redeployment.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable
import time

from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    ACTION, parent_id, saved_published_mixed_initial_review,
    saved_published_mixed_destroy_plans, recognize_published_mixed_plans_sealed,
    recognize_published_mixed_initial_checkpoint,
)
from app.services.provider_keyed_mixed_published_destroy_child import (
    child_id, recognize_published_mixed_destroy_child,
)
from app.services.provider_keyed_mixed_published_plan_worker import (
    prepare_published_mixed_destroy_plans,
)
from app.services.provider_keyed_mixed_published_first_destroy_go import (
    run_published_mixed_first_provider_destroy,
    run_published_mixed_second_provider_destroy,
)
from app.services.provider_keyed_mixed_published_first_absence_worker import (
    finish_published_mixed_first_absence,
)
from app.services.provider_keyed_mixed_published_second_absence_worker import (
    finish_published_mixed_second_absence,
)
from app.services.provider_keyed_mixed_published_tail import (
    advance_published_mixed_oci_core, advance_published_mixed_inspector_tail,
)
from app.services.provider_keyed_pending_dispatch import require_positive_control_ipv4
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun


class PublishedMixedPublicAttention(ValueError):
    """The one-action teardown stopped at an exact review boundary."""


def recover_published_mixed_dispatches(
    *, environment: str, schedule: Callable[[str], None],
    job_repository=None, lease_lookup=None,
) -> list[str]:
    """At startup, select saved parents; children decide safe continuation.

    This reader does not touch Terraform or providers. The coordinator and
    each one-shot child recheck their fence before any external action.
    """
    if environment != "devtest":
        return []
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    selected = []
    for parent in jobs.list():
        if parent.action != ACTION or parent.status != "queued":
            continue
        try:
            if parent.id != parent_id(parent.input["coreJobId"]):
                continue
            review = saved_published_mixed_initial_review(parent)
            scope, name = parent.input["reviewScope"], parent.input["engagementName"]
            if parent.input.get("phase") == "plans_sealed":
                recognize_published_mixed_plans_sealed(
                    parent, review, saved_published_mixed_destroy_plans(parent),
                    scope, name)
            else:
                recognize_published_mixed_initial_checkpoint(
                    parent, review, scope, name)
            if (parent.target_id != review.source.engagement_id
                    or lookup(parent.target_id) != (
                        review.source.core_plan_id,
                        "provider_keyed_teardown_fence")):
                continue
            selected.append(parent.id)
        except Exception:
            continue
    for identifier in selected:
        schedule(identifier)
    return selected


def advance_published_mixed_cleanup(
    cleanup_id: str, *, environment: str, positive_control_ipv4: str,
    state_root: Path | None = None,
    core_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    job_repository=None, lease_lookup=None,
    plan_worker: Callable = prepare_published_mixed_destroy_plans,
    first_runner: Callable = run_published_mixed_first_provider_destroy,
    first_absence: Callable = finish_published_mixed_first_absence,
    second_runner: Callable = run_published_mixed_second_provider_destroy,
    second_absence: Callable = finish_published_mixed_second_absence,
    oci_tail: Callable = advance_published_mixed_oci_core,
    inspector_tail: Callable = advance_published_mixed_inspector_tail,
    terminal: Callable | None = None,
    read_only_wait: Callable[[float], None] = time.sleep,
    dispatch_fence: Callable[[], None] | None = None,
) -> StoredJobRun:
    """Advance both sketch destroys, OCI, Inspector, then local retirement.

    This is private until the full chain and HTTP Start get independent review.
    A nonterminal one-shot child never goes back through its GO runner.
    """
    try:
        check_dispatch = dispatch_fence or (lambda: None)
        check_dispatch()
        if environment != "devtest":
            raise ValueError("published mixed cleanup is DevTest-only")
        state_root = state_root or _default_state_root()
        if (state_root != _default_state_root()
                or core_state_root != DEFAULT_TERRAFORM_STATE_ROOT):
            raise ValueError("published mixed cleanup roots differ")
        control = require_positive_control_ipv4(positive_control_ipv4)
        jobs = job_repository or SqlAlchemyJobRepository()
        lookup = lease_lookup or _db_lease_lookup
        parent = jobs.get(cleanup_id)
        if (parent is None or parent.action != ACTION
                or parent.id != parent_id(parent.input.get("coreJobId", ""))
                or parent.status not in {"queued", "succeeded"} or parent.target_id
                   != parent.input.get("engagementId")):
            raise ValueError("published mixed cleanup checkpoint differs")
        engagement_id, core_job_id = parent.target_id, parent.input["coreJobId"]
        if parent.status == "succeeded":
            from app.services.provider_keyed_mixed_published_terminal import (
                recognize_published_mixed_terminal,
            )
            return recognize_published_mixed_terminal(
                engagement_id, core_job_id, environment=environment,
                job_repository=jobs, lease_lookup=lookup)
        expected_lease = (parent.input["corePlanId"],
                          "provider_keyed_teardown_fence")
        if lookup(engagement_id) != expected_lease:
            raise ValueError("published mixed teardown fence differs")
        parent = plan_worker(cleanup_id, environment=environment,
                             state_root=state_root, core_state_root=core_state_root,
                             job_repository=jobs, lease_lookup=lookup)
        review = saved_published_mixed_initial_review(parent)
        plans = saved_published_mixed_destroy_plans(parent)
        recognize_published_mixed_plans_sealed(
            parent, review, plans, parent.input["reviewScope"],
            parent.input["engagementName"])

        def fence() -> None:
            check_dispatch()
            if (jobs.get(parent.id) != parent
                    or lookup(engagement_id) != expected_lease):
                raise ValueError("published mixed parent or fence changed")

        def advance_provider(index: int, runner: Callable,
                             finisher: Callable) -> None:
            fence()
            provider = review.source.ordered_providers[index]
            identifier = child_id(core_job_id, provider)
            child = jobs.get(identifier)
            phase = (None if child is None else
                     recognize_published_mixed_destroy_child(
                         child, parent, review, plans, provider,
                         parent.input["reviewScope"],
                         parent.input["engagementName"]))
            if phase in {None, "queued"}:
                child = runner(cleanup_id, environment=environment,
                               job_repository=jobs, lease_lookup=lookup)
                fence()
                phase = recognize_published_mixed_destroy_child(
                    child, parent, review, plans, provider,
                    parent.input["reviewScope"],
                    parent.input["engagementName"])
            if phase in {"result", "awaiting_absence"}:
                child = finisher(cleanup_id, job_repository=jobs,
                                 lease_lookup=lookup,
                                 core_state_root=core_state_root)
                fence()
                phase = recognize_published_mixed_destroy_child(
                    child, parent, review, plans, provider,
                    parent.input["reviewScope"],
                    parent.input["engagementName"])
            if phase != "absence_proved" or child != jobs.get(identifier):
                raise ValueError("published mixed provider absence is unproved")

        advance_provider(0, first_runner, first_absence)
        advance_provider(1, second_runner, second_absence)
        fence()
        if parent.input.get("sourceKind") in ("published-six-node-v1", "unpublished-six-node-cleanup-v1"):
            from app.services.provider_keyed_mixed_published_binding_manifest import advance_published_owned_bindings
            advance_published_owned_bindings(parent, environment=environment,
                state_root=state_root, jobs=jobs)
            fence()
        oci = oci_tail(engagement_id, core_job_id, environment=environment,
                       state_root=state_root, core_state_root=core_state_root,
                       job_repository=jobs)
        if oci.status != "succeeded":
            raise ValueError("published mixed OCI absence is unproved")
        fence()
        inspector = inspector_tail(
            engagement_id, core_job_id, environment=environment,
            state_root=state_root, core_state_root=core_state_root,
            positive_control={"id": "inspector-external-control", "type": "tcp",
                              "host": control, "port": 443},
            job_repository=jobs, read_only_wait=read_only_wait)
        if inspector.status != "succeeded":
            raise ValueError("published mixed Inspector retirement is unproved")
        fence()
        if terminal is None:
            from app.services.provider_keyed_mixed_published_terminal import (
                finish_published_mixed_terminal,
            )
            terminal = finish_published_mixed_terminal
        return terminal(engagement_id, core_job_id, environment=environment,
                        job_repository=jobs, lease_lookup=lookup)
    except Exception:
        raise PublishedMixedPublicAttention(
            "published mixed cleanup needs exact one-action reconciliation") from None
