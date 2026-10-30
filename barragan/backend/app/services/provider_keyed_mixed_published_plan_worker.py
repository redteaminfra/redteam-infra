# Copyright (c) 2026, Oracle and/or its affiliates.
"""Produce and atomically seal both exact published mixed destroy plans.

The existing fsynced provider plan journal owns every Terraform command.
This adapter only supplies the published two-provider source and artifact
names; an uncertain plan intent is not retried.
"""

from __future__ import annotations

from app.services.provider_keyed_mixed_published_teardown_authority import published_review_states, published_review_policy

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Callable

from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.services.provider_keyed_gated_runner import run_gated_command
from app.services.provider_keyed_mixed_initial_plan_parent import _parent_id as initial_id
from app.services.provider_keyed_mixed_interrupted_dispatch import _workspace
from app.services.provider_keyed_mixed_interrupted_plan_worker import _produce_state_backed_plan
from app.services.provider_keyed_mixed_published_destroy_plan import bind_published_mixed_initial_destroy_plans
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    ACTION, recognize_published_mixed_plans_sealed,
    saved_published_mixed_destroy_plans, saved_published_mixed_initial_review,
)
from app.services.provider_keyed_mixed_published_teardown_collector import (
    PublishedMixedTeardownCollection, collect_published_mixed_initial_teardown,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.sketch_ssh_key_repository import SqlAlchemySketchSshKeyRepository


class PublishedMixedPlanWorkerAttention(ValueError):
    """An exact provider destroy plan or command outcome is unproved."""


def prepare_published_mixed_destroy_plans(
    cleanup_id: str, *, environment: str,
    state_root: Path | None = None,
    core_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    job_repository=None, credential_repository=None, ssh_key_repository=None,
    lease_lookup=None, collector: Callable = collect_published_mixed_initial_teardown,
    release_validator: Callable = require_devtest_terraform_release,
    gated_command_runner: Callable = run_gated_command,
    command_environment=None,
) -> StoredJobRun:
    """Seal both reviewed plans before either provider destroy is allowed."""
    jobs = job_repository or SqlAlchemyJobRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    sketch_keys = ssh_key_repository or SqlAlchemySketchSshKeyRepository()
    lookup = lease_lookup or _db_lease_lookup
    state_root = state_root or _default_state_root()
    try:
        if (environment != "devtest" or state_root != _default_state_root()
                or core_state_root != DEFAULT_TERRAFORM_STATE_ROOT):
            raise ValueError("published plan worker root differs")
        parent = jobs.get(cleanup_id)
        if (parent is None or parent.action != ACTION or parent.status != "queued"):
            raise ValueError("published teardown reservation is absent")
        review = saved_published_mixed_initial_review(parent)
        source = review.source
        initial = jobs.get(initial_id(source.core_job_id))
        if (initial is None or source.engagement_id != parent.target_id
                or lookup(source.engagement_id) != (
                    source.core_plan_id, "provider_keyed_teardown_fence")):
            raise ValueError("published plan source or fence differs")
        if len(parent.events) == 2:
            plans = saved_published_mixed_destroy_plans(parent)
            recognize_published_mixed_plans_sealed(
                parent, review, plans, parent.input["reviewScope"],
                parent.input["engagementName"])
            return parent
        if len(parent.events) != 1:
            raise ValueError("published plan parent journal differs")

        def collect():
            value = collector(
                source.engagement_id, source.core_job_id,
                job_repository=jobs, core_state_root=core_state_root,
                lease_lookup=lookup, allow_teardown_fence=True)
            if (type(value) is not PublishedMixedTeardownCollection
                    or value.review != review
                    or value.core_inspector_scope != parent.input["reviewScope"]
                    or jobs.get(parent.id) != parent
                    or jobs.get(initial.id) != initial):
                raise ValueError("published two-provider source changed during plan")
            return value

        collection = collect()
        release = release_validator(environment=environment)
        if (release.version != "1.15.5" or release.platform != "linux_amd64"):
            raise ValueError("pinned Terraform release changed")
        generation = f"{parent.id}:{job_event_digest(parent.events)}"

        def fence() -> str:
            if (jobs.get(parent.id) != parent or jobs.get(initial.id) != initial
                    or lookup(source.engagement_id) != (
                        source.core_plan_id, "provider_keyed_teardown_fence")):
                raise ValueError("published two-plan fence changed")
            return generation

        before = {provider: collection.observations[provider].state_json
                  for provider in source.ordered_providers}
        paths, shown = {}, {}
        for provider, published in zip(source.ordered_providers,
                                       published_review_states(review), strict=True):
            # The reviewed four-host source is full/full. This adapter leaves
            # the existing audited provider command sequence untouched.
            scope = SimpleNamespace(
                kind="full", state_sha256=published.state_sha256,
                lineage=published.lineage, serial=published.serial,
                resource_ids=published.resource_ids)
            path, output = _produce_state_backed_plan(
                provider, scope, initial,
                _workspace(initial, provider, state_root),
                credentials=credentials, sketch_keys=sketch_keys, release=release,
                fence=fence, source_recheck=collect,
                gated_command_runner=gated_command_runner,
                command_environment=(os.environ if command_environment is None
                                     else command_environment),
                plan_variant="published",
                **({"reviewed_policy": published_review_policy(review, initial, provider)}
                   if (review.reviewed_policies is not None
                       or review.failed_append_recovery is not None
                       and review.failed_append_recovery.get("kind") == "failed-second-v1") else {}))
            paths[provider], shown[provider] = path, output
            collect()
        plan_set = bind_published_mixed_initial_destroy_plans(
            initial, review, before, paths, shown, fence=fence,
            terraform_path=release.path,
            expected_terraform_sha256=release.sha256)
        collect()
        result = jobs.seal_published_mixed_initial_destroy_plans(
            parent, collection=collection, plan_set=plan_set,
            before_states=before)
        recognize_published_mixed_plans_sealed(
            result, review, plan_set, parent.input["reviewScope"],
            parent.input["engagementName"])
        return result
    except Exception:
        raise PublishedMixedPlanWorkerAttention(
            "published mixed two-plan result requires exact reconciliation") from None
