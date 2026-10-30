# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only source transition between published mixed provider destroys.

After provider 1 is absent, the initial full/full publication review cannot be
run again. Provider 2 may proceed only with provider 1's fresh exact absence,
its own still-retained full state, and unchanged core/binding/source fences.
This module grants no Terraform GO.
"""

from __future__ import annotations

from app.services.provider_keyed_mixed_published_teardown_authority import published_review_states

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Callable

from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_mixed_initial_host_binding import ProviderHostObservation
from app.services.provider_keyed_mixed_partial_apply_source import _state
from app.services.provider_keyed_mixed_published_absence import (
    PublishedMixedProviderAbsenceReceipt, prove_published_mixed_provider_absence,
)
from app.services.provider_keyed_mixed_published_destroy_plan import PublishedMixedDestroyPlanSet
from app.services.provider_keyed_mixed_published_teardown_authority import PublishedMixedInitialTeardownReview
from app.services.provider_keyed_mixed_published_teardown_checkpoint import recognize_published_mixed_plans_sealed
from app.services.provider_keyed_mixed_partial_apply_inventory import MixedPartialApplyInventorySnapshot
from app.services.provider_keyed_mixed_published_teardown_authority import published_review_policy

from app.storage.job_repository import StoredJobRun


class PublishedMixedSecondTransitionAttention(ValueError):
    """The first absence or second retained source changed before provider 2."""


@dataclass(frozen=True)
class PublishedMixedSecondTransition:
    first_absence: PublishedMixedProviderAbsenceReceipt
    second_provider: str
    second_state_sha256: str
    second_scope_sha256: str
    plan_set_sha256: str
    source_generation: str


def review_published_mixed_second_transition(
    initial: StoredJobRun, cleanup: StoredJobRun,
    review: PublishedMixedInitialTeardownReview,
    plans: PublishedMixedDestroyPlanSet,
    first_destroy_child: StoredJobRun,
    first_snapshot: MixedPartialApplyInventorySnapshot,
    second_observation: ProviderHostObservation,
    core_inspector_scope: dict, engagement_name: str, *,
    fence: Callable[[], str], process_quiescent: Callable[[dict], bool],
    historical_source_unchanged: Callable[[], bool],
    fresh_core_inspector_scope: Callable[[], dict],
    fresh_empty_bindings: Callable[[], dict[str, tuple]],
) -> PublishedMixedSecondTransition:
    """Recheck the post-first source without pretending provider 1 is full."""
    try:
        recognize_published_mixed_plans_sealed(
            cleanup, review, plans, core_inspector_scope, engagement_name)
        order = review.source.ordered_providers
        first, second = order
        generation = fence()
        if type(generation) is not str or not generation:
            raise ValueError("published mixed teardown fence is absent")
        if (historical_source_unchanged() is not True
                or fresh_core_inspector_scope() != core_inspector_scope
                or fresh_empty_bindings() != {kind: () for kind in (
                    "channels", "domains", "certificates", "sites")}):
            raise ValueError("published mixed historical source or bindings changed")
        first_receipt = prove_published_mixed_provider_absence(
            initial, cleanup, review, plans, first,
            first_destroy_child, first_snapshot,
            core_inspector_scope, engagement_name,
            fence=fence, process_quiescent=process_quiescent)
        if (len(first_destroy_child.events) != 8
                or first_destroy_child.events[7].data.get("receiptSha256")
                   != first_receipt.receipt_sha256):
            raise ValueError("published mixed first absence is not persisted")
        scope, plan = review.provider_scopes[1], plans.plans[1]
        published = published_review_states(review)[1]
        observed = second_observation
        if (type(observed) is not ProviderHostObservation
                or observed.classification.provider != second
                or observed.classification.kind != "full"
                or type(observed.state_json) is not bytes
                or hashlib.sha256(observed.state_json).hexdigest()
                   != published.state_sha256
                or observed.classification.state_sha256 != published.state_sha256
                or observed.classification.lineage != published.lineage
                or observed.classification.serial != published.serial
                or tuple(sorted(observed.classification.resource_ids))
                   != published.resource_ids
                or scope["provider"] != second or plan.provider != second
                or scope["stateSha256"] != published.state_sha256
                or plan.before_state_sha256 != published.state_sha256
                or Path(scope["workspace"]).joinpath("terraform.tfstate").read_bytes()
                   != observed.state_json):
            raise ValueError("published mixed second provider no longer retains exact state")
        policy = published_review_policy(review, initial, second)
        state, actual, cloud = _state(second, policy, observed.state_json)
        if (state["lineage"] != published.lineage
                or state["serial"] != published.serial
                or tuple(sorted(cloud.items())) != published.resource_ids
                or {address: str(attrs["id"]) for address, attrs in actual.items()}
                   != {row["address"]: row["id"] for row in scope["resources"]}
                or historical_source_unchanged() is not True
                or fresh_core_inspector_scope() != core_inspector_scope
                or fresh_empty_bindings() != {kind: () for kind in (
                    "channels", "domains", "certificates", "sites")}
                or fence() != generation):
            raise ValueError("published mixed second provider source changed")
        return PublishedMixedSecondTransition(
            first_receipt, second, published.state_sha256,
            _fingerprint(scope), plans.plan_set_sha256, generation)
    except Exception:
        raise PublishedMixedSecondTransitionAttention(
            "published mixed second provider requires exact post-first review") from None
