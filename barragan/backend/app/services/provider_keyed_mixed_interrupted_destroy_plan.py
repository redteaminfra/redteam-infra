# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline exact-delete validation for both interrupted mixed providers.

All provider destroy plans (or explicit no-plan scopes) are bound together
before a later worker may consider its first one-shot destroy Apply.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import stat
from typing import Callable, Mapping

from app.services.provider_keyed_initial_teardown import require_exact_digitalocean_destroy_plan
from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_mixed_initial_plan_parent import validate_mixed_initial_apply_seal
from app.services.provider_keyed_mixed_interrupted_source import (
    MixedInterruptedReview, MixedInterruptedProviderScope,
)
from app.services.provider_keyed_mixed_partial_apply_source import _state
from app.storage.job_repository import StoredJobRun, job_event_digest


class MixedInterruptedDestroyPlanAttention(ValueError):
    """A saved destroy plan does not delete exactly the proved owned state."""


@dataclass(frozen=True)
class MixedInterruptedDestroyPlan:
    provider: str
    scope_sha256: str
    before_state_sha256: str | None
    state_lineage: str | None
    state_serial: int | None
    resource_ids: tuple[tuple[str, str], ...]
    plan_path: str | None
    plan_sha256: str | None
    show_json_sha256: str | None


@dataclass(frozen=True)
class MixedInterruptedDestroyPlanSet:
    review_sha256: str
    ordered_providers: tuple[str, str]
    plans: tuple[MixedInterruptedDestroyPlan, MixedInterruptedDestroyPlan]
    plan_set_sha256: str


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _scope_sha(scope: MixedInterruptedProviderScope) -> str:
    return _digest(scope.__dict__)


def bind_mixed_interrupted_destroy_plans(
    parent: StoredJobRun, review: MixedInterruptedReview,
    before_states: Mapping[str, bytes | None],
    plan_paths: Mapping[str, Path | None],
    show_json: Mapping[str, str | None], *, fence: Callable[[], str],
) -> MixedInterruptedDestroyPlanSet:
    """Bind both already-saved plans; no Terraform or provider call occurs."""
    try:
        seal = validate_mixed_initial_apply_seal(parent)
        order = tuple(seal["orderedProviders"])
        if (order != review.ordered_providers
                or review.engagement_id != parent.target_id
                or review.core_job_id != parent.input["coreJobId"]
                or review.seal_journal_sha256 != job_event_digest(parent.events[:6])
                or set(before_states) != set(order) or set(plan_paths) != set(order)
                or set(show_json) != set(order)):
            raise ValueError("mixed destroy review identity differs")
        expected_review = _digest({
            "engagementId": review.engagement_id, "coreJobId": review.core_job_id,
            "sealJournalSha256": review.seal_journal_sha256,
            "orderedProviders": order, "scopes": [scope.__dict__ for scope in review.scopes]})
        if expected_review != review.review_sha256:
            raise ValueError("mixed destroy review digest differs")
        generation = fence()
        if type(generation) is not str or not generation:
            raise ValueError("mixed destroy fence is unavailable")
        plans = []
        for provider, scope in zip(order, review.scopes, strict=True):
            if scope.provider != provider:
                raise ValueError("mixed destroy scope order differs")
            raw, path, shown = before_states[provider], plan_paths[provider], show_json[provider]
            if scope.kind in {"unstarted", "tag_only", "failed_absent"}:
                if (raw is not None or path is not None or shown is not None
                        or scope.resource_ids or scope.state_sha256 is not None):
                    raise ValueError("absent provider unexpectedly has a destroy plan")
                plan = MixedInterruptedDestroyPlan(
                    provider, _scope_sha(scope), None, None, None, (), None, None, None)
            elif scope.kind in {"partial", "full"}:
                if (type(raw) is not bytes or not isinstance(path, Path)
                        or not path.is_absolute() or type(shown) is not str
                        or not shown
                        or path.name != f".barragan-mixed-interrupted-destroy-{provider}.tfplan"
                        or path.parent.name != hashlib.sha256(
                            f"{provider}\0{seal['reviewedPolicy'][provider]['provider_connection_id']}".encode()
                        ).hexdigest()
                        or path.parent.parent.name != provider
                        or path.parent.parent.parent.name != "provider-keyed-v2"
                        or path.parent.parent.parent.parent.name != parent.target_id
                        or path.parent.resolve(strict=True) != path.parent):
                    raise ValueError("saved destroy plan artifact is absent")
                metadata = path.lstat()
                if (not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_size < 1 or metadata.st_size > 128 * 1024 * 1024):
                    raise ValueError("saved destroy plan file is unsafe")
                plan_bytes = path.read_bytes()
                if len(plan_bytes) != metadata.st_size:
                    raise ValueError("saved destroy plan bytes changed")
                state_sha = hashlib.sha256(raw).hexdigest()
                if state_sha != scope.state_sha256:
                    raise ValueError("retained state changed after review")
                policy = seal["reviewedPolicy"][provider]
                state, actual, cloud = _state(provider, policy, raw)
                if (state["lineage"] != scope.lineage or state["serial"] != scope.serial
                        or tuple(sorted(cloud.items())) != scope.resource_ids):
                    raise ValueError("retained resource identity changed")
                all_ids = {address: str(attrs["id"]) for address, attrs in actual.items()}
                if set(all_ids) != set(_state_resources(state)):
                    raise ValueError("retained state address set differs")
                require_exact_digitalocean_destroy_plan(
                    shown, expected_resource_ids=all_ids, state=state)
                plan = MixedInterruptedDestroyPlan(
                    provider, _scope_sha(scope), state_sha, state["lineage"],
                    state["serial"], tuple(sorted(all_ids.items())), str(path),
                    hashlib.sha256(plan_bytes).hexdigest(),
                    hashlib.sha256(shown.encode()).hexdigest())
            else:
                raise ValueError("mixed destroy scope kind is unrecognized")
            plans.append(plan)
            if fence() != generation:
                raise ValueError("mixed destroy generation changed")
        payload = {"reviewSha256": review.review_sha256, "orderedProviders": order,
                   "plans": [plan.__dict__ for plan in plans]}
        return MixedInterruptedDestroyPlanSet(review.review_sha256, order,
                                              tuple(plans), _digest(payload))
    except Exception:
        raise MixedInterruptedDestroyPlanAttention(
            "both mixed provider destroy plans require exact review") from None
