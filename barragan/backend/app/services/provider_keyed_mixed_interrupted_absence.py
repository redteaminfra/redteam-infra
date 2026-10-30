# Copyright (c) 2026, Oracle and/or its affiliates.
"""GET-only absence observation for an interrupted mixed provider.

This is provisional evidence. A later terminal job must bind it to the exact
one-shot destroy child before it can authorize OCI or Inspector teardown.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Callable
from uuid import UUID

from app.services.provider_keyed_mixed_initial_plan_parent import validate_mixed_initial_apply_seal
from app.services.provider_keyed_mixed_interrupted_source import (
    MixedInterruptedProviderScope, MixedInterruptedReview, _empty_inventory,
)
from app.services.provider_keyed_mixed_partial_apply_inventory import MixedPartialApplyInventorySnapshot
from app.services.provider_keyed_mixed_partial_apply_source import _state
from app.storage.job_repository import StoredJobRun, job_event_digest


class MixedInterruptedAbsenceAttention(ValueError):
    """Exact provider absence is not proved by retained state and fresh GETs."""


@dataclass(frozen=True)
class MixedInterruptedAbsenceObservation:
    provider: str
    review_sha256: str
    scope_sha256: str
    before_state_sha256: str | None
    after_state_sha256: str | None
    lineage: str | None
    before_serial: int | None
    after_serial: int | None
    verified_absent_ids: tuple[str, ...]
    inventory_sha256: str
    observation_sha256: str
    selector_retirement_pending: bool


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def inspect_mixed_interrupted_provider_absence(
    parent: StoredJobRun, review: MixedInterruptedReview,
    scope: MixedInterruptedProviderScope,
    before_state: bytes | None, after_state: bytes | None,
    snapshot: MixedPartialApplyInventorySnapshot, *, fence: Callable[[], str],
) -> MixedInterruptedAbsenceObservation:
    """Check exact pre/post state and full fresh inventory without writes."""
    try:
        seal = validate_mixed_initial_apply_seal(parent)
        order = tuple(seal["orderedProviders"])
        payload = {"engagementId": parent.target_id,
                   "coreJobId": parent.input["coreJobId"],
                   "sealJournalSha256": job_event_digest(parent.events[:6]),
                   "orderedProviders": order,
                   "scopes": [item.__dict__ for item in review.scopes]}
        if (review.review_sha256 != _digest(payload)
                or review.ordered_providers != order
                or review.engagement_id != parent.target_id
                or review.core_job_id != parent.input["coreJobId"]
                or scope.provider not in order
                or review.scopes[order.index(scope.provider)] != scope
                or type(snapshot) is not MixedPartialApplyInventorySnapshot
                or snapshot.provider != scope.provider
                or type(snapshot.inventory) is not tuple):
            raise ValueError("mixed absence source differs")
        generation = fence()
        if type(generation) is not str or not generation:
            raise ValueError("mixed absence fence is unavailable")
        _empty_inventory(parent, scope.provider, snapshot)
        ids = tuple(sorted({identifier for _, identifier in scope.resource_ids}))
        if any(str(row["id"]) in ids for row in snapshot.inventory):
            raise ValueError("original provider ID is still visible")
        if scope.kind in {"unstarted", "tag_only", "failed_absent"}:
            expected_phase = "apply_started" if scope.kind == "failed_absent" else None
            if (before_state is not None or after_state is not None
                    or snapshot.state_json is not None or snapshot.phase != expected_phase
                    or scope.resource_ids or scope.state_sha256 is not None):
                raise ValueError("no-destroy scope unexpectedly has retained state")
            if scope.provider == "digitalocean":
                expected_tag = scope.kind != "unstarted"
                if snapshot.selector_tag_exists is not expected_tag:
                    raise ValueError("selector presence differs from review")
            before_sha = after_sha = lineage = before_serial = after_serial = None
        elif scope.kind in {"partial", "full"}:
            if (type(before_state) is not bytes or type(after_state) is not bytes
                    or snapshot.state_json != after_state
                    or snapshot.state_sha256 != hashlib.sha256(after_state).hexdigest()
                    or snapshot.phase != "destroy_applied"
                    or hashlib.sha256(before_state).hexdigest() != scope.state_sha256):
                raise ValueError("destroyed state boundary differs")
            policy = seal["reviewedPolicy"][scope.provider]
            before, _, cloud = _state(scope.provider, policy, before_state)
            if (before["lineage"] != scope.lineage or before["serial"] != scope.serial
                    or tuple(sorted(cloud.items())) != scope.resource_ids):
                raise ValueError("pre-destroy owned state differs")
            after = json.loads(after_state)
            UUID(after["lineage"])
            if (after.get("version") != 4 or after.get("terraform_version") != "1.15.5"
                    or after["lineage"] != before["lineage"]
                    or type(after.get("serial")) is not int
                    or after["serial"] <= before["serial"]
                    or after.get("resources") != []):
                raise ValueError("destroy did not leave empty retained state")
            if scope.provider == "digitalocean" and snapshot.selector_tag_exists is not True:
                raise ValueError("owned selector vanished before retirement")
            before_sha, after_sha = scope.state_sha256, hashlib.sha256(after_state).hexdigest()
            lineage, before_serial, after_serial = before["lineage"], before["serial"], after["serial"]
        else:
            raise ValueError("mixed provider scope kind differs")
        if fence() != generation:
            raise ValueError("mixed absence generation changed")
        return MixedInterruptedAbsenceObservation(
            scope.provider, review.review_sha256, _digest(scope.__dict__),
            before_sha, after_sha, lineage, before_serial, after_serial,
            ids, _digest(snapshot.inventory), snapshot.observation_sha256,
            scope.selector_retirement_pending)
    except Exception:
        raise MixedInterruptedAbsenceAttention(
            "mixed provider absence requires exact state and fresh inventory") from None
