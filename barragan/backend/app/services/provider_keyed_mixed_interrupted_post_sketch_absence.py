# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only terminal evidence for both interrupted mixed Sketch providers.

The sealed destroy plan and its one-shot child carry prestate provenance.
This checkpoint observes the empty poststate and complete provider absence;
it neither runs Terraform nor retires DigitalOcean's empty selector tag.
OCI and Inspector destruction need a later fresh revalidation of this proof.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Callable, Mapping
from uuid import UUID

from app.services.provider_keyed_mixed_initial_plan_parent import validate_mixed_initial_apply_seal
from app.services.provider_keyed_mixed_interrupted_cleanup import recognize_mixed_interrupted_sealed_plans
from app.services.provider_keyed_mixed_interrupted_destroy_child import (
    _child_id as destroy_child_id, recognize_mixed_interrupted_destroy_child,
)
from app.services.provider_keyed_mixed_interrupted_destroy_plan import (
    MixedInterruptedDestroyPlanSet, _scope_sha,
)
from app.services.provider_keyed_mixed_interrupted_destroy_source import MixedInterruptedDestroyShow
from app.services.provider_keyed_mixed_interrupted_source import (
    MixedInterruptedReview, _empty_inventory,
)
from app.services.provider_keyed_mixed_partial_apply_inventory import MixedPartialApplyInventorySnapshot
from app.storage.job_repository import StoredJobRun, job_event_digest


class MixedInterruptedPostSketchAbsenceAttention(ValueError):
    """Exact one-shot destroy outcome or fresh provider absence is unproved."""


@dataclass(frozen=True)
class MixedInterruptedProviderAbsenceReceipt:
    provider: str
    scope_kind: str
    scope_sha256: str
    plan_set_sha256: str
    original_apply_journal_sha256: str | None
    destroy_child_id: str | None
    destroy_child_journal_sha256: str | None
    before_state_sha256: str | None
    after_state_sha256: str | None
    lineage: str | None
    before_serial: int | None
    after_serial: int | None
    verified_absent_ids: tuple[str, ...]
    inventory_sha256: str
    observation_sha256: str
    selector_retirement_pending: bool


@dataclass(frozen=True)
class MixedInterruptedPostSketchAbsence:
    cleanup_parent_id: str
    cleanup_journal_sha256: str
    review_sha256: str
    plan_set_sha256: str
    ordered_providers: tuple[str, str]
    receipts: tuple[MixedInterruptedProviderAbsenceReceipt, MixedInterruptedProviderAbsenceReceipt]
    checkpoint_sha256: str


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _valid_snapshot(snapshot: MixedPartialApplyInventorySnapshot, provider: str,
                    generation: str) -> bool:
    state_sha = hashlib.sha256(snapshot.state_json).hexdigest() if type(snapshot.state_json) is bytes else None
    summary = {"provider": provider, "stateSha256": state_sha, "phase": snapshot.phase,
               "inventory": snapshot.inventory,
               "linodeAttachments": snapshot.linode_firewall_attached_node_ids,
               "selectorExists": snapshot.selector_tag_exists,
               "selectorCount": snapshot.selector_resources_count,
               "selectorAttachments": snapshot.selector_attached_node_ids,
               "fence": generation}
    return (type(snapshot) is MixedPartialApplyInventorySnapshot
            and snapshot.provider == provider and type(snapshot.inventory) is tuple
            and snapshot.state_sha256 == state_sha
            and snapshot.observation_sha256 == _digest(summary))


def _bound(child: StoredJobRun) -> MixedInterruptedDestroyShow:
    data = child.input
    return MixedInterruptedDestroyShow(
        data["provider"], data["terraformPath"], data["terraformSha256"],
        data["planPath"], data["planSha256"], data["showSha256"],
        data["beforeStateSha256"],
        _digest((data["terraformPath"], "show", "-json", data["planPath"])))


def _poststate(raw: bytes, *, lineage: str, before_serial: int) -> tuple[str, int]:
    data = json.loads(raw)
    UUID(data["lineage"])
    if (type(data) is not dict or data.get("version") != 4
            or data.get("terraform_version") != "1.15.5"
            or data["lineage"] != lineage
            or type(data.get("serial")) is not int or data["serial"] <= before_serial
            or data.get("resources") != []):
        raise ValueError("retained provider state is not empty after destroy")
    return hashlib.sha256(raw).hexdigest(), data["serial"]


def prove_mixed_interrupted_provider_absence(
    initial: StoredJobRun, cleanup: StoredJobRun,
    review: MixedInterruptedReview, plans: MixedInterruptedDestroyPlanSet,
    provider: str, original_apply_child: StoredJobRun | None,
    destroy_child: StoredJobRun | None,
    snapshot: MixedPartialApplyInventorySnapshot, *,
    fence: Callable[[], str], process_quiescent: Callable[[dict], bool],
) -> MixedInterruptedProviderAbsenceReceipt:
    """Fresh exact one-provider proof; safe as a later provider's pre-GO gate."""
    try:
        recognize_mixed_interrupted_sealed_plans(cleanup, initial, review, plans)
        seal = validate_mixed_initial_apply_seal(initial)
        order = tuple(seal["orderedProviders"])
        if (type(provider) is not str or provider not in order
                or review.ordered_providers != order or plans.ordered_providers != order
                or not callable(fence) or not callable(process_quiescent)):
            raise ValueError("mixed provider absence boundary differs")
        generation = fence()
        if type(generation) is not str or not generation:
            raise ValueError("mixed provider absence fence is unavailable")
        index = order.index(provider)
        scope, plan = review.scopes[index], plans.plans[index]
        if (scope.provider != provider or plan.provider != provider
                or plan.scope_sha256 != _scope_sha(scope)
                or (job_event_digest(original_apply_child.events)
                    if original_apply_child is not None else None)
                != scope.child_journal_sha256
                or not _valid_snapshot(snapshot, provider, generation)):
            raise ValueError("mixed provider absence source differs")
        _empty_inventory(initial, provider, snapshot)
        ids = tuple(sorted({identifier for _, identifier in scope.resource_ids}))
        if any(str(row["id"]) in ids for row in snapshot.inventory):
            raise ValueError("original provider ID remains visible")
        if scope.kind in {"unstarted", "tag_only", "failed_absent"}:
            phase = "apply_started" if scope.kind == "failed_absent" else None
            if (destroy_child is not None or plan.plan_path is not None
                    or snapshot.state_json is not None or snapshot.phase != phase
                    or scope.state_sha256 is not None or scope.resource_ids):
                raise ValueError("no-plan provider has unexpected destroy state")
            if provider == "digitalocean" and snapshot.selector_tag_exists is not (
                    scope.kind != "unstarted"):
                raise ValueError("owned selector presence differs")
            after_sha = lineage = after_serial = None
            child_id = child_sha = None
        elif scope.kind in {"partial", "full"}:
            if (destroy_child is None
                    or destroy_child.id != destroy_child_id(review.core_job_id, provider)
                    or plan.before_state_sha256 != scope.state_sha256
                    or plan.state_lineage != scope.lineage
                    or plan.state_serial != scope.serial
                    or snapshot.phase != "destroy_applied"
                    or type(snapshot.state_json) is not bytes):
                raise ValueError("state-backed destroy outcome differs")
            bound = _bound(destroy_child)
            if recognize_mixed_interrupted_destroy_child(
                    destroy_child, initial, cleanup, review, plans, bound) != "awaiting_absence":
                raise ValueError("destroy command has no exact terminal result")
            started = destroy_child.events[4].data
            identity = {key: started[key] for key in ("bootId", "pid", "pgid", "startTicks")}
            if process_quiescent(identity) is not True:
                raise ValueError("recorded destroy process is active")
            after_sha, after_serial = _poststate(
                snapshot.state_json, lineage=scope.lineage, before_serial=scope.serial)
            if provider == "digitalocean" and snapshot.selector_tag_exists is not True:
                raise ValueError("selector vanished before reviewed retirement")
            lineage = scope.lineage
            child_id, child_sha = destroy_child.id, job_event_digest(destroy_child.events)
        else:
            raise ValueError("mixed provider scope kind differs")
        receipt = MixedInterruptedProviderAbsenceReceipt(
            provider, scope.kind, _scope_sha(scope), plans.plan_set_sha256,
            scope.child_journal_sha256, child_id, child_sha,
            scope.state_sha256, after_sha, lineage, scope.serial, after_serial,
            ids, _digest(snapshot.inventory), snapshot.observation_sha256,
            scope.selector_retirement_pending)
        if fence() != generation:
            raise ValueError("mixed provider absence fence changed")
        return receipt
    except Exception:
        raise MixedInterruptedPostSketchAbsenceAttention(
            "mixed provider requires exact terminal absence") from None


def prove_mixed_interrupted_post_sketch_absence(
    initial: StoredJobRun, cleanup: StoredJobRun,
    review: MixedInterruptedReview, plans: MixedInterruptedDestroyPlanSet,
    original_apply_children: Mapping[str, StoredJobRun | None],
    destroy_children: Mapping[str, StoredJobRun | None],
    snapshots: Mapping[str, MixedPartialApplyInventorySnapshot], *,
    fence: Callable[[], str], process_quiescent: Callable[[dict], bool],
) -> MixedInterruptedPostSketchAbsence:
    """Combine two exact terminal scopes; any uncertainty vetoes the whole tail."""
    try:
        recognize_mixed_interrupted_sealed_plans(cleanup, initial, review, plans)
        seal = validate_mixed_initial_apply_seal(initial)
        order = tuple(seal["orderedProviders"])
        if (set(original_apply_children) != set(order)
                or set(destroy_children) != set(order) or set(snapshots) != set(order)
                or not callable(fence) or not callable(process_quiescent)):
            raise ValueError("mixed provider absence set differs")
        generation = fence()
        if type(generation) is not str or not generation:
            raise ValueError("mixed provider absence fence is unavailable")
        receipts = []
        for provider in order:
            receipts.append(prove_mixed_interrupted_provider_absence(
                initial, cleanup, review, plans, provider,
                original_apply_children[provider], destroy_children[provider], snapshots[provider],
                fence=fence, process_quiescent=process_quiescent))
            if fence() != generation:
                raise ValueError("mixed provider absence fence changed")
        payload = {"cleanupParentId": cleanup.id,
                   "cleanupJournalSha256": job_event_digest(cleanup.events),
                   "reviewSha256": review.review_sha256,
                   "planSetSha256": plans.plan_set_sha256,
                   "orderedProviders": order,
                   "receipts": [asdict(receipt) for receipt in receipts]}
        return MixedInterruptedPostSketchAbsence(
            cleanup.id, payload["cleanupJournalSha256"], review.review_sha256,
            plans.plan_set_sha256, order, tuple(receipts), _digest(payload))
    except Exception:
        raise MixedInterruptedPostSketchAbsenceAttention(
            "both mixed providers require exact terminal absence") from None
