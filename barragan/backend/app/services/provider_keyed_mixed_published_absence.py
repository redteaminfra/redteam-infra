# Copyright (c) 2026, Oracle and/or its affiliates.
"""Fresh two-provider absence proof after published one-shot destroy.

This read-only receipt is a prerequisite for the OCI/Inspector tail. It does
not retire the DigitalOcean selector or perform any provider write.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Callable, Mapping

from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_mixed_interrupted_post_sketch_absence import (
    _poststate, _valid_snapshot,
)
from app.services.provider_keyed_mixed_interrupted_source import _empty_inventory
from app.services.provider_keyed_mixed_partial_apply_inventory import MixedPartialApplyInventorySnapshot
from app.services.provider_keyed_mixed_published_destroy_child import (
    recognize_published_mixed_destroy_child,
)
from app.domain import JobEvent
from app.services.provider_keyed_mixed_published_destroy_plan import PublishedMixedDestroyPlanSet
from app.services.provider_keyed_mixed_published_teardown_authority import (
    PublishedMixedInitialTeardownReview, PublishedSixTeardownSource, published_review_policy,
)
from app.services.provider_keyed_mixed_published_teardown_checkpoint import recognize_published_mixed_plans_sealed
from app.storage.job_repository import StoredJobRun, job_event_digest


class PublishedMixedAbsenceAttention(ValueError):
    """Both exact owned provider absences are not proved."""


@dataclass(frozen=True)
class PublishedMixedProviderAbsenceReceipt:
    provider: str
    scope_sha256: str
    plan_set_sha256: str
    destroy_child_id: str
    destroy_child_journal_sha256: str
    before_state_sha256: str
    after_state_sha256: str
    lineage: str
    before_serial: int
    after_serial: int
    verified_absent_ids: tuple[str, ...]
    inventory_sha256: str
    observation_sha256: str
    selector_retirement_pending: bool
    receipt_sha256: str


def prove_published_mixed_provider_absence(
    initial: StoredJobRun, cleanup: StoredJobRun,
    review: PublishedMixedInitialTeardownReview,
    plans: PublishedMixedDestroyPlanSet,
    provider: str, destroy_child: StoredJobRun,
    snapshot: MixedPartialApplyInventorySnapshot,
    core_inspector_scope: dict, engagement_name: str, *,
    fence: Callable[[], str], process_quiescent: Callable[[dict], bool],
) -> PublishedMixedProviderAbsenceReceipt:
    """Prove one provider's empty retained state and full fresh GET absence."""
    try:
        recognize_published_mixed_plans_sealed(
            cleanup, review, plans, core_inspector_scope, engagement_name)
        order = review.source.ordered_providers
        if (initial.id != review.source.parent_job_id
                or initial.status != "succeeded"
                or job_event_digest(initial.events)
                   != review.published_parent_journal_sha256
                or provider not in order
                or not callable(fence) or not callable(process_quiescent)):
            raise ValueError("published mixed absence source differs")
        generation = fence()
        if type(generation) is not str or not generation:
            raise ValueError("published mixed absence fence differs")
        index = order.index(provider)
        scope, plan = review.provider_scopes[index], plans.plans[index]
        phase = recognize_published_mixed_destroy_child(
                    destroy_child, cleanup, review, plans, provider,
                    core_inspector_scope, engagement_name)
        if (scope["provider"] != provider or plan.provider != provider
                or phase not in {"awaiting_absence", "absence_proved"}
                or not _valid_snapshot(snapshot, provider, generation)
                or snapshot.phase != "destroy_applied"
                or type(snapshot.state_json) is not bytes
                or snapshot.state_sha256 != hashlib.sha256(snapshot.state_json).hexdigest()):
            raise ValueError("published mixed destroy outcome differs")
        started = destroy_child.events[4].data
        identity = {key: started[key] for key in (
            "bootId", "pid", "pgid", "startTicks")}
        if process_quiescent(identity) is not True:
            raise ValueError("published mixed destroy command is still active")
        if type(review.source) is PublishedSixTeardownSource:
            from app.services.provider_keyed_mixed_partial_apply_source import _inventory
            _inventory(provider, published_review_policy(review, initial, provider), {}, {}, snapshot.inventory)
            if (snapshot.linode_firewall_attached_node_ids != () if provider == "linode" else
                    snapshot.selector_attached_node_ids != () or snapshot.selector_resources_count != 0):
                raise ValueError("published six-node provider retains an attachment")
        else:
            _empty_inventory(initial, provider, snapshot)
        if provider == "digitalocean" and snapshot.selector_tag_exists is not True:
            raise ValueError("published mixed selector disappeared before retirement")
        after_sha, after_serial = _poststate(
            snapshot.state_json, lineage=plan.state_lineage,
            before_serial=plan.state_serial)
        ids = tuple(sorted({identifier for address, identifier in plan.resource_ids
                            if not address.startswith("local_file.")
                            and address != "random_password.root_password"}))
        if any(str(item["id"]) in ids for item in snapshot.inventory):
            raise ValueError("published mixed original provider ID remains visible")
        if fence() != generation:
            raise ValueError("published mixed absence fence changed")
        payload = {
            "provider": provider, "scope_sha256": plan.scope_sha256,
            "plan_set_sha256": plans.plan_set_sha256,
            "destroy_child_id": destroy_child.id,
            "destroy_child_journal_sha256": job_event_digest(destroy_child.events[:7]),
            "before_state_sha256": plan.before_state_sha256,
            "after_state_sha256": after_sha,
            "lineage": plan.state_lineage,
            "before_serial": plan.state_serial,
            "after_serial": after_serial,
            "verified_absent_ids": ids,
            "inventory_sha256": _fingerprint({"inventory": snapshot.inventory}),
            "observation_sha256": snapshot.observation_sha256,
            "selector_retirement_pending": provider == "digitalocean",
        }
        receipt = PublishedMixedProviderAbsenceReceipt(
            **payload, receipt_sha256=_fingerprint(payload))
        if phase == "absence_proved":
            recorded = destroy_child.events[7].data
            if (recorded != {"receipt": json.loads(json.dumps(asdict(receipt))),
                             "receiptSha256": receipt.receipt_sha256}):
                raise ValueError("persisted published mixed absence differs")
        return receipt
    except Exception:
        raise PublishedMixedAbsenceAttention(
            "published mixed provider absence requires exact fresh review") from None


def _propose_published_mixed_absence_event(
    child: StoredJobRun, receipt: PublishedMixedProviderAbsenceReceipt,
) -> JobEvent:
    """Construct one durable provider receipt event, never save it here."""
    if (type(receipt) is not PublishedMixedProviderAbsenceReceipt
            or len(child.events) != 7
            or receipt.destroy_child_id != child.id
            or receipt.destroy_child_journal_sha256 != job_event_digest(child.events)
            or receipt.receipt_sha256 != _fingerprint({
                key: value for key, value in asdict(receipt).items()
                if key != "receipt_sha256"})):
        raise PublishedMixedAbsenceAttention("published mixed absence receipt differs")
    return JobEvent(8, "info", "published mixed provider exact absence proved",
                    {"receipt": json.loads(json.dumps(asdict(receipt))),
                     "receiptSha256": receipt.receipt_sha256})


def propose_published_mixed_first_absence_event(
    child: StoredJobRun, receipt: PublishedMixedProviderAbsenceReceipt,
) -> JobEvent:
    """Construct the first provider's durable receipt event."""
    if child.input.get("providerIndex") != 0:
        raise PublishedMixedAbsenceAttention("first published mixed provider differs")
    return _propose_published_mixed_absence_event(child, receipt)


def propose_published_mixed_second_absence_event(
    child: StoredJobRun, receipt: PublishedMixedProviderAbsenceReceipt,
    first_receipt: PublishedMixedProviderAbsenceReceipt,
) -> JobEvent:
    """Construct provider 2's terminal receipt only from exact prior absence."""
    if (type(first_receipt) is not PublishedMixedProviderAbsenceReceipt
            or child.input.get("providerIndex") != 1
            or child.input.get("priorAbsenceReceiptSha256")
               != first_receipt.receipt_sha256
            or receipt.provider == first_receipt.provider
            or receipt.plan_set_sha256 != first_receipt.plan_set_sha256
            or receipt.receipt_sha256 != _fingerprint({
                key: value for key, value in asdict(receipt).items()
                if key != "receipt_sha256"})):
        raise PublishedMixedAbsenceAttention(
            "second published mixed absence lacks exact prior receipt")
    return _propose_published_mixed_absence_event(child, receipt)


def prove_published_mixed_both_absent(
    initial: StoredJobRun, cleanup: StoredJobRun,
    review: PublishedMixedInitialTeardownReview,
    plans: PublishedMixedDestroyPlanSet,
    destroy_children: Mapping[str, StoredJobRun],
    snapshots: Mapping[str, MixedPartialApplyInventorySnapshot],
    core_inspector_scope: dict, engagement_name: str, *,
    fence: Callable[[], str], process_quiescent: Callable[[dict], bool],
) -> tuple[PublishedMixedProviderAbsenceReceipt, PublishedMixedProviderAbsenceReceipt]:
    """Bind provider 2 to provider 1's receipt and prove both again."""
    try:
        order = review.source.ordered_providers
        if set(destroy_children) != set(order) or set(snapshots) != set(order):
            raise ValueError("published mixed two-provider absence is incomplete")
        receipts = tuple(prove_published_mixed_provider_absence(
            initial, cleanup, review, plans, provider,
            destroy_children[provider], snapshots[provider],
            core_inspector_scope, engagement_name,
            fence=fence, process_quiescent=process_quiescent)
            for provider in order)
        if (len(destroy_children[order[0]].events) != 8
                or destroy_children[order[0]].events[7].data.get("receiptSha256")
                   != receipts[0].receipt_sha256
                or destroy_children[order[1]].input.get("priorAbsenceReceiptSha256")
                != receipts[0].receipt_sha256):
            raise ValueError("published mixed provider 2 lacks exact prior absence")
        return receipts
    except Exception:
        raise PublishedMixedAbsenceAttention(
            "both published mixed provider absences require exact fresh review") from None
