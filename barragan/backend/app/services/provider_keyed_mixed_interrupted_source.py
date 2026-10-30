# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only classification of both sealed mixed providers after interrupted Apply.

This produces review evidence, never delete authority. The caller must collect
complete fresh provider snapshots under one teardown lease generation.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import re
from typing import Callable, Mapping

from app.services.provider_keyed_mixed_initial_apply_child import (
    _base, _child_id, _CLAIM_KEYS, _precommand,
    recognize_mixed_initial_apply_result, recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_initial_plan_parent import validate_mixed_initial_apply_seal
from app.services.provider_keyed_mixed_partial_apply_inventory import MixedPartialApplyInventorySnapshot
from app.services.provider_keyed_mixed_partial_apply_source import (
    ApplyObservation, _inventory, classify_sealed_provider_apply,
)
from app.storage.job_repository import StoredJobRun, job_event_digest


_HASH = re.compile(r"[0-9a-f]{64}\Z")


class MixedInterruptedSourceAttention(ValueError):
    """The sealed provider ownership or Apply outcome remains uncertain."""


@dataclass(frozen=True)
class MixedInterruptedProviderScope:
    provider: str
    kind: str
    child_journal_sha256: str | None
    state_sha256: str | None
    lineage: str | None
    serial: int | None
    resource_ids: tuple[tuple[str, str], ...]
    inventory_sha256: str
    observation_sha256: str
    selector_tag: str | None
    selector_retirement_pending: bool


@dataclass(frozen=True)
class MixedInterruptedReview:
    engagement_id: str
    core_job_id: str
    seal_journal_sha256: str
    ordered_providers: tuple[str, str]
    scopes: tuple[MixedInterruptedProviderScope, MixedInterruptedProviderScope]
    review_sha256: str


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _empty_inventory(parent, provider, snapshot) -> None:
    policy = parent.events[5].data["reviewedPolicy"][provider]
    _inventory(provider, policy, {}, {}, snapshot.inventory)
    if provider == "linode":
        if snapshot.linode_firewall_attached_node_ids != ():
            raise ValueError("Linode has an unattested attachment")
    elif snapshot.selector_attached_node_ids != () or snapshot.selector_resources_count != 0:
        raise ValueError("DigitalOcean selector has an unattested member")


def _tag_only(parent, child, provider, seal) -> bool:
    if provider != "digitalocean" or child is None:
        return False
    index = seal["orderedProviders"].index(provider)
    base = _base(parent, seal, provider, index)
    rows = child.events
    messages = ["mixed provider Apply queued", "mixed provider Apply started",
                "mixed selector absent before Apply", "mixed selector POST intended",
                "mixed selector 201 received", "mixed selector exclusive visibility proved"]
    selector = seal["reviewedPolicy"][provider]["selector_tag"]
    if (child.id != _child_id(parent.input["coreJobId"], provider)
            or child.action != "provider_keyed_mixed_initial_apply_child"
            or child.status != "running" or child.started_at is None or child.finished_at is not None
            or child.target != parent.target or child.target_type != "engagement"
            or child.target_id != parent.target_id or child.requested_by != parent.requested_by
            or child.artifact_refs != []
            or {key: value for key, value in child.input.items() if key not in _CLAIM_KEYS} != base
            or len(rows) != 6
            or [(event.sequence, event.level, event.message) for event in rows]
            != [(number, "info", message) for number, message in enumerate(messages, 1)]
            or rows[0].data != {} or rows[1].data != {}):
        return False
    absence, intended, received, visible = (event.data for event in rows[2:])
    return (set(absence) == {"absenceSha256", "selectorTag"}
            and absence["selectorTag"] == selector
            and type(absence["absenceSha256"]) is str
            and _HASH.fullmatch(absence["absenceSha256"]) is not None
            and intended == {"selectorTag": selector,
                             "absenceSha256": absence["absenceSha256"]}
            and received == {"selectorTag": selector, "httpStatus": 201}
            and set(visible) == {"selectorTag", "visibleSha256"}
            and visible["selectorTag"] == selector
            and type(visible["visibleSha256"]) is str
            and _HASH.fullmatch(visible["visibleSha256"]) is not None)


def _failed_result(parent, child, provider) -> tuple[dict, int] | None:
    """Reuse the strict one-shot grammar with only the nonzero rc normalized."""
    if child is None or child.status != "running":
        return None
    rows = list(child.events)
    if not rows or rows[-1].message != "mixed provider Apply command result fenced":
        return None
    data = rows[-1].data
    if (type(data) is not dict or type(data.get("returnCode")) is not int
            or data["returnCode"] == 0):
        return None
    rows[-1] = replace(rows[-1], data={**data, "returnCode": 0})
    result = recognize_mixed_initial_apply_result(
        replace(child, events=rows), parent, provider)
    if result["stage"] != "result":
        return None
    return result, data["returnCode"]


def _provider_scope(parent, seal, provider, child, snapshot, generation,
                    process_quiescent) -> MixedInterruptedProviderScope:
    if (type(snapshot) is not MixedPartialApplyInventorySnapshot
            or snapshot.provider != provider
            or type(snapshot.inventory) is not tuple
            or type(snapshot.observation_sha256) is not str
            or _HASH.fullmatch(snapshot.observation_sha256) is None
            or snapshot.state_sha256 != (
                hashlib.sha256(snapshot.state_json).hexdigest()
                if type(snapshot.state_json) is bytes else None)
            or snapshot.observation_sha256 != _digest({
                "provider": provider, "stateSha256": snapshot.state_sha256,
                "phase": snapshot.phase, "inventory": snapshot.inventory,
                "linodeAttachments": snapshot.linode_firewall_attached_node_ids,
                "selectorExists": snapshot.selector_tag_exists,
                "selectorCount": snapshot.selector_resources_count,
                "selectorAttachments": snapshot.selector_attached_node_ids,
                "fence": generation})):
        raise ValueError("provider observation is incomplete")
    index = seal["orderedProviders"].index(provider)
    selector = seal["reviewedPolicy"][provider].get("selector_tag")
    child_sha = job_event_digest(child.events) if child is not None else None
    kind = None
    classification = None
    if child is None or _precommand(child, _base(parent, seal, provider, index)):
        if snapshot.state_json is not None or snapshot.phase is not None:
            raise ValueError("unstarted provider has retained state")
        _empty_inventory(parent, provider, snapshot)
        if provider == "digitalocean" and snapshot.selector_tag_exists is not False:
            raise ValueError("unstarted DigitalOcean selector exists")
        kind = "unstarted"
    elif _tag_only(parent, child, provider, seal):
        if (snapshot.state_json is not None or snapshot.phase is not None
                or snapshot.selector_tag_exists is not True):
            raise ValueError("tag-only provider has an Apply or missing selector")
        _empty_inventory(parent, provider, snapshot)
        kind = "tag_only"
    else:
        terminal = None
        if child is not None and child.status == "succeeded":
            terminal = recognize_mixed_initial_apply_terminal(child, parent, provider)
            outcome = "succeeded"
            result = terminal
        else:
            failed = _failed_result(parent, child, provider)
            if failed is None:
                raise ValueError("Apply command outcome is uncertain")
            result, _ = failed
            outcome = "failed"
        if process_quiescent(result["startedIdentity"]) is not True:
            raise ValueError("recorded Terraform process remains active")
        if snapshot.state_json is None:
            if outcome != "failed" or snapshot.phase != "apply_started":
                raise ValueError("missing retained state after Apply")
            _empty_inventory(parent, provider, snapshot)
            if provider == "digitalocean" and snapshot.selector_tag_exists is not True:
                raise ValueError("failed DigitalOcean selector is absent")
            kind = "failed_absent"
        else:
            observation = ApplyObservation(
                outcome, True, True, snapshot.phase, snapshot.state_json, True,
                snapshot.inventory, snapshot.selector_tag_exists,
                snapshot.selector_attached_node_ids,
                snapshot.linode_firewall_attached_node_ids,
                snapshot.selector_resources_count)
            classification = classify_sealed_provider_apply(parent, provider, observation)
            if classification.kind != ("full" if outcome == "succeeded" else "partial"):
                raise ValueError("state-backed provider classification differs")
            if terminal is not None:
                proof = terminal["proof"]
                if (classification.state_sha256 != proof["stateSha256"]
                        or classification.lineage != proof["lineage"]
                        or classification.serial != proof["serial"]
                        or dict(classification.resource_ids) != proof["resourceIds"]
                        or (provider == "digitalocean" and (
                            snapshot.selector_resources_count != proof["selectorResourcesCount"]
                            or list(snapshot.selector_attached_node_ids or ())
                            != proof["selectorAttachedNodeIds"]))
                        or (provider == "linode" and
                            list(snapshot.linode_firewall_attached_node_ids or ())
                            != proof["linodeFirewallAttachedNodeIds"])):
                    raise ValueError("full provider changed since proof")
            kind = classification.kind
    if provider == "digitalocean" and kind != "unstarted":
        if snapshot.selector_tag_exists is not True:
            raise ValueError("owned DigitalOcean selector is absent")
    return MixedInterruptedProviderScope(
        provider, kind, child_sha,
        classification.state_sha256 if classification else None,
        classification.lineage if classification else None,
        classification.serial if classification else None,
        classification.resource_ids if classification else (),
        _digest(snapshot.inventory), snapshot.observation_sha256,
        selector, provider == "digitalocean" and kind != "unstarted")


def review_mixed_interrupted_provider_source(
    parent: StoredJobRun, provider: str, child: StoredJobRun | None,
    snapshot: MixedPartialApplyInventorySnapshot, *,
    fence: Callable[[], str], process_quiescent: Callable[[dict], bool],
) -> MixedInterruptedProviderScope:
    """Fresh single-source check for a provider not yet destroyed."""
    try:
        seal = validate_mixed_initial_apply_seal(parent)
        if (provider not in seal["orderedProviders"] or not callable(fence)
                or not callable(process_quiescent)):
            raise ValueError("mixed provider source boundary differs")
        generation = fence()
        if type(generation) is not str or not generation:
            raise ValueError("teardown fence is unavailable")
        scope = _provider_scope(parent, seal, provider, child, snapshot,
                                generation, process_quiescent)
        if fence() != generation:
            raise ValueError("teardown fence changed during provider review")
        return scope
    except Exception:
        raise MixedInterruptedSourceAttention(
            "mixed interrupted provider ownership requires review") from None


def review_mixed_interrupted_source(
    parent: StoredJobRun, children_by_provider: Mapping[str, StoredJobRun | None],
    snapshots_by_provider: Mapping[str, MixedPartialApplyInventorySnapshot], *,
    fence: Callable[[], str], process_quiescent: Callable[[dict], bool],
) -> MixedInterruptedReview:
    """Classify both providers together; uncertain evidence vetoes the review."""
    try:
        seal = validate_mixed_initial_apply_seal(parent)
        order = tuple(seal["orderedProviders"])
        if (set(children_by_provider) != set(order)
                or set(snapshots_by_provider) != set(order)
                or not callable(fence) or not callable(process_quiescent)):
            raise ValueError("mixed provider set differs")
        generation = fence()
        if type(generation) is not str or not generation:
            raise ValueError("teardown fence is unavailable")
        scopes = []
        for provider in order:
            scopes.append(review_mixed_interrupted_provider_source(
                parent, provider, children_by_provider[provider],
                snapshots_by_provider[provider], fence=fence,
                process_quiescent=process_quiescent))
            if fence() != generation:
                raise ValueError("teardown fence changed during provider review")
        payload = {"engagementId": parent.target_id, "coreJobId": parent.input["coreJobId"],
                   "sealJournalSha256": job_event_digest(parent.events[:6]),
                   "orderedProviders": order,
                   "scopes": [scope.__dict__ for scope in scopes]}
        return MixedInterruptedReview(parent.target_id, parent.input["coreJobId"],
                                      payload["sealJournalSha256"], order,
                                      tuple(scopes), _digest(payload))
    except Exception:
        raise MixedInterruptedSourceAttention(
            "mixed interrupted provider ownership requires review") from None
