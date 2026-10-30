# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private, read-only full-state proof and terminal CAS for mixed initial Apply.

This module never invokes Terraform or a provider write. A durable zero-result
child is not successful until exact retained state and complete fresh provider
inventory classify as full under the sealed review.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from uuid import uuid4

from app.domain import JobEvent
from app.services.provider_keyed_initial_destroy_pre_go_recovery import _process_quiescent
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id, _parent_id, recognize_mixed_initial_apply_result,
    recognize_mixed_initial_apply_terminal, reconcile_mixed_initial_apply_phase,
)
from app.services.provider_keyed_mixed_partial_apply_inventory import (
    MixedPartialApplyInventorySettling, collect_provider_inventory_snapshot,
)
from app.services.provider_keyed_mixed_partial_apply_source import (
    ApplyObservation, ProviderApplyClassification, _state, classify_sealed_provider_apply,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _require_lease
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest


_HASH = re.compile(r"[0-9a-f]{64}\Z")


class MixedInitialApplyProofAttention(ValueError):
    """The mixed provider Apply cannot safely be marked successful."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(value: str) -> str:
    return (datetime.fromisoformat(value) + timedelta(seconds=120)).isoformat()


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _proof_data(result: dict, classification, snapshot) -> dict:
    ids = [identifier for _, identifier in classification.resource_ids]
    if len(ids) != len(set(ids)):
        raise ValueError("provider owned IDs overlap")
    if (type(snapshot.state_json) is not bytes
            or hashlib.sha256(snapshot.state_json).hexdigest() != classification.state_sha256
            or snapshot.state_sha256 != classification.state_sha256
            or not classification.lineage or type(classification.serial) is not int
            or classification.serial < 1):
        raise ValueError("classified retained state differs")
    provider = result["provider"]
    return {
        "classifierKind": "full", "stateSha256": classification.state_sha256,
        "lineage": classification.lineage, "serial": classification.serial,
        "inventorySha256": _digest(snapshot.inventory),
        "observationSha256": snapshot.observation_sha256,
        "resourceIds": dict(sorted(classification.resource_ids)),
        "selectorResourcesCount": (snapshot.selector_resources_count
                                   if provider == "digitalocean" else None),
        "selectorAttachedNodeIds": (list(snapshot.selector_attached_node_ids)
                                    if provider == "digitalocean" else None),
        "linodeFirewallAttachedNodeIds": (
            list(snapshot.linode_firewall_attached_node_ids) if provider == "linode" else None),
        "inventoryCount": len(snapshot.inventory),
        "commandResultJournalSha256": result["commandResultJournalSha256"],
    }


def _valid_proof_data(data: object, result: dict) -> bool:
    def ids(value) -> bool:
        return (type(value) is list and all(type(item) is str and item for item in value)
                and value == sorted(set(value)))

    return (type(data) is dict and set(data) == {
        "classifierKind", "stateSha256", "inventorySha256", "observationSha256",
        "lineage", "serial", "resourceIds", "selectorResourcesCount",
        "selectorAttachedNodeIds", "linodeFirewallAttachedNodeIds", "inventoryCount",
        "commandResultJournalSha256"}
        and data["classifierKind"] == "full"
        and all(type(data[key]) is str and _HASH.fullmatch(data[key]) is not None
                for key in ("stateSha256", "inventorySha256", "observationSha256",
                            "commandResultJournalSha256"))
        and data["commandResultJournalSha256"] == result["commandResultJournalSha256"]
        and type(data["lineage"]) is str and bool(data["lineage"])
        and type(data["serial"]) is int and data["serial"] >= 1
        and type(data["resourceIds"]) is dict and bool(data["resourceIds"])
        and list(data["resourceIds"]) == sorted(data["resourceIds"])
        and all(type(key) is str and key and type(value) is str and value
                for key, value in data["resourceIds"].items())
        and len(set(data["resourceIds"].values())) == len(data["resourceIds"])
        and type(data["inventoryCount"]) is int and data["inventoryCount"] >= 0
        and (result["provider"] == "digitalocean"
             and type(data["selectorResourcesCount"]) is int
             and data["selectorResourcesCount"] >= 0
             and ids(data["selectorAttachedNodeIds"])
             and data["selectorResourcesCount"] == len(data["selectorAttachedNodeIds"])
             and data["linodeFirewallAttachedNodeIds"] is None
             or result["provider"] == "linode"
             and data["selectorResourcesCount"] is None
             and data["selectorAttachedNodeIds"] is None
             and ids(data["linodeFirewallAttachedNodeIds"])))


def _linode_attachment_settling(parent, observation: ApplyObservation) -> bool:
    """Identify only a missing subset after every other full-state check passes."""
    try:
        policy = parent.events[5].data["reviewedPolicy"]["linode"]
        _, _, cloud = _state("linode", policy, observation.state_json)
        expected = {identifier for address, identifier in cloud.items()
                    if address in policy["nodes"]}
        actual = set(observation.linode_firewall_attached_node_ids)
        if not actual < expected:
            return False
        prospective = replace(observation,
                              linode_firewall_attached_node_ids=tuple(sorted(expected)))
        return classify_sealed_provider_apply(parent, "linode", prospective).kind == "full"
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


def prove_mixed_initial_prior_provider_fresh(
    parent: StoredJobRun, completed_child: StoredJobRun,
    workspace: ProviderKeyedWorkspace, *, fence: Callable[[], str],
    process_quiescent: Callable[[dict], bool],
    credential_repository=None, linode_transport=None, digitalocean_transport=None,
) -> ProviderApplyClassification:
    """Rebind historical first-provider success to fresh current presence.

    This is a read-only prerequisite for provider-two GO. The completed proof
    records historical success; it is never treated as current presence alone.
    """
    try:
        provider = completed_child.input["provider"]
        terminal = recognize_mixed_initial_apply_terminal(completed_child, parent, provider)
        historical = terminal["proof"]
        if (not isinstance(workspace, ProviderKeyedWorkspace)
                or workspace.provider != provider
                or workspace.path != Path(terminal["planPath"]).parent
                or not process_quiescent(terminal["startedIdentity"])):
            raise ValueError("first provider workspace or process differs")
        snapshot = collect_provider_inventory_snapshot(
            parent, provider, workspace, fence=fence,
            process_quiescent=lambda: process_quiescent(terminal["startedIdentity"]),
            credential_repository=credential_repository,
            linode_transport=linode_transport,
            digitalocean_transport=digitalocean_transport)
        observation = ApplyObservation(
            "succeeded", True, True, snapshot.phase, snapshot.state_json, True,
            snapshot.inventory, snapshot.selector_tag_exists,
            snapshot.selector_attached_node_ids,
            snapshot.linode_firewall_attached_node_ids,
            snapshot.selector_resources_count)
        classified = classify_sealed_provider_apply(parent, provider, observation)
        if (classified.kind != "full"
                or classified.state_sha256 != historical["stateSha256"]
                or classified.lineage != historical["lineage"]
                or classified.serial != historical["serial"]
                or dict(classified.resource_ids) != historical["resourceIds"]
                or (provider == "digitalocean" and (
                    snapshot.selector_resources_count != historical["selectorResourcesCount"]
                    or list(snapshot.selector_attached_node_ids)
                    != historical["selectorAttachedNodeIds"]))
                or (provider == "linode" and list(snapshot.linode_firewall_attached_node_ids)
                    != historical["linodeFirewallAttachedNodeIds"])):
            raise ValueError("first provider state or ownership changed since completion")
        fence()
        return classified
    except Exception:
        raise MixedInitialApplyProofAttention(
            "first mixed provider requires fresh current presence proof") from None


def prove_and_finish_mixed_initial_apply(
    engagement_id: str, core_job_id: str, provider: str,
    workspace: ProviderKeyedWorkspace, *, environment: str,
    job_repository=None, lease_lookup=None, credential_repository=None,
    linode_transport=None, digitalocean_transport=None,
    process_quiescent: Callable[[dict], bool] | None = None,
    claim_owner: str | None = None, claim_token: str | None = None,
    phase_reconciler: Callable = reconcile_mixed_initial_apply_phase,
    max_observation_attempts: int = 12, poll_interval_seconds: float = 5.0,
    sleeper: Callable[[float], None] = time.sleep,
) -> StoredJobRun:
    """Finish only the exact full, provider-observed result journal.

    The caller may pass its active claim for immediate continuation. After a
    restart an expired claim is safely replaced; an unrelated active claim is
    never stolen. The optional child-owned phase reconciler handles a crash
    after rc=0 but before the durable applied marker.
    """
    if (environment != "devtest" or provider not in {"linode", "digitalocean"}
            or type(max_observation_attempts) is not int
            or not 1 <= max_observation_attempts <= 12
            or not isinstance(poll_interval_seconds, (int, float))
            or not 0 <= poll_interval_seconds <= 10):
        raise MixedInitialApplyProofAttention("mixed Apply proof is DevTest-only")
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    quiescent = process_quiescent or (lambda identity: _process_quiescent(
        identity["bootId"], identity["pid"], identity["pgid"], identity["startTicks"]))
    try:
        parent = jobs.get(_parent_id(core_job_id))
        child = jobs.get(_child_id(core_job_id, provider))
        if (parent is None or child is None or parent.target_id != engagement_id
                or child.target_id != engagement_id
                or not isinstance(workspace, ProviderKeyedWorkspace)):
            raise ValueError("mixed Apply jobs or workspace differ")
        if child.status == "succeeded":
            terminal = recognize_mixed_initial_apply_terminal(child, parent, provider)
            if workspace.path != Path(terminal["planPath"]).parent:
                raise ValueError("historical mixed Apply workspace differs")
            return child
        result = recognize_mixed_initial_apply_result(child, parent, provider)
        if workspace.path != Path(result["planPath"]).parent:
            raise ValueError("retained provider workspace differs from Apply journal")
        _require_lease(lookup, engagement_id, parent.input["corePlanId"])
        if result["stage"] == "result":
            if phase_reconciler is None:
                raise ValueError("result-only Apply requires guarded phase reconciliation")
            child = phase_reconciler(
                parent, child, provider, workspace,
                process_quiescent=quiescent, job_repository=jobs, lease_lookup=lookup)
            result = recognize_mixed_initial_apply_result(child, parent, provider)
            # The guarded reconciler may have replaced an expired claim.
            claim_owner = child.input.get("claimOwner")
            claim_token = child.input.get("claimToken")
        if result["stage"] not in {"applied", "awaiting", "proved"}:
            raise ValueError("mixed Apply observation stage is unavailable")
        if not quiescent(result["startedIdentity"]):
            raise ValueError("recorded Terraform process is not quiescent")
        if (claim_owner is not None or claim_token is not None) and (
                child.input.get("claimOwner") != claim_owner
                or child.input.get("claimToken") != claim_token):
            raise ValueError("mixed Apply claim differs")
        if claim_owner is None or claim_token is None or (
                child.input.get("claimOwner") != claim_owner
                or child.input.get("claimToken") != claim_token):
            claim_owner = f"mixed-initial-proof-{uuid4().hex}"
            claim_token = uuid4().hex
            at = _now()
            claimed = jobs.claim_lease(child.id, owner=claim_owner, token=claim_token,
                                       claimed_at=at, expires_at=_later(at),
                                       eligible_statuses={"running"})
            if claimed is None or job_event_digest(claimed.events) != result["journalSha256"]:
                raise ValueError("mixed Apply claim is active or journal changed")
            child = claimed
        generation = _digest({"parent": job_event_digest(parent.events[:6]),
                              "result": result["commandResultJournalSha256"],
                              "claim": claim_token})

        def fence() -> str:
            nonlocal child
            _require_lease(lookup, engagement_id, parent.input["corePlanId"])
            fresh_parent, fresh_child = jobs.get(parent.id), jobs.get(child.id)
            if (fresh_parent != parent or fresh_child != child
                    or job_event_digest(fresh_child.events) != result["journalSha256"]
                    or fresh_child.input.get("claimOwner") != claim_owner
                    or fresh_child.input.get("claimToken") != claim_token
                    or datetime.now(timezone.utc) >= datetime.fromisoformat(
                        fresh_child.input["claimExpiresAt"])):
                raise ValueError("mixed Apply proof generation changed")
            at = _now()
            renewed = jobs.renew_lease(child.id, owner=claim_owner, token=claim_token,
                                       heartbeat_at=at, expires_at=_later(at))
            if renewed is None or renewed.events != child.events:
                raise ValueError("mixed Apply proof claim renewal failed")
            child = renewed
            return generation

        if result["stage"] == "applied":
            fence()
            at = _now()
            updated = jobs.append_event_if_running_claimed(
                child, owner=claim_owner, token=claim_token,
                expected_event_digest=job_event_digest(child.events),
                heartbeat_at=at, expires_at=_later(at),
                event=JobEvent(len(child.events) + 1, "info",
                               "mixed provider awaiting exact observation",
                               {"commandResultSequence": result["commandResultSequence"]}))
            if updated is None:
                raise ValueError("mixed Apply awaiting journal CAS lost")
            child = updated
            result = recognize_mixed_initial_apply_result(child, parent, provider)
            generation = _digest({"parent": job_event_digest(parent.events[:6]),
                                  "result": result["commandResultJournalSha256"],
                                  "claim": claim_token})
        if result["stage"] == "awaiting":
            pending_state_sha = None
            for attempt in range(max_observation_attempts):
                try:
                    snapshot = collect_provider_inventory_snapshot(
                        parent, provider, workspace, fence=fence,
                        process_quiescent=lambda: quiescent(result["startedIdentity"]),
                        credential_repository=credential_repository,
                        linode_transport=linode_transport,
                        digitalocean_transport=digitalocean_transport)
                except MixedPartialApplyInventorySettling:
                    if attempt + 1 == max_observation_attempts:
                        raise
                    fence()
                    sleeper(poll_interval_seconds)
                    continue
                if pending_state_sha is not None and snapshot.state_sha256 != pending_state_sha:
                    raise ValueError("retained state changed during provider settling")
                observation = ApplyObservation(
                    "succeeded", True, True, snapshot.phase, snapshot.state_json, True,
                    snapshot.inventory, snapshot.selector_tag_exists,
                    snapshot.selector_attached_node_ids,
                    snapshot.linode_firewall_attached_node_ids,
                    snapshot.selector_resources_count,
                )
                classified = classify_sealed_provider_apply(parent, provider, observation)
                if classified.kind == "full":
                    break
                if (provider == "linode" and attempt + 1 < max_observation_attempts
                        and _linode_attachment_settling(parent, observation)):
                    pending_state_sha = snapshot.state_sha256
                    fence()
                    sleeper(poll_interval_seconds)
                    continue
                raise ValueError("mixed Apply provider observation is uncertain")
            if classified.kind != "full" or classified.state_sha256 != snapshot.state_sha256:
                raise ValueError("mixed Apply retained provider state is not full")
            data = _proof_data(result, classified, snapshot)
            fence()
            at = _now()
            updated = jobs.append_event_if_running_claimed(
                child, owner=claim_owner, token=claim_token,
                expected_event_digest=job_event_digest(child.events),
                heartbeat_at=at, expires_at=_later(at),
                event=JobEvent(len(child.events) + 1, "info",
                               "mixed provider full observation proved", data))
            if updated is None:
                raise ValueError("mixed Apply proof journal CAS lost")
            child = updated
            result = recognize_mixed_initial_apply_result(child, parent, provider)
        if result["stage"] != "proved" or not _valid_proof_data(child.events[-1].data, result):
            raise ValueError("mixed Apply full proof journal differs")
        fence()
        finished = jobs.finish_if_running_claimed(
            child, owner=claim_owner, token=claim_token,
            expected_event_digest=job_event_digest(child.events),
            status="succeeded", finished_at=_now(),
            event=JobEvent(len(child.events) + 1, "info",
                           "mixed provider initial Apply succeeded",
                           {"observationSha256": child.events[-1].data["observationSha256"]}))
        if finished is None or finished.status != "succeeded":
            raise ValueError("mixed Apply terminal CAS lost")
        return finished
    except Exception:
        raise MixedInitialApplyProofAttention(
            "mixed initial Apply full-state proof requires review") from None
