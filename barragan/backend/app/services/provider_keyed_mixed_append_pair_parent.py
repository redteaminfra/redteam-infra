# Copyright (c) 2026, Oracle and/or its affiliates.
"""Durable reservation and one-digest approval for a mixed append pair.

Reservation atomically acquires the published generation's lease; approval
reopens both saved plans against a fresh, authenticated generation.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
from uuid import uuid4

from app.services.provider_keyed_mixed_append_availability import (
    MixedAppendAvailabilityAttention, require_reviewed_mixed_append_availability,
)
from app.domain import JobEvent
from app.services.provider_keyed_mixed_append_live_bindings import (
    collect_mixed_append_live_bindings,
)
from app.services.provider_keyed_mixed_append_pair_plan_worker import (
    _name, _read, reopen_mixed_append_pair_plan_review,
)
from app.services.provider_keyed_mixed_append_published_source import (
    collect_published_mixed_append_source,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun


ACTION = "provider_keyed_mixed_append"
PLAN_ACTION = "provider_keyed_mixed_append_plan_child"
_OPERATION = "provider_keyed_mixed_append"
_REQUEST_KEYS = {
    "digitalocean": frozenset({"selectedChainId", "edgeRegion", "edgeSize",
                               "edgeImage", "selectorTag"}),
    "linode": frozenset({"selectedChainId", "edgeRegion", "edgeType",
                         "edgeImage", "engagementTag"}),
}


class MixedAppendPairParentAttention(ValueError):
    """The paired append reservation or approval needs reconciliation."""


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _parent_id(core_job_id: str) -> str:
    return f"job-provider-keyed-mixed-append-{core_job_id.removeprefix('job-')}"


def _plan_child_id(parent_id: str) -> str:
    return f"job-provider-keyed-mixed-append-plan-{parent_id.removeprefix('job-')}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _matches_request(request: dict, digitalocean_intent, linode_intent) -> bool:
    do, linode = digitalocean_intent, linode_intent
    return request == {
        "digitalocean": {
            "selectedChainId": do.chain_id, "edgeRegion": do.new_edge.region,
            "edgeSize": do.new_edge.size, "edgeImage": do.new_edge.image,
            "selectorTag": do.new_edge.firewall_selector_tag,
        },
        "linode": {
            "selectedChainId": linode.chain_id, "edgeRegion": linode.new_edge.region,
            "edgeType": linode.new_edge.node_type,
            "edgeImage": linode.new_edge.image,
            "engagementTag": linode.new_edge.tag,
        },
    }


def mixed_append_approval_sha256(pair_plan_sha256: str, source) -> str:
    """The one digest displayed for operator approval after both plans exist."""
    return _digest({
        "schema": "mixed-append-pair-approval-v1",
        "pairPlanSha256": pair_plan_sha256,
        "publishedSourceSha256": _digest(asdict(source.source)),
        "liveBindingsSha256": source.live_bindings_sha256,
        "historicalRowsSha256": source.historical_rows_sha256,
    })


def mixed_append_review_summary(parent: StoredJobRun, seal) -> dict:
    """Small operator-facing summary derived from one authenticated pair seal."""
    order = parent.input["providerOrder"]
    request = parent.input["reviewRequest"]
    return {"schema": "mixed-append-pair-review-summary-v1",
            "providerOrder": list(order),
            "plans": [{
                "provider": provider,
                "selectedChainId": request[provider]["selectedChainId"],
                "edgeRegion": request[provider]["edgeRegion"],
                "edgeSizeOrType": request[provider][
                    "edgeSize" if provider == "digitalocean" else "edgeType"],
                "newEdgeAddress": seal.new_edge_addresses[index],
                "savedPlanSha256": seal.saved_plan_sha256[index],
            } for index, provider in enumerate(order)],
            "outcome": "add one edge per provider; retain all existing nodes"}


def _collect_published(engagement_id: str, core_job_id: str, jobs, lookup):
    return collect_published_mixed_append_source(
        engagement_id, core_job_id,
        binding_inventory=lambda: collect_mixed_append_live_bindings(engagement_id),
        job_repository=jobs, lease_lookup=lookup)


def reserve_mixed_append_pair(
    engagement_id: str, core_job_id: str, core_plan_id: str, *,
    requested_by: str, reviewed_request: dict,
    provider_order: tuple[str, str], chain_order: tuple[str, str],
    job_repository=None,
) -> StoredJobRun:
    """Persist one reviewed request and its lease before plan production.

    The request must contain the two nonsecret edge additions and selected
    middles. Its digest is stable across restart and duplicate-click retries.
    The repository transaction refuses a different active core plan or lease.
    """
    try:
        if (any(type(value) is not str or not value for value in
                (engagement_id, core_job_id, core_plan_id, requested_by))
                or type(reviewed_request) is not dict
                or set(reviewed_request) != {"digitalocean", "linode"}
                or any(type(reviewed_request[provider]) is not dict
                       or set(reviewed_request[provider]) != keys
                       or any(type(value) is not str or not value
                              for value in reviewed_request[provider].values())
                       for provider, keys in _REQUEST_KEYS.items())
                or type(provider_order) is not tuple or len(provider_order) != 2
                or set(provider_order) != {"digitalocean", "linode"}
                or type(chain_order) is not tuple or len(chain_order) != 2
                or len(set(chain_order)) != 2
                or any(type(value) is not str or not value for value in chain_order)):
            raise ValueError("mixed append reviewed request differs")
        request_sha = _digest({"request": reviewed_request,
                               "providerOrder": provider_order,
                               "chainOrder": chain_order})
        at = _now()
        parent_id = _parent_id(core_job_id)
        parent = StoredJobRun(
            parent_id, ACTION, "queued", f"engagement:{engagement_id}",
            "engagement", engagement_id, requested_by,
            {"schema": "mixed-append-pair-parent-v1", "phase": "planning",
             "engagementId": engagement_id, "coreJobId": core_job_id,
             "corePlanId": core_plan_id, "providerOrder": list(provider_order),
             "chainOrder": list(chain_order), "reviewRequest": reviewed_request,
             "requestSha256": request_sha, "mutation": True},
            [], at, None, None,
            [JobEvent(1, "info", "mixed append pair reserved",
                      {"requestSha256": request_sha})],
        )
        child = StoredJobRun(
            _plan_child_id(parent_id), PLAN_ACTION, "queued", parent.target,
            parent.target_type, engagement_id, requested_by,
            {"schema": "mixed-append-pair-plan-v1", "appendParentId": parent_id,
             "engagementId": engagement_id, "coreJobId": core_job_id,
             "corePlanId": core_plan_id, "requestSha256": request_sha,
             "mutation": False},
            [], at, None, None,
            [JobEvent(1, "info", "mixed append pair plan reserved",
                      {"requestSha256": request_sha})],
        )
        return (job_repository or SqlAlchemyJobRepository()).reserve_mixed_append_pair(
            parent, child)
    except Exception:
        raise MixedAppendPairParentAttention(
            "mixed append pair reservation needs exact published core and an available lease") from None


def approve_mixed_append_pair(
    parent_id: str, *, expected_review_sha256: str, binding_manifest: dict,
    digitalocean_intent, linode_intent, workspaces: dict,
    provider_states: dict[str, bytes], reviewed_inputs: dict,
    digitalocean_firewall, job_repository=None,
    credential_repository=None, lease_lookup=None,
    release_check=None, catalog_transport=None,
) -> StoredJobRun:
    """Reopen both plans, then CAS one operator-approved pair digest.

    The publication source is collected internally with the real binding
    inventory; callers cannot supply it. Tests patch the private reader.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        if (type(expected_review_sha256) is not str
                or len(expected_review_sha256) != 64
                or any(char not in "0123456789abcdef"
                       for char in expected_review_sha256)):
            raise ValueError("mixed append operator review digest differs")
        parent = jobs.get(parent_id)
        if (parent is None or parent.action != ACTION
                or parent.target_type != "engagement"
                or parent.input.get("schema") != "mixed-append-pair-parent-v1"
                or parent.input.get("engagementId") != parent.target_id
                or parent.input.get("coreJobId") is None
                or parent.input.get("corePlanId") is None
                or lookup(parent.target_id) != (parent.input["corePlanId"], _OPERATION)):
            raise ValueError("mixed append parent or lease differs")
        plan_child_id = _plan_child_id(parent.id)
        child = jobs.get(plan_child_id)
        if (child is None or child.action != PLAN_ACTION
                or child.input.get("requestSha256") != parent.input.get("requestSha256")):
            raise ValueError("mixed append plan child differs")
        if parent.input.get("phase") == "apply_sealed":
            if (parent.status != "running" or child.status != "succeeded"
                    or parent.input.get("reviewSha256") != expected_review_sha256
                    or child.events[-1].message != "mixed append pair plan reviewed"
                    or child.events[-1].data != {
                        "reviewSha256": expected_review_sha256}):
                raise ValueError("mixed append prior approval differs")
            return parent
        if parent.input.get("phase") != "planning":
            raise ValueError("mixed append planning phase differs")
        if (child.status != "succeeded"
                or child.events[-1].message != "mixed append pair plan reviewed"
                or child.events[-1].data != {
                    "reviewSha256": expected_review_sha256}):
            raise ValueError("mixed append reviewed plan child differs")
        if parent.status == "queued":
            parent = jobs.start_if_queued(parent, started_at=_now(), event=JobEvent(
                2, "info", "mixed append pair planning started", {}))
        if parent is None or parent.status != "running":
            raise ValueError("mixed append planning claim changed")
        require_reviewed_mixed_append_availability(parent, jobs=jobs,
            credential_repository=credential_repository, catalog_transport=catalog_transport)
        owner, token = f"mixed-append-pair-{uuid4().hex}", uuid4().hex
        at = _now()
        claimed = jobs.claim_lease(parent.id, owner=owner, token=token,
                                   claimed_at=at,
                                   expires_at=(datetime.fromisoformat(at)
                                               + timedelta(minutes=20)).isoformat(),
                                   eligible_statuses={"running"},
                                   eligible_phases={"planning"})
        if claimed is None:
            raise ValueError("mixed append planning claim unavailable")
        parent = claimed
        source = _collect_published(parent.target_id, parent.input["coreJobId"],
                                    jobs, lookup)
        published = source.source
        if (published.core_plan_id != parent.input["corePlanId"]
                or _digest(binding_manifest) != published.binding_manifest_sha256
                or not _matches_request(parent.input["reviewRequest"],
                                        digitalocean_intent, linode_intent)
                or set(workspaces) != {"digitalocean", "linode"}
                or dict(source.workspaces)
                   != {provider: workspaces[provider].path for provider in workspaces}
                or set(provider_states) != set(workspaces)
                or any(hashlib.sha256(provider_states[provider]).hexdigest()
                       != next(row.state_sha256 for row in published.provider_states
                               if row.provider == provider)
                       for provider in workspaces)):
            raise ValueError("mixed append published source differs")
        kwargs = dict(
            source=published, binding_manifest=binding_manifest,
            digitalocean_intent=digitalocean_intent, linode_intent=linode_intent,
            workspaces=workspaces, provider_states=provider_states,
            reviewed_inputs=reviewed_inputs,
            digitalocean_firewall=digitalocean_firewall,
            reviewed_provider_order=tuple(parent.input["providerOrder"]),
            reviewed_chain_order=tuple(parent.input["chainOrder"]),
            lease_lookup=lookup, lease_owner=parent.input["corePlanId"],
            credential_repository=credential_repository,
        )
        if release_check is not None:
            kwargs["release_check"] = release_check
        seal = reopen_mixed_append_pair_plan_review(**kwargs)
        approved_sha = mixed_append_approval_sha256(seal.review_sha256, source)
        if (seal.engagement_id != parent.target_id
                or seal.core_job_id != parent.input["coreJobId"]
                or approved_sha != expected_review_sha256
                or seal.provider_order != tuple(parent.input["providerOrder"])
                or seal.chain_order != tuple(parent.input["chainOrder"])
                or parent.input.get("reviewSummary") != mixed_append_review_summary(parent, seal)):
            raise ValueError("mixed append paired plan seal differs")
        # Every saved receipt has already been authenticated by the reopener.
        # Persist its exact bytes hash as a compact restart identity.
        receipts = {provider: hashlib.sha256(_read(
            workspaces[provider].path / _name(provider, "plan-receipt.json"))).hexdigest()
            for provider in workspaces}
        fresh = _collect_published(parent.target_id, parent.input["coreJobId"],
                                   jobs, lookup)
        if fresh != source or jobs.get(parent.id) != parent:
            raise ValueError("mixed append publication changed during approval")
        sealed = {**parent.input,
                  "phase": "apply_sealed", "reviewSha256": approved_sha,
                  "pairPlanSha256": seal.review_sha256,
                  "sourceSha256": _digest(asdict(published)),
                  "bindingManifestSha256": published.binding_manifest_sha256,
                  "liveBindingsSha256": source.live_bindings_sha256,
                  "historicalRowsSha256": source.historical_rows_sha256,
                  "receiptSha256": receipts,
                  "selectedMiddles": {
                      "digitalocean": digitalocean_intent.linode_middle_address,
                      "linode": linode_intent.digitalocean_middle_address},
                  "intents": {"digitalocean": asdict(digitalocean_intent),
                              "linode": asdict(linode_intent)},
                  "reviewedInputs": reviewed_inputs,
                  "digitaloceanFirewall": asdict(digitalocean_firewall),
                  }
        return jobs.seal_mixed_append_pair(
            parent, plan_child_id=plan_child_id, sealed_input=sealed,
            claim_owner=owner, claim_token=token, approved_at=_now())
    except MixedAppendAvailabilityAttention as exc:
        raise MixedAppendPairParentAttention(str(exc)) from None
    except Exception:
        raise MixedAppendPairParentAttention(
            "mixed append pair approval needs exact read-only reconciliation") from None
