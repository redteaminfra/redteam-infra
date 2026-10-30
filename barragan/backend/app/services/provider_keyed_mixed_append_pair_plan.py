# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only cross-check of two reviewed mixed-provider 4-to-6 append plans.

The caller authenticates each intent, saved binary, Terraform show JSON, and
receipt before calling this pure function. The returned digest is review
identity, never GO authority; it performs no provider or filesystem action.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re
from typing import Mapping

from app.services.provider_keyed_mixed_append_intent import (
    MixedDigitalOceanOnLinodeAppendIntent, _DO_NODE, _SHARED_DO, _SHARED_LINODE,
)
from app.services.provider_keyed_mixed_append_linode_intent import (
    MixedLinodeOnDigitalOceanAppendIntent, _LINODE_EDGE,
)

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_LINODE_NODE = re.compile(r'linode_instance\.(middle|edge)\["[a-z0-9_-]+"\]\Z')
_PROVIDERS = frozenset({"digitalocean", "linode"})
_RECEIPT_KEYS = frozenset({
    "provider", "engagementId", "coreJobId", "chainId", "predecessorStateSha256",
    "newEdgeAddress", "planSha256", "showJsonSha256", "sourceRevision",
    "sourceSha256", "credentialRecordId", "credentialSecretSha256",
    "credentialUpdatedAt",
})


class MixedAppendPairPlanError(ValueError):
    """Two append plans do not seal the same reviewed four-node generation."""


@dataclass(frozen=True)
class MixedAppendPairPlanSeal:
    engagement_id: str
    core_job_id: str
    provider_order: tuple[str, str]
    chain_order: tuple[str, str]
    original_digitalocean_state_sha256: str
    original_linode_state_sha256: str
    new_edge_addresses: tuple[str, str]
    saved_plan_sha256: tuple[str, str]
    review_sha256: str


def seal_mixed_append_pair_plan(
    digitalocean_intent: MixedDigitalOceanOnLinodeAppendIntent,
    linode_intent: MixedLinodeOnDigitalOceanAppendIntent,
    receipts_in_reviewed_order: tuple[Mapping[str, object], ...],
    *, reviewed_provider_order: tuple[str, str],
    reviewed_chain_order: tuple[str, str],
) -> MixedAppendPairPlanSeal:
    """Bind two independent, already-authenticated plan receipt summaries.

    Review order is explicit and stable across restarts. The caller must still
    revalidate each saved plan and source/credential snapshot before Apply.
    """
    if (not isinstance(digitalocean_intent, MixedDigitalOceanOnLinodeAppendIntent)
            or not isinstance(linode_intent, MixedLinodeOnDigitalOceanAppendIntent)
            or type(receipts_in_reviewed_order) is not tuple
            or len(receipts_in_reviewed_order) != 2
            or any(not isinstance(row, Mapping) or set(row) != _RECEIPT_KEYS
                   for row in receipts_in_reviewed_order)
            or type(reviewed_provider_order) is not tuple
            or len(reviewed_provider_order) != 2
            or set(reviewed_provider_order) != _PROVIDERS
            or type(reviewed_chain_order) is not tuple
            or len(reviewed_chain_order) != 2
            or tuple(row["provider"] for row in receipts_in_reviewed_order)
            != reviewed_provider_order):
        raise MixedAppendPairPlanError("paired append review order or receipt shape differs")
    do, linode = digitalocean_intent, linode_intent
    if (type(do.engagement_id) is not str or not do.engagement_id
            or type(do.core_job_id) is not str or not do.core_job_id
            or (do.engagement_id, do.core_job_id)
            != (linode.engagement_id, linode.core_job_id)
            or type(do.chain_id) is not str or not do.chain_id
            or type(linode.chain_id) is not str or not linode.chain_id
            or do.chain_id == linode.chain_id
            or reviewed_chain_order != tuple(
                do.chain_id if provider == "digitalocean" else linode.chain_id
                for provider in reviewed_provider_order)
            or do.digitalocean_state_sha256 != linode.digitalocean_state_sha256
            or do.linode_state_sha256 != linode.linode_state_sha256
            or do.retained_digitalocean_ids != linode.retained_digitalocean_ids
            or do.retained_linode_ids != linode.retained_linode_ids
            or not _sha(do.digitalocean_state_sha256)
            or not _sha(do.linode_state_sha256)
            or not _retained_ids(do.retained_digitalocean_ids, "digitalocean")
            or not _retained_ids(do.retained_linode_ids, "linode")
            or type(do.new_edge_address) is not str
            or not _DO_NODE.fullmatch(do.new_edge_address)
            or not do.new_edge_address.startswith("digitalocean_droplet.edge[")
            or type(linode.new_edge_address) is not str
            or not _LINODE_EDGE.fullmatch(linode.new_edge_address)
            or do.new_edge_address in dict(do.retained_digitalocean_ids)
            or linode.new_edge_address in dict(do.retained_linode_ids)
            or dict(do.retained_linode_ids).get(do.linode_middle_address)
            != do.linode_middle_id
            or dict(do.retained_digitalocean_ids).get(linode.digitalocean_middle_address)
            != linode.digitalocean_middle_id):
        raise MixedAppendPairPlanError("paired append original generation or selected middles differ")
    by_provider = {"digitalocean": do, "linode": linode}
    for row in receipts_in_reviewed_order:
        provider = row["provider"]
        intent = by_provider[provider]
        predecessor = (do.digitalocean_state_sha256 if provider == "digitalocean"
                       else do.linode_state_sha256)
        if (row["engagementId"] != do.engagement_id
                or row["coreJobId"] != do.core_job_id
                or row["chainId"] != intent.chain_id
                or row["predecessorStateSha256"] != predecessor
                or row["newEdgeAddress"] != intent.new_edge_address
                or not all(_sha(row[key]) for key in (
                    "planSha256", "showJsonSha256", "sourceSha256",
                    "credentialSecretSha256"))
                or any(type(row[key]) is not str or not row[key] for key in (
                    "sourceRevision", "credentialRecordId", "credentialUpdatedAt"))):
            raise MixedAppendPairPlanError("paired append receipt is stale or crossed")
    if receipts_in_reviewed_order[0]["planSha256"] == receipts_in_reviewed_order[1]["planSha256"]:
        raise MixedAppendPairPlanError("paired append receipts reuse one saved plan")
    payload = {
        "schema": "mixed-append-pair-plan-v1", "providerOrder": reviewed_provider_order,
        "chainOrder": reviewed_chain_order, "digitaloceanIntent": asdict(do),
        "linodeIntent": asdict(linode),
        "receipts": [dict(row) for row in receipts_in_reviewed_order],
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True,
                                       separators=(",", ":")).encode()).hexdigest()
    return MixedAppendPairPlanSeal(
        do.engagement_id, do.core_job_id, reviewed_provider_order,
        reviewed_chain_order, do.digitalocean_state_sha256, do.linode_state_sha256,
        tuple(by_provider[p].new_edge_address for p in reviewed_provider_order),
        tuple(row["planSha256"] for row in receipts_in_reviewed_order), digest,
    )


def _sha(value: object) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def _retained_ids(rows: object, provider: str) -> bool:
    if (type(rows) is not tuple or any(
            type(row) is not tuple or len(row) != 2
            or any(type(value) is not str or not value for value in row)
            for row in rows)):
        return False
    addresses = [address for address, _ in rows]
    shared = _SHARED_DO if provider == "digitalocean" else _SHARED_LINODE
    node_pattern = _DO_NODE if provider == "digitalocean" else _LINODE_NODE
    nodes = {address for address in addresses if node_pattern.fullmatch(address)}
    return (rows == tuple(sorted(rows)) and len(addresses) == len(set(addresses))
            and len(nodes) == 2
            and sum(".middle[" in address for address in nodes) == 1
            and sum(".edge[" in address for address in nodes) == 1
            and set(addresses) == nodes | shared)
