# Copyright (c) 2026, Oracle and/or its affiliates.
"""Reopen the exact six-node generation saved by mixed append publication.

The source is the append writer's immutable historical snapshot.  Current
chain rows are checked separately; they cannot reconstruct that history.
This reader grants no destroy or external-binding DELETE authority.
"""

from __future__ import annotations

from dataclasses import asdict, fields, replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Callable, Mapping

from app.services.provider_keyed_mixed_append_pair_apply_binding import _intent
from app.services.provider_keyed_mixed_append_pair_parent import _matches_request
from app.services.provider_keyed_mixed_append_pair_plan import seal_mixed_append_pair_plan
from app.services.provider_keyed_mixed_append_pair_plan_worker import (
    _name, _read, _RECEIPT_KEYS, _SUMMARY_KEYS,
)
from app.services.provider_keyed_mixed_append_pair_host_proof import (
    SixHostProofReceipt, SixNodeHostSource, validate_six_host_receipt_child,
    validate_six_node_host_source,
)
from app.services.provider_keyed_mixed_initial_plan_parent import validate_mixed_initial_apply_seal
from app.storage.job_repository import StoredJobRun, job_event_digest
from app.storage.sketch_chain_repository import StoredSketchChain


class MixedPublishedSixSourceAttention(ValueError):
    """The saved append generation no longer proves the current six hosts."""


def _chain(raw: object) -> StoredSketchChain:
    if type(raw) is not dict or set(raw) != {
            field.name for field in fields(StoredSketchChain)}:
        raise ValueError("saved six-node chain schema differs")
    return StoredSketchChain(**raw)


def _pair(raw: object) -> tuple[str, str]:
    if (type(raw) is not list or len(raw) != 2
            or any(type(value) is not str for value in raw)):
        raise ValueError("saved six-node pair differs")
    return tuple(raw)


def _source(raw: object) -> SixNodeHostSource:
    if type(raw) is not dict or set(raw) != {
            field.name for field in fields(SixNodeHostSource)}:
        raise ValueError("saved six-node source schema differs")
    value = dict(raw)
    for name in ("provider_order", "chain_ids", "new_edge_addresses",
                 "provider_proof_digests", "state_sha256s", "workspace_paths",
                 "source_revisions", "proxy_egress_ips"):
        value[name] = _pair(value[name])
    for name in ("before_chains", "chains"):
        rows = value[name]
        if type(rows) is not list or len(rows) != 2:
            raise ValueError("saved six-node chain pair differs")
        value[name] = tuple(_chain(row) for row in rows)
    source = SixNodeHostSource(**value)
    validate_six_node_host_source(source)
    if json.loads(json.dumps(asdict(source))) != raw:
        raise ValueError("saved six-node source encoding differs")
    return source


def same_published_chain(current: StoredSketchChain,
                         published: StoredSketchChain) -> bool:
    """Compare exact chain data across SQLite's UTC timezone serialization."""
    try:
        if type(current) is not StoredSketchChain or type(published) is not StoredSketchChain:
            return False
        def utc(value: str) -> datetime:
            stamp = datetime.fromisoformat(value)
            return (stamp.replace(tzinfo=timezone.utc) if stamp.tzinfo is None
                    else stamp.astimezone(timezone.utc))
        return (utc(current.created_at) == utc(published.created_at)
                and utc(current.updated_at) == utc(published.updated_at)
                and replace(current, created_at=published.created_at,
                            updated_at=published.updated_at) == published)
    except (ValueError, TypeError):
        return False


def _receipt(parent: StoredJobRun, child: StoredJobRun) -> SixHostProofReceipt:
    if not child.events or type(child.events[-1].data) is not dict:
        raise ValueError("saved six-host receipt is absent")
    data = child.events[-1].data
    expected = {"sourceSha256", "providerOrder", "chainIds",
                "newEdgeAddresses", "newEdgeIds", "providerProofDigests",
                "bootstrapEventDigests", "sketchKnownHostsDigests",
                "rawProbeDigests"}
    if set(data) != expected:
        raise ValueError("saved six-host receipt schema differs")
    return SixHostProofReceipt(
        parent.id, child.id, data["sourceSha256"],
        _pair(data["providerOrder"]), _pair(data["chainIds"]),
        _pair(data["newEdgeAddresses"]), _pair(data["newEdgeIds"]),
        _pair(data["providerProofDigests"]),
        _pair(data["bootstrapEventDigests"]),
        _pair(data["sketchKnownHostsDigests"]),
        _pair(data["rawProbeDigests"]), job_event_digest(child.events),
        child.input["claimOwner"], child.input["claimToken"],
    )


def recognize_mixed_published_six_source(
    append_parent: StoredJobRun, *, host_proof_child: StoredJobRun,
    provider_children: Mapping[str, StoredJobRun],
    current_chains: Mapping[str, StoredSketchChain],
    host_receipt_validator: Callable = validate_six_host_receipt_child,
) -> tuple[SixNodeHostSource, SixHostProofReceipt]:
    """Authenticate publication history and current rows from caller-fresh reads.

    The caller obtains these rows under the engagement fence and rereads them
    before any provider GO.  The existing host validator reopens retained raw
    evidence; this adapter never replaces its one-shot proof.
    """
    try:
        if (type(append_parent) is not StoredJobRun
                or append_parent.action != "provider_keyed_mixed_append"
                or append_parent.status != "succeeded"
                or append_parent.finished_at is None
                or append_parent.input.get("phase") != "completed"
                or not append_parent.events
                or append_parent.events[-1].message
                   != "mixed append six-node generation published"):
            raise ValueError("mixed append publication is absent")
        event = append_parent.events[-1].data
        if type(event) is not dict:
            raise ValueError("mixed append publication data differs")
        source = _source(event.get("source"))
        order = source.provider_order
        if (source.parent_id != append_parent.id
                or source.engagement_id != append_parent.target_id
                or source.core_job_id != append_parent.input.get("coreJobId")
                or source.core_plan_id != append_parent.input.get("corePlanId")
                or list(order) != append_parent.input.get("providerOrder")
                or list(source.chain_ids) != append_parent.input.get("chainOrder")
                or set(provider_children) != set(order)
                or set(current_chains) != set(source.chain_ids)
                or any(not same_published_chain(current_chains[chain.chain_id], chain)
                       for chain in source.chains)
                or event != {
                    "sourceSha256": source.source_sha256,
                    "source": json.loads(json.dumps(asdict(source))),
                    "hostProofJournalSha256": job_event_digest(host_proof_child.events),
                    "providerProofJournalSha256": {
                        provider: source.provider_proof_digests[index]
                        for index, provider in enumerate(order)},
                    "chainIds": list(source.chain_ids),
                }
                or any(job_event_digest(provider_children[provider].events)
                       != source.provider_proof_digests[index]
                       for index, provider in enumerate(order))):
            raise ValueError("mixed append saved source or current rows differ")
        receipt = _receipt(append_parent, host_proof_child)
        if host_receipt_validator(
                append_parent, host_proof_child, receipt,
                source=source) != receipt:
            raise ValueError("mixed append retained host proof differs")
        return source, receipt
    except Exception:
        raise MixedPublishedSixSourceAttention(
            "published six-node history requires exact append proof") from None


def derive_mixed_published_six_policies(
    source: SixNodeHostSource, append_parent: StoredJobRun,
    initial_parent: StoredJobRun, *,
    artifact_reader: Callable = _read,
    initial_seal_reader: Callable = validate_mixed_initial_apply_seal,
    pair_sealer: Callable = seal_mixed_append_pair_plan,
    unpublished_cleanup: bool = False,
) -> dict[str, dict]:
    """Reopen final Terraform inputs and extend the original reviewed policy.

    The append approval persisted both reviewed intents and exact saved-plan
    receipt hashes.  This reader checks those files against the approval and
    the six-node publication, then returns the final three-node policies.  It
    neither runs Terraform nor treats current state as its own review source.
    """
    try:
        validate_six_node_host_source(source)
        order, data = source.provider_order, append_parent.input
        if (append_parent.id != source.parent_id
                or (not unpublished_cleanup and (append_parent.status != "succeeded"
                    or append_parent.finished_at is None))
                or (unpublished_cleanup and (append_parent.status != "running"
                    or append_parent.finished_at is not None or data.get("phase") != "apply_sealed"))
                or append_parent.action != "provider_keyed_mixed_append"
                or append_parent.target_id != source.engagement_id
                or not append_parent.events
                or (not unpublished_cleanup and (data.get("phase") != "completed"
                or append_parent.events[-1].message
                   != "mixed append six-node generation published"
                or append_parent.events[-1].data.get("sourceSha256")
                   != source.source_sha256
                or append_parent.events[-1].data.get("source")
                   != json.loads(json.dumps(asdict(source)))))
                or data.get("coreJobId") != source.core_job_id
                or data.get("corePlanId") != source.core_plan_id
                or tuple(data.get("providerOrder", ())) != order
                or tuple(data.get("chainOrder", ())) != source.chain_ids
                or set(data.get("intents", {})) != set(order)
                or set(data.get("reviewedInputs", {})) != set(order)
                or set(data.get("receiptSha256", {})) != set(order)
                or initial_parent.target_id != source.engagement_id
                or initial_parent.input.get("engagementId") != source.engagement_id
                or initial_parent.input.get("coreJobId") != source.core_job_id):
            raise ValueError("mixed append final policy parent differs")
        initial = initial_seal_reader(initial_parent)
        if (initial.get("corePlanId") != source.core_plan_id
                or set(initial.get("reviewedPolicy", {})) != set(order)):
            raise ValueError("mixed append initial reviewed policy differs")
        intents = {provider: _intent(provider, data["intents"][provider])
                   for provider in order}
        if (not _matches_request(data["reviewRequest"],
                                 intents["digitalocean"], intents["linode"])
                or any(data["reviewedInputs"][provider]
                       != intents[provider].nonsecret_varfile
                       for provider in order)):
            raise ValueError("mixed append approved intent differs")
        receipts, final = {}, {}
        for index, provider in enumerate(order):
            intent, root = intents[provider], Path(source.workspace_paths[index])
            def read(suffix: str, *, private: bool = True) -> bytes:
                value = artifact_reader(root / suffix, private=private)
                if type(value) is not bytes:
                    raise ValueError("mixed append artifact bytes differ")
                return value
            def sha(value: bytes) -> str:
                return hashlib.sha256(value).hexdigest()
            receipt_bytes = read(_name(provider, "plan-receipt.json"))
            receipt = json.loads(receipt_bytes)
            inputs_bytes = read(_name(provider, "inputs.json"))
            predecessor = read(_name(provider, "predecessor.tfstate"))
            topology_bytes = read(".barragan-topology.json", private=False)
            if (type(receipt) is not dict or set(receipt) != _RECEIPT_KEYS
                    or sha(receipt_bytes) != data["receiptSha256"][provider]
                    or receipt["schema"] != "mixed-append-saved-plan-receipt-v1"
                    or receipt["provider"] != provider
                    or receipt["engagementId"] != source.engagement_id
                    or receipt["coreJobId"] != source.core_job_id
                    or receipt["chainId"] != intent.chain_id
                    or receipt["newEdgeAddress"] != intent.new_edge_address
                    or receipt["sourceRevision"] != source.source_revisions[index]
                    or receipt["predecessorStateSha256"] != sha(predecessor)
                    or receipt["predecessorStateSha256"] != (
                        intent.digitalocean_state_sha256 if provider == "digitalocean"
                        else intent.linode_state_sha256)
                    or receipt["inputSha256"] != sha(inputs_bytes)
                    or json.loads(inputs_bytes) != data["reviewedInputs"][provider]
                    or receipt["planSha256"] != sha(read(_name(provider, "saved.tfplan")))
                    or receipt["showJsonSha256"] != sha(read(_name(provider, "show.json")))
                    or receipt["topologySha256"] != sha(topology_bytes)
                    or receipt["sourceMarkerSha256"] != sha(read(
                        ".barragan-provider-keyed-state.json", private=False))
                    or receipt["lockfileSha256"] != sha(read(
                        ".terraform.lock.hcl", private=False))):
                raise ValueError("mixed append saved plan receipt differs")
            receipts[provider] = {key: receipt[key] for key in _SUMMARY_KEYS}
            new_node = source.chains[index].nodes[2]
            expected_size = (intent.new_edge.size if provider == "digitalocean"
                             else intent.new_edge.node_type)
            if (intent.chain_id != source.chain_ids[index]
                    or intent.new_edge_address != source.new_edge_addresses[index]
                    or intent.new_edge_address != new_node.get("terraformAddress")
                    or new_node.get("provider") != provider
                    or new_node.get("hostname") != (
                        intent.new_edge.name if provider == "digitalocean"
                        else intent.new_edge.label)
                    or new_node.get("region") != intent.new_edge.region
                    or source.chains[index].edge_intents[-1] != {
                        "id": "edge-02", "provider": provider,
                        "region": intent.new_edge.region, "size": expected_size}):
                raise ValueError("mixed append final node differs")
            base = json.loads(json.dumps(initial["reviewedPolicy"][provider]))
            old = {node["terraformAddress"] for chain in source.before_chains
                   for node in chain.nodes if node["provider"] == provider}
            if (type(base) is not dict or type(base.get("nodes")) is not dict
                    or set(base["nodes"]) != old
                    or intent.new_edge_address in old):
                raise ValueError("mixed append retained policy nodes differ")
            base["nodes"][intent.new_edge_address] = asdict(intent.new_edge)
            base["nonsecret_varfile"] = json.loads(inputs_bytes)
            base["topology"] = json.loads(topology_bytes)
            final[provider] = base
        seal = pair_sealer(
            intents["digitalocean"], intents["linode"],
            tuple(receipts[provider] for provider in order),
            reviewed_provider_order=order,
            reviewed_chain_order=source.chain_ids)
        if seal.review_sha256 != data.get("pairPlanSha256"):
            raise ValueError("mixed append paired plan review differs")
        return final
    except Exception:
        raise MixedPublishedSixSourceAttention(
            "published six-node policies require exact saved append review") from None
