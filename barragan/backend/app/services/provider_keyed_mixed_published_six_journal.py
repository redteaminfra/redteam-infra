# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only historical command/proof grammar for a published append.

Call after ``derive_mixed_published_six_policies`` has authenticated the full
saved-artifact approval, paired plan seal, and original reviewed policy. This
additional check authenticates the historical successful command and poststate
journals; it is not a full source audit, process check, or destroy authority.
"""

from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
from typing import Callable, Mapping

from app.services.provider_keyed_mixed_append_pair_apply_binding import _intent
from app.services.provider_keyed_mixed_append_pair_host_proof import (
    SixNodeHostSource, validate_six_node_host_source,
)
from app.services.provider_keyed_mixed_append_pair_parent import _plan_child_id
from app.services.provider_keyed_mixed_append_pair_plan_worker import _name, _read
from app.services.provider_keyed_mixed_append_first_poststate import FirstResultJournal
from app.services.provider_keyed_mixed_append_first_proof_job import (
    _ApprovedFirstSource, _journal as first_journal,
)
from app.services.provider_keyed_mixed_append_second_proof_job import _journal as second_journal
from app.storage.job_repository import StoredJobRun, job_event_digest


class MixedPublishedSixJournalAttention(ValueError):
    """The publication lacks exact terminal one-shot provider journals."""


def validate_mixed_published_six_journals(
    source: SixNodeHostSource, append_parent: StoredJobRun,
    provider_children: Mapping[str, StoredJobRun], *, artifact_reader: Callable = _read,
    unpublished_cleanup: bool = False,
) -> tuple[FirstResultJournal, FirstResultJournal]:
    """Reopen both terminal provider grammars without invoking any command.

    The policy derivation prerequisite authenticates topology, lockfile, review
    request and paired plan. Recheck the receipt and command artifacts here so
    a file change between readers cannot substitute a different result source.
    The collector must separately fence jobs/files and prove process quiescence.
    """
    try:
        validate_six_node_host_source(source)
        order, data = source.provider_order, append_parent.input
        publication = append_parent.events[-1]
        if (append_parent.id != source.parent_id
                or append_parent.action != "provider_keyed_mixed_append"
                or (not unpublished_cleanup and (append_parent.status != "succeeded" or append_parent.finished_at is None))
                or (unpublished_cleanup and (append_parent.status != "running" or append_parent.finished_at is not None
                    or data.get("phase") != "apply_sealed"))
                or append_parent.target_id != source.engagement_id
                or append_parent.target_type != "engagement"
                or append_parent.target != f"engagement:{source.engagement_id}"
                or data.get("schema") != "mixed-append-pair-parent-v1"
                or data.get("engagementId") != source.engagement_id
                or data.get("coreJobId") != source.core_job_id
                or data.get("corePlanId") != source.core_plan_id
                or tuple(data.get("providerOrder", ())) != order
                or tuple(data.get("chainOrder", ())) != source.chain_ids
                or set(provider_children) != set(order)
                or (not unpublished_cleanup and (data.get("phase") != "completed"
                or publication.message != "mixed append six-node generation published"
                or publication.data.get("sourceSha256") != source.source_sha256
                or publication.data.get("source") != json.loads(json.dumps(asdict(source)))))):
            raise ValueError("historical append publication differs")
        historical = (append_parent if unpublished_cleanup else replace(append_parent, status="running", finished_at=None,
            input={**data, "phase": "apply_sealed"}, events=append_parent.events[:-1]))
        if (not historical.events or historical.events[-1].message != "mixed append pair approved"
                or historical.events[-1].data != {
                    "reviewSha256": data["reviewSha256"],
                    "planChildId": _plan_child_id(append_parent.id)}):
            raise ValueError("historical append approval differs")
        results = []
        first_digest = job_event_digest(provider_children[order[0]].events)
        for index, provider in enumerate(order):
            child = provider_children[provider]
            if (child.target_type != "engagement" or child.target != append_parent.target
                    or child.artifact_refs != [] or len(child.events) != 10
                    or job_event_digest(child.events) != source.provider_proof_digests[index]):
                raise ValueError("historical provider identity differs")
            root = Path(source.workspace_paths[index])
            def read(suffix):
                value = artifact_reader(root / _name(provider, suffix))
                if type(value) is not bytes:
                    raise ValueError("historical artifact bytes differ")
                return value
            def sha(value: bytes) -> str:
                return hashlib.sha256(value).hexdigest()
            raw = read("plan-receipt.json")
            receipt = json.loads(raw)
            intent = _intent(provider, data["intents"][provider])
            predecessor, shown = read("predecessor.tfstate"), read("show.json")
            inputs = read("inputs.json")
            if (sha(raw) != data["receiptSha256"][provider]
                    or receipt.get("schema") != "mixed-append-saved-plan-receipt-v1"
                    or receipt.get("provider") != provider
                    or receipt.get("engagementId") != source.engagement_id
                    or receipt.get("coreJobId") != source.core_job_id
                    or receipt.get("chainId") != source.chain_ids[index]
                    or intent.chain_id != source.chain_ids[index]
                    or receipt.get("newEdgeAddress") != source.new_edge_addresses[index]
                    or intent.new_edge_address != source.new_edge_addresses[index]
                    or receipt.get("predecessorStateSha256") != sha(predecessor)
                    or sha(predecessor) != (intent.digitalocean_state_sha256
                        if provider == "digitalocean" else intent.linode_state_sha256)
                    or receipt.get("showJsonSha256") != sha(shown)
                    or receipt.get("planSha256") != sha(read("saved.tfplan"))
                    or receipt.get("inputSha256") != sha(inputs)
                    or json.loads(inputs) != intent.nonsecret_varfile
                    or data["reviewedInputs"][provider] != intent.nonsecret_varfile):
                raise ValueError("historical append command artifacts differ")
            approved = _ApprovedFirstSource(None, intent, receipt, sha(raw), predecessor, shown)
            result, stage = (first_journal(historical, child, approved) if index == 0
                             else second_journal(historical, child, approved, first_digest))
            new_edge = source.chains[index].nodes[2]
            proof = child.events[8].data
            if (proof.get("newEdgeProviderId") != new_edge.get("providerInstanceId")
                    or proof.get("newEdgePublicIp") != new_edge.get("publicIp")
                    or proof.get("stateSha256") != source.state_sha256s[index]):
                raise ValueError("historical poststate publication differs")
            if stage != "terminal":
                raise ValueError("historical append provider not terminal")
            results.append(result)
        return tuple(results)
    except Exception:
        raise MixedPublishedSixJournalAttention(
            "published six-node command and proof journals require exact review") from None
