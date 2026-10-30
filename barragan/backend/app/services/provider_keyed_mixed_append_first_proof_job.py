# Copyright (c) 2026, Oracle and/or its affiliates.
"""Durable exact first-provider proof after a one-shot mixed append Apply.

Only GETs and claimed job events occur here. The first provider's live state
has intentionally changed, so this worker never reopens the original four-host
source or runs Terraform again. An uncertain command journal is attention.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from typing import Callable
from uuid import UUID, uuid4

from app.domain import JobEvent
from app.services.provider_keyed_initial_destroy_pre_go_recovery import _process_quiescent
from app.services.provider_keyed_mixed_append_first_poststate import (
    FirstPoststateProof, FirstResultJournal,
    collect_first_mixed_append_inventory_snapshot,
    observe_first_mixed_append_poststate,
    recognize_first_mixed_append_zero_result,
)
from app.services.provider_keyed_mixed_append_pair_apply_binding import _intent
from app.services.provider_keyed_mixed_append_pair_apply_child import _child_id
from app.services.provider_keyed_mixed_append_pair_plan_worker import (
    _journal_complete, _name, _read, _sha,
)
from app.services.provider_keyed_mixed_append_pair_parent import _digest, _plan_child_id
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id as initial_child_id, _prior_workspace,
    recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_initial_host_binding import (
    _binding_child_id, recognize_mixed_initial_host_binding,
)
from app.services.provider_keyed_mixed_initial_plan_parent import _parent_id as initial_parent_id
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest


_OPERATION = "provider_keyed_mixed_append"
_PROOF_EVENT = "mixed append first exact poststate proved"
_TERMINAL_EVENT = "mixed append first provider Apply succeeded"


class MixedAppendFirstProofJobAttention(ValueError):
    """The first provider's exact result or current ownership needs review."""


@dataclass(frozen=True)
class _ApprovedFirstSource:
    workspace: object
    intent: object
    receipt: dict
    receipt_sha256: str
    predecessor_state: bytes
    reviewed_show_json: bytes


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(value: str) -> str:
    return (datetime.fromisoformat(value) + timedelta(seconds=120)).isoformat()


def _load_approved_first_source(parent: StoredJobRun, jobs,
                                release_check) -> _ApprovedFirstSource:
    """Rebind persisted approval to immutable artifacts, not live four-node state."""
    data = parent.input
    provider = data["providerOrder"][0]
    if (parent.action != _OPERATION or parent.status != "running"
            or data.get("schema") != "mixed-append-pair-parent-v1"
            or data.get("phase") != "apply_sealed"
            or data.get("engagementId") != parent.target_id
            or set(data.get("providerOrder", [])) != {"digitalocean", "linode"}
            or parent.events[-1].message != "mixed append pair approved"
            or parent.events[-1].data != {
                "reviewSha256": data["reviewSha256"],
                "planChildId": _plan_child_id(parent.id)}):
        raise ValueError("mixed append approval differs")
    plan_child = jobs.get(_plan_child_id(parent.id))
    if (plan_child is None or plan_child.status != "succeeded"
            or plan_child.input.get("requestSha256") != data.get("requestSha256")
            or plan_child.events[-1].message != "mixed append pair plan reviewed"
            or plan_child.events[-1].data != {"reviewSha256": data["reviewSha256"]}):
        raise ValueError("mixed append paired plan approval differs")
    initial = jobs.get(initial_parent_id(data["coreJobId"]))
    binding = jobs.get(_binding_child_id(data["coreJobId"]))
    if initial is None or binding is None or initial.target_id != parent.target_id:
        raise ValueError("mixed append original publication missing")
    historical = replace(initial, events=initial.events[:7])
    manifest = recognize_mixed_initial_host_binding(binding, historical)
    if _digest(manifest) != data["bindingManifestSha256"]:
        raise ValueError("mixed append historical binding differs")
    initial_child = jobs.get(initial_child_id(data["coreJobId"], provider))
    terminal = recognize_mixed_initial_apply_terminal(initial_child, historical, provider)
    workspace = _prior_workspace(initial, provider, terminal)
    intent = _intent(provider, data["intents"][provider])
    root = workspace.path
    receipt_bytes = _read(root / _name(provider, "plan-receipt.json"))
    receipt = json.loads(receipt_bytes)
    predecessor = _read(root / _name(provider, "predecessor.tfstate"))
    shown = _read(root / _name(provider, "show.json"))
    binary = _read(root / _name(provider, "saved.tfplan"))
    inputs = _read(root / _name(provider, "inputs.json"))
    release = release_check(environment="devtest")
    if (_sha(receipt_bytes) != data["receiptSha256"][provider]
            or receipt.get("schema") != "mixed-append-saved-plan-receipt-v1"
            or receipt.get("provider") != provider
            or receipt.get("engagementId") != parent.target_id
            or receipt.get("coreJobId") != data["coreJobId"]
            or receipt.get("chainId") != intent.chain_id
            or receipt.get("newEdgeAddress") != intent.new_edge_address
            or receipt.get("predecessorStateSha256") != _sha(predecessor)
            or receipt.get("predecessorStateSha256") != (
                intent.digitalocean_state_sha256 if provider == "digitalocean"
                else intent.linode_state_sha256)
            or receipt.get("showJsonSha256") != _sha(shown)
            or receipt.get("planSha256") != _sha(binary)
            or receipt.get("inputSha256") != _sha(inputs)
            or json.loads(inputs) != data["reviewedInputs"][provider]
            or data["reviewedInputs"][provider] != intent.nonsecret_varfile
            or receipt.get("sourceMarkerSha256") != _sha(_read(
                root / ".barragan-provider-keyed-state.json", private=False))
            or receipt.get("topologySha256") != _sha(_read(
                root / ".barragan-topology.json", private=False))
            or receipt.get("lockfileSha256") != _sha(_read(
                root / ".terraform.lock.hcl", private=False))
            or receipt.get("sourceRevision") != workspace.source_revision
            or receipt.get("sourceSha256") != workspace.source_sha256
            or receipt.get("credentialRecordId") != workspace.provider_connection_id
            or receipt.get("terraformBinarySha256") != release.sha256
            or _sha(_read(release.path, private=False)) != release.sha256):
        raise ValueError("mixed append approved artifact differs")
    _journal_complete(root / _name(provider, "plan-journal.jsonl"),
                      receipt["journalSha256"])
    return _ApprovedFirstSource(workspace, intent, receipt,
                                _sha(receipt_bytes), predecessor, shown)


def _valid_proof_data(data: dict, parent: StoredJobRun,
                      source: _ApprovedFirstSource,
                      result: FirstResultJournal) -> bool:
    try:
        receipt, intent = source.receipt, source.intent
        provider = result.provider
        originals = dict(intent.retained_digitalocean_ids if provider == "digitalocean"
                         else intent.retained_linode_ids)
        expected = (set(originals) - {"local_file.ansible_inventory[0]",
                                      "local_file.ssh_stanza[0]"}) | {intent.new_edge_address}
        rows = data["resourceIds"]
        ids = dict(rows)
        prior = json.loads(source.predecessor_state)
        UUID(data["lineage"])
        ip = ipaddress.IPv4Address(data["newEdgePublicIp"])
        return (
            set(data) == {
                "schema", "provider", "reviewSha256", "receiptSha256",
                "resultJournalSha256", "predecessorStateSha256", "stateSha256",
                "lineage", "serial", "resourceIds", "newEdgeAddress",
                "newEdgeProviderId", "newEdgePublicIp", "inventorySha256",
                "observationSha256", "selectorResourcesCount", "attachedNodeIds"}
            and data["schema"] == "mixed-append-first-poststate-v1"
            and data["provider"] == provider
            and data["reviewSha256"] == parent.input["reviewSha256"]
            and data["receiptSha256"] == source.receipt_sha256
            and data["resultJournalSha256"] == result.result_sha256
            and data["predecessorStateSha256"] == receipt["predecessorStateSha256"]
            and all(type(data[key]) is str and len(data[key]) == 64
                    and all(character in "0123456789abcdef" for character in data[key])
                    for key in ("stateSha256", "inventorySha256", "observationSha256"))
            and data["stateSha256"] != receipt["predecessorStateSha256"]
            and data["lineage"] == prior["lineage"]
            and type(data["serial"]) is int and data["serial"] > prior["serial"]
            and type(rows) is list and len(rows) == len(expected)
            and all(type(row) is list and len(row) == 2
                    and all(type(value) is str and value for value in row) for row in rows)
            and rows == sorted(rows) and set(ids) == expected
            and all(ids[address] == original_id for address, original_id in originals.items()
                    if address in ids)
            and data["newEdgeAddress"] == intent.new_edge_address
            and data["newEdgeProviderId"] == ids[intent.new_edge_address]
            and ip.is_global
            and type(data["attachedNodeIds"]) is list
            and data["attachedNodeIds"] == sorted(set(data["attachedNodeIds"]))
            and set(data["attachedNodeIds"]) == {
                identifier for address, identifier in ids.items()
                if address.startswith("linode_instance." if provider == "linode"
                                      else "digitalocean_droplet.")}
            and (data["selectorResourcesCount"] is None if provider == "linode"
                 else data["selectorResourcesCount"] == len(data["attachedNodeIds"])))
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


def _journal(parent: StoredJobRun, child: StoredJobRun,
             source: _ApprovedFirstSource) -> tuple[FirstResultJournal, str]:
    """Recognize awaiting, proved, or terminal without interpreting state."""
    if child.status not in {"running", "succeeded"} or len(child.events) not in {8, 9, 10}:
        raise ValueError("mixed append child has no exact successful result")
    initial = replace(child, status="running", finished_at=None,
                      events=child.events[:8])
    result = recognize_first_mixed_append_zero_result(parent, initial, source.receipt)
    if len(child.events) == 8:
        if child.status != "running":
            raise ValueError("mixed append pending result status differs")
        return result, "awaiting"
    proof = child.events[8]
    if (proof.sequence != 9 or proof.level != "info" or proof.message != _PROOF_EVENT
            or not isinstance(proof.data, dict)
            or not _valid_proof_data(proof.data, parent, source, result)):
        raise ValueError("mixed append first proof event differs")
    if len(child.events) == 9:
        if child.status != "running":
            raise ValueError("mixed append proved result status differs")
        return result, "proved"
    terminal = child.events[9]
    if (child.status != "succeeded" or child.finished_at is None
            or terminal.sequence != 10 or terminal.level != "info"
            or terminal.message != _TERMINAL_EVENT
            or terminal.data != {"proofJournalSha256": job_event_digest(child.events[:9])}):
        raise ValueError("mixed append first terminal event differs")
    return result, "terminal"


def _proof_event_data(parent: StoredJobRun, source: _ApprovedFirstSource,
                      journal: FirstResultJournal, proof: FirstPoststateProof) -> dict:
    if (proof.provider != journal.provider
            or proof.new_edge_address != source.intent.new_edge_address
            or proof.state_sha256 == source.receipt["predecessorStateSha256"]):
        raise ValueError("mixed append first poststate proof differs")
    return {
        "schema": "mixed-append-first-poststate-v1",
        "provider": proof.provider,
        "reviewSha256": parent.input["reviewSha256"],
        "receiptSha256": source.receipt_sha256,
        "resultJournalSha256": journal.result_sha256,
        "predecessorStateSha256": source.receipt["predecessorStateSha256"],
        "stateSha256": proof.state_sha256,
        "lineage": proof.lineage,
        "serial": proof.serial,
        "resourceIds": [list(row) for row in proof.resource_ids],
        "newEdgeAddress": proof.new_edge_address,
        "newEdgeProviderId": proof.new_edge_provider_id,
        "newEdgePublicIp": proof.new_edge_public_ip,
        "inventorySha256": proof.inventory_sha256,
        "observationSha256": proof.observation_sha256,
        "selectorResourcesCount": proof.selector_resources_count,
        "attachedNodeIds": list(proof.attached_node_ids),
    }


def prove_and_finish_first_mixed_append_apply(
    parent_id: str, *, environment: str, job_repository=None,
    lease_lookup=None, credential_repository=None,
    linode_transport=None, digitalocean_transport=None,
    process_quiescent: Callable[[dict], bool] | None = None,
    claim_owner: str | None = None, claim_token: str | None = None,
    source_loader: Callable | None = None,
    snapshot_collector: Callable = collect_first_mixed_append_inventory_snapshot,
    poststate_observer: Callable = observe_first_mixed_append_poststate,
    release_check: Callable = require_devtest_terraform_release,
    max_observation_attempts: int = 60, poll_interval_seconds: float = 5.0,
    sleeper=None,
) -> StoredJobRun:
    """Finish only a proved first write; restart never invokes Apply again."""
    if environment != "devtest":
        raise MixedAppendFirstProofJobAttention("mixed append first proof is DevTest-only")
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    quiescent = process_quiescent or (lambda identity: _process_quiescent(
        identity["bootId"], identity["pid"], identity["pgid"], identity["startTicks"]))
    try:
        parent = jobs.get(parent_id)
        if (parent is None or parent.action != _OPERATION or parent.status != "running"
                or parent.input.get("phase") != "apply_sealed"
                or lookup(parent.target_id) != (parent.input["corePlanId"], _OPERATION)):
            raise ValueError("mixed append first proof parent or lease changed")
        child = jobs.get(_child_id(parent.id))
        if child is None:
            raise ValueError("mixed append first Apply child missing")
        loader = source_loader or _load_approved_first_source
        source = loader(parent, jobs, release_check)
        journal, stage = _journal(parent, child, source)
        if stage == "terminal":
            return child
        if not quiescent(journal.started_identity):
            raise ValueError("mixed append first Apply process may still run")
        if (claim_owner is None) != (claim_token is None):
            raise ValueError("mixed append proof claim pair incomplete")
        if claim_owner is not None and (
                child.input.get("claimOwner") != claim_owner
                or child.input.get("claimToken") != claim_token):
            raise ValueError("mixed append first proof claim differs")
        owner = claim_owner or f"mixed-append-first-proof-{uuid4().hex}"
        token = claim_token or uuid4().hex
        at = _now()
        claimed = jobs.claim_lease(child.id, owner=owner, token=token,
                                   claimed_at=at, expires_at=_later(at),
                                   eligible_statuses={"running"})
        if claimed is None or job_event_digest(claimed.events) != job_event_digest(child.events):
            raise ValueError("mixed append first proof claim unavailable")
        child = claimed
        generation = _digest({"parent": job_event_digest(parent.events),
                              "result": journal.result_sha256,
                              "receipt": source.receipt_sha256, "claim": token})

        def fence() -> str:
            nonlocal child
            if (lookup(parent.target_id) != (parent.input["corePlanId"], _OPERATION)
                    or jobs.get(parent.id) != parent or jobs.get(child.id) != child
                    or datetime.now(timezone.utc) >= datetime.fromisoformat(
                        child.input["claimExpiresAt"])):
                raise ValueError("mixed append first proof generation changed")
            now = _now()
            renewed = jobs.renew_lease(child.id, owner=owner, token=token,
                                       heartbeat_at=now, expires_at=_later(now))
            if renewed is None or renewed.events != child.events:
                raise ValueError("mixed append first proof heartbeat lost")
            child = renewed
            return generation

        def read_snapshot():
            return snapshot_collector(
                intent=source.intent, workspace=source.workspace,
                receipt=source.receipt, fence=fence,
                process_quiescent=lambda: quiescent(journal.started_identity),
                credential_repository=credential_repository or SqlAlchemyCredentialRepository(),
                linode_transport=linode_transport,
                digitalocean_transport=digitalocean_transport)

        options = dict(
            intent=source.intent, predecessor_state=source.predecessor_state,
            reviewed_show_json=source.reviewed_show_json,
            journal=journal, snapshot_reader=read_snapshot,
            fence=fence, process_quiescent=quiescent,
            max_attempts=max_observation_attempts,
            poll_interval_seconds=poll_interval_seconds)
        if sleeper is not None:
            options["sleeper"] = sleeper
        proof = poststate_observer(**options)
        data = _proof_event_data(parent, source, journal, proof)
        fence()
        if stage == "awaiting":
            at = _now()
            updated = jobs.append_event_if_running_claimed(
                child, owner=owner, token=token,
                expected_event_digest=job_event_digest(child.events),
                heartbeat_at=at, expires_at=_later(at),
                event=JobEvent(9, "info", _PROOF_EVENT, data))
            if updated is None:
                raise ValueError("mixed append first proof journal CAS lost")
            child = updated
            journal, stage = _journal(parent, child, source)
        if stage != "proved" or child.events[8].data != data:
            raise ValueError("mixed append first persisted proof differs")
        fence()
        terminal = jobs.finish_if_running_claimed(
            child, owner=owner, token=token,
            expected_event_digest=job_event_digest(child.events),
            status="succeeded", finished_at=_now(),
            event=JobEvent(10, "info", _TERMINAL_EVENT,
                           {"proofJournalSha256": job_event_digest(child.events)}))
        if terminal is None or _journal(parent, terminal, source)[1] != "terminal":
            raise ValueError("mixed append first terminal CAS lost")
        return terminal
    except Exception:
        raise MixedAppendFirstProofJobAttention(
            "mixed append first Apply poststate proof requires review") from None
