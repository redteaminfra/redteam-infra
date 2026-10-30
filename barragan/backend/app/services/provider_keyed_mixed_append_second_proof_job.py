# Copyright (c) 2026, Oracle and/or its affiliates.
"""GET-only second-provider proof after the one-shot mixed append Apply.

The first provider has already changed. Rebind the saved approval and the
first terminal proof, but never reopen the original four-host source or issue
another Terraform command. An uncertain second result is attention, not retry.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from dataclasses import replace
import ipaddress
import json
from typing import Callable
from uuid import UUID, uuid4

from app.domain import JobEvent
from app.services.provider_keyed_initial_destroy_pre_go_recovery import _process_quiescent
from app.services.provider_keyed_mixed_append_first_poststate import (
    FirstResultJournal, collect_first_mixed_append_inventory_snapshot,
    observe_first_mixed_append_poststate,
)
from app.services.provider_keyed_mixed_append_second_apply_binding import (
    _approved_second, build_second_mixed_append_apply_bindings,
)
from app.services.provider_keyed_mixed_append_second_apply_child import (
    ACTION, _CLAIM_KEYS, _base, _child_id,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest


_OPERATION = "provider_keyed_mixed_append"
_PROOF_EVENT = "mixed append second exact poststate proved"
_TERMINAL_EVENT = "mixed append second provider Apply succeeded"


class MixedAppendSecondProofJobAttention(ValueError):
    """The second provider's exact result or current ownership needs review."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(value: str) -> str:
    return (datetime.fromisoformat(value) + timedelta(seconds=120)).isoformat()


def _hex(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value)


def _result(parent: StoredJobRun, child: StoredJobRun, receipt: dict) -> FirstResultJournal:
    """Recognize only a persisted zero-result second one-shot journal."""
    base = _base(parent)
    events = child.events
    expected = [
        "mixed append second Apply queued",
        "mixed append second Apply started",
        "mixed append second Apply command intended",
        "mixed append second Apply command started before GO",
        "mixed append second phase apply_started",
        "mixed append second Apply command result fenced",
        "mixed append second phase applied",
        "mixed append second awaiting exact poststate proof",
    ]
    if (child.id != _child_id(parent.id) or child.action != ACTION
            or child.target_id != parent.target_id or child.target_type != "engagement"
            or child.target != parent.target or child.requested_by != parent.requested_by
            or child.started_at is None or child.artifact_refs != []
            or {key: value for key, value in child.input.items()
                if key not in _CLAIM_KEYS} != base or len(events) != 8
            or [(event.sequence, event.level, event.message) for event in events]
               != [(index, "info", message) for index, message in enumerate(expected, 1)]
            or events[0].data != {} or events[1].data != {}
            or events[2].data.get("invocationId") != events[3].data.get("invocationId")
            or events[3].data.get("invocationId") != events[5].data.get("invocationId")
            or not events[2].data.get("invocationId")
            or events[2].data.get("planSha256") != receipt.get("planSha256")
            or events[2].data.get("terraformSha256") != receipt.get("terraformBinarySha256")
            or not _hex(events[2].data.get("argvSha256"))
            or type(events[2].data.get("planPath")) is not str
            or not events[2].data["planPath"]
            or type(events[2].data.get("terraformPath")) is not str
            or not events[2].data["terraformPath"]
            or events[4].data != {"commandStartSequence": 4}
            or events[6].data != {"commandResultSequence": 6}
            or events[7].data != {"commandResultSequence": 6}
            or events[5].data.get("returnCode") != 0
            or events[5].data.get("stdoutTruncated") is not False
            or events[5].data.get("stderrTruncated") is not False
            or any(type(events[5].data.get(key)) is not int or events[5].data[key] < 0
                   for key in ("stdoutBytes", "stderrBytes"))):
        raise ValueError("mixed append second result journal differs")
    identity = {key: events[3].data[key]
                for key in ("bootId", "pid", "pgid", "startTicks")}
    if (type(identity["bootId"]) is not str or not identity["bootId"]
            or any(type(identity[key]) is not int or identity[key] <= 0
                   for key in ("pid", "pgid", "startTicks"))):
        raise ValueError("mixed append second process identity differs")
    return FirstResultJournal(child.id, base["provider"], job_event_digest(events),
                              job_event_digest(events[:6]), identity)


def _proof_data(parent, source, result, first_digest, proof) -> dict:
    if (proof.provider != result.provider
            or proof.new_edge_address != source.intent.new_edge_address
            or proof.state_sha256 == source.receipt["predecessorStateSha256"]):
        raise ValueError("mixed append second poststate proof differs")
    return {
        "schema": "mixed-append-second-poststate-v1",
        "provider": proof.provider,
        "reviewSha256": parent.input["reviewSha256"],
        "firstProofJournalSha256": first_digest,
        "receiptSha256": source.receipt_sha256,
        "resultJournalSha256": result.result_sha256,
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


def _valid_proof_data(data, parent, source, result, first_digest) -> bool:
    try:
        provider = result.provider
        intent = source.intent
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
                "schema", "provider", "reviewSha256", "firstProofJournalSha256",
                "receiptSha256", "resultJournalSha256", "predecessorStateSha256",
                "stateSha256", "lineage", "serial", "resourceIds", "newEdgeAddress",
                "newEdgeProviderId", "newEdgePublicIp", "inventorySha256",
                "observationSha256", "selectorResourcesCount", "attachedNodeIds"}
            and data["schema"] == "mixed-append-second-poststate-v1"
            and data["provider"] == provider
            and data["reviewSha256"] == parent.input["reviewSha256"]
            and data["firstProofJournalSha256"] == first_digest
            and data["receiptSha256"] == source.receipt_sha256
            and data["resultJournalSha256"] == result.result_sha256
            and data["predecessorStateSha256"] == source.receipt["predecessorStateSha256"]
            and all(_hex(data[key]) for key in (
                "stateSha256", "inventorySha256", "observationSha256"))
            and data["stateSha256"] != source.receipt["predecessorStateSha256"]
            and data["lineage"] == prior["lineage"]
            and type(data["serial"]) is int and data["serial"] > prior["serial"]
            and type(rows) is list and len(rows) == len(expected)
            and all(type(row) is list and len(row) == 2
                    and all(type(value) is str and value for value in row) for row in rows)
            and rows == sorted(rows) and set(ids) == expected
            and all(ids[address] == old for address, old in originals.items()
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


def _journal(parent, child, source, first_digest) -> tuple[FirstResultJournal, str]:
    if child.status not in {"running", "succeeded"} or len(child.events) not in {8, 9, 10}:
        raise ValueError("mixed append second child has no exact successful result")
    initial = replace(child, status="running", finished_at=None, events=child.events[:8])
    result = _result(parent, initial, source.receipt)
    if len(child.events) == 8:
        if child.status != "running" or child.finished_at is not None:
            raise ValueError("mixed append second pending result status differs")
        return result, "awaiting"
    proof = child.events[8]
    if (proof.sequence != 9 or proof.level != "info" or proof.message != _PROOF_EVENT
            or not isinstance(proof.data, dict)
            or not _valid_proof_data(proof.data, parent, source, result, first_digest)):
        raise ValueError("mixed append second proof event differs")
    if len(child.events) == 9:
        if child.status != "running" or child.finished_at is not None:
            raise ValueError("mixed append second proved result status differs")
        return result, "proved"
    terminal = child.events[9]
    if (child.status != "succeeded" or child.finished_at is None
            or terminal.sequence != 10 or terminal.level != "info"
            or terminal.message != _TERMINAL_EVENT
            or terminal.data != {"proofJournalSha256": job_event_digest(child.events[:9])}):
        raise ValueError("mixed append second terminal event differs")
    return result, "terminal"


def prove_and_finish_second_mixed_append_apply(
    parent_id: str, *, environment: str, job_repository=None, lease_lookup=None,
    credential_repository=None, linode_transport=None, digitalocean_transport=None,
    process_quiescent: Callable[[dict], bool] | None = None,
    claim_owner: str | None = None, claim_token: str | None = None,
    source_loader: Callable | None = None, first_terminal_proof: Callable | None = None,
    snapshot_collector: Callable = collect_first_mixed_append_inventory_snapshot,
    poststate_observer: Callable = observe_first_mixed_append_poststate,
    release_check: Callable = require_devtest_terraform_release,
    max_observation_attempts: int = 60, poll_interval_seconds: float = 5.0,
    sleeper=None,
) -> StoredJobRun:
    """Prove the second write exactly once; restarts after event reobserve."""
    if environment != "devtest":
        raise MixedAppendSecondProofJobAttention("mixed append second proof is DevTest-only")
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    quiescent = process_quiescent or (lambda identity: _process_quiescent(
        identity["bootId"], identity["pid"], identity["pgid"], identity["startTicks"]))
    try:
        parent = jobs.get(parent_id)
        if (parent is None or parent.action != _OPERATION or parent.status != "running"
                or parent.input.get("phase") != "apply_sealed"
                or parent.target_type != "engagement"
                or parent.target != f"engagement:{parent.target_id}"
                or lookup(parent.target_id) != (parent.input["corePlanId"], _OPERATION)):
            raise ValueError("mixed append second proof parent or lease changed")
        loader = source_loader or _approved_second
        source = loader(parent, jobs, release_check)
        child = jobs.get(_child_id(parent.id))
        if child is None:
            raise ValueError("mixed append second Apply child missing")
        first_check = first_terminal_proof or build_second_mixed_append_apply_bindings(
            parent_id, job_repository=jobs, lease_lookup=lookup,
            credential_repository=credential_repository or SqlAlchemyCredentialRepository(),
            release_check=release_check, linode_transport=linode_transport,
            digitalocean_transport=digitalocean_transport)["first_terminal_proof"]
        # Even a terminal child must remain bound to the current first provider.
        # The provider GETs in this check are read-only.
        first_digest = first_check(parent, lambda: None)
        if not _hex(first_digest):
            raise ValueError("mixed append first terminal proof differs")
        journal, stage = _journal(parent, child, source, first_digest)
        if stage == "terminal":
            return child
        if not quiescent(journal.started_identity):
            raise ValueError("mixed append second Apply process may still run")
        if (claim_owner is None) != (claim_token is None):
            raise ValueError("mixed append second proof claim pair incomplete")
        if claim_owner is not None and (
                child.input.get("claimOwner") != claim_owner
                or child.input.get("claimToken") != claim_token):
            raise ValueError("mixed append second proof claim differs")
        owner = claim_owner or f"mixed-append-second-proof-{uuid4().hex}"
        token = claim_token or uuid4().hex
        at = _now()
        claimed = jobs.claim_lease(child.id, owner=owner, token=token,
                                   claimed_at=at, expires_at=_later(at),
                                   eligible_statuses={"running"})
        if claimed is None or job_event_digest(claimed.events) != job_event_digest(child.events):
            raise ValueError("mixed append second proof claim unavailable")
        child = claimed
        generation = first_digest

        def fence() -> str:
            nonlocal child
            if (lookup(parent.target_id) != (parent.input["corePlanId"], _OPERATION)
                    or jobs.get(parent.id) != parent or jobs.get(child.id) != child
                    or datetime.now(timezone.utc) >= datetime.fromisoformat(
                        child.input["claimExpiresAt"])):
                raise ValueError("mixed append second proof generation changed")
            at = _now()
            renewed = jobs.renew_lease(child.id, owner=owner, token=token,
                                       heartbeat_at=at, expires_at=_later(at))
            if renewed is None or renewed.events != child.events:
                raise ValueError("mixed append second proof heartbeat lost")
            child = renewed
            return generation

        def check_first() -> None:
            # Fresh GET proof at the durable boundaries, not once per
            # paginated GET in the second provider's inventory collector.
            fence()
            if first_check(parent, fence) != first_digest:
                raise ValueError("mixed append first provider changed during second proof")

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
        check_first()
        proof = poststate_observer(**options)
        data = _proof_data(parent, source, journal, first_digest, proof)
        check_first()
        if stage == "awaiting":
            at = _now()
            updated = jobs.append_event_if_running_claimed(
                child, owner=owner, token=token,
                expected_event_digest=job_event_digest(child.events),
                heartbeat_at=at, expires_at=_later(at),
                event=JobEvent(9, "info", _PROOF_EVENT, data))
            if updated is None:
                raise ValueError("mixed append second proof journal CAS lost")
            child = updated
            journal, stage = _journal(parent, child, source, first_digest)
        if stage != "proved" or child.events[8].data != data:
            raise ValueError("mixed append second persisted proof differs")
        check_first()
        terminal = jobs.finish_if_running_claimed(
            child, owner=owner, token=token,
            expected_event_digest=job_event_digest(child.events),
            status="succeeded", finished_at=_now(),
            event=JobEvent(10, "info", _TERMINAL_EVENT,
                           {"proofJournalSha256": job_event_digest(child.events)}))
        if terminal is None or _journal(parent, terminal, source, first_digest)[1] != "terminal":
            raise ValueError("mixed append second terminal CAS lost")
        return terminal
    except Exception:
        raise MixedAppendSecondProofJobAttention(
            "mixed append second Apply poststate proof requires review") from None
