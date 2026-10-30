# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline recognition of the mixed initial provider-to-host-proof boundary.

This module has no provider write, Terraform, SSH, or public dispatcher. The
fresh-presence callback is supplied by the later live continuation; its result
must match the first provider's exact terminal proof before a parent handoff
can be persisted.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping
from uuid import uuid4

from app.domain import JobEvent
from app.services.core_ssh import (
    CORE_DEPLOYMENT_ACTION, _core_job_is_active, active_core_connection_details,
)
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id, recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_initial_plan_parent import (
    _parent_id, validate_mixed_initial_apply_seal,
)
from app.services.provider_keyed_mixed_partial_apply_source import ProviderApplyClassification
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _require_lease
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest


HANDOFF_PHASE = "awaiting_mixed_host_proof"
HANDOFF_MESSAGE = "mixed provider Apply proofs joined; awaiting host proof"
_OWNER = f"mixed-initial-handoff-{uuid4().hex}"


class MixedInitialCoordinatorAttention(ValueError):
    """The reviewed mixed provider handoff is incomplete or has drifted."""


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _core_matches(parent: StoredJobRun, core: StoredJobRun, active_core_id: str) -> bool:
    inputs = core.input if isinstance(core.input, dict) else {}
    return (
        core.id == parent.input["coreJobId"] == active_core_id
        and core.action == CORE_DEPLOYMENT_ACTION
        and core.status == "succeeded"
        and _core_job_is_active(core)
        and core.requested_by == parent.requested_by
        and inputs.get("engagementId") == parent.target_id
        and inputs.get("corePlanId") == parent.input["corePlanId"]
        and inputs.get("sketchStateSchema") == "provider-keyed-v2"
        and core.target_type == "oci_compartment"
        and core.target == "oci-compartment:barragan-testing"
    )


def _terminal_proofs(
    parent: StoredJobRun, children: Mapping[str, StoredJobRun],
) -> tuple[list[dict], list[StoredJobRun]]:
    seal = validate_mixed_initial_apply_seal(parent)
    order = seal["orderedProviders"]
    if set(children) != set(order):
        raise MixedInitialCoordinatorAttention("both exact mixed Apply children are required")
    terminals = []
    rows = []
    for provider in order:
        child = children[provider]
        if child is None or child.id != _child_id(parent.input["coreJobId"], provider):
            raise MixedInitialCoordinatorAttention("mixed Apply child identity differs")
        terminal = recognize_mixed_initial_apply_terminal(child, parent, provider)
        terminals.append(terminal)
        rows.append(child)
    try:
        if datetime.fromisoformat(rows[1].started_at) < datetime.fromisoformat(rows[0].finished_at):
            raise ValueError("provider two started before provider one finished")
    except (TypeError, ValueError) as exc:
        raise MixedInitialCoordinatorAttention("mixed provider terminal order differs") from exc
    return terminals, rows


def _handoff_data(parent: StoredJobRun, terminals: list[dict]) -> dict:
    seal = validate_mixed_initial_apply_seal(parent)
    return {
        "schema": "mixed-initial-host-proof-handoff-v1",
        "sealJournalSha256": job_event_digest(parent.events[:6]),
        "coreJobId": parent.input["coreJobId"],
        "corePlanId": parent.input["corePlanId"],
        "orderedProviders": list(seal["orderedProviders"]),
        "chainIds": list(seal["chainIds"]),
        "terminalJournalSha256": [item["terminalJournalSha256"] for item in terminals],
        "providerProofSha256": [_digest(item["proof"]) for item in terminals],
        "firstFreshPresence": {
            "stateSha256": terminals[0]["proof"]["stateSha256"],
            "lineage": terminals[0]["proof"]["lineage"],
            "serial": terminals[0]["proof"]["serial"],
            "resourceIds": terminals[0]["proof"]["resourceIds"],
        },
    }


def recognize_mixed_initial_host_proof_handoff(
    parent: StoredJobRun, core: StoredJobRun, active_core_id: str,
    children: Mapping[str, StoredJobRun],
) -> dict:
    """Recognize a persisted handoff without repeating the fresh provider read."""
    try:
        if (parent.id != _parent_id(parent.input["coreJobId"])
                or parent.status != "running" or parent.finished_at is not None
                or parent.input.get("phase") != HANDOFF_PHASE
                or len(parent.events) != 7
                or not _core_matches(parent, core, active_core_id)):
            raise ValueError("mixed handoff parent or core differs")
        terminals, _ = _terminal_proofs(parent, children)
        event = parent.events[6]
        expected = _handoff_data(parent, terminals)
        if (event != JobEvent(7, "info", HANDOFF_MESSAGE, expected)
                or parent.input.get("engagementId") != parent.target_id):
            raise ValueError("mixed handoff checkpoint differs")
        return expected
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise MixedInitialCoordinatorAttention("mixed host-proof handoff differs") from exc


def inspect_mixed_initial_host_proof_handoff(
    parent: StoredJobRun, core: StoredJobRun, active_core_id: str,
    children: Mapping[str, StoredJobRun], *,
    fresh_first_prover: Callable[[StoredJobRun, StoredJobRun, Callable[[], str]], ProviderApplyClassification],
    fence: Callable[[], str],
) -> dict:
    """Build a typed handoff only after exact terminal and fresh first proof.

    This returns proposed event data, not a durable checkpoint. A caller must
    use the dedicated repository CAS before allowing host bootstrap or publish.
    """
    try:
        if (parent.id != _parent_id(parent.input["coreJobId"])
                or parent.status != "running" or parent.finished_at is not None
                or parent.input.get("phase") != "apply_sealed"
                or len(parent.events) != 6
                or parent.input.get("engagementId") != parent.target_id
                or not _core_matches(parent, core, active_core_id)):
            raise ValueError("mixed sealed parent or active core differs")
        terminals, rows = _terminal_proofs(parent, children)
        first = terminals[0]["proof"]
        generation = fence()
        if type(generation) is not str or not generation:
            raise ValueError("mixed provider read has no stable fence generation")
        fresh = fresh_first_prover(parent, rows[0], fence)
        if (not isinstance(fresh, ProviderApplyClassification)
                or fresh.provider != parent.input["orderedProviders"][0]
                or fresh.kind != "full" or fresh.state_sha256 != first["stateSha256"]
                or fresh.lineage != first["lineage"] or fresh.serial != first["serial"]
                or dict(fresh.resource_ids) != first["resourceIds"]):
            raise ValueError("first provider fresh presence differs")
        if fence() != generation:
            raise ValueError("mixed provider read fence generation changed")
        return _handoff_data(parent, terminals)
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise MixedInitialCoordinatorAttention("mixed initial host-proof handoff needs review") from exc


def prepare_or_reuse_mixed_initial_host_proof_handoff(
    engagement_id: str, core_job_id: str, *, environment: str,
    fresh_first_prover: Callable[[StoredJobRun, StoredJobRun, Callable[[], str]], ProviderApplyClassification],
    job_repository=None, lease_lookup=None,
) -> StoredJobRun:
    """Persist exactly one checkpoint after both offline terminal recognitions.

    The injected first-provider prover may do fresh read-only inventory work.
    It must not write provider state. This module never runs Terraform, SSH,
    selector operations, bootstrap, or publication.
    """
    if environment != "devtest" or not engagement_id or not core_job_id:
        raise MixedInitialCoordinatorAttention("mixed initial handoff is DevTest-only")
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        parent = jobs.get(_parent_id(core_job_id))
        core = jobs.get(core_job_id)
        if (parent is None or core is None or parent.target_id != engagement_id
                or parent.input.get("coreJobId") != core_job_id):
            raise ValueError("mixed parent or core is unavailable")
        lease_owner = parent.input["corePlanId"]
        _require_lease(lookup, engagement_id, lease_owner)
        active_id, _ = active_core_connection_details(jobs, engagement_id)
        def children():
            order = parent.input["orderedProviders"]
            return {provider: jobs.get(_child_id(core_job_id, provider)) for provider in order}

        if parent.input.get("phase") == HANDOFF_PHASE:
            recognize_mixed_initial_host_proof_handoff(parent, core, active_id, children())
            return parent
        if parent.input.get("phase") != "apply_sealed":
            raise ValueError("mixed parent is not sealed for Apply")

        now = datetime.now(timezone.utc)
        token = uuid4().hex
        claimed = jobs.claim_lease(
            parent.id, owner=_OWNER, token=token, claimed_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=120)).isoformat(),
            eligible_statuses={"running"}, eligible_phases={"apply_sealed"})
        if claimed is None or claimed.id != parent.id:
            raise ValueError("mixed parent handoff claim is unavailable")
        parent = claimed
        generation = _digest({
            "seal": job_event_digest(parent.events[:6]),
            "children": [
                job_event_digest(child.events) for child in children().values()
            ],
            "claim": token,
        })

        def fence() -> str:
            nonlocal parent
            _require_lease(lookup, engagement_id, lease_owner)
            if jobs.get(parent.id) != parent:
                raise ValueError("mixed handoff parent changed during provider read")
            at = datetime.now(timezone.utc)
            renewed = jobs.renew_lease(
                parent.id, owner=_OWNER, token=token,
                heartbeat_at=at.isoformat(),
                expires_at=(at + timedelta(seconds=120)).isoformat())
            if (renewed is None or renewed.input.get("phase") != "apply_sealed"
                    or job_event_digest(renewed.events) != job_event_digest(parent.events)):
                raise ValueError("mixed handoff claim or seal changed")
            parent = renewed
            return generation

        data = inspect_mixed_initial_host_proof_handoff(
            parent, core, active_id, children(),
            fresh_first_prover=fresh_first_prover, fence=fence)
        fence()
        if jobs.get(core_job_id) != core:
            raise ValueError("active core changed after fresh provider proof")
        current_active_id, _ = active_core_connection_details(jobs, engagement_id)
        current_terminals, _ = _terminal_proofs(parent, children())
        if (current_active_id != active_id
                or _handoff_data(parent, current_terminals) != data):
            raise ValueError("mixed provider proof changed before handoff")
        event = JobEvent(7, "info", HANDOFF_MESSAGE, data)
        checkpoint = jobs.append_mixed_initial_handoff_if_claimed(
            parent, owner=_OWNER, token=token, lease_owner=lease_owner,
            expected_event_digest=job_event_digest(parent.events), event=event)
        if checkpoint is None:
            raise ValueError("mixed handoff parent CAS was lost")
        recognize_mixed_initial_host_proof_handoff(
            checkpoint, core, current_active_id, children())
        return checkpoint
    except Exception as exc:
        raise MixedInitialCoordinatorAttention(
            "mixed initial host-proof handoff needs review") from exc
