# Copyright (c) 2026, Oracle and/or its affiliates.
"""DevTest-only rearm of an already sealed, stopped edge-append publication.

This module never starts Terraform, bootstrap, a provider request, or a host probe.
The normal append publication path remains responsible for its full source proof.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _inert_aborted_intent
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


class ProviderKeyedAppendPublicationRecoveryConflict(ValueError):
    """The sealed publication history changed or remains actively claimed."""


_SEAL = "strict append host proof completed"
_STOP = "strict append host proof stopped; reconciliation required"
_CLAIM_KEYS = frozenset({"claimOwner", "claimToken", "claimClaimedAt",
                         "claimHeartbeatAt", "claimExpiresAt"})


def _evidence(parent_id: str, *, environment: str, state_root: Path,
              jobs, chains, lease_lookup) -> tuple[str, StoredJobRun | None]:
    """Return availability plus the exact persisted parent; no mutation."""
    parent = jobs.get(parent_id)
    if (environment != "devtest" or parent is None
            or parent.action != "provider_keyed_edge_append"
            or parent.status != "failed" or parent.input.get("phase") != "attention"
            or not parent.started_at or not parent.finished_at
            or parent.target_type != "engagement"
            or parent.target != f"engagement:{parent.target_id}"
            or parent.input.get("engagementId") != parent.target_id
            or parent.input.get("mutation") is not True
            or parent.artifact_refs != [] or len(parent.events) < 3
            or parent.events[-2].message != _SEAL
            or parent.events[-2].level != "info"
            or set(parent.events[-2].data) != {
                "planJournalSha256", "applyJournalSha256", "hostProofJournalSha256"}
            or parent.events[-1].message != _STOP
            or parent.events[-1].level != "error"
            or parent.events[-1].data != {}
            or [event.sequence for event in parent.events]
               != list(range(1, len(parent.events) + 1))
            or sum(event.message == _SEAL for event in parent.events) != 1
            or sum(event.message == _STOP for event in parent.events) != 1):
        return "", None
    values = parent.input
    seal = parent.events[-2].data
    if (any(not isinstance(values.get(key), str) or not values[key]
            for key in ("coreJobId", "corePlanId", "chainId", "planJobId",
                        "applyJobId", "hostProofJobId", "initialSourceSha256"))
            or len({values[key] for key in ("planJobId", "applyJobId", "hostProofJobId")}) != 3
            or any(type(value) is not str or len(value) != 64
                   or any(char not in "0123456789abcdef" for char in value)
                   for value in seal.values())
            or lease_lookup(parent.target_id) != (
                values["corePlanId"], "provider_keyed_edge_append")):
        return "", None
    for kind, action, mutation in (
        ("plan", "provider_keyed_edge_append_plan", False),
        ("apply", "provider_keyed_edge_append_apply", True),
        ("hostProof", "provider_keyed_edge_append_host_proof", False),
    ):
        child = jobs.get(values[f"{kind}JobId"])
        if (child is None or child.action != action or child.status != "succeeded"
                or not child.finished_at or child.target != parent.target
                or child.target_type != parent.target_type
                or child.target_id != parent.target_id
                or child.input.get("parentJobId") != parent.id
                or child.input.get("mutation") is not mutation
                or child.requested_by != (
                    parent.requested_by if kind == "plan" else
                    parent.input.get("applyRequestedBy", parent.requested_by))
                or job_event_digest(child.events) != seal[f"{kind}JournalSha256"]):
            return "", None
        if kind == "plan":
            if (not child.events or child.events[-1].message != "reviewed append plan saved"
                    or child.events[-1].data.get("selectedChain") is None
                    or child.events[-1].data.get("initialSourceSha256") !=
                       values["initialSourceSha256"]):
                return "", None
            selected_receipt = child.events[-1].data["selectedChain"]
        elif kind == "apply":
            applied = child.events[-1]
            if (applied.message != "provider append apply completed"
                    or set(applied.data) != {"stateSha256", "newEdgeAddress",
                                            "newEdgeProviderId", "newEdgePublicIp",
                                            "providerMembershipVerified"}
                    or applied.data.get("providerMembershipVerified") is not True):
                return "", None
            state_sha = applied.data.get("stateSha256")
        elif kind == "hostProof":
            proof = child.events[-1]
            if (proof.message != _SEAL or proof.data.get("stateSha256") != state_sha
                    or proof.data.get("newEdgeAddress") != applied.data.get("newEdgeAddress")
                    or proof.data.get("newEdgeProviderId") != applied.data.get("newEdgeProviderId")):
                return "", None
    rows = [row for row in chains.list_for_engagement(parent.target_id)
            if not _inert_aborted_intent(row, parent.target_id)]
    if (len(rows) != 2 or len({row.chain_id for row in rows}) != 2
            or any(row.status != "deployed" or row.burned or row.edge_count != 1
                   or len(row.nodes) != 2 for row in rows)
            or sum(row.chain_id == values["chainId"] for row in rows) != 1
            or len({row.terraform_working_directory for row in rows}) != 1):
        return "", None
    selected = next(row for row in rows if row.chain_id == values["chainId"])
    if selected.to_dict() != selected_receipt:
        return "", None
    root = Path(rows[0].terraform_working_directory)
    try:
        if (not root.is_absolute() or state_root not in root.parents
                or root.is_symlink() or not (root / "terraform.tfstate").is_file()
                or (root / "terraform.tfstate").is_symlink()
                or hashlib.sha256((root / "terraform.tfstate").read_bytes()).hexdigest()
                   != state_sha):
            return "", None
        expiry = datetime.fromisoformat(values["claimExpiresAt"])
        if expiry.tzinfo is None:
            return "", None
    except (OSError, KeyError, TypeError, ValueError):
        return "", None
    return ("waiting" if expiry > datetime.now(timezone.utc) else "ready"), parent


def publication_recovery_state(parent_id: str, *, environment: str = "devtest",
                               state_root: Path | None = None, job_repository=None,
                               sketch_repository=None, lease_lookup=None) -> str:
    jobs = job_repository or SqlAlchemyJobRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    state, _ = _evidence(parent_id, environment=environment,
                         state_root=state_root or _default_state_root(),
                         jobs=jobs, chains=chains, lease_lookup=lookup)
    return state


def rearm_sealed_append_publication(parent_id: str, *, environment: str = "devtest",
                                    state_root: Path | None = None,
                                    job_repository=None, sketch_repository=None,
                                    lease_lookup=None) -> StoredJobRun:
    jobs = job_repository or SqlAlchemyJobRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    root = state_root or _default_state_root()
    state, parent = _evidence(parent_id, environment=environment, state_root=root,
                              jobs=jobs, chains=chains, lease_lookup=lookup)
    if state != "ready" or parent is None or not isinstance(jobs, SqlAlchemyJobRepository):
        raise ProviderKeyedAppendPublicationRecoveryConflict(
            "sealed append publication is unavailable or still claimed")
    result = jobs.rearm_sealed_provider_keyed_append_publication(
        parent, state_root=root)
    if result is None:
        raise ProviderKeyedAppendPublicationRecoveryConflict(
            "sealed append publication changed before rearm")
    return result
