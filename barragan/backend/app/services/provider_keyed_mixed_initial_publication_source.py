# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline source for a future mixed initial strict-proof/publication worker.

Recognition has no side effects. A caller must freshly rebind this source under
its own claim before host contact or durable chain publication.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from app.services.provider_keyed_mixed_initial_coordinator import (
    recognize_mixed_initial_host_proof_handoff,
)
from app.services.provider_keyed_mixed_initial_host_attestation import (
    recognize_completed_mixed_host_worker,
)
from app.services.provider_keyed_mixed_initial_host_binding import (
    ProviderHostObservation, _digest, build_mixed_initial_host_binding,
    recognize_mixed_initial_host_binding,
)
from app.services.provider_keyed_mixed_initial_plan_parent import validate_mixed_initial_apply_seal
from app.services.provider_keyed_mixed_initial_projection import project_mixed_initial_chains
from app.storage.job_repository import StoredJobRun, job_event_digest


class MixedInitialPublicationSourceAttention(ValueError):
    """The reviewed mixed publication source is incomplete or has drifted."""


@dataclass(frozen=True)
class MixedProviderState:
    provider: str
    state_sha256: str
    lineage: str
    serial: int
    resource_ids: tuple[tuple[str, str], ...]
    terminal_journal_sha256: str


@dataclass(frozen=True)
class MixedHostRow:
    chain_id: str
    provider: str
    role: str
    hostname: str
    terraform_address: str
    provider_instance_id: str
    public_ip: str
    assigned_proxy: str


@dataclass(frozen=True)
class MixedInitialPublicationSource:
    engagement_id: str
    core_job_id: str
    core_plan_id: str
    revision_id: str
    parent_job_id: str
    ordered_providers: tuple[str, str]
    chain_ids: tuple[str, str]
    parent_journal_sha256: str
    binding_manifest_sha256: str
    host_worker_journal_sha256: str
    provider_states: tuple[MixedProviderState, MixedProviderState]
    host_rows: tuple[MixedHostRow, MixedHostRow, MixedHostRow, MixedHostRow]


def recognize_mixed_initial_publication_source(
    *, parent: StoredJobRun, core: StoredJobRun, plan: object,
    children: Mapping[str, StoredJobRun], binding: StoredJobRun,
    host_worker: StoredJobRun, active_core_id: str,
    lease: tuple[str, str], chains: Mapping[str, object],
    observations: Mapping[str, ProviderHostObservation],
    process_quiescent: Callable[[dict], bool],
) -> MixedInitialPublicationSource:
    """Recognize the exact 2+2 state-backed bootstrap source without publishing.

    ``observations`` contain the raw retained Terraform state and its fresh,
    read-only provider classification. This function itself never opens a
    workspace or contacts a host/provider.
    """
    try:
        seal = validate_mixed_initial_apply_seal(parent)
        order = tuple(seal["orderedProviders"])
        chain_ids = tuple(seal["chainIds"])
        evidence = plan.evidence
        authorization = evidence["sketchAuthorization"]
        if (len(order) != 2 or set(order) != {"linode", "digitalocean"}
                or len(chain_ids) != 2 or len(set(chain_ids)) != 2
                or set(children) != set(order) or set(observations) != set(order)
                or set(chains) != set(chain_ids) or len(chains) != 2
                or lease != (parent.input["corePlanId"], "provider_keyed_initial")
                or plan.id != parent.input["corePlanId"]
                or plan.engagement_id != parent.target_id
                or plan.revision_id != parent.input["revisionId"]
                or plan.status != "applied" or plan.stage != "applied"
                or plan.apply_job_id != core.id
                or authorization["kind"] != "bounded-mixed-post-core-v1"
                or authorization["fingerprint"] != parent.input["reviewFingerprint"]
                or _digest({key: value for key, value in authorization.items()
                            if key != "fingerprint"}) != authorization["fingerprint"]
                or plan.review["reviewedConfiguration"]["sketchAuthorization"] != authorization
                or evidence["pendingSketchChainIds"] != list(chain_ids)
                or evidence["pendingSketchChainFingerprints"]
                   != core.input["pendingSketchChainFingerprints"]
                or core.input["pendingSketchChainIds"] != list(chain_ids)):
            raise ValueError("mixed reviewed plan, lease, or chain generation differs")
        recognize_mixed_initial_host_proof_handoff(parent, core, active_core_id, children)
        manifest = recognize_mixed_initial_host_binding(binding, parent)
        worker_sha = recognize_completed_mixed_host_worker(
            parent, core, children, binding, host_worker, active_core_id,
            process_quiescent=process_quiescent)
        rebuilt = build_mixed_initial_host_binding(
            parent, core, active_core_id, children, chains, observations)
        if rebuilt != manifest or _digest(rebuilt) != binding.input["manifestSha256"]:
            raise ValueError("mixed binding differs from raw 2+2 state")
        projections = project_mixed_initial_chains(manifest, chains, seal["reviewedPolicy"])
        if (len(projections) != 2
                or tuple(item.chain.chain_id for item in projections) != chain_ids
                or tuple(item.chain.middle_provider for item in projections) != order
                or any(len(item.chain.nodes) != 2 for item in projections)):
            raise ValueError("mixed chain projection differs")
        rows = tuple(MixedHostRow(
            chain_id=row["chainId"], provider=row["provider"], role=row["role"],
            hostname=row["hostname"], terraform_address=row["terraformAddress"],
            provider_instance_id=row["providerInstanceId"], public_ip=row["publicIp"],
            assigned_proxy=row["assignedProxy"],
        ) for item in projections for row in item.chain.nodes)
        if (len(rows) != 4 or tuple((row.chain_id, row.provider, row.role) for row in rows)
                != tuple((chain_id, provider, role)
                         for provider, chain_id in zip(order, chain_ids, strict=True)
                         for role in ("middle", "edge"))):
            raise ValueError("mixed projected host rows differ")
        states = tuple(MixedProviderState(
            provider=row["provider"], state_sha256=row["stateSha256"],
            lineage=row["lineage"], serial=row["serial"],
            resource_ids=tuple(sorted(observations[row["provider"]].classification.resource_ids)),
            terminal_journal_sha256=row["terminalJournalSha256"],
        ) for row in manifest["providerStates"])
        if len(states) != 2 or tuple(row.provider for row in states) != order:
            raise ValueError("mixed provider states differ")
        return MixedInitialPublicationSource(
            engagement_id=parent.target_id, core_job_id=core.id,
            core_plan_id=plan.id, revision_id=plan.revision_id,
            parent_job_id=parent.id, ordered_providers=order, chain_ids=chain_ids,
            parent_journal_sha256=job_event_digest(parent.events),
            binding_manifest_sha256=binding.input["manifestSha256"],
            host_worker_journal_sha256=worker_sha,
            provider_states=states, host_rows=rows,
        )
    except Exception as exc:
        raise MixedInitialPublicationSourceAttention(
            "mixed initial publication source requires exact reconciliation") from exc
