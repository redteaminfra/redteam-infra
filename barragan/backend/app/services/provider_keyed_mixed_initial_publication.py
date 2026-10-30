# Copyright (c) 2026, Oracle and/or its affiliates.
"""Join a fresh mixed host proof to one atomic two-provider publication."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from app.domain import JobEvent
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id as _apply_child_id, _prior_workspace,
    recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_initial_host_binding import (
    _binding_child_id, recognize_mixed_initial_host_binding,
)
from app.services.provider_keyed_mixed_initial_plan_parent import (
    _parent_id, validate_mixed_initial_apply_seal,
)
from app.services.provider_keyed_mixed_initial_projection import project_mixed_initial_chains
from app.services.provider_keyed_mixed_initial_host_proof import (
    collect_mixed_initial_strict_host_proof,
)
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


class MixedInitialPublicationAttention(ValueError):
    """The reviewed proof cannot be atomically published; no host replay is safe."""


def _mark_publication_attention(jobs, parent_id: str, receipt) -> None:
    """Retain a truthful terminal boundary after a claimed proof cannot commit."""
    try:
        child = jobs.get(receipt.child_id)
        if (child is not None and child.status == "running"
                and child.input.get("claimOwner") == receipt.claim_owner
                and child.input.get("claimToken") == receipt.claim_token):
            jobs.finish_if_running_claimed(
                child, owner=receipt.claim_owner, token=receipt.claim_token,
                expected_event_digest=job_event_digest(child.events), status="failed",
                finished_at=datetime.now(timezone.utc).isoformat(),
                event=JobEvent(len(child.events) + 1, "error",
                               "mixed strict host proof publication stopped; reconciliation required", {}),
            )
        parent = jobs.get(parent_id)
        if (parent is not None and parent.status == "running"
                and parent.input.get("claimOwner") == receipt.claim_owner
                and parent.input.get("claimToken") == receipt.claim_token):
            jobs.save_if_leased(replace(
                parent, status="failed", finished_at=datetime.now(timezone.utc).isoformat(),
                input={**parent.input, "phase": "attention"},
                events=[*parent.events, JobEvent(len(parent.events) + 1, "error",
                    "mixed strict host proof publication stopped; reconciliation required", {})]),
                owner=receipt.claim_owner, token=receipt.claim_token)
    except Exception:
        # The retained proof child remains a permanent no-replay fence even if
        # a concurrent claim prevents the best-effort attention transition.
        pass


def publish_mixed_initial_strict_host_proof(
    engagement_id: str, core_job_id: str, *, environment: str,
    job_repository=None, plan_repository=None, sketch_repository=None,
    collector=None,
):
    """Run the one-shot proof and publish both chains under its retained claim."""
    if environment != "devtest":
        raise MixedInitialPublicationAttention("mixed host publication is DevTest-only")
    jobs = job_repository or SqlAlchemyJobRepository()
    sketches = sketch_repository or SqlAlchemySketchChainRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    gather = collector or collect_mixed_initial_strict_host_proof
    receipt = gather(engagement_id, core_job_id, environment=environment,
                     job_repository=jobs, sketch_repository=sketches,
                     plan_repository=plans)
    try:
        source = receipt.source
        if source.engagement_id != engagement_id or source.core_job_id != core_job_id:
            raise ValueError("strict proof source differs")
        parent = jobs.get(_parent_id(core_job_id))
        proof_child = jobs.get(receipt.child_id)
        binding = jobs.get(_binding_child_id(core_job_id))
        if parent is None or proof_child is None or binding is None:
            raise ValueError("retained proof rows differ")
        seal = validate_mixed_initial_apply_seal(parent)
        manifest = recognize_mixed_initial_host_binding(binding, parent)
        pending = tuple(sketches.get(engagement_id, chain_id) for chain_id in source.chain_ids)
        if any(chain is None for chain in pending):
            raise ValueError("pending mixed chain differs")
        projections = project_mixed_initial_chains(
            manifest, {chain.chain_id: chain for chain in pending}, seal["reviewedPolicy"])
        workspaces = {}
        for provider in source.ordered_providers:
            child = jobs.get(_apply_child_id(core_job_id, provider))
            terminal = recognize_mixed_initial_apply_terminal(child, parent, provider)
            workspaces[provider] = str(_prior_workspace(parent, provider, terminal).path)
        sketches.publish_provider_keyed_mixed_initial_chains(
            parent=parent, proof_child=proof_child, receipt=receipt,
            pending_chains=pending, projected_chains=projections, source=source,
            provider_workspaces=workspaces,
            expected_parent_event_digest=source.parent_journal_sha256,
            expected_child_event_digest=receipt.child_event_sha256,
            claim_owner=receipt.claim_owner, claim_token=receipt.claim_token,
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        return jobs.get(parent.id)
    except Exception as exc:
        _mark_publication_attention(jobs, _parent_id(core_job_id), receipt)
        raise MixedInitialPublicationAttention(
            "mixed strict proof publication stopped; reconciliation required") from exc
