# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private one-Deploy continuation through both mixed provider proofs.

The reviewed core and both provider plans already exist. This sequencer runs
each one-shot provider child in seal order, then persists the existing host
proof handoff. It does not SSH to Sketch, bootstrap, or publish chain rows.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from app.services.core_ssh import active_core_connection_details
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id, recognize_mixed_initial_apply_result,
    recognize_mixed_initial_apply_terminal, run_mixed_initial_provider_apply,
)
from app.services.provider_keyed_mixed_initial_apply_proof import (
    _process_quiescent, prove_and_finish_mixed_initial_apply,
    prove_mixed_initial_prior_provider_fresh,
)
from app.services.provider_keyed_mixed_initial_apply_source import (
    audited_mixed_initial_apply_source,
)
from app.services.provider_keyed_mixed_initial_coordinator import (
    HANDOFF_PHASE, _core_matches, prepare_or_reuse_mixed_initial_host_proof_handoff,
    recognize_mixed_initial_host_proof_handoff,
)
from app.services.provider_keyed_mixed_initial_plan_parent import (
    _parent_id, validate_mixed_initial_apply_seal,
)
from app.services.provider_keyed_mixed_interrupted_dispatch import _workspace
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _require_lease
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun


class MixedInitialDeployContinuationAttention(ValueError):
    """The next proved mixed Deploy phase requires reconciliation."""


def _active_claim(child: StoredJobRun) -> tuple[str | None, str | None]:
    """Pass through only the claim held by the just-completed command worker."""
    data = child.input
    try:
        expiry = datetime.fromisoformat(data["claimExpiresAt"])
        if (expiry.tzinfo is not None and expiry > datetime.now(timezone.utc)
                and type(data.get("claimOwner")) is str
                and type(data.get("claimToken")) is str):
            return data["claimOwner"], data["claimToken"]
    except (KeyError, TypeError, ValueError):
        pass
    return None, None


def advance_mixed_initial_deploy_to_host_proof(
    engagement_id: str, core_job_id: str, *, environment: str,
    state_root: Path, selector_absence_prover: Callable,
    selector_get_transport, selector_post_transport,
    job_repository=None, lease_lookup=None, credential_repository=None,
    linode_transport=None, digitalocean_transport=None,
    source_session: Callable | None = None,
    workspace_reader: Callable | None = None,
    apply_runner: Callable = run_mixed_initial_provider_apply,
    proof_finisher: Callable = prove_and_finish_mixed_initial_apply,
    prior_fresh_prover: Callable = prove_mixed_initial_prior_provider_fresh,
    handoff_builder: Callable = prepare_or_reuse_mixed_initial_host_proof_handoff,
    fresh_first_prover: Callable | None = None,
) -> StoredJobRun:
    """Advance one reviewed Deploy through provider terminal proof and handoff.

    Selector absence is an explicit dependency because it must be a complete
    account read immediately before the DigitalOcean POST. An uncertain write
    stays in its saved child; this function never retries it by inference.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        if (environment != "devtest" or not isinstance(state_root, Path)
                or not state_root.is_absolute() or not callable(selector_absence_prover)
                or not callable(apply_runner) or not callable(proof_finisher)
                or not callable(handoff_builder)):
            raise ValueError("mixed Deploy continuation boundary differs")
        parent = jobs.get(_parent_id(core_job_id))
        core = jobs.get(core_job_id)
        if parent is None or core is None or parent.target_id != engagement_id:
            raise ValueError("mixed parent or core is missing")
        seal = validate_mixed_initial_apply_seal(parent)
        order = tuple(seal["orderedProviders"])
        if (set(order) != {"linode", "digitalocean"} or len(order) != 2
                or parent.input.get("coreJobId") != core_job_id
                or parent.input.get("phase") not in {"apply_sealed", HANDOFF_PHASE}
                or parent.status != "running"):
            raise ValueError("mixed provider review differs")
        _require_lease(lookup, engagement_id, parent.input["corePlanId"])
        active_id, _ = active_core_connection_details(jobs, engagement_id)
        if not _core_matches(parent, core, active_id):
            raise ValueError("active core differs from mixed Deploy")
        def active_core_unchanged() -> None:
            selected_id, _ = active_core_connection_details(jobs, engagement_id)
            if (selected_id != active_id or jobs.get(core.id) != core
                    or not _core_matches(parent, core, selected_id)):
                raise ValueError("mixed Deploy active core changed")
        children = {provider: jobs.get(_child_id(core_job_id, provider))
                    for provider in order}
        if parent.input["phase"] == HANDOFF_PHASE:
            recognize_mixed_initial_host_proof_handoff(parent, core, active_id, children)
            return parent

        read_workspace = workspace_reader or (lambda saved, provider: _workspace(
            saved, provider, state_root))
        source = source_session or (lambda saved, provider, renew:
            audited_mixed_initial_apply_source(
                saved, provider, renew, environment=environment,
                state_root=state_root, job_repository=jobs,
                credential_repository=credential_repository, lease_lookup=lookup))
        for provider in order:
            _require_lease(lookup, engagement_id, parent.input["corePlanId"])
            if jobs.get(parent.id) != parent or jobs.get(core.id) != core:
                raise ValueError("mixed Deploy authority changed")
            active_core_unchanged()
            child = jobs.get(_child_id(core_job_id, provider))
            if child is not None and child.status == "succeeded":
                recognize_mixed_initial_apply_terminal(child, parent, provider)
                active_core_unchanged()
                continue
            result = None
            if child is not None:
                try:
                    result = recognize_mixed_initial_apply_result(child, parent, provider)
                except Exception:
                    # Only the child runner may judge a queued/pre-command
                    # restart. It refuses any saved command intent.
                    pass
            if result is None:
                child = apply_runner(
                    engagement_id, core_job_id, provider, environment=environment,
                    job_repository=jobs, lease_lookup=lookup, source_session=source,
                    selector_absence_prover=selector_absence_prover,
                    selector_get_transport=selector_get_transport,
                    selector_post_transport=selector_post_transport,
                    prior_fresh_prover=prior_fresh_prover,
                    credential_repository=credential_repository,
                    linode_transport=linode_transport,
                    digitalocean_transport=digitalocean_transport)
            if child is None or child.id != _child_id(core_job_id, provider):
                raise ValueError("mixed provider Apply returned another child")
            if child.status != "succeeded":
                workspace = read_workspace(parent, provider)
                claim_owner, claim_token = _active_claim(child)
                child = proof_finisher(
                    engagement_id, core_job_id, provider, workspace,
                    environment=environment, job_repository=jobs,
                    lease_lookup=lookup, credential_repository=credential_repository,
                    linode_transport=linode_transport,
                    digitalocean_transport=digitalocean_transport,
                    claim_owner=claim_owner, claim_token=claim_token)
            recognize_mixed_initial_apply_terminal(child, parent, provider)
            if jobs.get(child.id) != child:
                raise ValueError("mixed provider terminal changed")
            active_core_unchanged()

        def first_fresh(saved, child, fence):
            if fresh_first_prover is not None:
                return fresh_first_prover(saved, child, fence)
            workspace = read_workspace(saved, order[0])
            return prior_fresh_prover(
                saved, child, workspace, fence=fence,
                process_quiescent=lambda identity: _process_quiescent(
                    identity["bootId"], identity["pid"], identity["pgid"],
                    identity["startTicks"]),
                credential_repository=credential_repository,
                linode_transport=linode_transport,
                digitalocean_transport=digitalocean_transport)

        active_core_unchanged()
        handoff = handoff_builder(
            engagement_id, core_job_id, environment=environment,
            fresh_first_prover=first_fresh, job_repository=jobs, lease_lookup=lookup)
        if (handoff.id != parent.id or handoff.input.get("phase") != HANDOFF_PHASE
                or handoff.status != "running"):
            raise ValueError("mixed host-proof handoff was not persisted")
        recognize_mixed_initial_host_proof_handoff(
            handoff, core, active_id,
            {provider: jobs.get(_child_id(core_job_id, provider)) for provider in order})
        return handoff
    except Exception:
        raise MixedInitialDeployContinuationAttention(
            "mixed Deploy stopped at its last proved phase") from None
