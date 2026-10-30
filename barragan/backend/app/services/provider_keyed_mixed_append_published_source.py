# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only selected four-node publication source for mixed append.

The published proof grammar is shared with teardown, but this reader requires
the append lease and permits independently owned live bindings. It performs
only selected job/plan/chain reads and fresh provider GETs; it never scans the
global job history, plans Terraform, or grants Apply authority.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from app.services.core_ssh import active_core_connection_details
from app.services.provider_keyed_core_destroy_preview import _read_regular
from app.services.provider_keyed_initial_destroy_pre_go_recovery import _process_quiescent
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id, _prior_workspace, recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_initial_apply_proof import (
    prove_mixed_initial_prior_provider_fresh,
)
from app.services.provider_keyed_mixed_initial_bootstrap import _worker_id
from app.services.provider_keyed_mixed_initial_host_binding import (
    ProviderHostObservation, _binding_child_id, _digest,
)
from app.services.provider_keyed_mixed_initial_plan_parent import (
    _parent_id, validate_mixed_initial_apply_seal,
)
from app.services.provider_keyed_mixed_initial_publication_source import MixedInitialPublicationSource
from app.services.provider_keyed_mixed_published_teardown_authority import (
    review_published_mixed_initial_teardown,
)
from app.services.provider_keyed_mixed_strict_host_receipt import child_id as proof_child_id
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, reviewed_mixed_chain_rows
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


class PublishedMixedAppendSourceAttention(ValueError):
    """Selected published source or fresh provider identity changed."""


@dataclass(frozen=True)
class PublishedMixedAppendSource:
    source: MixedInitialPublicationSource
    workspaces: tuple[tuple[str, Path], ...]
    live_binding_count: int
    live_bindings_sha256: str
    historical_rows_sha256: str


def collect_published_mixed_append_source(
    engagement_id: str, core_job_id: str, *,
    binding_inventory: Callable[[], Mapping[str, tuple]],
    job_repository=None, plan_repository=None, sketch_repository=None,
    lease_lookup: Callable[[str], tuple[str, str] | None] | None = None,
    fresh_observer: Callable[[StoredJobRun, str, Callable[[], str]],
                             ProviderHostObservation] | None = None,
) -> PublishedMixedAppendSource:
    """Authenticate one already-published 2+2 generation under its append lease.

    ``binding_inventory`` supplies the engagement's actual live binding
    snapshot; unlike teardown, live bindings are allowed. Its exact value is
    compared before/after every provider read. The returned workspace paths
    and source hashes are read-only evidence; a later Apply binder rereads
    state bytes under its own claim and locks.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    sketches = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        if (type(engagement_id) is not str or not engagement_id
                or type(core_job_id) is not str or not core_job_id
                or not callable(binding_inventory)):
            raise ValueError("mixed append source identity differs")
        core, parent = jobs.get(core_job_id), jobs.get(_parent_id(core_job_id))
        if (core is None or parent is None
                or core.input.get("engagementId") != engagement_id
                or parent.target_id != engagement_id):
            raise ValueError("mixed append published jobs differ")
        seal = validate_mixed_initial_apply_seal(parent)
        order, ids = tuple(seal["orderedProviders"]), tuple(seal["chainIds"])
        plan = plans.get(core.input.get("corePlanId"))
        binding = jobs.get(_binding_child_id(core_job_id))
        bootstrap = jobs.get(_worker_id(core_job_id))
        proof = jobs.get(proof_child_id(core_job_id))
        children = {provider: jobs.get(_child_id(core_job_id, provider)) for provider in order}
        if (plan is None or binding is None or bootstrap is None or proof is None
                or any(child is None for child in children.values())):
            raise ValueError("mixed append publication children differ")
        durable = tuple(sketches.list_for_engagement(engagement_id))
        selected = reviewed_mixed_chain_rows(durable, ids, engagement_id)
        if active_core_connection_details(jobs, engagement_id)[0] != core_job_id:
            raise ValueError("mixed append chain/core generation differs")
        chains = {row.chain_id: row for row in selected}
        workspaces = {
            provider: _prior_workspace(
                parent, provider,
                recognize_mixed_initial_apply_terminal(children[provider], parent, provider))
            for provider in order
        }
        actual_bindings = deepcopy(binding_inventory())
        lease = (plan.id, "provider_keyed_mixed_append")
        if lookup(engagement_id) != lease:
            raise ValueError("mixed append lease differs")

        def fence() -> str:
            if (lookup(engagement_id) != lease
                    or jobs.get(core.id) != core or jobs.get(parent.id) != parent
                    or plans.get(plan.id) != plan or jobs.get(binding.id) != binding
                    or jobs.get(bootstrap.id) != bootstrap or jobs.get(proof.id) != proof
                    or any(jobs.get(child.id) != child for child in children.values())
                    or tuple(sketches.list_for_engagement(engagement_id)) != durable
                    or binding_inventory() != actual_bindings
                    or active_core_connection_details(jobs, engagement_id)[0] != core_job_id):
                raise ValueError("mixed append published source changed during GET")
            return parent.events[-1].data["sourceSha256"]

        observations = {}
        for provider in order:
            fence()
            if fresh_observer is not None:
                observation = fresh_observer(parent, provider, fence)
            else:
                child, workspace = children[provider], workspaces[provider]
                classification = prove_mixed_initial_prior_provider_fresh(
                    parent, child, workspace, fence=fence,
                    process_quiescent=lambda identity: _process_quiescent(
                        identity["bootId"], identity["pid"], identity["pgid"],
                        identity["startTicks"]),
                )
                fence()
                observation = ProviderHostObservation(
                    classification, _read_regular(workspace.state_path))
            observations[provider] = observation
            fence()
        review = review_published_mixed_initial_teardown(
            parent=parent, core=core, plan=plan, binding=binding,
            bootstrap=bootstrap, proof_child=proof,
            apply_children=children, chains=chains, observations=observations,
            workspaces={provider: workspace.path
                        for provider, workspace in workspaces.items()},
            live_bindings=actual_bindings, mutation_lease=lease,
            allow_append_lease=True,
        )
        fence()
        return PublishedMixedAppendSource(
            review.source,
            tuple((provider, workspaces[provider].path) for provider in order),
            review.live_binding_count,
            _digest({"schema": "mixed-append-live-bindings-v1",
                     "bindings": actual_bindings}),
            review.historical_rows_sha256,
        )
    except Exception:
        raise PublishedMixedAppendSourceAttention(
            "mixed append published source needs exact read-only reconciliation") from None
