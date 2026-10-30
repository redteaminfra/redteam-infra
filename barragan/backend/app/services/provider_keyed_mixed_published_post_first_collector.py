# Copyright (c) 2026, Oracle and/or its affiliates.
"""Fresh persisted-source review between published mixed provider destroys.

The first provider's exact absence is a saved child receipt. This reader
reopens every historical row, then obtains new provider GET/state observations
under the teardown lease. It never executes Terraform or provider writes.
"""

from __future__ import annotations

from app.services.provider_keyed_runtime_preflight import reviewed_mixed_chain_rows

from dataclasses import dataclass
from pathlib import Path

from app.services.core_ssh import active_core_connection_details
from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.services.provider_keyed_core_destroy_preview import _read_regular
from app.services.provider_keyed_initial_destroy_pre_go_recovery import _process_quiescent
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id, _prior_workspace, recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_initial_apply_proof import prove_mixed_initial_prior_provider_fresh
from app.services.provider_keyed_mixed_initial_bootstrap import _worker_id
from app.services.provider_keyed_mixed_initial_host_binding import (
    ProviderHostObservation, _binding_child_id,
)
from app.services.provider_keyed_mixed_interrupted_dispatch import _core_inspector_scope
from app.services.provider_keyed_mixed_partial_apply_inventory import collect_provider_inventory_snapshot
from app.services.provider_keyed_mixed_published_destroy_child import (
    child_id as destroy_child_id, recognize_published_mixed_destroy_child,
)
from app.services.provider_keyed_mixed_published_second_transition import (
    PublishedMixedSecondTransition, review_published_mixed_second_transition,
)
from app.services.provider_keyed_mixed_published_teardown_authority import (
    historical_published_mixed_rows_sha256,
)
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    recognize_published_mixed_plans_sealed,
    saved_published_mixed_destroy_plans,
    saved_published_mixed_initial_review,
)
from app.services.provider_keyed_mixed_published_teardown_collector import _empty_owned_bindings
from app.services.provider_keyed_mixed_strict_host_receipt import child_id as proof_child_id
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_mixed_published_teardown_authority import (
    PublishedSixTeardownSource, six_historical_rows_sha256,
)

from app.services.provider_keyed_mixed_published_binding_manifest import require_published_bindings_unchanged

from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.domain_repository import SqlAlchemyDomainRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


class PublishedMixedPostFirstCollectionAttention(ValueError):
    """The post-first saved source or fresh provider observations differ."""


def _default_quiescent(identity: dict) -> bool:
    return _process_quiescent(identity["bootId"], identity["pid"],
                              identity["pgid"], identity["startTicks"])


@dataclass(frozen=True)
class PublishedMixedPostFirstCollection:
    cleanup: StoredJobRun
    initial: StoredJobRun
    review: object
    plans: object
    first_destroy_child: StoredJobRun
    transition: PublishedMixedSecondTransition
    second_observation: ProviderHostObservation


def collect_published_mixed_post_first_transition(
    cleanup_id: str, *, job_repository=None, plan_repository=None,
    sketch_repository=None, domain_repository=None,
    provider_resource_repository=None, credential_repository=None,
    lease_lookup=None, core_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    process_quiescent=_default_quiescent,
) -> PublishedMixedPostFirstCollection:
    """Reopen a saved receipt and collect fresh first-absent/second-full facts."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plan_rows = plan_repository or SqlAlchemyDeploymentPlanRepository()
    sketches = sketch_repository or SqlAlchemySketchChainRepository()
    domains = domain_repository or SqlAlchemyDomainRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        cleanup = jobs.get(cleanup_id)
        review = saved_published_mixed_initial_review(cleanup)
        plans = saved_published_mixed_destroy_plans(cleanup)
        source = review.source
        initial = jobs.get(source.parent_job_id)
        recognize_published_mixed_plans_sealed(
            cleanup, review, plans, cleanup.input["reviewScope"],
            cleanup.input["engagementName"])
        if (initial is None or cleanup.target_id != source.engagement_id
                or core_state_root != DEFAULT_TERRAFORM_STATE_ROOT):
            raise ValueError("published mixed post-first identity differs")
        order = source.ordered_providers
        first, second = order
        first_child = jobs.get(destroy_child_id(source.core_job_id, first))
        lease = (source.core_plan_id, "provider_keyed_teardown_fence")

        def fence() -> str:
            if (lookup(source.engagement_id) != lease
                    or jobs.get(cleanup.id) != cleanup
                    or jobs.get(initial.id) != initial
                    or jobs.get(destroy_child_id(source.core_job_id, first))
                       != first_child):
                raise ValueError("published mixed post-first lease or parent changed")
            return f"{cleanup.id}:{plans.plan_set_sha256}"

        def historical() -> bool:
            if type(source) is PublishedSixTeardownSource:
                return six_historical_rows_sha256(
                    review, jobs=jobs, plans=plan_rows, sketches=sketches) == review.historical_rows_sha256
            core = jobs.get(source.core_job_id)
            plan = plan_rows.get(source.core_plan_id)
            binding = jobs.get(_binding_child_id(source.core_job_id))
            bootstrap = jobs.get(_worker_id(source.core_job_id))
            proof = jobs.get(proof_child_id(source.core_job_id))
            children = {p: jobs.get(_child_id(source.core_job_id, p)) for p in order}
            durable = sketches.list_for_engagement(source.engagement_id)
            chains = {row.chain_id: row for row in reviewed_mixed_chain_rows(
                durable, source.chain_ids, source.engagement_id)}
            if (core is None or plan is None or binding is None
                    or bootstrap is None or proof is None
                    or any(child is None for child in children.values())
                    or set(chains) != set(source.chain_ids)
                    or active_core_connection_details(jobs, source.engagement_id)[0]
                       != source.core_job_id):
                return False
            return (historical_published_mixed_rows_sha256(
                parent=jobs.get(initial.id), core=core, plan=plan,
                binding=binding, bootstrap=bootstrap, proof_child=proof,
                apply_children=children, chains=chains, failed_append_recovery=review.failed_append_recovery, jobs=jobs)
                == review.historical_rows_sha256)

        def fresh_scope() -> dict:
            core = jobs.get(source.core_job_id)
            if core is None:
                raise ValueError("published mixed core disappeared")
            return _core_inspector_scope(
                core, jobs=jobs, core_state_root=core_state_root,
                plan_repository=plan_rows,
                provider_resource_repository=resources)

        def empty_bindings() -> dict[str, tuple]:
            return require_published_bindings_unchanged(review, jobs, domains)

        if (not historical()
                or fresh_scope() != cleanup.input["reviewScope"]
                or empty_bindings() != {kind: () for kind in (
                    "channels", "domains", "certificates", "sites")}):
            raise ValueError("published mixed post-first historical source changed")
        originals = {p: jobs.get(_child_id(source.core_job_id, p)) for p in order}
        workspaces = {p: _prior_workspace(
            initial, p, recognize_mixed_initial_apply_terminal(
                originals[p], initial, p)) for p in order}
        if any(str(workspaces[p].path) != review.provider_scopes[index]["workspace"]
               for index, p in enumerate(order)):
            raise ValueError("published mixed workspace source changed")
        if (first_child is None or recognize_published_mixed_destroy_child(
                first_child, cleanup, review, plans, first,
                cleanup.input["reviewScope"], cleanup.input["engagementName"])
                != "absence_proved"):
            raise ValueError("published mixed first provider receipt is not persisted")
        first_identity = first_child.events[4].data
        def quiescent() -> bool:
            return process_quiescent({key: first_identity[key] for key in (
                "bootId", "pid", "pgid", "startTicks")}) is True
        first_snapshot = collect_provider_inventory_snapshot(
            initial, first, workspaces[first], fence=fence,
            process_quiescent=quiescent,
            credential_repository=credential_repository,
            phase_mode="destroy_applied")
        if type(source) is PublishedSixTeardownSource:
            from app.services.provider_keyed_mixed_published_six_collector import _fresh_observation
            from app.services.provider_keyed_mixed_append_pair_apply_child import _child_id as first_append_id
            from app.services.provider_keyed_mixed_append_second_apply_child import _child_id as second_append_id
            six = source.six_node_source
            append = jobs.get(six.parent_id)
            append_child = jobs.get((first_append_id if six.provider_order.index(second) == 0
                                     else second_append_id)(append.id))
            from app.services.provider_keyed_channel_generation import read_channel_generation
            if review.unpublished_six_recovery is not None:
                generation = None
            elif review.cleanup_observation is not None:
                from app.services.provider_keyed_channel_cleanup_observation import read_cleanup_channel_generation
                generation, _ = read_cleanup_channel_generation(six, append, initial, jobs,
                    workspaces=workspaces, saved_observation=review.cleanup_observation, require_current_state=False)
            else:
                generation = read_channel_generation(six, append, initial, jobs, require_current_state=False)
            second_observation = _fresh_observation(
                second, six, append, workspaces[second], review.reviewed_policies[second],
                append_child, fence, credential_repository=credential_repository,
                current_generation=generation if generation is not None and generation.advances else None,
                cleanup_initial=initial, cleanup_observation=review.cleanup_observation)
        elif review.failed_append_recovery is not None:
            from app.services.provider_keyed_mixed_failed_append_teardown import fresh_failed_append_observation
            append = jobs.get(review.failed_append_recovery["appendParentId"])
            second_observation = fresh_failed_append_observation(initial, append, second,
                workspaces[second], fence=fence, jobs=jobs)
        else:
            second_class = prove_mixed_initial_prior_provider_fresh(
                initial, originals[second], workspaces[second], fence=fence,
                process_quiescent=process_quiescent,
                credential_repository=credential_repository)
            second_observation = ProviderHostObservation(
                second_class, _read_regular(workspaces[second].state_path))
        transition = review_published_mixed_second_transition(
            initial, cleanup, review, plans, first_child,
            first_snapshot, second_observation,
            cleanup.input["reviewScope"], cleanup.input["engagementName"],
            fence=fence, process_quiescent=process_quiescent,
            historical_source_unchanged=historical,
            fresh_core_inspector_scope=fresh_scope,
            fresh_empty_bindings=empty_bindings)
        if not historical() or fence() != transition.source_generation:
            raise ValueError("published mixed post-first source changed during GET")
        return PublishedMixedPostFirstCollection(
            cleanup, initial, review, plans, first_child,
            transition, second_observation)
    except Exception:
        raise PublishedMixedPostFirstCollectionAttention(
            "published mixed provider 2 requires exact fresh persisted review") from None
