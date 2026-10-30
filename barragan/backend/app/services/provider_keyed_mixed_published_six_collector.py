# Copyright (c) 2026, Oracle and/or its affiliates.
"""GET-only review of a published mixed six-node teardown generation.

This joins the saved append source, final reviewed policies, current provider
inventory, core/Inspector scope and external bindings. It reserves no job and
grants no Terraform or DNS write authority. The same collection must be run
again under the teardown lease at reservation and each provider GO.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Callable

from app.services.core_ssh import active_core_connection_details
from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_initial_destroy_pre_go_recovery import _process_quiescent
from app.services.provider_keyed_mixed_append_first_poststate import (
    collect_first_mixed_append_inventory_snapshot,
)
from app.services.provider_keyed_mixed_append_live_bindings import collect_mixed_append_live_bindings
from app.services.provider_keyed_mixed_append_pair_apply_binding import _intent
from app.services.provider_keyed_mixed_append_pair_apply_child import _child_id as first_child_id
from app.services.provider_keyed_mixed_append_pair_host_proof import (
    SixNodeHostSource, _child_id as host_child_id,
)
from app.services.provider_keyed_mixed_append_pair_plan_worker import _name, _read
from app.services.provider_keyed_mixed_append_pair_parent import _parent_id as append_parent_id
from app.services.provider_keyed_mixed_append_second_apply_child import _child_id as second_child_id
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id as initial_child_id, _prior_workspace, recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_initial_host_binding import ProviderHostObservation
from app.services.provider_keyed_mixed_initial_plan_parent import (
    _parent_id as initial_parent_id, validate_mixed_initial_apply_seal,
)
from app.services.provider_keyed_mixed_interrupted_dispatch import _core_inspector_scope
from app.services.provider_keyed_mixed_partial_apply_source import (
    ProviderApplyClassification, _inventory, _state,
)
from app.services.provider_keyed_mixed_published_binding_manifest import build_mixed_published_binding_manifest
from app.services.provider_keyed_mixed_published_dispatch_claim import _valid_marker
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    ACTION as TEARDOWN_ACTION, parent_id as teardown_parent_id,
)
from app.services.provider_keyed_mixed_published_six_scope import (
    PublishedMixedSixScope, build_mixed_published_six_teardown_scope,
    _POST_APPEND_SHARED,
)
from app.services.provider_keyed_mixed_published_six_source import (
    derive_mixed_published_six_policies, recognize_mixed_published_six_source,
)
from app.services.provider_keyed_mixed_published_six_journal import (
    validate_mixed_published_six_journals,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, reviewed_mixed_chain_rows
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.domain_repository import SqlAlchemyDomainRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


class MixedPublishedSixCollectionAttention(ValueError):
    """A current published six-node review cannot be authenticated."""


@dataclass(frozen=True)
class PublishedMixedSixCollection:
    source: SixNodeHostSource
    scope: PublishedMixedSixScope
    core_inspector_scope: dict
    binding_manifest: dict
    observations: dict[str, ProviderHostObservation]
    reviewed_policies: dict[str, dict]
    workspaces: dict[str, Path]
    cleanup_observation: dict | None = None
    unpublished_six_recovery: dict | None = None


def _fresh_observation(provider: str, source, append: StoredJobRun,
                       workspace, policy: dict, child: StoredJobRun,
                       fence: Callable[[], str], *, credential_repository=None,
                       linode_transport=None, digitalocean_transport=None,
                       snapshot_reader=collect_first_mixed_append_inventory_snapshot,
                       process_quiescent=_process_quiescent,
                       current_generation=None, cleanup_initial=None, cleanup_observation=None) -> ProviderHostObservation:
    """Use the existing complete provider GET and audited retained-state reader."""
    index = source.provider_order.index(provider)
    expected_hash = (source.state_sha256s[index] if current_generation is None
                     else current_generation.state_sha256s[index])
    intent = _intent(provider, append.input["intents"][provider])
    root = Path(source.workspace_paths[index])
    receipt_bytes = _read(root / _name(provider, "plan-receipt.json"))
    receipt = json.loads(receipt_bytes)
    started = child.events[3].data
    identity = {key: started[key] for key in ("bootId", "pid", "pgid", "startTicks")}
    if (workspace.path != root or receipt.get("provider") != provider
            or hashlib.sha256(receipt_bytes).hexdigest()
               != append.input["receiptSha256"][provider]
            or type(identity["bootId"]) is not str or not identity["bootId"]
            or any(type(identity[key]) is not int or identity[key] <= 0
                   for key in ("pid", "pgid", "startTicks"))):
        raise ValueError("saved append receipt or process differs")
    quiet = lambda: process_quiescent(
        identity["bootId"], identity["pid"], identity["pgid"], identity["startTicks"])
    expected_phase = "applied"
    if cleanup_observation is not None and cleanup_observation["provider"] == provider:
        from app.services.provider_keyed_mixed_partial_apply_inventory import collect_provider_inventory_snapshot
        snapshot = collect_provider_inventory_snapshot(cleanup_initial, provider, workspace,
            fence=fence, process_quiescent=quiet, credential_repository=credential_repository,
            linode_transport=linode_transport, digitalocean_transport=digitalocean_transport)
        expected_phase = "apply_started"
    else:
        snapshot = snapshot_reader(
            intent=intent, workspace=workspace, receipt=receipt, fence=fence,
            process_quiescent=quiet, credential_repository=credential_repository,
            linode_transport=linode_transport,
            digitalocean_transport=digitalocean_transport)
    if (not quiet() or snapshot.provider != provider
            or snapshot.phase != expected_phase or type(snapshot.state_json) is not bytes
            or snapshot.state_sha256 != expected_hash):
        raise ValueError("fresh append provider state differs")
    state, actual, cloud = _state(provider, policy, snapshot.state_json)
    _inventory(provider, policy, actual, cloud, snapshot.inventory)
    nodes = {identifier for address, identifier in cloud.items()
             if address in policy["nodes"]}
    if (set(actual) != set(policy["nodes"]) | _POST_APPEND_SHARED[provider]
            or (provider == "linode" and (
                type(snapshot.linode_firewall_attached_node_ids) is not tuple
                or len(snapshot.linode_firewall_attached_node_ids) != len(nodes)
                or set(snapshot.linode_firewall_attached_node_ids) != nodes))
            or (provider == "digitalocean" and (
                snapshot.selector_tag_exists is not True
                or type(snapshot.selector_attached_node_ids) is not tuple
                or len(snapshot.selector_attached_node_ids) != len(nodes)
                or set(snapshot.selector_attached_node_ids) != nodes
                or snapshot.selector_resources_count != len(nodes)))
            or (child.events[8].data.get("stateSha256") != snapshot.state_sha256
                if current_generation is None else False)
            or child.events[8].data.get("lineage") != state["lineage"]
            or (child.events[8].data.get("serial") != state["serial"]
                if current_generation is None else child.events[8].data.get("serial") > state["serial"])
            or child.events[8].data.get("resourceIds")
               != [[address, str(attributes["id"])]
                   for address, attributes in sorted(actual.items())]):
        raise ValueError("fresh append provider inventory differs")
    fence()
    return ProviderHostObservation(ProviderApplyClassification(
        provider, "full", snapshot.state_sha256, state["lineage"],
        state["serial"], tuple(sorted(cloud.items()))), snapshot.state_json)


def collect_published_mixed_six_teardown(
    engagement_id: str, core_job_id: str, *,
    job_repository=None, plan_repository=None, sketch_repository=None,
    domain_repository=None, provider_resource_repository=None,
    core_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    lease_lookup=None, credential_repository=None,
    linode_transport=None, digitalocean_transport=None,
    binding_inventory=collect_mixed_append_live_bindings,
    fresh_observer=None, manifest_builder=build_mixed_published_binding_manifest,
    allow_teardown_fence: bool = False,
    saved_unpublished_source=None,
) -> PublishedMixedSixCollection:
    """Collect one exact review; never reserve, destroy, or change DNS."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    sketches = sketch_repository or SqlAlchemySketchChainRepository()
    domains = domain_repository or SqlAlchemyDomainRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        if (type(engagement_id) is not str or not engagement_id
                or type(core_job_id) is not str or not core_job_id):
            raise ValueError("published six-node identity differs")
        core = jobs.get(core_job_id)
        initial = jobs.get(initial_parent_id(core_job_id))
        append = jobs.get(append_parent_id(core_job_id))
        if (core is None or initial is None or append is None
                or core.input.get("engagementId") != engagement_id
                or append.target_id != engagement_id):
            raise ValueError("published six-node jobs are absent")
        plan = plans.get(core.input.get("corePlanId"))
        if (plan is None or plan.id != append.input.get("corePlanId")
                or plan.engagement_id != engagement_id or plan.status != "applied"
                or plan.apply_job_id != core.id):
            raise ValueError("published core plan differs")
        seal = validate_mixed_initial_apply_seal(initial)
        order = tuple(append.input.get("providerOrder", ()))
        if set(order) != {"digitalocean", "linode"} or len(order) != 2:
            raise ValueError("published provider order differs")
        host = jobs.get(host_child_id(append.id))
        children = {order[0]: jobs.get(first_child_id(append.id)),
                    order[1]: jobs.get(second_child_id(append.id))}
        initial_children = {provider: jobs.get(initial_child_id(core.id, provider))
                            for provider in order}
        chain_rows = tuple(sketches.list_for_engagement(engagement_id))
        chains = {row.chain_id: row for row in reviewed_mixed_chain_rows(
            chain_rows, seal["chainIds"], engagement_id)}
        if (host is None or any(row is None for row in (*children.values(),
                                                       *initial_children.values()))
                or active_core_connection_details(jobs, engagement_id)[0] != core.id):
            raise ValueError("published six-node children or chains differ")
        unpublished = append.input.get("phase") == "apply_sealed" and host.status == "failed"
        recovery = None
        if unpublished:
            from app.services.provider_keyed_unpublished_six_cleanup import recovery_evidence
            from app.services.provider_keyed_mixed_append_six_source import collect_fresh_six_node_host_source
            if saved_unpublished_source is not None:
                if fresh_observer is None:
                    raise ValueError("saved unpublished source is writer-only")
                source = saved_unpublished_source
            else:
                source = collect_fresh_six_node_host_source(append.id, job_repository=jobs,
                    sketch_repository=sketches, credential_repository=credential_repository,
                    lease_lookup=lookup, linode_transport=linode_transport,
                    digitalocean_transport=digitalocean_transport,
                    lease_operation="provider_keyed_teardown_fence" if allow_teardown_fence else "provider_keyed_mixed_append")
            receipt = None
            recovery = recovery_evidence(source, append, host, children, fresh=True)
        else:
            if saved_unpublished_source is not None:
                raise ValueError("unpublished source lifecycle differs")
            source, receipt = recognize_mixed_published_six_source(
                append, host_proof_child=host, provider_children=children,
                current_chains=chains)
        if (source.core_job_id != core.id or source.core_plan_id != plan.id
                or set(source.provider_order) != set(seal["orderedProviders"])
                or set(source.chain_ids) != set(seal["chainIds"])):
            raise ValueError("published six-node initial identity differs")
        policies = derive_mixed_published_six_policies(source, append, initial, unpublished_cleanup=unpublished)
        from app.services.provider_keyed_channel_generation import read_channel_generation
        generation = None if unpublished else read_channel_generation(source, append, initial, jobs, require_current_state=False)
        validate_mixed_published_six_journals(source, append, children, unpublished_cleanup=unpublished)
        for before in source.before_chains:
            if (sketch_chain_intent_fingerprint(before)
                    != plan.evidence["pendingSketchChainFingerprints"][before.chain_id]):
                raise ValueError("published original chain intent differs")
        fingerprints = {chain.chain_id: sketch_chain_intent_fingerprint(chain)
                        for chain in (source.before_chains if unpublished else source.chains)}
        workspaces = {}
        for provider in order:
            terminal = recognize_mixed_initial_apply_terminal(
                initial_children[provider], initial, provider)
            workspace = _prior_workspace(initial, provider, terminal)
            if workspace.path != Path(source.workspace_paths[order.index(provider)]):
                raise ValueError("published provider workspace differs")
            workspaces[provider] = workspace
        from app.services.provider_keyed_channel_cleanup_observation import read_cleanup_channel_generation
        cleanup_observation = None
        if not unpublished:
            generation, cleanup_observation = read_cleanup_channel_generation(
                source, append, initial, jobs, workspaces=workspaces,
                credential_repository=credential_repository)
            policies = generation.policies
        bindings = binding_inventory(engagement_id)
        if unpublished:
            from app.services.provider_keyed_mixed_published_teardown_collector import _empty_owned_bindings
            _empty_owned_bindings(engagement_id, jobs, domains)
        core_scope = _core_inspector_scope(
            core, jobs=jobs, core_state_root=core_state_root,
            plan_repository=plans, provider_resource_repository=resources)
        lease = ((plan.id, "provider_keyed_teardown_fence")
                 if allow_teardown_fence else (plan.id, "provider_keyed_mixed_append") if unpublished else None)
        from app.services.provider_keyed_mixed_append_pair_parent import _plan_child_id
        append_plan = jobs.get(_plan_child_id(append.id)) if unpublished else None
        selected = (core, initial, append, host, plan, *((append_plan,) if append_plan is not None else ()), *children.values(),
                    *initial_children.values())
        teardown = jobs.get(teardown_parent_id(core_job_id))
        if teardown is not None and (
                teardown.action != TEARDOWN_ACTION
                or teardown.target_id != engagement_id
                or teardown.input.get("coreJobId") != core_job_id):
            raise ValueError("published six-node teardown parent differs")

        def related_jobs():
            return tuple(row for row in jobs.list_for_engagement(engagement_id)
                         if not (teardown is not None and _valid_marker(row, teardown)))

        related = related_jobs()

        def fence() -> str:
            if (lookup(engagement_id) != lease
                    or any((plans.get(row.id) if row is plan else jobs.get(row.id)) != row
                           for row in selected)
                    or tuple(sketches.list_for_engagement(engagement_id)) != chain_rows
                    or binding_inventory(engagement_id) != bindings
                    or jobs.get(teardown_parent_id(core_job_id)) != teardown
                    or related_jobs() != related
                    or active_core_connection_details(jobs, engagement_id)[0] != core.id):
                raise ValueError("published six-node source changed during review")
            if unpublished:
                if recovery_evidence(source, append, host, children) != recovery or any(
                        hashlib.sha256(_read(workspaces[p].state_path, private=False)).hexdigest()
                        != source.state_sha256s[order.index(p)] for p in order):
                    raise ValueError("unpublished cleanup source or state changed")
            if cleanup_observation is not None:
                from app.services.provider_keyed_channel_cleanup_observation import require_cleanup_observation_unchanged
                require_cleanup_observation_unchanged(cleanup_observation, jobs)
                if any(hashlib.sha256(_read(workspaces[p].state_path, private=False)).hexdigest()
                       != generation.state_sha256s[source.provider_order.index(p)] for p in order):
                    raise ValueError("cleanup ingress current provider state changed")
            return source.source_sha256

        fence()
        observations = {}
        for provider in order:
            fence()
            observations[provider] = (
                fresh_observer(provider, source, append, workspaces[provider],
                               policies[provider], children[provider], fence)
                if fresh_observer is not None else
                _fresh_observation(
                    provider, source, append, workspaces[provider],
                    policies[provider], children[provider], fence,
                    credential_repository=credential_repository,
                    linode_transport=linode_transport,
                    digitalocean_transport=digitalocean_transport,
                    current_generation=generation if generation is not None and generation.advances else None,
                    cleanup_initial=initial, cleanup_observation=cleanup_observation))
            if cleanup_observation is not None and fresh_observer is None:
                from app.services.provider_keyed_channel_provider_proof import require_current_keyed_firewall
                from app.services.provider_keyed_initial_teardown import _state_resources
                require_current_keyed_firewall(provider, policies[provider],
                    _state_resources(json.loads(observations[provider].state_json)),
                    fence=fence, credential_repository=credential_repository)
            fence()
        scope = build_mixed_published_six_teardown_scope(
            source, append_parent=append, host_proof_child=host,
            host_receipt=receipt, provider_children=children,
            reviewed_policies=policies, reviewed_chain_fingerprints=fingerprints,
            observations=observations, chains=chains, live_bindings=bindings,
            current_generation=generation if generation is not None and generation.advances else None,
            unpublished_cleanup=unpublished)
        fence()
        manifest = manifest_builder(
            source, scope, domain_repository=domains, job_repository=jobs,
            binding_inventory=binding_inventory, core_targets=core_scope["targets"])
        if (fence() != source.source_sha256
                or _core_inspector_scope(
                    core, jobs=jobs, core_state_root=core_state_root,
                    plan_repository=plans, provider_resource_repository=resources)
                   != core_scope):
            raise ValueError("published core/Inspector scope changed")
        return PublishedMixedSixCollection(
            source, scope, core_scope, manifest, observations, policies,
            {provider: workspace.path for provider, workspace in workspaces.items()}, cleanup_observation, recovery)
    except Exception:
        raise MixedPublishedSixCollectionAttention(
            "published six-node teardown requires exact read-only review") from None
