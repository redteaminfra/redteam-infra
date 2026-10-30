# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only runtime collection for the published four-host mixed teardown.

This is a review source, not a reservation or destroy command. The provider
reader performs GETs only, and every observation is bracketed by the same
persisted-source fence. A later writer must recheck this review under its
teardown lease before any provider GO.
"""

from __future__ import annotations

from app.storage.binding_history import is_independent_binding_history

from app.services.provider_keyed_runtime_preflight import reviewed_mixed_chain_rows

from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Callable

from app.services.core_ssh import active_core_connection_details
from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
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
    ProviderHostObservation, _binding_child_id,
)
from app.services.provider_keyed_mixed_initial_plan_parent import (
    _parent_id, validate_mixed_initial_apply_seal,
)
from app.services.provider_keyed_mixed_interrupted_dispatch import _core_inspector_scope
from app.services.provider_keyed_mixed_published_teardown_authority import (
    PublishedMixedInitialTeardownReview, review_published_mixed_initial_teardown,
)
from app.services.provider_keyed_mixed_published_dispatch_claim import _valid_marker
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    ACTION as TEARDOWN_ACTION,
    parent_id as teardown_parent_id,
)
from app.services.provider_keyed_mixed_strict_host_receipt import child_id as proof_child_id
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.domain_repository import SqlAlchemyDomainRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


class PublishedMixedTeardownCollectionAttention(ValueError):
    """The persisted published source or a fresh read cannot be authenticated."""


@dataclass(frozen=True)
class PublishedMixedTeardownCollection:
    review: PublishedMixedInitialTeardownReview
    core_inspector_scope: dict
    observations: dict[str, ProviderHostObservation]
    workspaces: dict[str, Path]
    six_collection: object | None = None




def _empty_owned_bindings(engagement_id: str, jobs, domains, *, read_only_transport=False) -> dict[str, tuple]:
    """Conservatively prove no independently persisted binding was created.

    The initial-only path rejects any channel/service/DNS/certificate work
    history, including records later marked removed. Such generations need
    the future bound-generation cleanup manifest instead.
    """
    from app.storage.database import db
    from app.storage.models import (
        CertificateAssetModel, CertificateBindingModel,
        DomainDnsRecordOwnershipModel, EngagementServiceModel,
    )

    related = jobs.list_for_engagement(engagement_id)
    if (domains.list_assignments(engagement_id=engagement_id)
            or any(is_independent_binding_history(row.action)
                    and not (read_only_transport and row.action in {
                        "outbound_channel_apply_preview", "outbound_channel_apply",
                        "outbound_channel_validation"}
                        and row.status in {"succeeded", "failed"}
                        and row.finished_at is not None)
                   for row in related)
            or db.session.query(DomainDnsRecordOwnershipModel.id).filter_by(
                engagement_id=engagement_id).first() is not None
            or db.session.query(CertificateAssetModel.id).filter_by(
                engagement_id=engagement_id).first() is not None
            or db.session.query(CertificateBindingModel.id).filter_by(
                engagement_id=engagement_id).first() is not None
            or db.session.query(EngagementServiceModel.service_id).filter_by(
                engagement_id=engagement_id).first() is not None):
        raise ValueError("published mixed generation has independently owned bindings")
    return {kind: () for kind in ("channels", "domains", "certificates", "sites")}


def _require_no_independent_failed_second_bindings(bindings, core, plan):
    """Allow only canonical initial core intent snapshots, retaining their hash.

    This is cleanup eligibility, not a filtered binding inventory. The caller
    still compares the full original append binding fence before reaching here.
    """
    from app.integrations.pilot_standard_rti import pilot_channel_rows, pilot_names
    from app.services.provider_keyed_mixed_append_live_bindings import _channel_history
    from app.services.provider_keyed_mixed_failed_append_teardown import _exact_json

    if (set(bindings) != {"channels", "domains", "certificates", "sites"}
            or any(bindings[kind] for kind in ("domains", "certificates", "sites"))):
        raise ValueError("failed second cleanup has independent bindings")
    if not bindings["channels"]:
        return
    target, count = core.input.get("target"), core.input.get("proxyCount")
    name = core.input.get("engagementName")
    if (core.action != "pilot_standard_rti_guarded_execute" or core.status != "succeeded"
            or core.input.get("deploymentMode") != "hold_for_review"
            or type(name) is not str or not name
            or type(count) is not int or count not in (1, 2)
            or type(target) is not dict or type(target.get("region")) is not str or not target["region"]
            or _exact_json(target) != _exact_json(plan.evidence.get("target"))
            or _exact_json(count) != _exact_json(plan.evidence.get("proxyCount"))):
        raise ValueError("failed second core intent source differs")
    expected = pilot_channel_rows(pilot_names(name), region=target["region"], proxy_count=count)
    snapshots = [event for event in core.events
                 if {"inboundChannels", "outboundChannels"} & set(event.data)]
    messages = ["core infrastructure deployed; preparing continuous Inspector",
                "operator inspection ready", "pilot Standard RTI run finished"]
    if ([event.message for event in snapshots] != messages or snapshots[-1] != core.events[-1]
            or any(event.level != "info" or _exact_json({key: event.data.get(key) for key in expected})
                   != _exact_json(expected) for event in snapshots)
            or core.events[-1].data.get("ok") is not True
            or core.events[-1].data.get("mutationStatus") != "deployed"
            or core.events[-1].data.get("ansibleStatus") != "validated"
            or core.events[-1].data.get("finalCleanupStatus") != "pending_operator_teardown"
            or bindings["channels"] != _channel_history([core])):
        raise ValueError("failed second cleanup has noncanonical channel history")


def collect_published_mixed_initial_teardown(
    engagement_id: str, core_job_id: str, *,
    job_repository=None, plan_repository=None, sketch_repository=None,
    domain_repository=None, provider_resource_repository=None,
    core_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    lease_lookup: Callable[[str], tuple[str, str] | None] | None = None,
    fresh_observer: Callable[[StoredJobRun, str, Callable[[], str]], ProviderHostObservation] | None = None,
    binding_inventory: Callable[[str, object, object], dict[str, tuple]] | None = None,
    allow_teardown_fence: bool = False,
    read_only_transport: bool = False,
    saved_no_apply_recovery=None,
) -> PublishedMixedTeardownCollection:
    """Collect one exact, currently present two-provider published generation."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    sketches = sketch_repository or SqlAlchemySketchChainRepository()
    domains = domain_repository or SqlAlchemyDomainRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    lookup = lease_lookup or _db_lease_lookup
    if read_only_transport and (allow_teardown_fence or binding_inventory is not None):
        raise PublishedMixedTeardownCollectionAttention("transport review cannot authorize teardown")
    inventory = binding_inventory or (lambda engagement, jobs, domains:
        _empty_owned_bindings(engagement, jobs, domains, read_only_transport=read_only_transport))
    from app.services.provider_keyed_mixed_append_pair_parent import _parent_id as append_id
    append = jobs.get(append_id(core_job_id))
    from app.services.provider_keyed_mixed_unapplied_append_teardown import no_apply_present
    unapplied_append = append is not None and no_apply_present(append, jobs)
    if saved_no_apply_recovery is not None and (not unapplied_append or fresh_observer is None):
        raise PublishedMixedTeardownCollectionAttention("saved no-Apply recovery is writer-only")
    failed_append = append is not None and (append.input.get("phase") == "apply_sealed" or unapplied_append)
    from app.services.provider_keyed_mixed_append_pair_host_proof import _child_id as append_host_id
    failed_host = jobs.get(append_host_id(append.id)) if append is not None else None
    unpublished_six = failed_append and failed_host is not None and failed_host.status == "failed"
    if append is not None and (not failed_append or unpublished_six):
        from app.services.provider_keyed_mixed_published_six_collector import collect_published_mixed_six_teardown
        from app.services.provider_keyed_mixed_published_teardown_authority import six_collection_review
        value = collect_published_mixed_six_teardown(
            engagement_id, core_job_id, job_repository=jobs, plan_repository=plans,
            sketch_repository=sketches, domain_repository=domains,
            provider_resource_repository=resources, core_state_root=core_state_root,
            lease_lookup=lookup, allow_teardown_fence=allow_teardown_fence)
        if read_only_transport and (value.cleanup_observation is not None or value.unpublished_six_recovery is not None):
            raise PublishedMixedTeardownCollectionAttention("cleanup-only observation cannot authorize channel transport")
        review = six_collection_review(value, jobs=jobs, plans=plans, sketches=sketches)
        return PublishedMixedTeardownCollection(
            review, value.core_inspector_scope, value.observations, value.workspaces, value)
    try:
        if (type(engagement_id) is not str or not engagement_id
                or type(core_job_id) is not str or not core_job_id):
            raise ValueError("mixed published identity absent")
        core = jobs.get(core_job_id)
        parent = jobs.get(_parent_id(core_job_id))
        if (core is None or parent is None or core.input.get("engagementId") != engagement_id
                or parent.target_id != engagement_id):
            raise ValueError("mixed published core/parent differs")
        seal = validate_mixed_initial_apply_seal(parent)
        order, ids = tuple(seal["orderedProviders"]), tuple(seal["chainIds"])
        plan = plans.get(core.input.get("corePlanId"))
        if plan is None:
            raise ValueError("mixed published plan absent")
        binding = jobs.get(_binding_child_id(core_job_id))
        bootstrap = jobs.get(_worker_id(core_job_id))
        proof = jobs.get(proof_child_id(core_job_id))
        children = {provider: jobs.get(_child_id(core_job_id, provider)) for provider in order}
        if (binding is None or bootstrap is None or proof is None
                or any(child is None for child in children.values())):
            raise ValueError("mixed publication children absent")
        durable = tuple(sketches.list_for_engagement(engagement_id))
        selected = reviewed_mixed_chain_rows(durable, ids, engagement_id)
        if (active_core_connection_details(jobs, engagement_id)[0] != core_job_id):
            raise ValueError("published chain/core generation differs")
        chains = {row.chain_id: row for row in selected}
        workspaces = {}
        for provider in order:
            terminal = recognize_mixed_initial_apply_terminal(children[provider], parent, provider)
            workspaces[provider] = _prior_workspace(parent, provider, terminal)
        workspace_paths = {provider: workspace.path for provider, workspace in workspaces.items()}
        # Exclude only this exact teardown parent's internal claim. A different
        # job with the same action remains publication-source evidence.
        teardown = jobs.get(teardown_parent_id(core_job_id))
        if (teardown is not None and (teardown.action != TEARDOWN_ACTION
                or teardown.target_id != engagement_id
                or teardown.input.get("coreJobId") != core_job_id)):
            raise ValueError("mixed published teardown parent differs")

        def related_jobs() -> tuple[StoredJobRun, ...]:
            return tuple(
                row for row in jobs.list_for_engagement(engagement_id)
                if not (teardown is not None and _valid_marker(row, teardown)))

        related = related_jobs()
        bindings = inventory(engagement_id, jobs, domains)
        scope = _core_inspector_scope(
            core, jobs=jobs, core_state_root=core_state_root,
            plan_repository=plans, provider_resource_repository=resources)
        lease = ((plan.id, "provider_keyed_teardown_fence")
                 if allow_teardown_fence else
                 (plan.id, "provider_keyed_mixed_append") if failed_append else None)
        if lookup(engagement_id) != lease:
            raise ValueError("published mixed mutation lease differs")
        journal = job_event_digest(parent.events)

        def fence() -> str:
            if (lookup(engagement_id) != lease
                    or jobs.get(core.id) != core or jobs.get(parent.id) != parent
                    or plans.get(plan.id) != plan or jobs.get(binding.id) != binding
                    or jobs.get(bootstrap.id) != bootstrap or jobs.get(proof.id) != proof
                    or any(jobs.get(child.id) != child for child in children.values())
                    or tuple(sketches.list_for_engagement(engagement_id)) != durable
                    or jobs.get(teardown_parent_id(core_job_id)) != teardown
                    or related_jobs() != related
                    or inventory(engagement_id, jobs, domains) != bindings
                    or active_core_connection_details(jobs, engagement_id)[0] != core_job_id):
                raise ValueError("mixed published source changed during review")
            return journal

        observations = {}
        for provider in order:
            fence()
            if failed_append:
                from app.services.provider_keyed_mixed_failed_append_teardown import fresh_failed_append_observation
                observations[provider] = (fresh_observer(parent, provider, fence) if fresh_observer is not None else
                    fresh_failed_append_observation(parent, append, provider, workspaces[provider],
                        fence=fence, jobs=jobs))
            elif fresh_observer is not None:
                observations[provider] = fresh_observer(parent, provider, fence)
            else:
                workspace, child = workspaces[provider], children[provider]
                classified = prove_mixed_initial_prior_provider_fresh(
                    parent, child, workspace, fence=fence,
                    process_quiescent=lambda identity: _process_quiescent(
                        identity["bootId"], identity["pid"], identity["pgid"],
                        identity["startTicks"]),
                )
                fence()
                raw = _read_regular(workspace.state_path)
                fence()
                observations[provider] = ProviderHostObservation(classified, raw)
            fence()
        historical_observations = observations
        if failed_append:
            from app.services.provider_keyed_mixed_append_pair_plan_worker import _name, _read, _sha, _canonical
            from app.services.provider_keyed_mixed_partial_apply_source import ProviderApplyClassification
            historical_observations = {}
            for provider in order:
                saved = recognize_mixed_initial_apply_terminal(children[provider], parent, provider)["proof"]
                raw = _read(workspaces[provider].path / _name(provider, "predecessor.tfstate"))
                if _sha(raw) != saved["stateSha256"]:
                    raise ValueError("failed append predecessor differs from publication")
                historical_observations[provider] = ProviderHostObservation(ProviderApplyClassification(
                    provider, "full", saved["stateSha256"], saved["lineage"], saved["serial"],
                    tuple(sorted(saved["resourceIds"].items()))), raw)
        reviewed = review_published_mixed_initial_teardown(
            parent=parent, core=core, plan=plan, binding=binding,
            bootstrap=bootstrap, proof_child=proof,
            apply_children=children, chains=chains, observations=historical_observations,
            workspaces=workspace_paths, live_bindings=bindings,
            mutation_lease=lease, allow_teardown_fence=allow_teardown_fence,
            allow_append_lease=failed_append and not allow_teardown_fence,
        )
        if failed_append:
            from app.services.provider_keyed_mixed_failed_append_teardown import immutable_failure_evidence, local_delete_projection
            from app.services.provider_keyed_mixed_published_teardown_authority import historical_published_mixed_rows_sha256
            from app.services.provider_keyed_mixed_append_live_bindings import collect_mixed_append_live_bindings
            append_bindings = collect_mixed_append_live_bindings(engagement_id, job_repository=jobs)
            if not unapplied_append and (append.input.get("historicalRowsSha256") != reviewed.historical_rows_sha256
                    or append.input.get("liveBindingsSha256") != _canonical({
                        "schema": "mixed-append-live-bindings-v1", "bindings": append_bindings})):
                raise ValueError("failed append initial source or bindings changed")
            from app.services.provider_keyed_mixed_failed_second_append import second_failure_present, build_second_failure_recovery
            if unapplied_append:
                from app.services.provider_keyed_mixed_unapplied_append_teardown import build_no_apply_recovery, no_apply_history
                scopes = reviewed.provider_scopes
                if saved_no_apply_recovery is None:
                    recovery = build_no_apply_recovery(reviewed, parent, append,
                        jobs=jobs, workspaces=workspaces, plans=plans, sketches=sketches,
                        lease_lookup=lookup)
                else:
                    recovery = saved_no_apply_recovery
                    no_apply_history(replace(reviewed, failed_append_recovery=recovery),
                        jobs=jobs, workspaces=workspaces, initial=parent)
            elif second_failure_present(append, jobs):
                if reviewed.live_binding_count != 0:
                    raise ValueError("failed second cleanup has independent bindings")
                _require_no_independent_failed_second_bindings(append_bindings, core, plan)
                scopes, recovery = build_second_failure_recovery(reviewed, parent, append,
                    observations=observations, workspaces=workspaces, jobs=jobs)
            else:
                first = append.input["providerOrder"][0]
                scopes = []
                for provider, old_scope in zip(order, reviewed.provider_scopes, strict=True):
                    observed = observations[provider]
                    phase = json_source_phase(workspaces[provider].path)
                    if phase != {"schema": "provider-keyed-v2", "phase": "apply_started" if provider == first else "applied"}:
                        raise ValueError("failed append phase changed")
                    predecessor = historical_observations[provider].state_json
                    if provider == first:
                        local_delete_projection(predecessor, observed.state_json,
                            _read(workspaces[provider].path / _name(provider, "show.json")))
                    elif observed.state_json != predecessor:
                        raise ValueError("untouched append state differs")
                    scopes.append({**old_scope, "stateSha256": observed.classification.state_sha256,
                        "lineage": observed.classification.lineage, "serial": observed.classification.serial,
                        "resources": [row for row in old_scope["resources"] if provider != first or row["kind"] != "local_file"]})
                evidence = immutable_failure_evidence(append, source=reviewed.source,
                    initial=parent, workspaces=workspaces, jobs=jobs)
                recovery = {"appendParentId": append.id, "failedProvider": first, "source": json_source(reviewed.source), "evidence": evidence}
            reviewed = replace(reviewed, provider_scopes=tuple(scopes), failed_append_recovery=recovery)
            reviewed = replace(reviewed, historical_rows_sha256=historical_published_mixed_rows_sha256(
                parent=parent, core=core, plan=plan, binding=binding, bootstrap=bootstrap,
                proof_child=proof, apply_children=children, chains=chains,
                failed_append_recovery=recovery, jobs=jobs))
        if (_core_inspector_scope(
                core, jobs=jobs, core_state_root=core_state_root,
                plan_repository=plans, provider_resource_repository=resources) != scope
                or fence() != journal):
            raise ValueError("mixed core/Inspector scope changed during review")
        return PublishedMixedTeardownCollection(reviewed, scope, observations,
                                                workspace_paths)
    except Exception:
        raise PublishedMixedTeardownCollectionAttention(
            "published mixed teardown collection requires exact read-only review") from None


def recheck_published_six_collection_local(collection, *, jobs, allow_teardown_fence):
    """Writer-only local recheck of saved observations; performs no provider GETs."""
    from app.services.provider_keyed_mixed_published_six_collector import collect_published_mixed_six_teardown
    from app.services.provider_keyed_mixed_published_teardown_authority import six_collection_review
    plans = SqlAlchemyDeploymentPlanRepository()
    sketches = SqlAlchemySketchChainRepository()
    review = collection.review
    for provider, workspace in collection.workspaces.items():
        if _read_regular(workspace / "terraform.tfstate") != collection.observations[provider].state_json:
            raise ValueError("published six-node retained state changed")
    from app.services.provider_keyed_mixed_published_binding_manifest import recheck_mixed_published_manifest_local
    domains = SqlAlchemyDomainRepository()
    value = collect_published_mixed_six_teardown(
        review.source.engagement_id, review.source.core_job_id,
        job_repository=jobs, plan_repository=plans, sketch_repository=sketches,
        allow_teardown_fence=allow_teardown_fence,
        fresh_observer=lambda provider, *_: collection.observations[provider],
        saved_unpublished_source=review.source.six_node_source if review.unpublished_six_recovery is not None else None,
        manifest_builder=lambda source, scope, **options: recheck_mixed_published_manifest_local(
            source, scope, review.binding_manifest, domains=domains, jobs=jobs,
            core_targets=options["core_targets"]))
    current = six_collection_review(value, jobs=jobs, plans=plans, sketches=sketches)
    if current != review or value.core_inspector_scope != collection.core_inspector_scope:
        raise ValueError("published six-node writer source changed")
    return current


def json_source(source):
    import json
    return json.loads(json.dumps(asdict(source)))


def recheck_failed_append_collection_local(collection, *, jobs, allow_teardown_fence):
    """Reuse collection with saved fresh observations; no provider GET in writer."""
    for provider, path in collection.workspaces.items():
        if _read_regular(path / "terraform.tfstate") != collection.observations[provider].state_json:
            raise ValueError("failed append retained state changed")
    current = collect_published_mixed_initial_teardown(
        collection.review.source.engagement_id, collection.review.source.core_job_id,
        job_repository=jobs, allow_teardown_fence=allow_teardown_fence,
        fresh_observer=lambda _parent, provider, _fence: collection.observations[provider],
        saved_no_apply_recovery=(collection.review.failed_append_recovery
            if collection.review.failed_append_recovery.get("kind") == "unapplied-append-v1" else None))
    if current != collection:
        raise ValueError("failed append teardown source changed")


def json_source_phase(path):
    import json
    return json.loads(_read_regular(path / ".barragan-apply-phase.json"))
