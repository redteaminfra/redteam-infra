# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only teardown authority for a published four-host mixed generation.

This is deliberately separate from interrupted-Apply recovery. A central
adapter must acquire the teardown fence under its writer transaction and
recheck this authority before a saved destroy plan or provider GO. No function
here reserves a job, runs Terraform, or contacts a provider.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Callable, Mapping

from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_mixed_initial_apply_child import (
    recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_initial_host_binding import (
    ProviderHostObservation, _digest, recognize_mixed_initial_host_binding,
)
from app.services.provider_keyed_mixed_initial_plan_parent import validate_mixed_initial_apply_seal
from app.services.provider_keyed_mixed_initial_publication_source import (
    MixedHostRow, MixedInitialPublicationSource, MixedProviderState,
)
from app.services.provider_keyed_mixed_published_teardown_scope import (
    build_mixed_published_initial_teardown_scopes,
)
from app.services.provider_keyed_mixed_strict_host_receipt import (
    MixedStrictHostReceipt, child_id as proof_child_id, validate_receipt_child,
)
from app.storage.job_repository import StoredJobRun, job_event_digest


class PublishedMixedInitialTeardownAttention(ValueError):
    """A published two-provider generation or its teardown review drifted."""


_BINDINGS = frozenset({"channels", "domains", "certificates", "sites"})


def _published_proof_grammar(source: MixedInitialPublicationSource,
                             child: StoredJobRun) -> None:
    """Recheck the historical command grammar after publication strips claims.

    The synthetic claim strings satisfy only the old parser's shape; they do
    not restore or grant a worker claim. The successful publication transaction
    authenticated the real claim and raw artifact before committing.
    """
    completed = child.events[-2].data
    expected = {
        "engagementId": source.engagement_id, "coreJobId": source.core_job_id,
        "corePlanId": source.core_plan_id, "mixedParentId": source.parent_job_id,
        "handoffJournalSha256": source.parent_journal_sha256,
        "bindingJobId": f"job-provider-keyed-mixed-host-binding-{source.core_job_id.removeprefix('job-')}",
        "bindingManifestSha256": source.binding_manifest_sha256,
        "bootstrapJobId": f"job-provider-keyed-mixed-host-worker-{source.core_job_id.removeprefix('job-')}",
        "bootstrapJournalSha256": source.host_worker_journal_sha256,
        "mutation": False,
    }
    if (child.id != proof_child_id(source.core_job_id)
            or child.input != expected
            or type(completed.get("hostEvidenceSha256")) is not str
            or type(completed.get("evidencePath")) is not str):
        raise ValueError("published strict proof identity differs")
    historical = replace(
        child, status="running", finished_at=None, events=child.events[:-1],
        input={**expected, "claimOwner": "historical-publication",
               "claimToken": "historical-publication",
               "claimClaimedAt": "historical", "claimHeartbeatAt": "historical",
               "claimExpiresAt": "historical"},
    )
    receipt = MixedStrictHostReceipt(
        source, child.id, job_event_digest(historical.events),
        completed["hostEvidenceSha256"],
        tuple(row.hostname for row in source.host_rows),
        tuple(row.provider_instance_id for row in source.host_rows),
        completed["evidencePath"], "historical-publication", "historical-publication",
        "0" * 64, "0" * 64,
    )
    validate_receipt_child(source, historical, receipt)


@dataclass(frozen=True)
class PublishedSixTeardownSource:
    """Tagged six-host source, with the original initial parent kept explicit."""
    six_node_source: object
    parent_job_id: str
    provider_states: tuple[MixedProviderState, MixedProviderState]

    @property
    def ordered_providers(self):
        return self.six_node_source.provider_order

    @property
    def engagement_id(self):
        return self.six_node_source.engagement_id

    @property
    def core_job_id(self):
        return self.six_node_source.core_job_id

    @property
    def core_plan_id(self):
        return self.six_node_source.core_plan_id

    @property
    def chain_ids(self):
        return self.six_node_source.chain_ids

    @property
    def host_rows(self):
        return self.six_node_source.host_rows


@dataclass(frozen=True)
class PublishedMixedInitialTeardownReview:
    source: MixedInitialPublicationSource
    provider_scopes: tuple[dict, dict]
    published_parent_journal_sha256: str
    published_proof_journal_sha256: str
    live_binding_count: int
    historical_rows_sha256: str
    reviewed_policies: dict | None = None
    binding_manifest: dict | None = None
    failed_append_recovery: dict | None = None
    cleanup_observation: dict | None = None
    unpublished_six_recovery: dict | None = None


def historical_published_mixed_rows_sha256(
    *, parent: StoredJobRun, core: StoredJobRun, plan: object,
    binding: StoredJobRun, bootstrap: StoredJobRun,
    proof_child: StoredJobRun,
    apply_children: Mapping[str, StoredJobRun],
    chains: Mapping[str, object],
    failed_append_recovery: dict | None = None, jobs=None,
) -> str:
    """Digest stable reviewed rows for recheck after provider 1 is absent."""
    def job(row: StoredJobRun) -> dict:
        return {"id": row.id, "action": row.action, "status": row.status,
                "target": row.target, "targetType": row.target_type,
                "targetId": row.target_id, "requestedBy": row.requested_by,
                "input": row.input, "artifacts": row.artifact_refs,
                "journalSha256": job_event_digest(row.events),
                "completed": row.finished_at is not None}
    plan_row = {key: value for key, value in asdict(plan).items()
                if key not in {"created_at", "updated_at", "prepared_at"}}
    from app.services.provider_keyed_runtime_preflight import reviewed_mixed_chain_rows
    if any(key != row.chain_id for key, row in chains.items()):
        raise ValueError("historical chain mapping identity differs")
    selected_chains = reviewed_mixed_chain_rows(tuple(chains.values()), parent.input["chainIds"], parent.target_id)
    chain_rows = {key: {field: value for field, value in asdict(row).items()
                        if field not in {"created_at", "updated_at"}}
                  for key, row in sorted((row.chain_id, row) for row in selected_chains)}
    failed = None
    if failed_append_recovery is not None:
        from app.services.provider_keyed_mixed_failed_append_teardown import failure_history
        from types import SimpleNamespace
        from app.services.provider_keyed_mixed_initial_apply_child import _prior_workspace
        workspaces = {provider: _prior_workspace(parent, provider,
            recognize_mixed_initial_apply_terminal(child, parent, provider))
            for provider, child in apply_children.items()}
        saved_source = failed_append_recovery["source"]
        source = MixedInitialPublicationSource(**{**saved_source,
            "ordered_providers": tuple(saved_source["ordered_providers"]),
            "chain_ids": tuple(saved_source["chain_ids"]),
            "provider_states": tuple(MixedProviderState(**{**row, "resource_ids": tuple(tuple(x) for x in row["resource_ids"])}) for row in saved_source["provider_states"]),
            "host_rows": tuple(MixedHostRow(**row) for row in saved_source["host_rows"])})
        failure_history(SimpleNamespace(source=source, failed_append_recovery=failed_append_recovery),
            jobs=jobs, workspaces=workspaces, initial=parent)
        failed = failed_append_recovery
    return _digest({
        **({"failedAppendRecovery": failed} if failed is not None else {}),
        "parent": job(parent), "core": job(core), "plan": plan_row,
        "binding": job(binding), "bootstrap": job(bootstrap),
        "proof": job(proof_child),
        "children": {key: job(row) for key, row in sorted(apply_children.items())},
        "chains": chain_rows,
    })


def review_published_mixed_initial_teardown(
    *, parent: StoredJobRun, core: StoredJobRun, plan: object,
    binding: StoredJobRun, bootstrap: StoredJobRun,
    proof_child: StoredJobRun,
    apply_children: Mapping[str, StoredJobRun],
    chains: Mapping[str, object],
    observations: Mapping[str, ProviderHostObservation],
    workspaces: Mapping[str, Path],
    live_bindings: Mapping[str, tuple],
    mutation_lease: tuple[str, str] | None,
    allow_teardown_fence: bool = False,
    allow_append_lease: bool = False,
) -> PublishedMixedInitialTeardownReview:
    """Authenticate completed publication and exact current two-state scope.

    ``observations`` must be fresh, complete provider GET/state classifications
    supplied by the caller. Append mode authenticates the same publication
    while allowing independently owned bindings and requiring the append lease.
    This review is only a saved-plan source, never write authorization.
    """
    try:
        seal = validate_mixed_initial_apply_seal(parent)
        order, ids = tuple(seal["orderedProviders"]), tuple(seal["chainIds"])
        authorization = plan.evidence["sketchAuthorization"]
        if (allow_append_lease and allow_teardown_fence
                or parent.status != "succeeded" or parent.finished_at is None
                or parent.input.get("phase") != "completed"
                or parent.input.get("mutation") is not True
                or parent.input.get("coreJobId") != core.id
                or parent.input.get("corePlanId") != plan.id
                or parent.input.get("revisionId") != plan.revision_id
                or len(parent.events) != 8
                or [event.sequence for event in parent.events] != list(range(1, 9))
                or parent.events[-1].level != "info"
                or parent.events[-1].message != "mixed two-provider host proof published"
                or mutation_lease != ((plan.id, "provider_keyed_mixed_append")
                                      if allow_append_lease else
                                      (plan.id, "provider_keyed_teardown_fence")
                                      if allow_teardown_fence else None)
                or set(apply_children) != set(order)
                or set(chains) != set(ids)
                or set(observations) != set(order)
                or set(workspaces) != set(order)
                or set(live_bindings) != _BINDINGS
                or any(type(value) is not tuple or (value and not allow_append_lease)
                       for value in live_bindings.values())
                or core.action != "pilot_standard_rti_guarded_execute"
                or core.status != "succeeded" or core.finished_at is None
                or core.input.get("engagementId") != parent.target_id
                or core.input.get("corePlanId") != plan.id
                or core.input.get("sketchStateSchema") != "provider-keyed-v2"
                or core.input.get("pendingSketchChainIds") != list(ids)
                or plan.engagement_id != parent.target_id
                or plan.status != "applied" or plan.stage != "applied"
                or plan.apply_job_id != core.id
                or plan.evidence.get("sketchStateSchema") != "provider-keyed-v2"
                or plan.evidence.get("pendingSketchChainIds") != list(ids)
                or plan.evidence.get("pendingSketchChainFingerprints")
                   != core.input.get("pendingSketchChainFingerprints")
                or authorization["kind"] != "bounded-mixed-post-core-v1"
                or authorization["fingerprint"] != parent.input["reviewFingerprint"]
                or _digest({key: value for key, value in authorization.items()
                            if key != "fingerprint"}) != authorization["fingerprint"]
                or plan.review["reviewedConfiguration"]["sketchAuthorization"]
                   != authorization):
            raise ValueError("published core, plan, lease or binding inventory differs")
        fingerprints = core.input["pendingSketchChainFingerprints"]
        if (type(fingerprints) is not dict or set(fingerprints) != set(ids)
                or any(sketch_chain_intent_fingerprint(chains[chain_id])
                       != fingerprints[chain_id] for chain_id in ids)):
            raise ValueError("published chain intent differs")
        historical = replace(parent, events=parent.events[:7])
        manifest = recognize_mixed_initial_host_binding(binding, historical)
        if (manifest.get("orderedProviders") != list(order)
                or manifest.get("chainIds") != list(ids)
                or len(manifest.get("nodes", [])) != 4
                or bootstrap.status != "succeeded" or bootstrap.finished_at is None):
            raise ValueError("mixed bootstrap or binding differs")
        states = []
        for provider in order:
            child = apply_children[provider]
            terminal = recognize_mixed_initial_apply_terminal(child, historical, provider)
            observed = observations[provider]
            classification = observed.classification
            saved = terminal["proof"]
            if (classification.kind != "full"
                    or classification.provider != provider
                    or saved["stateSha256"] != classification.state_sha256
                    or saved["lineage"] != classification.lineage
                    or saved["serial"] != classification.serial
                    or saved["resourceIds"] != dict(classification.resource_ids)
                    or Path(terminal["planPath"]).parent != workspaces[provider]):
                raise ValueError("published provider state differs")
            states.append(MixedProviderState(
                provider, saved["stateSha256"], saved["lineage"], saved["serial"],
                tuple(sorted(saved["resourceIds"].items())),
                job_event_digest(child.events),
            ))
        rows = tuple(MixedHostRow(
            chain_id=row["chainId"], provider=row["provider"], role=row["role"],
            hostname=row["hostname"], terraform_address=row["terraformAddress"],
            provider_instance_id=row["providerInstanceId"], public_ip=row["publicIp"],
            assigned_proxy=row["assignedProxy"],
        ) for row in manifest["nodes"])
        source = MixedInitialPublicationSource(
            engagement_id=parent.target_id, core_job_id=core.id, core_plan_id=plan.id,
            revision_id=plan.revision_id, parent_job_id=parent.id,
            ordered_providers=order, chain_ids=ids,
            parent_journal_sha256=job_event_digest(historical.events),
            binding_manifest_sha256=_digest(manifest),
            host_worker_journal_sha256=job_event_digest(bootstrap.events),
            provider_states=tuple(states), host_rows=rows,
        )
        source_sha = _digest(asdict(source))
        publication = parent.events[-1].data
        completed = proof_child.events[-2]
        proof_terminal = proof_child.events[-1]
        if (proof_child.status != "succeeded" or proof_child.finished_at is None
                or proof_child.action != "provider_keyed_mixed_initial_strict_host_proof"
                or proof_child.target_id != parent.target_id
                or len(proof_child.events) != 60
                or [event.sequence for event in proof_child.events]
                   != list(range(1, 61))
                or completed.level != "info"
                or completed.message != "mixed strict host proof completed"
                or completed.data.get("sourceSha256") != source_sha
                or proof_child.events[0].data != {"sourceSha256": source_sha}
                or proof_terminal.level != "info"
                or proof_terminal.message != "mixed strict host proof published"
                or proof_terminal.data != {
                    "parentJobId": parent.id,
                    "hostEvidenceSha256": completed.data.get("hostEvidenceSha256"),
                }
                or publication != {
                    "sourceSha256": source_sha,
                    "hostEvidenceSha256": completed.data.get("hostEvidenceSha256"),
                    "chainIds": list(ids),
                    "providerStates": [{"provider": state.provider,
                                        "stateSha256": state.state_sha256}
                                       for state in states],
                }):
            raise ValueError("mixed publication receipt differs")
        _published_proof_grammar(source, proof_child)
        scopes = build_mixed_published_initial_teardown_scopes(
            source, reviewed_policies=seal["reviewedPolicy"],
            reviewed_chain_fingerprints=fingerprints,
            observations=observations, workspaces=workspaces, chains=chains,
        )
        return PublishedMixedInitialTeardownReview(
            source, scopes, job_event_digest(parent.events),
            job_event_digest(proof_child.events),
            sum(len(value) for value in live_bindings.values()),
            historical_published_mixed_rows_sha256(
                parent=parent, core=core, plan=plan, binding=binding,
                bootstrap=bootstrap, proof_child=proof_child,
                apply_children=apply_children, chains=chains))
    except Exception:
        raise PublishedMixedInitialTeardownAttention(
            "published mixed initial teardown source requires exact review") from None


def recheck_published_mixed_initial_teardown_go(
    reviewed: PublishedMixedInitialTeardownReview, *,
    fresh_review: Callable[[], PublishedMixedInitialTeardownReview],
    fence: Callable[[], str],
) -> PublishedMixedInitialTeardownReview:
    """One read-only pre-GO comparison; a later writer owns the command journal."""
    try:
        before = fence()
        if (type(before) is not str or not before
                or type(reviewed) is not PublishedMixedInitialTeardownReview
                or not callable(fresh_review)):
            raise ValueError("published teardown fence differs")
        current = fresh_review()
        if current != reviewed or fence() != before:
            raise ValueError("published teardown source changed before GO")
        return current
    except Exception:
        raise PublishedMixedInitialTeardownAttention(
            "published mixed initial teardown GO requires fresh exact review") from None


def published_review_policy(review, initial, provider):
    """Select explicit final policy for append; never alter the initial seal."""
    if review.failed_append_recovery is not None and review.failed_append_recovery.get("kind") == "failed-second-v1":
        return review.failed_append_recovery["currentPolicies"][provider]
    if type(review.source) is PublishedSixTeardownSource:
        if not review.reviewed_policies or provider not in review.reviewed_policies:
            raise ValueError("published final policy absent")
        return review.reviewed_policies[provider]
    return validate_mixed_initial_apply_seal(initial)["reviewedPolicy"][provider]


def six_collection_review(collection, *, jobs, plans, sketches):
    """Adapt a fully authenticated six-node collection to the existing coordinator."""
    from app.services.provider_keyed_mixed_initial_plan_parent import _parent_id
    source = collection.source
    initial = jobs.get(_parent_id(source.core_job_id))
    append = jobs.get(source.parent_id)
    states = tuple(MixedProviderState(
        provider, observation.classification.state_sha256,
        observation.classification.lineage, observation.classification.serial,
        tuple(sorted(observation.classification.resource_ids)), source.provider_proof_digests[index])
        for index, provider in enumerate(source.provider_order)
        for observation in (collection.observations[provider],))
    wrapped = PublishedSixTeardownSource(source, initial.id, states)
    reviewed = PublishedMixedInitialTeardownReview(
        wrapped, collection.scope.provider_scopes, job_event_digest(initial.events),
        (collection.unpublished_six_recovery["failedHostSha256"] if collection.unpublished_six_recovery is not None
         else append.events[-1].data["hostProofJournalSha256"]),
        collection.scope.binding_count, "", collection.reviewed_policies,
        collection.binding_manifest, cleanup_observation=getattr(collection, "cleanup_observation", None),
        unpublished_six_recovery=getattr(collection, "unpublished_six_recovery", None))
    return replace(reviewed, historical_rows_sha256=six_historical_rows_sha256(
        reviewed, jobs=jobs, plans=plans, sketches=sketches))


def six_historical_rows_sha256(review, *, jobs, plans, sketches):
    """Reopen append journals, saved artifacts and local rows without provider GETs."""
    if review.unpublished_six_recovery is not None:
        from app.services.provider_keyed_unpublished_six_cleanup import historical_review
        return historical_review(review, jobs=jobs, plans=plans, sketches=sketches)
    from app.services.provider_keyed_mixed_append_pair_host_proof import _child_id as host_id
    from app.services.provider_keyed_mixed_append_pair_apply_child import _child_id as first_id
    from app.services.provider_keyed_mixed_append_second_apply_child import _child_id as second_id
    from app.services.provider_keyed_mixed_published_six_source import (
        recognize_mixed_published_six_source, derive_mixed_published_six_policies)
    from app.services.provider_keyed_mixed_published_six_journal import validate_mixed_published_six_journals
    source = review.source.six_node_source
    from app.services.provider_keyed_mixed_initial_apply_child import _child_id as initial_child_id
    from app.services.provider_keyed_mixed_initial_host_binding import _binding_child_id
    from app.services.provider_keyed_mixed_initial_bootstrap import _worker_id
    initial_rows = [jobs.get(initial_child_id(source.core_job_id, provider))
                    for provider in source.provider_order]
    initial_rows += [jobs.get(_binding_child_id(source.core_job_id)),
                     jobs.get(_worker_id(source.core_job_id)),
                     jobs.get(proof_child_id(source.core_job_id))]
    append = jobs.get(source.parent_id)
    initial = jobs.get(review.source.parent_job_id)
    host = jobs.get(host_id(append.id))
    children = {source.provider_order[0]: jobs.get(first_id(append.id)),
                source.provider_order[1]: jobs.get(second_id(append.id))}
    from app.services.provider_keyed_runtime_preflight import reviewed_mixed_chain_rows
    complete_chains = sketches.list_for_engagement(source.engagement_id)
    chains = {row.chain_id: row for row in reviewed_mixed_chain_rows(
        complete_chains, source.chain_ids, source.engagement_id)}
    current, receipt = recognize_mixed_published_six_source(
        append, host_proof_child=host, provider_children=children, current_chains=chains)
    from app.services.provider_keyed_channel_generation import read_channel_generation
    if review.cleanup_observation is not None:
        from app.services.provider_keyed_channel_cleanup_observation import read_cleanup_channel_generation
        from app.services.provider_keyed_mixed_initial_apply_child import _prior_workspace
        workspaces = {provider: _prior_workspace(initial, provider,
            recognize_mixed_initial_apply_terminal(jobs.get(initial_child_id(source.core_job_id, provider)), initial, provider))
            for provider in source.provider_order}
        generation, observation = read_cleanup_channel_generation(current, append, initial, jobs,
            workspaces=workspaces, saved_observation=review.cleanup_observation, require_current_state=False)
        if observation != review.cleanup_observation:
            raise ValueError("published cleanup observation changed")
    else:
        generation = read_channel_generation(current, append, initial, jobs, require_current_state=False)
    policies = generation.policies
    validate_mixed_published_six_journals(current, append, children)
    if (current != source or policies != review.reviewed_policies
            or generation.state_sha256s != tuple(state.state_sha256 for state in review.source.provider_states)):
        raise ValueError("published six-node historical source or policy changed")
    return _digest({"source": asdict(source), "append": job_event_digest(append.events),
                    "initial": job_event_digest(initial.events),
                    "core": asdict(jobs.get(source.core_job_id)),
                    "plan": {k: v for k, v in asdict(plans.get(source.core_plan_id)).items()
                             if k not in {"created_at", "updated_at", "prepared_at"}},
                    "initialRows": [asdict(row) if row is not None else None for row in initial_rows],
                    "policies": policies, "ingressAdvances": generation.advances,
                    "children": {key: job_event_digest(row.events) for key, row in children.items()},
                    "host": job_event_digest(host.events)})


def published_review_states(review):
    """Current destroy snapshots, keeping the initial publication immutable."""
    if review.failed_append_recovery is None:
        return review.source.provider_states
    return tuple(replace(state, state_sha256=scope["stateSha256"],
                         lineage=scope["lineage"], serial=scope["serial"],
                         resource_ids=(tuple(sorted(review.failed_append_recovery["currentResourceIds"][state.provider].items()))
                             if review.failed_append_recovery.get("kind") == "failed-second-v1" else state.resource_ids))
                 for state, scope in zip(review.source.provider_states, review.provider_scopes, strict=True))
