# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only historical published source after OCI state has become empty.

The pre-GO tail reader requires a full OCI state, so absence must reopen the
same saved two-provider handoff without treating an empty core state as drift.
"""

from __future__ import annotations

from app.services.provider_keyed_runtime_preflight import reviewed_mixed_chain_rows

from dataclasses import dataclass

from app.services.core_ssh import active_core_connection_details
from app.services.provider_keyed_mixed_initial_apply_child import _child_id as apply_child_id
from app.services.provider_keyed_mixed_initial_bootstrap import _worker_id
from app.services.provider_keyed_mixed_initial_host_binding import _binding_child_id
from app.services.provider_keyed_mixed_published_destroy_child import (
    child_id, recognize_published_mixed_destroy_child,
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
from app.services.provider_keyed_mixed_zero_apply_teardown_source import _owned_inspector_records
from app.services.provider_keyed_mixed_published_teardown_authority import (
    PublishedSixTeardownSource, six_historical_rows_sha256,
)

from app.services.provider_keyed_mixed_published_binding_manifest import require_published_bindings_unchanged

from app.storage.domain_repository import SqlAlchemyDomainRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from app.storage.job_repository import job_event_digest


class PublishedMixedPostOciSourceAttention(ValueError):
    """The saved published provider handoff or retained bindings changed."""


@dataclass(frozen=True)
class PublishedMixedPostOciSource:
    core_state_sha256: str
    core_inventory_sha256: str
    owned_inspector_record_ids: tuple[str, str]
    provider_child_journal_sha256: tuple[str, str]
    provider_absence_receipt_sha256: tuple[str, str]


def audit_published_mixed_post_oci_source(
    parent, initial, core, plan, jobs, lookup, *,
    sketch_repository=None, domain_repository=None, provider_resource_repository=None,
    active_core_reader=active_core_connection_details,
    binding_reader=_empty_owned_bindings,
    inspector_record_reader=_owned_inspector_records,
) -> PublishedMixedPostOciSource:
    """Authenticate historical rows and both terminal children under a fence.

    This does not read the OCI state or contact providers; the exact OCI
    empty-state and absent-ID scanner is the caller's next step.
    """
    sketches = sketch_repository or SqlAlchemySketchChainRepository()
    domains = domain_repository or SqlAlchemyDomainRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    try:
        review = saved_published_mixed_initial_review(parent)
        plans = saved_published_mixed_destroy_plans(parent)
        scope = parent.input["reviewScope"]
        name = parent.input["engagementName"]
        recognize_published_mixed_plans_sealed(parent, review, plans, scope, name)
        source = review.source
        order = source.ordered_providers
        children = {provider: jobs.get(child_id(source.core_job_id, provider))
                    for provider in order}
        original = {provider: jobs.get(apply_child_id(source.core_job_id, provider))
                    for provider in order}
        binding = jobs.get(_binding_child_id(source.core_job_id))
        bootstrap = jobs.get(_worker_id(source.core_job_id))
        proof = jobs.get(proof_child_id(source.core_job_id))
        durable = sketches.list_for_engagement(source.engagement_id)
        chains = {row.chain_id: row for row in reviewed_mixed_chain_rows(
            durable, source.chain_ids, source.engagement_id)}
        if (parent.target_id != source.engagement_id
                or initial.id != source.parent_job_id
                or job_event_digest(initial.events) != review.published_parent_journal_sha256
                or core.id != source.core_job_id or plan.id != source.core_plan_id
                or any(row is None for row in (*children.values(), *original.values(),
                                               binding, bootstrap, proof))
                or lookup(source.engagement_id) != (
                    source.core_plan_id, "provider_keyed_teardown_fence")
                or active_core_reader(jobs, source.engagement_id)[0] != source.core_job_id
                or (six_historical_rows_sha256(review, jobs=jobs, plans=_PlanRow(plan), sketches=sketches)
                    if type(source) is PublishedSixTeardownSource else historical_published_mixed_rows_sha256(
                    parent=initial, core=core, plan=plan, binding=binding,
                    bootstrap=bootstrap, proof_child=proof,
                    apply_children=original, chains=chains, failed_append_recovery=review.failed_append_recovery, jobs=jobs))
                   != review.historical_rows_sha256
                or (require_published_bindings_unchanged(review, jobs, domains, require_dns_absent=True)
                    if type(source) is PublishedSixTeardownSource else binding_reader(source.engagement_id, jobs, domains))
                   != {kind: () for kind in (
                       "channels", "domains", "certificates", "sites")}
                or tuple(scope["ownedInspectorRecordIds"])
                   != inspector_record_reader(source.engagement_id, jobs, resources)):
            raise ValueError("published historical rows or bindings changed")
        phases = tuple(recognize_published_mixed_destroy_child(
            children[provider], parent, review, plans, provider, scope, name)
            for provider in order)
        receipts = tuple(children[provider].events[7].data["receiptSha256"]
                         for provider in order)
        if (phases != ("absence_proved", "absence_proved")
                or children[order[1]].input["priorAbsenceReceiptSha256"] != receipts[0]
                or scope["jobId"] != core.id or scope["planId"] != plan.id):
            raise ValueError("published provider receipts changed")
        return PublishedMixedPostOciSource(
            scope["stateSha256"], scope["inventorySha256"],
            tuple(scope["ownedInspectorRecordIds"]),
            tuple(job_event_digest(children[provider].events) for provider in order),
            receipts)
    except Exception:
        raise PublishedMixedPostOciSourceAttention(
            "published post-OCI source requires exact historical provider receipts") from None


class _PlanRow:
    def __init__(self, plan):
        self.plan = plan
    def get(self, plan_id):
        return self.plan if self.plan.id == plan_id else None
