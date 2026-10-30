# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only checkpoint contract for a published mixed initial teardown.

The normal engagement Tear Down writer must reserve this proposal while it
atomically acquires the teardown fence and rechecks the reviewed source. A
proposal or a saved checkpoint alone never authorizes a provider write.
"""

from __future__ import annotations

from dataclasses import asdict
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path

from app.domain import JobEvent
from app.services.engagement_teardown import (
    _fingerprint, preview_published_mixed_initial_scope,
)
from app.services.provider_keyed_mixed_interrupted_cleanup import _review_scope_input
from app.services.provider_keyed_mixed_published_destroy_plan import (
    PublishedMixedDestroyPlan, PublishedMixedDestroyPlanSet,
)
from app.services.provider_keyed_mixed_published_teardown_authority import (
    PublishedMixedInitialTeardownReview, PublishedSixTeardownSource,
)
from app.services.provider_keyed_mixed_initial_publication_source import (
    MixedHostRow, MixedInitialPublicationSource, MixedProviderState,
)
from app.storage.job_repository import StoredJobRun


ACTION = "provider_keyed_mixed_published_cleanup"
SCHEMA = "mixed-published-initial-cleanup-v1"


def parent_id(core_job_id: str) -> str:
    return f"job-provider-keyed-mixed-published-cleanup-{core_job_id.removeprefix('job-')}"


def _input(review: PublishedMixedInitialTeardownReview,
           core_inspector_scope: dict, engagement_name: str, *, historical=False) -> dict:
    preview = preview_published_mixed_initial_scope(
        review, core_inspector_scope, engagement_name)
    source = review.source
    if not historical and type(source) is PublishedSixTeardownSource and (
            type(review.binding_manifest) is not dict or "publicTargetSeal" not in review.binding_manifest):
        raise ValueError("new published six-node cleanup requires sealed public targets")
    if type(review.binding_manifest) is dict and "publicTargetSeal" in review.binding_manifest:
        from types import SimpleNamespace
        from app.services.provider_keyed_mixed_public_targets import published_targets
        published_targets(SimpleNamespace(input={"bindingManifest": review.binding_manifest,
            "publicTargetSealSha256": review.binding_manifest["publicTargetSeal"].get("sha256")}),
            core_inspector_scope["targets"])
    scope_input = _review_scope_input(core_inspector_scope)
    if (not scope_input or scope_input["reviewScope"]["jobId"] != source.core_job_id
            or scope_input["reviewScope"]["planId"] != source.core_plan_id):
        raise ValueError("published mixed core/Inspector review differs")
    return {
        "schema": SCHEMA,
        "engagementId": source.engagement_id,
        "engagementName": engagement_name,
        "coreJobId": source.core_job_id,
        "corePlanId": source.core_plan_id,
        "publishedParentId": source.parent_job_id,
        "publishedSource": json.loads(json.dumps(asdict(source))),
        "publishedSourceSha256": _fingerprint(asdict(source)),
        "publishedParentJournalSha256": review.published_parent_journal_sha256,
        "publishedProofJournalSha256": review.published_proof_journal_sha256,
        "historicalRowsSha256": review.historical_rows_sha256,
        "orderedProviders": list(source.ordered_providers),
        "providerScopes": list(review.provider_scopes),
        "providerScopeSha256": _fingerprint({"providerScopes": list(review.provider_scopes)}),
        "reviewScope": scope_input["reviewScope"],
        "reviewScopeSha256": scope_input["reviewScopeSha256"],
        "reviewSnapshotId": preview["snapshotId"],
        "phase": "awaiting_both_destroy_plans",
        "mutation": True,
        **({"publicTargetSealSha256": review.binding_manifest["publicTargetSeal"]["sha256"]}
           if type(review.binding_manifest) is dict and "publicTargetSeal" in review.binding_manifest else {}),
        **({"unpublishedSixRecovery": review.unpublished_six_recovery} if review.unpublished_six_recovery is not None else {}),
        **({"cleanupObservation": review.cleanup_observation} if review.cleanup_observation is not None else {}),
        **({"failedAppendRecovery": review.failed_append_recovery} if review.failed_append_recovery is not None else {}),
        **({"sourceKind": "unpublished-six-node-cleanup-v1" if review.unpublished_six_recovery is not None else "published-six-node-v1",
            "reviewedPolicies": review.reviewed_policies,
            "bindingManifest": review.binding_manifest,
            "liveBindingCount": review.live_binding_count}
           if type(source) is PublishedSixTeardownSource else {}),
    }


def propose_published_mixed_initial_cleanup(
    review: PublishedMixedInitialTeardownReview, core_inspector_scope: dict,
    engagement_name: str, *, requested_by: str, _historical=False,
) -> StoredJobRun:
    """Build the single-action proposal; no reservation or Terraform call."""
    if type(requested_by) is not str or not requested_by.strip() or requested_by != requested_by.strip():
        raise ValueError("published mixed teardown requester differs")
    inputs = _input(review, core_inspector_scope, engagement_name, historical=_historical)
    engagement_id = inputs["engagementId"]
    return StoredJobRun(
        id=parent_id(inputs["coreJobId"]), action=ACTION, status="queued",
        target=f"engagement:{engagement_id}", target_type="engagement",
        target_id=engagement_id, requested_by=requested_by,
        input=inputs, artifact_refs=[],
        created_at=datetime.now(timezone.utc).isoformat(),
        started_at=None, finished_at=None,
        events=[JobEvent(1, "info", "published mixed cleanup review queued", {
            "reviewSnapshotId": inputs["reviewSnapshotId"],
            "providerScopeSha256": inputs["providerScopeSha256"],
        })],
    )


def recognize_published_mixed_initial_checkpoint(
    saved: StoredJobRun, review: PublishedMixedInitialTeardownReview,
    core_inspector_scope: dict, engagement_name: str,
) -> StoredJobRun:
    """Authenticate only the queued source checkpoint, never a GO."""
    expected = propose_published_mixed_initial_cleanup(
        review, core_inspector_scope, engagement_name,
        requested_by=saved.requested_by)
    if (saved.id != expected.id or saved.action != expected.action
            or saved.status != "queued" or saved.target != expected.target
            or saved.target_type != expected.target_type
            or saved.target_id != expected.target_id
            or saved.input != expected.input or saved.events != expected.events
            or saved.artifact_refs != [] or saved.started_at is not None
            or saved.finished_at is not None):
        raise ValueError("published mixed teardown checkpoint differs")
    return saved


def saved_published_mixed_initial_review(
    saved: StoredJobRun,
) -> PublishedMixedInitialTeardownReview:
    """Reopen exact saved publication facts after provider 1 is absent.

    The full/full collector cannot run after the first destroy. Callers must
    also reread the historical rows and post-first provider observations under
    the same teardown fence before using this saved source for any GO.
    """
    try:
        if ((saved.input.get("sourceKind") == "unpublished-six-node-cleanup-v1")
                != (saved.input.get("unpublishedSixRecovery") is not None)):
            raise ValueError("saved unpublished cleanup tag differs")
        raw = saved.input["publishedSource"]
        if saved.input.get("sourceKind") in ("published-six-node-v1", "unpublished-six-node-cleanup-v1"):
            from app.services.provider_keyed_mixed_published_six_source import _source
            if set(raw) != set(PublishedSixTeardownSource.__dataclass_fields__):
                raise ValueError("saved six-node source shape differs")
            states = tuple(MixedProviderState(
                **{**row, "resource_ids": tuple(tuple(item) for item in row["resource_ids"])})
                for row in raw["provider_states"])
            source = PublishedSixTeardownSource(
                _source(raw["six_node_source"]), raw["parent_job_id"], states)
        else:
            if (type(raw) is not dict
                    or set(raw) != set(MixedInitialPublicationSource.__dataclass_fields__)
                    or type(raw["provider_states"]) is not list
                    or len(raw["provider_states"]) != 2
                    or type(raw["host_rows"]) is not list
                    or len(raw["host_rows"]) != 4):
                raise ValueError("saved published mixed source shape differs")
            states = tuple(MixedProviderState(
                **{**row, "resource_ids": tuple(tuple(item)
                                                  for item in row["resource_ids"])})
                for row in raw["provider_states"])
            hosts = tuple(MixedHostRow(**row) for row in raw["host_rows"])
            source = MixedInitialPublicationSource(
                **{**raw, "ordered_providers": tuple(raw["ordered_providers"]),
                   "chain_ids": tuple(raw["chain_ids"]),
                   "provider_states": states, "host_rows": hosts})
        scopes = saved.input["providerScopes"]
        if (json.loads(json.dumps(asdict(source))) != raw
                or source.engagement_id != saved.target_id
                or source.core_job_id != saved.input["coreJobId"]
                or source.core_plan_id != saved.input["corePlanId"]
                or source.parent_job_id != saved.input["publishedParentId"]
                or list(source.ordered_providers) != saved.input["orderedProviders"]
                or _fingerprint(raw) != saved.input["publishedSourceSha256"]
                or type(scopes) is not list or len(scopes) != 2
                or _fingerprint({"providerScopes": scopes})
                   != saved.input["providerScopeSha256"]
                or tuple(scope["provider"] for scope in scopes)
                   != source.ordered_providers):
            raise ValueError("saved published mixed source digest differs")
        if saved.input.get("publicTargetSealSha256") is not None:
            from app.services.provider_keyed_mixed_public_targets import published_targets
            published_targets(saved, saved.input["reviewScope"]["targets"])
        return PublishedMixedInitialTeardownReview(
            source, tuple(scopes), saved.input["publishedParentJournalSha256"],
            saved.input["publishedProofJournalSha256"], saved.input.get("liveBindingCount", 0),
            saved.input["historicalRowsSha256"],
            saved.input.get("reviewedPolicies"), saved.input.get("bindingManifest"),
            saved.input.get("failedAppendRecovery"), saved.input.get("cleanupObservation"),
            saved.input.get("unpublishedSixRecovery"))
    except Exception:
        raise ValueError("saved published mixed review requires exact checkpoint") from None


def saved_published_mixed_destroy_plans(
    saved: StoredJobRun,
) -> PublishedMixedDestroyPlanSet:
    """Reopen the two sealed exact-delete plan receipts after a restart."""
    try:
        if (len(saved.events) != 2
                or saved.events[1].message
                   != "both published mixed destroy plans sealed"):
            raise ValueError("saved published mixed plan event absent")
        event = saved.events[1].data
        raw = event["planSet"]
        if (type(event) is not dict or set(event) != {"planSet", "planSetSha256"}
                or type(raw) is not dict
                or set(raw) != set(PublishedMixedDestroyPlanSet.__dataclass_fields__)
                or type(raw["plans"]) is not list or len(raw["plans"]) != 2):
            raise ValueError("saved published mixed plan shape differs")
        plans = tuple(PublishedMixedDestroyPlan(
            **{**item, "resource_ids": tuple(tuple(row)
                                               for row in item["resource_ids"])})
            for item in raw["plans"])
        result = PublishedMixedDestroyPlanSet(
            raw["published_parent_journal_sha256"],
            tuple(raw["ordered_providers"]), plans, raw["plan_set_sha256"])
        if (json.loads(json.dumps(asdict(result))) != raw
                or event["planSetSha256"] != result.plan_set_sha256
                or saved.input.get("planSetSha256") != result.plan_set_sha256):
            raise ValueError("saved published mixed plan digest differs")
        return result
    except Exception:
        raise ValueError("saved published mixed plans require exact checkpoint") from None


def recognize_published_mixed_plans_sealed(
    saved: StoredJobRun, review: PublishedMixedInitialTeardownReview,
    plans: PublishedMixedDestroyPlanSet, core_inspector_scope: dict,
    engagement_name: str,
) -> StoredJobRun:
    """Require both exact saved plans in one journal event before any GO."""
    baseline = propose_published_mixed_initial_cleanup(
        review, core_inspector_scope, engagement_name,
        requested_by=saved.requested_by, _historical=True)
    order = review.source.ordered_providers
    if (type(plans) is not PublishedMixedDestroyPlanSet
            or plans.ordered_providers != order
            or plans.published_parent_journal_sha256
               != review.published_parent_journal_sha256
            or tuple(plan.provider for plan in plans.plans) != order
            or plans.plan_set_sha256 != _fingerprint({
                "publishedParentJournalSha256": plans.published_parent_journal_sha256,
                "orderedProviders": order,
                "plans": [asdict(plan) for plan in plans.plans],
            })
            or any(plan.scope_sha256 != _fingerprint(scope)
                   for plan, scope in zip(plans.plans, review.provider_scopes, strict=True))):
        raise ValueError("published mixed two-plan seal differs")
    for plan, scope in zip(plans.plans, review.provider_scopes, strict=True):
        if (plan.before_state_sha256 != scope["stateSha256"]
                or plan.state_lineage != scope["lineage"]
                or plan.state_serial != scope["serial"]
                or plan.resource_ids != tuple(sorted(
                    (row["address"], row["id"]) for row in scope["resources"]))
                or Path(plan.plan_path).parent != Path(scope["workspace"])
                or not plan.terraform_path or not plan.terraform_sha256):
            raise ValueError("published mixed two-plan retained identity differs")
    expected_input = {**baseline.input, "phase": "plans_sealed",
                      "planSetSha256": plans.plan_set_sha256}
    expected_events = [*baseline.events, JobEvent(
        2, "info", "both published mixed destroy plans sealed",
        {"planSet": json.loads(json.dumps(asdict(plans))),
         "planSetSha256": plans.plan_set_sha256})]
    if (saved.id != baseline.id or saved.action != ACTION or saved.status != "queued"
            or saved.target != baseline.target or saved.target_type != baseline.target_type
            or saved.target_id != baseline.target_id
            or saved.requested_by != baseline.requested_by
            or saved.input != expected_input or saved.events != expected_events
            or saved.artifact_refs != [] or saved.started_at is not None
            or saved.finished_at is not None):
        raise ValueError("published mixed two-plan checkpoint differs")
    return saved


def propose_published_mixed_plans_sealed(
    queued: StoredJobRun, review: PublishedMixedInitialTeardownReview,
    plans: PublishedMixedDestroyPlanSet, core_inspector_scope: dict,
    engagement_name: str,
) -> StoredJobRun:
    """Construct the exact seal for a later CAS writer; do not save it here."""
    recognize_published_mixed_initial_checkpoint(
        queued, review, core_inspector_scope, engagement_name)
    sealed = replace(
        queued,
        input={**queued.input, "phase": "plans_sealed",
               "planSetSha256": plans.plan_set_sha256},
        events=[*queued.events, JobEvent(
            2, "info", "both published mixed destroy plans sealed",
            {"planSet": json.loads(json.dumps(asdict(plans))),
             "planSetSha256": plans.plan_set_sha256})],
    )
    return recognize_published_mixed_plans_sealed(
        sealed, review, plans, core_inspector_scope, engagement_name)
