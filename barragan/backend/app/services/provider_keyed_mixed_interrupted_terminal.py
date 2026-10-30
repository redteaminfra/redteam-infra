# Copyright (c) 2026, Oracle and/or its affiliates.
"""Atomically finish an attested interrupted mixed engagement teardown.

This module reads saved journals and local ownership only. Provider DELETE and
Terraform Apply have already finished in their one-shot children.
"""

from __future__ import annotations

from dataclasses import asdict, fields, replace
from datetime import datetime, timezone
from pathlib import Path

from app.domain import JobEvent
from app.services.engagement_lifecycle import (
    _fingerprint as lifecycle_fingerprint, _job_after, resolve_engagement_lifecycle,
)
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id as original_apply_id, recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_initial_plan_parent import _parent_id as initial_id
from app.services.provider_keyed_mixed_interrupted_cleanup import (
    ACTION, _parent_id, recognize_mixed_interrupted_sealed_plans,
)
from app.services.provider_keyed_mixed_interrupted_destroy_child import (
    _child_id as destroy_id, recognize_mixed_interrupted_destroy_child,
)
from app.services.provider_keyed_mixed_interrupted_destroy_plan import _scope_sha
from app.services.provider_keyed_mixed_interrupted_dispatch import _saved_plans, _saved_review
from app.services.provider_keyed_mixed_interrupted_post_sketch_absence import (
    MixedInterruptedPostSketchAbsence, MixedInterruptedProviderAbsenceReceipt, _bound,
)
from app.services.provider_keyed_mixed_interrupted_oci_tail import InterruptedHistoricalOciSource
from app.services.provider_keyed_mixed_interrupted_source import (
    _base as original_base, _failed_result, _precommand, _tag_only,
)
from app.services.provider_keyed_mixed_interrupted_selector_retirement import (
    ACTION as SELECTOR_ACTION, _child_id as selector_id,
)
from app.services.provider_keyed_mixed_zero_apply_core_absence import (
    ACTION as OCI_ABSENCE_ACTION, _authority, _authority_digest,
    _child_prefix as oci_absence_prefix, prove_mixed_zero_apply_oci_core_absence,
)
from app.services.provider_keyed_mixed_zero_apply_core_apply import _child_id as oci_apply_id
from app.services.provider_keyed_mixed_zero_apply_core_preview import _child_id as oci_preview_id
from app.services.provider_keyed_mixed_zero_apply_inspector_negative import (
    ACTION as NEGATIVE_ACTION, _child_id as negative_id, latest_negative_attempt,
    _targets as core_targets,
)
from app.services.provider_keyed_mixed_zero_apply_inspector_retirement import (
    ACTION as RETIRE_ACTION, _child_id as retirement_id,
    _messages as retirement_messages, retire_mixed_zero_apply_inspector,
)
from app.services.provider_keyed_mixed_zero_apply_terminal import (
    _residue, _retired_inspector_record_matches,
)
from app.services.provider_keyed_mixed_zero_apply_teardown_source import (
    canonical_mixed_core_apply_events,
)
from app.services.provider_keyed_inspector_negative import _classified_results
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


_PHASE = "lifecycle_reconciliation"
_FENCE = "provider_keyed_teardown_fence"
_HASH_CHARS = set("0123456789abcdef")


class MixedInterruptedTerminalAttention(ValueError):
    """Saved terminal authority or its local transaction is uncertain."""


def _historical_parent(parent: StoredJobRun) -> StoredJobRun:
    data = dict(parent.input)
    data.pop("remainingOwnedResources", None)
    data["phase"] = "plans_sealed"
    return replace(parent, status="queued", started_at=None, finished_at=None,
                   input=data, events=parent.events[:2])


def _provider_history(initial, parent, review, plan_set, jobs) -> tuple[str, str]:
    """Verify both exact child journals without current provider observations."""
    digests = []
    seal = initial.events[5].data
    for index, (provider, scope, plan) in enumerate(zip(
            review.ordered_providers, review.scopes, plan_set.plans, strict=True)):
        original = jobs.get(original_apply_id(review.core_job_id, provider))
        digest = job_event_digest(original.events) if original is not None else None
        if digest != scope.child_journal_sha256:
            raise ValueError("original provider journal changed")
        if scope.kind == "unstarted":
            if original is not None and not _precommand(
                    original, original_base(initial, seal, provider, index)):
                raise ValueError("unstarted provider has an Apply")
        elif scope.kind == "tag_only":
            if not _tag_only(initial, original, provider, seal):
                raise ValueError("tag-only selector source changed")
        elif scope.kind in {"failed_absent", "partial"}:
            if _failed_result(initial, original, provider) is None:
                raise ValueError("failed provider result changed")
        elif scope.kind == "full":
            proof = recognize_mixed_initial_apply_terminal(original, initial, provider)["proof"]
            if (proof["stateSha256"] != scope.state_sha256
                    or proof["lineage"] != scope.lineage
                    or proof["serial"] != scope.serial
                    or tuple(sorted(proof["resourceIds"].items())) != scope.resource_ids):
                raise ValueError("full provider proof changed")
        else:
            raise ValueError("mixed provider scope differs")
        destroy = jobs.get(destroy_id(review.core_job_id, provider))
        if scope.kind in {"partial", "full"}:
            if (destroy is None or plan.plan_path is None
                    or recognize_mixed_interrupted_destroy_child(
                        destroy, initial, parent, review, plan_set,
                        _bound(destroy)) != "awaiting_absence"):
                raise ValueError("provider destroy result differs")
        elif destroy is not None or plan.plan_path is not None:
            raise ValueError("no-plan provider has a destroy child")
        digests.append(job_event_digest(destroy.events) if destroy is not None else "none")
    return tuple(digests)


def _saved_sketch_absence(parent, review, plan_set, applied, provider_digests):
    """Bind GO's saved two-provider absence to exact reviewed ownership."""
    go_support = canonical_mixed_core_apply_events(applied)[8].data
    raw = go_support.get("postSketchAbsence")
    keys = {field.name for field in fields(MixedInterruptedPostSketchAbsence)}
    receipt_keys = {field.name for field in fields(MixedInterruptedProviderAbsenceReceipt)}
    if (type(raw) is not dict or set(raw) != keys
            or raw["cleanup_parent_id"] != parent.id
            or raw["cleanup_journal_sha256"] != job_event_digest(parent.events[:2])
            or raw["review_sha256"] != review.review_sha256
            or raw["plan_set_sha256"] != plan_set.plan_set_sha256
            or raw["ordered_providers"] != list(review.ordered_providers)
            or type(raw["receipts"]) is not list or len(raw["receipts"]) != 2
            or raw["checkpoint_sha256"] != go_support.get("providerObservationSha256")):
        raise ValueError("saved two-provider absence checkpoint differs")
    for index, (saved, scope, plan, digest) in enumerate(zip(
            raw["receipts"], review.scopes, plan_set.plans, provider_digests, strict=True)):
        if type(saved) is not dict or set(saved) != receipt_keys:
            raise ValueError("saved provider absence receipt differs")
        ids = sorted({identifier for _, identifier in scope.resource_ids})
        state_backed = scope.kind in {"partial", "full"}
        expected_child = destroy_id(review.core_job_id, scope.provider) if state_backed else None
        if (saved["provider"] != review.ordered_providers[index]
                or saved["provider"] != scope.provider
                or saved["scope_kind"] != scope.kind
                or saved["scope_sha256"] != _scope_sha(scope)
                or saved["plan_set_sha256"] != plan_set.plan_set_sha256
                or saved["original_apply_journal_sha256"] != scope.child_journal_sha256
                or saved["destroy_child_id"] != expected_child
                or saved["destroy_child_journal_sha256"] != (
                    digest if state_backed else None)
                or saved["before_state_sha256"] != scope.state_sha256
                or saved["lineage"] != scope.lineage
                or saved["before_serial"] != scope.serial
                or saved["verified_absent_ids"] != ids
                or saved["selector_retirement_pending"]
                is not scope.selector_retirement_pending
                or any(type(saved[key]) is not str or len(saved[key]) != 64
                       or set(saved[key]) - _HASH_CHARS
                       for key in ("inventory_sha256", "observation_sha256"))):
            raise ValueError("saved provider absence ownership differs")
        if state_backed:
            if (type(saved["after_state_sha256"]) is not str
                    or len(saved["after_state_sha256"]) != 64
                    or set(saved["after_state_sha256"]) - _HASH_CHARS
                    or type(saved["after_serial"]) is not int
                    or saved["after_serial"] <= scope.serial):
                raise ValueError("saved provider poststate differs")
        elif saved["after_state_sha256"] is not None or saved["after_serial"] is not None:
            raise ValueError("no-plan provider has poststate")
    payload = {"cleanupParentId": raw["cleanup_parent_id"],
               "cleanupJournalSha256": raw["cleanup_journal_sha256"],
               "reviewSha256": raw["review_sha256"],
               "planSetSha256": raw["plan_set_sha256"],
               "orderedProviders": raw["ordered_providers"],
               "receipts": raw["receipts"]}
    if _fingerprint(payload) != raw["checkpoint_sha256"]:
        raise ValueError("saved provider absence digest differs")
    return raw["checkpoint_sha256"]


def _selector_terminal(selector, initial, parent, review, plan_set, absent, negative):
    scope = next(row for row in review.scopes if row.provider == "digitalocean")
    if not scope.selector_retirement_pending:
        if selector is not None:
            raise ValueError("unexpected selector retirement")
        return None
    policy = initial.events[5].data["reviewedPolicy"]["digitalocean"]
    expected = {
        "schema": "mixed-interrupted-selector-retirement-v1",
        "engagementId": parent.target_id, "coreJobId": review.core_job_id,
        "corePlanId": parent.input["corePlanId"], "teardownParentId": parent.id,
        "reviewSha256": review.review_sha256,
        "planSetSha256": plan_set.plan_set_sha256,
        "doScopeSha256": _scope_sha(scope), "selectorTag": scope.selector_tag,
        "providerConnectionId": policy["provider_connection_id"],
        "credentialSecretSha256": policy["credential_secret_sha256"],
        "credentialUpdatedAt": policy["credential_updated_at"],
        "ociAbsenceJobId": absent.id,
        "ociAbsenceJournalSha256": job_event_digest(absent.events),
        "inspectorNegativeJobId": negative.id,
        "inspectorNegativeJournalSha256": job_event_digest(negative.events),
        "mutation": True,
    }
    intent = {"selectorTag": scope.selector_tag,
              "doScopeSha256": expected["doScopeSha256"],
              "ociAbsenceJournalSha256": expected["ociAbsenceJournalSha256"],
              "inspectorNegativeJournalSha256": expected["inspectorNegativeJournalSha256"]}
    terminal = [
        JobEvent(4, "info", "mixed interrupted selector DELETE 204 received",
                 {"selectorTag": scope.selector_tag, "httpStatus": 204}),
        JobEvent(4, "info", "mixed interrupted selector absence reconciled",
                 {"selectorTag": scope.selector_tag, "exactGetStatus": 404,
                  "completeTagListAbsent": True}),
    ]
    if (selector is None or selector.id != selector_id(review.core_job_id)
            or selector.action != SELECTOR_ACTION or selector.status != "succeeded"
            or selector.target != parent.target or selector.target_type != "engagement"
            or selector.target_id != parent.target_id
            or selector.requested_by != parent.requested_by
            or selector.input != expected or selector.artifact_refs != []
            or selector.started_at is None or selector.finished_at is None
            or selector.events[:3] != [
                JobEvent(1, "info", "mixed interrupted selector retirement queued", {}),
                JobEvent(2, "info", "mixed interrupted selector retirement started", {}),
                JobEvent(3, "info", "mixed interrupted selector DELETE intended", intent)]
            or len(selector.events) != 4 or selector.events[3] not in terminal):
        raise ValueError("exact selector terminal receipt differs")
    return selector


def _saved_public_receipts(parent, core, plan, preview, applied, absent, negative):
    """Authenticate immutable OCI/negative journals after the fence is released."""
    review_sha = parent.input["sourceSha256"]
    source_sha = _fingerprint(parent.input["source"])
    if (absent.action != OCI_ABSENCE_ACTION or absent.status != "succeeded"
            or absent.target != parent.target or absent.target_type != "engagement"
            or absent.target_id != parent.target_id
            or absent.requested_by != parent.requested_by
            or absent.started_at is None or absent.finished_at is None
            or absent.artifact_refs != []
            or absent.input.get("teardownParentId") != parent.id
            or absent.input.get("coreJobId") != core.id
            or absent.input.get("corePlanId") != plan.id
            or absent.input.get("sourceSha256") != source_sha
            or absent.input.get("previewJobId") != preview.id
            or absent.input.get("previewJournalSha256") != job_event_digest(preview.events)
            or absent.input.get("applyJobId") != applied.id
            or absent.input.get("applyJournalSha256") != job_event_digest(applied.events)
            or len(absent.events) != 3
            or absent.events[:2] != [
                JobEvent(1, "info", "mixed core absence queued", {}),
                JobEvent(2, "info", "mixed core absence started", {})]):
        raise ValueError("historical OCI absence differs")
    receipt = absent.events[2]
    if (receipt.sequence != 3 or receipt.level != "info"
            or receipt.message != "mixed core exact absence proved"
            or type(receipt.data) is not dict
            or set(receipt.data) != {"emptyStateSha256", "preDestroyResourceIdsSha256",
                                     "ociAbsenceWitness"}
            or receipt.data["emptyStateSha256"] != absent.input.get("emptyStateSha256")
            or receipt.data["preDestroyResourceIdsSha256"] != absent.input.get(
                "preDestroyResourceIdsSha256")
            or type(receipt.data["ociAbsenceWitness"]) is not dict
            or receipt.data["ociAbsenceWitness"].get("phase") != "absent"):
        raise ValueError("historical OCI witness differs")
    targets = core_targets(core, plan.evidence["proxyCount"])
    control = negative.input.get("positiveControl")
    neg_receipt = negative.events[2] if len(negative.events) == 3 else None
    classifications = ([_classified_results(row, targets, control)
                        for row in neg_receipt.data.get("rounds", [])]
                       if neg_receipt is not None and type(neg_receipt.data) is dict
                       and type(control) is dict else [])
    if (negative.action != NEGATIVE_ACTION or negative.status != "succeeded"
            or negative.target != parent.target or negative.target_type != "engagement"
            or negative.target_id != parent.target_id
            or negative.requested_by != parent.requested_by
            or negative.started_at is None or negative.finished_at is None
            or negative.artifact_refs != []
            or negative.input.get("teardownParentId") != parent.id
            or negative.input.get("coreJobId") != core.id
            or negative.input.get("corePlanId") != plan.id
            or negative.input.get("sourceSha256") != review_sha
            or negative.input.get("ociAbsenceJobId") != absent.id
            or negative.input.get("ociAbsenceJournalSha256") != job_event_digest(absent.events)
            or negative.events[:2] != [
                JobEvent(1, "info", "mixed Inspector negative queued", {}),
                JobEvent(2, "info", "mixed Inspector negative started", {})]
            or neg_receipt is None or neg_receipt.sequence != 3
            or neg_receipt.level != "info"
            or neg_receipt.message != "mixed Inspector exact public negative proved"
            or len(classifications) != 2 or any(row is None for row in classifications)
            or neg_receipt.data.get("classifications") != classifications
            or neg_receipt.data.get("targetSha256") != _fingerprint(targets)):
        raise ValueError("historical public negative differs")


def _receipts(engagement_id, core_job_id, *, state_root, core_state_root,
              jobs, plans, resources, settings, lookup, identity_reader=None):
    historical = _authority(engagement_id, core_job_id, jobs, plans, lookup,
                            interrupted=True)
    parent, core, initial, preview, applied, plan, source, *_ = historical
    review, plan_set = _saved_review(parent), _saved_plans(parent)
    recognize_mixed_interrupted_sealed_plans(parent, initial, review, plan_set)
    provider_digests = _provider_history(initial, parent, review, plan_set, jobs)
    _saved_sketch_absence(parent, review, plan_set, applied, provider_digests)
    attempts = [row for row in jobs.list_for_engagement(engagement_id)
                if row.action == OCI_ABSENCE_ACTION and row.id.startswith(
                    oci_absence_prefix(core_job_id) + "-attempt-")
                and row.status == "succeeded"]
    if len(attempts) != 1:
        raise ValueError("exact OCI absence job missing")
    absent = prove_mixed_zero_apply_oci_core_absence(
        engagement_id, core_job_id, environment="devtest", state_root=state_root,
        core_state_root=core_state_root, job_repository=jobs,
        plan_repository=plans, lease_lookup=lookup,
        identity_reader=identity_reader, interrupted=True)
    if absent != attempts[0]:
        raise ValueError("OCI absence receipt changed")
    negative = latest_negative_attempt(jobs, engagement_id, core_job_id)
    retirement = jobs.get(retirement_id(core_job_id))
    if (negative is None or negative.action != NEGATIVE_ACTION
            or negative.status != "succeeded" or retirement is None
            or retirement.action != RETIRE_ACTION or retirement.status != "succeeded"
            or retirement.input.get("negativeJobId") != negative.id
            or retirement.input.get("negativeJournalSha256") != job_event_digest(negative.events)
            or retirement.input.get("historicalAuthoritySha256")
            != _authority_digest(historical)
            or retirement_messages(retirement, retirement.input["hostId"],
                                   retirement.input["firewallId"])[-1]
            != "mixed Inspector local retirement committed"):
        raise ValueError("Inspector terminal receipts differ")
    _saved_public_receipts(parent, core, plan, preview, applied, absent, negative)
    selector = _selector_terminal(jobs.get(selector_id(core_job_id)), initial, parent,
                                  review, plan_set, absent, negative)
    selected = [row for row in resources.list_for_engagement(engagement_id)
                if row.id in source.owned_inspector_record_ids]
    if len(selected) != 2 or settings.get(engagement_id).current_host != {}:
        raise ValueError("retired Inspector local ownership differs")
    if any(not _retired_inspector_record_matches(row, retirement) for row in selected):
        raise ValueError("retired Inspector record differs")
    return (historical, review, plan_set, provider_digests, absent,
            negative, selector, retirement)


def _terminal_event(parent, provider_digests, applied, absent, negative, selector, retirement):
    go_support = canonical_mixed_core_apply_events(applied)[8].data
    return JobEvent(3, "info", "mixed interrupted teardown complete", {
        "state": "destroyed", "finalCleanupStatus": "verified_clean",
        "reviewSha256": parent.input["sourceSha256"],
        "planSetSha256": parent.events[1].data["planSetSha256"],
        "providerDestroyJournalSha256": list(provider_digests),
        "postSketchAbsenceSha256": go_support["providerObservationSha256"],
        "ociAbsenceJobId": absent.id,
        "ociAbsenceJournalSha256": job_event_digest(absent.events),
        "inspectorNegativeJobId": negative.id,
        "inspectorNegativeJournalSha256": job_event_digest(negative.events),
        "selectorRetirementJobId": selector.id if selector else None,
        "selectorRetirementJournalSha256": job_event_digest(selector.events) if selector else None,
        "inspectorRetirementJobId": retirement.id,
        "inspectorRetirementJournalSha256": job_event_digest(retirement.events),
    })


def recognize_mixed_interrupted_terminal(
    engagement_id: str, core_job_id: str, *, environment: str,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, sketch_repository=None, lease_lookup=None,
) -> StoredJobRun:
    """Authenticate immutable terminal history after the teardown lease is gone."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    settings = settings_repository or SqlAlchemyObserverSettingsRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        if environment != "devtest":
            raise ValueError("private DevTest terminal differs")
        parent = jobs.get(_parent_id(core_job_id))
        core = jobs.get(core_job_id)
        initial = jobs.get(initial_id(core_job_id))
        preview = jobs.get(oci_preview_id(core_job_id))
        applied = jobs.get(oci_apply_id(core_job_id))
        retirement = jobs.get(retirement_id(core_job_id))
        if any(row is None for row in (parent, core, initial, preview, applied, retirement)):
            raise ValueError("mixed terminal jobs missing")
        plan = plans.get(parent.input.get("corePlanId"))
        if plan is None:
            raise ValueError("mixed terminal plan missing")
        original = _historical_parent(parent)
        review, plan_set = _saved_review(original), _saved_plans(original)
        recognize_mixed_interrupted_sealed_plans(original, initial, review, plan_set)
        record_ids = preview.input.get("inspectorRecordIds")
        source_hashes = [preview.input.get(key) for key in ("stateSha256", "inventorySha256")]
        if (type(record_ids) is not list or len(record_ids) != 2
                or any(type(value) is not str or not value for value in record_ids)
                or len(set(record_ids)) != 2
                or any(type(value) is not str or len(value) != 64
                       or set(value) - _HASH_CHARS for value in source_hashes)):
            raise ValueError("historical interrupted source differs")
        source = InterruptedHistoricalOciSource(*source_hashes, tuple(record_ids))
        authority_sha = _authority_digest(
            (original, core, initial, preview, applied, plan, source))
        provider_digests = _provider_history(initial, original, review, plan_set, jobs)
        _saved_sketch_absence(original, review, plan_set, applied, provider_digests)
        negative = latest_negative_attempt(jobs, engagement_id, core_job_id)
        selector = jobs.get(selector_id(core_job_id))
        # Inspector retirement saves the negative and OCI Apply lineage;
        # negative saves the exact OCI absence child.
        if negative is None:
            raise ValueError("historical negative missing")
        absent = jobs.get(negative.input.get("ociAbsenceJobId"))
        absence_attempts = [row for row in jobs.list_for_engagement(engagement_id)
                            if row.action == OCI_ABSENCE_ACTION
                            and row.id.startswith(oci_absence_prefix(core_job_id) + "-attempt-")
                            and row.status == "succeeded"]
        if (absent is None or absent.action != OCI_ABSENCE_ACTION
                or absent.status != "succeeded"
                or absence_attempts != [absent]
                or negative.action != NEGATIVE_ACTION or negative.status != "succeeded"
                or negative.input.get("teardownParentId") != original.id
                or negative.input.get("ociAbsenceJournalSha256")
                != job_event_digest(absent.events)
                or retirement.action != RETIRE_ACTION or retirement.status != "succeeded"
                or retirement.input.get("historicalAuthoritySha256") != authority_sha
                or retirement.input.get("negativeJobId") != negative.id
                or retirement.input.get("negativeJournalSha256")
                != job_event_digest(negative.events)
                or retirement_messages(retirement, retirement.input["hostId"],
                                       retirement.input["firewallId"])[-1]
                != "mixed Inspector local retirement committed"):
            raise ValueError("historical Inspector or OCI receipt differs")
        _saved_public_receipts(original, core, plan, preview, applied, absent, negative)
        _selector_terminal(selector, initial, original, review, plan_set,
                           absent, negative)
        if (parent.action != ACTION or parent.status != "succeeded"
                or parent.target != f"engagement:{engagement_id}"
                or parent.target_type != "engagement" or parent.target_id != engagement_id
                or parent.started_at is None or parent.finished_at is None
                or parent.artifact_refs != [] or len(parent.events) != 3
                or parent.input != {**original.input, "phase": _PHASE,
                                    "remainingOwnedResources": []}
                or parent.events[2] != _terminal_event(
                    original, provider_digests, applied, absent, negative, selector, retirement)):
            raise ValueError("mixed terminal parent differs")
        from app.storage.database import db
        from app.storage.models import EngagementLifecycleEventModel, EngagementLifecycleModel
        newer = [row for row in jobs.list_for_engagement(engagement_id)
                 if row.action == "pilot_standard_rti_guarded_execute"
                 and _job_after(row.created_at, parent.finished_at)]
        lease = lookup(engagement_id)
        if newer:
            latest = max(newer, key=lambda row: (row.created_at, row.id))
            latest_plan = plans.get(latest.input.get("corePlanId"))
            if (latest_plan is None or latest_plan.engagement_id != engagement_id
                    or latest_plan.apply_job_id not in {None, latest.id}
                    or (lease is not None and lease[0] != latest_plan.id)):
                raise ValueError("newer core lease differs")
        elif lease is not None:
            raise ValueError("mixed terminal fence remains")
        selected = [row for row in resources.list_for_engagement(engagement_id)
                    if row.id in record_ids]
        if len(selected) != 2:
            raise ValueError("historical Inspector pair missing")
        if any(not _retired_inspector_record_matches(row, retirement) for row in selected):
            raise ValueError("historical Inspector record differs")
        if not newer:
            _residue(engagement_id, resources, chains, initial.input["chainIds"])
            saved_settings = settings.get(engagement_id)
            if saved_settings is None or saved_settings.current_host != {}:
                raise ValueError("Inspector current host remains")
        lifecycle = db.session.query(EngagementLifecycleModel).filter_by(
            engagement_id=engagement_id).one_or_none()
        events = db.session.query(EngagementLifecycleEventModel).filter_by(
            engagement_id=engagement_id,
            reason=f"mixed_interrupted_teardown_verified:{parent.id}").all()
        resolution = resolve_engagement_lifecycle(
            engagement_id, previous_state=lifecycle.state if lifecycle else None,
            job_repository=jobs, provider_resource_repository=resources,
            sketch_chain_repository=chains)
        fingerprint = lifecycle_fingerprint(resolution.evidence)
        if (len(events) != 1 or events[0].state != "destroyed"
                or events[0].evidence_fingerprint != lifecycle_fingerprint(events[0].evidence)
                or not any(row.get("kind") == "engagement_teardown_job"
                           and row.get("id") == parent.id and row.get("status") == "succeeded"
                           for row in events[0].evidence)
                or (not newer and (lifecycle is None or lifecycle.state != "destroyed"
                                   or resolution.state != "destroyed"
                                   or lifecycle.evidence_fingerprint != fingerprint
                                   or lifecycle.evidence != resolution.evidence
                                   or events[0].evidence_fingerprint != fingerprint
                                   or events[0].evidence != resolution.evidence))):
            raise ValueError("mixed terminal lifecycle differs")
        return parent
    except Exception:
        raise MixedInterruptedTerminalAttention(
            "mixed interrupted terminal history requires exact reconciliation") from None


def finish_mixed_interrupted_terminal(
    engagement_id: str, core_job_id: str, *, environment: str,
    state_root: Path, core_state_root: Path, job_repository=None,
    plan_repository=None, settings_repository=None,
    provider_resource_repository=None, sketch_repository=None, lease_lookup=None,
    identity_reader=None,
) -> StoredJobRun:
    """Commit parent, lifecycle event, and exact teardown fence in one writer slot."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    settings = settings_repository or SqlAlchemyObserverSettingsRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    existing = jobs.get(_parent_id(core_job_id))
    if existing is not None and existing.status == "succeeded":
        return recognize_mixed_interrupted_terminal(
            engagement_id, core_job_id, environment=environment,
            job_repository=jobs, plan_repository=plans, settings_repository=settings,
            provider_resource_repository=resources, sketch_repository=chains,
            lease_lookup=lookup)
    try:
        if environment != "devtest":
            raise ValueError("private DevTest terminal differs")
        receipt_args = dict(state_root=state_root, core_state_root=core_state_root,
                            jobs=jobs, plans=plans, resources=resources, settings=settings,
                            lookup=lookup, identity_reader=identity_reader)
        receipts = _receipts(engagement_id, core_job_id, **receipt_args)
        historical, review, plan_set, provider_digests, absent, negative, selector, saved = receipts
        parent, core, initial, _, applied, plan, *_ = historical
        authority_sha = _authority_digest(historical)
        retirement = retire_mixed_zero_apply_inspector(
            engagement_id, core_job_id, environment=environment,
            state_root=state_root, core_state_root=core_state_root,
            job_repository=jobs, plan_repository=plans,
            settings_repository=settings, provider_resource_repository=resources,
            lease_lookup=lookup, identity_reader=identity_reader, interrupted=True)
        if retirement != saved:
            raise ValueError("Inspector retirement history changed")
        from sqlalchemy import delete, update
        from app.storage.database import db
        from app.storage.models import (
            CoreMutationLeaseModel, EngagementLifecycleEventModel,
            EngagementLifecycleModel, JobEventModel, JobRunModel,
        )
        if db.session.get_bind().dialect.name != "sqlite":
            raise ValueError("reviewed SQLite writer required")
        stamp = datetime.now(timezone.utc)
        staged = {**parent.input, "phase": _PHASE, "remainingOwnedResources": []}
        db.session.rollback()
        locked = db.session.execute(update(JobRunModel).where(
            JobRunModel.id == parent.id, JobRunModel.action == ACTION,
            JobRunModel.status == "queued", JobRunModel.started_at.is_(None),
            JobRunModel.finished_at.is_(None), JobRunModel.input == parent.input,
            JobRunModel.target_id == engagement_id,
            JobRunModel.requested_by == parent.requested_by,
        ).values(status="queued"))
        db.session.expire_all()
        if (locked.rowcount != 1
                or _authority_digest(_authority(
                    engagement_id, core_job_id, jobs, plans, lookup,
                    interrupted=True)) != authority_sha
                or jobs.get(saved.id) != saved
                or jobs.get(absent.id) != absent or jobs.get(negative.id) != negative
                or (selector is not None and jobs.get(selector.id) != selector)
                or _provider_history(initial, parent, review, plan_set, jobs)
                != provider_digests):
            raise ValueError("terminal writer authority changed")
        _residue(engagement_id, resources, chains, initial.input["chainIds"])
        saved_settings = settings.get(engagement_id)
        if saved_settings is None or saved_settings.current_host != {}:
            raise ValueError("Inspector settings still claim a host")
        lease = db.session.query(CoreMutationLeaseModel).filter_by(
            engagement_id=engagement_id).one_or_none()
        if lease is None or lease.owner_id != plan.id or lease.operation != _FENCE:
            raise ValueError("mixed terminal fence differs")
        prior = db.session.query(EngagementLifecycleModel).filter_by(
            engagement_id=engagement_id).one_or_none()
        previous_state = prior.state if prior else "not_deployed"
        changed = db.session.execute(update(JobRunModel).where(
            JobRunModel.id == parent.id, JobRunModel.action == ACTION,
            JobRunModel.status == "queued", JobRunModel.input == parent.input,
            JobRunModel.started_at.is_(None), JobRunModel.finished_at.is_(None),
        ).values(status="succeeded", started_at=stamp, finished_at=stamp,
                 input=staged))
        if changed.rowcount != 1:
            raise ValueError("mixed terminal parent changed")
        terminal = _terminal_event(parent, provider_digests, applied, absent, negative,
                                   selector, retirement)
        db.session.add(JobEventModel(job_id=parent.id, sequence=3, level="info",
                                     message=terminal.message, data=terminal.data,
                                     created_at=stamp))
        db.session.flush()
        resolution = resolve_engagement_lifecycle(
            engagement_id, previous_state=previous_state,
            job_repository=jobs, provider_resource_repository=resources,
            sketch_chain_repository=chains)
        if resolution.state != "destroyed":
            raise ValueError("mixed terminal lifecycle did not resolve destroyed")
        fingerprint = lifecycle_fingerprint(resolution.evidence)
        if prior is None:
            prior = EngagementLifecycleModel(engagement_id=engagement_id)
            db.session.add(prior)
        prior.state = "destroyed"
        prior.evidence_fingerprint = fingerprint
        prior.evidence = resolution.evidence
        prior.reconciled_at = stamp
        db.session.add(EngagementLifecycleEventModel(
            engagement_id=engagement_id, previous_state=previous_state,
            state="destroyed", evidence_fingerprint=fingerprint,
            evidence=resolution.evidence,
            reason=f"mixed_interrupted_teardown_verified:{parent.id}",
            created_at=stamp))
        released = db.session.execute(delete(CoreMutationLeaseModel).where(
            CoreMutationLeaseModel.engagement_id == engagement_id,
            CoreMutationLeaseModel.owner_id == plan.id,
            CoreMutationLeaseModel.operation == _FENCE))
        if released.rowcount != 1:
            raise ValueError("mixed terminal fence release changed")
        db.session.commit()
    except Exception:
        from app.storage.database import db
        db.session.rollback()
        raise MixedInterruptedTerminalAttention(
            "mixed interrupted terminal requires exact local reconciliation") from None
    return recognize_mixed_interrupted_terminal(
        engagement_id, core_job_id, environment=environment,
        job_repository=jobs, plan_repository=plans, settings_repository=settings,
        provider_resource_repository=resources, sketch_repository=chains,
        lease_lookup=lookup)
