# Copyright (c) 2026, Oracle and/or its affiliates.
"""Local terminal reconciliation after published mixed teardown receipts.

No Terraform, provider DELETE, or network probe is issued here. The saved
provider/OCI/Inspector journals are reopened before a single SQLite writer
transaction marks only reviewed Barragan-owned rows destroyed.
"""

from __future__ import annotations

from app.services.provider_keyed_runtime_preflight import reviewed_mixed_chain_rows

from dataclasses import asdict
from datetime import datetime, timezone

from app.domain import JobEvent
from app.services.engagement_lifecycle import (
    _fingerprint as lifecycle_fingerprint, resolve_engagement_lifecycle,
)
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_mixed_published_destroy_child import (
    child_id, recognize_published_mixed_destroy_child,
)
from app.services.provider_keyed_mixed_published_post_oci_source import (
    audit_published_mixed_post_oci_source,
)
from app.services.provider_keyed_mixed_published_selector_retirement import (
    ACTION as SELECTOR_ACTION, _child_id as selector_id,
)
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    ACTION, parent_id, recognize_published_mixed_plans_sealed,
    saved_published_mixed_destroy_plans, saved_published_mixed_initial_review,
)
from app.services.provider_keyed_mixed_zero_apply_core_absence import (
    ACTION as OCI_ABSENCE_ACTION, _authority, _authority_digest,
)
from app.services.provider_keyed_mixed_zero_apply_inspector_negative import (
    ACTION as NEGATIVE_ACTION, _targets as core_targets, latest_negative_attempt,
)
from app.services.provider_keyed_inspector_negative import _classified_results
from app.services.provider_keyed_mixed_zero_apply_inspector_retirement import (
    PUBLISHED_ACTION as RETIRE_ACTION, _messages as retirement_messages,
    _published_child_id as retirement_id,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import (
    SqlAlchemyProviderResourceRepository, TERMINAL_RECORD_STATUSES,
    is_barragan_owned_record,
)
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


_PHASE = "lifecycle_reconciliation"
_FENCE = "provider_keyed_teardown_fence"


class PublishedMixedTerminalAttention(ValueError):
    """Exact published terminal history or local reconciliation is unproved."""


def _saved_public_receipts(parent, core, plan, preview, applied, absent, negative):
    """Check exact saved OCI/public-negative journals without a provider call."""
    source_sha = parent.input["publishedSourceSha256"]
    if (absent.input.get("teardownParentId") != parent.id
            or absent.input.get("coreJobId") != core.id
            or absent.input.get("corePlanId") != plan.id
            or absent.input.get("sourceSha256") != source_sha
            or absent.input.get("previewJobId") != preview.id
            or absent.input.get("previewJournalSha256") != job_event_digest(preview.events)
            or absent.input.get("applyJobId") != applied.id
            or absent.input.get("applyJournalSha256") != job_event_digest(applied.events)
            or absent.events[:2] != [
                JobEvent(1, "info", "mixed core absence queued", {}),
                JobEvent(2, "info", "mixed core absence started", {})]
            or absent.events[2].message != "mixed core exact absence proved"
            or absent.events[2].level != "info"
            or absent.events[2].sequence != 3
            or absent.events[2].data.get("ociAbsenceWitness", {}).get("phase") != "absent"
            or negative.input.get("teardownParentId") != parent.id
            or negative.input.get("coreJobId") != core.id
            or negative.input.get("corePlanId") != plan.id
            or negative.input.get("sourceSha256") != source_sha
            or negative.input.get("ociAbsenceJobId") != absent.id
            or negative.input.get("ociAbsenceJournalSha256") != job_event_digest(absent.events)
            or negative.events[:2] != [
                JobEvent(1, "info", "mixed Inspector negative queued", {}),
                JobEvent(2, "info", "mixed Inspector negative started", {})]
            or negative.events[2].message != "mixed Inspector exact public negative proved"
            or negative.events[2].level != "info"
            or negative.events[2].sequence != 3):
        raise ValueError("published OCI or public-negative journal differs")
    targets = core_targets(core, plan.evidence["proxyCount"])
    from app.services.provider_keyed_mixed_public_targets import published_targets
    targets = published_targets(parent, targets)
    if parent.input.get("publicTargetSealSha256") is not None and (
            negative.input.get("publicTargetSealSha256") != parent.input["publicTargetSealSha256"]
            or negative.input.get("targetCount") != len(targets)
            or negative.input.get("targetSha256") != _fingerprint(targets)):
        raise ValueError("published public target seal differs")
    recovery = parent.input.get("failedAppendRecovery")
    if recovery is not None and recovery.get("kind") == "failed-second-v1" and (
            type(negative.input.get("targetCount")) is not int or negative.input["targetCount"] != len(targets)
            or negative.input.get("targetSha256") != _fingerprint(targets)):
        raise ValueError("failed second public-negative target seal differs")
    control = negative.input["positiveControl"]
    data = negative.events[2].data
    classified = [_classified_results(item, targets, control)
                  for item in data.get("rounds", [])]
    if (len(classified) != 2 or any(item is None for item in classified)
            or data.get("classifications") != classified
            or data.get("targetSha256") != _fingerprint(targets)):
        raise ValueError("published public-negative proof differs")


def _saved_selector(parent, review, sealed, selector, absent, negative, do_receipt):
    """Recognize the exact one-shot selector terminal, including event data."""
    tag = selector.input.get("selectorTag")
    if (selector.id != selector_id(review.source.core_job_id)
            or selector.action != SELECTOR_ACTION or selector.status != "succeeded"
            or selector.target != parent.target or selector.target_id != parent.target_id
            or selector.requested_by != parent.requested_by
            or selector.started_at is None or selector.finished_at is None
            or selector.artifact_refs != []
            or selector.input.get("reviewSha256") != parent.input["publishedSourceSha256"]
            or selector.input.get("planSetSha256") != sealed.plan_set_sha256
            or selector.input.get("doAbsenceReceiptSha256") != do_receipt
            or selector.input.get("ociAbsenceJobId") != absent.id
            or selector.input.get("ociAbsenceJournalSha256") != job_event_digest(absent.events)
            or selector.input.get("inspectorNegativeJobId") != negative.id
            or selector.input.get("inspectorNegativeJournalSha256") != job_event_digest(negative.events)
            or type(tag) is not str or not tag
            or selector.events[:2] != [
                JobEvent(1, "info", "mixed published selector retirement queued", {}),
                JobEvent(2, "info", "mixed published selector retirement started", {})]):
        raise ValueError("published selector authority differs")
    already = JobEvent(3, "info", "mixed published selector already absent",
                       {"selectorTag": tag, "exactGetStatus": 404})
    intended = JobEvent(3, "info", "mixed published selector DELETE intended", {
        "selectorTag": tag, "doAbsenceReceiptSha256": do_receipt,
        "ociAbsenceJournalSha256": job_event_digest(absent.events),
        "inspectorNegativeJournalSha256": job_event_digest(negative.events),
    })
    terminal = (
        JobEvent(4, "info", "mixed published selector DELETE 204 received",
                 {"selectorTag": tag, "httpStatus": 204}),
        JobEvent(4, "info", "mixed published selector absence reconciled",
                 {"selectorTag": tag, "exactGetStatus": 404}),
    )
    if selector.events not in ([*selector.events[:2], already],
                               [*selector.events[:2], intended, terminal[0]],
                               [*selector.events[:2], intended, terminal[1]]):
        raise ValueError("published selector terminal journal differs")


def _record_kind(provider: str, resource_type: str) -> str | None:
    """Map only known owned record types to reviewed Terraform kinds."""
    kinds = {
        "linode": {
            "instance": "instance", "linode_instance": "instance",
            "firewall": "firewall", "linode_firewall": "firewall",
        },
        "digitalocean": {
            "droplet": "droplet", "digitalocean_droplet": "droplet",
            "firewall": "firewall", "digitalocean_firewall": "firewall",
            "ssh_key": "ssh_key", "digitalocean_ssh_key": "ssh_key",
        },
    }
    return kinds.get(provider, {}).get(resource_type.lower().replace("-", "_"))


def _history(engagement_id, core_job_id, jobs, plans, settings, resources, chains, lookup):
    """Reopen persisted receipts; no external provider or host observation."""
    parent = jobs.get(parent_id(core_job_id))
    if (parent is None or parent.status != "queued" or parent.action != ACTION
            or parent.target_id != engagement_id or parent.started_at is not None
            or parent.finished_at is not None or parent.artifact_refs != []):
        raise ValueError("published teardown parent differs")
    review = saved_published_mixed_initial_review(parent)
    sealed = saved_published_mixed_destroy_plans(parent)
    scope, name = parent.input["reviewScope"], parent.input["engagementName"]
    recognize_published_mixed_plans_sealed(parent, review, sealed, scope, name)
    if lookup(engagement_id) != (review.source.core_plan_id, _FENCE):
        raise ValueError("published teardown fence differs")
    original = jobs.get(review.source.parent_job_id)
    core = jobs.get(core_job_id)
    plan = plans.get(review.source.core_plan_id)
    if original is None or core is None or plan is None:
        raise ValueError("published historical jobs differ")
    order = review.source.ordered_providers
    destroy = tuple(jobs.get(child_id(core_job_id, provider)) for provider in order)
    if any(child is None or child.status != "succeeded" for child in destroy):
        raise ValueError("published provider absence child missing")
    for provider, child in zip(order, destroy, strict=True):
        if (recognize_published_mixed_destroy_child(
                child, parent, review, sealed, provider, scope, name)
                != "absence_proved"):
            raise ValueError("published provider absence differs")
    if destroy[1].input.get("priorAbsenceReceiptSha256") != destroy[0].events[7].data.get("receiptSha256"):
        raise ValueError("published provider handoff differs")
    # The Inspector was already retired. Its two records are historical IDs,
    # so substitute those IDs only for the post-OCI historical row reader.
    ids = tuple(scope["ownedInspectorRecordIds"])
    historical_reader = lambda *args: audit_published_mixed_post_oci_source(
        *args, sketch_repository=chains, provider_resource_repository=resources,
        inspector_record_reader=lambda *_: ids)
    authority = _authority(engagement_id, core_job_id, jobs, plans, lookup,
                           published=True, post_source_reader=historical_reader)
    if authority[0] != parent or authority[1] != core or authority[5] != plan:
        raise ValueError("published OCI source differs")
    negative = latest_negative_attempt(jobs, engagement_id, core_job_id)
    absent = jobs.get(negative.input.get("ociAbsenceJobId")) if negative else None
    selector = jobs.get(selector_id(core_job_id))
    retirement = jobs.get(retirement_id(core_job_id))
    if (negative is None or negative.action != NEGATIVE_ACTION
            or negative.status != "succeeded" or len(negative.events) != 3
            or absent is None or absent.action != OCI_ABSENCE_ACTION
            or absent.status != "succeeded" or len(absent.events) != 3
            or negative.input.get("ociAbsenceJournalSha256") != job_event_digest(absent.events)
            or absent.input.get("teardownParentId") != parent.id
            or selector is None or selector.action != SELECTOR_ACTION
            or selector.status != "succeeded" or selector.input.get("teardownParentId") != parent.id
            or selector.input.get("inspectorNegativeJournalSha256") != job_event_digest(negative.events)
            or selector.input.get("doAbsenceReceiptSha256") != destroy[order.index("digitalocean")].events[7].data.get("receiptSha256")
            or retirement is None or retirement.action != RETIRE_ACTION
            or retirement.status != "succeeded" or retirement.input.get("teardownParentId") != parent.id
            or retirement.input.get("negativeJournalSha256") != job_event_digest(negative.events)
            or retirement.input.get("historicalAuthoritySha256") != _authority_digest(authority)
            or retirement_messages(retirement, retirement.input["hostId"],
                                   retirement.input["firewallId"])[-1]
               != "mixed Inspector local retirement committed"):
        raise ValueError("published OCI, selector, or Inspector receipt differs")
    _saved_public_receipts(parent, core, plan, authority[3], authority[4],
                           absent, negative)
    _saved_selector(parent, review, sealed, selector, absent, negative,
                    destroy[order.index("digitalocean")].events[7].data["receiptSha256"])
    selected = [row for row in resources.list_for_engagement(engagement_id) if row.id in ids]
    current = settings.get(engagement_id)
    if (len(selected) != 2 or {row.id for row in selected} != set(ids)
            or any(row.status != "destroyed" or row.lifecycle_state != "destroyed"
                   or row.destroyed_at is None for row in selected)
            or current is None or current.current_host != {}):
        raise ValueError("published Inspector local retirement differs")
    rows = reviewed_mixed_chain_rows(chains.list_for_engagement(engagement_id),
                                     review.source.chain_ids, engagement_id)
    if ({row.chain_id for row in rows} != set(review.source.chain_ids)
            or any(row.status != "deployed" or row.teardown_job_id or not row.nodes
                   for row in rows)):
        raise ValueError("published chain generation changed")
    # The reviewed provider scopes include every owned provider ID that can
    # be retired here. Alien or merely name-matching records are never changed.
    allowed = {provider: {(item["kind"], str(item["id"])): item["address"]
                          for item in provider_scope["resources"]
                          if item["kind"] not in {"local_file", "random_password"}}
               for provider, provider_scope in zip(order, review.provider_scopes, strict=True)}
    # OCI record retirement needs its own resource-kind mapping if core rows
    # are ever recorded here; an unrecognized active owned row remains a veto.
    records = resources.list_for_engagement(engagement_id)
    to_retire = []
    for record in records:
        if not is_barragan_owned_record(record) or record.status.lower() in TERMINAL_RECORD_STATUSES:
            continue
        kind = _record_kind(record.provider, record.resource_type)
        address = allowed.get(record.provider, {}).get((kind, record.resource_id))
        metadata = record.metadata if isinstance(record.metadata, dict) else {}
        if (address is None
                or ("terraformAddress" in metadata
                    and metadata["terraformAddress"] != address)
                or record.adoption_job_id not in {core.id, *(row.deploy_job_id for row in rows)}):
            raise ValueError("unrecognized active owned provider resource remains")
        to_retire.append(record)
    evidence = {
        "parent": asdict(parent), "authoritySha256": _authority_digest(authority),
        "providerJournalSha256": [job_event_digest(child.events) for child in destroy],
        "ociAbsenceJobId": absent.id, "ociAbsenceJournalSha256": job_event_digest(absent.events),
        "negativeJobId": negative.id, "negativeJournalSha256": job_event_digest(negative.events),
        "selectorJobId": selector.id, "selectorJournalSha256": job_event_digest(selector.events),
        "inspectorJobId": retirement.id,
        "inspectorJournalSha256": job_event_digest(retirement.events),
        "chainRows": [asdict(row) for row in sorted(rows, key=lambda item: item.chain_id)],
        "retireRecords": [asdict(row) for row in sorted(to_retire, key=lambda item: item.id)],
    }
    return parent, plan, rows, to_retire, evidence



def _deployment_bindings(parent, jobs):
    """Desired channel/site/certificate rows, to retire after exact host absence."""
    if parent.input.get("sourceKind") not in ("published-six-node-v1", "unpublished-six-node-cleanup-v1"):
        return None
    from app.storage.certificate_repository import SqlAlchemyCertificateRepository
    from app.storage.service_repository import SqlAlchemyEngagementServiceRepository
    from app.services.engagement_operations import _latest_job_with_event_key
    bindings = SqlAlchemyCertificateRepository().list_bindings(parent.target_id)
    services = SqlAlchemyEngagementServiceRepository().list_for_engagement(parent.target_id)
    snapshots = {}
    history = jobs.list_for_engagement(parent.target_id)
    for key in ("inboundChannels", "outboundChannels"):
        latest = _latest_job_with_event_key(history, key)
        rows = next((event.data[key] for event in reversed(latest.events)
                     if isinstance(event.data.get(key), list)), []) if latest else []
        desired = []
        for row in rows:
            item = {key: value for key, value in row.items() if key not in {
                "validation", "artifactTargets", "applyJobId", "lastJobId", "publicIp",
                "edgePublicIp", "middlePublicIp", "proxyPublicIp"}}
            if str(item.get("status", "")).lower() not in {"removed", "disabled"}:
                item["status"] = "Pending Apply"
            item["validation"] = {"status": "Pending Apply", "externalIngressVerified": False,
                                  "detail": "Infrastructure removed; apply after redeployment."}
            if isinstance(item.get("certificate"), dict):
                item["certificate"] = {**item["certificate"], "status": "unbound"}
            desired.append(item)
        snapshots[key] = desired
    return {"bindings": [asdict(row) for row in bindings],
            "services": [asdict(row) for row in services], "snapshots": snapshots}

def _terminal_event(parent, evidence):
    return JobEvent(3, "info", "published mixed teardown complete", {
        "state": "destroyed", "finalCleanupStatus": "verified_clean",
        "sourceSha256": parent.input["publishedSourceSha256"],
        "planSetSha256": parent.input["planSetSha256"],
        "terminalEvidenceSha256": _fingerprint(evidence),
        "providerDestroyJournalSha256": evidence["providerJournalSha256"],
        "ociAbsenceJournalSha256": evidence["ociAbsenceJournalSha256"],
        "inspectorRetirementJournalSha256": evidence["inspectorJournalSha256"],
    })


def recognize_published_mixed_terminal(
    engagement_id: str, core_job_id: str, *, environment: str,
    job_repository=None, provider_resource_repository=None,
    sketch_repository=None, lease_lookup=None,
) -> StoredJobRun:
    """Read a finished local transaction for an idempotent restart."""
    jobs = job_repository or SqlAlchemyJobRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        if environment != "devtest":
            raise ValueError("private DevTest terminal differs")
        parent = jobs.get(parent_id(core_job_id))
        if (parent is None or parent.action != ACTION or parent.status != "succeeded"
                or parent.target_id != engagement_id or parent.finished_at is None
                or parent.started_at is None or parent.artifact_refs != []
                or parent.input.get("phase") != _PHASE
                or parent.input.get("remainingOwnedResources") != []
                or len(parent.events) != 3
                or parent.events[2].message != "published mixed teardown complete"
                or parent.events[2].level != "info"
                or parent.events[2].sequence != 3
                or parent.events[2].data.get("finalCleanupStatus") != "verified_clean"
                or parent.events[2].data.get("state") != "destroyed"
                or parent.events[2].data.get("sourceSha256")
                   != parent.input.get("publishedSourceSha256")
                or parent.events[2].data.get("planSetSha256")
                   != parent.input.get("planSetSha256")
                or lookup(engagement_id) is not None):
            raise ValueError("published terminal parent or lease differs")
        from app.storage.database import db
        from app.storage.models import EngagementLifecycleEventModel, EngagementLifecycleModel
        reviewed_ids = (saved_published_mixed_initial_review(parent).source.chain_ids
                        if parent.input.get("sourceKind") in ("published-six-node-v1", "unpublished-six-node-cleanup-v1")
                        else parent.input["publishedSource"]["chain_ids"])
        rows = reviewed_mixed_chain_rows(chains.list_for_engagement(engagement_id),
                                         reviewed_ids, engagement_id)
        if ({row.chain_id for row in rows} != set(reviewed_ids)
                or any(row.status != "destroyed" or row.nodes
                       or row.teardown_job_id != parent.id for row in rows)
                or any(is_barragan_owned_record(row)
                       and row.status.lower() not in TERMINAL_RECORD_STATUSES
                       for row in resources.list_for_engagement(engagement_id))):
            raise ValueError("published terminal local residue remains")
        if parent.input.get("sourceKind") in ("published-six-node-v1", "unpublished-six-node-cleanup-v1"):
            from app.storage.models import CertificateBindingModel, EngagementServiceModel
            bindings = db.session.query(CertificateBindingModel).filter_by(engagement_id=engagement_id).all()
            services = db.session.query(EngagementServiceModel).filter_by(engagement_id=engagement_id).all()
            if (sorted(row.id for row in bindings) != sorted(parent.events[2].data.get("retiredCertificateBindingIds", []))
                    or any(row.status != "unbound" or row.last_job_id != parent.id for row in bindings)
                    or sorted(row.service_id for row in services) != sorted(parent.events[2].data.get("retiredServiceIds", []))
                    or any(row.status != "Removed" or row.apply_job_id != parent.id for row in services)):
                raise ValueError("active deployment bindings remain after teardown")
        lifecycle = db.session.query(EngagementLifecycleModel).filter_by(
            engagement_id=engagement_id).one_or_none()
        events = db.session.query(EngagementLifecycleEventModel).filter_by(
            engagement_id=engagement_id,
            reason=f"mixed_published_teardown_verified:{parent.id}").all()
        if (lifecycle is None or lifecycle.state != "destroyed"
                or len(events) != 1 or events[0].state != "destroyed"
                or events[0].evidence_fingerprint != lifecycle.evidence_fingerprint
                or events[0].evidence != lifecycle.evidence):
            raise ValueError("published terminal lifecycle differs")
        return parent
    except Exception:
        raise PublishedMixedTerminalAttention(
            "published terminal history requires exact reconciliation") from None


def finish_published_mixed_terminal(
    engagement_id: str, core_job_id: str, *, environment: str,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, sketch_repository=None, lease_lookup=None,
) -> StoredJobRun:
    """Commit exact owned-row retirement, lifecycle, parent, and fence once."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    settings = settings_repository or SqlAlchemyObserverSettingsRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    from app.storage.database import db
    if environment != "devtest":
        raise PublishedMixedTerminalAttention("published terminal is DevTest-only")
    previous = jobs.get(parent_id(core_job_id))
    if previous is not None and previous.status == "succeeded":
        return recognize_published_mixed_terminal(
            engagement_id, core_job_id, environment=environment,
            job_repository=jobs, provider_resource_repository=resources,
            sketch_repository=chains, lease_lookup=lookup)
    try:
        parent, plan, rows, retire, evidence = _history(
            engagement_id, core_job_id, jobs, plans, settings, resources, chains, lookup)
        deployment_bindings = _deployment_bindings(parent, jobs)
        from sqlalchemy import delete, update
        from app.storage.models import (
            CoreMutationLeaseModel, EngagementLifecycleEventModel,
            EngagementLifecycleModel, JobEventModel, JobRunModel,
            ProviderResourceRecordModel, SketchChainModel,
        )
        if db.session.get_bind().dialect.name != "sqlite":
            raise ValueError("reviewed SQLite writer required")
        stamp = datetime.now(timezone.utc)
        db.session.rollback()
        locked = db.session.execute(update(JobRunModel).where(
            JobRunModel.id == parent.id, JobRunModel.action == ACTION,
            JobRunModel.status == "queued", JobRunModel.input == parent.input,
            JobRunModel.target_id == engagement_id,
            JobRunModel.started_at.is_(None), JobRunModel.finished_at.is_(None),
        ).values(status="queued"))
        db.session.expire_all()
        if locked.rowcount != 1:
            raise ValueError("published terminal parent CAS lost")
        reread = _history(engagement_id, core_job_id, jobs, plans, settings,
                          resources, chains, lookup)
        if reread[4] != evidence or _deployment_bindings(parent, jobs) != deployment_bindings:
            raise ValueError("published terminal history changed under writer")
        lease = db.session.query(CoreMutationLeaseModel).filter_by(
            engagement_id=engagement_id).one_or_none()
        if lease is None or lease.owner_id != plan.id or lease.operation != _FENCE:
            raise ValueError("published terminal fence differs")
        for expected in rows:
            model = db.session.query(SketchChainModel).filter_by(
                engagement_id=engagement_id, chain_id=expected.chain_id).one()
            model.status = "destroyed"
            model.nodes = []
            model.teardown_job_id = parent.id
            model.updated_at = stamp
        for expected in retire:
            model = db.session.get(ProviderResourceRecordModel, expected.id)
            if model is None:
                raise ValueError("reviewed owned record disappeared")
            model.status = "destroyed"
            model.lifecycle_state = "destroyed"
            model.destroyed_at = stamp
            model.updated_at = stamp
        if deployment_bindings is not None:
            from app.storage.models import CertificateBindingModel, EngagementServiceModel
            for expected in deployment_bindings["bindings"]:
                binding = db.session.get(CertificateBindingModel, expected["id"])
                if binding is None or binding.engagement_id != engagement_id:
                    raise ValueError("reviewed certificate binding disappeared")
                binding.status = "unbound"
                binding.validation = {"status": "inactive", "detail": "Infrastructure removed."}
                binding.last_job_id = parent.id
                binding.updated_at = stamp
            for expected in deployment_bindings["services"]:
                service = db.session.query(EngagementServiceModel).filter_by(
                    engagement_id=engagement_id, service_id=expected["service_id"]).one()
                service.status = "Removed"
                service.apply_job_id = parent.id
                service.updated_at = stamp
        staged = {**parent.input, "phase": _PHASE, "remainingOwnedResources": []}
        changed = db.session.execute(update(JobRunModel).where(
            JobRunModel.id == parent.id, JobRunModel.status == "queued",
            JobRunModel.input == parent.input, JobRunModel.finished_at.is_(None),
        ).values(status="succeeded", started_at=stamp, finished_at=stamp,
                 input=staged))
        if changed.rowcount != 1:
            raise ValueError("published terminal parent changed")
        event = _terminal_event(parent, evidence)
        if deployment_bindings is not None:
            event = JobEvent(event.sequence, event.level, event.message, {
                **event.data, **deployment_bindings["snapshots"],
                "retiredCertificateBindingIds": [row["id"] for row in deployment_bindings["bindings"]],
                "retiredServiceIds": [row["service_id"] for row in deployment_bindings["services"]]})
        db.session.add(JobEventModel(job_id=parent.id, sequence=3,
                                     level="info", message=event.message,
                                     data=event.data, created_at=stamp))
        db.session.flush()
        previous = db.session.query(EngagementLifecycleModel).filter_by(
            engagement_id=engagement_id).one_or_none()
        before = previous.state if previous else "not_deployed"
        resolution = resolve_engagement_lifecycle(
            engagement_id, previous_state=before, job_repository=jobs,
            provider_resource_repository=resources, sketch_chain_repository=chains)
        if resolution.state != "destroyed":
            raise ValueError("published terminal lifecycle did not resolve destroyed")
        fingerprint = lifecycle_fingerprint(resolution.evidence)
        if previous is None:
            previous = EngagementLifecycleModel(engagement_id=engagement_id)
            db.session.add(previous)
        previous.state = "destroyed"
        previous.evidence_fingerprint = fingerprint
        previous.evidence = resolution.evidence
        previous.reconciled_at = stamp
        db.session.add(EngagementLifecycleEventModel(
            engagement_id=engagement_id, previous_state=before,
            state="destroyed", evidence_fingerprint=fingerprint,
            evidence=resolution.evidence,
            reason=f"mixed_published_teardown_verified:{parent.id}", created_at=stamp))
        released = db.session.execute(delete(CoreMutationLeaseModel).where(
            CoreMutationLeaseModel.engagement_id == engagement_id,
            CoreMutationLeaseModel.owner_id == plan.id,
            CoreMutationLeaseModel.operation == _FENCE))
        if released.rowcount != 1:
            raise ValueError("published terminal lease release changed")
        db.session.commit()
        result = jobs.get(parent.id)
        if result is None or result.status != "succeeded" or result.events[-1] != event:
            raise ValueError("published terminal commit uncertain")
        return result
    except Exception:
        db.session.rollback()
        raise PublishedMixedTerminalAttention(
            "published terminal requires exact local reconciliation") from None
