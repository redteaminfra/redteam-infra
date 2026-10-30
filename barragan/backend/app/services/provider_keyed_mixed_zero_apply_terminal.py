# Copyright (c) 2026, Oracle and/or its affiliates.
"""Finish the attested mixed zero-Apply teardown without another provider write."""

from __future__ import annotations

from dataclasses import asdict, fields, replace
from datetime import datetime, timezone
from pathlib import Path

from app.domain import JobEvent
from app.services.engagement_lifecycle import (
    FAILED_SKETCH_STATES, LIVE_SKETCH_STATES, _fingerprint as lifecycle_fingerprint,
    _job_after,
    resolve_engagement_lifecycle,
)
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_mixed_zero_apply_cleanup import (
    ACTION, _PHASE, _parent_id,
)
from app.services.provider_keyed_mixed_zero_apply_core_absence import (
    _authority, _authority_digest,
)
from app.services.provider_keyed_mixed_zero_apply_inspector_retirement import (
    ACTION as RETIRE_ACTION, _child_id as retirement_child_id, _messages as retirement_messages,
    retire_mixed_zero_apply_inspector,
)
from app.services.provider_keyed_mixed_initial_plan_parent import _parent_id as initial_parent_id
from app.services.provider_keyed_mixed_zero_apply_core_preview import _child_id as preview_child_id
from app.services.provider_keyed_mixed_zero_apply_core_apply import _child_id as apply_child_id
from app.services.provider_keyed_mixed_zero_apply_teardown_source import MixedZeroApplySource
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import (
    SqlAlchemyProviderResourceRepository, TERMINAL_RECORD_STATUSES,
    is_barragan_owned_record,
)
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


_FINAL_PHASE = "lifecycle_reconciliation"
_FENCE = "provider_keyed_teardown_fence"


class MixedZeroApplyTerminalAttention(ValueError):
    """The exact final authority or terminal history cannot be established."""


def _terminal_event(parent: StoredJobRun, retirement: StoredJobRun) -> JobEvent:
    return JobEvent(2, "info", "mixed zero-Apply teardown complete", {
        "state": "destroyed", "finalCleanupStatus": "verified_clean",
        "inspectorRetirementJobId": retirement.id,
        "inspectorRetirementJournalSha256": job_event_digest(retirement.events),
        "sourceSha256": parent.input["sourceSha256"],
    })


def _residue(engagement_id, resources, chains, expected_chain_ids):
    records = resources.list_for_engagement(engagement_id)
    if any(is_barragan_owned_record(row)
           and row.status.lower() not in TERMINAL_RECORD_STATUSES for row in records):
        raise ValueError("owned provider residue remains")
    rows = chains.list_for_engagement(engagement_id)
    if (len(rows) != 2 or {row.chain_id for row in rows} != set(expected_chain_ids)
            or any(row.status != "pending" or row.nodes or row.deploy_job_id
                   or row.teardown_job_id for row in rows)
            or any(row.status.lower() in LIVE_SKETCH_STATES | FAILED_SKETCH_STATES
                   for row in rows)):
        raise ValueError("mixed Sketch residue differs")


def _retired_inspector_record_matches(row, retirement: StoredJobRun) -> bool:
    """Match the writer's exact owned record and versioned cleanup projection."""
    version = retirement.input.get("cleanupMetadataVersion")
    if ("cleanupMetadataVersion" in retirement.input
            and (type(version) is not int or version != 1)):
        return False
    snapshot_key = {"inspector_instance": "hostRecord",
                    "inspector_firewall": "firewallRecord"}.get(row.resource_type)
    if snapshot_key is None:
        return False
    prior = retirement.input.get(snapshot_key)
    if type(prior) is not dict or type(prior.get("metadata")) is not dict:
        return False
    expected = dict(prior)
    if version == 1:
        expected["metadata"] = {**prior["metadata"], "cleanupRequired": False}
    actual = asdict(row)
    if version == 1 and row.metadata.get("cleanupRequired") is not False:
        return False
    return (row.status == "destroyed" and row.lifecycle_state == "destroyed"
            and row.destroyed_at is not None
            and all(actual.get(key) == value for key, value in expected.items()
                    if key not in {"status", "lifecycle_state", "updated_at", "destroyed_at"}))


def _historical_parent(parent: StoredJobRun) -> StoredJobRun:
    original_input = dict(parent.input)
    original_input.pop("remainingOwnedResources", None)
    original_input["phase"] = _PHASE
    return replace(parent, status="queued", started_at=None, finished_at=None,
                   input=original_input, events=parent.events[:1])


def recognize_mixed_zero_apply_terminal(
    engagement_id: str, core_job_id: str, *, environment: str,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, sketch_repository=None, lease_lookup=None,
) -> StoredJobRun:
    """Read exact local terminal history after the teardown fence was released."""
    if environment != "devtest":
        raise MixedZeroApplyTerminalAttention("private DevTest boundary differs")
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    settings = settings_repository or SqlAlchemyObserverSettingsRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        parent = jobs.get(_parent_id(core_job_id))
        retirement = jobs.get(retirement_child_id(core_job_id))
        core = jobs.get(core_job_id)
        if parent is None or retirement is None or core is None:
            raise ValueError("terminal jobs missing")
        original = _historical_parent(parent)
        initial = jobs.get(initial_parent_id(core_job_id))
        preview = jobs.get(preview_child_id(core_job_id))
        applied = jobs.get(apply_child_id(core_job_id))
        plan = plans.get(parent.input.get("corePlanId"))
        if any(row is None for row in (initial, preview, applied, plan)):
            raise ValueError("terminal authority missing")
        source = original.input.get("source")
        if (type(source) is not dict
                or set(source) != {field.name for field in fields(MixedZeroApplySource)}
                or _fingerprint(source) != original.input["sourceSha256"]
                or source.get("engagement_id") != engagement_id
                or source.get("core_job_id") != core.id
                or source.get("core_plan_id") != plan.id):
            raise ValueError("terminal source differs")
        record_ids = source["owned_inspector_record_ids"]
        if (type(record_ids) is not list or len(record_ids) != 2
                or any(type(value) is not str or not value for value in record_ids)
                or len(set(record_ids)) != 2
                or any(type(value) is not str or len(value) != 64
                       or set(value) - set("0123456789abcdef")
                       for value in (source["core_state_sha256"], source["core_inventory_sha256"]))):
            raise ValueError("terminal source identity differs")
        historical_source = MixedZeroApplySource(**source)
        authority_digest = _authority_digest(
            (original, core, initial, preview, applied, plan, historical_source))
        if (parent.action != ACTION or parent.status != "succeeded"
                or parent.target_id != engagement_id
                or parent.target != f"engagement:{engagement_id}"
                or parent.target_type != "engagement"
                or parent.started_at is None or parent.finished_at is None
                or parent.artifact_refs != []
                or parent.input != {**original.input, "phase": _FINAL_PHASE,
                                    "remainingOwnedResources": []}
                or len(parent.events) != 2
                or parent.events[0] != JobEvent(1, "info", "mixed zero-Apply cleanup fenced",
                                                 {"sourceSha256": parent.input["sourceSha256"]})
                or parent.events[1] != _terminal_event(parent, retirement)
                or retirement.action != RETIRE_ACTION or retirement.status != "succeeded"
                or retirement.started_at is None or retirement.finished_at is None
                or retirement.artifact_refs != []
                or retirement.target_id != engagement_id
                or retirement.requested_by != parent.requested_by
                or retirement.input.get("teardownParentId") != parent.id
                or retirement.input.get("coreJobId") != core.id
                or retirement.input.get("corePlanId") != plan.id
                or retirement.input.get("sourceSha256") != parent.input["sourceSha256"]
                or retirement.input.get("historicalAuthoritySha256") != authority_digest
                or retirement_messages(retirement, retirement.input["hostId"],
                                       retirement.input["firewallId"])[-1]
                != "mixed Inspector local retirement committed"):
            raise ValueError("terminal authority differs")
        from app.storage.database import db
        from app.storage.models import EngagementLifecycleEventModel, EngagementLifecycleModel
        newer = [job for job in jobs.list_for_engagement(engagement_id)
                 if job.action == "pilot_standard_rti_guarded_execute"
                 and _job_after(job.created_at, parent.finished_at)]
        lease = lookup(engagement_id)
        if newer:
            latest = max(newer, key=lambda job: (job.created_at, job.id))
            latest_plan = plans.get(latest.input.get("corePlanId"))
            if (latest_plan is None or latest_plan.engagement_id != engagement_id
                    or latest_plan.id != latest.input.get("corePlanId")
                    or latest_plan.apply_job_id not in {None, latest.id}
                    or (lease is not None and lease[0] != latest_plan.id)):
                raise ValueError("new core generation or lease differs")
        elif lease is not None:
            raise ValueError("terminal fence was not released")
        selected = [row for row in resources.list_for_engagement(engagement_id)
                    if row.id in source["owned_inspector_record_ids"]]
        if len(selected) != 2:
            raise ValueError("historical Inspector pair differs")
        if any(not _retired_inspector_record_matches(row, retirement) for row in selected):
            raise ValueError("historical Inspector record differs")
        if not newer:
            _residue(engagement_id, resources, chains, initial.input["chainIds"])
            observed = settings.get(engagement_id)
            if observed is None or observed.current_host != {}:
                raise ValueError("retired Inspector current host differs")
        lifecycle = db.session.query(EngagementLifecycleModel).filter_by(
            engagement_id=engagement_id).one_or_none()
        events = db.session.query(EngagementLifecycleEventModel).filter_by(
            engagement_id=engagement_id, reason=f"mixed_zero_apply_teardown_verified:{parent.id}").all()
        resolution = resolve_engagement_lifecycle(
            engagement_id, previous_state=lifecycle.state if lifecycle else None,
            job_repository=jobs, provider_resource_repository=resources,
            sketch_chain_repository=chains)
        fingerprint = lifecycle_fingerprint(resolution.evidence)
        if (len(events) != 1 or events[0].state != "destroyed"
                or events[0].evidence_fingerprint != lifecycle_fingerprint(events[0].evidence)
                or not any(row.get("kind") == "engagement_teardown_job"
                               and row.get("id") == parent.id
                               and row.get("status") == "succeeded"
                               for row in events[0].evidence)
                or (not newer and (lifecycle is None or lifecycle.state != "destroyed"
                                   or resolution.state != "destroyed"
                                   or lifecycle.evidence_fingerprint != fingerprint
                                   or lifecycle.evidence != resolution.evidence
                                   or events[0].evidence_fingerprint != fingerprint
                                   or events[0].evidence != resolution.evidence))):
            raise ValueError("terminal lifecycle differs")
        return parent
    except Exception:
        raise MixedZeroApplyTerminalAttention(
            "mixed zero-Apply terminal history requires exact reconciliation") from None


def finish_mixed_zero_apply_terminal(
    engagement_id: str, core_job_id: str, *, environment: str,
    state_root: Path, core_state_root: Path, job_repository=None,
    plan_repository=None, settings_repository=None,
    provider_resource_repository=None, sketch_repository=None, lease_lookup=None,
) -> StoredJobRun:
    """Complete local lifecycle, parent and fence in one SQLite transaction."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    settings = settings_repository or SqlAlchemyObserverSettingsRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    existing = jobs.get(_parent_id(core_job_id))
    if existing is not None and existing.status == "succeeded":
        return recognize_mixed_zero_apply_terminal(
            engagement_id, core_job_id, environment=environment,
            job_repository=jobs, plan_repository=plans, settings_repository=settings,
            provider_resource_repository=resources, sketch_repository=chains,
            lease_lookup=lookup)
    try:
        if environment != "devtest":
            raise ValueError("private DevTest boundary differs")
        historical = _authority(engagement_id, core_job_id, jobs, plans, lookup)
        parent, core, initial, _, _, plan, *_ = historical
        authority_digest = _authority_digest(historical)
        saved_retirement = jobs.get(retirement_child_id(core_job_id))
        if saved_retirement is None or saved_retirement.status != "succeeded":
            raise ValueError("completed Inspector retirement required")
        retirement = retire_mixed_zero_apply_inspector(
            engagement_id, core_job_id, environment=environment,
            state_root=state_root, core_state_root=core_state_root,
            job_repository=jobs, plan_repository=plans,
            settings_repository=settings, provider_resource_repository=resources,
            lease_lookup=lookup)
        if (retirement.status != "succeeded" or retirement.action != RETIRE_ACTION
                or retirement.input.get("historicalAuthoritySha256") != authority_digest):
            raise ValueError("Inspector retirement authority differs")
        from sqlalchemy import delete, update
        from app.storage.database import db
        from app.storage.models import (
            CoreMutationLeaseModel, EngagementLifecycleEventModel,
            EngagementLifecycleModel, JobEventModel, JobRunModel,
        )
        if db.session.get_bind().dialect.name != "sqlite":
            raise ValueError("reviewed SQLite writer required")
        stamp = datetime.now(timezone.utc)
        staged_input = {**parent.input, "phase": _FINAL_PHASE,
                        "remainingOwnedResources": []}
        db.session.rollback()
        locked = db.session.execute(update(JobRunModel).where(
            JobRunModel.id == parent.id, JobRunModel.action == ACTION,
            JobRunModel.status == "queued", JobRunModel.started_at.is_(None),
            JobRunModel.finished_at.is_(None), JobRunModel.input == parent.input,
            JobRunModel.target_id == engagement_id,
            JobRunModel.requested_by == parent.requested_by,
        ).values(status="queued"))
        db.session.expire_all()
        if (locked.rowcount != 1 or _authority_digest(_authority(
                engagement_id, core_job_id, jobs, plans, lookup)) != authority_digest
                or jobs.get(retirement.id) != retirement
                or retirement.input.get("historicalAuthoritySha256") != authority_digest):
            raise ValueError("terminal writer authority changed")
        _residue(engagement_id, resources, chains, initial.input["chainIds"])
        if _authority_digest(_authority(
                engagement_id, core_job_id, jobs, plans, lookup)) != authority_digest:
            raise ValueError("terminal authority changed before mutation")
        if retire_mixed_zero_apply_inspector(
                engagement_id, core_job_id, environment=environment,
                state_root=state_root, core_state_root=core_state_root,
                job_repository=jobs, plan_repository=plans,
                settings_repository=settings, provider_resource_repository=resources,
                lease_lookup=lookup) != retirement:
            raise ValueError("Inspector retirement changed before mutation")
        settings_row = settings.get(engagement_id)
        if settings_row is None or settings_row.current_host != {}:
            raise ValueError("Inspector settings still claim a host")
        lease = db.session.query(CoreMutationLeaseModel).filter_by(
            engagement_id=engagement_id).one_or_none()
        if lease is None or lease.owner_id != plan.id or lease.operation != _FENCE:
            raise ValueError("terminal fence differs")
        prior = db.session.query(EngagementLifecycleModel).filter_by(
            engagement_id=engagement_id).one_or_none()
        previous_state = prior.state if prior else "not_deployed"
        changed = db.session.execute(update(JobRunModel).where(
            JobRunModel.id == parent.id, JobRunModel.action == ACTION,
            JobRunModel.status == "queued", JobRunModel.input == parent.input,
            JobRunModel.started_at.is_(None), JobRunModel.finished_at.is_(None),
        ).values(status="succeeded", started_at=stamp, finished_at=stamp,
                 input=staged_input))
        if changed.rowcount != 1:
            raise ValueError("terminal parent changed")
        db.session.add(JobEventModel(
            job_id=parent.id, sequence=2, level="info",
            message="mixed zero-Apply teardown complete",
            data=_terminal_event(parent, retirement).data, created_at=stamp))
        db.session.flush()
        resolution = resolve_engagement_lifecycle(
            engagement_id, previous_state=previous_state,
            job_repository=jobs, provider_resource_repository=resources,
            sketch_chain_repository=chains)
        if resolution.state != "destroyed":
            raise ValueError("terminal lifecycle did not resolve destroyed")
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
            reason=f"mixed_zero_apply_teardown_verified:{parent.id}",
            created_at=stamp))
        released = db.session.execute(delete(CoreMutationLeaseModel).where(
            CoreMutationLeaseModel.engagement_id == engagement_id,
            CoreMutationLeaseModel.owner_id == plan.id,
            CoreMutationLeaseModel.operation == _FENCE))
        if released.rowcount != 1:
            raise ValueError("terminal fence release changed")
        db.session.commit()
    except Exception:
        from app.storage.database import db
        db.session.rollback()
        raise MixedZeroApplyTerminalAttention(
            "mixed zero-Apply terminal requires exact local reconciliation") from None
    return recognize_mixed_zero_apply_terminal(
        engagement_id, core_job_id, environment=environment,
        job_repository=jobs, plan_repository=plans, settings_repository=settings,
        provider_resource_repository=resources, sketch_repository=chains,
        lease_lookup=lookup)
