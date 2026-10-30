# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from sqlalchemy.exc import IntegrityError

from app.domain.deployment_plan import DEPLOYMENT_PLAN_STATUSES, DeploymentPlan


class DeploymentPlanConflictError(RuntimeError):
    pass


_OCI_CORE_STATE_SEAL_MESSAGE = "applied OCI core state sealed"


def _read_keyed_core_state_seal(evidence: dict, inputs: dict) -> dict:
    """Read exact post-apply bytes from the reviewed plan's durable state path."""
    from app.services.provider_keyed_oci_core_state import OciCoreStateError, parse_applied_oci_core_state

    path_value = evidence.get("terraformStatePath")
    target = evidence.get("target") if isinstance(evidence.get("target"), dict) else {}
    job_target = inputs.get("target") if isinstance(inputs.get("target"), dict) else {}
    if (not isinstance(path_value, str) or not Path(path_value).is_absolute()
            or Path(path_value).is_symlink() or not Path(path_value).is_file()
            or inputs.get("proxyCount") != evidence.get("proxyCount")
            or inputs.get("elkEnabled") != evidence.get("elkEnabled")
            or any(job_target.get(key) != target.get(key)
                   for key in ("name", "region", "compartmentId", "auth"))):
        raise DeploymentPlanConflictError("keyed core state source or reviewed inputs changed")
    try:
        inventory = parse_applied_oci_core_state(
            Path(path_value).read_bytes(), proxy_count=inputs["proxyCount"],
            elk_enabled=inputs["elkEnabled"], compartment_id=target["compartmentId"],
            engagement_name=inputs["engagementName"],
        )
    except (OSError, OciCoreStateError, KeyError, TypeError) as exc:
        raise DeploymentPlanConflictError("applied OCI core state cannot be sealed") from exc
    return {
        "schema": "applied-oci-core-state-v1",
        "corePlanEvidenceSha256": inputs["corePlanEvidenceSha256"],
        "rawStateSha256": inventory.raw_state_sha256,
        "inventorySha256": inventory.inventory_sha256,
        "lineage": inventory.lineage,
        "serial": inventory.serial,
        "resourceCount": len(inventory.resources),
    }


def _keyed_core_state_seal_event_data(seal: dict) -> dict:
    """Keep OCIDs and state bytes out of public job events."""
    return {
        "schema": seal["schema"],
        "corePlanEvidenceSha256": seal["corePlanEvidenceSha256"],
        "rawStateSha256": seal["rawStateSha256"],
        "inventorySha256": seal["inventorySha256"],
        "lineage": seal["lineage"],
        "serial": seal["serial"],
        "resourceCount": seal["resourceCount"],
    }


class DeploymentPlanRepository(Protocol):
    def get(self, plan_id: str) -> DeploymentPlan | None: ...
    def current(self, engagement_id: str) -> DeploymentPlan | None: ...
    def save(self, plan: DeploymentPlan) -> DeploymentPlan: ...
    def acquire(self, engagement_id: str, owner_id: str, operation: str) -> bool: ...
    def retag(self, engagement_id: str, owner_id: str, operation: str) -> None: ...
    def retag_if_operation(self, engagement_id: str, owner_id: str,
                           expected_operation: str, next_operation: str) -> None: ...
    def release(self, engagement_id: str, owner_id: str) -> None: ...
    def complete_apply(self, plan: DeploymentPlan, *, next_operation: str | None) -> DeploymentPlan: ...
    def invalidate_current(self, engagement_id: str, except_id: str = "") -> None: ...


class SqlAlchemyDeploymentPlanRepository:
    def reserve_provider_keyed_append_plan(self, parent, child) -> bool:
        """Atomically create one append review, child, and core mutation lease."""
        from sqlalchemy import text

        from app.storage.database import db
        from app.storage.models import (
            CoreMutationLeaseModel, JobEventModel, JobRunModel,
        )

        if (parent.action != "provider_keyed_edge_append"
                or child.action != "provider_keyed_edge_append_plan"
                or parent.status != "running" or child.status != "queued"
                or parent.target_id != child.target_id
                or parent.input.get("planJobId") != child.id
                or child.input.get("parentJobId") != parent.id
                or parent.input.get("coreJobId") != child.input.get("coreJobId")):
            raise DeploymentPlanConflictError("append reservation input differs")
        try:
            db.session.rollback()
            locked = db.session.execute(text("""
                UPDATE deployment_plans SET status = status
                WHERE id = :plan AND engagement_id = :engagement
                  AND status = 'applied' AND apply_job_id = :core
            """), {"plan": parent.input.get("corePlanId"),
                   "engagement": parent.target_id, "core": parent.input.get("coreJobId")})
            prior = db.session.query(JobRunModel).filter_by(
                action="provider_keyed_edge_append", target_id=parent.target_id).all()
            if locked.rowcount != 1:
                raise ValueError("reviewed append source changed")
            if prior:
                from app.services.provider_keyed_teardown_scope import (
                    _reconciled_unapplied_append_state_sha,
                )
                from app.storage.job_repository import SqlAlchemyJobRepository

                previous_sha = _reconciled_unapplied_append_state_sha(
                    parent.target_id, SqlAlchemyJobRepository(),
                    expected_core_job_id=parent.input.get("coreJobId"),
                    expected_core_plan_id=parent.input.get("corePlanId"))
                source = parent.input.get("initialSource")
                if (previous_sha is None or type(source) is not dict
                        or source.get("state_sha256") != previous_sha):
                    raise ValueError("previous append review changed")
            db.session.add(CoreMutationLeaseModel(
                engagement_id=parent.target_id,
                owner_id=parent.input["corePlanId"],
                operation="provider_keyed_edge_append",
            ))
            for job in (parent, child):
                db.session.add(JobRunModel(
                    id=job.id, action=job.action, status=job.status, target=job.target,
                    target_type=job.target_type, target_id=job.target_id,
                    requested_by=job.requested_by, input=job.input,
                    artifact_refs=job.artifact_refs,
                    created_at=_parse_datetime(job.created_at),
                    started_at=_parse_datetime(job.started_at) if job.started_at else None,
                    finished_at=None,
                ))
                for event in job.events:
                    db.session.add(JobEventModel(
                        job_id=job.id, sequence=event.sequence, level=event.level,
                        message=event.message, data=event.data,
                    ))
            db.session.commit()
            return True
        except Exception:
            db.session.rollback()
            raise DeploymentPlanConflictError("append review reservation was not committed") from None

    def close_unapplied_provider_keyed_append_plan(self, parent, child, *, state_sha256: str):
        """Commit a proven no-apply append close and release its lease together."""
        from sqlalchemy import text

        from app.domain import JobEvent
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel, JobEventModel, JobRunModel
        from app.storage.job_repository import SqlAlchemyJobRepository
        from app.services.provider_keyed_append_plan_job import (
            _only_attested_historical_no_go_apply_children,
        )

        if (parent.action != "provider_keyed_edge_append" or parent.status != "running"
                or parent.input.get("phase") not in {"planning", "discarding"}
                or child.action != "provider_keyed_edge_append_plan"
                or child.status not in {"failed", "succeeded"}
                or (child.status == "succeeded" and parent.input.get("phase") != "discarding")
                or (child.status == "failed" and parent.input.get("phase") != "planning")
                or parent.input.get("planJobId") != child.id
                or child.input.get("parentJobId") != parent.id
                or not isinstance(state_sha256, str) or len(state_sha256) != 64):
            raise DeploymentPlanConflictError("unapplied append close input differs")
        try:
            db.session.rollback()
            locked = db.session.execute(text("""
                UPDATE deployment_plans SET status = status
                WHERE id = :plan AND engagement_id = :engagement
                  AND status = 'applied' AND apply_job_id = :core
            """), {"plan": parent.input.get("corePlanId"),
                   "engagement": parent.target_id, "core": parent.input.get("coreJobId")})
            jobs = SqlAlchemyJobRepository()
            current_parent, current_child = jobs.get(parent.id), jobs.get(child.id)
            lease = db.session.query(CoreMutationLeaseModel).filter_by(
                engagement_id=parent.target_id).one_or_none()
            if (locked.rowcount != 1 or current_parent != parent or current_child != child
                    or lease is None or lease.owner_id != parent.input["corePlanId"]
                    or lease.operation != "provider_keyed_edge_append"
                    or not _only_attested_historical_no_go_apply_children(parent, jobs)):
                raise ValueError("unapplied append changed before close")
            row = db.session.get(JobRunModel, parent.id)
            row.status = "failed"
            row.finished_at = datetime.now(timezone.utc)
            row.input = {**parent.input, "phase": "unapplied_reconciled"}
            terminal = JobEvent(len(parent.events) + 1, "info",
                "append plan reconciled without mutation", {"stateSha256": state_sha256})
            db.session.add(JobEventModel(job_id=parent.id, sequence=terminal.sequence,
                level=terminal.level, message=terminal.message, data=terminal.data))
            db.session.delete(lease)
            db.session.commit()
            return jobs.get(parent.id)
        except Exception:
            db.session.rollback()
            raise DeploymentPlanConflictError("unapplied append close was not committed") from None

    def fence_no_go_provider_keyed_append_apply(self, parent, plan, child, *, state_sha256: str):
        """Atomically stop a queued Apply child while retaining the engagement lease."""
        from sqlalchemy import text
        from app.domain import JobEvent
        from app.storage.database import db
        from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
        from app.storage.models import CoreMutationLeaseModel, JobEventModel, JobRunModel
        from app.services.provider_keyed_teardown_scope import _exact_no_go_apply_child

        if (parent.action != "provider_keyed_edge_append" or parent.status != "failed"
                or parent.input.get("phase") != "attention"
                or plan.id != parent.input.get("planJobId")
                or plan.status != "succeeded" or not plan.events
                or plan.events[-1].data.get("stateSha256") != state_sha256
                or not parent.events or parent.events[-1].message !=
                "provider append Apply stopped; reconciliation required"):
            raise DeploymentPlanConflictError("no-GO append input differs")
        try:
            db.session.rollback()
            locked = db.session.execute(text("""
                UPDATE deployment_plans SET status = status
                WHERE id = :plan AND engagement_id = :engagement
                  AND status = 'applied' AND apply_job_id = :core
            """), {"plan": parent.input.get("corePlanId"),
                   "engagement": parent.target_id, "core": parent.input.get("coreJobId")})
            jobs = SqlAlchemyJobRepository()
            related = jobs.list_for_engagement(parent.target_id)
            lease = db.session.query(CoreMutationLeaseModel).filter_by(
                engagement_id=parent.target_id).one_or_none()
            expiry = parent.input.get("claimExpiresAt")
            if (locked.rowcount != 1 or jobs.get(parent.id) != parent
                    or jobs.get(plan.id) != plan or jobs.get(child.id) != child
                    or _exact_no_go_apply_child(parent, related, jobs) != child
                    or lease is None or lease.owner_id != parent.input["corePlanId"]
                    or lease.operation != "provider_keyed_edge_append"
                    or type(expiry) is not str or datetime.fromisoformat(expiry).tzinfo is None
                    or datetime.now(timezone.utc) < datetime.fromisoformat(expiry)):
                raise ValueError("no-GO append source changed")
            now = datetime.now(timezone.utc)
            child_event = JobEvent(2, "info", "provider append Apply never started", {
                "stateSha256": state_sha256,
                "planJournalSha256": parent.input["planJournalSha256"],
            })
            child_row = db.session.get(JobRunModel, child.id)
            child_row.status = "failed"
            child_row.finished_at = now
            db.session.add(JobEventModel(job_id=child.id, sequence=2,
                level=child_event.level, message=child_event.message,
                data=child_event.data))
            fenced_journal = job_event_digest([*child.events, child_event])
            parent_row = db.session.get(JobRunModel, parent.id)
            parent_row.input = {**parent.input, "phase": "no_go_cleaning"}
            db.session.add(JobEventModel(job_id=parent.id,
                sequence=len(parent.events) + 1, level="info",
                message="provider append Apply no-GO fenced",
                data={"stateSha256": state_sha256,
                      "applyChildJournalSha256": fenced_journal}))
            db.session.commit()
            return jobs.get(parent.id)
        except Exception:
            db.session.rollback()
            raise DeploymentPlanConflictError("no-GO append fence was not committed") from None

    def close_no_go_provider_keyed_append_apply(self, parent, plan, child, *, state_sha256: str):
        """Close a previously fenced no-GO child and release its lease in one CAS."""
        from sqlalchemy import text
        from app.domain import JobEvent
        from app.storage.database import db
        from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
        from app.storage.models import CoreMutationLeaseModel, JobEventModel, JobRunModel
        from app.services.provider_keyed_teardown_scope import _exact_no_go_apply_child

        if (parent.status != "failed" or parent.input.get("phase") != "no_go_cleaning"
                or plan.id != parent.input.get("planJobId")
                or plan.events[-1].data.get("stateSha256") != state_sha256
                or child.status != "failed"):
            raise DeploymentPlanConflictError("no-GO append close input differs")
        try:
            db.session.rollback()
            locked = db.session.execute(text("""
                UPDATE deployment_plans SET status = status
                WHERE id = :plan AND engagement_id = :engagement
                  AND status = 'applied' AND apply_job_id = :core
            """), {"plan": parent.input.get("corePlanId"),
                   "engagement": parent.target_id, "core": parent.input.get("coreJobId")})
            jobs = SqlAlchemyJobRepository()
            related = jobs.list_for_engagement(parent.target_id)
            lease = db.session.query(CoreMutationLeaseModel).filter_by(
                engagement_id=parent.target_id).one_or_none()
            digest = job_event_digest(child.events)
            if (locked.rowcount != 1 or jobs.get(parent.id) != parent
                    or jobs.get(plan.id) != plan or jobs.get(child.id) != child
                    or _exact_no_go_apply_child(parent, related, jobs, fenced=True) != child
                    or parent.events[-1].message != "provider append Apply no-GO fenced"
                    or parent.events[-1].data != {
                        "stateSha256": state_sha256, "applyChildJournalSha256": digest}
                    or lease is None or lease.owner_id != parent.input["corePlanId"]
                    or lease.operation != "provider_keyed_edge_append"):
                raise ValueError("no-GO append source changed before close")
            row = db.session.get(JobRunModel, parent.id)
            row.input = {**parent.input, "phase": "unapplied_reconciled"}
            terminal = JobEvent(len(parent.events) + 1, "info",
                "append plan reconciled without mutation", {
                    "stateSha256": state_sha256,
                    "noGoApplyChildJournalSha256": digest,
                })
            db.session.add(JobEventModel(job_id=parent.id, sequence=terminal.sequence,
                level=terminal.level, message=terminal.message, data=terminal.data))
            db.session.delete(lease)
            db.session.commit()
            return jobs.get(parent.id)
        except Exception:
            db.session.rollback()
            raise DeploymentPlanConflictError("no-GO append close was not committed") from None

    def fence_failed_prebinding_keyed_teardown(
        self, *, teardown_parent_id: str, coordinator_job_id: str,
        expected_snapshot: dict, expected_coordinator_journal_sha256: str,
        expected_initial_journal_sha256: str, expected_claim_token: str,
        fence_at: str,
    ):
        """Commit the failed prebinding lease handoff and coordinator marker together.

        The terminal failed initial row is immutable. A lost commit can be
        recognized from the exact fenced lease and fourth coordinator event;
        this method never retries a partial or different history.
        """
        from datetime import datetime
        from sqlalchemy import text

        from app.domain import JobEvent
        from app.services.engagement_teardown import (
            _fingerprint, _parent_id, _valid_keyed_dns_cleanup_manifest,
            _validated_parent_boundary,
        )
        from app.services.provider_keyed_comprehensive_teardown import _same_child
        from app.services.provider_keyed_dns_cleanup_manifest import _require_empty_prebinding_ownership
        from app.services.provider_keyed_initial_continuation import _job_ids
        from app.services.provider_keyed_teardown_quiescence import audit_failed_prebinding_provider_bootstrap
        from app.storage.database import db
        from app.storage.domain_repository import SqlAlchemyDomainRepository
        from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
        from app.storage.models import CoreMutationLeaseModel, JobEventModel

        try:
            moment = datetime.fromisoformat(fence_at)
            if (moment.tzinfo is None or type(expected_snapshot) is not dict
                    or not all(type(value) is str and value for value in (
                        teardown_parent_id, coordinator_job_id,
                        expected_coordinator_journal_sha256,
                        expected_initial_journal_sha256, expected_claim_token))
                    or not _valid_keyed_dns_cleanup_manifest(expected_snapshot)
                    or expected_snapshot["dnsCleanupManifest"]["schema"]
                       != "provider-keyed-empty-dns-prebinding-v1"):
                raise ValueError("failed prebinding handoff arguments differ")
            core_id = expected_snapshot["coreJobId"]
            plan_id = expected_snapshot["providerScopes"][0]["corePlanId"]
            engagement_id = expected_snapshot["engagementId"]
            if (teardown_parent_id != _parent_id(core_id)
                    or coordinator_job_id != f"job-provider-keyed-comprehensive-teardown-{core_id.removeprefix('job-')}"
                    or expected_snapshot["snapshotId"] != _fingerprint({
                        key: value for key, value in expected_snapshot.items() if key != "snapshotId"})):
                raise ValueError("failed prebinding handoff identity differs")
            db.session.rollback()
            locked = db.session.execute(text("""
                UPDATE deployment_plans SET status = status
                WHERE id = :plan AND engagement_id = :engagement
                  AND status = 'applied' AND apply_job_id = :core
            """), {"plan": plan_id, "engagement": engagement_id, "core": core_id})
            if locked.rowcount != 1:
                raise ValueError("applied core plan changed")
            db.session.expire_all()
            jobs = SqlAlchemyJobRepository()
            teardown = jobs.get(teardown_parent_id)
            coordinator = jobs.get(coordinator_job_id)
            core = jobs.get(core_id)
            initial = jobs.get(_job_ids(core_id)[0])
            lease = db.session.query(CoreMutationLeaseModel).filter_by(
                engagement_id=engagement_id).one_or_none()
            snapshot = teardown.input.get("scopeSnapshot") if teardown is not None else None
            if (teardown is None or coordinator is None or core is None or initial is None
                    or snapshot != expected_snapshot
                    or teardown.status != "queued" or teardown.started_at is not None
                    or teardown.finished_at is not None or teardown.input.get("phase") != "queued"
                    or teardown.events != [JobEvent(1, "info", "engagement teardown queued",
                                                    {"snapshotId": snapshot["snapshotId"]})]
                    or _validated_parent_boundary(teardown, jobs) != (core, snapshot)
                    or coordinator.status != "running" or coordinator.finished_at is not None
                    or coordinator.input.get("phase") != "handoff_pending"
                    or coordinator.input.get("scopeSnapshotId") != snapshot["snapshotId"]
                    or coordinator.input.get("providerScopeSha256") != snapshot["providerScopeSha256"]
                    or coordinator.input.get("claimOwner") != "provider-keyed-comprehensive-handoff"
                    or coordinator.input.get("claimToken") != expected_claim_token
                    or datetime.fromisoformat(coordinator.input["claimExpiresAt"]) <= moment
                    or len(coordinator.events) != 3
                    or [event.message for event in coordinator.events] != [
                        "keyed teardown coordinator queued", "keyed teardown coordinator started",
                        "keyed teardown handoff intended"]
                    or [event.data for event in coordinator.events] != [
                        {"snapshotId": snapshot["snapshotId"]}, {}, {}]
                    or job_event_digest(coordinator.events) != expected_coordinator_journal_sha256
                    or not _same_child(coordinator, teardown, core, snapshot)
                    or job_event_digest(initial.events) != expected_initial_journal_sha256
                    or snapshot["dnsCleanupManifest"]["initialJournalSha256"]
                       != expected_initial_journal_sha256
                    or lease is None or lease.owner_id != plan_id
                    or lease.operation != "provider_keyed_initial"):
                raise ValueError("failed prebinding handoff source changed")
            _require_empty_prebinding_ownership(
                engagement_id, jobs, SqlAlchemyDomainRepository(), core_id=core_id)
            audit_failed_prebinding_provider_bootstrap(
                core_id, confirmed_scope=snapshot["providerScopes"][0],
                confirmed_scope_sha256=_fingerprint(snapshot),
                workspace_root=Path(snapshot["providerScopes"][0]["workspace"]),
                job_repository=jobs,
            )
            lease.operation = "provider_keyed_teardown_fence"
            changed = db.session.execute(text("""
                UPDATE job_runs SET input = json_set(
                    input, '$.phase', 'awaiting_inspector_preflight',
                    '$.claimExpiresAt', :fence_at)
                WHERE id = :coordinator AND action = 'provider_keyed_comprehensive_teardown'
                  AND status = 'running' AND finished_at IS NULL
                  AND json_extract(input, '$.phase') = 'handoff_pending'
                  AND json_extract(input, '$.claimOwner') = 'provider-keyed-comprehensive-handoff'
                  AND json_extract(input, '$.claimToken') = :token
            """), {"coordinator": coordinator_job_id, "token": expected_claim_token,
                   "fence_at": fence_at})
            if changed.rowcount != 1:
                raise ValueError("failed prebinding coordinator changed")
            db.session.add(JobEventModel(
                job_id=coordinator_job_id, sequence=4, level="info",
                message="keyed teardown handoff verified; Inspector preflight pending",
                data={"corePlanId": plan_id},
            ))
            db.session.commit()
            return jobs.get(coordinator_job_id)
        except Exception:
            db.session.rollback()
            raise DeploymentPlanConflictError(
                "failed prebinding teardown handoff is unproved") from None

    def begin_private_keyed_core_apply(self, reviewed: DeploymentPlan) -> DeploymentPlan:
        """Atomically reserve a DevTest keyed plan and its exact apply lease.

        A crash after this commit but before job binding is handled by the
        existing interrupted-plan recovery. No Terraform command runs here.
        """
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel, DeploymentPlanModel

        if (db.engine.dialect.name != "sqlite" or reviewed.status != "ready"
                or reviewed.stage != "ready" or reviewed.apply_job_id
                or reviewed.evidence.get("sketchStateSchema") != "provider-keyed-v2"):
            raise DeploymentPlanConflictError("private keyed core plan is not ready")
        try:
            db.session.add(CoreMutationLeaseModel(
                engagement_id=reviewed.engagement_id, owner_id=reviewed.id,
                operation="apply",
            ))
            db.session.flush()  # Take the SQLite writer slot before reading the plan.
            row = DeploymentPlanModel.query.populate_existing().filter_by(
                id=reviewed.id, engagement_id=reviewed.engagement_id,
                status="ready", stage="ready", apply_job_id="", is_current=True,
            ).one_or_none()
            if row is None or _from_model(row) != reviewed:
                raise DeploymentPlanConflictError("reviewed keyed core plan changed")
            row.status = "applying"
            row.stage = "terraform_apply"
            db.session.commit()
            return self.get(reviewed.id) or reviewed
        except IntegrityError as exc:
            db.session.rollback()
            raise DeploymentPlanConflictError("another core mutation is in progress") from exc
        except Exception:
            db.session.rollback()
            raise

    def rollback_unbound_private_keyed_core_apply(self, reviewed: DeploymentPlan) -> None:
        """Release only the exact pre-bind reservation after a synchronous error."""
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel, DeploymentPlanModel

        if db.engine.dialect.name != "sqlite":
            raise DeploymentPlanConflictError("private keyed rollback requires SQLite")
        try:
            # The conditional no-op UPDATE takes the SQLite writer slot. Force
            # fresh reads after it; a cached ORM row is not CAS authority.
            updated = DeploymentPlanModel.query.filter_by(
                id=reviewed.id, engagement_id=reviewed.engagement_id,
                status="applying", stage="terraform_apply", apply_job_id="", is_current=True,
            ).update({"status": "applying"}, synchronize_session=False)
            row = DeploymentPlanModel.query.populate_existing().filter_by(
                id=reviewed.id, engagement_id=reviewed.engagement_id,
            ).one_or_none()
            lease = CoreMutationLeaseModel.query.populate_existing().filter_by(
                engagement_id=reviewed.engagement_id,
            ).one_or_none()
            persisted = _from_model(row) if row is not None else None
            if (updated != 1 or row is None or lease is None or row.engagement_id != reviewed.engagement_id
                    or row.revision_id != reviewed.revision_id
                    or row.status != "applying" or row.stage != "terraform_apply"
                    or row.apply_job_id or row.evidence != reviewed.evidence
                    or row.review != reviewed.review or not row.is_current
                    or persisted.prepared_at != reviewed.prepared_at
                    or persisted.created_at != reviewed.created_at
                    or persisted.error != reviewed.error
                    or lease.owner_id != reviewed.id or lease.operation != "apply"):
                raise DeploymentPlanConflictError("private keyed apply is bound or changed")
            row.status = "ready"
            row.stage = "ready"
            db.session.delete(lease)
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise

    def fail_keyed_core_completion(self, job_id: str, plan_id: str, engagement_id: str) -> None:
        """Publish attention for an uncertain post-apply result without releasing GO."""
        from datetime import datetime, timezone

        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel, DeploymentPlanModel, JobEventModel, JobRunModel

        if db.engine.dialect.name != "sqlite":
            raise DeploymentPlanConflictError("atomic keyed core attention requires SQLite")
        try:
            updated = DeploymentPlanModel.query.filter_by(
                id=plan_id, engagement_id=engagement_id,
                status="applying", apply_job_id=job_id,
            ).update({"stage": "keyed_core_completion_attention"}, synchronize_session=False)
            plan = DeploymentPlanModel.query.get(plan_id)
            lease = CoreMutationLeaseModel.query.filter_by(
                engagement_id=engagement_id, owner_id=plan_id, operation="apply",
            ).one_or_none()
            job = JobRunModel.query.get(job_id)
            from app.storage.job_repository import SqlAlchemyJobRepository
            current = SqlAlchemyJobRepository().get(job_id)
            if (updated != 1 or plan is None or lease is None or job is None or current is None
                    or plan.evidence.get("sketchStateSchema") != "provider-keyed-v2"
                    or current.action != "pilot_standard_rti_guarded_execute"
                    or current.status != "running" or current.finished_at is not None
                    or current.input.get("corePlanId") != plan_id
                    or current.input.get("engagementId") != engagement_id):
                raise DeploymentPlanConflictError("keyed core attention boundary changed")
            db.session.add(JobEventModel(
                job_id=job_id, sequence=len(current.events) + 1, level="error",
                message="keyed core post-apply state could not be verified; reconcile retained infrastructure",
                data={"status": "reconciliation_required", "cleanupRequired": True},
            ))
            job.status = "failed"
            job.finished_at = datetime.now(timezone.utc)
            plan.status = "reconciliation_required"
            plan.stage = "reconciliation_required"
            plan.error = "keyed core post-apply state verification failed; reconcile before retry"
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise

    def finish_keyed_core_success(self, finished) -> None:
        """Publish terminal core success, applied plan, and lease handoff together."""
        from datetime import datetime

        from app.storage.database import db
        from app.storage.job_repository import SqlAlchemyJobRepository
        from app.storage.models import CoreMutationLeaseModel, DeploymentPlanModel, JobEventModel, JobRunModel

        inputs = finished.input if isinstance(finished.input, dict) else {}
        plan_id = inputs.get("corePlanId")
        engagement_id = inputs.get("engagementId")
        if (db.engine.dialect.name != "sqlite" or finished.action != "pilot_standard_rti_guarded_execute"
                or finished.status != "succeeded" or not finished.finished_at
                or not isinstance(plan_id, str) or not plan_id
                or not isinstance(engagement_id, str) or not engagement_id
                or inputs.get("sketchStateSchema") != "provider-keyed-v2"
                or inputs.get("postCoreSketchContinuationEligible") is not False
                or type(inputs.get("providerKeyedDispatchAuthorized")) is not bool
                or not isinstance(inputs.get("inspectorReadiness"), dict)
                or inputs["inspectorReadiness"].get("ready") is not True):
            raise DeploymentPlanConflictError("keyed core completion evidence is invalid")
        try:
            # Lock the plan writer before reading the job and lease; this is
            # one SQLite transaction with no visible success/retag gap.
            updated = DeploymentPlanModel.query.filter_by(
                id=plan_id, engagement_id=engagement_id,
                status="applying", apply_job_id=finished.id,
            ).update({"stage": "keyed_core_completion"}, synchronize_session=False)
            plan = DeploymentPlanModel.query.get(plan_id)
            lease = CoreMutationLeaseModel.query.filter_by(
                engagement_id=engagement_id, owner_id=plan_id, operation="apply",
            ).one_or_none()
            current = SqlAlchemyJobRepository().get(finished.id)
            row = JobRunModel.query.get(finished.id)
            evidence = plan.evidence if plan is not None and isinstance(plan.evidence, dict) else {}
            evidence_sha = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            terminal = finished.events[-1] if finished.events else None
            suffix = finished.events[len(current.events):] if current is not None else []
            if (updated != 1 or plan is None or lease is None or current is None or row is None
                    or evidence.get("sketchStateSchema") != "provider-keyed-v2"
                    or inputs.get("corePlanEvidenceSha256") != evidence_sha
                    or current.action != finished.action or current.status != "running"
                    or current.target != finished.target or current.target_type != finished.target_type
                    or current.target_id != finished.target_id or current.requested_by != finished.requested_by
                    or current.created_at != finished.created_at or current.started_at != finished.started_at
                    or current.finished_at is not None
                    or {key: value for key, value in inputs.items()
                        if key not in {"inspectorReadiness", "postCoreSketchContinuationEligible",
                                       "providerKeyedDispatchAuthorized"}} != current.input
                    or finished.events[:len(current.events)] != current.events
                    or len(finished.events) <= len(current.events)
                    or [event.sequence for event in finished.events] != list(range(1, len(finished.events) + 1))
                    or terminal is None or terminal.message != "pilot Standard RTI run finished"
                    or terminal.data.get("ok") is not True
                    or terminal.data.get("mutationStatus") != "deployed"
                    or terminal.data.get("ansibleStatus") != "validated"
                    or terminal.data.get("finalCleanupStatus") != "pending_operator_teardown"):
                raise DeploymentPlanConflictError("keyed core completion changed")
            # The write lock is already held. Re-read and parse the exact
            # reviewed post-apply state before any terminal row becomes visible.
            seal = _read_keyed_core_state_seal(evidence, current.input)
            if (len([event for event in finished.events if event.message == _OCI_CORE_STATE_SEAL_MESSAGE]) != 1
                    or len(suffix) < 2
                    or suffix[-2].message != _OCI_CORE_STATE_SEAL_MESSAGE
                    or suffix[-2].level != "info"
                    or suffix[-2].data != _keyed_core_state_seal_event_data(seal)):
                raise DeploymentPlanConflictError("keyed core post-apply state seal changed")
            for event in finished.events[len(current.events):]:
                db.session.add(JobEventModel(
                    job_id=finished.id, sequence=event.sequence, level=event.level,
                    message=event.message, data=event.data,
                ))
            row.status = "succeeded"
            row.input = inputs
            row.artifact_refs = finished.artifact_refs
            row.finished_at = datetime.fromisoformat(finished.finished_at)
            plan.status = "applied"
            plan.stage = "applied"
            plan.is_current = False
            lease.operation = "provider_keyed_initial"
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise

    def retain_failed_keyed_apply_fence(self, plan: DeploymentPlan) -> None:
        """Keep the exact v2 apply lease after a failed/uncertain core worker."""
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel, DeploymentPlanModel

        try:
            updated = DeploymentPlanModel.query.filter_by(
                id=plan.id, engagement_id=plan.engagement_id,
                status="applying", apply_job_id=plan.apply_job_id,
            ).update({
                "status": "reconciliation_required", "stage": "reconciliation_required",
                "error": "keyed core apply requires reconciliation before another mutation",
            }, synchronize_session=False)
            lease = CoreMutationLeaseModel.query.filter_by(
                engagement_id=plan.engagement_id, owner_id=plan.id, operation="apply",
            ).one_or_none()
            if (updated != 1 or lease is None or not plan.apply_job_id
                    or plan.evidence.get("sketchStateSchema") != "provider-keyed-v2"):
                raise DeploymentPlanConflictError("keyed core apply fence changed")
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise

    def reserve_keyed_core_apply_job(self, job, *, expected_evidence: dict,
                                     expected_revision_id: str) -> None:
        """Insert a v2 queued core job and bind its applying plan atomically.

        This is an internal DevTest reservation, not permission to run Terraform.
        The plan-owned apply lease remains held across the transaction.
        """
        from datetime import datetime

        from app.core.request_identity import current_request_identity
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel, DeploymentPlanModel, JobEventModel, JobRunModel

        if db.engine.dialect.name != "sqlite":
            raise DeploymentPlanConflictError("atomic keyed core reservation requires SQLite")
        inputs = job.input if isinstance(job.input, dict) else {}
        plan_id = inputs.get("corePlanId")
        engagement_id = inputs.get("engagementId")
        if (job.action != "pilot_standard_rti_guarded_execute" or job.status != "queued"
                or job.started_at is not None or job.finished_at is not None
                or job.target_type != "oci_compartment" or not job.target_id
                or inputs.get("sketchStateSchema") != "provider-keyed-v2"
                or not isinstance(expected_evidence, dict)
                or not isinstance(expected_revision_id, str) or not expected_revision_id
                or not isinstance(plan_id, str) or not plan_id
                or not isinstance(engagement_id, str) or not engagement_id
                or len(job.events) != 1 or job.events[0].sequence != 1
                or job.events[0].level != "info"
                or job.events[0].message != "pilot Standard RTI run queued"
                or job.artifact_refs != []):
            raise DeploymentPlanConflictError("keyed core reservation input is invalid")
        try:
            # The INSERT takes the SQLite writer lock before checking the plan.
            # A second reservation rolls back its own job and event on CAS loss.
            requester = current_request_identity()
            db.session.add(JobRunModel(
                id=job.id, action=job.action, status=job.status, target=job.target,
                target_type=job.target_type, target_id=job.target_id,
                requested_by=requester.username if requester is not None else job.requested_by,
                input=inputs, artifact_refs=job.artifact_refs,
                created_at=datetime.fromisoformat(job.created_at),
            ))
            db.session.add(JobEventModel(
                job_id=job.id, sequence=1, level=job.events[0].level,
                message=job.events[0].message, data=job.events[0].data,
            ))
            db.session.flush()
            updated = DeploymentPlanModel.query.filter_by(
                id=plan_id, engagement_id=engagement_id, status="applying", apply_job_id="",
            ).update({"apply_job_id": job.id}, synchronize_session=False)
            plan = DeploymentPlanModel.query.get(plan_id)
            lease = CoreMutationLeaseModel.query.filter_by(
                engagement_id=engagement_id, owner_id=plan_id, operation="apply",
            ).one_or_none()
            evidence = plan.evidence if plan is not None and isinstance(plan.evidence, dict) else {}
            target = evidence.get("target") if isinstance(evidence.get("target"), dict) else {}
            authorization = evidence.get("sketchAuthorization") if isinstance(evidence.get("sketchAuthorization"), dict) else {}
            mixed = authorization.get("kind") == "bounded-mixed-post-core-v1"
            if mixed:
                scopes = authorization.get("providerScopes")
                mixed_scopes_valid = (isinstance(scopes, list) and len(scopes) == 2
                                      and all(isinstance(scope, dict) for scope in scopes)
                                      and [scope.get("provider") for scope in scopes] ==
                                      ["digitalocean", "linode"]
                                      and all(isinstance(scope.get("source"), dict)
                                              and isinstance(scope["source"].get("revision"), str)
                                              and scope["source"]["revision"]
                                              and isinstance(scope["source"].get("templateSha256"), str)
                                              and scope["source"]["templateSha256"]
                                              and isinstance(scope.get("chain"), dict)
                                              and isinstance(scope["chain"].get("id"), str)
                                              and scope["chain"]["id"] in (evidence.get("pendingSketchChainIds")
                                                                             if isinstance(evidence.get("pendingSketchChainIds"), list)
                                                                             else [])
                                              and scope["chain"].get("fingerprint") ==
                                              (evidence.get("pendingSketchChainFingerprints")
                                               if isinstance(evidence.get("pendingSketchChainFingerprints"), dict)
                                               else {}).get(scope["chain"]["id"])
                                              for scope in scopes)
                                      and scopes[0]["chain"]["id"] != scopes[1]["chain"]["id"])
                reviewed_source = scopes[0]["source"] if mixed_scopes_valid else {}
            else:
                mixed_scopes_valid = True
                reviewed_source = authorization.get("source") if isinstance(authorization.get("source"), dict) else {}
            source_pin = inputs.get("providerKeyedSourcePin") if isinstance(inputs.get("providerKeyedSourcePin"), dict) else {}
            job_target = inputs.get("target") if isinstance(inputs.get("target"), dict) else {}
            reviewed_ids = evidence.get("pendingSketchChainIds")
            reviewed_fingerprints = evidence.get("pendingSketchChainFingerprints")
            initial_event = job.events[0].data
            if (updated != 1 or plan is None or lease is None
                    or plan.revision_id != expected_revision_id
                    or evidence != expected_evidence
                    or inputs.get("corePlanEvidenceSha256") != hashlib.sha256(
                        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest()
                    or evidence.get("sketchStateSchema") != "provider-keyed-v2"
                    or not isinstance(reviewed_ids, list) or len(reviewed_ids) != 2
                    or any(not isinstance(value, str) or not value for value in reviewed_ids)
                    or len(set(reviewed_ids)) != 2
                    or not isinstance(reviewed_fingerprints, dict)
                    or set(reviewed_fingerprints) != set(reviewed_ids)
                    or any(not isinstance(value, str) or not value for value in reviewed_fingerprints.values())
                    or inputs.get("pendingSketchChainIds") != reviewed_ids
                    or inputs.get("pendingSketchChainFingerprints") != reviewed_fingerprints
                    or not mixed_scopes_valid
                    or set(source_pin) != {"root", "revision", "templateSha256"}
                    or not isinstance(source_pin.get("root"), str)
                    or not source_pin["root"].startswith("/")
                    or source_pin.get("revision") != reviewed_source.get("revision")
                    or source_pin.get("templateSha256") != reviewed_source.get("templateSha256")
                    or any(job_target.get(key) != target.get(key)
                           for key in ("name", "region", "compartmentId", "auth"))
                    or job.target != f"oci-compartment:{target.get('name')}"
                    or job.target_id != target.get("compartmentId")
                    or not target.get("name") or not target.get("compartmentId")
                    or not isinstance(inputs.get("workspaceDir"), str)
                    or inputs.get("workspaceDir") != evidence.get("runDirectory")
                    or inputs.get("workspace") != "barragan-pilot-standard-rti"
                    or initial_event != {
                        "workspace": "barragan-pilot-standard-rti",
                        "workspaceDir": inputs["workspaceDir"],
                        "target": target["name"], "region": target.get("region"),
                    }):
                raise DeploymentPlanConflictError("reviewed keyed core plan or lease changed")
            db.session.commit()
        except IntegrityError as exc:
            db.session.rollback()
            raise DeploymentPlanConflictError("keyed core job identity is already reserved") from exc
        except Exception:
            db.session.rollback()
            raise

    def get(self, plan_id: str) -> DeploymentPlan | None:
        from app.storage.models import DeploymentPlanModel

        row = DeploymentPlanModel.query.get(plan_id)
        return _from_model(row) if row is not None else None

    def current(self, engagement_id: str) -> DeploymentPlan | None:
        from app.storage.models import DeploymentPlanModel

        row = (
            DeploymentPlanModel.query.filter_by(engagement_id=engagement_id, is_current=True)
            .order_by(DeploymentPlanModel.created_at.desc())
            .first()
        )
        return _from_model(row) if row is not None else None

    def save(self, plan: DeploymentPlan) -> DeploymentPlan:
        from app.storage.database import db
        from app.storage.models import DeploymentPlanModel

        if plan.status not in DEPLOYMENT_PLAN_STATUSES:
            raise ValueError(f"unknown deployment plan status: {plan.status}")
        row = DeploymentPlanModel.query.get(plan.id)
        if row is None:
            row = DeploymentPlanModel(id=plan.id, engagement_id=plan.engagement_id)
            db.session.add(row)
        row.revision_id = plan.revision_id
        row.status = plan.status
        row.stage = plan.stage
        row.review = plan.review
        row.evidence = plan.evidence
        row.prepared_at = _parse_datetime(plan.prepared_at)
        row.apply_job_id = plan.apply_job_id
        row.error = plan.error
        row.is_current = plan.status not in {"invalidated", "applied"}
        db.session.commit()
        return self.get(plan.id) or plan

    def acquire(self, engagement_id: str, owner_id: str, operation: str) -> bool:
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel

        try:
            db.session.add(CoreMutationLeaseModel(engagement_id=engagement_id, owner_id=owner_id, operation=operation))
            db.session.commit()
            return True
        except IntegrityError as exc:
            db.session.rollback()
            current = CoreMutationLeaseModel.query.get(engagement_id)
            if current is not None and current.owner_id == owner_id and current.operation == operation:
                return False
            raise DeploymentPlanConflictError("another core mutation is already in progress") from exc

    def release(self, engagement_id: str, owner_id: str) -> None:
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel

        CoreMutationLeaseModel.query.filter_by(engagement_id=engagement_id, owner_id=owner_id).delete()
        db.session.commit()

    def retag(self, engagement_id: str, owner_id: str, operation: str) -> None:
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel

        updated = CoreMutationLeaseModel.query.filter_by(
            engagement_id=engagement_id,
            owner_id=owner_id,
        ).update({"operation": operation})
        if updated != 1:
            db.session.rollback()
            raise DeploymentPlanConflictError("core mutation lease is no longer owned by this deployment plan")
        db.session.commit()

    def retag_if_operation(self, engagement_id: str, owner_id: str,
                           expected_operation: str, next_operation: str) -> None:
        """Atomically change only an exactly owned, expected lease operation.

        The row and owner stay in place throughout. This is a primitive for a
        future fenced v2 handoff, not a teardown authorization by itself.
        """
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel

        if any(type(value) is not str or not value or value != value.strip()
               for value in (engagement_id, owner_id, expected_operation, next_operation)):
            raise ValueError("core mutation lease retag arguments are invalid")
        if expected_operation == next_operation:
            raise ValueError("core mutation lease retag requires a new operation")
        updated = CoreMutationLeaseModel.query.filter_by(
            engagement_id=engagement_id, owner_id=owner_id, operation=expected_operation,
        ).update({"operation": next_operation}, synchronize_session=False)
        if updated != 1:
            db.session.rollback()
            raise DeploymentPlanConflictError("core mutation lease owner or operation changed")
        db.session.commit()

    def complete_apply(self, plan: DeploymentPlan, *, next_operation: str | None) -> DeploymentPlan:
        """Commit terminal core status and its plan-owned lease in one transaction."""
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel, DeploymentPlanModel

        if plan.status not in {"applied", "reconciliation_required"} or (
            next_operation is not None and (
                plan.status != "applied" or next_operation not in {"post_core", "provider_keyed_initial"}
            )
        ):
            raise ValueError("core apply completion transition is invalid")
        try:
            row = DeploymentPlanModel.query.get(plan.id)
            lease = CoreMutationLeaseModel.query.filter_by(
                engagement_id=plan.engagement_id, owner_id=plan.id, operation="apply",
            ).one_or_none()
            if row is None or row.engagement_id != plan.engagement_id or row.status != "applying" or lease is None:
                raise DeploymentPlanConflictError("core apply plan or mutation lease changed before completion")
            row.status = plan.status
            row.stage = plan.stage
            row.is_current = plan.status != "applied"
            if next_operation is None:
                db.session.delete(lease)
            else:
                lease.operation = next_operation
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return self.get(plan.id) or plan

    def invalidate_current(self, engagement_id: str, except_id: str = "") -> None:
        from app.storage.database import db
        from app.storage.models import DeploymentPlanModel

        query = DeploymentPlanModel.query.filter_by(engagement_id=engagement_id, is_current=True)
        if except_id:
            query = query.filter(DeploymentPlanModel.id != except_id)
        for row in query.all():
            if row.status in {"ready", "no_changes", "failed"}:
                row.status = "invalidated"
                row.stage = "invalidated"
                row.is_current = False
        db.session.commit()


def _from_model(row) -> DeploymentPlan:
    return DeploymentPlan(
        id=row.id,
        engagement_id=row.engagement_id,
        revision_id=row.revision_id,
        status=row.status,
        stage=row.stage,
        review=dict(row.review or {}),
        evidence=dict(row.evidence or {}),
        prepared_at=_format_datetime(row.prepared_at),
        created_at=_format_datetime(row.created_at),
        updated_at=_format_datetime(row.updated_at),
        apply_job_id=row.apply_job_id or "",
        error=row.error or "",
    )


def _format_datetime(value) -> str:
    return value.isoformat() if value is not None else ""


def _parse_datetime(value: str):
    from datetime import datetime

    return datetime.fromisoformat(value) if value else None
