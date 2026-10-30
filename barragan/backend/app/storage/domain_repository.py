# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol


@dataclass(frozen=True)
class StoredDomainAsset:
    id: str
    domain_name: str
    registrar: str
    registration_started_at: str
    expiration_at: str
    auto_renew: bool
    provider_status: str
    notes: str
    risk_status: str
    risk_flags: list[str]
    cooldown_until: str
    assignable_override: bool
    catalog_state: str
    metadata: dict[str, Any]
    last_synced_at: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class StoredDomainAssignment:
    id: int | None
    domain_id: str
    engagement_id: str
    engagement_name: str
    purpose: str
    status: str
    notes: str
    assigned_by: str
    released_by: str
    assigned_at: str
    released_at: str | None
    purpose_tags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class StoredDomainDnsSnapshot:
    id: int | None
    domain_id: str
    provider: str
    hosts: list[dict[str, Any]]
    source: str
    sync_job_id: str
    fetched_at: str


@dataclass(frozen=True)
class StoredDomainDnsRecordOwnership:
    id: int
    domain_id: str
    assignment_id: int
    engagement_id: str
    creating_job_id: str
    snapshot_id: int
    record: dict[str, Any]
    retired_at: str | None


class DomainAssignmentFenceError(ValueError):
    """A queued or running keyed teardown owns the assignment boundary."""


class DomainRepository(Protocol):
    def list_assets(self) -> list[StoredDomainAsset]:
        ...

    def get_asset(self, domain_id: str) -> StoredDomainAsset | None:
        ...

    def get_asset_by_name(self, domain_name: str) -> StoredDomainAsset | None:
        ...

    def save_asset(self, asset: StoredDomainAsset) -> StoredDomainAsset:
        ...

    def list_assignments(self, domain_id: str | None = None, engagement_id: str | None = None) -> list[StoredDomainAssignment]:
        ...

    def save_assignment(self, assignment: StoredDomainAssignment) -> StoredDomainAssignment:
        ...

    def list_snapshots(self, domain_id: str) -> list[StoredDomainDnsSnapshot]:
        ...

    def save_snapshot(self, snapshot: StoredDomainDnsSnapshot) -> StoredDomainDnsSnapshot:
        ...

    def list_record_ownership(self, domain_id: str, *, active_only: bool = False) -> list[StoredDomainDnsRecordOwnership]:
        ...


class SqlAlchemyDomainRepository:
    def list_assets(self) -> list[StoredDomainAsset]:
        from app.storage.models import DomainAssetModel

        rows = DomainAssetModel.query.order_by(DomainAssetModel.domain_name.asc()).all()
        return [_asset_from_model(row) for row in rows]

    def get_asset(self, domain_id: str) -> StoredDomainAsset | None:
        from app.storage.models import DomainAssetModel

        row = DomainAssetModel.query.session.get(DomainAssetModel, domain_id)
        if row is None:
            return None
        return _asset_from_model(row)

    def get_asset_by_name(self, domain_name: str) -> StoredDomainAsset | None:
        from app.storage.models import DomainAssetModel

        row = DomainAssetModel.query.filter_by(domain_name=domain_name).first()
        if row is None:
            return None
        return _asset_from_model(row)

    def save_asset(self, asset: StoredDomainAsset) -> StoredDomainAsset:
        from app.storage.database import db
        from app.storage.models import DomainAssetModel

        row = DomainAssetModel.query.session.get(DomainAssetModel, asset.id)
        if row is None:
            row = DomainAssetModel(id=asset.id)
            db.session.add(row)
        row.domain_name = asset.domain_name
        row.registrar = asset.registrar
        row.registration_started_at = asset.registration_started_at
        row.expiration_at = asset.expiration_at
        row.auto_renew = asset.auto_renew
        row.provider_status = asset.provider_status
        row.notes = asset.notes
        row.risk_status = asset.risk_status
        row.risk_flags = asset.risk_flags
        row.cooldown_until = asset.cooldown_until
        row.assignable_override = asset.assignable_override
        row.catalog_state = asset.catalog_state
        row.metadata_json = asset.metadata
        row.last_synced_at = _parse_datetime(asset.last_synced_at) if asset.last_synced_at else None
        if asset.created_at:
            row.created_at = _parse_datetime(asset.created_at)
        if asset.updated_at:
            row.updated_at = _parse_datetime(asset.updated_at)
        db.session.commit()
        return _asset_from_model(row)

    def list_assignments(self, domain_id: str | None = None, engagement_id: str | None = None) -> list[StoredDomainAssignment]:
        from app.storage.models import DomainAssignmentModel

        query = DomainAssignmentModel.query
        if domain_id:
            query = query.filter_by(domain_id=domain_id)
        if engagement_id:
            query = query.filter_by(engagement_id=engagement_id)
        rows = query.order_by(DomainAssignmentModel.assigned_at.desc(), DomainAssignmentModel.id.desc()).all()
        return [_assignment_from_model(row) for row in rows]

    def save_assignment(self, assignment: StoredDomainAssignment) -> StoredDomainAssignment:
        return self.save_assignments([assignment])[0]

    def save_assignments(
        self, assignments: list[StoredDomainAssignment],
    ) -> list[StoredDomainAssignment]:
        """Public direct-write path: domain flock precedes the SQLite writer."""
        from app.services.engagement_dns import _dns01_domain_lock

        if not assignments or len({row.domain_id for row in assignments}) != 1:
            raise ValueError("assignment batch must concern one domain")
        with _dns01_domain_lock(assignments[0].domain_id):
            return self._save_assignments_locked(assignments)

    def _save_assignments_locked(
        self, assignments: list[StoredDomainAssignment],
    ) -> list[StoredDomainAssignment]:
        """Caller holds domain flock; fence and change membership atomically."""
        from sqlalchemy import update
        from app.storage.database import db
        from app.storage.models import (
            CoreMutationLeaseModel, DomainAssetModel, DomainAssignmentModel, JobRunModel,
        )

        if (not assignments or len({row.domain_id for row in assignments}) != 1
                or len({row.id for row in assignments if row.id is not None})
                != sum(row.id is not None for row in assignments)):
            raise ValueError("assignment batch identity differs")
        domain_id = assignments[0].domain_id
        try:
            db.session.rollback()
            writer = db.session.execute(update(DomainAssetModel).where(
                DomainAssetModel.id == domain_id,
            ).values(registrar=DomainAssetModel.registrar,
                     updated_at=DomainAssetModel.updated_at))
            if writer.rowcount != 1:
                raise ValueError("domain asset is unavailable")
            db.session.expire_all()
            prior = []
            for assignment in assignments:
                row = (db.session.get(DomainAssignmentModel, assignment.id)
                       if assignment.id is not None else None)
                if assignment.id is not None and (row is None or row.domain_id != domain_id):
                    raise ValueError("assignment identity changed")
                prior.append(row)
            active = DomainAssignmentModel.query.filter_by(
                domain_id=domain_id, status="active").all()
            affected: set[str] = set()
            for wanted, old in zip(assignments, prior, strict=True):
                was_active = old is not None and old.status == "active"
                will_be_active = wanted.status == "active"
                if (was_active != will_be_active
                        or (was_active and old.engagement_id != wanted.engagement_id)):
                    if was_active:
                        affected.add(old.engagement_id)
                    if will_be_active:
                        affected.add(wanted.engagement_id)
                        affected.update(row.engagement_id for row in active)
            if affected:
                append_lease = CoreMutationLeaseModel.query.filter(
                    CoreMutationLeaseModel.engagement_id.in_(affected),
                    CoreMutationLeaseModel.operation == "provider_keyed_mixed_append",
                ).first()
                if append_lease is not None:
                    raise DomainAssignmentFenceError(
                        "domain assignment is unavailable during paired edge append")
                parents = JobRunModel.query.filter(
                    JobRunModel.target_id.in_(affected),
                    JobRunModel.action == "engagement_comprehensive_teardown",
                    JobRunModel.status.in_(("queued", "running")),
                ).all()
                if any(isinstance(parent.input, dict)
                       and isinstance(parent.input.get("scopeSnapshot"), dict)
                       and "providerScopes" in parent.input["scopeSnapshot"]
                       for parent in parents):
                    raise DomainAssignmentFenceError(
                        "domain assignment is fenced by keyed engagement teardown")
            saved = []
            for wanted, row in zip(assignments, prior, strict=True):
                if row is None:
                    row = DomainAssignmentModel()
                    db.session.add(row)
                row.domain_id = domain_id
                row.engagement_id = wanted.engagement_id
                row.engagement_name = wanted.engagement_name
                row.purpose = wanted.purpose
                row.purpose_tags = list(wanted.purpose_tags or [])
                row.status = wanted.status
                row.notes = wanted.notes
                row.assigned_by = wanted.assigned_by
                row.released_by = wanted.released_by
                row.assigned_at = _parse_datetime(wanted.assigned_at)
                row.released_at = _parse_datetime(wanted.released_at) if wanted.released_at else None
                saved.append(row)
            db.session.commit()
            return [_assignment_from_model(row) for row in saved]
        except Exception:
            db.session.rollback()
            raise

    def list_snapshots(self, domain_id: str) -> list[StoredDomainDnsSnapshot]:
        from app.storage.models import DomainDnsSnapshotModel

        rows = (
            DomainDnsSnapshotModel.query.filter_by(domain_id=domain_id)
            .order_by(DomainDnsSnapshotModel.fetched_at.desc(), DomainDnsSnapshotModel.id.desc())
            .all()
        )
        return [_snapshot_from_model(row) for row in rows]

    def save_snapshot(self, snapshot: StoredDomainDnsSnapshot) -> StoredDomainDnsSnapshot:
        from app.storage.database import db
        from app.storage.models import DomainDnsSnapshotModel

        row = DomainDnsSnapshotModel()
        db.session.add(row)
        row.domain_id = snapshot.domain_id
        row.provider = snapshot.provider
        row.hosts = snapshot.hosts
        row.source = snapshot.source
        row.sync_job_id = snapshot.sync_job_id
        row.fetched_at = _parse_datetime(snapshot.fetched_at)
        db.session.commit()
        return _snapshot_from_model(row)

    def list_record_ownership(self, domain_id: str, *, active_only: bool = False) -> list[StoredDomainDnsRecordOwnership]:
        from app.storage.models import DomainDnsRecordOwnershipModel

        query = DomainDnsRecordOwnershipModel.query.filter_by(domain_id=domain_id)
        if active_only:
            query = query.filter_by(retired_at=None)
        rows = query.order_by(DomainDnsRecordOwnershipModel.id).all()
        return [StoredDomainDnsRecordOwnership(
            id=row.id,
            domain_id=row.domain_id, assignment_id=row.assignment_id,
            engagement_id=row.engagement_id, creating_job_id=row.creating_job_id,
            snapshot_id=row.snapshot_id, record=dict(row.record),
            retired_at=_format_datetime(row.retired_at) if row.retired_at else None,
        ) for row in rows]

    def complete_dns_apply(
        self, *, snapshot: StoredDomainDnsSnapshot, assignment_id: int,
        engagement_id: str, job_id: str, owned_records: list[dict[str, Any]],
        accepted_sequence: int, fresh_fingerprint: str,
    ) -> StoredDomainDnsSnapshot:
        """Commit the provider read, proven ownership and terminal job in one SQLite transaction."""
        from sqlalchemy import update
        from app.services.engagement_dns import (
            _canonical_record, _new_record_candidates, _record_from_provider,
            dns_record_fingerprint,
        )
        from app.storage.database import db
        from app.storage.models import (
            DomainAssignmentModel, DomainDnsRecordOwnershipModel, DomainDnsSnapshotModel,
            JobEventModel, JobRunModel,
        )

        try:
            # Take SQLite's writer slot before reading authority. All assignment
            # transfers must wait until this publication commits or rolls back.
            db.session.rollback()
            locked = db.session.execute(
                update(DomainAssignmentModel)
                .where(DomainAssignmentModel.id == assignment_id,
                       DomainAssignmentModel.domain_id == snapshot.domain_id,
                       DomainAssignmentModel.engagement_id == engagement_id,
                       DomainAssignmentModel.status == "active")
                .values(status="active")
            )
            if locked.rowcount != 1:
                raise ValueError("domain assignment changed before DNS ownership publication")
            assignment = db.session.get(DomainAssignmentModel, assignment_id)
            if (assignment is None or assignment.domain_id != snapshot.domain_id
                    or assignment.engagement_id != engagement_id or assignment.status != "active"):
                raise ValueError("domain assignment changed before DNS ownership publication")
            active_assignments = DomainAssignmentModel.query.filter_by(domain_id=snapshot.domain_id, status="active").all()
            if len(active_assignments) != 1 or active_assignments[0].id != assignment_id:
                raise ValueError("domain has competing active assignments")
            job = db.session.get(JobRunModel, job_id)
            if (job is None or job.action != "engagement_dns_apply" or job.status != "running"
                    or job.target_id != engagement_id or job.input.get("domainId") != snapshot.domain_id):
                raise ValueError("DNS apply job changed before ownership publication")
            accepted = JobEventModel.query.filter_by(job_id=job_id, sequence=accepted_sequence).one_or_none()
            intent = JobEventModel.query.filter_by(job_id=job_id, sequence=accepted_sequence - 1).one_or_none()
            if (accepted is None or accepted.message != "Namecheap DNS setHosts accepted"
                    or accepted.data.get("assignmentId") != assignment_id
                    or intent is None or intent.message != "Namecheap DNS setHosts intended"
                    or intent.data.get("assignmentId") != assignment_id):
                raise ValueError("DNS apply accepted marker missing")
            before = [_record_from_provider(record) for record in intent.data.get("beforeRecords", [])]
            submitted = [_record_from_provider(record) for record in intent.data.get("submittedRecords", [])]
            refreshed = [_record_from_provider(record) for record in snapshot.hosts]
            candidates = _new_record_candidates(before, submitted)
            if (dns_record_fingerprint(before) != job.input.get("currentFingerprint")
                    or dns_record_fingerprint(submitted) != intent.data.get("submittedFingerprint")
                    or accepted.data.get("submittedFingerprint") != intent.data.get("submittedFingerprint")
                    or [record.to_dict(include_host_id=False) for record in candidates] != intent.data.get("candidateRecords")
                    or dns_record_fingerprint(refreshed) != fresh_fingerprint
                    or fresh_fingerprint != intent.data.get("submittedFingerprint")):
                raise ValueError("DNS apply provider proof differs from persisted journal")
            prior_active = DomainDnsRecordOwnershipModel.query.filter_by(
                domain_id=snapshot.domain_id, retired_at=None,
            ).all()
            if any(row.assignment_id != assignment_id or row.engagement_id != engagement_id
                   for row in prior_active):
                raise ValueError("domain has active DNS ownership from another assignment")
            replacements = intent.data.get("replacementCandidates", [])
            if not isinstance(replacements, list):
                raise ValueError("DNS replacement journal is invalid")
            replacement_after = []
            seen_prior_ids: set[int] = set()
            for entry in replacements:
                if not isinstance(entry, dict) or type(entry.get("priorOwnershipId")) is not int:
                    raise ValueError("DNS replacement journal is invalid")
                prior_id = entry["priorOwnershipId"]
                if prior_id in seen_prior_ids:
                    raise ValueError("DNS replacement ownership is duplicated")
                seen_prior_ids.add(prior_id)
                prior = next((row for row in prior_active if row.id == prior_id), None)
                if prior is None:
                    raise ValueError("DNS replacement prior ownership is unavailable")
                before_key = _canonical_record(entry.get("beforeRecord", {}))
                after_key = _canonical_record(entry.get("afterRecord", {}))
                slot = (before_key["name"], before_key["type"])
                before_slot = [row for row in before if (row.name.lower(), row.record_type) == slot]
                submitted_slot = [row for row in submitted if (row.name.lower(), row.record_type) == slot]
                if (len(before_slot) != 1 or len(submitted_slot) != 1
                        or _canonical_record(before_slot[0]) != before_key
                        or _canonical_record(submitted_slot[0]) != after_key
                        or _canonical_record(prior.record) != before_key
                        or before_key == after_key):
                    raise ValueError("DNS replacement does not match unique owned slot")
                source_job = db.session.get(JobRunModel, prior.creating_job_id)
                source_snapshot = db.session.get(DomainDnsSnapshotModel, prior.snapshot_id)
                if (source_job is None or source_job.action != "engagement_dns_apply"
                        or source_job.status != "succeeded" or source_job.target_id != engagement_id
                        or source_job.input.get("domainId") != snapshot.domain_id
                        or source_snapshot is None or source_snapshot.sync_job_id != prior.creating_job_id
                        or sum(_canonical_record(record) == before_key for record in source_snapshot.hosts) != 1
                        or not JobEventModel.query.filter_by(
                            job_id=prior.creating_job_id,
                            message="Namecheap DNS setHosts completed with full desired host list",
                        ).filter(JobEventModel.data["snapshotId"].as_integer() == prior.snapshot_id).first()):
                    raise ValueError("DNS replacement lacks creating-job/provider-snapshot proof")
                replacement_after.append(entry["afterRecord"])
            expected_owned = []
            for candidate in [*candidates, *[_record_from_provider(row) for row in replacement_after]]:
                key = (candidate.name.lower(), candidate.record_type)
                slot = [record for record in refreshed if (record.name.lower(), record.record_type) == key]
                if len(slot) == 1 and _canonical_record(slot[0]) == _canonical_record(candidate):
                    expected_owned.append(slot[0].to_dict())
            if sorted(owned_records, key=str) != sorted(expected_owned, key=str):
                raise ValueError("DNS owned records differ from verified provider snapshot")
            # A later verified whole-zone edit can replace or remove an owned
            # tuple. Retire the old receipt; only a proven unique replacement
            # in the same name/type slot receives a new ownership receipt.
            for existing in prior_active:
                if not any(_canonical_record(record) == _canonical_record(existing.record)
                           for record in refreshed):
                    existing.retired_at = datetime.now(timezone.utc)
            row = DomainDnsSnapshotModel(
                domain_id=snapshot.domain_id, provider=snapshot.provider, hosts=snapshot.hosts,
                source=snapshot.source, sync_job_id=job_id, fetched_at=_parse_datetime(snapshot.fetched_at),
            )
            db.session.add(row)
            db.session.flush()
            for record in owned_records:
                db.session.add(DomainDnsRecordOwnershipModel(
                    domain_id=snapshot.domain_id, assignment_id=assignment_id,
                    engagement_id=engagement_id, creating_job_id=job_id,
                    snapshot_id=row.id, record=record,
                ))
            later = JobEventModel.query.filter(JobEventModel.job_id == job_id, JobEventModel.sequence > accepted_sequence).order_by(JobEventModel.sequence).all()
            if any(event.sequence != accepted_sequence + index or event.message != "Namecheap DNS readback pending"
                   for index, event in enumerate(later, start=1)):
                raise ValueError("DNS apply journal changed before ownership publication")
            terminal_sequence = accepted_sequence + len(later) + 1
            db.session.add(JobEventModel(
                job_id=job_id, sequence=terminal_sequence, level="info",
                message="Namecheap DNS setHosts completed with full desired host list",
                data={"domainId": snapshot.domain_id, "snapshotId": row.id,
                      "freshFingerprint": fresh_fingerprint, "ownedRecordCount": len(owned_records),
                      "mutation": True, "providerReadIsNotConditional": True},
            ))
            job.status = "succeeded"
            job.finished_at = datetime.now(timezone.utc)
            db.session.commit()
            return _snapshot_from_model(row)
        except Exception:
            db.session.rollback()
            raise

    def complete_keyed_owned_dns_cleanup(
        self, *, snapshot: StoredDomainDnsSnapshot, job_id: str,
        accepted_sequence: int | None, fresh_fingerprint: str, authority,
    ) -> StoredDomainDnsSnapshot:
        """Atomically retire only reviewed receipts after a fresh authority read."""
        from sqlalchemy import update
        from app.domain import JobEvent
        from app.services.engagement_dns import (
            _canonical_record, _record_from_provider, dns_record_fingerprint,
            DNS_CLEANUP_ACTION, DNS_APPLY_ACTION,
        )
        from app.storage.database import db
        from app.storage.job_repository import job_event_digest
        from app.storage.models import (
            DomainAssetModel, DomainAssignmentModel, DomainDnsRecordOwnershipModel,
            DomainDnsSnapshotModel, JobEventModel, JobRunModel,
        )

        try:
            db.session.rollback()
            # SQLite has one writer. Fence it before reading any job,
            # assignment or receipt authority in this transaction.
            asset_writer = db.session.execute(update(DomainAssetModel).where(
                DomainAssetModel.id == snapshot.domain_id,
                DomainAssetModel.registrar == "namecheap",
            ).values(registrar="namecheap",
                     updated_at=DomainAssetModel.updated_at))
            if asset_writer.rowcount != 1:
                raise ValueError("Namecheap domain changed")
            db.session.expire_all()
            job = db.session.get(JobRunModel, job_id)
            if (job is None or job.action != DNS_CLEANUP_ACTION
                    or job.input.get("domainId") != snapshot.domain_id):
                raise ValueError("owned DNS child changed")
            saved = job.input
            expected_authority = saved.get("authority")
            assignment_id = expected_authority.get("assignment_id") if type(expected_authority) is dict else None
            if type(assignment_id) is not int:
                raise ValueError("saved domain assignment is unavailable")
            writer = db.session.execute(update(DomainAssignmentModel).where(
                DomainAssignmentModel.id == assignment_id,
                DomainAssignmentModel.domain_id == snapshot.domain_id,
                DomainAssignmentModel.engagement_id == job.target_id,
                DomainAssignmentModel.status == "active",
            ).values(status="active"))
            if writer.rowcount != 1:
                raise ValueError("domain assignment changed")
            if authority() != expected_authority:
                raise ValueError("persisted keyed teardown authority changed")
            if (len(DomainAssignmentModel.query.filter_by(
                    domain_id=snapshot.domain_id, status="active").all()) != 1
                    or db.session.get(DomainAssetModel, snapshot.domain_id) is None
                    or db.session.get(DomainAssetModel, snapshot.domain_id).domain_name
                    != saved.get("domainName")):
                raise ValueError("domain asset or assignment changed")
            plan = saved.get("previewPlan")
            if (type(plan) is not dict or plan.get("engagementId") != job.target_id
                    or plan.get("domainId") != snapshot.domain_id
                    or plan.get("assignmentId") != assignment_id
                    or plan.get("oldEdgeIps") != sorted(expected_authority["edge_public_ips"])
                    or plan.get("blockers") != []):
                raise ValueError("saved cleanup plan changed")
            from hashlib import sha256
            import json
            plan_body = {key: value for key, value in plan.items() if key != "planSha256"}
            plan_digest = "sha256:" + sha256(json.dumps(
                plan_body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if plan_digest != plan.get("planSha256"):
                raise ValueError("saved cleanup plan digest changed")
            events = JobEventModel.query.filter_by(job_id=job_id).order_by(
                JobEventModel.sequence).all()
            if (not events or events[0].sequence != 1
                    or events[0].message != "owned DNS cleanup reserved"
                    or events[0].level != "info"
                    or events[0].data != {"planSha256": plan_digest,
                                          "bindingSha256": expected_authority["binding_sha256"]}):
                raise ValueError("cleanup reservation journal changed")
            active = DomainDnsRecordOwnershipModel.query.filter_by(
                domain_id=snapshot.domain_id, retired_at=None).all()
            plan_owned = plan.get("ownedRecords")
            if (type(plan_owned) is not list or len({row.get("ownershipId")
                    for row in plan_owned if type(row) is dict}) != len(plan_owned)
                    or {row.id for row in active} != {row["ownershipId"] for row in plan_owned}
                    or any(row.assignment_id != assignment_id or row.engagement_id != job.target_id
                           for row in active)):
                raise ValueError("active owned receipt set changed")
            expected_records = {row["ownershipId"]: _canonical_record(row["record"])
                                for row in plan_owned}
            if any(_canonical_record(row.record) != expected_records[row.id] for row in active):
                raise ValueError("owned record changed")
            refreshed = [_record_from_provider(row) for row in snapshot.hosts]
            if dns_record_fingerprint(refreshed) != fresh_fingerprint:
                raise ValueError("provider readback changed")
            if accepted_sequence is None:
                if (job.status != "queued" or saved.get("mutation") is not False
                        or active or len(events) != 1
                        or fresh_fingerprint != plan["zoneFingerprint"]):
                    raise ValueError("read-only cleanup proof changed")
            else:
                if (job.status != "running" or saved.get("mutation") is not True
                        or type(accepted_sequence) is not int or accepted_sequence < 3
                        or len(events) < accepted_sequence
                        or [(row.sequence, row.level, row.message) for row in events[:2]] != [
                            (1, "info", "owned DNS cleanup reserved"),
                            (2, "info", "owned DNS setHosts intended")]
                        or events[accepted_sequence - 1].message != "owned DNS setHosts accepted"
                        or events[accepted_sequence - 1].level != "info"
                        or any(event.sequence != index or event.level != "info"
                               or event.message != "owned DNS readback pending"
                               or event.data != {"attempt": index - 2}
                               for index, event in enumerate(events[2:accepted_sequence - 1], start=3))):
                    raise ValueError("accepted cleanup journal changed")
                intent, accepted = events[1].data, events[accepted_sequence - 1].data
                normal_acceptance = {"planSha256": plan_digest,
                                     "submittedFingerprint": intent.get("submittedFingerprint")}
                if (type(intent) is not dict or type(accepted) is not dict
                        or intent.get("planSha256") != plan_digest
                        or intent.get("bindingSha256") != expected_authority["binding_sha256"]
                        or intent.get("assignmentId") != assignment_id
                        or accepted not in (normal_acceptance,
                            {**normal_acceptance, "recoveredByProviderReadback": True})
                        or (accepted_sequence > 3 and
                            accepted.get("recoveredByProviderReadback") is not True)
                        or intent.get("submittedFingerprint") != fresh_fingerprint
                        or dns_record_fingerprint([_record_from_provider(row)
                            for row in intent.get("beforeRecords", [])]) != plan["zoneFingerprint"]
                        or dns_record_fingerprint([_record_from_provider(row)
                            for row in intent.get("submittedRecords", [])]) != fresh_fingerprint):
                    raise ValueError("full-zone cleanup journal changed")
                proofs = intent.get("receiptProofs")
                if (type(proofs) is not list or len(proofs) != len(active)
                        or [row.get("ownershipId") for row in proofs]
                        != sorted(row.id for row in active)
                        or intent.get("maxRemovedTtl") != max(
                            int(row["record"]["ttl"]) for row in proofs)):
                    raise ValueError("reviewed receipt proofs changed")
                before = [_canonical_record(row) for row in intent["beforeRecords"]]
                submitted = [_canonical_record(row) for row in intent["submittedRecords"]]
                for row in proofs:
                    receipt = next(item for item in active if item.id == row["ownershipId"])
                    if (row.get("record") != expected_records[receipt.id]
                            or row.get("creatingJobId") != receipt.creating_job_id
                            or row.get("snapshotId") != receipt.snapshot_id
                            or before.count(row["record"]) != 1):
                        raise ValueError("receipt source or before-zone changed")
                    before.remove(row["record"])
                    source = db.session.get(JobRunModel, receipt.creating_job_id)
                    source_snapshot = db.session.get(DomainDnsSnapshotModel, receipt.snapshot_id)
                    source_events = JobEventModel.query.filter_by(job_id=receipt.creating_job_id).order_by(
                        JobEventModel.sequence).all()
                    if (source is None or source.action != DNS_APPLY_ACTION
                            or source.status != "succeeded" or source.target_id != job.target_id
                            or source.input.get("domainId") != snapshot.domain_id
                            or source_snapshot is None or source_snapshot.sync_job_id != source.id
                            or source_snapshot.domain_id != snapshot.domain_id
                            or sum(_canonical_record(item) == row["record"]
                                   for item in source_snapshot.hosts) != 1
                            or job_event_digest([JobEvent(event.sequence, event.level,
                                event.message, event.data) for event in source_events])
                            != row.get("creatingJournalSha256")
                            or not any(event.message ==
                                "Namecheap DNS setHosts completed with full desired host list"
                                and event.data.get("snapshotId") == receipt.snapshot_id
                                for event in source_events)):
                        raise ValueError("receipt creating-job proof changed")
                if sorted(before, key=str) != sorted(submitted, key=str):
                    raise ValueError("submitted zone removes more than reviewed receipts")
                if any(event.sequence != index or event.level != "info"
                       or event.message != "owned DNS readback pending"
                       or event.data != {"attempt": index - 3}
                       for index, event in enumerate(events[accepted_sequence:],
                                                     start=accepted_sequence + 1)):
                    raise ValueError("cleanup recovery journal changed")
            row = DomainDnsSnapshotModel(
                domain_id=snapshot.domain_id, provider=snapshot.provider, hosts=snapshot.hosts,
                source=snapshot.source, sync_job_id=job_id,
                fetched_at=_parse_datetime(snapshot.fetched_at),
            )
            db.session.add(row)
            db.session.flush()
            timestamp = datetime.now(timezone.utc)
            for receipt in active:
                receipt.retired_at = timestamp
            db.session.add(JobEventModel(job_id=job_id, sequence=len(events) + 1,
                level="info", message="owned DNS cleanup verified",
                data={"domainId": snapshot.domain_id, "snapshotId": row.id,
                      "freshFingerprint": fresh_fingerprint,
                      "retiredOwnershipIds": sorted(item.id for item in active),
                      "maxRemovedTtl": events[1].data["maxRemovedTtl"]
                      if accepted_sequence is not None else 0}))
            job.status = "succeeded"
            job.finished_at = timestamp
            db.session.commit()
            return _snapshot_from_model(row)
        except Exception:
            db.session.rollback()
            raise


def _asset_from_model(row) -> StoredDomainAsset:
    return StoredDomainAsset(
        id=row.id,
        domain_name=row.domain_name,
        registrar=row.registrar,
        registration_started_at=row.registration_started_at,
        expiration_at=row.expiration_at,
        auto_renew=bool(row.auto_renew),
        provider_status=row.provider_status,
        notes=row.notes,
        risk_status=row.risk_status,
        risk_flags=list(row.risk_flags or []),
        cooldown_until=row.cooldown_until,
        assignable_override=bool(row.assignable_override),
        catalog_state=str(getattr(row, "catalog_state", "auto") or "auto"),
        metadata=dict(row.metadata_json or {}),
        last_synced_at=_format_datetime(row.last_synced_at) if row.last_synced_at else None,
        created_at=_format_datetime(row.created_at),
        updated_at=_format_datetime(row.updated_at),
    )


def _assignment_from_model(row) -> StoredDomainAssignment:
    return StoredDomainAssignment(
        id=row.id,
        domain_id=row.domain_id,
        engagement_id=row.engagement_id,
        engagement_name=row.engagement_name,
        purpose=row.purpose,
        status=row.status,
        notes=row.notes,
        assigned_by=row.assigned_by,
        released_by=row.released_by,
        assigned_at=_format_datetime(row.assigned_at),
        released_at=_format_datetime(row.released_at) if row.released_at else None,
        purpose_tags=_string_list(row.purpose_tags),
    )


def _snapshot_from_model(row) -> StoredDomainDnsSnapshot:
    return StoredDomainDnsSnapshot(
        id=row.id,
        domain_id=row.domain_id,
        provider=row.provider,
        hosts=list(row.hosts or []),
        source=row.source,
        sync_job_id=row.sync_job_id,
        fetched_at=_format_datetime(row.fetched_at),
    )


def _format_datetime(value: datetime | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item is not None]
