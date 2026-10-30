# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant one-shot reservation before Inspector host preparation."""

from __future__ import annotations

import os
from threading import Lock
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from sqlalchemy import text, update

from app.services.provider_keyed_comprehensive_teardown import ACTION, _FENCE, _boundary
from app.services.provider_keyed_inspector_materialize import recover_materialized_keyed_inspector
from app.services.observer_checks import _running_inspector_lifecycle_job
from app.services.provider_keyed_inspector_prepare_binder import (
    InspectorPreparationReceipt, _existing_key_identity, _safe_key_identity,
    _verify_key_pair, bind_owned_keyed_inspector_for_preparation,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_teardown_quiescence import audit_pending_provider_keyed_bootstrap
from app.storage.database import db
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import (
    SqlAlchemyJobRepository, _claimed_apply_journal_matches,
    _parse_datetime, _sqlalchemy_apply_input_conditions, job_event_digest,
)
from app.storage.models import JobEventModel, JobRunModel
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.services.observer_checks import INSPECTOR_RESOURCE_SOURCE
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from app.storage.provider_resource_repository import TERMINAL_RECORD_STATUSES


_OWNER = "provider-keyed-inspector-create"
_PHASE = "inspector_prepare_started"
_ISSUER = object()


class InspectorPreparationIntentAttention(ValueError):
    """The one-shot preparation boundary is uncertain; never replay SSH."""


class InspectorPreparationCapability:
    """Process-local one-use handoff; possession alone is not an SSH authority."""

    __slots__ = ("_receipt", "_journal_sha256", "_expires_at", "_pid", "_used", "_lock")

    def __init__(self, issuer: object, receipt: InspectorPreparationReceipt,
                 journal_sha256: str, expires_at: datetime):
        if issuer is not _ISSUER:
            raise TypeError("Inspector preparation capability cannot be constructed")
        self._receipt = receipt
        self._journal_sha256 = journal_sha256
        self._expires_at = expires_at
        self._pid = os.getpid()
        self._used = False
        self._lock = Lock()

    def consume_for_executor(self) -> tuple[InspectorPreparationReceipt, str]:
        """Consume once; a future executor must additionally recheck live authority."""
        with self._lock:
            if (self._used or os.getpid() != self._pid
                    or datetime.now(timezone.utc) >= self._expires_at):
                raise InspectorPreparationIntentAttention(
                    "Inspector preparation capability is no longer usable")
            self._used = True
            return self._receipt, self._journal_sha256

    def __copy__(self):
        return self

    def __deepcopy__(self, _memo):
        return self

    def __repr__(self) -> str:
        return "<InspectorPreparationCapability one-shot>"


def begin_keyed_inspector_preparation(
    coordinator_job_id: str, engagement_id: str, *, environment: str,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, lease_lookup=None,
    pending_auditor: Callable = audit_pending_provider_keyed_bootstrap,
    key_identity_reader: Callable = _existing_key_identity,
    key_pair_verifier: Callable = _verify_key_pair,
    binder: Callable = bind_owned_keyed_inspector_for_preparation,
    binder_options: dict | None = None,
) -> InspectorPreparationCapability:
    """Persist one nonsecret intent; no SSH, provider write, or settings update."""
    try:
        if environment != "devtest" or db.engine.dialect.name != "sqlite":
            raise ValueError("DevTest SQLite preparation required")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        lookup = lease_lookup or _db_lease_lookup
        if not isinstance(jobs, SqlAlchemyJobRepository) or not isinstance(resources, SqlAlchemyProviderResourceRepository):
            raise ValueError("one SQLAlchemy reservation transaction required")
        receipt = binder(
            coordinator_job_id, engagement_id, environment=environment,
            job_repository=jobs, plan_repository=plans, settings_repository=settings_repo,
            provider_resource_repository=resources, lease_lookup=lookup,
            pending_auditor=pending_auditor,
            key_identity_reader=key_identity_reader, key_pair_verifier=key_pair_verifier,
            **(binder_options or {}),
        )
        if (type(receipt) is not InspectorPreparationReceipt
                or receipt.host_prepare_authorized is not False
                or receipt.engagement_id != engagement_id
                or receipt.coordinator_job_id != coordinator_job_id
                or datetime.fromisoformat(receipt.expires_at) <= datetime.now(timezone.utc)):
            raise ValueError("fresh preparation binder receipt required")

        def authority(phase: str):
            parent, core, snapshot, operation = _boundary(
                jobs.get(coordinator_job_id).input["teardownParentId"], jobs, plans, lookup)
            child = jobs.get(coordinator_job_id)
            settings = settings_repo.get(engagement_id)
            host = resources.get(f"{receipt.provider}:inspector:{receipt.host_id}")
            firewall = resources.get(f"{receipt.provider}:inspector-firewall:{receipt.firewall_id}")
            path, fingerprint = _safe_key_identity(key_identity_reader)
            key_pair_verifier(path, fingerprint)
            if (operation != _FENCE or parent.target_id != engagement_id
                    or child.action != ACTION or child.status != "running"
                    or child.finished_at is not None or child.artifact_refs != []
                    or child.input.get("phase") != phase
                    or child.input.get("claimOwner") != _OWNER
                    or child.input.get("claimToken") != receipt.claim_token
                    or child.input.get("claimClaimedAt") != receipt.claim_claimed_at
                    or child.input.get("scopeSnapshotId") != receipt.scope_snapshot_id
                    or snapshot["snapshotId"] != receipt.scope_snapshot_id
                    or child.input.get("coreJobId") != core.id
                    or child.input.get("corePlanId") != core.input["corePlanId"]
                    or child.input.get("providerScopeSha256") != snapshot["providerScopeSha256"]
                    or child.input.get("mutation") is not True
                    or job_event_digest(child.events) != receipt.journal_sha256
                    or path != receipt.key_path or fingerprint != receipt.key_fingerprint_sha256
                    or settings is None or settings.current_host != {}
                    or host is None or firewall is None
                    or host.status != "preparation_required"
                    or firewall.status != "preparation_required"
                    or host.resource_id != receipt.host_id
                    or firewall.resource_id != receipt.firewall_id
                    or host.metadata.get("publicIp") != receipt.public_ip
                    or _running_inspector_lifecycle_job(jobs, engagement_id) is not None
                    or {
                        row.id for row in resources.list_for_engagement(engagement_id)
                        if str(row.status).lower() not in TERMINAL_RECORD_STATUSES
                        and (str(row.resource_type).startswith("inspector_")
                             or str((row.metadata or {}).get("role", "")).startswith("inspector")
                             or row.source == INSPECTOR_RESOURCE_SOURCE)
                    } != {host.id, firewall.id}
                    or datetime.fromisoformat(child.input["claimExpiresAt"]) <= datetime.now(timezone.utc)
                    or datetime.fromisoformat(receipt.expires_at) <= datetime.now(timezone.utc)):
                raise ValueError("Inspector preparation authority differs")
            return parent, core, snapshot, child, settings, host, firewall

        recover_materialized_keyed_inspector(
            coordinator_job_id, engagement_id, environment=environment,
            job_repository=jobs, plan_repository=plans, settings_repository=settings_repo,
            provider_resource_repository=resources, lease_lookup=lookup,
            pending_auditor=pending_auditor,
        )
        before = authority("inspector_owned_unprepared")
        parent, core, snapshot, child, settings, host, firewall = before
        data = {
            "scopeSnapshotId": snapshot["snapshotId"],
            "providerScopeSha256": snapshot["providerScopeSha256"],
            "sourceJournalSha256": receipt.journal_sha256,
            "provider": receipt.provider,
            "hostRecordId": host.id, "firewallRecordId": firewall.id,
            "hostId": receipt.host_id, "firewallId": receipt.firewall_id,
            "publicIp": receipt.public_ip,
            "keyFingerprintSha256": receipt.key_fingerprint_sha256,
        }
        from app.domain import JobEvent
        updated_input = {**child.input, "phase": _PHASE}
        changed = db.session.execute(update(JobRunModel).where(
            JobRunModel.id == child.id, JobRunModel.action == ACTION,
            JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
            JobRunModel.target == child.target, JobRunModel.target_type == child.target_type,
            JobRunModel.target_id == child.target_id, JobRunModel.requested_by == child.requested_by,
            JobRunModel.created_at == _parse_datetime(child.created_at),
            JobRunModel.started_at == _parse_datetime(child.started_at),
            JobRunModel.artifact_refs == [],
            *_sqlalchemy_apply_input_conditions(JobRunModel, child.input),
            text("julianday('now') < julianday(json_extract(job_runs.input, '$.claimExpiresAt'))"),
        ).values(input=updated_input))
        if changed.rowcount != 1:
            raise ValueError("Inspector preparation claim lost")
        rows = db.session.execute(text(
            "SELECT sequence, level, message, data FROM job_events "
            "WHERE job_id = :job_id ORDER BY sequence"
        ), {"job_id": child.id}).fetchall()
        if not _claimed_apply_journal_matches(rows, child, receipt.journal_sha256):
            raise ValueError("Inspector preparation journal changed")
        db.session.expire_all()
        after = authority(_PHASE)
        if (after[:3] != before[:3] or after[4:] != before[4:]
                or after[3].input != updated_input or after[3].events != child.events):
            raise ValueError("Inspector preparation scope changed")
        # The writer lock is held; repeat the key/record fence before append.
        event = JobEvent(len(child.events) + 1, "info", _PHASE, data)
        db.session.add(JobEventModel(job_id=child.id, sequence=event.sequence,
                                     level=event.level, message=event.message, data=event.data))
        db.session.flush()
        db.session.commit()
        expiry = min(datetime.fromisoformat(receipt.expires_at),
                     datetime.fromisoformat(child.input["claimExpiresAt"]))
        return InspectorPreparationCapability(
            _ISSUER, receipt, job_event_digest([*child.events, event]), expiry)
    except Exception:
        db.session.rollback()
        raise InspectorPreparationIntentAttention(
            "Inspector preparation intent is uncertain; do not replay host preparation"
        ) from None
