# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant atomic ownership of an exactly proved, staged DevTest Inspector."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from sqlalchemy import text, update

from app.services.engagement_teardown import _fingerprint
from app.services.observer_checks import (
    INSPECTOR_ADMIN_USER, INSPECTOR_RESOURCE_SOURCE, ObserverHost,
    _inspector_firewall_label, _inspector_firewall_tag,
    _running_inspector_lifecycle_job,
)
from app.services.provider_keyed_comprehensive_teardown import ACTION, _FENCE, _boundary, _child_id
from app.services.provider_keyed_inspector_create_intent import (
    InspectorCreateIntentReceipt, _existing_key_fingerprint, _inspector_rows_absent,
)
from app.services.provider_keyed_inspector_provider_proof import (
    InspectorProviderProof, _ipv4,
)
from app.services.provider_keyed_inspector_submit import InspectorSubmittedUnverified, _stage_data
from app.services.provider_keyed_inspector_settlement import settle_submitted_keyed_inspector
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_teardown_quiescence import audit_pending_provider_keyed_bootstrap
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.database import db
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import (
    SqlAlchemyJobRepository, _claimed_apply_journal_matches,
    _sqlalchemy_apply_input_conditions, _valid_completed_inspector_submission_heartbeat,
    _parse_datetime, inspector_claim_generation_digest, job_event_digest,
)
from app.storage.models import JobEventModel, JobRunModel
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import (
    TERMINAL_RECORD_STATUSES, SqlAlchemyProviderResourceRepository, StoredProviderResourceRecord,
)


_OWNER = "provider-keyed-inspector-create"
_PHASE = "inspector_owned_unprepared"


class InspectorMaterializationAttention(ValueError):
    """Submitted provider resources need explicit reconciliation, not adoption."""


@dataclass(frozen=True)
class InspectorMaterializedOwnership:
    status: str
    cleanup_required: bool
    host_record_id: str
    firewall_record_id: str
    coordinator_job_id: str


def _proof_hash(proof: InspectorProviderProof) -> str:
    payload = {"host": proof.host.to_dict(), "firewallId": proof.firewall_id,
               "managementCidr": proof.management_cidr, "tagName": proof.tag_name,
               "tagExclusive": proof.tag_exclusive}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _record_pair(parent, snapshot: dict, child, submission: InspectorSubmittedUnverified,
                 proof: InspectorProviderProof, expected_region: str, stamp: str):
    host = proof.host
    provider = submission.provider
    host_id = f"{provider}:inspector:{submission.host_id}"
    firewall_id = f"{provider}:inspector-firewall:{submission.firewall_id}"
    firewall = (host.metadata or {}).get("providerFirewall")
    expected_firewall = {
        "provider": provider, "resourceType": "firewall",
        "resourceId": submission.firewall_id,
        "name": _inspector_firewall_label(provider, submission.resource_name),
        "managementSourceCidr": proof.management_cidr,
    }
    if provider == "digitalocean":
        expected_firewall["tag"] = submission.tag_name
    if (type(firewall) is not dict or firewall.get("provider") != provider
            or firewall.get("resourceType") != "firewall"
            or firewall.get("resourceId") != submission.firewall_id
            or firewall.get("managementSourceCidr") != proof.management_cidr
            or not firewall.get("name")
            or host.provider != provider or host.resource_id != submission.host_id
            or host.name != submission.resource_name or host.region != expected_region
            or host.resource_type != ("instance" if provider == "linode" else "droplet")
            or host.ssh_user != INSPECTOR_ADMIN_USER
            or proof.firewall_id != submission.firewall_id
            or proof.tag_name != submission.tag_name or proof.tag_exclusive is not False
            or firewall != expected_firewall
            or host.metadata != {"publicIps": [host.public_ip], "providerFirewall": expected_firewall}
            or host.status != ("running" if provider == "linode" else "active")):
        raise ValueError("Inspector proof differs from returned IDs")
    _ipv4(host.public_ip)
    safe_firewall = {key: value for key, value in firewall.items() if key != "tag"}
    host_metadata = {
        **{key: value for key, value in (host.metadata or {}).items() if key != "providerFirewall"},
        "providerFirewall": safe_firewall,
        "role": "inspector", "barraganOwned": True,
        "inspectionJobId": child.id, "cleanupRequired": True,
        "publicIp": host.public_ip, "publicIps": [host.public_ip],
        "sshUser": host.ssh_user,
    }
    if provider == "digitalocean":
        host_metadata["nonexclusiveSelectorTag"] = submission.tag_name
    common = dict(engagement_id=parent.target_id,
                  engagement_name=snapshot["engagementName"], provider=provider,
                  region=host.region, lifecycle_state="preparation_required",
                  status="preparation_required", source=INSPECTOR_RESOURCE_SOURCE,
                  adoption_job_id=child.id, adopted_at=stamp, updated_at=stamp)
    host_row = StoredProviderResourceRecord(
        id=host_id, resource_type=f"inspector_{host.resource_type}",
        resource_id=host.resource_id, name=host.name, metadata=host_metadata, **common)
    firewall_metadata = {
        "role": "inspector_firewall", "barraganOwned": True,
        "inspectorHostResourceId": host.resource_id,
        "inspectionJobId": child.id, "managementSourceCidr": proof.management_cidr,
        "cleanupRequired": True,
    }
    if provider == "digitalocean":
        firewall_metadata["nonexclusiveSelectorTag"] = submission.tag_name
    firewall_row = StoredProviderResourceRecord(
        id=firewall_id, resource_type="inspector_firewall",
        resource_id=submission.firewall_id, name=firewall["name"],
        metadata=firewall_metadata, **common)
    event_data = {
        "stageJournalSha256": submission.event_digest,
        "proofSha256": _proof_hash(proof),
        "hostRecordId": host_id, "firewallRecordId": firewall_id,
        "hostId": submission.host_id, "firewallId": submission.firewall_id,
        "provider": provider, "publicIp": host.public_ip,
        "scopeSnapshotId": snapshot["snapshotId"],
        "cleanupRequired": True,
    }
    return host_row, firewall_row, event_data


def materialize_proved_keyed_inspector(
    receipt: InspectorCreateIntentReceipt, submission: InspectorSubmittedUnverified,
    *, environment: str,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, credential_repository=None, lease_lookup=None,
    pending_auditor: Callable = audit_pending_provider_keyed_bootstrap,
    key_fingerprint_reader: Callable[[], str] = _existing_key_fingerprint,
    settler: Callable = settle_submitted_keyed_inspector,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> InspectorMaterializedOwnership:
    """Insert both owned rows and one phase event in one SQLite-backed SQLA transaction."""
    try:
        if (environment != "devtest" or type(receipt) is not InspectorCreateIntentReceipt
                or type(submission) is not InspectorSubmittedUnverified
                or submission.status != "submitted_unverified"
                or db.engine.dialect.name != "sqlite"):
            raise ValueError("DevTest SQLAlchemy Inspector proof required")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        if not isinstance(jobs, SqlAlchemyJobRepository) or not isinstance(resources, SqlAlchemyProviderResourceRepository):
            raise ValueError("one SQLAlchemy ownership transaction required")
        lookup = lease_lookup or _db_lease_lookup
        # Settlement is a bounded GET-only operation. It completes before the
        # write transaction, whose claim/scope CAS fences any drift during GET.
        proof = settler(
            receipt, submission, environment=environment, job_repository=jobs,
            plan_repository=plans, settings_repository=settings_repo,
            provider_resource_repository=resources, credential_repository=credentials,
            lease_lookup=lookup, pending_auditor=pending_auditor,
            key_fingerprint_reader=key_fingerprint_reader,
        )
        if type(proof) is not InspectorProviderProof:
            raise ValueError("bounded Inspector provider proof required")

        def authority():
            parent, core, snapshot, operation = _boundary(receipt.teardown_parent_id, jobs, plans, lookup)
            child = jobs.get(_child_id(core.id))
            if (operation != _FENCE or child is None or child.id != receipt.coordinator_job_id
                    or child.action != ACTION or child.status != "running"
                    or child.finished_at is not None or child.artifact_refs != []
                    or child.input.get("phase") not in {"inspector_create_started", _PHASE}
                    or child.input.get("claimOwner") != _OWNER
                    or child.input.get("claimToken") != receipt.claim_token
                    or child.input.get("claimClaimedAt") != receipt.claim_claimed_at
                    or child.input.get("engagementId") != parent.target_id
                    or child.input.get("coreJobId") != core.id
                    or child.input.get("corePlanId") != core.input["corePlanId"]
                    or child.input.get("teardownParentId") != parent.id
                    or child.input.get("scopeSnapshotId") != snapshot["snapshotId"]
                    or child.input.get("providerScopeSha256") != snapshot["providerScopeSha256"]
                    or child.input.get("mutation") is not True
                    or len([row for row in jobs.list_for_engagement(parent.target_id)
                            if row.action == ACTION]) != 1
                    or _running_inspector_lifecycle_job(jobs, parent.target_id) is not None
                    or job_event_digest(child.events[:5]) != receipt.event_digest
                    or child.events[4].data.get("claimGenerationSha256")
                    != inspector_claim_generation_digest(
                        token=receipt.claim_token, claimed_at=receipt.claim_claimed_at)):
                raise ValueError("Inspector materialization authority differs")
            intent = child.events[4].data
            if (intent.get("provider") != submission.provider
                    or intent.get("resourceName") != receipt.resource_name
                    or submission.resource_name != receipt.resource_name
                    or submission.tag_name != (_inspector_firewall_tag(receipt.resource_name)
                                                   if submission.provider == "digitalocean" else "")
                    or proof.management_cidr != intent.get("managementSourceCidr")
                    or proof.host.region != intent.get("region")):
                raise ValueError("Inspector materialization intent differs")
            expected = _stage_data(submission.provider, receipt.resource_name,
                                   submission.host_id, submission.firewall_id, submission.tag_name)
            if (len(child.events) < 5 + len(expected)
                    or [item.sequence for item in child.events[:5 + len(expected)]]
                    != list(range(1, 6 + len(expected)))
                    or job_event_digest(child.events[:5 + len(expected)]) != submission.event_digest
                    or any(item.message != "inspector_create_stage" or item.level != "info"
                           or item.data != data for item, data in zip(child.events[5:5 + len(expected)], expected))):
                raise ValueError("Inspector materialization journal differs")
            pending_auditor(core.id, confirmed_scope=snapshot["providerScopes"][0],
                            confirmed_scope_sha256=_fingerprint(snapshot),
                            workspace_root=Path(snapshot["providerScopes"][0]["workspace"]),
                            job_repository=jobs)
            settings = settings_repo.get(parent.target_id)
            if (settings is None or not settings.enabled or settings.current_host != {}
                    or settings.provider != submission.provider
                    or settings.region != intent.get("region") or settings.size != intent.get("size")):
                raise ValueError("Inspector settings differ")
            selected = credentials.get_default(submission.provider)
            defaults = [row for row in credentials.list(submission.provider)
                        if row.provider == submission.provider and row.status == "active" and row.is_default]
            if (len(defaults) != 1 or selected != defaults[0]
                    or selected.id != receipt.credential_id
                    or hashlib.sha256(selected.encrypted_secret.encode()).hexdigest()
                       != receipt.encrypted_secret_sha256
                    or selected.alias != intent.get("credentialAlias")
                    or selected.updated_at != intent.get("credentialUpdatedAt")
                    or key_fingerprint_reader() != intent.get("keyFingerprintSha256")):
                raise ValueError("Inspector credential or key differs")
            return parent, core, snapshot, child, settings, selected

        before = authority()
        parent, _core, snapshot, child, settings, selected = before
        stamp_at = now()
        if stamp_at.tzinfo is None or stamp_at.utcoffset() != timedelta(0):
            raise ValueError("Inspector materialization clock invalid")
        host_row, firewall_row, link = _record_pair(
            parent, snapshot, child, submission, proof, settings.region, stamp_at.isoformat())
        receipt_value = InspectorMaterializedOwnership(
            "preparation_required", True, host_row.id, firewall_row.id, child.id)

        if child.input.get("phase") == _PHASE:
            active_inspector_ids = {
                row.id for row in resources.list_for_engagement(parent.target_id)
                if str(row.status).lower() not in TERMINAL_RECORD_STATUSES
                and (str(row.resource_type).startswith("inspector_")
                     or str((row.metadata or {}).get("role", "")).startswith("inspector")
                     or row.source == INSPECTOR_RESOURCE_SOURCE)
            }
            if (len(child.events) != 6 + len(_stage_data(submission.provider, receipt.resource_name,
                         submission.host_id, submission.firewall_id, submission.tag_name))
                    or child.events[-1].message != _PHASE or child.events[-1].data != link
                    or active_inspector_ids != {host_row.id, firewall_row.id}
                    or settings.current_host != {}
                    or not _same_owned_record(resources.get(host_row.id), host_row)
                    or not _same_owned_record(resources.get(firewall_row.id), firewall_row)):
                raise ValueError("Inspector owned recovery differs")
            return receipt_value
        if (child.input.get("phase") != "inspector_create_started"
                or len(child.events) != 5 + len(_stage_data(submission.provider, receipt.resource_name,
                         submission.host_id, submission.firewall_id, submission.tag_name))
                or not _inspector_rows_absent(tuple(resources.list_for_engagement(parent.target_id)), snapshot)
                or resources.get(host_row.id) is not None or resources.get(firewall_row.id) is not None):
            raise ValueError("Inspector ownership is not empty")
        heartbeat_at = stamp_at.isoformat()
        if not _valid_completed_inspector_submission_heartbeat(
            child, owner=_OWNER, token=receipt.claim_token,
            claimed_at=receipt.claim_claimed_at,
            expected_event_digest=submission.event_digest,
            heartbeat_at=heartbeat_at,
            expires_at=(stamp_at + timedelta(minutes=5)).isoformat(),
        ):
            raise ValueError("Inspector original claim or journal unproved")
        updated_input = {**child.input, "phase": _PHASE}
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == child.id, JobRunModel.action == ACTION,
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                *_sqlalchemy_apply_input_conditions(JobRunModel, child.input),
                JobRunModel.artifact_refs == [],
                JobRunModel.target == child.target,
                JobRunModel.target_type == child.target_type,
                JobRunModel.target_id == child.target_id,
                JobRunModel.requested_by == child.requested_by,
                JobRunModel.created_at == _parse_datetime(child.created_at),
                JobRunModel.started_at == _parse_datetime(child.started_at),
                text("julianday('now') < julianday(json_extract(job_runs.input, '$.claimExpiresAt'))"),
            ).values(input=updated_input))
            if changed.rowcount != 1:
                raise ValueError("Inspector ownership phase claim lost")
            rows = db.session.execute(text("""
                SELECT sequence, level, message, data FROM job_events
                WHERE job_id = :job_id ORDER BY sequence
            """), {"job_id": child.id}).fetchall()
            if not _claimed_apply_journal_matches(rows, child, submission.event_digest):
                raise ValueError("Inspector ownership journal changed")
            db.session.expire_all()
            after = authority()
            if (after[:3] != before[:3] or after[4:] != before[4:]
                    or after[3].input != updated_input
                    or after[3].events != child.events
                    or not _inspector_rows_absent(
                        tuple(resources.list_for_engagement(parent.target_id)), snapshot)
                    or resources.get(host_row.id) is not None or resources.get(firewall_row.id) is not None):
                raise ValueError("Inspector ownership boundary changed")
            resources.add_new_owned_pair_uncommitted(host_row, firewall_row)
            db.session.add(JobEventModel(job_id=child.id, sequence=len(child.events) + 1,
                                         level="info", message=_PHASE, data=link))
            db.session.flush()
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return receipt_value
    except Exception:
        db.session.rollback()
        raise InspectorMaterializationAttention(
            "Inspector ownership is unverified; explicit reconciliation is required"
        ) from None


def _same_owned_record(actual: StoredProviderResourceRecord | None,
                       expected: StoredProviderResourceRecord) -> bool:
    return (actual is not None and all(getattr(actual, key) == getattr(expected, key)
            for key in ("id", "engagement_id", "engagement_name", "provider", "resource_type",
                        "resource_id", "name", "region", "lifecycle_state", "status",
                        "source", "metadata", "adoption_job_id")))


def recover_materialized_keyed_inspector(
    coordinator_job_id: str, engagement_id: str, *, environment: str,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, lease_lookup=None,
    pending_auditor: Callable = audit_pending_provider_keyed_bootstrap,
) -> InspectorMaterializedOwnership:
    """Read only the persisted ownership boundary after process loss.

    This confirms Barragan's two owned records, not current provider readiness.
    No in-memory submit receipt, token or GET proof is accepted as authority.
    """
    try:
        if (environment != "devtest" or type(coordinator_job_id) is not str
                or type(engagement_id) is not str or db.engine.dialect.name != "sqlite"):
            raise ValueError("DevTest SQLAlchemy recovery required")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        lookup = lease_lookup or _db_lease_lookup
        if not isinstance(jobs, SqlAlchemyJobRepository) or not isinstance(resources, SqlAlchemyProviderResourceRepository):
            raise ValueError("persisted SQLAlchemy recovery required")
        child = jobs.get(coordinator_job_id)
        if (child is None or child.action != ACTION or child.status != "running"
                or child.input.get("phase") != _PHASE or child.finished_at is not None
                or child.target_id != engagement_id or child.artifact_refs != []
                or child.input.get("claimOwner") != _OWNER):
            raise ValueError("Inspector materialization phase absent")
        parent, core, snapshot, operation = _boundary(
            child.input.get("teardownParentId"), jobs, plans, lookup)
        if (operation != _FENCE or parent.target_id != engagement_id
                or child.id != _child_id(core.id)
                or child.target != f"engagement:{engagement_id}"
                or child.target_type != "engagement"
                or child.requested_by != parent.requested_by
                or child.input.get("coreJobId") != core.id
                or child.input.get("corePlanId") != core.input.get("corePlanId")
                or child.input.get("scopeSnapshotId") != snapshot["snapshotId"]
                or child.input.get("providerScopeSha256") != snapshot["providerScopeSha256"]
                or child.input.get("mutation") is not True
                or len([row for row in jobs.list_for_engagement(engagement_id)
                        if row.action == ACTION]) != 1
                or _running_inspector_lifecycle_job(jobs, engagement_id) is not None):
            raise ValueError("Inspector materialization scope differs")
        base = {key: value for key, value in child.input.items() if not key.startswith("claim")}
        if base != {
            "engagementId": engagement_id, "coreJobId": core.id,
            "corePlanId": core.input["corePlanId"], "teardownParentId": parent.id,
            "scopeSnapshotId": snapshot["snapshotId"],
            "providerScopeSha256": snapshot["providerScopeSha256"],
            "mutation": True, "phase": _PHASE,
        }:
            raise ValueError("Inspector materialization input differs")
        events = child.events
        if (len(events) not in (10, 14)
                or [event.sequence for event in events] != list(range(1, len(events) + 1))
                or any(event.level != "info" for event in events)
                or [event.message for event in events[:4]] != [
                    "keyed teardown coordinator queued", "keyed teardown coordinator started",
                    "keyed teardown handoff intended",
                    "keyed teardown handoff verified; Inspector preflight pending",
                ]
                or [event.data for event in events[:4]] != [
                    {"snapshotId": snapshot["snapshotId"]}, {}, {},
                    {"corePlanId": core.input["corePlanId"]},
                ] or events[4].message != "inspector_create_started"
                or type(events[4].data) is not dict
                or events[-1].message != _PHASE or type(events[-1].data) is not dict):
            raise ValueError("Inspector materialization journal differs")
        intent = events[4].data
        link = events[-1].data
        provider = intent.get("provider")
        name = intent.get("resourceName")
        host_id = link.get("hostId")
        firewall_id = link.get("firewallId")
        token = child.input.get("claimToken")
        claimed_at = child.input.get("claimClaimedAt")
        if (provider not in {"linode", "digitalocean"}
                or type(name) is not str or re.fullmatch(r"inspector-[0-9a-f]{32}", name) is None
                or type(token) is not str or len(token) < 16
                or type(claimed_at) is not str
                or intent.get("claimGenerationSha256") != inspector_claim_generation_digest(
                    token=token, claimed_at=claimed_at)
                or type(host_id) is not str or type(firewall_id) is not str
                or type(link.get("proofSha256")) is not str
                or re.fullmatch(r"[0-9a-f]{64}", link["proofSha256"]) is None):
            raise ValueError("Inspector materialization provenance differs")
        tag = _inspector_firewall_tag(name) if provider == "digitalocean" else ""
        stages = _stage_data(provider, name, host_id, firewall_id, tag)
        if (len(events) != 6 + len(stages)
                or any(event.message != "inspector_create_stage" or event.data != expected
                       for event, expected in zip(events[5:-1], stages))
                or link != {
                    "stageJournalSha256": job_event_digest(events[:-1]),
                    "proofSha256": link["proofSha256"],
                    "hostRecordId": f"{provider}:inspector:{host_id}",
                    "firewallRecordId": f"{provider}:inspector-firewall:{firewall_id}",
                    "hostId": host_id, "firewallId": firewall_id,
                    "provider": provider, "publicIp": link.get("publicIp"),
                    "scopeSnapshotId": snapshot["snapshotId"], "cleanupRequired": True,
                }):
            raise ValueError("Inspector materialization link differs")
        _ipv4(link["publicIp"])
        pending_auditor(core.id, confirmed_scope=snapshot["providerScopes"][0],
                        confirmed_scope_sha256=_fingerprint(snapshot),
                        workspace_root=Path(snapshot["providerScopes"][0]["workspace"]),
                        job_repository=jobs)
        settings = settings_repo.get(engagement_id)
        if (settings is None or settings.current_host != {} or not settings.enabled
                or settings.provider != provider or settings.region != intent.get("region")
                or settings.size != intent.get("size")):
            raise ValueError("Inspector settings differ")
        host = resources.get(link["hostRecordId"])
        firewall = resources.get(link["firewallRecordId"])
        active_inspectors = {
            row.id for row in resources.list_for_engagement(engagement_id)
            if str(row.status).lower() not in TERMINAL_RECORD_STATUSES
            and (str(row.resource_type).startswith("inspector_")
                 or str((row.metadata or {}).get("role", "")).startswith("inspector")
                 or row.source == INSPECTOR_RESOURCE_SOURCE)
        }
        firewall_name = _inspector_firewall_label(provider, name)
        proof_firewall = {
            "provider": provider, "resourceType": "firewall", "resourceId": firewall_id,
            "name": firewall_name, "managementSourceCidr": intent.get("managementSourceCidr"),
        }
        if provider == "digitalocean":
            proof_firewall["tag"] = tag
        expected_host_metadata = {
            "publicIps": [link["publicIp"]],
            "providerFirewall": {key: value for key, value in proof_firewall.items() if key != "tag"},
            "role": "inspector", "barraganOwned": True,
            "inspectionJobId": child.id, "cleanupRequired": True,
            "publicIp": link["publicIp"], "sshUser": INSPECTOR_ADMIN_USER,
        }
        expected_firewall_metadata = {
            "role": "inspector_firewall", "barraganOwned": True,
            "inspectorHostResourceId": host_id, "inspectionJobId": child.id,
            "managementSourceCidr": intent.get("managementSourceCidr"),
            "cleanupRequired": True,
        }
        if provider == "digitalocean":
            expected_host_metadata["nonexclusiveSelectorTag"] = tag
            expected_firewall_metadata["nonexclusiveSelectorTag"] = tag
        reconstructed_proof = InspectorProviderProof(
            ObserverHost(
                provider, "instance" if provider == "linode" else "droplet",
                host_id, name, settings.region, link["publicIp"],
                ssh_user=INSPECTOR_ADMIN_USER,
                status="running" if provider == "linode" else "active",
                metadata={"publicIps": [link["publicIp"]], "providerFirewall": proof_firewall},
            ),
            firewall_id, intent.get("managementSourceCidr"), tag,
        )
        if (host is None or firewall is None
                or active_inspectors != {host.id, firewall.id}
                or any(row.engagement_id != engagement_id or row.provider != provider
                       or row.status != "preparation_required"
                       or row.lifecycle_state != "preparation_required"
                       or row.source != INSPECTOR_RESOURCE_SOURCE
                       or row.adoption_job_id != child.id
                       or row.metadata.get("barraganOwned") is not True
                       or row.metadata.get("cleanupRequired") is not True
                       for row in (host, firewall))
                or host.engagement_name != snapshot["engagementName"]
                or firewall.engagement_name != snapshot["engagementName"]
                or host.resource_type != ("inspector_instance" if provider == "linode"
                                          else "inspector_droplet")
                or firewall.resource_type != "inspector_firewall"
                or host.resource_id != host_id or host.name != name
                or host.region != settings.region
                or host.metadata != expected_host_metadata
                or firewall.resource_id != firewall_id
                or firewall.name != firewall_name
                or firewall.region != settings.region
                or firewall.metadata != expected_firewall_metadata
                or link["proofSha256"] != _proof_hash(reconstructed_proof)):
            raise ValueError("Inspector owned records differ")
        return InspectorMaterializedOwnership(
            "preparation_required", True, host.id, firewall.id, child.id)
    except Exception:
        raise InspectorMaterializationAttention(
            "Inspector ownership recovery is unverified; explicit reconciliation is required"
        ) from None
