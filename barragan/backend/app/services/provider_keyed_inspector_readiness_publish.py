# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant atomic publication of one freshly proved DevTest Inspector.

The proof capability is process-local and one-use.  This module performs no
provider GET, SSH, or host operation; a crash before commit needs a fresh proof.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import secrets
import re
from pathlib import Path

from sqlalchemy import update, text

from app.services.observer_checks import (
    INSPECTOR_ADMIN_IDENTITY_VERSION, INSPECTOR_ADMIN_USER,
    INSPECTOR_DEFAULT_SUPPORT_PACKAGES, INSPECTOR_SUPPORT_PREPARATION_VERSION,
    INSPECTOR_RESOURCE_SOURCE, ObserverHost, _inspector_firewall_label,
    _inspector_firewall_tag,
)
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_comprehensive_teardown import _FENCE, _boundary, _child_id
from app.services.provider_keyed_inspector_create_intent import valid_inspector_management_source_cidr
from app.services.provider_keyed_inspector_submit import _stage_data
from app.services.provider_keyed_inspector_preparation_proof import (
    InspectorSupportHostProof, InspectorSupportHostProofCapability,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_teardown_quiescence import audit_pending_provider_keyed_bootstrap
from app.storage.database import db
from app.storage.job_repository import (
    SqlAlchemyJobRepository, _claimed_apply_journal_matches, inspector_claim_generation_digest,
    job_event_digest,
)
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import (
    TERMINAL_RECORD_STATUSES, SqlAlchemyProviderResourceRepository,
)
from app.storage.models import (
    EngagementObserverSettingsModel, JobEventModel, JobRunModel,
    ProviderResourceRecordModel,
)


class InspectorReadinessPublicationAttention(ValueError):
    """Publication may be uncertain; reconcile persisted phase before continuation."""


_READY_PHASE = "inspector_ready"
_HANDOFF_OWNER = "provider-keyed-inspector-ready-handoff"


@dataclass(frozen=True)
class InspectorReadyRecognition:
    status: str
    coordinator_job_id: str
    host_record_id: str
    firewall_record_id: str
    support_proof_sha256: str


def _support_proof_digest(proof: InspectorSupportHostProof) -> str:
    return hashlib.sha256(json.dumps(asdict(proof), sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def publish_proved_keyed_inspector_readiness(
    capability: InspectorSupportHostProofCapability, engagement_id: str,
    *, environment: str,
) -> ObserverHost:
    """Atomically publish settings, two owned rows, and an intermediate ready event."""
    if type(capability) is not InspectorSupportHostProofCapability:
        raise InspectorReadinessPublicationAttention("Fresh Inspector proof capability required")
    try:
        proof, token, claimed_at, validate = capability.consume_for_publication()
        if environment != "devtest" or type(engagement_id) is not str or not engagement_id:
            raise ValueError("DevTest engagement required")
        if db.session.get_bind().dialect.name != "sqlite":
            raise ValueError("Atomic Inspector publication requires reviewed SQLite backend")

        # A conditional UPDATE takes SQLite's writer slot before the read-only
        # authority closure rederives parent, lease, rows, key, and journal.
        changed = db.session.execute(update(JobRunModel).where(
            JobRunModel.id == proof.coordinator_job_id,
            JobRunModel.action == "provider_keyed_comprehensive_teardown",
            JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
            JobRunModel.target_id == engagement_id,
            text("json_extract(job_runs.input, '$.phase') = 'inspector_prepare_started'"),
            text("json_extract(job_runs.input, '$.claimToken') = :proof_token")
                .bindparams(proof_token=token),
            text("json_extract(job_runs.input, '$.claimClaimedAt') = :proof_claimed")
                .bindparams(proof_claimed=claimed_at),
            text("julianday('now') < julianday(json_extract(job_runs.input, '$.claimExpiresAt'))"),
        ).values(status="running"))
        if changed.rowcount != 1:
            raise ValueError("Inspector publication claim lost")
        db.session.expire_all()
        (child, host, firewall, settings, _credential, observer_host,
         _key_path, _key_digest, _intent, _link, _provider_proof) = validate()
        if (child.target_id != engagement_id or child.id != proof.coordinator_job_id
                or host.id != proof.host_record_id or firewall.id != proof.firewall_record_id
                or host.provider != proof.provider or host.resource_id != proof.host_id
                or observer_host.public_ip != proof.public_ip
                or proof.settings_published is not False):
            raise ValueError("Inspector proof and owned rows differ")
        raw_events = db.session.execute(text("""
            SELECT sequence, level, message, data FROM job_events
            WHERE job_id = :job_id ORDER BY sequence
        """), {"job_id": child.id}).fetchall()
        if not _claimed_apply_journal_matches(
            raw_events, child, proof.preparation_journal_sha256
        ):
            raise ValueError("Inspector preparation journal changed")

        metadata = {
            **host.metadata,
            "adminIdentityVersion": INSPECTOR_ADMIN_IDENTITY_VERSION,
            "rootLoginDisabled": True,
            "supportPreparationVersion": INSPECTOR_SUPPORT_PREPARATION_VERSION,
            "supportPreparedPackages": sorted(INSPECTOR_DEFAULT_SUPPORT_PACKAGES),
        }
        # Preserve the sanitized providerFirewall and DO nonexclusive selector
        # provenance.  Never add a tag to providerFirewall (cleanup authority).
        published = replace(observer_host,
                            status="running" if host.provider == "linode" else "active",
                            metadata=metadata)
        current_host = published.to_dict()
        if current_host["sshUser"] != INSPECTOR_ADMIN_USER:
            raise ValueError("Inspector admin identity differs")
        stamp = datetime.now(timezone.utc)
        event_data = {
            "providerProofSha256": proof.provider_proof_sha256,
            "preparationJournalSha256": proof.preparation_journal_sha256,
            "selectedSourceSshPolicySha256": proof.ssh_policy_sha256,
            "nmapVersion": proof.nmap_version,
            "supportProofSha256": _support_proof_digest(proof),
            "priorClaimGenerationSha256": inspector_claim_generation_digest(
                token=token, claimed_at=claimed_at),
            "hostRecordId": host.id,
            "firewallRecordId": firewall.id,
            "scopeSnapshotId": child.input["scopeSnapshotId"],
            "settingsPublished": True,
        }

        host_changed = db.session.execute(update(ProviderResourceRecordModel).where(
            ProviderResourceRecordModel.id == host.id,
            ProviderResourceRecordModel.engagement_id == engagement_id,
            ProviderResourceRecordModel.status == "preparation_required",
            ProviderResourceRecordModel.lifecycle_state == "preparation_required",
            ProviderResourceRecordModel.metadata_json == host.metadata,
            ProviderResourceRecordModel.adoption_job_id == child.id,
        ).values(status="active", lifecycle_state="active", metadata_json=metadata,
                 updated_at=stamp))
        if host_changed.rowcount != 1:
            raise ValueError("Inspector host record changed")
        firewall_changed = db.session.execute(update(ProviderResourceRecordModel).where(
            ProviderResourceRecordModel.id == firewall.id,
            ProviderResourceRecordModel.engagement_id == engagement_id,
            ProviderResourceRecordModel.status == "preparation_required",
            ProviderResourceRecordModel.lifecycle_state == "preparation_required",
            ProviderResourceRecordModel.metadata_json == firewall.metadata,
            ProviderResourceRecordModel.adoption_job_id == child.id,
        ).values(status="active", lifecycle_state="active", updated_at=stamp))
        if firewall_changed.rowcount != 1:
            raise ValueError("Inspector firewall record changed")
        settings_changed = db.session.execute(update(EngagementObserverSettingsModel).where(
            EngagementObserverSettingsModel.engagement_id == engagement_id,
            EngagementObserverSettingsModel.enabled.is_(True),
            EngagementObserverSettingsModel.provider == settings.provider,
            EngagementObserverSettingsModel.region == settings.region,
            EngagementObserverSettingsModel.size == settings.size,
            EngagementObserverSettingsModel.current_host == {},
        ).values(current_host=current_host, updated_at=stamp))
        if settings_changed.rowcount != 1:
            raise ValueError("Inspector settings changed")
        database_now = db.session.execute(text(
            "SELECT strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now')"
        )).scalar_one()
        handoff_input = {
            **child.input, "phase": _READY_PHASE,
            "claimOwner": _HANDOFF_OWNER,
            "claimToken": secrets.token_hex(16),
            "claimClaimedAt": database_now,
            "claimHeartbeatAt": database_now,
            "claimExpiresAt": database_now,
        }
        phase_changed = db.session.execute(update(JobRunModel).where(
            JobRunModel.id == child.id,
            JobRunModel.action == child.action,
            JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
            JobRunModel.input == child.input,
            text("julianday('now') < julianday(json_extract(job_runs.input, '$.claimExpiresAt'))"),
        ).values(input=handoff_input))
        if phase_changed.rowcount != 1:
            raise ValueError("Inspector publication claim expired")
        db.session.add(JobEventModel(
            job_id=child.id, sequence=len(child.events) + 1, level="info",
            message="inspector selected-source proof published", data=event_data,
            created_at=stamp,
        ))
        db.session.flush()
        db.session.commit()
        return published
    except Exception:
        db.session.rollback()
        raise InspectorReadinessPublicationAttention(
            "Inspector readiness publication is uncertain; reconcile persisted phase"
        ) from None


def recognize_published_keyed_inspector_readiness(
    coordinator_job_id: str, engagement_id: str, *, environment: str,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, lease_lookup=None,
    pending_auditor=audit_pending_provider_keyed_bootstrap,
    _historical: bool = False,
) -> InspectorReadyRecognition:
    """Read-only exact phase recognition; it cannot launch the next action."""
    try:
        if environment != "devtest" or not coordinator_job_id or not engagement_id:
            raise ValueError("DevTest ready phase required")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        lookup = lease_lookup or _db_lease_lookup
        child = jobs.get(coordinator_job_id)
        if child is None:
            raise ValueError("Inspector coordinator missing")
        parent, core, snapshot, operation = _boundary(
            child.input["teardownParentId"], jobs, plans, lookup)
        inputs = child.input
        all_events = child.events
        if _historical:
            ready_positions = [index for index, event in enumerate(all_events)
                               if event.message == "inspector selected-source proof published"]
            historical_phase = ("group_retired" if "publishedSource" in parent.input
                                else "pending_group_retired")
            if len(ready_positions) != 1 or inputs.get("phase") != historical_phase:
                raise ValueError("historical Inspector publication missing")
            events = all_events[:ready_positions[0] + 1]
        else:
            events = all_events
        if (operation != _FENCE or parent.target_id != engagement_id
                or child.id != _child_id(core.id) or child.target_id != engagement_id
                or child.action != "provider_keyed_comprehensive_teardown"
                or child.status != "running" or child.finished_at is not None
                or child.artifact_refs != [] or child.requested_by != parent.requested_by
                or (not _historical and (
                    inputs.get("phase") != _READY_PHASE
                    or inputs.get("claimOwner") != _HANDOFF_OWNER
                    or type(inputs.get("claimToken")) is not str
                    or re.fullmatch(r"[0-9a-f]{32}", inputs["claimToken"]) is None
                    or inputs.get("claimClaimedAt") != inputs.get("claimHeartbeatAt")
                    or inputs.get("claimExpiresAt") != inputs.get("claimClaimedAt")
                    or datetime.fromisoformat(inputs["claimExpiresAt"]) > datetime.now(timezone.utc)))
                or inputs.get("coreJobId") != core.id
                or inputs.get("corePlanId") != core.input["corePlanId"]
                or inputs.get("scopeSnapshotId") != snapshot["snapshotId"]
                or inputs.get("providerScopeSha256") != snapshot["providerScopeSha256"]
                or inputs.get("mutation") is not True
                or (_historical and (
                    len(all_events) <= len(events)
                    or [event.sequence for event in all_events]
                    != list(range(1, len(all_events) + 1))
                    or any(event.level != "info" for event in all_events)))
                or len(events) not in (12, 16)
                or [event.sequence for event in events] != list(range(1, len(events) + 1))
                or any(event.level != "info" for event in events)
                or [event.message for event in events[:5]] != [
                    "keyed teardown coordinator queued", "keyed teardown coordinator started",
                    "keyed teardown handoff intended",
                    "keyed teardown handoff verified; Inspector preflight pending",
                    "inspector_create_started",
                ] or events[-3].message != "inspector_owned_unprepared"
                or events[-2].message != "inspector_prepare_started"
                or events[-1].message != "inspector selected-source proof published"
                or [event.data for event in events[:4]] != [
                    {"snapshotId": snapshot["snapshotId"]}, {}, {},
                    {"corePlanId": core.input["corePlanId"]},
                ]):
            raise ValueError("Inspector ready phase or journal differs")
        if not _historical:
            pending_auditor(core.id, confirmed_scope=snapshot["providerScopes"][0],
                            confirmed_scope_sha256=_fingerprint(snapshot),
                            workspace_root=Path(snapshot["providerScopes"][0]["workspace"]),
                            job_repository=jobs)
        intent = events[4].data
        link = events[-3].data
        prepare = events[-2].data
        ready = events[-1].data
        provider = intent["provider"]
        name = intent["resourceName"]
        host_id = link["hostId"]
        firewall_id = link["firewallId"]
        tag = _inspector_firewall_tag(name) if provider == "digitalocean" else ""
        stages = _stage_data(provider, name, host_id, firewall_id, tag)
        if (provider not in {"linode", "digitalocean"}
                or set(intent) != {
                    "scopeSnapshotId", "providerScopeSha256", "provider", "region", "size",
                    "credentialAlias", "credentialId", "credentialSha256",
                    "credentialUpdatedAt", "resourceName",
                    "keyFingerprintSha256", "managementSourceCidr", "claimGenerationSha256",
                }
                or intent["scopeSnapshotId"] != snapshot["snapshotId"]
                or intent["providerScopeSha256"] != snapshot["providerScopeSha256"]
                or not valid_inspector_management_source_cidr(intent["managementSourceCidr"])
                or type(intent["keyFingerprintSha256"]) is not str
                or re.fullmatch(r"[0-9a-f]{64}", intent["keyFingerprintSha256"]) is None
                or type(intent["credentialId"]) is not str or not intent["credentialId"]
                or type(intent["credentialSha256"]) is not str
                or re.fullmatch(r"[0-9a-f]{64}", intent["credentialSha256"]) is None
                or type(intent["claimGenerationSha256"]) is not str
                or re.fullmatch(r"[0-9a-f]{64}", intent["claimGenerationSha256"]) is None
                or re.fullmatch(r"inspector-[0-9a-f]{32}", name) is None
                or len(events) != 8 + len(stages)
                or any(event.message != "inspector_create_stage" or event.data != expected
                       for event, expected in zip(events[5:-3], stages))
                or link != {
                    "stageJournalSha256": job_event_digest(events[:-3]),
                    "proofSha256": link.get("proofSha256"),
                    "hostRecordId": f"{provider}:inspector:{host_id}",
                    "firewallRecordId": f"{provider}:inspector-firewall:{firewall_id}",
                    "hostId": host_id, "firewallId": firewall_id,
                    "provider": provider, "publicIp": link.get("publicIp"),
                    "scopeSnapshotId": snapshot["snapshotId"],
                    "cleanupRequired": True,
                }
                or prepare != {
                    "scopeSnapshotId": snapshot["snapshotId"],
                    "providerScopeSha256": snapshot["providerScopeSha256"],
                    "sourceJournalSha256": job_event_digest(events[:-2]),
                    "provider": provider,
                    "hostRecordId": link["hostRecordId"],
                    "firewallRecordId": link["firewallRecordId"],
                    "hostId": host_id, "firewallId": firewall_id,
                    "publicIp": link["publicIp"],
                    "keyFingerprintSha256": intent["keyFingerprintSha256"],
                }
                or ready != {
                    "providerProofSha256": link.get("proofSha256"),
                    "preparationJournalSha256": job_event_digest(events[:-1]),
                    "selectedSourceSshPolicySha256": ready.get("selectedSourceSshPolicySha256"),
                    "nmapVersion": ready.get("nmapVersion"),
                    "supportProofSha256": ready.get("supportProofSha256"),
                    "priorClaimGenerationSha256": intent.get("claimGenerationSha256"),
                    "hostRecordId": link["hostRecordId"],
                    "firewallRecordId": link["firewallRecordId"],
                    "scopeSnapshotId": snapshot["snapshotId"],
                    "settingsPublished": True,
                }):
            raise ValueError("Inspector ready provenance differs")
        settings = settings_repo.get(engagement_id)
        host = resources.get(link["hostRecordId"])
        firewall = resources.get(link["firewallRecordId"])
        active = {row.id for row in resources.list_for_engagement(engagement_id)
                  if str(row.status).lower() not in TERMINAL_RECORD_STATUSES
                  and (row.resource_type.startswith("inspector_")
                       or str((row.metadata or {}).get("role", "")).startswith("inspector")
                       or row.source == INSPECTOR_RESOURCE_SOURCE)}
        if settings is None or host is None or firewall is None:
            raise ValueError("Inspector ready records missing")
        proof = InspectorSupportHostProof(
            "support_host_proved_unpublished", child.id, host.id, firewall.id,
            provider, host_id, link["publicIp"], ready["providerProofSha256"],
            ready["preparationJournalSha256"], ready["selectedSourceSshPolicySha256"],
            ready["nmapVersion"], False,
        )
        if any(type(ready.get(key)) is not str
               or re.fullmatch(r"[0-9a-f]{64}", ready[key]) is None
               for key in ("providerProofSha256", "preparationJournalSha256",
                           "selectedSourceSshPolicySha256", "supportProofSha256",
                           "priorClaimGenerationSha256")):
            raise ValueError("Inspector ready evidence digest differs")
        firewall_data = {
            "provider": provider, "resourceType": "firewall", "resourceId": firewall_id,
            "name": _inspector_firewall_label(provider, name),
            "managementSourceCidr": intent["managementSourceCidr"],
        }
        host_meta = {
            "publicIps": [link["publicIp"]], "providerFirewall": firewall_data,
            "role": "inspector", "barraganOwned": True,
            "inspectionJobId": child.id, "cleanupRequired": True,
            "publicIp": link["publicIp"], "sshUser": INSPECTOR_ADMIN_USER,
            "adminIdentityVersion": INSPECTOR_ADMIN_IDENTITY_VERSION,
            "rootLoginDisabled": True,
            "supportPreparationVersion": INSPECTOR_SUPPORT_PREPARATION_VERSION,
            "supportPreparedPackages": sorted(INSPECTOR_DEFAULT_SUPPORT_PACKAGES),
        }
        firewall_meta = {
            "role": "inspector_firewall", "barraganOwned": True,
            "inspectorHostResourceId": host_id, "inspectionJobId": child.id,
            "managementSourceCidr": intent["managementSourceCidr"],
            "cleanupRequired": True,
        }
        if tag:
            host_meta["nonexclusiveSelectorTag"] = tag
            firewall_meta["nonexclusiveSelectorTag"] = tag
        expected_host = ObserverHost(
            provider, "instance" if provider == "linode" else "droplet",
            host_id, name, settings.region, link["publicIp"],
            ssh_user=INSPECTOR_ADMIN_USER,
            status="running" if provider == "linode" else "active",
            metadata=host_meta,
        )
        if (ready.get("supportProofSha256") != _support_proof_digest(proof)
                or type(ready.get("nmapVersion")) is not str
                or not ready["nmapVersion"].startswith("Nmap version ")
                or settings.current_host != expected_host.to_dict()
                or settings.provider != provider or settings.region != intent["region"]
                or settings.size != intent["size"] or not settings.enabled
                or active != {host.id, firewall.id}
                or host.resource_id != host_id or host.name != name
                or host.provider != provider or host.region != settings.region
                or host.resource_type != ("inspector_instance" if provider == "linode"
                                          else "inspector_droplet")
                or host.metadata != host_meta
                or firewall.resource_type != "inspector_firewall"
                or firewall.resource_id != firewall_id
                or firewall.name != firewall_data["name"]
                or firewall.provider != provider or firewall.region != settings.region
                or firewall.metadata != firewall_meta
                or any(row.status != "active" or row.lifecycle_state != "active"
                       or row.engagement_id != engagement_id
                       or row.engagement_name != snapshot["engagementName"]
                       or row.source != INSPECTOR_RESOURCE_SOURCE
                       or row.adoption_job_id != child.id for row in (host, firewall))):
            raise ValueError("Inspector ready settings or rows differ")
        return InspectorReadyRecognition(
            "inspector_ready_historical" if _historical else "inspector_ready",
            child.id, host.id, firewall.id,
            ready["supportProofSha256"],
        )
    except Exception:
        raise InspectorReadinessPublicationAttention(
            "Inspector ready phase is unverified; continuation remains gated"
        ) from None


def recognize_historical_keyed_inspector_readiness(
    coordinator_job_id: str, engagement_id: str, *, environment: str,
    state_root: Path,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, sketch_repository=None,
    credential_repository=None, lease_lookup=None,
) -> InspectorReadyRecognition:
    """Reprove the original publication after later cleanup phases without state mutation.

    The current coordinator remains running under the teardown fence.  The
    original 12/16-event creation/publication prefix and exclusive live
    Inspector pair receive the same strict validation as the ready phase.
    """
    from app.services.provider_keyed_comprehensive_teardown import (
        recognize_provider_keyed_group_retired,
    )
    from app.services.provider_keyed_pending_retirement import (
        recognize_pending_keyed_group_retired,
    )

    jobs = job_repository or SqlAlchemyJobRepository()
    child = jobs.get(coordinator_job_id)
    if child is None or child.target_id != engagement_id:
        raise InspectorReadinessPublicationAttention(
            "historical Inspector coordinator is unverified")
    try:
        parent = jobs.get(child.input.get("teardownParentId"))
        recognizer = (recognize_provider_keyed_group_retired
                      if parent is not None and "publishedSource" in parent.input
                      else recognize_pending_keyed_group_retired)
        retired = recognizer(
            child.input.get("teardownParentId"), environment=environment,
            state_root=state_root, job_repository=jobs,
            plan_repository=plan_repository,
            sketch_repository=sketch_repository,
            credential_repository=credential_repository,
            provider_resource_repository=provider_resource_repository,
            lease_lookup=lease_lookup,
        )
    except Exception:
        raise InspectorReadinessPublicationAttention(
            "historical Inspector retirement is unverified") from None
    if type(retired) is not tuple or len(retired) != 2:
        raise InspectorReadinessPublicationAttention(
            "historical Inspector retirement is unverified")
    return recognize_published_keyed_inspector_readiness(
        coordinator_job_id, engagement_id, environment=environment,
        job_repository=jobs, plan_repository=plan_repository,
        settings_repository=settings_repository,
        provider_resource_repository=provider_resource_repository,
        lease_lookup=lease_lookup, _historical=True,
    )
