# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant, one-shot execution of an already reserved Inspector preparation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import stat
from typing import Callable

from app.services.engagement_teardown import _fingerprint
from app.services.observer_checks import (
    INSPECTOR_ADMIN_USER, INSPECTOR_DEFAULT_SUPPORT_PACKAGES,
    INSPECTOR_RESOURCE_SOURCE, ObserverSshKey, _inspector_firewall_label,
    _inspector_firewall_tag,
    SshObserverRunner, _inspector_host_from_resource_record,
    _running_inspector_lifecycle_job,
)
from app.services.provider_keyed_comprehensive_teardown import ACTION, _FENCE, _boundary, _child_id
from app.services.provider_keyed_inspector_prepare_binder import (
    InspectorPreparationReceipt, _existing_key_identity, _safe_key_identity, _verify_key_pair,
)
from app.services.provider_keyed_inspector_prepare_intent import InspectorPreparationCapability
from app.services.provider_keyed_inspector_materialize import _proof_hash
from app.services.provider_keyed_inspector_provider_proof import InspectorProviderProof
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_teardown_quiescence import audit_pending_provider_keyed_bootstrap
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import (
    SqlAlchemyJobRepository, _valid_keyed_inspector_prepare_heartbeat, job_event_digest,
)
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import (
    TERMINAL_RECORD_STATUSES, SqlAlchemyProviderResourceRepository,
)


_OWNER = "provider-keyed-inspector-create"
_PHASE = "inspector_prepare_started"


class InspectorPreparationExecutionAttention(ValueError):
    """Preparation may have contacted the host; reconciliation is required."""


@dataclass(frozen=True)
class InspectorPreparedUnverified:
    status: str
    coordinator_job_id: str
    host_record_id: str
    firewall_record_id: str
    provider: str
    host_id: str
    public_ip: str
    preparation_journal_sha256: str


def execute_reserved_keyed_inspector_preparation(
    capability: InspectorPreparationCapability, *, environment: str,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, lease_lookup=None,
    pending_auditor: Callable = audit_pending_provider_keyed_bootstrap,
    key_identity_reader: Callable = _existing_key_identity,
    key_pair_verifier: Callable = _verify_key_pair,
    runner: SshObserverRunner | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> InspectorPreparedUnverified:
    """Consume before SSH; never publish readiness or retry a command sequence."""
    if type(capability) is not InspectorPreparationCapability:
        raise InspectorPreparationExecutionAttention("Inspector preparation capability is invalid")
    # Consumption is intentionally first, including before repository/key reads.
    try:
        receipt, expected_journal = capability.consume_for_executor()
        if environment != "devtest" or type(receipt) is not InspectorPreparationReceipt:
            raise ValueError("DevTest preparation receipt required")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        lookup = lease_lookup or _db_lease_lookup
        command_runner = runner or SshObserverRunner()
        if type(command_runner) is not SshObserverRunner:
            raise ValueError("fenced Inspector SSH runner required")

        def authority():
            child = jobs.get(receipt.coordinator_job_id)
            if child is None or child.action != ACTION or child.input.get("teardownParentId") is None:
                raise ValueError("Inspector coordinator differs")
            parent, core, snapshot, operation = _boundary(
                child.input["teardownParentId"], jobs, plans, lookup)
            if (operation != _FENCE or child.id != _child_id(core.id)
                    or parent.target_id != receipt.engagement_id
                    or snapshot["snapshotId"] != receipt.scope_snapshot_id
                    or child.status != "running" or child.finished_at is not None
                    or child.target != f"engagement:{receipt.engagement_id}"
                    or child.target_type != "engagement" or child.target_id != receipt.engagement_id
                    or child.requested_by != parent.requested_by or child.artifact_refs != []
                    or child.input.get("phase") != _PHASE
                    or child.input.get("claimOwner") != _OWNER
                    or child.input.get("claimToken") != receipt.claim_token
                    or child.input.get("claimClaimedAt") != receipt.claim_claimed_at
                    or child.input.get("coreJobId") != core.id
                    or child.input.get("corePlanId") != core.input["corePlanId"]
                    or child.input.get("scopeSnapshotId") != snapshot["snapshotId"]
                    or child.input.get("providerScopeSha256") != snapshot["providerScopeSha256"]
                    or child.input.get("mutation") is not True
                    or job_event_digest(child.events) != expected_journal
                    or child.events[-1].message != _PHASE
                    or child.events[-1].data.get("sourceJournalSha256") != receipt.journal_sha256
                    or child.events[-1].data.get("hostId") != receipt.host_id
                    or child.events[-1].data.get("firewallId") != receipt.firewall_id
                    or child.events[-1].data.get("keyFingerprintSha256") != receipt.key_fingerprint_sha256):
                raise ValueError("Inspector preparation journal or scope differs")
            instant = now()
            expiry = datetime.fromisoformat(child.input["claimExpiresAt"])
            if (instant.tzinfo is None or instant.utcoffset() != timedelta(0)
                    or expiry <= instant or expiry <= datetime.now(timezone.utc)):
                raise ValueError("Inspector preparation authority expired")
            if not _valid_keyed_inspector_prepare_heartbeat(
                    child, owner=_OWNER, token=receipt.claim_token,
                    claimed_at=receipt.claim_claimed_at,
                    expected_event_digest=expected_journal,
                    heartbeat_at=instant.isoformat(),
                    expires_at=(instant + timedelta(minutes=4, seconds=50)).isoformat()):
                raise ValueError("Inspector preparation journal differs")
            pending_auditor(
                core.id, confirmed_scope=snapshot["providerScopes"][0],
                confirmed_scope_sha256=_fingerprint(snapshot),
                workspace_root=Path(snapshot["providerScopes"][0]["workspace"]),
                job_repository=jobs,
            )
            settings = settings_repo.get(receipt.engagement_id)
            host = resources.get(f"{receipt.provider}:inspector:{receipt.host_id}")
            firewall = resources.get(f"{receipt.provider}:inspector-firewall:{receipt.firewall_id}")
            active = {
                row.id for row in resources.list_for_engagement(receipt.engagement_id)
                if str(row.status).lower() not in TERMINAL_RECORD_STATUSES
                and (str(row.resource_type).startswith("inspector_")
                     or str((row.metadata or {}).get("role", "")).startswith("inspector")
                     or row.source == INSPECTOR_RESOURCE_SOURCE)
            }
            key_path, fingerprint = _safe_key_identity(key_identity_reader)
            key_pair_verifier(key_path, fingerprint)
            intent = child.events[4].data
            link = child.events[-2].data
            name = intent["resourceName"]
            firewall_name = _inspector_firewall_label(receipt.provider, name)
            tag = _inspector_firewall_tag(name) if receipt.provider == "digitalocean" else ""
            proof_firewall = {
                "provider": receipt.provider, "resourceType": "firewall",
                "resourceId": receipt.firewall_id, "name": firewall_name,
                "managementSourceCidr": intent["managementSourceCidr"],
            }
            if tag:
                proof_firewall["tag"] = tag
            expected_host_metadata = {
                "publicIps": [receipt.public_ip],
                "providerFirewall": {key: value for key, value in proof_firewall.items() if key != "tag"},
                "role": "inspector", "barraganOwned": True,
                "inspectionJobId": child.id, "cleanupRequired": True,
                "publicIp": receipt.public_ip, "sshUser": INSPECTOR_ADMIN_USER,
            }
            expected_firewall_metadata = {
                "role": "inspector_firewall", "barraganOwned": True,
                "inspectorHostResourceId": receipt.host_id,
                "inspectionJobId": child.id,
                "managementSourceCidr": intent["managementSourceCidr"],
                "cleanupRequired": True,
            }
            if tag:
                expected_host_metadata["nonexclusiveSelectorTag"] = tag
                expected_firewall_metadata["nonexclusiveSelectorTag"] = tag
            if (settings is None or settings.current_host != {}
                    or not settings.enabled or settings.provider != receipt.provider
                    or settings.region != intent["region"] or settings.size != intent["size"]
                    or host is None or firewall is None
                    or active != {host.id, firewall.id}
                    or any(row.engagement_id != receipt.engagement_id
                           or row.engagement_name != snapshot["engagementName"]
                           or row.provider != receipt.provider
                           or row.status != "preparation_required"
                           or row.lifecycle_state != "preparation_required"
                           or row.source != INSPECTOR_RESOURCE_SOURCE
                           or row.adoption_job_id != child.id
                           for row in (host, firewall))
                    or host.resource_type != ("inspector_instance" if receipt.provider == "linode"
                                              else "inspector_droplet")
                    or host.resource_id != receipt.host_id or host.name != name
                    or host.region != settings.region or host.metadata != expected_host_metadata
                    or firewall.resource_type != "inspector_firewall"
                    or firewall.resource_id != receipt.firewall_id
                    or firewall.name != firewall_name or firewall.region != settings.region
                    or firewall.metadata != expected_firewall_metadata
                    or link["hostId"] != receipt.host_id
                    or link["firewallId"] != receipt.firewall_id
                    or link["publicIp"] != receipt.public_ip
                    or key_path != receipt.key_path
                    or fingerprint != receipt.key_fingerprint_sha256
                    or _running_inspector_lifecycle_job(jobs, receipt.engagement_id) is not None):
                raise ValueError("Inspector host, settings or key differs")
            observer_host = _inspector_host_from_resource_record(host, settings=settings)
            if (observer_host.provider != receipt.provider
                    or observer_host.public_ip != receipt.public_ip
                    or observer_host.ssh_user != INSPECTOR_ADMIN_USER
                    or observer_host.resource_id != receipt.host_id):
                raise ValueError("Inspector SSH host differs")
            proof_host = type(observer_host)(
                observer_host.provider, observer_host.resource_type,
                observer_host.resource_id, observer_host.name, observer_host.region,
                observer_host.public_ip, ssh_user=INSPECTOR_ADMIN_USER,
                status="running" if receipt.provider == "linode" else "active",
                metadata={"publicIps": [receipt.public_ip], "providerFirewall": proof_firewall},
            )
            if link["proofSha256"] != _proof_hash(InspectorProviderProof(
                    proof_host, receipt.firewall_id, intent["managementSourceCidr"], tag)):
                raise ValueError("Inspector owned proof differs")
            return child, host, firewall, settings, observer_host, key_path

        if datetime.fromisoformat(receipt.expires_at) <= datetime.now(timezone.utc):
            raise ValueError("Inspector preparation receipt expired before contact")
        before = authority()
        command_fences = 0

        def fence():
            nonlocal command_fences
            previous = authority()
            moment = now()
            renewed = jobs.heartbeat_keyed_inspector_preparation_if_running_claimed(
                previous[0], owner=_OWNER, token=receipt.claim_token,
                claimed_at=receipt.claim_claimed_at,
                expected_event_digest=expected_journal,
                heartbeat_at=moment.isoformat(),
                expires_at=(moment + timedelta(minutes=4, seconds=50)).isoformat(),
            )
            if renewed is None:
                raise ValueError("Inspector preparation claim changed")
            after = authority()
            if (after[0] != renewed or after[1:] != previous[1:]
                    or after[1:] != before[1:]):
                raise ValueError("Inspector preparation authority changed")
            command_fences += 1

        fence()
        public_path = Path(before[5] + ".pub")
        fd = os.open(public_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            public_raw = os.read(fd, 4097)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o022
                    or len(public_raw) > 4096 or len(public_raw.splitlines()) != 1):
                raise ValueError("Inspector public key is unsafe")
            public_key = public_raw.decode("ascii").strip()
            if (not public_key.startswith("ssh-ed25519 ")
                    or hashlib.sha256(public_raw.strip()).hexdigest()
                       != receipt.key_fingerprint_sha256):
                raise ValueError("Inspector public key differs")
        finally:
            os.close(fd)
        fence()
        prepared = command_runner.prepare_support_host(
            host=before[4], ssh_key=ObserverSshKey(before[5], public_key),
            fence=fence,
        )
        fence()
        if (command_fences < 15 or prepared.provider != before[4].provider
                or prepared.resource_id != before[4].resource_id
                or prepared.name != before[4].name or prepared.region != before[4].region
                or prepared.public_ip != before[4].public_ip
                or prepared.ssh_user != INSPECTOR_ADMIN_USER
                or prepared.metadata.get("adminIdentityVersion") != 1
                or prepared.metadata.get("rootLoginDisabled") is not True
                or prepared.metadata.get("supportPreparationVersion") != 1
                or prepared.metadata.get("supportPreparedPackages")
                   != sorted(INSPECTOR_DEFAULT_SUPPORT_PACKAGES)):
            raise ValueError("Inspector preparation result is unverified")
        return InspectorPreparedUnverified(
            "prepared_unverified", receipt.coordinator_job_id, before[1].id,
            before[2].id, receipt.provider, receipt.host_id, receipt.public_ip,
            expected_journal,
        )
    except Exception:
        raise InspectorPreparationExecutionAttention(
            "Inspector host preparation is uncertain; explicit reconciliation is required"
        ) from None
