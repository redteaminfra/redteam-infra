# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant independent GET/SSH proof after one-shot Inspector preparation.

This uses the existing Inspector SSH trust model; it does not pin host keys or
publish settings/readiness. Every read-only command is claim-fenced.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import stat
from threading import Lock
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from app.services.credentials import decrypt_secret_value
from app.services.engagement_teardown import _fingerprint
from app.services.observer_checks import (
    INSPECTOR_ADMIN_USER, INSPECTOR_RESOURCE_SOURCE, ObserverSshKey,
    SshObserverRunner, _inspector_firewall_label, _inspector_firewall_tag,
    _inspector_host_from_resource_record, _running_inspector_lifecycle_job,
    _run_checked,
)
from app.services.provider_keyed_comprehensive_teardown import ACTION, _FENCE, _boundary, _child_id
from app.services.provider_keyed_inspector_materialize import _proof_hash
from app.services.provider_keyed_inspector_prepare_binder import (
    _existing_key_identity, _safe_key_identity, _verify_key_pair,
)
from app.services.provider_keyed_inspector_prepare_execute import InspectorPreparedUnverified
from app.services.provider_keyed_inspector_provider_proof import (
    InspectorProviderProof, prove_keyed_inspector_provider,
)
from app.services.provider_keyed_inspector_settlement import _GetOnlyTransport, _default_transport
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_teardown_quiescence import audit_pending_provider_keyed_bootstrap
from app.storage.credential_repository import SqlAlchemyCredentialRepository
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
_ISSUER = object()
_SSHD_REQUIRED = {
    "permitrootlogin no", "passwordauthentication no",
    "kbdinteractiveauthentication no",
}


class InspectorPreparationProofAttention(ValueError):
    """Read-only proof is insufficient; no readiness was published."""


@dataclass(frozen=True)
class InspectorSupportHostProof:
    status: str
    coordinator_job_id: str
    host_record_id: str
    firewall_record_id: str
    provider: str
    host_id: str
    public_ip: str
    provider_proof_sha256: str
    preparation_journal_sha256: str
    ssh_policy_sha256: str
    nmap_version: str
    settings_published: bool = False


class InspectorSupportHostProofCapability:
    """One-use process-local proof handoff; persistence must revalidate authority."""

    __slots__ = ("_proof", "_claim_token", "_claimed_at", "_validate", "_expires_at",
                 "_pid", "_used", "_lock")

    def __init__(self, issuer: object, proof: InspectorSupportHostProof,
                 claim_token: str, claimed_at: str, validate: Callable,
                 expires_at: datetime):
        if issuer is not _ISSUER:
            raise TypeError("Inspector support proof capability cannot be constructed")
        self._proof = proof
        self._claim_token = claim_token
        self._claimed_at = claimed_at
        self._validate = validate
        self._expires_at = expires_at
        self._pid = os.getpid()
        self._used = False
        self._lock = Lock()

    def consume_for_publication(self):
        with self._lock:
            if (self._used or os.getpid() != self._pid
                    or datetime.now(timezone.utc) >= self._expires_at):
                raise InspectorPreparationProofAttention("Inspector support proof expired or consumed")
            self._used = True
            return self._proof, self._claim_token, self._claimed_at, self._validate

    @property
    def evidence(self) -> InspectorSupportHostProof:
        return self._proof

    def __copy__(self):
        return self

    def __deepcopy__(self, _memo):
        return self

    def __repr__(self) -> str:
        return "<InspectorSupportHostProofCapability one-shot>"


def prove_prepared_keyed_inspector_support_host(
    prepared: InspectorPreparedUnverified, engagement_id: str, *, environment: str,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, credential_repository=None, lease_lookup=None,
    pending_auditor: Callable = audit_pending_provider_keyed_bootstrap,
    key_identity_reader: Callable = _existing_key_identity,
    key_pair_verifier: Callable = _verify_key_pair,
    transport_factory: Callable = _default_transport,
    provider_prover: Callable = prove_keyed_inspector_provider,
    decrypt_secret: Callable = decrypt_secret_value,
    runner: SshObserverRunner | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> InspectorSupportHostProofCapability:
    """Read exact provider identity and selected-source SSH facts; publish nothing.

    OpenSSH host-key trust remains the inherited Inspector model.  A selected
    peer context and one rejected root key do not prove policy for every source
    or every possible root identity.
    """
    try:
        if (environment != "devtest" or type(prepared) is not InspectorPreparedUnverified
                or prepared.status != "prepared_unverified"):
            raise ValueError("DevTest preparation evidence required")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        lookup = lease_lookup or _db_lease_lookup
        ssh_runner = runner or SshObserverRunner(readiness_attempts=1)
        if type(ssh_runner) is not SshObserverRunner:
            raise ValueError("concrete read-only SSH runner required")

        def authority():
            child = jobs.get(prepared.coordinator_job_id)
            if child is None or child.action != ACTION:
                raise ValueError("Inspector coordinator missing")
            parent, core, snapshot, operation = _boundary(
                child.input["teardownParentId"], jobs, plans, lookup)
            moment = now()
            if (operation != _FENCE or parent.target_id != engagement_id
                    or child.id != _child_id(core.id) or child.status != "running"
                    or child.finished_at is not None or child.artifact_refs != []
                    or child.target_id != engagement_id
                    or child.target != f"engagement:{engagement_id}"
                    or child.target_type != "engagement"
                    or child.requested_by != parent.requested_by
                    or child.input.get("phase") != _PHASE
                    or child.input.get("claimOwner") != _OWNER
                    or child.input.get("coreJobId") != core.id
                    or child.input.get("corePlanId") != core.input["corePlanId"]
                    or child.input.get("scopeSnapshotId") != snapshot["snapshotId"]
                    or child.input.get("providerScopeSha256") != snapshot["providerScopeSha256"]
                    or child.input.get("mutation") is not True
                    or job_event_digest(child.events) != prepared.preparation_journal_sha256
                    or type(moment) is not datetime or moment.tzinfo is None
                    or moment.utcoffset() != timedelta(0)
                    or datetime.fromisoformat(child.input["claimExpiresAt"]) <= moment
                    or datetime.fromisoformat(child.input["claimExpiresAt"]) <= datetime.now(timezone.utc)
                    or not _valid_keyed_inspector_prepare_heartbeat(
                        child, owner=_OWNER, token=child.input["claimToken"],
                        claimed_at=child.input["claimClaimedAt"],
                        expected_event_digest=prepared.preparation_journal_sha256,
                        heartbeat_at=moment.isoformat(),
                        expires_at=(moment + timedelta(minutes=4, seconds=50)).isoformat())):
                raise ValueError("Inspector preparation claim or journal differs")
            pending_auditor(core.id, confirmed_scope=snapshot["providerScopes"][0],
                            confirmed_scope_sha256=_fingerprint(snapshot),
                            workspace_root=Path(snapshot["providerScopes"][0]["workspace"]),
                            job_repository=jobs)
            intent = child.events[4].data
            link = child.events[-2].data
            settings = settings_repo.get(engagement_id)
            host = resources.get(prepared.host_record_id)
            firewall = resources.get(prepared.firewall_record_id)
            selected = credentials.get_default(prepared.provider)
            defaults = [row for row in credentials.list(prepared.provider)
                        if row.provider == prepared.provider and row.status == "active" and row.is_default]
            key_path, key_digest = _safe_key_identity(key_identity_reader)
            key_pair_verifier(key_path, key_digest)
            active = {
                row.id for row in resources.list_for_engagement(engagement_id)
                if str(row.status).lower() not in TERMINAL_RECORD_STATUSES
                and (str(row.resource_type).startswith("inspector_")
                     or str((row.metadata or {}).get("role", "")).startswith("inspector")
                     or row.source == INSPECTOR_RESOURCE_SOURCE)
            }
            name = intent["resourceName"]
            tag = _inspector_firewall_tag(name) if prepared.provider == "digitalocean" else ""
            firewall_data = {
                "provider": prepared.provider, "resourceType": "firewall",
                "resourceId": link["firewallId"],
                "name": _inspector_firewall_label(prepared.provider, name),
                "managementSourceCidr": intent["managementSourceCidr"],
            }
            if tag:
                firewall_data["tag"] = tag
            host_metadata = {
                "publicIps": [link["publicIp"]],
                "providerFirewall": {k: v for k, v in firewall_data.items() if k != "tag"},
                "role": "inspector", "barraganOwned": True,
                "inspectionJobId": child.id, "cleanupRequired": True,
                "publicIp": link["publicIp"], "sshUser": INSPECTOR_ADMIN_USER,
            }
            firewall_metadata = {
                "role": "inspector_firewall", "barraganOwned": True,
                "inspectorHostResourceId": link["hostId"],
                "inspectionJobId": child.id,
                "managementSourceCidr": intent["managementSourceCidr"],
                "cleanupRequired": True,
            }
            if tag:
                host_metadata["nonexclusiveSelectorTag"] = tag
                firewall_metadata["nonexclusiveSelectorTag"] = tag
            if (settings is None or settings.current_host != {} or not settings.enabled
                    or settings.provider != prepared.provider
                    or settings.region != intent["region"] or settings.size != intent["size"]
                    or host is None or firewall is None
                    or active != {host.id, firewall.id}
                    or host.id != f"{prepared.provider}:inspector:{link['hostId']}"
                    or firewall.id != f"{prepared.provider}:inspector-firewall:{link['firewallId']}"
                    or host.id != prepared.host_record_id
                    or firewall.id != prepared.firewall_record_id
                    or link["hostId"] != prepared.host_id
                    or link["publicIp"] != prepared.public_ip
                    or host.resource_type != ("inspector_instance" if prepared.provider == "linode"
                                              else "inspector_droplet")
                    or firewall.resource_type != "inspector_firewall"
                    or host.resource_id != link["hostId"]
                    or firewall.resource_id != link["firewallId"]
                    or host.name != name or firewall.name != firewall_data["name"]
                    or host.region != settings.region or firewall.region != settings.region
                    or host.metadata != host_metadata or firewall.metadata != firewall_metadata
                    or any(row.engagement_id != engagement_id
                           or row.engagement_name != snapshot["engagementName"]
                           or row.provider != prepared.provider
                           or row.status != "preparation_required"
                           or row.lifecycle_state != "preparation_required"
                           or row.source != INSPECTOR_RESOURCE_SOURCE
                           or row.adoption_job_id != child.id for row in (host, firewall))
                    or len(defaults) != 1 or selected != defaults[0]
                    or selected.alias != intent["credentialAlias"]
                    or selected.updated_at != intent["credentialUpdatedAt"]
                    or key_digest != intent["keyFingerprintSha256"]
                    or _running_inspector_lifecycle_job(jobs, engagement_id) is not None):
                raise ValueError("Inspector owned row, credential or key differs")
            observer_host = _inspector_host_from_resource_record(host, settings=settings)
            proof_host = type(observer_host)(
                prepared.provider, "instance" if prepared.provider == "linode" else "droplet",
                link["hostId"], name, settings.region, link["publicIp"],
                ssh_user=INSPECTOR_ADMIN_USER,
                status="running" if prepared.provider == "linode" else "active",
                metadata={"publicIps": [link["publicIp"]], "providerFirewall": firewall_data},
            )
            expected_proof = InspectorProviderProof(
                proof_host, link["firewallId"], intent["managementSourceCidr"], tag)
            if link["proofSha256"] != _proof_hash(expected_proof):
                raise ValueError("Inspector materialization proof differs")
            return (child, host, firewall, settings, selected, observer_host,
                    key_path, key_digest, intent, link, expected_proof)

        baseline = authority()
        claim_token = baseline[0].input["claimToken"]
        claimed_at = baseline[0].input["claimClaimedAt"]

        def fence():
            previous = authority()
            if (previous[0].input["claimToken"] != claim_token
                    or previous[0].input["claimClaimedAt"] != claimed_at
                    or previous[1:] != baseline[1:]):
                raise ValueError("Inspector proof authority changed")
            moment = now()
            renewed = jobs.heartbeat_keyed_inspector_preparation_if_running_claimed(
                previous[0], owner=_OWNER, token=claim_token, claimed_at=claimed_at,
                expected_event_digest=prepared.preparation_journal_sha256,
                heartbeat_at=moment.isoformat(),
                expires_at=(moment + timedelta(minutes=4, seconds=50)).isoformat(),
            )
            after = authority()
            if renewed is None or after[0] != renewed or after[1:] != baseline[1:]:
                raise ValueError("Inspector proof claim or scope changed")

        fence()
        encrypted = baseline[4].encrypted_secret
        token = decrypt_secret(encrypted)
        if type(token) is not str or not token:
            raise ValueError("Inspector provider credential unavailable")
        transport = _GetOnlyTransport(transport_factory(prepared.provider),
                                      before_get=fence, after_get=fence)
        actual = provider_prover(
            provider=prepared.provider, token=token, transport=transport,
            resource_name=baseline[5].name, region=baseline[3].region,
            size=baseline[3].size, host_id=prepared.host_id,
            firewall_id=baseline[2].resource_id,
            management_cidr=baseline[8]["managementSourceCidr"],
        )
        fence()
        if type(actual) is not InspectorProviderProof or _proof_hash(actual) != _proof_hash(baseline[10]):
            raise ValueError("Inspector provider proof differs")
        fd = os.open(baseline[6] + ".pub", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            raw = os.read(fd, 4097)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o022
                    or len(raw) > 4096 or len(raw.splitlines()) != 1
                    or hashlib.sha256(raw.strip()).hexdigest() != baseline[7]
                    or not raw.strip().startswith(b"ssh-ed25519 ")):
                raise ValueError("Inspector public key differs")
            public_key = raw.decode("ascii").strip()
        finally:
            os.close(fd)
        fence()
        key = ObserverSshKey(baseline[6], public_key)
        policy_digest, first_line = verify_inspector_selected_source_ssh(
            baseline[5], key, baseline[8]["managementSourceCidr"], fence, ssh_runner,
        )
        proof = InspectorSupportHostProof(
            "support_host_proved_unpublished", prepared.coordinator_job_id,
            prepared.host_record_id, prepared.firewall_record_id,
            prepared.provider, prepared.host_id, prepared.public_ip,
            _proof_hash(actual), prepared.preparation_journal_sha256,
            policy_digest,
            first_line, False,
        )
        def validate_for_publication():
            current = authority()
            if (current[0].input.get("claimToken") != claim_token
                    or current[0].input.get("claimClaimedAt") != claimed_at
                    or current[1:] != baseline[1:]):
                raise ValueError("Inspector support proof authority changed")
            return current

        return InspectorSupportHostProofCapability(
            _ISSUER, proof, claim_token, claimed_at, validate_for_publication,
            min(datetime.now(timezone.utc) + timedelta(seconds=30),
                datetime.fromisoformat(authority()[0].input["claimExpiresAt"])),
        )
    except Exception:
        raise InspectorPreparationProofAttention(
            "Inspector support-host proof is unverified; readiness was not published"
        ) from None


def verify_inspector_selected_source_ssh(
    host: ObserverHost, key: ObserverSshKey, management_cidr: str,
    fence: Callable[[], None], ssh_runner: SshObserverRunner,
    *, timeout_seconds: int = 120,
) -> tuple[str, str]:
    """Five fenced, read-only SSH commands for the reviewed management source."""
    if type(ssh_runner) is not SshObserverRunner or type(key) is not ObserverSshKey:
        raise ValueError("concrete Inspector SSH runner and existing key required")
    common = ssh_runner._ssh_common(key)

    def checked(command: list[str]):
        completed = _run_checked(command, check=False, fence=fence,
                                 timeout_seconds=timeout_seconds)
        if completed.returncode != 0:
            raise ValueError("Inspector read-only SSH proof failed")
        return completed.stdout

    fence()
    checked(["ssh", *common, f"{INSPECTOR_ADMIN_USER}@{host.public_ip}", "sudo", "-n", "true"])
    peer = checked(["ssh", *common, f"{INSPECTOR_ADMIN_USER}@{host.public_ip}",
                    "/usr/bin/printenv", "SSH_CONNECTION"])
    peer_parts = peer.strip().split()
    if len(peer_parts) != 4 or len(peer) > 128:
        raise ValueError("Inspector SSH peer context is unproved")
    try:
        peer_ip = ipaddress.IPv4Address(peer_parts[0])
        source_network = ipaddress.IPv4Network(management_cidr, strict=True)
        if (peer_ip not in source_network or peer_ip.is_private or peer_ip.is_loopback
                or peer_ip.is_link_local or peer_ip.is_multicast or peer_ip.is_unspecified
                or peer_ip.is_reserved or not peer_ip.is_global
                or not all(peer_parts[index].isdecimal()
                           and 0 <= int(peer_parts[index]) <= 65535
                           for index in (1, 3))):
            raise ValueError("Inspector SSH peer context differs")
        ipaddress.IPv4Address(peer_parts[2])
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
        raise ValueError("Inspector SSH peer context is invalid") from exc
    policy = checked(["ssh", *common, f"{INSPECTOR_ADMIN_USER}@{host.public_ip}",
                      "sudo", "-n", "/usr/sbin/sshd", "-T", "-C",
                      f"user=root,addr={peer_ip},host={peer_ip}"])
    if not _SSHD_REQUIRED.issubset(set(policy.lower().splitlines())):
        raise ValueError("Inspector effective SSH policy differs")
    root = _run_checked(["ssh", *common, f"root@{host.public_ip}", "true"],
                        check=False, fence=fence, timeout_seconds=timeout_seconds)
    if root.returncode != 255 or "Permission denied (publickey)" not in root.stderr:
        raise ValueError("Inspector root SSH denial is unproved")
    package = checked(["ssh", *common, f"{INSPECTOR_ADMIN_USER}@{host.public_ip}",
                       "/usr/bin/nmap", "--version"])
    first_line = package.splitlines()[0] if package else ""
    if (len(package) > 1000 or not re.fullmatch(r"Nmap version [0-9][0-9A-Za-z.+_-]*.*",
                                               first_line, flags=re.ASCII)):
        raise ValueError("Inspector nmap version is unproved")
    fence()
    return hashlib.sha256(policy.encode("utf-8")).hexdigest(), first_line
