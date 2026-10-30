# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only, short-lived DevTest binding for an already owned Inspector."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from app.services.credentials import decrypt_secret_value
from app.services.observer_checks import _inspector_key_dir, _running_inspector_lifecycle_job
from app.services.provider_keyed_comprehensive_teardown import ACTION, _FENCE, _boundary, _child_id
from app.services.provider_keyed_inspector_create_intent import _existing_key_fingerprint
from app.services.provider_keyed_inspector_materialize import (
    _proof_hash, recover_materialized_keyed_inspector,
)
from app.services.provider_keyed_inspector_provider_proof import (
    InspectorProviderPending, InspectorProviderProof, prove_keyed_inspector_provider,
)
from app.services.provider_keyed_inspector_settlement import _GetOnlyTransport, _default_transport
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_teardown_quiescence import audit_pending_provider_keyed_bootstrap
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository


_OWNER = "provider-keyed-inspector-create"
_MAX_SECONDS = 120.0
_INTERVAL_SECONDS = 10.0


class InspectorPreparationAttention(ValueError):
    """Read-only preparation authority or provider proof is unverified."""


@dataclass(frozen=True)
class InspectorPreparationReceipt:
    status: str
    engagement_id: str
    coordinator_job_id: str
    scope_snapshot_id: str
    provider: str
    host_id: str
    firewall_id: str
    public_ip: str
    key_path: str
    key_fingerprint_sha256: str
    claim_token: str = field(repr=False)
    claim_claimed_at: str
    journal_sha256: str
    expires_at: str
    host_prepare_authorized: bool = False


def _existing_key_identity() -> tuple[Path, str]:
    fingerprint = _existing_key_fingerprint()
    return _inspector_key_dir() / "id_ed25519", fingerprint


def _safe_key_identity(reader: Callable[[], tuple[Path, str]]) -> tuple[str, str]:
    path, fingerprint = reader()
    if (not isinstance(path, Path) or not path.is_absolute()
            or type(fingerprint) is not str or len(fingerprint) != 64
            or any(char not in "0123456789abcdef" for char in fingerprint)):
        raise ValueError("Inspector key identity differs")
    info = path.lstat()
    directory = path.parent.lstat()
    if (path != path.resolve(strict=True) or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid() or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o077
            or not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid()
            or stat.S_IMODE(directory.st_mode) & 0o022):
        raise ValueError("Inspector key path is unsafe")
    return str(path), fingerprint


def _verify_key_pair(private_path: str, expected_public_sha256: str) -> None:
    """Prove the retained private key corresponds to its pinned public key."""
    public_path = Path(private_path + ".pub")
    fd = os.open(public_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        raw = os.read(fd, 4097)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o022
                or len(raw) > 4096 or len(raw.splitlines()) != 1
                or hashlib.sha256(raw.strip()).hexdigest() != expected_public_sha256):
            raise ValueError("Inspector public key differs")
    finally:
        os.close(fd)
    result = subprocess.run(
        ["/usr/bin/ssh-keygen", "-y", "-P", "", "-f", private_path],
        capture_output=True, check=False, timeout=5,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"},
    )
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise ValueError("Inspector private key cannot be verified")
    public_parts = raw.strip().split()
    derived_parts = result.stdout.strip().split()
    if (len(public_parts) < 2 or len(derived_parts) < 2
            or public_parts[:2] != derived_parts[:2]
            or public_parts[0] != b"ssh-ed25519"):
        raise ValueError("Inspector private/public keys differ")


def bind_owned_keyed_inspector_for_preparation(
    coordinator_job_id: str, engagement_id: str, *, environment: str,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, credential_repository=None, lease_lookup=None,
    pending_auditor: Callable = audit_pending_provider_keyed_bootstrap,
    key_identity_reader: Callable[[], tuple[Path, str]] = _existing_key_identity,
    key_pair_verifier: Callable[[str, str], None] = _verify_key_pair,
    decrypt_secret: Callable[[str], str] = decrypt_secret_value,
    transport_factory: Callable = _default_transport,
    proof: Callable = prove_keyed_inspector_provider,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> InspectorPreparationReceipt:
    """Poll exact returned IDs using GET only; never grant SSH execution."""
    try:
        if environment != "devtest":
            raise ValueError("DevTest keyed Inspector only")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        lookup = lease_lookup or _db_lease_lookup

        def authority():
            owned = recover_materialized_keyed_inspector(
                coordinator_job_id, engagement_id, environment=environment,
                job_repository=jobs, plan_repository=plans,
                settings_repository=settings_repo, provider_resource_repository=resources,
                lease_lookup=lookup, pending_auditor=pending_auditor,
            )
            child = jobs.get(coordinator_job_id)
            parent, core, snapshot, operation = _boundary(
                child.input["teardownParentId"], jobs, plans, lookup)
            settings = settings_repo.get(engagement_id)
            host = resources.get(owned.host_record_id)
            firewall = resources.get(owned.firewall_record_id)
            intent = child.events[4].data
            defaults = [item for item in credentials.list(intent["provider"])
                        if item.provider == intent["provider"] and item.status == "active"
                        and item.is_default]
            selected = credentials.get_default(intent["provider"])
            key_path, fingerprint = _safe_key_identity(key_identity_reader)
            key_pair_verifier(key_path, fingerprint)
            expiry = datetime.fromisoformat(child.input["claimExpiresAt"])
            instant = now()
            if (operation != _FENCE or child.id != _child_id(core.id)
                    or child.action != ACTION or child.status != "running"
                    or child.input.get("phase") != "inspector_owned_unprepared"
                    or child.input.get("claimOwner") != _OWNER
                    or type(child.input.get("claimToken")) is not str
                    or type(child.input.get("claimClaimedAt")) is not str
                    or expiry.tzinfo is None or instant.tzinfo is None
                    or instant.utcoffset() != timedelta(0)
                    or expiry <= instant or expiry <= datetime.now(timezone.utc)
                    or len(defaults) != 1 or selected != defaults[0]
                    or selected.alias != intent["credentialAlias"]
                    or selected.updated_at != intent["credentialUpdatedAt"]
                    or fingerprint != intent["keyFingerprintSha256"]
                    or settings.current_host != {}
                    or _running_inspector_lifecycle_job(jobs, engagement_id) is not None):
                raise ValueError("Inspector preparation authority differs")
            return (parent, core, snapshot, child, settings, host, firewall,
                    selected, key_path, fingerprint)

        baseline = authority()
        parent, core, snapshot, child, settings, host, firewall, selected, key_path, fingerprint = baseline
        intent = child.events[4].data
        token = decrypt_secret(selected.encrypted_secret)
        if type(token) is not str or not token:
            raise ValueError("Inspector credential unavailable")
        if authority() != baseline:
            raise ValueError("Inspector preparation boundary changed")
        start = monotonic()
        deadline = start + _MAX_SECONDS
        transport = transport_factory(settings.provider)

        def fence():
            if monotonic() >= deadline or authority() != baseline:
                raise ValueError("Inspector preparation authority changed or timed out")

        guarded = _GetOnlyTransport(transport, before_get=fence, after_get=fence)
        while True:
            fence()
            try:
                checked = proof(
                    provider=settings.provider, token=token, transport=guarded,
                    resource_name=host.name, region=settings.region, size=settings.size,
                    host_id=host.resource_id, firewall_id=firewall.resource_id,
                    management_cidr=intent["managementSourceCidr"],
                )
            except InspectorProviderPending:
                fence()
                remaining = deadline - monotonic()
                if remaining <= _INTERVAL_SECONDS:
                    raise ValueError("Inspector preparation GET proof did not settle")
                sleep(_INTERVAL_SECONDS)
                continue
            fence()
            if (type(checked) is not InspectorProviderProof
                    or checked.host.provider != settings.provider
                    or checked.host.resource_id != host.resource_id
                    or checked.host.name != host.name or checked.host.region != host.region
                    or checked.host.public_ip != host.metadata["publicIp"]
                    or checked.firewall_id != firewall.resource_id
                    or checked.management_cidr != intent["managementSourceCidr"]
                    or checked.tag_exclusive is not False
                    or _proof_hash(checked) != child.events[-1].data["proofSha256"]):
                raise ValueError("Inspector preparation provider identity differs")
            if authority() != baseline:
                raise ValueError("Inspector preparation authority changed")
            return InspectorPreparationReceipt(
                "proved_unprepared", engagement_id, child.id, snapshot["snapshotId"],
                settings.provider, host.resource_id, firewall.resource_id,
                host.metadata["publicIp"], key_path, fingerprint,
                child.input["claimToken"], child.input["claimClaimedAt"],
                job_event_digest(child.events),
                min(datetime.fromisoformat(child.input["claimExpiresAt"]),
                    datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat(), False,
            )
    except Exception:
        raise InspectorPreparationAttention(
            "Inspector preparation binding is unverified; explicit reconciliation is required"
        ) from None
