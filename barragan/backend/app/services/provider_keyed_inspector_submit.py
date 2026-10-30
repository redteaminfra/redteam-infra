# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant, one-shot DevTest Inspector submission; returned IDs are unverified."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from app.services.credentials import decrypt_secret_value
from app.services.observer_checks import (
    DigitalOceanObserverProvider, InspectorStagedSubmission, LinodeObserverProvider,
    _inspector_firewall_tag, _inspector_key_dir, _running_inspector_lifecycle_job,
)
from app.services.provider_keyed_comprehensive_teardown import _FENCE, _boundary, _child_id
from app.services.provider_keyed_inspector_create_intent import (
    InspectorCreateIntentReceipt, _existing_key_fingerprint, _inspector_rows_absent,
    recorded_keyed_inspector_intent,
)
from app.services.provider_keyed_inspector_stage import make_keyed_inspector_stage_recorder
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_teardown_quiescence import audit_pending_provider_keyed_bootstrap
from app.services.engagement_teardown import _fingerprint
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository


_OWNER = "provider-keyed-inspector-create"


class ProviderKeyedInspectorSubmitAttention(ValueError):
    """Submission may be ambiguous; never automatically submit it again."""


@dataclass(frozen=True)
class InspectorSubmittedUnverified:
    status: str
    provider: str
    resource_name: str
    host_id: str
    firewall_id: str
    tag_name: str
    event_digest: str


def _existing_public_key() -> tuple[str, str]:
    """Read the already-approved public key, never generate or alter key files."""
    fingerprint = _existing_key_fingerprint()  # validates private and public metadata
    path = _inspector_key_dir() / "id_ed25519.pub"
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        raw = os.read(fd, 4097)
        after = os.fstat(fd)
        if (before != after or not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid() or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) & 0o022
                or len(raw) > 4096 or len(raw.splitlines()) != 1
                or not raw.startswith(b"ssh-ed25519 ")
                or hashlib.sha256(raw.strip()).hexdigest() != fingerprint):
            raise ValueError("existing Inspector public key changed")
        return raw.decode("ascii").strip(), fingerprint
    finally:
        os.close(fd)


def _stage_data(provider: str, name: str, host_id: str, firewall_id: str, tag: str) -> list[dict]:
    stages = ("firewall", "instance") if provider == "linode" else (
        "tag", "firewall", "droplet", "attachment")
    data = []
    for stage in stages:
        for point in ("before_post", "response_received"):
            resource_id = (firewall_id if stage == "firewall" else host_id
                           if stage in {"instance", "droplet"} else "") if point == "response_received" else ""
            data.append({
                "provider": provider, "resourceName": name, "stage": stage,
                "point": point, "resourceId": resource_id,
                "firewallId": firewall_id if provider == "digitalocean" and (
                    stage in {"droplet", "attachment"} or stage == "firewall" and point == "response_received")
                else firewall_id if provider == "linode" and stage == "instance" else "",
                "dropletId": host_id if provider == "digitalocean" and (
                    stage == "attachment" or stage == "droplet" and point == "response_received") else "",
                "tagName": tag, "tagExclusive": False,
            })
    return data


def submit_keyed_inspector_once(
    receipt: InspectorCreateIntentReceipt, *, environment: str,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, credential_repository=None, lease_lookup=None,
    pending_auditor: Callable = audit_pending_provider_keyed_bootstrap,
    public_key_reader: Callable[[], tuple[str, str]] = _existing_public_key,
    decrypt_secret: Callable[[str], str] = decrypt_secret_value,
    provider_factory: Callable | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> InspectorSubmittedUnverified:
    """Use only a fresh in-process receipt; no recovery path calls this function."""
    started = False
    try:
        if environment != "devtest" or type(receipt) is not InspectorCreateIntentReceipt:
            raise ValueError("DevTest receipt required")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        settings = settings_repository or SqlAlchemyObserverSettingsRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        lookup = lease_lookup or _db_lease_lookup
        parent, core, snapshot, operation = _boundary(receipt.teardown_parent_id, jobs, plans, lookup)
        child = jobs.get(_child_id(core.id))
        if (operation != _FENCE or child is None or child.id != receipt.coordinator_job_id
                or snapshot["snapshotId"] != receipt.scope_snapshot_id
                or child.input.get("phase") != "inspector_create_started"
                or child.input.get("claimOwner") != _OWNER
                or child.input.get("claimToken") != receipt.claim_token
                or child.input.get("claimClaimedAt") != receipt.claim_claimed_at
                or child.status != "running" or len(child.events) != 5
                or job_event_digest(child.events) != receipt.event_digest
                or child.events[4].data.get("resourceName") != receipt.resource_name
                or not recorded_keyed_inspector_intent(child, parent, core, snapshot)):
            raise ValueError("Inspector receipt differs")
        intent = child.events[4].data
        provider = intent["provider"]
        if provider != "linode":
            raise ValueError("keyed Inspector provider is unsupported")
        initial_settings = settings.get(parent.target_id)
        if (initial_settings is None or initial_settings.engagement_id != parent.target_id
                or initial_settings.current_host != {}
                or initial_settings.provider != provider
                or initial_settings.region != intent["region"]
                or initial_settings.size != intent["size"]
                or not _inspector_rows_absent(tuple(resources.list_for_engagement(parent.target_id)), snapshot)
                or _running_inspector_lifecycle_job(jobs, parent.target_id) is not None):
            raise ValueError("Inspector settings or ownership differs")
        selected = credentials.get_default(provider)
        defaults = [row for row in credentials.list(provider)
                    if row.provider == provider and row.status == "active" and row.is_default]
        if (len(defaults) != 1 or selected != defaults[0]
                or not selected.id or not selected.encrypted_secret
                or selected.id != receipt.credential_id
                or hashlib.sha256(selected.encrypted_secret.encode("utf-8")).hexdigest()
                   != receipt.encrypted_secret_sha256
                or selected.alias != intent["credentialAlias"]
                or selected.updated_at != intent["credentialUpdatedAt"]):
            raise ValueError("Inspector credential differs")
        public_key, fingerprint = public_key_reader()
        if (type(public_key) is not str or not public_key.startswith("ssh-ed25519 ")
                or type(fingerprint) is not str
                or fingerprint != intent["keyFingerprintSha256"]
                or hashlib.sha256(public_key.strip().encode("ascii")).hexdigest() != fingerprint):
            raise ValueError("Inspector key differs")
        token = child.input["claimToken"]
        claimed_at = child.input["claimClaimedAt"]
        recorder = make_keyed_inspector_stage_recorder(
            receipt, environment=environment, job_repository=jobs, plan_repository=plans,
            settings_repository=settings, provider_resource_repository=resources,
            credential_repository=credentials, lease_lookup=lookup,
            pending_auditor=pending_auditor,
            key_fingerprint_reader=lambda: public_key_reader()[1], now=now,
        )
        if (credentials.get_default(provider) != selected
                or [row for row in credentials.list(provider)
                    if row.provider == provider and row.status == "active" and row.is_default] != [selected]
                or public_key_reader() != (public_key, fingerprint)
                or jobs.get(child.id) != child):
            raise ValueError("Inspector pre-submit authority changed")
        secret = decrypt_secret(selected.encrypted_secret)
        if type(secret) is not str or not secret:
            raise ValueError("Inspector credential cannot be decrypted")
        if (credentials.get_default(provider) != selected
                or [row for row in credentials.list(provider)
                    if row.provider == provider and row.status == "active" and row.is_default] != [selected]
                or public_key_reader() != (public_key, fingerprint)
                or jobs.get(child.id) != child):
            raise ValueError("Inspector credential or claim changed before submission")
        factory = provider_factory or (lambda kind, source: (
            LinodeObserverProvider(management_source_resolver=lambda: source)
            if kind == "linode" else DigitalOceanObserverProvider(
                management_source_resolver=lambda: source)))
        instance = factory(provider, intent["managementSourceCidr"])
        if (provider != "linode" or settings.get(parent.target_id) != initial_settings
                or initial_settings.provider != "linode"):
            raise ValueError("Inspector provider changed before submission")
        started = True
        submission = instance.submit_staged_inspector(
            token=secret, name=receipt.resource_name, region=intent["region"],
            size=intent["size"], public_key=public_key, stage_hook=recorder,
        )
        if (type(submission) is not InspectorStagedSubmission
                or submission.provider != provider or submission.resource_name != receipt.resource_name
                or type(submission.host_id) is not str or not submission.host_id
                or type(submission.firewall_id) is not str or not submission.firewall_id
                or submission.tag_exclusive is not False
                or submission.tag_name != (_inspector_firewall_tag(receipt.resource_name)
                                           if provider == "digitalocean" else "")):
            raise ValueError("Inspector submission differs")
        after = jobs.get(child.id)
        expected = _stage_data(provider, receipt.resource_name, submission.host_id,
                               submission.firewall_id, submission.tag_name)
        if (after is None or after.status != "running" or after.input.get("phase") != "inspector_create_started"
                or after.input.get("claimOwner") != _OWNER or after.input.get("claimToken") != token
                or after.input.get("claimClaimedAt") != claimed_at
                or datetime.fromisoformat(after.input["claimExpiresAt"]) <= now()
                or len(after.events) != 5 + len(expected)
                or job_event_digest(after.events[:5]) != receipt.event_digest
                or [event.sequence for event in after.events] != list(range(1, len(after.events) + 1))
                or any(event.message != "inspector_create_stage" or event.level != "info"
                       or event.data != data for event, data in zip(after.events[5:], expected))
                or credentials.get_default(provider) != selected
                or [row for row in credentials.list(provider)
                    if row.provider == provider and row.status == "active" and row.is_default] != [selected]
                or public_key_reader() != (public_key, fingerprint)
                or settings.get(parent.target_id) != initial_settings
                or not _inspector_rows_absent(tuple(resources.list_for_engagement(parent.target_id)), snapshot)
                or _running_inspector_lifecycle_job(jobs, parent.target_id) is not None):
            raise ValueError("Inspector submission journal differs")
        final_parent, final_core, final_snapshot, final_operation = _boundary(
            receipt.teardown_parent_id, jobs, plans, lookup)
        if ((final_parent, final_core, final_snapshot, final_operation)
                != (parent, core, snapshot, operation)):
            raise ValueError("Inspector authority changed after submission")
        pending_auditor(core.id, confirmed_scope=snapshot["providerScopes"][0],
                        confirmed_scope_sha256=_fingerprint(snapshot),
                        workspace_root=Path(snapshot["providerScopes"][0]["workspace"]),
                        job_repository=jobs)
        return InspectorSubmittedUnverified(
            "submitted_unverified", provider, receipt.resource_name,
            submission.host_id, submission.firewall_id, submission.tag_name,
            job_event_digest(after.events),
        )
    except Exception:
        raise ProviderKeyedInspectorSubmitAttention(
            "Inspector submission requires explicit reconciliation" if started
            else "Inspector submission preflight failed") from None
