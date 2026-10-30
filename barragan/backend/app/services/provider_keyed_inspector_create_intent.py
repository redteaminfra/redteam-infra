# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant DevTest one-shot Inspector creation intent; no host or provider action."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from uuid import uuid4

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.observer_checks import (
    INSPECTOR_RESOURCE_SOURCE, _inspector_key_dir, _running_inspector_lifecycle_job,
    resolve_inspector_management_source_cidr,
)
from app.services.provider_keyed_comprehensive_teardown import (
    ACTION, _FENCE, _boundary, _child_id, _same_child,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_teardown_quiescence import audit_pending_provider_keyed_bootstrap
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import (
    SqlAlchemyJobRepository, inspector_claim_generation_digest, job_event_digest,
    valid_inspector_management_source_cidr,
)
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import (
    SqlAlchemyProviderResourceRepository, TERMINAL_RECORD_STATUSES,
)


_OWNER = "provider-keyed-inspector-create"
_PHASE = "inspector_create_started"


class ProviderKeyedInspectorCreateIntentError(ValueError):
    """Inspector creation authority cannot be proven without mutation."""


class ProviderKeyedInspectorCreateAttention(ProviderKeyedInspectorCreateIntentError):
    """A one-shot create intent already exists or became ambiguous; never retry."""


@dataclass(frozen=True)
class InspectorCreateIntentReceipt:
    coordinator_job_id: str
    teardown_parent_id: str
    scope_snapshot_id: str
    resource_name: str
    event_digest: str
    claim_token: str = field(repr=False)
    claim_claimed_at: str
    credential_id: str
    encrypted_secret_sha256: str
    provider_create_authorized: bool = False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _existing_key_fingerprint() -> str:
    """Read an existing durable public key without generating or changing files."""
    directory = _inspector_key_dir()
    directory_info = directory.lstat()
    if (not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_uid != os.geteuid()
            or stat.S_IMODE(directory_info.st_mode) & 0o022):
        raise ValueError("existing Inspector key directory is unsafe")
    private = directory / "id_ed25519"
    public = directory / "id_ed25519.pub"
    for path, private_file in ((private, True), (public, False)):
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or mode & 0o022
                or (private_file and mode & 0o077)):
            raise ValueError("existing Inspector key is unsafe")
    descriptor = os.open(public, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        content = os.read(descriptor, 4097)
        after = os.fstat(descriptor)
        if (before != after or len(content) > 4096 or not content.startswith(b"ssh-ed25519 ")
                or len(content.splitlines()) != 1):
            raise ValueError("existing Inspector public key is invalid")
        return hashlib.sha256(content.strip()).hexdigest()
    finally:
        os.close(descriptor)


def _inspector_rows_absent(rows: tuple, snapshot: dict) -> bool:
    inspector = snapshot.get("inspector")
    if (not isinstance(inspector, dict) or inspector.get("tracked") is not False
            or inspector.get("ownedProviderRecordIds") != []):
        return False
    for row in rows:
        metadata = row.metadata if isinstance(row.metadata, dict) else {}
        role = str(metadata.get("role") or "").lower()
        if (str(row.status).lower() not in TERMINAL_RECORD_STATUSES
                and (str(row.resource_type).startswith("inspector_")
                     or role.startswith("inspector")
                     or row.source == INSPECTOR_RESOURCE_SOURCE)):
            return False
    return True


def recorded_keyed_inspector_intent(child, parent, core, snapshot: dict) -> bool:
    """Recognize the exact consumed journal for read-only recovery attention."""
    inputs = child.input
    base = {key: value for key, value in inputs.items() if not key.startswith("claim")}
    expected = {
        "engagementId": parent.target_id, "coreJobId": core.id,
        "corePlanId": core.input.get("corePlanId"), "teardownParentId": parent.id,
        "scopeSnapshotId": snapshot["snapshotId"],
        "providerScopeSha256": snapshot["providerScopeSha256"],
        "mutation": True, "phase": _PHASE,
    }
    events = child.events
    if (child.id != _child_id(core.id) or child.action != ACTION
            or child.status != "running" or child.finished_at is not None
            or child.target != f"engagement:{parent.target_id}"
            or child.target_type != "engagement" or child.target_id != parent.target_id
            or child.requested_by != parent.requested_by or child.artifact_refs != []
            or base != expected or inputs.get("claimOwner") != _OWNER
            or type(inputs.get("claimToken")) is not str or len(inputs["claimToken"]) < 16
            or len(events) != 5 or [item.sequence for item in events] != [1, 2, 3, 4, 5]
            or [item.message for item in events[:4]] != [
                "keyed teardown coordinator queued", "keyed teardown coordinator started",
                "keyed teardown handoff intended",
                "keyed teardown handoff verified; Inspector preflight pending",
            ]
            or [item.data for item in events[:4]] != [
                {"snapshotId": snapshot["snapshotId"]}, {}, {}, {"corePlanId": core.input["corePlanId"]},
            ] or any(item.level != "info" for item in events)
            or events[4].message != _PHASE or not isinstance(events[4].data, dict)):
        return False
    data = events[4].data
    return (set(data) == {
                "scopeSnapshotId", "providerScopeSha256", "provider", "region", "size",
                "credentialAlias", "credentialId", "credentialSha256",
                "credentialUpdatedAt", "resourceName", "keyFingerprintSha256",
                "managementSourceCidr", "claimGenerationSha256",
            }
            and data["scopeSnapshotId"] == snapshot["snapshotId"]
            and data["providerScopeSha256"] == snapshot["providerScopeSha256"]
            and type(data["provider"]) is str and data["provider"] in {"linode", "digitalocean"}
            and type(data["credentialId"]) is str and bool(data["credentialId"])
            and type(data["credentialSha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", data["credentialSha256"]) is not None
            and type(data["resourceName"]) is str
            and re.fullmatch(r"inspector-[0-9a-f]{32}", data["resourceName"]) is not None
            and type(data["keyFingerprintSha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", data["keyFingerprintSha256"]) is not None
            and type(inputs.get("claimClaimedAt")) is str
            and data["claimGenerationSha256"] == inspector_claim_generation_digest(
                token=inputs["claimToken"], claimed_at=inputs["claimClaimedAt"])
            and valid_inspector_management_source_cidr(data["managementSourceCidr"]))


def reserve_keyed_inspector_create_intent(
    teardown_parent_id: str, *, environment: str,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, credential_repository=None, lease_lookup=None,
    pending_auditor: Callable = audit_pending_provider_keyed_bootstrap,
    key_fingerprint_reader: Callable[[], str] = _existing_key_fingerprint,
    management_source_resolver: Callable[[], str] = resolve_inspector_management_source_cidr,
    now: Callable[[], datetime] = _now,
    token_factory: Callable[[], str] = lambda: uuid4().hex,
    name_token_factory: Callable[[], str] = lambda: uuid4().hex,
) -> InspectorCreateIntentReceipt:
    """Consume the one-shot intent without calling a provider or SSH runner."""
    consumed = False
    try:
        if environment != "devtest" or not teardown_parent_id:
            raise ValueError("DevTest keyed intent only")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        lookup = lease_lookup or _db_lease_lookup

        def authority(*, require_handoff_claim: bool = True):
            parent, core, snapshot, operation = _boundary(
                teardown_parent_id, jobs, plans, lookup)
            child = jobs.get(_child_id(core.id))
            if (operation != _FENCE or child is None or child.action != ACTION
                    or len([row for row in jobs.list_for_engagement(parent.target_id)
                            if row.action == ACTION]) != 1
                    or _running_inspector_lifecycle_job(jobs, parent.target_id) is not None):
                raise ValueError("keyed coordinator handoff differs")
            if child.input.get("phase") == _PHASE:
                raise ProviderKeyedInspectorCreateAttention(
                    "Inspector create intent already recorded; explicit reconciliation is required")
            if (child.input.get("phase") != "awaiting_inspector_preflight"
                    or (require_handoff_claim and not _same_child(child, parent, core, snapshot))):
                raise ValueError("keyed coordinator handoff differs")
            scope = snapshot["providerScopes"][0]
            pending_auditor(
                core.id, confirmed_scope=scope,
                confirmed_scope_sha256=_fingerprint(snapshot),
                workspace_root=Path(scope["workspace"]), job_repository=jobs,
            )
            settings = settings_repo.get(parent.target_id)
            if (settings is None or settings.engagement_id != parent.target_id
                    or settings.current_host != {}
                    or settings.provider not in {"linode", "digitalocean"}
                    or not settings.region or not settings.size):
                raise ValueError("persisted Inspector settings are absent or ambiguous")
            if settings.provider == "digitalocean":
                raise ProviderKeyedInspectorCreateIntentError(
                    "Keyed infrastructure requires a Linode Inspector; select Linode before deployment"
                )
            rows = tuple(resources.list_for_engagement(parent.target_id))
            if not _inspector_rows_absent(rows, snapshot):
                raise ValueError("Inspector ownership is not absent")
            defaults = [item for item in credentials.list(settings.provider)
                        if item.provider == settings.provider and item.status == "active"
                        and item.is_default]
            selected = credentials.get_default(settings.provider)
            if (len(defaults) != 1 or selected != defaults[0]
                    or not selected.alias or not selected.updated_at):
                raise ValueError("Inspector credential version is ambiguous")
            fingerprint = key_fingerprint_reader()
            if (type(fingerprint) is not str or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None):
                raise ValueError("Inspector key identity is unproved")
            return parent, core, snapshot, child, settings, rows, selected, fingerprint

        before = authority()
        parent, core, snapshot, child, settings, rows, credential, fingerprint = before
        # Resolve and bind the one egress /32 before consuming the one-shot
        # claim. A later provider submitter must use this exact journaled CIDR.
        management_source = management_source_resolver()
        if not valid_inspector_management_source_cidr(management_source):
            raise ValueError("Inspector management source is unproved")
        instant = now()
        token = token_factory()
        name_token = name_token_factory()
        if (instant.tzinfo is None or instant.utcoffset() != timedelta(0)
                or type(token) is not str or len(token) < 16
                or type(name_token) is not str or re.fullmatch(r"[0-9a-f]{32}", name_token) is None):
            raise ValueError("Inspector claim or opaque name is invalid")
        claimed = jobs.claim_lease(
            child.id, owner=_OWNER, token=token, claimed_at=instant.isoformat(),
            expires_at=(instant + timedelta(minutes=5)).isoformat(),
            eligible_statuses={"running"}, eligible_phases={"awaiting_inspector_preflight"},
        )
        if claimed is None:
            raise ValueError("Inspector intent claim lost")
        # A pre-read cannot authorize the CAS: check every separate authority row
        # again after claiming, then check them once more after consuming intent.
        after_claim = authority(require_handoff_claim=False)
        if (after_claim[:3] != before[:3] or after_claim[4:] != before[4:]
                or after_claim[3] != claimed
                or claimed.events != child.events
                or {key: value for key, value in claimed.input.items()
                    if not key.startswith("claim")} != {key: value for key, value in child.input.items()
                                                       if not key.startswith("claim")}
                or claimed.input.get("claimOwner") != _OWNER
                or claimed.input.get("claimToken") != token):
            raise ValueError("Inspector authority drifted after claim")
        event = JobEvent(5, "info", _PHASE, {
            "scopeSnapshotId": snapshot["snapshotId"],
            "providerScopeSha256": snapshot["providerScopeSha256"],
            "provider": settings.provider, "region": settings.region, "size": settings.size,
            "credentialAlias": credential.alias,
            "credentialId": credential.id,
            "credentialSha256": hashlib.sha256(
                credential.encrypted_secret.encode("utf-8")).hexdigest(),
            "credentialUpdatedAt": credential.updated_at,
            "resourceName": f"inspector-{name_token}",
            "keyFingerprintSha256": fingerprint,
            "managementSourceCidr": management_source,
            "claimGenerationSha256": inspector_claim_generation_digest(
                token=token, claimed_at=claimed.input["claimClaimedAt"]),
        })
        moment = now()
        written = jobs.append_keyed_inspector_create_intent_if_running_claimed(
            claimed, owner=_OWNER, token=token,
            expected_event_digest=job_event_digest(claimed.events),
            heartbeat_at=moment.isoformat(),
            expires_at=(moment + timedelta(minutes=5)).isoformat(), event=event,
        )
        if written is None:
            raise ValueError("Inspector intent CAS lost")
        consumed = True
        final_parent, final_core, final_snapshot, final_operation = _boundary(
            teardown_parent_id, jobs, plans, lookup)
        final_defaults = [item for item in credentials.list(settings.provider)
                          if item.provider == settings.provider and item.status == "active"
                          and item.is_default]
        pending_auditor(
            core.id, confirmed_scope=snapshot["providerScopes"][0],
            confirmed_scope_sha256=_fingerprint(snapshot),
            workspace_root=Path(snapshot["providerScopes"][0]["workspace"]),
            job_repository=jobs,
        )
        if ((final_parent, final_core, final_snapshot) != before[:3]
                or final_operation != _FENCE
                or jobs.get(parent.id) != parent
                or lookup(parent.target_id) != (core.input["corePlanId"], _FENCE)
                or len([row for row in jobs.list_for_engagement(parent.target_id)
                        if row.action == ACTION]) != 1
                or _running_inspector_lifecycle_job(jobs, parent.target_id) is not None
                or settings_repo.get(parent.target_id) != settings
                or tuple(resources.list_for_engagement(parent.target_id)) != rows
                or final_defaults != [credential]
                or credentials.get_default(settings.provider) != credential
                or key_fingerprint_reader() != fingerprint
                or jobs.get(claimed.id) != written
                or not recorded_keyed_inspector_intent(written, parent, core, snapshot)):
            raise ProviderKeyedInspectorCreateAttention(
                "Inspector intent recorded but authority changed; explicit reconciliation is required")
        return InspectorCreateIntentReceipt(
            written.id, parent.id, snapshot["snapshotId"], event.data["resourceName"],
            job_event_digest(written.events), token, written.input["claimClaimedAt"],
            event.data["credentialId"], event.data["credentialSha256"],
        )
    except (ProviderKeyedInspectorCreateAttention, ProviderKeyedInspectorCreateIntentError):
        raise
    except Exception:
        if consumed:
            raise ProviderKeyedInspectorCreateAttention(
                "Inspector intent recorded but verification is incomplete; explicit reconciliation is required"
            ) from None
        raise ProviderKeyedInspectorCreateIntentError(
            "Inspector create intent is unproved; no provider or SSH action was started"
        ) from None
