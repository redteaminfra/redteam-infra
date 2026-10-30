# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant, claim-fenced recorder for opt-in Inspector provider stage hooks."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.observer_checks import InspectorCreateStage, _running_inspector_lifecycle_job
from app.services.provider_keyed_comprehensive_teardown import ACTION, _FENCE, _boundary, _child_id
from app.services.provider_keyed_inspector_create_intent import (
    InspectorCreateIntentReceipt, _existing_key_fingerprint, _inspector_rows_absent,
    recorded_keyed_inspector_intent,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_teardown_quiescence import audit_pending_provider_keyed_bootstrap
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository


_OWNER = "provider-keyed-inspector-create"


class ProviderKeyedInspectorStageAttention(ValueError):
    """The one-shot provider stage cannot continue without reconciliation."""


def make_keyed_inspector_stage_recorder(
    receipt: InspectorCreateIntentReceipt, *, environment: str,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, credential_repository=None, lease_lookup=None,
    pending_auditor: Callable = audit_pending_provider_keyed_bootstrap,
    key_fingerprint_reader: Callable[[], str] = _existing_key_fingerprint,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> Callable[[InspectorCreateStage], None]:
    """Return a synchronous journal callback; this never invokes a provider."""
    if (environment != "devtest" or type(receipt) is not InspectorCreateIntentReceipt
            or receipt.provider_create_authorized is not False
            or type(receipt.event_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", receipt.event_digest) is None):
        raise ProviderKeyedInspectorStageAttention("Inspector stage receipt is unproved")
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    expected_digest = receipt.event_digest
    consumed = False
    bound_token: str | None = None
    bound_claimed_at: str | None = None

    def authority(expected: str):
        parent, core, snapshot, operation = _boundary(receipt.teardown_parent_id, jobs, plans, lookup)
        child = jobs.get(_child_id(core.id))
        if (operation != _FENCE or parent.id != receipt.teardown_parent_id
                or snapshot["snapshotId"] != receipt.scope_snapshot_id
                or child is None or child.id != receipt.coordinator_job_id
                or child.action != ACTION or child.status != "running" or child.finished_at is not None
                or child.input.get("phase") != "inspector_create_started"
                or child.input.get("claimOwner") != _OWNER
                or child.input.get("claimToken") != receipt.claim_token
                or child.input.get("claimClaimedAt") != receipt.claim_claimed_at
                or type(child.input.get("claimToken")) is not str
                or len(child.input["claimToken"]) < 16
                or (bound_token is not None and child.input.get("claimToken") != bound_token)
                or (bound_claimed_at is not None
                    and child.input.get("claimClaimedAt") != bound_claimed_at)
                or child.input.get("engagementId") != parent.target_id
                or child.input.get("coreJobId") != core.id
                or child.input.get("corePlanId") != core.input["corePlanId"]
                or child.input.get("teardownParentId") != parent.id
                or child.input.get("scopeSnapshotId") != snapshot["snapshotId"]
                or child.input.get("providerScopeSha256") != snapshot["providerScopeSha256"]
                or child.input.get("mutation") is not True
                or child.target != f"engagement:{parent.target_id}"
                or child.target_type != "engagement" or child.target_id != parent.target_id
                or child.requested_by != parent.requested_by or child.artifact_refs != []
                or len([row for row in jobs.list_for_engagement(parent.target_id)
                        if row.action == ACTION]) != 1
                or _running_inspector_lifecycle_job(jobs, parent.target_id) is not None
                or len(child.events) < 5
                or job_event_digest(child.events[:5]) != receipt.event_digest
                or job_event_digest(child.events) != expected
                or child.events[4].message != "inspector_create_started"
                or child.events[4].data.get("resourceName") != receipt.resource_name):
            raise ValueError("Inspector stage authority differs")
        instant = now()
        expiry = child.input.get("claimExpiresAt")
        if (instant.tzinfo is None or instant.utcoffset() != timedelta(0)
                or type(expiry) is not str or instant >= datetime.fromisoformat(expiry)):
            raise ValueError("Inspector stage claim expired")
        pending_auditor(
            core.id, confirmed_scope=snapshot["providerScopes"][0],
            confirmed_scope_sha256=_fingerprint(snapshot),
            workspace_root=Path(snapshot["providerScopes"][0]["workspace"]),
            job_repository=jobs,
        )
        settings = settings_repo.get(parent.target_id)
        rows = tuple(resources.list_for_engagement(parent.target_id))
        if (settings is None or settings.engagement_id != parent.target_id
                or settings.current_host != {} or settings.provider not in {"linode", "digitalocean"}
                or not settings.region or not settings.size
                or not _inspector_rows_absent(rows, snapshot)):
            raise ValueError("Inspector settings or ownership differs")
        defaults = [item for item in credentials.list(settings.provider)
                    if item.provider == settings.provider and item.status == "active" and item.is_default]
        selected = credentials.get_default(settings.provider)
        intent = child.events[4].data
        if (len(defaults) != 1 or selected != defaults[0]
                or intent.get("provider") != settings.provider
                or intent.get("region") != settings.region or intent.get("size") != settings.size
                or intent.get("credentialAlias") != selected.alias
                or intent.get("credentialUpdatedAt") != selected.updated_at
                or selected.id != receipt.credential_id
                or hashlib.sha256(selected.encrypted_secret.encode("utf-8")).hexdigest()
                   != receipt.encrypted_secret_sha256
                or intent.get("scopeSnapshotId") != snapshot["snapshotId"]
                or intent.get("providerScopeSha256") != snapshot["providerScopeSha256"]
                or intent.get("keyFingerprintSha256") != key_fingerprint_reader()):
            raise ValueError("Inspector credential or key differs")
        return parent, core, snapshot, child, settings, rows, selected

    try:
        parent, core, snapshot, child, *_ = authority(expected_digest)
        if (len(child.events) != 5
                or not recorded_keyed_inspector_intent(child, parent, core, snapshot)):
            raise ValueError("Inspector create receipt journal differs")
        bound_token = child.input["claimToken"]
        bound_claimed_at = child.input["claimClaimedAt"]
    except Exception:
        raise ProviderKeyedInspectorStageAttention("Inspector stage receipt cannot be bound") from None

    def record(stage: InspectorCreateStage) -> None:
        nonlocal expected_digest, consumed
        if consumed:
            raise ProviderKeyedInspectorStageAttention("Inspector stage callback already consumed")
        # Any attempted callback is one-use, including failed prechecks. A POST
        # may already have happened before a response hook reaches this function.
        consumed = True
        written = False
        try:
            if type(stage) is not InspectorCreateStage or stage.resource_name != receipt.resource_name:
                raise ValueError("Inspector stage identity differs")
            before = authority(expected_digest)
            child = before[3]
            data = {
                "provider": stage.provider, "resourceName": stage.resource_name,
                "stage": stage.stage, "point": stage.point, "resourceId": stage.resource_id,
                "firewallId": stage.firewall_id, "dropletId": stage.droplet_id,
                "tagName": stage.tag_name, "tagExclusive": stage.tag_exclusive,
            }
            moment = now()
            event = JobEvent(len(child.events) + 1, "info", "inspector_create_stage", data)
            updated = jobs.append_keyed_inspector_stage_if_running_claimed(
                child, owner=_OWNER, token=child.input["claimToken"],
                expected_event_digest=expected_digest,
                heartbeat_at=moment.isoformat(),
                expires_at=(moment + timedelta(minutes=5)).isoformat(), event=event,
            )
            if updated is None:
                raise ValueError("Inspector stage append lost")
            written = True
            next_digest = job_event_digest(updated.events)
            after = authority(next_digest)
            if (after[:3] != before[:3] or after[4:] != before[4:]
                    or after[3] != updated or jobs.get(child.id) != updated):
                raise ValueError("Inspector stage authority changed")
            expected_digest = next_digest
            consumed = False
        except Exception:
            message = ("Inspector stage recorded but authority changed; explicit reconciliation is required"
                       if written else "Inspector stage unproved; explicit reconciliation is required")
            raise ProviderKeyedInspectorStageAttention(message) from None

    return record
