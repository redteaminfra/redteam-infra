# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant bounded GET settlement of one already-submitted DevTest Inspector."""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from app.integrations.digitalocean_validation import UrllibDigitalOceanTransport
from app.integrations.linode_validation import UrllibLinodeTransport
from app.services.credentials import decrypt_secret_value
from app.services.engagement_teardown import _fingerprint
from app.services.observer_checks import (
    _inspector_firewall_tag, _running_inspector_lifecycle_job,
)
from app.services.provider_keyed_comprehensive_teardown import ACTION, _FENCE, _boundary, _child_id
from app.services.provider_keyed_inspector_create_intent import (
    InspectorCreateIntentReceipt, _existing_key_fingerprint, _inspector_rows_absent,
)
from app.services.provider_keyed_inspector_provider_proof import (
    InspectorProviderPending, InspectorProviderProof, prove_keyed_inspector_provider,
)
from app.services.provider_keyed_inspector_submit import InspectorSubmittedUnverified, _stage_data
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_teardown_quiescence import audit_pending_provider_keyed_bootstrap
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import (
    SqlAlchemyJobRepository, inspector_claim_generation_digest, job_event_digest,
    valid_inspector_management_source_cidr,
)
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository


_OWNER = "provider-keyed-inspector-create"
_MAX_SECONDS = 600.0
_INTERVAL_SECONDS = 10.0


class InspectorSettlementAttention(ValueError):
    """GET proof or one-shot authority is uncertain; explicit reconciliation is needed."""


class _GetOnlyTransport:
    def __init__(self, transport, *, before_get: Callable[[], None],
                 after_get: Callable[[], None]):
        self._transport = transport
        self._before_get = before_get
        self._after_get = after_get

    def request(self, method: str, path: str, token: str, body=None):
        if method != "GET" or body is not None:
            raise ValueError("Inspector settlement transport is GET-only")
        self._before_get()
        try:
            return self._transport.request("GET", path, token)
        finally:
            self._after_get()


def _default_transport(provider: str):
    return (UrllibLinodeTransport(timeout=10) if provider == "linode"
            else UrllibDigitalOceanTransport(timeout=10))


def settle_submitted_keyed_inspector(
    receipt: InspectorCreateIntentReceipt, submission: InspectorSubmittedUnverified, *,
    environment: str, job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, credential_repository=None, lease_lookup=None,
    pending_auditor: Callable = audit_pending_provider_keyed_bootstrap,
    key_fingerprint_reader: Callable[[], str] = _existing_key_fingerprint,
    decrypt_secret: Callable[[str], str] = decrypt_secret_value,
    transport_factory: Callable = _default_transport,
    proof: Callable = prove_keyed_inspector_provider,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> InspectorProviderProof:
    """Retry typed pending reads only; this never submits or adopts a resource."""
    try:
        if (environment != "devtest" or type(receipt) is not InspectorCreateIntentReceipt
                or receipt.provider_create_authorized is not False
                or type(submission) is not InspectorSubmittedUnverified
                or submission.status != "submitted_unverified"):
            raise ValueError("fresh DevTest submission required")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        lookup = lease_lookup or _db_lease_lookup

        def authority():
            parent, core, snapshot, operation = _boundary(
                receipt.teardown_parent_id, jobs, plans, lookup)
            child = jobs.get(_child_id(core.id))
            if (operation != _FENCE or child is None or child.id != receipt.coordinator_job_id
                    or child.action != ACTION or child.status != "running"
                    or child.finished_at is not None or child.artifact_refs != []
                    or child.input.get("phase") != "inspector_create_started"
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
                    or child.target_type != "engagement" or child.target_id != parent.target_id
                    or child.target != f"engagement:{parent.target_id}"
                    or child.requested_by != parent.requested_by
                    or len([row for row in jobs.list_for_engagement(parent.target_id)
                            if row.action == ACTION]) != 1
                    or _running_inspector_lifecycle_job(jobs, parent.target_id) is not None
                    or len(child.events) < 5
                    or job_event_digest(child.events[:5]) != receipt.event_digest
                    or job_event_digest(child.events) != submission.event_digest
                    or child.events[4].message != "inspector_create_started"):
                raise ValueError("Inspector settlement authority differs")
            intent = child.events[4].data
            if (type(intent) is not dict or intent.get("resourceName") != receipt.resource_name
                    or intent.get("scopeSnapshotId") != snapshot["snapshotId"]
                    or intent.get("providerScopeSha256") != snapshot["providerScopeSha256"]
                    or intent.get("claimGenerationSha256") != inspector_claim_generation_digest(
                        token=receipt.claim_token, claimed_at=receipt.claim_claimed_at)
                    or intent.get("provider") not in {"linode", "digitalocean"}
                    or not valid_inspector_management_source_cidr(intent.get("managementSourceCidr"))
                    or submission.provider != intent["provider"]
                    or submission.resource_name != receipt.resource_name
                    or submission.tag_name != (_inspector_firewall_tag(receipt.resource_name)
                                                   if intent["provider"] == "digitalocean" else "")
                    or not submission.host_id or not submission.firewall_id):
                raise ValueError("Inspector settlement intent differs")
            expected = _stage_data(intent["provider"], receipt.resource_name,
                                   submission.host_id, submission.firewall_id, submission.tag_name)
            if (len(child.events) != 5 + len(expected)
                    or [item.sequence for item in child.events] != list(range(1, len(child.events) + 1))
                    or any(item.message != "inspector_create_stage" or item.level != "info"
                           or item.data != data for item, data in zip(child.events[5:], expected))):
                raise ValueError("Inspector settlement journal differs")
            instant = now()
            if (instant.tzinfo is None or instant.utcoffset() != timedelta(0)
                    or datetime.fromisoformat(child.input["claimExpiresAt"]) <= instant):
                raise ValueError("Inspector settlement claim expired")
            pending_auditor(
                core.id, confirmed_scope=snapshot["providerScopes"][0],
                confirmed_scope_sha256=_fingerprint(snapshot),
                workspace_root=Path(snapshot["providerScopes"][0]["workspace"]),
                job_repository=jobs,
            )
            settings = settings_repo.get(parent.target_id)
            if (settings is None or settings.engagement_id != parent.target_id
                    or settings.current_host != {} or settings.provider != intent["provider"]
                    or settings.region != intent.get("region") or settings.size != intent.get("size")
                    or not _inspector_rows_absent(
                        tuple(resources.list_for_engagement(parent.target_id)), snapshot)):
                raise ValueError("Inspector settlement ownership differs")
            selected = credentials.get_default(intent["provider"])
            defaults = [row for row in credentials.list(intent["provider"])
                        if row.provider == intent["provider"] and row.status == "active" and row.is_default]
            if (len(defaults) != 1 or selected != defaults[0]
                    or selected.id != receipt.credential_id
                    or hashlib.sha256(selected.encrypted_secret.encode("utf-8")).hexdigest()
                       != receipt.encrypted_secret_sha256
                    or selected.alias != intent.get("credentialAlias")
                    or selected.updated_at != intent.get("credentialUpdatedAt")
                    or key_fingerprint_reader() != intent.get("keyFingerprintSha256")):
                raise ValueError("Inspector settlement credential or key differs")
            return parent, core, snapshot, child, settings, selected, intent

        first = authority()
        token = decrypt_secret(first[5].encrypted_secret)
        if type(token) is not str or not token or authority()[:3] != first[:3]:
            raise ValueError("Inspector settlement credential changed")
        started_at = monotonic()
        if type(started_at) not in (int, float):
            raise ValueError("Inspector settlement clock invalid")

        def heartbeat():
            before = authority()
            if before[:3] != first[:3] or before[4:] != first[4:]:
                raise ValueError("Inspector settlement baseline changed")
            moment = now()
            updated = jobs.heartbeat_keyed_inspector_submission_if_running_claimed(
                before[3], owner=_OWNER, token=receipt.claim_token,
                claimed_at=receipt.claim_claimed_at,
                expected_event_digest=submission.event_digest,
                heartbeat_at=moment.isoformat(),
                expires_at=(moment + timedelta(minutes=5)).isoformat(),
            )
            if updated is None or jobs.get(before[3].id) != updated:
                raise ValueError("Inspector settlement heartbeat lost")
            after = authority()
            if (after[:3] != before[:3] or after[4:] != before[4:]
                    or after[3] != updated):
                raise ValueError("Inspector settlement authority changed")
            return after

        def deadline():
            elapsed = monotonic() - started_at
            if type(elapsed) not in (int, float) or not 0 <= elapsed < _MAX_SECONDS:
                raise ValueError("Inspector settlement elapsed bound exceeded")

        def before_get():
            deadline()
            heartbeat()
            deadline()

        def after_get():
            heartbeat()
            deadline()

        transport = _GetOnlyTransport(
            transport_factory(first[6]["provider"]),
            before_get=before_get, after_get=after_get,
        )

        while True:
            deadline()
            bound = heartbeat()
            outcome = None
            pending = False
            hard_failure = False
            try:
                outcome = proof(
                    provider=bound[6]["provider"], token=token, transport=transport,
                    resource_name=receipt.resource_name, region=bound[6]["region"],
                    size=bound[6]["size"], host_id=submission.host_id,
                    firewall_id=submission.firewall_id,
                    management_cidr=bound[6]["managementSourceCidr"],
                )
            except InspectorProviderPending:
                pending = True
            except Exception:
                hard_failure = True
            heartbeat()
            if hard_failure or monotonic() - started_at > _MAX_SECONDS:
                raise ValueError("Inspector settlement proof is unverified")
            if not pending:
                if (type(outcome) is not InspectorProviderProof
                        or outcome.host.provider != submission.provider
                        or outcome.host.resource_id != submission.host_id
                        or outcome.host.name != receipt.resource_name
                        or outcome.host.region != bound[6]["region"]
                        or outcome.firewall_id != submission.firewall_id
                        or outcome.management_cidr != bound[6]["managementSourceCidr"]
                        or outcome.tag_name != submission.tag_name
                        or outcome.tag_exclusive is not False):
                    raise ValueError("Inspector settlement proof differs")
                final = authority()
                if final[:3] != first[:3] or final[4:] != first[4:]:
                    raise ValueError("Inspector settlement baseline changed")
                return outcome
            remaining = _MAX_SECONDS - (monotonic() - started_at)
            if remaining < _INTERVAL_SECONDS:
                raise ValueError("Inspector settlement timed out")
            sleep(_INTERVAL_SECONDS)
    except Exception:
        raise InspectorSettlementAttention(
            "Inspector GET settlement is unverified; explicit reconciliation is required"
        ) from None
