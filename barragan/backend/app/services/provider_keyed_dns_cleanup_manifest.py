# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only, pre-destroy review manifest for exact keyed DNS cleanup.

The caller must put this value into the keyed scope before computing its
snapshotId. Nothing here reserves a child or authorizes a provider write.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.services.engagement_dns import (
    SUPPORTED_DNS_RECORD_TYPES, _canonical_record, _dns01_domain_lock,
    _namecheap_dns_client, _record_from_provider, dns_record_fingerprint,
    preview_owned_dns_cleanup,
)
from app.services.engagement_teardown import (
    ENGAGEMENT_TEARDOWN_ACTION, _active_keyed_domain_assignments,
    _parent_id, _valid_keyed_domain_assignments,
)
from app.services.provider_keyed_dns_cleanup_binding import bind_provider_keyed_dns_cleanup_targets
from app.services.provider_keyed_initial_continuation import ACTION as INITIAL_ACTION, CORE_ACTION, _job_ids
from app.services.provider_keyed_teardown_quiescence import audit_failed_prebinding_provider_bootstrap
from app.storage.domain_repository import SqlAlchemyDomainRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest


class ProviderKeyedDnsCleanupManifestError(ValueError):
    """The reviewed DNS deletion set or its persisted provenance is unproved."""


_PREBINDING_ACTIVE_CLEANUP_ACTIONS = frozenset({
    ENGAGEMENT_TEARDOWN_ACTION, "provider_keyed_comprehensive_teardown",
    "provider_keyed_initial_destroy_plan",
})
_PREBINDING_FORBIDDEN_ACTION_PREFIXES = (
    "inbound_channel_", "outbound_channel_", "certificate_asset_",
    "engagement_dns_", "web_static_service_", "backflips_service_",
    "desktop_service_", "legacy_homebase_role_service_",
)


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()


def _record_sort_key(row: dict[str, str]) -> tuple[str, str, str, str, str]:
    return row["name"], row["type"], row["address"], row["mxPref"], row["ttl"]


def _require_empty_prebinding_ownership(
    engagement_id: str, jobs, domains, *, core_id: str,
    active_destroy_apply_core_id: str | None = None,
) -> None:
    """Fail closed on any persisted domain, DNS, certificate, site, or route work."""
    from app.storage.database import db
    from app.storage.models import (
        CertificateAssetModel, CertificateBindingModel, DomainDnsRecordOwnershipModel,
        EngagementServiceModel,
    )

    related_jobs = jobs.list_for_engagement(engagement_id)
    expected_cleanup_ids = {
        ENGAGEMENT_TEARDOWN_ACTION: _parent_id(core_id),
        "provider_keyed_comprehensive_teardown": (
            "job-provider-keyed-comprehensive-teardown-" + core_id.removeprefix("job-")),
        "provider_keyed_initial_destroy_plan": (
            "job-provider-keyed-initial-destroy-plan-" + core_id.removeprefix("job-")),
    }
    active_destroy = [job for job in related_jobs
                      if job.action == "provider_keyed_initial_destroy_apply"
                      and job.status in {"queued", "running"}]
    if active_destroy_apply_core_id is not None:
        expected_id = ("job-provider-keyed-initial-destroy-apply-"
                       + active_destroy_apply_core_id.removeprefix("job-"))
        if (len(active_destroy) != 1 or active_destroy[0].id != expected_id
                or active_destroy[0].status != "running"
                or active_destroy[0].target_id != engagement_id
                or active_destroy[0].input.get("coreJobId") != active_destroy_apply_core_id
                or active_destroy[0].input.get("teardownParentId") != (
                    _parent_id(active_destroy_apply_core_id))):
            raise ValueError("current destroy apply child differs")
    elif active_destroy:
        raise ValueError("unreviewed destroy apply child exists")
    if (domains.list_assignments(engagement_id=engagement_id)
            or any(job.action.startswith(_PREBINDING_FORBIDDEN_ACTION_PREFIXES)
                   or job.action == "engagement_channels_update"
                   for job in related_jobs)
            or any(job.status in {"queued", "running"}
                   and job.action not in _PREBINDING_ACTIVE_CLEANUP_ACTIONS
                   and job not in active_destroy
                   for job in related_jobs)
            or any(job.action in expected_cleanup_ids and (
                       job.id != expected_cleanup_ids[job.action]
                       or job.target_id != engagement_id
                       or (job.action != ENGAGEMENT_TEARDOWN_ACTION
                           and job.input.get("teardownParentId") != _parent_id(core_id)))
                   for job in related_jobs)
            or db.session.query(DomainDnsRecordOwnershipModel.id).filter_by(
                engagement_id=engagement_id).first() is not None
            or db.session.query(CertificateAssetModel.id).filter_by(
                engagement_id=engagement_id).first() is not None
            or db.session.query(CertificateBindingModel.id).filter_by(
                engagement_id=engagement_id).first() is not None
            or db.session.query(EngagementServiceModel.service_id).filter_by(
                engagement_id=engagement_id).first() is not None):
        raise ValueError("prebinding DNS, certificate, or route ownership exists")


def _empty_failed_prebinding_manifest(
    scope_snapshot: dict, jobs, domains, *,
    active_destroy_apply_core_id: str | None = None,
) -> dict[str, Any]:
    from pathlib import Path

    engagement_id = scope_snapshot["engagementId"]
    core_id = scope_snapshot["coreJobId"]
    scope = scope_snapshot["providerScopes"][0]
    initial = jobs.get(_job_ids(core_id)[0])
    chain_rows = scope_snapshot.get("chains")
    if (initial is None or initial.status != "failed"
            or scope_snapshot.get("domainAssignments") != []
            or type(chain_rows) is not list or len(chain_rows) != 2
            or any(row.get("status") != "pending" or row.get("deployJobId") != ""
                   or row.get("outboundChannelIds") != [] for row in chain_rows)):
        raise ValueError("failed prebinding preview is not empty")
    _require_empty_prebinding_ownership(
        engagement_id, jobs, domains, core_id=core_id,
        active_destroy_apply_core_id=active_destroy_apply_core_id)
    proof = audit_failed_prebinding_provider_bootstrap(
        core_id, confirmed_scope=scope, workspace_root=Path(scope["workspace"]),
        job_repository=jobs,
    )
    result = {
        "schema": "provider-keyed-empty-dns-prebinding-v1",
        "engagementId": engagement_id,
        "coreJobId": core_id,
        "corePlanId": scope["corePlanId"],
        "providerScopeSha256": scope_snapshot["providerScopeSha256"],
        "stateSha256": scope["stateSha256"],
        "initialJobId": proof.parent_job_id,
        "initialJournalSha256": proof.manifest_sha256,
        "domainAssignments": [],
        "domains": [],
    }
    result["manifestSha256"] = _digest(result)
    return result


class _FrozenZoneAdapter:
    """Feed the existing receipt preview the exact one provider GET result."""

    def __init__(self, domain_name: str, records: list):
        self.domain_name = domain_name
        self.records = records

    def get_hosts(self, domain_name: str) -> list:
        if domain_name != self.domain_name:
            raise ValueError("Namecheap zone changed during DNS manifest read")
        return list(self.records)

    def set_hosts(self, domain_name: str, hosts: list) -> bool:
        raise AssertionError("DNS manifest is read-only")


def build_provider_keyed_dns_cleanup_manifest(
    scope_snapshot: dict, *, job_repository=None, domain_repository=None,
    adapter=None, active_destroy_apply_core_id: str | None = None,
) -> dict[str, Any]:
    """Seal every frozen assigned domain using persisted host identity and one GET each.

    ``scope_snapshot`` is the keyed preview scope before its final snapshotId.
    The resulting manifest is independently digestible and belongs inside that
    scope so the existing parent confirmation also binds its complete content.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    domains = domain_repository or SqlAlchemyDomainRepository()
    try:
        if (type(scope_snapshot) is not dict or "snapshotId" in scope_snapshot
                or "dnsCleanupManifest" in scope_snapshot
                or type(scope_snapshot.get("engagementId")) is not str
                or not scope_snapshot["engagementId"]
                or type(scope_snapshot.get("coreJobId")) is not str
                or not scope_snapshot["coreJobId"]
                or type(scope_snapshot.get("providerScopes")) is not list
                or len(scope_snapshot["providerScopes"]) != 1
                or not _valid_keyed_domain_assignments(scope_snapshot.get("domainAssignments"))):
            raise ValueError("keyed review scope is incomplete")
        # Never retain mutable caller-owned rows in a hashed review artifact.
        scope_snapshot = json.loads(json.dumps(scope_snapshot, sort_keys=True))
        engagement_id = scope_snapshot["engagementId"]
        core_id = scope_snapshot["coreJobId"]
        frozen = scope_snapshot["domainAssignments"]
        if any(job.action == "provider_keyed_edge_append"
               for job in jobs.list_for_engagement(engagement_id)):
            from app.services.provider_keyed_teardown_scope import (
                _reconciled_unapplied_append_state_sha,
            )
            unapplied_sha = _reconciled_unapplied_append_state_sha(
                engagement_id, jobs, expected_core_job_id=core_id,
                expected_core_plan_id=scope_snapshot["providerScopes"][0].get("corePlanId"))
            if unapplied_sha is None:
                return _empty_published_append_manifest(
                    scope_snapshot, jobs, domains,
                    active_destroy_apply_core_id=active_destroy_apply_core_id)
            if unapplied_sha != scope_snapshot["providerScopes"][0].get("stateSha256"):
                raise ValueError("reconciled append state differs from current scope")
        core = jobs.get(core_id)
        initial_id = _job_ids(core_id)[0]
        initial = jobs.get(initial_id)
        if initial is not None and getattr(initial, "status", None) == "failed":
            return _empty_failed_prebinding_manifest(
                scope_snapshot, jobs, domains,
                active_destroy_apply_core_id=active_destroy_apply_core_id)
        if (core is None or core.action != CORE_ACTION or core.status != "succeeded"
                or core.input.get("engagementId") != engagement_id
                or core.input.get("sketchStateSchema") != "provider-keyed-v2"
                or initial is None or initial.action != INITIAL_ACTION
                or initial.target_id != engagement_id
                or initial.input.get("coreJobId") != core_id
                or initial.input.get("corePlanId") != core.input.get("corePlanId")
                or len([event for event in initial.events
                        if event.message == "provider host identity binding intended"]) != 1
                or len([event for event in initial.events
                        if event.message == "provider host identity bound"]) != 1):
            raise ValueError("persisted initial host identity is unavailable")
        intent = next(event for event in initial.events
                      if event.message == "provider host identity binding intended")
        bound = next(event for event in initial.events
                     if event.message == "provider host identity bound")
        binding = bind_provider_keyed_dns_cleanup_targets(
            engagement_id, confirmed_scope=scope_snapshot["providerScopes"][0],
            provider_scope_sha256=scope_snapshot.get("providerScopeSha256"),
            host_binding_intent_event=intent, host_binding_bound_event=bound,
        )
        if _active_keyed_domain_assignments(engagement_id, domains) != frozen:
            raise ValueError("active domain assignment inventory changed")
        initial_journal_sha = job_event_digest(initial.events)
        client = adapter or (_namecheap_dns_client() if frozen else None)
        entries: list[dict[str, Any]] = []
        for assignment in frozen:
            domain_id = assignment["domainId"]
            with _dns01_domain_lock(domain_id):
                if _active_keyed_domain_assignments(engagement_id, domains) != frozen:
                    raise ValueError("active domain assignment inventory changed")
                asset = domains.get_asset(domain_id)
                if (asset is None or asset.id != domain_id
                        or asset.domain_name != assignment["domainName"]
                        or asset.registrar != "namecheap"):
                    raise ValueError("frozen Namecheap asset changed")
                raw = client.get_hosts(asset.domain_name)
                if type(raw) is not list:
                    raise ValueError("complete Namecheap zone is unavailable")
                zone = [_record_from_provider(row) for row in raw]
                if any(row.record_type not in SUPPORTED_DNS_RECORD_TYPES for row in zone):
                    raise ValueError("Namecheap zone includes an unsupported record type")
                preview = preview_owned_dns_cleanup(
                    engagement_id, domain_id, list(binding.edge_public_ips),
                    repository=domains, job_repository=jobs,
                    adapter=_FrozenZoneAdapter(asset.domain_name, zone), _lock_held=True,
                )
                if (preview["assignmentId"] != assignment["assignmentId"]
                        or preview["zoneFingerprint"] != dns_record_fingerprint(zone)):
                    raise ValueError("frozen DNS preview differs from provider zone")
                if preview["blockers"]:
                    raise ValueError("owned DNS cleanup has a blocker")
                preserved = [_canonical_record(row) for row in zone]
                for owned in preview["ownedRecords"]:
                    record = _canonical_record(owned["record"])
                    if preserved.count(record) != 1:
                        raise ValueError("owned DNS record is ambiguous")
                    preserved.remove(record)
                preserved.sort(key=_record_sort_key)
                owned_ttls = [int(row["record"]["ttl"])
                              for row in preview["ownedRecords"]]
                if any(ttl <= 0 for ttl in owned_ttls):
                    raise ValueError("owned DNS TTL is invalid")
                owned_proofs = sorted(({
                    "ownershipId": row["ownershipId"],
                    "record": _canonical_record(row["record"]),
                } for row in preview["ownedRecords"]), key=lambda row: row["ownershipId"])
                entry = {
                    "domainId": domain_id,
                    "domainName": asset.domain_name,
                    "assignmentId": assignment["assignmentId"],
                    "oldEdgeIps": list(binding.edge_public_ips),
                    "bindingSha256": binding.binding_sha256,
                    "zoneFingerprint": preview["zoneFingerprint"],
                    "cleanupPlanSha256": preview["planSha256"],
                    "ownedReceiptIds": sorted(row["ownershipId"]
                                              for row in preview["ownedRecords"]),
                    "ownedRecordCount": len(owned_proofs),
                    "ownedRecordsSha256": _digest(owned_proofs),
                    "maxOwnedTtl": max(owned_ttls, default=0),
                    "preservedRecordCount": len(preserved),
                    "preservedRecordsSha256": _digest(preserved),
                    "blockers": preview["blockers"],
                }
                entry["entrySha256"] = _digest(entry)
                entries.append(entry)
        if _active_keyed_domain_assignments(engagement_id, domains) != frozen:
            raise ValueError("active domain assignment inventory changed")
        latest_initial = jobs.get(initial_id)
        if (latest_initial is None or latest_initial.action != initial.action
                or latest_initial.input != initial.input
                or job_event_digest(latest_initial.events) != initial_journal_sha
                or jobs.get(core_id) != core):
            raise ValueError("persisted host binding changed during DNS review")
        result = {
            "schema": "provider-keyed-dns-cleanup-manifest-v1",
            "engagementId": engagement_id,
            "coreJobId": core_id,
            "providerScopeSha256": binding.provider_scope_sha256,
            "bindingSha256": binding.binding_sha256,
            "initialJobId": initial_id,
            "initialJournalSha256": initial_journal_sha,
            "domainAssignments": frozen,
            "domains": entries,
        }
        result["manifestSha256"] = _digest(result)
        return result
    except Exception:
        raise ProviderKeyedDnsCleanupManifestError(
            "persisted pre-destroy DNS cleanup manifest is unproved"
        ) from None


def _empty_published_append_manifest(
    scope_snapshot: dict, jobs, domains, *,
    active_destroy_apply_core_id: str | None = None,
) -> dict[str, Any]:
    """A five-node append has no initial-manifest binding for its new edge.

    This narrow review path is only for an engagement with no DNS, channel,
    certificate, or site ownership. It authorizes no cleanup child.
    """
    from app.storage.database import db
    from app.storage.models import (
        CertificateAssetModel, CertificateBindingModel,
        DomainDnsRecordOwnershipModel, EngagementServiceModel,
    )

    engagement_id = scope_snapshot["engagementId"]
    core_id = scope_snapshot["coreJobId"]
    related = jobs.list_for_engagement(engagement_id)
    expected_active = {ENGAGEMENT_TEARDOWN_ACTION: _parent_id(core_id)}
    if active_destroy_apply_core_id is not None:
        if active_destroy_apply_core_id != core_id:
            raise ValueError("current destroy Apply core differs")
        expected_active.update({
            "provider_keyed_comprehensive_teardown": (
                "job-provider-keyed-comprehensive-teardown-" + core_id.removeprefix("job-")),
            "provider_keyed_initial_destroy_apply": (
                "job-provider-keyed-initial-destroy-apply-" + core_id.removeprefix("job-")),
        })
    active = [job for job in related if job.status in {"queued", "running"}]
    if any(job.action not in expected_active
           or job.id != expected_active[job.action]
           or job.target_id != engagement_id
           or (job.action != ENGAGEMENT_TEARDOWN_ACTION and
               (job.input.get("teardownParentId") != _parent_id(core_id)
                or job.input.get("coreJobId") != core_id))
           or (job.action == "provider_keyed_initial_destroy_apply"
               and job.status != "running")
           for job in active):
        raise ValueError("foreign active teardown child differs")
    if active_destroy_apply_core_id is not None and not any(
            job.action == "provider_keyed_initial_destroy_apply" for job in active):
        raise ValueError("current destroy Apply child is absent")
    if (scope_snapshot["domainAssignments"] != []
            or domains.list_assignments(engagement_id=engagement_id)
            or any(job.action.startswith(_PREBINDING_FORBIDDEN_ACTION_PREFIXES)
                   or job.action == "engagement_channels_update" for job in related)
            or db.session.query(DomainDnsRecordOwnershipModel.id).filter_by(
                engagement_id=engagement_id).first() is not None
            or db.session.query(CertificateAssetModel.id).filter_by(
                engagement_id=engagement_id).first() is not None
            or db.session.query(CertificateBindingModel.id).filter_by(
                engagement_id=engagement_id).first() is not None
            or db.session.query(EngagementServiceModel.service_id).filter_by(
                engagement_id=engagement_id).first() is not None):
        raise ValueError("expanded generation is not channel and DNS free")
    initial = jobs.get(_job_ids(core_id)[0])
    append = [job for job in related if job.action == "provider_keyed_edge_append"]
    published = [job for job in append if job.status == "succeeded"]
    if (initial is None or initial.status != "succeeded" or len(published) != 1):
        raise ValueError("expanded publication differs")
    if len(append) > 1:
        from app.services.provider_keyed_teardown_scope import (
            _reconciled_unapplied_append_state_sha,
        )
        prior_sha = _reconciled_unapplied_append_state_sha(
                engagement_id, jobs,
                allowed_published_parent_id=published[0].id,
                expected_core_job_id=core_id,
                expected_core_plan_id=scope_snapshot["providerScopes"][0].get("corePlanId"),
                )
        initial_source = published[0].input.get("initialSource")
        if (type(initial_source) is not dict
                or prior_sha is None or prior_sha != initial_source.get("state_sha256")):
            raise ValueError("prior append review history differs")
    result = {
        "schema": "provider-keyed-empty-dns-append-v1",
        "engagementId": engagement_id,
        "coreJobId": core_id,
        "corePlanId": scope_snapshot["providerScopes"][0]["corePlanId"],
        "providerScopeSha256": scope_snapshot["providerScopeSha256"],
        "stateSha256": scope_snapshot["providerScopes"][0]["stateSha256"],
        "initialJobId": initial.id,
        "initialJournalSha256": job_event_digest(initial.events),
        "appendJobId": published[0].id,
        "appendJournalSha256": job_event_digest(published[0].events),
        "domainAssignments": [], "domains": [],
    }
    result["manifestSha256"] = _digest(result)
    return result
