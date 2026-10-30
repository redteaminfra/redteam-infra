# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Protocol

from app.domain import JobEvent
from app.core.request_identity import current_request_identity
from app.integrations.namecheap import NamecheapError, NamecheapReadOnlyClient, parse_namecheap_secret
from app.services.credentials import (
    CredentialStoreLockedError,
    CredentialValidationError,
    resolve_credential_secret,
    resolve_default_credential_alias,
)
from app.storage.domain_repository import (
    DomainAssignmentFenceError,
    DomainRepository,
    SqlAlchemyDomainRepository,
    StoredDomainAsset,
    StoredDomainAssignment,
    StoredDomainDnsSnapshot,
)
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun


RISK_STATUSES = {"clear", "burned", "quarantined", "cooldown"}
RISKY_STATUSES = {"burned", "quarantined", "cooldown"}
ENGAGEMENT_PAST_STATUSES = {"archived", "retired"}
CATALOG_STATES = {"auto", "currently_being_used", "waiting_to_be_used", "used_in_past_engagements"}
MANUAL_CATALOG_STATES = CATALOG_STATES - {"auto"}
DNS_APPLY_ACTION = "engagement_dns_apply"


class DomainValidationError(Exception):
    def __init__(self, errors: list[str]):
        super().__init__("domain validation failed")
        self.errors = errors


class DomainNotFoundError(LookupError):
    pass


class DomainConfirmationRequired(Exception):
    def __init__(self, token: str, reasons: list[str]):
        super().__init__("domain assignment requires typed confirmation")
        self.token = token
        self.reasons = reasons

    def to_dict(self) -> dict[str, Any]:
        return {"required": True, "token": self.token, "reasons": self.reasons}


class NamecheapDomainAdapter(Protocol):
    def get_domains(self) -> list[Any]:
        ...

    def get_hosts(self, domain_name: str) -> list[Any]:
        ...


@dataclass(frozen=True)
class DomainAssignmentView:
    id: int | None
    domain_id: str
    engagement_id: str
    engagement_name: str
    purpose: str
    purpose_tags: list[str]
    status: str
    notes: str
    assigned_at: str
    released_at: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "domainId": self.domain_id,
            "engagementId": self.engagement_id,
            "engagementName": self.engagement_name,
            "purpose": self.purpose,
            "purposeTags": self.purpose_tags,
            "status": self.status,
            "notes": self.notes,
            "assignedAt": self.assigned_at,
            "releasedAt": self.released_at,
        }


@dataclass(frozen=True)
class DomainView:
    asset: StoredDomainAsset
    active_assignment: DomainAssignmentView | None
    assignments: list[DomainAssignmentView]
    bucket: str
    dns_summary: dict[str, Any]

    def to_summary_dict(self) -> dict[str, Any]:
        return {
            **_asset_dict(self.asset),
            "bucket": self.bucket,
            "engagement": _engagement_dict(self.active_assignment),
            "purpose": self.active_assignment.purpose if self.active_assignment else "",
            "purposeTags": self.active_assignment.purpose_tags if self.active_assignment else [],
            "dnsSummary": self.dns_summary,
        }

    def to_detail_dict(self) -> dict[str, Any]:
        return {
            **self.to_summary_dict(),
            "assignments": [assignment.to_dict() for assignment in self.assignments],
        }


@dataclass(frozen=True)
class DomainHostsView:
    domain_id: str
    domain_name: str
    provider: str
    source: str
    sync_job_id: str
    fetched_at: str
    hosts: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "domainId": self.domain_id,
            "domainName": self.domain_name,
            "provider": self.provider,
            "source": self.source,
            "syncJobId": self.sync_job_id,
            "fetchedAt": self.fetched_at,
            "hosts": self.hosts,
            "readOnly": True,
        }


def list_domain_groups(repository: DomainRepository | None = None) -> dict[str, list[dict[str, Any]]]:
    views = _domain_views(_repo(repository))
    groups = {
        "currently_being_used": [],
        "waiting_to_be_used": [],
        "used_in_past_engagements": [],
    }
    for view in views:
        groups[view.bucket].append(view.to_summary_dict())
    return groups


def get_domain_detail(domain_id: str, repository: DomainRepository | None = None) -> dict[str, Any] | None:
    repo = _repo(repository)
    asset = repo.get_asset(domain_id)
    if asset is None:
        return None
    return _domain_view(repo, asset).to_detail_dict()


def get_cached_hosts(domain_id: str, repository: DomainRepository | None = None) -> DomainHostsView | None:
    repo = _repo(repository)
    asset = repo.get_asset(domain_id)
    if asset is None:
        return None
    snapshots = repo.list_snapshots(domain_id)
    if not snapshots:
        return DomainHostsView(
            domain_id=asset.id,
            domain_name=asset.domain_name,
            provider=asset.registrar,
            source="provider_snapshot",
            sync_job_id="",
            fetched_at="",
            hosts=[],
        )
    latest = snapshots[0]
    return DomainHostsView(asset.id, asset.domain_name, latest.provider, latest.source, latest.sync_job_id, latest.fetched_at, latest.hosts)


def list_engagement_domains(engagement_id: str, repository: DomainRepository | None = None) -> list[dict[str, Any]]:
    repo = _repo(repository)
    views = []
    for assignment in repo.list_assignments(engagement_id=engagement_id):
        if assignment.status != "active":
            continue
        asset = repo.get_asset(assignment.domain_id)
        if asset is None:
            continue
        view = _domain_view(repo, asset)
        if view.active_assignment is not None and view.active_assignment.engagement_id == engagement_id:
            views.append(view.to_summary_dict())
    return views


def list_domain_purposes(repository: DomainRepository | None = None) -> list[str]:
    repo = _repo(repository)
    suggestions: set[str] = set()
    for assignment in repo.list_assignments():
        if assignment.status not in {"active", "released"}:
            continue
        tags = normalize_purpose_tags(assignment.purpose_tags)
        if tags:
            suggestions.update(tags)
            continue
        suggestions.update(normalize_purpose_tags([assignment.purpose]))
    return sorted(suggestions)


def assign_domain(domain_id: str, body: dict[str, Any], repository: DomainRepository | None = None) -> dict[str, Any]:
    # Assignment ownership and full-zone DNS writes share one per-domain gate.
    from app.services.engagement_dns import _dns01_domain_lock

    with _dns01_domain_lock(domain_id):
        return _assign_domain_locked(domain_id, body, repository)


def _assign_domain_locked(domain_id: str, body: dict[str, Any], repository: DomainRepository | None = None) -> dict[str, Any]:
    repo = _repo(repository)
    asset = repo.get_asset(domain_id)
    if asset is None:
        raise DomainNotFoundError("domain not found")
    engagement_id = str(body.get("engagementId", "")).strip()
    purpose_tags = _purpose_tags_from_body(body)
    purpose = ", ".join(purpose_tags)
    notes = str(body.get("notes", "")).strip()
    request_identity = current_request_identity()
    assigned_by = request_identity.username if request_identity is not None else (str(body.get("assignedBy", "operator")).strip() or "operator")
    if not engagement_id:
        raise DomainValidationError(["engagementId is required"])
    engagement_name = _engagement_name(engagement_id)
    if engagement_name is None:
        raise DomainValidationError(["engagementId must reference an existing engagement"])

    active_assignments = _current_assignments(repo, domain_id)
    reasons = []
    if asset.risk_status in RISKY_STATUSES:
        reasons.append(f"domain risk status is {asset.risk_status}")
    if active_assignments:
        reasons.append("domain is already actively assigned")
    if reasons:
        token = confirmation_token(asset.domain_name)
        if str(body.get("confirmationToken", "")).strip() != token:
            raise DomainConfirmationRequired(token, reasons)

    now = _now()
    releases = [replace(assignment, status="released",
                        released_by=assigned_by, released_at=now)
                for assignment in active_assignments]
    requested = StoredDomainAssignment(
            id=None,
            domain_id=domain_id,
            engagement_id=engagement_id,
            engagement_name=engagement_name,
            purpose=purpose,
            purpose_tags=purpose_tags,
            status="active",
            notes=notes,
            assigned_by=assigned_by,
            released_by="",
            assigned_at=now,
            released_at=None,
        )
    try:
        if isinstance(repo, SqlAlchemyDomainRepository):
            assignment = repo._save_assignments_locked([*releases, requested])[-1]
        else:
            for release in releases:
                repo.save_assignment(release)
            assignment = repo.save_assignment(requested)
    except DomainAssignmentFenceError as exc:
        raise DomainValidationError([str(exc)]) from None
    return {"domain": _domain_view(repo, asset).to_detail_dict(), "assignment": _assignment_view(assignment).to_dict()}


def release_domain(domain_id: str, body: dict[str, Any], repository: DomainRepository | None = None) -> dict[str, Any]:
    from app.services.engagement_dns import _dns01_domain_lock

    with _dns01_domain_lock(domain_id):
        return _release_domain_locked(domain_id, body, repository)


def _release_domain_locked(domain_id: str, body: dict[str, Any], repository: DomainRepository | None = None) -> dict[str, Any]:
    repo = _repo(repository)
    asset = repo.get_asset(domain_id)
    if asset is None:
        raise DomainNotFoundError("domain not found")
    active_assignments = _current_assignments(repo, domain_id)
    if not active_assignments:
        raise DomainValidationError(["domain has no active assignment"])
    request_identity = current_request_identity()
    released_by = request_identity.username if request_identity is not None else (str(body.get("releasedBy", "operator")).strip() or "operator")
    now = _now()
    requested = [replace(assignment, status="released", released_by=released_by,
                         released_at=now) for assignment in active_assignments]
    try:
        if isinstance(repo, SqlAlchemyDomainRepository):
            released = repo._save_assignments_locked(requested)
        else:
            released = [repo.save_assignment(row) for row in requested]
    except DomainAssignmentFenceError as exc:
        raise DomainValidationError([str(exc)]) from None
    return {
        "domain": _domain_view(repo, asset).to_detail_dict(),
        "releasedAssignments": [_assignment_view(assignment).to_dict() for assignment in released],
    }


def patch_domain_assignment(domain_id: str, body: dict[str, Any], repository: DomainRepository | None = None) -> dict[str, Any]:
    repo = _repo(repository)
    asset = repo.get_asset(domain_id)
    if asset is None:
        raise DomainNotFoundError("domain not found")
    active_assignments = _current_assignments(repo, domain_id)
    if not active_assignments:
        raise DomainValidationError(["domain has no active assignment"])
    purpose_tags = _purpose_tags_patch_from_body(body)
    purpose = ", ".join(purpose_tags)
    updated = [
        repo.save_assignment(
            replace(
                assignment,
                purpose=purpose,
                purpose_tags=purpose_tags,
            )
        )
        for assignment in active_assignments
    ]
    refreshed_asset = repo.get_asset(domain_id) or asset
    return {
        "domain": _domain_view(repo, refreshed_asset).to_detail_dict(),
        "assignments": [_assignment_view(assignment).to_dict() for assignment in updated],
    }


def patch_domain_risk(domain_id: str, body: dict[str, Any], repository: DomainRepository | None = None) -> dict[str, Any]:
    repo = _repo(repository)
    asset = repo.get_asset(domain_id)
    if asset is None:
        raise DomainNotFoundError("domain not found")
    risk_status = str(body.get("riskStatus", asset.risk_status)).strip().lower() or asset.risk_status
    if risk_status not in RISK_STATUSES:
        raise DomainValidationError(["riskStatus must be clear, burned, quarantined, or cooldown"])
    risk_flags = body.get("riskFlags", asset.risk_flags)
    if not isinstance(risk_flags, list):
        raise DomainValidationError(["riskFlags must be a list"])
    updated = repo.save_asset(
        replace(
            asset,
            risk_status=risk_status,
            risk_flags=[str(flag).strip() for flag in risk_flags if str(flag).strip()],
            cooldown_until=str(body.get("cooldownUntil", asset.cooldown_until)).strip(),
            assignable_override=bool(body.get("assignableOverride", asset.assignable_override)),
            notes=str(body.get("notes", asset.notes)).strip(),
            updated_at=_now(),
        )
    )
    return _domain_view(repo, updated).to_detail_dict()


def patch_domain_catalog_state(domain_id: str, body: dict[str, Any], repository: DomainRepository | None = None) -> dict[str, Any]:
    repo = _repo(repository)
    asset = repo.get_asset(domain_id)
    if asset is None:
        raise DomainNotFoundError("domain not found")
    catalog_state = str(body.get("catalogState", asset.catalog_state)).strip().lower() or asset.catalog_state
    if catalog_state not in CATALOG_STATES:
        raise DomainValidationError(["catalogState must be auto, currently_being_used, waiting_to_be_used, or used_in_past_engagements"])
    if catalog_state in {"waiting_to_be_used", "used_in_past_engagements"}:
        blockers = _active_catalog_blockers(repo, asset)
        if blockers:
            raise DomainValidationError([f"catalogState cannot hide active use: {', '.join(blockers)}"])
    updated = repo.save_asset(replace(asset, catalog_state=catalog_state, updated_at=_now()))
    return _domain_view(repo, updated).to_detail_dict()


def sync_namecheap_domains(
    body: dict[str, Any] | None = None,
    *,
    repository: DomainRepository | None = None,
    job_repository: JobRepository | None = None,
    adapter: NamecheapDomainAdapter | None = None,
) -> dict[str, Any]:
    body = body or {}
    repo = _repo(repository)
    jobs = job_repository or SqlAlchemyJobRepository()
    now = _now()
    include_hosts = bool(body.get("includeHosts", True))
    credential_alias = str(body.get("credentialAlias", "")).strip()
    job = jobs.save(
        StoredJobRun(
            id=f"job-{hashlib.sha256((now + credential_alias).encode('utf-8')).hexdigest()[:12]}",
            action="namecheap_domain_sync",
            status="running",
            target="provider:namecheap",
            target_type="provider",
            target_id="namecheap",
            requested_by=str(body.get("requestedBy", "operator")).strip() or "operator",
            input={"provider": "namecheap", "credentialAlias": credential_alias or "default", "includeHosts": include_hosts},
            artifact_refs=[],
            created_at=now,
            started_at=now,
            finished_at=None,
            events=[JobEvent(1, "info", "Namecheap read-only domain sync started", {"allowedCommands": sorted(["namecheap.domains.getList", "namecheap.domains.dns.getHosts"])})],
        )
    )

    try:
        client = adapter or _namecheap_client(credential_alias or None)
        domains = client.get_domains()
        synced = 0
        host_snapshots = 0
        host_warnings: list[dict[str, Any]] = []
        for provider_domain in domains:
            domain_name = normalize_domain_name(str(provider_domain.name))
            metadata = dict(getattr(provider_domain, "metadata", {}) or {})
            existing = repo.get_asset_by_name(domain_name)
            asset = repo.save_asset(
                StoredDomainAsset(
                    id=existing.id if existing else domain_id_for(domain_name),
                    domain_name=domain_name,
                    registrar="namecheap",
                    registration_started_at=str(getattr(provider_domain, "created", "")),
                    expiration_at=str(getattr(provider_domain, "expires", "")),
                    auto_renew=bool(getattr(provider_domain, "auto_renew", False)),
                    provider_status=str(getattr(provider_domain, "status", "")),
                    notes=existing.notes if existing else "",
                    risk_status=existing.risk_status if existing else "clear",
                    risk_flags=existing.risk_flags if existing else [],
                    cooldown_until=existing.cooldown_until if existing else "",
                    assignable_override=existing.assignable_override if existing else False,
                    catalog_state=existing.catalog_state if existing else "auto",
                    metadata=metadata,
                    last_synced_at=now,
                    created_at=existing.created_at if existing else now,
                    updated_at=now,
                )
            )
            synced += 1
            if include_hosts:
                hosts, source, warning = _namecheap_host_snapshot(client, domain_name, metadata)
                repo.save_snapshot(StoredDomainDnsSnapshot(None, asset.id, "namecheap", hosts, source, job.id, now))
                host_snapshots += 1
                if warning is not None:
                    host_warnings.append({"domainId": asset.id, **warning})
        events = list(job.events)
        if host_warnings:
            events.append(
                JobEvent(
                    len(events) + 1,
                    "warning",
                    "Namecheap DNS host snapshot warnings recorded",
                    {"warningCount": len(host_warnings), "warnings": host_warnings},
                )
            )
        events.append(
            JobEvent(
                len(events) + 1,
                "info",
                "Namecheap read-only domain sync completed",
                {"domainsSynced": synced, "hostSnapshots": host_snapshots, "hostSnapshotWarnings": len(host_warnings)},
            )
        )
        finished = jobs.save(
            replace(
                job,
                status="succeeded",
                finished_at=_now(),
                events=events,
            )
        )
        return {"job": finished.to_detail().to_dict(), "domainsSynced": synced, "hostSnapshots": host_snapshots}
    except Exception as exc:
        finished = jobs.save(
            replace(
                job,
                status="failed",
                finished_at=_now(),
                events=[*job.events, JobEvent(2, "error", _safe_error(exc), {})],
            )
        )
        return {"job": finished.to_detail().to_dict(), "domainsSynced": 0, "hostSnapshots": 0}


def normalize_domain_name(value: str) -> str:
    stripped = value.strip().strip(".").lower()
    if not stripped:
        raise DomainValidationError(["domain name is required"])
    try:
        normalized = stripped.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DomainValidationError(["domain name must be valid ASCII/punycode"]) from exc
    if "." not in normalized or len(normalized) > 253:
        raise DomainValidationError(["domain name must include a valid suffix"])
    return normalized


def domain_id_for(domain_name: str) -> str:
    return f"dom-{hashlib.sha256(domain_name.encode('ascii')).hexdigest()[:16]}"


def confirmation_token(domain_name: str) -> str:
    return f"ASSIGN {domain_name}"


def _domain_views(repo: DomainRepository) -> list[DomainView]:
    return [_domain_view(repo, asset) for asset in repo.list_assets()]


def _domain_view(repo: DomainRepository, asset: StoredDomainAsset) -> DomainView:
    assignments = [_assignment_view(assignment) for assignment in repo.list_assignments(domain_id=asset.id)]
    statuses = _engagement_statuses([assignment.engagement_id for assignment in assignments])
    active = [
        assignment
        for assignment in assignments
        if assignment.status == "active" and statuses.get(assignment.engagement_id, "") not in ENGAGEMENT_PAST_STATUSES
    ]
    active_assignment = active[0] if active else None
    bucket = _bucket_for(repo, asset, assignments, active_assignment)
    return DomainView(asset, active_assignment, assignments, bucket, _dns_summary(repo, asset.id))


def _bucket_for(repo: DomainRepository, asset: StoredDomainAsset, assignments: list[DomainAssignmentView], active_assignment: DomainAssignmentView | None) -> str:
    if active_assignment is not None:
        return "currently_being_used"
    if asset.catalog_state in MANUAL_CATALOG_STATES:
        return asset.catalog_state
    if assignments:
        return "used_in_past_engagements"
    if _has_active_barragan_dns(repo, asset.id):
        return "currently_being_used"
    if asset.risk_status in RISKY_STATUSES and not asset.assignable_override:
        return "used_in_past_engagements"
    return "waiting_to_be_used"


def _dns_summary(repo: DomainRepository, domain_id: str) -> dict[str, Any]:
    snapshots = repo.list_snapshots(domain_id)
    if not snapshots:
        return {
            "recordCount": 0,
            "recordsPreview": [],
            "source": "",
            "syncJobId": "",
            "fetchedAt": "",
        }
    latest = snapshots[0]
    hosts = [host for host in latest.hosts if isinstance(host, dict)]
    return {
        "recordCount": len(hosts),
        "recordsPreview": [_dns_summary_record(host) for host in hosts[:5]],
        "source": latest.source,
        "syncJobId": latest.sync_job_id,
        "fetchedAt": latest.fetched_at,
    }


def _dns_summary_record(host: dict[str, Any]) -> dict[str, str]:
    return {
        "name": str(host.get("name", "")),
        "type": str(host.get("type", "")),
        "address": str(host.get("address", "")),
        "ttl": str(host.get("ttl", "")),
    }


def _current_assignments(repo: DomainRepository, domain_id: str) -> list[StoredDomainAssignment]:
    statuses = _engagement_statuses([assignment.engagement_id for assignment in repo.list_assignments(domain_id=domain_id)])
    return [
        assignment
        for assignment in repo.list_assignments(domain_id=domain_id)
        if assignment.status == "active" and statuses.get(assignment.engagement_id, "") not in ENGAGEMENT_PAST_STATUSES
    ]


def _assignment_view(assignment: StoredDomainAssignment) -> DomainAssignmentView:
    purpose_tags = _assignment_purpose_tags(assignment)
    return DomainAssignmentView(
        id=assignment.id,
        domain_id=assignment.domain_id,
        engagement_id=assignment.engagement_id,
        engagement_name=assignment.engagement_name,
        purpose=_purpose_from_tags(purpose_tags, assignment.purpose),
        purpose_tags=purpose_tags,
        status=assignment.status,
        notes=assignment.notes,
        assigned_at=assignment.assigned_at,
        released_at=assignment.released_at,
    )


def _asset_dict(asset: StoredDomainAsset) -> dict[str, Any]:
    return {
        "id": asset.id,
        "domainName": asset.domain_name,
        "registrar": asset.registrar,
        "registration": {"createdAt": asset.registration_started_at, "expiresAt": asset.expiration_at, "autoRenew": asset.auto_renew},
        "healthRisk": {
            "status": asset.risk_status,
            "flags": asset.risk_flags,
            "cooldownUntil": asset.cooldown_until,
            "assignableOverride": asset.assignable_override,
        },
        "providerStatus": asset.provider_status,
        "notes": asset.notes,
        "catalogState": asset.catalog_state,
        "lastSyncedAt": asset.last_synced_at,
    }


def _engagement_dict(assignment: DomainAssignmentView | None) -> dict[str, str] | None:
    if assignment is None:
        return None
    return {"id": assignment.engagement_id, "name": assignment.engagement_name}


def _purpose_tags_from_body(body: dict[str, Any]) -> list[str]:
    if "purposeTags" in body:
        value = body.get("purposeTags")
        if not isinstance(value, list):
            raise DomainValidationError(["purposeTags must be a list"])
        return normalize_purpose_tags(value)
    return normalize_purpose_tags([body.get("purpose", "other")])


def _purpose_tags_patch_from_body(body: dict[str, Any]) -> list[str]:
    if "purposeTags" in body:
        value = body.get("purposeTags")
        if not isinstance(value, list):
            raise DomainValidationError(["purposeTags must be a list"])
        return normalize_purpose_tags(value)
    if "purpose" in body:
        return normalize_purpose_tags([body.get("purpose", "")])
    raise DomainValidationError(["purposeTags is required"])


def _assignment_purpose_tags(assignment: StoredDomainAssignment) -> list[str]:
    tags = normalize_purpose_tags(assignment.purpose_tags)
    if tags:
        return tags
    return normalize_purpose_tags([assignment.purpose])


def _purpose_from_tags(tags: list[str], legacy_purpose: str) -> str:
    if tags:
        return ", ".join(tags)
    return str(legacy_purpose or "").strip()


def normalize_purpose_tags(values: list[Any]) -> list[str]:
    tags: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value is None:
            continue
        tag = str(value).strip().lower()
        if not tag or tag in seen:
            continue
        seen.add(tag)
        tags.append(tag)
    return tags


def _engagement_name(engagement_id: str) -> str | None:
    from app.storage.models import EngagementModel

    row = EngagementModel.query.session.get(EngagementModel, engagement_id)
    if row is None:
        return None
    return str(row.name)


def _engagement_statuses(engagement_ids: list[str]) -> dict[str, str]:
    if not engagement_ids:
        return {}
    from app.storage.models import EngagementModel

    rows = EngagementModel.query.filter(EngagementModel.id.in_(set(engagement_ids))).all()
    return {row.id: row.status for row in rows}


def _active_catalog_blockers(repo: DomainRepository, asset: StoredDomainAsset) -> list[str]:
    blockers: list[str] = []
    if _current_assignments(repo, asset.id):
        blockers.append("active assignment")
    if _has_active_barragan_dns(repo, asset.id):
        blockers.append("active Barragan-managed DNS")
    return blockers


def _has_active_barragan_dns(repo: DomainRepository, domain_id: str) -> bool:
    snapshots = repo.list_snapshots(domain_id)
    for snapshot in snapshots:
        if not snapshot.hosts:
            continue
        if _is_barragan_dns_apply_job(snapshot.sync_job_id):
            return True
    return False


def _is_barragan_dns_apply_job(job_id: str) -> bool:
    if not job_id:
        return False
    job = SqlAlchemyJobRepository().get(job_id)
    return bool(job and job.action == DNS_APPLY_ACTION and job.status == "succeeded")


def _namecheap_client(alias: str | None) -> NamecheapReadOnlyClient:
    resolved_alias = alias or resolve_default_credential_alias("namecheap")
    if not resolved_alias:
        raise CredentialValidationError(["no active default namecheap credential configured"])
    secret = resolve_credential_secret("namecheap", resolved_alias)
    username, api_key = parse_namecheap_secret(secret)
    return NamecheapReadOnlyClient(username, api_key)


def _host_dict(host: Any) -> dict[str, Any]:
    if hasattr(host, "to_dict"):
        return dict(host.to_dict())
    body = {
        "name": str(getattr(host, "name", "")),
        "type": str(getattr(host, "record_type", getattr(host, "type", ""))),
        "address": str(getattr(host, "address", "")),
        "ttl": str(getattr(host, "ttl", "")),
        "mxPref": str(getattr(host, "mx_pref", "")),
    }
    host_id = str(getattr(host, "host_id", getattr(host, "hostId", ""))).strip()
    if host_id:
        body["hostId"] = host_id
    return body


def _namecheap_host_snapshot(
    client: NamecheapDomainAdapter,
    domain_name: str,
    metadata: dict[str, Any],
) -> tuple[list[dict[str, Any]], str, dict[str, str] | None]:
    if _metadata_is_explicit_false(metadata, "isOurDNS"):
        return [], "external_dns_provider", None
    try:
        return [_host_dict(host) for host in client.get_hosts(domain_name)], "provider_snapshot", None
    except NamecheapError:
        return (
            [],
            "provider_snapshot_error",
            {"source": "provider_snapshot_error", "reason": "namecheap_get_hosts_unavailable"},
        )


def _metadata_is_explicit_false(metadata: dict[str, Any], key: str) -> bool:
    if key not in metadata:
        return False
    value = metadata[key]
    if isinstance(value, bool):
        return value is False
    if isinstance(value, str):
        return value.strip().lower() in {"false", "no", "0"}
    return value == 0


def _safe_error(exc: Exception) -> str:
    if isinstance(exc, CredentialStoreLockedError):
        return str(exc)
    if isinstance(exc, CredentialValidationError):
        return "; ".join(exc.errors)
    message = str(exc)
    for marker in ("ApiKey", "apikey", "api_key", "secret", "token", "password", "?"):
        if marker.lower() in message.lower():
            return "domain sync failed with redacted sensitive details"
    return message or "domain sync failed"


def _repo(repository: DomainRepository | None) -> DomainRepository:
    return repository or SqlAlchemyDomainRepository()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
