# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from app.services.domains import normalize_domain_name
from app.services.engagement_operations import get_operations_overview
from app.services.engagements import get_engagement
from app.services.inbound_channel_certificate import (
    COMMAND_TIMEOUT_SECONDS,
    CertificateCoreHost,
    _assert_no_private_key_contents,
    _certificate_proxy_host,
    _run_command,
    _safe_command_display,
    _sanitize_output,
    _start_background_task,
)
from app.services.shared_proxy_stack import (
    SharedProxyStackMutationConflict,
    reserve_shared_proxy_stack_mutation,
)
from app.integrations.ansible_disposable_validation import resolve_ansible_playbook
from app.integrations.oci_disposable_terraform import DisposableCommandResult
from app.services.core_ssh import ensure_known_hosts_file
from app.domain import JobEvent
from app.storage.certificate_repository import (
    CertificateRepository,
    SqlAlchemyCertificateRepository,
    StoredCertificateAsset,
    StoredCertificateBinding,
    StoredCertificateProfile,
    StoredCertificateVersion,
)
from app.storage.domain_repository import DomainRepository, SqlAlchemyDomainRepository
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.service_repository import EngagementServiceRepository, SqlAlchemyEngagementServiceRepository, StoredEngagementService


CERTIFICATE_SOURCES = {"letsencrypt", "self-signed", "external"}
ACME_ENVIRONMENTS = {"staging", "production"}
MAX_IDENTIFIERS = 100
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
DEFAULT_WORKSPACE_ROOT = Path("/tmp/barragan-certificate-manager")
CERTIFICATE_ISSUE_ACTION = "certificate_asset_issue"
CERTIFICATE_RENEW_ACTION = "certificate_asset_renew"
CERTIFICATE_REISSUE_ACTION = "certificate_asset_reissue"
CERTIFICATE_REVOKE_ACTION = "certificate_asset_revoke"
CERTIFICATE_BIND_ACTION = "certificate_asset_bind"
CERTIFICATE_UNBIND_ACTION = "certificate_asset_unbind"
CERTIFICATE_EVIDENCE_PREFIX = "BARRAGAN_CERTIFICATE_ASSET_EVIDENCE="
CommandRunner = Callable[[list[str], Path | None], subprocess.CompletedProcess[str]]
BackgroundRunner = Callable[[Callable[[], None]], None]


class CertificateManagerValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("certificate manager validation failed")
        self.errors = errors


def certificate_manager_workspace(
    engagement_id: str,
    *,
    repository: CertificateRepository | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    repo = repository or SqlAlchemyCertificateRepository()
    profile = repo.get_profile(engagement_id) or StoredCertificateProfile(engagement_id)
    assets = [_asset_detail(repo, asset) for asset in repo.list_assets(engagement_id)]
    overview = get_operations_overview(engagement_id, include_provider_findings=False) or {}
    proxies = [
        {"id": str(row.get("hostname") or ""), "label": str(row.get("hostname") or ""), "status": str(row.get("status") or "")}
        for row in overview.get("coreInfrastructure", [])
        if isinstance(row, dict) and row.get("role") == "proxy" and row.get("hostname")
    ]
    return {
        "engagement": {"id": engagement_id, "name": engagement.name},
        "profile": profile.to_dict(),
        "certificates": assets,
        "proxies": proxies,
        "sources": sorted(CERTIFICATE_SOURCES),
        "maxIdentifiers": MAX_IDENTIFIERS,
    }


def update_certificate_profile(
    engagement_id: str,
    body: dict[str, Any],
    *,
    repository: CertificateRepository | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    email = str(body.get("acmeEmail") or "").strip()
    environment = str(body.get("defaultEnvironment") or "staging").strip().lower()
    errors = []
    if email and not EMAIL_PATTERN.fullmatch(email):
        errors.append("acmeEmail must be a valid email address")
    if environment not in ACME_ENVIRONMENTS:
        errors.append("defaultEnvironment must be staging or production")
    if errors:
        raise CertificateManagerValidationError(errors)
    repo = repository or SqlAlchemyCertificateRepository()
    return {"profile": repo.save_profile(StoredCertificateProfile(engagement_id, email, environment)).to_dict()}


def migrate_legacy_channel_certificates(repository: CertificateRepository | None = None) -> int:
    """Idempotently adopt only unambiguous Barragan-managed channel metadata."""
    from app.storage.models import EngagementOperationsModel

    repo = repository or SqlAlchemyCertificateRepository()
    migrated = 0
    for row in EngagementOperationsModel.query.all():
        overview = get_operations_overview(row.engagement_id, include_provider_findings=False) or {}
        for channel in overview.get("inboundChannels", []):
            if not isinstance(channel, dict):
                continue
            legacy = channel.get("certificate")
            if not isinstance(legacy, dict) or str(legacy.get("managedBy") or "").lower() != "barragan":
                continue
            hostname = str(legacy.get("domain") or channel.get("domain") or "").lower().rstrip(".")
            proxy_id = str(legacy.get("targetProxyId") or channel.get("proxy") or "")
            service_id = str(channel.get("serviceId") or "")
            paths = legacy.get("paths") if isinstance(legacy.get("paths"), dict) else {}
            if not hostname or not proxy_id or not service_id or not paths.get("fullchain") or not paths.get("privkey"):
                continue
            digest = hashlib.sha256(f"{row.engagement_id}\n{proxy_id}\n{hostname}".encode()).hexdigest()[:16]
            asset_id = f"cert-migrated-{digest}"
            if repo.get_asset(row.engagement_id, asset_id):
                continue
            source = "self-signed" if str(legacy.get("type") or "").lower() == "self-signed" else "letsencrypt"
            version_id = f"certver-migrated-{digest}"
            status = "revoked" if str(legacy.get("status") or "").lower() == "revoked" else "active"
            asset = repo.save_asset(StoredCertificateAsset(
                id=asset_id, engagement_id=row.engagement_id, name=f"Migrated {hostname}", source=source,
                target_proxy_id=proxy_id, identifiers=(hostname,), primary_identifier=hostname,
                status=status,
            ))
            repo.save_version(StoredCertificateVersion(
                id=version_id, certificate_id=asset_id, sequence=1, status=status,
                acme_environment=str(legacy.get("acmeEnvironment") or ""), key_generation=1,
                issuer=str(legacy.get("issuer") or ""), serial_number=str(legacy.get("serialNumber") or ""),
                fingerprint_sha256=str(legacy.get("fingerprintSha256") or ""), paths=dict(paths),
                issued_at=str(legacy.get("issuedAt") or ""), expires_at=str(legacy.get("expiresAt") or ""),
            ))
            repo.save_asset(replace(asset, current_version_id=version_id))
            repo.save_binding(StoredCertificateBinding(
                id=f"certbind-migrated-{digest}", engagement_id=row.engagement_id, certificate_id=asset_id,
                service_id=service_id, channel_id=str(channel.get("channelId") or ""), hostname=hostname,
                status="critical_revoked" if status == "revoked" else "bound",
                validation={"status": "pending", "detail": "Migrated from legacy channel certificate metadata; Inspector validation is pending."},
            ))
            migrated += 1
    return migrated


def create_certificate_asset(
    engagement_id: str,
    body: dict[str, Any],
    *,
    repository: CertificateRepository | None = None,
    domain_repository: DomainRepository | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    repo = repository or SqlAlchemyCertificateRepository()
    source = str(body.get("source") or "letsencrypt").strip().lower()
    name = str(body.get("name") or "").strip()
    proxy_id = str(body.get("targetProxyId") or "").strip()
    notes = str(body.get("notes") or "").strip()
    identifiers = _validated_identifiers(body.get("identifiers"), engagement_id, domain_repository or SqlAlchemyDomainRepository())
    errors = []
    if source not in CERTIFICATE_SOURCES:
        errors.append("source must be letsencrypt, self-signed, or external")
    if not name:
        errors.append("name is required")
    if any(asset.name.lower() == name.lower() for asset in repo.list_assets(engagement_id)):
        errors.append("certificate name must be unique within the engagement")
    if not _active_proxy(engagement_id, proxy_id):
        errors.append("targetProxyId must identify an active proxy in this engagement")
    if errors:
        raise CertificateManagerValidationError(errors)
    certificate_pem = str(body.get("certificatePem") or "")
    if source == "external":
        if not certificate_pem:
            raise CertificateManagerValidationError(["certificatePem is required for an external certificate"])
        _parse_external_certificate(certificate_pem, tuple(identifiers))
    asset = repo.save_asset(StoredCertificateAsset(
        id=f"cert-{uuid4().hex[:12]}",
        engagement_id=engagement_id,
        name=name,
        source=source,
        target_proxy_id=proxy_id,
        identifiers=tuple(identifiers),
        primary_identifier=identifiers[0],
        notes=notes,
    ))
    if source == "external":
        asset = _store_external_version(repo, asset, certificate_pem)
    return {"certificate": _asset_detail(repo, asset)}


def update_certificate_asset_metadata(
    engagement_id: str,
    certificate_id: str,
    body: dict[str, Any],
    *,
    repository: CertificateRepository | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    unsupported = sorted(set(body) - {"notes"})
    if unsupported:
        raise CertificateManagerValidationError([f"unsupported certificate metadata fields: {', '.join(unsupported)}"])
    repo = repository or SqlAlchemyCertificateRepository()
    asset = repo.get_asset(engagement_id, certificate_id)
    if asset is None:
        return None
    notes = str(body.get("notes") or "")
    if len(notes) > 4000:
        raise CertificateManagerValidationError(["notes must be 4000 characters or fewer"])
    saved = repo.save_asset(replace(asset, notes=notes.strip()))
    return {"certificate": _asset_detail(repo, saved)}


def get_certificate_asset(
    engagement_id: str,
    certificate_id: str,
    *,
    repository: CertificateRepository | None = None,
) -> dict[str, Any] | None:
    repo = repository or SqlAlchemyCertificateRepository()
    asset = repo.get_asset(engagement_id, certificate_id)
    return {"certificate": _asset_detail(repo, asset)} if asset else None


def start_certificate_issue(
    engagement_id: str,
    certificate_id: str,
    body: dict[str, Any],
    *,
    requested_by: str = "operator",
    certificate_repository: CertificateRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
    job_repository: JobRepository | None = None,
    runner: CommandRunner | None = None,
    background_runner: BackgroundRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
    action: str = CERTIFICATE_ISSUE_ACTION,
) -> dict[str, Any] | None:
    from app.services.engagement_teardown import assert_engagement_mutation_allowed

    assert_engagement_mutation_allowed(engagement_id, repository=job_repository)
    repo = certificate_repository or SqlAlchemyCertificateRepository()
    jobs = job_repository or SqlAlchemyJobRepository()
    asset = repo.get_asset(engagement_id, certificate_id)
    if asset is None:
        return None
    if asset.source == "external":
        raise CertificateManagerValidationError(["external certificate metadata cannot be issued by Barragan"])
    if asset.status in {"issuing", "renewing", "reissuing", "revoking"}:
        raise CertificateManagerValidationError([f"certificate job {asset.last_job_id or 'unknown'} is already running"])
    versions = repo.list_versions(asset.id)
    if action == CERTIFICATE_ISSUE_ACTION and any(version.status != "failed" for version in versions):
        raise CertificateManagerValidationError(["certificate has already been issued; use Renew or Reissue"])
    if action == CERTIFICATE_RENEW_ACTION and (not versions or asset.source != "letsencrypt" or asset.status != "active"):
        raise CertificateManagerValidationError(["Renew requires an active Let's Encrypt certificate"])
    profile = repo.get_profile(engagement_id) or StoredCertificateProfile(engagement_id)
    environment = str(body.get("acmeEnvironment") or profile.default_environment or "staging").lower()
    if environment not in ACME_ENVIRONMENTS:
        raise CertificateManagerValidationError(["acmeEnvironment must be staging or production"])
    if (
        asset.source == "letsencrypt"
        and environment == "production"
        and action in {CERTIFICATE_RENEW_ACTION, CERTIFICATE_REISSUE_ACTION}
        and requested_by != "certificate-scheduler"
    ):
        expected = production_confirmation(asset, action)
        if str(body.get("productionConfirmation") or "") != expected:
            raise CertificateManagerValidationError([f'productionConfirmation must equal "{expected}"'])
    if asset.source == "letsencrypt" and not EMAIL_PATTERN.fullmatch(profile.acme_email or ""):
        raise CertificateManagerValidationError(["configure a valid engagement ACME email before issuance"])
    stack = _proxy_stack(asset, service_repository or SqlAlchemyEngagementServiceRepository())
    resolution = resolve_ansible_playbook(env=env)
    if not resolution.ok:
        raise CertificateManagerValidationError([resolution.error or "Could not resolve ansible-playbook executable"])
    proxy = _certificate_proxy_host(jobs, engagement_id, asset.target_proxy_id)
    ensure_known_hosts_file(proxy.known_hosts_file)
    sequence = len(versions) + 1
    current = repo.get_version(asset.current_version_id) if asset.current_version_id else None
    key_generation = (current.key_generation if action == CERTIFICATE_RENEW_ACTION and current else (current.key_generation + 1 if current else 1))
    version = repo.save_version(StoredCertificateVersion(
        id=f"certver-{uuid4().hex[:12]}", certificate_id=asset.id, sequence=sequence,
        status="pending", acme_environment=environment if asset.source == "letsencrypt" else "",
        key_generation=key_generation,
    ))
    workspace = _write_managed_certificate_workspace(
        workspace_root or DEFAULT_WORKSPACE_ROOT,
        asset,
        version,
        proxy,
        stack,
        reuse_current_key=action == CERTIFICATE_RENEW_ACTION,
    )
    ansible = resolution.command or "ansible-playbook"
    prepare_name = "issue_self_signed_certificate.yml" if asset.source == "self-signed" else "prepare_certificate_csr.yml"
    prepare_command = [ansible, "-i", "ansible/inventory.ini", f"ansible/{prepare_name}"]
    issue_command = (
        [] if asset.source == "self-signed"
        else _certbot_issue_command(workspace, asset, profile.acme_email, environment, env=env)
    )
    deploy_command = [ansible, "-i", "ansible/inventory.ini", "ansible/deploy_certificate_version.yml"]
    state = "renewing" if action == CERTIFICATE_RENEW_ACTION else "reissuing" if action == CERTIFICATE_REISSUE_ACTION else "issuing"
    timestamp = _now()
    job = jobs.save(StoredJobRun(
        id=f"job-{uuid4().hex[:12]}", action=action, status="running",
        target=f"certificate:{asset.id}", target_type="certificate", target_id=asset.id,
        requested_by=requested_by,
        input={"engagementId": engagement_id, "certificateId": asset.id, "versionId": version.id, "source": asset.source, "identifiers": list(asset.identifiers), "targetProxyId": asset.target_proxy_id, "mutation": True},
        artifact_refs=["ansible/inventory.ini", f"ansible/{prepare_name}", "ansible/deploy_certificate_version.yml", "hooks/dns01-auth.sh", "hooks/dns01-cleanup.sh", "MANIFEST.json"],
        created_at=timestamp, started_at=timestamp, finished_at=None,
        events=[JobEvent(1, "info", "certificate asset workspace rendered", {
            "certificateId": asset.id, "versionId": version.id, "source": asset.source,
            "identifiers": list(asset.identifiers), "targetProxyId": asset.target_proxy_id,
            "workspaceDir": str(workspace), "inventoryTargets": ["selected_proxy"],
            "commands": {"prepare": prepare_command, "issue": _safe_command_display(issue_command), "deploy": deploy_command},
            "opsecBoundary": {"throughHomebase": True, "selectedProxyOnly": True, "privateKeyLeavesProxy": False, "namecheapCredentialOnProxy": False, "directEdgeProbeFromAppHost": False},
        })],
    ))
    repo.save_version(replace(version, status=state, last_job_id=job.id))
    pending_asset = repo.save_asset(replace(asset, status=state, last_job_id=job.id))
    (background_runner or _start_background_task)(lambda: _finish_certificate_issue(
        repo, jobs, pending_asset, version, current, job.id, workspace,
        prepare_command, issue_command, deploy_command, runner, action,
    ))
    return {"job": job.to_detail().to_dict(), "certificate": _asset_detail(repo, pending_asset), "status": state}


def start_certificate_renew(engagement_id: str, certificate_id: str, body: dict[str, Any], **kwargs) -> dict[str, Any] | None:
    return start_certificate_issue(engagement_id, certificate_id, body, action=CERTIFICATE_RENEW_ACTION, **kwargs)


def start_certificate_reissue(engagement_id: str, certificate_id: str, body: dict[str, Any], **kwargs) -> dict[str, Any] | None:
    return start_certificate_issue(engagement_id, certificate_id, body, action=CERTIFICATE_REISSUE_ACTION, **kwargs)


def start_certificate_revoke(
    engagement_id: str,
    certificate_id: str,
    body: dict[str, Any],
    *,
    requested_by: str = "operator",
    certificate_repository: CertificateRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
    job_repository: JobRepository | None = None,
    runner: CommandRunner | None = None,
    background_runner: BackgroundRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any] | None:
    repo = certificate_repository or SqlAlchemyCertificateRepository()
    jobs = job_repository or SqlAlchemyJobRepository()
    asset = repo.get_asset(engagement_id, certificate_id)
    if asset is None:
        return None
    if asset.source != "letsencrypt":
        raise CertificateManagerValidationError(["issuer-side revocation is available only for Let's Encrypt certificates"])
    version = repo.get_version(asset.current_version_id) if asset.current_version_id else None
    if version is None or version.status not in {"active", "renewed", "reissued"}:
        raise CertificateManagerValidationError(["an active Let's Encrypt certificate version is required"])
    if asset.status in {"issuing", "renewing", "reissuing", "revoking"}:
        raise CertificateManagerValidationError([f"certificate job {asset.last_job_id or 'unknown'} is already running"])
    if version.acme_environment == "production" and requested_by != "certificate-scheduler":
        expected = production_confirmation(asset, CERTIFICATE_REVOKE_ACTION)
        if str(body.get("productionConfirmation") or "") != expected:
            raise CertificateManagerValidationError([f'productionConfirmation must equal "{expected}"'])
    stack = _proxy_stack(asset, service_repository or SqlAlchemyEngagementServiceRepository())
    resolution = resolve_ansible_playbook(env=env)
    if not resolution.ok:
        raise CertificateManagerValidationError([resolution.error or "Could not resolve ansible-playbook executable"])
    proxy = _certificate_proxy_host(jobs, engagement_id, asset.target_proxy_id)
    workspace = _write_revoke_workspace(workspace_root or DEFAULT_WORKSPACE_ROOT, asset, version, proxy, stack)
    ensure_known_hosts_file(proxy.known_hosts_file)
    ansible = resolution.command or "ansible-playbook"
    fetch_command = [ansible, "-i", "ansible/inventory.ini", "ansible/fetch_public_certificate.yml"]
    revoke_command = _certbot_revoke_command(workspace, engagement_id, version.acme_environment, env=env)
    timestamp = _now()
    job = jobs.save(StoredJobRun(
        id=f"job-{uuid4().hex[:12]}", action=CERTIFICATE_REVOKE_ACTION, status="running",
        target=f"certificate:{asset.id}", target_type="certificate", target_id=asset.id,
        requested_by=requested_by,
        input={"engagementId": engagement_id, "certificateId": asset.id, "versionId": version.id, "mutation": True},
        artifact_refs=["ansible/inventory.ini", "ansible/fetch_public_certificate.yml", "MANIFEST.json"],
        created_at=timestamp, started_at=timestamp, finished_at=None,
        events=[JobEvent(1, "info", "certificate revocation workspace rendered", {
            "certificateId": asset.id, "versionId": version.id, "workspaceDir": str(workspace),
            "commands": {"fetchPublicCertificate": fetch_command, "revoke": _safe_command_display(revoke_command)},
            "bindingsRemainActive": True,
            "opsecBoundary": {"privateKeyLeavesProxy": False, "selectedProxyOnly": True, "directEdgeProbeFromAppHost": False},
        })],
    ))
    pending = repo.save_asset(replace(asset, status="revoking", last_job_id=job.id))
    repo.save_version(replace(version, status="revoking", last_job_id=job.id))
    (background_runner or _start_background_task)(lambda: _finish_certificate_revoke(
        repo, jobs, pending, version, job.id, workspace, fetch_command, revoke_command, runner,
    ))
    return {"job": job.to_detail().to_dict(), "certificate": _asset_detail(repo, pending), "status": "revoking"}


def production_confirmation(asset: StoredCertificateAsset, action: str) -> str:
    operation = "revoke" if action == CERTIFICATE_REVOKE_ACTION else "reissue" if action == CERTIFICATE_REISSUE_ACTION else "renew" if action == CERTIFICATE_RENEW_ACTION else "issue"
    digest = hashlib.sha256("\n".join(asset.identifiers).encode("utf-8")).hexdigest()[:12]
    return f"{operation}-production-{asset.id}-{asset.target_proxy_id}-{digest}"


def replace_external_certificate(
    engagement_id: str,
    certificate_id: str,
    body: dict[str, Any],
    *,
    repository: CertificateRepository | None = None,
) -> dict[str, Any] | None:
    repo = repository or SqlAlchemyCertificateRepository()
    asset = repo.get_asset(engagement_id, certificate_id)
    if asset is None:
        return None
    if asset.source != "external":
        raise CertificateManagerValidationError(["only external certificates accept public certificate replacement"])
    certificate_pem = str(body.get("certificatePem") or "")
    if not certificate_pem:
        raise CertificateManagerValidationError(["certificatePem is required"])
    asset = _store_external_version(repo, asset, certificate_pem)
    return {"certificate": _asset_detail(repo, asset)}


def retire_certificate_asset(
    engagement_id: str,
    certificate_id: str,
    *,
    repository: CertificateRepository | None = None,
) -> dict[str, Any] | None:
    repo = repository or SqlAlchemyCertificateRepository()
    asset = repo.get_asset(engagement_id, certificate_id)
    if asset is None:
        return None
    if repo.list_bindings(engagement_id, certificate_id):
        raise CertificateManagerValidationError(["remove or replace all bindings before retiring this certificate"])
    saved = repo.save_asset(replace(asset, status="retired"))
    return {"certificate": _asset_detail(repo, saved)}


def channel_certificate_binding_workspace(
    engagement_id: str,
    channel_id: str,
    *,
    certificate_repository: CertificateRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    channel = _channel(engagement_id, channel_id)
    if channel is None:
        raise CertificateManagerValidationError([f"inbound channel {channel_id} was not found"])
    service_id = str(channel.get("serviceId") or "")
    repo = certificate_repository or SqlAlchemyCertificateRepository()
    service_repo = service_repository or SqlAlchemyEngagementServiceRepository()
    service = service_repo.get(engagement_id, service_id) if service_id else None
    binding = repo.get_binding_for_service(engagement_id, service_id) if service_id else None
    hostname = str(channel.get("domain") or "").lower()
    proxy_id = str(channel.get("proxy") or "")
    candidates = [
        _asset_detail(repo, asset)
        for asset in repo.list_assets(engagement_id)
        if asset.target_proxy_id == proxy_id
        and asset.status == "active"
        and certificate_covers_hostname(asset.identifiers, hostname)
    ]
    return {
        "channel": channel,
        "service": service.to_dict() if service else None,
        "binding": binding.to_dict() if binding else None,
        "certificate": _asset_detail(repo, repo.get_asset(engagement_id, binding.certificate_id)) if binding else None,
        "candidates": candidates,
        "routeStatus": str(channel.get("status") or ""),
        "tlsStatus": _tls_status(binding, repo.get_asset(engagement_id, binding.certificate_id) if binding else None),
    }


def bind_certificate_to_channel(
    engagement_id: str,
    channel_id: str,
    certificate_id: str,
    *,
    certificate_repository: CertificateRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
    job_repository: JobRepository | None = None,
    runner: CommandRunner | None = None,
    background_runner: BackgroundRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any] | None:
    repo = certificate_repository or SqlAlchemyCertificateRepository()
    workspace = channel_certificate_binding_workspace(
        engagement_id,
        channel_id,
        certificate_repository=repo,
        service_repository=service_repository,
    )
    if workspace is None:
        return None
    channel = workspace["channel"]
    service = workspace["service"]
    asset = repo.get_asset(engagement_id, certificate_id)
    errors = []
    if str(channel.get("mode") or "") != "https-openresty" or str(channel.get("protocol") or "").upper() != "HTTPS":
        errors.append("certificate binding requires the exact managed HTTPS channel")
    if service is None:
        errors.append("certificate binding requires a managed service endpoint")
    if asset is None:
        errors.append("certificateId was not found in this engagement")
    if asset and asset.target_proxy_id != str(channel.get("proxy") or ""):
        errors.append("certificate and channel must target the same proxy")
    hostname = str(channel.get("domain") or "").lower()
    if asset and not certificate_covers_hostname(asset.identifiers, hostname):
        errors.append("certificate identifiers do not cover the channel hostname")
    if asset and asset.status != "active":
        errors.append("certificate is not active and cannot be bound")
    if errors:
        raise CertificateManagerValidationError(errors)
    assert asset is not None and service is not None
    status = "expected_external" if asset.source == "external" else "activating"
    existing = repo.get_binding_for_service(engagement_id, str(service["serviceId"]))
    binding = StoredCertificateBinding(
        id=existing.id if existing else f"certbind-{uuid4().hex[:12]}",
        engagement_id=engagement_id,
        certificate_id=asset.id,
        service_id=str(service["serviceId"]),
        channel_id=channel_id,
        hostname=hostname,
        status=status,
        validation={"status": "pending", "detail": "Inspector TLS validation has not confirmed this binding."},
    )
    if asset.source != "external":
        try:
            jobs = job_repository or SqlAlchemyJobRepository()
            stored_service = (service_repository or SqlAlchemyEngagementServiceRepository()).get(engagement_id, str(service["serviceId"]))
            assert stored_service is not None
            proxy = _certificate_proxy_host(jobs, engagement_id, asset.target_proxy_id)
            ensure_known_hosts_file(proxy.known_hosts_file)
            resolution = resolve_ansible_playbook(env=env)
            if not resolution.ok:
                raise CertificateManagerValidationError([resolution.error or "Could not resolve ansible-playbook executable"])
            work = _write_binding_workspace(
                workspace_root or DEFAULT_WORKSPACE_ROOT,
                asset,
                binding,
                stored_service,
                proxy,
                previous_binding=(
                    existing
                    if existing is not None and existing.status in {"bound", "deactivation_failed"}
                    else None
                ),
            )
        except Exception:
            raise
        command = [resolution.command or "ansible-playbook", "-i", "ansible/inventory.ini", "ansible/activate_certificate_binding.yml"]
        now = _now()
        candidate_job = StoredJobRun(
            id=f"job-{uuid4().hex[:12]}", action=CERTIFICATE_BIND_ACTION, status="running",
            target=f"certificate-binding:{binding.id}", target_type="certificate_binding", target_id=binding.id,
            requested_by="operator", input={"engagementId": engagement_id, "certificateId": asset.id, "channelId": channel_id, "proxyId": asset.target_proxy_id, "mutation": True},
            artifact_refs=["ansible/inventory.ini", "ansible/activate_certificate_binding.yml", "MANIFEST.json"],
            created_at=now, started_at=now, finished_at=None,
            events=[JobEvent(1, "info", "certificate binding workspace rendered", {"certificateId": asset.id, "channelId": channel_id, "selectedProxy": asset.target_proxy_id, "privateKeyLeavesProxy": False})],
        )
        try:
            job = reserve_shared_proxy_stack_mutation(
                jobs,
                candidate_job,
                engagement_id=engagement_id,
                proxy_id=asset.target_proxy_id,
            )
        except SharedProxyStackMutationConflict as exc:
            shutil.rmtree(work, ignore_errors=True)
            raise CertificateManagerValidationError(
                [f"Shared proxy web-stack mutation already running on {asset.target_proxy_id}: {exc.job.id} ({exc.job.action})"]
            ) from exc
        binding = repo.save_binding(replace(binding, last_job_id=job.id))
        (background_runner or _start_background_task)(
            lambda: _finish_certificate_binding(repo, jobs, binding, existing, job.id, work, command, runner)
        )
    else:
        binding = repo.save_binding(binding)
    result = channel_certificate_binding_workspace(
        engagement_id,
        channel_id,
        certificate_repository=repo,
        service_repository=service_repository,
    )
    result["job"] = None
    if asset.source != "external":
        result["job"] = jobs.get(binding.last_job_id).to_detail().to_dict() if jobs.get(binding.last_job_id) else None
    return result


def unbind_certificate_from_channel(
    engagement_id: str,
    channel_id: str,
    *,
    certificate_repository: CertificateRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
    job_repository: JobRepository | None = None,
    runner: CommandRunner | None = None,
    background_runner: BackgroundRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    channel = _channel(engagement_id, channel_id)
    if channel is None:
        raise CertificateManagerValidationError([f"inbound channel {channel_id} was not found"])
    repo = certificate_repository or SqlAlchemyCertificateRepository()
    unbind_job: StoredJobRun | None = None
    service_id = str(channel.get("serviceId") or "")
    binding = repo.get_binding_for_service(engagement_id, service_id) if service_id else None
    if binding:
        if binding.channel_id != channel_id:
            raise CertificateManagerValidationError(["certificate unbinding must target the exact bound HTTPS channel"])
        asset = repo.get_asset(engagement_id, binding.certificate_id)
        if asset and asset.source != "external":
            services = service_repository or SqlAlchemyEngagementServiceRepository()
            service = services.get(engagement_id, service_id)
            if service is None:
                raise CertificateManagerValidationError(["bound service metadata was not found"])
            jobs = job_repository or SqlAlchemyJobRepository()
            resolution = resolve_ansible_playbook(env=env)
            if not resolution.ok:
                raise CertificateManagerValidationError([resolution.error or "Could not resolve ansible-playbook executable"])
            proxy = _certificate_proxy_host(jobs, engagement_id, asset.target_proxy_id)
            ensure_known_hosts_file(proxy.known_hosts_file)
            work = _write_unbinding_workspace(workspace_root or DEFAULT_WORKSPACE_ROOT, binding, service, proxy)
            command = [resolution.command or "ansible-playbook", "-i", "ansible/inventory.ini", "ansible/deactivate_certificate_binding.yml"]
            now = _now()
            candidate_job = StoredJobRun(
                id=f"job-{uuid4().hex[:12]}", action=CERTIFICATE_UNBIND_ACTION, status="running",
                target=f"certificate-binding:{binding.id}", target_type="certificate_binding", target_id=binding.id,
                requested_by="operator", input={"engagementId": engagement_id, "certificateId": asset.id, "channelId": channel_id, "proxyId": asset.target_proxy_id, "mutation": True}, artifact_refs=["ansible/inventory.ini", "ansible/deactivate_certificate_binding.yml", "MANIFEST.json"],
                created_at=now, started_at=now, finished_at=None,
                events=[JobEvent(1, "info", "certificate unbinding workspace rendered", {"certificateId": asset.id, "channelId": channel_id, "selectedProxy": asset.target_proxy_id})],
            )
            try:
                unbind_job = reserve_shared_proxy_stack_mutation(
                    jobs,
                    candidate_job,
                    engagement_id=engagement_id,
                    proxy_id=asset.target_proxy_id,
                )
            except SharedProxyStackMutationConflict as exc:
                shutil.rmtree(work, ignore_errors=True)
                raise CertificateManagerValidationError(
                    [f"Shared proxy web-stack mutation already running on {asset.target_proxy_id}: {exc.job.id} ({exc.job.action})"]
                ) from exc
            pending = repo.save_binding(replace(binding, status="deactivating", last_job_id=unbind_job.id))
            job_id = unbind_job.id
            (background_runner or _start_background_task)(
                lambda job_id=job_id: _finish_certificate_unbinding(repo, jobs, pending, job_id, work, command, runner)
            )
        else:
            repo.delete_binding(engagement_id, binding.id)
    result = channel_certificate_binding_workspace(
        engagement_id,
        channel_id,
        certificate_repository=repo,
    )
    if result is not None:
        result["job"] = None
    if result is not None and unbind_job is not None:
        current_job = (job_repository or SqlAlchemyJobRepository()).get(unbind_job.id)
        result["job"] = current_job.to_detail().to_dict() if current_job else None
    return result


def certificate_covers_hostname(identifiers: tuple[str, ...] | list[str], hostname: str) -> bool:
    normalized = normalize_domain_name(hostname)
    for identifier in identifiers:
        if identifier == normalized:
            return True
        if identifier.startswith("*."):
            suffix = identifier[2:]
            if normalized.endswith(f".{suffix}") and normalized.count(".") == suffix.count(".") + 1:
                return True
    return False


def _validated_identifiers(raw: Any, engagement_id: str, repository: DomainRepository) -> list[str]:
    if not isinstance(raw, list) or not raw:
        raise CertificateManagerValidationError(["identifiers must contain at least one DNS name"])
    if len(raw) > MAX_IDENTIFIERS:
        raise CertificateManagerValidationError([f"identifiers cannot contain more than {MAX_IDENTIFIERS} names"])
    identifiers: list[str] = []
    errors: list[str] = []
    assigned = [
        asset.domain_name
        for asset in repository.list_assets()
        if any(assignment.status == "active" for assignment in repository.list_assignments(domain_id=asset.id, engagement_id=engagement_id))
    ]
    for value in raw:
        identifier = str(value or "").strip().lower().rstrip(".")
        wildcard = identifier.startswith("*.")
        base = identifier[2:] if wildcard else identifier
        try:
            normalized = normalize_domain_name(base)
        except ValueError:
            errors.append(f"invalid DNS identifier: {identifier}")
            continue
        if "*" in normalized or ("*" in identifier and not wildcard):
            errors.append(f"wildcard must be the complete leftmost label: {identifier}")
            continue
        normalized_identifier = f"*.{normalized}" if wildcard else normalized
        if normalized_identifier in identifiers:
            errors.append(f"duplicate identifier: {normalized_identifier}")
            continue
        if not any(normalized == zone or normalized.endswith(f".{zone}") for zone in assigned):
            errors.append(f"identifier is not covered by an active engagement domain assignment: {normalized_identifier}")
            continue
        identifiers.append(normalized_identifier)
    if errors:
        raise CertificateManagerValidationError(errors)
    return identifiers


def _store_external_version(repo: CertificateRepository, asset: StoredCertificateAsset, certificate_pem: str) -> StoredCertificateAsset:
    certificate, sans = _parse_external_certificate(certificate_pem, asset.identifiers)
    sequence = len(repo.list_versions(asset.id)) + 1
    version = repo.save_version(StoredCertificateVersion(
        id=f"certver-{uuid4().hex[:12]}", certificate_id=asset.id, sequence=sequence, status="active",
        issuer=certificate.issuer.rfc4514_string(), serial_number=format(certificate.serial_number, "x"),
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        public_metadata={"subject": certificate.subject.rfc4514_string(), "identifiers": sans, "source": "external-metadata"},
        issued_at=certificate.not_valid_before_utc.astimezone(timezone.utc).isoformat(),
        expires_at=certificate.not_valid_after_utc.astimezone(timezone.utc).isoformat(),
    ))
    return repo.save_asset(replace(asset, status="active", current_version_id=version.id))


def _parse_external_certificate(certificate_pem: str, identifiers: tuple[str, ...]) -> tuple[x509.Certificate, list[str]]:
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
    except ValueError:
        raise CertificateManagerValidationError(["certificatePem must contain one valid PEM certificate"])
    try:
        sans = [name.lower() for name in certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        sans = []
    if set(sans) != set(identifiers):
        raise CertificateManagerValidationError(["public certificate DNS SANs must exactly match the immutable certificate identifiers"])
    return certificate, sans


def _asset_detail(repo: CertificateRepository, asset: StoredCertificateAsset | None) -> dict[str, Any] | None:
    if asset is None:
        return None
    versions = repo.list_versions(asset.id)
    bindings = repo.list_bindings(asset.engagement_id, asset.id)
    current = next((version for version in versions if version.id == asset.current_version_id), None)
    return {
        **asset.to_dict(),
        "currentVersion": current.to_dict() if current else None,
        "versions": [version.to_dict() for version in versions],
        "bindings": [binding.to_dict() for binding in bindings],
        "productionConfirmations": {
            "issue": production_confirmation(asset, CERTIFICATE_ISSUE_ACTION),
            "renew": production_confirmation(asset, CERTIFICATE_RENEW_ACTION),
            "reissue": production_confirmation(asset, CERTIFICATE_REISSUE_ACTION),
            "revoke": production_confirmation(asset, CERTIFICATE_REVOKE_ACTION),
        },
    }


def _active_proxy(engagement_id: str, proxy_id: str) -> bool:
    overview = get_operations_overview(engagement_id, include_provider_findings=False) or {}
    aliases = {proxy_id, proxy_id.split("-")[0] if proxy_id else ""}
    return any(
        isinstance(row, dict)
        and row.get("role") == "proxy"
        and str(row.get("status") or "").lower() in {"active", "healthy", "deployed"}
        and ({str(row.get("hostname") or ""), str(row.get("hostname") or "").split("-")[0]} & aliases)
        for row in overview.get("coreInfrastructure", [])
    )


def _channel(engagement_id: str, channel_id: str) -> dict[str, Any] | None:
    overview = get_operations_overview(engagement_id, include_provider_findings=False) or {}
    return next((row for row in overview.get("inboundChannels", []) if isinstance(row, dict) and row.get("channelId") == channel_id), None)


def _tls_status(binding: StoredCertificateBinding | None, asset: StoredCertificateAsset | None) -> str:
    if binding is None or asset is None:
        return "unbound"
    if asset.status == "revoked":
        return "critical_revoked"
    if asset.source == "external":
        return "expected_external"
    return binding.status


def _finish_certificate_issue(
    repo: CertificateRepository,
    jobs: JobRepository,
    asset: StoredCertificateAsset,
    version: StoredCertificateVersion,
    previous: StoredCertificateVersion | None,
    job_id: str,
    workspace: Path,
    prepare_command: list[str],
    issue_command: list[str],
    deploy_command: list[str],
    runner: CommandRunner | None,
    action: str,
) -> None:
    job = jobs.get(job_id)
    if job is None:
        return
    prepare = _run_command(prepare_command, workspace, runner)
    job = _append_progress(jobs, job, "proxy certificate key and request prepared", prepare)
    issue = DisposableCommandResult([], str(workspace), 1, "", "certificate preparation failed", False)
    if prepare.ok and asset.source == "self-signed":
        issue = prepare
    elif prepare.ok and (workspace / "csr.pem").is_file():
        issue = _run_command(issue_command, workspace, runner)
        job = _append_progress(jobs, job, "DNS-01 ACME issuance completed" if issue.ok else "DNS-01 ACME issuance failed", issue)
    deploy = DisposableCommandResult([], str(workspace), 1, "", "certificate was not issued", False)
    required = (workspace / "cert.pem").is_file() and (workspace / "fullchain.pem").is_file()
    if issue.ok and required:
        deploy = _run_command(deploy_command, workspace, runner)
        job = _append_progress(jobs, job, "proxy certificate version activated" if deploy.ok else "proxy certificate activation failed", deploy)
    current_asset = repo.get_asset(asset.engagement_id, asset.id)
    owns_state = current_asset is not None and current_asset.last_job_id == job_id
    public = _public_certificate_metadata(workspace / "cert.pem", asset.identifiers) if deploy.ok else None
    succeeded = bool(prepare.ok and issue.ok and deploy.ok and public and owns_state)
    if succeeded and public:
        paths = {
            "liveDir": f"/etc/letsencrypt/live/barragan/{asset.id}",
            "versionDir": f"/etc/letsencrypt/live/barragan/{asset.id}/versions/{version.id}",
            "fullchain": f"/etc/letsencrypt/live/barragan/{asset.id}/current/fullchain.pem",
            "cert": f"/etc/letsencrypt/live/barragan/{asset.id}/current/cert.pem",
            "chain": f"/etc/letsencrypt/live/barragan/{asset.id}/current/chain.pem",
            "privkey": f"/etc/letsencrypt/live/barragan/{asset.id}/current/privkey.pem",
        }
        final_status = "renewed" if action == CERTIFICATE_RENEW_ACTION else "reissued" if action == CERTIFICATE_REISSUE_ACTION else "active"
        saved_version = repo.save_version(replace(
            version, status=final_status, issuer=public["issuer"], serial_number=public["serialNumber"],
            fingerprint_sha256=public["fingerprintSha256"], public_metadata=public,
            paths=paths, issued_at=public["issuedAt"], expires_at=public["expiresAt"], last_job_id=job_id,
        ))
        final_asset = repo.save_asset(replace(asset, status="active", current_version_id=saved_version.id, last_job_id=job_id))
        if previous and previous.id != saved_version.id and previous.status not in {"revoked", "retired"}:
            repo.save_version(replace(previous, status="superseded"))
        _restore_binding_health(repo, final_asset)
    else:
        repo.save_version(replace(version, status="failed", last_job_id=job_id))
        final_asset = repo.save_asset(replace(asset, status=("revoked" if previous and previous.status == "revoked" else "active" if previous else "failed"), current_version_id=previous.id if previous else "", last_job_id=job_id))
    final = JobEvent(len(job.events) + 1, "info" if succeeded else "error", f"certificate asset {'renewal' if action == CERTIFICATE_RENEW_ACTION else 'reissue' if action == CERTIFICATE_REISSUE_ACTION else 'issuance'} {'succeeded' if succeeded else 'failed'}", {
        "certificateId": asset.id, "versionId": version.id,
        "phases": {"prepare": prepare.ok, "issue": issue.ok, "activate": deploy.ok},
        "certificate": _asset_detail(repo, final_asset),
        **({"error": "certificate job no longer owns asset state"} if not owns_state else {}),
    })
    saved_job = replace(job, status="succeeded" if succeeded else "failed", finished_at=_now(), events=job.events + [final])
    _assert_no_private_key_contents(saved_job.to_detail().to_dict())
    jobs.save(saved_job)
    _remove_public_workspace_files(workspace)


def _finish_certificate_revoke(
    repo: CertificateRepository,
    jobs: JobRepository,
    asset: StoredCertificateAsset,
    version: StoredCertificateVersion,
    job_id: str,
    workspace: Path,
    fetch_command: list[str],
    revoke_command: list[str],
    runner: CommandRunner | None,
) -> None:
    job = jobs.get(job_id)
    if job is None:
        return
    fetched = _run_command(fetch_command, workspace, runner)
    job = _append_progress(jobs, job, "public certificate fetched for revocation", fetched)
    revoked = DisposableCommandResult([], str(workspace), 1, "", "public certificate fetch failed", False)
    if fetched.ok and (workspace / "cert.pem").is_file():
        revoked = _run_command(revoke_command, workspace, runner)
        job = _append_progress(jobs, job, "ACME revocation completed" if revoked.ok else "ACME revocation failed", revoked)
    current = repo.get_asset(asset.engagement_id, asset.id)
    owns_state = current is not None and current.last_job_id == job_id
    succeeded = bool(fetched.ok and revoked.ok and owns_state)
    if succeeded:
        repo.save_version(replace(version, status="revoked", revoked_at=_now(), last_job_id=job_id))
        final_asset = repo.save_asset(replace(asset, status="revoked", last_job_id=job_id))
        for binding in repo.list_bindings(asset.engagement_id, asset.id):
            repo.save_binding(replace(binding, status="critical_revoked", validation={"status": "critical", "detail": "The bound certificate was revoked; reissue or replace it."}, last_job_id=job_id))
    else:
        repo.save_version(replace(version, status="active", last_job_id=job_id))
        final_asset = repo.save_asset(replace(asset, status="active", last_job_id=job_id))
    final = JobEvent(len(job.events) + 1, "info" if succeeded else "error", f"certificate asset revocation {'succeeded' if succeeded else 'failed'}", {
        "certificateId": asset.id, "versionId": version.id, "bindingsRemainActive": True,
        "certificate": _asset_detail(repo, final_asset),
    })
    saved_job = replace(job, status="succeeded" if succeeded else "failed", finished_at=_now(), events=job.events + [final])
    _assert_no_private_key_contents(saved_job.to_detail().to_dict())
    jobs.save(saved_job)
    _remove_public_workspace_files(workspace)


def _write_managed_certificate_workspace(
    root: Path,
    asset: StoredCertificateAsset,
    version: StoredCertificateVersion,
    proxy: CertificateCoreHost,
    stack: dict[str, str],
    *,
    reuse_current_key: bool,
) -> Path:
    workspace = root / f"{asset.id}-{version.id}-{uuid4().hex[:8]}"
    ansible_dir = workspace / "ansible"
    hooks_dir = workspace / "hooks"
    ansible_dir.mkdir(parents=True, exist_ok=True)
    hooks_dir.mkdir(parents=True, exist_ok=True)
    inventory = "\n".join(["# Barragan certificate asset target; selected proxy only.", "[selected_proxy]", proxy.inventory_line(), ""])
    compose = stack["composePath"]
    front = stack["frontProxyService"]
    ownership = stack["ownershipPath"]
    asset_root = f"/etc/letsencrypt/live/barragan/{asset.id}"
    version_dir = f"{asset_root}/versions/{version.id}"
    san = ",".join(f"DNS:{identifier}" for identifier in asset.identifiers)
    key_command = (
        f"test -s {asset_root}/current/privkey.pem; cp {asset_root}/current/privkey.pem {version_dir}/privkey.pem"
        if reuse_current_key else
        f"openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out {version_dir}/privkey.pem"
    )
    prepare = f'''---
- name: Prepare proxy-held certificate key and CSR
  hosts: selected_proxy
  become: true
  gather_facts: false
  tasks:
    - ansible.builtin.stat:
        path: {ownership}
      register: marker
    - ansible.builtin.assert:
        that: [marker.stat.exists, marker.stat.isreg]
    - name: Generate version-specific key and CSR inside the shared proxy volume
      ansible.builtin.command:
        argv: [docker, exec, proxy, sh, -c, "set -eu; umask 077; mkdir -p {version_dir}; {key_command}; openssl req -new -key {version_dir}/privkey.pem -subj /CN={asset.primary_identifier} -addext subjectAltName={san} -out /tmp/{version.id}.csr"]
      no_log: true
    - ansible.builtin.command:
        argv: [docker, cp, proxy:/tmp/{version.id}.csr, /tmp/{version.id}.csr]
    - ansible.builtin.fetch:
        src: /tmp/{version.id}.csr
        dest: {workspace / 'csr.pem'}
        flat: true
    - ansible.builtin.file:
        path: /tmp/{version.id}.csr
        state: absent
'''
    self_signed = f'''---
- name: Generate proxy-held Self-Signed certificate version
  hosts: selected_proxy
  become: true
  gather_facts: false
  tasks:
    - ansible.builtin.stat:
        path: {ownership}
      register: marker
    - ansible.builtin.assert:
        that: [marker.stat.exists, marker.stat.isreg]
    - name: Generate key and Self-Signed certificate inside the shared proxy volume
      ansible.builtin.command:
        argv: [docker, exec, proxy, sh, -c, "set -eu; umask 077; mkdir -p {version_dir}; openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out {version_dir}/privkey.pem; openssl req -x509 -new -sha256 -days 90 -key {version_dir}/privkey.pem -subj /CN={asset.primary_identifier} -addext subjectAltName={san} -out {version_dir}/cert.pem; cp {version_dir}/cert.pem {version_dir}/fullchain.pem"]
      no_log: true
    - ansible.builtin.command:
        argv: [docker, cp, proxy:{version_dir}/cert.pem, /tmp/{version.id}-cert.pem]
    - ansible.builtin.fetch:
        src: /tmp/{version.id}-cert.pem
        dest: {workspace / 'cert.pem'}
        flat: true
    - ansible.builtin.fetch:
        src: /tmp/{version.id}-cert.pem
        dest: {workspace / 'fullchain.pem'}
        flat: true
'''
    deploy = f'''---
- name: Deploy public certificate and atomically activate its version
  hosts: selected_proxy
  become: true
  gather_facts: false
  tasks:
    - name: Stage public certificate files
      ansible.builtin.copy:
        src: "{{{{ item }}}}"
        dest: "/tmp/{version.id}-{{{{ item | basename }}}}"
        mode: "0644"
      loop:
        - {workspace / 'cert.pem'}
        - {workspace / 'fullchain.pem'}
    - name: Copy public files into the version directory
      ansible.builtin.command:
        argv: [docker, cp, "/tmp/{version.id}-{{{{ item }}}}", "proxy:{version_dir}/{{{{ item }}}}"]
      loop: [cert.pem, fullchain.pem]
    - name: Activate version with a stable relative symlink
      ansible.builtin.command:
        argv: [docker, exec, proxy, sh, -c, "set -eu; cd {asset_root}; ln -sfn versions/{version.id} current; openssl x509 -in current/cert.pem -noout -checkend 1"]
    - ansible.builtin.file:
        path: "/tmp/{version.id}-{{{{ item }}}}"
        state: absent
      loop: [cert.pem, fullchain.pem]
'''
    python = json.dumps(sys.executable)
    auth_hook = f"#!/bin/sh\nset -eu\nexec {python} -m app.cli.dns01_hook auth --engagement-id {json.dumps(asset.engagement_id)}\n"
    cleanup_hook = f"#!/bin/sh\nset -eu\nexec {python} -m app.cli.dns01_hook cleanup --engagement-id {json.dumps(asset.engagement_id)}\n"
    manifest = {"engagementId": asset.engagement_id, "certificateId": asset.id, "versionId": version.id, "identifiers": list(asset.identifiers), "targetProxyId": asset.target_proxy_id, "privateKeyLeavesProxy": False, "credentialLeavesBarragan": False}
    (ansible_dir / "inventory.ini").write_text(inventory, encoding="utf-8")
    (ansible_dir / "prepare_certificate_csr.yml").write_text(prepare, encoding="utf-8")
    (ansible_dir / "issue_self_signed_certificate.yml").write_text(self_signed, encoding="utf-8")
    (ansible_dir / "deploy_certificate_version.yml").write_text(deploy, encoding="utf-8")
    (hooks_dir / "dns01-auth.sh").write_text(auth_hook, encoding="utf-8")
    (hooks_dir / "dns01-cleanup.sh").write_text(cleanup_hook, encoding="utf-8")
    (hooks_dir / "dns01-auth.sh").chmod(0o700)
    (hooks_dir / "dns01-cleanup.sh").chmod(0o700)
    (workspace / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    _assert_no_private_key_contents({"inventory": inventory, "prepare": prepare, "selfSigned": self_signed, "deploy": deploy, "manifest": manifest})
    return workspace


def _write_revoke_workspace(root: Path, asset: StoredCertificateAsset, version: StoredCertificateVersion, proxy: CertificateCoreHost, stack: dict[str, str]) -> Path:
    workspace = root / f"{asset.id}-{version.id}-revoke-{uuid4().hex[:8]}"
    ansible = workspace / "ansible"
    ansible.mkdir(parents=True, exist_ok=True)
    inventory = "\n".join(["# Barragan certificate revocation; selected proxy only.", "[selected_proxy]", proxy.inventory_line(), ""])
    cert_path = f"/etc/letsencrypt/live/barragan/{asset.id}/versions/{version.id}/cert.pem"
    transfer = f"/tmp/{version.id}-cert.pem"
    playbook = f'''---
- name: Fetch only the public certificate for revocation
  hosts: selected_proxy
  become: true
  gather_facts: false
  tasks:
    - ansible.builtin.command:
        argv: [docker, cp, proxy:{cert_path}, {transfer}]
    - ansible.builtin.fetch:
        src: {transfer}
        dest: {workspace / 'cert.pem'}
        flat: true
    - ansible.builtin.file:
        path: {transfer}
        state: absent
'''
    (ansible / "inventory.ini").write_text(inventory, encoding="utf-8")
    (ansible / "fetch_public_certificate.yml").write_text(playbook, encoding="utf-8")
    (workspace / "MANIFEST.json").write_text(json.dumps({"certificateId": asset.id, "versionId": version.id, "publicCertificateOnly": True, "bindingsRemainActive": True}, indent=2) + "\n", encoding="utf-8")
    return workspace


def _certbot_issue_command(workspace: Path, asset: StoredCertificateAsset, email: str, environment: str, *, env: Mapping[str, str] | None) -> list[str]:
    values = dict(os.environ if env is None else env)
    certbot = _resolve_certbot_bin(values)
    root = Path(values.get("BARRAGAN_DATA_DIR", str(Path("backend/.data").resolve()))) / "acme" / asset.engagement_id / environment
    command = [certbot, "certonly", "--manual", "--preferred-challenges", "dns", "--manual-auth-hook", str(workspace / "hooks/dns01-auth.sh"), "--manual-cleanup-hook", str(workspace / "hooks/dns01-cleanup.sh"), "--csr", str(workspace / "csr.pem"), "--cert-path", str(workspace / "cert.pem"), "--chain-path", str(workspace / "chain.pem"), "--fullchain-path", str(workspace / "fullchain.pem"), "--config-dir", str(root / "config"), "--work-dir", str(root / "work"), "--logs-dir", str(root / "logs"), "--email", email, "--agree-tos", "--no-eff-email", "--non-interactive"]
    if environment == "staging":
        command.extend(["--server", "https://acme-staging-v02.api.letsencrypt.org/directory"])
    return command


def _certbot_revoke_command(workspace: Path, engagement_id: str, environment: str, *, env: Mapping[str, str] | None) -> list[str]:
    values = dict(os.environ if env is None else env)
    certbot = _resolve_certbot_bin(values)
    root = Path(values.get("BARRAGAN_DATA_DIR", str(Path("backend/.data").resolve()))) / "acme" / engagement_id / environment
    command = [certbot, "revoke", "--cert-path", str(workspace / "cert.pem"), "--config-dir", str(root / "config"), "--work-dir", str(root / "work"), "--logs-dir", str(root / "logs"), "--non-interactive", "--no-delete-after-revoke", "--reason", "cessationofoperation"]
    if environment == "staging":
        command.extend(["--server", "https://acme-staging-v02.api.letsencrypt.org/directory"])
    return command


def _resolve_certbot_bin(values: Mapping[str, str]) -> str:
    configured = str(values.get("CERTBOT_BIN") or "").strip()
    if configured:
        return configured
    discovered = shutil.which("certbot")
    if discovered:
        return discovered
    sibling = Path(sys.executable).parent / "certbot"
    if sibling.is_file() and os.access(sibling, os.X_OK):
        return str(sibling)
    return "certbot"


def _http_backend_site_metadata(service: StoredEngagementService) -> tuple[str, str, str, str, str]:
    """Return the exact, channel-owned backend site paths or fail closed."""
    config = service.config
    site_name = str(config.get("siteName") or "")
    site_compose = str(config.get("siteComposePath") or "")
    site_service = str(config.get("siteService") or "")
    site_config = str(config.get("siteConfigPath") or "")
    unbound_config = str(config.get("unboundConfigPath") or "")
    expected = f"/opt/web/inbound/{site_name}/conf/default.conf"
    valid = (
        str(config.get("stackModel") or "") == "containerized-openresty-v1"
        and str(config.get("composePath") or "") == "/opt/web/docker-compose.yml"
        and str(config.get("stackOwnershipPath") or "") == "/opt/web/.barragan-stack.json"
        and bool(re.fullmatch(r"[a-z0-9][a-z0-9-]*", site_name))
        and site_compose == f"/opt/web/sites/{site_name}.compose.yml"
        # Compose service names emitted for managed HTTP backends use the
        # Docker-safe hyphenated form (for example ``barragan-inbound-…``).
        and bool(re.fullmatch(r"[a-z0-9_-]+", site_service))
        and site_config == expected
        and unbound_config == f"{expected}.barragan-unbound"
    )
    if not valid:
        raise CertificateManagerValidationError(["managed HTTP backend TLS metadata is invalid"])
    return site_name, site_compose, site_service, site_config, unbound_config


def _http_backend_transition_command(*, mode: str, source: str, destination: str, live: str = "") -> str:
    """Return the remote, no-log transition for Barragan-owned backend sites."""
    from app.services.managed_site_observability import render_managed_site_observability_config

    http_observability = render_managed_site_observability_config(receives_proxy_protocol=False).rstrip()
    tls_observability = render_managed_site_observability_config(receives_proxy_protocol=True).rstrip()
    script = f'''import pathlib,sys
mode,source,destination,live=sys.argv[1:]
text=pathlib.Path(source).read_text()
http_observability={http_observability!r}
tls_observability={tls_observability!r}
http_listener='listen 8081;'
legacy_listener='listen 8081 proxy_protocol;'
tls_listener='listen 8081 proxy_protocol ssl;\\n    ssl_certificate '+live+'/fullchain.pem;\\n    ssl_certificate_key '+live+'/privkey.pem;'
is_http=text.count(http_listener)==1 and text.count(http_observability)==1
is_legacy=text.count(legacy_listener)==1 and text.count(tls_observability)==1
if mode == 'unbound':
    output=text if is_http else text.replace(legacy_listener,http_listener).replace(tls_observability,http_observability) if is_legacy else None
elif mode == 'tls':
    output=text.replace(http_listener,tls_listener).replace(http_observability,tls_observability) if is_http else text.replace(legacy_listener,tls_listener) if is_legacy else None
else:
    output=None
if output is None or 'ssl_certificate ' in text or 'ssl_certificate_key ' in text:
    raise SystemExit('managed backend config is not an unbound TLS candidate')
pathlib.Path(destination).write_text(output)
'''
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    return f'''python3 -c "import base64;exec(base64.b64decode('{encoded}').decode())" {mode!r} {source!r} {destination!r} {live!r}'''


def _compose_runtime_tasks() -> str:
    return '''    - name: Detect Docker Compose v2
      ansible.builtin.command:
        argv: [docker, compose, version]
      register: barragan_compose_v2
      failed_when: false
      changed_when: false
    - name: Detect Docker Compose v1 fallback
      ansible.builtin.command:
        argv: [docker-compose, version]
      register: barragan_compose_v1
      when: barragan_compose_v2.rc != 0
      failed_when: false
      changed_when: false
    - name: Require a supported Docker Compose runtime
      ansible.builtin.assert:
        that:
          - barragan_compose_v2.rc == 0 or barragan_compose_v1.rc == 0
    - name: Select Docker Compose command
      ansible.builtin.set_fact:
        barragan_compose_argv: "{{ ['docker', 'compose'] if barragan_compose_v2.rc == 0 else ['docker-compose'] }}"
'''


def _write_http_backend_binding_workspace(root: Path, asset: StoredCertificateAsset, binding: StoredCertificateBinding, service: StoredEngagementService, proxy: CertificateCoreHost) -> Path:
    """Overlay TLS on the existing backend config without exposing its secret."""
    _site_name, site_compose, site_service, site_config, unbound_config = _http_backend_site_metadata(service)
    workspace = root / f"{binding.id}-activate-{uuid4().hex[:8]}"
    ansible = workspace / "ansible"
    ansible.mkdir(parents=True, exist_ok=True)
    inventory = "\n".join(["# Barragan certificate binding; selected proxy only.", "[selected_proxy]", proxy.inventory_line(), ""])
    candidate = f"{site_config}.barragan-tls-candidate"
    live = f"/etc/letsencrypt/live/barragan/{asset.id}/current"
    site_container = f"barragan_{site_service}"
    preserve_unbound = _http_backend_transition_command(
        mode="unbound", source=site_config, destination=unbound_config
    )
    render_tls = _http_backend_transition_command(
        mode="tls", source=site_config, destination=candidate, live=live
    )
    playbook = f'''---
- name: Activate TLS on a managed HTTP backend site
  hosts: selected_proxy
  become: true
  gather_facts: false
  tasks:
{_compose_runtime_tasks()}
    - name: Verify exact Barragan shared-stack ownership
      ansible.builtin.shell:
        cmd: >-
          python3 -c "import json,pathlib,sys; p=pathlib.Path('/opt/web/.barragan-stack.json');
          expected={{'managedBy':'barragan','stackModel':'containerized-openresty-v1'}};
          sys.exit(0 if p.is_file() and not p.is_symlink() and json.loads(p.read_text()) == expected else 1)"
      changed_when: false
    - name: Preserve the managed backend's unbound configuration
      ansible.builtin.shell:
        cmd: >-
          {preserve_unbound}
      no_log: true
    - name: Render TLS overlay without reading or logging backend configuration
      ansible.builtin.shell:
        cmd: >-
          {render_tls}
      no_log: true
    - name: Restrict generated managed backend configurations
      ansible.builtin.file:
        path: "{{{{ item }}}}"
        owner: root
        group: redteam
        mode: "0640"
      loop:
        - {unbound_config}
        - {candidate}
    - name: Activate and validate only the selected backend site
      block:
        - ansible.builtin.command:
            argv: [mv, {candidate}, {site_config}]
        - ansible.builtin.command:
            argv: "{{{{ barragan_compose_argv + ['-f', '/opt/web/docker-compose.yml', '-f', '{site_compose}', 'rm', '-s', '-f', '{site_service}'] }}}}"
          failed_when: false
        - ansible.builtin.command:
            argv: [docker, rm, -f, {site_container}]
          failed_when: false
        - ansible.builtin.command:
            argv: "{{{{ barragan_compose_argv + ['-f', '/opt/web/docker-compose.yml', '-f', '{site_compose}', 'up', '-d', '{site_service}'] }}}}"
        - ansible.builtin.command:
            argv: "{{{{ barragan_compose_argv + ['-f', '/opt/web/docker-compose.yml', '-f', '{site_compose}', 'exec', '-T', '{site_service}', 'openresty', '-t'] }}}}"
        - ansible.builtin.command:
            argv: "{{{{ barragan_compose_argv + ['-f', '/opt/web/docker-compose.yml', '-f', '{site_compose}', 'exec', '-T', '{site_service}', 'openresty', '-s', 'reload'] }}}}"
      rescue:
        - ansible.builtin.copy:
            src: {unbound_config}
            dest: {site_config}
            remote_src: true
            owner: root
            group: redteam
            mode: "0640"
        - ansible.builtin.command:
            argv: "{{{{ barragan_compose_argv + ['-f', '/opt/web/docker-compose.yml', '-f', '{site_compose}', 'up', '-d', '{site_service}'] }}}}"
          failed_when: false
        - ansible.builtin.fail:
            msg: TLS activation failed; the selected HTTP backend configuration was restored.
'''
    (ansible / "inventory.ini").write_text(inventory, encoding="utf-8")
    (ansible / "activate_certificate_binding.yml").write_text(playbook, encoding="utf-8")
    (workspace / "MANIFEST.json").write_text(json.dumps({"certificateId": asset.id, "bindingId": binding.id, "channelId": binding.channel_id, "selectedProxy": asset.target_proxy_id, "privateKeyLeavesProxy": False, "siteKind": "http-backend"}, indent=2) + "\n", encoding="utf-8")
    _assert_no_private_key_contents({"inventory": inventory, "playbook": playbook})
    return workspace


def _write_http_backend_unbinding_workspace(root: Path, binding: StoredCertificateBinding, service: StoredEngagementService, proxy: CertificateCoreHost) -> Path:
    _site_name, site_compose, site_service, site_config, unbound_config = _http_backend_site_metadata(service)
    workspace = root / f"{binding.id}-deactivate-{uuid4().hex[:8]}"
    ansible = workspace / "ansible"
    ansible.mkdir(parents=True, exist_ok=True)
    inventory = "\n".join(["# Barragan certificate unbinding; selected proxy only.", "[selected_proxy]", proxy.inventory_line(), ""])
    playbook = f'''---
- name: Restore a managed HTTP backend's unbound configuration
  hosts: selected_proxy
  become: true
  gather_facts: false
  tasks:
{_compose_runtime_tasks()}
    - name: Verify exact Barragan shared-stack ownership
      ansible.builtin.shell:
        cmd: >-
          python3 -c "import json,pathlib,sys; p=pathlib.Path('/opt/web/.barragan-stack.json');
          expected={{'managedBy':'barragan','stackModel':'containerized-openresty-v1'}};
          sys.exit(0 if p.is_file() and not p.is_symlink() and json.loads(p.read_text()) == expected else 1)"
      changed_when: false
    - ansible.builtin.copy:
        src: {unbound_config}
        dest: {site_config}
        remote_src: true
        owner: root
        group: redteam
        mode: "0640"
    - ansible.builtin.command:
        argv: "{{{{ barragan_compose_argv + ['-f', '/opt/web/docker-compose.yml', '-f', '{site_compose}', 'up', '-d', '{site_service}'] }}}}"
    - ansible.builtin.command:
        argv: "{{{{ barragan_compose_argv + ['-f', '/opt/web/docker-compose.yml', '-f', '{site_compose}', 'exec', '-T', '{site_service}', 'openresty', '-t'] }}}}"
    - ansible.builtin.command:
        argv: "{{{{ barragan_compose_argv + ['-f', '/opt/web/docker-compose.yml', '-f', '{site_compose}', 'exec', '-T', '{site_service}', 'openresty', '-s', 'reload'] }}}}"
'''
    (ansible / "inventory.ini").write_text(inventory, encoding="utf-8")
    (ansible / "deactivate_certificate_binding.yml").write_text(playbook, encoding="utf-8")
    (workspace / "MANIFEST.json").write_text(json.dumps({"bindingId": binding.id, "channelId": binding.channel_id, "tlsMode": "unbound", "siteKind": "http-backend"}, indent=2) + "\n", encoding="utf-8")
    return workspace


def _write_binding_workspace(
    root: Path,
    asset: StoredCertificateAsset,
    binding: StoredCertificateBinding,
    service: StoredEngagementService,
    proxy: CertificateCoreHost,
    *,
    previous_binding: StoredCertificateBinding | None = None,
) -> Path:
    if service.service_type == "web-http-backend":
        return _write_http_backend_binding_workspace(root, asset, binding, service, proxy)
    site_name, site_compose, _http_service, tls_service, tls_config, tls_route = _static_web_tls_metadata(service)
    workspace = root / f"{binding.id}-activate-{uuid4().hex[:8]}"
    ansible = workspace / "ansible"
    ansible.mkdir(parents=True, exist_ok=True)
    inventory = "\n".join(["# Barragan certificate binding; selected proxy only.", "[selected_proxy]", proxy.inventory_line(), ""])
    from app.services.managed_site_observability import render_managed_site_observability_config

    live = f"/etc/letsencrypt/live/barragan/{asset.id}/current"
    site_container = f"barragan_{tls_service}"
    site_config = f"""server {{
    listen 8081 proxy_protocol ssl;
    server_name {binding.hostname};
    root /var/www/html/{site_name};
    index index.html;
    real_ip_header proxy_protocol;
    ssl_certificate {live}/fullchain.pem;
    ssl_certificate_key {live}/privkey.pem;
    include /etc/nginx/conf.d/request-header-gate*.inc;
    location / {{ try_files $uri $uri/ /index.html; }}
}}
"""
    candidate_config = f"{tls_config}.candidate"
    candidate_route = f"{tls_route}.candidate"
    backup_config = f"{tls_config}.previous"
    backup_route = f"{tls_route}.previous"
    tls_observability = f"/opt/web/{site_name}/tls-conf/00-barragan-observability.conf"
    candidate_observability = f"{tls_observability}.candidate"
    backup_observability = f"{tls_observability}.previous"
    observability = render_managed_site_observability_config(receives_proxy_protocol=True)
    route = f"{binding.hostname} {tls_service}:8081;\n"
    previous_asset_id = previous_binding.certificate_id if previous_binding else ""
    previous_hostname = previous_binding.hostname if previous_binding else ""
    existing_runtime_preflight = f'''import pathlib,sys
config=pathlib.Path({tls_config!r})
route=pathlib.Path({tls_route!r})
expected_route={f"{previous_hostname} {tls_service}:8081;"!r}
previous_live={f"/etc/letsencrypt/live/barragan/{previous_asset_id}/current"!r}
if {bool(previous_binding)!r}:
    if not config.is_file() or config.is_symlink() or not route.is_file() or route.is_symlink():
        raise SystemExit('persisted TLS binding runtime is incomplete')
    text=config.read_text()
    lines=[line.strip() for line in route.read_text().splitlines() if line.strip()]
    if lines != [expected_route]:
        raise SystemExit('persisted TLS route does not match the exact prior binding')
    if text.count('listen 8081 proxy_protocol ssl;') != 1 or text.count('ssl_certificate '+previous_live+'/fullchain.pem;') != 1 or text.count('ssl_certificate_key '+previous_live+'/privkey.pem;') != 1:
        raise SystemExit('persisted TLS certificate lineage does not match the exact prior binding')
elif config.exists() or config.is_symlink() or route.exists() or route.is_symlink():
    raise SystemExit('unbound Static Web service has unexpected TLS runtime')
'''
    existing_runtime_preflight = base64.b64encode(existing_runtime_preflight.encode("utf-8")).decode("ascii")
    playbook = f'''---
- name: Activate selected certificate binding
  hosts: selected_proxy
  become: true
  gather_facts: false
  tasks:
{_compose_runtime_tasks()}
    - name: Verify exact Barragan shared-stack ownership
      ansible.builtin.shell:
        cmd: >-
          python3 -c "import json,pathlib,sys; p=pathlib.Path('/opt/web/.barragan-stack.json');
          expected={{'managedBy':'barragan','stackModel':'containerized-openresty-v1'}};
          sys.exit(0 if p.is_file() and not p.is_symlink() and json.loads(p.read_text()) == expected else 1)"
      changed_when: false
    - name: Verify exact persisted TLS binding lineage before mutation
      ansible.builtin.command:
        argv:
          - python3
          - -c
          - "import base64;exec(base64.b64decode('{existing_runtime_preflight}').decode())"
      changed_when: false
    - name: Prepare selected TLS sibling candidates transactionally
      block:
        - name: Ensure the selected TLS sibling directories exist
          ansible.builtin.file:
            path: "{{{{ item }}}}"
            state: directory
            owner: root
            group: redteam
            mode: "0775"
          loop:
            - /opt/web/{site_name}/tls-conf
            - /opt/web/tls
        - name: Render the selected site's TLS configuration candidate
          ansible.builtin.copy:
            dest: {candidate_config}
            owner: root
            group: redteam
            mode: "0644"
            content: |
{''.join('              ' + line + chr(10) for line in site_config.splitlines())}
        - name: Render the selected site's TLS route candidate
          ansible.builtin.copy:
            dest: {candidate_route}
            owner: root
            group: redteam
            mode: "0644"
            content: {json.dumps(route)}
        - name: Render TLS sibling request observability candidate
          ansible.builtin.copy:
            dest: {candidate_observability}
            owner: root
            group: redteam
            mode: "0644"
            content: |
{''.join('              ' + line + chr(10) for line in observability.splitlines())}
        - name: Inspect independent HTTPS request-header gate files
          ansible.builtin.stat:
            path: "/opt/web/{site_name}/tls-conf/{{{{ item }}}}"
          loop:
            - 00-request-header-gate-00-runtime.conf
            - 00-request-header-gate-map.conf
            - request-header-gate.inc
          register: prior_https_gate_files
        - name: Create missing disabled HTTPS gate runtime
          ansible.builtin.copy:
            dest: /opt/web/{site_name}/tls-conf/00-request-header-gate-00-runtime.conf.candidate
            owner: root
            group: redteam
            mode: "0640"
            content: "# Map hash sizing is provided by the stock OpenResty base configuration.\n"
          when: not prior_https_gate_files.results[0].stat.exists
        - name: Create missing disabled HTTPS gate map
          ansible.builtin.copy:
            dest: /opt/web/{site_name}/tls-conf/00-request-header-gate-map.conf.candidate
            owner: root
            group: redteam
            mode: "0640"
            content: "# Barragan request-header gate is disabled.\n"
          when: not prior_https_gate_files.results[1].stat.exists
        - name: Create missing disabled HTTPS gate server include
          ansible.builtin.copy:
            dest: /opt/web/{site_name}/tls-conf/request-header-gate.inc.candidate
            owner: root
            group: redteam
            mode: "0640"
            content: "client_max_body_size 500000000;\n# Barragan request-header gate is disabled.\n"
          when: not prior_https_gate_files.results[2].stat.exists
      rescue:
        - name: Remove incomplete TLS sibling candidates
          ansible.builtin.file:
            path: "{{{{ item }}}}"
            state: absent
          loop:
            - {candidate_config}
            - {candidate_route}
            - {candidate_observability}
            - /opt/web/{site_name}/tls-conf/00-request-header-gate-00-runtime.conf.candidate
            - /opt/web/{site_name}/tls-conf/00-request-header-gate-map.conf.candidate
            - /opt/web/{site_name}/tls-conf/request-header-gate.inc.candidate
        - ansible.builtin.fail:
            msg: TLS sibling candidate preparation failed; no active runtime was changed.
    - name: Record whether this is a rebind
      ansible.builtin.stat:
        path: {tls_config}
      register: prior_tls_config
    - name: Record prior selected TLS container state
      ansible.builtin.command:
        argv: [docker, inspect, -f, "{{% raw %}}{{{{.State.Running}}}}{{% endraw %}}", {site_container}]
      register: prior_tls_container
      failed_when: false
      changed_when: false
    - name: Activate only the selected TLS sibling transactionally
      block:
        - ansible.builtin.shell:
            cmd: >-
              set -eu;
              test ! -e {tls_config} || cp -p {tls_config} {backup_config};
              test ! -e {tls_route} || cp -p {tls_route} {backup_route};
              test ! -e {tls_observability} || cp -p {tls_observability} {backup_observability};
              mv {candidate_config} {tls_config};
              mv {candidate_route} {tls_route};
              mv {candidate_observability} {tls_observability};
              for name in 00-request-header-gate-00-runtime.conf 00-request-header-gate-map.conf request-header-gate.inc; do
                test ! -e "/opt/web/{site_name}/tls-conf/$name.candidate" || mv "/opt/web/{site_name}/tls-conf/$name.candidate" "/opt/web/{site_name}/tls-conf/$name";
              done
        - name: Remove exact selected TLS container before candidate start
          ansible.builtin.command:
            argv: [docker, rm, -f, {site_container}]
          register: candidate_tls_remove
          failed_when: candidate_tls_remove.rc not in [0, 1]
        - name: Find renamed selected TLS Compose containers before candidate start
          ansible.builtin.command:
            argv: [docker, ps, -aq, --filter, "label=com.docker.compose.project=web", --filter, "label=com.docker.compose.service={tls_service}"]
          register: candidate_tls_remnants
          changed_when: false
        - name: Remove renamed selected TLS Compose containers before candidate start
          ansible.builtin.command:
            argv: [docker, rm, -f, "{{{{ item }}}}"]
          loop: "{{{{ candidate_tls_remnants.stdout_lines }}}}"
          when: item | length > 0
        - name: Start selected TLS container with candidate configuration
          ansible.builtin.command:
            argv: "{{{{ barragan_compose_argv + ['-f', '/opt/web/docker-compose.yml', '-f', '{site_compose}', 'up', '-d', '{tls_service}'] }}}}"
        - ansible.builtin.command:
            argv: "{{{{ barragan_compose_argv + ['-f', '/opt/web/docker-compose.yml', '-f', '{site_compose}', 'exec', '-T', '{tls_service}', 'openresty', '-t'] }}}}"
        - ansible.builtin.command:
            argv: [docker, exec, proxy, openresty, -t]
        - ansible.builtin.command:
            argv: [docker, exec, proxy, openresty, -s, reload]
        - ansible.builtin.file:
            path: "{{{{ item }}}}"
            state: absent
          loop: [{backup_config}, {backup_route}, {backup_observability}]
      rescue:
        - ansible.builtin.shell:
            cmd: >-
              set -eu;
              if test -e {backup_config}; then mv {backup_config} {tls_config}; else rm -f {tls_config}; fi;
              if test -e {backup_route}; then mv {backup_route} {tls_route}; else rm -f {tls_route}; fi;
              if test -e {backup_observability}; then mv {backup_observability} {tls_observability}; else rm -f {tls_observability}; fi;
              rm -f {candidate_config} {candidate_route} {candidate_observability};
              for name in 00-request-header-gate-00-runtime.conf 00-request-header-gate-map.conf request-header-gate.inc; do
                rm -f "/opt/web/{site_name}/tls-conf/$name.candidate";
              done
        - name: Remove HTTPS gate files introduced by a failed first bind
          ansible.builtin.file:
            path: "/opt/web/{site_name}/tls-conf/{{{{ item.item }}}}"
            state: absent
          loop: "{{{{ prior_https_gate_files.results }}}}"
          when: not item.stat.exists
          no_log: true
        - name: Remove candidate selected TLS container before rollback
          ansible.builtin.command:
            argv: [docker, rm, -f, {site_container}]
          register: rollback_tls_remove
          failed_when: rollback_tls_remove.rc not in [0, 1]
        - name: Find renamed selected TLS Compose containers before rollback
          ansible.builtin.command:
            argv: [docker, ps, -aq, --filter, "label=com.docker.compose.project=web", --filter, "label=com.docker.compose.service={tls_service}"]
          register: rollback_tls_remnants
          changed_when: false
        - name: Remove renamed selected TLS Compose containers before rollback
          ansible.builtin.command:
            argv: [docker, rm, -f, "{{{{ item }}}}"]
          loop: "{{{{ rollback_tls_remnants.stdout_lines }}}}"
          when: item | length > 0
        - name: Restore prior selected TLS container from Compose definitions
          ansible.builtin.command:
            argv: "{{{{ barragan_compose_argv + ['-f', '/opt/web/docker-compose.yml', '-f', '{site_compose}', 'up', '-d', '{tls_service}'] }}}}"
          when: prior_tls_container.rc == 0
        - name: Return prior selected TLS container to stopped state
          ansible.builtin.command:
            argv: [docker, stop, {site_container}]
          when: prior_tls_container.rc == 0 and prior_tls_container.stdout | trim != 'true'
        - name: Wait for restored running TLS container readiness
          ansible.builtin.command:
            argv: [docker, exec, {site_container}, "true"]
          register: restored_tls_ready
          retries: 12
          delay: 5
          until: restored_tls_ready.rc == 0
          when: prior_tls_container.rc == 0 and prior_tls_container.stdout | trim == 'true'
          changed_when: false
        - name: Validate restored running TLS OpenResty configuration
          ansible.builtin.command:
            argv: [docker, exec, {site_container}, openresty, -t]
          when: prior_tls_container.rc == 0 and prior_tls_container.stdout | trim == 'true'
          changed_when: false
        - name: Verify restored TLS binding lineage
          ansible.builtin.command:
            argv: [python3, -c, "import base64;exec(base64.b64decode('{existing_runtime_preflight}').decode())"]
        - name: Inspect restored selected TLS container state
          ansible.builtin.command:
            argv: [docker, inspect, -f, "{{% raw %}}{{{{.State.Running}}}}{{% endraw %}}", {site_container}]
          register: restored_tls_container
          when: prior_tls_container.rc == 0
          changed_when: false
        - name: Require exact prior selected TLS container state
          ansible.builtin.assert:
            that:
              - restored_tls_container.rc == 0
              - restored_tls_container.stdout | trim == prior_tls_container.stdout | trim
          when: prior_tls_container.rc == 0
        - name: Verify TLS container remains absent after failed first bind
          ansible.builtin.command:
            argv: [docker, inspect, {site_container}]
          register: absent_tls_container
          failed_when: absent_tls_container.rc == 0
          changed_when: false
          when: prior_tls_container.rc != 0
        - name: Validate shared front after TLS rollback
          ansible.builtin.command:
            argv: [docker, exec, proxy, openresty, -t]
          changed_when: false
        - name: Reload shared front after verified TLS rollback
          ansible.builtin.command:
            argv: [docker, exec, proxy, openresty, -s, reload]
        - ansible.builtin.fail:
            msg: TLS sibling activation failed after verified restoration of the prior binding runtime.
'''
    (ansible / "inventory.ini").write_text(inventory, encoding="utf-8")
    (ansible / "activate_certificate_binding.yml").write_text(playbook, encoding="utf-8")
    (workspace / "MANIFEST.json").write_text(json.dumps({"certificateId": asset.id, "bindingId": binding.id, "channelId": binding.channel_id, "selectedProxy": asset.target_proxy_id, "privateKeyLeavesProxy": False}, indent=2) + "\n", encoding="utf-8")
    _assert_no_private_key_contents({"inventory": inventory, "playbook": playbook})
    return workspace


def _finish_certificate_binding(
    repo: CertificateRepository,
    jobs: JobRepository,
    binding: StoredCertificateBinding,
    previous_binding: StoredCertificateBinding | None,
    job_id: str,
    workspace: Path,
    command: list[str],
    runner: CommandRunner | None,
) -> None:
    job = jobs.get(job_id)
    if job is None:
        return
    result = _run_command(command, workspace, runner)
    current = repo.get_binding_for_service(binding.engagement_id, binding.service_id)
    owns_state = current is not None and current.last_job_id == job_id
    status = "bound" if result.ok and owns_state else "activation_failed"
    if owns_state and current:
        if result.ok:
            repo.save_binding(replace(current, status=status, validation={"status": "pending", "detail": "Inspector TLS validation is pending."}))
        elif previous_binding is not None:
            repo.save_binding(previous_binding)
        else:
            repo.save_binding(replace(current, status=status, validation={"status": "error", "detail": "Proxy TLS activation failed."}))
    event = JobEvent(len(job.events) + 1, "info" if result.ok and owns_state else "error", f"certificate binding activation {'succeeded' if result.ok and owns_state else 'failed'}", {"commandResult": {"command": result.command, "returncode": result.returncode, "stdout": _sanitize_output(result.stdout), "stderr": _sanitize_output(result.stderr)}, "bindingStatus": status})
    jobs.save(replace(job, status="succeeded" if result.ok and owns_state else "failed", finished_at=_now(), events=job.events + [event]))


def _write_unbinding_workspace(root: Path, binding: StoredCertificateBinding, service: StoredEngagementService, proxy: CertificateCoreHost) -> Path:
    if service.service_type == "web-http-backend":
        return _write_http_backend_unbinding_workspace(root, binding, service, proxy)
    site_name, site_compose, _http_service, tls_service, tls_config, tls_route = _static_web_tls_metadata(service)
    workspace = root / f"{binding.id}-deactivate-{uuid4().hex[:8]}"
    ansible = workspace / "ansible"
    ansible.mkdir(parents=True, exist_ok=True)
    inventory = "\n".join(["# Barragan certificate unbinding; selected proxy only.", "[selected_proxy]", proxy.inventory_line(), ""])
    site_container = f"barragan_{tls_service}"
    tls_observability = f"/opt/web/{site_name}/tls-conf/00-barragan-observability.conf"
    backup_config = f"{tls_config}.barragan-unbind-backup"
    backup_route = f"{tls_route}.barragan-unbind-backup"
    backup_observability = f"{tls_observability}.barragan-unbind-backup"
    expected_live = f"/etc/letsencrypt/live/barragan/{binding.certificate_id}/current"
    existing_runtime_preflight = f'''import pathlib
config=pathlib.Path({tls_config!r})
route=pathlib.Path({tls_route!r})
if not config.is_file() or config.is_symlink() or not route.is_file() or route.is_symlink():
    raise SystemExit('persisted TLS binding runtime is incomplete')
text=config.read_text()
lines=[line.strip() for line in route.read_text().splitlines() if line.strip()]
if lines != [{f"{binding.hostname} {tls_service}:8081;"!r}]:
    raise SystemExit('TLS route does not match the exact bound channel')
if text.count('listen 8081 proxy_protocol ssl;') != 1 or text.count({'ssl_certificate ' + expected_live + '/fullchain.pem;'!r}) != 1 or text.count({'ssl_certificate_key ' + expected_live + '/privkey.pem;'!r}) != 1:
    raise SystemExit('TLS certificate lineage does not match the exact bound certificate')
'''
    existing_runtime_preflight = base64.b64encode(existing_runtime_preflight.encode("utf-8")).decode("ascii")
    playbook = f'''---
- name: Deactivate selected certificate binding
  hosts: selected_proxy
  become: true
  gather_facts: false
  tasks:
{_compose_runtime_tasks()}
    - name: Verify exact Barragan shared-stack ownership
      ansible.builtin.shell:
        cmd: >-
          python3 -c "import json,pathlib,sys; p=pathlib.Path('/opt/web/.barragan-stack.json');
          expected={{'managedBy':'barragan','stackModel':'containerized-openresty-v1'}};
          sys.exit(0 if p.is_file() and not p.is_symlink() and json.loads(p.read_text()) == expected else 1)"
      changed_when: false
    - name: Verify exact bound TLS runtime before mutation
      ansible.builtin.command:
        argv:
          - python3
          - -c
          - "import base64;exec(base64.b64decode('{existing_runtime_preflight}').decode())"
      changed_when: false
    - name: Record prior selected TLS container state
      ansible.builtin.command:
        argv: [docker, inspect, -f, "{{% raw %}}{{{{.State.Running}}}}{{% endraw %}}", {site_container}]
      register: prior_tls_container
      changed_when: false
    - name: Deactivate only the selected TLS sibling transactionally
      block:
        - ansible.builtin.copy:
            src: "{{{{ item.src }}}}"
            dest: "{{{{ item.dest }}}}"
            remote_src: true
            owner: root
            group: redteam
            mode: "0600"
          loop:
            - {{src: {tls_config}, dest: {backup_config}}}
            - {{src: {tls_route}, dest: {backup_route}}}
            - {{src: {tls_observability}, dest: {backup_observability}}}
        - name: Stop only the selected TLS sibling
          ansible.builtin.command:
            argv: "{{{{ barragan_compose_argv + ['-f', '/opt/web/docker-compose.yml', '-f', '{site_compose}', 'rm', '-s', '-f', '{tls_service}'] }}}}"
        - name: Remove a prior selected TLS sibling outside Compose state
          ansible.builtin.command:
            argv: [docker, rm, -f, {site_container}]
          register: unbind_tls_remove
          failed_when: unbind_tls_remove.rc not in [0, 1]
        - name: Remove only the selected TLS sibling configuration and route
          ansible.builtin.file:
            path: "{{{{ item }}}}"
            state: absent
          loop:
            - {tls_config}
            - {tls_observability}
            - {tls_route}
        - ansible.builtin.command:
            argv: [docker, exec, proxy, openresty, -t]
        - ansible.builtin.command:
            argv: [docker, exec, proxy, openresty, -s, reload]
      rescue:
        - ansible.builtin.copy:
            src: "{{{{ item.src }}}}"
            dest: "{{{{ item.dest }}}}"
            remote_src: true
            owner: root
            group: redteam
            mode: "0644"
          loop:
            - {{src: {backup_config}, dest: {tls_config}}}
            - {{src: {backup_route}, dest: {tls_route}}}
            - {{src: {backup_observability}, dest: {tls_observability}}}
        - name: Find renamed selected TLS Compose containers before unbind rollback
          ansible.builtin.command:
            argv: [docker, ps, -aq, --filter, "label=com.docker.compose.project=web", --filter, "label=com.docker.compose.service={tls_service}"]
          register: unbind_rollback_tls_remnants
          changed_when: false
        - name: Remove renamed selected TLS Compose containers before unbind rollback
          ansible.builtin.command:
            argv: [docker, rm, -f, "{{{{ item }}}}"]
          loop: "{{{{ unbind_rollback_tls_remnants.stdout_lines }}}}"
          when: item | length > 0
        - name: Restore prior selected TLS container from Compose definitions
          ansible.builtin.command:
            argv: "{{{{ barragan_compose_argv + ['-f', '/opt/web/docker-compose.yml', '-f', '{site_compose}', 'up', '-d', '{tls_service}'] }}}}"
        - name: Return prior selected TLS container to stopped state
          ansible.builtin.command:
            argv: [docker, stop, {site_container}]
          when: prior_tls_container.stdout | trim != 'true'
        - name: Wait for restored running TLS container readiness
          ansible.builtin.command:
            argv: [docker, exec, {site_container}, "true"]
          register: unbind_restored_tls_ready
          retries: 12
          delay: 5
          until: unbind_restored_tls_ready.rc == 0
          when: prior_tls_container.stdout | trim == 'true'
          changed_when: false
        - name: Validate restored running TLS OpenResty configuration
          ansible.builtin.command:
            argv: [docker, exec, {site_container}, openresty, -t]
          when: prior_tls_container.stdout | trim == 'true'
          changed_when: false
        - name: Verify restored bound TLS runtime
          ansible.builtin.command:
            argv: [python3, -c, "import base64;exec(base64.b64decode('{existing_runtime_preflight}').decode())"]
        - name: Inspect restored selected TLS container state
          ansible.builtin.command:
            argv: [docker, inspect, -f, "{{% raw %}}{{{{.State.Running}}}}{{% endraw %}}", {site_container}]
          register: restored_tls_container
          changed_when: false
        - name: Require exact prior selected TLS container state
          ansible.builtin.assert:
            that:
              - restored_tls_container.rc == 0
              - restored_tls_container.stdout | trim == prior_tls_container.stdout | trim
        - name: Validate shared front after TLS rollback
          ansible.builtin.command:
            argv: [docker, exec, proxy, openresty, -t]
          changed_when: false
        - name: Reload shared front after verified TLS rollback
          ansible.builtin.command:
            argv: [docker, exec, proxy, openresty, -s, reload]
        - ansible.builtin.fail:
            msg: TLS sibling deactivation failed after verified restoration of the prior binding runtime.
      always:
        - ansible.builtin.file:
            path: "{{{{ item }}}}"
            state: absent
          loop: [{backup_config}, {backup_route}, {backup_observability}]
'''
    (ansible / "inventory.ini").write_text(inventory, encoding="utf-8")
    (ansible / "deactivate_certificate_binding.yml").write_text(playbook, encoding="utf-8")
    (workspace / "MANIFEST.json").write_text(json.dumps({"bindingId": binding.id, "channelId": binding.channel_id, "tlsMode": "unbound"}, indent=2) + "\n", encoding="utf-8")
    return workspace


def _static_web_tls_metadata(service: StoredEngagementService) -> tuple[str, str, str, str, str, str]:
    config = service.config
    site_name = str(config.get("siteName") or "")
    site_compose = str(config.get("siteComposePath") or "")
    http_service = str(config.get("siteService") or "")
    tls_service = str(config.get("tlsSiteService") or "")
    tls_config = str(config.get("tlsSiteConfigPath") or "")
    tls_route = str(config.get("tlsRoutePath") or "")
    valid = (
        service.service_type == "web-static"
        and str(config.get("stackModel") or "") == "containerized-openresty-v1"
        and str(config.get("composePath") or "") == "/opt/web/docker-compose.yml"
        and str(config.get("stackOwnershipPath") or "") == "/opt/web/.barragan-stack.json"
        and bool(re.fullmatch(r"[a-z0-9][a-z0-9-]*", site_name))
        and site_compose == f"/opt/web/sites/{site_name}.compose.yml"
        and bool(re.fullmatch(r"[a-z0-9_]+", http_service))
        and tls_service == f"{http_service}_tls"
        and tls_config == f"/opt/web/{site_name}/tls-conf/default.conf"
        and tls_route == f"/opt/web/tls/{site_name}.map"
    )
    if not valid:
        raise CertificateManagerValidationError(["service TLS sibling metadata is incomplete or invalid"])
    return site_name, site_compose, http_service, tls_service, tls_config, tls_route


def _finish_certificate_unbinding(repo: CertificateRepository, jobs: JobRepository, binding: StoredCertificateBinding, job_id: str, workspace: Path, command: list[str], runner: CommandRunner | None) -> None:
    job = jobs.get(job_id)
    if job is None:
        return
    result = _run_command(command, workspace, runner)
    current = repo.get_binding_for_service(binding.engagement_id, binding.service_id)
    owns_state = current is not None and current.last_job_id == job_id
    if result.ok and owns_state:
        repo.delete_binding(binding.engagement_id, binding.id)
    elif owns_state and current:
        repo.save_binding(replace(current, status="deactivation_failed", validation={"status": "error", "detail": "Proxy TLS deactivation failed; the prior binding remains recorded."}))
    succeeded = result.ok and owns_state
    event = JobEvent(len(job.events) + 1, "info" if succeeded else "error", f"certificate unbinding {'succeeded' if succeeded else 'failed'}", {"commandResult": {"command": result.command, "returncode": result.returncode, "stdout": _sanitize_output(result.stdout), "stderr": _sanitize_output(result.stderr)}, "bindingRemoved": succeeded})
    jobs.save(replace(job, status="succeeded" if succeeded else "failed", finished_at=_now(), events=job.events + [event]))


def _proxy_stack(asset: StoredCertificateAsset, repository: EngagementServiceRepository) -> dict[str, str]:
    aliases = {asset.target_proxy_id, asset.target_proxy_id.split("-")[0]}
    services = [service for service in repository.list_for_engagement(asset.engagement_id) if {service.proxy_id, service.proxy_id.split("-")[0]} & aliases]
    service = next((row for row in services if str(row.config.get("stackModel") or "") == "containerized-openresty-v1"), None)
    if service is None:
        raise CertificateManagerValidationError(["target proxy does not have a Barragan-owned containerized OpenResty stack"])
    config = service.config
    if str(config.get("composePath") or "") != "/opt/web/docker-compose.yml" or str(config.get("stackOwnershipPath") or "") != "/opt/web/.barragan-stack.json":
        raise CertificateManagerValidationError(["target proxy stack metadata is invalid"])
    return {"composePath": "/opt/web/docker-compose.yml", "ownershipPath": "/opt/web/.barragan-stack.json", "frontProxyService": str(config.get("frontProxyService") or "reverse-proxy")}


def _public_certificate_metadata(path: Path, expected_identifiers: tuple[str, ...]) -> dict[str, Any] | None:
    try:
        certificate = x509.load_pem_x509_certificate(path.read_bytes())
        identifiers = [name.lower() for name in certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)]
    except (OSError, ValueError, x509.ExtensionNotFound):
        return None
    if set(identifiers) != set(expected_identifiers):
        return None
    not_before = certificate.not_valid_before_utc.isoformat()
    not_after = certificate.not_valid_after_utc.isoformat()
    return {"issuer": certificate.issuer.rfc4514_string(), "subject": certificate.subject.rfc4514_string(), "serialNumber": format(certificate.serial_number, "x"), "fingerprintSha256": certificate.fingerprint(hashes.SHA256()).hex(), "identifiers": identifiers, "notBefore": not_before, "issuedAt": not_before, "expiresAt": not_after}


def _append_progress(jobs: JobRepository, job: StoredJobRun, message: str, result: DisposableCommandResult) -> StoredJobRun:
    event = JobEvent(len(job.events) + 1, "info" if result.ok else "error", message, {"commandResult": {"command": result.command, "cwd": result.cwd, "returncode": result.returncode, "ok": result.ok, "stdout": _sanitize_output(result.stdout), "stderr": _sanitize_output(result.stderr)}})
    saved = replace(job, events=job.events + [event])
    _assert_no_private_key_contents(saved.to_detail().to_dict())
    return jobs.save(saved)


def _restore_binding_health(repo: CertificateRepository, asset: StoredCertificateAsset) -> None:
    for binding in repo.list_bindings(asset.engagement_id, asset.id):
        status = "expected_external" if asset.source == "external" else "bound"
        repo.save_binding(replace(binding, status=status, validation={"status": "pending", "detail": "Certificate version changed; Inspector TLS validation is pending."}, last_job_id=asset.last_job_id))


def _remove_public_workspace_files(workspace: Path) -> None:
    for name in ("csr.pem", "cert.pem", "chain.pem", "fullchain.pem"):
        try:
            (workspace / name).unlink(missing_ok=True)
        except OSError:
            pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
