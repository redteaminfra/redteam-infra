# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Mapping
from uuid import uuid4

from app.core.command_environment import barragan_subprocess_env
from app.core.runtime import start_runtime_task
from app.domain import JobEvent
from app.integrations.ansible_disposable_validation import resolve_ansible_playbook
from app.integrations.oci_disposable_terraform import DisposableCommandResult
from app.services.core_ssh import deployment_known_hosts_file, ensure_known_hosts_file, latest_core_connection_details
from app.services.engagement_operations import get_operations_overview, update_operations_overview
from app.services.engagements import get_engagement
from app.services.inbound_channel_apply import InboundChannelApplyValidationError, start_inbound_channel_apply
from app.services.inbound_channel_workflow import InboundChannelWorkflowValidationError, derive_inbound_channel
from app.services.shared_proxy_stack import (
    SharedProxyStackMutationConflict,
    reserve_shared_proxy_stack_mutation,
)
from app.storage.domain_repository import DomainRepository, SqlAlchemyDomainRepository, StoredDomainAsset
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.service_repository import EngagementServiceRepository, SqlAlchemyEngagementServiceRepository

CERTIFICATE_ISSUE_ACTION = "inbound_channel_certificate_issue"
CERTIFICATE_RENEW_ACTION = "inbound_channel_certificate_renew"
CERTIFICATE_REVOKE_ACTION = "inbound_channel_certificate_revoke"
CERTIFICATE_CHALLENGE_CHANNEL_ACTION = "inbound_channel_certificate_challenge_channel"
LETSENCRYPT_CERT_TYPE = "letsencrypt"
SELF_SIGNED_CERT_TYPE = "self-signed"
SUPPORTED_CERT_TYPES = {LETSENCRYPT_CERT_TYPE, SELF_SIGNED_CERT_TYPE}
SUPPORTED_ACME_ENVIRONMENTS = {"staging", "production"}
DNS01_CHALLENGE_TYPE = "dns-01"
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DOMAIN_PATTERN = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)
HTTP01_RELAY_PORTS = range(8000, 8081)
DEFAULT_WORKSPACE_ROOT = Path("/tmp/barragan-inbound-certificate")
DEFAULT_KNOWN_HOSTS_ROOT = Path("/tmp/barragan-inbound-certificate-known-hosts")
DEFAULT_CORE_SSH_PRIVATE_KEY = "/var/lib/barragan/.ssh/barragan_testing"
CORE_SSH_KEY_ENV = "BARRAGAN_VALIDATION_SSH_PRIVATE_KEY"
EVIDENCE_PREFIX = "BARRAGAN_CERTIFICATE_EVIDENCE="
REVOCATION_EVIDENCE_PREFIX = "BARRAGAN_CERTIFICATE_REVOCATION_EVIDENCE="
MAX_RESULT_CHARS = 4000
COMMAND_TIMEOUT_SECONDS = 900
SECRET_OUTPUT_REDACTIONS = (
    (re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.IGNORECASE | re.DOTALL), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*", re.IGNORECASE | re.DOTALL), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-api-token)\s*:\s*).+$"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(bearer|basic)\s+\S+"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)\b(api[_ -]?key|private[_ -]?key|password|passwd|token|secret)\s*[:=]\s*([^\s&;]+)"), r"\1=[REDACTED]"),
)

CommandRunner = Callable[[list[str], Path | None], subprocess.CompletedProcess[str]]
BackgroundRunner = Callable[[Callable[[], None]], None]


@dataclass(frozen=True)
class CertificateCoreHost:
    name: str
    ansible_host: str
    ansible_user: str
    ssh_private_key_file: str
    proxy_jump: str
    known_hosts_file: str

    def inventory_line(self) -> str:
        proxy_command = (
            f"ssh -i {self.ssh_private_key_file} -o StrictHostKeyChecking=accept-new "
            f"-o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10 "
            f"-o UserKnownHostsFile={self.known_hosts_file} -W %h:%p {self.proxy_jump}"
        )
        common = (
            f"-o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -o BatchMode=yes "
            f"-o ConnectTimeout=10 -o UserKnownHostsFile={self.known_hosts_file} "
            f"-o ProxyCommand='{proxy_command}'"
        )
        return (
            f"{self.name} ansible_host={self.ansible_host} ansible_user={self.ansible_user} "
            f"ansible_ssh_private_key_file={self.ssh_private_key_file} "
            f"ansible_ssh_common_args={json.dumps(common)}"
        )


class InboundChannelCertificateValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("inbound channel certificate validation failed")
        self.errors = errors


def certificate_workspace(
    engagement_id: str,
    channel_id: str,
    *,
    domain_repository: DomainRepository | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    overview = get_operations_overview(engagement_id)
    channel = _channel_by_id(overview, channel_id)
    if channel is None:
        raise InboundChannelCertificateValidationError([f"inbound channel {channel_id} was not found"])
    prerequisites = _certificate_prerequisites(engagement_id, channel, overview, domain_repository=domain_repository)
    certificate = _certificate_metadata(channel)
    return {"channel": channel, "certificate": certificate, "prerequisites": prerequisites}


def auto_configure_http01_channel(
    engagement_id: str,
    channel_id: str,
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    repo = repository or SqlAlchemyJobRepository()
    parent = _required_https_channel(get_operations_overview(engagement_id), channel_id)
    job = _instant_job(
        repo,
        CERTIFICATE_CHALLENGE_CHANNEL_ACTION,
        engagement_id,
        requested_by,
        "HTTP-01 support channel is not required for DNS-01",
        {"parentChannelId": channel_id, "challengeType": DNS01_CHALLENGE_TYPE, "mutation": False},
    )
    return {"job": job.to_detail().to_dict(), "channel": parent, "status": "not_required", "challengeType": DNS01_CHALLENGE_TYPE}


def issue_certificate(
    engagement_id: str,
    channel_id: str,
    body: dict[str, Any],
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    domain_repository: DomainRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
    runner: CommandRunner | None = None,
    background_runner: BackgroundRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any] | None:
    return _certificate_job(
        engagement_id,
        channel_id,
        body,
        action=CERTIFICATE_ISSUE_ACTION,
        requested_by=requested_by,
        repository=repository,
        domain_repository=domain_repository,
        service_repository=service_repository,
        runner=runner,
        background_runner=background_runner,
        env=env,
        workspace_root=workspace_root,
    )


def renew_certificate(
    engagement_id: str,
    channel_id: str,
    body: dict[str, Any],
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    domain_repository: DomainRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
    runner: CommandRunner | None = None,
    background_runner: BackgroundRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    repo = repository or SqlAlchemyJobRepository()
    overview = get_operations_overview(engagement_id)
    channel = _required_https_channel(overview, channel_id)
    certificate = _certificate_metadata(channel)
    _reject_active_certificate_job(certificate)
    domain = _validated_managed_letsencrypt_certificate(channel, certificate, require_managed=True)
    prerequisites = _certificate_prerequisites(engagement_id, channel, overview, domain_repository=domain_repository)
    if not prerequisites["ready"]:
        raise InboundChannelCertificateValidationError(
            [check["detail"] for check in prerequisites["checks"] if check["status"] != "ready"]
        )
    environment = _recorded_acme_environment(certificate)
    if environment == "production" and requested_by != "certificate-scheduler":
        expected = _production_confirmation(channel_id, domain)
        if str(body.get("productionConfirmation") or "") != expected:
            raise InboundChannelCertificateValidationError([f'productionConfirmation must equal "{expected}"'])
    email = _validated_email(certificate.get("acmeEmail"))
    return _start_dns01_issue(
        engagement_id,
        channel,
        domain,
        email,
        environment,
        prerequisites,
        requested_by=requested_by,
        repository=repo,
        service_repository=service_repository,
        runner=runner,
        background_runner=background_runner,
        env=env,
        workspace_root=workspace_root,
        action=CERTIFICATE_RENEW_ACTION,
    )


def revoke_certificate(
    engagement_id: str,
    channel_id: str,
    body: dict[str, Any],
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
    runner: CommandRunner | None = None,
    background_runner: BackgroundRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    repo = repository or SqlAlchemyJobRepository()
    overview = get_operations_overview(engagement_id)
    channel = _required_https_channel(overview, channel_id)
    certificate = _certificate_metadata(channel)
    _reject_active_certificate_job(certificate)
    domain = _validated_managed_letsencrypt_certificate(channel, certificate, require_managed=True)
    environment = _recorded_acme_environment(certificate)
    result = _start_dns01_revoke(
        engagement_id,
        channel,
        certificate,
        domain,
        environment,
        requested_by=requested_by,
        repository=repo,
        service_repository=service_repository,
        runner=runner,
        background_runner=background_runner,
        env=env,
        workspace_root=workspace_root,
        reason=str(body.get("reason") or "operator requested revocation"),
    )
    return result


def _start_dns01_revoke(
    engagement_id: str,
    channel: dict[str, Any],
    certificate: dict[str, Any],
    domain: str,
    environment: str,
    *,
    requested_by: str,
    repository: JobRepository,
    service_repository: EngagementServiceRepository | None,
    runner: CommandRunner | None,
    background_runner: BackgroundRunner | None,
    env: Mapping[str, str] | None,
    workspace_root: Path | None,
    reason: str,
) -> dict[str, Any]:
    stack = _managed_proxy_stack(
        engagement_id,
        channel,
        service_repository or SqlAlchemyEngagementServiceRepository(),
    )
    resolution = resolve_ansible_playbook(env=env)
    if not resolution.ok:
        raise InboundChannelCertificateValidationError([resolution.error or "Could not resolve ansible-playbook executable"])
    proxy = _certificate_proxy_host(repository, engagement_id, str(channel.get("proxy") or ""))
    workspace = _write_dns01_revoke_workspace(
        workspace_root or DEFAULT_WORKSPACE_ROOT,
        engagement_id,
        str(channel["channelId"]),
        proxy,
        domain,
        stack,
    )
    ensure_known_hosts_file(proxy.known_hosts_file)
    ansible = resolution.command or "ansible-playbook"
    fetch_command = [ansible, "-i", "ansible/inventory.ini", "ansible/fetch_public_certificate.yml"]
    revoke_command = _dns01_certbot_revoke_command(workspace, domain, environment, env=env)
    retire_command = [ansible, "-i", "ansible/inventory.ini", "ansible/retire_proxy_certificate.yml"]
    timestamp = _now()
    pending = {
        **certificate,
        "status": "Revoking",
        "lastAttemptAt": timestamp,
        "detail": "Barragan is revoking the public certificate and retiring its owned proxy material.",
    }
    candidate_job = StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=CERTIFICATE_REVOKE_ACTION,
        status="running",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by=requested_by,
        input={"engagementId": engagement_id, "channelId": channel["channelId"], "proxyId": str(channel.get("proxy") or ""), "certificateType": LETSENCRYPT_CERT_TYPE, "challengeType": DNS01_CHALLENGE_TYPE, "acmeEnvironment": environment, "mutation": True},
        artifact_refs=["ansible/inventory.ini", "ansible/fetch_public_certificate.yml", "ansible/retire_proxy_certificate.yml", "MANIFEST.json"],
        created_at=timestamp,
        started_at=timestamp,
        finished_at=None,
        events=[JobEvent(1, "info", "DNS-01 certificate revocation workspace rendered", {
            "channelId": channel["channelId"],
            "workspaceDir": str(workspace),
            "inventoryTargets": ["selected_proxy"],
            "reason": reason,
            "commands": {"fetchPublicCertificate": fetch_command, "revoke": _safe_command_display(revoke_command), "retireProxyCertificate": retire_command},
            "opsecBoundary": {"throughHomebase": True, "selectedProxyOnly": True, "privateKeyLeavesProxy": False, "namecheapCredentialOnProxy": False, "directEdgeProbeFromAppHost": False},
        })],
    )
    try:
        job = reserve_shared_proxy_stack_mutation(
            repository,
            candidate_job,
            engagement_id=engagement_id,
            proxy_id=str(channel.get("proxy") or ""),
        )
    except SharedProxyStackMutationConflict as exc:
        shutil.rmtree(workspace, ignore_errors=True)
        raise InboundChannelCertificateValidationError(
            [f"Shared proxy web-stack mutation already running on {channel.get('proxy')}: {exc.job.id} ({exc.job.action})"]
        ) from exc
    pending["lastJobId"] = job.id
    _replace_inbound_channel(engagement_id, {**channel, "certificate": pending})
    (background_runner or _start_background_task)(lambda: _finish_dns01_revoke(
        repository, engagement_id, channel, pending, certificate, job.id,
        fetch_command, revoke_command, retire_command, workspace, runner,
    ))
    return {"job": job.to_detail().to_dict(), "certificate": pending, "status": "Revoking"}


def _finish_dns01_revoke(
    repository: JobRepository,
    engagement_id: str,
    channel: dict[str, Any],
    pending: dict[str, Any],
    previous: dict[str, Any],
    job_id: str,
    fetch_command: list[str],
    revoke_command: list[str],
    retire_command: list[str],
    workspace: Path,
    runner: CommandRunner | None,
) -> None:
    job = repository.get(job_id)
    if job is None:
        return
    fetched = _run_command(fetch_command, workspace, runner)
    job = _save_certificate_progress(repository, job, "public certificate fetched for revocation", fetched, level="info" if fetched.ok else "error")
    revoked = DisposableCommandResult([], str(workspace), 1, "", "public certificate fetch failed", False)
    retired = DisposableCommandResult([], str(workspace), 1, "", "certificate was not revoked", False)
    if fetched.ok and (workspace / "cert.pem").is_file():
        revoked = _run_command(revoke_command, workspace, runner)
        job = _save_certificate_progress(repository, job, "ACME certificate revocation completed" if revoked.ok else "ACME certificate revocation failed", revoked, level="info" if revoked.ok else "error")
    if revoked.ok:
        retired = _run_command(retire_command, workspace, runner)
        job = _save_certificate_progress(repository, job, "proxy certificate material retired" if retired.ok else "proxy certificate retirement failed", retired, level="info" if retired.ok else "error")
    current = _channel_by_id(get_operations_overview(engagement_id), str(channel.get("channelId") or ""))
    current_certificate = _certificate_metadata(current or {})
    owns_state = current is not None and str(current_certificate.get("lastJobId") or "") == job_id
    succeeded = bool(fetched.ok and revoked.ok and retired.ok and owns_state)
    if owns_state and revoked.ok:
        certificate = {**pending, "status": "Revoked", "revokedAt": _now(), "lastAttemptStatus": "Revoked" if retired.ok else "Retirement Failed", "activationStatus": "Retired" if retired.ok else "Retirement Failed", "detail": "Certificate revoked and owned proxy material retired." if retired.ok else "Certificate revoked, but owned proxy material retirement requires operator attention."}
        if retired.ok:
            certificate.pop("paths", None)
    elif owns_state:
        certificate = {**previous, "lastAttemptStatus": "Revoke Failed", "lastAttemptAt": _now(), "detail": "Certificate revocation failed; the prior certificate remains active."}
    else:
        certificate = previous
    if current is not None and owns_state:
        _replace_inbound_channel(engagement_id, {**current, "certificate": certificate})
    final = JobEvent(len(job.events) + 1, "info" if succeeded else "error", f"DNS-01 certificate revocation {'succeeded' if succeeded else 'failed'}", {
        "channelId": channel["channelId"],
        "certificate": _public_certificate(certificate),
        "phases": {"fetchPublicCertificate": fetched.ok, "acmeRevoke": revoked.ok, "retireProxyCertificate": retired.ok},
        **({"error": "certificate job no longer owns channel state"} if not owns_state else {}),
    })
    saved = replace(job, status="succeeded" if succeeded else "failed", finished_at=_now(), events=job.events + [final])
    _assert_no_private_key_contents(saved.to_detail().to_dict())
    repository.save(saved)
    _remove_dns01_workspace_secrets(workspace)


def _certificate_job(
    engagement_id: str,
    channel_id: str,
    body: dict[str, Any],
    *,
    action: str,
    requested_by: str,
    repository: JobRepository | None,
    domain_repository: DomainRepository | None,
    service_repository: EngagementServiceRepository | None = None,
    runner: CommandRunner | None = None,
    background_runner: BackgroundRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    repo = repository or SqlAlchemyJobRepository()
    overview = get_operations_overview(engagement_id)
    channel = _required_https_channel(overview, channel_id)
    active_certificate = _certificate_metadata(channel)
    if str(active_certificate.get("status") or "").strip().lower() in {"issuing", "renewing", "revoking"}:
        raise InboundChannelCertificateValidationError([
            f"certificate job {active_certificate.get('lastJobId') or 'unknown'} is already running for this inbound channel"
        ])
    certificate_type = str(body.get("certificateType") or body.get("type") or LETSENCRYPT_CERT_TYPE).strip().lower()
    if certificate_type not in SUPPORTED_CERT_TYPES:
        raise InboundChannelCertificateValidationError(["certificateType must be letsencrypt or self-signed"])
    domain = _validated_domain(channel)
    prerequisites = _certificate_prerequisites(engagement_id, channel, overview, domain_repository=domain_repository)
    if certificate_type == LETSENCRYPT_CERT_TYPE:
        email = _validated_email(body.get("acmeEmail"))
        environment = str(body.get("acmeEnvironment") or "staging").strip().lower()
        if environment not in SUPPORTED_ACME_ENVIRONMENTS:
            raise InboundChannelCertificateValidationError(["acmeEnvironment must be staging or production"])
        if environment == "production":
            expected = _production_confirmation(channel_id, domain)
            if str(body.get("productionConfirmation") or "") != expected:
                raise InboundChannelCertificateValidationError([f'productionConfirmation must equal "{expected}"'])
        if not prerequisites["ready"]:
            raise InboundChannelCertificateValidationError([check["detail"] for check in prerequisites["checks"] if check["status"] != "ready"])
        if action == CERTIFICATE_ISSUE_ACTION:
            return _start_dns01_issue(
                engagement_id,
                channel,
                domain,
                email,
                environment,
                prerequisites,
                requested_by=requested_by,
                repository=repo,
                service_repository=service_repository,
                runner=runner,
                background_runner=background_runner,
                env=env,
                workspace_root=workspace_root,
            )
        certificate = _letsencrypt_certificate(domain, email, environment, prerequisites, action)
        command = _certbot_command(domain, email, environment, action, f"/opt/web/{domain}/html")
    else:
        certificate = _self_signed_certificate(domain, prerequisites, action)
        command = _self_signed_command(domain, certificate)
    job = _certificate_lifecycle_job(
        repo,
        action=action,
        engagement_id=engagement_id,
        channel=channel,
        certificate=certificate,
        requested_by=requested_by,
        event_message="inbound channel certificate issue rendered" if action == CERTIFICATE_ISSUE_ACTION else "inbound channel certificate renew rendered",
        command=command,
        extra={"prerequisites": prerequisites},
    )
    certificate["lastJobId"] = job.id
    updated = {**channel, "certificate": certificate}
    _replace_inbound_channel(engagement_id, updated)
    saved = repo.save(replace(job, events=_events_with_channels(job.events, engagement_id, updated)))
    return {"job": saved.to_detail().to_dict(), "certificate": certificate, "prerequisites": prerequisites, "status": certificate["status"]}


def _certificate_prerequisites(
    engagement_id: str,
    channel: dict[str, Any],
    overview: dict[str, Any],
    *,
    domain_repository: DomainRepository | None = None,
) -> dict[str, Any]:
    now = _now()
    checks: list[dict[str, str]] = []
    is_https = _is_https_channel(channel)
    checks.append(_check("https-channel", "HTTPS inbound channel", is_https, "This action is available only for HTTPS/OpenResty inbound channels."))
    domain = str(channel.get("domain") or "").strip().lower()
    valid_domain = bool(DOMAIN_PATTERN.match(domain))
    checks.append(_check("domain-present", "Channel domain", valid_domain, "Add a real domain name to this HTTPS inbound channel."))
    asset, assignment_ready = _assigned_domain_asset(engagement_id, domain, domain_repository=domain_repository)
    checks.append(_check("domain-assigned", "Engagement domain assignment", assignment_ready, "Assign this domain or its parent domain to the engagement."))
    edge_ip = _edge_public_ip(channel, overview)
    dns01_ready = bool(asset and asset.registrar == "namecheap")
    checks.append(_check("dns01-provider", "DNS-01 provider", dns01_ready, "DNS-01 requires an actively assigned Namecheap domain."))
    ready = all(check["status"] == "ready" for check in checks)
    return {
        "status": "ready" if ready else "blocked",
        "ready": ready,
        "summary": "Ready to request a Let's Encrypt certificate with DNS-01." if ready else "Complete the DNS-01 prerequisites before requesting a Let's Encrypt certificate.",
        "checkedAt": now,
        "challengeType": DNS01_CHALLENGE_TYPE,
        "edgePublicIp": edge_ip,
        "domainAssetId": asset.id if asset else "",
        "dnsZone": asset.domain_name if asset else "",
        "challengeChannelId": "",
        "checks": checks,
    }


def _check(check_id: str, label: str, ok: bool, detail: str) -> dict[str, str]:
    return {
        "id": check_id,
        "label": label,
        "status": "ready" if ok else "blocked",
        "detail": "Ready." if ok else detail,
    }


def _letsencrypt_certificate(domain: str, email: str, environment: str, prerequisites: dict[str, Any], action: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return {
        "type": LETSENCRYPT_CERT_TYPE,
        "status": "Renewed" if action == CERTIFICATE_RENEW_ACTION else "Issued",
        "domain": domain,
        "acmeEmail": email,
        "acmeEnvironment": environment,
        "challengeType": DNS01_CHALLENGE_TYPE,
        "issuedAt": now.isoformat(),
        "expiresAt": (now + timedelta(days=90)).isoformat(),
        "challengeChannelId": str(prerequisites.get("challengeChannelId") or ""),
        "detail": "Let's Encrypt certificate workflow rendered for operator review.",
        "paths": {
            "liveDir": f"/etc/letsencrypt/live/{domain}",
            "fullchain": f"/etc/letsencrypt/live/{domain}/fullchain.pem",
            "privkey": f"/etc/letsencrypt/live/{domain}/privkey.pem",
        },
        "prerequisites": _compact_prerequisites_for_certificate(prerequisites),
    }


def _self_signed_certificate(domain: str, prerequisites: dict[str, Any], action: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return {
        "type": SELF_SIGNED_CERT_TYPE,
        "status": "Renewed" if action == CERTIFICATE_RENEW_ACTION else "Issued",
        "domain": domain,
        "issuedAt": now.isoformat(),
        "expiresAt": (now + timedelta(days=365)).isoformat(),
        "detail": "Self-signed certificate workflow rendered with a domain-only subject and SAN.",
        "paths": {
            "liveDir": f"/etc/barragan/certs/{domain}",
            "fullchain": f"/etc/barragan/certs/{domain}/fullchain.pem",
            "privkey": f"/etc/barragan/certs/{domain}/privkey.pem",
        },
        "prerequisites": _compact_prerequisites_for_certificate(prerequisites),
    }


def _compact_prerequisites_for_certificate(prerequisites: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": str(prerequisites.get("status") or ""),
        "summary": str(prerequisites.get("summary") or ""),
        "checkedAt": str(prerequisites.get("checkedAt") or ""),
        "checks": [
            {key: str(check.get(key) or "") for key in ("id", "label", "status", "detail")}
            for check in prerequisites.get("checks", [])
            if isinstance(check, dict)
        ],
    }


def _certbot_command(domain: str, email: str, environment: str, action: str, webroot: str) -> list[str]:
    command = [
        "certbot",
        "certonly",
        "--webroot",
        "--webroot-path",
        webroot,
        "-d",
        domain,
        "--cert-name",
        domain,
        "--email",
        email,
        "--agree-tos",
        "--no-eff-email",
        "--non-interactive",
        "--force-renewal" if action == CERTIFICATE_RENEW_ACTION or environment == "production" else "--keep-until-expiring",
    ]
    if environment == "staging":
        command.append("--test-cert")
    return command


def _start_dns01_issue(
    engagement_id: str,
    channel: dict[str, Any],
    domain: str,
    email: str,
    environment: str,
    prerequisites: dict[str, Any],
    *,
    requested_by: str,
    repository: JobRepository,
    service_repository: EngagementServiceRepository | None,
    runner: CommandRunner | None,
    background_runner: BackgroundRunner | None,
    env: Mapping[str, str] | None,
    workspace_root: Path | None,
    action: str = CERTIFICATE_ISSUE_ACTION,
) -> dict[str, Any]:
    stack = _managed_proxy_stack(
        engagement_id,
        channel,
        service_repository or SqlAlchemyEngagementServiceRepository(),
    )
    resolution = resolve_ansible_playbook(env=env)
    if not resolution.ok:
        raise InboundChannelCertificateValidationError([resolution.error or "Could not resolve ansible-playbook executable"])
    proxy = _certificate_proxy_host(repository, engagement_id, str(channel.get("proxy") or ""))
    workspace_dir = _write_dns01_workspace(
        workspace_root or DEFAULT_WORKSPACE_ROOT,
        engagement_id,
        str(channel["channelId"]),
        proxy,
        domain,
        email,
        environment,
        stack,
    )
    ensure_known_hosts_file(proxy.known_hosts_file)
    ansible = resolution.command or "ansible-playbook"
    prepare_command = [ansible, "-i", "ansible/inventory.ini", "ansible/prepare_dns01_certificate.yml"]
    deploy_command = [ansible, "-i", "ansible/inventory.ini", "ansible/deploy_dns01_certificate.yml"]
    certbot_command = _dns01_certbot_command(workspace_dir, engagement_id, domain, email, environment, env=env)
    timestamp = _now()
    status = "Renewing" if action == CERTIFICATE_RENEW_ACTION else "Issuing"
    pending_certificate = {
        "type": LETSENCRYPT_CERT_TYPE,
        "status": status,
        "domain": domain,
        "acmeEmail": email,
        "acmeEnvironment": environment,
        "challengeType": DNS01_CHALLENGE_TYPE,
        "managedBy": "barragan",
        "storageModel": "proxy-docker-volume",
        "detail": "DNS-01 certificate issuance is running under Barragan orchestration.",
        "prerequisites": _compact_prerequisites_for_certificate(prerequisites),
    }
    candidate_job = StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=action,
            status="running",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={
                "engagementId": engagement_id,
                "channelId": channel["channelId"],
                "proxyId": str(channel.get("proxy") or ""),
                "certificateType": LETSENCRYPT_CERT_TYPE,
                "challengeType": DNS01_CHALLENGE_TYPE,
                "acmeEnvironment": environment,
                "mutation": True,
            },
            artifact_refs=[
                "ansible/inventory.ini",
                "ansible/prepare_dns01_certificate.yml",
                "ansible/deploy_dns01_certificate.yml",
                "hooks/dns01-auth.sh",
                "hooks/dns01-cleanup.sh",
                "MANIFEST.json",
            ],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=None,
            events=[
                JobEvent(
                    1,
                    "info",
                    "DNS-01 certificate workspace rendered",
                    {
                        "channelId": channel["channelId"],
                        "workspaceDir": str(workspace_dir),
                        "challengeType": DNS01_CHALLENGE_TYPE,
                        "dnsZone": prerequisites.get("dnsZone"),
                        "inventoryTargets": ["selected_proxy"],
                        "proxyStack": stack,
                        "commands": {
                            "prepareCsr": prepare_command,
                            "certbot": _safe_command_display(certbot_command),
                            "deployCertificate": deploy_command,
                        },
                        "opsecBoundary": {
                            "throughHomebase": True,
                            "selectedProxyOnly": True,
                            "namecheapCredentialOnProxy": False,
                            "privateKeyLeavesProxy": False,
                            "directEdgeProbeFromAppHost": False,
                        },
                    },
                )
            ],
        )
    try:
        job = reserve_shared_proxy_stack_mutation(
            repository,
            candidate_job,
            engagement_id=engagement_id,
            proxy_id=str(channel.get("proxy") or ""),
        )
    except SharedProxyStackMutationConflict as exc:
        shutil.rmtree(workspace_dir, ignore_errors=True)
        raise InboundChannelCertificateValidationError(
            [f"Shared proxy web-stack mutation already running on {channel.get('proxy')}: {exc.job.id} ({exc.job.action})"]
        ) from exc
    pending_certificate["lastJobId"] = job.id
    previous_certificate = _certificate_metadata(channel)
    _replace_inbound_channel(engagement_id, {**channel, "certificate": pending_certificate})
    (background_runner or _start_background_task)(
        lambda: _finish_dns01_issue(
            repository,
            engagement_id,
            channel,
            pending_certificate,
            previous_certificate,
            job.id,
            prepare_command,
            certbot_command,
            deploy_command,
            workspace_dir,
            runner,
            action,
        )
    )
    return {"job": job.to_detail().to_dict(), "certificate": pending_certificate, "prerequisites": prerequisites, "status": status}


def _finish_dns01_issue(
    repository: JobRepository,
    engagement_id: str,
    channel: dict[str, Any],
    pending_certificate: dict[str, Any],
    previous_certificate: dict[str, Any],
    job_id: str,
    prepare_command: list[str],
    certbot_command: list[str],
    deploy_command: list[str],
    workspace_dir: Path,
    runner: CommandRunner | None,
    action: str,
) -> None:
    job = repository.get(job_id)
    if job is None:
        return
    prepare = _run_command(prepare_command, workspace_dir, runner)
    job = _save_certificate_progress(repository, job, "proxy private key retained and CSR prepared", prepare, level="info" if prepare.ok else "error")
    certbot = DisposableCommandResult([], str(workspace_dir), 1, "", "CSR preparation failed", False)
    deploy = DisposableCommandResult([], str(workspace_dir), 1, "", "certificate was not issued", False)
    if prepare.ok and (workspace_dir / "csr.pem").is_file():
        certbot = _run_command(certbot_command, workspace_dir, runner)
        job = _save_certificate_progress(repository, job, "DNS-01 ACME validation completed" if certbot.ok else "DNS-01 ACME validation failed", certbot, level="info" if certbot.ok else "error")
    if certbot.ok and all((workspace_dir / name).is_file() for name in ("cert.pem", "chain.pem", "fullchain.pem")):
        deploy = _run_command(deploy_command, workspace_dir, runner)
        job = _save_certificate_progress(repository, job, "proxy certificate activation completed" if deploy.ok else "proxy certificate activation failed", deploy, level="info" if deploy.ok else "error")
    evidence = _parse_certificate_evidence(deploy.stdout, str(pending_certificate.get("domain") or "")) if deploy.ok else None
    succeeded = bool(prepare.ok and certbot.ok and deploy.ok and evidence is not None)
    current_channel = _channel_by_id(get_operations_overview(engagement_id), str(channel.get("channelId") or ""))
    current_certificate = _certificate_metadata(current_channel or {})
    if current_channel is None or str(current_certificate.get("lastJobId") or "") != job_id:
        repository.save(replace(job, status="failed", finished_at=_now(), events=job.events + [JobEvent(len(job.events) + 1, "error", "DNS-01 certificate result ignored", {"error": "certificate job no longer owns channel state"})]))
        _remove_dns01_workspace_secrets(workspace_dir)
        return
    if succeeded and evidence is not None:
        certificate = {
            **pending_certificate,
            "status": "Renewed" if action == CERTIFICATE_RENEW_ACTION else "Issued",
            "activationStatus": "Active",
            "certName": str(pending_certificate.get("domain") or ""),
            "issuedAt": evidence["issuedAt"],
            "expiresAt": evidence["expiresAt"],
            **({"renewedAt": _now(), "lastAttemptStatus": "Renewed"} if action == CERTIFICATE_RENEW_ACTION else {}),
            "paths": evidence["paths"],
            "detail": "Let's Encrypt certificate issued with DNS-01 and activated on the selected proxy site container.",
        }
    elif certbot.ok:
        certificate = {
            **pending_certificate,
            "status": "Issued",
            "activationStatus": "Activation Failed",
            "lastAttemptStatus": "Activation Failed",
            "detail": "The certificate was issued, but proxy activation failed. Retry activation without issuing another certificate.",
        }
    elif previous_certificate.get("type"):
        certificate = {
            **previous_certificate,
            "lastAttemptStatus": "Renew Failed" if action == CERTIFICATE_RENEW_ACTION else "Issue Failed",
            "lastAttemptAt": _now(),
            "detail": f"DNS-01 {'renewal' if action == CERTIFICATE_RENEW_ACTION else 'issuance'} failed; the prior certificate remains active.",
        }
    else:
        certificate = {**pending_certificate, "status": "Issue Failed", "detail": "DNS-01 issuance failed before certificate activation."}
    updated = {**current_channel, "certificate": certificate}
    _replace_inbound_channel(engagement_id, updated)
    final = JobEvent(
        len(job.events) + 1,
        "info" if succeeded else "error",
        f"DNS-01 certificate {'renewal' if action == CERTIFICATE_RENEW_ACTION else 'issuance'} {'succeeded' if succeeded else 'failed'}",
        {
            "channelId": channel["channelId"],
            "certificate": _public_certificate(certificate),
            "phases": {"prepare": prepare.ok, "dns01Acme": certbot.ok, "activate": deploy.ok},
            "inboundChannels": _replace_channel_rows(get_operations_overview(engagement_id), updated),
        },
    )
    saved = replace(job, status="succeeded" if succeeded else "failed", finished_at=_now(), events=job.events + [final])
    _assert_no_private_key_contents(saved.to_detail().to_dict())
    repository.save(saved)
    _remove_dns01_workspace_secrets(workspace_dir)


def _save_certificate_progress(repository: JobRepository, job: StoredJobRun, message: str, result: DisposableCommandResult, *, level: str) -> StoredJobRun:
    saved = replace(job, events=job.events + [JobEvent(len(job.events) + 1, level, message, {"commandResult": _safe_command_result(result)})])
    _assert_no_private_key_contents(saved.to_detail().to_dict())
    return repository.save(saved)


def _managed_proxy_stack(engagement_id: str, channel: dict[str, Any], repository: EngagementServiceRepository) -> dict[str, str]:
    service_id = str(channel.get("serviceId") or "")
    service = repository.get(engagement_id, service_id) if service_id else None
    if service is None or service.service_type not in {"web-static", "web-http-backend"}:
        raise InboundChannelCertificateValidationError(["certificate issuance requires a Barragan-owned managed HTTPS site"])
    if not _same_proxy(service.proxy_id, str(channel.get("proxy") or "")):
        raise InboundChannelCertificateValidationError(["managed site is not on the selected proxy"])
    config = dict(service.config or {})
    if str(config.get("domain") or "").strip().lower() != str(channel.get("domain") or "").strip().lower():
        raise InboundChannelCertificateValidationError(["managed site domain does not match the HTTPS channel domain"])
    stack_model = str(config.get("stackModel") or "")
    if stack_model != "containerized-openresty-v1":
        raise InboundChannelCertificateValidationError(["managed site is not attached to a Barragan-owned containerized OpenResty stack"])
    site_name = str(config.get("siteName") or "")
    values = {
        "stackModel": stack_model,
        "composePath": str(config.get("composePath") or ""),
        "siteComposePath": str(config.get("siteComposePath") or f"/opt/web/sites/{site_name}.compose.yml"),
        "ownershipPath": str(config.get("stackOwnershipPath") or ""),
        "frontProxyService": str(config.get("frontProxyService") or ""),
        "siteService": str(config.get("siteService") or ""),
        "siteName": site_name,
    }
    expected_paths = (
        values["composePath"] == "/opt/web/docker-compose.yml"
        and values["siteComposePath"] == f"/opt/web/sites/{site_name}.compose.yml"
        and values["ownershipPath"] == "/opt/web/.barragan-stack.json"
    )
    if not expected_paths or values["frontProxyService"] != "reverse-proxy" or not re.fullmatch(r"[a-z0-9_-]+", values["siteService"]) or not re.fullmatch(r"[a-z0-9-]+", values["siteName"]):
        raise InboundChannelCertificateValidationError(["managed site container stack metadata is invalid"])
    return values


def _dns01_certbot_command(workspace: Path, engagement_id: str, domain: str, email: str, environment: str, *, env: Mapping[str, str] | None) -> list[str]:
    environment_values = dict(os.environ if env is None else env)
    certbot = environment_values.get("CERTBOT_BIN") or shutil.which("certbot") or "certbot"
    data_root = Path(environment_values.get("BARRAGAN_DATA_DIR", str(Path("backend/.data").resolve())))
    acme_root = data_root / "acme" / environment
    command = [
        certbot,
        "certonly",
        "--manual",
        "--preferred-challenges",
        "dns",
        "--manual-auth-hook",
        str(workspace / "hooks" / "dns01-auth.sh"),
        "--manual-cleanup-hook",
        str(workspace / "hooks" / "dns01-cleanup.sh"),
        "--csr",
        str(workspace / "csr.pem"),
        "--cert-path",
        str(workspace / "cert.pem"),
        "--chain-path",
        str(workspace / "chain.pem"),
        "--fullchain-path",
        str(workspace / "fullchain.pem"),
        "--config-dir",
        str(acme_root / "config"),
        "--work-dir",
        str(acme_root / "work"),
        "--logs-dir",
        str(acme_root / "logs"),
        "--email",
        email,
        "--agree-tos",
        "--no-eff-email",
        "--non-interactive",
    ]
    if environment == "staging":
        command.append("--test-cert")
    return command


def _dns01_certbot_revoke_command(workspace: Path, domain: str, environment: str, *, env: Mapping[str, str] | None) -> list[str]:
    environment_values = dict(os.environ if env is None else env)
    certbot = environment_values.get("CERTBOT_BIN") or shutil.which("certbot") or "certbot"
    data_root = Path(environment_values.get("BARRAGAN_DATA_DIR", str(Path("backend/.data").resolve())))
    acme_root = data_root / "acme" / environment
    command = [
        certbot,
        "revoke",
        "--cert-path",
        str(workspace / "cert.pem"),
        "--config-dir",
        str(acme_root / "config"),
        "--work-dir",
        str(acme_root / "work"),
        "--logs-dir",
        str(acme_root / "logs"),
        "--non-interactive",
        "--no-delete-after-revoke",
        "--reason",
        "cessationofoperation",
    ]
    if environment == "staging":
        command.extend(["--server", "https://acme-staging-v02.api.letsencrypt.org/directory"])
    return command


def _write_dns01_revoke_workspace(
    root: Path,
    engagement_id: str,
    channel_id: str,
    proxy: CertificateCoreHost,
    domain: str,
    stack: dict[str, str],
) -> Path:
    safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "-", f"{engagement_id}-{channel_id}-dns01-revoke").strip("-")
    workspace = root / f"{safe_name}-{uuid4().hex[:12]}"
    ansible_dir = workspace / "ansible"
    ansible_dir.mkdir(parents=True, exist_ok=True)
    inventory = "\n".join([
        "# Managed by Barragan DNS-01 certificate revocation.",
        "# Selected proxy only; reached through homebase. Never add sketch nodes.",
        "[selected_proxy]",
        proxy.inventory_line(),
        "",
    ])
    compose_path = stack["composePath"]
    site_compose_path = stack["siteComposePath"]
    ownership_path = stack["ownershipPath"]
    front_service = stack["frontProxyService"]
    site_service = stack["siteService"]
    transfer_dir = f"/opt/web/.barragan/revoke/{domain}"
    fetch = f'''---
- name: Fetch only the public certificate for ACME revocation
  hosts: selected_proxy
  become: true
  gather_facts: false
  tasks:
    - name: Verify Barragan proxy-stack ownership marker
      ansible.builtin.stat:
        path: {ownership_path}
      register: barragan_stack_marker
    - name: Refuse an unmanaged proxy stack
      ansible.builtin.assert:
        that:
          - barragan_stack_marker.stat.exists
          - barragan_stack_marker.stat.isreg
    - name: Create public certificate transfer directory
      ansible.builtin.file:
        path: {transfer_dir}
        state: directory
        owner: root
        group: root
        mode: "0700"
    - name: Copy public certificate out of the shared certificate volume
      ansible.builtin.command:
        argv: [docker, compose, -f, {compose_path}, cp, {front_service}:/etc/letsencrypt/live/{domain}/cert.pem, {transfer_dir}/cert.pem]
    - name: Fetch public certificate to the Barragan job workspace
      ansible.builtin.fetch:
        src: {transfer_dir}/cert.pem
        dest: {workspace / 'cert.pem'}
        flat: true
    - name: Remove public certificate transfer directory
      ansible.builtin.file:
        path: {transfer_dir}
        state: absent
'''
    retire = f'''---
- name: Retire the exact Barragan-owned proxy certificate
  hosts: selected_proxy
  become: true
  gather_facts: false
  tasks:
    - name: Stop only the selected TLS site
      ansible.builtin.command:
        argv: [docker, compose, -f, {compose_path}, -f, {site_compose_path}, stop, {site_service}]
    - name: Delete only canonical files for the revoked domain from the shared volume
      ansible.builtin.command:
        argv:
          - docker
          - compose
          - -f
          - {compose_path}
          - exec
          - -T
          - {front_service}
          - sh
          - -c
          - >-
            set -eu; target=/etc/letsencrypt/live/{domain};
            test "$target" = "/etc/letsencrypt/live/{domain}";
            rm -f "$target/cert.pem" "$target/chain.pem" "$target/fullchain.pem" "$target/privkey.pem";
            rmdir "$target"
      no_log: true
'''
    manifest = {
        "engagementId": engagement_id,
        "channelId": channel_id,
        "domain": domain,
        "operation": "dns01-revoke",
        "inventoryTargets": ["selected_proxy"],
        "throughHomebase": True,
        "privateKeyLeavesProxy": False,
        "publicCertificateFetched": True,
        "retirePath": f"/etc/letsencrypt/live/{domain}",
    }
    (ansible_dir / "inventory.ini").write_text(inventory, encoding="utf-8")
    (ansible_dir / "fetch_public_certificate.yml").write_text(fetch, encoding="utf-8")
    (ansible_dir / "retire_proxy_certificate.yml").write_text(retire, encoding="utf-8")
    (workspace / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    _assert_no_private_key_contents({"inventory": inventory, "fetch": fetch, "retire": retire, "manifest": manifest})
    return workspace


def _start_letsencrypt_issue(
    engagement_id: str,
    channel: dict[str, Any],
    domain: str,
    email: str,
    environment: str,
    prerequisites: dict[str, Any],
    *,
    requested_by: str,
    repository: JobRepository,
    service_repository: EngagementServiceRepository | None,
    runner: CommandRunner | None,
    background_runner: BackgroundRunner | None,
    env: Mapping[str, str] | None,
    workspace_root: Path | None,
) -> dict[str, Any]:
    service_repo = service_repository or SqlAlchemyEngagementServiceRepository()
    webroot = _managed_webroot(engagement_id, channel, service_repo)
    resolution = resolve_ansible_playbook(env=env)
    if not resolution.ok:
        raise InboundChannelCertificateValidationError([resolution.error or "Could not resolve ansible-playbook executable"])
    proxy = _certificate_proxy_host(repository, engagement_id, str(channel.get("proxy") or ""))
    command = _certbot_command(domain, email, environment, CERTIFICATE_ISSUE_ACTION, webroot)
    workspace_dir = _write_certificate_workspace(
        workspace_root or DEFAULT_WORKSPACE_ROOT,
        engagement_id,
        str(channel["channelId"]),
        proxy,
        command,
        domain,
        allow_existing_lineage=(
            str(_certificate_metadata(channel).get("managedBy") or "").lower() == "barragan"
            and str(_certificate_metadata(channel).get("certName") or "") == domain
        ),
    )
    ensure_known_hosts_file(proxy.known_hosts_file)
    ansible_command = [resolution.command or "ansible-playbook", "-i", "ansible/inventory.ini", "ansible/issue_certificate.yml"]
    timestamp = _now()
    pending_certificate = {
        "type": LETSENCRYPT_CERT_TYPE,
        "status": "Issuing",
        "domain": domain,
        "acmeEmail": email,
        "acmeEnvironment": environment,
        "challengeType": DNS01_CHALLENGE_TYPE,
        "challengeChannelId": str(prerequisites.get("challengeChannelId") or ""),
        "detail": "Certificate issuance is running on the selected proxy.",
        "prerequisites": _compact_prerequisites_for_certificate(prerequisites),
    }
    candidate_job = StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=CERTIFICATE_ISSUE_ACTION,
            status="running",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={
                "engagementId": engagement_id,
                "channelId": channel["channelId"],
                "proxyId": str(channel.get("proxy") or ""),
                "certificateType": LETSENCRYPT_CERT_TYPE,
                "acmeEnvironment": environment,
                "mutation": True,
            },
            artifact_refs=["ansible/inventory.ini", "ansible/issue_certificate.yml", "MANIFEST.json"],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=None,
            events=[
                JobEvent(
                    1,
                    "info",
                    "inbound channel certificate issue workspace rendered",
                    {
                        "channelId": channel["channelId"],
                        "workspaceDir": str(workspace_dir),
                        "inventoryTargets": ["selected_proxy"],
                        "webroot": webroot,
                        "command": _safe_command_display(command),
                        "opsecBoundary": {
                            "throughHomebase": True,
                            "selectedProxyOnly": True,
                            "directEdgeProbeFromAppHost": False,
                            "privateKeyContentsExposed": False,
                        },
                    },
                ),
                JobEvent(2, "info", "selected-proxy certificate issuance started", {"command": ansible_command}),
            ],
        )
    try:
        job = reserve_shared_proxy_stack_mutation(
            repository,
            candidate_job,
            engagement_id=engagement_id,
            proxy_id=str(channel.get("proxy") or ""),
        )
    except SharedProxyStackMutationConflict as exc:
        shutil.rmtree(workspace_dir, ignore_errors=True)
        raise InboundChannelCertificateValidationError(
            [f"Shared proxy web-stack mutation already running on {channel.get('proxy')}: {exc.job.id} ({exc.job.action})"]
        ) from exc
    pending_certificate["lastJobId"] = job.id
    _replace_inbound_channel(engagement_id, {**channel, "certificate": pending_certificate})
    (background_runner or _start_background_task)(
        lambda: _finish_letsencrypt_issue(
            repository,
            engagement_id,
            channel,
            pending_certificate,
            _certificate_metadata(channel),
            job.id,
            ansible_command,
            workspace_dir,
            runner,
        )
    )
    return {
        "job": job.to_detail().to_dict(),
        "certificate": pending_certificate,
        "prerequisites": prerequisites,
        "status": "Issuing",
    }


def _finish_letsencrypt_issue(
    repository: JobRepository,
    engagement_id: str,
    channel: dict[str, Any],
    pending_certificate: dict[str, Any],
    previous_certificate: dict[str, Any],
    job_id: str,
    command: list[str],
    workspace_dir: Path,
    runner: CommandRunner | None,
) -> None:
    job = repository.get(job_id)
    if job is None:
        return
    result = _run_command(command, workspace_dir, runner)
    evidence = _parse_certificate_evidence(result.stdout, str(pending_certificate.get("domain") or "")) if result.ok else None
    error = ""
    if result.ok and evidence is None:
        error = "remote certificate evidence was missing or invalid"
    succeeded = result.ok and evidence is not None
    current_channel = _channel_by_id(get_operations_overview(engagement_id), str(channel.get("channelId") or ""))
    current_certificate = _certificate_metadata(current_channel or {})
    if current_channel is None or str(current_certificate.get("lastJobId") or "") != job_id:
        stale_event = JobEvent(
            len(job.events) + 1,
            "error",
            "selected-proxy certificate issuance result ignored",
            {
                "channelId": channel["channelId"],
                "commandResult": _safe_command_result(result),
                "error": "certificate job no longer owns the channel state",
            },
        )
        repository.save(replace(job, status="failed", finished_at=_now(), events=job.events + [stale_event]))
        return
    certificate = dict(pending_certificate)
    if succeeded and evidence is not None:
        certificate.update(
            {
                "status": "Issued",
                "managedBy": "barragan",
                "certName": str(pending_certificate.get("domain") or ""),
                "issuedAt": evidence["issuedAt"],
                "expiresAt": evidence["expiresAt"],
                "paths": evidence["paths"],
                "detail": "Let's Encrypt certificate issued on the selected proxy.",
            }
        )
        updated_channel = {**current_channel, "certificate": certificate}
        _replace_inbound_channel(engagement_id, updated_channel)
    else:
        if previous_certificate.get("type"):
            certificate = {
                **previous_certificate,
                "lastAttemptStatus": "Issue Failed",
                "lastAttemptAt": _now(),
                "detail": error or "Certbot failed on the selected proxy; the prior certificate remains active.",
            }
        else:
            certificate.update({"status": "Issue Failed", "detail": error or "Certbot failed on the selected proxy."})
        updated_channel = {**current_channel, "certificate": certificate}
        _replace_inbound_channel(engagement_id, updated_channel)
    event = JobEvent(
        len(job.events) + 1,
        "info" if succeeded else "error",
        "selected-proxy certificate issuance succeeded" if succeeded else "selected-proxy certificate issuance failed",
        {
            "channelId": channel["channelId"],
            "commandResult": _safe_command_result(result),
            "certificate": _public_certificate(certificate),
            **({"error": error} if error else {}),
            "inboundChannels": _replace_channel_rows(get_operations_overview(engagement_id), updated_channel),
        },
    )
    saved = replace(job, status="succeeded" if succeeded else "failed", finished_at=_now(), events=job.events + [event])
    _assert_no_private_key_contents(saved.to_detail().to_dict())
    repository.save(saved)


def _start_letsencrypt_lifecycle(
    engagement_id: str,
    channel: dict[str, Any],
    previous_certificate: dict[str, Any],
    domain: str,
    certbot_command: list[str],
    *,
    action: str,
    requested_by: str,
    repository: JobRepository,
    runner: CommandRunner | None,
    background_runner: BackgroundRunner | None,
    env: Mapping[str, str] | None,
    workspace_root: Path | None,
    webroot: str = "",
    prerequisites: dict[str, Any] | None = None,
    reason: str = "",
) -> dict[str, Any]:
    resolution = resolve_ansible_playbook(env=env)
    if not resolution.ok:
        raise InboundChannelCertificateValidationError([resolution.error or "Could not resolve ansible-playbook executable"])
    proxy = _certificate_proxy_host(repository, engagement_id, str(channel.get("proxy") or ""))
    workspace_dir, playbook_name = _write_certificate_lifecycle_workspace(
        workspace_root or DEFAULT_WORKSPACE_ROOT,
        engagement_id,
        str(channel["channelId"]),
        proxy,
        certbot_command,
        domain,
        action,
        webroot=webroot,
    )
    ensure_known_hosts_file(proxy.known_hosts_file)
    ansible_command = [resolution.command or "ansible-playbook", "-i", "ansible/inventory.ini", f"ansible/{playbook_name}"]
    status = "Renewing" if action == CERTIFICATE_RENEW_ACTION else "Revoking"
    pending = {
        **previous_certificate,
        "status": status,
        "lastAttemptAt": _now(),
        "detail": f"Certificate {status.lower()} is running on the selected proxy.",
    }
    timestamp = _now()
    candidate_job = StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=action,
            status="running",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={
                "engagementId": engagement_id,
                "channelId": channel["channelId"],
                "proxyId": str(channel.get("proxy") or ""),
                "certificateType": LETSENCRYPT_CERT_TYPE,
                "acmeEnvironment": previous_certificate.get("acmeEnvironment"),
                "mutation": True,
            },
            artifact_refs=["ansible/inventory.ini", f"ansible/{playbook_name}", "MANIFEST.json"],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=None,
            events=[
                JobEvent(
                    1,
                    "info",
                    f"inbound channel certificate {'renew' if action == CERTIFICATE_RENEW_ACTION else 'revoke'} workspace rendered",
                    {
                        "channelId": channel["channelId"],
                        "workspaceDir": str(workspace_dir),
                        "inventoryTargets": ["selected_proxy"],
                        "command": _safe_command_display(certbot_command),
                        **({"webroot": webroot, "prerequisites": prerequisites} if webroot else {}),
                        **({"reason": reason} if reason else {}),
                        "opsecBoundary": {
                            "throughHomebase": True,
                            "selectedProxyOnly": True,
                            "directEdgeProbeFromAppHost": False,
                            "privateKeyContentsExposed": False,
                        },
                    },
                ),
                JobEvent(2, "info", f"selected-proxy certificate {status.lower()} started", {"command": ansible_command}),
            ],
        )
    try:
        job = reserve_shared_proxy_stack_mutation(
            repository,
            candidate_job,
            engagement_id=engagement_id,
            proxy_id=str(channel.get("proxy") or ""),
        )
    except SharedProxyStackMutationConflict as exc:
        shutil.rmtree(workspace_dir, ignore_errors=True)
        raise InboundChannelCertificateValidationError(
            [f"Shared proxy web-stack mutation already running on {channel.get('proxy')}: {exc.job.id} ({exc.job.action})"]
        ) from exc
    pending["lastJobId"] = job.id
    _replace_inbound_channel(engagement_id, {**channel, "certificate": pending})
    (background_runner or _start_background_task)(
        lambda: _finish_letsencrypt_lifecycle(
            repository,
            engagement_id,
            channel,
            pending,
            previous_certificate,
            job.id,
            ansible_command,
            workspace_dir,
            runner,
            action,
        )
    )
    response = {"job": job.to_detail().to_dict(), "certificate": pending, "status": status}
    if prerequisites is not None:
        response["prerequisites"] = prerequisites
    return response


def _finish_letsencrypt_lifecycle(
    repository: JobRepository,
    engagement_id: str,
    channel: dict[str, Any],
    pending_certificate: dict[str, Any],
    previous_certificate: dict[str, Any],
    job_id: str,
    command: list[str],
    workspace_dir: Path,
    runner: CommandRunner | None,
    action: str,
) -> None:
    job = repository.get(job_id)
    if job is None:
        return
    result = _run_command(command, workspace_dir, runner)
    domain = str(pending_certificate.get("domain") or "")
    evidence = _parse_certificate_evidence(result.stdout, domain) if action == CERTIFICATE_RENEW_ACTION and result.ok else None
    revoke_evidence = _parse_revocation_evidence(result.stdout, domain) if action == CERTIFICATE_REVOKE_ACTION and result.ok else False
    succeeded = bool(result.ok and (evidence is not None if action == CERTIFICATE_RENEW_ACTION else revoke_evidence))
    evidence_error = ""
    if result.ok and not succeeded:
        evidence_error = "remote certificate evidence was missing or invalid" if action == CERTIFICATE_RENEW_ACTION else "remote revocation evidence was missing or invalid"
    current_channel = _channel_by_id(get_operations_overview(engagement_id), str(channel.get("channelId") or ""))
    current_certificate = _certificate_metadata(current_channel or {})
    operation = "renewal" if action == CERTIFICATE_RENEW_ACTION else "revocation"
    if current_channel is None or str(current_certificate.get("lastJobId") or "") != job_id:
        event = JobEvent(len(job.events) + 1, "error", f"selected-proxy certificate {operation} result ignored", {
            "channelId": channel["channelId"],
            "commandResult": _safe_command_result(result),
            "error": "certificate job no longer owns the channel state",
        })
        repository.save(replace(job, status="failed", finished_at=_now(), events=job.events + [event]))
        return
    if succeeded and action == CERTIFICATE_RENEW_ACTION and evidence is not None:
        certificate = {
            **pending_certificate,
            "status": "Renewed",
            "managedBy": "barragan",
            "renewedAt": _now(),
            "issuedAt": evidence["issuedAt"],
            "expiresAt": evidence["expiresAt"],
            "paths": evidence["paths"],
            "lastAttemptStatus": "Renewed",
            "detail": "Let's Encrypt certificate renewed on the selected proxy.",
        }
    elif succeeded:
        certificate = {
            **pending_certificate,
            "status": "Revoked",
            "revokedAt": _now(),
            "lastAttemptStatus": "Revoked",
            "detail": "Barragan-managed Let's Encrypt certificate revoked and retired on the selected proxy.",
        }
        certificate.pop("paths", None)
    else:
        certificate = {
            **previous_certificate,
            "lastAttemptStatus": "Renew Failed" if action == CERTIFICATE_RENEW_ACTION else "Revoke Failed",
            "lastAttemptAt": _now(),
            "detail": evidence_error or f"Certbot {operation} failed on the selected proxy; the prior certificate remains active.",
        }
    updated_channel = {**current_channel, "certificate": certificate}
    _replace_inbound_channel(engagement_id, updated_channel)
    event = JobEvent(
        len(job.events) + 1,
        "info" if succeeded else "error",
        f"selected-proxy certificate {operation} {'succeeded' if succeeded else 'failed'}",
        {
            "channelId": channel["channelId"],
            "commandResult": _safe_command_result(result),
            "certificate": _public_certificate(certificate),
            **({"error": evidence_error} if evidence_error else {}),
            "inboundChannels": _replace_channel_rows(get_operations_overview(engagement_id), updated_channel),
        },
    )
    saved = replace(job, status="succeeded" if succeeded else "failed", finished_at=_now(), events=job.events + [event])
    _assert_no_private_key_contents(saved.to_detail().to_dict())
    repository.save(saved)


def _managed_webroot(
    engagement_id: str,
    channel: dict[str, Any],
    repository: EngagementServiceRepository,
) -> str:
    service_id = str(channel.get("serviceId") or "")
    service = repository.get(engagement_id, service_id) if service_id else None
    if service is None or service.service_type != "web-static":
        raise InboundChannelCertificateValidationError(["certificate issuance requires a Barragan-owned web-static service"])
    channel_proxies = {str(channel.get("proxy") or ""), str(channel.get("terminatesOn") or "")}
    if not any(_same_proxy(service.proxy_id, candidate) for candidate in channel_proxies):
        raise InboundChannelCertificateValidationError(["managed web-static service is not on the selected proxy"])
    config = dict(service.config or {})
    if str(config.get("domain") or "").strip().lower().rstrip(".") != str(channel.get("domain") or "").strip().lower().rstrip("."):
        raise InboundChannelCertificateValidationError(["managed web-static service domain does not match the HTTPS channel domain"])
    site_name = str(config.get("siteName") or "").strip()
    content_path = str(config.get("contentPath") or "").strip().rstrip("/")
    expected = f"/opt/web/{site_name}/html"
    if not site_name or content_path != expected or not re.fullmatch(r"/opt/web/[a-z0-9][a-z0-9-]*/html", content_path):
        raise InboundChannelCertificateValidationError(["managed web-static service has no valid Barragan-owned contentPath"])
    if str(config.get("internalPort") or "") != str(channel.get("internalPort") or ""):
        raise InboundChannelCertificateValidationError(["managed web-static listener does not match the HTTPS channel internalPort"])
    return content_path


def _reject_active_certificate_job(certificate: dict[str, Any]) -> None:
    if str(certificate.get("status") or "").strip().lower() in {"issuing", "renewing", "revoking"}:
        raise InboundChannelCertificateValidationError([
            f"certificate job {certificate.get('lastJobId') or 'unknown'} is already running for this inbound channel"
        ])


def _validated_managed_letsencrypt_certificate(
    channel: dict[str, Any],
    certificate: dict[str, Any],
    *,
    require_managed: bool,
) -> str:
    if str(certificate.get("type") or "").strip().lower() != LETSENCRYPT_CERT_TYPE:
        raise InboundChannelCertificateValidationError(["a Let's Encrypt certificate is required for this action"])
    if require_managed and str(certificate.get("managedBy") or "").strip().lower() != "barragan":
        raise InboundChannelCertificateValidationError(["only certificates managedBy=barragan can use live renewal or revocation"])
    domain = _validated_domain(channel)
    if str(certificate.get("domain") or "").strip().lower() != domain:
        raise InboundChannelCertificateValidationError(["recorded certificate domain does not match the HTTPS channel domain"])
    if str(certificate.get("certName") or "").strip().lower() != domain:
        raise InboundChannelCertificateValidationError(["recorded certificate certName does not match the Barragan-managed domain lineage"])
    expected = {
        "liveDir": f"/etc/letsencrypt/live/{domain}",
        "fullchain": f"/etc/letsencrypt/live/{domain}/fullchain.pem",
        "privkey": f"/etc/letsencrypt/live/{domain}/privkey.pem",
    }
    paths = certificate.get("paths")
    if not isinstance(paths, dict) or any(str(paths.get(key) or "") != value for key, value in expected.items()):
        raise InboundChannelCertificateValidationError(["recorded certificate paths are not the canonical domain paths"])
    if str(certificate.get("status") or "").strip().lower() == "revoked":
        raise InboundChannelCertificateValidationError(["the recorded certificate is already revoked"])
    return domain


def _recorded_acme_environment(certificate: dict[str, Any]) -> str:
    environment = str(certificate.get("acmeEnvironment") or "").strip().lower()
    if environment not in SUPPORTED_ACME_ENVIRONMENTS:
        raise InboundChannelCertificateValidationError(["recorded certificate acmeEnvironment must be staging or production"])
    return environment


def _certificate_proxy_host(repository: JobRepository, engagement_id: str, proxy_id: str) -> CertificateCoreHost:
    deployment_id, details = latest_core_connection_details(repository, engagement_id)
    homebase = next((row for row in details if str(row.get("role") or "") == "homebase"), None)
    proxy = next(
        (
            row
            for row in details
            if str(row.get("role") or "") in {"proxy", proxy_id}
            and proxy_id in {str(row.get("displayName") or ""), str(row.get("sshAlias") or ""), str(row.get("hostname") or "")}
        ),
        None,
    )
    if homebase is None or proxy is None:
        raise InboundChannelCertificateValidationError(["latest core connection details must include homebase and the selected proxy"])
    homebase_host = str(homebase.get("publicIp") or "").strip()
    proxy_host = str(proxy.get("privateIp") or proxy.get("publicIp") or "").strip()
    if not homebase_host or not proxy_host:
        raise InboundChannelCertificateValidationError(["homebase and selected proxy connection addresses are required"])
    ssh_key = os.environ.get(CORE_SSH_KEY_ENV, DEFAULT_CORE_SSH_PRIVATE_KEY)
    known_hosts = deployment_known_hosts_file(DEFAULT_KNOWN_HOSTS_ROOT, engagement_id, deployment_id)
    homebase_user = str(homebase.get("sshUser") or "user")
    return CertificateCoreHost(
        proxy_id,
        proxy_host,
        str(proxy.get("sshUser") or "user"),
        ssh_key,
        f"{homebase_user}@{homebase_host}",
        known_hosts,
    )


def _write_dns01_workspace(
    root: Path,
    engagement_id: str,
    channel_id: str,
    proxy: CertificateCoreHost,
    domain: str,
    email: str,
    environment: str,
    stack: dict[str, str],
) -> Path:
    safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "-", f"{engagement_id}-{channel_id}-dns01").strip("-")
    workspace = root / f"{safe_name}-{uuid4().hex[:12]}"
    ansible_dir = workspace / "ansible"
    hooks_dir = workspace / "hooks"
    ansible_dir.mkdir(parents=True, exist_ok=True)
    hooks_dir.mkdir(parents=True, exist_ok=True)
    inventory = "\n".join([
        "# Managed by Barragan DNS-01 certificate orchestration.",
        "# Selected proxy only; reached through homebase. Never add sketch nodes.",
        "[selected_proxy]",
        proxy.inventory_line(),
        "",
    ])
    compose_path = stack["composePath"]
    site_compose_path = stack["siteComposePath"]
    ownership_path = stack["ownershipPath"]
    front_service = stack["frontProxyService"]
    site_service = stack["siteService"]
    site_name = stack["siteName"]
    csr_host_dir = f"/opt/web/.barragan/csr/{domain}"
    certificate_stage_dir = f"/opt/web/.barragan/certificate-staging/{domain}"
    prepare = f'''---
- name: Generate a proxy-held private key and public CSR
  hosts: selected_proxy
  become: true
  gather_facts: false
  tasks:
    - name: Verify Barragan proxy-stack ownership marker
      ansible.builtin.stat:
        path: {ownership_path}
      register: barragan_stack_marker
    - name: Refuse an unmanaged proxy stack
      ansible.builtin.assert:
        that:
          - barragan_stack_marker.stat.exists
          - barragan_stack_marker.stat.isreg
    - name: Create CSR transfer directory
      ansible.builtin.file:
        path: {csr_host_dir}
        state: directory
        owner: root
        group: root
        mode: "0700"
    - name: Generate or reuse the private key inside the shared proxy certificate volume
      ansible.builtin.command:
        argv:
          - docker
          - compose
          - -f
          - {compose_path}
          - exec
          - -T
          - {front_service}
          - sh
          - -c
          - >-
            set -eu; umask 077; mkdir -p /etc/letsencrypt/live/{domain};
            test -s /etc/letsencrypt/live/{domain}/privkey.pem ||
            openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /etc/letsencrypt/live/{domain}/privkey.pem;
            openssl req -new -key /etc/letsencrypt/live/{domain}/privkey.pem
            -subj /CN={domain} -addext subjectAltName=DNS:{domain} -out /tmp/barragan-{domain}.csr
      no_log: true
    - name: Copy only the public CSR out of the front proxy container
      ansible.builtin.command:
        argv: [docker, compose, -f, {compose_path}, cp, {front_service}:/tmp/barragan-{domain}.csr, {csr_host_dir}/csr.pem]
    - name: Fetch public CSR to the Barragan job workspace
      ansible.builtin.fetch:
        src: {csr_host_dir}/csr.pem
        dest: {workspace / 'csr.pem'}
        flat: true
    - name: Remove CSR transfer artifacts from the proxy host
      ansible.builtin.file:
        path: {csr_host_dir}
        state: absent
'''
    deploy = f'''---
- name: Deploy public DNS-01 certificate material to the selected proxy
  hosts: selected_proxy
  become: true
  gather_facts: false
  tasks:
    - name: Create public certificate staging directory
      ansible.builtin.file:
        path: {certificate_stage_dir}
        state: directory
        owner: root
        group: root
        mode: "0700"
    - name: Stage public certificate files
      ansible.builtin.copy:
        src: "{{{{ item }}}}"
        dest: "{certificate_stage_dir}/{{{{ item | basename }}}}"
        owner: root
        group: root
        mode: "0644"
      loop:
        - {workspace / 'cert.pem'}
        - {workspace / 'chain.pem'}
        - {workspace / 'fullchain.pem'}
    - name: Copy public certificate files into the shared certificate volume
      ansible.builtin.command:
        argv: [docker, compose, -f, {compose_path}, cp, "{certificate_stage_dir}/{{{{ item }}}}", "{front_service}:/etc/letsencrypt/live/{domain}/{{{{ item }}}}"]
      loop: [cert.pem, chain.pem, fullchain.pem]
    - name: Write Barragan-owned TLS site configuration
      ansible.builtin.copy:
        dest: /opt/web/{site_name}/conf/default.conf
        owner: root
        group: redteam
        mode: "0644"
        content: |
          server {{
              listen 8081 proxy_protocol ssl;
              server_name {domain};
              root /var/www/html/{site_name};
              index index.html;
              real_ip_header proxy_protocol;
              ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
              ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
              include /etc/nginx/conf.d/request-header-gate*.inc;
              location / {{ try_files $uri $uri/ /index.html; }}
          }}
    - name: Recreate the selected site with its TLS configuration
      ansible.builtin.command:
        argv: [docker, compose, -f, {compose_path}, -f, {site_compose_path}, up, -d, --force-recreate, {site_service}]
    - name: Validate selected site OpenResty configuration
      ansible.builtin.command:
        argv: [docker, compose, -f, {compose_path}, -f, {site_compose_path}, exec, -T, {site_service}, openresty, -t]
    - name: Reload selected site OpenResty
      ansible.builtin.command:
        argv: [docker, compose, -f, {compose_path}, -f, {site_compose_path}, exec, -T, {site_service}, openresty, -s, reload]
    - name: Inspect active certificate without reading its private key
      ansible.builtin.shell: |
        set -eu
        issued=$(docker compose -f {compose_path} -f {site_compose_path} exec -T {site_service} openssl x509 -in /etc/letsencrypt/live/{domain}/fullchain.pem -noout -startdate | cut -d= -f2-)
        expires=$(docker compose -f {compose_path} -f {site_compose_path} exec -T {site_service} openssl x509 -in /etc/letsencrypt/live/{domain}/fullchain.pem -noout -enddate | cut -d= -f2-)
        python3 -c 'import json,sys; print("{EVIDENCE_PREFIX}" + json.dumps({{"domain": "{domain}", "issuedAt": sys.argv[1], "expiresAt": sys.argv[2], "liveDir": "/etc/letsencrypt/live/{domain}", "fullchain": "/etc/letsencrypt/live/{domain}/fullchain.pem", "privkey": "/etc/letsencrypt/live/{domain}/privkey.pem"}}))' "$issued" "$expires"
      args:
        executable: /bin/bash
      register: certificate_evidence
      changed_when: false
    - name: Return bounded certificate metadata evidence
      ansible.builtin.debug:
        msg: "{{{{ certificate_evidence.stdout }}}}"
    - name: Remove public certificate staging artifacts
      ansible.builtin.file:
        path: {certificate_stage_dir}
        state: absent
'''
    python = json.dumps(sys.executable)
    common_args = f"--engagement-id {json.dumps(engagement_id)} --identifier {json.dumps(domain)}"
    auth_hook = f"#!/bin/sh\nset -eu\nexec {python} -m app.cli.dns01_hook auth {common_args}\n"
    cleanup_hook = f"#!/bin/sh\nset -eu\nexec {python} -m app.cli.dns01_hook cleanup {common_args}\n"
    manifest = {
        "engagementId": engagement_id,
        "channelId": channel_id,
        "domain": domain,
        "acmeEmail": email,
        "acmeEnvironment": environment,
        "challengeType": DNS01_CHALLENGE_TYPE,
        "inventoryTargets": ["selected_proxy"],
        "namecheapCredentialOnProxy": False,
        "privateKeyLeavesProxy": False,
        "proxyStack": stack,
    }
    (ansible_dir / "inventory.ini").write_text(inventory, encoding="utf-8")
    (ansible_dir / "prepare_dns01_certificate.yml").write_text(prepare, encoding="utf-8")
    (ansible_dir / "deploy_dns01_certificate.yml").write_text(deploy, encoding="utf-8")
    (hooks_dir / "dns01-auth.sh").write_text(auth_hook, encoding="utf-8")
    (hooks_dir / "dns01-cleanup.sh").write_text(cleanup_hook, encoding="utf-8")
    (hooks_dir / "dns01-auth.sh").chmod(0o700)
    (hooks_dir / "dns01-cleanup.sh").chmod(0o700)
    (workspace / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    _assert_no_private_key_contents({"inventory": inventory, "prepare": prepare, "deploy": deploy, "manifest": manifest})
    return workspace


def _remove_dns01_workspace_secrets(workspace: Path) -> None:
    # CSR and issued certificates are public, but keeping transient ACME output
    # out of abandoned workspaces makes the ownership boundary explicit.
    for name in ("csr.pem", "cert.pem", "chain.pem", "fullchain.pem"):
        try:
            (workspace / name).unlink(missing_ok=True)
        except OSError:
            pass


def _write_certificate_workspace(
    root: Path,
    engagement_id: str,
    channel_id: str,
    proxy: CertificateCoreHost,
    certbot_command: list[str],
    domain: str,
    *,
    allow_existing_lineage: bool,
) -> Path:
    safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "-", f"{engagement_id}-{channel_id}").strip("-")
    workspace = root / f"{safe_name}-{uuid4().hex[:12]}"
    ansible_dir = workspace / "ansible"
    ansible_dir.mkdir(parents=True, exist_ok=True)
    inventory = "\n".join([
        "# Managed by Barragan certificate issuance.",
        "# Selected proxy only; reached through homebase. Never add sketch nodes.",
        "[selected_proxy]",
        proxy.inventory_line(),
        "",
    ])
    argv_json = json.dumps(certbot_command)
    playbook = f'''---
- name: Issue certificate on selected proxy
  hosts: selected_proxy
  become: true
  gather_facts: false
  tasks:
    - name: Install Certbot
      ansible.builtin.apt:
        name: certbot
        state: present
        update_cache: true
    - name: Verify Barragan-managed webroot exists
      ansible.builtin.stat:
        path: {certbot_command[certbot_command.index("--webroot-path") + 1]}
      register: barragan_certificate_webroot
    - name: Refuse an absent or non-directory webroot
      ansible.builtin.assert:
        that:
          - barragan_certificate_webroot.stat.exists
          - barragan_certificate_webroot.stat.isdir
    - name: Inspect the requested Certbot lineage
      ansible.builtin.stat:
        path: /etc/letsencrypt/renewal/{domain}.conf
      register: barragan_certificate_lineage
    - name: Refuse to adopt an existing operator-managed Certbot lineage
      ansible.builtin.assert:
        that:
          - not barragan_certificate_lineage.stat.exists
        fail_msg: Existing Certbot lineage is not recorded as Barragan-owned.
      when: {str(not allow_existing_lineage).lower()}
    - name: Run Certbot using the Barragan-managed host webroot
      ansible.builtin.command:
        argv: {argv_json}
      register: certbot_result
      changed_when: certbot_result.rc == 0
    - name: Inspect issued certificate without reading its private key
      ansible.builtin.shell: |
        set -eu
        issued=$(openssl x509 -in /etc/letsencrypt/live/{domain}/fullchain.pem -noout -startdate | cut -d= -f2-)
        expires=$(openssl x509 -in /etc/letsencrypt/live/{domain}/fullchain.pem -noout -enddate | cut -d= -f2-)
        python3 -c 'import json,sys; print("{EVIDENCE_PREFIX}" + json.dumps({{"domain": "{domain}", "issuedAt": sys.argv[1], "expiresAt": sys.argv[2], "liveDir": "/etc/letsencrypt/live/{domain}", "fullchain": "/etc/letsencrypt/live/{domain}/fullchain.pem", "privkey": "/etc/letsencrypt/live/{domain}/privkey.pem"}}))' "$issued" "$expires"
      args:
        executable: /bin/bash
      register: certificate_evidence
      changed_when: false
    - name: Return bounded certificate metadata evidence
      ansible.builtin.debug:
        msg: "{{{{ certificate_evidence.stdout }}}}"
'''
    manifest = {
        "engagementId": engagement_id,
        "channelId": channel_id,
        "domain": domain,
        "inventoryTargets": ["selected_proxy"],
        "throughHomebase": True,
        "directEdgeProbeFromAppHost": False,
        "privateKeyContentsRead": False,
        "existingLineageAllowed": allow_existing_lineage,
    }
    (ansible_dir / "inventory.ini").write_text(inventory, encoding="utf-8")
    (ansible_dir / "issue_certificate.yml").write_text(playbook, encoding="utf-8")
    (workspace / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    _assert_no_private_key_contents({"inventory": inventory, "playbook": playbook, "manifest": manifest})
    return workspace


def _write_certificate_lifecycle_workspace(
    root: Path,
    engagement_id: str,
    channel_id: str,
    proxy: CertificateCoreHost,
    certbot_command: list[str],
    domain: str,
    action: str,
    *,
    webroot: str = "",
) -> tuple[Path, str]:
    operation = "renew" if action == CERTIFICATE_RENEW_ACTION else "revoke"
    safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "-", f"{engagement_id}-{channel_id}-{operation}").strip("-")
    workspace = root / f"{safe_name}-{uuid4().hex[:12]}"
    ansible_dir = workspace / "ansible"
    ansible_dir.mkdir(parents=True, exist_ok=True)
    inventory = "\n".join([
        f"# Managed by Barragan certificate {operation}.",
        "# Selected proxy only; reached through homebase. Never add sketch nodes.",
        "[selected_proxy]",
        proxy.inventory_line(),
        "",
    ])
    argv_json = json.dumps(certbot_command)
    if action == CERTIFICATE_RENEW_ACTION:
        operation_tasks = f'''    - name: Verify Barragan-managed webroot exists
      ansible.builtin.stat:
        path: {webroot}
      register: barragan_certificate_webroot
    - name: Refuse an absent or non-directory webroot
      ansible.builtin.assert:
        that:
          - barragan_certificate_webroot.stat.exists
          - barragan_certificate_webroot.stat.isdir
'''
        evidence_task = f'''    - name: Inspect renewed certificate without reading its private key
      ansible.builtin.shell: |
        set -eu
        issued=$(openssl x509 -in /etc/letsencrypt/live/{domain}/fullchain.pem -noout -startdate | cut -d= -f2-)
        expires=$(openssl x509 -in /etc/letsencrypt/live/{domain}/fullchain.pem -noout -enddate | cut -d= -f2-)
        python3 -c 'import json,sys; print("{EVIDENCE_PREFIX}" + json.dumps({{"domain": "{domain}", "issuedAt": sys.argv[1], "expiresAt": sys.argv[2], "liveDir": "/etc/letsencrypt/live/{domain}", "fullchain": "/etc/letsencrypt/live/{domain}/fullchain.pem", "privkey": "/etc/letsencrypt/live/{domain}/privkey.pem"}}))' "$issued" "$expires"
      args:
        executable: /bin/bash
      register: certificate_evidence
      changed_when: false
    - name: Return bounded certificate metadata evidence
      ansible.builtin.debug:
        msg: "{{{{ certificate_evidence.stdout }}}}"
'''
    else:
        operation_tasks = ""
        evidence_task = f'''    - name: Verify Certbot retired the canonical live certificate path
      ansible.builtin.stat:
        path: /etc/letsencrypt/live/{domain}
      register: revoked_certificate_path
    - name: Refuse a revocation result that left the live certificate path present
      ansible.builtin.assert:
        that:
          - not revoked_certificate_path.stat.exists
    - name: Return bounded revocation evidence
      ansible.builtin.debug:
        msg: '{REVOCATION_EVIDENCE_PREFIX}{{"domain":"{domain}","liveDir":"/etc/letsencrypt/live/{domain}","absent":true}}'
'''
    playbook = f'''---
- name: {operation.title()} certificate on selected proxy
  hosts: selected_proxy
  become: true
  gather_facts: false
  tasks:
    - name: Install Certbot
      ansible.builtin.apt:
        name: certbot
        state: present
        update_cache: true
{operation_tasks}    - name: Run Certbot for the recorded certificate name
      ansible.builtin.command:
        argv: {argv_json}
      register: certbot_result
      changed_when: certbot_result.rc == 0
{evidence_task}'''
    playbook_name = f"{operation}_certificate.yml"
    manifest = {
        "engagementId": engagement_id,
        "channelId": channel_id,
        "domain": domain,
        "operation": operation,
        "inventoryTargets": ["selected_proxy"],
        "throughHomebase": True,
        "directEdgeProbeFromAppHost": False,
        "privateKeyContentsRead": False,
    }
    (ansible_dir / "inventory.ini").write_text(inventory, encoding="utf-8")
    (ansible_dir / playbook_name).write_text(playbook, encoding="utf-8")
    (workspace / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    _assert_no_private_key_contents({"inventory": inventory, "playbook": playbook, "manifest": manifest})
    return workspace, playbook_name


def _run_command(command: list[str], cwd: Path, runner: CommandRunner | None) -> DisposableCommandResult:
    try:
        completed = runner(command, cwd) if runner else subprocess.run(
            command,
            cwd=cwd,
            env=barragan_subprocess_env(),
            check=False,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        completed = subprocess.CompletedProcess(command, 124, stdout=exc.stdout or "", stderr=exc.stderr or "command timed out")
    except OSError as exc:
        completed = subprocess.CompletedProcess(command, 1, stdout="", stderr=str(exc))
    return DisposableCommandResult(command, str(cwd), int(completed.returncode), str(completed.stdout or ""), str(completed.stderr or ""), int(completed.returncode) == 0)


def _safe_command_result(result: DisposableCommandResult) -> dict[str, Any]:
    return {
        "command": result.command,
        "cwd": result.cwd,
        "returncode": result.returncode,
        "ok": result.ok,
        "stdout": _sanitize_output(result.stdout),
        "stderr": _sanitize_output(result.stderr),
    }


def _sanitize_output(value: str) -> str:
    text = str(value or "")
    for pattern, replacement in SECRET_OUTPUT_REDACTIONS:
        text = pattern.sub(replacement, text)
    if len(text) > MAX_RESULT_CHARS:
        text = text[:MAX_RESULT_CHARS] + "\n[truncated]"
    return text


def _parse_certificate_evidence(stdout: str, expected_domain: str) -> dict[str, Any] | None:
    for line in reversed(str(stdout or "").splitlines()):
        marker = line.find(EVIDENCE_PREFIX)
        if marker < 0:
            continue
        candidate = line[marker + len(EVIDENCE_PREFIX):].strip().strip('"')
        candidate = candidate.replace('\\"', '"')
        try:
            evidence = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        required = ("domain", "issuedAt", "expiresAt", "liveDir", "fullchain", "privkey")
        if not isinstance(evidence, dict) or any(not str(evidence.get(key) or "") for key in required):
            continue
        domain = str(evidence["domain"])
        if domain != expected_domain:
            continue
        live_dir = f"/etc/letsencrypt/live/{domain}"
        fullchain = f"{live_dir}/fullchain.pem"
        privkey = f"{live_dir}/privkey.pem"
        if (
            str(evidence["liveDir"]) != live_dir
            or str(evidence["fullchain"]) != fullchain
            or str(evidence["privkey"]) != privkey
        ):
            continue
        issued_at = _certificate_datetime(str(evidence["issuedAt"]))
        expires_at = _certificate_datetime(str(evidence["expiresAt"]))
        if issued_at is None or expires_at is None or expires_at <= issued_at or expires_at <= datetime.now(timezone.utc):
            continue
        return {
            "issuedAt": issued_at.isoformat(),
            "expiresAt": expires_at.isoformat(),
            "paths": {
                "liveDir": live_dir,
                "fullchain": fullchain,
                "privkey": privkey,
            },
        }
    return None


def _parse_revocation_evidence(stdout: str, expected_domain: str) -> bool:
    for line in reversed(str(stdout or "").splitlines()):
        marker = line.find(REVOCATION_EVIDENCE_PREFIX)
        if marker < 0:
            continue
        candidate = line[marker + len(REVOCATION_EVIDENCE_PREFIX):].strip().strip('"').replace('\\"', '"')
        try:
            evidence = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if not isinstance(evidence, dict) or evidence.get("absent") is not True:
            continue
        if str(evidence.get("domain") or "") != expected_domain:
            continue
        if str(evidence.get("liveDir") or "") != f"/etc/letsencrypt/live/{expected_domain}":
            continue
        return True
    return False


def _certificate_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _start_background_task(task: Callable[[], None]) -> None:
    start_runtime_task(task, name="barragan-certificate-issue-runner")


def _production_confirmation(channel_id: str, domain: str) -> str:
    return f"issue-production-{channel_id}-{domain}"


def _same_proxy(left: str, right: str) -> bool:
    left = str(left or "").strip().lower()
    right = str(right or "").strip().lower()
    if not left or not right:
        return False
    return left == right or left.startswith(f"{right}-") or right.startswith(f"{left}-")


def _self_signed_command(domain: str, certificate: dict[str, Any]) -> list[str]:
    paths = certificate["paths"]
    return [
        "openssl",
        "req",
        "-x509",
        "-nodes",
        "-newkey",
        "rsa:2048",
        "-days",
        "365",
        "-subj",
        f"/CN={domain}",
        "-addext",
        f"subjectAltName=DNS:{domain}",
        "-keyout",
        paths["privkey"],
        "-out",
        paths["fullchain"],
    ]


def _revoke_command(certificate: dict[str, Any]) -> list[str]:
    if certificate.get("type") == LETSENCRYPT_CERT_TYPE:
        cert_path = str(certificate.get("paths", {}).get("fullchain") or "")
        return ["certbot", "revoke", "--cert-path", cert_path, "--non-interactive"]
    return ["update-barragan-certificate-state", "--status", "revoked", "--domain", str(certificate.get("domain") or "")]


def _certificate_lifecycle_job(
    repo: JobRepository,
    *,
    action: str,
    engagement_id: str,
    channel: dict[str, Any],
    certificate: dict[str, Any],
    requested_by: str,
    event_message: str,
    command: list[str],
    extra: dict[str, Any],
) -> StoredJobRun:
    timestamp = _now()
    events = [
        JobEvent(
            1,
            "info",
            event_message,
            {
                "channelId": channel["channelId"],
                "certificate": _public_certificate(certificate),
                "command": _safe_command_display(command),
                **extra,
                "opsecBoundary": {
                    "privateKeyContentsExposed": False,
                    "directEdgeProbeFromAppHost": False,
                    "certificateIdentity": "domain-only",
                },
            },
        ),
        JobEvent(
            2,
            "info",
            "inbound channel certificate state recorded",
            {
                "channelId": channel["channelId"],
                "certificate": _public_certificate(certificate),
            },
        ),
    ]
    job = StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=action,
        status="succeeded",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by=requested_by,
        input={
            "engagementId": engagement_id,
            "channelId": channel["channelId"],
            "certificateType": certificate.get("type"),
            "mutation": True,
        },
        artifact_refs=[],
        created_at=timestamp,
        started_at=timestamp,
        finished_at=timestamp,
        events=events,
    )
    _assert_no_private_key_contents(job.to_detail().to_dict())
    return repo.save(job)


def _instant_job(
    repo: JobRepository,
    action: str,
    engagement_id: str,
    requested_by: str,
    message: str,
    data: dict[str, Any],
) -> StoredJobRun:
    timestamp = _now()
    job = StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=action,
        status="succeeded",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by=requested_by,
        input={"engagementId": engagement_id, "mutation": True},
        artifact_refs=[],
        created_at=timestamp,
        started_at=timestamp,
        finished_at=timestamp,
        events=[JobEvent(1, "info", message, data)],
    )
    _assert_no_private_key_contents(job.to_detail().to_dict())
    return repo.save(job)


def _events_with_channels(events: list[JobEvent], engagement_id: str, updated_channel: dict[str, Any]) -> list[JobEvent]:
    overview = get_operations_overview(engagement_id)
    inbound_channels = _replace_channel_rows(overview, updated_channel)
    if not events:
        return events
    last = events[-1]
    return [
        *events[:-1],
        JobEvent(
            last.sequence,
            last.level,
            last.message,
            {**last.data, "inboundChannels": inbound_channels},
        ),
    ]


def _public_certificate(certificate: dict[str, Any]) -> dict[str, Any]:
    return dict(certificate)


def _required_https_channel(overview: dict[str, Any], channel_id: str) -> dict[str, Any]:
    channel = _channel_by_id(overview, channel_id)
    if channel is None:
        raise InboundChannelCertificateValidationError([f"inbound channel {channel_id} was not found"])
    if not _is_https_channel(channel):
        raise InboundChannelCertificateValidationError(["certificates can only be managed for HTTPS/OpenResty inbound channels"])
    return channel


def _is_https_channel(channel: dict[str, Any]) -> bool:
    return (
        str(channel.get("mode") or "").strip().lower() == "https-openresty"
        and str(channel.get("protocol") or "").strip().upper() == "HTTPS"
    )


def _validated_domain(channel: dict[str, Any]) -> str:
    domain = str(channel.get("domain") or "").strip().lower()
    if not DOMAIN_PATTERN.match(domain):
        raise InboundChannelCertificateValidationError(["channel must have a real domain before certificate management"])
    return domain


def _validated_email(value: Any) -> str:
    email = str(value or "").strip()
    if not EMAIL_PATTERN.match(email):
        raise InboundChannelCertificateValidationError(["acmeEmail must be a valid email address"])
    return email


def _channel_by_id(overview: dict[str, Any] | None, channel_id: str) -> dict[str, Any] | None:
    rows = overview.get("inboundChannels", []) if isinstance(overview, dict) else []
    for row in rows:
        if isinstance(row, dict) and str(row.get("channelId") or "") == channel_id:
            return dict(row)
    return None


def _certificate_metadata(channel: dict[str, Any]) -> dict[str, Any]:
    certificate = channel.get("certificate")
    if isinstance(certificate, dict):
        return dict(certificate)
    return {}


def _http01_channel_for(parent: dict[str, Any], overview: dict[str, Any]) -> dict[str, Any] | None:
    parent_edge = str(parent.get("edge") or "")
    parent_proxy = str(parent.get("proxy") or "")
    rows = overview.get("inboundChannels", []) if isinstance(overview, dict) else []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("edge") or "") != parent_edge:
            continue
        if str(row.get("externalPort") or "") != "80":
            continue
        if str(row.get("proxy") or "") != parent_proxy:
            continue
        if str(row.get("terminatesOn") or "") != str(parent.get("terminatesOn") or parent_proxy):
            continue
        if str(row.get("domain") or "").strip().lower() != str(parent.get("domain") or "").strip().lower():
            continue
        if str(row.get("serviceId") or "") != str(parent.get("serviceId") or ""):
            continue
        support = row.get("certificateSupport")
        if not isinstance(support, dict) or str(support.get("parentChannelId") or "") != str(parent.get("channelId") or ""):
            continue
        if str(row.get("mode") or "") != "tcp-forward":
            continue
        if str(row.get("protocol") or "").upper() != "TCP":
            continue
        if str(row.get("internalPort") or "") != str(parent.get("internalPort") or ""):
            continue
        try:
            relay_port = int(str(row.get("relayPort") or row.get("proxyRelayPort") or ""))
        except ValueError:
            continue
        if relay_port not in HTTP01_RELAY_PORTS or relay_port in {80, int(str(row.get("internalPort") or "0"))}:
            continue
        if str(row.get("status") or "").strip().lower() not in {"pending validation", "validated"}:
            continue
        return dict(row)
    return None


def _free_http01_relay_port(overview: dict[str, Any]) -> str:
    claimed: set[int] = set()
    for row in overview.get("inboundChannels", []) if isinstance(overview, dict) else []:
        if not isinstance(row, dict):
            continue
        if str(row.get("status") or "").strip().lower() in {"removed", "disabled"}:
            continue
        for key in ("externalPort", "relayPort", "middleRelayPort", "proxyRelayPort", "internalPort"):
            try:
                claimed.add(int(str(row.get(key) or "")))
            except ValueError:
                pass
    for port in HTTP01_RELAY_PORTS:
        if port not in claimed:
            return str(port)
    raise InboundChannelCertificateValidationError(["no free HTTP-01 relay port is available in 8000-8080"])


def _channel_with_certificate_support(channel: dict[str, Any], parent: dict[str, Any]) -> dict[str, Any]:
    return {
        **channel,
        "certificateSupport": {
            "role": "http-01-challenge",
            "parentChannelId": str(parent.get("channelId") or ""),
            "purpose": HTTP01_PURPOSE,
            "dependency": "letsencrypt-renewal",
            "status": "active",
        },
    }


def _replace_inbound_channel(engagement_id: str, updated_channel: dict[str, Any]) -> None:
    overview = get_operations_overview(engagement_id)
    update_operations_overview(engagement_id, {"inboundChannels": _replace_channel_rows(overview, updated_channel)})


def _replace_channel_rows(overview: dict[str, Any], updated_channel: dict[str, Any]) -> list[dict[str, Any]]:
    rows = overview.get("inboundChannels", []) if isinstance(overview, dict) else []
    channel_id = str(updated_channel.get("channelId") or "")
    replaced = False
    next_rows: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("channelId") or "") == channel_id:
            next_rows.append(dict(updated_channel))
            replaced = True
        else:
            next_rows.append(dict(row))
    if not replaced:
        next_rows.append(dict(updated_channel))
    return next_rows


def _assigned_domain_asset(
    engagement_id: str,
    fqdn: str,
    *,
    domain_repository: DomainRepository | None = None,
) -> tuple[StoredDomainAsset | None, bool]:
    if not fqdn:
        return None, False
    repo = domain_repository or SqlAlchemyDomainRepository()
    labels = fqdn.split(".")
    candidates = [".".join(labels[index:]) for index in range(len(labels) - 1)]
    for candidate in candidates:
        asset = repo.get_asset_by_name(candidate)
        if asset is None:
            continue
        active = any(
            assignment.engagement_id == engagement_id and assignment.status == "active"
            for assignment in repo.list_assignments(domain_id=asset.id, engagement_id=engagement_id)
        )
        if active:
            return asset, True
        return asset, False
    return None, False


def _dns_points_to_edge(
    asset: StoredDomainAsset,
    fqdn: str,
    edge_ip: str,
    *,
    domain_repository: DomainRepository | None = None,
) -> bool:
    try:
        edge_address = ipaddress.ip_address(edge_ip)
    except ValueError:
        return False
    repo = domain_repository or SqlAlchemyDomainRepository()
    snapshots = repo.list_snapshots(asset.id)
    if not snapshots:
        return False
    relative_host = _relative_dns_host(fqdn, asset.domain_name)
    for host in snapshots[0].hosts:
        if not isinstance(host, dict):
            continue
        record_type = str(host.get("type") or host.get("recordType") or "").strip().upper()
        if record_type not in {"A", "AAAA"}:
            continue
        host_name = str(host.get("hostName") or host.get("name") or host.get("host") or "").strip() or "@"
        if host_name != relative_host:
            continue
        try:
            if ipaddress.ip_address(str(host.get("address") or "").strip()) == edge_address:
                return True
        except ValueError:
            continue
    return False


def _relative_dns_host(fqdn: str, domain_name: str) -> str:
    fqdn = fqdn.rstrip(".").lower()
    domain_name = domain_name.rstrip(".").lower()
    if fqdn == domain_name:
        return "@"
    suffix = f".{domain_name}"
    if fqdn.endswith(suffix):
        return fqdn[: -len(suffix)]
    return fqdn


def _edge_public_ip(channel: dict[str, Any], overview: dict[str, Any]) -> str:
    edge = str(channel.get("edge") or "")
    for row in overview.get("sketchInfrastructure", []) if isinstance(overview, dict) else []:
        if not isinstance(row, dict):
            continue
        if str(row.get("hostname") or "") == edge and str(row.get("role") or "") == "edge":
            return str(row.get("publicIp") or "").strip()
    return ""


def _safe_command_display(command: list[str]) -> list[str]:
    return [str(part) for part in command]


def _assert_no_private_key_contents(value: Any) -> None:
    body = str(value)
    forbidden = ("BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY")
    leaked = [marker for marker in forbidden if marker in body]
    if leaked:
        raise InboundChannelCertificateValidationError([f"certificate job contains forbidden secret marker {leaked[0]}"])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
