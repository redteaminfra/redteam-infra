# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import base64
import json
import re
import os
import ipaddress
import hashlib
import secrets
import socket
import subprocess
import tempfile
import textwrap
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Protocol
from uuid import uuid4

from app.core.runtime import runtime_value, start_runtime_task
from app.domain import JobEvent
from app.integrations.digitalocean_validation import (
    DigitalOceanTransport,
    DigitalOceanValidationError,
    UrllibDigitalOceanTransport,
)
from app.integrations.ansible_disposable_validation import resolve_ansible_playbook
from app.integrations.linode_validation import LinodeTransport, LinodeValidationError, UrllibLinodeTransport
from app.services.credentials import (
    CredentialStoreLockedError,
    CredentialValidationError,
    resolve_credential_secret,
    resolve_default_credential_alias,
)
from app.services.engagement_dns import get_engagement_dns_workspace
from app.services.engagement_operations import get_operations_overview
from app.services.inbound_raw_route_plan import (
    InboundRawRoutePlanError,
    assert_raw_route_plan_available,
    validate_persisted_raw_route_plan,
)
from app.services.engagements import get_engagement
from app.services.provider_region_policy import (
    DEFAULT_ALLOWED_REGIONS,
    ProviderRegionPolicyValidationError,
    get_provider_region_policy,
    is_provider_region_allowed,
)
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.inspection_run_repository import (
    InspectionRunRepository,
    SqlAlchemyInspectionRunRepository,
    StoredInspectionRun,
)
from app.storage.observer_settings_repository import (
    DEFAULT_INSPECTOR_CHECK_FAMILIES,
    DEFAULT_INSPECTOR_MODE,
    DEFAULT_INSPECTOR_SCHEDULE_TIME_UTC,
    DEFAULT_INSPECTOR_SCHEDULE_WEEKDAYS,
    ObserverSettingsRepository,
    SqlAlchemyObserverSettingsRepository,
    StoredObserverSettings,
)
from app.storage.provider_resource_repository import (
    ProviderResourceRepository,
    SqlAlchemyProviderResourceRepository,
    StoredProviderResourceRecord,
    TERMINAL_RECORD_STATUSES,
    is_barragan_owned_record,
)
from app.integrations.managed_host_images import ManagedHostImageProfile, managed_host_image_profile
from app.services.managed_host_image_continuity import resolve_or_pin_profile_for_new_managed_host


OBSERVER_CHECK_ACTION = "observer_host_check"
INSPECTION_ACTION = "inspector_inspection"
INSPECTOR_READINESS_ACTION = "inspector_readiness"
INSPECTOR_CLEANUP_ACTION = "inspector_cleanup"
SUPPORTED_OBSERVER_PROVIDERS = {"linode", "digitalocean"}
DEFAULT_OBSERVER_SIZES = {"linode": "g6-nanode-1", "digitalocean": "s-1vcpu-1gb"}
DEFAULT_FORBIDDEN_TCP_PORTS = [2222, 5000, 5173, 5900]
LEGACY_DEFAULT_FORBIDDEN_TCP_PORTS = [22, 2222, 5000, 5173, 5900]
OBSERVER_RESOURCE_SOURCE = "barragan_observer_job"
INSPECTOR_RESOURCE_SOURCE = "barragan_inspector_job"
INSPECTOR_MODES = {"once", "regular", "continuous"}
INSPECTOR_TRIGGER_TYPES = {"manual", "scheduled", "mutation"}
INSPECTOR_WEEKDAYS = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
INSPECTOR_SCAN_TARGET_GROUPS = {"edges", "assigned-domains", "core-public-management"}
INSPECTOR_SCAN_MODES = {"tcp-connect"}
INSPECTOR_SCAN_TIMINGS = {"slow", "normal"}
INSPECTOR_ONCE_RETENTION_MINUTES = 30
INSPECTOR_SUPPORT_PREPARATION_VERSION = 1
INSPECTOR_ADMIN_IDENTITY_VERSION = 1
INSPECTOR_ADMIN_USER = "barragan"
INSPECTOR_DEFAULT_SUPPORT_PACKAGES = ("nmap",)
MAX_SSH_OUTPUT_CHARS = 20000
INSPECTOR_CHECK_EXECUTION_MAX_SECONDS = 3600
INSPECTOR_EGRESS_ENDPOINTS = ("https://ifconfig.me/ip", "https://icanhazip.com")
INSPECTOR_EGRESS_RESOLUTION_ATTEMPTS = 3

BackgroundRunner = Callable[[Callable[[], None]], None]
CredentialAliasResolver = Callable[[str], str | None]
CredentialSecretResolver = Callable[[str, str], str]


class ObserverSettingsValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("observer settings validation failed")
        self.errors = errors


class InspectorSettingsValidationError(ObserverSettingsValidationError):
    def __init__(self, errors: list[str]):
        super().__init__(errors)


class ObserverCheckValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("observer check validation failed")
        self.errors = errors


class InspectionValidationError(ObserverCheckValidationError):
    def __init__(self, errors: list[str]):
        super().__init__(errors)


class InspectorAddressCollisionError(InspectionValidationError):
    failure_class = "retired_target_address_reuse"
    next_action = "Run dedicated Inspector Cleanup, then explicitly retry teardown"

    def __init__(self, target_ids: list[str]):
        super().__init__(["Inspector public address collides with a retired endpoint"])
        self.target_ids = list(target_ids)


class InspectorReadinessError(InspectionValidationError):
    """An enabled continuous Inspector could not become a usable retained host."""


class InspectorCleanupValidationError(InspectionValidationError):
    """A guarded standalone Inspector cleanup could not be started."""


class ObserverProviderError(RuntimeError):
    pass


def resolve_inspector_management_source_cidr(*, max_attempts: int | None = None) -> str:
    """Resolve Barragan's egress /32 without accepting a single-source guess."""

    attempts = INSPECTOR_EGRESS_RESOLUTION_ATTEMPTS if max_attempts is None else max_attempts
    if type(attempts) is not int or not 1 <= attempts <= INSPECTOR_EGRESS_RESOLUTION_ATTEMPTS:
        raise ValueError("Inspector egress resolution attempt bound differs")
    last_error = ""
    for _attempt in range(attempts):
        values: list[str] = []
        try:
            for endpoint in INSPECTOR_EGRESS_ENDPOINTS:
                request = urllib.request.Request(endpoint, headers={"Accept": "text/plain"})
                with urllib.request.urlopen(request, timeout=10) as response:
                    value = response.read(128).decode("utf-8", errors="replace").strip()
                parsed = ipaddress.ip_address(value)
                if parsed.version != 4 or not parsed.is_global:
                    raise ValueError("response was not a global IPv4 address")
                values.append(str(parsed))
            if len(set(values)) == 1:
                return f"{values[0]}/32"
            last_error = "egress reflectors returned different IPv4 addresses"
        except (OSError, ValueError, urllib.error.URLError) as exc:
            last_error = str(exc)
        if _attempt + 1 < attempts:
            time.sleep(1)
    raise ObserverProviderError(f"could not verify Barragan Inspector SSH source address: {last_error or 'unknown error'}")


def _inspector_firewall_label(provider: str, name: str) -> str:
    # Provider labels are Internet-visible inventory metadata. Keep them opaque
    # and below Linode's 32-character limit.
    return f"bi-{provider[:2]}-{hashlib.sha256(name.encode('utf-8')).hexdigest()[:18]}"


def _inspector_firewall_tag(name: str) -> str:
    return f"bi-{hashlib.sha256(name.encode('utf-8')).hexdigest()[:20]}"


def _inspector_firewall_id(host: "ObserverHost", provider: str) -> str:
    firewall = dict(host.metadata or {}).get("providerFirewall")
    if not isinstance(firewall, dict) or firewall.get("provider") != provider:
        return ""
    return _text(firewall.get("resourceId"))


@dataclass(frozen=True)
class ObserverHost:
    provider: str
    resource_type: str
    resource_id: str
    name: str
    region: str
    public_ip: str
    ssh_user: str = "root"
    status: str = "running"
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "resourceType": self.resource_type,
            "resourceId": self.resource_id,
            "name": self.name,
            "region": self.region,
            "publicIp": self.public_ip,
            "sshUser": self.ssh_user,
            "status": self.status,
            "metadata": dict(self.metadata or {}),
        }


@dataclass(frozen=True)
class ObserverSshKey:
    private_key_path: str
    public_key: str
    cleanup_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class InspectorCreateStage:
    """Nonsecret provider mutation intent/receipt; tag names are not ownership proof."""

    provider: str
    resource_name: str
    stage: str
    point: str
    resource_id: str = ""
    firewall_id: str = ""
    droplet_id: str = ""
    tag_name: str = ""
    tag_exclusive: bool = False


@dataclass(frozen=True)
class InspectorStagedSubmission:
    """Nonsecret returned IDs only; submission is not readiness or ownership."""

    provider: str
    resource_name: str
    host_id: str
    firewall_id: str
    tag_name: str = ""
    tag_exclusive: bool = False


class InspectorCreateUncertainError(ObserverProviderError):
    """An opt-in create may have changed the provider; manual reconciliation is required."""


def _hooked_numeric_provider_id(value: Any) -> bool:
    return ((type(value) is int and value > 0)
            or (type(value) is str and re.fullmatch(r"[1-9][0-9]*", value) is not None))


def _hooked_firewall_provider_id(value: Any) -> bool:
    return (_hooked_numeric_provider_id(value)
            or (type(value) is str and len(value) <= 128
                and re.fullmatch(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+", value) is not None))


class ObserverProvider(Protocol):
    def create(
        self, *, token: str, name: str, region: str, size: str, public_key: str,
        stage_hook: Callable[[InspectorCreateStage], None] | None = None,
    ) -> ObserverHost:
        ...

    def destroy(self, *, token: str, host: ObserverHost) -> bool:
        ...


class ObserverRunner(Protocol):
    def run(self, *, host: ObserverHost, ssh_key: ObserverSshKey, spec: dict[str, Any]) -> dict[str, Any]:
        ...


def ensure_continuous_inspector_ready(
    engagement_id: str,
    *,
    requested_by: str = "deployment",
    settings_repository: ObserverSettingsRepository | None = None,
    job_repository: JobRepository | None = None,
    provider_resource_repository: ProviderResourceRepository | None = None,
    provider_factory: Callable[[str], ObserverProvider] | None = None,
    runner: ObserverRunner | None = None,
    ssh_key_factory: Callable[[str], ObserverSshKey] | None = None,
    credential_alias_resolver: CredentialAliasResolver | None = None,
    credential_secret_resolver: CredentialSecretResolver | None = None,
) -> dict[str, Any]:
    """Synchronously establish the retained Inspector required by continuous mode.

    This intentionally does not run public probes.  It is the deployment
    readiness boundary that makes a later mutation inspection possible even
    when the periodic scheduler is disabled (as it is in devtest).
    """
    from app.services.engagement_teardown import assert_engagement_mutation_allowed

    assert_engagement_mutation_allowed(engagement_id, repository=job_repository)
    engagement = get_engagement(engagement_id)
    if engagement is None:
        raise InspectorReadinessError(["engagement not found"])

    settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
    settings = _settings_for_engagement(engagement_id, repository=settings_repo)
    if not settings.enabled or settings.mode != "continuous":
        return {"required": False, "ready": True, "status": "not_required", "job": None}

    lifecycle_repo = job_repository or SqlAlchemyJobRepository()
    conflict = _running_inspector_lifecycle_job(lifecycle_repo, engagement_id)
    if conflict is not None and conflict.action != INSPECTOR_READINESS_ACTION:
        raise InspectorReadinessError([f"Inspector lifecycle operation {conflict.id} ({conflict.action}) is already {conflict.status}"])
    existing = _running_inspector_readiness_result(lifecycle_repo, engagement_id)
    if existing is not None:
        return {"required": True, "ready": False, "status": "running", **existing}

    host = _reusable_inspector_host(settings)
    effective_runner = runner or SshObserverRunner()
    effective_ssh_key_factory = ssh_key_factory or _generate_inspector_ssh_key
    replace_unreachable_host = False
    if host is not None and _inspector_support_baseline_current(host):
        if isinstance(effective_runner, SshObserverRunner):
            try:
                effective_runner.verify_access(
                    host=host,
                    ssh_key=effective_ssh_key_factory(f"reuse-{engagement_id}"),
                )
            except ObserverCheckValidationError:
                replace_unreachable_host = True
        if not replace_unreachable_host:
            # The SSH probe can outlive the initial teardown read. Recheck
            # before reporting a reusable host ready for further work.
            assert_engagement_mutation_allowed(engagement_id, repository=lifecycle_repo)
            return {
                "required": True,
                "ready": True,
                "status": "ready",
                "reused": True,
                "inspectorHost": host.to_dict(),
                "job": None,
            }

    alias_resolver = credential_alias_resolver or resolve_default_credential_alias
    secret_resolver = credential_secret_resolver or resolve_credential_secret
    alias = alias_resolver(settings.provider)
    if not alias:
        raise InspectorReadinessError([f"default {settings.provider} credential alias is required"])
    try:
        token = secret_resolver(settings.provider, alias)
    except CredentialStoreLockedError:
        raise
    except CredentialValidationError as exc:
        raise InspectorReadinessError(exc.errors) from exc

    repo = lifecycle_repo
    timestamp = _now()
    job = repo.insert_inspector_teardown_barrier(
        StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=INSPECTOR_READINESS_ACTION,
            status="running",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={
                "engagementId": engagement_id,
                "provider": settings.provider,
                "region": settings.region,
                "size": settings.size,
                "mode": settings.mode,
                "credentialAlias": alias,
                "replacesUnreachableInspector": replace_unreachable_host,
            },
            artifact_refs=[],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=None,
            events=[
                JobEvent(
                    1,
                    "info",
                    "continuous Inspector readiness started",
                    {"provider": settings.provider, "region": settings.region, "size": settings.size},
                )
            ],
        )
    )
    if job is None:
        raise InspectorReadinessError(["engagement teardown is active; Inspector readiness cannot start"])
    _assert_no_secret_material(job.to_detail().to_dict())
    completed = _finish_inspector_readiness_job(
        repo,
        settings_repo,
        provider_resource_repository or SqlAlchemyProviderResourceRepository(),
        job,
        engagement_id,
        engagement.name,
        settings,
        alias,
        token,
        _provider_factory_for_engagement(engagement_id, provider_factory),
        effective_runner,
        effective_ssh_key_factory,
        replace_unreachable_host=replace_unreachable_host,
    )
    return {
        "required": True,
        "ready": completed.status == "succeeded",
        "status": "ready" if completed.status == "succeeded" else "failed",
        "job": completed.to_detail().to_dict(),
    }


def get_observer_settings(
    engagement_id: str,
    *,
    repository: ObserverSettingsRepository | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    settings = _settings_for_engagement(engagement_id, repository=repository)
    return _settings_response(
        settings,
        configured=(repository or SqlAlchemyObserverSettingsRepository()).get(engagement_id) is not None,
        engagement_name=engagement.name,
        legacy_observer=True,
    )


def get_inspector_settings(
    engagement_id: str,
    *,
    repository: ObserverSettingsRepository | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    settings = _settings_for_engagement(engagement_id, repository=repository)
    return _settings_response(
        settings,
        configured=(repository or SqlAlchemyObserverSettingsRepository()).get(engagement_id) is not None,
        engagement_name=engagement.name,
    )


def update_observer_settings(
    engagement_id: str,
    body: dict[str, Any],
    *,
    repository: ObserverSettingsRepository | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    settings = _settings_from_body(engagement_id, body)
    saved = (repository or SqlAlchemyObserverSettingsRepository()).save(settings)
    return _settings_response(saved, configured=True, engagement_name=engagement.name, legacy_observer=True)


def update_inspector_settings(
    engagement_id: str,
    body: dict[str, Any],
    *,
    repository: ObserverSettingsRepository | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    settings = _settings_from_body(engagement_id, body)
    saved = (repository or SqlAlchemyObserverSettingsRepository()).save(settings)
    return _settings_response(saved, configured=True, engagement_name=engagement.name)


def preview_inspector_cleanup(
    engagement_id: str,
    *,
    settings_repository: ObserverSettingsRepository | None = None,
    provider_resource_repository: ProviderResourceRepository | None = None,
    job_repository: JobRepository | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    settings = _settings_for_engagement(
        engagement_id,
        repository=settings_repository or SqlAlchemyObserverSettingsRepository(),
    )
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    hosts = _inspector_hosts_for_cleanup(
        engagement_id,
        current_host=_inspector_host_from_settings(settings.current_host, settings=settings),
        settings=settings,
        repository=resources,
    )
    running = _running_inspector_lifecycle_job(job_repository or SqlAlchemyJobRepository(), engagement_id)
    return {
        "engagementId": engagement_id,
        "engagementName": engagement.name,
        "confirmationToken": inspector_cleanup_confirmation_token(engagement.name),
        "canDestroy": bool(hosts) and running is None,
        "blockers": (
            [f"Inspector lifecycle operation {running.id} ({running.action}) is already {running.status}"]
            if running is not None
            else ([] if hosts else ["No retained Barragan-owned Inspector resources are tracked"])
        ),
        "hosts": [_reviewable_inspector_host(host) for host in hosts],
        "resourceCount": sum(1 + len(_reviewable_inspector_children(host)) for host in hosts),
        "scope": {
            "inspectorOnly": True,
            "coreInfrastructure": False,
            "sketchInfrastructure": False,
            "channels": False,
            "dns": False,
            "certificates": False,
            "capabilities": False,
        },
    }


def start_inspector_cleanup(
    engagement_id: str,
    body: dict[str, Any],
    *,
    requested_by: str = "operator",
    settings_repository: ObserverSettingsRepository | None = None,
    job_repository: JobRepository | None = None,
    provider_resource_repository: ProviderResourceRepository | None = None,
    provider_factory: Callable[[str], ObserverProvider] | None = None,
    credential_alias_resolver: CredentialAliasResolver | None = None,
    credential_secret_resolver: CredentialSecretResolver | None = None,
    background_runner: BackgroundRunner | None = None,
) -> dict[str, Any] | None:
    from app.services.engagement_teardown import assert_engagement_mutation_allowed

    assert_engagement_mutation_allowed(engagement_id, repository=job_repository)
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    repo = job_repository or SqlAlchemyJobRepository()
    preview = preview_inspector_cleanup(
        engagement_id,
        settings_repository=settings_repository,
        provider_resource_repository=provider_resource_repository,
        job_repository=repo,
    )
    if preview is None:
        return None
    errors: list[str] = []
    if _text(body.get("confirmation")) != preview["confirmationToken"]:
        errors.append(f"confirmation must equal {preview['confirmationToken']}")
    errors.extend(preview["blockers"])
    if errors:
        raise InspectorCleanupValidationError(errors)

    timestamp = _now()
    job = repo.insert_inspector_teardown_barrier(
        StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=INSPECTOR_CLEANUP_ACTION,
            status="running",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={
                "engagementId": engagement_id,
                "mutation": True,
                "inspectorOnly": True,
                "resourceCount": preview["resourceCount"],
                "hosts": preview["hosts"],
            },
            artifact_refs=[],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=None,
            events=[JobEvent(1, "info", "inspector cleanup queued", {"resourceCount": preview["resourceCount"]})],
        )
    )
    if job is None:
        raise InspectorCleanupValidationError(["engagement teardown is active; Inspector cleanup cannot start"])
    _assert_no_secret_material(job.to_detail().to_dict())
    completed: StoredJobRun | None = None

    def run_cleanup() -> None:
        nonlocal completed
        active = _append_event(repo, job, "info", "inspector host cleanup started", {"hosts": preview["hosts"]})
        result = cleanup_inspector_for_infrastructure_teardown(
            engagement_id,
            engagement.name,
            job.id,
            settings_repository=settings_repository,
            provider_resource_repository=provider_resource_repository,
            provider_factory=provider_factory,
            credential_alias_resolver=credential_alias_resolver,
            credential_secret_resolver=credential_secret_resolver,
        )
        succeeded = bool(result.get("ok"))
        completed = repo.save(
            replace(
                _append_event(
                    repo,
                    active,
                    "info" if succeeded else "error",
                    "inspector host cleanup verified" if succeeded else "inspector host cleanup failed",
                    {"inspectorCleanup": result},
                ),
                status="succeeded" if succeeded else "failed",
                finished_at=_now(),
            )
        )

    (background_runner or _start_background_task)(run_cleanup)
    result_job = completed or job
    return {"job": result_job.to_detail().to_dict(), "status": result_job.status}


def cleanup_inspector_for_infrastructure_teardown(
    engagement_id: str,
    engagement_name: str,
    teardown_job_id: str,
    *,
    settings_repository: ObserverSettingsRepository | None = None,
    provider_resource_repository: ProviderResourceRepository | None = None,
    provider_factory: Callable[[str], ObserverProvider] | None = None,
    credential_alias_resolver: CredentialAliasResolver | None = None,
    credential_secret_resolver: CredentialSecretResolver | None = None,
) -> dict[str, Any]:
    settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    settings = _settings_for_engagement(engagement_id, repository=settings_repo)
    current_host = _inspector_host_from_settings(settings.current_host, settings=settings)
    hosts = _inspector_hosts_for_cleanup(
        engagement_id,
        current_host=current_host,
        settings=settings,
        repository=resources,
    )
    disabled = replace(
        settings,
        enabled=False,
        idle_retention_until="",
        updated_at=_now(),
    )
    if not hosts:
        saved = settings_repo.save(replace(disabled, current_host={}))
        return {
            "ok": True,
            "status": "disabled_no_host",
            "disabled": saved.enabled is False,
            "cleanupVerified": True,
            "currentHostCleared": True,
            "inspectorHost": {},
        }

    alias_resolver = credential_alias_resolver or resolve_default_credential_alias
    secret_resolver = credential_secret_resolver or resolve_credential_secret
    provider_builder = provider_factory or _provider_for
    errors: list[str] = []
    cleanup_results: dict[tuple[str, str], bool] = {}
    for host in hosts:
        provider_name = host.provider or settings.provider
        alias = alias_resolver(provider_name)
        cleanup_verified = False
        if not alias:
            errors.append(f"default {provider_name} credential alias is required to destroy Inspector host {host.resource_id}")
        else:
            try:
                token = secret_resolver(provider_name, alias)
                cleanup_verified = bool(provider_builder(provider_name).destroy(token=token, host=host))
            except CredentialStoreLockedError:
                errors.append(f"{provider_name} Inspector host {host.resource_id}: credential store is locked")
            except CredentialValidationError as exc:
                errors.extend(f"{provider_name} Inspector host {host.resource_id}: {error}" for error in exc.errors)
            except Exception as exc:
                errors.append(f"{provider_name} Inspector host {host.resource_id}: {_safe_cleanup_error(exc)}")

        cleanup_results[_inspector_host_key(host)] = cleanup_verified
        _record_inspector_resource(
            resources,
            engagement_id,
            engagement_name,
            host,
            teardown_job_id,
            status="destroyed" if cleanup_verified else "cleanup_required",
            destroyed=cleanup_verified,
        )

    cleanup_verified = all(cleanup_results.values())
    current_host_cleared = current_host is None or cleanup_results.get(_inspector_host_key(current_host), False)
    settings_repo.save(replace(disabled, current_host={} if current_host_cleared else settings.current_host))
    return {
        "ok": cleanup_verified,
        "status": "destroyed" if cleanup_verified else "cleanup_required",
        "disabled": True,
        "cleanupVerified": cleanup_verified,
        "currentHostCleared": current_host_cleared,
        "inspectorHost": (current_host or hosts[0]).to_dict(),
        "inspectorHosts": [host.to_dict() for host in hosts],
        "errors": errors,
    }


def verify_retired_public_endpoints_for_teardown(
    engagement_id: str,
    engagement_name: str,
    teardown_job_id: str,
    targets: list[dict[str, Any]],
    *,
    settings_repository: ObserverSettingsRepository | None = None,
    runner: ObserverRunner | None = None,
    ssh_key_factory: Callable[[str], ObserverSshKey] | None = None,
) -> dict[str, Any]:
    safe_targets = [_teardown_target(target) for target in targets]
    safe_targets = [target for target in safe_targets if target]
    if not safe_targets:
        return {
            "ok": True,
            "status": "skipped_no_targets",
            "engagementId": engagement_id,
            "engagementName": engagement_name,
            "teardownJobId": teardown_job_id,
            "targetCount": 0,
            "targets": [],
            "evidence": {},
        }

    settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
    settings = _settings_for_engagement(engagement_id, repository=settings_repo)
    host = _inspector_host_from_settings(settings.current_host, settings=settings)
    if host is None:
        return {
            "ok": False,
            "status": "inspector_unavailable",
            "engagementId": engagement_id,
            "engagementName": engagement_name,
            "teardownJobId": teardown_job_id,
            "targetCount": len(safe_targets),
            "targets": safe_targets,
            "evidence": {},
            "errors": ["retained Inspector host is required for teardown verification"],
        }
    if host.public_ip in _retired_target_public_ips(safe_targets):
        return {
            "ok": False, "status": "invalid_inspector_vantage",
            "failureClass": "retired_target_address_reuse",
            "engagementId": engagement_id, "engagementName": engagement_name,
            "teardownJobId": teardown_job_id, "targetCount": len(safe_targets),
            "targets": safe_targets, "evidence": {}, "inspectorHost": host.to_dict(),
            "errors": ["Inspector vantage address collides with a retired endpoint target"],
        }

    ssh_key = (ssh_key_factory or _generate_inspector_ssh_key)(teardown_job_id)
    evidence: dict[str, Any] = {}
    try:
        evidence = (runner or SshObserverRunner()).run(
            host=host,
            ssh_key=ssh_key,
            spec={"positive": [], "negative": safe_targets, "timeoutSeconds": 8},
        )
        ok = bool(evidence.get("ok"))
    except Exception as exc:
        evidence = {"ok": False, "errorType": type(exc).__name__, "detail": _safe_provider_error(exc)}
        ok = False
    return {
        "ok": ok,
        "status": "verified_absent" if ok else "verification_failed",
        "engagementId": engagement_id,
        "engagementName": engagement_name,
        "teardownJobId": teardown_job_id,
        "targetCount": len(safe_targets),
        "targets": safe_targets,
        "evidence": _safe_evidence(evidence),
        "inspectorHost": host.to_dict(),
    }


def inspector_state_for_infrastructure_teardown(
    engagement_id: str,
    *,
    settings_repository: ObserverSettingsRepository | None = None,
    provider_resource_repository: ProviderResourceRepository | None = None,
) -> dict[str, Any]:
    settings = _settings_for_engagement(
        engagement_id,
        repository=settings_repository or SqlAlchemyObserverSettingsRepository(),
    )
    owned_records = [
        record
        for record in (provider_resource_repository or SqlAlchemyProviderResourceRepository()).list_for_engagement(
            engagement_id
        )
        if is_barragan_owned_record(record)
        and _is_inspector_owned_resource_record(record)
        and record.status.lower() not in TERMINAL_RECORD_STATUSES
    ]
    host_records = [record for record in owned_records if _is_inspector_resource_record(record)]
    current_host = _inspector_host_from_settings(settings.current_host, settings=settings)
    candidates = [_inspector_host_from_resource_record(record, settings=settings) for record in host_records]
    host = next(
        (candidate for candidate in [current_host, *candidates] if _usable_inspector_host(candidate)),
        None,
    )
    tracked = bool(settings.current_host) or bool(owned_records)
    return {
        "tracked": tracked,
        "reusable": host is not None,
        "prepared": bool(host is not None and _inspector_support_baseline_current(host)),
        "status": host.status if host is not None else ("unusable" if tracked else "none"),
        "ownedProviderRecordIds": sorted(str(record.id) for record in owned_records),
    }


def ensure_inspector_for_infrastructure_teardown(
    engagement_id: str,
    engagement_name: str,
    teardown_job_id: str,
    *,
    settings_repository: ObserverSettingsRepository | None = None,
    provider_resource_repository: ProviderResourceRepository | None = None,
    provider_factory: Callable[[str], ObserverProvider] | None = None,
    runner: ObserverRunner | None = None,
    ssh_key_factory: Callable[[str], ObserverSshKey] | None = None,
    credential_alias_resolver: CredentialAliasResolver | None = None,
    credential_secret_resolver: CredentialSecretResolver | None = None,
    retired_targets: list[dict[str, Any]] | None = None,
    resource_name: str | None = None,
) -> dict[str, Any]:
    """Ensure teardown has a retained, reachable, prepared external Inspector."""

    if (resource_name is not None
            and (type(resource_name) is not str
                 or re.fullmatch(r"inspector-[0-9a-f]{32}", resource_name) is None)):
        raise InspectionValidationError(["Inspector resource name must be opaque and canonical"])

    settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    settings = _settings_for_engagement(engagement_id, repository=settings_repo)
    records = list(resources.list_for_engagement(engagement_id))
    current_host = _inspector_host_from_settings(settings.current_host, settings=settings)
    matching_current = [
        record
        for record in records
        if current_host is not None
        and is_barragan_owned_record(record)
        and _is_inspector_resource_record(record)
        and _inspector_host_key(_inspector_host_from_resource_record(record, settings=settings))
        == _inspector_host_key(current_host)
    ]
    if matching_current and all(record.status.lower() in TERMINAL_RECORD_STATUSES for record in matching_current):
        current_host = None
    active_inspector_records = [
        record
        for record in records
        if is_barragan_owned_record(record)
        and _is_inspector_resource_record(record)
        and record.status.lower() not in TERMINAL_RECORD_STATUSES
    ]
    candidates = [
        _inspector_host_from_resource_record(record, settings=settings)
        for record in active_inspector_records
    ]
    if current_host is not None:
        exact = [record for record in active_inspector_records if _inspector_host_key(
            _inspector_host_from_resource_record(record, settings=settings)
        ) == _inspector_host_key(current_host)
            and record.provider.strip().lower() == current_host.provider.strip().lower()
            and record.resource_type == f"inspector_{current_host.resource_type}"]
        if len(exact) != 1:
            raise InspectionValidationError(["Inspector teardown preflight requires one explicit owned retained-host record"])
        host = current_host if _usable_inspector_host(current_host) else None
    else:
        usable = [(record, candidate) for record, candidate in zip(active_inspector_records, candidates) if _usable_inspector_host(candidate)]
        if len(usable) > 1:
            raise InspectionValidationError(["Inspector teardown preflight found ambiguous owned retained hosts"])
        host = usable[0][1] if usable else None
    if host is None and active_inspector_records:
        raise InspectionValidationError(
            ["active Barragan-owned Inspector record has no usable public IPv4 address; reconcile it before retrying teardown"]
        )
    created = False
    credential_alias = ""
    if host is None:
        credential_alias = (credential_alias_resolver or resolve_default_credential_alias)(settings.provider) or ""
        if not credential_alias:
            raise InspectionValidationError([f"default {settings.provider} credential alias is required for Inspector teardown preflight"])
        try:
            token = (credential_secret_resolver or resolve_credential_secret)(settings.provider, credential_alias)
        except CredentialStoreLockedError as exc:
            raise InspectionValidationError(["Inspector credential store is locked during teardown preflight"]) from exc
        except CredentialValidationError as exc:
            raise InspectionValidationError(exc.errors) from exc
        ssh_key = (ssh_key_factory or _generate_inspector_ssh_key)(teardown_job_id)
        try:
            host = _provider_factory_for_engagement(engagement_id, provider_factory)(settings.provider).create(
                token=token,
                name=(resource_name if resource_name is not None
                      else _inspector_host_name(engagement_name, teardown_job_id)),
                region=settings.region,
                size=settings.size,
                public_key=ssh_key.public_key,
            )
        except Exception as exc:
            raise InspectionValidationError([f"Inspector host creation failed: {_safe_provider_error(exc)}"]) from exc
        created = True
        _record_inspector_resource(resources, engagement_id, engagement_name, host, teardown_job_id, status="active")
        settings = settings_repo.save(replace(settings, current_host=host.to_dict(), updated_at=_now()))
    else:
        ssh_key = (ssh_key_factory or _generate_inspector_ssh_key)(teardown_job_id)
        settings = settings_repo.save(replace(settings, current_host=host.to_dict(), updated_at=_now()))

    if host.public_ip in _retired_target_public_ips(retired_targets or []):
        raise InspectorAddressCollisionError([
            str(target.get("id") or "") for target in (retired_targets or [])
            if isinstance(target, dict)
        ])

    preparer = runner or SshObserverRunner()
    prepare_support_host = getattr(preparer, "prepare_support_host", None)
    if not callable(prepare_support_host):
        raise InspectionValidationError(["Inspector support-host preparation is unavailable"])
    try:
        host = prepare_support_host(
            host=host,
            ssh_key=ssh_key,
            packages=INSPECTOR_DEFAULT_SUPPORT_PACKAGES,
        )
    except ObserverCheckValidationError:
        raise
    except Exception as exc:
        raise InspectionValidationError([f"Inspector support-host preparation failed: {_safe_provider_error(exc)}"]) from exc
    settings_repo.save(replace(settings, current_host=host.to_dict(), updated_at=_now()))
    return {
        "ok": True,
        "status": "created_prepared" if created else "reused_prepared",
        "created": created,
        "credentialAlias": credential_alias,
        "inspectorHost": host.to_dict(),
    }


def _retired_target_public_ips(targets: list[dict[str, Any]]) -> frozenset[str]:
    values: set[str] = set()
    for target in targets:
        if not isinstance(target, dict):
            continue
        candidates = [target.get("expectedIp")]
        if _text(target.get("type")) == "tcp-forbidden":
            candidates.append(target.get("host"))
        for candidate in candidates:
            try:
                address = ipaddress.ip_address(_text(candidate))
            except ValueError:
                continue
            if address.version == 4:
                values.add(str(address))
    return frozenset(values)


def _teardown_target(target: dict[str, Any]) -> dict[str, Any]:
    target_type = _text(target.get("type"))
    host = _text(target.get("host"))
    if target_type == "tcp-forbidden":
        port = _port(target.get("port"))
        if not host or port is None:
            return {}
        return {
            key: value
            for key, value in {
                "id": _text(target.get("id")) or f"{host}:{port}",
                "type": "tcp-forbidden",
                "host": host,
                "port": port,
                "edge": _text(target.get("edge")),
                "protocol": _text(target.get("protocol")),
                "targetGroup": _text(target.get("targetGroup")),
                "service": _text(target.get("service")),
                "purpose": _text(target.get("purpose")),
            }.items()
            if value not in {"", None}
        }
    if target_type == "dns-absent":
        if not host:
            return {}
        return {
            key: value
            for key, value in {
                "id": _text(target.get("id")) or f"dns:{host}",
                "type": "dns-absent",
                "host": host,
                "expectedIp": _text(target.get("expectedIp")),
                "channelId": _text(target.get("channelId")),
            }.items()
            if value not in {"", None}
        }
    return {}


def _inspector_hosts_for_cleanup(
    engagement_id: str,
    *,
    current_host: ObserverHost | None,
    settings: StoredObserverSettings,
    repository: ProviderResourceRepository,
) -> list[ObserverHost]:
    hosts: list[ObserverHost] = []
    seen: set[tuple[str, str]] = set()
    if current_host is not None:
        hosts.append(current_host)
        seen.add(_inspector_host_key(current_host))
    for record in repository.list_active():
        if (
            record.engagement_id != engagement_id
            or not is_barragan_owned_record(record)
            or not _is_inspector_resource_record(record)
        ):
            continue
        host = _inspector_host_from_resource_record(record, settings=settings)
        key = _inspector_host_key(host)
        if key in seen:
            continue
        hosts.append(host)
        seen.add(key)
    return hosts


def _is_inspector_resource_record(record: StoredProviderResourceRecord) -> bool:
    return (
        record.resource_type.startswith("inspector_")
        and record.resource_type != "inspector_firewall"
    ) or str(record.metadata.get("role") or "").lower() == "inspector"


def _is_inspector_owned_resource_record(record: StoredProviderResourceRecord) -> bool:
    return record.resource_type.startswith("inspector_") or str(
        record.metadata.get("role") or ""
    ).lower().startswith("inspector")


def _inspector_host_from_resource_record(
    record: StoredProviderResourceRecord,
    *,
    settings: StoredObserverSettings,
) -> ObserverHost:
    metadata = dict(record.metadata or {})
    public_ips = metadata.get("publicIps") if isinstance(metadata.get("publicIps"), list) else []
    public_ip = str(metadata.get("publicIp") or (public_ips[0] if public_ips else ""))
    resource_type = record.resource_type.removeprefix("inspector_") or "instance"
    return ObserverHost(
        provider=record.provider or settings.provider,
        resource_type=resource_type,
        resource_id=record.resource_id,
        name=record.name,
        region=record.region or settings.region,
        public_ip=public_ip,
        ssh_user=str(metadata.get("sshUser") or "root"),
        status=record.status or "running",
        metadata=metadata,
    )


def _inspector_host_key(host: ObserverHost) -> tuple[str, str]:
    return (host.provider.strip().lower(), host.resource_id.strip())


def _reviewable_inspector_children(host: ObserverHost) -> list[dict[str, Any]]:
    firewall = dict(host.metadata or {}).get("providerFirewall")
    if not isinstance(firewall, dict):
        return []
    resource_id = _text(firewall.get("resourceId"))
    tag = _text(firewall.get("tag"))
    children: list[dict[str, Any]] = []
    if resource_id:
        children.append(
            {
                "provider": host.provider,
                "resourceType": "firewall",
                "resourceId": resource_id,
                "name": _text(firewall.get("name")),
            }
        )
    if tag:
        children.append(
            {
                "provider": host.provider,
                "resourceType": "provider-tag",
                "resourceId": tag,
                "name": tag,
            }
        )
    return children


def _reviewable_inspector_host(host: ObserverHost) -> dict[str, Any]:
    return {
        "provider": host.provider,
        "resourceType": host.resource_type,
        "resourceId": host.resource_id,
        "name": host.name,
        "region": host.region,
        "publicIp": host.public_ip,
        "status": host.status,
        "associatedResources": _reviewable_inspector_children(host),
    }


def _usable_inspector_host(host: ObserverHost | None) -> bool:
    if host is None or not host.resource_id:
        return False
    try:
        return ipaddress.ip_address(host.public_ip).version == 4
    except ValueError:
        return False


def start_observer_check(
    engagement_id: str,
    body: dict[str, Any],
    *,
    requested_by: str = "operator",
    settings_repository: ObserverSettingsRepository | None = None,
    job_repository: JobRepository | None = None,
    provider_resource_repository: ProviderResourceRepository | None = None,
    provider_factory: Callable[[str], ObserverProvider] | None = None,
    runner: ObserverRunner | None = None,
    ssh_key_factory: Callable[[str], ObserverSshKey] | None = None,
    credential_alias_resolver: CredentialAliasResolver | None = None,
    credential_secret_resolver: CredentialSecretResolver | None = None,
    background_runner: BackgroundRunner | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None

    expected_confirmation = observer_confirmation_token(engagement.name)
    if str(body.get("confirmation") or "").strip() != expected_confirmation:
        raise ObserverCheckValidationError([f"confirmation must be {expected_confirmation}"])

    settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
    stored_settings = settings_repo.get(engagement_id)
    if stored_settings is None:
        raise ObserverCheckValidationError(["observer host settings must be saved before running a check"])
    settings = _settings_for_engagement(engagement_id, repository=settings_repo)
    targets = observer_check_targets(engagement_id)
    if not targets["positive"] and not targets["negative"]:
        raise ObserverCheckValidationError(["no deployed inbound channels, DNS records, or edge public IPs are available to validate"])

    alias_resolver = credential_alias_resolver or resolve_default_credential_alias
    secret_resolver = credential_secret_resolver or resolve_credential_secret
    alias = alias_resolver(settings.provider)
    if not alias:
        raise ObserverCheckValidationError([f"default {settings.provider} credential alias is required"])

    try:
        token = secret_resolver(settings.provider, alias)
    except CredentialStoreLockedError:
        raise
    except CredentialValidationError as exc:
        raise ObserverCheckValidationError(exc.errors) from exc

    repo = job_repository or SqlAlchemyJobRepository()
    timestamp = _now()
    job = repo.save(
        StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=OBSERVER_CHECK_ACTION,
            status="running",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={
                "engagementId": engagement_id,
                "mutation": True,
                "provider": settings.provider,
                "region": settings.region,
                "size": settings.size,
                "credentialAlias": alias,
                "confirmation": "redacted",
                "targetCount": len(targets["positive"]) + len(targets["negative"]),
            },
            artifact_refs=[],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=None,
            events=[
                JobEvent(
                    1,
                    "info",
                    "observer host check queued",
                    {
                        "provider": settings.provider,
                        "region": settings.region,
                        "size": settings.size,
                        "credentialAlias": alias,
                        "targets": _target_summary(targets),
                        "opsecBoundary": {
                            "directEdgeProbeFromBarraganHost": False,
                            "publicProbeOrigin": "ephemeral observer host",
                        },
                    },
                )
            ],
        )
    )
    _assert_no_secret_material(job.to_detail().to_dict())

    completed: StoredJobRun | None = None

    def run_check() -> None:
        nonlocal completed
        completed = _finish_observer_check_job(
            repo,
            provider_resource_repository or SqlAlchemyProviderResourceRepository(),
            job,
            engagement_id,
            engagement.name,
            settings,
            alias,
            token,
            targets,
            _provider_factory_for_engagement(engagement_id, provider_factory),
            runner or SshObserverRunner(),
            ssh_key_factory or _generate_observer_ssh_key,
        )

    (background_runner or _start_background_task)(run_check)
    result_job = completed or job
    return {"job": result_job.to_detail().to_dict(), "status": result_job.status}


def start_inspection(
    engagement_id: str,
    body: dict[str, Any],
    *,
    requested_by: str = "operator",
    settings_repository: ObserverSettingsRepository | None = None,
    job_repository: JobRepository | None = None,
    inspection_repository: InspectionRunRepository | None = None,
    provider_resource_repository: ProviderResourceRepository | None = None,
    provider_factory: Callable[[str], ObserverProvider] | None = None,
    runner: ObserverRunner | None = None,
    ssh_key_factory: Callable[[str], ObserverSshKey] | None = None,
    credential_alias_resolver: CredentialAliasResolver | None = None,
    credential_secret_resolver: CredentialSecretResolver | None = None,
    background_runner: BackgroundRunner | None = None,
) -> dict[str, Any] | None:
    from app.services.engagement_teardown import assert_engagement_mutation_allowed

    assert_engagement_mutation_allowed(engagement_id, repository=job_repository)
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None

    trigger_type = _text(body.get("triggerType") or "manual").lower()
    if trigger_type not in INSPECTOR_TRIGGER_TYPES:
        raise InspectionValidationError(["triggerType must be manual, scheduled, or mutation"])

    settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
    settings = _settings_for_engagement(engagement_id, repository=settings_repo)
    if not settings.enabled:
        raise InspectionValidationError(["inspector is disabled for this engagement"])

    repo = job_repository or SqlAlchemyJobRepository()
    conflict = _running_inspector_lifecycle_job(repo, engagement_id)
    if conflict is not None and conflict.action != INSPECTION_ACTION:
        raise InspectionValidationError([f"Inspector lifecycle operation {conflict.id} ({conflict.action}) is already {conflict.status}"])
    inspection_repo = inspection_repository or SqlAlchemyInspectionRunRepository()
    existing = _running_inspection_result(repo, inspection_repo, engagement_id)
    if existing is not None:
        return existing

    targets = inspection_targets(engagement_id, settings_repository=settings_repo)
    if not targets["positive"] and not targets["negative"]:
        raise InspectionValidationError(["no deployed inbound channels, DNS records, or edge public IPs are available to inspect"])

    alias_resolver = credential_alias_resolver or resolve_default_credential_alias
    secret_resolver = credential_secret_resolver or resolve_credential_secret
    alias = alias_resolver(settings.provider)
    if not alias:
        raise InspectionValidationError([f"default {settings.provider} credential alias is required"])

    try:
        token = secret_resolver(settings.provider, alias)
    except CredentialStoreLockedError:
        raise
    except CredentialValidationError as exc:
        raise InspectionValidationError(exc.errors) from exc

    timestamp = _now()
    job = repo.insert_inspector_teardown_barrier(
        StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=INSPECTION_ACTION,
            status="running",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={
                "engagementId": engagement_id,
                "mutation": True,
                "provider": settings.provider,
                "region": settings.region,
                "size": settings.size,
                "mode": settings.mode,
                "triggerType": trigger_type,
                "credentialAlias": alias,
                "targetCount": len(targets["positive"]) + len(targets["negative"]),
            },
            artifact_refs=[],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=None,
            events=[
                JobEvent(
                    1,
                    "info",
                    "inspection queued",
                    {
                        "provider": settings.provider,
                        "region": settings.region,
                        "size": settings.size,
                        "mode": settings.mode,
                        "triggerType": trigger_type,
                        "credentialAlias": alias,
                        "targets": _target_summary(targets),
                        "opsecBoundary": {
                            "directEdgeProbeFromBarraganHost": False,
                            "publicProbeOrigin": "inspector host",
                        },
                    },
                )
            ],
        )
    )
    if job is None:
        raise InspectionValidationError(["engagement teardown is active; inspection cannot start"])
    run = inspection_repo.save(
        StoredInspectionRun(
            id=f"insp-{uuid4().hex[:12]}",
            engagement_id=engagement_id,
            job_id=job.id,
            trigger_type=trigger_type,
            mode=settings.mode,
            status="running",
            provider=settings.provider,
            region=settings.region,
            host={},
            targets=_target_summary(targets),
            evidence={},
            findings=[],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=None,
        )
    )
    _assert_no_secret_material(job.to_detail().to_dict())

    completed: StoredJobRun | None = None

    def run_inspection() -> None:
        nonlocal completed
        completed = _finish_inspection_job(
            repo,
            inspection_repo,
            settings_repo,
            provider_resource_repository or SqlAlchemyProviderResourceRepository(),
            job,
            run,
            engagement_id,
            engagement.name,
            settings,
            alias,
            token,
            targets,
            _provider_factory_for_engagement(engagement_id, provider_factory),
            runner or SshObserverRunner(),
            ssh_key_factory or _generate_inspector_ssh_key,
        )

    (background_runner or _start_background_task)(run_inspection)
    result_job = completed or job
    result_inspection = inspection_repo.get(run.id) or run
    return {"job": result_job.to_detail().to_dict(), "status": result_job.status, "inspection": result_inspection.to_dict()}


def _running_inspection_result(
    repo: JobRepository,
    inspection_repo: InspectionRunRepository,
    engagement_id: str,
) -> dict[str, Any] | None:
    for job in repo.list_for_engagement(engagement_id):
        if job.action != INSPECTION_ACTION:
            continue
        if job.status not in {"queued", "running"}:
            continue
        inspection = next(
            (
                run
                for run in inspection_repo.list_for_engagement(engagement_id)
                if run.job_id == job.id and run.status in {"queued", "running"}
            ),
            None,
        )
        if inspection is None:
            inspection = StoredInspectionRun(
                id=f"insp-{job.id}",
                engagement_id=engagement_id,
                job_id=job.id,
                trigger_type=_text(job.input.get("triggerType") or "manual"),
                mode=_text(job.input.get("mode") or DEFAULT_INSPECTOR_MODE),
                status=job.status,
                provider=_text(job.input.get("provider")),
                region=_text(job.input.get("region")),
                host={},
                targets={},
                evidence={},
                findings=[],
                created_at=job.created_at,
                started_at=job.started_at,
                finished_at=job.finished_at,
            )
        return {
            "job": job.to_detail().to_dict(),
            "status": job.status,
            "inspection": inspection.to_dict(),
            "idempotent": True,
        }
    return None


def _running_inspector_readiness_result(repo: JobRepository, engagement_id: str) -> dict[str, Any] | None:
    for job in repo.list_for_engagement(engagement_id):
        if job.action != INSPECTOR_READINESS_ACTION or job.status not in {"queued", "running"}:
            continue
        return {"job": job.to_detail().to_dict(), "idempotent": True}
    return None


def _running_inspector_lifecycle_job(repo: JobRepository, engagement_id: str) -> StoredJobRun | None:
    for job in repo.list_for_engagement(engagement_id):
        if job.action not in {INSPECTION_ACTION, INSPECTOR_READINESS_ACTION, INSPECTOR_CLEANUP_ACTION}:
            continue
        if job.status in {"queued", "running"}:
            return job
    return None


def list_inspections(
    engagement_id: str,
    *,
    repository: InspectionRunRepository | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    return {"inspections": [run.to_dict() for run in (repository or SqlAlchemyInspectionRunRepository()).list_for_engagement(engagement_id)]}


def inspector_confirmation_token(engagement_name: str) -> str:
    slug = "".join(character.lower() if character.isalnum() else "-" for character in engagement_name.strip())
    slug = "-".join(part for part in slug.split("-") if part)
    return f"inspect-{slug or 'engagement'}"


def inspector_cleanup_confirmation_token(engagement_name: str) -> str:
    slug = "".join(character.lower() if character.isalnum() else "-" for character in engagement_name.strip())
    slug = "-".join(part for part in slug.split("-") if part)
    return f"destroy-inspector-{slug or 'engagement'}"


def observer_confirmation_token(engagement_name: str) -> str:
    slug = "".join(character.lower() if character.isalnum() else "-" for character in engagement_name.strip())
    slug = "-".join(part for part in slug.split("-") if part)
    return f"observer-{slug or 'engagement'}"


def inspection_targets(
    engagement_id: str,
    *,
    settings_repository: ObserverSettingsRepository | None = None,
) -> dict[str, list[dict[str, Any]]]:
    targets = observer_check_targets(engagement_id)
    settings = _settings_for_engagement(engagement_id, repository=settings_repository)
    if settings.port_scan_profiles:
        targets["positive"] = [*targets["positive"], *_port_scan_targets(engagement_id, settings.port_scan_profiles)]
    return targets


def observer_check_targets(engagement_id: str) -> dict[str, list[dict[str, Any]]]:
    overview = get_operations_overview(engagement_id, include_provider_findings=False) or {}
    settings = _settings_for_engagement(engagement_id)
    edges = _edge_public_ips(overview)
    middles = _sketch_public_ips(overview, role="middle")
    core_by_hostname = _core_public_ips_by_hostname(overview)
    assigned_domains = _assigned_domain_names(engagement_id)
    positive: list[dict[str, Any]] = []
    expected_public_tcp_ports_by_ip: dict[str, set[int]] = {}
    raw_route_negative: list[dict[str, Any]] = []

    for channel in _real_inbound_channels(overview):
        edge_name = _text(channel.get("edge"))
        edge = _resolve_channel_sketch_component(channel, edges, role="edge")
        if edge is None:
            continue
        external_port = _port(channel.get("externalPort"))
        if external_port is None:
            continue
        protocol = _text(channel.get("protocol") or "TCP").upper()
        assigned_channel_domain = _assigned_channel_domain(channel.get("domain"), assigned_domains)
        display_host = assigned_channel_domain or edge["publicIp"]
        connect_host = edge["publicIp"]
        profile_type = _validation_profile_type(channel)
        looks_http = _looks_http_channel(channel)
        http_host_header = assigned_channel_domain or _channel_http_host_header(channel.get("domain")) or display_host
        target_base = {
            "id": _text(channel.get("channelId")) or f"{edge_name}:{external_port}",
            "channelId": _text(channel.get("channelId")),
            "edge": edge_name,
            "edgePublicIp": edge["publicIp"],
            "host": display_host,
            "connectHost": connect_host,
            "hostHeader": display_host,
            "port": external_port,
            "protocol": protocol,
            "purpose": _text(channel.get("purpose")),
            "service": _text(channel.get("service")),
        }
        raw_plan = channel.get("rawRoutePlan")
        if isinstance(raw_plan, dict):
            try:
                raw_plan = validate_persisted_raw_route_plan(
                    channel,
                    raw_plan,
                    infrastructure=overview,
                )
                assert_raw_route_plan_available(
                    raw_plan,
                    list(overview.get("inboundChannels", [])),
                    exclude_channel_id=_text(channel.get("channelId")),
                )
            except InboundRawRoutePlanError as exc:
                raise ObserverCheckValidationError(exc.errors) from exc
            target_base["routeFingerprint"] = _text(raw_plan.get("routeFingerprint"))
            target_base["infrastructureFingerprint"] = _text(raw_plan.get("infrastructureFingerprint"))
        if protocol == "UDP":
            if profile_type == "manual":
                continue
            positive.append(
                {
                    **target_base,
                    "type": "udp",
                    "requestText": _validation_profile_text(channel, "requestText") or "barragan-observer-udp",
                    "expectedResponse": _validation_expected(channel),
                }
            )
        else:
            expected_public_tcp_ports_by_ip.setdefault(edge["publicIp"], set()).add(external_port)
            positive.append({**target_base, "type": "tcp"})
            if profile_type == "tcp-send-receive" and not looks_http:
                positive.append(
                    {
                        **target_base,
                        "type": "tcp-send-expect",
                        "requestText": _validation_profile_text(channel, "requestText"),
                        "expectedResponse": _validation_expected(channel),
                    }
                )
            if profile_type == "http" or looks_http:
                positive.append(
                    {
                        **target_base,
                        "type": "https" if protocol == "HTTPS" else "http",
                        "hostHeader": http_host_header,
                        "path": "/",
                        "expectedResponse": _http_validation_expected(channel),
                    }
                )
        if assigned_channel_domain:
            positive.append(
                {
                    "id": f"dns:{assigned_channel_domain}:{edge['publicIp']}",
                    "type": "dns",
                    "host": assigned_channel_domain,
                    "expectedIp": edge["publicIp"],
                    "channelId": _text(channel.get("channelId")),
                }
            )
        if isinstance(raw_plan, dict):
            control_id = target_base["id"]
            middle = _resolve_channel_sketch_component(channel, middles, role="middle")
            for role, endpoint_name, address in (
                (
                    "middle",
                    "middleRelay",
                    middle.get("publicIp") if middle else "",
                ),
                (
                    "proxy",
                    "proxyRelay",
                    core_by_hostname.get(_text((raw_plan.get("proxyRelay") or {}).get("host"))),
                ),
                (
                    "termination",
                    "termination",
                    core_by_hostname.get(_text((raw_plan.get("termination") or {}).get("host"))),
                ),
            ):
                endpoint = raw_plan.get(endpoint_name)
                port = _port(endpoint.get("port")) if isinstance(endpoint, dict) else None
                if not address or port is None:
                    continue
                raw_route_negative.append(
                    {
                        "id": f"raw-isolation:{target_base['channelId']}:{role}:{protocol.lower()}:{port}",
                        "type": "udp-forbidden" if protocol == "UDP" else "tcp-forbidden",
                        "channelId": target_base["channelId"],
                        "host": address,
                        "port": port,
                        "protocol": protocol,
                        "role": role,
                        "controlId": control_id,
                        "routeFingerprint": target_base.get("routeFingerprint", ""),
                        "infrastructureFingerprint": target_base.get("infrastructureFingerprint", ""),
                        "requestText": _validation_profile_text(channel, "requestText") or "barragan-observer-udp",
                    }
                )

    positive.extend(_dns_record_targets(engagement_id, edges))

    negative = []
    for edge in edges:
        expected_ports = expected_public_tcp_ports_by_ip.get(edge["publicIp"], set())
        for port in settings.forbidden_tcp_ports:
            if port in expected_ports:
                continue
            negative.append(
                {
                    "id": (
                        f"forbidden:{edge.get('chainId') or 'legacy'}:"
                        f"{edge.get('componentId') or edge['hostname']}:{port}"
                    ),
                    "type": "tcp-forbidden",
                    "host": edge["publicIp"],
                    "port": port,
                    "edge": edge["hostname"],
                    "edgePublicIp": edge["publicIp"],
                }
            )
    return {"positive": positive, "negative": [*raw_route_negative, *negative]}


class LinodeObserverProvider:
    def __init__(
        self,
        *,
        transport: LinodeTransport | None = None,
        poll_attempts: int = 30,
        poll_delay_seconds: float = 5.0,
        management_source_resolver: Callable[[], str] = resolve_inspector_management_source_cidr,
        image: str | None = None,
    ):
        self.transport = transport or UrllibLinodeTransport()
        self.poll_attempts = poll_attempts
        self.poll_delay_seconds = poll_delay_seconds
        self.management_source_resolver = management_source_resolver
        self.image = image or managed_host_image_profile().linode_image

    def create(
        self, *, token: str, name: str, region: str, size: str, public_key: str,
        stage_hook: Callable[[InspectorCreateStage], None] | None = None,
    ) -> ObserverHost:
        return self._create(
            token=token, name=name, region=region, size=size, public_key=public_key,
            stage_hook=stage_hook, submit_only=False,
        )

    def submit_staged_inspector(
        self, *, token: str, name: str, region: str, size: str, public_key: str,
        stage_hook: Callable[[InspectorCreateStage], None],
    ) -> InspectorStagedSubmission:
        return self._create(
            token=token, name=name, region=region, size=size, public_key=public_key,
            stage_hook=stage_hook, submit_only=True,
        )

    def _create(
        self, *, token: str, name: str, region: str, size: str, public_key: str,
        stage_hook: Callable[[InspectorCreateStage], None] | None,
        submit_only: bool,
    ) -> ObserverHost | InspectorStagedSubmission:
        if submit_only and stage_hook is None:
            raise ObserverProviderError("staged Inspector submission requires a durable stage hook")
        if (stage_hook is not None and (type(name) is not str
                or re.fullmatch(r"inspector-[0-9a-f]{32}", name) is None)):
            raise ObserverProviderError("hooked Inspector name must be opaque and canonical")
        source_cidr = self.management_source_resolver()
        firewall_label = _inspector_firewall_label("linode", name)
        firewall_id = ""
        linode_id = ""
        body = {
            "label": name,
            "region": region,
            "type": size,
            "image": self.image,
            "root_pass": _observer_root_password(),
            "authorized_keys": [public_key],
            "metadata": {
                "user_data": base64.b64encode(_observer_cloud_init(public_key).encode("utf-8")).decode("ascii")
            },
            "tags": ["barragan", "inspector"],
        }
        try:
            if stage_hook is not None:
                stage_hook(InspectorCreateStage("linode", name, "firewall", "before_post"))
            firewall = self.transport.request(
                "POST",
                "/networking/firewalls",
                token,
                {
                    "label": firewall_label,
                    "rules": {
                        "inbound_policy": "DROP",
                        "outbound_policy": "ACCEPT",
                        "inbound": [
                            {
                                "action": "ACCEPT",
                                "protocol": "TCP",
                                "ports": "22",
                                "addresses": {"ipv4": [source_cidr]},
                            }
                        ],
                        "outbound": [],
                    },
                },
            )
            raw_firewall_id = firewall["id"]
            if stage_hook is not None and not _hooked_numeric_provider_id(raw_firewall_id):
                raise ValueError("firewall ID missing or malformed")
            firewall_id = str(raw_firewall_id)
            if stage_hook is not None:
                stage_hook(InspectorCreateStage(
                    "linode", name, "firewall", "response_received", resource_id=firewall_id))
            body["firewall_id"] = int(firewall_id)
            if stage_hook is not None:
                stage_hook(InspectorCreateStage(
                    "linode", name, "instance", "before_post", firewall_id=firewall_id))
            created = self.transport.request("POST", "/linode/instances", token, body)
            raw_linode_id = created["id"]
            if stage_hook is not None and not _hooked_numeric_provider_id(raw_linode_id):
                raise ValueError("instance ID missing or malformed")
            linode_id = str(raw_linode_id)
            if stage_hook is not None:
                stage_hook(InspectorCreateStage(
                    "linode", name, "instance", "response_received",
                    resource_id=linode_id, firewall_id=firewall_id))
            if submit_only:
                return InspectorStagedSubmission("linode", name, linode_id, firewall_id)
            inspected = self._wait_for_instance(token, linode_id, created)
        except Exception as exc:
            if stage_hook is not None:
                raise InspectorCreateUncertainError(
                    "Inspector create result is uncertain; explicit provider reconciliation is required"
                ) from None
            if linode_id:
                try:
                    self.transport.request("DELETE", f"/linode/instances/{linode_id}", token)
                except Exception:
                    pass
            if firewall_id:
                try:
                    self.transport.request("DELETE", f"/networking/firewalls/{firewall_id}", token)
                except Exception:
                    pass
            raise ObserverProviderError(_safe_provider_error(exc)) from exc
        public_ip = _linode_public_ip(inspected)
        if not public_ip:
            if stage_hook is not None:
                raise InspectorCreateUncertainError(
                    "Inspector create result is uncertain; explicit provider reconciliation is required"
                ) from None
            raise ObserverProviderError("Linode observer host did not report a public IPv4 address")
        return ObserverHost(
            provider="linode",
            resource_type="instance",
            resource_id=linode_id,
            name=name,
            region=region,
            public_ip=public_ip,
            ssh_user=INSPECTOR_ADMIN_USER,
            status=_text(inspected.get("status")) or "running",
            metadata={
                "publicIps": [public_ip],
                "providerFirewall": {
                    "provider": "linode",
                    "resourceType": "firewall",
                    "resourceId": firewall_id,
                    "name": firewall_label,
                    "managementSourceCidr": source_cidr,
                },
            },
        )

    def destroy(self, *, token: str, host: ObserverHost) -> bool:
        firewall_id = _inspector_firewall_id(host, "linode")
        try:
            self.transport.request("DELETE", f"/linode/instances/{host.resource_id}", token)
            for _attempt in range(self.poll_attempts):
                try:
                    self.transport.request("GET", f"/linode/instances/{host.resource_id}", token)
                except LinodeValidationError as exc:
                    if "HTTP 404" in str(exc):
                        return self._destroy_firewall(token, firewall_id)
                    raise
                time.sleep(self.poll_delay_seconds)
        except LinodeValidationError as exc:
            # Provider absence is the desired postcondition. This also lets a
            # later reconciliation repair local records left by an older
            # cleanup implementation after the provider resource is gone.
            if "HTTP 404" in str(exc):
                return self._destroy_firewall(token, firewall_id)
            return False
        except Exception:
            return False
        return False

    def _destroy_firewall(self, token: str, firewall_id: str) -> bool:
        if not firewall_id:
            return True
        try:
            self.transport.request("DELETE", f"/networking/firewalls/{firewall_id}", token)
            return True
        except LinodeValidationError as exc:
            return "HTTP 404" in str(exc)
        except Exception:
            return False

    def _wait_for_instance(self, token: str, linode_id: str, created: dict[str, Any]) -> dict[str, Any]:
        inspected = created
        for _attempt in range(self.poll_attempts):
            inspected = self.transport.request("GET", f"/linode/instances/{linode_id}", token)
            if _text(inspected.get("status")).lower() in {"running", "offline"} and _linode_public_ip(inspected):
                return inspected
            time.sleep(self.poll_delay_seconds)
        return inspected


class DigitalOceanObserverProvider:
    def __init__(
        self,
        *,
        transport: DigitalOceanTransport | None = None,
        poll_attempts: int = 30,
        poll_delay_seconds: float = 5.0,
        management_source_resolver: Callable[[], str] = resolve_inspector_management_source_cidr,
        image: str | None = None,
    ):
        self.transport = transport or UrllibDigitalOceanTransport()
        self.poll_attempts = poll_attempts
        self.poll_delay_seconds = poll_delay_seconds
        self.management_source_resolver = management_source_resolver
        self.image = image or managed_host_image_profile().digitalocean_image

    def create(
        self, *, token: str, name: str, region: str, size: str, public_key: str,
        stage_hook: Callable[[InspectorCreateStage], None] | None = None,
    ) -> ObserverHost:
        return self._create(
            token=token, name=name, region=region, size=size, public_key=public_key,
            stage_hook=stage_hook, submit_only=False,
        )

    def submit_staged_inspector(
        self, *, token: str, name: str, region: str, size: str, public_key: str,
        stage_hook: Callable[[InspectorCreateStage], None],
    ) -> InspectorStagedSubmission:
        return self._create(
            token=token, name=name, region=region, size=size, public_key=public_key,
            stage_hook=stage_hook, submit_only=True,
        )

    def _create(
        self, *, token: str, name: str, region: str, size: str, public_key: str,
        stage_hook: Callable[[InspectorCreateStage], None] | None,
        submit_only: bool,
    ) -> ObserverHost | InspectorStagedSubmission:
        if submit_only and stage_hook is None:
            raise ObserverProviderError("staged Inspector submission requires a durable stage hook")
        if (stage_hook is not None and (type(name) is not str
                or re.fullmatch(r"inspector-[0-9a-f]{32}", name) is None)):
            raise ObserverProviderError("hooked Inspector name must be opaque and canonical")
        source_cidr = self.management_source_resolver()
        firewall_name = _inspector_firewall_label("digitalocean", name)
        firewall_tag = _inspector_firewall_tag(name)
        firewall_id = ""
        droplet_id = ""
        firewall_tag_created = False
        body = {
            "name": name,
            "region": region,
            "size": size,
            "image": self.image,
            "user_data": _observer_cloud_init(public_key),
            "tags": ["barragan", "inspector", firewall_tag],
        }
        try:
            if stage_hook is not None:
                stage_hook(InspectorCreateStage(
                    "digitalocean", name, "tag", "before_post", tag_name=firewall_tag))
            self.transport.request("POST", "/tags", token, {"name": firewall_tag})
            firewall_tag_created = True
            if stage_hook is not None:
                # A successful tag POST does not prove this global tag is exclusive.
                stage_hook(InspectorCreateStage(
                    "digitalocean", name, "tag", "response_received", tag_name=firewall_tag))
                stage_hook(InspectorCreateStage(
                    "digitalocean", name, "firewall", "before_post", tag_name=firewall_tag))
            firewall = self.transport.request(
                "POST",
                "/firewalls",
                token,
                {
                    "name": firewall_name,
                    "tags": [firewall_tag],
                    "inbound_rules": [
                        {"protocol": "tcp", "ports": "22", "sources": {"addresses": [source_cidr]}}
                    ],
                    "outbound_rules": [
                        {"protocol": "tcp", "ports": "1-65535", "destinations": {"addresses": ["0.0.0.0/0", "::/0"]}},
                        {"protocol": "udp", "ports": "1-65535", "destinations": {"addresses": ["0.0.0.0/0", "::/0"]}},
                        {"protocol": "icmp", "destinations": {"addresses": ["0.0.0.0/0", "::/0"]}},
                    ],
                },
            )
            raw_firewall_id = firewall.get("firewall", firewall)["id"]
            if stage_hook is not None and not _hooked_firewall_provider_id(raw_firewall_id):
                raise ValueError("firewall ID missing or malformed")
            firewall_id = str(raw_firewall_id)
            if stage_hook is not None:
                stage_hook(InspectorCreateStage(
                    "digitalocean", name, "firewall", "response_received",
                    resource_id=firewall_id, firewall_id=firewall_id, tag_name=firewall_tag))
                stage_hook(InspectorCreateStage(
                    "digitalocean", name, "droplet", "before_post",
                    firewall_id=firewall_id, tag_name=firewall_tag))
            created = self.transport.request("POST", "/droplets", token, body)
            droplet = created.get("droplet", created)
            raw_droplet_id = droplet["id"]
            if stage_hook is not None and not _hooked_numeric_provider_id(raw_droplet_id):
                raise ValueError("Droplet ID missing or malformed")
            droplet_id = str(raw_droplet_id)
            if stage_hook is not None:
                stage_hook(InspectorCreateStage(
                    "digitalocean", name, "droplet", "response_received",
                    resource_id=droplet_id, firewall_id=firewall_id,
                    droplet_id=droplet_id, tag_name=firewall_tag))
                stage_hook(InspectorCreateStage(
                    "digitalocean", name, "attachment", "before_post",
                    firewall_id=firewall_id, droplet_id=droplet_id, tag_name=firewall_tag))
            self.transport.request("POST", f"/firewalls/{firewall_id}/droplets", token, {"droplet_ids": [int(droplet_id)]})
            if stage_hook is not None:
                stage_hook(InspectorCreateStage(
                    "digitalocean", name, "attachment", "response_received",
                    firewall_id=firewall_id, droplet_id=droplet_id, tag_name=firewall_tag))
            if submit_only:
                return InspectorStagedSubmission(
                    "digitalocean", name, droplet_id, firewall_id, firewall_tag,
                    tag_exclusive=False,
                )
            self._wait_for_firewall_attachment(token, firewall_id, droplet_id)
            inspected = self._wait_for_droplet(token, droplet_id, droplet)
        except Exception as exc:
            if stage_hook is not None:
                raise InspectorCreateUncertainError(
                    "Inspector create result is uncertain; explicit provider reconciliation is required"
                ) from None
            if droplet_id:
                try:
                    self.transport.request("DELETE", f"/droplets/{droplet_id}", token)
                except Exception:
                    pass
            if firewall_id:
                try:
                    self.transport.request("DELETE", f"/firewalls/{firewall_id}", token)
                except Exception:
                    pass
            if firewall_tag_created:
                try:
                    self.transport.request("DELETE", f"/tags/{firewall_tag}", token)
                except Exception:
                    pass
            raise ObserverProviderError(_safe_provider_error(exc)) from exc
        public_ip = _digitalocean_public_ip(inspected)
        if not public_ip:
            if stage_hook is not None:
                raise InspectorCreateUncertainError(
                    "Inspector create result is uncertain; explicit provider reconciliation is required"
                ) from None
            raise ObserverProviderError("DigitalOcean observer host did not report a public IPv4 address")
        return ObserverHost(
            provider="digitalocean",
            resource_type="droplet",
            resource_id=droplet_id,
            name=name,
            region=region,
            public_ip=public_ip,
            ssh_user=INSPECTOR_ADMIN_USER,
            status=_text(inspected.get("status")) or "active",
            metadata={
                "publicIps": [public_ip],
                "providerFirewall": {
                    "provider": "digitalocean",
                    "resourceType": "firewall",
                    "resourceId": firewall_id,
                    "name": firewall_name,
                    "tag": firewall_tag,
                    "managementSourceCidr": source_cidr,
                },
            },
        )

    def destroy(self, *, token: str, host: ObserverHost) -> bool:
        firewall_id = _inspector_firewall_id(host, "digitalocean")
        firewall = dict(host.metadata or {}).get("providerFirewall")
        firewall_tag = _text(firewall.get("tag")) if isinstance(firewall, dict) else ""
        try:
            self.transport.request("DELETE", f"/droplets/{host.resource_id}", token)
            for _attempt in range(self.poll_attempts):
                try:
                    self.transport.request("GET", f"/droplets/{host.resource_id}", token)
                except DigitalOceanValidationError as exc:
                    if "HTTP 404" in str(exc):
                        return self._destroy_firewall_and_tag(token, firewall_id, firewall_tag)
                    raise
                time.sleep(self.poll_delay_seconds)
        except DigitalOceanValidationError as exc:
            # A missing droplet is already clean and should repair any stale
            # Barragan provider record during an idempotent cleanup retry.
            if "HTTP 404" in str(exc):
                return self._destroy_firewall_and_tag(token, firewall_id, firewall_tag)
            return False
        except Exception:
            return False
        return False

    def _wait_for_firewall_attachment(self, token: str, firewall_id: str, droplet_id: str) -> None:
        for _attempt in range(self.poll_attempts):
            response = self.transport.request("GET", f"/firewalls/{firewall_id}", token)
            firewall = response.get("firewall", response)
            ids = {str(value) for value in firewall.get("droplet_ids", [])}
            pending = firewall.get("pending_changes", [])
            if droplet_id in ids and not pending:
                return
            time.sleep(self.poll_delay_seconds)
        raise ObserverProviderError("DigitalOcean Inspector firewall did not attach before SSH readiness")

    def _destroy_firewall(self, token: str, firewall_id: str) -> bool:
        return self._destroy_firewall_and_tag(token, firewall_id, "")

    def _destroy_firewall_and_tag(self, token: str, firewall_id: str, firewall_tag: str) -> bool:
        try:
            if firewall_id:
                self.transport.request("DELETE", f"/firewalls/{firewall_id}", token)
        except DigitalOceanValidationError as exc:
            if "HTTP 404" not in str(exc):
                return False
        except Exception:
            return False
        if not firewall_tag:
            return True
        try:
            self.transport.request("DELETE", f"/tags/{firewall_tag}", token)
            return True
        except DigitalOceanValidationError as exc:
            return "HTTP 404" in str(exc)
        except Exception:
            return False

    def _wait_for_droplet(self, token: str, droplet_id: str, created: dict[str, Any]) -> dict[str, Any]:
        inspected = created
        for _attempt in range(self.poll_attempts):
            response = self.transport.request("GET", f"/droplets/{droplet_id}", token)
            inspected = response.get("droplet", response)
            if _text(inspected.get("status")).lower() in {"active", "off"} and _digitalocean_public_ip(inspected):
                return inspected
            time.sleep(self.poll_delay_seconds)
        return inspected


class SshObserverRunner:
    def __init__(self, *, ssh_timeout_seconds: int = 20, readiness_attempts: int = 18, readiness_delay_seconds: float = 5.0):
        self.ssh_timeout_seconds = ssh_timeout_seconds
        self.readiness_attempts = readiness_attempts
        self.readiness_delay_seconds = readiness_delay_seconds

    def prepare_support_host(
        self,
        *,
        host: ObserverHost,
        ssh_key: ObserverSshKey,
        packages: tuple[str, ...] = INSPECTOR_DEFAULT_SUPPORT_PACKAGES,
        fence: Callable[[], None] | None = None,
    ) -> ObserverHost:
        with tempfile.TemporaryDirectory(prefix="barragan-inspector-prepare-") as temp_dir:
            workspace = Path(temp_dir)
            host = self._prepare_admin_identity(
                host=host, ssh_key=ssh_key, workspace=workspace, **_fence_option(fence))
            _prepare_inspector_support_host(
                host, ssh_key, list(packages), workspace, **_fence_option(fence))
        return _mark_inspector_support_prepared(host, packages)

    def _prepare_admin_identity(
        self,
        *,
        host: ObserverHost,
        ssh_key: ObserverSshKey,
        workspace: Path,
        fence: Callable[[], None] | None = None,
    ) -> ObserverHost:
        ssh_common = self._ssh_common(ssh_key)
        if host.ssh_user != INSPECTOR_ADMIN_USER:
            _run_checked_with_retries(
                ["ssh", *ssh_common, f"{host.ssh_user}@{host.public_ip}", "true"],
                attempts=self.readiness_attempts,
                delay_seconds=self.readiness_delay_seconds,
                description="existing Inspector SSH identity did not become ready for migration",
                **_fence_option(fence),
            )
            _bootstrap_inspector_admin_identity(host, ssh_key, workspace, **_fence_option(fence))

        candidate = replace(host, ssh_user=INSPECTOR_ADMIN_USER)
        _run_checked_with_retries(
            ["ssh", *ssh_common, f"{INSPECTOR_ADMIN_USER}@{host.public_ip}", "sudo", "-n", "true"],
            attempts=self.readiness_attempts,
            delay_seconds=self.readiness_delay_seconds,
            description="Inspector barragan administration identity did not become ready",
            **_fence_option(fence),
        )
        _harden_inspector_ssh(candidate, ssh_key, workspace, **_fence_option(fence))
        _run_checked_with_retries(
            ["ssh", *ssh_common, f"{INSPECTOR_ADMIN_USER}@{host.public_ip}", "sudo", "-n", "true"],
            attempts=self.readiness_attempts,
            delay_seconds=self.readiness_delay_seconds,
            description="Inspector barragan administration identity failed after SSH hardening",
            **_fence_option(fence),
        )
        effective_policy = _run_checked(
            [
                "ssh",
                *ssh_common,
                f"{INSPECTOR_ADMIN_USER}@{host.public_ip}",
                "sudo",
                "-n",
                "/usr/sbin/sshd",
                "-T",
            ], **_fence_option(fence)
        )
        effective_settings = set(effective_policy.stdout.lower().splitlines())
        required_settings = {
            "permitrootlogin no",
            "passwordauthentication no",
            "kbdinteractiveauthentication no",
        }
        if not required_settings.issubset(effective_settings):
            raise InspectionValidationError(["Inspector effective SSH policy did not disable root and password login"])
        root_result = _run_checked(
            ["ssh", *ssh_common, f"root@{host.public_ip}", "true"],
            check=False,
            **_fence_option(fence),
        )
        if root_result.returncode == 0:
            raise InspectionValidationError(["Inspector root SSH login remained enabled after hardening"])
        return _mark_inspector_admin_identity(candidate)

    def verify_access(self, *, host: ObserverHost, ssh_key: ObserverSshKey) -> None:
        _run_checked_with_retries(
            ["ssh", *self._ssh_common(ssh_key), f"{host.ssh_user}@{host.public_ip}", "true"],
            attempts=self.readiness_attempts,
            delay_seconds=self.readiness_delay_seconds,
            description="retained Inspector SSH verification failed",
        )

    def run(self, *, host: ObserverHost, ssh_key: ObserverSshKey, spec: dict[str, Any]) -> dict[str, Any]:
        execution_timeout = _observer_check_execution_timeout(spec)
        with tempfile.TemporaryDirectory(prefix="barragan-observer-check-") as temp_dir:
            temp_path = Path(temp_dir)
            script_path = temp_path / "observer_check.py"
            spec_path = temp_path / "observer_spec.json"
            result_path = temp_path / "observer_result.json"
            script_path.write_text(_OBSERVER_SCRIPT, encoding="utf-8")
            spec_path.write_text(json.dumps(spec, sort_keys=True), encoding="utf-8")
            remote_dir = f"/tmp/barragan-observer-{uuid4().hex[:8]}"
            destination = f"{host.ssh_user}@{host.public_ip}:{remote_dir}/"
            ssh_common = self._ssh_common(ssh_key)
            _run_checked_with_retries(
                ["ssh", *ssh_common, f"{host.ssh_user}@{host.public_ip}", "mkdir", "-p", remote_dir],
                attempts=self.readiness_attempts,
                delay_seconds=self.readiness_delay_seconds,
                description="inspector SSH did not become ready",
            )
            _run_checked(["scp", *ssh_common, str(script_path), str(spec_path), destination])
            completed = _run_checked(
                [
                    "ssh",
                    *ssh_common,
                    f"{host.ssh_user}@{host.public_ip}",
                    "python3",
                    f"{remote_dir}/observer_check.py",
                    f"{remote_dir}/observer_spec.json",
                ],
                timeout_seconds=execution_timeout,
            )
            result_path.write_text(completed.stdout[-MAX_SSH_OUTPUT_CHARS:], encoding="utf-8")
            _run_checked(["ssh", *ssh_common, f"{host.ssh_user}@{host.public_ip}", "rm", "-rf", remote_dir], check=False)
            try:
                return json.loads(result_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                return {
                    "ok": False,
                    "error": "observer runner did not return JSON",
                    "stdoutPreview": completed.stdout[-1000:],
                    "stderrPreview": completed.stderr[-1000:],
                    "errorType": type(exc).__name__,
                }

    def _ssh_common(self, ssh_key: ObserverSshKey) -> list[str]:
        return [
            "-i",
            ssh_key.private_key_path,
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={self.ssh_timeout_seconds}",
        ]


def _prepare_inspector_support_host(
    host: ObserverHost, ssh_key: ObserverSshKey, packages: list[str], workspace: Path,
    *, fence: Callable[[], None] | None = None,
) -> None:
    if not packages:
        return
    resolution = resolve_ansible_playbook()
    if not resolution.ok:
        raise InspectionValidationError(
            [
                "Inspector support-host Ansible preparation is unavailable",
                resolution.error or "Could not resolve ansible-playbook executable",
            ]
        )
    ansible_dir = workspace / "ansible"
    ansible_dir.mkdir(parents=True, exist_ok=True)
    inventory = ansible_dir / "inspector_inventory.ini"
    playbook = ansible_dir / "prepare_inspector.yml"
    inventory.write_text(_render_inspector_inventory(host, ssh_key), encoding="utf-8")
    playbook.write_text(_render_inspector_prepare_playbook(packages), encoding="utf-8")
    completed = _run_checked(
        [
            resolution.command or "ansible-playbook",
            "-i",
            "ansible/inspector_inventory.ini",
            "ansible/prepare_inspector.yml",
        ],
        cwd=workspace,
        check=False,
        **_fence_option(fence),
    )
    if completed.returncode != 0:
        raise InspectionValidationError(
            [
                "Inspector support-host preparation failed",
                _safe_command_error(completed),
            ]
        )


def _bootstrap_inspector_admin_identity(
    host: ObserverHost,
    ssh_key: ObserverSshKey,
    workspace: Path,
    *, fence: Callable[[], None] | None = None,
) -> None:
    _run_inspector_ansible_playbook(
        host,
        ssh_key,
        workspace,
        name="bootstrap_inspector_admin",
        playbook=_render_inspector_admin_bootstrap_playbook(ssh_key.public_key),
        failure="Inspector barragan administration identity bootstrap failed",
        **_fence_option(fence),
    )


def _harden_inspector_ssh(
    host: ObserverHost,
    ssh_key: ObserverSshKey,
    workspace: Path,
    *, fence: Callable[[], None] | None = None,
) -> None:
    _run_inspector_ansible_playbook(
        host,
        ssh_key,
        workspace,
        name="harden_inspector_ssh",
        playbook=_render_inspector_ssh_hardening_playbook(),
        failure="Inspector SSH hardening failed",
        **_fence_option(fence),
    )


def _run_inspector_ansible_playbook(
    host: ObserverHost,
    ssh_key: ObserverSshKey,
    workspace: Path,
    *,
    name: str,
    playbook: str,
    failure: str,
    fence: Callable[[], None] | None = None,
) -> None:
    resolution = resolve_ansible_playbook()
    if not resolution.ok:
        raise InspectionValidationError(
            [
                "Inspector support-host Ansible preparation is unavailable",
                resolution.error or "Could not resolve ansible-playbook executable",
            ]
        )
    ansible_dir = workspace / "ansible"
    ansible_dir.mkdir(parents=True, exist_ok=True)
    inventory = ansible_dir / f"{name}_inventory.ini"
    playbook_path = ansible_dir / f"{name}.yml"
    inventory.write_text(_render_inspector_inventory(host, ssh_key), encoding="utf-8")
    playbook_path.write_text(playbook, encoding="utf-8")
    completed = _run_checked(
        [
            resolution.command or "ansible-playbook",
            "-i",
            f"ansible/{inventory.name}",
            f"ansible/{playbook_path.name}",
        ],
        cwd=workspace,
        check=False,
        **_fence_option(fence),
    )
    if completed.returncode != 0:
        raise InspectionValidationError([failure, _safe_command_error(completed)])


def _inspector_support_baseline_current(host: ObserverHost) -> bool:
    metadata = dict(host.metadata or {})
    packages = metadata.get("supportPreparedPackages")
    return (
        host.ssh_user == INSPECTOR_ADMIN_USER
        and metadata.get("adminIdentityVersion") == INSPECTOR_ADMIN_IDENTITY_VERSION
        and metadata.get("rootLoginDisabled") is True
        and metadata.get("supportPreparationVersion") == INSPECTOR_SUPPORT_PREPARATION_VERSION
        and isinstance(packages, list)
        and sorted(_text(package) for package in packages) == sorted(INSPECTOR_DEFAULT_SUPPORT_PACKAGES)
    )


def _mark_inspector_admin_identity(host: ObserverHost) -> ObserverHost:
    metadata = dict(host.metadata or {})
    metadata["adminIdentityVersion"] = INSPECTOR_ADMIN_IDENTITY_VERSION
    metadata["rootLoginDisabled"] = True
    return replace(host, ssh_user=INSPECTOR_ADMIN_USER, metadata=metadata)


def _mark_inspector_support_prepared(host: ObserverHost, packages: tuple[str, ...]) -> ObserverHost:
    metadata = dict(host.metadata or {})
    metadata["supportPreparationVersion"] = INSPECTOR_SUPPORT_PREPARATION_VERSION
    metadata["supportPreparedPackages"] = sorted(packages)
    return replace(host, metadata=metadata)


def _render_inspector_inventory(host: ObserverHost, ssh_key: ObserverSshKey) -> str:
    return "\n".join(
        [
            "[inspector]",
            (
                f"inspector ansible_host={host.public_ip} ansible_user={host.ssh_user} "
                f"ansible_ssh_private_key_file={ssh_key.private_key_path} "
                "ansible_ssh_common_args='-o UserKnownHostsFile=/dev/null "
                "-o StrictHostKeyChecking=no -o IdentitiesOnly=yes -o BatchMode=yes'"
            ),
            "",
        ]
    )


def _render_inspector_prepare_playbook(packages: list[str]) -> str:
    package_lines = "\n".join(f"        - {package}" for package in packages)
    verify_lines = "\n".join(
        "\n".join(
            [
                f"    - name: Verify Inspector package {package} command is available",
                "      ansible.builtin.command:",
                f"        cmd: which {package}",
                "      changed_when: false",
                "",
            ]
        )
        for package in packages
    )
    return (
        "---\n"
        "- name: Prepare Barragan Inspector support host\n"
        "  hosts: inspector\n"
        "  become: true\n"
        "  tasks:\n"
        "    - name: Install Inspector package dependencies\n"
        "      ansible.builtin.apt:\n"
        "        name:\n"
        f"{package_lines}\n"
        "        state: present\n"
        "        update_cache: true\n"
        f"{verify_lines}"
    )


def _render_inspector_admin_bootstrap_playbook(public_key: str) -> str:
    return textwrap.dedent(
        f"""\
        ---
        - name: Provision Barragan Inspector administration identity
          hosts: inspector
          become: true
          tasks:
            - name: Create Barragan Inspector administration account
              ansible.builtin.user:
                name: {INSPECTOR_ADMIN_USER}
                groups: sudo
                append: true
                create_home: true
                shell: /bin/bash
                password_lock: true

            - name: Create Barragan Inspector SSH directory
              ansible.builtin.file:
                path: /home/{INSPECTOR_ADMIN_USER}/.ssh
                state: directory
                owner: {INSPECTOR_ADMIN_USER}
                group: {INSPECTOR_ADMIN_USER}
                mode: "0700"

            - name: Install retained Inspector public key
              ansible.builtin.copy:
                dest: /home/{INSPECTOR_ADMIN_USER}/.ssh/authorized_keys
                content: |
                  {public_key}
                owner: {INSPECTOR_ADMIN_USER}
                group: {INSPECTOR_ADMIN_USER}
                mode: "0600"

            - name: Grant passwordless Inspector administration
              ansible.builtin.copy:
                dest: /etc/sudoers.d/90-barragan-inspector
                content: "{INSPECTOR_ADMIN_USER} ALL=(ALL) NOPASSWD:ALL\\n"
                owner: root
                group: root
                mode: "0440"
                validate: /usr/sbin/visudo -cf %s
        """
    )


def _render_inspector_ssh_hardening_playbook() -> str:
    return textwrap.dedent(
        """\
        ---
        - name: Harden Barragan Inspector SSH access
          hosts: inspector
          become: true
          tasks:
            - name: Disable root and password SSH authentication
              ansible.builtin.copy:
                dest: /etc/ssh/sshd_config.d/10-barragan-inspector.conf
                content: |
                  PermitRootLogin no
                  PasswordAuthentication no
                  KbdInteractiveAuthentication no
                  PubkeyAuthentication yes
                owner: root
                group: root
                mode: "0644"
              register: inspector_sshd_policy

            - name: Validate Inspector SSH configuration
              ansible.builtin.command: /usr/sbin/sshd -t
              changed_when: false

            - name: Reload Inspector SSH service
              ansible.builtin.service:
                name: ssh
                state: reloaded
              when: inspector_sshd_policy.changed
        """
    )


def _finish_observer_check_job(
    repo: JobRepository,
    resources: ProviderResourceRepository,
    job: StoredJobRun,
    engagement_id: str,
    engagement_name: str,
    settings: StoredObserverSettings,
    credential_alias: str,
    token: str,
    targets: dict[str, list[dict[str, Any]]],
    provider_factory: Callable[[str], ObserverProvider],
    runner: ObserverRunner,
    ssh_key_factory: Callable[[str], ObserverSshKey],
) -> StoredJobRun:
    provider = provider_factory(settings.provider)
    ssh_key = ssh_key_factory(job.id)
    host: ObserverHost | None = None
    current = _append_event(repo, job, "info", "observer host create started", {"provider": settings.provider, "region": settings.region, "size": settings.size})
    try:
        name = _observer_host_name(engagement_name, job.id)
        host = provider.create(token=token, name=name, region=settings.region, size=settings.size, public_key=ssh_key.public_key)
        _record_observer_resource(resources, engagement_id, engagement_name, host, job.id, status="active")
        current = _append_event(
            repo,
            current,
            "info",
            "observer host create succeeded",
            {
                "observerHost": host.to_dict(),
                "credentialAlias": credential_alias,
                "publicProbeOrigin": "observer host",
            },
        )
        spec = {"positive": targets["positive"], "negative": targets["negative"], "timeoutSeconds": 8}
        current = _append_event(repo, current, "info", "observer public checks started", {"targets": _target_summary(targets)})
        evidence = runner.run(host=host, ssh_key=ssh_key, spec=spec)
        ok = bool(evidence.get("ok"))
        current = _append_event(
            repo,
            current,
            "info" if ok else "error",
            "observer public checks succeeded" if ok else "observer public checks failed",
            {"observerEvidence": _safe_evidence(evidence), "targets": _target_summary(targets)},
        )
    except Exception as exc:
        current = _append_event(
            repo,
            current,
            "error",
            "observer public checks failed",
            {"errorType": type(exc).__name__, "detail": _safe_provider_error(exc)},
        )
        ok = False
    finally:
        cleanup_verified = False
        if host is not None:
            current = _append_event(repo, current, "info", "observer host cleanup started", {"observerHost": host.to_dict()})
            cleanup_verified = provider.destroy(token=token, host=host)
            _record_observer_resource(
                resources,
                engagement_id,
                engagement_name,
                host,
                job.id,
                status="destroyed" if cleanup_verified else "cleanup_required",
                destroyed=cleanup_verified,
            )
            current = _append_event(
                repo,
                current,
                "info" if cleanup_verified else "error",
                "observer host cleanup verified" if cleanup_verified else "observer host cleanup failed",
                {"observerHost": host.to_dict(), "cleanupVerified": cleanup_verified},
            )
        _cleanup_ssh_key(ssh_key)

    final_status = "succeeded" if ok and cleanup_verified else "failed"
    final = replace(current, status=final_status, finished_at=_now())
    _assert_no_secret_material(final.to_detail().to_dict())
    return repo.save(final)


def _finish_inspector_readiness_job(
    repo: JobRepository,
    settings_repo: ObserverSettingsRepository,
    resources: ProviderResourceRepository,
    job: StoredJobRun,
    engagement_id: str,
    engagement_name: str,
    settings: StoredObserverSettings,
    credential_alias: str,
    token: str,
    provider_factory: Callable[[str], ObserverProvider],
    runner: ObserverRunner,
    ssh_key_factory: Callable[[str], ObserverSshKey],
    *,
    replace_unreachable_host: bool = False,
) -> StoredJobRun:
    provider = provider_factory(settings.provider)
    ssh_key = ssh_key_factory(job.id)
    host: ObserverHost | None = _reusable_inspector_host(settings)
    host_created = False
    current = job
    cleanup_verified = True
    try:
        if host is not None and replace_unreachable_host:
            current = _append_event(
                repo,
                current,
                "error",
                "retained Inspector SSH verification failed; replacement started",
                {"inspectorHost": host.to_dict()},
            )
            cleanup_verified = provider.destroy(token=token, host=host)
            _record_inspector_resource(
                resources,
                engagement_id,
                engagement_name,
                host,
                job.id,
                status="destroyed" if cleanup_verified else "cleanup_required",
                destroyed=cleanup_verified,
            )
            if not cleanup_verified:
                raise InspectorReadinessError(["retained Inspector cleanup failed; replacement was not created"])
            settings = settings_repo.save(replace(settings, current_host={}, idle_retention_until=""))
            current = _append_event(
                repo,
                current,
                "info",
                "retained Inspector cleanup verified",
                {"inspectorHost": host.to_dict(), "cleanupVerified": True},
            )
            host = None
        if host is None:
            current = _append_event(
                repo,
                current,
                "info",
                "Inspector host create started",
                {"provider": settings.provider, "region": settings.region, "size": settings.size},
            )
            host = provider.create(
                token=token,
                name=_inspector_host_name(engagement_name, job.id),
                region=settings.region,
                size=settings.size,
                public_key=ssh_key.public_key,
            )
            host_created = True
            _record_inspector_resource(resources, engagement_id, engagement_name, host, job.id, status="active")
            current = _append_event(
                repo,
                current,
                "info",
                "Inspector host create succeeded",
                {"inspectorHost": host.to_dict(), "credentialAlias": credential_alias},
            )
        else:
            current = _append_event(
                repo,
                current,
                "info",
                "Inspector host reused for readiness",
                {"inspectorHost": host.to_dict()},
            )

        if isinstance(runner, SshObserverRunner) and not _inspector_support_baseline_current(host):
            current = _append_event(
                repo,
                current,
                "info",
                "Inspector support host preparation started",
                {"inspectorHost": host.to_dict(), "packages": list(INSPECTOR_DEFAULT_SUPPORT_PACKAGES)},
            )
            host = runner.prepare_support_host(
                host=host,
                ssh_key=ssh_key,
                packages=INSPECTOR_DEFAULT_SUPPORT_PACKAGES,
            )
            _record_inspector_resource(resources, engagement_id, engagement_name, host, job.id, status="active")
            current = _append_event(
                repo,
                current,
                "info",
                "Inspector support host preparation succeeded",
                {"inspectorHost": host.to_dict(), "packages": list(INSPECTOR_DEFAULT_SUPPORT_PACKAGES)},
            )

        if not _inspector_support_baseline_current(host):
            raise InspectorReadinessError(["Inspector support-host baseline was not verified"])

        settings_repo.save(replace(settings, current_host=host.to_dict(), idle_retention_until=""))
        current = _append_event(
            repo,
            current,
            "info",
            "continuous Inspector readiness succeeded",
            {"inspectorHost": host.to_dict(), "retentionMode": "continuous"},
        )
        final = replace(current, status="succeeded", finished_at=_now())
    except Exception as exc:
        error_data = {"errorType": type(exc).__name__, "detail": _safe_provider_error(exc)}
        if isinstance(exc, ObserverCheckValidationError):
            error_data["errors"] = [_redact_secretish(_text(error)) for error in exc.errors]
        current = _append_event(
            repo,
            current,
            "error",
            "continuous Inspector readiness failed",
            error_data,
        )
        if host is not None and host_created:
            current = _append_event(repo, current, "info", "Inspector host cleanup started", {"inspectorHost": host.to_dict()})
            try:
                cleanup_verified = provider.destroy(token=token, host=host)
            except Exception:
                cleanup_verified = False
            _record_inspector_resource(
                resources,
                engagement_id,
                engagement_name,
                host,
                job.id,
                status="destroyed" if cleanup_verified else "cleanup_required",
                destroyed=cleanup_verified,
            )
            if not cleanup_verified:
                settings_repo.save(replace(settings, current_host=host.to_dict(), idle_retention_until=""))
            current = _append_event(
                repo,
                current,
                "info" if cleanup_verified else "error",
                "Inspector host cleanup verified" if cleanup_verified else "Inspector host cleanup failed",
                {"inspectorHost": host.to_dict(), "cleanupVerified": cleanup_verified},
            )
        final = replace(current, status="failed", finished_at=_now())
    _assert_no_secret_material(final.to_detail().to_dict())
    return repo.save(final)


def _finish_inspection_job(
    repo: JobRepository,
    inspection_repo: InspectionRunRepository,
    settings_repo: ObserverSettingsRepository,
    resources: ProviderResourceRepository,
    job: StoredJobRun,
    inspection: StoredInspectionRun,
    engagement_id: str,
    engagement_name: str,
    settings: StoredObserverSettings,
    credential_alias: str,
    token: str,
    targets: dict[str, list[dict[str, Any]]],
    provider_factory: Callable[[str], ObserverProvider],
    runner: ObserverRunner,
    ssh_key_factory: Callable[[str], ObserverSshKey],
) -> StoredJobRun:
    provider = provider_factory(settings.provider)
    ssh_key = ssh_key_factory(job.id)
    host: ObserverHost | None = _reusable_inspector_host(settings)
    host_created = False
    evidence: dict[str, Any] = {}
    ok = False
    current = job
    try:
        if host is None:
            current = _append_event(repo, current, "info", "inspector host create started", {"provider": settings.provider, "region": settings.region, "size": settings.size})
            name = _inspector_host_name(engagement_name, job.id)
            host = provider.create(token=token, name=name, region=settings.region, size=settings.size, public_key=ssh_key.public_key)
            host_created = True
            _record_inspector_resource(resources, engagement_id, engagement_name, host, job.id, status="active")
            current = _append_event(
                repo,
                current,
                "info",
                "inspector host create succeeded",
                {
                    "inspectorHost": host.to_dict(),
                    "credentialAlias": credential_alias,
                    "publicProbeOrigin": "inspector host",
                },
            )
        else:
            current = _append_event(
                repo,
                current,
                "info",
                "inspector host reused",
                {"inspectorHost": host.to_dict(), "publicProbeOrigin": "inspector host"},
            )

        if isinstance(runner, SshObserverRunner) and not _inspector_support_baseline_current(host):
            current = _append_event(
                repo,
                current,
                "info",
                "inspector support host preparation started",
                {"inspectorHost": host.to_dict(), "packages": list(INSPECTOR_DEFAULT_SUPPORT_PACKAGES)},
            )
            host = runner.prepare_support_host(
                host=host,
                ssh_key=ssh_key,
                packages=INSPECTOR_DEFAULT_SUPPORT_PACKAGES,
            )
            _record_inspector_resource(resources, engagement_id, engagement_name, host, job.id, status="active")
            current = _append_event(
                repo,
                current,
                "info",
                "inspector support host preparation succeeded",
                {"inspectorHost": host.to_dict(), "packages": list(INSPECTOR_DEFAULT_SUPPORT_PACKAGES)},
            )

        spec = {"positive": targets["positive"], "negative": targets["negative"], "timeoutSeconds": 8}
        current = _append_event(repo, current, "info", "inspection checks started", {"targets": _target_summary(targets)})
        evidence = runner.run(host=host, ssh_key=ssh_key, spec=spec)
        ok = bool(evidence.get("ok"))
        current = _append_event(
            repo,
            current,
            "info" if ok else "error",
            "inspection checks succeeded" if ok else "inspection checks failed",
            {"inspectionEvidence": _safe_evidence(evidence), "targets": _target_summary(targets)},
        )
    except ObserverCheckValidationError as exc:
        evidence = {"ok": False, "errorType": type(exc).__name__, "errors": exc.errors}
        current = _append_event(repo, current, "error", "inspection checks failed", evidence)
        ok = False
    except Exception as exc:
        evidence = {"ok": False, "errorType": type(exc).__name__, "detail": _safe_provider_error(exc)}
        current = _append_event(repo, current, "error", "inspection checks failed", evidence)
        ok = False
    finally:
        retain_host = _should_retain_inspector_host(settings, host)
        cleanup_verified = True
        if host is not None and retain_host:
            retained_settings = replace(
                settings,
                current_host=host.to_dict(),
                idle_retention_until=_retention_until(settings),
            )
            settings_repo.save(retained_settings)
            current = _append_event(
                repo,
                current,
                "info",
                "inspector host retained",
                {
                    "inspectorHost": host.to_dict(),
                    "retentionMode": settings.mode,
                    "idleRetentionUntil": retained_settings.idle_retention_until,
                },
            )
        elif host is not None:
            current = _append_event(repo, current, "info", "inspector host cleanup started", {"inspectorHost": host.to_dict()})
            cleanup_verified = provider.destroy(token=token, host=host)
            _record_inspector_resource(
                resources,
                engagement_id,
                engagement_name,
                host,
                job.id,
                status="destroyed" if cleanup_verified else "cleanup_required",
                destroyed=cleanup_verified,
            )
            if cleanup_verified and settings.current_host.get("resourceId") == host.resource_id:
                settings_repo.save(replace(settings, current_host={}, idle_retention_until=""))
            current = _append_event(
                repo,
                current,
                "info" if cleanup_verified else "error",
                "inspector host cleanup verified" if cleanup_verified else "inspector host cleanup failed",
                {"inspectorHost": host.to_dict(), "cleanupVerified": cleanup_verified},
            )
        if not retain_host or host_created is False:
            _cleanup_ssh_key(ssh_key)

    final_status = "succeeded" if ok and cleanup_verified else "failed"
    final = replace(current, status=final_status, finished_at=_now())
    saved = repo.save(final)
    inspection_repo.save(
        replace(
            inspection,
            status=final_status,
            host=host.to_dict() if host else {},
            evidence=_safe_evidence(evidence),
            findings=_inspection_findings(evidence),
            finished_at=final.finished_at,
        )
    )
    _record_certificate_binding_validation(engagement_id, evidence, job.id)
    _assert_no_secret_material(saved.to_detail().to_dict())
    return saved


def _record_certificate_binding_validation(
    engagement_id: str,
    evidence: dict[str, Any],
    inspector_job_id: str,
    *,
    certificate_repository: Any | None = None,
) -> None:
    from app.storage.certificate_repository import SqlAlchemyCertificateRepository

    results = evidence.get("results") if isinstance(evidence, dict) else None
    if not isinstance(results, list):
        return
    https_results = {
        _text(result.get("channelId") or result.get("id")): result
        for result in results
        if isinstance(result, dict) and _text(result.get("type")).lower() == "https"
    }
    if not https_results:
        return
    repository = certificate_repository or SqlAlchemyCertificateRepository()
    for binding in repository.list_bindings(engagement_id):
        result = https_results.get(binding.channel_id)
        if result is None or binding.status != "bound":
            continue
        observed = result.get("observed") if isinstance(result.get("observed"), dict) else {}
        observed_fingerprint = _text(observed.get("fingerprintSha256")).lower()
        asset = repository.get_asset(engagement_id, binding.certificate_id)
        version = repository.get_version(asset.current_version_id) if asset and asset.current_version_id else None
        expected_fingerprint = _text(version.fingerprint_sha256 if version else "").lower()
        fingerprint_matches = bool(expected_fingerprint and observed_fingerprint == expected_fingerprint)
        handshake_ok = result.get("ok") is True
        if handshake_ok and fingerprint_matches:
            tls_version = _text(observed.get("tlsVersion"))
            validation = {
                "status": "validated",
                "detail": f"Inspector TLS handshake verified by {inspector_job_id}; active certificate fingerprint matched{f' over {tls_version}' if tls_version else ''}.",
                "inspectorJobId": inspector_job_id,
                "fingerprintSha256": observed_fingerprint,
                "tlsVersion": tls_version,
            }
        elif handshake_ok:
            validation = {
                "status": "error",
                "detail": f"Inspector TLS handshake succeeded in {inspector_job_id}, but the served certificate fingerprint did not match the active Barragan version.",
                "inspectorJobId": inspector_job_id,
                "fingerprintSha256": observed_fingerprint,
            }
        else:
            validation = {
                "status": "error",
                "detail": f"Inspector TLS validation failed in {inspector_job_id}: {_text(result.get('observed'))[:240]}",
                "inspectorJobId": inspector_job_id,
            }
        repository.save_binding(replace(binding, validation=validation, updated_at=_now()))


def _settings_for_engagement(
    engagement_id: str,
    *,
    repository: ObserverSettingsRepository | None = None,
) -> StoredObserverSettings:
    repo = repository or SqlAlchemyObserverSettingsRepository()
    stored = repo.get(engagement_id)
    if stored is not None:
        return stored
    provider = "linode"
    region = _default_region(provider)
    now = _now()
    return StoredObserverSettings(
        engagement_id=engagement_id,
        enabled=True,
        provider=provider,
        region=region,
        size=DEFAULT_OBSERVER_SIZES[provider],
        mode=DEFAULT_INSPECTOR_MODE,
        schedule_weekdays=list(DEFAULT_INSPECTOR_SCHEDULE_WEEKDAYS),
        schedule_time_utc=DEFAULT_INSPECTOR_SCHEDULE_TIME_UTC,
        check_families=list(DEFAULT_INSPECTOR_CHECK_FAMILIES),
        forbidden_tcp_ports=list(DEFAULT_FORBIDDEN_TCP_PORTS),
        port_scan_profiles=[],
        current_host={},
        idle_retention_until="",
        last_scheduled_slot="",
        last_mutation_job_inspected="",
        created_at=now,
        updated_at=now,
    )


def _settings_from_body(engagement_id: str, body: dict[str, Any]) -> StoredObserverSettings:
    existing = _settings_for_engagement(engagement_id)
    enabled = _bool(body.get("enabled"), default=existing.enabled)
    provider = _text(body.get("provider")).lower()
    region = _text(body.get("region")).lower()
    size = _text(body.get("size"))
    mode = _text(body.get("mode") or existing.mode).lower()
    schedule_weekdays = _schedule_weekdays(body.get("scheduleWeekdays"), existing.schedule_weekdays)
    schedule_time_utc = _schedule_time_utc(body.get("scheduleTimeUtc") or existing.schedule_time_utc)
    check_families = _check_families(body.get("checkFamilies"), existing.check_families)
    errors: list[str] = []
    if provider not in SUPPORTED_OBSERVER_PROVIDERS:
        errors.append("provider must be linode or digitalocean")
    if provider and not region:
        errors.append("region is required")
    if provider and region:
        try:
            if not is_provider_region_allowed(provider, region):
                errors.append(f"{provider} region {region} is not allowed by Global Settings")
        except ProviderRegionPolicyValidationError as exc:
            errors.extend(exc.errors)
    if not size:
        errors.append("size is required")
    if mode not in INSPECTOR_MODES:
        errors.append("mode must be once, regular, or continuous")
    if schedule_weekdays is None:
        errors.append("scheduleWeekdays must contain UTC weekdays mon through sun")
        schedule_weekdays = list(DEFAULT_INSPECTOR_SCHEDULE_WEEKDAYS)
    if schedule_time_utc is None:
        errors.append("scheduleTimeUtc must use HH:MM UTC")
        schedule_time_utc = DEFAULT_INSPECTOR_SCHEDULE_TIME_UTC
    ports = _forbidden_ports(body.get("forbiddenTcpPorts"), errors)
    port_scan_profiles = _port_scan_profiles(body.get("portScanProfiles"), errors)
    if errors:
        raise InspectorSettingsValidationError(errors)
    now = _now()
    return StoredObserverSettings(
        engagement_id=engagement_id,
        enabled=enabled,
        provider=provider,
        region=region,
        size=size,
        mode=mode,
        schedule_weekdays=schedule_weekdays,
        schedule_time_utc=schedule_time_utc,
        check_families=check_families,
        forbidden_tcp_ports=ports,
        port_scan_profiles=port_scan_profiles,
        current_host=dict(existing.current_host),
        idle_retention_until=existing.idle_retention_until,
        last_scheduled_slot=existing.last_scheduled_slot,
        last_mutation_job_inspected=existing.last_mutation_job_inspected,
        created_at=now,
        updated_at=now,
    )


def _settings_response(settings: StoredObserverSettings, *, configured: bool, engagement_name: str, legacy_observer: bool = False) -> dict[str, Any]:
    confirmation_token = observer_confirmation_token(engagement_name) if legacy_observer else inspector_confirmation_token(engagement_name)
    return {
        "settings": {
            **settings.to_dict(),
            "configured": configured,
            "confirmationToken": confirmation_token,
            "defaults": {
                "provider": "linode",
                "regions": {provider: _default_region(provider) for provider in sorted(SUPPORTED_OBSERVER_PROVIDERS)},
                "sizes": DEFAULT_OBSERVER_SIZES,
                "forbiddenTcpPorts": [str(port) for port in DEFAULT_FORBIDDEN_TCP_PORTS],
                "mode": DEFAULT_INSPECTOR_MODE,
                "scheduleWeekdays": list(DEFAULT_INSPECTOR_SCHEDULE_WEEKDAYS),
                "scheduleTimeUtc": DEFAULT_INSPECTOR_SCHEDULE_TIME_UTC,
                "checkFamilies": list(DEFAULT_INSPECTOR_CHECK_FAMILIES),
            },
        }
    }


def _forbidden_ports(value: Any, errors: list[str]) -> list[int]:
    raw_values = value if isinstance(value, list) else DEFAULT_FORBIDDEN_TCP_PORTS
    ports: list[int] = []
    for index, raw in enumerate(raw_values):
        port = _port(raw)
        if port is None:
            errors.append(f"forbiddenTcpPorts[{index}] must be between 1 and 65535")
            continue
        if port not in ports:
            ports.append(port)
    return ports


def _bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return _text(value).lower() in {"1", "true", "yes", "on", "enabled"}


def _schedule_weekdays(value: Any, default: list[str]) -> list[str] | None:
    if value is None:
        return list(default)
    if not isinstance(value, list):
        return None
    weekdays: list[str] = []
    for raw in value:
        weekday = _text(raw).lower()[:3]
        if weekday not in INSPECTOR_WEEKDAYS:
            return None
        if weekday not in weekdays:
            weekdays.append(weekday)
    return weekdays or list(default)


def _schedule_time_utc(value: Any) -> str | None:
    text = _text(value)
    if len(text) != 5 or text[2] != ":":
        return None
    try:
        hour = int(text[:2])
        minute = int(text[3:])
    except ValueError:
        return None
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        return None
    return f"{hour:02d}:{minute:02d}"


def _check_families(value: Any, default: list[str]) -> list[str]:
    supported = set(DEFAULT_INSPECTOR_CHECK_FAMILIES)
    if not isinstance(value, list):
        return list(default)
    families: list[str] = []
    for raw in value:
        family = _text(raw).lower()
        if family in supported and family not in families:
            families.append(family)
    return families or list(default)


def _port_scan_profiles(value: Any, errors: list[str]) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        errors.append("portScanProfiles must be a list")
        return []
    profiles: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            errors.append(f"portScanProfiles[{index}] must be an object")
            continue
        enabled = _bool(raw.get("enabled"), default=False)
        target_group = _text(raw.get("targetGroup") or "edges").lower()
        scan_mode = _text(raw.get("scanMode") or "tcp-connect").lower()
        timing = _text(raw.get("timing") or "normal").lower()
        ports = _normalize_scan_ports(raw.get("ports") or "")
        if target_group not in INSPECTOR_SCAN_TARGET_GROUPS:
            errors.append(f"portScanProfiles[{index}].targetGroup must be edges, assigned-domains, or core-public-management")
        if scan_mode not in INSPECTOR_SCAN_MODES:
            errors.append(f"portScanProfiles[{index}].scanMode must be tcp-connect")
        if timing not in INSPECTOR_SCAN_TIMINGS:
            errors.append(f"portScanProfiles[{index}].timing must be slow or normal")
        if ports is None:
            errors.append(f"portScanProfiles[{index}].ports must contain ports or ranges between 1 and 65535")
        profiles.append(
            {
                "enabled": enabled,
                "targetGroup": target_group,
                "scanMode": scan_mode,
                "timing": timing,
                "ports": ports or "",
                "coreTargetWarningAcknowledged": _bool(raw.get("coreTargetWarningAcknowledged"), default=False),
            }
        )
    for index, profile in enumerate(profiles):
        if profile["enabled"] and profile["targetGroup"] == "core-public-management" and not profile["coreTargetWarningAcknowledged"]:
            errors.append(f"portScanProfiles[{index}] must acknowledge the OPSEC warning before scanning core public management IPs")
    return profiles


def _normalize_scan_ports(value: Any) -> str | None:
    text = _text(value)
    if not text:
        return ""
    normalized_parts: list[str] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            left, right = part.split("-", 1)
            start = _port(left)
            end = _port(right)
            if start is None or end is None or start > end:
                return None
            normalized_parts.append(f"{start}-{end}")
        else:
            port = _port(part)
            if port is None:
                return None
            normalized_parts.append(str(port))
    return ",".join(normalized_parts)


def _default_region(provider: str) -> str:
    try:
        policy = get_provider_region_policy(provider)
        if policy.allowed_regions:
            return policy.allowed_regions[0]
    except Exception:
        pass
    return DEFAULT_ALLOWED_REGIONS[provider][0]


def _real_inbound_channels(overview: dict[str, Any]) -> list[dict[str, Any]]:
    rows = overview.get("inboundChannels")
    if not isinstance(rows, list):
        return []
    channels = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        status = _text(row.get("status")).lower()
        if status in {"removed", "disabled", "not ready", "pending apply"}:
            continue
        if not _text(row.get("edge")) or not _text(row.get("externalPort")):
            continue
        channels.append(row)
    return channels


def _edge_public_ips(overview: dict[str, Any]) -> list[dict[str, str]]:
    return _sketch_public_ips(overview, role="edge")


def _sketch_public_ips(overview: dict[str, Any], *, role: str) -> list[dict[str, str]]:
    rows = overview.get("sketchInfrastructure")
    if not isinstance(rows, list):
        return []
    edges: list[dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict) or _text(row.get("role")).lower() != role:
            continue
        status = _text(row.get("status")).lower()
        public_ip = _text(row.get("publicIp"))
        if not public_ip or public_ip.lower() in {"not deployed", "not ready", "n/a", "not recorded"}:
            continue
        hostname = _text(row.get("hostname")) or _text(row.get("chainId")) or public_ip
        chain_id = _text(row.get("chainId"))
        component_id = _text(row.get("componentId"))
        edges.append(
            {
                "hostname": hostname,
                "publicIp": public_ip,
                "provider": _text(row.get("provider")),
                "chainId": chain_id,
                "componentId": component_id,
                "status": status,
            }
        )
    return edges


def _resolve_channel_sketch_component(
    channel: dict[str, Any],
    rows: list[dict[str, str]],
    *,
    role: str,
) -> dict[str, str] | None:
    host_field = "edge" if role == "edge" else "middle"
    component_field = "edgeComponentId" if role == "edge" else "middleComponentId"
    host_name = _text(channel.get(host_field))
    chain_id = _text(channel.get("chainId"))
    component_id = _text(channel.get(component_field))
    if chain_id or component_id:
        if not chain_id or not component_id:
            raise ObserverCheckValidationError(
                [f"inbound channel {role} identity requires both chainId and {component_field}"]
            )
        matches = [
            row
            for row in rows
            if row.get("chainId") == chain_id
            and row.get("componentId") == component_id
            and row.get("status") == "deployed"
            and (not host_name or row.get("hostname") == host_name)
        ]
        if len(matches) != 1:
            raise ObserverCheckValidationError(
                [
                    f"inbound channel {_text(channel.get('channelId')) or host_name} "
                    f"does not resolve one exact deployed {role} component"
                ]
            )
        return matches[0]

    matches = [
        row
        for row in rows
        if row.get("hostname") == host_name and row.get("status") in {"", "deployed"}
    ]
    if len(matches) > 1:
        raise ObserverCheckValidationError(
            [
                f"legacy inbound channel {_text(channel.get('channelId')) or host_name} "
                f"has an ambiguous {role} hostname"
            ]
        )
    return matches[0] if matches else None


def _core_public_ips_by_hostname(overview: dict[str, Any]) -> dict[str, str]:
    rows = overview.get("coreInfrastructure")
    if not isinstance(rows, list):
        return {}
    result: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        address = _text(row.get("publicIp"))
        if not address or address.lower() in {"not deployed", "not ready", "n/a", "not recorded"}:
            continue
        for name in {row.get("hostname"), row.get("displayName"), row.get("sshAlias")}:
            if _text(name):
                result[_text(name)] = address
    return result


def _dns_record_targets(engagement_id: str, edges: list[dict[str, str]]) -> list[dict[str, Any]]:
    if not edges:
        return []
    edge_ips = {edge["publicIp"] for edge in edges}
    try:
        workspace = get_engagement_dns_workspace(engagement_id) or {}
    except Exception:
        return []
    targets = []
    for domain in workspace.get("domains", []):
        if not isinstance(domain, dict):
            continue
        domain_name = _text(domain.get("domainName") or domain.get("domain"))
        dns = domain.get("dns")
        hosts = dns.get("hosts") if isinstance(dns, dict) else []
        if not domain_name or not isinstance(hosts, list):
            continue
        for record in hosts:
            if not isinstance(record, dict) or _text(record.get("type")).upper() not in {"A", "AAAA", "CNAME", "MX"}:
                continue
            address = _text(record.get("address") or record.get("value"))
            if address not in edge_ips:
                continue
            host_name = _text(record.get("name")) or "@"
            fqdn = domain_name if host_name == "@" else f"{host_name}.{domain_name}"
            targets.append(
                {
                    "id": f"dns:{fqdn}:{address}",
                    "type": "dns",
                    "host": fqdn,
                    "expectedIp": address,
                }
            )
    return targets


def _assigned_domain_names(engagement_id: str) -> set[str]:
    try:
        workspace = get_engagement_dns_workspace(engagement_id) or {}
    except Exception:
        return set()
    domains = set()
    for domain in workspace.get("domains", []):
        if not isinstance(domain, dict):
            continue
        domain_name = _normalize_domain(_text(domain.get("domainName") or domain.get("domain")))
        if domain_name and not _is_placeholder_domain(domain_name):
            domains.add(domain_name)
    return domains


def _assigned_channel_domain(value: Any, assigned_domains: set[str]) -> str:
    domain = _normalize_domain(_text(value))
    if not domain or _is_ip_address(domain) or _is_placeholder_domain(domain):
        return ""
    if any(domain == assigned or domain.endswith(f".{assigned}") for assigned in assigned_domains):
        return domain
    return ""


def _channel_http_host_header(value: Any) -> str:
    domain = _normalize_domain(_text(value))
    if not domain or _is_ip_address(domain):
        return ""
    if any(character.isspace() for character in domain) or "/" in domain or ":" in domain:
        return ""
    if "." not in domain:
        return ""
    return domain


def _normalize_domain(value: str) -> str:
    return value.strip().strip(".").lower()


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_placeholder_domain(domain: str) -> bool:
    labels = [label for label in domain.split(".") if label]
    if len(labels) < 2:
        return True
    if labels[-1] in {"invalid", "test", "localhost", "local", "internal"}:
        return True
    return domain in {"example.com", "example.net", "example.org"} or domain.endswith((".example.com", ".example.net", ".example.org"))


def _port_scan_targets(engagement_id: str, profiles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    overview = get_operations_overview(engagement_id, include_provider_findings=False) or {}
    edges = _edge_public_ips(overview)
    dns_targets = _dns_record_targets(engagement_id, edges)
    core_hosts = _core_public_management_hosts(overview)
    targets: list[dict[str, Any]] = []
    for index, profile in enumerate(profiles):
        if not profile.get("enabled"):
            continue
        ports = _text(profile.get("ports"))
        if not ports:
            continue
        group = _text(profile.get("targetGroup"))
        if group == "edges":
            for edge in edges:
                identity = (
                    f"{edge['chainId']}:{edge['componentId']}"
                    if edge.get("chainId") and edge.get("componentId")
                    else edge.get("componentId") or edge.get("chainId") or edge["hostname"]
                )
                targets.append(_nmap_target(index, identity, edge["publicIp"], ports, profile))
        elif group == "assigned-domains":
            for dns in dns_targets:
                targets.append(_nmap_target(index, _text(dns.get("host")), _text(dns.get("host")), ports, profile))
        elif group == "core-public-management":
            for core in core_hosts:
                targets.append(_nmap_target(index, core["hostname"], core["publicIp"], ports, profile))
    return targets


def _nmap_target(index: int, name: str, host: str, ports: str, profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"nmap:{index}:{name}:{ports}",
        "type": "nmap",
        "host": host,
        "ports": ports,
        "scanMode": profile.get("scanMode") or "tcp-connect",
        "timing": profile.get("timing") or "normal",
        "targetGroup": profile.get("targetGroup") or "edges",
    }


def _core_public_management_hosts(overview: dict[str, Any]) -> list[dict[str, str]]:
    rows = overview.get("coreInfrastructure")
    if not isinstance(rows, list):
        return []
    hosts: list[dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        public_ip = _text(row.get("publicIp") or row.get("publicManagementIp"))
        if not public_ip or public_ip.lower() in {"not deployed", "not ready", "n/a", "not recorded"}:
            continue
        hostname = _text(row.get("hostname") or row.get("host") or row.get("role") or public_ip)
        hosts.append({"hostname": hostname, "publicIp": public_ip})
    return hosts


def _looks_http_channel(channel: dict[str, Any]) -> bool:
    if _validation_profile_type(channel) == "http":
        return True
    request = _validation_profile_text(channel, "requestText").lstrip().upper()
    service = _text(channel.get("service")).lower()
    purpose = _text(channel.get("purpose")).lower()
    return request.startswith(("GET ", "HEAD ")) or "web" in service or "web" in purpose


def _validation_profile_type(channel: dict[str, Any]) -> str:
    profile = channel.get("validationProfile")
    if not isinstance(profile, dict):
        return ""
    return _text(profile.get("type")).lower()


def _validation_profile_text(channel: dict[str, Any], field: str) -> str:
    profile = channel.get("validationProfile")
    if not isinstance(profile, dict):
        return ""
    return _text(profile.get(field))


def _validation_expected(channel: dict[str, Any]) -> str:
    validation = channel.get("validation")
    if isinstance(validation, dict):
        observed = _text(validation.get("expectedResponse") or validation.get("expectedMarker"))
        if observed:
            return observed
    return _validation_profile_text(channel, "expectedResponse")


def _http_validation_expected(channel: dict[str, Any]) -> str:
    expected = _validation_expected(channel)
    # This is an operator-facing status contract, not a required response-body
    # marker. HTTP/HTTPS probes already enforce the documented 200--499 range
    # when no explicit marker is supplied.
    if expected.strip().casefold() == "http status below 500":
        return ""
    return expected


def _target_summary(targets: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    return {
        "positiveCount": len(targets.get("positive", [])),
        "negativeCount": len(targets.get("negative", [])),
        "positive": [_public_target_summary(target) for target in targets.get("positive", [])],
        "negative": [_public_target_summary(target) for target in targets.get("negative", [])],
    }


def _public_target_summary(target: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in target.items()
        if key
        in {
            "id",
            "type",
            "channelId",
            "edge",
            "edgePublicIp",
            "host",
            "port",
            "protocol",
            "ports",
            "expectedIp",
            "connectHost",
            "hostHeader",
            "targetGroup",
            "service",
            "purpose",
            "role",
            "controlId",
            "routeFingerprint",
            "infrastructureFingerprint",
        }
        and value not in {"", None}
    }


def _safe_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    return _redact_secretish(evidence)


def _record_observer_resource(
    repository: ProviderResourceRepository,
    engagement_id: str,
    engagement_name: str,
    host: ObserverHost,
    job_id: str,
    *,
    status: str,
    destroyed: bool = False,
) -> None:
    now = _now()
    repository.save(
        StoredProviderResourceRecord(
            id=f"{host.provider}:observer:{host.resource_id}",
            engagement_id=engagement_id,
            engagement_name=engagement_name,
            provider=host.provider,
            resource_type=f"observer_{host.resource_type}",
            resource_id=host.resource_id,
            name=host.name,
            region=host.region,
            lifecycle_state=status,
            status=status,
            source=OBSERVER_RESOURCE_SOURCE,
            metadata={
                **dict(host.metadata or {}),
                "role": "observer",
                "barraganOwned": True,
                "observerJobId": job_id,
                "cleanupRequired": not destroyed,
                "publicIp": host.public_ip,
                "publicIps": [host.public_ip],
                "sshUser": host.ssh_user,
            },
            adoption_job_id=job_id,
            adopted_at=now,
            updated_at=now,
            destroyed_at=now if destroyed else None,
        )
    )


def _record_inspector_resource(
    repository: ProviderResourceRepository,
    engagement_id: str,
    engagement_name: str,
    host: ObserverHost,
    job_id: str,
    *,
    status: str,
    destroyed: bool = False,
) -> None:
    now = _now()
    repository.save(
        StoredProviderResourceRecord(
            id=f"{host.provider}:inspector:{host.resource_id}",
            engagement_id=engagement_id,
            engagement_name=engagement_name,
            provider=host.provider,
            resource_type=f"inspector_{host.resource_type}",
            resource_id=host.resource_id,
            name=host.name,
            region=host.region,
            lifecycle_state=status,
            status=status,
            source=INSPECTOR_RESOURCE_SOURCE,
            metadata={
                **dict(host.metadata or {}),
                "role": "inspector",
                "barraganOwned": True,
                "inspectionJobId": job_id,
                "cleanupRequired": not destroyed,
                "publicIp": host.public_ip,
                "publicIps": [host.public_ip],
                "sshUser": host.ssh_user,
            },
            adoption_job_id=job_id,
            adopted_at=now,
            updated_at=now,
            destroyed_at=now if destroyed else None,
        )
    )
    firewall = dict(host.metadata or {}).get("providerFirewall")
    if not isinstance(firewall, dict) or not _text(firewall.get("resourceId")):
        return
    repository.save(
        StoredProviderResourceRecord(
            id=f"{host.provider}:inspector-firewall:{_text(firewall.get('resourceId'))}",
            engagement_id=engagement_id,
            engagement_name=engagement_name,
            provider=host.provider,
            resource_type="inspector_firewall",
            resource_id=_text(firewall.get("resourceId")),
            name=_text(firewall.get("name")),
            region=host.region,
            lifecycle_state=status,
            status=status,
            source=INSPECTOR_RESOURCE_SOURCE,
            metadata={
                "role": "inspector_firewall",
                "barraganOwned": True,
                "inspectorHostResourceId": host.resource_id,
                "inspectionJobId": job_id,
                "managementSourceCidr": _text(firewall.get("managementSourceCidr")),
                "cleanupRequired": not destroyed,
            },
            adoption_job_id=job_id,
            adopted_at=now,
            updated_at=now,
            destroyed_at=now if destroyed else None,
        )
    )


def _provider_for(
    provider: str,
    image_profile: ManagedHostImageProfile | None = None,
) -> ObserverProvider:
    selected = image_profile or managed_host_image_profile()
    if provider == "linode":
        return LinodeObserverProvider(image=selected.linode_image)
    if provider == "digitalocean":
        return DigitalOceanObserverProvider(image=selected.digitalocean_image)
    raise ObserverCheckValidationError(["provider must be linode or digitalocean"])


def _provider_factory_for_engagement(
    engagement_id: str,
    provider_factory: Callable[[str], ObserverProvider] | None,
) -> Callable[[str], ObserverProvider]:
    if provider_factory is not None:
        return provider_factory
    return lambda provider: _provider_for(
        provider,
        resolve_or_pin_profile_for_new_managed_host(engagement_id),
    )


def _observer_host_name(engagement_name: str, job_id: str) -> str:
    slug = "".join(character.lower() if character.isalnum() else "-" for character in engagement_name)
    slug = "-".join(part for part in slug.split("-") if part) or "engagement"
    return f"observer-{slug}-{job_id[-6:]}"[:64]


def _inspector_host_name(engagement_name: str, job_id: str) -> str:
    slug = "".join(character.lower() if character.isalnum() else "-" for character in engagement_name)
    slug = "-".join(part for part in slug.split("-") if part) or "engagement"
    return f"inspector-{slug}-{job_id[-6:]}"[:64]


def _observer_root_password() -> str:
    return f"BarraganObserver-{secrets.token_urlsafe(24)}A1!"


def _observer_cloud_init(public_key: str) -> str:
    return textwrap.dedent(
        f"""\
        #cloud-config
        users:
          - default
          - name: {INSPECTOR_ADMIN_USER}
            groups: sudo
            shell: /bin/bash
            lock_passwd: true
            sudo: ALL=(ALL) NOPASSWD:ALL
            ssh_authorized_keys:
              - {public_key}
        ssh_pwauth: false
        package_update: false
        """
    )


def _reusable_inspector_host(settings: StoredObserverSettings) -> ObserverHost | None:
    host = _inspector_host_from_settings(settings.current_host, settings=settings)
    if host is None:
        return None
    if settings.mode == "once" and _parse_utc(settings.idle_retention_until) <= datetime.now(timezone.utc):
        return None
    if settings.mode not in {"once", "continuous"}:
        return None
    return host


def _inspector_host_from_settings(
    value: dict[str, Any],
    *,
    settings: StoredObserverSettings,
) -> ObserverHost | None:
    host = value or {}
    provider = _text(host.get("provider") or settings.provider)
    resource_type = _text(host.get("resourceType") or "instance")
    resource_id = _text(host.get("resourceId"))
    name = _text(host.get("name"))
    region = _text(host.get("region") or settings.region)
    public_ip = _text(host.get("publicIp"))
    ssh_user = _text(host.get("sshUser")) or "root"
    if not provider or not resource_id or not public_ip:
        return None
    return ObserverHost(
        provider=provider,
        resource_type=resource_type,
        resource_id=resource_id,
        name=name,
        region=region,
        public_ip=public_ip,
        ssh_user=ssh_user,
        status=_text(host.get("status") or "running"),
        metadata=dict(host.get("metadata") or {}),
    )


def _safe_cleanup_error(exc: Exception) -> str:
    message = str(exc) or type(exc).__name__
    message = re.sub(r"(?i)(token|secret|key|password)[^,\s]+", "[redacted]", message)
    return message[:300]


def _should_retain_inspector_host(settings: StoredObserverSettings, host: ObserverHost | None) -> bool:
    return host is not None and settings.mode in {"once", "continuous"}


def _retention_until(settings: StoredObserverSettings) -> str:
    if settings.mode == "once":
        return (datetime.now(timezone.utc) + timedelta(minutes=INSPECTOR_ONCE_RETENTION_MINUTES)).isoformat()
    return ""


def _parse_utc(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def _inspection_findings(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in evidence.get("results", []):
        if isinstance(result, dict) and not result.get("ok"):
            findings.append(
                {
                    "id": _text(result.get("id")),
                    "type": _text(result.get("type")),
                    "severity": "warning",
                    "detail": _text(result.get("observed"))[:500],
                }
            )
    return findings


def _generate_observer_ssh_key(job_id: str) -> ObserverSshKey:
    temp_dir = tempfile.mkdtemp(prefix=f"barragan-observer-{job_id}-")
    private_key_path = str(Path(temp_dir) / "id_ed25519")
    completed = subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", private_key_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ObserverCheckValidationError(["could not generate observer SSH key"])
    public_key = Path(f"{private_key_path}.pub").read_text(encoding="utf-8").strip()
    return ObserverSshKey(private_key_path=private_key_path, public_key=public_key, cleanup_paths=(temp_dir,))


def _generate_inspector_ssh_key(job_id: str) -> ObserverSshKey:
    key_dir = _inspector_key_dir()
    key_dir.mkdir(parents=True, exist_ok=True)
    private_key_path = key_dir / "id_ed25519"
    if not private_key_path.exists():
        completed = subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private_key_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise InspectionValidationError(["could not generate inspector SSH key"])
        private_key_path.chmod(0o600)
    public_key = Path(f"{private_key_path}.pub").read_text(encoding="utf-8").strip()
    return ObserverSshKey(private_key_path=str(private_key_path), public_key=public_key, cleanup_paths=())


def _inspector_key_dir() -> Path:
    try:
        data_dir = runtime_value("DATA_DIR")
        if data_dir:
            return Path(data_dir) / "inspector-keys"
    except RuntimeError:
        pass
    return Path(os.environ.get("BARRAGAN_INSPECTOR_KEY_DIR", ".data/inspector-keys"))


def _cleanup_ssh_key(ssh_key: ObserverSshKey) -> None:
    for path_text in ssh_key.cleanup_paths:
        path = Path(path_text)
        try:
            if path.is_dir():
                for child in path.iterdir():
                    child.unlink(missing_ok=True)
                path.rmdir()
            else:
                path.unlink(missing_ok=True)
        except OSError:
            pass


def _linode_public_ip(instance: dict[str, Any]) -> str:
    ipv4 = instance.get("ipv4")
    if isinstance(ipv4, list):
        for value in ipv4:
            text = _text(value)
            if text:
                return text
    return ""


def _digitalocean_public_ip(droplet: dict[str, Any]) -> str:
    networks = droplet.get("networks")
    if isinstance(networks, dict):
        for network in networks.get("v4", []):
            if isinstance(network, dict) and network.get("type") == "public":
                return _text(network.get("ip_address"))
    return ""


def _fence_option(fence: Callable[[], None] | None) -> dict[str, Callable[[], None]]:
    return {"fence": fence} if fence is not None else {}



def _observer_check_execution_timeout(spec: dict[str, Any]) -> int:
    """Allow the serialized probe matrix to finish within a finite outer budget."""
    timeout = spec.get("timeoutSeconds") or 8
    if type(timeout) is not int or not 1 <= timeout <= 120:
        raise ObserverCheckValidationError(["Inspector probe timeout is invalid"])
    # SSH startup, JSON serialization and result transfer retain a fixed margin.
    settle = spec.get("dnsSettleSeconds", 0)
    if type(settle) is not int or not 0 <= settle <= 900:
        raise ObserverCheckValidationError(["Inspector DNS settling budget is invalid"])
    budget = 60 + settle
    for target in spec.get("positive", []):
        kind = target.get("type")
        # DNS: two resolvers, up to A+AAAA; HTTP/TLS and request/reply
        # probes also perform several serial socket operations per target.
        budget += (60 if kind == "nmap" else timeout if kind == "tcp"
                   else 2 * timeout if kind == "udp" else 4 * timeout)
    for target in spec.get("negative", []):
        kind = target.get("type")
        # Match the script's bounded DNS absence retries and negative socket cap.
        budget += (2 * timeout if kind == "dns-record-absent" else 12 * timeout + 4 if kind == "dns-absent"
                   else 2 * min(timeout, 4) if kind == "udp-forbidden"
                   else min(timeout, 4))
    if budget > INSPECTOR_CHECK_EXECUTION_MAX_SECONDS:
        raise ObserverCheckValidationError(["Inspector check matrix exceeds the bounded execution budget"])
    return max(120, budget)


def _run_checked(
    command: list[str], *, cwd: Path | None = None, check: bool = True,
    fence: Callable[[], None] | None = None,
    timeout_seconds: int = 120,
) -> subprocess.CompletedProcess[str]:
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= INSPECTOR_CHECK_EXECUTION_MAX_SECONDS:
        raise ValueError("observer command timeout differs")
    if fence is not None:
        fence()
    try:
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, timeout=timeout_seconds, check=False, cwd=cwd)
    finally:
        if fence is not None:
            fence()
    if check and completed.returncode != 0:
        raise ObserverCheckValidationError([f"observer command failed: {command[0]}", _safe_command_error(completed)])
    return completed


def _run_checked_with_retries(
    command: list[str], *, attempts: int, delay_seconds: float, description: str,
    fence: Callable[[], None] | None = None,
) -> subprocess.CompletedProcess[str]:
    last_completed: subprocess.CompletedProcess[str] | None = None
    for attempt in range(max(1, attempts)):
        last_completed = _run_checked(command, check=False, **_fence_option(fence))
        if last_completed.returncode == 0:
            return last_completed
        if attempt < attempts - 1:
            time.sleep(delay_seconds)
    detail = _safe_command_error(last_completed) if last_completed is not None else "no command result recorded"
    raise ObserverCheckValidationError([description, detail])


def _safe_command_error(completed: subprocess.CompletedProcess[str]) -> str:
    preview = (completed.stderr or completed.stdout or "").strip()[-1000:]
    if not preview:
        preview = f"exit status {completed.returncode}"
    return _redact_secretish(preview)


def _append_event(repository: JobRepository, job: StoredJobRun, level: str, message: str, data: dict[str, Any]) -> StoredJobRun:
    updated = replace(job, events=[*job.events, JobEvent(len(job.events) + 1, level, message, _redact_secretish(data))])
    _assert_no_secret_material(updated.to_detail().to_dict())
    return repository.save(updated)


def _start_background_task(task: Callable[[], None]) -> None:
    start_runtime_task(task, name="barragan-observer-check-runner")


def _port(value: Any) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if port < 1 or port > 65535:
        return None
    return port


def _text(value: Any) -> str:
    return str(value or "").strip()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_provider_error(exc: Exception) -> str:
    text = str(exc)
    lowered = text.lower()
    for marker in ("token", "secret", "password", "root_pass", "authorization", "private key"):
        if marker in lowered:
            return f"{type(exc).__name__}: provider error redacted"
    return text[:1000]


def _redact_secretish(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: ("<redacted>" if _secretish_key(key) else _redact_secretish(child)) for key, child in value.items()}
    if isinstance(value, list):
        return [_redact_secretish(child) for child in value]
    if isinstance(value, str) and _secretish_value(value):
        return "<redacted>"
    return value


def _secretish_key(key: str) -> bool:
    normalized = "".join(character.lower() if character.isalnum() else "_" for character in key)
    return any(part in normalized for part in ("token", "secret", "password", "private_key", "root_pass", "authorization"))


def _secretish_value(value: str) -> bool:
    lowered = value.lower()
    return any(
        marker in lowered
        for marker in (
            "begin openssh private key",
            "authorization:",
            "bearer ",
            "root_pass",
            "linode_api_token",
            "digitalocean_token",
            "do_pat",
        )
    )


def _assert_no_secret_material(payload: dict[str, Any]) -> None:
    serialized = json.dumps(payload, sort_keys=True)
    if _secretish_value(serialized):
        raise ObserverCheckValidationError(["observer job payload appears to contain secret material"])


_OBSERVER_SCRIPT = r"""
import errno
import http.client
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import shutil
import struct
import subprocess
import sys
import time


def tcp_connect(host, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, int(port)))
        return True, ""
    except Exception as exc:
        return False, str(exc)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def tcp_absence_probe(host, port, timeout):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        return "open", {"status": "open", "reason": "connection_succeeded"}
    except OSError as exc:
        if exc.errno == errno.ECONNREFUSED:
            return "closed", {"status": "closed", "reason": "connection_refused"}
        reason = ("timed_out" if isinstance(exc, TimeoutError)
                  else "name_resolution_failed" if isinstance(exc, socket.gaierror)
                  else "network_unreachable" if exc.errno in {errno.ENETUNREACH, errno.EHOSTUNREACH}
                  else "transport_error")
        return "inconclusive", {"status": "inconclusive", "reason": reason, "errorType": type(exc).__name__}
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def udp_absence_probe(host, port, timeout):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        sock.send(b"probe")
        sock.recv(4096)
        return "open", {"status": "open", "reason": "response_received"}
    except OSError as exc:
        if exc.errno == errno.ECONNREFUSED:
            return "closed", {"status": "closed", "reason": "connection_refused"}
        reason = "timed_out" if isinstance(exc, TimeoutError) else "transport_error"
        return "inconclusive", {"status": "inconclusive", "reason": reason, "errorType": type(exc).__name__}
    finally:
        if sock is not None:
            sock.close()


def tcp_send_expect(host, port, request_text, expected, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, int(port)))
        if request_text:
            sock.sendall(request_text.encode("utf-8"))
        data = sock.recv(8192)
        observed = data.decode("utf-8", errors="replace")
        return (expected in observed if expected else bool(observed)), observed
    except Exception as exc:
        return False, str(exc)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def udp_probe(host, port, request_text, expected, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto((request_text or "barragan-observer-udp").encode("utf-8"), (host, int(port)))
        data, _addr = sock.recvfrom(4096)
        observed = data.decode("utf-8", errors="replace")
        return (expected in observed if expected else bool(observed)), observed
    except Exception as exc:
        return False, str(exc)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def http_probe(connect_host, host_header, port, path, expected, timeout):
    try:
        conn = http.client.HTTPConnection(connect_host, int(port), timeout=timeout)
        conn.request("GET", path or "/", headers={"Host": host_header or connect_host})
        response = conn.getresponse()
        body = response.read(8192).decode("utf-8", errors="replace")
        conn.close()
        ok_status = 200 <= int(response.status) < 500
        ok_body = expected in body if expected else True
        return ok_status and ok_body, {"status": response.status, "bodyPreview": body[:500]}
    except Exception as exc:
        return False, str(exc)


def https_probe(connect_host, server_name, port, path, expected, timeout):
    raw = None
    tls = None
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((connect_host, int(port)), timeout=timeout)
        tls = context.wrap_socket(raw, server_hostname=server_name or connect_host)
        request = "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n".format(path or "/", server_name or connect_host)
        tls.sendall(request.encode("utf-8"))
        chunks = []
        total = 0
        while total < 8192:
            chunk = tls.recv(min(4096, 8192 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        response = b"".join(chunks)
        headers, _separator, body = response.partition(b"\r\n\r\n")
        status_line = headers.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        parts = status_line.split(" ", 2)
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        body_text = body.decode("utf-8", errors="replace")
        peer = tls.getpeercert(binary_form=True) or b""
        observed = {
            "status": status,
            "bodyPreview": body_text[:500],
            "tlsVersion": tls.version(),
            "cipher": (tls.cipher() or [""])[0],
            "fingerprintSha256": hashlib.sha256(peer).hexdigest() if peer else "",
            "sni": server_name or connect_host,
        }
        ok_status = 200 <= status < 500
        ok_body = expected in body_text if expected else True
        return bool(peer) and ok_status and ok_body, observed
    except Exception as exc:
        return False, str(exc)
    finally:
        try:
            if tls is not None:
                tls.close()
            elif raw is not None:
                raw.close()
        except Exception:
            pass


DNS_RESOLVERS = ("1.1.1.1", "8.8.8.8")
DNS_ABSENCE_ATTEMPTS = 3


def _dns_name(packet, offset):
    # Validate even compressed names; a bad pointer must never prove absence.
    visited = set()
    end = None
    labels = []
    while True:
        if offset >= len(packet) or offset in visited:
            raise ValueError("malformed DNS name")
        visited.add(offset)
        length = packet[offset]
        if length & 0xc0 == 0xc0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3f) << 8) | packet[offset + 1]
            if pointer >= len(packet):
                raise ValueError("invalid DNS pointer")
            if end is None:
                end = offset + 2
            offset = pointer
        elif length & 0xc0:
            raise ValueError("invalid DNS label")
        elif length == 0:
            return b".".join(labels).lower(), end if end is not None else offset + 1
        else:
            if length > 63 or offset + 1 + length > len(packet):
                raise ValueError("truncated DNS label")
            labels.append(packet[offset + 1:offset + 1 + length])
            offset += 1 + length


def _dns_ip_response(packet, query_id, question_name, question_type):
    if len(packet) < 12:
        raise ValueError("truncated DNS header")
    response_id, flags, questions, answers, authority, additional = struct.unpack("!HHHHHH", packet[:12])
    if (response_id != query_id or not flags & 0x8000 or not flags & 0x0080
            or flags & 0x0200 or questions != 1):
        raise ValueError("invalid or truncated DNS response")
    rcode = flags & 0x000f
    if rcode not in (0, 3):
        raise ValueError("DNS resolver returned error")
    echoed_name, offset = _dns_name(packet, 12)
    if (echoed_name != question_name or offset + 4 > len(packet)
            or packet[offset:offset + 4] != struct.pack("!HH", question_type, 1)):
        raise ValueError("invalid DNS question")
    offset += 4
    addresses = {}
    aliases = {}
    for _ in range(answers):
        owner, offset = _dns_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("truncated DNS answer")
        record_type, record_class, _ttl, size = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        if offset + size > len(packet):
            raise ValueError("truncated DNS record")
        if record_class == 1 and record_type == question_type:
            if question_type in (1, 28):
                if size != (4 if question_type == 1 else 16):
                    raise ValueError("invalid DNS address record")
                address = (socket.inet_ntoa(packet[offset:offset + 4]) if question_type == 1
                           else socket.inet_ntop(socket.AF_INET6, packet[offset:offset + 16]))
            elif question_type in (2, 5, 15):
                start = offset + 2 if question_type == 15 else offset
                if start > offset + size:
                    raise ValueError("invalid DNS name record")
                name, end = _dns_name(packet, start)
                if end != offset + size:
                    raise ValueError("invalid DNS name record")
                address = name.decode("ascii").lower().rstrip(".")
                if question_type == 15:
                    address = str(struct.unpack("!H", packet[offset:offset + 2])[0]) + " " + address
            elif question_type == 16:
                chunks, cursor = [], offset
                while cursor < offset + size:
                    length = packet[cursor]
                    cursor += 1
                    if cursor + length > offset + size:
                        raise ValueError("invalid DNS text record")
                    chunks.append(packet[cursor:cursor + length])
                    cursor += length
                address = b"".join(chunks).decode("utf-8")
            else:
                raise ValueError("unsupported DNS record type")
            addresses.setdefault(owner, set()).add(address)
        if record_class == 1 and record_type == 5:
            alias, end = _dns_name(packet, offset)
            if end != offset + size or owner in aliases and aliases[owner] != alias:
                raise ValueError("invalid DNS CNAME record")
            aliases[owner] = alias
        offset += size
    negative_soa = False
    for _ in range(authority):
        _owner, offset = _dns_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("truncated DNS authority")
        record_type, record_class, _ttl, size = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        if offset + size > len(packet):
            raise ValueError("truncated DNS authority record")
        if record_class == 1 and record_type == 6:
            _mname, next_offset = _dns_name(packet, offset)
            _rname, next_offset = _dns_name(packet, next_offset)
            if next_offset + 20 != offset + size:
                raise ValueError("invalid DNS SOA record")
            negative_soa = True
        offset += size
    for _ in range(additional):
        _owner, offset = _dns_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("truncated DNS additional record")
        _record_type, _record_class, _ttl, size = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10 + size
        if offset > len(packet):
            raise ValueError("truncated DNS additional value")
    if offset != len(packet):
        raise ValueError("unexpected DNS response bytes")
    if rcode == 3:
        if answers or not negative_soa:
            raise ValueError("inconsistent DNS NXDOMAIN response")
        return []
    if question_type not in (1, 28):
        selected = sorted(addresses.get(question_name, set()))
        if not selected and not negative_soa:
            raise ValueError("DNS negative answer lacks SOA proof")
        return selected
    name = question_name
    visited = set()
    while name in aliases:
        if name in visited:
            raise ValueError("DNS CNAME loop")
        visited.add(name)
        name = aliases[name]
    if name != question_name and not addresses.get(name):
        raise ValueError("DNS CNAME target was not resolved")
    selected_addresses = sorted(addresses.get(name, set()))
    if not selected_addresses and not negative_soa:
        raise ValueError("DNS negative answer lacks SOA proof")
    return selected_addresses


def _dns_ip_lookup(host, resolver, timeout, question_type):
    labels = host.rstrip(".").encode("idna").split(b".")
    if not labels or any(not label or len(label) > 63 for label in labels):
        raise ValueError("invalid DNS host")
    question_name = b".".join(labels).lower()
    query_id = struct.unpack("!H", os.urandom(2))[0]
    question = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00" + struct.pack("!HH", question_type, 1)
    packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect((resolver, 53))
        sock.sendall(packet)
        return _dns_ip_response(sock.recv(4096), query_id, question_name, question_type)


def dns_probe(host, expected_ip, timeout=8):
    try:
        question_types = (28,) if expected_ip and ipaddress.ip_address(expected_ip).version == 6 else ((1,) if expected_ip else (1, 28))
    except ValueError:
        return "inconclusive", {"error": "invalid expected IP address"}
    observations = {}
    for resolver in DNS_RESOLVERS:
        addresses = []
        try:
            for question_type in question_types:
                addresses.extend(_dns_ip_lookup(host, resolver, timeout, question_type))
            observations[resolver] = {"status": "answered", "ips": sorted(set(addresses))}
        except (OSError, ValueError) as exc:
            observations[resolver] = {"status": "inconclusive", "error": type(exc).__name__}
    answered = [row["ips"] for row in observations.values() if row["status"] == "answered"]
    present = any(expected_ip in ips if expected_ip else bool(ips) for ips in answered)
    if present:
        return "present", observations
    if len(answered) == len(DNS_RESOLVERS):
        return "absent", observations
    return "inconclusive", observations


def dns_record_probe(host, record_type, previous, timeout=8):
    kinds = {"A": 1, "AAAA": 28, "CNAME": 5, "TXT": 16, "MX": 15, "NS": 2}
    observations = {}
    for resolver in DNS_RESOLVERS:
        try:
            answers = _dns_ip_lookup(host, resolver, timeout, kinds[record_type])
            observations[resolver] = {"status": "answered", "answers": sorted(set(answers))}
        except (OSError, ValueError, KeyError) as exc:
            observations[resolver] = {"status": "inconclusive", "error": type(exc).__name__}
    answered = [row["answers"] for row in observations.values() if row["status"] == "answered"]
    if any(previous in values for values in answered):
        return "present", observations
    return ("absent" if len(answered) == len(DNS_RESOLVERS) else "inconclusive"), observations


def nmap_probe(host, ports, scan_mode, timing):
    if not shutil.which("nmap"):
        return False, {"error": "Inspector nmap dependency is unavailable on inspector host"}
    args = ["nmap", "-Pn", "-n"]
    if scan_mode == "tcp-connect":
        args.append("-sT")
    if timing == "slow":
        args.append("-T2")
    else:
        args.append("-T3")
    args.extend(["-p", str(ports), str(host)])
    try:
        completed = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60, check=False)
        output = (completed.stdout + "\n" + completed.stderr)[-12000:]
        requested_ports = set()
        for part in str(ports).split(","):
            if "-" in part:
                start, end = (int(value) for value in part.split("-", 1))
                requested_ports.update(range(start, end + 1))
            else:
                requested_ports.add(int(part))
        open_ports = {
            int(match.group(1))
            for match in re.finditer(r"(?m)^(\d+)/(?:tcp|udp)\s+open(?:\s|$)", output)
        }
        missing_ports = sorted(requested_ports - open_ports)
        observed = {
            "returnCode": completed.returncode,
            "requestedPorts": sorted(requested_ports),
            "openPorts": sorted(open_ports),
            "missingOpenPorts": missing_ports,
            "output": output,
        }
        return completed.returncode == 0 and not missing_ports, observed
    except Exception as exc:
        return False, str(exc)


def run(spec):
    timeout = int(spec.get("timeoutSeconds") or 8)
    results = []
    positive_results = {}
    ok = True
    settle = spec.get("dnsSettleSeconds", 0)
    if type(settle) is not int or not 0 <= settle <= 900:
        raise ValueError("invalid DNS settling budget")
    dns_deadline = time.monotonic() + settle if settle else None
    for target in spec.get("positive", []):
        check_type = target.get("type")
        target_ok = False
        observed = ""
        if check_type == "tcp":
            target_ok, observed = tcp_connect(target.get("connectHost") or target["host"], target["port"], timeout)
        elif check_type == "tcp-send-expect":
            target_ok, observed = tcp_send_expect(target.get("connectHost") or target["host"], target["port"], target.get("requestText"), target.get("expectedResponse"), timeout)
        elif check_type == "udp":
            target_ok, observed = udp_probe(target.get("connectHost") or target["host"], target["port"], target.get("requestText"), target.get("expectedResponse"), timeout)
        elif check_type == "http":
            target_ok, observed = http_probe(target.get("connectHost") or target["host"], target.get("hostHeader") or target["host"], target["port"], target.get("path"), target.get("expectedResponse"), timeout)
        elif check_type == "https":
            target_ok, observed = https_probe(target.get("connectHost") or target["host"], target.get("hostHeader") or target["host"], target["port"], target.get("path"), target.get("expectedResponse"), timeout)
        elif check_type == "dns":
            dns_status, observed = dns_probe(target["host"], target.get("expectedIp"), timeout)
            target_ok = dns_status == "present"
        elif check_type == "nmap":
            target_ok, observed = nmap_probe(target["host"], target.get("ports"), target.get("scanMode"), target.get("timing"))
        else:
            observed = "unsupported check type"
        ok = ok and target_ok
        results.append({"id": target.get("id"), "type": check_type, "expected": "reachable", "ok": target_ok, "observed": observed})
        positive_results[target.get("id")] = target_ok
    for target in spec.get("negative", []):
        check_type = target.get("type")
        if check_type == "dns-record-absent":
            attempts = 0
            while True:
                attempts += 1
                remaining = max(0, dns_deadline - time.monotonic()) if dns_deadline is not None else 0
                dns_status, observed = dns_record_probe(target["host"], target["recordType"],
                    target["previousAnswer"], min(timeout, max(1, remaining / 2)) if dns_deadline is not None else timeout)
                if dns_status != "present" or attempts >= 451 or dns_deadline is None or time.monotonic() >= dns_deadline:
                    break
                time.sleep(min(2, max(0, dns_deadline - time.monotonic())))
            target_ok = dns_status == "absent"
            results.append({"id": target.get("id"), "type": check_type, "expected": "absent",
                "ok": target_ok, "observed": observed, "attemptCount": attempts})
            ok = ok and target_ok
            continue
        if check_type == "dns-absent":
            for attempt in range(DNS_ABSENCE_ATTEMPTS):
                dns_status, observed = dns_probe(target["host"], target.get("expectedIp"), timeout)
                if dns_status != "present" or attempt + 1 == DNS_ABSENCE_ATTEMPTS:
                    break
                time.sleep(2)
            target_ok = dns_status == "absent"
            results.append({"id": target.get("id"), "type": check_type, "expected": "absent", "ok": target_ok, "observed": observed})
            ok = ok and target_ok
            continue
        if check_type == "udp-forbidden" and spec.get("strictNegativeUdp") is True:
            udp_status, observed = udp_absence_probe(target["host"], target["port"], min(timeout, 4))
            target_ok = udp_status == "closed"
        elif check_type == "udp-forbidden":
            control_id = target.get("controlId")
            if positive_results.get(control_id) is not True:
                target_ok = False
                observed = "same-run UDP positive control failed or was not run"
                results.append({"id": target.get("id"), "type": check_type, "expected": "closed", "ok": target_ok, "observed": observed})
                ok = False
                continue
            connected, observed = udp_probe(target["host"], target["port"], target.get("requestText"), "", min(timeout, 4))
            target_ok = not connected
            if connected:
                observed = "unexpectedly open"
        elif spec.get("strictNegativeTcp") is True:
            tcp_status, observed = tcp_absence_probe(target["host"], target["port"], min(timeout, 4))
            target_ok = tcp_status == "closed"
        else:
            connected, observed = tcp_connect(target["host"], target["port"], min(timeout, 4))
            target_ok = not connected
            if connected:
                observed = "unexpectedly open"
        ok = ok and target_ok
        results.append({"id": target.get("id"), "type": check_type, "expected": "closed", "ok": target_ok, "observed": observed})
    return {"ok": ok, "results": results}


with open(sys.argv[1], "r", encoding="utf-8") as handle:
    print(json.dumps(run(json.load(handle)), sort_keys=True))
"""
