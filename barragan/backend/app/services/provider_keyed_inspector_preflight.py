# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only retained-Inspector gate for the keyed teardown coordinator.

Persisted preparation metadata is not a fresh reachability or external-probe
result. This gate never creates, prepares, or contacts an Inspector host.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from app.services.engagement_teardown import _fingerprint
from app.services.observer_checks import (
    INSPECTOR_RESOURCE_SOURCE, _inspector_host_from_settings,
    _inspector_support_baseline_current, _is_inspector_resource_record,
    _retired_target_public_ips, _usable_inspector_host,
)
from app.services.provider_keyed_comprehensive_teardown import (
    ACTION, _FENCE, _boundary, _child_id, _same_child, _verify_published_source,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_teardown_quiescence import audit_pending_provider_keyed_bootstrap
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import (
    SqlAlchemyProviderResourceRepository, TERMINAL_RECORD_STATUSES,
)


class ProviderKeyedInspectorPreflightError(ValueError):
    """The retained Inspector boundary cannot be proven read-only."""


class ProviderKeyedInspectorPreflightRequired(ProviderKeyedInspectorPreflightError):
    """No exact prepared retained Inspector exists; creation is a separate gate."""


class ProviderKeyedInspectorPreflightAmbiguous(ProviderKeyedInspectorPreflightError):
    """Multiple or mismatched active Inspector identities require reconciliation."""


@dataclass(frozen=True)
class PersistedInspectorPreflightEvidence:
    engagement_id: str
    teardown_parent_id: str
    coordinator_job_id: str
    scope_snapshot_id: str
    owned_record_id: str
    provider: str
    resource_type: str
    provider_resource_id: str
    public_ip: str
    settings_updated_at: str
    prepared_metadata_only: bool = True
    live_reachability_proven: bool = False


def inspect_prepared_keyed_teardown_inspector(
    teardown_parent_id: str, *, environment: str,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, lease_lookup=None,
    pending_auditor: Callable = audit_pending_provider_keyed_bootstrap,
    state_root: Path | None = None,
) -> PersistedInspectorPreflightEvidence:
    """Return exact persisted identity, with no provider, SSH, or DB mutation."""
    try:
        if environment != "devtest" or not teardown_parent_id:
            raise ValueError("DevTest keyed Inspector gate only")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        lookup = lease_lookup or _db_lease_lookup

        def authority():
            parent, core, snapshot, operation = _boundary(
                teardown_parent_id, jobs, plans, lookup)
            child = jobs.get(_child_id(core.id))
            if (operation != _FENCE or child is None or child.action != ACTION
                    or child.input.get("phase") != "awaiting_inspector_preflight"
                    or not _same_child(child, parent, core, snapshot)
                    or len([row for row in jobs.list_for_engagement(parent.target_id)
                            if row.action == ACTION]) != 1):
                raise ValueError("coordinator handoff is not sealed")
            scope = snapshot["providerScopes"][0]
            if "publishedSource" in parent.input:
                _verify_published_source(parent, environment=environment,
                                         state_root=state_root, jobs=jobs, plans=plans)
            else:
                pending_auditor(
                    core.id, confirmed_scope=scope,
                    confirmed_scope_sha256=_fingerprint(snapshot),
                    workspace_root=Path(scope["workspace"]), job_repository=jobs,
                )
            return parent, core, snapshot, child

        before = authority()
        parent, _core, snapshot, child = before
        settings = settings_repo.get(parent.target_id)
        if settings is None or settings.engagement_id != parent.target_id:
            raise ProviderKeyedInspectorPreflightRequired(
                "a prepared retained Inspector is required before outbound cleanup")
        current = settings.current_host
        host = _inspector_host_from_settings(current, settings=settings)
        if (not isinstance(current, dict) or not all(
                isinstance(current.get(key), str) and current[key] for key in
                ("provider", "resourceType", "resourceId", "publicIp"))
                or not _usable_inspector_host(host)
                or not _inspector_support_baseline_current(host)
                or (host.status.lower() not in {"active", "running"}
                    and not (host.provider == "linode" and host.status.lower() == "offline"))):
            raise ProviderKeyedInspectorPreflightRequired(
                "a prepared retained Inspector is required before outbound cleanup")
        if (host.provider != settings.provider or host.region != settings.region
                or host.public_ip in _retired_target_public_ips(
                    list(snapshot.get("publicVerificationTargets") or []))):
            raise ProviderKeyedInspectorPreflightAmbiguous(
                "retained Inspector identity conflicts with confirmed teardown targets")
        records = tuple(resources.list_for_engagement(parent.target_id))
        active_hosts = [row for row in records if _is_inspector_resource_record(row)
                        and str(row.status).lower() not in TERMINAL_RECORD_STATUSES]
        if not active_hosts:
            raise ProviderKeyedInspectorPreflightRequired(
                "an explicitly owned active Inspector record is required")
        if len(active_hosts) != 1:
            raise ProviderKeyedInspectorPreflightAmbiguous(
                "active Inspector ownership is ambiguous")
        record = active_hosts[0]
        metadata = record.metadata if isinstance(record.metadata, dict) else {}
        if (metadata.get("barraganOwned") is not True
                or record.source != INSPECTOR_RESOURCE_SOURCE
                or record.id != f"{record.provider}:inspector:{record.resource_id}"
                or record.engagement_id != parent.target_id
                or record.status.lower() not in {"active", "running"}
                or record.lifecycle_state.lower() not in {"active", "running"}
                or record.provider != host.provider
                or record.resource_type != f"inspector_{host.resource_type}"
                or record.resource_id != host.resource_id
                or record.region != host.region or record.name != host.name
                or metadata.get("publicIp") != host.public_ip
                or type(metadata.get("publicIps")) is not list
                or host.public_ip not in metadata["publicIps"]
                or metadata.get("role") != "inspector"
                or metadata.get("providerFirewall")
                != dict(host.metadata or {}).get("providerFirewall")
                or not record.adoption_job_id
                or metadata.get("inspectionJobId") != record.adoption_job_id):
            raise ProviderKeyedInspectorPreflightAmbiguous(
                "retained Inspector record differs from settings")
        active_firewalls = [row for row in records
                            if (row.resource_type == "inspector_firewall"
                                or (isinstance(row.metadata, dict)
                                    and row.metadata.get("role") == "inspector_firewall"))
                            and str(row.status).lower() not in TERMINAL_RECORD_STATUSES]
        firewall = dict(host.metadata or {}).get("providerFirewall")
        if firewall is None:
            if active_firewalls:
                raise ProviderKeyedInspectorPreflightAmbiguous(
                    "unexpected active Inspector firewall record")
        else:
            if (not isinstance(firewall, dict) or len(active_firewalls) != 1
                    or not all(isinstance(firewall.get(key), str) and firewall[key] for key in
                               ("provider", "resourceType", "resourceId", "name"))
                    or firewall["provider"] != host.provider
                    or firewall["resourceType"] != "firewall"):
                raise ProviderKeyedInspectorPreflightAmbiguous(
                    "reviewed Inspector firewall record is missing or ambiguous")
            firewall_record = active_firewalls[0]
            firewall_metadata = (firewall_record.metadata
                                 if isinstance(firewall_record.metadata, dict) else {})
            if (firewall_record.id != f"{host.provider}:inspector-firewall:{firewall['resourceId']}"
                    or firewall_record.engagement_id != parent.target_id
                    or firewall_record.source != INSPECTOR_RESOURCE_SOURCE
                    or firewall_record.provider != host.provider
                    or firewall_record.resource_type != "inspector_firewall"
                    or firewall_record.resource_id != firewall["resourceId"]
                    or firewall_record.name != firewall["name"]
                    or firewall_record.region != host.region
                    or firewall_record.status.lower() not in {"active", "running"}
                    or firewall_record.lifecycle_state.lower() not in {"active", "running"}
                    or firewall_record.adoption_job_id != record.adoption_job_id
                    or firewall_metadata.get("barraganOwned") is not True
                    or firewall_metadata.get("role") != "inspector_firewall"
                    or firewall_metadata.get("inspectorHostResourceId") != host.resource_id
                    or firewall_metadata.get("inspectionJobId") != record.adoption_job_id
                    or firewall_metadata.get("managementSourceCidr")
                    != firewall.get("managementSourceCidr", "")):
                raise ProviderKeyedInspectorPreflightAmbiguous(
                    "active Inspector firewall identity differs")
        after = authority()
        if (after != before or settings_repo.get(parent.target_id) != settings
                or tuple(resources.list_for_engagement(parent.target_id)) != records):
            raise ProviderKeyedInspectorPreflightAmbiguous(
                "Inspector or teardown authority changed during read")
        return PersistedInspectorPreflightEvidence(
            parent.target_id, parent.id, child.id, snapshot["snapshotId"],
            record.id, host.provider, host.resource_type, host.resource_id,
            host.public_ip, settings.updated_at,
        )
    except (ProviderKeyedInspectorPreflightRequired, ProviderKeyedInspectorPreflightAmbiguous):
        raise
    except Exception:
        raise ProviderKeyedInspectorPreflightError(
            "keyed Inspector preflight is unproved; outbound cleanup was not started"
        ) from None
