# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.core.runtime import runtime_value
from app.integrations.oci_deployment_targets import allowed_oci_deployment_targets
from app.integrations.oci_read_validation import resolve_oci_cli
from app.services.credentials import (
    CredentialDecryptError,
    CredentialStoreLockedError,
    CredentialValidationError,
    resolve_credential_secret,
    resolve_default_credential_alias,
)
from app.services.provider_catalog import ProviderCatalogError, ProviderCatalogTransport, UrllibProviderCatalogTransport
from app.storage.engagement_repository import StoredEngagement
from app.storage.job_repository import StoredJobRun

PILOT_JOB_ACTION = "pilot_standard_rti_guarded_execute"
SKETCH_DEPLOY_ACTIONS = {"linode_sketch_deploy", "digitalocean_sketch_deploy"}
SKETCH_TEARDOWN_ACTIONS = {"linode_sketch_teardown", "digitalocean_sketch_teardown"}
TERMINAL_PROVIDER_STATES = {"absent", "deleted", "destroyed", "terminated"}
LIVE_DISCOVERY_ENV = "BARRAGAN_PROVIDER_RECONCILIATION_LIVE"
LIVE_DISCOVERY_CACHE_SECONDS_ENV = "BARRAGAN_PROVIDER_RECONCILIATION_CACHE_SECONDS"
PROVIDER_REQUEST_TIMEOUT_SECONDS = 10
OCI_REQUEST_TIMEOUT_SECONDS = 20
DEFAULT_DISCOVERY_CACHE_SECONDS = 30.0


@dataclass(frozen=True)
class ProviderDiscoveryCache:
    expires_at: float
    resources: list[dict[str, Any]]
    evidence: dict[str, Any]


_DISCOVERY_CACHE: ProviderDiscoveryCache | None = None
_DISCOVERY_CACHE_LOCK = threading.Lock()


@dataclass(frozen=True)
class ProviderReconciliation:
    orphan_candidates: list[dict[str, Any]]
    provider_resource_count: int

    @property
    def status(self) -> str:
        return "provider-reconciled" if self.provider_resource_count else "local-records"

    @property
    def detail(self) -> str:
        if self.provider_resource_count and self.orphan_candidates:
            return "Provider inventory found active Barragan-owned resources that are not backed by active local deployment state."
        if self.provider_resource_count:
            return "Provider inventory was reconciled with Barragan runtime records."
        return "Dashboard inventory is derived from Barragan runtime records. Provider reconciliation did not report active resources."


@dataclass(frozen=True)
class ActiveLocalResourceIndex:
    exact_keys: set[str]
    name_keys: set[str]
    address_keys: set[str]
    engagement_fallback_ids: set[str]


class ProviderDiscoveryError(RuntimeError):
    def __init__(self, status: str, detail: str, resources: list[dict[str, Any]] | None = None):
        super().__init__(detail)
        self.status, self.detail, self.resources = status, detail, resources or []


_DISCOVERY_COVERAGE = {
    "oci": ["compute_instance", "vcn", "subnet", "internet_gateway", "route_table", "security_list", "boot_volume"],
    "linode": ["instance", "firewall"],
    "digitalocean": ["droplet", "firewall"],
}


def _discovery_evidence(status: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    observed = [row["observedAt"] for row in rows if row["observedAt"]]
    return {"status": status, "observedAt": min(observed) if observed else None,
            "cached": False, "ageSeconds": 0 if observed else None, "providers": rows,
            "detail": "Read-only candidate inventory; listed resource families only, not complete billing inventory. "
                      "Failed or partial reads do not prove absence."}


def unchecked_provider_inventory() -> dict[str, Any]:
    return {"resources": [], "evidence": _discovery_evidence("not_checked", [])}


def discover_provider_inventory() -> dict[str, Any]:
    """Read existing provider families with explicit completeness and observation evidence."""
    if not _live_discovery_enabled():
        rows = [{"provider": provider, "status": "disabled", "observedAt": None,
                 "resourceCount": 0, "coverage": coverage,
                 "detail": "Live provider discovery is disabled."}
                for provider, coverage in _DISCOVERY_COVERAGE.items()]
        return {"resources": [], "evidence": _discovery_evidence("disabled", rows)}
    global _DISCOVERY_CACHE
    cache_seconds = _live_discovery_cache_seconds()
    if cache_seconds > 0:
        with _DISCOVERY_CACHE_LOCK:
            cached = copy.deepcopy(_DISCOVERY_CACHE)
        if cached is not None and cached.expires_at > time.monotonic():
            evidence = cached.evidence
            evidence["cached"] = True
            observed = evidence.get("observedAt")
            evidence["ageSeconds"] = max(0, (datetime.now(timezone.utc) - datetime.fromisoformat(observed)).total_seconds()) if observed else None
            return {"resources": cached.resources, "evidence": evidence}
    resources, rows = [], []
    for provider, discover in (("oci", _discover_oci_resources), ("linode", _discover_linode_resources),
                               ("digitalocean", _discover_digitalocean_resources)):
        try:
            found = discover()
            status, detail = "checked", "Enumerated configured scope and listed resource families."
        except ProviderDiscoveryError as error:
            found, status, detail = error.resources, error.status, error.detail
        except Exception:
            found, status, detail = [], "failed", "Provider inventory request failed; current presence is unknown."
        observed = datetime.now(timezone.utc).isoformat() if status in {"checked", "partial"} else None
        resources.extend(found)
        rows.append({"provider": provider, "status": status, "observedAt": observed,
                     "resourceCount": sum(_provider_resource_is_active(row) for row in found),
                     "coverage": _DISCOVERY_COVERAGE[provider], "detail": detail})
    statuses = {row["status"] for row in rows}
    status = "checked" if statuses == {"checked"} else "partial" if statuses & {"checked", "partial"} else "failed"
    evidence = _discovery_evidence(status, rows)
    if cache_seconds > 0:
        with _DISCOVERY_CACHE_LOCK:
            _DISCOVERY_CACHE = ProviderDiscoveryCache(time.monotonic() + cache_seconds,
                                                      copy.deepcopy(resources), copy.deepcopy(evidence))
    return {"resources": resources, "evidence": evidence}


def discover_provider_resources() -> list[dict[str, Any]]:
    """Compatibility list boundary; dashboard uses the evidence-bearing API."""
    return discover_provider_inventory()["resources"]


def provider_inventory_rows(
    engagements: list[StoredEngagement], jobs: list[StoredJobRun],
    resources: list[dict[str, Any]], local_resources: list[dict[str, Any]],
    evidence: dict[str, Any],
) -> list[dict[str, Any]]:
    index = _active_local_resource_index(jobs, local_resources)
    by_id = {row.id: row for row in engagements}
    by_name = {_normalized_name(row.name): row for row in engagements}
    observed = {row["provider"]: row["observedAt"] for row in evidence["providers"]}
    rows = []
    for raw in resources:
        resource = _normalize_provider_resource(raw)
        if not _provider_resource_is_active(resource):
            continue
        engagement = _resolve_engagement(resource, by_id, by_name)
        owned = _strong_barragan_identity(resource)
        engagement_id = engagement.id if engagement else resource["engagementId"]
        matched = _resource_matches_active_local_state(resource, index) or engagement_id in index.engagement_fallback_ids
        rows.append({**{key: resource[key] for key in ("provider", "resourceType", "resourceId", "name", "region", "lifecycleState", "source")},
                     "engagementId": engagement_id,
                     "engagementName": engagement.name if engagement else resource["engagementName"],
                     "classification": "observation_only" if _support_observation(resource) else "unmanaged_rti" if not owned else "recorded" if matched else "barragan_orphan",
                     "barraganOwned": owned, "observedAt": observed.get(resource["provider"]), "actions": []})
    return rows


def clear_provider_discovery_cache() -> None:
    global _DISCOVERY_CACHE
    with _DISCOVERY_CACHE_LOCK:
        _DISCOVERY_CACHE = None


def reconcile_provider_inventory(
    engagements: list[StoredEngagement],
    jobs: list[StoredJobRun],
    provider_resources: list[dict[str, Any]] | None = None,
    local_provider_resources: list[dict[str, Any]] | None = None,
) -> ProviderReconciliation:
    resources = provider_resources if provider_resources is not None else discover_provider_resources()
    active_resources = [_normalize_provider_resource(resource) for resource in resources]
    active_resources = [resource for resource in active_resources if _provider_resource_is_active(resource)]
    active_local_resources = _active_local_resource_index(jobs, local_provider_resources or [])
    engagements_by_id = {engagement.id: engagement for engagement in engagements}
    engagements_by_name = {_normalized_name(engagement.name): engagement for engagement in engagements}

    candidates = []
    for resource in active_resources:
        if _support_observation(resource):
            continue
        engagement = _resolve_engagement(resource, engagements_by_id, engagements_by_name)
        engagement_id = engagement.id if engagement else str(resource.get("engagementId") or "").strip()
        if _resource_matches_active_local_state(resource, active_local_resources):
            continue
        if engagement_id and engagement_id in active_local_resources.engagement_fallback_ids:
            continue
        if not engagement_id and not _strong_barragan_identity(resource):
            continue
        candidates.append(_orphan_candidate(resource, engagement))

    return ProviderReconciliation(orphan_candidates=candidates, provider_resource_count=len(active_resources))


def _live_discovery_enabled() -> bool:
    return os.environ.get(LIVE_DISCOVERY_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def _live_discovery_cache_seconds() -> float:
    raw = os.environ.get(LIVE_DISCOVERY_CACHE_SECONDS_ENV, "").strip()
    if not raw:
        return DEFAULT_DISCOVERY_CACHE_SECONDS
    try:
        return max(0.0, float(raw))
    except ValueError:
        return DEFAULT_DISCOVERY_CACHE_SECONDS


def _valid_inventory_identity(row: Any, provider: str, resource_type: str = "") -> bool:
    if not isinstance(row, dict):
        return False
    identifier = row.get("id")
    if provider == "oci":
        valid_id = isinstance(identifier, str) and bool(identifier.strip())
        name = row.get("display-name") or row.get("displayName") or row.get("name")
        state = row.get("lifecycle-state") or row.get("lifecycleState")
        for key in ("freeform-tags", "freeformTags", "defined-tags", "definedTags"):
            if key in row and not isinstance(row[key], dict):
                return False
    else:
        valid_id = ((type(identifier) is int and identifier > 0)
                    or (isinstance(identifier, str) and identifier.isdigit() and int(identifier) > 0))
        if provider == "digitalocean" and resource_type == "firewall":
            try:
                valid_id = isinstance(identifier, str) and str(uuid.UUID(identifier)) == identifier.lower()
            except (ValueError, AttributeError):
                valid_id = False
        name = row.get("label" if provider == "linode" else "name")
        state = row.get("status")
        tags = row.get("tags", [])
        if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
            return False
    return valid_id and isinstance(name, str) and bool(name.strip()) and isinstance(state, str) and bool(state.strip())


def _inventory_response_rows(body: Any, key: str, provider: str, resource_type: str = "") -> tuple[list[dict[str, Any]], bool]:
    if not isinstance(body, dict) or not isinstance(body.get(key), list):
        raise ProviderDiscoveryError("failed", "Provider returned malformed inventory.")
    rows = body[key]
    valid = [row for row in rows if _valid_inventory_identity(row, provider, resource_type)]
    return valid, len(valid) != len(rows)


def _nonnegative_integer(value: Any) -> bool:
    return type(value) is int and value >= 0


def _discover_linode_resources(transport: ProviderCatalogTransport | None = None) -> list[dict[str, Any]]:
    return _discover_account_resources("linode", transport)


def _discover_digitalocean_resources(transport: ProviderCatalogTransport | None = None) -> list[dict[str, Any]]:
    return _discover_account_resources("digitalocean", transport)


def _discover_account_resources(provider: str, transport: ProviderCatalogTransport | None) -> list[dict[str, Any]]:
    token = _provider_token(provider)
    if not token:
        raise ProviderDiscoveryError("unavailable", "Provider credential is unavailable; current presence is unknown.")
    transport = transport or UrllibProviderCatalogTransport(timeout=PROVIDER_REQUEST_TIMEOUT_SECONDS)
    linode = provider == "linode"
    base = "https://api.linode.com/v4" if linode else "https://api.digitalocean.com/v2"
    families = [("instance", "/linode/instances?page_size=500", "data"),
                ("firewall", "/networking/firewalls?page_size=500", "data")] if linode else [
                ("droplet", "/droplets?per_page=200", "droplets"),
                ("firewall", "/firewalls?per_page=200", "firewalls")]
    resources, successes, failures = [], 0, 0
    incomplete = []
    for resource_type, path, key in families:
        try:
            body = transport.request(base, "GET", path, token)
            valid, malformed = _inventory_response_rows(body, key, provider, resource_type)
            if resource_type == "firewall":
                resources.extend(_firewall_resources_from_response(provider, valid))
            else:
                mapper = _linode_resources_from_response if linode else _digitalocean_resources_from_response
                resources.extend(mapper({**body, key: valid}))
            if linode:
                pages, results, page = body.get("pages"), body.get("results"), body.get("page", 1)
                bad = (not _nonnegative_integer(pages) or pages < 1
                       or not _nonnegative_integer(results) or results < len(body[key])
                       or type(page) is not int or page != 1)
                unread = not bad and (pages > 1 or results > len(body[key]))
            else:
                links, meta = body.get("links"), body.get("meta")
                pages = links.get("pages", {}) if isinstance(links, dict) else None
                total = meta.get("total") if isinstance(meta, dict) else None
                bad = (not isinstance(links, dict) or not isinstance(meta, dict)
                       or not isinstance(pages, dict) or not _nonnegative_integer(total)
                       or total < len(body[key]))
                if isinstance(pages, dict):
                    bad = bad or any(not isinstance(value, str) or not value.strip() for value in pages.values())
                unread = not bad and (bool(pages.get("next")) or total > len(body[key]))
            if malformed or bad or unread:
                incomplete.append(resource_type)
                failures += 1
                if valid or unread:
                    successes += 1
            else:
                successes += 1
        except Exception:
            incomplete.append(resource_type)
            failures += 1
    if failures:
        raise ProviderDiscoveryError("partial" if successes else "failed",
                                     f"Incomplete inventory families: {', '.join(incomplete)}; malformed, failed or unread pages do not prove absence.", resources)
    return resources


def _firewall_resources_from_response(provider: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    resources = []
    for row in rows:
        tags = row.get("tags", [])
        name = _text(row.get("label") if provider == "linode" else row.get("name"))
        resources.append({
            "provider": provider, "resourceType": "firewall", "resourceId": _text(row["id"]),
            "name": name, "region": "", "lifecycleState": _text(row["status"]),
            "engagementName": _tagged_engagement_name(tags) or _engagement_name_from_rti_name(name),
            "source": f"{provider}_api",
            "metadata": {"tags": tags, "barraganOwned": _tags_indicate_barragan(tags)},
        })
    return resources


def _discover_oci_resources(
    runner: Any | None = None,
    env: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    resolution = resolve_oci_cli(env=env)
    if not resolution.ok:
        raise ProviderDiscoveryError("unavailable", "OCI CLI is unavailable; current presence is unknown.")
    oci = resolution.command or "oci"
    command_runner = runner or _run_provider_command
    resources: list[dict[str, Any]] = []
    try:
        environment = str(runtime_value("ENVIRONMENT", "local") or "local")
    except RuntimeError:
        environment = "local"
    failures = successes = 0
    incomplete = set()
    for target in allowed_oci_deployment_targets(environment):
        target.validate()
        base = [oci, "--auth", target.auth, "--region", target.region]
        scope = ["--compartment-id", target.compartment_id, "--all", "--output", "json"]
        for resource_type, command in (
            ("compute_instance", [*base, "compute", "instance", "list", *scope]),
            ("vcn", [*base, "network", "vcn", "list", *scope]),
            ("subnet", [*base, "network", "subnet", "list", *scope]),
            ("internet_gateway", [*base, "network", "internet-gateway", "list", *scope]),
            ("route_table", [*base, "network", "route-table", "list", *scope]),
            ("security_list", [*base, "network", "security-list", "list", *scope]),
            ("boot_volume", [*base, "bv", "boot-volume", "list", *scope]),
        ):
            try:
                completed = command_runner(command)
                if completed.returncode != 0:
                    raise ValueError("provider command failed")
                body = json.loads(completed.stdout) if completed.stdout.strip() else {"data": []}
                valid, malformed = _inventory_response_rows(body, "data", "oci")
                resources.extend(_oci_resources_from_response(resource_type, {**body, "data": valid}, target.region))
                # --all requests the complete family; any residual pagination
                # marker cannot establish complete absence.
                pagination_present = "opc-next-page" in body or "opcNextPage" in body
                if malformed or pagination_present:
                    incomplete.add(resource_type)
                    failures += 1
                    if valid:
                        successes += 1
                else:
                    successes += 1
            except Exception:
                incomplete.add(resource_type)
                failures += 1
    if failures or not successes:
        raise ProviderDiscoveryError("partial" if successes else "failed",
                                     f"Incomplete OCI inventory families: {', '.join(sorted(incomplete))}; current presence is incomplete.", resources)
    return resources


def _provider_token(provider: str) -> str | None:
    try:
        alias = resolve_default_credential_alias(provider)
        if not alias:
            return None
        return resolve_credential_secret(provider, alias)
    except (
        CredentialDecryptError,
        CredentialStoreLockedError,
        CredentialValidationError,
        ProviderCatalogError,
    ):
        return None


def _run_provider_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=OCI_REQUEST_TIMEOUT_SECONDS, check=False)


def _linode_resources_from_response(body: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for instance in body.get("data", []):
        if not isinstance(instance, dict):
            continue
        name = _text(instance.get("label"))
        tags = [str(tag) for tag in instance.get("tags", []) if str(tag).strip()]
        if not _provider_resource_candidate(name, tags):
            continue
        rows.append(
            {
                "provider": "linode",
                "resourceType": "instance",
                "resourceId": _text(instance.get("id")),
                "name": name,
                "region": _text(instance.get("region")),
                "lifecycleState": _text(instance.get("status")),
                "engagementName": _tagged_engagement_name(tags) or _engagement_name_from_rti_name(name),
                "source": "linode_api",
                "metadata": {
                    "tags": tags,
                    "barraganOwned": _tags_indicate_barragan(tags),
                    "publicIps": [_text(ip) for ip in instance.get("ipv4", []) if _text(ip)],
                },
            }
        )
    return rows


def _digitalocean_resources_from_response(body: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for droplet in body.get("droplets", []):
        if not isinstance(droplet, dict):
            continue
        name = _text(droplet.get("name"))
        tags = [str(tag) for tag in droplet.get("tags", []) if str(tag).strip()]
        if not _provider_resource_candidate(name, tags):
            continue
        region = droplet.get("region") if isinstance(droplet.get("region"), dict) else {}
        networks = droplet.get("networks") if isinstance(droplet.get("networks"), dict) else {}
        rows.append(
            {
                "provider": "digitalocean",
                "resourceType": "droplet",
                "resourceId": _text(droplet.get("id")),
                "name": name,
                "region": _text(region.get("slug") or droplet.get("region")),
                "lifecycleState": _text(droplet.get("status")),
                "engagementName": _tagged_engagement_name(tags) or _engagement_name_from_rti_name(name),
                "source": "digitalocean_api",
                "metadata": {
                    "tags": tags,
                    "barraganOwned": _tags_indicate_barragan(tags),
                    "publicIps": _digitalocean_public_ips(networks),
                },
            }
        )
    return rows


def _oci_resources_from_response(resource_type: str, body: dict[str, Any], region: str) -> list[dict[str, Any]]:
    rows = []
    for resource in body.get("data", []):
        if not isinstance(resource, dict):
            continue
        name = _text(resource.get("display-name") or resource.get("displayName") or resource.get("name"))
        tags = _oci_tags(resource)
        if resource_type != "boot_volume" and not _provider_resource_candidate(name, tags):
            continue
        rows.append(
            {
                "provider": "oci",
                "resourceType": resource_type,
                "resourceId": _text(resource.get("id")),
                "name": name,
                "region": region,
                "lifecycleState": _text(resource.get("lifecycle-state") or resource.get("lifecycleState")),
                "engagementId": _tag_value(tags, "barragan_engagement_id"),
                "engagementName": _tag_value(tags, "barragan_engagement") or _engagement_name_from_rti_name(name),
                "source": "oci_api",
                "metadata": {
                    "tags": tags,
                    "barraganOwned": _tags_indicate_barragan(tags),
                    "compartmentId": _text(resource.get("compartment-id") or resource.get("compartmentId")),
                    "vcnId": _text(resource.get("vcn-id") or resource.get("vcnId")),
                    "subnetId": _text(resource.get("subnet-id") or resource.get("subnetId")),
                },
            }
        )
    return rows


def orphan_candidates_for_engagement(
    engagement_id: str,
    engagements: list[StoredEngagement],
    jobs: list[StoredJobRun],
    provider_resources: list[dict[str, Any]] | None = None,
    local_provider_resources: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    return [
        candidate
        for candidate in reconcile_provider_inventory(engagements, jobs, provider_resources, local_provider_resources).orphan_candidates
        if candidate.get("engagementId") == engagement_id
    ]


def _active_local_resource_index(
    jobs: list[StoredJobRun],
    local_provider_resources: list[dict[str, Any]],
) -> ActiveLocalResourceIndex:
    exact_keys: set[str] = set()
    name_keys: set[str] = set()
    address_keys: set[str] = set()
    engagement_fallback_ids: set[str] = set()
    for resource in local_provider_resources:
        normalized = _normalize_provider_resource(resource)
        if _provider_resource_is_active(normalized):
            _add_resource_keys(normalized, exact_keys, name_keys, address_keys)
    destroyed_sketch_job_ids = {
        str(job.input.get("parentJobId") or "")
        for job in jobs
        if job.action in SKETCH_TEARDOWN_ACTIONS and job.status == "succeeded"
    }
    for job in jobs:
        engagement_id = str(job.input.get("engagementId") or "").strip()
        if not engagement_id:
            continue
        if job.action == PILOT_JOB_ACTION and _core_job_is_active(job):
            before = len(exact_keys) + len(name_keys) + len(address_keys)
            for resource in _core_local_resource_rows(job):
                _add_resource_keys(resource, exact_keys, name_keys, address_keys)
            if job.status in {"queued", "running"} and len(exact_keys) + len(name_keys) + len(address_keys) == before:
                engagement_fallback_ids.add(engagement_id)
        if job.action in SKETCH_DEPLOY_ACTIONS and job.status == "succeeded" and job.id not in destroyed_sketch_job_ids:
            for resource in _sketch_local_resource_rows(job):
                _add_resource_keys(resource, exact_keys, name_keys, address_keys)
    return ActiveLocalResourceIndex(
        exact_keys=exact_keys,
        name_keys=name_keys,
        address_keys=address_keys,
        engagement_fallback_ids=engagement_fallback_ids,
    )


def _resource_matches_active_local_state(resource: dict[str, Any], index: ActiveLocalResourceIndex) -> bool:
    exact_key = _resource_exact_key(resource)
    if exact_key and exact_key in index.exact_keys:
        return True
    name_key = _resource_name_key(resource)
    if name_key and name_key in index.name_keys:
        return True
    return any(key in index.address_keys for key in _resource_address_keys(resource))


def _core_local_resource_rows(job: StoredJobRun) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in job.events:
        for resource in _dict_rows(event.data.get("createdResources")):
            rows.append(
                {
                    "provider": resource.get("provider") or "oci",
                    "resourceType": _local_resource_type(resource.get("provider") or "oci", resource.get("type")),
                    "resourceId": resource.get("resourceId") or resource.get("id") or "",
                    "name": resource.get("displayName") or resource.get("name") or "",
                    "region": resource.get("region") or "",
                    "metadata": {"publicIps": _public_ips(resource)},
                }
            )
        for detail in _dict_rows(event.data.get("connectionDetails")):
            rows.append(
                {
                    "provider": "oci",
                    "resourceType": "compute_instance",
                    "resourceId": detail.get("resourceId") or detail.get("instanceId") or detail.get("id") or "",
                    "name": detail.get("displayName") or detail.get("hostname") or detail.get("sshAlias") or "",
                    "region": detail.get("region") or "",
                    "metadata": {"publicIps": _public_ips(detail)},
                }
            )
    return rows


def _sketch_local_resource_rows(job: StoredJobRun) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in job.events:
        for row in _dict_rows(event.data.get("sketchInfrastructure")):
            provider = _text(row.get("provider"))
            rows.append(
                {
                    "provider": provider,
                    "resourceType": _local_resource_type(provider, row.get("resourceType") or row.get("type")),
                    "resourceId": row.get("providerInstanceId") or row.get("resourceId") or row.get("id") or "",
                    "name": row.get("hostname") or row.get("displayName") or row.get("name") or "",
                    "region": row.get("region") or "",
                    "metadata": {"publicIps": _public_ips(row)},
                }
            )
    return rows


def _add_resource_keys(
    resource: dict[str, Any],
    exact_keys: set[str],
    name_keys: set[str],
    address_keys: set[str],
) -> None:
    exact_key = _resource_exact_key(resource)
    if exact_key:
        exact_keys.add(exact_key)
    name_key = _resource_name_key(resource)
    if name_key:
        name_keys.add(name_key)
    address_keys.update(_resource_address_keys(resource))


def _resource_exact_key(resource: dict[str, Any]) -> str:
    provider = _normalized_name(str(resource.get("provider") or ""))
    resource_type = _normalized_resource_type(resource.get("provider"), resource.get("resourceType"))
    resource_id = _resource_id_key(resource.get("resourceId"))
    if not provider or not resource_type or not resource_id:
        return ""
    return f"{provider}:{resource_type}:{resource_id}"


def _resource_name_key(resource: dict[str, Any]) -> str:
    provider = _normalized_name(str(resource.get("provider") or ""))
    resource_type = _normalized_resource_type(resource.get("provider"), resource.get("resourceType"))
    name = _normalized_name(str(resource.get("name") or ""))
    if not provider or not resource_type or not name:
        return ""
    return f"{provider}:{resource_type}:{name}"


def _resource_address_keys(resource: dict[str, Any]) -> set[str]:
    provider = _normalized_name(str(resource.get("provider") or ""))
    if not provider:
        return set()
    return {f"{provider}:ip:{ip}" for ip in _public_ips(resource)}


def _local_resource_type(provider: Any, resource_type: Any) -> str:
    normalized_type = str(resource_type or "").strip().lower().replace("-", "_")
    mapped = {
        "oci_core_instance": "compute_instance",
        "oci_core_vcn": "vcn",
        "oci_core_subnet": "subnet",
        "oci_core_internet_gateway": "internet_gateway",
        "oci_core_route_table": "route_table",
        "oci_core_security_list": "security_list",
        "oci_core_boot_volume": "boot_volume",
        "linode_firewall": "firewall",
        "digitalocean_firewall": "firewall",
    }.get(normalized_type)
    if mapped:
        return mapped
    normalized_provider = _normalized_name(str(provider or ""))
    if normalized_provider == "linode" and not normalized_type:
        return "instance"
    if normalized_provider == "digitalocean" and not normalized_type:
        return "droplet"
    return normalized_type


def _normalized_resource_type(provider: Any, resource_type: Any) -> str:
    return _normalized_name(_local_resource_type(provider, resource_type))


def _resource_id_key(value: Any) -> str:
    return str(value or "").strip().lower()


def _public_ips(row: dict[str, Any]) -> list[str]:
    values: list[str] = []
    public_ip = _text(row.get("publicIp") or row.get("public_ip") or row.get("ip"))
    if _usable_public_ip(public_ip):
        values.append(public_ip)
    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    for value in metadata.get("publicIps", []):
        text = _text(value)
        if _usable_public_ip(text):
            values.append(text)
    return values


def _usable_public_ip(value: str) -> bool:
    return bool(value and _normalized_name(value) not in {"n-a", "not-deployed", "not-ready", "unknown"})


def _dict_rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [row for row in value if isinstance(row, dict)]


def _core_job_is_active(job: StoredJobRun) -> bool:
    if job.status in {"queued", "running"}:
        return True
    final_cleanup_status = _latest_event_value(job, "finalCleanupStatus")
    mutation_status = _latest_event_value(job, "mutationStatus")
    if final_cleanup_status == "pending_operator_teardown":
        return True
    return job.status == "succeeded" and mutation_status == "deployed" and final_cleanup_status != "verified_clean"


def _latest_event_value(job: StoredJobRun, key: str) -> Any:
    event = next((entry for entry in reversed(job.events) if entry.data.get(key) is not None), None)
    return event.data.get(key) if event is not None else None


def _normalize_provider_resource(resource: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": _text(resource.get("provider")),
        "resourceType": _text(resource.get("resourceType") or resource.get("type")),
        "resourceId": _text(resource.get("resourceId") or resource.get("id")),
        "name": _text(resource.get("name") or resource.get("displayName") or resource.get("label")),
        "region": _text(resource.get("region")),
        "lifecycleState": _text(resource.get("lifecycleState") or resource.get("status") or resource.get("state")),
        "engagementId": _text(resource.get("engagementId")),
        "engagementName": _text(resource.get("engagementName")),
        "source": _text(resource.get("source")) or "provider_inventory",
        "metadata": resource.get("metadata") if isinstance(resource.get("metadata"), dict) else {},
    }


def _support_observation(resource: dict[str, Any]) -> bool:
    return (_normalized_name(resource.get("provider", "")),
            _normalized_resource_type(resource.get("provider"), resource.get("resourceType"))) in {
                ("oci", "boot-volume"), ("linode", "firewall"), ("digitalocean", "firewall")}


def _provider_resource_is_active(resource: dict[str, Any]) -> bool:
    state = str(resource.get("lifecycleState") or "").strip().lower()
    return state not in TERMINAL_PROVIDER_STATES


def _strong_barragan_identity(resource: dict[str, Any]) -> bool:
    metadata = resource.get("metadata") if isinstance(resource.get("metadata"), dict) else {}
    return bool(metadata.get("barraganOwned"))


def _resolve_engagement(
    resource: dict[str, Any],
    engagements_by_id: dict[str, StoredEngagement],
    engagements_by_name: dict[str, StoredEngagement],
) -> StoredEngagement | None:
    engagement_id = str(resource.get("engagementId") or "").strip()
    if engagement_id in engagements_by_id:
        return engagements_by_id[engagement_id]
    engagement_name = _normalized_name(str(resource.get("engagementName") or ""))
    if engagement_name and engagement_name in engagements_by_name:
        return engagements_by_name[engagement_name]
    name = _normalized_name(str(resource.get("name") or ""))
    for candidate_name, engagement in engagements_by_name.items():
        if candidate_name and re.search(rf"(^|[-_]){re.escape(candidate_name)}($|[-_])", name):
            return engagement
    return None


def _orphan_candidate(resource: dict[str, Any], engagement: StoredEngagement | None) -> dict[str, Any]:
    engagement_id = engagement.id if engagement else str(resource.get("engagementId") or "").strip()
    engagement_name = engagement.name if engagement else str(resource.get("engagementName") or "").strip()
    barragan_owned = _strong_barragan_identity(resource)
    classification = "barragan_orphan" if barragan_owned else "unmanaged_rti"
    if barragan_owned:
        reason = (
            "Provider inventory reports an active Barragan-owned resource, but Barragan has no active local deployment state for this engagement."
            if engagement_id
            else "Provider inventory reports an active Barragan-owned resource with no matching local engagement record."
        )
    else:
        reason = (
            "Provider inventory found RTI-looking infrastructure for this engagement, but it does not carry Barragan ownership tags. Treat it as manually managed unless an operator explicitly tracks it."
            if engagement_id
            else "Provider inventory found RTI-looking infrastructure without Barragan ownership tags. Treat it as manually managed unless an operator explicitly tracks it."
        )
    return {
        "candidateId": _candidate_id(resource),
        "provider": resource.get("provider") or "unknown",
        "resourceType": resource.get("resourceType") or "resource",
        "resourceId": resource.get("resourceId") or "",
        "name": resource.get("name") or "",
        "region": resource.get("region") or "",
        "lifecycleState": resource.get("lifecycleState") or "unknown",
        "engagementId": engagement_id,
        "engagementName": engagement_name,
        "source": resource.get("source") or "provider_inventory",
        "metadata": _candidate_metadata(resource),
        "publicIps": _public_ips(resource),
        "classification": classification,
        "reason": reason,
        "actions": ["track", "mark_destroyed", "tear_down"] if barragan_owned else ["track", "mark_destroyed"],
    }


def _candidate_metadata(resource: dict[str, Any]) -> dict[str, Any]:
    metadata = resource.get("metadata") if isinstance(resource.get("metadata"), dict) else {}
    safe = {
        "barraganOwned": bool(metadata.get("barraganOwned")),
        "publicIps": _public_ips(resource),
    }
    compartment_id = _text(metadata.get("compartmentId"))
    if compartment_id:
        safe["compartmentId"] = compartment_id
    vcn_id = _text(metadata.get("vcnId"))
    if vcn_id:
        safe["vcnId"] = vcn_id
    subnet_id = _text(metadata.get("subnetId"))
    if subnet_id:
        safe["subnetId"] = subnet_id
    return safe


def _candidate_id(resource: dict[str, Any]) -> str:
    parts = [
        str(resource.get("provider") or "unknown"),
        str(resource.get("resourceType") or "resource"),
        str(resource.get("resourceId") or resource.get("name") or "unknown"),
    ]
    return ":".join(parts)


def _normalized_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")


def _text(value: Any) -> str:
    return str(value or "").strip()


def _provider_resource_candidate(name: str, tags: Any) -> bool:
    return _tags_indicate_barragan(tags) or _rti_name_pattern(name)


def _tags_indicate_barragan(tags: Any) -> bool:
    if isinstance(tags, dict):
        normalized = {_normalized_name(str(key)): _normalized_name(str(value)) for key, value in tags.items()}
        return (
            normalized.get("barragan") in {"true", "yes", "1", "barragan"}
            or "barragan" in normalized
            or "barragan" in normalized.values()
        )
    if isinstance(tags, list):
        values = {_normalized_name(str(tag)) for tag in tags}
        return bool(values.intersection({"barragan", "barragan-testing"}))
    return False


def _tagged_engagement_name(tags: list[str]) -> str:
    for tag in tags:
        text = str(tag).strip()
        if text.startswith("engagement:"):
            return text.split(":", 1)[1].strip()
    return ""


def _engagement_name_from_rti_name(name: str) -> str:
    normalized = name.strip()
    for pattern in (
        r"^(?:homebase|proxy[0-9]+)-(?P<engagement>[A-Za-z0-9][A-Za-z0-9_.-]*)$",
        r"^middle[0-9]+-(?P<engagement>[A-Za-z0-9][A-Za-z0-9_.-]*)$",
        r"^(?P<engagement>[A-Za-z0-9][A-Za-z0-9_.-]*)-vcn$",
    ):
        match = re.fullmatch(pattern, normalized)
        if match:
            return match.group("engagement")
    return ""


def _rti_name_pattern(name: str) -> bool:
    normalized = name.strip()
    return any(
        re.fullmatch(pattern, normalized)
        for pattern in (
            r"(?:homebase|proxy[0-9]+)-[A-Za-z0-9][A-Za-z0-9_.-]*",
            r"middle[0-9]+-[A-Za-z0-9][A-Za-z0-9_.-]*",
            r"edge-[A-Za-z0-9][A-Za-z0-9_.-]*-[0-9]{2}",
            r"[A-Za-z0-9][A-Za-z0-9_.-]*-vcn",
        )
    )


def _oci_tags(resource: dict[str, Any]) -> dict[str, str]:
    tags: dict[str, str] = {}
    freeform = resource.get("freeform-tags") or resource.get("freeformTags") or {}
    if isinstance(freeform, dict):
        tags.update({str(key): str(value) for key, value in freeform.items()})
    defined = resource.get("defined-tags") or resource.get("definedTags") or {}
    if isinstance(defined, dict):
        for namespace, values in defined.items():
            if isinstance(values, dict):
                for key, value in values.items():
                    tags[f"{namespace}.{key}"] = str(value)
    return tags


def _tag_value(tags: dict[str, str], key: str) -> str:
    for tag_key, value in tags.items():
        if _normalized_name(tag_key) == _normalized_name(key):
            return str(value).strip()
    return ""


def _digitalocean_public_ips(networks: dict[str, Any]) -> list[str]:
    ips = []
    for network in networks.get("v4", []):
        if isinstance(network, dict) and str(network.get("type") or "").lower() == "public":
            ip = _text(network.get("ip_address"))
            if ip:
                ips.append(ip)
    return ips
