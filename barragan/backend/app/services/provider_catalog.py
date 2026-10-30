# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from app.services.credentials import (
    CredentialDecryptError,
    CredentialStoreLockedError,
    CredentialValidationError,
    resolve_credential_secret,
    resolve_default_credential_alias,
)
from app.services.provider_region_policy import get_provider_region_policy
from app.storage.provider_catalog_repository import (
    ProviderCatalogRepository,
    SqlAlchemyProviderCatalogRepository,
    StoredProviderCatalog,
)


CATALOG_TTL = timedelta(hours=12)
SUPPORTED_SKETCH_PROVIDERS = {"linode", "digitalocean"}
DIGITALOCEAN_SKETCH_PREFLIGHT_REGION = "sfo3"
DIGITALOCEAN_SKETCH_PREFLIGHT_SIZE = "s-1vcpu-1gb"

SEEDED_CATALOGS: dict[str, dict[str, Any]] = {
    "linode": {
        "provider": "linode",
        "regions": [{"id": "us-sea", "label": "Seattle, WA", "available": True}],
        "sizes": [
            {
                "id": "g6-nanode-1",
                "label": "Nanode 1 GB",
                "vcpus": 1,
                "memoryMb": 1024,
                "diskGb": 25,
                "priceMonthly": 5.0,
                "available": True,
                "regions": [],
            }
        ],
        "defaults": {"region": "us-sea", "size": "g6-nanode-1"},
    },
    "digitalocean": {
        "provider": "digitalocean",
        "regions": [{"id": "sfo3", "label": "San Francisco 3", "available": True}],
        "sizes": [
            {
                "id": "s-1vcpu-1gb",
                "label": "Basic 1 vCPU / 1 GB",
                "vcpus": 1,
                "memoryMb": 1024,
                "diskGb": 25,
                "priceMonthly": 6.0,
                "available": True,
                "regions": ["sfo3"],
            }
        ],
        "defaults": {"region": "sfo3", "size": "s-1vcpu-1gb"},
    },
}


class ProviderCatalogError(Exception):
    pass


class ProviderCatalogRegionSizeUnavailable(ProviderCatalogError):
    """The selected regional offer is absent from the live catalog."""


class ProviderCatalogTransport(Protocol):
    def request(self, base_url: str, method: str, path: str, token: str) -> dict[str, Any]:
        ...


class UrllibProviderCatalogTransport:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def request(self, base_url: str, method: str, path: str, token: str) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{base_url.rstrip('/')}{path}",
            method=method,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise ProviderCatalogError(f"provider catalog request failed with HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise ProviderCatalogError(f"provider catalog request failed: {exc.reason}") from exc
        if not payload:
            return {}
        return json.loads(payload)


@dataclass(frozen=True)
class ProviderCatalog:
    provider: str
    regions: list[dict[str, Any]]
    sizes: list[dict[str, Any]]
    defaults: dict[str, str]
    source: str
    cached_at: str
    expires_at: str
    warnings: list[str]
    region_policy: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "regions": self.regions,
            "sizes": self.sizes,
            "defaults": self.defaults,
            "source": self.source,
            "cachedAt": self.cached_at,
            "expiresAt": self.expires_at,
            "warnings": self.warnings,
            "regionPolicy": self.region_policy,
        }


@dataclass(frozen=True)
class SketchProviderPreflight:
    provider: str
    ready: bool
    catalog_source: str
    checked_region: str
    checked_size: str
    errors: list[str]
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "ready": self.ready,
            "catalogSource": self.catalog_source,
            "checkedRegion": self.checked_region,
            "checkedSize": self.checked_size,
            "errors": self.errors,
            "warnings": self.warnings,
            "mutation": False,
            "opsecBoundary": {
                "directSketchAccessFromAppHost": False,
                "middleAccess": "not used by provider preflight",
                "edgeAccess": "not used by provider preflight",
            },
        }


def get_sketch_provider_catalog(
    provider: str,
    refresh: bool = False,
    include_blocked: bool = False,
    repository: ProviderCatalogRepository | None = None,
    transport: ProviderCatalogTransport | None = None,
) -> ProviderCatalog:
    normalized_provider = provider.strip().lower()
    if normalized_provider not in SUPPORTED_SKETCH_PROVIDERS:
        raise ProviderCatalogError("provider must be linode or digitalocean")

    repo = repository or SqlAlchemyProviderCatalogRepository()
    now = datetime.now(timezone.utc)
    cached = repo.get(normalized_provider)
    if cached and not refresh and _parse_datetime(cached.expires_at) > now:
        return _catalog_from_stored(cached, source="cache", include_blocked=include_blocked)

    try:
        live_catalog = _fetch_live_catalog(normalized_provider, transport or UrllibProviderCatalogTransport())
    except Exception as exc:
        if cached:
            warnings = [*cached.warnings, f"live catalog refresh failed; using stale cache: {_safe_error(exc)}"]
            return _catalog_from_stored(cached, source="stale_cache", warnings=warnings, include_blocked=include_blocked)
        return _seed_catalog(
            normalized_provider,
            now,
            warnings=[f"live catalog unavailable; using seeded RTI defaults: {_safe_error(exc)}"],
            include_blocked=include_blocked,
        )

    cached_at = now.isoformat()
    expires_at = (now + CATALOG_TTL).isoformat()
    stored = repo.save(
        StoredProviderCatalog(
            provider=normalized_provider,
            catalog=live_catalog,
            source="live",
            warnings=[],
            cached_at=cached_at,
            expires_at=expires_at,
        )
    )
    return _catalog_from_stored(stored, source="live", include_blocked=include_blocked)


def preflight_digitalocean_sketch_live_readiness(
    repository: ProviderCatalogRepository | None = None,
    transport: ProviderCatalogTransport | None = None,
) -> SketchProviderPreflight:
    errors: list[str] = []
    try:
        catalog = _fetch_live_catalog("digitalocean", transport or UrllibProviderCatalogTransport())
    except Exception as exc:
        return SketchProviderPreflight(
            provider="digitalocean",
            ready=False,
            catalog_source="unavailable",
            checked_region=DIGITALOCEAN_SKETCH_PREFLIGHT_REGION,
            checked_size=DIGITALOCEAN_SKETCH_PREFLIGHT_SIZE,
            errors=[_safe_error(exc)],
            warnings=[],
        )

    now = datetime.now(timezone.utc)
    repo = repository or SqlAlchemyProviderCatalogRepository()
    stored = repo.save(
        StoredProviderCatalog(
            provider="digitalocean",
            catalog=catalog,
            source="live",
            warnings=[],
            cached_at=now.isoformat(),
            expires_at=(now + CATALOG_TTL).isoformat(),
        )
    )
    live_catalog = _catalog_from_stored(stored, source="live")
    region = _find_by_id(live_catalog.regions, DIGITALOCEAN_SKETCH_PREFLIGHT_REGION)
    if region is None:
        errors.append(f"approved DigitalOcean test region {DIGITALOCEAN_SKETCH_PREFLIGHT_REGION} was not returned by the live catalog")
    elif not region.get("available", True):
        errors.append(f"approved DigitalOcean test region {DIGITALOCEAN_SKETCH_PREFLIGHT_REGION} is not available")

    size = _find_by_id(live_catalog.sizes, DIGITALOCEAN_SKETCH_PREFLIGHT_SIZE)
    if size is None:
        errors.append(f"approved DigitalOcean test size {DIGITALOCEAN_SKETCH_PREFLIGHT_SIZE} was not returned by the live catalog")
    elif not _size_available_in_region(size, DIGITALOCEAN_SKETCH_PREFLIGHT_REGION):
        errors.append(f"approved DigitalOcean test size {DIGITALOCEAN_SKETCH_PREFLIGHT_SIZE} is not available in {DIGITALOCEAN_SKETCH_PREFLIGHT_REGION}")

    return SketchProviderPreflight(
        provider="digitalocean",
        ready=not errors,
        catalog_source=live_catalog.source,
        checked_region=DIGITALOCEAN_SKETCH_PREFLIGHT_REGION,
        checked_size=DIGITALOCEAN_SKETCH_PREFLIGHT_SIZE,
        errors=errors,
        warnings=live_catalog.warnings,
    )


def _fetch_live_catalog(provider: str, transport: ProviderCatalogTransport) -> dict[str, Any]:
    alias = resolve_default_credential_alias(provider)
    if not alias:
        raise ProviderCatalogError(f"no active default {provider} credential configured")
    token = resolve_credential_secret(provider, alias)
    if provider == "linode":
        return _fetch_linode_catalog(token, transport)
    return _fetch_digitalocean_catalog(token, transport)


def _fetch_linode_catalog(token: str, transport: ProviderCatalogTransport) -> dict[str, Any]:
    regions_response = transport.request("https://api.linode.com/v4", "GET", "/regions", token)
    types_response = transport.request("https://api.linode.com/v4", "GET", "/linode/types", token)
    regions = [
        {
            "id": str(region.get("id", "")).strip(),
            "label": str(region.get("label") or region.get("id") or "").strip(),
            "available": str(region.get("status") or "ok").lower() not in {"down", "unavailable"},
        }
        for region in regions_response.get("data", [])
        if str(region.get("id", "")).strip()
    ]
    sizes = [
        {
            "id": str(size.get("id", "")).strip(),
            "label": str(size.get("label") or size.get("id") or "").strip(),
            "vcpus": _int_or_none(size.get("vcpus")),
            "memoryMb": _int_or_none(size.get("memory")),
            "diskGb": _int_or_none(size.get("disk")),
            "priceMonthly": _price_monthly(size),
            "available": True,
            "regions": [],
        }
        for size in types_response.get("data", [])
        if str(size.get("id", "")).strip()
    ]
    return _catalog_with_defaults("linode", regions, sizes)


def _fetch_digitalocean_catalog(token: str, transport: ProviderCatalogTransport) -> dict[str, Any]:
    regions_response = transport.request("https://api.digitalocean.com/v2", "GET", "/regions", token)
    sizes_response = transport.request("https://api.digitalocean.com/v2", "GET", "/sizes", token)
    region_sizes: dict[str, list[str]] = {}
    regions = []
    for region in regions_response.get("regions", []):
        region_id = str(region.get("slug", "")).strip()
        if not region_id:
            continue
        sizes = [str(size) for size in region.get("sizes", []) if str(size).strip()]
        region_sizes[region_id] = sizes
        regions.append(
            {
                "id": region_id,
                "label": str(region.get("name") or region_id).strip(),
                "available": bool(region.get("available", True)),
            }
        )
    sizes = []
    for size in sizes_response.get("sizes", []):
        size_id = str(size.get("slug", "")).strip()
        if not size_id:
            continue
        supported_regions = [region for region, size_ids in region_sizes.items() if size_id in size_ids]
        sizes.append(
            {
                "id": size_id,
                "label": str(size.get("description") or size_id).strip(),
                "vcpus": _int_or_none(size.get("vcpus")),
                "memoryMb": _int_or_none(size.get("memory")),
                "diskGb": _int_or_none(size.get("disk")),
                "priceMonthly": _float_or_none(size.get("price_monthly")),
                "available": bool(size.get("available", True)) and bool(supported_regions),
                "regions": supported_regions,
            }
        )
    return _catalog_with_defaults("digitalocean", regions, sizes)


def require_selected_digitalocean_region_sizes(
    token: str, selections: list[tuple[str, str]],
    transport: ProviderCatalogTransport | None = None,
) -> None:
    """Read live regional size offers for reviewed nodes; never use cached defaults.

    This observation is not a capacity reservation. A truncated catalog is
    rejected rather than treating an omitted region or size as unavailable.
    """
    catalog = (transport or UrllibProviderCatalogTransport()).request(
        "https://api.digitalocean.com/v2", "GET", "/regions?per_page=200", token)
    if type(catalog) is not dict:
        raise ProviderCatalogError("DigitalOcean region catalog is incomplete")
    offered, links, meta = catalog.get("regions"), catalog.get("links"), catalog.get("meta")
    if (type(offered) is not list or type(links) is not dict or type(meta) is not dict
            or type(meta.get("total")) is not int or meta["total"] < 0
            or meta["total"] != len(offered)):
        raise ProviderCatalogError("DigitalOcean region catalog is incomplete")
    pages = links.get("pages", {})
    if (type(pages) is not dict or not set(pages) <= {"first", "last", "prev", "next"}
            or "next" in pages or "prev" in pages
            or any(type(url) is not str or not url.strip() for url in pages.values())):
        raise ProviderCatalogError("DigitalOcean region catalog is incomplete")
    regions = {}
    for region in offered:
        if (type(region) is not dict or type(region.get("slug")) is not str
                or not region["slug"].strip() or region["slug"] in regions
                or type(region.get("available")) is not bool
                or type(region.get("sizes")) is not list
                or any(type(size) is not str or not size.strip() for size in region["sizes"])
                or len(set(region["sizes"])) != len(region["sizes"])):
            raise ProviderCatalogError("DigitalOcean region catalog is malformed or ambiguous")
        regions[region["slug"]] = region
    for region_slug, size_slug in selections:
        region = regions.get(region_slug)
        if (region is None or region.get("available") is not True
                or not isinstance(region.get("sizes"), list)
                or size_slug not in region["sizes"]):
            raise ProviderCatalogRegionSizeUnavailable(
                f"selected DigitalOcean size {size_slug} is unavailable in region {region_slug}"
            )


def _catalog_with_defaults(provider: str, regions: list[dict[str, Any]], sizes: list[dict[str, Any]]) -> dict[str, Any]:
    seeded = SEEDED_CATALOGS[provider]
    default_region = _default_region(regions, seeded["defaults"]["region"])
    default_size = _default_size(sizes, seeded["defaults"]["size"], default_region)
    return {
        "provider": provider,
        "regions": sorted(regions, key=lambda region: region["label"].lower()),
        "sizes": sorted(sizes, key=lambda size: (_price_sort_key(size), size["id"])),
        "defaults": {"region": default_region, "size": default_size},
    }


def _catalog_from_stored(
    stored: StoredProviderCatalog,
    source: str,
    warnings: list[str] | None = None,
    include_blocked: bool = False,
) -> ProviderCatalog:
    policy = get_provider_region_policy(stored.provider)
    catalog = _apply_region_policy(stored.catalog, policy.allowed_regions, include_blocked=include_blocked)
    return ProviderCatalog(
        provider=stored.provider,
        regions=list(catalog.get("regions", [])),
        sizes=list(catalog.get("sizes", [])),
        defaults=dict(catalog.get("defaults", {})),
        source=source,
        cached_at=stored.cached_at,
        expires_at=stored.expires_at,
        warnings=warnings if warnings is not None else list(stored.warnings),
        region_policy={
            "allowedRegions": policy.allowed_regions,
            "includeBlocked": include_blocked,
        },
    )


def _seed_catalog(provider: str, now: datetime, warnings: list[str], include_blocked: bool = False) -> ProviderCatalog:
    seeded = SEEDED_CATALOGS[provider]
    policy = get_provider_region_policy(provider)
    catalog = _apply_region_policy(seeded, policy.allowed_regions, include_blocked=include_blocked)
    return ProviderCatalog(
        provider=provider,
        regions=list(catalog["regions"]),
        sizes=list(catalog["sizes"]),
        defaults=dict(catalog["defaults"]),
        source="seed",
        cached_at=now.isoformat(),
        expires_at=now.isoformat(),
        warnings=warnings,
        region_policy={
            "allowedRegions": policy.allowed_regions,
            "includeBlocked": include_blocked,
        },
    )


def _apply_region_policy(catalog: dict[str, Any], allowed_regions: list[str], include_blocked: bool) -> dict[str, Any]:
    allowed = set(allowed_regions)
    source_regions = [dict(region) for region in catalog.get("regions", [])]
    source_sizes = [dict(size) for size in catalog.get("sizes", [])]
    annotated_regions = [
        {
            **region,
            "allowed": region.get("id") in allowed,
        }
        for region in source_regions
    ]
    if include_blocked:
        regions = annotated_regions
    else:
        regions = [region for region in annotated_regions if region.get("allowed")]

    sizes = []
    for size in source_sizes:
        supported_regions = list(size.get("regions") or [])
        if not allowed:
            allowed_size_regions: list[str] = []
        elif supported_regions:
            allowed_size_regions = [region for region in supported_regions if region in allowed]
        else:
            allowed_size_regions = []
        if include_blocked or not supported_regions or allowed_size_regions:
            sizes.append(
                {
                    **size,
                    "regions": supported_regions if include_blocked else allowed_size_regions,
                }
            )

    defaults = dict(catalog.get("defaults", {}))
    default_region = _default_region(regions, defaults.get("region", ""))
    default_size = _default_size(sizes, defaults.get("size", ""), default_region)
    return {
        **catalog,
        "regions": regions,
        "sizes": sizes,
        "defaults": {"region": default_region, "size": default_size},
    }


def _default_region(regions: list[dict[str, Any]], preferred: str) -> str:
    if not regions:
        return ""
    if any(region["id"] == preferred and region.get("available", True) for region in regions):
        return preferred
    for region in regions:
        if region.get("available", True):
            return region["id"]
    return preferred


def _default_size(sizes: list[dict[str, Any]], preferred: str, region: str) -> str:
    if not region:
        return ""
    if any(size["id"] == preferred and _size_available_in_region(size, region) for size in sizes):
        return preferred
    available = [size for size in sizes if _size_available_in_region(size, region)]
    if not available:
        return preferred
    return sorted(available, key=lambda size: (_price_sort_key(size), _int_or_none(size.get("memoryMb")) or 0, size["id"]))[0]["id"]


def _size_available_in_region(size: dict[str, Any], region: str) -> bool:
    if not size.get("available", True):
        return False
    regions = list(size.get("regions") or [])
    return not regions or region in regions


def _find_by_id(rows: list[dict[str, Any]], row_id: str) -> dict[str, Any] | None:
    for row in rows:
        if str(row.get("id") or "").strip() == row_id:
            return row
    return None


def _price_monthly(size: dict[str, Any]) -> float | None:
    price = size.get("price")
    if isinstance(price, dict):
        return _float_or_none(price.get("monthly"))
    return _float_or_none(size.get("price_monthly"))


def _price_sort_key(size: dict[str, Any]) -> float:
    price = _float_or_none(size.get("priceMonthly"))
    return price if price is not None else 999999.0


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _safe_error(exc: Exception) -> str:
    if isinstance(exc, (CredentialStoreLockedError, CredentialDecryptError, CredentialValidationError, ProviderCatalogError)):
        return str(exc)
    return exc.__class__.__name__
