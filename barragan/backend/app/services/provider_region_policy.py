# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.storage.database import db
from app.storage.models import ProviderRegionPolicyModel


SUPPORTED_SKETCH_PROVIDERS = {"linode", "digitalocean"}
DEFAULT_ALLOWED_REGIONS = {
    "linode": ["us-sea"],
    "digitalocean": ["sfo3"],
}
REGION_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")


class ProviderRegionPolicyValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("provider region policy validation failed")
        self.errors = errors


@dataclass(frozen=True)
class ProviderRegionPolicy:
    provider: str
    allowed_regions: list[str]
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "allowedRegions": self.allowed_regions,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        }


def list_provider_region_policies() -> list[ProviderRegionPolicy]:
    return [get_provider_region_policy(provider) for provider in sorted(SUPPORTED_SKETCH_PROVIDERS)]


def get_provider_region_policy(provider: str) -> ProviderRegionPolicy:
    normalized_provider = _normalize_provider(provider)
    row = ProviderRegionPolicyModel.query.filter_by(provider=normalized_provider).first()
    if row is None:
        now = datetime.now(timezone.utc).isoformat()
        return ProviderRegionPolicy(
            provider=normalized_provider,
            allowed_regions=list(DEFAULT_ALLOWED_REGIONS[normalized_provider]),
            created_at=now,
            updated_at=now,
        )
    return _from_model(row)


def update_provider_region_policy(provider: str, body: dict[str, Any]) -> ProviderRegionPolicy:
    normalized_provider = _normalize_provider(provider)
    allowed_regions = _validated_regions(body.get("allowedRegions"))
    row = ProviderRegionPolicyModel.query.filter_by(provider=normalized_provider).first()
    if row is None:
        row = ProviderRegionPolicyModel(provider=normalized_provider)
        db.session.add(row)
    row.allowed_regions = allowed_regions
    db.session.commit()
    return _from_model(row)


def is_provider_region_allowed(provider: str, region: str) -> bool:
    policy = get_provider_region_policy(provider)
    return region in set(policy.allowed_regions)


def _normalize_provider(provider: str) -> str:
    normalized = str(provider or "").strip().lower()
    if normalized not in SUPPORTED_SKETCH_PROVIDERS:
        raise ProviderRegionPolicyValidationError(["provider must be linode or digitalocean"])
    return normalized


def _validated_regions(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise ProviderRegionPolicyValidationError(["allowedRegions must be a list"])
    regions: list[str] = []
    errors: list[str] = []
    for index, item in enumerate(value):
        region = str(item or "").strip().lower()
        if not REGION_ID_PATTERN.fullmatch(region):
            errors.append(f"allowedRegions[{index}] must be a provider region id")
            continue
        if region not in regions:
            regions.append(region)
    if errors:
        raise ProviderRegionPolicyValidationError(errors)
    return regions


def _from_model(row: ProviderRegionPolicyModel) -> ProviderRegionPolicy:
    return ProviderRegionPolicy(
        provider=row.provider,
        allowed_regions=list(row.allowed_regions or []),
        created_at=row.created_at.isoformat(),
        updated_at=row.updated_at.isoformat(),
    )
