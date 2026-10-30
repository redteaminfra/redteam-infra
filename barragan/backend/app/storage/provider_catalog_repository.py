# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol


@dataclass(frozen=True)
class StoredProviderCatalog:
    provider: str
    catalog: dict[str, Any]
    source: str
    warnings: list[str]
    cached_at: str
    expires_at: str


class ProviderCatalogRepository(Protocol):
    def get(self, provider: str) -> StoredProviderCatalog | None:
        ...

    def save(self, catalog: StoredProviderCatalog) -> StoredProviderCatalog:
        ...


class SqlAlchemyProviderCatalogRepository:
    def get(self, provider: str) -> StoredProviderCatalog | None:
        from app.storage.models import ProviderCatalogCacheModel

        row = ProviderCatalogCacheModel.query.session.get(ProviderCatalogCacheModel, provider)
        if row is None:
            return None
        return _from_model(row)

    def save(self, catalog: StoredProviderCatalog) -> StoredProviderCatalog:
        from app.storage.database import db
        from app.storage.models import ProviderCatalogCacheModel

        row = ProviderCatalogCacheModel.query.session.get(ProviderCatalogCacheModel, catalog.provider)
        if row is None:
            row = ProviderCatalogCacheModel(provider=catalog.provider)
            db.session.add(row)
        row.catalog = catalog.catalog
        row.source = catalog.source
        row.warnings = catalog.warnings
        row.cached_at = _parse_datetime(catalog.cached_at)
        row.expires_at = _parse_datetime(catalog.expires_at)
        db.session.commit()
        return _from_model(row)


def _from_model(row) -> StoredProviderCatalog:
    return StoredProviderCatalog(
        provider=row.provider,
        catalog=row.catalog,
        source=row.source,
        warnings=list(row.warnings or []),
        cached_at=_format_datetime(row.cached_at),
        expires_at=_format_datetime(row.expires_at),
    )


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _format_datetime(value: datetime | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()
