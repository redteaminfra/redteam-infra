# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from app.domain import CredentialSummary


@dataclass(frozen=True)
class StoredCredential:
    id: str
    provider: str
    alias: str
    status: str
    description: str
    encrypted_secret: str
    is_default: bool
    created_at: str
    updated_at: str

    def to_summary(self) -> CredentialSummary:
        return CredentialSummary(
            id=self.id,
            provider=self.provider,
            alias=self.alias,
            status=self.status,
            description=self.description,
            is_default=self.is_default,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )


class CredentialRepository(Protocol):
    def list(self, provider: str | None = None) -> list[StoredCredential]:
        ...

    def get(self, credential_id: str) -> StoredCredential | None:
        ...

    def get_by_alias(self, provider: str, alias: str) -> StoredCredential | None:
        ...

    def get_default(self, provider: str) -> StoredCredential | None:
        ...

    def save(self, credential: StoredCredential) -> StoredCredential:
        ...

    def set_default(self, credential_id: str) -> StoredCredential | None:
        ...

    def disable(self, credential_id: str) -> StoredCredential | None:
        ...


class SqlAlchemyCredentialRepository:
    def list(self, provider: str | None = None) -> list[StoredCredential]:
        from app.storage.models import CredentialModel

        query = CredentialModel.query
        if provider:
            query = query.filter_by(provider=provider)
        rows = query.order_by(CredentialModel.provider.asc(), CredentialModel.alias.asc()).all()
        return [_from_model(row) for row in rows]

    def get(self, credential_id: str) -> StoredCredential | None:
        from app.storage.models import CredentialModel

        row = CredentialModel.query.session.get(CredentialModel, credential_id)
        if row is None:
            return None
        return _from_model(row)

    def get_by_alias(self, provider: str, alias: str) -> StoredCredential | None:
        from app.storage.models import CredentialModel

        row = CredentialModel.query.filter_by(provider=provider, alias=alias).first()
        if row is None:
            return None
        return _from_model(row)

    def get_default(self, provider: str) -> StoredCredential | None:
        from app.storage.models import CredentialModel

        row = CredentialModel.query.filter_by(provider=provider, status="active", is_default=True).first()
        if row is None:
            return None
        return _from_model(row)

    def save(self, credential: StoredCredential) -> StoredCredential:
        from app.storage.database import db
        from app.storage.models import CredentialModel

        row = CredentialModel.query.session.get(CredentialModel, credential.id)
        if row is None:
            row = CredentialModel(id=credential.id)
            db.session.add(row)
        row.provider = credential.provider
        row.alias = credential.alias
        row.status = credential.status
        row.description = credential.description
        row.encrypted_secret = credential.encrypted_secret
        row.is_default = credential.is_default
        db.session.commit()
        return _from_model(row)

    def set_default(self, credential_id: str) -> StoredCredential | None:
        from app.storage.database import db
        from app.storage.models import CredentialModel

        row = CredentialModel.query.session.get(CredentialModel, credential_id)
        if row is None or row.status != "active":
            return None
        CredentialModel.query.filter_by(provider=row.provider).update({"is_default": False})
        row.is_default = True
        db.session.commit()
        return _from_model(row)

    def disable(self, credential_id: str) -> StoredCredential | None:
        from app.storage.database import db
        from app.storage.models import CredentialModel

        row = CredentialModel.query.session.get(CredentialModel, credential_id)
        if row is None:
            return None
        row.status = "disabled"
        row.is_default = False
        db.session.commit()
        return _from_model(row)


def _from_model(row) -> StoredCredential:
    return StoredCredential(
        id=row.id,
        provider=row.provider,
        alias=row.alias,
        status=row.status,
        description=row.description,
        encrypted_secret=row.encrypted_secret,
        is_default=bool(row.is_default),
        created_at=_format_datetime(row.created_at),
        updated_at=_format_datetime(row.updated_at),
    )


def _format_datetime(value: datetime | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()
