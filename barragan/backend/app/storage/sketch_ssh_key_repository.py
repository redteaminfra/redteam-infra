# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol


@dataclass(frozen=True)
class StoredSketchSshKey:
    engagement_id: str
    private_key_name: str
    public_key_name: str
    encrypted_private_key: str
    encrypted_public_key: str
    fingerprint: str
    retired_keys: list[dict[str, Any]]
    created_at: str
    updated_at: str


class SketchSshKeyRepository(Protocol):
    def get(self, engagement_id: str) -> StoredSketchSshKey | None:
        ...

    def save(self, key: StoredSketchSshKey) -> StoredSketchSshKey:
        ...

    def delete(self, engagement_id: str) -> StoredSketchSshKey | None:
        ...


class SqlAlchemySketchSshKeyRepository:
    def get(self, engagement_id: str) -> StoredSketchSshKey | None:
        from app.storage.models import SketchSshKeyModel

        row = SketchSshKeyModel.query.session.get(SketchSshKeyModel, engagement_id)
        if row is None:
            return None
        return _from_model(row)

    def save(self, key: StoredSketchSshKey) -> StoredSketchSshKey:
        from app.storage.database import db
        from app.storage.models import SketchSshKeyModel

        row = SketchSshKeyModel.query.session.get(SketchSshKeyModel, key.engagement_id)
        if row is None:
            row = SketchSshKeyModel(engagement_id=key.engagement_id)
            db.session.add(row)
        row.private_key_name = key.private_key_name
        row.public_key_name = key.public_key_name
        row.encrypted_private_key = key.encrypted_private_key
        row.encrypted_public_key = key.encrypted_public_key
        row.fingerprint = key.fingerprint
        row.retired_keys = key.retired_keys
        db.session.commit()
        return _from_model(row)

    def delete(self, engagement_id: str) -> StoredSketchSshKey | None:
        from app.storage.database import db
        from app.storage.models import SketchSshKeyModel

        row = SketchSshKeyModel.query.session.get(SketchSshKeyModel, engagement_id)
        if row is None:
            return None
        stored = _from_model(row)
        db.session.delete(row)
        db.session.commit()
        return stored


def _from_model(row) -> StoredSketchSshKey:
    return StoredSketchSshKey(
        engagement_id=row.engagement_id,
        private_key_name=row.private_key_name,
        public_key_name=row.public_key_name,
        encrypted_private_key=row.encrypted_private_key,
        encrypted_public_key=row.encrypted_public_key,
        fingerprint=row.fingerprint,
        retired_keys=list(row.retired_keys or []),
        created_at=_format_datetime(row.created_at),
        updated_at=_format_datetime(row.updated_at),
    )


def _format_datetime(value: datetime | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()
