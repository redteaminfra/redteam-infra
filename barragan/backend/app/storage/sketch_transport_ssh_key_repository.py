# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from app.storage.sketch_ssh_key_repository import StoredSketchSshKey, _format_datetime


class SqlAlchemySketchTransportSshKeyRepository:
    def get(self, engagement_id: str) -> StoredSketchSshKey | None:
        from app.storage.models import SketchTransportSshKeyModel

        row = SketchTransportSshKeyModel.query.session.get(
            SketchTransportSshKeyModel, engagement_id
        )
        return _from_model(row) if row else None

    def save(self, key: StoredSketchSshKey) -> StoredSketchSshKey:
        from app.storage.database import db
        from app.storage.models import SketchTransportSshKeyModel

        row = SketchTransportSshKeyModel.query.session.get(
            SketchTransportSshKeyModel, key.engagement_id
        )
        if row is None:
            row = SketchTransportSshKeyModel(engagement_id=key.engagement_id)
            db.session.add(row)
        for field in (
            "private_key_name",
            "public_key_name",
            "encrypted_private_key",
            "encrypted_public_key",
            "fingerprint",
            "retired_keys",
        ):
            setattr(row, field, getattr(key, field))
        db.session.commit()
        return _from_model(row)


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
