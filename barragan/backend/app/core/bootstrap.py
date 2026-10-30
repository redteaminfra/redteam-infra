# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.services.certificate_manager import migrate_legacy_channel_certificates
from app.storage.database import DatabaseState, db, ensure_database_schema, seed_database


def initialize_database(
    config: type | Mapping[str, Any],
    *,
    state: DatabaseState | None = None,
    make_default: bool = False,
) -> DatabaseState:
    """Initialize Barragan persistence without relying on a web framework."""

    database_uri = str(_config_value(config, "SQLALCHEMY_DATABASE_URI") or "")
    if not database_uri:
        raise RuntimeError("SQLALCHEMY_DATABASE_URI is required")
    database_state = state or db.configure(database_uri, make_default=make_default)
    with db.bind(database_state):
        from app.storage import models  # noqa: F401

        db.create_all()
        ensure_database_schema()
        seed_database()
        migrate_legacy_channel_certificates()
    return database_state


def _config_value(config: type | Mapping[str, Any], key: str) -> Any:
    if isinstance(config, Mapping):
        return config.get(key)
    return getattr(config, key, None)
