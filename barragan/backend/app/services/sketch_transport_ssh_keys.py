# Copyright (c) 2026, Oracle and/or its affiliates.
"""Durable channel-only SSH identity for sketch transport."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import shutil

from app.services.credentials import decrypt_secret_value
from app.services.engagements import get_engagement
from app.services.sketch_ssh_keys import (
    SketchSshKeyMaterial,
    SketchSshKeyNotFoundError,
    _metadata,
    _new_stored_key,
)
from app.storage.sketch_transport_ssh_key_repository import (
    SqlAlchemySketchTransportSshKeyRepository,
)


def ensure_sketch_transport_ssh_key(engagement_id: str, repository=None):
    repo = repository or SqlAlchemySketchTransportSshKeyRepository()
    existing = repo.get(engagement_id)
    if existing is not None:
        return _metadata(existing)
    engagement = get_engagement(engagement_id)
    if engagement is None:
        raise ValueError("engagement not found")
    bootstrap = _new_stored_key(engagement_id, engagement.name)
    stored = repo.save(
        replace(
            bootstrap,
            private_key_name=bootstrap.private_key_name.replace(
                "-sketch", "-sketch-transport"
            ),
            public_key_name=bootstrap.public_key_name.replace(
                "-sketch.pub", "-sketch-transport.pub"
            ),
        )
    )
    return _metadata(stored)


def retrieve_sketch_transport_ssh_key(
    engagement_id: str, repository=None
) -> SketchSshKeyMaterial | None:
    stored = (repository or SqlAlchemySketchTransportSshKeyRepository()).get(
        engagement_id
    )
    if stored is None:
        return None
    return SketchSshKeyMaterial(
        _metadata(stored),
        decrypt_secret_value(stored.encrypted_private_key),
        decrypt_secret_value(stored.encrypted_public_key),
    )


def write_sketch_transport_ssh_key_files(
    engagement_id: str, directory: Path, repository=None
) -> tuple[str, str]:
    """Materialize the channel identity only in a per-run private workspace."""
    material = retrieve_sketch_transport_ssh_key(engagement_id, repository)
    if material is None:
        ensure_sketch_transport_ssh_key(engagement_id, repository)
        material = retrieve_sketch_transport_ssh_key(engagement_id, repository)
    if material is None:
        raise SketchSshKeyNotFoundError("sketch transport SSH key not found")
    directory.mkdir(parents=True, exist_ok=True)
    private_path = directory / material.metadata.private_key_name
    public_path = directory / material.metadata.public_key_name
    private_path.write_text(material.private_key, encoding="utf-8")
    public_path.write_text(material.public_key, encoding="utf-8")
    private_path.chmod(0o600)
    public_path.chmod(0o644)
    return str(private_path), str(public_path)


def write_existing_sketch_transport_ssh_key_files(
    engagement_id: str, directory: Path, repository=None
) -> tuple[str, str]:
    """Materialize an already-provisioned transport identity for an apply run.

    Unlike ``write_sketch_transport_ssh_key_files``, this intentionally never
    creates a key.  Applying a channel or Backflips configuration must not
    rotate the identity deployed to sketch nodes.
    """
    material = retrieve_sketch_transport_ssh_key(engagement_id, repository)
    if material is None:
        raise SketchSshKeyNotFoundError(
            "sketch transport SSH key not found; deploy the sketch chain before applying channels"
        )
    try:
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)
        private_path = directory / material.metadata.private_key_name
        public_path = directory / material.metadata.public_key_name
        private_path.write_text(material.private_key, encoding="utf-8")
        public_path.write_text(material.public_key, encoding="utf-8")
        private_path.chmod(0o600)
        public_path.chmod(0o644)
    except Exception:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    return str(private_path), str(public_path)
