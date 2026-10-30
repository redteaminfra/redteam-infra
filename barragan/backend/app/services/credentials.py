# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import base64
import hashlib
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken

from app.domain import CredentialSummary
from app.storage.credential_repository import CredentialRepository, SqlAlchemyCredentialRepository, StoredCredential


SUPPORTED_PROVIDERS = {"linode", "digitalocean", "namecheap"}


class CredentialValidationError(Exception):
    def __init__(self, errors: list[str]):
        super().__init__("credential validation failed")
        self.errors = errors


class CredentialStoreLockedError(Exception):
    pass


class CredentialDecryptError(Exception):
    pass


@dataclass(frozen=True)
class CredentialValidationResult:
    credential: CredentialSummary
    decryptable: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "credential": self.credential.to_dict(),
            "decryptable": self.decryptable,
        }


def list_credentials(provider: str | None = None, repository: CredentialRepository | None = None) -> list[CredentialSummary]:
    repo = repository or SqlAlchemyCredentialRepository()
    normalized_provider = _normalize_provider(provider) if provider else None
    return [credential.to_summary() for credential in repo.list(provider=normalized_provider)]


def create_credential(body: dict[str, Any], repository: CredentialRepository | None = None) -> CredentialSummary:
    repo = repository or SqlAlchemyCredentialRepository()
    provider = _normalize_provider(str(body.get("provider", "")))
    alias = _normalize_alias(str(body.get("alias", "")))
    secret = str(body.get("secret", ""))
    description = str(body.get("description", "")).strip()
    is_default = bool(body.get("isDefault", False))

    errors = _validate(provider, alias, secret)
    if repo.get_by_alias(provider, alias) is not None:
        errors.append("credential alias already exists for provider")
    if errors:
        raise CredentialValidationError(errors)

    now = datetime.now(timezone.utc).isoformat()
    encrypted_secret = _fernet().encrypt(secret.encode("utf-8")).decode("utf-8")
    stored = repo.save(
        StoredCredential(
            id=f"cred-{uuid4().hex[:12]}",
            provider=provider,
            alias=alias,
            status="active",
            description=description,
            encrypted_secret=encrypted_secret,
            is_default=False,
            created_at=now,
            updated_at=now,
        )
    )
    if is_default:
        stored = repo.set_default(stored.id) or stored
    return stored.to_summary()


def validate_credential(credential_id: str, repository: CredentialRepository | None = None) -> CredentialValidationResult | None:
    repo = repository or SqlAlchemyCredentialRepository()
    credential = repo.get(credential_id)
    if credential is None:
        return None
    try:
        _decrypt_stored_secret(credential)
    except CredentialDecryptError:
        return CredentialValidationResult(credential.to_summary(), decryptable=False)
    return CredentialValidationResult(credential.to_summary(), decryptable=True)


def rotate_credential(credential_id: str, body: dict[str, Any], repository: CredentialRepository | None = None) -> CredentialSummary | None:
    repo = repository or SqlAlchemyCredentialRepository()
    credential = repo.get(credential_id)
    if credential is None:
        return None
    secret = str(body.get("secret", ""))
    description = str(body.get("description", credential.description)).strip()
    errors = _validate(credential.provider, credential.alias, secret)
    if errors:
        raise CredentialValidationError(errors)

    now = datetime.now(timezone.utc).isoformat()
    encrypted_secret = _fernet().encrypt(secret.encode("utf-8")).decode("utf-8")
    stored = repo.save(
        StoredCredential(
            id=credential.id,
            provider=credential.provider,
            alias=credential.alias,
            status="active",
            description=description,
            encrypted_secret=encrypted_secret,
            is_default=credential.is_default,
            created_at=credential.created_at,
            updated_at=now,
        )
    )
    return stored.to_summary()


def disable_credential(credential_id: str, repository: CredentialRepository | None = None) -> CredentialSummary | None:
    repo = repository or SqlAlchemyCredentialRepository()
    credential = repo.disable(credential_id)
    if credential is None:
        return None
    return credential.to_summary()


def resolve_credential_secret(provider: str, alias: str, repository: CredentialRepository | None = None) -> str:
    repo = repository or SqlAlchemyCredentialRepository()
    credential = repo.get_by_alias(_normalize_provider(provider), _normalize_alias(alias))
    if credential is None or credential.status != "active":
        raise CredentialValidationError(["active credential alias not found"])
    return _decrypt_stored_secret(credential)


def set_default_credential(credential_id: str, repository: CredentialRepository | None = None) -> CredentialSummary | None:
    credential = (repository or SqlAlchemyCredentialRepository()).set_default(credential_id)
    if credential is None:
        return None
    return credential.to_summary()


def get_default_credential(provider: str, repository: CredentialRepository | None = None) -> CredentialSummary | None:
    credential = (repository or SqlAlchemyCredentialRepository()).get_default(_normalize_provider(provider))
    if credential is None:
        return None
    return credential.to_summary()


def resolve_default_credential_alias(provider: str, repository: CredentialRepository | None = None) -> str | None:
    credential = (repository or SqlAlchemyCredentialRepository()).get_default(_normalize_provider(provider))
    if credential is None:
        return None
    return credential.alias


def _decrypt_stored_secret(credential: StoredCredential) -> str:
    return decrypt_secret_value(credential.encrypted_secret)


def encrypt_secret_value(secret: str) -> str:
    return _fernet().encrypt(secret.encode("utf-8")).decode("utf-8")


def decrypt_secret_value(encrypted_secret: str) -> str:
    try:
        return _fernet().decrypt(encrypted_secret.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise CredentialDecryptError("credential cannot be decrypted with the configured master key") from exc


def _validate(provider: str, alias: str, secret: str) -> list[str]:
    errors = []
    if provider not in SUPPORTED_PROVIDERS:
        errors.append("provider must be linode, digitalocean, or namecheap")
    if not alias:
        errors.append("alias is required")
    if alias and not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,78}[a-z0-9]", alias):
        errors.append("alias must be 3-80 lowercase letters, numbers, dots, underscores, or dashes")
    if not secret:
        errors.append("secret is required")
    if provider == "namecheap" and secret:
        parts = secret.split(":", 1)
        if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
            errors.append("namecheap secret must be formatted as username:apikey")
    return errors


def _normalize_provider(value: str) -> str:
    return value.strip().lower()


def _normalize_alias(value: str) -> str:
    return value.strip().lower()


def _fernet() -> Fernet:
    return Fernet(_master_key())


def _master_key() -> bytes:
    raw_key = os.environ.get("BARRAGAN_CREDENTIAL_MASTER_KEY", "").strip()
    key_file = os.environ.get("BARRAGAN_CREDENTIAL_MASTER_KEY_FILE", "").strip()
    if not raw_key and key_file:
        raw_key = Path(key_file).read_text(encoding="utf-8").strip()
    if not raw_key:
        raise CredentialStoreLockedError(
            "credential store master key is not configured; set BARRAGAN_CREDENTIAL_MASTER_KEY or BARRAGAN_CREDENTIAL_MASTER_KEY_FILE"
        )
    key = raw_key.encode("utf-8")
    try:
        decoded = base64.urlsafe_b64decode(key)
    except Exception as exc:
        raise CredentialStoreLockedError("credential store master key must be urlsafe base64") from exc
    if len(decoded) != 32:
        raise CredentialStoreLockedError("credential store master key must decode to 32 bytes")
    return key


def test_master_key() -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(b"barragan-test-credential-master-key").digest()).decode("utf-8")
