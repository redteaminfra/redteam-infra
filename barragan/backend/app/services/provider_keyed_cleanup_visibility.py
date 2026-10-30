# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only DigitalOcean visibility check before a disposable keyed deploy.

The selected credential must enumerate each scoped taggable resource family
used by guarded selector retirement. A permission error here must stop core creation,
before there is any billable infrastructure to clean up.
"""

from __future__ import annotations

from typing import Callable, Mapping

from app.services.credentials import decrypt_secret_value
from app.services.provider_catalog import ProviderCatalogTransport, UrllibProviderCatalogTransport
from app.services.provider_keyed_digitalocean_tag_eligibility import _TYPES, _complete_inventory
from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
from app.storage.credential_repository import CredentialRepository, SqlAlchemyCredentialRepository


class ProviderKeyedCleanupVisibilityError(ValueError):
    """The reviewed provider credential cannot prove future cleanup visibility."""


def require_digitalocean_cleanup_visibility(
    connection_id: str,
    reviewed_snapshot: Mapping[str, str],
    *,
    credential_repository: CredentialRepository | None = None,
    transport: ProviderCatalogTransport | None = None,
    decrypt_secret: Callable[[str], str] = decrypt_secret_value,
) -> tuple[str, ...]:
    """GET complete scoped inventories with the exact reviewed credential.

    This checks read permission and page completeness, not tag ownership. The
    initial selector reservation and teardown repeat their own fenced checks.
    """
    try:
        if (type(connection_id) is not str or not connection_id
                or type(reviewed_snapshot) is not dict
                or set(reviewed_snapshot) != {"encryptedSecretSha256", "updatedAt"}):
            raise ValueError("reviewed credential evidence is incomplete")
        credentials = credential_repository or SqlAlchemyCredentialRepository()

        def checked_secret() -> str:
            digest, updated_at, encrypted = _credential_snapshot(connection_id, credentials)
            if (digest != reviewed_snapshot["encryptedSecretSha256"]
                    or updated_at != reviewed_snapshot["updatedAt"]):
                raise ValueError("reviewed provider credential changed")
            return encrypted

        token = decrypt_secret(checked_secret())
        if type(token) is not str or not token:
            raise ValueError("selected provider credential is unavailable")
        client = transport or UrllibProviderCatalogTransport()
        readable: list[str] = []
        for label, endpoint, key, filters in _TYPES:
            rows = _complete_inventory(client, token, endpoint, key, filters,
                                       lambda: checked_secret())
            for row in rows:
                tags = row.get("tags")
                if (type(tags) is not list or any(type(tag) is not str or not tag for tag in tags)
                        or len(tags) != len({tag.casefold() for tag in tags})):
                    raise ValueError("provider tag membership is incomplete")
                if label == "images" and row.get("private") is not True:
                    raise ValueError("private image visibility differs")
                if label == "volume_snapshots" and row.get("resource_type") != "volume":
                    raise ValueError("snapshot visibility differs")
            readable.append(label)
        _complete_inventory(client, token, "/firewalls", "firewalls", {},
                            lambda: checked_secret())
        checked_secret()
        return tuple(readable)
    except Exception:
        raise ProviderKeyedCleanupVisibilityError(
            "selected DigitalOcean credential cannot prove complete cleanup visibility"
        ) from None
