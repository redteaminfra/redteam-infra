# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only credential visibility required before a keyed diagnostic core GO."""

from copy import deepcopy
from dataclasses import replace
import hashlib

import pytest

from app.services.provider_keyed_cleanup_visibility import (
    ProviderKeyedCleanupVisibilityError, require_digitalocean_cleanup_visibility,
)
from app.storage.credential_repository import StoredCredential


CONNECTION = "cred-do"
SECRET = "encrypted-test-value"
SNAPSHOT = {
    "encryptedSecretSha256": hashlib.sha256(SECRET.encode()).hexdigest(),
    "updatedAt": "2026-10-09T00:00:00+00:00",
}


class Credentials:
    def __init__(self):
        self.record = StoredCredential(
            CONNECTION, "digitalocean", "team", "active", "", SECRET, True,
            SNAPSHOT["updatedAt"], SNAPSHOT["updatedAt"],
        )

    def get(self, credential_id):
        return self.record if credential_id == CONNECTION else None

    def get_default(self, provider):
        return self.record if provider == "digitalocean" else None


class Catalog:
    def __init__(self, pages, credentials=None, drift_after=None):
        self.pages = pages
        self.credentials = credentials
        self.drift_after = drift_after
        self.calls = []

    def request(self, origin, method, path, token):
        assert origin == "https://api.digitalocean.com/v2"
        assert method == "GET" and token == "token-fixture"
        self.calls.append(path)
        if path.startswith("/databases?"):
            raise PermissionError("database:read unavailable")
        if self.drift_after == len(self.calls):
            self.credentials.record = replace(self.credentials.record, updated_at="changed")
        result = self.pages[path]
        if isinstance(result, Exception):
            raise result
        return deepcopy(result)


def _page(key, rows):
    return {key: rows, "meta": {"total": len(rows)}, "links": {"pages": {}}}


def _pages():
    return {
        "/droplets?page=1&per_page=200": _page("droplets", []),
        "/droplets?page=1&per_page=200&type=gpus": _page("droplets", []),
        "/images?page=1&per_page=200&private=true": _page("images", []),
        "/volumes?page=1&per_page=200": _page("volumes", []),
        "/snapshots?page=1&per_page=200&resource_type=volume": _page("snapshots", []),
        "/firewalls?page=1&per_page=200": _page("firewalls", []),
    }


def _check(credentials, catalog):
    return require_digitalocean_cleanup_visibility(
        CONNECTION, SNAPSHOT, credential_repository=credentials,
        transport=catalog, decrypt_secret=lambda _: "token-fixture",
    )


def test_complete_selected_credential_visibility_is_read_only():
    credentials = Credentials()
    catalog = Catalog(_pages())
    assert _check(credentials, catalog) == (
        "droplets", "gpu_droplets", "images", "volumes", "volume_snapshots")
    assert len(catalog.calls) == 6
    assert not any(path.startswith("/databases") for path in catalog.calls)


@pytest.mark.parametrize("failure", ["image_403", "incomplete_page", "credential_drift"])
def test_incomplete_visibility_or_credential_drift_blocks_before_core_go(failure):
    credentials = Credentials()
    pages = _pages()
    if failure == "image_403":
        pages["/images?page=1&per_page=200&private=true"] = PermissionError("403")
    elif failure == "incomplete_page":
        pages["/volumes?page=1&per_page=200"] = {
            "volumes": [], "meta": {"total": 1}, "links": {"pages": {}}}
    catalog = Catalog(pages, credentials,
                      drift_after=1 if failure == "credential_drift" else None)
    with pytest.raises(ProviderKeyedCleanupVisibilityError, match="complete cleanup visibility"):
        _check(credentials, catalog)
    assert all(path.startswith("/") for path in catalog.calls)
