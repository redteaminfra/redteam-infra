# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import pytest

from app.services import provider_keyed_selector_preflight as preflight
from app.storage.credential_repository import StoredCredential


SELECTOR = "barragan-opaque-123"
CONNECTION = "cred-connection"


class FakeRepository:
    def __init__(self, credential=None):
        self.credential = credential or StoredCredential(
            id=CONNECTION,
            provider="digitalocean",
            alias="shared",
            status="active",
            description="",
            encrypted_secret="encrypted",
            is_default=True,
            created_at="",
            updated_at="",
        )

    def get_default(self, provider):
        assert provider == "digitalocean"
        return self.credential


class FakeTransport:
    def __init__(self, responses):
        self.responses = responses
        self.paths = []

    def request(self, base_url, method, path, token):
        assert base_url == "https://api.digitalocean.com/v2"
        assert method == "GET"
        assert token == "test-token"
        self.paths.append(path)
        response = self.responses[path]
        if isinstance(response, Exception):
            raise response
        return response


def _page(kind, items, total=None, next_page=None):
    result = {kind: items, "meta": {"total": len(items) if total is None else total}}
    if next_page is not None:
        result["links"] = {"pages": {"next": next_page}}
    return result


def _url(kind, page, page_size=200, *, gpu_only=False):
    suffix = "&type=gpus" if gpu_only else ""
    return f"https://api.digitalocean.com/v2/{kind}?page={page}&per_page={page_size}{suffix}"


def _check(monkeypatch, responses, connection=CONNECTION):
    monkeypatch.setattr(preflight, "decrypt_secret_value", lambda encrypted: "test-token")
    pages = dict(responses)
    pages.setdefault("/tags?page=1&per_page=200", _page("tags", []))
    pages.setdefault("/droplets?page=1&per_page=200&type=gpus", _page("droplets", []))
    transport = FakeTransport(pages)
    result = preflight.require_new_digitalocean_selector_available(
        SELECTOR,
        "engagement-tag",
        connection,
        repository=FakeRepository(),
        transport=transport,
    )
    return result, transport.paths


def test_empty_account_has_safe_count_evidence(monkeypatch):
    result, paths = _check(monkeypatch, {
        "/firewalls?page=1&per_page=200": _page("firewalls", []),
        "/droplets?page=1&per_page=200": _page("droplets", []),
    })
    assert result == preflight.SelectorPreflightEvidence(0, 0, 0)
    assert paths == ["/tags?page=1&per_page=200", "/firewalls?page=1&per_page=200", "/droplets?page=1&per_page=200", "/droplets?page=1&per_page=200&type=gpus"]
    assert SELECTOR not in repr(result)


def test_scans_all_pages_of_both_inventories(monkeypatch):
    responses = {}
    for kind in ("tags", "firewalls", "droplets"):
        items = [{"name": "other-tag"}] if kind == "tags" else [{"id": 1, "tags": ["other"]}]
        last_items = [{"name": "second-tag"}] if kind == "tags" else [{"id": 2, "tags": []}]
        responses[f"/{kind}?page=1&per_page=200"] = _page(
            kind, items, total=2, next_page=_url(kind, 2)
        )
        responses[f"/{kind}?page=2&per_page=200"] = _page(kind, last_items, total=2)
    result, paths = _check(monkeypatch, responses)
    assert result == preflight.SelectorPreflightEvidence(2, 2, 2)
    assert len(paths) == 7


def test_gpu_droplets_are_scanned_on_all_pages(monkeypatch):
    gpu_first = "/droplets?page=1&per_page=200&type=gpus"
    gpu_second = "/droplets?page=2&per_page=100&type=gpus"
    responses = {
        "/firewalls?page=1&per_page=200": _page("firewalls", []),
        "/droplets?page=1&per_page=200": _page("droplets", []),
        gpu_first: _page("droplets", [{"id": 10, "tags": ["other"]}], total=2,
                         next_page=_url("droplets", 2, 100, gpu_only=True)),
        gpu_second: _page("droplets", [{"id": 11, "tags": ["other"]}], total=2),
    }
    result, paths = _check(monkeypatch, responses)
    assert result.droplets_checked == 2
    assert paths[-2:] == [gpu_first, gpu_second]


def test_gpu_droplet_selector_collision_on_later_page_fails(monkeypatch):
    responses = {
        "/firewalls?page=1&per_page=200": _page("firewalls", []),
        "/droplets?page=1&per_page=200": _page("droplets", []),
        "/droplets?page=1&per_page=200&type=gpus": _page(
            "droplets", [{"id": 10, "tags": []}], total=2,
            next_page=_url("droplets", 2, gpu_only=True),
        ),
        "/droplets?page=2&per_page=200&type=gpus": _page(
            "droplets", [{"id": 11, "tags": [SELECTOR]}], total=2,
        ),
    }
    with pytest.raises(preflight.SelectorPreflightError, match="already used"):
        _check(monkeypatch, responses)


@pytest.mark.parametrize("next_url", [
    _url("droplets", 2),
    "https://api.digitalocean.com/v2/droplets?page=2&per_page=200&type=default",
    "https://api.digitalocean.com/v2/droplets?page=2&per_page=200&type=gpus&tag_name=other",
])
def test_gpu_pagination_cannot_escape_gpu_inventory(monkeypatch, next_url):
    responses = {
        "/firewalls?page=1&per_page=200": _page("firewalls", []),
        "/droplets?page=1&per_page=200": _page("droplets", []),
        "/droplets?page=1&per_page=200&type=gpus": _page(
            "droplets", [{"id": 10, "tags": []}], total=2, next_page=next_url,
        ),
    }
    with pytest.raises(preflight.SelectorPreflightError, match="next URL is unsafe"):
        _check(monkeypatch, responses)


def test_existing_account_tag_on_later_page_is_rejected_even_without_droplets(monkeypatch):
    responses = {
        "/tags?page=1&per_page=200": _page("tags", [{"name": "other"}], total=2, next_page=_url("tags", 2)),
        "/tags?page=2&per_page=200": _page("tags", [{"name": SELECTOR.upper()}], total=2),
    }
    with pytest.raises(preflight.SelectorPreflightError, match="already used"):
        _check(monkeypatch, responses)


def test_provider_may_cap_requested_page_size_without_hiding_later_tags(monkeypatch):
    responses = {
        "/tags?page=1&per_page=200": _page("tags", [{"name": "other"}], total=2, next_page=_url("tags", 2, 100)),
        "/tags?page=2&per_page=100": _page("tags", [{"name": SELECTOR}], total=2),
    }
    with pytest.raises(preflight.SelectorPreflightError, match="already used"):
        _check(monkeypatch, responses)


def test_provider_page_size_cannot_change_again_mid_inventory(monkeypatch):
    responses = {
        "/tags?page=1&per_page=200": _page("tags", [{"name": "first"}], total=3, next_page=_url("tags", 2, 100)),
        "/tags?page=2&per_page=100": _page("tags", [{"name": "second"}], total=3, next_page=_url("tags", 3, 50)),
    }
    with pytest.raises(preflight.SelectorPreflightError, match="next URL is unsafe"):
        _check(monkeypatch, responses)


@pytest.mark.parametrize("kind", ["firewalls", "droplets"])
def test_collision_on_any_resource_is_rejected(monkeypatch, kind):
    responses = {
        "/firewalls?page=1&per_page=200": _page("firewalls", []),
        "/droplets?page=1&per_page=200": _page("droplets", []),
    }
    responses[f"/{kind}?page=1&per_page=200"] = _page(kind, [{"id": 9, "tags": [SELECTOR]}])
    with pytest.raises(preflight.SelectorPreflightError, match="already used"):
        _check(monkeypatch, responses)


@pytest.mark.parametrize("bad", [
    {"firewalls": [], "meta": {"total": 1}},
    {"firewalls": [], "meta": {"total": True}},
    {"firewalls": [], "meta": {"total": 0}, "links": {"pages": {"next": _url("firewalls", 2)}}},
    {"firewalls": [{"id": 1, "tags": []}], "meta": {"total": 2}},
    {"firewalls": [{"id": 1}], "meta": {"total": 1}},
    {"firewalls": [{"id": 1, "tags": []}], "meta": {"total": 2}, "links": {"pages": {"next": _url("firewalls", 1)}}},
    {"firewalls": [{"id": 1, "tags": []}], "meta": {"total": 2}, "links": {"pages": {"next": "https://evil.example/v2/firewalls?page=2&per_page=200"}}},
    {"firewalls": [{"id": 1, "tags": []}], "meta": {"total": 2}, "links": {"pages": {"next": "https://api.digitalocean.com/v2/firewalls?page=2&per_page=200&token=bad"}}},
])
def test_incomplete_malformed_or_unsafe_inventory_fails_closed(monkeypatch, bad):
    with pytest.raises(preflight.SelectorPreflightError):
        _check(monkeypatch, {"/firewalls?page=1&per_page=200": bad})


def test_provider_request_failure_is_redacted(monkeypatch):
    with pytest.raises(preflight.SelectorPreflightError, match="provider inventory request failed") as error:
        _check(monkeypatch, {"/firewalls?page=1&per_page=200": RuntimeError("token-secret")})
    assert "token-secret" not in str(error.value)


def test_credential_repository_failure_is_redacted():
    class BrokenRepository:
        def get_default(self, provider):
            raise RuntimeError("sensitive backend detail")

    with pytest.raises(preflight.SelectorPreflightError, match="provider connection is unavailable") as error:
        preflight.require_new_digitalocean_selector_available(
            SELECTOR, "engagement-tag", CONNECTION, repository=BrokenRepository(), transport=FakeTransport({})
        )
    assert "sensitive backend detail" not in str(error.value)


def test_connection_mismatch_never_decrypts_or_calls_provider(monkeypatch):
    monkeypatch.setattr(preflight, "decrypt_secret_value", lambda encrypted: pytest.fail("must not decrypt"))
    with pytest.raises(preflight.SelectorPreflightError, match="connection changed"):
        preflight.require_new_digitalocean_selector_available(
            SELECTOR, "engagement-tag", "cred-other", repository=FakeRepository(), transport=FakeTransport({})
        )


@pytest.mark.parametrize("selector,engagement", [("short", "other"), (SELECTOR, SELECTOR), ("UPPERCASE-TAG", "other")])
def test_invalid_selector_is_rejected_before_credential_access(selector, engagement):
    with pytest.raises(preflight.SelectorPreflightError):
        preflight.require_new_digitalocean_selector_available(
            selector, engagement, CONNECTION, repository=FakeRepository(), transport=FakeTransport({})
        )
