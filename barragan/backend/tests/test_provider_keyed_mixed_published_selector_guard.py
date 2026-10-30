# Copyright (c) 2026, Oracle and/or its affiliates.
"""The published selector guard uses only aggregate tag and firewall reads."""

import pytest

from app.services.provider_keyed_mixed_published_selector_guard import (
    PublishedSelectorGuardError, read_published_selector_guard,
)


SELECTOR = "s01234567890123456789"


class Catalog:
    def __init__(self, *, count=0, firewall=None):
        self.calls = []
        self.count = count
        self.firewall = firewall

    def request(self, base, method, path, token):
        self.calls.append(path)
        assert method == "GET" and token == "token"
        if path == f"/tags/{SELECTOR}":
            return {"tag": {"name": SELECTOR,
                            "resources": {"count": self.count}}}
        if path == "/firewalls?page=1&per_page=200":
            return {"firewalls": [self.firewall] if self.firewall else [],
                    "meta": {"total": 1 if self.firewall else 0},
                    "links": {"pages": {}}}
        pytest.fail(f"unexpected inventory endpoint: {path}")


class Status:
    def __init__(self, *values):
        self.values = iter(values)
        self.calls = 0

    def get_tag_status(self, token, selector):
        assert token == "token" and selector == SELECTOR
        self.calls += 1
        return next(self.values)


@pytest.mark.parametrize("status,expected", [(200, True), (404, False)])
def test_guard_uses_only_exact_tag_and_complete_firewall_inventory(status, expected):
    catalog = Catalog()
    result = read_published_selector_guard(
        catalog, Status(status, status), "token", SELECTOR, lambda: None)
    assert result is expected
    assert catalog.calls == ([f"/tags/{SELECTOR}"] if expected else []) + [
        "/firewalls?page=1&per_page=200"]


@pytest.mark.parametrize("count,firewall", [
    (1, None),
    (0, {"id": "firewall-1", "tags": [SELECTOR],
         "inbound_rules": [], "outbound_rules": []}),
    (0, {"id": "firewall-1", "tags": [],
         "inbound_rules": [{"sources": {"tags": [SELECTOR]}}],
         "outbound_rules": []}),
])
def test_guard_vetoes_attachments_and_firewall_references(count, firewall):
    catalog = Catalog(count=count, firewall=firewall)
    with pytest.raises(PublishedSelectorGuardError):
        read_published_selector_guard(
            catalog, Status(200, 200), "token", SELECTOR, lambda: None)
    assert all("databases" not in path for path in catalog.calls)


def test_guard_vetoes_status_drift():
    with pytest.raises(PublishedSelectorGuardError):
        read_published_selector_guard(
            Catalog(), Status(200, 404), "token", SELECTOR, lambda: None)
