# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network, GET-only DigitalOcean selector visibility evidence."""

from copy import deepcopy
from dataclasses import replace

import pytest

from app.services import provider_keyed_digitalocean_tag_eligibility as service
from test_provider_keyed_destroy_absence_preflight import _prepared


def _page(key, rows, *, total=None, next_url=None):
    return {key: rows, "meta": {"total": len(rows) if total is None else total},
            "links": {"pages": {"next": next_url}}}


class Transport:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def request(self, origin, method, path, token):
        assert origin == "https://api.digitalocean.com/v2"
        assert method == "GET" and token == "token-fixture"
        self.calls.append(path)
        if path.startswith("/databases?"):
            raise PermissionError("database:read unavailable")
        value = self.pages[path]
        if isinstance(value, Exception):
            raise value
        return deepcopy(value)


def _pages(selector):
    return {
        "/droplets?page=1&per_page=200": _page("droplets", []),
        "/droplets?page=1&per_page=200&type=gpus": _page("droplets", []),
        "/images?page=1&per_page=200&private=true": _page("images", []),
        "/volumes?page=1&per_page=200": _page("volumes", []),
        "/snapshots?page=1&per_page=200&resource_type=volume": _page("snapshots", []),
        f"/tags/{selector}": {"tag": {"name": selector, "resources": {"count": 0}}},
    }


def test_complete_managed_inventories_and_tag_get_still_do_not_authorize_delete():
    selector = "s12345678901234567890"
    transport = Transport(_pages(selector))
    checked = service._empty_visible_tag_inventory(transport, "token-fixture", selector,
                                                    lambda: None)
    assert checked == ("droplets", "gpu_droplets", "images", "volumes",
                       "volume_snapshots")
    assert len(transport.calls) == 6
    assert not any(path.startswith("/databases") for path in transport.calls)
    assert all(path.startswith("/") for path in transport.calls)


def test_nullable_zero_volume_snapshots_are_typed_empty_only_for_filtered_endpoint():
    selector = "s12345678901234567890"
    pages = _pages(selector)
    path = "/snapshots?page=1&per_page=200&resource_type=volume"
    # Redacted DevTest observation: HTTP 200, snapshots:null, meta.total:0,
    # links:{}. No other collection gets this interpretation.
    pages[path] = {"snapshots": None, "meta": {"total": 0}, "links": {}}
    transport = Transport(pages)
    checked = service._empty_visible_tag_inventory(
        transport, "token-fixture", selector, lambda: None)
    assert checked == ("droplets", "gpu_droplets", "images", "volumes",
                       "volume_snapshots")
    assert path in transport.calls and f"/tags/{selector}" in transport.calls


@pytest.mark.parametrize("drift", [
    "positive_total", "bool_total", "missing_meta", "extra_meta",
    "next_page", "malformed_pages", "extra_link", "extra_body",
    "other_collection", "image_403",
])
def test_nullable_snapshot_scope_and_pagination_fail_closed(drift):
    selector = "s12345678901234567890"
    pages = _pages(selector)
    snapshot_path = "/snapshots?page=1&per_page=200&resource_type=volume"
    body = {"snapshots": None, "meta": {"total": 0}, "links": {"pages": {}}}
    if drift == "positive_total":
        body["meta"]["total"] = 1
    elif drift == "bool_total":
        body["meta"]["total"] = False
    elif drift == "missing_meta":
        del body["meta"]
    elif drift == "extra_meta":
        body["meta"]["page"] = 1
    elif drift == "next_page":
        body["links"]["pages"]["next"] = (
            "https://api.digitalocean.com/v2/snapshots?page=2&per_page=200&resource_type=volume")
    elif drift == "malformed_pages":
        body["links"]["pages"] = None
    elif drift == "extra_link":
        body["links"]["pages"]["last"] = "https://api.digitalocean.com/v2/snapshots"
    elif drift == "extra_body":
        body["hidden"] = []
    elif drift == "other_collection":
        pages["/volumes?page=1&per_page=200"] = {
            "volumes": None, "meta": {"total": 0}, "links": {"pages": {}}}
    elif drift == "image_403":
        pages["/images?page=1&per_page=200&private=true"] = PermissionError("403")
    pages[snapshot_path] = body
    transport = Transport(pages)
    expected = PermissionError if drift == "image_403" else service.DigitalOceanTagEligibilityError
    with pytest.raises(expected):
        service._empty_visible_tag_inventory(
            transport, "token-fixture", selector, lambda: None)
    assert f"/tags/{selector}" not in transport.calls


def test_nullable_snapshot_second_page_does_not_satisfy_total():
    first = "/snapshots?page=1&per_page=200&resource_type=volume"
    second = "/snapshots?page=2&per_page=200&resource_type=volume"
    pages = {
        first: _page("snapshots", [{"id": "s1", "resource_type": "volume", "tags": []}],
                     total=2, next_url=(
                         "https://api.digitalocean.com/v2/snapshots?page=2&per_page=200&resource_type=volume")),
        second: {"snapshots": None, "meta": {"total": 2}, "links": {"pages": {}}},
    }
    transport = Transport(pages)
    with pytest.raises(service.DigitalOceanTagEligibilityError):
        service._complete_inventory(
            transport, "token-fixture", "/snapshots", "snapshots",
            {"resource_type": "volume"}, lambda: None)
    assert transport.calls == [first, second]


@pytest.mark.parametrize("endpoint,key,filters", [
    ("/snapshots", "snapshots", {}),
    ("/snapshots", "snapshots", {"resource_type": "droplet"}),
    ("/volumes", "snapshots", {"resource_type": "volume"}),
    ("/snapshots", "volumes", {"resource_type": "volume"}),
])
def test_nullable_snapshot_interpretation_rejects_other_query_shapes(endpoint, key, filters):
    body = {key: None, "meta": {"total": 0}, "links": {"pages": {}}}
    class OnePage:
        def request(self, *_args):
            return body
    with pytest.raises(service.DigitalOceanTagEligibilityError):
        service._complete_inventory(
            OnePage(), "token-fixture", endpoint, key, filters, lambda: None)


def test_snapshot_403_cannot_be_interpreted_as_empty():
    class Denied:
        def request(self, *_args):
            raise PermissionError("403")
    with pytest.raises(PermissionError):
        service._complete_inventory(
            Denied(), "token-fixture", "/snapshots", "snapshots",
            {"resource_type": "volume"}, lambda: None)


@pytest.mark.parametrize("kind,path,key,row", [
    ("ordinary", "/droplets?page=1&per_page=200", "droplets", {"id": 101, "tags": ["s12345678901234567890"]}),
    ("gpu", "/droplets?page=1&per_page=200&type=gpus", "droplets", {"id": 102, "tags": ["s12345678901234567890"]}),
    ("image", "/images?page=1&per_page=200&private=true", "images", {"id": 103, "private": True, "tags": ["s12345678901234567890"]}),
    ("volume", "/volumes?page=1&per_page=200", "volumes", {"id": "vol-1", "tags": ["s12345678901234567890"]}),
    ("snapshot", "/snapshots?page=1&per_page=200&resource_type=volume", "snapshots", {"id": "snap-1", "resource_type": "volume", "tags": ["s12345678901234567890"]}),
])
def test_any_taggable_member_blocks(kind, path, key, row):
    selector = "s12345678901234567890"
    pages = _pages(selector)
    pages[path] = _page(key, [row])
    transport = Transport(pages)
    with pytest.raises(service.DigitalOceanTagEligibilityError):
        service._empty_visible_tag_inventory(transport, "token-fixture", selector, lambda: None)
    assert f"/tags/{selector}" not in transport.calls


@pytest.mark.parametrize("drift", ["null_tags", "missing_type", "hidden_scope",
                                    "short_page", "unsafe_next", "tag_count",
                                    "database_count", "tag_name"])
def test_ambiguous_inventory_or_tag_get_blocks(drift):
    selector = "s12345678901234567890"
    pages = _pages(selector)
    if drift == "null_tags":
        pages["/volumes?page=1&per_page=200"] = _page("volumes", [{"id": "v1", "tags": None}])
    elif drift == "missing_type":
        pages["/snapshots?page=1&per_page=200&resource_type=volume"] = _page(
            "snapshots", [{"id": "s1", "tags": []}])
    elif drift == "hidden_scope":
        pages["/images?page=1&per_page=200&private=true"] = PermissionError("403")
    elif drift == "short_page":
        pages["/volumes?page=1&per_page=200"] = _page("volumes", [], total=1)
    elif drift == "unsafe_next":
        pages["/images?page=1&per_page=200&private=true"] = _page(
            "images", [{"id": 1, "private": True, "tags": []}], total=2,
            next_url="https://evil.example/v2/images?page=2&per_page=200&private=true")
    elif drift == "tag_count":
        pages[f"/tags/{selector}"]["tag"]["resources"]["count"] = 1
    elif drift == "database_count":
        pages[f"/tags/{selector}"]["tag"]["resources"]["databases"] = {"count": 1}
    else:
        pages[f"/tags/{selector}"]["tag"]["name"] = "different"
    expected = PermissionError if drift == "hidden_scope" else service.DigitalOceanTagEligibilityError
    with pytest.raises(expected):
        service._empty_visible_tag_inventory(Transport(pages), "token-fixture", selector,
                                             lambda: None)


def test_complete_multi_page_filter_and_fence_each_get():
    selector = "s12345678901234567890"
    pages = _pages(selector)
    first = "/images?page=1&per_page=200&private=true"
    pages[first] = _page(
        "images", [{"id": 1, "private": True, "tags": []}], total=2,
        next_url="https://api.digitalocean.com/v2/images?page=2&per_page=200&private=true")
    pages["/images?page=2&per_page=200&private=true"] = _page(
        "images", [{"id": 2, "private": True, "tags": []}], total=2)
    transport = Transport(pages)
    fences = []
    service._empty_visible_tag_inventory(transport, "token-fixture", selector,
                                         lambda: fences.append(len(transport.calls)))
    assert len(transport.calls) == 7
    assert len(fences) == 14  # before and after every GET


def test_successful_destroy_scope_and_absence_bind_read_only_ineligible_result(tmp_path, monkeypatch):
    jobs, queued, scope, plans, workspace, child, proof, _calls, args = _prepared(
        tmp_path, monkeypatch)
    monkeypatch.setattr(service, "_default_state_root", lambda: args["state_root"])
    selector = scope["selectorTag"]
    transport = Transport(_pages(selector))
    args["decrypt_secret"] = lambda _encrypted: "token-fixture"
    args["transport"] = transport
    args["absence_reconciler"] = lambda *_a, **_k: proof
    result = service.inspect_successful_digitalocean_tag_eligibility(queued.id, **args)
    assert result.selector_tag == selector
    assert result.zero_membership and result.reviewed_selector_use
    assert not result.exclusive_creation_proven and not result.delete_authorized
    assert jobs.get(queued.id) == queued
    assert plans.lease == (scope["corePlanId"], "provider_keyed_teardown_fence")


def test_parent_or_credential_drift_blocks_before_tag_get(tmp_path, monkeypatch):
    jobs, queued, scope, plans, workspace, child, proof, _calls, args = _prepared(
        tmp_path, monkeypatch)
    monkeypatch.setattr(service, "_default_state_root", lambda: args["state_root"])
    transport = Transport(_pages(scope["selectorTag"]))
    args.update(transport=transport, decrypt_secret=lambda _encrypted: "token-fixture",
                absence_reconciler=lambda *_a, **_k: proof)
    plans.lease = (scope["corePlanId"], "wrong-operation")
    with pytest.raises(service.DigitalOceanTagEligibilityError):
        service.inspect_successful_digitalocean_tag_eligibility(queued.id, **args)
    assert transport.calls == []
