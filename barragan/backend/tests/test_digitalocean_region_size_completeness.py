# Copyright (c) 2026, Oracle and/or its affiliates.
from copy import deepcopy
from types import SimpleNamespace

import pytest

from app.services.provider_catalog import (
    ProviderCatalogError, ProviderCatalogRegionSizeUnavailable,
    require_selected_digitalocean_region_sizes,
)


def complete():
    return {"regions": [{"slug": "nyc3", "available": True, "sizes": ["s-1vcpu-1gb"]}],
            "links": {}, "meta": {"total": 1}}


def require(body, selections=None):
    return require_selected_digitalocean_region_sizes("fixture-token",
        selections if selections is not None else [("nyc3", "s-1vcpu-1gb")],
        transport=SimpleNamespace(request=lambda *_: body))


def test_genuine_complete_single_page_and_empty_catalog():
    require(complete())
    body = complete()
    body["links"] = {"pages": {}}
    require(body)
    with pytest.raises(ProviderCatalogRegionSizeUnavailable):
        require({"regions": [], "links": {}, "meta": {"total": 0}})


@pytest.mark.parametrize("key,value", [
    ("links", None), ("links", []), ("meta", None), ("meta", []),
    ("meta", {}), ("meta", {"total": True}), ("meta", {"total": 1.0}),
    ("meta", {"total": "1"}), ("meta", {"total": -1}),
    ("meta", {"total": 0}), ("meta", {"total": 2}),
    ("links", {"pages": None}), ("links", {"pages": []}),
    ("links", {"pages": {"next": "https://api.digitalocean.com/v2/regions?page=2"}}),
    ("links", {"pages": {"next": None}}), ("links", {"pages": {"next": False}}),
    ("links", {"pages": {"last": False}}), ("links", {"pages": {"prev": "previous"}}),
])
def test_malformed_or_incomplete_pagination_is_not_available(key, value):
    body = complete()
    body[key] = value
    with pytest.raises(ProviderCatalogError):
        require(body)


@pytest.mark.parametrize("key", ["links", "meta", "regions"])
def test_missing_pagination_is_unknown_not_success(key):
    body = complete()
    del body[key]
    with pytest.raises(ProviderCatalogError):
        require(body)


@pytest.mark.parametrize("mutation", [
    lambda rows: rows.append(deepcopy(rows[0])),
    lambda rows: rows.append({**rows[0], "available": False}),
    lambda rows: rows.append({}),
    lambda rows: rows[0].update(available="true"),
    lambda rows: rows[0].update(sizes="s-1vcpu-1gb"),
    lambda rows: rows[0].update(sizes=["s-1vcpu-1gb", "s-1vcpu-1gb"]),
    lambda rows: rows[0].update(slug=""),
])
def test_ambiguous_or_malformed_region_rows_are_rejected(mutation):
    body = complete()
    mutation(body["regions"])
    body["meta"]["total"] = len(body["regions"])
    with pytest.raises(ProviderCatalogError):
        require(body)
