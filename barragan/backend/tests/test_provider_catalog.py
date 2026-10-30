# Copyright (c) 2026, Oracle and/or its affiliates.
from app import create_app
from app.core.config import TestConfig
from app.services.credentials import test_master_key as credential_test_master_key
from app.services import provider_catalog


class FakeCatalogTransport:
    def __init__(self):
        self.fail = False
        self.region_available = True
        self.region_sizes = ["s-1vcpu-1gb"]
        self.size_available = True
        self.calls = []

    def request(self, base_url, method, path, token):
        self.calls.append((base_url, method, path, token))
        if self.fail:
            raise provider_catalog.ProviderCatalogError("provider unavailable")
        if base_url.endswith("linode.com/v4") and path == "/regions":
            return {
                "data": [
                    {"id": "us-lax", "label": "Los Angeles, CA", "status": "ok"},
                    {"id": "us-sea", "label": "Seattle, WA", "status": "ok"},
                ]
            }
        if base_url.endswith("linode.com/v4") and path == "/linode/types":
            return {
                "data": [
                    {"id": "g6-nanode-1", "label": "Nanode 1 GB", "vcpus": 1, "memory": 1024, "disk": 25, "price": {"monthly": 5}},
                    {"id": "g6-standard-1", "label": "Linode 2 GB", "vcpus": 1, "memory": 2048, "disk": 50, "price": {"monthly": 12}},
                ]
            }
        if base_url.endswith("digitalocean.com/v2") and path == "/regions":
            return {
                "regions": [
                    {
                        "slug": "nyc1",
                        "name": "New York 1",
                        "available": True,
                        "sizes": self.region_sizes,
                    },
                    {
                        "slug": "sfo3",
                        "name": "San Francisco 3",
                        "available": self.region_available,
                        "sizes": self.region_sizes,
                    }
                ]
            }
        if base_url.endswith("digitalocean.com/v2") and path == "/sizes":
            return {
                "sizes": [
                    {
                        "slug": "s-1vcpu-1gb",
                        "description": "Basic 1 vCPU / 1 GB",
                        "vcpus": 1,
                        "memory": 1024,
                        "disk": 25,
                        "price_monthly": 6,
                        "available": self.size_available,
                    },
                    {"slug": "s-2vcpu-2gb", "description": "Basic 2 vCPU / 2 GB", "vcpus": 2, "memory": 2048, "disk": 60, "price_monthly": 18},
                ]
            }
        raise AssertionError(f"unexpected request: {base_url} {path}")


def catalog_client(monkeypatch):
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", credential_test_master_key())
    app = create_app(TestConfig)
    return app, app.test_client()


def test_linode_catalog_uses_default_credential_and_redacts_response(monkeypatch):
    _app, client = catalog_client(monkeypatch)
    transport = FakeCatalogTransport()
    monkeypatch.setattr(provider_catalog, "UrllibProviderCatalogTransport", lambda: transport)
    client.post(
        "/api/credentials",
        json={"provider": "linode", "alias": "linode-catalog", "secret": "linode-token-sensitive-value", "isDefault": True},
    )

    response = client.get("/api/provider-catalog/sketch?provider=linode")
    body = response.get_json()

    assert response.status_code == 200
    assert body["catalog"]["source"] == "live"
    assert body["catalog"]["defaults"] == {"region": "us-sea", "size": "g6-nanode-1"}
    assert [region["id"] for region in body["catalog"]["regions"]] == ["us-sea"]
    assert body["catalog"]["sizes"][0]["id"] == "g6-nanode-1"
    assert body["catalog"]["regionPolicy"]["allowedRegions"] == ["us-sea"]
    assert "linode-token-sensitive-value" not in str(body)
    assert "linode-catalog" not in str(body)
    assert transport.calls[0][3] == "linode-token-sensitive-value"


def test_catalog_returns_stale_cache_when_refresh_fails(monkeypatch):
    _app, client = catalog_client(monkeypatch)
    transport = FakeCatalogTransport()
    monkeypatch.setattr(provider_catalog, "UrllibProviderCatalogTransport", lambda: transport)
    client.post(
        "/api/credentials",
        json={"provider": "linode", "alias": "linode-catalog", "secret": "linode-token-sensitive-value", "isDefault": True},
    )
    assert client.get("/api/provider-catalog/sketch?provider=linode").status_code == 200

    transport.fail = True
    response = client.get("/api/provider-catalog/sketch?provider=linode&refresh=1")
    body = response.get_json()

    assert response.status_code == 200
    assert body["catalog"]["source"] == "stale_cache"
    assert body["catalog"]["regions"][0]["id"] == "us-sea"
    assert body["catalog"]["warnings"]
    assert "linode-token-sensitive-value" not in str(body)


def test_digitalocean_catalog_filters_sizes_by_region(monkeypatch):
    _app, client = catalog_client(monkeypatch)
    transport = FakeCatalogTransport()
    monkeypatch.setattr(provider_catalog, "UrllibProviderCatalogTransport", lambda: transport)
    client.post(
        "/api/credentials",
        json={"provider": "digitalocean", "alias": "do-catalog", "secret": "do-token-sensitive-value", "isDefault": True},
    )

    response = client.get("/api/provider-catalog/sketch?provider=digitalocean")
    body = response.get_json()

    assert response.status_code == 200
    assert body["catalog"]["source"] == "live"
    assert body["catalog"]["defaults"] == {"region": "sfo3", "size": "s-1vcpu-1gb"}
    assert [region["id"] for region in body["catalog"]["regions"]] == ["sfo3"]
    assert body["catalog"]["sizes"][0]["regions"] == ["sfo3"]
    assert body["catalog"]["sizes"][1]["available"] is False
    assert "do-token-sensitive-value" not in str(body)
    assert "do-catalog" not in str(body)


def test_catalog_falls_back_to_seed_without_default_credential(monkeypatch):
    _app, client = catalog_client(monkeypatch)

    response = client.get("/api/provider-catalog/sketch?provider=linode")
    body = response.get_json()

    assert response.status_code == 200
    assert body["catalog"]["source"] == "seed"
    assert body["catalog"]["defaults"]["region"] == "us-sea"
    assert body["catalog"]["defaults"]["size"] == "g6-nanode-1"
    assert body["catalog"]["warnings"]


def test_provider_region_policy_api_filters_operator_catalog_and_exposes_full_settings_catalog(monkeypatch):
    _app, client = catalog_client(monkeypatch)
    transport = FakeCatalogTransport()
    monkeypatch.setattr(provider_catalog, "UrllibProviderCatalogTransport", lambda: transport)
    client.post(
        "/api/credentials",
        json={"provider": "linode", "alias": "linode-catalog", "secret": "linode-token-sensitive-value", "isDefault": True},
    )

    filtered = client.get("/api/provider-catalog/sketch?provider=linode").get_json()["catalog"]
    full = client.get("/api/provider-catalog/sketch?provider=linode&includeBlocked=1").get_json()["catalog"]

    assert [region["id"] for region in filtered["regions"]] == ["us-sea"]
    assert {region["id"]: region["allowed"] for region in full["regions"]} == {"us-lax": False, "us-sea": True}
    assert full["regionPolicy"] == {"allowedRegions": ["us-sea"], "includeBlocked": True}

    response = client.patch("/api/provider-catalog/sketch/region-policies/linode", json={"allowedRegions": ["us-lax", "us-sea"]})
    assert response.status_code == 200
    assert response.get_json()["policy"]["allowedRegions"] == ["us-lax", "us-sea"]

    filtered_after_update = client.get("/api/provider-catalog/sketch?provider=linode").get_json()["catalog"]
    assert [region["id"] for region in filtered_after_update["regions"]] == ["us-lax", "us-sea"]


def test_provider_region_policy_api_rejects_invalid_region_ids(monkeypatch):
    _app, client = catalog_client(monkeypatch)

    response = client.patch("/api/provider-catalog/sketch/region-policies/linode", json={"allowedRegions": ["us-sea", "../bad"]})

    assert response.status_code == 400
    assert "allowedRegions[1]" in response.get_json()["errors"][0]


def test_digitalocean_preflight_requires_live_default_credential_and_redacts(monkeypatch):
    _app, client = catalog_client(monkeypatch)
    transport = FakeCatalogTransport()
    monkeypatch.setattr(provider_catalog, "UrllibProviderCatalogTransport", lambda: transport)
    client.post(
        "/api/credentials",
        json={"provider": "digitalocean", "alias": "do-live-preflight", "secret": "do-token-sensitive-value", "isDefault": True},
    )

    response = client.post("/api/provider-catalog/sketch/digitalocean/preflight")
    body = response.get_json()

    assert response.status_code == 200
    assert body["preflight"]["ready"] is True
    assert body["preflight"]["provider"] == "digitalocean"
    assert body["preflight"]["catalogSource"] == "live"
    assert body["preflight"]["checkedRegion"] == "sfo3"
    assert body["preflight"]["checkedSize"] == "s-1vcpu-1gb"
    assert body["preflight"]["mutation"] is False
    assert body["preflight"]["opsecBoundary"]["directSketchAccessFromAppHost"] is False
    assert "do-token-sensitive-value" not in str(body)
    assert "do-live-preflight" not in str(body)
    assert "TF_VAR_do_pat" not in str(body)
    assert transport.calls[0][3] == "do-token-sensitive-value"


def test_digitalocean_preflight_fails_closed_without_default_credential(monkeypatch):
    _app, client = catalog_client(monkeypatch)
    transport = FakeCatalogTransport()
    monkeypatch.setattr(provider_catalog, "UrllibProviderCatalogTransport", lambda: transport)

    response = client.post("/api/provider-catalog/sketch/digitalocean/preflight")
    body = response.get_json()

    assert response.status_code == 400
    assert body["preflight"]["ready"] is False
    assert body["preflight"]["catalogSource"] == "unavailable"
    assert body["preflight"]["errors"]
    assert transport.calls == []


def test_digitalocean_preflight_fails_closed_when_provider_unavailable(monkeypatch):
    _app, client = catalog_client(monkeypatch)
    transport = FakeCatalogTransport()
    transport.fail = True
    monkeypatch.setattr(provider_catalog, "UrllibProviderCatalogTransport", lambda: transport)
    client.post(
        "/api/credentials",
        json={"provider": "digitalocean", "alias": "do-live-preflight", "secret": "do-token-sensitive-value", "isDefault": True},
    )

    response = client.post("/api/provider-catalog/sketch/digitalocean/preflight")
    body = response.get_json()

    assert response.status_code == 400
    assert body["preflight"]["ready"] is False
    assert body["preflight"]["catalogSource"] == "unavailable"
    assert body["preflight"]["errors"] == ["provider unavailable"]
    assert "do-token-sensitive-value" not in str(body)


def test_digitalocean_preflight_rejects_unavailable_region_or_size(monkeypatch):
    _app, client = catalog_client(monkeypatch)
    transport = FakeCatalogTransport()
    transport.region_available = False
    transport.region_sizes = []
    monkeypatch.setattr(provider_catalog, "UrllibProviderCatalogTransport", lambda: transport)
    client.post(
        "/api/credentials",
        json={"provider": "digitalocean", "alias": "do-live-preflight", "secret": "do-token-sensitive-value", "isDefault": True},
    )

    response = client.post("/api/provider-catalog/sketch/digitalocean/preflight")
    body = response.get_json()

    assert response.status_code == 400
    assert body["preflight"]["ready"] is False
    assert body["preflight"]["catalogSource"] == "live"
    assert "sfo3 is not available" in body["preflight"]["errors"][0]
    assert any("s-1vcpu-1gb is not available in sfo3" in error for error in body["preflight"]["errors"])
