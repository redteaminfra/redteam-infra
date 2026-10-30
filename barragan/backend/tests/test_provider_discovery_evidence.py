# Copyright (c) 2026, Oracle and/or its affiliates.
import subprocess
from types import SimpleNamespace

import pytest

from app.services import provider_reconciliation as inventory
from app.services.dashboard import _provider_health


@pytest.fixture(autouse=True)
def isolate_discovery(monkeypatch):
    inventory.clear_provider_discovery_cache()
    monkeypatch.setenv(inventory.LIVE_DISCOVERY_ENV, "true")
    monkeypatch.setenv(inventory.LIVE_DISCOVERY_CACHE_SECONDS_ENV, "0")
    monkeypatch.setattr(inventory, "_discover_oci_resources", lambda: [])
    monkeypatch.setattr(inventory, "_discover_linode_resources", lambda: [])
    monkeypatch.setattr(inventory, "_discover_digitalocean_resources", lambda: [])
    yield
    inventory.clear_provider_discovery_cache()


def test_disabled_discovery_never_reports_checked(monkeypatch):
    monkeypatch.delenv(inventory.LIVE_DISCOVERY_ENV)
    result = inventory.discover_provider_inventory()
    assert result["evidence"]["status"] == "disabled"
    assert result["evidence"]["observedAt"] is None
    reconciliation = inventory.reconcile_provider_inventory([], [], [])
    health = _provider_health(reconciliation, True, "now", result["evidence"])
    assert health["status"] == "not checked"
    assert health["checkedAt"] is None


def test_successful_zero_inventory_is_checked():
    result = inventory.discover_provider_inventory()
    assert result["evidence"]["status"] == "checked"
    assert result["evidence"]["observedAt"]
    assert all(row["resourceCount"] == 0 for row in result["evidence"]["providers"])


def test_timeout_is_visible_and_sanitized(monkeypatch):
    def failure():
        raise TimeoutError("secret must not be exposed")
    monkeypatch.setattr(inventory, "_discover_linode_resources", failure)
    result = inventory.discover_provider_inventory()
    assert result["evidence"]["status"] == "partial"
    linode = result["evidence"]["providers"][1]
    assert linode["status"] == "failed"
    assert linode["observedAt"] is None
    assert "secret" not in str(result)
    health = _provider_health(inventory.reconcile_provider_inventory([], [], []), True, "now", result["evidence"])
    assert health["status"] == "attention"


def test_cache_preserves_observation_time(monkeypatch):
    monkeypatch.setenv(inventory.LIVE_DISCOVERY_CACHE_SECONDS_ENV, "30")
    first = inventory.discover_provider_inventory()
    second = inventory.discover_provider_inventory()
    assert second["evidence"]["cached"] is True
    assert first["evidence"]["observedAt"] == second["evidence"]["observedAt"]
    assert first["evidence"]["providers"] == second["evidence"]["providers"]
    assert second["evidence"]["ageSeconds"] >= 0


def test_matched_and_unmanaged_rows_stay_visible_without_actions():
    resource = {"provider": "linode", "resourceType": "instance", "resourceId": "1",
                "name": "middle01-test", "lifecycleState": "running", "metadata": {"barraganOwned": True}}
    unmanaged = {**resource, "resourceId": "2", "metadata": {}}
    rows = inventory.provider_inventory_rows([], [], [resource, unmanaged], [resource], {"providers": []})
    assert [row["classification"] for row in rows] == ["recorded", "unmanaged_rti"]
    assert all(row["actions"] == [] for row in rows)


class Transport:
    def __init__(self, body):
        self.body = body

    def request(self, base, method, path, token):
        if "firewalls" in path:
            if "linode" in base:
                return {"data": [], "pages": 1, "page": 1, "results": 0}
            return {"firewalls": [], "links": {}, "meta": {"total": 0}}
        return self.body


def test_real_adapters_missing_credentials(monkeypatch):
    monkeypatch.setattr(inventory, "_provider_token", lambda _: None)
    # Fixture patches discovery entry points, so call the originals saved below.
    for adapter in (LINODE, DIGITALOCEAN):
        with pytest.raises(inventory.ProviderDiscoveryError) as error:
            adapter(Transport({}))
        assert error.value.status == "unavailable"


@pytest.mark.parametrize("adapter,body", [("linode", {}), ("digitalocean", {"droplets": None})])
def test_malformed_response_is_not_zero_inventory(monkeypatch, adapter, body):
    monkeypatch.setattr(inventory, "_provider_token", lambda _: "test-token")
    with pytest.raises(inventory.ProviderDiscoveryError) as error:
        (LINODE if adapter == "linode" else DIGITALOCEAN)(Transport(body))
    assert error.value.status == "partial"


@pytest.mark.parametrize("adapter,body", [("linode", {"data": [], "pages": 2, "results": 1}),
                                         ("digitalocean", {"droplets": [], "links": {"pages": {"next": "unused"}}, "meta": {"total": 1}})])
def test_unread_pages_are_partial(monkeypatch, adapter, body):
    monkeypatch.setattr(inventory, "_provider_token", lambda _: "test-token")
    with pytest.raises(inventory.ProviderDiscoveryError) as error:
        (LINODE if adapter == "linode" else DIGITALOCEAN)(Transport(body))
    assert error.value.status == "partial"


def test_oci_partial_failure_keeps_successful_resource_family(monkeypatch):
    monkeypatch.setattr(inventory, "resolve_oci_cli", lambda **_: SimpleNamespace(ok=True, command="oci"))
    monkeypatch.setattr(inventory, "allowed_oci_deployment_targets", lambda _: [SimpleNamespace(
        auth="instance_principal", region="test", compartment_id="test", validate=lambda: None)])
    def runner(command):
        if "instance" in command:
            return subprocess.CompletedProcess(command, 0, '{"data":[{"id":"1","display-name":"homebase-test","lifecycle-state":"RUNNING","freeform-tags":{"barragan":"true"}}]}', "")
        if "subnet" in command:
            return subprocess.CompletedProcess(command, 0, 'not json', "")
        raise TimeoutError("sensitive stderr")
    with pytest.raises(inventory.ProviderDiscoveryError) as error:
        OCI(runner=runner)
    assert error.value.status == "partial"
    assert len(error.value.resources) == 1
    assert error.value.resources[0]["resourceId"] == "1"
    assert "sensitive" not in str(error.value)


LINODE = inventory._discover_linode_resources
DIGITALOCEAN = inventory._discover_digitalocean_resources
OCI = inventory._discover_oci_resources


def test_all_unavailable_providers_have_no_success_timestamp(monkeypatch):
    def unavailable():
        raise inventory.ProviderDiscoveryError("unavailable", "Credential unavailable.")
    for name in ("_discover_oci_resources", "_discover_linode_resources", "_discover_digitalocean_resources"):
        monkeypatch.setattr(inventory, name, unavailable)
    result = inventory.discover_provider_inventory()
    assert result["evidence"]["status"] == "failed"
    assert result["evidence"]["observedAt"] is None
    assert all(row["status"] == "unavailable" for row in result["evidence"]["providers"])


@pytest.mark.parametrize("adapter,body", [
    ("linode", {"data": [{}], "pages": 1, "results": 1}),
    ("linode", {"data": [], "pages": 1, "results": "0"}),
    ("linode", {"data": [{"id": 1, "label": "homebase-test", "status": "running", "tags": {"barragan": False}}], "pages": 1, "results": 1}),
    ("digitalocean", {"droplets": [], "links": [], "meta": {"total": 0}}),
    ("digitalocean", {"droplets": [{}], "links": {}, "meta": {"total": 1}}),
    ("digitalocean", {"droplets": [], "links": {}, "meta": {"total": False}}),
])
def test_malformed_identity_and_metadata_do_not_prove_empty(monkeypatch, adapter, body):
    monkeypatch.setattr(inventory, "_provider_token", lambda _: "test-token")
    with pytest.raises(inventory.ProviderDiscoveryError) as error:
        (LINODE if adapter == "linode" else DIGITALOCEAN)(Transport(body))
    assert error.value.status == "partial"


@pytest.mark.parametrize("adapter,body", [
    ("linode", {"data": [], "pages": 1, "page": 1, "results": 0}),
    ("digitalocean", {"droplets": [], "links": {}, "meta": {"total": 0}}),
])
def test_real_valid_empty_inventory_remains_checked(monkeypatch, adapter, body):
    monkeypatch.setattr(inventory, "_provider_token", lambda _: "test-token")
    assert (LINODE if adapter == "linode" else DIGITALOCEAN)(Transport(body)) == []


def test_valid_rows_survive_malformed_sibling(monkeypatch):
    monkeypatch.setattr(inventory, "_provider_token", lambda _: "test-token")
    body = {"data": [{"id": 1, "label": "homebase-test", "status": "running", "tags": ["barragan"]}, {}],
            "pages": 1, "results": 2}
    with pytest.raises(inventory.ProviderDiscoveryError) as error:
        LINODE(Transport(body))
    assert error.value.status == "partial"
    assert [row["resourceId"] for row in error.value.resources] == ["1"]


def test_oci_malformed_identity_is_not_successful_empty(monkeypatch):
    monkeypatch.setattr(inventory, "resolve_oci_cli", lambda **_: SimpleNamespace(ok=True, command="oci"))
    monkeypatch.setattr(inventory, "allowed_oci_deployment_targets", lambda _: [SimpleNamespace(
        auth="instance_principal", region="test", compartment_id="test", validate=lambda: None)])
    with pytest.raises(inventory.ProviderDiscoveryError) as error:
        OCI(runner=lambda command: subprocess.CompletedProcess(command, 0, '{"data":[{}]}', ""))
    assert error.value.status == "failed"
