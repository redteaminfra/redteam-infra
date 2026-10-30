# Copyright (c) 2026, Oracle and/or its affiliates.
import json
import subprocess
from types import SimpleNamespace

import pytest

from app.services import provider_reconciliation as inventory


class Transport:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def request(self, base, method, path, token):
        self.calls.append((base, method, path))
        response = self.responses[path]
        if isinstance(response, Exception):
            raise response
        return response


def linode(rows=(), **pagination):
    return {"data": list(rows), "page": 1, "pages": 1, "results": len(rows), **pagination}


def ocean(key, rows=(), **pagination):
    return {key: list(rows), "links": {}, "meta": {"total": len(rows)}, **pagination}


@pytest.fixture(autouse=True)
def credentials(monkeypatch):
    monkeypatch.setattr(inventory, "_provider_token", lambda _: "fixture-token")


@pytest.mark.parametrize("status", ["enabled", "disabled"])
def test_opaque_linode_firewall_is_present_observation_only(status):
    transport = Transport({
        "/linode/instances?page_size=500": linode(),
        "/networking/firewalls?page_size=500": linode([{
            "id": 42, "label": "opaque-token", "status": status,
            "rules": {"secret": "must-not-copy"}, "tags": [],
        }]),
    })
    resources = inventory._discover_linode_resources(transport)
    assert len(resources) == 1
    assert resources[0]["lifecycleState"] == status
    assert resources[0]["region"] == ""
    assert "must-not-copy" not in str(resources)
    rows = inventory.provider_inventory_rows([], [], resources, [], {"providers": []})
    assert rows[0]["classification"] == "observation_only"
    assert rows[0]["actions"] == []
    assert all(method == "GET" for _, method, _ in transport.calls)


def test_digitalocean_firewall_accepts_uuid_not_numeric_droplet_id():
    transport = Transport({
        "/droplets?per_page=200": ocean("droplets"),
        "/firewalls?per_page=200": ocean("firewalls", [{
            "id": "d39b3b98-9a51-4c53-bde0-3a60ebd6f98a", "name": "opaque", "status": "succeeded",
            "inbound_rules": [{"secret": "must-not-copy"}],
        }]),
    })
    resources = inventory._discover_digitalocean_resources(transport)
    assert resources[0]["resourceType"] == "firewall"
    assert resources[0]["resourceId"] == "d39b3b98-9a51-4c53-bde0-3a60ebd6f98a"
    assert "must-not-copy" not in str(resources)
    transport.responses["/firewalls?per_page=200"]["firewalls"][0]["id"] = 42
    with pytest.raises(inventory.ProviderDiscoveryError) as error:
        inventory._discover_digitalocean_resources(transport)
    assert error.value.status == "partial"
    assert "firewall" in error.value.detail
    assert error.value.resources == []


@pytest.mark.parametrize("compute_failed", [True, False])
def test_successful_sibling_survives_denied_family_in_both_directions(compute_failed):
    compute = "/linode/instances?page_size=500"
    firewall = "/networking/firewalls?page_size=500"
    transport = Transport({
        compute: linode([{"id": 1, "label": "middle01-test", "status": "running"}]),
        firewall: linode([{"id": 2, "label": "opaque", "status": "disabled"}]),
    })
    transport.responses[compute if compute_failed else firewall] = PermissionError("secret denial")
    with pytest.raises(inventory.ProviderDiscoveryError) as error:
        inventory._discover_linode_resources(transport)
    assert error.value.status == "partial"
    assert [r["resourceType"] for r in error.value.resources] == ["firewall" if compute_failed else "instance"]
    assert ("instance" if compute_failed else "firewall") in error.value.detail
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("bad", [
    {"data": None}, linode([{}]), linode(pages=2), linode(results="0"),
])
def test_support_malformed_or_unread_pages_never_prove_complete_empty(bad):
    transport = Transport({"/linode/instances?page_size=500": linode(),
                           "/networking/firewalls?page_size=500": bad})
    with pytest.raises(inventory.ProviderDiscoveryError) as error:
        inventory._discover_linode_resources(transport)
    assert error.value.status == "partial"
    assert "firewall" in error.value.detail


@pytest.mark.parametrize("provider,resource_type", [
    ("oci", "boot_volume"), ("oci", "oci_core_boot_volume"),
    ("linode", "firewall"), ("linode", "linode_firewall"),
    ("digitalocean", "firewall"), ("digitalocean", "digitalocean_firewall"),
])
def test_forged_owned_support_resources_never_become_recovery_candidates(provider, resource_type):
    resource = {"provider": provider, "resourceType": resource_type, "resourceId": "123",
                "name": "homebase-test", "engagementId": "eng-test", "lifecycleState": "available",
                "metadata": {"barraganOwned": True, "observationOnly": False}}
    result = inventory.reconcile_provider_inventory([], [], [resource])
    assert result.provider_resource_count == 1
    assert result.orphan_candidates == []
    assert inventory.orphan_candidates_for_engagement("eng-test", [], [], [resource]) == []
    assert inventory.provider_inventory_rows([], [], [resource], [], {"providers": []})[0]["classification"] == "observation_only"


def test_oci_blank_stdout_is_empty_but_invalid_json_is_incomplete_and_boot_terminal_filtered(monkeypatch):
    monkeypatch.setattr(inventory, "resolve_oci_cli", lambda **_: SimpleNamespace(ok=True, command="oci"))
    monkeypatch.setattr(inventory, "allowed_oci_deployment_targets", lambda _: [SimpleNamespace(
        auth="instance_principal", region="test", compartment_id="test", validate=lambda: None)])
    calls = []
    def runner(command):
        calls.append(command)
        body = ""
        if "boot-volume" in command:
            body = json.dumps({"data": [
                {"id": "ocid1.bootvolume.active", "display-name": "opaque", "lifecycle-state": "AVAILABLE"},
                {"id": "ocid1.bootvolume.gone", "display-name": "opaque-gone", "lifecycle-state": "TERMINATED"},
            ]})
        return subprocess.CompletedProcess(command, 0, body, "")
    resources = inventory._discover_oci_resources(runner=runner)
    assert len(resources) == 2
    assert len(calls) == 7
    assert all("--all" in call and "--availability-domain" not in call for call in calls)
    visible = inventory.provider_inventory_rows([], [], resources, [], {"providers": []})
    assert [row["resourceId"] for row in visible] == ["ocid1.bootvolume.active"]
    assert visible[0]["classification"] == "observation_only"
    def malformed(command):
        return subprocess.CompletedProcess(command, 0, "bad json" if "boot-volume" in command else "", "")
    with pytest.raises(inventory.ProviderDiscoveryError) as error:
        inventory._discover_oci_resources(runner=malformed)
    assert error.value.status == "partial"
    assert "boot_volume" in error.value.detail


@pytest.mark.parametrize("bad", [
    {"firewalls": None}, ocean("firewalls", [{}]),
    ocean("firewalls", links={"pages": {"next": "https://api.digitalocean.com/v2/firewalls?page=2"}}),
    ocean("firewalls", meta={"total": "0"}),
    ocean("firewalls", links={"pages": {"next": False}}),
])
def test_digitalocean_support_malformed_or_unread_pages_are_incomplete(bad):
    transport = Transport({"/droplets?per_page=200": ocean("droplets"),
                           "/firewalls?per_page=200": bad})
    with pytest.raises(inventory.ProviderDiscoveryError) as error:
        inventory._discover_digitalocean_resources(transport)
    assert error.value.status == "partial"
    assert "firewall" in error.value.detail
    assert len(transport.calls) == 2


@pytest.mark.parametrize("compute_failed", [True, False])
def test_digitalocean_denied_family_keeps_successful_sibling(compute_failed):
    compute, firewall = "/droplets?per_page=200", "/firewalls?per_page=200"
    transport = Transport({
        compute: ocean("droplets", [{"id": 1, "name": "middle01-test", "status": "active"}]),
        firewall: ocean("firewalls", [{"id": "d39b3b98-9a51-4c53-bde0-3a60ebd6f98a", "name": "opaque", "status": "succeeded"}]),
    })
    transport.responses[compute if compute_failed else firewall] = PermissionError("private denial")
    with pytest.raises(inventory.ProviderDiscoveryError) as error:
        inventory._discover_digitalocean_resources(transport)
    assert error.value.status == "partial"
    assert [r["resourceType"] for r in error.value.resources] == ["firewall" if compute_failed else "droplet"]
    assert ("droplet" if compute_failed else "firewall") in error.value.detail
    assert "private" not in str(error.value)


@pytest.mark.parametrize("provider,resource_type", [
    ("oci", "boot_volume"), ("linode", "firewall"), ("digitalocean", "firewall"),
])
def test_forged_support_teardown_request_rejected_before_mutation(provider, resource_type):
    from app.services.provider_orphan_recovery import (
        ProviderOrphanRecoveryError, recover_provider_orphan_candidate,
    )

    class ReadOnlyRepository:
        def list(self):
            return []

        def list_active(self):
            return []

        def __getattr__(self, name):
            pytest.fail(f"unexpected repository operation: {name}")

    class ForbiddenTransport:
        def request(self, *args, **kwargs):
            pytest.fail("support observation must not authorize a provider request")

    def forbidden_background(*args):
        pytest.fail("support observation must not enqueue recovery")

    resource = {"provider": provider, "resourceType": resource_type, "resourceId": "123",
                "name": "homebase-test", "engagementId": "eng-test", "lifecycleState": "available",
                "metadata": {"barraganOwned": True, "observationOnly": False}}
    repository = ReadOnlyRepository()
    with pytest.raises(ProviderOrphanRecoveryError) as error:
        recover_provider_orphan_candidate(
            {"candidateId": f"{provider}:{resource_type}:123", "action": "tear_down", "mutation": True},
            engagement_repository=repository, job_repository=repository,
            provider_resource_repository=repository, provider_resources=[resource],
            transport=ForbiddenTransport(), background_runner=forbidden_background,
        )
    assert error.value.status_code == 404
    assert error.value.job is None
