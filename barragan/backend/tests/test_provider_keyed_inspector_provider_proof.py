# Copyright (c) 2026, Oracle and/or its affiliates.
"""Returned-ID-only GET proof for staged Inspector creation, with no writes."""

from copy import deepcopy
import urllib.error

import pytest

from app.services.observer_checks import ObserverHost, _inspector_firewall_label, _inspector_firewall_tag
from app.services.provider_keyed_inspector_provider_proof import (
    InspectorProviderPending, InspectorProviderProofError, prove_keyed_inspector_provider,
    prove_retained_keyed_inspector_provider,
)
from app.integrations.linode_validation import LinodeValidationError
from app.integrations.digitalocean_validation import DigitalOceanValidationError


NAME = "inspector-" + "a" * 32
CIDR = "8.8.8.8/32"


class Transport:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def request(self, method, path, token, body=None):
        assert method == "GET" and body is None and token == "private-token"
        self.calls.append(path)
        return deepcopy(self.responses[path])


def linode_responses():
    return {
        "/linode/instances/123": {"id": 123, "label": NAME, "region": "us-east",
                                  "type": "g6-nanode-1", "status": "running",
                                  "tags": ["barragan", "inspector"], "ipv4": ["1.1.1.1"]},
        "/networking/firewalls/42": {"id": 42, "label": _inspector_firewall_label("linode", NAME),
                                      "status": "enabled"},
        "/networking/firewalls/42/rules": {
            "inbound_policy": "DROP", "outbound_policy": "ACCEPT", "outbound": [],
            "inbound": [{"action": "ACCEPT", "protocol": "TCP", "ports": "22",
                         "addresses": {"ipv4": [CIDR]}}],
        },
        "/networking/firewalls/42/devices?page=1&page_size=100": {
            "page": 1, "pages": 1, "results": 1,
            "data": [{"id": 900, "entity": {"id": 123, "type": "linode"}}],
        },
    }


def do_responses():
    tag = _inspector_firewall_tag(NAME)
    rules = lambda side: [
        {"protocol": protocol, "ports": port, side: {"addresses": addresses}}
        for protocol, port, addresses in (
            ("tcp", "1-65535", ["0.0.0.0/0", "::/0"]),
            ("udp", "1-65535", ["0.0.0.0/0", "::/0"]),
            ("icmp", "0", ["0.0.0.0/0", "::/0"]),
        )]
    return {
        "/droplets/123": {"droplet": {
            "id": 123, "name": NAME, "region": {"slug": "nyc3"},
            "size": {"slug": "s-1vcpu-1gb"}, "status": "active",
            "tags": ["barragan", "inspector", tag],
            "networks": {"v4": [{"type": "public", "ip_address": "1.1.1.1"}]},
        }},
        "/firewalls/fw-42": {"firewall": {
            "id": "fw-42", "name": _inspector_firewall_label("digitalocean", NAME),
            "tags": [tag], "status": "succeeded", "pending_changes": [], "droplet_ids": [123],
            "inbound_rules": [{"protocol": "tcp", "ports": "22",
                               "sources": {"addresses": [CIDR]}}],
            "outbound_rules": rules("destinations"),
        }},
        "/droplets/123/firewalls?page=1&per_page=200": {
            "firewalls": [{"id": "fw-42"}], "meta": {"total": 1}, "links": {"pages": {}},
        },
        f"/droplets?page=1&per_page=200&tag_name={tag}": {
            "droplets": [{"id": 123, "tags": ["barragan", "inspector", tag]}],
            "meta": {"total": 1}, "links": {"pages": {}},
        },
        "/droplets?page=1&per_page=200&type=gpus": {
            "droplets": [], "meta": {"total": 0}, "links": {"pages": {}},
        },
    }


def prove(provider, transport):
    return prove_keyed_inspector_provider(
        provider=provider, token="private-token", transport=transport,
        resource_name=NAME, region="us-east" if provider == "linode" else "nyc3",
        size="g6-nanode-1" if provider == "linode" else "s-1vcpu-1gb",
        host_id="123", firewall_id="42" if provider == "linode" else "fw-42",
        management_cidr=CIDR,
    )


@pytest.mark.parametrize("provider,fixture", [("linode", linode_responses), ("digitalocean", do_responses)])
def test_exact_returned_identity_policy_and_get_only(provider, fixture):
    transport = Transport(fixture())
    evidence = prove(provider, transport)
    assert evidence.host.resource_id == "123"
    assert evidence.host.public_ip == "1.1.1.1"
    assert evidence.host.ssh_user == "barragan"
    assert evidence.host.metadata["publicIps"] == ["1.1.1.1"]
    assert evidence.host.metadata["providerFirewall"] == {
        "provider": provider, "resourceType": "firewall", "resourceId": evidence.firewall_id,
        "name": _inspector_firewall_label(provider, NAME),
        **({"tag": evidence.tag_name} if provider == "digitalocean" else {}),
        "managementSourceCidr": CIDR,
    }
    assert evidence.tag_exclusive is False
    assert all("?name=" not in path for path in transport.calls)


@pytest.mark.parametrize("provider,fixture", [("linode", linode_responses), ("digitalocean", do_responses)])
def test_retained_legacy_name_uses_only_bound_ids_and_exact_get(provider, fixture, monkeypatch):
    legacy_name = "inspector-existing-core-host"
    monkeypatch.setitem(globals(), "NAME", legacy_name)
    transport = Transport(fixture())
    host = ObserverHost(provider, "instance" if provider == "linode" else "droplet",
                        "123", legacy_name, "us-east" if provider == "linode" else "nyc3",
                        "1.1.1.1", ssh_user="barragan",
                        metadata={"providerFirewall": {"resourceId": "42" if provider == "linode" else "fw-42"}})
    result = prove_retained_keyed_inspector_provider(
        expected_host=host, size="g6-nanode-1" if provider == "linode" else "s-1vcpu-1gb",
        token="private-token", transport=transport,
        firewall_id="42" if provider == "linode" else "fw-42", management_cidr=CIDR,
    )
    assert result.host.name == legacy_name and result.host.public_ip == host.public_ip
    assert all("?name=" not in path for path in transport.calls)
    with pytest.raises(InspectorProviderProofError):
        prove_keyed_inspector_provider(
            provider=provider, token="private-token", transport=Transport(fixture()),
            resource_name=legacy_name, region=host.region,
            size="g6-nanode-1" if provider == "linode" else "s-1vcpu-1gb",
            host_id="123", firewall_id="42" if provider == "linode" else "fw-42",
            management_cidr=CIDR,
        )


def test_retained_get_rejects_owned_ip_and_foreign_tag_drift(monkeypatch):
    monkeypatch.setitem(globals(), "NAME", "inspector-existing-core-host")
    host = ObserverHost("digitalocean", "droplet", "123", NAME, "nyc3", "1.1.1.1",
                        ssh_user="barragan")
    kwargs = dict(expected_host=host, size="s-1vcpu-1gb", token="private-token",
                  firewall_id="fw-42", management_cidr=CIDR)
    changed = do_responses()
    changed["/droplets/123"]["droplet"]["networks"]["v4"][0]["ip_address"] = "8.8.4.4"
    with pytest.raises(InspectorProviderProofError):
        prove_retained_keyed_inspector_provider(**kwargs, transport=Transport(changed))
    changed = do_responses()
    tag = _inspector_firewall_tag(NAME)
    changed[f"/droplets?page=1&per_page=200&tag_name={tag}"]["droplets"].append(
        {"id": 999, "tags": ["barragan", "inspector", tag]})
    with pytest.raises(InspectorProviderProofError):
        prove_retained_keyed_inspector_provider(**kwargs, transport=Transport(changed))


@pytest.mark.parametrize("provider,fixture", [("linode", linode_responses), ("digitalocean", do_responses)])
def test_provider_tag_order_is_irrelevant_but_duplicates_and_extras_fail(provider, fixture):
    responses = fixture()
    row = responses["/linode/instances/123"] if provider == "linode" else responses["/droplets/123"]["droplet"]
    row["tags"].reverse()
    assert prove(provider, Transport(responses)).host.resource_id == "123"
    row["tags"].append(row["tags"][0])
    with pytest.raises(InspectorProviderProofError):
        prove(provider, Transport(responses))
    row["tags"][-1] = "unexpected"
    with pytest.raises(InspectorProviderProofError):
        prove(provider, Transport(responses))


@pytest.mark.parametrize("cidr", [
    "8.8.8.0/24", "10.0.0.1/32", "224.0.0.1/32", "127.0.0.1/32",
    "169.254.1.1/32", "0.0.0.0/32", "8.8.8.8/31",
])
def test_management_source_requires_public_unicast_host_cidr(cidr):
    with pytest.raises(InspectorProviderProofError):
        prove_keyed_inspector_provider(
            provider="linode", token="private-token", transport=Transport(linode_responses()),
            resource_name=NAME, region="us-east", size="g6-nanode-1", host_id="123",
            firewall_id="42", management_cidr=cidr,
        )


@pytest.mark.parametrize("field,value", [
    ("label", "wrong"), ("region", "wrong"), ("ipv4", []),
    ("ipv4", ["1.1.1.1", "1.0.0.1"]), ("ipv4", ["10.0.0.1"]),
    ("ipv4", ["224.0.0.1"]),
    ("tags", ["barragan"]), ("id", 999),
])
def test_linode_instance_drift_fails(field, value):
    responses = linode_responses()
    responses["/linode/instances/123"][field] = value
    with pytest.raises(InspectorProviderProofError):
        prove("linode", Transport(responses))


@pytest.mark.parametrize("change", [
    lambda r: r["/networking/firewalls/42/rules"]["inbound"][0].update(ports="22,80"),
    lambda r: r["/networking/firewalls/42/devices?page=1&page_size=100"].update(results=2),
    lambda r: r["/networking/firewalls/42/devices?page=1&page_size=100"]["data"][0]["entity"].update(type="linode_interface"),
    lambda r: r["/networking/firewalls/42/devices?page=1&page_size=100"]["data"][0]["entity"].update(id=999),
])
def test_linode_policy_or_device_drift_fails(change):
    responses = linode_responses()
    change(responses)
    with pytest.raises(InspectorProviderProofError):
        prove("linode", Transport(responses))


def test_linode_invalid_ip_is_hard_even_while_device_is_pending():
    responses = linode_responses()
    responses["/linode/instances/123"]["ipv4"] = ["10.0.0.1"]
    responses["/networking/firewalls/42/devices?page=1&page_size=100"].update(results=0, data=[])
    with pytest.raises(InspectorProviderProofError) as caught:
        prove("linode", Transport(responses))
    assert not isinstance(caught.value, InspectorProviderPending)


def test_digitalocean_numeric_equivalent_float_member_is_hard():
    responses = do_responses()
    responses["/firewalls/fw-42"]["firewall"]["droplet_ids"] = [123.0]
    with pytest.raises(InspectorProviderProofError) as caught:
        prove("digitalocean", Transport(responses))
    assert not isinstance(caught.value, InspectorProviderPending)


@pytest.mark.parametrize("change", [
    lambda r: r["/droplets/123"]["droplet"].update(name="wrong"),
    lambda r: r["/droplets/123"]["droplet"]["networks"].update(v4=[]),
    lambda r: r["/droplets/123"]["droplet"]["networks"].update(
        v4=[{"type": "public", "ip_address": "1.1.1.1"},
            {"type": "public", "ip_address": "1.0.0.1"}]),
    lambda r: r["/droplets/123"]["droplet"]["networks"].update(
        v4=[{"type": "public", "ip_address": "10.0.0.1"}]),
    lambda r: r["/firewalls/fw-42"]["firewall"]["inbound_rules"][0].update(ports="80"),
    lambda r: r["/firewalls/fw-42"]["firewall"].update(pending_changes=[{"status": "waiting"}]),
    lambda r: r["/firewalls/fw-42"]["firewall"].update(droplet_ids=[123, 999]),
    lambda r: r["/droplets/123/firewalls?page=1&per_page=200"].update(meta={"total": 2}),
    lambda r: r["/droplets/123/firewalls?page=1&per_page=200"].pop("links"),
    lambda r: r["/droplets?page=1&per_page=200&type=gpus"].update(
        droplets=[{"id": 999, "tags": [_inspector_firewall_tag(NAME)]}], meta={"total": 1}),
    lambda r: r[f"/droplets?page=1&per_page=200&tag_name={_inspector_firewall_tag(NAME)}"].update(
        meta={"total": 2}),
])
def test_digitalocean_identity_membership_policy_or_pagination_drift_fails(change):
    responses = do_responses()
    change(responses)
    with pytest.raises(InspectorProviderProofError):
        prove("digitalocean", Transport(responses))


@pytest.mark.parametrize("provider,fixture", [("linode", linode_responses),
                                               ("digitalocean", do_responses)])
@pytest.mark.parametrize("code,pending", [(404, True), (429, True), (503, True),
                                           (401, False), (403, False), (422, False)])
def test_exact_id_http_read_classification(provider, fixture, code, pending):
    path = "/linode/instances/123" if provider == "linode" else "/droplets/123"
    error_type = LinodeValidationError if provider == "linode" else DigitalOceanValidationError

    class Failing(Transport):
        def request(self, method, requested_path, token, body=None):
            if requested_path == path:
                error = urllib.error.HTTPError(requested_path, code, "private provider detail", None, None)
                raise error_type("private provider detail") from error
            return super().request(method, requested_path, token, body)

    with pytest.raises(InspectorProviderProofError) as caught:
        prove(provider, Failing(fixture()))
    assert isinstance(caught.value, InspectorProviderPending) is pending
    assert "private" not in str(caught.value)


@pytest.mark.parametrize("provider,fixture", [("linode", linode_responses),
                                               ("digitalocean", do_responses)])
def test_network_and_exact_attachment_404_are_pending(provider, fixture):
    exact = "/linode/instances/123" if provider == "linode" else "/droplets/123"
    inventory = ("/networking/firewalls/42/devices?page=1&page_size=100"
                 if provider == "linode" else "/droplets/123/firewalls?page=1&per_page=200")

    class Failing(Transport):
        path = exact
        error = urllib.error.URLError("private transport detail")

        def request(self, method, path, token, body=None):
            if path == self.path:
                raise self.error
            return super().request(method, path, token, body)

    failing = Failing(fixture())
    with pytest.raises(InspectorProviderPending):
        prove(provider, failing)
    failing.path = inventory
    failing.error = urllib.error.HTTPError(inventory, 404, "private", None, None)
    with pytest.raises(InspectorProviderProofError) as caught:
        prove(provider, failing)
    # Both attachment paths are scoped by an exact returned resource ID.
    assert isinstance(caught.value, InspectorProviderPending)


def test_digitalocean_selector_inventory_404_is_hard():
    tag = _inspector_firewall_tag(NAME)
    inventory = f"/droplets?page=1&per_page=200&tag_name={tag}"

    class Failing(Transport):
        def request(self, method, path, token, body=None):
            if path == inventory:
                raise urllib.error.HTTPError(path, 404, "private", None, None)
            return super().request(method, path, token, body)

    with pytest.raises(InspectorProviderProofError) as caught:
        prove("digitalocean", Failing(do_responses()))
    assert type(caught.value) is InspectorProviderProofError


@pytest.mark.parametrize("code,pending", [(503, True), (429, True), (401, False)])
def test_digitalocean_selector_inventory_transient_vs_auth(code, pending):
    tag = _inspector_firewall_tag(NAME)
    inventory = f"/droplets?page=1&per_page=200&tag_name={tag}"

    class Failing(Transport):
        def request(self, method, path, token, body=None):
            if path == inventory:
                error = urllib.error.HTTPError(path, code, "private", None, None)
                raise DigitalOceanValidationError("private") from error
            return super().request(method, path, token, body)

    with pytest.raises(InspectorProviderProofError) as caught:
        prove("digitalocean", Failing(do_responses()))
    assert isinstance(caught.value, InspectorProviderPending) is pending


def test_digitalocean_foreign_member_is_hard_even_while_firewall_waits():
    responses = do_responses()
    responses["/firewalls/fw-42"]["firewall"]["status"] = "waiting"
    responses["/firewalls/fw-42"]["firewall"]["droplet_ids"] = [123, 999]
    with pytest.raises(InspectorProviderProofError) as caught:
        prove("digitalocean", Transport(responses))
    assert type(caught.value) is InspectorProviderProofError


@pytest.mark.parametrize("provider,fixture", [("linode", linode_responses),
                                               ("digitalocean", do_responses)])
def test_wrong_host_identity_is_hard_before_missing_firewall_pending(provider, fixture):
    responses = fixture()
    if provider == "linode":
        responses["/linode/instances/123"]["label"] = "wrong"
        missing = "/networking/firewalls/42"
    else:
        responses["/droplets/123"]["droplet"]["name"] = "wrong"
        missing = "/firewalls/fw-42"

    class MissingFirewall(Transport):
        def request(self, method, path, token, body=None):
            if path == missing:
                raise urllib.error.HTTPError(path, 404, "private", None, None)
            return super().request(method, path, token, body)

    transport = MissingFirewall(responses)
    with pytest.raises(InspectorProviderProofError) as caught:
        prove(provider, transport)
    assert type(caught.value) is InspectorProviderProofError
    assert missing not in transport.calls


@pytest.mark.parametrize("status", ["offline", "provisioning", "booting", "busy"])
def test_linode_transitional_status_pending_after_policy_check(status):
    responses = linode_responses()
    responses["/linode/instances/123"]["status"] = status
    with pytest.raises(InspectorProviderPending):
        prove("linode", Transport(responses))
    responses["/networking/firewalls/42/rules"]["inbound"][0]["ports"] = "22,80"
    with pytest.raises(InspectorProviderProofError) as caught:
        prove("linode", Transport(responses))
    assert type(caught.value) is InspectorProviderProofError


def test_linode_missing_ip_or_device_pending_but_wrong_device_hard():
    responses = linode_responses()
    responses["/linode/instances/123"]["ipv4"] = []
    with pytest.raises(InspectorProviderPending):
        prove("linode", Transport(responses))
    responses["/linode/instances/123"]["ipv4"] = ["1.1.1.1"]
    device = responses["/networking/firewalls/42/devices?page=1&page_size=100"]
    device.update(data=[], results=0)
    with pytest.raises(InspectorProviderPending):
        prove("linode", Transport(responses))
    device.update(data=[{"entity": {"id": 999, "type": "linode"}}], results=1)
    with pytest.raises(InspectorProviderProofError) as caught:
        prove("linode", Transport(responses))
    assert type(caught.value) is InspectorProviderProofError


@pytest.mark.parametrize("change", [
    lambda r: r["/droplets/123"]["droplet"].update(status="new"),
    lambda r: r["/droplets/123"]["droplet"]["networks"].update(v4=[]),
    lambda r: r["/firewalls/fw-42"]["firewall"].update(status="waiting"),
    lambda r: r["/firewalls/fw-42"]["firewall"].update(pending_changes=[{"status": "waiting"}]),
    lambda r: r["/firewalls/fw-42"]["firewall"].update(droplet_ids=[]),
    lambda r: r["/droplets/123/firewalls?page=1&per_page=200"].update(
        firewalls=[], meta={"total": 0}),
    lambda r: r[f"/droplets?page=1&per_page=200&tag_name={_inspector_firewall_tag(NAME)}"].update(
        droplets=[], meta={"total": 0}),
])
def test_digitalocean_convergence_pending_only_with_valid_policy(change):
    responses = do_responses()
    change(responses)
    with pytest.raises(InspectorProviderPending):
        prove("digitalocean", Transport(responses))
    responses["/firewalls/fw-42"]["firewall"]["inbound_rules"][0]["ports"] = "80"
    with pytest.raises(InspectorProviderProofError) as caught:
        prove("digitalocean", Transport(responses))
    assert type(caught.value) is InspectorProviderProofError
