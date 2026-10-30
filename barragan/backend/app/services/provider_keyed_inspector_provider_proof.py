# Copyright (c) 2026, Oracle and/or its affiliates.
"""GET-only proof of one completed, staged Inspector provider creation."""

from __future__ import annotations

import ipaddress
import errno
import re
import urllib.error
from dataclasses import dataclass
from typing import Any

from app.services.observer_checks import (
    INSPECTOR_ADMIN_USER, ObserverHost, _digitalocean_public_ip, _inspector_firewall_label,
    _inspector_firewall_tag, _linode_public_ip,
)
from app.integrations.linode_validation import LinodeValidationError
from app.integrations.digitalocean_validation import DigitalOceanValidationError
from app.services.provider_catalog import ProviderCatalogError
from app.services.provider_keyed_digitalocean_attachment import (
    _normalize_rules, _selector_droplet_ids,
)


class InspectorProviderProofError(ValueError):
    """Returned provider identity or policy is unproved; no adoption is allowed."""


class InspectorProviderPending(InspectorProviderProofError):
    """An exact returned resource is still converging; only bounded GET may retry."""


@dataclass(frozen=True)
class InspectorProviderProof:
    host: ObserverHost
    firewall_id: str
    management_cidr: str
    tag_name: str = ""
    tag_exclusive: bool = False


def _id(value: object) -> str:
    if type(value) not in (str, int) or re.fullmatch(r"[1-9][0-9]*", str(value)) is None:
        raise ValueError("provider ID differs")
    return str(value)


def _get(transport, path: str, token: str) -> dict[str, Any]:
    try:
        body = transport.request("GET", path, token)
    except Exception as exc:
        cause = exc.__cause__ if isinstance(exc, (
            LinodeValidationError, DigitalOceanValidationError, ProviderCatalogError,
        )) and exc.__cause__ is not None else exc
        exact_id = re.fullmatch(
            r"/(?:linode/instances/[1-9][0-9]*|networking/firewalls/[1-9][0-9]*(?:/rules|/devices)?|droplets/[1-9][0-9]*(?:/firewalls)?|firewalls/[A-Za-z0-9-]+)(?:\?.*)?",
            path,
        ) is not None
        if isinstance(cause, urllib.error.HTTPError):
            if (cause.code == 404 and exact_id) or cause.code == 429 or cause.code >= 500:
                raise InspectorProviderPending("Inspector provider read is still settling") from None
        elif (isinstance(cause, (urllib.error.URLError, TimeoutError, ConnectionError))
              or isinstance(cause, OSError) and cause.errno in {
                  errno.ECONNRESET, errno.ECONNREFUSED, errno.ENETUNREACH,
                  errno.EHOSTUNREACH, errno.ETIMEDOUT, errno.EPIPE,
              }):
            raise InspectorProviderPending("Inspector provider read is still settling") from None
        raise
    if type(body) is not dict:
        raise ValueError("provider read incomplete")
    return body


def _ipv4(value: str) -> str:
    if type(value) is not str:
        raise ValueError("public IPv4 unproved")
    address = ipaddress.ip_address(value)
    if (address.version != 4 or not address.is_global or address.is_private
            or address.is_reserved or address.is_multicast or address.is_loopback
            or address.is_link_local or address.is_unspecified):
        raise ValueError("public IPv4 unproved")
    return value


def _exact_tags(value: object, expected: set[str]) -> bool:
    return (type(value) is list and all(type(tag) is str for tag in value)
            and len(value) == len(expected) and set(value) == expected)


def _linode_devices(transport, token: str, firewall_id: str, instance_id: str) -> None:
    devices: list[dict] = []
    pages = None
    results = None
    for page in range(1, 101):
        body = _get(transport, f"/networking/firewalls/{firewall_id}/devices?page={page}&page_size=100", token)
        data = body.get("data")
        if (type(data) is not list or type(body.get("page")) is not int or body["page"] != page
                or type(body.get("pages")) is not int or body["pages"] < 1
                or type(body.get("results")) is not int or body["results"] < 0
                or len(data) > 100):
            raise ValueError("firewall devices pagination incomplete")
        if pages is None:
            pages, results = body["pages"], body["results"]
        elif pages != body["pages"] or results != body["results"]:
            raise ValueError("firewall devices changed during pagination")
        devices.extend(data)
        if page == pages:
            break
    else:
        raise ValueError("firewall devices pagination exceeded bound")
    if len(devices) == results == 0:
        raise InspectorProviderPending("Inspector firewall device is still settling")
    if (len(devices) != results or len(devices) != 1 or type(devices[0]) is not dict
            or type(devices[0].get("entity")) is not dict
            or devices[0]["entity"].get("type") != "linode"
            or _id(devices[0]["entity"].get("id")) != instance_id):
        # A Linode-interface attachment is not interchangeable with the
        # legacy instance device used by this provider create path.
        raise ValueError("firewall device identity differs")


def _linode(transport, token: str, *, name: str, region: str, size: str,
            host_id: str, firewall_id: str, management_cidr: str) -> InspectorProviderProof:
    instance = _get(transport, f"/linode/instances/{host_id}", token)
    if (_id(instance.get("id")) != host_id or instance.get("label") != name
            or instance.get("region") != region or instance.get("type") != size
            or instance.get("status") not in {"running", "offline", "provisioning", "booting", "busy"}
            or type(instance.get("ipv4")) is not list or len(instance["ipv4"]) > 1
            or not _exact_tags(instance.get("tags"), {"barragan", "inspector"})):
        raise ValueError("Linode Inspector identity differs")
    if instance["ipv4"]:
        _ipv4(instance["ipv4"][0])
    firewall = _get(transport, f"/networking/firewalls/{firewall_id}", token)
    rules = _get(transport, f"/networking/firewalls/{firewall_id}/rules", token)
    if (_id(firewall.get("id")) != firewall_id
            or firewall.get("label") != _inspector_firewall_label("linode", name)
            or firewall.get("status") != "enabled"):
        raise ValueError("Linode Inspector identity differs")
    expected = {"action": "ACCEPT", "protocol": "TCP", "ports": "22",
                "addresses": {"ipv4": [management_cidr]}}
    inbound = rules.get("inbound")
    if (rules.get("inbound_policy") != "DROP" or rules.get("outbound_policy") != "ACCEPT"
            or type(inbound) is not list or len(inbound) != 1
            or type(inbound[0]) is not dict
            or {key: inbound[0].get(key) for key in expected} != expected
            or set(inbound[0]) - set(expected) - {"label", "description"}
            or rules.get("outbound") != []):
        raise ValueError("Linode Inspector firewall policy differs")
    _linode_devices(transport, token, firewall_id, host_id)
    if instance["status"] in {"offline", "provisioning", "booting", "busy"} or not instance["ipv4"]:
        raise InspectorProviderPending("Inspector instance is still settling")
    ip = _ipv4(_linode_public_ip(instance))
    host = ObserverHost("linode", "instance", host_id, name, region, ip,
                        ssh_user=INSPECTOR_ADMIN_USER, status=instance["status"],
                        metadata={"publicIps": [ip], "providerFirewall": {
                            "provider": "linode", "resourceType": "firewall",
                            "resourceId": firewall_id,
                            "name": _inspector_firewall_label("linode", name),
                            "managementSourceCidr": management_cidr}})
    return InspectorProviderProof(host, firewall_id, management_cidr)


class _SelectorAdapter:
    def __init__(self, transport):
        self.transport = transport

    def request(self, _origin: str, method: str, path: str, token: str) -> dict:
        if method != "GET":
            raise ValueError("Inspector proof is GET-only")
        return _get(self.transport, path, token)


def _digitalocean(transport, token: str, *, name: str, region: str, size: str,
                  host_id: str, firewall_id: str, management_cidr: str) -> InspectorProviderProof:
    tag = _inspector_firewall_tag(name)
    droplet = _get(transport, f"/droplets/{host_id}", token).get("droplet")
    if (type(droplet) is not dict or _id(droplet.get("id")) != host_id
            or droplet.get("name") != name or type(droplet.get("region")) is not dict
            or droplet["region"].get("slug") != region
            or type(droplet.get("size")) is not dict or droplet["size"].get("slug") != size
            or droplet.get("status") not in {"active", "new"}
            or not _exact_tags(droplet.get("tags"), {"barragan", "inspector", tag})):
        raise ValueError("DigitalOcean Inspector identity or attachment differs")
    networks = droplet.get("networks")
    v4 = networks.get("v4") if type(networks) is dict else None
    if (type(v4) is not list or sum(type(item) is dict and item.get("type") == "public"
                                    for item in v4) > 1):
        raise ValueError("DigitalOcean public IPv4 is ambiguous")
    if any(type(item) is dict and item.get("type") == "public" for item in v4):
        _ipv4(_digitalocean_public_ip(droplet))
    firewall = _get(transport, f"/firewalls/{firewall_id}", token).get("firewall")
    if (type(firewall) is not dict or firewall.get("id") != firewall_id
            or firewall.get("name") != _inspector_firewall_label("digitalocean", name)
            or firewall.get("tags") != [tag]
            or firewall.get("status") not in {"succeeded", "waiting"}
            or type(firewall.get("pending_changes")) is not list
            or type(firewall.get("droplet_ids")) is not list
            or firewall["droplet_ids"] not in ([], [int(host_id)])
            or any(type(item) is not int for item in firewall["droplet_ids"])):
        raise ValueError("DigitalOcean Inspector identity or attachment differs")
    ingress = {("tcp", "22", (management_cidr,))}
    egress = {("tcp", "1-65535", ("0.0.0.0/0", "::/0")),
              ("udp", "1-65535", ("0.0.0.0/0", "::/0")),
              ("icmp", "0", ("0.0.0.0/0", "::/0"))}
    if (_normalize_rules(firewall.get("inbound_rules"), "sources") != ingress
            or _normalize_rules(firewall.get("outbound_rules"), "destinations") != egress):
        raise ValueError("DigitalOcean Inspector firewall policy differs")
    settling = (droplet["status"] == "new" or firewall["status"] == "waiting"
                or bool(firewall["pending_changes"]) or firewall["droplet_ids"] == [])
    memberships = _get(transport, f"/droplets/{host_id}/firewalls?page=1&per_page=200", token)
    meta = memberships.get("meta")
    links = memberships.get("links")
    if (type(meta) is not dict or type(meta.get("total")) is not int or meta["total"] not in (0, 1)
            or type(links) is not dict or type(links.get("pages")) is not dict
            or links["pages"].get("next") is not None
            or type(memberships.get("firewalls")) is not list
            or len(memberships["firewalls"]) != meta["total"]
            or (meta["total"] == 1 and (type(memberships["firewalls"][0]) is not dict
                or memberships["firewalls"][0].get("id") != firewall_id))):
        raise ValueError("DigitalOcean direct firewall membership differs")
    if meta["total"] == 0:
        settling = True
    selector_ids = _selector_droplet_ids(_SelectorAdapter(transport), token, tag)
    if selector_ids - {host_id}:
        raise ValueError("DigitalOcean selector includes another Droplet")
    if not selector_ids:
        settling = True
    if not any(type(item) is dict and item.get("type") == "public" for item in v4):
        settling = True
    if settling:
        raise InspectorProviderPending("Inspector provider attachment is still settling")
    ip = _ipv4(_digitalocean_public_ip(droplet))
    host = ObserverHost("digitalocean", "droplet", host_id, name, region, ip,
                        ssh_user=INSPECTOR_ADMIN_USER, status="active",
                        metadata={"publicIps": [ip], "providerFirewall": {
                            "provider": "digitalocean", "resourceType": "firewall",
                            "resourceId": firewall_id,
                            "name": _inspector_firewall_label("digitalocean", name),
                            "tag": tag, "managementSourceCidr": management_cidr}})
    return InspectorProviderProof(host, firewall_id, management_cidr, tag)


def prove_keyed_inspector_provider(
    *, provider: str, token: str, transport, resource_name: str, region: str,
    size: str, host_id: str, firewall_id: str, management_cidr: str,
) -> InspectorProviderProof:
    """Verify returned IDs only; never search by name or mutate a provider."""
    try:
        if (provider not in {"linode", "digitalocean"}
                or type(resource_name) is not str
                or re.fullmatch(r"inspector-[0-9a-f]{32}", resource_name) is None
                or type(region) is not str or not region or type(size) is not str or not size
                or type(token) is not str or not token
                or type(management_cidr) is not str
                or ipaddress.ip_network(management_cidr, strict=True).version != 4
                or ipaddress.ip_network(management_cidr, strict=True).prefixlen != 32
                or management_cidr != f"{_ipv4(str(ipaddress.ip_network(management_cidr).network_address))}/32"):
            raise ValueError("Inspector proof input invalid")
        normalized_host = _id(host_id)
        if provider == "linode":
            normalized_firewall = _id(firewall_id)
            return _linode(transport, token, name=resource_name, region=region, size=size,
                           host_id=normalized_host, firewall_id=normalized_firewall,
                           management_cidr=management_cidr)
        if (type(firewall_id) is not str or not re.fullmatch(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+", firewall_id)):
            raise ValueError("firewall ID invalid")
        return _digitalocean(transport, token, name=resource_name, region=region, size=size,
                             host_id=normalized_host, firewall_id=firewall_id,
                             management_cidr=management_cidr)
    except InspectorProviderPending:
        raise
    except Exception:
        raise InspectorProviderProofError(
            "Inspector provider identity or policy is unverified; explicit reconciliation is required"
        ) from None


def prove_retained_keyed_inspector_provider(
    *, expected_host: ObserverHost, size: str, token: str, transport,
    firewall_id: str, management_cidr: str,
) -> InspectorProviderProof:
    """GET the exact already-owned legacy Inspector IDs, never search by name.

    Core deployment may have created a retained Inspector before keyed teardown
    with its established (non-opaque) name. This entrypoint accepts that name
    only as part of the independently bound settings/ownership host identity;
    the new-create entrypoint retains its opaque-name requirement.
    """
    try:
        host = expected_host
        if (type(host) is not ObserverHost or host.provider not in {"linode", "digitalocean"}
                or type(host.name) is not str or not host.name or host.name != host.name.strip()
                or type(host.region) is not str or not host.region
                or type(host.public_ip) is not str or not host.public_ip
                or type(size) is not str or not size
                or type(token) is not str or not token
                or type(management_cidr) is not str
                or ipaddress.ip_network(management_cidr, strict=True).version != 4
                or ipaddress.ip_network(management_cidr, strict=True).prefixlen != 32
                or management_cidr != f"{_ipv4(str(ipaddress.ip_network(management_cidr).network_address))}/32"):
            raise ValueError("retained Inspector identity differs")
        host_id = _id(host.resource_id)
        if host.provider == "linode":
            selected_firewall = _id(firewall_id)
            result = _linode(transport, token, name=host.name, region=host.region,
                             size=size, host_id=host_id, firewall_id=selected_firewall,
                             management_cidr=management_cidr)
        else:
            if type(firewall_id) is not str or not re.fullmatch(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+", firewall_id):
                raise ValueError("retained firewall ID differs")
            result = _digitalocean(transport, token, name=host.name, region=host.region,
                                   size=size, host_id=host_id, firewall_id=firewall_id,
                                   management_cidr=management_cidr)
        if (result.host.provider != host.provider or result.host.resource_type != host.resource_type
                or result.host.resource_id != host.resource_id or result.host.name != host.name
                or result.host.region != host.region or result.host.public_ip != host.public_ip
                or result.host.ssh_user != host.ssh_user or result.firewall_id != firewall_id
                or result.management_cidr != management_cidr):
            raise ValueError("retained Inspector GET identity differs")
        return result
    except InspectorProviderPending:
        raise
    except Exception:
        raise InspectorProviderProofError(
            "retained Inspector provider identity or policy is unverified"
        ) from None
