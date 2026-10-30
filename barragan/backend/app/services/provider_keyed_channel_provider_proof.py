# Copyright (c) 2026, Oracle and/or its affiliates.
"""Fresh GET veto for the exact retained keyed firewall and attachments."""
from __future__ import annotations

from time import sleep

from app.integrations.linode_validation import UrllibLinodeTransport
from app.services.credentials import decrypt_secret_value
from app.services.provider_catalog import UrllibProviderCatalogTransport
from app.services.provider_keyed_digitalocean_attachment import (
    _request, _normalize_rules, _selector_droplet_ids,
)
from app.services.provider_keyed_inspector_provider_proof import _get
from app.services.provider_keyed_inspector_linode_cleanup import _complete_rows
from app.services.provider_keyed_mixed_partial_apply_inventory import (
    _credential, _FencedDigitalOceanTransport, _FencedLinodeTransport,
)
from app.storage.credential_repository import SqlAlchemyCredentialRepository


def _do_rules(rows, side):
    result = []
    for rule in rows:
        prefix = "source" if side == "sources" else "destination"
        if rule.get("action", "allow") != "allow" or any(
                value not in ([], None) for key, value in rule.items()
                if key.startswith(prefix + "_") and key != prefix + "_addresses"):
            raise ValueError("retained firewall peer selector differs")
        ports = rule["port_range"]
        if side == "destinations" and rule["protocol"] == "icmp" and ports == "":
            ports = "0"
        result.append({"protocol": rule["protocol"], "ports": ports,
                       side: {"addresses": rule[prefix + "_addresses"]}})
    return _normalize_rules(result, side)


def _linode_rules(rows, *, api=False):
    if type(rows) is not list:
        raise ValueError("Linode firewall rules incomplete")
    result = []
    seen = set()
    for rule in rows:
        if type(rule) is not dict:
            raise ValueError("Linode firewall rule differs")
        if set(rule) - {"action", "protocol", "ports", "label", "description",
                        *( ["addresses"] if api else ["ipv4", "ipv6"] )}:
            raise ValueError("Linode firewall rule fields differ")
        addresses = rule.get("addresses") if api else {
            key: rule.get(key) for key in ("ipv4", "ipv6")}
        if type(addresses) is not dict or set(addresses) - {"ipv4", "ipv6"}:
            raise ValueError("Linode firewall source differs")
        for values in addresses.values():
            if values is not None and (type(values) is not list
                    or any(type(value) is not str for value in values)
                    or len(values) != len(set(values))):
                raise ValueError("Linode firewall addresses differ")
        protocol, ports = rule.get("protocol"), rule.get("ports")
        if (type(rule.get("action")) is not str or rule["action"] not in {"ACCEPT", "DROP"}
                or type(protocol) is not str or protocol not in {"TCP", "UDP", "ICMP"}
                or (ports is not None and type(ports) is not str)
                or any(rule.get(key) is not None and type(rule[key]) is not str
                       for key in ("label", "description"))):
            raise ValueError("Linode firewall rule content differs")
        # Official List firewall rules schema: omitted ports match all TCP/UDP
        # ports; empty strings are only supported by port-bearing protocols.
        # https://techdocs.akamai.com/linode-api/reference/get-firewall-rules
        if protocol == "ICMP" and ports is not None:
            raise ValueError("Linode ICMP ports must be absent")
        if protocol in {"TCP", "UDP"} and ports == "":
            ports = None
        normalized = (rule.get("action"), protocol, ports,
                      tuple(sorted(addresses.get("ipv4") or [])),
                      tuple(sorted(addresses.get("ipv6") or [])),
                      rule.get("label") or "", rule.get("description") or "")
        if normalized in seen:
            raise ValueError("Linode firewall rule repeats")
        seen.add(normalized)
        result.append(normalized)
    return result


class _FirewallPending(ValueError):
    pass


def require_current_keyed_firewall(provider, policy, resources, *, fence,
                                   credential_repository=None, transport=None,
                                   wait_for_completion=False):
    """Optionally bound post-Apply DO convergence to 16 observations.

    Only the post-Apply caller opts in. Every observation repeats the complete
    checks; only completion or rule propagation retries. Ownership, credential
    and generation failures stop immediately. No mismatching observation succeeds.
    """
    if type(wait_for_completion) is not bool:
        raise ValueError("keyed completion wait option differs")
    generation = fence()
    def stable_fence():
        if fence() != generation:
            raise ValueError("keyed provider snapshot fence changed")
        return generation
    for attempt in range(16 if wait_for_completion else 1):
        try:
            return _require_current_keyed_firewall(
                provider, policy, resources, fence=stable_fence,
                credential_repository=credential_repository, transport=transport)
        except _FirewallPending:
            if not wait_for_completion or attempt == 15:
                raise
            sleep(2)


def _require_current_keyed_firewall(provider, policy, resources, *, fence,
                                    credential_repository=None, transport=None):
    """Compare real provider rules, egress and membership with retained state.

    The caller separately authenticates complete account ownership inventory;
    this closes its deliberately missing rule-content and overlapping-firewall
    checks immediately before and after a shared ingress update.
    """
    repository = credential_repository or SqlAlchemyCredentialRepository()
    encrypted = _credential(repository, provider, policy)
    token = decrypt_secret_value(encrypted)
    if not token:
        raise ValueError("keyed provider credential unavailable")
    generation = fence()
    firewall = resources[f"{provider}_firewall.firewall"]
    identifier = str(firewall["id"])
    nodes = {str(resources[address]["id"]) for address in policy["nodes"]}
    if not nodes or len(nodes) != len(policy["nodes"]):
        raise ValueError("retained keyed node identities differ")
    pending_completion = False
    if provider == "digitalocean":
        client = _FencedDigitalOceanTransport(
            transport or UrllibProviderCatalogTransport(), fence, generation)
        observed = _request(client, f"/firewalls/{identifier}", token).get("firewall")
        if (type(observed) is not dict or observed.get("id") != identifier
                or observed.get("name") != firewall["name"]
                or observed.get("droplet_ids") != []
                or observed.get("tags") != firewall["tags"]
                or _selector_droplet_ids(client, token, firewall["tags"][0]) != nodes):
            raise ValueError("current DigitalOcean firewall differs")
        inbound = _normalize_rules(observed.get("inbound_rules"), "sources")
        outbound = _normalize_rules(observed.get("outbound_rules"), "destinations")
        pending_completion = (
            inbound != _do_rules(firewall["inbound_rule"], "sources")
            or outbound != _do_rules(firewall["outbound_rule"], "destinations"))
        if observed.get("status") != "succeeded" or observed.get("pending_changes") != []:
            pending = observed.get("pending_changes")
            if (observed.get("status") != "waiting" or type(pending) is not list
                    or any(type(row) is not dict
                           or set(row) != {"droplet_id", "removing", "status"}
                           or type(row["droplet_id"]) is not int
                           or str(row["droplet_id"]) not in nodes
                           or row["removing"] is not False or row["status"] != "waiting"
                           for row in pending)
                    or len({row["droplet_id"] for row in pending}) != len(pending)):
                raise ValueError("current DigitalOcean completion metadata differs")
            pending_completion = True
        for node in sorted(nodes):
            fence()
            response = _request(client, f"/droplets/{node}/firewalls?page=1&per_page=200", token)
            if (type(response.get("meta", {}).get("total")) is not int
                    or response["meta"]["total"] != 1
                    or response.get("links", {}).get("pages", {}).get("next") is not None
                    or [row.get("id") for row in response.get("firewalls", [])] != [identifier]):
                raise ValueError("DigitalOcean node has overlapping firewall membership")
    elif provider == "linode":
        client = _FencedLinodeTransport(transport or UrllibLinodeTransport(), fence, generation)
        observed = _get(client, f"/networking/firewalls/{identifier}", token)
        rules = _get(client, f"/networking/firewalls/{identifier}/rules", token)
        devices = _complete_rows(client, token, f"/networking/firewalls/{identifier}/devices")
        if (str(observed.get("id")) != identifier
                or observed.get("label") != firewall["label"]
                or observed.get("tags") != firewall["tags"]
                or observed.get("status") != "enabled"
                or firewall.get("disabled") is not False
                or rules.get("inbound_policy") != firewall["inbound_policy"]
                or rules.get("outbound_policy") != firewall["outbound_policy"]
                or _linode_rules(rules.get("inbound"), api=True) != _linode_rules(firewall["inbound"])
                or _linode_rules(rules.get("outbound"), api=True) != _linode_rules(firewall["outbound"])
                or type(firewall.get("linodes")) is not list
                or len(firewall["linodes"]) != len(nodes)
                or {str(node) for node in firewall["linodes"]} != nodes
                or len(devices) != len(nodes)
                or any(row.get("entity", {}).get("type") != "linode" for row in devices)
                or {str(row["entity"]["id"]) for row in devices} != nodes):
            raise ValueError("current Linode firewall differs")
        for other in _complete_rows(client, token, "/networking/firewalls"):
            if str(other.get("id")) == identifier:
                continue
            devices = _complete_rows(client, token, f"/networking/firewalls/{other['id']}/devices")
            if any(row.get("entity", {}).get("type") != "linode" for row in devices):
                raise ValueError("Linode other-firewall attachment kind is unreviewed")
            if any(row.get("entity", {}).get("type") == "linode"
                   and str(row["entity"].get("id")) in nodes for row in devices):
                raise ValueError("Linode node has overlapping firewall membership")
    else:
        raise ValueError("unsupported keyed provider")
    if fence() != generation:
        raise ValueError("keyed provider snapshot fence changed")
    if _credential(repository, provider, policy) != encrypted:
        raise ValueError("keyed provider credential changed")
    if fence() != generation:
        raise ValueError("keyed provider snapshot fence changed")
    if pending_completion:
        raise _FirewallPending("current DigitalOcean firewall is still applying")
