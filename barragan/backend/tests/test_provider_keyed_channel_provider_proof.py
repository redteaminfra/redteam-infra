# Copyright (c) 2026, Oracle and/or its affiliates.
"""Literal provider GET shapes: retained policy, full egress and membership."""
from copy import deepcopy
from hashlib import sha256
from types import SimpleNamespace

import pytest

from app.services import provider_keyed_channel_provider_proof as proof


class Transport:
    def __init__(self, provider, responses, fence):
        self.provider, self.responses, self.fence = provider, responses, fence
        self.calls = []

    def request(self, *args, **kwargs):
        if self.provider == "digitalocean":
            origin, method, path, token = args
            assert origin == "https://api.digitalocean.com/v2"
        else:
            method, path, token = args
        assert method == "GET" and token == "private-token" and not kwargs
        self.calls.append(path)
        assert self.fence.calls > 0
        assert self.fence.change_at is None or self.fence.calls < self.fence.change_at
        return deepcopy(self.responses[path])


class Fence:
    def __init__(self):
        self.calls = 0
        self.change_at = None

    def __call__(self):
        self.calls += 1
        return "changed" if self.change_at is not None and self.calls >= self.change_at else "generation"


def _page(rows):
    return {"page": 1, "pages": 1, "results": len(rows), "data": rows}


def _case(monkeypatch, provider):
    encrypted = "encrypted-fixture"
    record = SimpleNamespace(provider=provider, status="active", is_default=True,
                             encrypted_secret=encrypted, updated_at="time")
    repository = SimpleNamespace(get=lambda _: record, get_default=lambda _: record)
    monkeypatch.setattr(proof, "decrypt_secret_value", lambda secret: "private-token" if secret == encrypted else None)
    node_type = "digitalocean_droplet" if provider == "digitalocean" else "linode_instance"
    nodes = [f'{node_type}.{role}["x"]' for role in ("middle", "edge")]
    policy = {"nodes": nodes, "provider_connection_id": "connection", "credential_updated_at": "time",
              "credential_secret_sha256": sha256(encrypted.encode()).hexdigest()}
    resources = {nodes[0]: {"id": 101}, nodes[1]: {"id": 102}}
    if provider == "digitalocean":
        inbound = [{"protocol": "tcp", "ports": "22", "sources": {"addresses": ["192.0.2.1/32"]}},
                   {"protocol": "udp", "ports": "5353", "sources": {"addresses": ["0.0.0.0/0"]}}]
        outbound = [{"protocol": proto, "ports": ports, "destinations": {"addresses": ["0.0.0.0/0", "::/0"]}}
                    for proto, ports in (("tcp", "1-65535"), ("udp", "1-65535"), ("icmp", "0"))]
        fw = {"id": "fw-1", "name": "opaque", "tags": ["opaque"], "droplet_ids": [],
              "inbound_rule": [{"protocol": r["protocol"], "port_range": r["ports"],
                                "source_addresses": r["sources"]["addresses"]} for r in inbound],
              "outbound_rule": [{"protocol": r["protocol"], "port_range": "" if r["protocol"] == "icmp" else r["ports"],
                                 "destination_addresses": r["destinations"]["addresses"]} for r in outbound]}
        responses = {"/firewalls/fw-1": {"firewall": {"id": "fw-1", "name": "opaque", "tags": ["opaque"],
            "status": "succeeded", "pending_changes": [], "droplet_ids": [], "inbound_rules": inbound,
            "outbound_rules": outbound}},
            "/droplets?page=1&per_page=200&tag_name=opaque": {"droplets": [{"id": n, "tags": ["opaque"]} for n in (101, 102)],
                "meta": {"total": 2}, "links": {"pages": {}}},
            "/droplets?page=1&per_page=200&type=gpus": {"droplets": [], "meta": {"total": 0}, "links": {"pages": {}}}}
        for node in (101, 102):
            responses[f"/droplets/{node}/firewalls?page=1&per_page=200"] = {
                "firewalls": [{"id": "fw-1"}], "meta": {"total": 1}, "links": {"pages": {}}}
    else:
        inbound = [{"action": "ACCEPT", "protocol": "TCP", "ports": "22", "label": "ssh", "description": "",
                    "addresses": {"ipv4": ["192.0.2.1/32"], "ipv6": []}},
                   {"action": "ACCEPT", "protocol": "UDP", "ports": "5353", "label": "channel", "description": "",
                    "addresses": {"ipv4": ["0.0.0.0/0"], "ipv6": []}},
                   {"action": "DROP", "protocol": "ICMP", "ports": None, "label": "block-v6", "description": "",
                    "addresses": {"ipv4": [], "ipv6": ["::/0"]}}]
        fw = {"id": "42", "label": "opaque", "tags": ["opaque"], "disabled": False,
              "inbound_policy": "DROP", "outbound_policy": "ACCEPT", "linodes": [101, 102],
              "inbound": [{**{k: v for k, v in r.items() if k != "addresses"},
                           "ipv4": r["addresses"]["ipv4"] or None, "ipv6": r["addresses"]["ipv6"] or None} for r in inbound],
              "outbound": []}
        responses = {"/networking/firewalls/42": {"id": 42, "label": "opaque", "tags": ["opaque"], "status": "enabled"},
                     "/networking/firewalls/42/rules": {"inbound_policy": "DROP", "outbound_policy": "ACCEPT", "inbound": inbound, "outbound": []},
                     "/networking/firewalls/42/devices?page=1&page_size=100": _page([
                         {"id": n + 1000, "entity": {"id": n, "type": "linode"}} for n in (101, 102)]),
                     "/networking/firewalls?page=1&page_size=100": _page([{"id": 42}, {"id": 43}]),
                     "/networking/firewalls/43/devices?page=1&page_size=100": _page([
                         {"id": 1999, "entity": {"id": 999, "type": "linode"}}])}
    resources[f"{provider}_firewall.firewall"] = fw
    fence = Fence()
    transport = Transport(provider, responses, fence)
    args = dict(fence=fence, credential_repository=repository, transport=transport)
    return policy, resources, responses, args, record


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_exact_current_rules_default_egress_and_complete_membership(monkeypatch, provider):
    policy, resources, responses, args, _ = _case(monkeypatch, provider)
    assert proof.require_current_keyed_firewall(provider, policy, resources, **args) is None
    assert set(args["transport"].calls) == set(responses)


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize("change", ["missing", "extra", "duplicate", "egress", "selector", "pending", "membership", "overlap"])
def test_provider_policy_or_membership_drift_veto(monkeypatch, provider, change):
    policy, resources, responses, args, _ = _case(monkeypatch, provider)
    if provider == "digitalocean":
        fw = responses["/firewalls/fw-1"]["firewall"]
        rules = fw["inbound_rules"]
        if change == "egress": fw["outbound_rules"].pop()
        elif change == "selector": rules[0]["sources"]["tags"] = ["unreviewed"]
        elif change == "pending": fw["pending_changes"] = [{"status": "waiting"}]
        elif change == "membership": responses["/droplets?page=1&per_page=200&tag_name=opaque"]["droplets"][1]["id"] = 103
        elif change == "overlap": responses["/droplets/101/firewalls?page=1&per_page=200"].update(firewalls=[{"id": "fw-1"}, {"id": "fw-2"}], meta={"total": 2})
    else:
        fw = responses["/networking/firewalls/42/rules"]
        rules = fw["inbound"]
        if change == "egress": fw["outbound_policy"] = "DROP"
        elif change == "selector": rules[0]["addresses"]["ipv6"] = ["::/0"]
        elif change == "pending": responses["/networking/firewalls/42"]["status"] = "disabled"
        elif change == "membership": responses["/networking/firewalls/42/devices?page=1&page_size=100"]["data"][1]["entity"]["id"] = 103
        elif change == "overlap": responses["/networking/firewalls/43/devices?page=1&page_size=100"]["data"][0]["entity"]["id"] = 101
    if change == "missing": rules.pop()
    elif change == "duplicate": rules.append(deepcopy(rules[0]))
    elif change == "extra":
        rule = deepcopy(rules[0]); rule["ports"] = "8888"; rules.append(rule)
    with pytest.raises(ValueError):
        proof.require_current_keyed_firewall(provider, policy, resources, **args)


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_credential_changed_during_get_veto(monkeypatch, provider):
    policy, resources, _, args, record = _case(monkeypatch, provider)
    request = args["transport"].request
    def changed(*a, **kw):
        result = request(*a, **kw)
        record.updated_at = "later"
        return result
    args["transport"].request = changed
    with pytest.raises(ValueError, match="credential changed"):
        proof.require_current_keyed_firewall(provider, policy, resources, **args)


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_every_get_and_final_fence_veto_generation_changes(monkeypatch, provider):
    policy, resources, _, args, _ = _case(monkeypatch, provider)
    proof.require_current_keyed_firewall(provider, policy, resources, **args)
    checks = args["fence"].calls
    # Every boundary after the initial generation capture, including the final
    # return guard, must veto. No request may be issued after a changed fence.
    for change_at in range(2, checks + 1):
        policy, resources, _, args, _ = _case(monkeypatch, provider)
        args["fence"].change_at = change_at
        with pytest.raises(ValueError, match="fence changed"):
            proof.require_current_keyed_firewall(provider, policy, resources, **args)


@pytest.mark.parametrize("ports", [None, ""])
def test_linode_supported_all_port_spelling_normalization(monkeypatch, ports):
    policy, resources, responses, args, _ = _case(monkeypatch, "linode")
    # Terraform null and API omission/empty represent the same all-port TCP rule.
    resources["linode_firewall.firewall"]["inbound"][0]["ports"] = None
    rule = responses["/networking/firewalls/42/rules"]["inbound"][0]
    if ports is None: rule.pop("ports")
    else: rule["ports"] = ports
    proof.require_current_keyed_firewall("linode", policy, resources, **args)


def test_linode_icmp_omission_matches_null_but_empty_ports_invalid(monkeypatch):
    policy, resources, responses, args, _ = _case(monkeypatch, "linode")
    rule = responses["/networking/firewalls/42/rules"]["inbound"][-1]
    rule.pop("ports")
    proof.require_current_keyed_firewall("linode", policy, resources, **args)
    rule["ports"] = ""
    with pytest.raises(ValueError, match="ICMP ports"):
        proof.require_current_keyed_firewall("linode", policy, resources, **args)


def test_linode_rule_order_is_semantic_and_duplicate_expected_rules_rejected(monkeypatch):
    policy, resources, responses, args, _ = _case(monkeypatch, "linode")
    rules = responses["/networking/firewalls/42/rules"]["inbound"]
    rules.reverse()
    with pytest.raises(ValueError):
        proof.require_current_keyed_firewall("linode", policy, resources, **args)
    rules.reverse()
    rules.append(deepcopy(rules[0]))
    resources["linode_firewall.firewall"]["inbound"].append(deepcopy(resources["linode_firewall.firewall"]["inbound"][0]))
    with pytest.raises(ValueError, match="rule repeats"):
        proof.require_current_keyed_firewall("linode", policy, resources, **args)


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize("change", ["duplicate_member", "truncated", "wrong_type", "credential", "duplicate_nodes"])
def test_incomplete_inventory_and_retained_authority_fail_closed(monkeypatch, provider, change):
    policy, resources, responses, args, record = _case(monkeypatch, provider)
    if change == "credential": record.status = "inactive"
    elif change == "duplicate_nodes": policy["nodes"].append(policy["nodes"][0])
    elif provider == "digitalocean":
        page = responses["/droplets?page=1&per_page=200&tag_name=opaque"]
        if change == "duplicate_member": page["droplets"][1] = deepcopy(page["droplets"][0])
        elif change == "truncated": page["meta"]["total"] = 3; page["droplets"] = []
        else: page["droplets"][0]["id"] = "other-kind"
    else:
        page = responses["/networking/firewalls/42/devices?page=1&page_size=100"]
        if change == "duplicate_member": page["data"][1]["entity"]["id"] = 101
        elif change == "truncated": page["results"] = 3
        else: page["data"][0]["entity"]["type"] = "linode_interface"
    with pytest.raises(ValueError):
        proof.require_current_keyed_firewall(provider, policy, resources, **args)


def test_linode_retained_attachment_set_must_match_authenticated_nodes(monkeypatch):
    policy, resources, _, args, _ = _case(monkeypatch, "linode")
    resources["linode_firewall.firewall"]["linodes"] = [101, 101]
    with pytest.raises(ValueError):
        proof.require_current_keyed_firewall("linode", policy, resources, **args)


@pytest.mark.parametrize("kind", ["linode_interface", "nodebalancer", None])
def test_other_linode_firewall_unknown_device_kind_cannot_exclude_overlap(monkeypatch, kind):
    policy, resources, responses, args, _ = _case(monkeypatch, "linode")
    responses["/networking/firewalls/43/devices?page=1&page_size=100"]["data"][0]["entity"]["type"] = kind
    with pytest.raises(ValueError, match="attachment kind"):
        proof.require_current_keyed_firewall("linode", policy, resources, **args)


def test_digitalocean_boolean_membership_total_is_not_a_count(monkeypatch):
    policy, resources, responses, args, _ = _case(monkeypatch, "digitalocean")
    responses["/droplets/101/firewalls?page=1&per_page=200"]["meta"]["total"] = True
    with pytest.raises(ValueError):
        proof.require_current_keyed_firewall("digitalocean", policy, resources, **args)


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_generation_changes_during_terminal_credential_read_veto(monkeypatch, provider):
    policy, resources, _, args, record = _case(monkeypatch, provider)
    count = 0
    def reread(_):
        nonlocal count
        count += 1
        if count > 1:
            args["fence"].change_at = args["fence"].calls + 1
        return record
    args["credential_repository"].get = reread
    with pytest.raises(ValueError, match="fence changed"):
        proof.require_current_keyed_firewall(provider, policy, resources, **args)


def test_do_post_apply_completion_wait_repeats_full_fenced_proof(monkeypatch):
    policy, resources, responses, args, _ = _case(monkeypatch, "digitalocean")
    fw = responses["/firewalls/fw-1"]["firewall"]
    fw.update(status="waiting", pending_changes=[
        {"droplet_id": 101, "removing": False, "status": "waiting"},
        {"droplet_id": 102, "removing": False, "status": "waiting"}])
    sleeps = []
    def settle(seconds):
        sleeps.append(seconds)
        fw.update(status="succeeded", pending_changes=[])
    monkeypatch.setattr(proof, "sleep", settle)
    proof.require_current_keyed_firewall("digitalocean", policy, resources,
                                        wait_for_completion=True, **args)
    assert sleeps == [2]
    assert args["transport"].calls.count("/firewalls/fw-1") == 2
    assert args["transport"].calls.count("/droplets/101/firewalls?page=1&per_page=200") == 2


def test_do_completion_wait_is_opt_in_and_finite(monkeypatch):
    policy, resources, responses, args, _ = _case(monkeypatch, "digitalocean")
    responses["/firewalls/fw-1"]["firewall"].update(status="waiting", pending_changes=[])
    sleeps = []
    monkeypatch.setattr(proof, "sleep", sleeps.append)
    with pytest.raises(ValueError, match="still applying"):
        proof.require_current_keyed_firewall("digitalocean", policy, resources, **args)
    assert sleeps == []
    with pytest.raises(ValueError, match="still applying"):
        proof.require_current_keyed_firewall("digitalocean", policy, resources,
                                            wait_for_completion=True, **args)
    assert sleeps == [2] * 15
    assert args["transport"].calls.count("/firewalls/fw-1") == 17


@pytest.mark.parametrize("change", ["overlap", "foreign", "removing", "duplicate", "status", "shape", "boolean"])
def test_do_completion_wait_never_retries_policy_or_pending_identity_drift(monkeypatch, change):
    policy, resources, responses, args, _ = _case(monkeypatch, "digitalocean")
    fw = responses["/firewalls/fw-1"]["firewall"]
    pending = {"droplet_id": 101, "removing": False, "status": "waiting"}
    fw.update(status="waiting", pending_changes=[pending])
    if change == "rule": fw["inbound_rules"].pop()
    elif change == "egress": fw["outbound_rules"].pop()
    elif change == "overlap": responses["/droplets/101/firewalls?page=1&per_page=200"]["meta"]["total"] = 2
    elif change == "foreign": pending["droplet_id"] = 999
    elif change == "removing": pending["removing"] = True
    elif change == "duplicate": fw["pending_changes"].append(deepcopy(pending))
    elif change == "status": pending["status"] = "failed"
    elif change == "shape": pending["extra"] = 1
    elif change == "boolean": pending["droplet_id"] = True
    monkeypatch.setattr(proof, "sleep", lambda _: pytest.fail("drift must not retry"))
    with pytest.raises(ValueError):
        proof.require_current_keyed_firewall("digitalocean", policy, resources,
                                            wait_for_completion=True, **args)


def test_do_completion_wait_cannot_adopt_new_generation_between_attempts(monkeypatch):
    policy, resources, responses, args, _ = _case(monkeypatch, "digitalocean")
    responses["/firewalls/fw-1"]["firewall"].update(status="waiting", pending_changes=[])
    def change(_):
        args["fence"].change_at = args["fence"].calls + 1
    monkeypatch.setattr(proof, "sleep", change)
    with pytest.raises(ValueError, match="fence changed"):
        proof.require_current_keyed_firewall("digitalocean", policy, resources,
                                            wait_for_completion=True, **args)
    assert args["transport"].calls.count("/firewalls/fw-1") == 1


@pytest.mark.parametrize("side", ["inbound_rules", "outbound_rules"])
def test_do_post_apply_rule_propagation_requires_exact_final_rules(monkeypatch, side):
    policy, resources, responses, args, _ = _case(monkeypatch, "digitalocean")
    fw = responses["/firewalls/fw-1"]["firewall"]
    expected = deepcopy(fw[side])
    fw[side].pop()
    sleeps = []
    monkeypatch.setattr(proof, "sleep", sleeps.append)
    with pytest.raises(ValueError, match="still applying"):
        proof.require_current_keyed_firewall("digitalocean", policy, resources,
                                            wait_for_completion=True, **args)
    assert len(sleeps) == 15
    sleeps.clear()
    def propagate(seconds):
        sleeps.append(seconds)
        fw[side] = expected
    monkeypatch.setattr(proof, "sleep", propagate)
    proof.require_current_keyed_firewall("digitalocean", policy, resources,
                                        wait_for_completion=True, **args)
    assert sleeps == [2]
