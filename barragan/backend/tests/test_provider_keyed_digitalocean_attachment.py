# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only DigitalOcean attachment reconciliation with injected API reads."""

import copy
import hashlib
import io
import json
import urllib.error
from pathlib import Path

import pytest

import app.services.provider_keyed_digitalocean_attachment as service
from app.services.provider_catalog import ProviderCatalogError
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace


class Repository:
    secret = "encrypted-token"
    updated_at = "2026-10-02T00:00:00Z"

    def get(self, identifier):
        return self.get_default("digitalocean") if identifier == "cred-000000000001" else None

    def get_default(self, provider):
        assert provider == "digitalocean"
        return type("Credential", (), {
            "id": "cred-000000000001", "provider": provider, "status": "active",
            "is_default": True, "encrypted_secret": self.secret,
            "updated_at": self.updated_at,
        })()


class Transport:
    def __init__(self, response_map):
        self.responses = response_map
        self.requests = []
        self.attempt = 0

    def request(self, origin, method, path, token):
        self.requests.append((origin, method, path, token))
        if path.startswith("/firewalls/"):
            self.attempt += 1
        value = self.responses[path]
        if isinstance(value, list):
            value = value[min(self.attempt - 1, len(value) - 1)]
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)


def _rule(protocol, ports, addresses, side="sources"):
    return {"protocol": protocol, "ports": ports, "action": "allow", side: {"addresses": list(addresses)}}


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    root = tmp_path / "provider-state"
    root.mkdir()
    nodes = (
        service.ExpectedDigitalOceanNode('digitalocean_droplet.middle["primary"]', "101", "middle01-eng", "nyc3", "192.0.2.11"),
        service.ExpectedDigitalOceanNode('digitalocean_droplet.edge["sfo3-01"]', "102", "edge-eng-sfo3-01", "sfo3", "192.0.2.12"),
    )
    firewall_id = "bb4b2611-3d72-467b-8602-280330ecd65c"
    selector = "opaque-selector-a1"
    state = {
        "version": 4, "serial": 1,
        "lineage": "db0cb9ba-cad2-43dc-9a6e-8b2418517370", "resources": [
            {"mode": "managed", "type": "digitalocean_droplet", "name": "middle", "instances": [
                {"index_key": "primary", "attributes": {"id": "101", "name": nodes[0].name, "region": nodes[0].region, "ipv4_address": nodes[0].public_ipv4, "tags": [selector]}}
            ]},
            {"mode": "managed", "type": "digitalocean_droplet", "name": "edge", "instances": [
                {"index_key": "sfo3-01", "attributes": {"id": "102", "name": nodes[1].name, "region": nodes[1].region, "ipv4_address": nodes[1].public_ipv4, "tags": [selector]}}
            ]},
            {"mode": "managed", "type": "digitalocean_firewall", "name": "firewall", "instances": [
                {"attributes": {"id": firewall_id, "name": "eng-firewall", "tags": [selector]}}
            ]},
        ],
    }
    state_path = root / "terraform.tfstate"
    state_path.write_text(json.dumps(state))
    (root / ".barragan-apply-phase.json").write_text('{"schema":"provider-keyed-v2","phase":"applied"}')
    workspace = ProviderKeyedWorkspace(
        root, state_path, root / ".terraform-data", "provider-keyed-v2",
        "digitalocean", "cred-000000000001", "fingerprint",
        "ca5bcad7d2be274aaa79d6c9127cbd9b5c2b10cc", "source-hash",
    )
    intent = service.DigitalOceanAttachmentIntent(
        hashlib.sha256(state_path.read_bytes()).hexdigest(), firewall_id,
        "eng-firewall", selector, ("198.51.100.10/32",), nodes,
        workspace.provider_connection_id, hashlib.sha256(b"encrypted-token").hexdigest(),
        "2026-10-02T00:00:00Z",
    )
    peers = ("192.0.2.11/32", "192.0.2.12/32")
    inbound = [_rule("tcp", port, ["0.0.0.0/0"]) for port in ("80", "443", "2222")]
    inbound.append(_rule("tcp", "22", ["198.51.100.10/32"]))
    inbound.extend(_rule(proto, "1-65535", peers)
                   for proto in ("tcp", "udp", "icmp"))
    outbound = [_rule(proto, "0" if proto == "icmp" else "1-65535", ["0.0.0.0/0"], "destinations")
                for proto in ("tcp", "udp", "icmp")]
    firewall = {"firewall": {"id": firewall_id, "name": intent.firewall_name,
                             "status": "succeeded", "pending_changes": [],
                             "tags": [selector], "droplet_ids": [],
                             "inbound_rules": inbound, "outbound_rules": outbound}}
    responses = {f"/firewalls/{firewall_id}": firewall}
    responses[f"/droplets?page=1&per_page=200&tag_name={selector}"] = {
        "droplets": [{"id": 101, "tags": [selector]}, {"id": 102, "tags": [selector]}],
        "meta": {"total": 2}, "links": {},
    }
    responses["/droplets?page=1&per_page=200&type=gpus"] = {
        "droplets": [], "meta": {"total": 0}, "links": {},
    }
    for node in nodes:
        responses[f"/droplets/{node.droplet_id}"] = {"droplet": {
            "id": int(node.droplet_id), "name": node.name, "region": {"slug": node.region},
            "tags": [selector], "status": "active",
        }}
        responses[f"/droplets/{node.droplet_id}/firewalls?page=1&per_page=200"] = {
            "firewalls": [{"id": firewall_id}], "meta": {"total": 1}, "links": {}}
    monkeypatch.setattr(service, "decrypt_secret_value", lambda encrypted: "api-token-fixture")
    return workspace, intent, Repository(), responses


def _run(prepared, *, responses=None, repository=None, **kwargs):
    workspace, intent, default_repository, default_responses = prepared
    transport = Transport(responses or default_responses)
    result = service.reconcile_digitalocean_initial_attachment(
        workspace, intent, environment="devtest", deployment_target="barragan-testing",
        credential_repository=repository or default_repository, transport=transport,
        sleeper=lambda seconds: None, **kwargs,
    )
    return result, transport


def _veto(prepared, *, responses=None):
    workspace, intent, repository, defaults = prepared
    transport = Transport(responses if responses is not None else defaults)
    service.require_digitalocean_pre_destroy_membership(
        workspace, intent, environment="devtest", deployment_target="barragan-testing",
        credential_repository=repository, transport=transport,
    )
    return transport


def test_pre_destroy_veto_accepts_exact_current_membership_with_get_only(prepared):
    transport = _veto(prepared)
    assert transport.requests
    assert all(method == "GET" for _, method, _, _ in transport.requests)
    assert not any(path == "/droplets/101" for _, _, path, _ in transport.requests)


def test_pre_destroy_veto_allows_stopped_owned_node_and_changed_allowed_port(prepared):
    _, intent, _, defaults = prepared
    responses = copy.deepcopy(defaults)
    responses["/droplets/101"]["droplet"]["status"] = "off"
    responses[f"/firewalls/{intent.firewall_id}"]["firewall"]["inbound_rules"].append(
        _rule("tcp", "8443", ["0.0.0.0/0"]))
    transport = _veto(prepared, responses=responses)
    assert not any(path == "/droplets/101" for _, _, path, _ in transport.requests)


@pytest.mark.parametrize("kind", ["normal", "gpu"])
def test_pre_destroy_veto_rejects_extra_manual_tagged_droplet(prepared, kind):
    _, intent, _, defaults = prepared
    responses = copy.deepcopy(defaults)
    path = (f"/droplets?page=1&per_page=200&tag_name={intent.selector_tag}"
            if kind == "normal" else "/droplets?page=1&per_page=200&type=gpus")
    responses[path]["droplets"].append({"id": 999, "tags": [intent.selector_tag]})
    responses[path]["meta"]["total"] += 1
    with pytest.raises(service.DigitalOceanAttachmentError, match="selector membership"):
        _veto(prepared, responses=responses)


def test_pre_destroy_veto_rejects_explicit_firewall_member(prepared):
    _, intent, _, defaults = prepared
    explicit = copy.deepcopy(defaults)
    explicit[f"/firewalls/{intent.firewall_id}"]["firewall"]["droplet_ids"] = [101]
    with pytest.raises(service.DigitalOceanAttachmentError, match="firewall membership"):
        _veto(prepared, responses=explicit)


def test_pre_destroy_veto_rejects_pending_firewall_change(prepared):
    _, intent, _, defaults = prepared
    pending = copy.deepcopy(defaults)
    pending[f"/firewalls/{intent.firewall_id}"]["firewall"]["pending_changes"] = [
        {"droplet_id": 101, "status": "waiting"}]
    with pytest.raises(service.DigitalOceanAttachmentError, match="not settled"):
        _veto(prepared, responses=pending)


def test_pre_destroy_veto_ignores_other_firewall_on_owned_node(prepared):
    _, _, _, defaults = prepared
    overlap = copy.deepcopy(defaults)
    path = "/droplets/101/firewalls?page=1&per_page=200"
    overlap[path]["firewalls"].append({"id": "other-firewall"})
    overlap[path]["meta"]["total"] = 2
    transport = _veto(prepared, responses=overlap)
    assert all(request_path != path for _, _, request_path, _ in transport.requests)


def test_pre_destroy_veto_rejects_missing_owned_or_partial_inventory(prepared):
    _, intent, _, defaults = prepared
    missing = copy.deepcopy(defaults)
    path = f"/droplets?page=1&per_page=200&tag_name={intent.selector_tag}"
    missing[path]["droplets"].pop()
    missing[path]["meta"]["total"] = 1
    with pytest.raises(service.DigitalOceanAttachmentError, match="selector membership"):
        _veto(prepared, responses=missing)
    partial = copy.deepcopy(defaults)
    partial[path]["droplets"].pop()
    partial[path]["links"] = {"pages": {"next": "unread-page"}}
    partial[f"/droplets?page=2&per_page=200&tag_name={intent.selector_tag}"] = {
        "droplets": [], "meta": {"total": 2}, "links": {},
    }
    with pytest.raises(service.DigitalOceanAttachmentError, match="incomplete|truncated|pagination"):
        _veto(prepared, responses=partial)


def test_pre_destroy_veto_rejects_transport_without_retry(prepared):
    _, intent, _, defaults = prepared
    broken = copy.deepcopy(defaults)
    broken[f"/firewalls/{intent.firewall_id}"] = OSError("provider unavailable")
    with pytest.raises(service.DigitalOceanAttachmentError, match="unverified"):
        _veto(prepared, responses=broken)


def test_waits_for_provider_settling_then_verifies_all_memberships(prepared):
    _, intent, _, responses = prepared
    responses = copy.deepcopy(responses)
    pending = copy.deepcopy(responses[f"/firewalls/{intent.firewall_id}"])
    pending["firewall"].update(status="waiting", pending_changes=[{"droplet_id": 101, "status": "waiting"}])
    responses[f"/firewalls/{intent.firewall_id}"] = [pending, responses[f"/firewalls/{intent.firewall_id}"]]
    result, transport = _run(prepared, responses=responses)
    assert result.attempts == 2
    assert result.provider_membership_verified is True
    assert result.host_policy_verified is False
    assert result.verified_droplet_ids == ("101", "102")
    assert all(method == "GET" for _, method, _, _ in transport.requests)
    assert "api-token-fixture" not in repr(result)


def test_membership_links_may_be_absent_when_total_matches(prepared):
    _, _, _, responses = prepared
    without_links = copy.deepcopy(responses)
    without_links["/droplets/101/firewalls?page=1&per_page=200"].pop("links")
    result, _ = _run(prepared, responses=without_links)
    assert result.provider_membership_verified is True


def test_absent_membership_links_do_not_hide_total_mismatch(prepared):
    _, _, _, responses = prepared
    incomplete = copy.deepcopy(responses)
    membership = incomplete["/droplets/101/firewalls?page=1&per_page=200"]
    membership.pop("links")
    membership["meta"]["total"] = 0
    with pytest.raises(service.DigitalOceanAttachmentError, match="total differs"):
        _run(prepared, responses=incomplete)


def test_extra_firewall_fails_without_waiting(prepared):
    _, intent, _, responses = prepared
    responses = copy.deepcopy(responses)
    path = f"/droplets/101/firewalls?page=1&per_page=200"
    responses[path]["firewalls"].append({"id": "other-firewall"})
    responses[path]["meta"]["total"] = 2
    with pytest.raises(service.DigitalOceanAttachmentError, match="overlapping"):
        _run(prepared, responses=responses)


def test_unmanaged_selector_droplet_or_explicit_member_fails(prepared):
    _, intent, _, responses = prepared
    unmanaged = copy.deepcopy(responses)
    path = f"/droplets?page=1&per_page=200&tag_name={intent.selector_tag}"
    unmanaged[path]["droplets"].append({"id": 999, "tags": [intent.selector_tag]})
    unmanaged[path]["meta"]["total"] = 3
    with pytest.raises(service.DigitalOceanAttachmentError, match="unreviewed Droplet"):
        _run(prepared, responses=unmanaged)
    explicit = copy.deepcopy(responses)
    explicit[f"/firewalls/{intent.firewall_id}"]["firewall"]["droplet_ids"] = [999]
    with pytest.raises(service.DigitalOceanAttachmentError, match="explicit"):
        _run(prepared, responses=explicit)


def test_unmanaged_gpu_selector_droplet_fails(prepared):
    _, intent, _, responses = prepared
    gpu = copy.deepcopy(responses)
    gpu["/droplets?page=1&per_page=200&type=gpus"] = {
        "droplets": [{"id": 999, "tags": [intent.selector_tag]}],
        "meta": {"total": 1}, "links": {},
    }
    with pytest.raises(service.DigitalOceanAttachmentError, match="unreviewed Droplet"):
        _run(prepared, responses=gpu)


def test_second_inventory_page_cannot_hide_unmanaged_droplet(prepared):
    _, intent, _, responses = prepared
    paged = copy.deepcopy(responses)
    first = f"/droplets?page=1&per_page=200&tag_name={intent.selector_tag}"
    second = f"/droplets?page=2&per_page=200&tag_name={intent.selector_tag}"
    paged[first] = {
        "droplets": [{"id": 101, "tags": [intent.selector_tag]}],
        "meta": {"total": 3}, "links": {"pages": {"next": "opaque-next"}},
    }
    paged[second] = {
        "droplets": [{"id": 102, "tags": [intent.selector_tag]},
                     {"id": 999, "tags": [intent.selector_tag]}],
        "meta": {"total": 3}, "links": {},
    }
    with pytest.raises(service.DigitalOceanAttachmentError, match="unreviewed Droplet"):
        _run(prepared, responses=paged)


def test_wrong_firewall_policy_fails_without_retry(prepared):
    _, intent, _, responses = prepared
    responses = copy.deepcopy(responses)
    responses[f"/firewalls/{intent.firewall_id}"]["firewall"]["inbound_rules"].append(
        _rule("tcp", "8080", ["0.0.0.0/0"])
    )
    with pytest.raises(service.DigitalOceanAttachmentError, match="rules differ"):
        _run(prepared, responses=responses)


def test_peer_icmp_port_range_must_match_rendered_provider_rule(prepared):
    _, intent, _, responses = prepared
    changed = copy.deepcopy(responses)
    firewall = changed[f"/firewalls/{intent.firewall_id}"]["firewall"]
    peer_icmp = next(rule for rule in firewall["inbound_rules"] if rule["protocol"] == "icmp")
    assert peer_icmp["ports"] == "1-65535"
    outbound_icmp = next(rule for rule in firewall["outbound_rules"] if rule["protocol"] == "icmp")
    assert outbound_icmp["ports"] == "0"
    result, _ = _run(prepared, responses=changed)
    assert result.provider_membership_verified is True
    peer_icmp["ports"] = "0"
    with pytest.raises(service.DigitalOceanAttachmentError, match="rules differ"):
        _run(prepared, responses=changed)
    peer_icmp["ports"] = "1-65535"
    outbound_icmp["ports"] = "1-65535"
    with pytest.raises(service.DigitalOceanAttachmentError, match="rules differ"):
        _run(prepared, responses=changed)


def test_unexpected_selector_or_droplet_identity_fails(prepared):
    _, intent, _, responses = prepared
    wrong_selector = copy.deepcopy(responses)
    wrong_selector[f"/firewalls/{intent.firewall_id}"]["firewall"]["tags"] = ["other"]
    with pytest.raises(service.DigitalOceanAttachmentError, match="selector"):
        _run(prepared, responses=wrong_selector)
    wrong_node = copy.deepcopy(responses)
    wrong_node["/droplets/101"]["droplet"]["region"]["slug"] = "nyc1"
    with pytest.raises(service.DigitalOceanAttachmentError, match="Droplet differs"):
        _run(prepared, responses=wrong_node)


def test_credential_rotation_rejected_before_provider_read(prepared):
    workspace, intent, repository, responses = prepared
    repository.secret = "rotated-secret"
    transport = Transport(responses)
    with pytest.raises(service.DigitalOceanAttachmentError, match="credential changed"):
        service.reconcile_digitalocean_initial_attachment(
            workspace, intent, environment="devtest", deployment_target="barragan-testing",
            credential_repository=repository, transport=transport,
        )
    assert not transport.requests


def test_prod_scope_rejected_without_provider_read(prepared):
    workspace, intent, repository, responses = prepared
    transport = Transport(responses)
    with pytest.raises(service.DigitalOceanAttachmentError, match="DevTest"):
        service.reconcile_digitalocean_initial_attachment(
            workspace, intent, environment="prod", deployment_target="production",
            credential_repository=repository, transport=transport,
        )
    assert not transport.requests


def test_unsettled_membership_expires_at_bound(prepared):
    _, _, _, responses = prepared
    responses = copy.deepcopy(responses)
    responses["/droplets/101/firewalls?page=1&per_page=200"]["firewalls"] = []
    responses["/droplets/101/firewalls?page=1&per_page=200"]["meta"]["total"] = 0
    with pytest.raises(service.DigitalOceanAttachmentStillSettling, match="did not settle"):
        _run(prepared, responses=responses, max_attempts=2)


@pytest.mark.parametrize("slow", ["firewall", "inactive_node", "transport"])
def test_bounded_slow_provider_is_typed_still_settling(prepared, slow):
    _, intent, _, default_responses = prepared
    responses = copy.deepcopy(default_responses)
    if slow == "firewall":
        responses[f"/firewalls/{intent.firewall_id}"]["firewall"]["status"] = "waiting"
    elif slow == "inactive_node":
        responses["/droplets/101"]["droplet"]["status"] = "new"
    else:
        responses[f"/firewalls/{intent.firewall_id}"] = OSError("temporary transport failure")
    with pytest.raises(service.DigitalOceanAttachmentStillSettling, match="did not settle"):
        _run(prepared, responses=responses, max_attempts=2)


def _catalog_http_failure(status):
    cause = urllib.error.HTTPError(
        "https://api.digitalocean.com/v2/firewalls/fixture", status,
        "sensitive-provider-detail", {}, io.BytesIO(b"sensitive-response-body"),
    )
    try:
        raise ProviderCatalogError("sensitive-token-detail") from cause
    except ProviderCatalogError as exc:
        return exc


@pytest.mark.parametrize("status", [401, 403])
def test_provider_authorization_http_failure_is_hard_and_redacted(prepared, status):
    workspace, intent, repository, default_responses = prepared
    responses = copy.deepcopy(default_responses)
    responses[f"/firewalls/{intent.firewall_id}"] = _catalog_http_failure(status)
    transport = Transport(responses)
    with pytest.raises(service.DigitalOceanAttachmentError, match="credential was rejected") as failure:
        service.reconcile_digitalocean_initial_attachment(
            workspace, intent, environment="devtest", deployment_target="barragan-testing",
            credential_repository=repository, transport=transport, max_attempts=2,
            sleeper=lambda _seconds: None,
        )
    assert type(failure.value) is service.DigitalOceanAttachmentError
    assert "sensitive" not in str(failure.value)
    assert transport.attempt == 1


@pytest.mark.parametrize("status", [429, 500, 503])
def test_provider_throttle_or_server_http_failure_remains_settling(prepared, status):
    _, intent, _, default_responses = prepared
    responses = copy.deepcopy(default_responses)
    responses[f"/firewalls/{intent.firewall_id}"] = _catalog_http_failure(status)
    with pytest.raises(service.DigitalOceanAttachmentStillSettling, match="did not settle") as failure:
        _run(prepared, responses=responses, max_attempts=2)
    assert "sensitive" not in str(failure.value)


def test_state_hash_drift_rejected_before_provider_read(prepared):
    workspace, intent, repository, responses = prepared
    workspace.state_path.write_text("changed")
    transport = Transport(responses)
    with pytest.raises(service.DigitalOceanAttachmentError, match="reviewed state"):
        service.reconcile_digitalocean_initial_attachment(
            workspace, intent, environment="devtest", deployment_target="barragan-testing",
            credential_repository=repository, transport=transport,
        )
    assert not transport.requests
