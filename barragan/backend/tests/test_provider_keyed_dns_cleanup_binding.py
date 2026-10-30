# Copyright (c) 2026, Oracle and/or its affiliates.
"""Sealed, read-only edge identity for later keyed DNS cleanup."""

from copy import deepcopy
from dataclasses import FrozenInstanceError

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_dns_cleanup_binding import (
    ProviderKeyedDnsCleanupBindingError, bind_provider_keyed_dns_cleanup_targets,
)
from app.services.provider_keyed_host_binding import _digest_json


def _fixture():
    fingerprints = {"chain-a": "a" * 64, "chain-b": "b" * 64}
    resources = [
        {"address": 'digitalocean_droplet.edge["sea-01"]', "id": "101", "kind": "droplet"},
        {"address": 'digitalocean_droplet.edge["sea-02"]', "id": "102", "kind": "droplet"},
        {"address": 'digitalocean_droplet.middle["sea-01"]', "id": "201", "kind": "droplet"},
        {"address": 'digitalocean_droplet.middle["sea-02"]', "id": "202", "kind": "droplet"},
        {"address": "digitalocean_firewall.firewall", "id": "f-1", "kind": "firewall"},
    ]
    scope = {
        "schema": "provider-keyed-v2", "provider": "digitalocean",
        "coreJobId": "job-core", "corePlanId": "plan-1", "revisionId": "rev-1",
        "stateSha256": "c" * 64, "sourceRevision": "source-1",
        "providerConnectionId": "connection-1", "chainIds": list(fingerprints),
        "chainFingerprints": fingerprints, "resources": resources,
    }
    manifest = {
        "schema": "provider-keyed-v2", "engagementId": "eng-1",
        **{key: scope[key] for key in (
            "coreJobId", "corePlanId", "revisionId", "stateSha256",
            "sourceRevision", "providerConnectionId")},
        "chainFingerprints": [{"chainId": chain, "fingerprint": fingerprint}
                              for chain, fingerprint in fingerprints.items()],
        "nodes": [
            {"terraformAddress": resources[0]["address"], "providerInstanceId": "101",
             "role": "edge", "chainId": "chain-a", "publicIp": "8.8.8.8"},
            {"terraformAddress": resources[1]["address"], "providerInstanceId": "102",
             "role": "edge", "chainId": "chain-b", "publicIp": "1.1.1.1"},
            {"terraformAddress": resources[2]["address"], "providerInstanceId": "201",
             "role": "middle", "chainId": "chain-a", "publicIp": "9.9.9.9"},
            {"terraformAddress": resources[3]["address"], "providerInstanceId": "202",
             "role": "middle", "chainId": "chain-b", "publicIp": "4.4.4.4"},
        ],
    }
    return scope, manifest


def _bind(scope, manifest, *, digest=None, bound_data=None):
    intent = JobEvent(1, "info", "provider host identity binding intended", manifest)
    bound = JobEvent(2, "info", "provider host identity bound", bound_data or {
        "manifestSha256": _digest_json(manifest), "hostProofPending": True,
    })
    return bind_provider_keyed_dns_cleanup_targets(
        "eng-1", confirmed_scope=scope,
        provider_scope_sha256=digest or _digest_json({"providerScopes": [scope]}),
        host_binding_intent_event=intent, host_binding_bound_event=bound,
    )


def test_binding_returns_sorted_immutable_redacted_digest_and_does_not_mutate_input():
    scope, manifest = _fixture()
    original = deepcopy((scope, manifest))
    binding = _bind(scope, manifest)
    assert binding.edge_public_ips == ("1.1.1.1", "8.8.8.8")
    assert len(binding.binding_sha256) == 64
    assert binding.manifest_sha256 == _digest_json(manifest)
    assert binding == _bind(scope, manifest)
    assert (scope, manifest) == original
    with pytest.raises(FrozenInstanceError):
        binding.edge_public_ips = ()
    assert "connection-1" not in repr(binding)
    assert "201" not in repr(binding)


@pytest.mark.parametrize("mutation", [
    "missing_edge", "extra_edge", "duplicate_address", "duplicate_id", "duplicate_ip",
    "wrong_id", "wrong_role", "private_ip", "ipv6", "noncanonical_ip", "wrong_chain",
    "scope_duplicate_id", "scope_duplicate_address", "unexpected_droplet",
])
def test_edge_inventory_ambiguity_fails_closed(mutation):
    scope, manifest = _fixture()
    nodes = manifest["nodes"]
    if mutation == "missing_edge":
        nodes.pop(0)
    elif mutation == "extra_edge":
        nodes.append({**nodes[0], "terraformAddress": 'digitalocean_droplet.edge["nyc-01"]',
                      "providerInstanceId": "103"})
    elif mutation == "duplicate_address":
        nodes.append({**nodes[0], "providerInstanceId": "103"})
    elif mutation == "duplicate_id":
        nodes[1]["providerInstanceId"] = nodes[0]["providerInstanceId"]
    elif mutation == "duplicate_ip":
        nodes[1]["publicIp"] = nodes[0]["publicIp"]
    elif mutation == "wrong_id":
        nodes[0]["providerInstanceId"] = "999"
    elif mutation == "wrong_role":
        nodes[0]["role"] = "middle"
    elif mutation == "private_ip":
        nodes[0]["publicIp"] = "192.168.1.1"
    elif mutation == "ipv6":
        nodes[0]["publicIp"] = "2606:4700:4700::1111"
    elif mutation == "noncanonical_ip":
        nodes[0]["publicIp"] = "008.008.008.008"
    elif mutation == "wrong_chain":
        nodes[0]["chainId"] = "foreign"
    elif mutation == "scope_duplicate_id":
        scope["resources"][1]["id"] = scope["resources"][0]["id"]
    elif mutation == "scope_duplicate_address":
        scope["resources"][1]["address"] = scope["resources"][0]["address"]
    else:
        scope["resources"][0]["address"] = 'digitalocean_droplet.other["sea-01"]'
    with pytest.raises(ProviderKeyedDnsCleanupBindingError):
        _bind(scope, manifest)


@pytest.mark.parametrize("key", [
    "coreJobId", "corePlanId", "revisionId", "stateSha256", "sourceRevision",
    "providerConnectionId", "chainFingerprints", "engagementId",
])
def test_sealed_context_drift_fails_closed(key):
    scope, manifest = _fixture()
    manifest[key] = "changed" if key != "chainFingerprints" else []
    with pytest.raises(ProviderKeyedDnsCleanupBindingError):
        _bind(scope, manifest)


def test_stale_scope_digest_or_binding_event_digest_fails_closed():
    scope, manifest = _fixture()
    with pytest.raises(ProviderKeyedDnsCleanupBindingError):
        _bind(scope, manifest, digest="0" * 64)
    with pytest.raises(ProviderKeyedDnsCleanupBindingError):
        _bind(scope, manifest, bound_data={"manifestSha256": "0" * 64,
                                          "hostProofPending": True})
