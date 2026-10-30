# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline proof that mixed DigitalOcean inputs follow the applied core review."""

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.services.provider_keyed_mixed_linode_intent as linode_module
import app.services.provider_keyed_mixed_digitalocean_intent as digitalocean_module
from app.services.provider_keyed_mixed_digitalocean_intent import (
    MixedDigitalOceanIntentError, compile_mixed_digitalocean_initial_intent,
)
from app.services.provider_keyed_mixed_digitalocean_plan_gate import _LOCK_SHA256
from app.services.provider_keyed_initial_plan_gate import _SOURCE_REVISION, _SOURCE_SHA256
from app.services.provider_keyed_mixed_linode_intent import _digest
from app.services.sketch_ssh_keys import SketchSshKeyMaterial, SketchSshKeyMetadata, _fingerprint
from app.storage.credential_repository import StoredCredential
from test_provider_keyed_mixed_linode_intent import _records, PUBLIC_KEY, WRONG_PUBLIC_KEY


@pytest.fixture(autouse=True)
def durable_admin_key(monkeypatch):
    material = SketchSshKeyMaterial(
        SketchSshKeyMetadata("eng-opaque", "admin-private", "admin-public",
                             _fingerprint(PUBLIC_KEY), [], "now", "now"),
        "durable-private-key", PUBLIC_KEY,
    )
    monkeypatch.setattr(linode_module, "retrieve_sketch_ssh_key",
                        lambda engagement_id, repository: material)


def _mixed_records(*, linode_first=True, same_region=False):
    values = _records(linode_first=linode_first, same_region=same_region)
    plan = values["core_plan"]
    auth = plan.evidence["sketchAuthorization"]
    scope = auth["providerScopes"][0]
    scope.update({
        "image": "ubuntu-24-04-x64",
        "source": {"revision": _SOURCE_REVISION, "templateSha256": _SOURCE_SHA256,
                   "providerLock": {"path": "barragan-v2/.terraform.lock.hcl",
                                    "sha256": _LOCK_SHA256, "providerVersion": "2.103.0"}},
        "firewall": {
            "publicTcpPorts": ["80", "443", "2222"], "publicUdpPorts": [],
            "publicIpv6Allowed": False,
            "managementSsh": {"port": 22,
                              "sourceRule": "selected-proxy-public-ipv4-32",
                              "proxyNames": ["proxy01"]},
            "peerIngress": {"protocols": ["tcp", "udp", "icmp"],
                            "portRange": "1-65535",
                            "sourceRule": "all-created-provider-middle-and-edge-public-ipv4-32"},
            "outboundIpv4": [
                {"protocol": protocol, "portRange": "1-65535",
                 "destination": "0.0.0.0/0"} for protocol in ("tcp", "udp")
            ] + [{"protocol": "icmp", "destination": "0.0.0.0/0"}],
            "outboundIpv6": "not-configured",
        },
    })
    auth["fingerprint"] = _digest({key: value for key, value in auth.items()
                                   if key != "fingerprint"})
    plan.evidence["digitaloceanImage"] = scope["image"]
    plan.review["reviewedConfiguration"]["digitaloceanImage"] = scope["image"]
    do_credential = StoredCredential("cred-do", "digitalocean", "team", "active", "",
                                     "encrypted-do-test", True, "now", "now")
    linode_credential = values["credential_repository"].get("cred-linode")
    credentials = {item.id: item for item in (do_credential, linode_credential)}
    values["credential_repository"] = SimpleNamespace(
        get=lambda connection_id: credentials.get(connection_id),
        get_default=lambda provider: next((item for item in credentials.values()
                                           if item.provider == provider), None))
    plan.evidence["keyedProviderCredentialSnapshots"]["digitalocean"] = {
        "encryptedSecretSha256": hashlib.sha256(do_credential.encrypted_secret.encode()).hexdigest(),
        "updatedAt": do_credential.updated_at,
    }
    return values


def test_compiles_exact_one_chain_inputs_and_local_artifacts():
    values = _mixed_records()
    intent = compile_mixed_digitalocean_initial_intent(**values)
    selector = "s" + hashlib.sha256(values["engagement"].id.encode()).hexdigest()[:20]
    assert (intent.core_job_id, intent.core_plan_id, intent.review_fingerprint) == (
        "job-core", "plan-1", values["core_plan"].evidence["sketchAuthorization"]["fingerprint"])
    assert (intent.middle_key, intent.edge_key) == ("middle_02", "sfo3-01")
    assert intent.trusted_ssh_cidrs == ("8.8.8.8/32",)
    assert intent.admin_public_key == PUBLIC_KEY
    assert intent.ssh_key_name == "do-key"
    assert intent.selector_tag == selector
    assert intent.topology["regional_high_water"] == {"sfo3": 1, "us-west": 1}
    assert set(intent.nodes) == {
        'digitalocean_droplet.middle["middle_02"]',
        'digitalocean_droplet.edge["sfo3-01"]',
    }
    assert intent.nodes['digitalocean_droplet.middle["middle_02"]'].name == "middle02-opaque-fixture"
    assert intent.nodes['digitalocean_droplet.edge["sfo3-01"]'].name == "edge-opaque-fixture-sfo3-01"
    assert {node.firewall_selector_tag for node in intent.nodes.values()} == {selector}
    assert intent.firewall.trusted_ssh_cidrs == ("8.8.8.8/32",)
    assert intent.nonsecret_varfile["edge_groups"] == intent.topology["edge_groups"]
    assert intent.nonsecret_varfile["firewall_selector_tag"] == selector
    assert intent.nonsecret_varfile["allowed_tcp_ports"] == ["22", "80", "443", "2222"]
    local = intent.expected_local_files(Path("/safe/private"), Path("/safe/output"))
    assert set(local) == {"local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]"}
    assert "middle02-opaque-fixture\n" in local["local_file.ansible_inventory[0]"]["content"]
    assert "edge-opaque-fixture-sfo3-01\n" in local["local_file.ansible_inventory[0]"]["content"]
    assert local["local_file.ssh_stanza[0]"]["filename"] == "/safe/output/opaque-fixture-sketch"


@pytest.mark.parametrize("linode_first,middle,edge", [
    (False, "middle_01", "us-west-01"),
    (True, "middle_02", "us-west-02"),
])
def test_engagement_wide_ordinals_include_other_provider(linode_first, middle, edge):
    values = _mixed_records(linode_first=linode_first, same_region=True)
    intent = compile_mixed_digitalocean_initial_intent(**values)
    assert (intent.middle_key, intent.edge_key) == (middle, edge)
    assert intent.topology["regional_high_water"] == {"us-west": int(edge[-2:])}
    assert f'digitalocean_droplet.edge["{edge}"]' in intent.nodes


def test_rejects_selector_collision_with_engagement_tag(monkeypatch):
    values = _mixed_records()
    selector = "s" + hashlib.sha256(values["engagement"].id.encode()).hexdigest()[:20]
    monkeypatch.setattr(digitalocean_module, "pilot_names",
                        lambda name: SimpleNamespace(engagement_name=selector))
    with pytest.raises(MixedDigitalOceanIntentError):
        compile_mixed_digitalocean_initial_intent(**values)


@pytest.mark.parametrize("drift", [
    lambda v: v["core_plan"].evidence.update(digitaloceanImage="other-image"),
    lambda v: v["core_plan"].evidence["sketchAuthorization"]["providerScopes"][0]["source"].update(
        templateSha256="0" * 64),
    lambda v: v["core_plan"].evidence["sketchAuthorization"]["providerScopes"][0]["firewall"][
        "managementSsh"].update(proxyNames=["proxy02"]),
    lambda v: v["core_plan"].evidence["keyedProviderCredentialSnapshots"]["digitalocean"].update(
        updatedAt="old"),
    lambda v: v.update(expected_admin_public_key=WRONG_PUBLIC_KEY),
    lambda v: v["core_job"].events[0].data["connectionDetails"][0].update(publicIp="192.0.2.1"),
    lambda v: v["core_job"].input.update(pendingSketchChainIds=list(reversed(
        v["core_job"].input["pendingSketchChainIds"]))),
    lambda v: v["core_job"].input.update(target={}),
])
def test_stale_or_unreviewed_inputs_fail_closed(drift):
    values = _mixed_records()
    drift(values)
    auth = values["core_plan"].evidence["sketchAuthorization"]
    auth["fingerprint"] = _digest({key: value for key, value in auth.items()
                                   if key != "fingerprint"})
    with pytest.raises(MixedDigitalOceanIntentError):
        compile_mixed_digitalocean_initial_intent(**values)
