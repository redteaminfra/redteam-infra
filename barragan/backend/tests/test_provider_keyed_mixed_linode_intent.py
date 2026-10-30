# Copyright (c) 2026, Oracle and/or its affiliates.
"""Mixed Linode intent comes from durable applied core and pending chain records."""

import copy
import hashlib
from dataclasses import replace
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.domain import JobEvent
from app.integrations.oci_deployment_targets import BARRAGAN_TESTING_TARGET
from app.domain.deployment_plan import DeploymentPlan
from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_linode_initial_plan_gate import (
    _SOURCE_REVISION, _SOURCE_SHA256, _LOCK_SHA256,
)
from app.services.sketch_ssh_keys import SketchSshKeyMaterial, SketchSshKeyMetadata, _fingerprint
import app.services.provider_keyed_mixed_linode_intent as intent_module
from app.services.provider_keyed_mixed_linode_intent import (
    MixedLinodeIntentError, _digest, compile_mixed_linode_initial_intent,
)
from app.storage.credential_repository import StoredCredential
from app.storage.engagement_repository import StoredEngagement
from app.storage.job_repository import StoredJobRun
from app.storage.sketch_chain_repository import StoredSketchChain


def _chain(chain_id, provider, middle_region, edge_region):
    return StoredSketchChain(
        chain_id, "eng-opaque", "proxy01", provider, middle_region,
        "g6-nanode-1" if provider == "linode" else "s-1vcpu-1gb",
        provider, edge_region,
        "g6-nanode-1" if provider == "linode" else "s-1vcpu-1gb",
        "pending", False, "", "", "", "", [], "now", "now",
        edge_count=1, edge_intents=[{"id": "edge-01", "provider": provider,
                                    "region": edge_region,
                                    "size": "g6-nanode-1" if provider == "linode" else "s-1vcpu-1gb"}],
    )


def _valid_public(seed):
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()


PUBLIC_KEY = _valid_public(bytes(range(32)))
WRONG_PUBLIC_KEY = _valid_public(bytes(range(1, 33)))


@pytest.fixture(autouse=True)
def durable_admin_key(monkeypatch):
    material = SketchSshKeyMaterial(
        SketchSshKeyMetadata("eng-opaque", "admin-private", "admin-public",
                             _fingerprint(PUBLIC_KEY), [], "now", "now"),
        "durable-private-key", PUBLIC_KEY,
    )
    monkeypatch.setattr(intent_module, "retrieve_sketch_ssh_key",
                        lambda engagement_id, repository: material)


def _records(linode_first=True, same_region=False):
    linode = _chain("chain-linode", "linode", "us-east", "us-west")
    digitalocean = _chain("chain-do", "digitalocean", "nyc3",
                          "us-west" if same_region else "sfo3")
    chains = [linode, digitalocean] if linode_first else [digitalocean, linode]
    ids = [chain.chain_id for chain in chains]
    fingerprints = {chain.chain_id: sketch_chain_intent_fingerprint(chain) for chain in chains}
    auth = {"kind": "bounded-mixed-post-core-v1", "providerScopes": [
        {"provider": "digitalocean", "providerConnectionId": "cred-do",
         "chain": {"id": digitalocean.chain_id,
                   "fingerprint": fingerprints[digitalocean.chain_id],
                   "assignedProxy": "proxy01",
                   "middle": {"provider": "digitalocean", "region": "nyc3",
                              "size": "s-1vcpu-1gb"},
                   "edges": [{"id": "edge-01", "provider": "digitalocean",
                              "region": digitalocean.edge_region, "size": "s-1vcpu-1gb"}]}},
        {"provider": "linode", "providerConnectionId": "cred-linode",
         "image": "linode/ubuntu24.04",
         "firewall": {"publicTcpPorts": ["80", "443", "2222"], "publicUdpPorts": [],
                      "publicIpv6Allowed": False,
                      "managementSsh": {"port": 22,
                                        "sourceRule": "selected-proxy-public-ipv4-32",
                                        "proxyNames": ["proxy01"]},
                      "peerIngress": {"protocols": ["tcp", "udp", "icmp"],
                                      "portRange": "1-65535",
                                      "sourceRule": "all-created-provider-middle-and-edge-public-ipv4-32"},
                      "outboundIpv4": "accept", "outboundIpv6": "drop"},
         "source": {"revision": _SOURCE_REVISION, "templateSha256": _SOURCE_SHA256,
                    "providerLock": {"path": "barragan-v2/.terraform.lock.hcl",
                                     "sha256": _LOCK_SHA256, "providerVersion": "4.5.0"}},
         "chain": {"id": linode.chain_id, "fingerprint": fingerprints[linode.chain_id],
                   "assignedProxy": "proxy01",
                   "middle": {"provider": "linode", "region": "us-east", "size": "g6-nanode-1"},
                   "edges": [{"id": "edge-01", "provider": "linode", "region": "us-west",
                              "size": "g6-nanode-1"}]}}]}
    auth["fingerprint"] = _digest(auth)
    target = BARRAGAN_TESTING_TARGET.to_dict()
    core_target = {"name": target["name"], "region": target["region"],
                   "compartmentId": target["compartmentId"], "auth": target["auth"]}
    engagement = StoredEngagement("eng-opaque", "opaque-fixture", "deployed", "owner",
                                  "standard-rti", "rev-1", {"deploymentTarget": target},
                                  sketch_state_schema="provider-keyed-v2")
    job = StoredJobRun("job-core", "pilot_standard_rti_guarded_execute", "succeeded",
                       "oci-compartment:barragan-testing", "oci_compartment", target["compartmentId"],
                       "owner", {"engagementId": engagement.id, "engagementName": engagement.name,
                                 "sketchStateSchema": "provider-keyed-v2",
                                 "postCoreSketchContinuationEligible": False,
                                 "corePlanId": "plan-1", "target": core_target,
                                 "pendingSketchChainIds": ids,
                                 "pendingSketchChainFingerprints": fingerprints},
                       [], "now", "now", "now", [JobEvent(1, "info", "core ready", {
                           "connectionDetails": [{"role": "proxy", "displayName": "proxy01-opaque-fixture",
                                                  "sshAlias": "proxy01-opaque-fixture",
                                                  "publicIp": "8.8.8.8"}]})])
    credential = StoredCredential("cred-linode", "linode", "team", "active", "",
                                  "encrypted-test", True, "now", "now")
    snapshot = {"encryptedSecretSha256": hashlib.sha256(credential.encrypted_secret.encode()).hexdigest(),
                "updatedAt": credential.updated_at}
    plan = DeploymentPlan("plan-1", engagement.id, "rev-1", "applied", "core",
                          review={"reviewedConfiguration": {"sketchAuthorization": auth,
                                                             "linodeImage": "linode/ubuntu24.04"}},
                          evidence={"sketchAuthorization": auth, "linodeImage": "linode/ubuntu24.04",
                                    "target": core_target,
                                    "pendingSketchChainIds": ids,
                                    "pendingSketchChainFingerprints": fingerprints,
                                    "keyedProviderCredentialSnapshots": {"digitalocean": {},
                                                                          "linode": snapshot}},
                          apply_job_id=job.id)
    repo = SimpleNamespace(get=lambda connection_id: credential if connection_id == credential.id else None,
                           get_default=lambda provider: credential if provider == "linode" else None)
    jobs = SimpleNamespace(get=lambda job_id: job if job_id == job.id else None,
                           list=lambda: [job], list_for_engagement=lambda _: [job])
    return {"engagement": engagement, "chains": chains, "core_job": job,
            "core_plan": plan, "job_repository": jobs, "credential_repository": repo,
            "ssh_key_repository": SimpleNamespace(),
            "expected_admin_public_key": PUBLIC_KEY, "environment": "devtest"}


def test_derives_reviewed_one_chain_and_engagement_ordinals():
    for first, ordinal in ((True, 1), (False, 2)):
        values = _records(first)
        intent = compile_mixed_linode_initial_intent(**values)
        assert intent.middle_key == f"middle_{ordinal:02d}"
        assert intent.edge_key == "us-west-01"
        assert intent.trusted_ssh_cidrs == ("8.8.8.8/32",)
        assert set(intent.nodes) == {
            f'linode_instance.middle["middle_{ordinal:02d}"]',
            'linode_instance.edge["us-west-01"]',
        }
        assert intent.nonsecret_varfile["edge_groups"] == intent.topology["edge_groups"]
        assert intent.nonsecret_varfile["allowed_udp_ports"] == []


def _wrong_compartment(values):
    job = replace(values["core_job"], target_id="wrong-compartment")
    values["core_job"] = job
    values["job_repository"] = SimpleNamespace(get=lambda _: job, list=lambda: [job], list_for_engagement=lambda _: [job])


def _missing_reviewed_linode_firewall(values):
    values["core_plan"].evidence["sketchAuthorization"]["providerScopes"][1].pop("firewall")


@pytest.mark.parametrize("drift", [
    lambda v: v.update(job_repository=SimpleNamespace(get=lambda _: None, list=lambda: [])),
    lambda v: v.update(expected_admin_public_key=WRONG_PUBLIC_KEY),
    lambda v: v["core_plan"].evidence.update(linodeImage="linode/ubuntu22.04"),
    _wrong_compartment,
    lambda v: v["core_plan"].evidence["sketchAuthorization"]["providerScopes"][1]["source"].update(
        templateSha256="0" * 64),
    _missing_reviewed_linode_firewall,
    lambda v: v["core_job"].events[0].data["connectionDetails"][0].update(publicIp="192.0.2.1"),
    lambda v: v["chains"][0].edge_intents[0].update(region="other"),
    lambda v: v["core_job"].input.update(pendingSketchChainIds=list(reversed(
        v["core_job"].input["pendingSketchChainIds"]))),
    lambda v: v["core_plan"].evidence["keyedProviderCredentialSnapshots"]["linode"].update(updatedAt="old"),
])
def test_rejects_stale_core_proxy_chain_or_credential(drift):
    values = _records()
    drift(values)
    auth = values["core_plan"].evidence["sketchAuthorization"]
    auth["fingerprint"] = _digest({key: value for key, value in auth.items()
                                   if key != "fingerprint"})
    with pytest.raises(MixedLinodeIntentError):
        compile_mixed_linode_initial_intent(**values)


def test_same_region_second_provider_uses_engagement_edge_02():
    values = _records(linode_first=False, same_region=True)
    intent = compile_mixed_linode_initial_intent(**values)
    assert intent.middle_key == "middle_02"
    assert intent.edge_key == "us-west-02"
    assert intent.topology["regional_high_water"] == {"us-west": 2}
    assert 'linode_instance.edge["us-west-02"]' in intent.nodes
