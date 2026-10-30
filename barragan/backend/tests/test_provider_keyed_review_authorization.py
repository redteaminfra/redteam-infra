# Copyright (c) 2026, Oracle and/or its affiliates.
"""The post-core plan cannot exceed the saved whole-infrastructure review."""

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.domain.deployment_plan import DeploymentPlan
import app.services.core_deployment_plans as core_review
from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_initial_plan_gate import DigitalOceanInitialFirewallIntent, DigitalOceanNodeCreate
from app.services.provider_keyed_persisted_intent import ProviderKeyedChainRoute, ProviderKeyedPersistedIntent
from app.services.provider_keyed_review_authorization import (
    ProviderKeyedReviewAuthorizationError,
    require_fresh_digitalocean_review_authorization,
)
from app.storage.credential_repository import StoredCredential


class Credentials:
    def __init__(self, credential):
        self.credential = credential

    def get(self, credential_id):
        return self.credential if credential_id == self.credential.id else None

    def get_default(self, provider):
        return self.credential if provider == "digitalocean" and self.credential.is_default else None


def _fixture():
    routes = (ProviderKeyedChainRoute("chain-a", "middle_01", "proxy01", ("sfo3-01",)),
              ProviderKeyedChainRoute("chain-b", "middle_02", "proxy02", ("sfo3-02",)))
    selector = "s12345678901234567890"
    nodes = {
        'digitalocean_droplet.middle["middle_01"]': DigitalOceanNodeCreate("middle01", "ubuntu-24-04-x64", "s-1vcpu-1gb", "nyc3", selector),
        'digitalocean_droplet.middle["middle_02"]': DigitalOceanNodeCreate("middle02", "ubuntu-24-04-x64", "s-1vcpu-1gb", "sea1", selector),
        'digitalocean_droplet.edge["sfo3-01"]': DigitalOceanNodeCreate("edge01", "ubuntu-24-04-x64", "s-1vcpu-1gb", "sfo3", selector),
        'digitalocean_droplet.edge["sfo3-02"]': DigitalOceanNodeCreate("edge02", "ubuntu-24-04-x64", "s-1vcpu-1gb", "sfo3", selector),
    }
    intent = ProviderKeyedPersistedIntent(
        "eng-opaque", "job-core", "plan-core", "revision-opaque", "digitalocean", "opaque",
        selector, {"proxy01": "8.8.8.8", "proxy02": "1.1.1.1"},
        {"middles": {"middle_01": {"region": "nyc3"}, "middle_02": {"region": "sea1"}}, "edge_groups": {}},
        routes, nodes,
        DigitalOceanInitialFirewallIntent("opaque-firewall", selector, ("80", "443", "2222"), (),
                                          ("1.1.1.1/32", "8.8.8.8/32")),
        {},
    )
    chains = [
        {"id": route.chain_id, "fingerprint": f"fingerprint-{index}",
         "assignedProxy": route.assigned_proxy,
         "middle": {"provider": "digitalocean", "region": nodes[f'digitalocean_droplet.middle["{route.middle_node}"]'].region,
                    "size": "s-1vcpu-1gb"},
         "edges": [{"id": "edge-01", "provider": "digitalocean", "region": "sfo3", "size": "s-1vcpu-1gb"}]}
        for index, route in enumerate(routes, 1)
    ]
    auth = {
        "kind": "bounded-post-core", "provider": "digitalocean", "providerConnectionId": "credential-opaque",
        "source": {"revision": "cae68e63b8495f0e6d31dfa4a991f4024f18e58b",
                   "templateSha256": "0fcadb0560b4f765ae521788e0d2db55cdba0147d6eacc5a933235ee23c98f60",
                   "providerLock": {"path": "barragan-v2/.terraform.lock.hcl",
                                    "sha256": "0e6a4207cca9db67bba23b918748e02c4d32c1c504e09bad54e5d37751d99736",
                                    "digitaloceanVersion": "2.103.0"}},
        "image": "ubuntu-24-04-x64", "chains": chains,
        "firewall": {"publicTcpPorts": ["80", "443", "2222"], "publicUdpPorts": [], "publicIpv6Allowed": False,
                     "managementSsh": {"port": 22, "sourceRule": "selected-proxy-public-ipv4-32", "proxyNames": ["proxy01", "proxy02"]},
                     "peerIngress": {"protocols": ["tcp", "udp", "icmp"], "portRange": "1-65535",
                                     "sourceRule": "all-created-middle-and-edge-public-ipv4-32"},
                     "outboundIpv4": [{"protocol": protocol, "portRange": "1-65535", "destination": "0.0.0.0/0"}
                                       for protocol in ("tcp", "udp")]
                     + [{"protocol": "icmp", "destination": "0.0.0.0/0"}]},
    }
    auth["fingerprint"] = hashlib.sha256(json.dumps(auth, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    secret = "ENCRYPTED-FIXTURE"
    credential = StoredCredential("credential-opaque", "digitalocean", "team", "active", "", secret, True, "", "2026-10-07T00:00:00Z")
    evidence = {"sketchAuthorization": auth, "sketchStateSchema": "provider-keyed-v2",
                "digitaloceanImage": "ubuntu-24-04-x64",
                "pendingSketchChainIds": ["chain-a", "chain-b"],
                "pendingSketchChainFingerprints": {"chain-a": "fingerprint-1", "chain-b": "fingerprint-2"},
                "keyedProviderCredentialSnapshot": {
                    "encryptedSecretSha256": hashlib.sha256(secret.encode()).hexdigest(),
                    "updatedAt": credential.updated_at}}
    plan = DeploymentPlan("plan-core", "eng-opaque", "revision-opaque", "applied", "applied",
                          review={"reviewedConfiguration": {"sketchAuthorization": auth,
                                                            "digitaloceanImage": "ubuntu-24-04-x64"},
                                  "sketchStateSchema": "provider-keyed-v2"},
                          evidence=evidence)
    return intent, plan, Credentials(credential)


def _check(intent, plan, credentials, connection_id="credential-opaque"):
    require_fresh_digitalocean_review_authorization(
        intent, plan, connection_id=connection_id, credential_repository=credentials)


def test_matching_persisted_intent_and_saved_review_pass():
    _check(*_fixture())


def test_real_core_review_builder_is_accepted_by_plan_gate(monkeypatch):
    """Exercise the two real schema implementations without cloud or Terraform."""
    intent, plan, credentials = _fixture()
    records = []
    scope_chains = []
    for route in intent.chain_routes:
        middle = intent.nodes[f'digitalocean_droplet.middle["{route.middle_node}"]']
        edges = [
            {"id": f"edge-{index:02d}", "provider": "digitalocean",
             "region": intent.nodes[f'digitalocean_droplet.edge["{key}"]'].region,
             "size": intent.nodes[f'digitalocean_droplet.edge["{key}"]'].size}
            for index, key in enumerate(route.edge_nodes, 1)
        ]
        records.append(SimpleNamespace(
            chain_id=route.chain_id, status="pending", assigned_proxy=route.assigned_proxy,
            middle_provider="digitalocean", middle_region=middle.region, middle_size=middle.size,
            edge_provider="digitalocean", edge_region=edges[0]["region"],
            edge_size=edges[0]["size"], edge_count=len(edges), edge_intents=edges,
        ))
        scope_chains.append({
            "id": route.chain_id, "assignedProxy": route.assigned_proxy,
            "middle": {"region": middle.region},
            "edges": [{key: edge[key] for key in ("id", "provider", "region")}
                      for edge in edges],
        })
    fingerprints = {record.chain_id: sketch_chain_intent_fingerprint(record) for record in records}
    monkeypatch.setattr(core_review, "SqlAlchemySketchChainRepository",
                        lambda: SimpleNamespace(list_for_engagement=lambda _engagement: records))
    monkeypatch.setattr("app.services.provider_keyed_sketch.resolve_default_provider_connection",
                        lambda _provider: credentials.credential.id)
    authorization = core_review._reviewed_keyed_sketch_authorization(
        intent.engagement_id, {"chains": scope_chains}, fingerprints, "ubuntu-24-04-x64")
    plan = replace(
        plan,
        review={**plan.review, "reviewedConfiguration": {
            **plan.review["reviewedConfiguration"], "sketchAuthorization": authorization}},
        evidence={**plan.evidence, "sketchAuthorization": authorization,
                  "pendingSketchChainFingerprints": fingerprints},
    )
    _check(intent, plan, credentials)


@pytest.mark.parametrize("drift", [
    "missing_review", "missing_evidence", "chain_order", "chain_fingerprint", "proxy",
    "middle_region", "edge_size", "image", "public_port", "ssh_source", "peer_policy",
    "source_revision", "template_hash", "lock_hash", "provider_version", "auth_fingerprint",
    "credential_rotation", "credential_default", "credential_switch", "missing_credential_snapshot",
])
def test_review_gate_rejects_drift(drift):
    intent, plan, credentials = _fixture()
    evidence = json.loads(json.dumps(plan.evidence))
    review = json.loads(json.dumps(plan.review))
    auth = evidence["sketchAuthorization"]
    if drift == "missing_review":
        review["reviewedConfiguration"].pop("sketchAuthorization")
    elif drift == "missing_evidence":
        evidence.pop("sketchAuthorization")
    elif drift == "chain_order":
        auth["chains"].reverse()
    elif drift == "chain_fingerprint":
        evidence["pendingSketchChainFingerprints"]["chain-a"] = "different"
    elif drift == "proxy":
        intent = replace(intent, chain_routes=(replace(intent.chain_routes[0], assigned_proxy="proxy02"), intent.chain_routes[1]))
    elif drift == "middle_region":
        intent.nodes['digitalocean_droplet.middle["middle_01"]'] = replace(
            intent.nodes['digitalocean_droplet.middle["middle_01"]'], region="sfo3")
    elif drift == "edge_size":
        intent.nodes['digitalocean_droplet.edge["sfo3-01"]'] = replace(
            intent.nodes['digitalocean_droplet.edge["sfo3-01"]'], size="s-2vcpu-2gb")
    elif drift == "image":
        intent.nodes['digitalocean_droplet.edge["sfo3-01"]'] = replace(
            intent.nodes['digitalocean_droplet.edge["sfo3-01"]'], image="ubuntu-20-04-x64")
    elif drift == "public_port":
        auth["firewall"]["publicTcpPorts"].append("8080")
    elif drift == "ssh_source":
        intent = replace(intent, firewall=replace(intent.firewall, trusted_ssh_cidrs=("0.0.0.0/0",)))
    elif drift == "peer_policy":
        auth["firewall"]["peerIngress"]["sourceRule"] = "any"
    elif drift == "source_revision":
        auth["source"]["revision"] = "other"
    elif drift == "template_hash":
        auth["source"]["templateSha256"] = "other"
    elif drift == "lock_hash":
        auth["source"]["providerLock"]["sha256"] = "other"
    elif drift == "provider_version":
        auth["source"]["providerLock"]["digitaloceanVersion"] = "other"
    elif drift == "auth_fingerprint":
        auth["fingerprint"] = "other"
    elif drift == "credential_rotation":
        credentials.credential = replace(credentials.credential, encrypted_secret="ROTATED")
    elif drift == "credential_default":
        credentials.credential = replace(credentials.credential, is_default=False)
    elif drift == "credential_switch":
        with pytest.raises(ProviderKeyedReviewAuthorizationError):
            _check(intent, plan, credentials, "credential-other")
        return
    elif drift == "missing_credential_snapshot":
        evidence.pop("keyedProviderCredentialSnapshot")
    plan = replace(plan, review=review, evidence=evidence)
    with pytest.raises(ProviderKeyedReviewAuthorizationError):
        _check(intent, plan, credentials)
