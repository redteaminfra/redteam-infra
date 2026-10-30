# Copyright (c) 2026, Oracle and/or its affiliates.
"""Compare fresh provider intent with the operator's saved Sketch review.

This gate runs before a provider workspace exists. It does not authorize a
Terraform apply; the exact saved plan still needs its independent plan gate.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from app.domain.deployment_plan import DeploymentPlan
from app.services.core_deployment_plans import KEYED_DIGITALOCEAN_LOCK_SHA256
from app.services.provider_keyed_initial_plan_gate import _SOURCE_REVISION, _SOURCE_SHA256
from app.services.provider_keyed_persisted_intent import ProviderKeyedPersistedIntent
from app.storage.credential_repository import CredentialRepository


class ProviderKeyedReviewAuthorizationError(ValueError):
    """The current provider intent is outside the saved operator review."""


def require_fresh_digitalocean_review_authorization(
    intent: ProviderKeyedPersistedIntent,
    core_plan: DeploymentPlan | None,
    *,
    connection_id: str,
    credential_repository: CredentialRepository,
) -> None:
    """Fail closed on any reviewed intent, source, policy, or secret drift."""

    def reject() -> None:
        raise ProviderKeyedReviewAuthorizationError("provider intent differs from reviewed Sketch authorization")

    if (not isinstance(intent, ProviderKeyedPersistedIntent)
            or not isinstance(core_plan, DeploymentPlan)
            or core_plan.id != intent.core_plan_id
            or core_plan.engagement_id != intent.engagement_id
            or core_plan.revision_id != intent.revision_id
            or core_plan.status != "applied"
            or not isinstance(core_plan.review, Mapping)
            or not isinstance(core_plan.evidence, Mapping)
            or not isinstance(connection_id, str) or not connection_id):
        reject()
    evidence = core_plan.evidence
    reviewed = core_plan.review.get("reviewedConfiguration")
    authorization = evidence.get("sketchAuthorization")
    if (not isinstance(reviewed, Mapping) or not isinstance(authorization, dict)
            or reviewed.get("sketchAuthorization") != authorization
            or evidence.get("sketchStateSchema") != "provider-keyed-v2"
            or core_plan.review.get("sketchStateSchema") != "provider-keyed-v2"
            or evidence.get("digitaloceanImage") != authorization.get("image")
            or reviewed.get("digitaloceanImage") != authorization.get("image")
            or authorization.get("providerConnectionId") != connection_id):
        reject()
    routes = intent.chain_routes
    identifiers = [route.chain_id for route in routes]
    fingerprints = evidence.get("pendingSketchChainFingerprints")
    if (len(routes) != 2 or len(set(identifiers)) != 2
            or evidence.get("pendingSketchChainIds") != identifiers
            or not isinstance(fingerprints, dict) or set(fingerprints) != set(identifiers)
            or any(not isinstance(fingerprints[key], str) or not fingerprints[key] for key in identifiers)):
        reject()
    chains: list[dict[str, Any]] = []
    for route in routes:
        middle = intent.topology.get("middles", {}).get(route.middle_node)
        middle_node = intent.nodes.get(f'digitalocean_droplet.middle["{route.middle_node}"]')
        if not isinstance(middle, Mapping) or middle_node is None or middle_node.region != middle.get("region"):
            reject()
        edges: list[dict[str, str]] = []
        for ordinal, edge_key in enumerate(route.edge_nodes, 1):
            node = intent.nodes.get(f'digitalocean_droplet.edge["{edge_key}"]')
            if node is None:
                reject()
            edges.append({"id": f"edge-{ordinal:02d}", "provider": "digitalocean",
                          "region": node.region, "size": node.size})
        chains.append({
            "id": route.chain_id, "fingerprint": fingerprints[route.chain_id],
            "assignedProxy": route.assigned_proxy,
            "middle": {"provider": "digitalocean", "region": middle_node.region,
                       "size": middle_node.size},
            "edges": edges,
        })
    proxy_names = sorted({route.assigned_proxy for route in routes})
    if set(intent.proxy_egress_ips) != set(proxy_names):
        reject()
    expected_sources = tuple(sorted(f"{intent.proxy_egress_ips[name]}/32" for name in proxy_names))
    if (intent.provider != "digitalocean"
            or intent.firewall.public_tcp_ports != ("80", "443", "2222")
            or intent.firewall.public_udp_ports != ()
            or intent.firewall.peer_cidrs != ()
            or intent.firewall.trusted_ssh_cidrs != expected_sources
            or any(node.image != authorization.get("image") for node in intent.nodes.values())):
        reject()
    expected = {
        "kind": "bounded-post-core", "provider": "digitalocean",
        "providerConnectionId": connection_id,
        "source": {
            "revision": _SOURCE_REVISION, "templateSha256": _SOURCE_SHA256,
            "providerLock": {"path": "barragan-v2/.terraform.lock.hcl",
                             "sha256": KEYED_DIGITALOCEAN_LOCK_SHA256,
                             "digitaloceanVersion": "2.103.0"},
        },
        "image": authorization.get("image"), "chains": chains,
        "firewall": {
            "publicTcpPorts": ["80", "443", "2222"], "publicUdpPorts": [],
            "publicIpv6Allowed": False,
            "managementSsh": {"port": 22, "sourceRule": "selected-proxy-public-ipv4-32",
                              "proxyNames": proxy_names},
            "peerIngress": {"protocols": ["tcp", "udp", "icmp"], "portRange": "1-65535",
                            "sourceRule": "all-created-middle-and-edge-public-ipv4-32"},
            "outboundIpv4": [
                {"protocol": protocol, "portRange": "1-65535", "destination": "0.0.0.0/0"}
                for protocol in ("tcp", "udp")
            ] + [{"protocol": "icmp", "destination": "0.0.0.0/0"}],
        },
    }
    expected["fingerprint"] = hashlib.sha256(
        json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if authorization != expected:
        reject()
    snapshot = evidence.get("keyedProviderCredentialSnapshot")
    credential = credential_repository.get(connection_id)
    default = credential_repository.get_default("digitalocean")
    if (not isinstance(snapshot, dict) or set(snapshot) != {"encryptedSecretSha256", "updatedAt"}
            or credential is None or default is None
            or credential.id != connection_id or default.id != connection_id
            or credential.provider != "digitalocean" or default.provider != "digitalocean"
            or credential.status != "active" or default.status != "active"
            or credential.is_default is not True or default.is_default is not True
            or not isinstance(credential.encrypted_secret, str) or not credential.encrypted_secret
            or credential.encrypted_secret != default.encrypted_secret
            or credential.updated_at != default.updated_at
            or snapshot != {
                "encryptedSecretSha256": hashlib.sha256(credential.encrypted_secret.encode()).hexdigest(),
                "updatedAt": credential.updated_at,
            }):
        reject()
