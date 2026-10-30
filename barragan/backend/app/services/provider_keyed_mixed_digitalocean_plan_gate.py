# Copyright (c) 2026, Oracle and/or its affiliates.
"""Reviewed mixed-scope wrapper for one keyed DigitalOcean initial saved plan.

Pure validation only. The caller must read the authorization from the reviewed
core plan, derive node labels/ordinals, selector, trusted proxy /32, durable
admin key and local artifacts from reviewed/core records, and bind JSON to the
saved binary plan SHA. This module does not run Terraform or authorize Apply.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Mapping

from app.services.provider_keyed_initial_plan_gate import (
    DigitalOceanInitialFirewallIntent, DigitalOceanNodeCreate,
    _SOURCE_REVISION, _SOURCE_SHA256,
    require_digitalocean_keyed_initial_full_plan,
)
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.terraform_plan_gate import TerraformPlanGateError

_LOCK_SHA256 = "0e6a4207cca9db67bba23b918748e02c4d32c1c504e09bad54e5d37751d99736"
_EDGE = re.compile(r'^digitalocean_droplet\.edge\["[a-z0-9-]+-[0-9]{2}"\]$')


def _reject() -> None:
    raise TerraformPlanGateError("DigitalOcean initial plan differs from reviewed mixed scope")


def require_mixed_digitalocean_keyed_initial_plan(
    saved_plan_json: str, *, workspace: ProviderKeyedWorkspace,
    reviewed_authorization: Mapping[str, object],
    expected_nodes: Mapping[str, DigitalOceanNodeCreate],
    expected_ssh_key_name: str, expected_ssh_public_key: str,
    expected_firewall: DigitalOceanInitialFirewallIntent,
    expected_middle_ordinal: int, expected_edge_ordinal: int,
    expected_local_files: Mapping[str, Mapping[str, object]],
) -> None:
    """Check one DO middle/edge against the reviewed two-provider authorization."""
    auth = reviewed_authorization
    if (not isinstance(auth, Mapping) or auth.get("kind") != "bounded-mixed-post-core-v1"
            or not isinstance(auth.get("providerScopes"), list)
            or len(auth["providerScopes"]) != 2
            or not all(isinstance(row, dict) for row in auth["providerScopes"])
            or [row.get("provider") for row in auth["providerScopes"]] != ["digitalocean", "linode"]
            or auth.get("fingerprint") != hashlib.sha256(json.dumps(
                {key: value for key, value in auth.items() if key != "fingerprint"},
                sort_keys=True, separators=(",", ":")).encode()).hexdigest()):
        _reject()
    if (type(expected_middle_ordinal) is not int or expected_middle_ordinal not in (1, 2)
            or type(expected_edge_ordinal) is not int or expected_edge_ordinal < 1):
        _reject()
    middle_address = f'digitalocean_droplet.middle["middle_{expected_middle_ordinal:02d}"]'
    scope = auth["providerScopes"][0]
    source = scope.get("source")
    chain = scope.get("chain")
    policy = scope.get("firewall")
    if (not isinstance(workspace, ProviderKeyedWorkspace)
            or scope.get("providerConnectionId") != workspace.provider_connection_id
            or source != {"revision": _SOURCE_REVISION, "templateSha256": _SOURCE_SHA256,
                          "providerLock": {"path": "barragan-v2/.terraform.lock.hcl",
                                           "sha256": _LOCK_SHA256, "providerVersion": "2.103.0"}}
            or not isinstance(chain, dict) or not isinstance(policy, dict)
            or not isinstance(expected_nodes, Mapping) or len(expected_nodes) != 2
            or middle_address not in expected_nodes
            or len([key for key in expected_nodes if _EDGE.fullmatch(key)]) != 1
            or not all(isinstance(node, DigitalOceanNodeCreate)
                       for node in expected_nodes.values())
            or not isinstance(expected_firewall, DigitalOceanInitialFirewallIntent)):
        _reject()
    middle = expected_nodes[middle_address]
    edge_address, edge = next((key, node) for key, node in expected_nodes.items()
                              if _EDGE.fullmatch(key))
    if (not isinstance(edge.region, str)
            or edge_address != f'digitalocean_droplet.edge["{edge.region.lower()}-{expected_edge_ordinal:02d}"]'
            or middle.name != f"middle{expected_middle_ordinal:02d}-{expected_firewall.name.removesuffix('-firewall')}"
            or edge.name != f"edge-{expected_firewall.name.removesuffix('-firewall')}-{edge.region}-{expected_edge_ordinal:02d}"):
        _reject()
    if (set(chain) != {"id", "fingerprint", "assignedProxy", "middle", "edges"}
            or not isinstance(chain.get("edges"), list) or len(chain["edges"]) != 1
            or not isinstance(chain["edges"][0], dict)
            or set(chain["edges"][0]) != {"id", "provider", "region", "size"}
            or chain["edges"][0].get("id") != "edge-01"
            or not isinstance(chain.get("id"), str) or not chain["id"]
            or not isinstance(chain.get("fingerprint"), str) or not chain["fingerprint"]
            or not isinstance(chain.get("assignedProxy"), str) or not chain["assignedProxy"]
            or chain.get("middle") != {"provider": "digitalocean",
                                       "region": middle.region, "size": middle.size}
            or chain["edges"][0].get("provider") != "digitalocean"
            or chain["edges"][0].get("region") != edge.region
            or chain["edges"][0].get("size") != edge.size
            or middle.image != scope.get("image") or edge.image != scope.get("image")
            or middle.firewall_selector_tag != expected_firewall.selector_tag
            or edge.firewall_selector_tag != expected_firewall.selector_tag
            or policy != {
                "publicTcpPorts": ["80", "443", "2222"], "publicUdpPorts": [],
                "publicIpv6Allowed": False,
                "managementSsh": {"port": 22, "sourceRule": "selected-proxy-public-ipv4-32",
                                  "proxyNames": [chain["assignedProxy"]]},
                "peerIngress": {"protocols": ["tcp", "udp", "icmp"],
                                "portRange": "1-65535",
                                "sourceRule": "all-created-provider-middle-and-edge-public-ipv4-32"},
                "outboundIpv4": [
                    {"protocol": protocol, "portRange": "1-65535",
                     "destination": "0.0.0.0/0"} for protocol in ("tcp", "udp")
                ] + [{"protocol": "icmp", "destination": "0.0.0.0/0"}],
                "outboundIpv6": "not-configured",
            }
            or not isinstance(expected_firewall.trusted_ssh_cidrs, tuple)
            or not expected_firewall.trusted_ssh_cidrs
            or len(set(expected_firewall.trusted_ssh_cidrs)) != len(expected_firewall.trusted_ssh_cidrs)):
        _reject()
    try:
        if any(ipaddress.ip_network(cidr, strict=True).version != 4
               or not cidr.endswith("/32") for cidr in expected_firewall.trusted_ssh_cidrs):
            _reject()
    except (ValueError, TypeError) as exc:
        raise TerraformPlanGateError("DigitalOcean initial trusted proxy source is invalid") from exc
    require_digitalocean_keyed_initial_full_plan(
        saved_plan_json, workspace=workspace, expected_nodes=expected_nodes,
        expected_ssh_key_name=expected_ssh_key_name,
        expected_ssh_public_key=expected_ssh_public_key,
        expected_firewall=expected_firewall,
        expected_local_files=expected_local_files,
    )
