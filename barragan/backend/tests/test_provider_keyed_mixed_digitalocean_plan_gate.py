# Copyright (c) 2026, Oracle and/or its affiliates.
"""One-chain mixed DO authorization against the existing real Terraform fixture.

The redacted fixture `fixtures/provider_keyed/digitalocean-initial-full-terraform-
1.15.5.json` came from Terraform 1.15.5 / DigitalOcean 2.103.0 with mock-token
planning; its provenance and saved-plan binding are covered by the pilot gate
suite. No network/provider credential is used by these tests.
"""

import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

import app.services.provider_keyed_mixed_digitalocean_plan_gate as mixed
from app.services.terraform_plan_gate import TerraformPlanGateError
from test_provider_keyed_initial_plan_gate import (
    EDGE, LOCAL, MIDDLE as PILOT_MIDDLE, NODES, POLICY, PUBKEY, workspace,
)

FIXTURE = Path(__file__).parent / "fixtures/provider_keyed/digitalocean-initial-full-terraform-1.15.5.json"
MIDDLE = 'digitalocean_droplet.middle["middle_01"]'


def _review():
    scopes = [{
        "provider": "digitalocean", "providerConnectionId": "central-connection",
        "image": "ubuntu-22-04-x64",
        "source": {"revision": mixed._SOURCE_REVISION,
                   "templateSha256": mixed._SOURCE_SHA256,
                   "providerLock": {"path": "barragan-v2/.terraform.lock.hcl",
                                    "sha256": mixed._LOCK_SHA256, "providerVersion": "2.103.0"}},
        "chain": {"id": "chain-do", "fingerprint": "reviewed-chain", "assignedProxy": "proxy01",
                  "middle": {"provider": "digitalocean", "region": "nyc3", "size": "s-1vcpu-1gb"},
                  "edges": [{"id": "edge-01", "provider": "digitalocean",
                             "region": "sfo3", "size": "s-1vcpu-1gb"}]},
        "firewall": {
            "publicTcpPorts": ["80", "443", "2222"], "publicUdpPorts": [],
            "publicIpv6Allowed": False,
            "managementSsh": {"port": 22, "sourceRule": "selected-proxy-public-ipv4-32",
                              "proxyNames": ["proxy01"]},
            "peerIngress": {"protocols": ["tcp", "udp", "icmp"],
                            "portRange": "1-65535",
                            "sourceRule": "all-created-provider-middle-and-edge-public-ipv4-32"},
            "outboundIpv4": [
                {"protocol": proto, "portRange": "1-65535", "destination": "0.0.0.0/0"}
                for proto in ("tcp", "udp")
            ] + [{"protocol": "icmp", "destination": "0.0.0.0/0"}],
            "outboundIpv6": "not-configured",
        },
    }, {"provider": "linode"}]
    authorization = {"kind": "bounded-mixed-post-core-v1", "providerScopes": scopes}
    authorization["fingerprint"] = hashlib.sha256(json.dumps(
        authorization, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return authorization


def _args(workspace):
    local = copy.deepcopy(LOCAL)
    local["local_file.ansible_inventory[0]"]["content"] = "inventory fixture"
    return {
        "workspace": workspace,
        "reviewed_authorization": _review(),
        "expected_nodes": {
            MIDDLE: replace(NODES[PILOT_MIDDLE], name="middle01-e7c9a4d2"),
            EDGE: replace(NODES[EDGE], name="edge-e7c9a4d2-sfo3-01"),
        },
        "expected_ssh_key_name": "do-key", "expected_ssh_public_key": PUBKEY,
        "expected_firewall": replace(POLICY, name="e7c9a4d2-firewall"),
        "expected_middle_ordinal": 1, "expected_edge_ordinal": 1,
        "expected_local_files": local,
    }


def _check(workspace, *, args=None, plan=None):
    data = copy.deepcopy(plan if plan is not None else json.loads(FIXTURE.read_text()))
    for row in data["resource_changes"]:
        if row["address"] == PILOT_MIDDLE:
            row["address"] = MIDDLE
    mixed.require_mixed_digitalocean_keyed_initial_plan(
        json.dumps(data),
        **(args if args is not None else _args(workspace)),
    )


def test_one_chain_real_offline_plan_passes_and_restarts(workspace):
    _check(workspace)
    _check(workspace)


@pytest.mark.parametrize("drift", [
    lambda a: a["reviewed_authorization"]["providerScopes"][0].update(providerConnectionId="other"),
    lambda a: a["reviewed_authorization"]["providerScopes"][0].update(image="ubuntu-24-04-x64"),
    lambda a: a["reviewed_authorization"]["providerScopes"][0]["source"]["providerLock"].update(providerVersion="latest"),
    lambda a: a["reviewed_authorization"]["providerScopes"][0]["firewall"].update(publicTcpPorts=["22", "80", "443"]),
    lambda a: a["reviewed_authorization"]["providerScopes"][0]["chain"]["middle"].update(region="sfo3"),
    lambda a: a["reviewed_authorization"]["providerScopes"][0]["chain"]["edges"][0].update(id="edge-02"),
    lambda a: a.update(expected_middle_ordinal=2),
    lambda a: a["expected_nodes"].pop(EDGE),
    lambda a: a["expected_nodes"].update({
        'digitalocean_droplet.edge["nyc3-01"]': a["expected_nodes"].pop(EDGE)}),
])
def test_rejects_mixed_review_or_scope_drift(workspace, drift):
    args = _args(workspace)
    drift(args)
    auth = args["reviewed_authorization"]
    auth["fingerprint"] = hashlib.sha256(json.dumps(
        {k: v for k, v in auth.items() if k != "fingerprint"},
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    with pytest.raises(TerraformPlanGateError):
        _check(workspace, args=args)


@pytest.mark.parametrize("change", [
    lambda p: p["resource_changes"][0]["change"].update(actions=["delete", "create"]),
    lambda p: p["resource_changes"].pop(),
    lambda p: p.update(resource_drift=[{"address": MIDDLE}]),
])
def test_rejects_changed_saved_actions(workspace, change):
    plan = json.loads(FIXTURE.read_text())
    change(plan)
    with pytest.raises(TerraformPlanGateError):
        _check(workspace, plan=plan)
