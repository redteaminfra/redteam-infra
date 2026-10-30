# Copyright (c) 2026, Oracle and/or its affiliates.
"""Exact Linode initial plan gate against Terraform's offline mock-provider plan.

Fixture provenance: redteam-infra commit
ca5bcad7d2be274aaa79d6c9127cbd9b5c2b10cc, Terraform 1.15.5,
Linode 4.5.0, local 2.9.1, random 3.9.1. In a disposable directory, extract
`external/sketch/linode` from that commit; overlay
`barragan-v2/providers.tf` as `providers.tf` and
`barragan-v2/.terraform.lock.hcl` at root. Add `tests/one_chain_middle01.tftest.hcl`
with mock_provider blocks for linode, local, and random; one `middle_01`
middle in us-east and one `us-west` edge group (count 1) connected to it;
image linode/ubuntu24.04, type g6-nanode-1, trusted SSH 192.0.2.10/32,
engagement opaque-fixture, and the checked-in public-key fixture.
Run offline with the three pinned provider binaries already cached:

    TF_IN_AUTOMATION=1 terraform init -backend=false -input=false \
      -lockfile=readonly -plugin-dir=<cached-providers> -no-color
    TF_IN_AUTOMATION=1 terraform test -json -verbose \
      -filter=tests/one_chain_middle01.tftest.hcl > test.jsonl

The passing `test_plan` event contains six actual Terraform resource_changes.
Extract only those changes, then wrap them in a saved-plan-like envelope:
format_version 1.2, terraform_version 1.15.5, applyable/complete true,
errored false, and prior_state.values.root_module = {}. The envelope is
synthetic because `terraform test` does not emit a binary saved plan/show
header; the resource changes and computed/sensitive fields are Terraform's
real offline output. The JSON contains no token, key secret, or host path.
The historical fixture predates the keyed-v2 label overlay, so only its
firewall label is normalized below.
"""

import copy
import hashlib
import json
from pathlib import Path

import pytest

import app.services.provider_keyed_linode_initial_plan_gate as gate
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.terraform_plan_gate import TerraformPlanGateError

PLAN = json.loads((Path(__file__).parent / "fixtures/linode_one_chain_middle01_plan.json").read_text())
for _row in PLAN["resource_changes"]:
    if _row["address"] == "linode_firewall.firewall":
        _row["change"]["after"]["label"] = "fw-opaque-fixture-firewall"
MIDDLE = 'linode_instance.middle["middle_01"]'
EDGE = 'linode_instance.edge["us-west-01"]'


def _review():
    scopes = [{"provider": "digitalocean"}, {
        "provider": "linode", "providerConnectionId": "central-linode",
        "image": "linode/ubuntu24.04",
        "source": {"revision": gate._SOURCE_REVISION, "templateSha256": gate._SOURCE_SHA256,
                   "providerLock": {"path": "barragan-v2/.terraform.lock.hcl",
                                    "sha256": gate._LOCK_SHA256, "providerVersion": "4.5.0"}},
        "chain": {"id": "chain-linode", "fingerprint": "reviewed-chain", "assignedProxy": "proxy01",
                  "middle": {"provider": "linode", "region": "us-east", "size": "g6-nanode-1"},
                  "edges": [{"id": "edge-01", "provider": "linode", "region": "us-west",
                             "size": "g6-nanode-1"}]},
        "firewall": {"publicTcpPorts": ["80", "443", "2222"], "publicUdpPorts": [],
                     "publicIpv6Allowed": False,
                     "managementSsh": {"port": 22, "sourceRule": "selected-proxy-public-ipv4-32",
                                       "proxyNames": ["proxy01"]},
                     "peerIngress": {"protocols": ["tcp", "udp", "icmp"],
                                     "portRange": "1-65535",
                                     "sourceRule": "all-created-provider-middle-and-edge-public-ipv4-32"},
                     "outboundIpv4": "accept", "outboundIpv6": "drop"},
    }]
    auth = {"kind": "bounded-mixed-post-core-v1", "providerScopes": scopes}
    auth["fingerprint"] = gate._digest(auth)
    return auth


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "linode"
    root.mkdir()
    source_bytes = {
        "middle.tf": b"middle", "firewall.tf": b"legacy firewall",
        "barragan-v2/firewall.tf": b"keyed firewall",
        "barragan-v2/providers.tf": b"provider", "barragan-v2/.terraform.lock.hcl": b"lock",
    }
    source = {key: hashlib.sha256(value).hexdigest() for key, value in source_bytes.items()}
    rendered = dict(source)
    rendered["providers.tf"] = source["barragan-v2/providers.tf"]
    rendered["firewall.tf"] = source["barragan-v2/firewall.tf"]
    rendered[".terraform.lock.hcl"] = source["barragan-v2/.terraform.lock.hcl"]
    for name in rendered:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        content = source_bytes.get(name)
        if name == "providers.tf":
            content = source_bytes["barragan-v2/providers.tf"]
        if name == "firewall.tf":
            content = source_bytes["barragan-v2/firewall.tf"]
        if name == ".terraform.lock.hcl":
            content = source_bytes["barragan-v2/.terraform.lock.hcl"]
        path.write_bytes(content)
    monkeypatch.setattr(gate, "_SOURCE_SHA256", hashlib.sha256(
        json.dumps(source, sort_keys=True).encode()).hexdigest())
    monkeypatch.setattr(gate, "_LOCK_SHA256", source["barragan-v2/.terraform.lock.hcl"])
    marker = {"schema": "provider-keyed-v2", "provider": "linode",
              "provider_connection_id": "central-linode", "connection_fingerprint": "fprint",
              "source_revision": gate._SOURCE_REVISION, "source_files": source,
              "rendered_files": rendered}
    (root / ".barragan-provider-keyed-state.json").write_text(json.dumps(marker))
    return ProviderKeyedWorkspace(root, root / "terraform.tfstate", root / ".terraform-data",
                                  "provider-keyed-v2", "linode", "central-linode", "fprint",
                                  gate._SOURCE_REVISION, gate._SOURCE_SHA256)


def _arguments(workspace):
    resources = {row["address"]: row["change"]["after"] for row in PLAN["resource_changes"]}
    nodes = {address: gate.LinodeNodeCreate(
        label=resources[address]["label"], image=resources[address]["image"],
        node_type=resources[address]["type"], region=resources[address]["region"],
        tag=resources[address]["tags"][0],
        authorized_keys=tuple(resources[address]["authorized_keys"]))
        for address in (MIDDLE, EDGE)}
    return {"workspace": workspace, "reviewed_authorization": _review(),
            "expected_nodes": nodes, "engagement_name": "opaque-fixture",
            "trusted_ssh_cidrs": ("192.0.2.10/32",),
            "expected_middle_ordinal": 1, "expected_edge_ordinal": 1,
            "expected_local_files": {address: resources[address] for address in gate._LOCAL}}


def _check(plan, args):
    gate.require_linode_keyed_initial_full_plan(json.dumps(plan), **args)


def _saved_plan_shape():
    """Nonsecret schema/default delta observed in a fresh Terraform show -json."""
    plan = copy.deepcopy(PLAN)
    plan["prior_state"] = {
        "format_version": "1.0", "terraform_version": "1.15.5",
        "values": {"outputs": {
            "middle_public_ip": {"sensitive": False, "value": ""},
            "edge_public_ips": {"sensitive": False, "value": []},
        }, "root_module": {}},
    }
    for row in plan["resource_changes"]:
        address, change = row["address"], row["change"]
        unknown, after = change["after_unknown"], change["after"]
        if address == "linode_firewall.firewall":
            unknown.pop("disabled")
            for rule in unknown["inbound"] + unknown["outbound"]:
                rule.pop("description")
            after["disabled"] = False
            for rule in after["inbound"] + after["outbound"]:
                rule["description"] = ""
        elif address in {MIDDLE, EDGE}:
            for name in ("alerts", "config", "disk"):
                unknown[name] = True
                after.pop(name)
            after.update(migration_type="cold", resize_disk=False,
                         watchdog_enabled=True)
        elif address in gate._LOCAL:
            unknown.pop("directory_permission")
            after["directory_permission"] = "0777"
        elif address == "random_password.root_password":
            for name in ("lower", "number", "numeric", "special", "upper",
                         "min_lower", "min_numeric", "min_special", "min_upper"):
                unknown.pop(name)
            after.update({name: True for name in
                          ("lower", "number", "numeric", "special", "upper")})
            after.update({name: 0 for name in
                          ("min_lower", "min_numeric", "min_special", "min_upper")})
    return plan


def test_exact_offline_terraform_plan_passes_and_restarts(workspace):
    args = _arguments(workspace)
    _check(PLAN, args)
    _check(PLAN, args)


def test_output_only_prior_state_from_fresh_saved_plan_passes(workspace):
    plan = _saved_plan_shape()
    for row in plan["resource_changes"]:
        kind = ("firewall" if row["address"] == "linode_firewall.firewall" else
                "password" if row["address"] == "random_password.root_password" else
                "inventory" if row["address"] == "local_file.ansible_inventory[0]" else
                "ssh" if row["address"] == "local_file.ssh_stanza[0]" else "node")
        assert gate._digest(row["change"]["after_unknown"]) == gate._REAL_UNKNOWN_SHA256[kind]
    _check(plan, _arguments(workspace))


@pytest.mark.parametrize("mutation", [
    lambda p: p["resource_changes"][0]["change"]["after"].pop("disabled"),
    lambda p: p["resource_changes"][0]["change"]["after"]["inbound"][0].update(description="unexpected"),
    lambda p: p["resource_changes"][1]["change"]["after"].update(migration_type="warm"),
    lambda p: p["resource_changes"][1]["change"]["after"].update(resize_disk=True),
    lambda p: p["resource_changes"][1]["change"]["after_unknown"].update(alerts=[]),
    lambda p: p["resource_changes"][3]["change"]["after"].update(directory_permission="0755"),
    lambda p: p["resource_changes"][5]["change"]["after"].update(min_special=1),
    lambda p: p["resource_changes"][5]["change"]["after_unknown"].update(lower=True),
    lambda p: p.update(resource_drift=[{"address": MIDDLE}]),
    lambda p: p.update(resource_drift={}),
    lambda p: p.update(resource_drift=None),
    lambda p: p["resource_changes"].pop(),
])
def test_rejects_real_saved_plan_shape_or_action_drift(workspace, mutation):
    plan = _saved_plan_shape()
    mutation(plan)
    with pytest.raises(TerraformPlanGateError):
        _check(plan, _arguments(workspace))


def test_rejects_mixed_mock_and_saved_plan_profiles(workspace):
    plan = _saved_plan_shape()
    plan["resource_changes"][1]["change"] = copy.deepcopy(PLAN["resource_changes"][1]["change"])
    with pytest.raises(TerraformPlanGateError):
        _check(plan, _arguments(workspace))


@pytest.mark.parametrize("prior", [
    {"values": {"root_module": {"resources": [{"address": MIDDLE}]}}},
    {"values": {"root_module": {"child_modules": []}}},
    {"values": {"root_module": {}, "outputs": [], "resources": []}},
    {"values": {"root_module": {}, "outputs": []}},
    {"values": {"outputs": {}}},
    {"values": []},
    {"values": {"root_module": {}}, "resources": []},
    {"format_version": "2.0", "values": {"root_module": {}}},
    {"terraform_version": 1155, "values": {"root_module": {}}},
    None,
])
def test_rejects_prior_resources_or_invalid_empty_state(workspace, prior):
    plan = copy.deepcopy(PLAN)
    plan["prior_state"] = prior
    with pytest.raises(TerraformPlanGateError):
        _check(plan, _arguments(workspace))


@pytest.mark.parametrize("mutation", [
    lambda p: p["resource_changes"].pop(),
    lambda p: p["resource_changes"].append(copy.deepcopy(p["resource_changes"][0])),
    lambda p: p["resource_changes"][0]["change"].update(actions=["delete", "create"]),
    lambda p: p.update(resource_drift=[{"address": MIDDLE}]),
    lambda p: p["resource_changes"][0]["change"]["after"]["inbound"][0].update(ipv4=["0.0.0.0/0", "::/0"]),
    lambda p: p["resource_changes"][0]["change"]["after"].update(label="opaque-fixture-firewall"),
    lambda p: p["resource_changes"][0]["change"]["after"].update(inbound_policy="ACCEPT"),
    lambda p: p["resource_changes"][0]["change"]["after"]["outbound"][0].update(action="ACCEPT"),
    lambda p: p["resource_changes"][1]["change"]["after"].update(image="linode/ubuntu22.04"),
    lambda p: p["resource_changes"][1]["change"]["after_unknown"].update(root_pass=False),
])
def test_rejects_unreviewed_action_firewall_or_schema(workspace, mutation):
    args = _arguments(workspace)
    plan = copy.deepcopy(PLAN)
    mutation(plan)
    with pytest.raises(TerraformPlanGateError):
        _check(plan, args)


def test_rejects_reviewed_scope_and_workspace_drift(workspace):
    args = _arguments(workspace)
    args["reviewed_authorization"]["providerScopes"][1]["providerConnectionId"] = "other"
    args["reviewed_authorization"]["fingerprint"] = gate._digest({
        k: v for k, v in args["reviewed_authorization"].items() if k != "fingerprint"})
    with pytest.raises(TerraformPlanGateError):
        _check(PLAN, args)
    args = _arguments(workspace)
    (workspace.path / "extra.auto.tfvars").write_text('allowed_tcp_ports = ["22"]')
    with pytest.raises(TerraformPlanGateError):
        _check(PLAN, args)


def test_rejects_wrong_engagement_middle_ordinal(workspace):
    args = _arguments(workspace)
    args["expected_middle_ordinal"] = 2
    with pytest.raises(TerraformPlanGateError):
        _check(PLAN, args)
