# Copyright (c) 2026, Oracle and/or its affiliates.
"""One saved append plan is inspected again before any provider mutation."""

import copy
import hashlib
import json
import re
import subprocess
from uuid import uuid4

import pytest

import app.services.provider_keyed_append_apply as subject
from app.services.provider_keyed_append_plan_runner import ProviderKeyedAppendPlanEvidence
from test_provider_keyed_append_plan_runner import _case
from test_provider_keyed_append_plan_gate import (
    NEW, INTENT, POLICY, INVENTORY, REVIEWED_VARIABLES, _fixture,
)
from test_provider_keyed_initial_plan_gate import workspace


def _reviewed_case(workspace, tmp_path, monkeypatch):
    _case(workspace, tmp_path, monkeypatch)
    shown, retained = _fixture()
    plan = workspace.path / ".barragan-edge-append.tfplan"
    plan.write_bytes(b"reviewed-binary")
    plan.chmod(0o600)
    phase = workspace.path / ".barragan-apply-phase.json"
    phase.write_text(json.dumps({"schema": workspace.schema, "phase": "applied"}))
    phase.chmod(0o600)
    material = workspace.path.parents[1] / ".plan-material" / "digitalocean"
    material.mkdir(parents=True, exist_ok=True)
    varfile = material / "append-inputs.json"
    varfile.write_text(json.dumps(REVIEWED_VARIABLES))
    varfile.chmod(0o600)
    binary = tmp_path / "terraform"
    evidence = ProviderKeyedAppendPlanEvidence(
        plan, hashlib.sha256(plan.read_bytes()).hexdigest(),
        hashlib.sha256(workspace.state_path.read_bytes()).hexdigest(),
        subject._topology_hash(workspace), workspace.source_sha256,
        subject._hash_file(workspace.path / ".terraform.lock.hcl"),
        ((str(varfile), hashlib.sha256(varfile.read_bytes()).hexdigest()),),
        workspace.provider_connection_id, "a" * 64,
        "2026-10-13T00:00:00+00:00", binary,
        hashlib.sha256(binary.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(subject, "_credential_snapshot",
                        lambda *_args: ("a" * 64, "2026-10-13T00:00:00+00:00", "ciphertext"))
    # The pure plan-gate fixture intentionally omits redundant state fields;
    # the pre-GO branch under test only needs the five-address identity set.
    retained_nodes = {
        address: INTENT for address in retained
        if address.startswith("digitalocean_droplet.")
    }
    return shown, retained, evidence, phase, plan, {**retained_nodes, NEW: INTENT}


def test_changed_saved_plan_after_fresh_provider_get_never_reaches_apply(workspace, tmp_path, monkeypatch):
    shown, retained, evidence, phase, plan, expected_nodes = _reviewed_case(
        workspace, tmp_path, monkeypatch)
    calls = []

    def run(args, *_args):
        calls.append(args[1])
        assert args[1] == "show"
        return subprocess.CompletedProcess(args, 0, json.dumps(shown), "")

    def fresh_get():
        plan.write_bytes(b"tampered-binary")

    with pytest.raises(subject.ProviderKeyedAppendApplyError):
        subject.apply_digitalocean_keyed_edge_append_saved_plan(
            workspace, evidence, retained_resources=retained,
            expected_nodes=expected_nodes, new_edge_address=NEW, expected_firewall=POLICY,
            expected_inventory_content=INVENTORY,
            reviewed_variables=REVIEWED_VARIABLES,
            credential_repository=object(), command_environment={},
            before_go_provider_check=fresh_get, command_runner=run,
        )
    assert calls == ["show"]
    assert json.loads(phase.read_text())["phase"] == "applied"


@pytest.mark.parametrize("drift", [None, "retained-id", "firewall-id"])
def test_exact_saved_plan_appends_one_edge_and_retains_four_node_identities(
        workspace, tmp_path, monkeypatch, drift):
    shown, retained, evidence, phase, _plan, expected_nodes = _reviewed_case(
        workspace, tmp_path, monkeypatch)
    state = json.loads(workspace.state_path.read_text())
    # The plan-gate fixture deliberately omits retained node fields that real
    # Terraform state carries. Complete the same four identities in all three
    # views so the production nine-resource post-Apply validator runs here.
    for resource in state["resources"]:
        if resource["type"] != "digitalocean_droplet":
            continue
        instance = resource["instances"][0]
        address = f'{resource["type"]}.{resource["name"]}[{json.dumps(instance["index_key"])}]'
        intent = subject.DigitalOceanNodeCreate(
            f'retained-{instance["index_key"]}', INTENT.image, INTENT.size,
            "sfo3" if "sfo3" in address else "nyc3", POLICY.selector_tag)
        expected_nodes[address] = intent
        additions = {"name": intent.name, "region": intent.region,
                     "tags": [intent.firewall_selector_tag]}
        instance["attributes"].update(additions)
        retained[address].update(additions)
        change = next(row["change"] for row in shown["resource_changes"]
                      if row["address"] == address)
        change["before"].update(additions)
        change["after"].update(additions)
        prior = next(row for row in shown["prior_state"]["values"]["root_module"]["resources"]
                     if row["address"] == address)
        prior["values"].update(additions)
    state.update(lineage=str(uuid4()), serial=2, terraform_version="1.15.5")
    workspace.state_path.write_text(json.dumps(state, sort_keys=True))
    evidence = subject.ProviderKeyedAppendPlanEvidence(
        evidence.plan_path, evidence.plan_sha256,
        hashlib.sha256(workspace.state_path.read_bytes()).hexdigest(),
        evidence.topology_sha256, evidence.source_sha256, evidence.lockfile_sha256,
        evidence.input_sha256, evidence.credential_record_id,
        evidence.credential_secret_sha256, evidence.credential_updated_at,
        evidence.terraform_binary_path, evidence.terraform_binary_sha256,
    )
    after = copy.deepcopy(state)
    new = {
        "id": "900001", "name": INTENT.name, "image": INTENT.image,
        "size": INTENT.size, "region": INTENT.region,
        "tags": [POLICY.selector_tag], "ipv4_address": "203.0.113.55",
    }
    name = re.match(r'digitalocean_droplet\.edge\["([^"]+)"\]', NEW).group(1)
    after["resources"].append({
        "mode": "managed", "type": "digitalocean_droplet", "name": "edge",
        "instances": [{"index_key": name, "attributes": new}],
    })
    after["serial"] = 3
    if drift:
        kind = "digitalocean_droplet" if drift == "retained-id" else "digitalocean_firewall"
        row = next(resource for resource in after["resources"] if resource["type"] == kind)
        row["instances"][0]["attributes"]["id"] = "changed-provider-identity"
    calls = []

    def run(args, *_args):
        calls.append(args[1])
        if args[1] == "show":
            return subprocess.CompletedProcess(args, 0, json.dumps(shown), "")
        assert json.loads(phase.read_text())["phase"] == "apply_started"
        workspace.state_path.write_text(json.dumps(after, sort_keys=True))
        return subprocess.CompletedProcess(args, 0, "", "")

    invoke = lambda: subject.apply_digitalocean_keyed_edge_append_saved_plan(
        workspace, evidence, retained_resources=retained,
        expected_nodes=expected_nodes, new_edge_address=NEW,
        expected_firewall=POLICY, expected_inventory_content=INVENTORY,
        reviewed_variables=REVIEWED_VARIABLES,
        credential_repository=object(), command_environment={},
        before_go_provider_check=lambda: calls.append("provider-get"), command_runner=run,
    )
    if drift:
        with pytest.raises(subject.ProviderKeyedAppendApplyError):
            invoke()
        assert calls == ["show", "provider-get", "apply"]
        assert json.loads(phase.read_text())["phase"] == "apply_started"
        return
    result = invoke()
    assert calls == ["show", "provider-get", "apply"]
    assert result.new_edge_provider_id == "900001"
    assert result.new_edge_public_ip == "203.0.113.55"
    assert result.state_sha256 == hashlib.sha256(workspace.state_path.read_bytes()).hexdigest()
    assert json.loads(phase.read_text())["phase"] == "applied"
