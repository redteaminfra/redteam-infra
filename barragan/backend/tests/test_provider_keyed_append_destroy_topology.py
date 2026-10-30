# Copyright (c) 2026, Oracle and/or its affiliates.
"""Destroy topology checks use the hash-attested append input for five nodes."""

import hashlib
import json
from copy import deepcopy
from dataclasses import replace

import pytest

from app.services.provider_keyed_initial_plan_gate import (
    DigitalOceanInitialFirewallIntent, DigitalOceanNodeCreate,
)
from app.services.provider_keyed_saved_plan_runner import (
    ProviderKeyedPlanPreparationError, _require_nodes_match_topology,
    _require_plan_topology_variables,
)
from app.services.provider_keyed_initial_teardown import (
    ProviderKeyedTeardownPreviewError, prepare_digitalocean_keyed_initial_teardown_preview,
)
from test_provider_keyed_initial_plan_gate import workspace
from test_provider_keyed_initial_teardown import preview_setup


def _expanded_case(workspace):
    original = workspace.path / ".barragan-topology.json"
    initial_sha = hashlib.sha256(original.read_bytes()).hexdigest()
    topology = json.loads(original.read_text())
    topology["edge_groups"]["sfo"]["ordinals"] = [1, 2]
    path = workspace.path.parents[1] / ".plan-material" / "digitalocean" / "append-inputs.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({**topology, "engagement_name": "opaque"}))
    path.chmod(0o600)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    nodes = {
        'digitalocean_droplet.middle["primary"]': DigitalOceanNodeCreate(
            "middle01-opaque", "ubuntu-22-04-x64", "s-1vcpu-1gb", "nyc3", "selector"),
        **{f'digitalocean_droplet.edge["sfo3-{number:02d}"]': DigitalOceanNodeCreate(
            f"edge-opaque-sfo3-{number:02d}", "ubuntu-22-04-x64", "s-1vcpu-1gb",
            "sfo3", "selector") for number in (1, 2)},
    }
    firewall = DigitalOceanInitialFirewallIntent(
        "opaque-firewall", "selector", ("80", "443"), (), ("192.0.2.1/32",))
    plan = json.dumps({"variables": {
        "middles": {"value": topology["middles"]},
        "edge_groups": {"value": {"sfo": {
            **topology["edge_groups"]["sfo"], "count": None, "ordinal_start": 1,
        }}},
    }})
    return original, initial_sha, path, digest, nodes, firewall, plan


def test_attested_append_input_selects_five_node_topology_for_both_checks(workspace):
    original, initial_sha, path, digest, nodes, firewall, plan = _expanded_case(workspace)
    with pytest.raises(ProviderKeyedPlanPreparationError):
        _require_nodes_match_topology(workspace, nodes, firewall)
    with pytest.raises(ProviderKeyedPlanPreparationError):
        _require_plan_topology_variables(plan, workspace)
    kwargs = {"expected_topology_path": path, "expected_topology_sha256": digest}
    _require_nodes_match_topology(workspace, nodes, firewall, **kwargs)
    _require_plan_topology_variables(plan, workspace, **kwargs)
    assert hashlib.sha256(original.read_bytes()).hexdigest() == initial_sha


@pytest.mark.parametrize("drift", ["wrong-digest", "missing", "changed", "wrong-path"])
def test_append_topology_rejects_unreviewed_input_before_either_comparison(workspace, drift):
    _original, _initial_sha, path, digest, nodes, firewall, plan = _expanded_case(workspace)
    if drift == "wrong-digest":
        digest = "0" * 64
    elif drift == "missing":
        path.unlink()
    elif drift == "changed":
        path.write_bytes(path.read_bytes() + b"\n")
    else:
        path = path.with_name("inputs.json")
    kwargs = {"expected_topology_path": path, "expected_topology_sha256": digest}
    with pytest.raises(ProviderKeyedPlanPreparationError):
        _require_nodes_match_topology(workspace, nodes, firewall, **kwargs)
    with pytest.raises(ProviderKeyedPlanPreparationError):
        _require_plan_topology_variables(plan, workspace, **kwargs)


def test_appended_saved_plan_must_match_attested_topology(workspace):
    _original, _initial_sha, path, digest, _nodes, _firewall, plan = _expanded_case(workspace)
    changed = json.loads(plan)
    changed["variables"]["edge_groups"]["value"]["sfo"]["ordinals"] = [1]
    with pytest.raises(ProviderKeyedPlanPreparationError):
        _require_plan_topology_variables(
            json.dumps(changed), workspace,
            expected_topology_path=path, expected_topology_sha256=digest)


def _five_node_preview(preview_setup):
    workspace, intent, kwargs, runner = preview_setup
    root = workspace.path
    original = root / ".barragan-topology.json"
    marker_hash = hashlib.sha256(original.read_bytes()).hexdigest()
    topology = {
        "schema": "provider-keyed-v2",
        "middles": {
            "primary": {"region": "nyc3", "ordinal": 1},
            "secondary": {"region": "nyc3", "ordinal": 2},
        },
        "edge_groups": {
            "sfo": {"region": "sfo3", "middle_node": "primary", "ordinals": [1, 2]},
            "nyc": {"region": "nyc3", "middle_node": "secondary", "ordinals": [1]},
        },
    }
    path = root.parents[1] / ".plan-material" / "digitalocean" / "append-inputs.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({**topology, "engagement_name": "opaque"}))
    path.chmod(0o600)
    nodes = dict(intent.nodes)
    selector = intent.firewall.selector_tag
    for address, name, region in (
        ('digitalocean_droplet.middle["secondary"]', "middle02-opaque", "nyc3"),
        ('digitalocean_droplet.edge["sfo3-02"]', "edge-opaque-sfo3-02", "sfo3"),
        ('digitalocean_droplet.edge["nyc3-01"]', "edge-opaque-nyc3-01", "nyc3"),
    ):
        nodes[address] = DigitalOceanNodeCreate(
            name, "ubuntu-22-04-x64", "s-1vcpu-1gb", region, selector)
    state = json.loads(workspace.state_path.read_text())
    ids = dict(intent.resource_ids)
    for number, address in enumerate(sorted(set(nodes) - set(intent.nodes)), 1003):
        kind, rest = address.split(".", 1)
        name, encoded_key = rest.split("[", 1)
        key = json.loads(encoded_key[:-1])
        node = nodes[address]
        values = {"id": str(number), "name": node.name, "image": node.image,
                  "size": node.size, "region": node.region, "tags": [selector]}
        state["resources"].append({"mode": "managed", "type": kind, "name": name,
                                   "instances": [{"index_key": key, "attributes": values}]})
        runner.plan["prior_state"]["values"]["root_module"]["resources"].append({
            "address": address, "mode": "managed", "values": deepcopy(values),
        })
        runner.plan["resource_changes"].append({"address": address, "change": {
            "actions": ["delete"], "before": deepcopy(values), "after": None,
            "after_unknown": {},
        }})
        ids[address] = str(number)
    workspace.state_path.write_text(json.dumps(state))
    intent = replace(intent, nodes=nodes, resource_ids=ids,
                     state_sha256=hashlib.sha256(workspace.state_path.read_bytes()).hexdigest())
    runner.plan["variables"] = {
        "middles": {"value": topology["middles"]},
        "edge_groups": {"value": {key: {**value, "count": None, "ordinal_start": 1}
                                  for key, value in topology["edge_groups"].items()}},
    }
    kwargs["input_sha256"] = {path: hashlib.sha256(path.read_bytes()).hexdigest()}
    kwargs["var_files"] = [path]
    kwargs["expected_topology_path"] = path
    return workspace, intent, kwargs, runner, original, marker_hash


def test_two_middle_three_edge_destroy_preview_uses_attested_append_input(preview_setup):
    workspace, intent, kwargs, runner, marker, marker_hash = _five_node_preview(preview_setup)
    result = prepare_digitalocean_keyed_initial_teardown_preview(workspace, intent, **kwargs)
    assert [call[0][1] for call in runner.calls] == ["version", "init", "plan", "show"]
    assert len(intent.nodes) == 5 and len(intent.resource_ids) == 9
    assert result.state_sha256 == intent.state_sha256
    assert result.input_sha256 == ((str(kwargs["var_files"][0]),
                                    kwargs["input_sha256"][kwargs["var_files"][0]]),)
    assert hashlib.sha256(marker.read_bytes()).hexdigest() == marker_hash


@pytest.mark.parametrize("drift", ["extra-group", "missing-group", "wrong-middle"])
def test_five_node_destroy_preview_rejects_saved_plan_topology_drift(preview_setup, drift):
    workspace, intent, kwargs, runner, _marker, _marker_hash = _five_node_preview(preview_setup)
    groups = runner.plan["variables"]["edge_groups"]["value"]
    if drift == "extra-group":
        groups["extra"] = {"region": "nyc3", "middle_node": "secondary",
                           "ordinals": [2], "count": None, "ordinal_start": 1}
    elif drift == "missing-group":
        del groups["nyc"]
    else:
        groups["nyc"]["middle_node"] = "primary"
    with pytest.raises(ProviderKeyedTeardownPreviewError) as failure:
        prepare_digitalocean_keyed_initial_teardown_preview(workspace, intent, **kwargs)
    assert failure.value.stage == "topology_variables"
    assert [call[0][1] for call in runner.calls] == ["version", "init", "plan", "show"]
