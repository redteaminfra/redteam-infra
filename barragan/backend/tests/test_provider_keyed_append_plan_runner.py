# Copyright (c) 2026, Oracle and/or its affiliates.
"""Saved append planning leaves the active four-node state/topology untouched."""

import copy
import hashlib
import json
import re
import subprocess

import pytest

import app.services.provider_keyed_append_plan_runner as runner
from app.services.terraform_plan_gate import TerraformPlanGateError
from test_provider_keyed_append_plan_gate import (
    NEW, INTENT, POLICY, INVENTORY, REVIEWED_VARIABLES, _fixture,
)
from test_provider_keyed_initial_plan_gate import workspace


def _case(workspace, tmp_path, monkeypatch, *, bad_plan=False):
    plan, retained = _fixture()
    state_resources = []
    for address, attributes in retained.items():
        kind, rest = address.split(".", 1)
        name = rest.split("[")[0]
        indexed = re.search(r'\[("[^"]+"|0)\]$', address)
        instance = {"attributes": copy.deepcopy(attributes)}
        if indexed:
            instance["index_key"] = json.loads(indexed.group(1))
        state_resources.append({"mode": "managed", "type": kind, "name": name,
                                "instances": [instance]})
    state = {"version": 4, "resources": state_resources}
    workspace.state_path.write_text(json.dumps(state, sort_keys=True))
    state_sha = hashlib.sha256(workspace.state_path.read_bytes()).hexdigest()
    (workspace.path / ".barragan-initial-full-plan.lock").write_bytes(b"")
    (workspace.path / ".barragan-initial-full-plan.lock").chmod(0o600)
    varfile = tmp_path / "reviewed-input.json"
    varfile.write_text(json.dumps(REVIEWED_VARIABLES, sort_keys=True))
    varfile.chmod(0o600)
    terraform = tmp_path / "terraform"
    terraform.write_text("#!/bin/sh\nexit 0\n")
    terraform.chmod(0o700)
    monkeypatch.setattr(runner, "_credential_snapshot",
                        lambda *_args: ("a" * 64, "2026-10-13T00:00:00+00:00", "ciphertext"))
    monkeypatch.setattr(runner, "decrypt_secret_value", lambda _value: "test-token")
    calls = []

    def run(args, cwd, env):
        calls.append([*args])
        assert cwd == workspace.path
        if args[1] == "version":
            return subprocess.CompletedProcess(args, 0, '{"terraform_version":"1.15.5"}', "")
        if args[1] == "plan":
            path = next(value.removeprefix("-out=") for value in args if value.startswith("-out="))
            with open(path, "wb") as output:
                output.write(b"opaque-binary-plan")
        if args[1] == "show":
            if bad_plan:
                plan["resource_changes"] = [row for row in plan["resource_changes"]
                                            if row["address"] != NEW]
            return subprocess.CompletedProcess(args, 0, json.dumps(plan), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    kwargs = dict(
        retained_state_sha256=state_sha, retained_resources=retained,
        new_edge_address=NEW, new_edge=INTENT, firewall=POLICY,
        expected_inventory_content=INVENTORY, reviewed_variables=REVIEWED_VARIABLES,
        input_sha256={varfile: hashlib.sha256(varfile.read_bytes()).hexdigest()},
        var_files=[varfile], credential_repository=object(), command_environment={},
        expected_terraform_sha256=hashlib.sha256(terraform.read_bytes()).hexdigest(),
        environment="devtest", deployment_target="barragan-testing",
        terraform=str(terraform), command_runner=run,
    )
    return kwargs, calls, state_sha


def test_append_runner_saves_binary_plan_without_changing_live_topology(workspace, tmp_path, monkeypatch):
    kwargs, calls, state_sha = _case(workspace, tmp_path, monkeypatch)
    topology_before = (workspace.path / ".barragan-topology.json").read_bytes()
    ledger = workspace.path.parents[1] / "regional-ordinals.json"
    evidence = runner.prepare_digitalocean_keyed_edge_append_plan(workspace, **kwargs)
    assert evidence.plan_path == workspace.path / ".barragan-edge-append.tfplan"
    assert evidence.plan_sha256 == hashlib.sha256(b"opaque-binary-plan").hexdigest()
    assert evidence.state_sha256 == state_sha
    assert workspace.state_path.is_file()
    assert (workspace.path / ".barragan-topology.json").read_bytes() == topology_before
    assert not ledger.exists()
    assert [args[1] for args in calls] == ["version", "init", "plan", "show"]
    assert "-refresh=false" in calls[2]
    assert not any(args[1] == "apply" for args in calls)


def test_append_runner_rejects_saved_plan_drift_without_touching_state(workspace, tmp_path, monkeypatch):
    kwargs, calls, state_sha = _case(workspace, tmp_path, monkeypatch, bad_plan=True)
    topology_before = (workspace.path / ".barragan-topology.json").read_bytes()
    with pytest.raises(runner.ProviderKeyedAppendPlanPreparationError) as error:
        runner.prepare_digitalocean_keyed_edge_append_plan(workspace, **kwargs)
    assert error.value.stage == "saved_plan_gate"
    assert error.value.reason_code == "resource_omitted"
    assert not (workspace.path / ".barragan-edge-append.tfplan").exists()
    assert hashlib.sha256(workspace.state_path.read_bytes()).hexdigest() == state_sha
    assert (workspace.path / ".barragan-topology.json").read_bytes() == topology_before
    assert not any(args[1] == "apply" for args in calls)


@pytest.mark.parametrize("failure", [
    TerraformPlanGateError("secret=/private/credential"),
    RuntimeError("secret=/private/credential"),
])
def test_append_runner_redacts_unknown_gate_failure(workspace, tmp_path, monkeypatch, failure):
    kwargs, calls, _ = _case(workspace, tmp_path, monkeypatch)
    monkeypatch.setattr(runner, "require_digitalocean_keyed_edge_append_full_plan",
                        lambda *_a, **_k: (_ for _ in ()).throw(failure))
    with pytest.raises(runner.ProviderKeyedAppendPlanPreparationError) as error:
        runner.prepare_digitalocean_keyed_edge_append_plan(workspace, **kwargs)
    assert error.value.stage == "saved_plan_gate"
    assert error.value.reason_code is None
    assert "secret" not in str(error.value)
    assert not (workspace.path / ".barragan-edge-append.tfplan").exists()
    assert not any(args[1] == "apply" for args in calls)


def test_append_preparation_error_rejects_forged_reason_code():
    error = runner.ProviderKeyedAppendPlanPreparationError(
        "saved_plan_gate", "credential=/private/secret")
    assert error.reason_code is None
    assert "credential" not in str(error)


def test_append_runner_blocks_unsafe_workspace_before_terraform(workspace, tmp_path, monkeypatch):
    kwargs, calls, state_sha = _case(workspace, tmp_path, monkeypatch)
    workspace.path.chmod(0o777)
    with pytest.raises(runner.ProviderKeyedAppendPlanPreparationError) as error:
        runner.prepare_digitalocean_keyed_edge_append_plan(workspace, **kwargs)
    assert error.value.stage == "workspace_and_inputs"
    assert calls == []
    assert not (workspace.path / ".barragan-edge-append.tfplan").exists()
    assert hashlib.sha256(workspace.state_path.read_bytes()).hexdigest() == state_sha
