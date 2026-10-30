# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-apply orchestration tests for the provider-keyed initial saved plan."""

import hashlib
import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

import app.services.provider_keyed_saved_plan_runner as service
from app.services.provider_keyed_initial_plan_gate import DigitalOceanInitialFirewallIntent, DigitalOceanNodeCreate
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace


class Repository:
    connection_id = "cred-000000000001"
    encrypted_secret = "encrypted-fixture-token"
    updated_at = "2026-10-02T00:00:00Z"

    def get(self, credential_id):
        if credential_id != self.connection_id:
            return None
        return self.get_default("digitalocean")

    def get_default(self, provider):
        assert provider == "digitalocean"
        return type("Credential", (), {
            "id": self.connection_id, "provider": "digitalocean", "status": "active",
            "is_default": True, "encrypted_secret": self.encrypted_secret,
            "updated_at": self.updated_at,
        })()


class Runner:
    def __init__(self, plan_json='{"accepted": true}'):
        self.calls = []
        self.plan_json = plan_json
        self.fail = None
        self.after_plan = None
        self.before_plan = None

    def __call__(self, args, cwd, env):
        self.calls.append((args, cwd, env))
        if self.fail == args[1]:
            return subprocess.CompletedProcess(args, 1, "", "secret-from-provider-command")
        if args[1] == "version":
            return subprocess.CompletedProcess(args, 0, '{"terraform_version":"1.15.5"}', "")
        if args[1] == "plan":
            plan_path = Path(next(value.split("=", 1)[1] for value in args if value.startswith("-out=")))
            if self.before_plan:
                self.before_plan(plan_path)
            plan_path.write_bytes(b"binary plan")
            if self.after_plan:
                self.after_plan()
        if args[1] == "show":
            return subprocess.CompletedProcess(args, 0, self.plan_json, "")
        return subprocess.CompletedProcess(args, 0, "", "")


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    schema_root = tmp_path / "eng-opaque" / "provider-keyed-v2"
    root = schema_root / "digitalocean" / "fingerprint"
    root.mkdir(parents=True)
    root.chmod(0o700)
    (root / ".terraform-data").mkdir(mode=0o700)
    (root / ".barragan-topology.json").write_text('{"schema":"provider-keyed-v2","middles":{"primary":{"region":"nyc3","ordinal":1}},"edge_groups":{"sfo":{"region":"sfo3","middle_node":"primary","ordinals":[1]}}}')
    (schema_root / ".regional-ordinals.lock").write_text("")
    (schema_root / ".regional-ordinals.lock").chmod(0o600)
    marker = root / ".barragan-provider-keyed-state.json"
    marker.write_text('{"schema":"provider-keyed-v2"}')
    lockfile = root / ".terraform.lock.hcl"
    lockfile.write_text('provider "registry.terraform.io/digitalocean/digitalocean" {\n  version = "2.103.0"\n}\n')
    var_file = tmp_path / "secret.tfvars"
    var_file.write_text('do_pat = "redacted-test-value"\n')
    var_file.chmod(0o600)
    workspace = ProviderKeyedWorkspace(
        root, root / "terraform.tfstate", root / ".terraform-data",
        "provider-keyed-v2", "digitalocean", "cred-000000000001",
        "fingerprint", "ca5bcad7d2be274aaa79d6c9127cbd9b5c2b10cc", "source-digest",
    )
    monkeypatch.setattr(service, "_verify_audited_workspace", lambda workspace: None)
    monkeypatch.setattr(service, "decrypt_secret_value", lambda value: "central-do-token")
    gate_calls = []
    monkeypatch.setattr(service, "require_digitalocean_keyed_initial_full_plan",
                        lambda payload, **kwargs: gate_calls.append((payload, kwargs)))
    runner = Runner(json.dumps({
        "variables": {
            "middles": {"value": {"primary": {"region": "nyc3", "ordinal": 1}}},
            "edge_groups": {"value": {"sfo": {"region": "sfo3", "middle_node": "primary", "count": None, "ordinal_start": 1, "ordinals": [1]}}},
        },
    }))
    repository = Repository()
    selector = "opaque-selector-a1"
    nodes = {
        'digitalocean_droplet.middle["primary"]': DigitalOceanNodeCreate("middle01-eng-opaque", "ubuntu-22-04-x64", "s-1vcpu-1gb", "nyc3", selector),
        'digitalocean_droplet.edge["sfo3-01"]': DigitalOceanNodeCreate("edge-eng-opaque-sfo3-01", "ubuntu-22-04-x64", "s-1vcpu-1gb", "sfo3", selector),
    }
    firewall = DigitalOceanInitialFirewallIntent("eng-opaque-firewall", selector, ("80", "443", "2222"), (), ("192.0.2.1/32",))
    kwargs = dict(
        environment="devtest", deployment_target="barragan-testing",
        expected_connection_id="cred-000000000001",
        input_sha256={var_file: hashlib.sha256(var_file.read_bytes()).hexdigest()},
        var_files=[var_file], expected_nodes=nodes, expected_ssh_key_name="opaque-key",
        expected_ssh_public_key="ssh-ed25519 fixture", expected_firewall=firewall,
        expected_local_files={}, credential_repository=repository,
        command_environment={"PATH": "/usr/bin", "UNRELATED_SECRET": "hidden"},
        expected_terraform_sha256=hashlib.sha256(Path("/usr/bin/true").resolve().read_bytes()).hexdigest(),
        terraform="/usr/bin/true",
        command_runner=runner,
    )
    return workspace, kwargs, runner, repository, gate_calls, var_file


def test_full_plan_is_saved_inspected_and_bound_to_immutable_evidence(prepared):
    workspace, kwargs, runner, _, gate_calls, var_file = prepared
    evidence = service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert [call[0][1] for call in runner.calls] == ["version", "init", "plan", "show"]
    assert "-lockfile=readonly" in runner.calls[1][0]
    assert not any(arg == "-target" or arg.startswith("-target=") for call in runner.calls for arg in call[0])
    staged_argument = next(arg for arg in runner.calls[2][0] if arg.startswith("-var-file="))
    staged_path = Path(staged_argument.split("=", 1)[1])
    assert staged_path.parent.parent == workspace.path
    assert staged_path.name == "input-0.input"
    assert not staged_path.exists()  # temporary secret copy is removed after review
    assert runner.calls[2][0][-1].endswith("/credential.json")
    assert not Path(runner.calls[2][0][-1].split("=", 1)[1]).exists()
    assert runner.calls[3][0][-1] == str(evidence.plan_path)
    assert all(call[2]["TF_DATA_DIR"] == str(workspace.terraform_data_dir) for call in runner.calls)
    assert all(call[2]["TF_CLI_CONFIG_FILE"] == "/dev/null" for call in runner.calls)
    assert all("UNRELATED_SECRET" not in call[2] for call in runner.calls)
    assert json.loads(gate_calls[0][0])["variables"]["middles"]["value"]["primary"]["ordinal"] == 1
    assert gate_calls[0][1]["workspace"] == workspace
    assert evidence.plan_sha256 == hashlib.sha256(b"binary plan").hexdigest()
    assert evidence.state_sha256 is None
    assert evidence.topology_sha256 == hashlib.sha256((workspace.path / ".barragan-topology.json").read_bytes()).hexdigest()
    assert evidence.credential_record_id == workspace.provider_connection_id
    assert evidence.credential_secret_sha256 == hashlib.sha256(b"encrypted-fixture-token").hexdigest()
    assert evidence.terraform_binary_sha256 == hashlib.sha256(Path("/usr/bin/true").resolve().read_bytes()).hexdigest()
    assert evidence.plan_path.stat().st_mode & 0o777 == 0o600
    assert evidence.input_sha256 == ((str(var_file), kwargs["input_sha256"][var_file]),)
    assert "redacted-test-value" not in repr(evidence)
    assert "central-do-token" not in repr(evidence)


@pytest.mark.parametrize("failure", ["prod", "connection", "state", "input", "var_location", "old_plan"])
def test_preflight_rejects_unsafe_inputs_without_running_terraform(prepared, failure):
    workspace, kwargs, runner, repository, _, var_file = prepared
    if failure == "prod":
        kwargs["environment"] = "prod"
    elif failure == "connection":
        repository.connection_id = "cred-other"
    elif failure == "state":
        workspace.state_path.write_text("{}")
    elif failure == "input":
        var_file.write_text("changed")
    elif failure == "var_location":
        kwargs["var_files"] = [workspace.path / "secret.tfvars"]
    else:
        (workspace.path / service._PLAN_NAME).write_text("prior plan")
    with pytest.raises(service.ProviderKeyedPlanPreparationError):
        service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert not runner.calls
    if failure == "old_plan":
        assert (workspace.path / service._PLAN_NAME).read_text() == "prior plan"


@pytest.mark.parametrize("command", ["init", "plan", "show"])
def test_command_failure_is_redacted_and_removes_only_new_plan(prepared, command):
    workspace, kwargs, runner, _, _, _ = prepared
    runner.fail = command
    with pytest.raises(service.ProviderKeyedPlanPreparationError) as exc:
        service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert "secret-from-provider-command" not in str(exc.value)
    assert not (workspace.path / service._PLAN_NAME).exists()


def test_rejects_input_or_credential_change_during_plan(prepared):
    workspace, kwargs, runner, repository, _, var_file = prepared
    runner.after_plan = lambda: setattr(repository, "connection_id", "cred-other")
    with pytest.raises(service.ProviderKeyedPlanPreparationError, match="connection differs"):
        service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)


def test_rejects_same_record_credential_rotation_during_plan(prepared):
    workspace, kwargs, runner, repository, _, _ = prepared
    runner.after_plan = lambda: setattr(repository, "encrypted_secret", "rotated-ciphertext")
    with pytest.raises(service.ProviderKeyedPlanPreparationError, match="credential rotated"):
        service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert not (workspace.path / service._PLAN_NAME).exists()


def test_rejects_mismatched_or_inactive_exact_credential_record(prepared):
    workspace, kwargs, runner, repository, _, _ = prepared
    repository.get = lambda credential_id: None
    with pytest.raises(service.ProviderKeyedPlanPreparationError, match="connection differs"):
        service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert not runner.calls


def test_plan_uses_sealed_copy_even_if_external_source_changes(prepared):
    workspace, kwargs, runner, _, _, var_file = prepared
    original = var_file.read_bytes()
    observed = []

    def inspect_staged():
        command = runner.calls[-1][0]
        var_paths = [Path(arg.split("=", 1)[1]) for arg in command if arg.startswith("-var-file=")]
        staged = var_paths[0]
        observed.append((staged.read_bytes(), staged.stat().st_mode & 0o777,
                         var_paths[-1].read_text(), var_paths[-1].stat().st_mode & 0o777))
        var_file.write_text("changed after staging")

    runner.after_plan = inspect_staged
    evidence = service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert observed == [(original, 0o600, '{"do_pat": "central-do-token"}\n', 0o600)]
    assert evidence.input_sha256 == ((str(var_file), hashlib.sha256(original).hexdigest()),)


def test_rejects_staged_input_mutation_during_plan(prepared):
    workspace, kwargs, runner, _, _, _ = prepared

    def mutate_staged():
        command = runner.calls[-1][0]
        staged = Path(next(arg.split("=", 1)[1] for arg in command if arg.startswith("-var-file=")))
        staged.write_text("changed")

    runner.after_plan = mutate_staged
    with pytest.raises(service.ProviderKeyedPlanPreparationError, match="input changed"):
        service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert not (workspace.path / service._PLAN_NAME).exists()


def test_rejects_terraform_version_and_provider_lock_drift(prepared):
    workspace, kwargs, runner, _, _, _ = prepared
    (workspace.path / ".terraform.lock.hcl").write_text('provider "registry.terraform.io/digitalocean/digitalocean" { version = "2.104.0" }')
    with pytest.raises(service.ProviderKeyedPlanPreparationError, match="provider lock"):
        service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert not runner.calls


@pytest.mark.parametrize("which", ["state", "data"])
def test_rejects_noncanonical_state_or_data_directory(prepared, which):
    workspace, kwargs, runner, _, _, _ = prepared
    changed = replace(
        workspace,
        **({"state_path": workspace.path / "other.tfstate"} if which == "state"
           else {"terraform_data_dir": workspace.path / "other-data"}),
    )
    with pytest.raises(service.ProviderKeyedPlanPreparationError, match="not canonical"):
        service.prepare_digitalocean_keyed_initial_full_plan(changed, **kwargs)
    assert not runner.calls


def test_rejects_node_intent_different_from_reserved_topology(prepared):
    workspace, kwargs, runner, _, _, _ = prepared
    nodes = dict(kwargs["expected_nodes"])
    address = 'digitalocean_droplet.edge["sfo3-01"]'
    nodes[address] = replace(nodes[address], region="nyc3")
    kwargs["expected_nodes"] = nodes
    with pytest.raises(service.ProviderKeyedPlanPreparationError, match="reserved topology"):
        service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert not runner.calls


def test_rejects_saved_plan_with_different_middle_association(prepared):
    workspace, kwargs, runner, _, _, _ = prepared
    payload = json.loads(runner.plan_json)
    payload["variables"]["edge_groups"]["value"]["sfo"]["middle_node"] = "other"
    runner.plan_json = json.dumps(payload)
    with pytest.raises(service.ProviderKeyedPlanPreparationError, match="edge group"):
        service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert [args[0][1] for args in runner.calls] == ["version", "init", "plan", "show"]
    assert not (workspace.path / service._PLAN_NAME).exists()


def test_accepts_equivalent_count_allocation_and_rejects_different_start(prepared):
    workspace, kwargs, runner, _, _, _ = prepared
    payload = json.loads(runner.plan_json)
    group = payload["variables"]["edge_groups"]["value"]["sfo"]
    group.update(count=1, ordinal_start=1, ordinals=None)
    runner.plan_json = json.dumps(payload)
    service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    (workspace.path / service._PLAN_NAME).unlink()
    group["ordinal_start"] = 2
    runner.plan_json = json.dumps(payload)
    with pytest.raises(service.ProviderKeyedPlanPreparationError, match="allocation differs"):
        service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)


def test_rejects_unreviewed_terraform_binary_before_commands(prepared):
    workspace, kwargs, runner, _, _, _ = prepared
    kwargs["expected_terraform_sha256"] = "0" * 64
    with pytest.raises(service.ProviderKeyedPlanPreparationError, match="reviewed release"):
        service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert not runner.calls


@pytest.mark.parametrize("unsafe", [
    {"TF_VAR_do_pat": "hidden"}, {"TF_CLI_ARGS_plan": "-destroy"},
    {"TF_WORKSPACE": "other"}, {"TF_LOG": "TRACE"},
])
def test_rejects_unreviewed_terraform_environment(prepared, unsafe):
    workspace, kwargs, runner, _, _, _ = prepared
    kwargs["command_environment"] = {"PATH": "/usr/bin", **unsafe}
    with pytest.raises(service.ProviderKeyedPlanPreparationError, match="environment"):
        service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert not runner.calls


def test_rejects_world_readable_workspace_or_var_file(prepared):
    workspace, kwargs, runner, _, _, var_file = prepared
    workspace.path.chmod(0o755)
    with pytest.raises(service.ProviderKeyedPlanPreparationError, match="workspace is not private"):
        service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    workspace.path.chmod(0o700)
    var_file.chmod(0o644)
    with pytest.raises(service.ProviderKeyedPlanPreparationError, match="var files must be private"):
        service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert not runner.calls


def test_accepts_collaborator_workspace_and_regional_lock(prepared, monkeypatch):
    workspace, kwargs, runner, _, _, _ = prepared
    workspace.path.chmod(0o2750)
    (workspace.path.parents[1] / ".regional-ordinals.lock").chmod(0o640)
    monkeypatch.setattr(service, "_collaborator_group_gid", lambda: workspace.path.stat().st_gid)
    service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert [call[0][1] for call in runner.calls] == ["version", "init", "plan", "show"]


def test_plan_file_is_precreated_private_and_tampering_fails_closed(prepared):
    workspace, kwargs, runner, _, _, _ = prepared
    plan_path = workspace.path / service._PLAN_NAME
    observed = []
    runner.before_plan = lambda path: observed.append((path == plan_path, path.stat().st_mode & 0o777))
    service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert observed == [(True, 0o600)]
    plan_path.unlink()

    def make_world_readable(path):
        path.chmod(0o644)

    runner.before_plan = make_world_readable
    with pytest.raises(service.ProviderKeyedPlanPreparationError, match="unsafe"):
        service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert not plan_path.exists()


def test_failed_plan_does_not_delete_replacement_path(prepared):
    workspace, kwargs, runner, _, _, _ = prepared
    plan_path = workspace.path / service._PLAN_NAME

    def replace(path):
        path.unlink()
        path.write_bytes(b"replacement")
        path.chmod(0o600)

    runner.before_plan = replace
    runner.fail = "show"
    with pytest.raises(service.ProviderKeyedPlanPreparationError):
        service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert plan_path.read_bytes() == b"binary plan"


def test_replaced_plan_in_same_private_mode_cannot_pass(prepared):
    workspace, kwargs, runner, _, _, _ = prepared
    plan_path = workspace.path / service._PLAN_NAME

    def replace(path):
        path.unlink()
        path.write_bytes(b"replacement")
        path.chmod(0o600)

    runner.before_plan = replace
    with pytest.raises(service.ProviderKeyedPlanPreparationError, match="unsafe"):
        service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert plan_path.is_file()


def test_real_runner_sets_child_umask(monkeypatch, tmp_path):
    observed = []
    monkeypatch.setattr(service.subprocess, "run", lambda *args, **kwargs: observed.append(kwargs))
    service._run_command(["terraform", "version"], tmp_path, {})
    assert observed[0]["umask"] == 0o077


@pytest.mark.parametrize("workspace_mode,lock_mode", [(0o2750, 0o600), (0o700, 0o640)])
def test_wrong_group_is_rejected_only_for_group_readable_artifact(
    prepared, monkeypatch, workspace_mode, lock_mode,
):
    workspace, kwargs, runner, _, _, _ = prepared
    workspace.path.chmod(workspace_mode)
    (workspace.path.parents[1] / ".regional-ordinals.lock").chmod(lock_mode)
    monkeypatch.setattr(service, "_collaborator_group_gid", lambda: workspace.path.stat().st_gid + 1)
    with pytest.raises(service.ProviderKeyedPlanPreparationError):
        service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert not runner.calls


@pytest.mark.parametrize("workspace_mode,lock_mode", [
    (0o2770, 0o640), (0o2755, 0o640), (0o2750, 0o660), (0o2750, 0o644),
])
def test_rejects_writable_or_world_readable_workspace_or_regional_lock(
    prepared, workspace_mode, lock_mode, monkeypatch,
):
    workspace, kwargs, runner, _, _, _ = prepared
    workspace.path.chmod(workspace_mode)
    (workspace.path.parents[1] / ".regional-ordinals.lock").chmod(lock_mode)
    monkeypatch.setattr(service, "_collaborator_group_gid", lambda: workspace.path.stat().st_gid)
    with pytest.raises(service.ProviderKeyedPlanPreparationError):
        service.prepare_digitalocean_keyed_initial_full_plan(workspace, **kwargs)
    assert not runner.calls
