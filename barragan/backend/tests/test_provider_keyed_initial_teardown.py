# Copyright (c) 2026, Oracle and/or its affiliates.
"""Fail-closed checks for a non-executing provider-keyed destroy preview."""

import json
import hashlib
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

import app.services.provider_keyed_initial_teardown as service
from app.services.provider_keyed_initial_teardown import (
    DigitalOceanTeardownIntent, ProviderKeyedTeardownPreviewError,
    ProviderKeyedTeardownPreviewUncertainError,
    prepare_digitalocean_keyed_initial_teardown_preview,
    require_exact_digitalocean_destroy_plan,
)
from app.services.provider_keyed_initial_plan_gate import (
    DigitalOceanInitialFirewallIntent, DigitalOceanNodeCreate,
)
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace


def _fixture():
    resources = [
        ("digitalocean_droplet.middle", "primary", "1001"),
        ("digitalocean_droplet.edge", "sfo3-01", "1002"),
        ("digitalocean_ssh_key.key", None, "2001"),
        ("digitalocean_firewall.firewall", None, "firewall-opaque"),
        ("local_file.ansible_inventory", 0, "local-1"),
        ("local_file.ssh_stanza", 0, "local-2"),
    ]
    state_resources = []
    prior_resources = []
    changes = []
    ids = {}
    for base, key, identity in resources:
        address = base + (f"[{json.dumps(key)}]" if key is not None else "")
        values = {"id": identity, "name": "opaque"}
        item = {"mode": "managed", "type": base.split(".")[0], "name": base.split(".")[1],
                "instances": [{"attributes": values}]}
        if key is not None:
            item["instances"][0]["index_key"] = key
        state_resources.append(item)
        prior_resources.append({"address": address, "mode": "managed", "values": deepcopy(values)})
        changes.append({"address": address, "change": {
            "actions": ["delete"], "before": deepcopy(values), "after": None,
            "after_unknown": {},
        }})
        ids[address] = identity
    state = {"version": 4, "resources": state_resources}
    plan = {"format_version": "1.2", "terraform_version": "1.15.5",
            "applyable": True, "complete": True, "errored": False,
            "prior_state": {"values": {"root_module": {"resources": prior_resources}}},
            "planned_values": {"root_module": {}}, "resource_changes": changes}
    return state, ids, plan


def _accept(state, ids, plan):
    require_exact_digitalocean_destroy_plan(
        json.dumps(plan), expected_resource_ids=ids, state=state,
    )


def test_exact_full_delete_is_accepted():
    _accept(*_fixture())


def test_terraform_115_top_level_output_delete_actions_are_accepted():
    state, ids, plan = _fixture()
    # Captured from an isolated Terraform 1.15.5 builtin-resource destroy
    # plan: output_changes entries have top-level actions, not change.actions.
    plan["output_changes"] = {
        "public-key": {
            "actions": ["delete"], "before": "opaque",
            "after": None, "after_unknown": False,
            "before_sensitive": False, "after_sensitive": False,
        },
        "unchanged": {"actions": ["no-op"], "before": "opaque", "after": "opaque"},
    }
    _accept(state, ids, plan)


def test_documented_nested_output_delete_actions_are_accepted():
    state, ids, plan = _fixture()
    plan["output_changes"] = {
        "public-key": {"change": {
            "actions": ["delete"], "before": "opaque", "after": None,
        }},
        "unchanged": {"change": {
            "actions": ["no-op"], "before": "opaque", "after": "opaque",
        }},
    }
    _accept(state, ids, plan)


@pytest.mark.parametrize("output_changes", [
    {"opaque": {"actions": ["create"]}},
    {"opaque": {"actions": ["update"]}},
    {"opaque": {"actions": ["delete", "create"]}},
    {"opaque": {"actions": ["delete"], "change": {"actions": ["delete"]}}},
    {"opaque": {"change": {"actions": ["create"]}}},
    {"opaque": {"change": {"actions": ["delete"]}, "extra": True}},
    {"opaque": {"change": None}},
    {"opaque": None},
    [],
])
def test_output_changes_reject_non_destroy_or_malformed_actions(output_changes):
    state, ids, plan = _fixture()
    plan["output_changes"] = output_changes
    with pytest.raises(ProviderKeyedTeardownPreviewError) as failure:
        _accept(state, ids, plan)
    assert failure.value.stage == "exact_delete"
    assert failure.value.predicate_category == "output"


@pytest.mark.parametrize("category,mutate", [
    ("envelope", lambda state, ids, plan: plan.update(format_version="secret-2")),
    ("state_prior_inventory", lambda state, ids, plan:
     plan["prior_state"]["values"]["root_module"]["resources"][0]["values"].update(id="secret-id")),
    ("action_before", lambda state, ids, plan:
     plan["resource_changes"][0]["change"].update(actions=["secret-update"])),
    ("output", lambda state, ids, plan: plan.update(output_changes={
        "secret-output": {"actions": ["create"]},
    })),
    ("planned_remainder", lambda state, ids, plan: plan.update(planned_values={
        "root_module": {"resources": [{"address": "secret-survivor"}]},
    })),
])
def test_exact_delete_rejection_exposes_only_bounded_predicate(category, mutate):
    state, ids, plan = _fixture()
    mutate(state, ids, plan)
    with pytest.raises(ProviderKeyedTeardownPreviewError) as failure:
        _accept(state, ids, plan)
    assert failure.value.stage == "exact_delete"
    assert failure.value.predicate_category == category
    assert "secret" not in str(failure.value) + repr(failure.value)


def test_terraform_115_prior_values_can_differ_from_raw_state_encoding():
    state, ids, plan = _fixture()
    # Terraform's raw v4 state uses typed encoding for some complex values;
    # show -json normalizes them in prior_state and resource_changes.before.
    state["resources"][0]["instances"][0]["attributes"]["input"] = {
        "type": "string", "value": "opaque",
    }
    plan["prior_state"]["values"]["root_module"]["resources"][0]["values"]["input"] = "opaque"
    plan["resource_changes"][0]["change"]["before"]["input"] = "opaque"
    _accept(state, ids, plan)


@pytest.mark.parametrize("mutation", [
    lambda state, ids, plan: plan["resource_changes"].pop(),
    lambda state, ids, plan: plan["resource_changes"][0]["change"].update(actions=["update"]),
    lambda state, ids, plan: plan["resource_changes"][0]["change"].update(after={"id": "1001"}),
    lambda state, ids, plan: plan["resource_changes"][0]["change"]["before"].update(id="9999"),
    lambda state, ids, plan: plan["prior_state"]["values"]["root_module"]["resources"][0]["values"].update(name="changed"),
    lambda state, ids, plan: plan.update(resource_drift=[{"address": "unrelated"}]),
    lambda state, ids, plan: plan["resource_changes"].append(deepcopy(plan["resource_changes"][0])),
    lambda state, ids, plan: plan["resource_changes"][0].update(deposed="abc"),
    lambda state, ids, plan: plan.update(planned_values={"root_module": {"resources": [{"address": "survivor"}]}}),
    lambda state, ids, plan: ids.update({"unmanaged.resource": "3333"}),
])
def test_rejects_nonexact_destroy(mutation):
    state, ids, plan = _fixture()
    mutation(state, ids, plan)
    with pytest.raises(ProviderKeyedTeardownPreviewError):
        _accept(state, ids, plan)


def test_teardown_preview_rejects_non_devtest_without_commands():
    state, ids, _ = _fixture()
    intent = DigitalOceanTeardownIntent(
        nodes={'digitalocean_droplet.middle["primary"]': DigitalOceanNodeCreate(
            "middle01-opaque", "ubuntu-22-04-x64", "s-1vcpu-1gb", "nyc3", "opaque-selector-a1",
        )},
        firewall=DigitalOceanInitialFirewallIntent(
            "opaque-firewall", "opaque-selector-a1", ("80", "443", "2222"), (), ("192.0.2.1/32",),
        ),
        resource_ids=ids, state_sha256="0" * 64,
        credential_record_id="cred-opaque", credential_secret_sha256="1" * 64,
        credential_updated_at="2026-10-02T00:00:00Z",
    )
    with pytest.raises(ProviderKeyedTeardownPreviewError, match="disposable DevTest"):
        prepare_digitalocean_keyed_initial_teardown_preview(
            None, intent, environment="prod", deployment_target="production",
            input_sha256={}, var_files=[], credential_repository=None,
            command_environment={}, expected_terraform_sha256="2" * 64,
        )


class _Runner:
    def __init__(self, plan):
        self.plan = plan
        self.calls = []
        self.fail_on = None
        self.before_plan = None

    def __call__(self, args, cwd, env):
        self.calls.append((args, cwd, env))
        if args[1] == "plan":
            plan_path = Path(next(value.split("=", 1)[1] for value in args if value.startswith("-out=")))
            if self.before_plan:
                self.before_plan(plan_path)
            plan_path.write_bytes(b"opaque saved destroy plan")
        if args[1] == self.fail_on:
            return subprocess.CompletedProcess(args, 1, "", "secret-from-command")
        if args[1] == "version":
            return subprocess.CompletedProcess(args, 0, '{"terraform_version":"1.15.5"}', "")
        if args[1] == "show":
            return subprocess.CompletedProcess(args, 0, json.dumps(self.plan), "")
        return subprocess.CompletedProcess(args, 0, "", "")


@pytest.fixture
def preview_setup(tmp_path, monkeypatch):
    schema_root = tmp_path / "eng-opaque" / "provider-keyed-v2"
    root = schema_root / "digitalocean" / "fingerprint"
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    (root / ".terraform-data").mkdir(mode=0o700)
    (schema_root / ".regional-ordinals.lock").write_text("")
    (schema_root / ".regional-ordinals.lock").chmod(0o600)
    (root / ".barragan-initial-full-plan.lock").write_text("")
    (root / ".barragan-initial-full-plan.lock").chmod(0o600)
    (root / ".barragan-provider-keyed-state.json").write_text('{"schema":"provider-keyed-v2"}')
    (root / ".terraform.lock.hcl").write_text(
        'provider "registry.terraform.io/digitalocean/digitalocean" {\n  version = "2.103.0"\n}\n'
    )
    (root / ".barragan-apply-phase.json").write_text('{"schema":"provider-keyed-v2","phase":"applied"}')
    topology = {"schema": "provider-keyed-v2", "middles": {"primary": {"region": "nyc3", "ordinal": 1}},
                "edge_groups": {"sfo": {"region": "sfo3", "middle_node": "primary", "ordinals": [1]}}}
    (root / ".barragan-topology.json").write_text(json.dumps(topology))
    workspace = ProviderKeyedWorkspace(
        root, root / "terraform.tfstate", root / ".terraform-data", "provider-keyed-v2",
        "digitalocean", "cred-opaque", "fingerprint",
        "ca5bcad7d2be274aaa79d6c9127cbd9b5c2b10cc", "source-fixture-hash",
    )
    state, ids, plan = _fixture()
    selector = "opaque-selector-a1"
    nodes = {
        'digitalocean_droplet.middle["primary"]': DigitalOceanNodeCreate(
            "middle01-opaque", "ubuntu-22-04-x64", "s-1vcpu-1gb", "nyc3", selector,
        ),
        'digitalocean_droplet.edge["sfo3-01"]': DigitalOceanNodeCreate(
            "edge-opaque-sfo3-01", "ubuntu-22-04-x64", "s-1vcpu-1gb", "sfo3", selector,
        ),
    }
    firewall = DigitalOceanInitialFirewallIntent(
        "opaque-firewall", selector, ("80", "443", "2222"), (), ("192.0.2.1/32",),
    )
    for address, node in nodes.items():
        index = 0 if ".middle" in address else 1
        values = state["resources"][index]["instances"][0]["attributes"]
        values.update(name=node.name, image=node.image, size=node.size,
                      region=node.region, tags=[selector])
        plan["prior_state"]["values"]["root_module"]["resources"][index]["values"] = deepcopy(values)
        plan["resource_changes"][index]["change"]["before"] = deepcopy(values)
    firewall_values = state["resources"][3]["instances"][0]["attributes"]
    firewall_values.update(name=firewall.name, tags=[selector])
    plan["prior_state"]["values"]["root_module"]["resources"][3]["values"] = deepcopy(firewall_values)
    plan["resource_changes"][3]["change"]["before"] = deepcopy(firewall_values)
    state.update(lineage="047f8280-73d6-4d3a-8dfa-9d0c1bb3f084", serial=1,
                 terraform_version="1.15.5")
    workspace.state_path.write_text(json.dumps(state))
    plan["variables"] = {
        "middles": {"value": topology["middles"]},
        "edge_groups": {"value": {"sfo": {**topology["edge_groups"]["sfo"], "count": None, "ordinal_start": 1}}},
    }
    var_file = tmp_path / "reviewed.tfvars"
    var_file.write_text('engagement_name = "opaque"\n')
    var_file.chmod(0o600)
    monkeypatch.setattr(service, "_verify_audited_workspace", lambda workspace: None)
    monkeypatch.setattr(service, "decrypt_secret_value", lambda encrypted: "central-fixture-token")
    monkeypatch.setattr(service, "_credential_snapshot",
                        lambda connection, repository: ("a" * 64, "2026-10-02T00:00:00Z", "encrypted-fixture"))
    executable = Path("/usr/bin/true").resolve()
    binary_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
    intent = DigitalOceanTeardownIntent(
        nodes, firewall, ids, hashlib.sha256(workspace.state_path.read_bytes()).hexdigest(),
        "cred-opaque", "a" * 64, "2026-10-02T00:00:00Z",
    )
    runner = _Runner(plan)
    kwargs = dict(
        environment="devtest", deployment_target="barragan-testing",
        input_sha256={var_file: hashlib.sha256(var_file.read_bytes()).hexdigest()},
        var_files=[var_file], credential_repository=object(),
        command_environment={"PATH": "/usr/bin", "UNRELATED_SECRET": "hidden"},
        expected_terraform_sha256=binary_hash, terraform=str(executable),
        command_runner=runner,
    )
    return workspace, intent, kwargs, runner


def test_preview_saves_exact_destroy_plan_and_binds_evidence(preview_setup, monkeypatch):
    workspace, intent, kwargs, runner = preview_setup
    workspace.path.chmod(0o2750)
    (workspace.path.parents[1] / ".regional-ordinals.lock").chmod(0o640)
    monkeypatch.setattr("app.services.provider_keyed_saved_plan_runner._collaborator_group_gid",
                        lambda: workspace.path.stat().st_gid)
    result = prepare_digitalocean_keyed_initial_teardown_preview(workspace, intent, **kwargs)
    assert [call[0][1] for call in runner.calls] == ["version", "init", "plan", "show"]
    assert "-destroy" in runner.calls[2][0]
    assert "-lockfile=readonly" in runner.calls[1][0]
    assert not any(arg.startswith("-target") for call in runner.calls for arg in call[0])
    assert runner.calls[2][0][-1].endswith("/credential.json")
    assert all("UNRELATED_SECRET" not in call[2] for call in runner.calls)
    assert result.state_sha256 == intent.state_sha256
    assert result.credential_record_id == intent.credential_record_id
    assert result.plan_sha256 == hashlib.sha256(result.plan_path.read_bytes()).hexdigest()
    assert result.plan_path.stat().st_mode & 0o077 == 0
    assert json.loads((workspace.path / ".barragan-apply-phase.json").read_text())["phase"] == "applied"
    assert not list(workspace.path.glob(".barragan-plan-inputs-*"))


@pytest.mark.parametrize("stage", [
    "plan_integrity", "exact_delete", "topology_variables", "unchanged_inputs",
])
def test_post_show_failure_reports_only_bounded_stage(preview_setup, monkeypatch, stage):
    workspace, intent, kwargs, runner = preview_setup
    secret = "secret-from-provider-output"
    if stage == "plan_integrity":
        original = runner.__call__

        def changed_after_show(args, cwd, env):
            result = original(args, cwd, env)
            if args[1] == "show":
                (workspace.path / service._PLAN).write_bytes(secret.encode())
            return result

        kwargs["command_runner"] = changed_after_show
    elif stage == "exact_delete":
        runner.plan["resource_changes"][0]["change"]["actions"] = ["update"]
    elif stage == "topology_variables":
        runner.plan = deepcopy(runner.plan)
        runner.plan["variables"]["middles"]["value"]["primary"]["ordinal"] = 2
    else:
        original = service._require_unchanged
        calls = 0

        def changed_after_show(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ValueError(secret)
            return original(*args)

        monkeypatch.setattr(service, "_require_unchanged", changed_after_show)
    with pytest.raises(ProviderKeyedTeardownPreviewError) as error:
        prepare_digitalocean_keyed_initial_teardown_preview(workspace, intent, **kwargs)
    assert [call[0][1] for call in runner.calls] == ["version", "init", "plan", "show"]
    assert error.value.stage == stage
    assert error.value.predicate_category == (
        "action_before" if stage == "exact_delete" else None)
    assert secret not in str(error.value)
    assert not (workspace.path / service._PLAN).exists()


def _preselected(workspace):
    return workspace.path / (".barragan-destroy-inputs-" + "a" * 32)


def test_preselected_private_staging_is_used_and_removed_on_success(preview_setup):
    workspace, intent, kwargs, runner = preview_setup
    selected = _preselected(workspace)
    result = prepare_digitalocean_keyed_initial_teardown_preview(
        workspace, intent, staging_path=selected, authority_check=lambda: None, **kwargs,
    )
    plan_args = runner.calls[2][0]
    assert f"-var-file={selected / 'input-0.input'}" in plan_args
    assert plan_args[-1] == f"-var-file={selected / 'credential.json'}"
    assert result.plan_path.is_file()
    assert not selected.exists()


@pytest.mark.parametrize("bad_path", ["existing", "outside", "wrong_name"])
def test_preselected_staging_vetoes_before_commands_or_creation(preview_setup, bad_path):
    workspace, intent, kwargs, runner = preview_setup
    selected = _preselected(workspace)
    if bad_path == "existing":
        selected.mkdir(mode=0o700)
    elif bad_path == "outside":
        selected = workspace.path.parent / selected.name
    else:
        selected = workspace.path / "not-an-audited-name"
    with pytest.raises(ProviderKeyedTeardownPreviewError):
        prepare_digitalocean_keyed_initial_teardown_preview(
            workspace, intent, staging_path=selected, authority_check=lambda: None, **kwargs,
        )
    assert not runner.calls
    assert not (workspace.path / service._PLAN).exists()


@pytest.mark.parametrize("veto_at", [1, 2, 3, 4])
def test_claim_authority_veto_precedes_each_internal_staging_write(preview_setup, veto_at):
    workspace, intent, kwargs, runner = preview_setup
    selected = _preselected(workspace)
    observed = []

    def check_authority():
        observed.append((
            selected.exists(), (selected / "input-0.input").exists(),
            (selected / "credential.json").exists(),
            (workspace.path / service._PLAN).exists(),
        ))
        if len(observed) == veto_at:
            raise ValueError("claim lost")

    with pytest.raises(ProviderKeyedTeardownPreviewError):
        prepare_digitalocean_keyed_initial_teardown_preview(
            workspace, intent, staging_path=selected,
            authority_check=check_authority, **kwargs,
        )
    assert observed[:4] == [
        (False, False, False, False),
        (True, False, False, False),
        (True, True, False, False),
        (True, True, True, False),
    ][:veto_at]
    assert not selected.exists()
    assert not (workspace.path / service._PLAN).exists()
    assert not any(args[1] == "plan" for args in runner.calls)


def test_preselected_staging_requires_authority_callback(preview_setup):
    workspace, intent, kwargs, runner = preview_setup
    selected = _preselected(workspace)
    with pytest.raises(ProviderKeyedTeardownPreviewError):
        prepare_digitalocean_keyed_initial_teardown_preview(
            workspace, intent, staging_path=selected, **kwargs,
        )
    assert not selected.exists()
    assert not runner.calls


@pytest.mark.parametrize("at_command", ["version", "plan"])
def test_uncertain_command_retains_exact_staging_and_owned_plan(preview_setup, at_command):
    workspace, intent, kwargs, runner = preview_setup
    selected = _preselected(workspace)
    original = kwargs["command_runner"]

    def uncertain_run(args, cwd, env):
        result = original(args, cwd, env)
        if args[1] == at_command:
            raise ProviderKeyedTeardownPreviewUncertainError("result audit missing")
        return result

    kwargs["command_runner"] = uncertain_run
    with pytest.raises(ProviderKeyedTeardownPreviewUncertainError):
        prepare_digitalocean_keyed_initial_teardown_preview(
            workspace, intent, staging_path=selected, authority_check=lambda: None, **kwargs,
        )
    assert (selected / "input-0.input").is_file()
    assert (selected / "credential.json").is_file()
    assert (workspace.path / service._PLAN).exists() is (at_command == "plan")


def test_proven_command_failure_cleans_exact_preselected_files(preview_setup):
    workspace, intent, kwargs, runner = preview_setup
    selected = _preselected(workspace)
    runner.fail_on = "show"
    with pytest.raises(ProviderKeyedTeardownPreviewError):
        prepare_digitalocean_keyed_initial_teardown_preview(
            workspace, intent, staging_path=selected, authority_check=lambda: None, **kwargs,
        )
    assert not selected.exists()
    assert not (workspace.path / service._PLAN).exists()


def test_credential_partial_creation_is_retained_as_uncertain(preview_setup, monkeypatch):
    workspace, intent, kwargs, runner = preview_setup
    selected = _preselected(workspace)

    def partial_credential(directory, token):
        (directory / "credential.json").write_text("partial")
        raise OSError("write interrupted")

    monkeypatch.setattr(service, "_stage_credential", partial_credential)
    with pytest.raises(ProviderKeyedTeardownPreviewUncertainError):
        prepare_digitalocean_keyed_initial_teardown_preview(
            workspace, intent, staging_path=selected, authority_check=lambda: None, **kwargs,
        )
    assert (selected / "credential.json").is_file()
    assert not runner.calls


def test_success_cleanup_uncertainty_retains_reviewed_plan(preview_setup, monkeypatch):
    workspace, intent, kwargs, runner = preview_setup
    selected = _preselected(workspace)
    original = service._remove_staging_checked

    def fail_cleanup(path, identity, names):
        if path == selected:
            raise ProviderKeyedTeardownPreviewUncertainError("cleanup unproved")
        return original(path, identity, names)

    monkeypatch.setattr(service, "_remove_staging_checked", fail_cleanup)
    with pytest.raises(ProviderKeyedTeardownPreviewUncertainError):
        prepare_digitalocean_keyed_initial_teardown_preview(
            workspace, intent, staging_path=selected, authority_check=lambda: None, **kwargs,
        )
    assert (workspace.path / service._PLAN).is_file()
    assert (selected / "credential.json").is_file()


def test_destroy_plan_precreated_private_and_tampering_fails_closed(preview_setup):
    workspace, intent, kwargs, runner = preview_setup
    plan_path = workspace.path / service._PLAN
    observed = []
    runner.before_plan = lambda path: observed.append((path == plan_path, path.stat().st_mode & 0o777))
    prepare_digitalocean_keyed_initial_teardown_preview(workspace, intent, **kwargs)
    assert observed == [(True, 0o600)]
    plan_path.unlink()
    runner.before_plan = lambda path: path.chmod(0o644)
    with pytest.raises(ProviderKeyedTeardownPreviewError):
        prepare_digitalocean_keyed_initial_teardown_preview(workspace, intent, **kwargs)
    assert not plan_path.exists()


def test_failed_destroy_plan_does_not_delete_replacement_path(preview_setup):
    workspace, intent, kwargs, runner = preview_setup
    plan_path = workspace.path / service._PLAN

    def replace(path):
        path.unlink()
        path.write_bytes(b"replacement")
        path.chmod(0o600)

    runner.before_plan = replace
    runner.fail_on = "show"
    with pytest.raises(ProviderKeyedTeardownPreviewError):
        prepare_digitalocean_keyed_initial_teardown_preview(workspace, intent, **kwargs)
    assert plan_path.read_bytes() == b"opaque saved destroy plan"


def test_replaced_destroy_plan_in_same_private_mode_cannot_pass(preview_setup):
    workspace, intent, kwargs, runner = preview_setup
    plan_path = workspace.path / service._PLAN

    def replace(path):
        path.unlink()
        path.write_bytes(b"replacement")
        path.chmod(0o600)

    runner.before_plan = replace
    with pytest.raises(ProviderKeyedTeardownPreviewError):
        prepare_digitalocean_keyed_initial_teardown_preview(workspace, intent, **kwargs)
    assert plan_path.is_file()


def test_real_destroy_runner_sets_child_umask(monkeypatch, tmp_path):
    observed = []
    monkeypatch.setattr(service.subprocess, "run", lambda *args, **kwargs: observed.append(kwargs))
    service._run_command(["terraform", "version"], tmp_path, {})
    assert observed[0]["umask"] == 0o077


def test_failed_preview_removes_its_plan_but_preserves_applied_state(preview_setup):
    workspace, intent, kwargs, runner = preview_setup
    original_state = workspace.state_path.read_bytes()
    runner.fail_on = "show"
    with pytest.raises(ProviderKeyedTeardownPreviewError) as error:
        prepare_digitalocean_keyed_initial_teardown_preview(workspace, intent, **kwargs)
    assert "secret-from-command" not in str(error.value)
    assert not (workspace.path / ".barragan-initial-destroy.tfplan").exists()
    assert workspace.state_path.read_bytes() == original_state
    assert json.loads((workspace.path / ".barragan-apply-phase.json").read_text())["phase"] == "applied"
    assert not list(workspace.path.glob(".barragan-plan-inputs-*"))
