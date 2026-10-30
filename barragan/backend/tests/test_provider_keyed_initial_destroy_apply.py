# Copyright (c) 2026, Oracle and/or its affiliates.
"""Destroy execution checks use an injected runner; no Terraform apply runs."""

import hashlib
import json
import subprocess
from copy import deepcopy
from dataclasses import replace

import pytest

import app.services.provider_keyed_initial_destroy_apply as service
from app.services.provider_keyed_initial_plan_gate import DigitalOceanInitialFirewallIntent, DigitalOceanNodeCreate
from app.services.provider_keyed_initial_teardown import DigitalOceanTeardownIntent, DigitalOceanTeardownPreview
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace


class Repository:
    def __init__(self):
        self.encrypted_secret = "encrypted-token"

    def get(self, identifier):
        return self.get_default("digitalocean") if identifier == "cred-opaque" else None

    def get_default(self, provider):
        return type("Credential", (), {
            "id": "cred-opaque", "provider": provider, "status": "active",
            "is_default": True, "encrypted_secret": self.encrypted_secret,
            "updated_at": "2026-10-02T00:00:00Z",
        })()


class Runner:
    def __init__(self, workspace, plan):
        self.workspace = workspace
        self.plan = plan
        self.calls = []
        self.apply_code = 0
        self.after_apply = None

    def __call__(self, args, cwd, env):
        self.calls.append((args, cwd, env))
        if args[1] == "show":
            return subprocess.CompletedProcess(args, 0, json.dumps(self.plan), "")
        if args[1] == "apply":
            if self.after_apply:
                self.after_apply()
            return subprocess.CompletedProcess(args, self.apply_code, "", "secret-in-stderr")
        raise AssertionError("unexpected Terraform command")


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    schema_root = tmp_path / "opaque" / "provider-keyed-v2"
    root = schema_root / "digitalocean" / "fingerprint"
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    (root / ".terraform-data").mkdir(mode=0o700)
    (schema_root / ".regional-ordinals.lock").write_text("")
    (schema_root / ".regional-ordinals.lock").chmod(0o600)
    (root / ".barragan-initial-full-plan.lock").write_text("")
    (root / ".barragan-initial-full-plan.lock").chmod(0o600)
    topology = {"schema": "provider-keyed-v2",
                "middles": {"primary": {"region": "nyc3", "ordinal": 1}},
                "edge_groups": {"sfo": {"region": "sfo3", "middle_node": "primary", "ordinals": [1]}}}
    (root / ".barragan-topology.json").write_text(json.dumps(topology))
    marker = root / ".barragan-provider-keyed-state.json"
    marker.write_text('{"schema":"provider-keyed-v2"}')
    lockfile = root / ".terraform.lock.hcl"
    lockfile.write_text("reviewed lock")
    phase = root / ".barragan-apply-phase.json"
    phase.write_text('{"schema":"provider-keyed-v2","phase":"applied"}')
    plan_path = root / ".barragan-initial-destroy.tfplan"
    plan_path.write_bytes(b"exact reviewed destroy plan")
    plan_path.chmod(0o600)
    workspace = ProviderKeyedWorkspace(
        root, root / "terraform.tfstate", root / ".terraform-data",
        "provider-keyed-v2", "digitalocean", "cred-opaque", "fingerprint",
        "ca5bcad7d2be274aaa79d6c9127cbd9b5c2b10cc", "source-fixture-hash",
    )
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
    IDs = {
        **dict(zip(nodes, ("1001", "1002"))),
        "digitalocean_ssh_key.key": "2001",
        "digitalocean_firewall.firewall": "firewall-opaque",
        "local_file.ansible_inventory[0]": "local-1",
        "local_file.ssh_stanza[0]": "local-2",
    }
    resources = []
    prior = []
    changes = []
    for address, identity in IDs.items():
        base, _, key = address.partition("[")
        kind, name = base.split(".")
        values = {"id": identity}
        if address in nodes:
            node = nodes[address]
            values.update(name=node.name, region=node.region, image=node.image,
                          size=node.size, tags=[selector])
        elif address == "digitalocean_firewall.firewall":
            values.update(name=firewall.name, tags=[selector])
        instance = {"attributes": values}
        if key:
            instance["index_key"] = json.loads(key[:-1])
        resources.append({"mode": "managed", "type": kind, "name": name,
                          "instances": [instance]})
        prior.append({"address": address, "mode": "managed", "values": values.copy()})
        changes.append({"address": address, "change": {"actions": ["delete"],
                        "before": values.copy(), "after": None, "after_unknown": {}}})
    state = {"version": 4, "terraform_version": "1.15.5", "serial": 1,
             "lineage": "047f8280-73d6-4d3a-8dfa-9d0c1bb3f084", "resources": resources}
    workspace.state_path.write_text(json.dumps(state))
    plan = {"format_version": "1.2", "terraform_version": "1.15.5",
            "applyable": True, "complete": True, "errored": False,
            "prior_state": {"values": {"root_module": {"resources": prior}}},
            "planned_values": {"root_module": {}}, "resource_changes": changes,
            "variables": {
                "middles": {"value": topology["middles"]},
                "edge_groups": {"value": {"sfo": {**topology["edge_groups"]["sfo"],
                                                  "count": None, "ordinal_start": 1}}},
            }}
    binary = (tmp_path / "terraform-fixture").resolve()
    binary.write_bytes(b"reviewed binary")
    binary.chmod(0o700)
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    repository = Repository()
    intent = DigitalOceanTeardownIntent(
        nodes, firewall, IDs, digest(workspace.state_path), "cred-opaque",
        hashlib.sha256(repository.encrypted_secret.encode()).hexdigest(),
        "2026-10-02T00:00:00Z",
    )
    preview = DigitalOceanTeardownPreview(
        plan_path, digest(plan_path), intent.state_sha256, workspace.source_sha256,
        digest(marker), digest(lockfile), digest(root / ".barragan-topology.json"),
        digest(phase), (), intent.credential_record_id,
        intent.credential_secret_sha256, intent.credential_updated_at,
        binary, digest(binary),
    )
    monkeypatch.setattr(service, "_verify_audited_workspace", lambda workspace: None)
    runner = Runner(workspace, plan)
    runner.after_apply = lambda: workspace.state_path.write_text(json.dumps({
        **state, "serial": 2, "resources": [],
    }))
    kwargs = dict(environment="devtest", deployment_target="barragan-testing",
                  expected_terraform_sha256=digest(binary), credential_repository=repository,
                  command_environment={"PATH": "/usr/bin", "UNRELATED_SECRET": "hidden"},
                  command_runner=runner)
    return workspace, preview, intent, kwargs, runner, state


def test_applies_exact_binary_after_full_gate_and_marks_absence_pending(prepared, monkeypatch):
    workspace, preview, intent, kwargs, runner, _ = prepared
    workspace.path.chmod(0o2750)
    (workspace.path.parents[1] / ".regional-ordinals.lock").chmod(0o640)
    monkeypatch.setattr("app.services.provider_keyed_saved_plan_runner._collaborator_group_gid",
                        lambda: workspace.path.stat().st_gid)
    result = service.apply_digitalocean_keyed_initial_destroy_plan(
        workspace, preview, intent, **kwargs,
    )
    assert [call[0][1] for call in runner.calls] == ["show", "apply"]
    assert runner.calls[1][0] == [str(preview.terraform_binary_path), "apply",
                                  "-input=false", "-lock=true", "-no-color", str(preview.plan_path)]
    assert all("UNRELATED_SECRET" not in call[2] for call in runner.calls)
    assert result.provider_absence_proof_pending is True
    assert result.state_sha256 == hashlib.sha256(workspace.state_path.read_bytes()).hexdigest()
    assert json.loads((workspace.path / ".barragan-apply-phase.json").read_text())["phase"] == "destroy_applied"
    assert preview.plan_path.exists()


def _expanded_apply_case(prepared):
    workspace, preview, intent, kwargs, runner, state = prepared
    marker = workspace.path / ".barragan-topology.json"
    marker_sha = hashlib.sha256(marker.read_bytes()).hexdigest()
    topology = {
        "schema": "provider-keyed-v2",
        "middles": {"primary": {"region": "nyc3", "ordinal": 1},
                    "secondary": {"region": "nyc3", "ordinal": 2}},
        "edge_groups": {
            "sfo": {"region": "sfo3", "middle_node": "primary", "ordinals": [1, 2]},
            "nyc": {"region": "nyc3", "middle_node": "secondary", "ordinals": [1]},
        },
    }
    path = workspace.path.parents[1] / ".plan-material" / "digitalocean" / "append-inputs.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({**topology, "engagement_name": "opaque"}))
    path.chmod(0o600)
    selector = intent.firewall.selector_tag
    nodes = dict(intent.nodes)
    for address, name, region in (
        ('digitalocean_droplet.middle["secondary"]', "middle02-opaque", "nyc3"),
        ('digitalocean_droplet.edge["sfo3-02"]', "edge-opaque-sfo3-02", "sfo3"),
        ('digitalocean_droplet.edge["nyc3-01"]', "edge-opaque-nyc3-01", "nyc3"),
    ):
        node = DigitalOceanNodeCreate(name, "ubuntu-22-04-x64", "s-1vcpu-1gb", region, selector)
        nodes[address] = node
        kind, rest = address.split(".", 1)
        name_part, encoded_key = rest.split("[", 1)
        values = {"id": str(1000 + len(nodes)), "name": node.name, "region": node.region,
                  "image": node.image, "size": node.size, "tags": [selector]}
        state["resources"].append({"mode": "managed", "type": kind, "name": name_part,
                                   "instances": [{"index_key": json.loads(encoded_key[:-1]),
                                                  "attributes": values}]})
        runner.plan["prior_state"]["values"]["root_module"]["resources"].append(
            {"address": address, "mode": "managed", "values": deepcopy(values)})
        runner.plan["resource_changes"].append({"address": address, "change": {
            "actions": ["delete"], "before": deepcopy(values), "after": None,
            "after_unknown": {},
        }})
    workspace.state_path.write_text(json.dumps(state))
    ids = dict(intent.resource_ids)
    for resource in state["resources"]:
        if resource["type"] != "digitalocean_droplet":
            continue
        key = resource["instances"][0].get("index_key")
        address = f'{resource["type"]}.{resource["name"]}[{json.dumps(key)}]'
        ids[address] = resource["instances"][0]["attributes"]["id"]
    intent = replace(intent, nodes=nodes, resource_ids=ids,
                     state_sha256=hashlib.sha256(workspace.state_path.read_bytes()).hexdigest())
    runner.plan["variables"] = {
        "middles": {"value": topology["middles"]},
        "edge_groups": {"value": {key: {**value, "count": None, "ordinal_start": 1}
                                  for key, value in topology["edge_groups"].items()}},
    }
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    preview = replace(preview, state_sha256=intent.state_sha256,
                      input_sha256=((str(path), digest),))
    kwargs["expected_topology_path"] = path
    kwargs["expected_topology_sha256"] = digest
    runner.after_apply = lambda: workspace.state_path.write_text(json.dumps({
        **state, "serial": state["serial"] + 1, "resources": [],
    }))
    return workspace, preview, intent, kwargs, runner, marker, marker_sha


def test_five_node_apply_uses_exact_attested_append_topology(prepared):
    workspace, preview, intent, kwargs, runner, marker, marker_sha = _expanded_apply_case(prepared)
    result = service.apply_digitalocean_keyed_initial_destroy_plan(workspace, preview, intent, **kwargs)
    assert result.provider_absence_proof_pending is True
    assert [call[0][1] for call in runner.calls] == ["show", "apply"]
    assert len(intent.nodes) == 5 and len(intent.resource_ids) == 9
    assert hashlib.sha256(marker.read_bytes()).hexdigest() == marker_sha


@pytest.mark.parametrize("drift", ["missing-input", "wrong-hash", "other-reviewed-input",
                                    "missing-edge", "wrong-middle"])
def test_five_node_apply_rejects_unreviewed_topology_before_mutation(prepared, drift):
    workspace, preview, intent, kwargs, runner, _marker, _sha = _expanded_apply_case(prepared)
    if drift == "missing-input":
        kwargs["expected_topology_path"].unlink()
    elif drift == "wrong-hash":
        kwargs["expected_topology_sha256"] = "0" * 64
    elif drift == "other-reviewed-input":
        other = kwargs["expected_topology_path"].with_name("inputs.json")
        other.write_bytes(kwargs["expected_topology_path"].read_bytes())
        other.chmod(0o600)
        preview = replace(preview, input_sha256=(
            (str(other), hashlib.sha256(other.read_bytes()).hexdigest()),))
    elif drift == "missing-edge":
        del runner.plan["variables"]["edge_groups"]["value"]["nyc"]
    else:
        runner.plan["variables"]["edge_groups"]["value"]["nyc"]["middle_node"] = "primary"
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyError):
        service.apply_digitalocean_keyed_initial_destroy_plan(workspace, preview, intent, **kwargs)
    assert all(call[0][1] != "apply" for call in runner.calls)


@pytest.mark.parametrize("drift", [
    "environment", "plan", "state", "phase", "topology", "source", "credential", "binary", "intent",
])
def test_drift_never_reaches_apply(prepared, drift):
    workspace, preview, intent, kwargs, runner, _ = prepared
    if drift == "environment":
        kwargs["environment"] = "prod"
    elif drift == "plan":
        preview.plan_path.write_bytes(b"swapped")
    elif drift == "state":
        workspace.state_path.write_text("{}")
    elif drift == "phase":
        (workspace.path / ".barragan-apply-phase.json").write_text('{"phase":"destroy_started"}')
    elif drift == "topology":
        (workspace.path / ".barragan-topology.json").write_text("{}")
    elif drift == "source":
        (workspace.path / ".terraform.lock.hcl").write_text("changed")
    elif drift == "credential":
        kwargs["credential_repository"].encrypted_secret = "rotated"
    elif drift == "binary":
        kwargs["expected_terraform_sha256"] = "0" * 64
    else:
        intent = replace(intent, state_sha256="0" * 64)
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyError):
        service.apply_digitalocean_keyed_initial_destroy_plan(
            workspace, preview, intent, **kwargs,
        )
    assert not any(call[0][1] == "apply" for call in runner.calls)


def test_altered_destroy_plan_json_never_reaches_apply(prepared):
    workspace, preview, intent, kwargs, runner, _ = prepared
    runner.plan["resource_changes"].pop()
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyError):
        service.apply_digitalocean_keyed_initial_destroy_plan(workspace, preview, intent, **kwargs)
    assert [call[0][1] for call in runner.calls] == ["show"]
    assert json.loads((workspace.path / ".barragan-apply-phase.json").read_text())["phase"] == "applied"


def test_failed_apply_preserves_plan_state_and_destroy_fence(prepared):
    workspace, preview, intent, kwargs, runner, state = prepared
    runner.apply_code = 1
    runner.after_apply = None
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyError) as error:
        service.apply_digitalocean_keyed_initial_destroy_plan(workspace, preview, intent, **kwargs)
    assert "secret-in-stderr" not in str(error.value)
    assert preview.plan_path.exists()
    assert json.loads(workspace.state_path.read_text()) == state
    assert json.loads((workspace.path / ".barragan-apply-phase.json").read_text())["phase"] == "destroy_started"


def test_partial_retained_state_preserves_plan_and_fence(prepared):
    workspace, preview, intent, kwargs, runner, state = prepared
    runner.after_apply = lambda: workspace.state_path.write_text(json.dumps({
        **state, "serial": 2, "resources": state["resources"][:1],
    }))
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyError):
        service.apply_digitalocean_keyed_initial_destroy_plan(workspace, preview, intent, **kwargs)
    assert preview.plan_path.exists()
    assert len(json.loads(workspace.state_path.read_text())["resources"]) == 1
    assert json.loads((workspace.path / ".barragan-apply-phase.json").read_text())["phase"] == "destroy_started"


def test_phase_intent_veto_precedes_destroy_started_write_and_apply(prepared):
    workspace, preview, intent, kwargs, runner, state = prepared
    observed = []

    def veto(path, phase):
        observed.append((path, phase, json.loads(path.read_text())["phase"]))
        raise ValueError("claim lost")

    with pytest.raises(service.ProviderKeyedInitialDestroyApplyError):
        service.apply_digitalocean_keyed_initial_destroy_plan(
            workspace, preview, intent, phase_write_intent=veto, **kwargs,
        )
    assert observed == [(workspace.path / ".barragan-apply-phase.json",
                         "destroy_started", "applied")]
    assert [call[0][1] for call in runner.calls] == ["show"]
    assert json.loads(workspace.state_path.read_text()) == state


def test_phase_intent_runs_before_both_writes(prepared):
    workspace, preview, intent, kwargs, runner, _ = prepared
    observed = []

    def audit(path, phase):
        observed.append((phase, json.loads(path.read_text())["phase"]))

    result = service.apply_digitalocean_keyed_initial_destroy_plan(
        workspace, preview, intent, phase_write_intent=audit, **kwargs,
    )
    assert result.provider_absence_proof_pending is True
    assert observed == [("destroy_started", "applied"),
                        ("destroy_applied", "destroy_started")]


def test_uncertain_apply_error_preserves_type_and_recovery_files(prepared):
    workspace, preview, intent, kwargs, _, state = prepared
    observed = []

    def uncertain_run(args, cwd, env):
        observed.append(args[1])
        if args[1] == "show":
            return subprocess.CompletedProcess(args, 0, json.dumps(prepared[4].plan), "")
        raise service.ProviderKeyedInitialDestroyApplyUncertainError(
            "secret-in-stderr"
        )

    kwargs["command_runner"] = uncertain_run
    with pytest.raises(service.ProviderKeyedInitialDestroyApplyUncertainError) as error:
        service.apply_digitalocean_keyed_initial_destroy_plan(
            workspace, preview, intent, **kwargs,
        )
    assert "secret-in-stderr" not in str(error.value)
    assert observed == ["show", "apply"]
    assert json.loads(workspace.state_path.read_text()) == state
    assert preview.plan_path.exists()
    assert json.loads((workspace.path / ".barragan-apply-phase.json").read_text())["phase"] == "destroy_started"
