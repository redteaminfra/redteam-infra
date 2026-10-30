# Copyright (c) 2026, Oracle and/or its affiliates.
"""Exact saved-plan apply boundary; every command is an injected fake."""

import hashlib
import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

import app.services.provider_keyed_initial_apply as service
from app.services.provider_keyed_initial_plan_gate import DigitalOceanInitialFirewallIntent, DigitalOceanNodeCreate
from app.services.provider_keyed_saved_plan_runner import ProviderKeyedInitialPlanEvidence
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.provider_keyed_selector_preflight import SelectorPreflightEvidence


class Repository:
    def __init__(self):
        self.id = "cred-000000000001"
        self.encrypted_secret = "encrypted-token"
        self.updated_at = "2026-10-02T00:00:00Z"

    def get(self, identifier):
        return self.get_default("digitalocean") if identifier == self.id else None

    def get_default(self, provider):
        assert provider == "digitalocean"
        return type("Credential", (), {
            "id": self.id, "provider": provider, "status": "active",
            "is_default": True, "encrypted_secret": self.encrypted_secret,
            "updated_at": self.updated_at,
        })()


class Runner:
    def __init__(self, workspace):
        self.workspace = workspace
        self.calls = []
        self.apply_code = 0
        self.after_apply = None
        self.after_show = None
        self.retained_state = None
        self.plan_json = json.dumps({
            "variables": {
                "middles": {"value": {"primary": {"region": "nyc3", "ordinal": 1}}},
                "edge_groups": {"value": {"sfo": {"region": "sfo3", "middle_node": "primary", "count": None, "ordinal_start": 1, "ordinals": [1]}}},
            },
        })

    def __call__(self, args, cwd, env):
        self.calls.append((args, cwd, env))
        if args[1] == "show":
            if self.after_show:
                self.after_show()
            return subprocess.CompletedProcess(args, 0, self.plan_json, "")
        if args[1] == "apply":
            if self.apply_code == 0:
                self.workspace.state_path.write_text(json.dumps(self.retained_state))
            if self.after_apply:
                self.after_apply()
            return subprocess.CompletedProcess(args, self.apply_code, "", "token-in-stderr")
        raise AssertionError("unexpected Terraform command")


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    schema_root = tmp_path / "eng-opaque" / "provider-keyed-v2"
    root = schema_root / "digitalocean" / "fingerprint"
    root.mkdir(mode=0o700, parents=True)
    (root / ".terraform-data").mkdir(mode=0o700)
    (schema_root / ".regional-ordinals.lock").write_text("")
    (schema_root / ".regional-ordinals.lock").chmod(0o600)
    (root / ".barragan-initial-full-plan.lock").write_text("")
    (root / ".barragan-initial-full-plan.lock").chmod(0o600)
    topology = root / ".barragan-topology.json"
    topology.write_text('{"schema":"provider-keyed-v2","middles":{"primary":{"region":"nyc3","ordinal":1}},"edge_groups":{"sfo":{"region":"sfo3","middle_node":"primary","ordinals":[1]}}}')
    marker = root / ".barragan-provider-keyed-state.json"
    marker.write_text('{"schema":"provider-keyed-v2"}')
    lockfile = root / ".terraform.lock.hcl"
    lockfile.write_text("reviewed lock")
    plan = root / ".barragan-initial-full.tfplan"
    plan.write_bytes(b"exact saved plan")
    plan.chmod(0o600)
    material_dir = schema_root / ".plan-material" / "digitalocean"
    material_dir.mkdir(mode=0o700, parents=True)
    reviewed_input = material_dir / "inputs.json"
    reviewed_input.write_text('{"middle":"primary"}')
    reviewed_input.chmod(0o600)
    workspace = ProviderKeyedWorkspace(
        root, root / "terraform.tfstate", root / ".terraform-data",
        "provider-keyed-v2", "digitalocean", "cred-000000000001",
        "fingerprint", "ca5bcad7d2be274aaa79d6c9127cbd9b5c2b10cc", "source-digest",
    )
    binary = Path("/usr/bin/true").resolve()
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    evidence = ProviderKeyedInitialPlanEvidence(
        plan, hashlib.sha256(plan.read_bytes()).hexdigest(), workspace.source_sha256,
        hashlib.sha256(marker.read_bytes()).hexdigest(),
        hashlib.sha256(topology.read_bytes()).hexdigest(),
        hashlib.sha256(lockfile.read_bytes()).hexdigest(), None,
        ((str(reviewed_input), hashlib.sha256(reviewed_input.read_bytes()).hexdigest()),),
        workspace.provider_connection_id, hashlib.sha256(b"encrypted-token").hexdigest(),
        "2026-10-02T00:00:00Z", "1.15.5", binary, binary_hash,
    )
    firewall = DigitalOceanInitialFirewallIntent(
        "eng-opaque-firewall", "opaque-selector-a1", ("80", "443", "2222"), (),
        ("192.0.2.1/32",),
    )
    repository = Repository()
    runner = Runner(workspace)
    middle = DigitalOceanNodeCreate("middle01-eng-opaque", "ubuntu-22-04-x64", "s-1vcpu-1gb", "nyc3", firewall.selector_tag)
    edge = DigitalOceanNodeCreate("edge-eng-opaque-sfo3-01", "ubuntu-22-04-x64", "s-1vcpu-1gb", "sfo3", firewall.selector_tag)
    nodes = {
        'digitalocean_droplet.middle["primary"]': middle,
        'digitalocean_droplet.edge["sfo3-01"]': edge,
    }
    def resource(kind, name, instances):
        return {"mode": "managed", "type": kind, "name": name, "instances": instances}
    def instance(key, attributes):
        return {"index_key": key, "attributes": attributes}
    runner.retained_state = {
        "version": 4, "terraform_version": "1.15.5", "serial": 1,
        "lineage": "db0cb9ba-cad2-43dc-9a6e-8b2418517370", "outputs": {},
        "resources": [
            resource("digitalocean_droplet", "middle", [instance("primary", {"id": "111", "name": middle.name, "region": middle.region, "tags": [firewall.selector_tag]})]),
            resource("digitalocean_droplet", "edge", [instance("sfo3-01", {"id": "222", "name": edge.name, "region": edge.region, "tags": [firewall.selector_tag]})]),
            resource("digitalocean_ssh_key", "key", [instance(None, {"id": "333"})]),
            resource("digitalocean_firewall", "firewall", [instance(None, {"id": "444", "name": firewall.name, "tags": [firewall.selector_tag]})]),
            resource("local_file", "ansible_inventory", [instance(0, {"id": "555"})]),
            resource("local_file", "ssh_stanza", [instance(0, {"id": "666"})]),
        ],
    }
    checked = []
    preflight = []
    monkeypatch.setattr(service, "_verify_audited_workspace", lambda value: checked.append(value))
    monkeypatch.setattr(service, "require_digitalocean_keyed_initial_full_plan",
                        lambda payload, **kwargs: checked.append((payload, kwargs)))
    monkeypatch.setattr(service, "require_new_digitalocean_selector_available",
                        lambda *args, **kwargs: preflight.append((args, kwargs)) or SelectorPreflightEvidence(0, 0, 0))
    kwargs = dict(
        environment="devtest", deployment_target="barragan-testing",
        expected_terraform_sha256=binary_hash, expected_nodes=nodes,
        expected_ssh_key_name="opaque-key", expected_ssh_public_key="ssh-ed25519 fixture",
        expected_firewall=firewall, expected_local_files={}, engagement_tag="eng-opaque",
        credential_repository=repository, command_environment={"PATH": "/usr/bin"},
        command_runner=runner,
        selector_absence_callback=lambda evidence: None,
        selector_reservation_callback=lambda: None,
    )
    return workspace, evidence, kwargs, repository, runner, checked, preflight


def test_applies_only_exact_saved_binary_after_gate_and_fresh_preflight(prepared, monkeypatch):
    workspace, evidence, kwargs, _, runner, checked, preflight = prepared
    workspace.path.chmod(0o2750)
    (workspace.path.parents[1] / ".regional-ordinals.lock").chmod(0o640)
    monkeypatch.setattr("app.services.provider_keyed_saved_plan_runner._collaborator_group_gid",
                        lambda: workspace.path.stat().st_gid)
    result = service.apply_digitalocean_keyed_initial_saved_plan(workspace, evidence, **kwargs)
    assert [call[0][1] for call in runner.calls] == ["show", "apply"]
    assert runner.calls[1][0] == [str(evidence.terraform_binary_path), "apply", "-input=false", "-lock=true", "-no-color", str(evidence.plan_path)]
    assert all("TF_VAR_do_pat" not in call[2] for call in runner.calls)
    assert preflight[0][0] == (kwargs["expected_firewall"].selector_tag, "eng-opaque", evidence.credential_record_id)
    assert json.loads(checked[1][0])["variables"]["edge_groups"]["value"]["sfo"]["middle_node"] == "primary"
    assert result.state_sha256 == hashlib.sha256(workspace.state_path.read_bytes()).hexdigest()
    assert result.attachment_proof_pending is True
    assert not evidence.plan_path.exists()
    assert json.loads((workspace.path / ".barragan-apply-phase.json").read_text())["phase"] == "applied"


@pytest.mark.parametrize("failure", [
    "prod", "plan", "marker", "topology", "lockfile", "state", "credential", "terraform", "phase",
])
def test_preflight_drift_never_runs_apply(prepared, failure):
    workspace, evidence, kwargs, repository, runner, _, preflight = prepared
    if failure == "prod":
        kwargs["environment"] = "prod"
    elif failure == "plan":
        evidence.plan_path.write_bytes(b"different")
    elif failure == "marker":
        (workspace.path / ".barragan-provider-keyed-state.json").write_text("different")
    elif failure == "topology":
        (workspace.path / ".barragan-topology.json").write_text('{"schema":"provider-keyed-v2","middles":{"changed":{"region":"nyc3","ordinal":2}},"edge_groups":{}}')
    elif failure == "lockfile":
        (workspace.path / ".terraform.lock.hcl").write_text("different")
    elif failure == "state":
        workspace.state_path.write_text("{}")
    elif failure == "credential":
        repository.encrypted_secret = "rotated"
    elif failure == "terraform":
        kwargs["expected_terraform_sha256"] = "0" * 64
    else:
        (workspace.path / ".barragan-apply-phase.json").write_text('{"phase":"apply_started"}')
    with pytest.raises(service.ProviderKeyedInitialApplyError):
        service.apply_digitalocean_keyed_initial_saved_plan(workspace, evidence, **kwargs)
    assert not any(args[1] == "apply" for args, _, _ in runner.calls)
    assert not preflight


def test_selector_collision_or_mismatch_never_runs_apply(prepared, monkeypatch):
    workspace, evidence, kwargs, _, runner, _, _ = prepared
    kwargs["engagement_tag"] = kwargs["expected_firewall"].selector_tag
    with pytest.raises(service.ProviderKeyedInitialApplyError):
        service.apply_digitalocean_keyed_initial_saved_plan(workspace, evidence, **kwargs)
    assert not any(args[1] == "apply" for args, _, _ in runner.calls)
    kwargs["engagement_tag"] = "eng-opaque"
    monkeypatch.setattr(service, "require_new_digitalocean_selector_available",
                        lambda *a, **kw: (_ for _ in ()).throw(ValueError("occupied")))
    with pytest.raises(service.ProviderKeyedInitialApplyError, match="inspect phase"):
        service.apply_digitalocean_keyed_initial_saved_plan(workspace, evidence, **kwargs)
    assert not any(args[1] == "apply" for args, _, _ in runner.calls)


def test_missing_selector_reservation_journal_never_runs_apply(prepared):
    workspace, evidence, kwargs, _, runner, _, _ = prepared
    kwargs["selector_reservation_callback"] = None
    with pytest.raises(service.ProviderKeyedInitialApplyError):
        service.apply_digitalocean_keyed_initial_saved_plan(workspace, evidence, **kwargs)
    assert [args[1] for args, _, _ in runner.calls] == ["show"]
    assert not (workspace.path / ".barragan-apply-phase.json").exists()


def test_saved_plan_middle_association_mismatch_never_applies(prepared):
    workspace, evidence, kwargs, _, runner, _, preflight = prepared
    payload = json.loads(runner.plan_json)
    payload["variables"]["edge_groups"]["value"]["sfo"]["middle_node"] = "other"
    runner.plan_json = json.dumps(payload)
    with pytest.raises(service.ProviderKeyedInitialApplyError):
        service.apply_digitalocean_keyed_initial_saved_plan(workspace, evidence, **kwargs)
    assert [args[1] for args, _, _ in runner.calls] == ["show"]
    assert not preflight


def test_apply_failure_preserves_fence_and_plan_for_reconciliation(prepared):
    workspace, evidence, kwargs, _, runner, _, _ = prepared
    runner.apply_code = 1
    with pytest.raises(service.ProviderKeyedInitialApplyError) as exc:
        service.apply_digitalocean_keyed_initial_saved_plan(workspace, evidence, **kwargs)
    assert "token-in-stderr" not in str(exc.value)
    assert evidence.plan_path.exists()
    assert json.loads((workspace.path / ".barragan-apply-phase.json").read_text())["phase"] == "apply_started"


def test_plan_changed_during_apply_preserves_state_and_fence(prepared):
    workspace, evidence, kwargs, _, runner, _, _ = prepared
    runner.after_apply = lambda: evidence.plan_path.write_bytes(b"swapped binary")
    with pytest.raises(service.ProviderKeyedInitialApplyError):
        service.apply_digitalocean_keyed_initial_saved_plan(workspace, evidence, **kwargs)
    assert workspace.state_path.exists()
    assert evidence.plan_path.exists()
    assert json.loads((workspace.path / ".barragan-apply-phase.json").read_text())["phase"] == "apply_started"


@pytest.mark.parametrize("bad_state", [
    {"version": 4},
    {"version": 4, "terraform_version": "1.15.5", "serial": 1,
     "lineage": "db0cb9ba-cad2-43dc-9a6e-8b2418517370", "resources": []},
])
def test_partial_state_does_not_mark_applied(prepared, bad_state):
    workspace, evidence, kwargs, _, runner, _, _ = prepared
    runner.retained_state = bad_state
    with pytest.raises(service.ProviderKeyedInitialApplyError):
        service.apply_digitalocean_keyed_initial_saved_plan(workspace, evidence, **kwargs)
    assert workspace.state_path.exists()
    assert evidence.plan_path.exists()
    assert json.loads((workspace.path / ".barragan-apply-phase.json").read_text())["phase"] == "apply_started"


@pytest.mark.parametrize("which", ["state", "data"])
def test_noncanonical_workspace_paths_rejected_before_commands(prepared, which):
    workspace, evidence, kwargs, _, runner, _, _ = prepared
    changed = replace(
        workspace,
        **({"state_path": workspace.path / "other.tfstate"} if which == "state"
           else {"terraform_data_dir": workspace.path / "other-data"}),
    )
    with pytest.raises(service.ProviderKeyedInitialApplyError, match="not canonical"):
        service.apply_digitalocean_keyed_initial_saved_plan(changed, evidence, **kwargs)
    assert not runner.calls


def test_rejects_ambient_terraform_override(prepared):
    workspace, evidence, kwargs, _, runner, _, _ = prepared
    kwargs["command_environment"] = {"TF_CLI_ARGS_apply": "-destroy"}
    with pytest.raises(service.ProviderKeyedInitialApplyError):
        service.apply_digitalocean_keyed_initial_saved_plan(workspace, evidence, **kwargs)
    assert not runner.calls


@pytest.mark.parametrize("failure", [
    "empty", "changed", "missing", "symlink", "relative", "workspace", "digest",
    "duplicate", "permissive", "noncanonical", "alternate", "extra",
])
def test_reviewed_input_drift_rejected_before_terraform_or_phase(prepared, tmp_path, failure):
    workspace, evidence, kwargs, _, runner, _, _ = prepared
    input_path = Path(evidence.input_sha256[0][0])
    if failure == "empty":
        evidence = replace(evidence, input_sha256=())
    elif failure == "changed":
        input_path.write_text("changed")
    elif failure == "missing":
        input_path.unlink()
    elif failure == "symlink":
        original = tmp_path / "original.tfvars.json"
        input_path.rename(original)
        input_path.symlink_to(original)
    elif failure == "relative":
        evidence = replace(evidence, input_sha256=(("relative.tfvars", evidence.input_sha256[0][1]),))
    elif failure == "workspace":
        evidence = replace(evidence, input_sha256=((str(workspace.path / "terraform.tfvars"), evidence.input_sha256[0][1]),))
    elif failure == "digest":
        evidence = replace(evidence, input_sha256=((str(input_path), "invalid"),))
    elif failure == "duplicate":
        evidence = replace(evidence, input_sha256=(evidence.input_sha256[0], evidence.input_sha256[0]))
    elif failure == "alternate":
        alternate = tmp_path / "alternate.tfvars.json"
        alternate.write_bytes(input_path.read_bytes())
        alternate.chmod(0o600)
        evidence = replace(evidence, input_sha256=((str(alternate), evidence.input_sha256[0][1]),))
    elif failure == "extra":
        alternate = tmp_path / "extra.tfvars.json"
        alternate.write_bytes(input_path.read_bytes())
        alternate.chmod(0o600)
        evidence = replace(evidence, input_sha256=(*evidence.input_sha256, (str(alternate), evidence.input_sha256[0][1])))
    elif failure == "permissive":
        input_path.chmod(0o644)
    else:
        evidence = replace(evidence, input_sha256=((str(input_path.parent / ".." / input_path.parent.name / input_path.name), evidence.input_sha256[0][1]),))
    with pytest.raises(service.ProviderKeyedInitialApplyError):
        service.apply_digitalocean_keyed_initial_saved_plan(workspace, evidence, **kwargs)
    assert not runner.calls
    assert not (workspace.path / ".barragan-apply-phase.json").exists()


@pytest.mark.parametrize("failure", ["changed", "missing", "symlink"])
def test_reviewed_input_rechecked_before_apply_fence(prepared, failure):
    workspace, evidence, kwargs, _, runner, _, _ = prepared
    input_path = Path(evidence.input_sha256[0][0])

    def change_input():
        if failure == "changed":
            input_path.write_text("changed")
        elif failure == "missing":
            input_path.unlink()
        else:
            original = input_path.with_name("original.tfvars.json")
            input_path.rename(original)
            input_path.symlink_to(original)

    runner.after_show = change_input
    with pytest.raises(service.ProviderKeyedInitialApplyError):
        service.apply_digitalocean_keyed_initial_saved_plan(workspace, evidence, **kwargs)
    assert [args[1] for args, _, _ in runner.calls] == ["show"]
    assert not (workspace.path / ".barragan-apply-phase.json").exists()
