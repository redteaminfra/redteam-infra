# Copyright (c) 2026, Oracle and/or its affiliates.
"""Saved-plan policy checks for the audited DigitalOcean v2 source."""

import copy
import hashlib
import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

import app.services.provider_keyed_initial_plan_gate as gate
import app.services.provider_keyed_saved_plan_runner as plan_runner
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.terraform_plan_gate import TerraformPlanGateError


MIDDLE = 'digitalocean_droplet.middle["primary"]'
EDGE = 'digitalocean_droplet.edge["sfo3-01"]'
TAG = "a3d9c7e1f4b6"
PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixture"
NODES = {
    MIDDLE: gate.DigitalOceanNodeCreate("middle01-fixture", "ubuntu-22-04-x64", "s-1vcpu-1gb", "nyc3", TAG),
    EDGE: gate.DigitalOceanNodeCreate("edge-fixture-sfo3-01", "ubuntu-22-04-x64", "s-1vcpu-1gb", "sfo3", TAG),
}
POLICY = gate.DigitalOceanInitialFirewallIntent(
    "opaque-firewall", TAG, ("80", "443", "2222"), (), ("192.0.2.10/32",),
)
LOCAL = {
    "local_file.ansible_inventory[0]": {
        "content": "[middle]\nfixture\n", "content_base64": None,
        "directory_permission": "0777", "file_permission": "0600",
        "filename": "inventory.ini", "sensitive_content": None, "source": None,
    },
    "local_file.ssh_stanza[0]": {
        "content_base64": None, "directory_permission": "0777",
        "file_permission": "0600", "filename": "/tmp/opaque-sketch",
        "sensitive_content": None, "source": None,
    },
}


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "provider-keyed-v2" / "digitalocean" / "opaque-fingerprint"
    (root / "barragan-v2").mkdir(parents=True)
    root.chmod(0o700)
    (root / ".terraform-data").mkdir(mode=0o700)
    (root.parents[1] / ".regional-ordinals.lock").write_text("", encoding="utf-8")
    (root.parents[1] / ".regional-ordinals.lock").chmod(0o600)
    (root / ".barragan-topology.json").write_text(json.dumps({
        "schema": "provider-keyed-v2",
        "middles": {"primary": {"region": "nyc3", "ordinal": 1}},
        "edge_groups": {"sfo": {
            "region": "sfo3", "middle_node": "primary", "ordinals": [1],
        }},
    }), encoding="utf-8")
    source_bytes = {
        "middle.tf": b"middle fixture",
        "edge.tf": b"edge fixture",
        "firewall.tf": b"legacy firewall fixture",
        "providers.tf": b"legacy provider fixture",
        "barragan-v2/firewall.tf": b"safe firewall fixture",
        "barragan-v2/providers.tf": b"pinned provider fixture",
        "barragan-v2/.terraform.lock.hcl": b'provider "registry.terraform.io/digitalocean/digitalocean" {\n  version = "2.103.0"\n}\n',
    }
    source_files = {name: hashlib.sha256(value).hexdigest() for name, value in source_bytes.items()}
    rendered = dict(source_files)
    rendered["firewall.tf"] = source_files["barragan-v2/firewall.tf"]
    rendered["providers.tf"] = source_files["barragan-v2/providers.tf"]
    rendered[".terraform.lock.hcl"] = source_files["barragan-v2/.terraform.lock.hcl"]
    for name, digest in rendered.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        content = source_bytes.get(name)
        if name == "firewall.tf":
            content = source_bytes["barragan-v2/firewall.tf"]
        elif name == "providers.tf":
            content = source_bytes["barragan-v2/providers.tf"]
        elif name == ".terraform.lock.hcl":
            content = source_bytes["barragan-v2/.terraform.lock.hcl"]
        assert hashlib.sha256(content).hexdigest() == digest
        path.write_bytes(content)
    source_sha = hashlib.sha256(json.dumps(source_files, sort_keys=True).encode()).hexdigest()
    monkeypatch.setattr(gate, "_SOURCE_SHA256", source_sha)
    marker = {
        "schema": "provider-keyed-v2", "provider": "digitalocean",
        "provider_connection_id": "central-connection",
        "connection_fingerprint": "opaque-fingerprint",
        "source_revision": gate._SOURCE_REVISION,
        "source_files": source_files, "rendered_files": rendered,
    }
    (root / ".barragan-provider-keyed-state.json").write_text(json.dumps(marker), encoding="utf-8")
    return ProviderKeyedWorkspace(
        root, root / "terraform.tfstate", root / ".terraform-data",
        "provider-keyed-v2", "digitalocean", "central-connection",
        "opaque-fingerprint", gate._SOURCE_REVISION, source_sha,
    )


def _created(address, after, unknown, sensitive):
    return {"address": address, "change": {
        "actions": ["create"], "before": None, "before_sensitive": False,
        "after": copy.deepcopy(after), "after_unknown": copy.deepcopy(unknown),
        "after_sensitive": copy.deepcopy(sensitive),
    }}


def _plan():
    ingress = [gate._inbound_unknown_peer(proto) for proto in ("icmp", "tcp", "udp")]
    ingress += [gate._inbound("tcp", "22", ["192.0.2.10/32"])]
    ingress += [gate._inbound("tcp", port, ["0.0.0.0/0"]) for port in ("2222", "443", "80")]
    egress = [gate._outbound(proto, "" if proto == "icmp" else "1-65535", "0.0.0.0/0")
              for proto in ("icmp", "tcp", "udp")]
    ingress_unknown = [
        {**gate._INBOUND_SOURCE_UNKNOWN,
         "source_addresses": True if "source_addresses" not in rule else [False]}
        for rule in ingress
    ]
    ingress_sensitive = [
        {**gate._INBOUND_SOURCE_UNKNOWN,
         "source_addresses": [] if "source_addresses" not in rule else [False]}
        for rule in ingress
    ]
    egress_meta = [{**gate._OUTBOUND_DEST_UNKNOWN, "destination_addresses": [False]}
                   for _ in egress]
    resources = []
    for address, intent in NODES.items():
        resources.append(_created(
            address,
            {**gate._NODE_KNOWN_DEFAULTS, "name": intent.name, "image": intent.image,
             "size": intent.size, "region": intent.region, "tags": [TAG]},
            gate._NODE_UNKNOWN,
            {"backup_policy": [], "ssh_keys": [], "tags": [False], "volume_ids": []},
        ))
    resources.append(_created(
        "digitalocean_ssh_key.key",
        {"name": "opaque-key", "public_key": PUBKEY, "timeouts": None},
        gate._KEY_UNKNOWN, {},
    ))
    resources.append(_created(
        "digitalocean_firewall.firewall",
        {"name": POLICY.name, "tags": [TAG], "droplet_ids": None,
         "inbound_rule": ingress, "outbound_rule": egress},
        {**gate._COMPUTED_FIREWALL, "inbound_rule": ingress_unknown,
         "outbound_rule": egress_meta},
        {"inbound_rule": ingress_sensitive, "outbound_rule": egress_meta,
         "pending_changes": [], "tags": [False]},
    ))
    for address, after in LOCAL.items():
        resources.append(_created(
            address, after,
            {**gate._COMPUTED_LOCAL,
             **({"content": True} if address.endswith("ssh_stanza[0]") else {})},
            {"sensitive_content": True},
        ))
    return {
        "format_version": "1.2", "terraform_version": "1.15.5",
        "applyable": True, "complete": True, "errored": False,
        "prior_state": {"values": {"root_module": {}, "outputs": {}}},
        "resource_changes": resources,
    }


def _check(plan, workspace, *, policy=POLICY):
    gate.require_digitalocean_keyed_initial_full_plan(
        json.dumps(plan), workspace=workspace, expected_nodes=NODES,
        expected_ssh_key_name="opaque-key", expected_ssh_public_key=PUBKEY,
        expected_firewall=policy, expected_local_files=LOCAL,
    )


def test_audited_source_real_plan_shape_passes(workspace):
    _check(_plan(), workspace)


def test_redacted_real_saved_plan_shape_passes(workspace):
    """Terraform 1.15.5/DO 2.103.0 mock-token plan, with secrets removed."""

    fixture = Path(__file__).parent / "fixtures/provider_keyed/digitalocean-initial-full-terraform-1.15.5.json"
    plan = json.loads(fixture.read_text(encoding="utf-8"))
    assert set(plan["variables"]) == {"middles", "edge_groups"}
    assert "do_pat" not in plan["variables"] and "configuration" not in plan
    nodes = {
        MIDDLE: replace(NODES[MIDDLE], name="middle01-e7c9a4d2"),
        EDGE: replace(NODES[EDGE], name="edge-e7c9a4d2-sfo3-01"),
    }
    policy = replace(POLICY, name="e7c9a4d2-firewall")
    local_files = dict(LOCAL)
    local_files["local_file.ansible_inventory[0]"] = {
        **LOCAL["local_file.ansible_inventory[0]"], "content": "inventory fixture",
    }
    gate.require_digitalocean_keyed_initial_full_plan(
        json.dumps(plan), workspace=workspace, expected_nodes=nodes,
        expected_ssh_key_name="do-key", expected_ssh_public_key=PUBKEY,
        expected_firewall=policy, expected_local_files=local_files,
    )


def test_saved_plan_runner_checks_real_gate_with_terraform_json_fixture(workspace, tmp_path, monkeypatch):
    """Exercise source audit, saved-binary binding, and gate in one path."""

    fixture = Path(__file__).parent / "fixtures/provider_keyed/digitalocean-initial-full-terraform-1.15.5.json"
    shown_json = fixture.read_text(encoding="utf-8")
    var_file = tmp_path / "reviewed.tfvars"
    var_file.write_text('do_pat = "ignored-caller-token"\n', encoding="utf-8")
    var_file.chmod(0o600)
    credential = type("Credential", (), {
        "id": workspace.provider_connection_id,
        "provider": "digitalocean",
        "status": "active",
        "is_default": True,
        "encrypted_secret": "encrypted-fixture-token",
        "updated_at": "2026-10-02T00:00:00Z",
    })()

    class Repository:
        def get(self, credential_id):
            return credential if credential_id == credential.id else None

        def get_default(self, provider):
            return credential if provider == "digitalocean" else None

    monkeypatch.setattr(plan_runner, "decrypt_secret_value", lambda ciphertext: "central-fixture-token")
    calls = []

    def run(args, cwd, env):
        calls.append(args)
        if args[1] == "version":
            return subprocess.CompletedProcess(args, 0, '{"terraform_version":"1.15.5"}', "")
        if args[1] == "plan":
            Path(next(arg.split("=", 1)[1] for arg in args if arg.startswith("-out="))).write_bytes(b"opaque-saved-plan")
            credential_path = Path(args[-1].split("=", 1)[1])
            assert json.loads(credential_path.read_text()) == {"do_pat": "central-fixture-token"}
        if args[1] == "show":
            return subprocess.CompletedProcess(args, 0, shown_json, "")
        return subprocess.CompletedProcess(args, 0, "", "")

    nodes = {
        MIDDLE: replace(NODES[MIDDLE], name="middle01-e7c9a4d2"),
        EDGE: replace(NODES[EDGE], name="edge-e7c9a4d2-sfo3-01"),
    }
    local_files = dict(LOCAL)
    local_files["local_file.ansible_inventory[0]"] = {
        **LOCAL["local_file.ansible_inventory[0]"], "content": "inventory fixture",
    }
    binary = Path("/usr/bin/true").resolve()
    evidence = plan_runner.prepare_digitalocean_keyed_initial_full_plan(
        workspace,
        environment="devtest", deployment_target="barragan-testing",
        expected_connection_id=workspace.provider_connection_id,
        input_sha256={var_file: hashlib.sha256(var_file.read_bytes()).hexdigest()},
        var_files=[var_file], expected_nodes=nodes,
        expected_ssh_key_name="do-key", expected_ssh_public_key=PUBKEY,
        expected_firewall=replace(POLICY, name="e7c9a4d2-firewall"),
        expected_local_files=local_files, credential_repository=Repository(),
        command_environment={"PATH": "/usr/bin"},
        expected_terraform_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        terraform=str(binary), command_runner=run,
    )
    assert [args[1] for args in calls] == ["version", "init", "plan", "show"]
    assert evidence.plan_sha256 == hashlib.sha256(b"opaque-saved-plan").hexdigest()
    assert evidence.source_sha256 == workspace.source_sha256
    assert evidence.credential_record_id == credential.id
    assert "central-fixture-token" not in repr(evidence)


def test_two_chain_real_mock_plan_passes_exact_gate(workspace):
    """The first provider-wide deployment shape has four keyed nodes."""

    fixture = Path(__file__).parent / "fixtures/provider_keyed/digitalocean-two-chain-full-terraform-1.15.5.json"
    plan = json.loads(fixture.read_text(encoding="utf-8"))
    assert set(plan["variables"]) == {"middles", "edge_groups"}
    assert "do_pat" not in plan["variables"] and "configuration" not in plan
    nodes = {
        'digitalocean_droplet.middle["primary"]': gate.DigitalOceanNodeCreate(
            "middle01-e7c9a4d2", "ubuntu-22-04-x64", "s-1vcpu-1gb", "nyc3", TAG,
        ),
        'digitalocean_droplet.middle["secondary"]': gate.DigitalOceanNodeCreate(
            "middle02-e7c9a4d2", "ubuntu-22-04-x64", "s-1vcpu-1gb", "sfo3", TAG,
        ),
        'digitalocean_droplet.edge["nyc3-01"]': gate.DigitalOceanNodeCreate(
            "edge-e7c9a4d2-nyc3-01", "ubuntu-22-04-x64", "s-1vcpu-1gb", "nyc3", TAG,
        ),
        'digitalocean_droplet.edge["sfo3-01"]': gate.DigitalOceanNodeCreate(
            "edge-e7c9a4d2-sfo3-01", "ubuntu-22-04-x64", "s-1vcpu-1gb", "sfo3", TAG,
        ),
    }
    local_files = dict(LOCAL)
    local_files["local_file.ansible_inventory[0]"] = {
        **LOCAL["local_file.ansible_inventory[0]"], "content": "two-chain inventory fixture",
    }
    gate.require_digitalocean_keyed_initial_full_plan(
        json.dumps(plan), workspace=workspace, expected_nodes=nodes,
        expected_ssh_key_name="do-key", expected_ssh_public_key=PUBKEY,
        expected_firewall=gate.DigitalOceanInitialFirewallIntent(
            "e7c9a4d2-firewall", TAG, ("80", "443", "2222"),
            (), ("192.0.2.10/32",),
        ),
        expected_local_files=local_files,
    )


@pytest.mark.parametrize("tcp,udp", [
    (("80", "443", "2222", "18085"), ()),
    (("80", "443", "2222"), ("3478",)),
])
def test_initial_plan_rejects_channel_ports_before_host_firewall(workspace, tcp, udp):
    policy = gate.DigitalOceanInitialFirewallIntent(
        POLICY.name, TAG, tcp, udp, POLICY.trusted_ssh_cidrs,
    )
    with pytest.raises(TerraformPlanGateError, match="baseline public ports"):
        _check(_plan(), workspace, policy=policy)


@pytest.mark.parametrize("mutate,match", [
    (lambda p: p["resource_changes"][3]["change"]["after"]["inbound_rule"].append(
        gate._inbound("tcp", "8080", ["0.0.0.0/0"])), "ingress"),
    (lambda p: p["resource_changes"][3]["change"]["after"]["inbound_rule"][3].update(
        source_addresses=["0.0.0.0/0"]), "ingress"),
    (lambda p: p["resource_changes"][3]["change"]["after"]["inbound_rule"][0].update(
        source_addresses=["::/0"]), "IPv6 ingress"),
    (lambda p: p["resource_changes"][3]["change"]["after"]["outbound_rule"][0].update(
        destination_addresses=["::/0"]), "egress"),
    (lambda p: p["resource_changes"][3]["change"]["after"].update(tags=["legacy"]), "selector"),
    (lambda p: p["resource_changes"][3]["change"]["after_unknown"]["inbound_rule"][0].update(
        source_tags=True), "unknown ingress"),
    (lambda p: p["resource_changes"][3]["change"]["after_sensitive"]["inbound_rule"][3].update(
        source_addresses=[True]), "sensitivity"),
    (lambda p: p["resource_changes"][0]["change"]["after"].update(image="ubuntu-24-04-x64"), "node differs"),
])
def test_rejects_unreviewed_policy_and_node_deltas(workspace, mutate, match):
    plan = _plan()
    mutate(plan)
    with pytest.raises(TerraformPlanGateError, match=match):
        _check(plan, workspace)


def test_rejects_old_source_and_rendered_source_tamper(workspace):
    with pytest.raises(TerraformPlanGateError, match="source revision"):
        _check(_plan(), replace(workspace, source_revision="067044225392719c8412708f8682f9428a4ba66b"))
    (workspace.path / "firewall.tf").write_text("changed", encoding="utf-8")
    with pytest.raises(TerraformPlanGateError, match="source verification"):
        _check(_plan(), workspace)


def test_rejects_noncanonical_public_port_and_extra_action(workspace):
    unsafe = gate.DigitalOceanInitialFirewallIntent(POLICY.name, TAG, ("022",), (), POLICY.trusted_ssh_cidrs)
    with pytest.raises(TerraformPlanGateError, match="public port"):
        _check(_plan(), workspace, policy=unsafe)
    plan = _plan()
    plan["resource_changes"].append(_created("digitalocean_firewall.other", {}, {}, {}))
    with pytest.raises(TerraformPlanGateError, match="unapproved"):
        _check(plan, workspace)


def test_rejects_nonempty_state_version_and_drift(workspace):
    for key, value in (("format_version", "1.3"), ("terraform_version", "1.16.0"),
                       ("applyable", False)):
        plan = _plan()
        plan[key] = value
        with pytest.raises(TerraformPlanGateError, match="version, status, or empty state"):
            _check(plan, workspace)
    plan = _plan()
    plan["prior_state"]["values"]["root_module"] = {"resources": [{"address": MIDDLE}]}
    with pytest.raises(TerraformPlanGateError, match="empty state"):
        _check(plan, workspace)
    plan = _plan()
    plan["resource_drift"] = [{"address": MIDDLE}]
    with pytest.raises(TerraformPlanGateError, match="drift"):
        _check(plan, workspace)


def test_rejects_unreviewed_local_content_and_sensitive_metadata(workspace):
    plan = _plan()
    local = next(r for r in plan["resource_changes"] if r["address"] == "local_file.ansible_inventory[0]")
    local["change"]["after"]["content"] = "different inventory"
    with pytest.raises(TerraformPlanGateError, match="local artifact differs"):
        _check(plan, workspace)
    plan = _plan()
    local = next(r for r in plan["resource_changes"] if r["address"] == "local_file.ssh_stanza[0]")
    local["change"]["after_unknown"]["source"] = True
    with pytest.raises(TerraformPlanGateError, match="unproved content"):
        _check(plan, workspace)
    plan = _plan()
    local = next(r for r in plan["resource_changes"] if r["address"] == "local_file.ssh_stanza[0]")
    local["change"]["after_sensitive"]["filename"] = True
    with pytest.raises(TerraformPlanGateError, match="sensitivity"):
        _check(plan, workspace)


@pytest.mark.parametrize("filename", [
    "extra.tf", "extra.tf.json", "terraform.tfvars", "override.auto.tfvars",
    "override.auto.tfvars.json",
])
def test_rejects_extra_rendered_terraform_source_or_autoloaded_input(workspace, filename):
    (workspace.path / filename).write_text("{}", encoding="utf-8")
    with pytest.raises(TerraformPlanGateError, match="source verification"):
        _check(_plan(), workspace)


def test_rejects_symlinked_terraform_input(workspace, tmp_path):
    outside = tmp_path / "outside.tfvars"
    outside.write_text("{}", encoding="utf-8")
    (workspace.path / "override.auto.tfvars").symlink_to(outside)
    with pytest.raises(TerraformPlanGateError, match="source verification"):
        _check(_plan(), workspace)
