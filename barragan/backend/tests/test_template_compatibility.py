# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.asgi import create_app
from app.core.config import TestConfig
from app.services.redteam_infra_template import RedteamInfraTemplateSource
from app.services.template_compatibility import (
    audit_redteam_infra_template,
    disable_legacy_sketch_local_artifacts,
    ensure_linode_firewall_protocol_compatibility,
    ensure_sketch_firewall_port_list_compatibility,
    ensure_sketch_udp_ingress_compatibility,
    ensure_sketch_resource_name_suffix_compatibility,
    prepare_digitalocean_borrower_teardown,
    prepare_digitalocean_ssh_key_reuse,
    stabilize_digitalocean_ssh_key_ownership,
)


def test_template_compatibility_audit_reports_source_git_and_checks(tmp_path: Path) -> None:
    root = tmp_path / "redteam-infra"
    _write_minimal_template(root, include_udp=True, inventory_user="root")
    (root / ".git").mkdir()

    report = audit_redteam_infra_template(
        source=RedteamInfraTemplateSource(root, "test"),
        git_runner=_fake_git,
    ).to_dict()

    assert report["source"]["path"] == str(root)
    assert report["source"]["kind"] == "test"
    assert report["git"] == {
        "isCheckout": True,
        "branch": "master",
        "commit": "abc123",
        "dirty": True,
    }
    assert report["status"] == "passed"
    checks = {check["id"]: check for check in report["checks"]}
    assert checks["desktop.firefox.role"]["status"] == "pass"
    assert checks["sketch.digitalocean.allowed_udp_ports"]["status"] == "pass"
    assert checks["sketch.linode.bootstrap_root_ssh"]["status"] == "pass"
    assert checks["sketch.linode.bootstrap_root_ssh"]["severity"] == "info"


def test_template_compatibility_audit_fails_missing_required_and_udp_support(tmp_path: Path) -> None:
    root = tmp_path / "redteam-infra"
    _write_minimal_template(root, include_udp=False, inventory_user="root")
    (root / "ansible" / "roles" / "firefox").rmdir()

    report = audit_redteam_infra_template(
        source=RedteamInfraTemplateSource(root, "test"),
        git_runner=_fake_git,
    ).to_dict()

    assert report["status"] == "failed"
    checks = {check["id"]: check for check in report["checks"]}
    assert checks["desktop.firefox.role"]["status"] == "fail"
    assert checks["desktop.firefox.role"]["severity"] == "blocking"
    assert checks["sketch.digitalocean.allowed_udp_ports"]["status"] == "fail"
    assert checks["sketch.digitalocean.allowed_udp_ports"]["severity"] == "blocking"


def test_template_compatibility_api_preserves_read_only_shape() -> None:
    client = create_app(TestConfig).test_client()

    response = client.get("/api/templates/redteam-infra/compatibility")

    assert response.status_code == 200
    body = response.json()
    assert "compatibility" in body
    assert {"source", "git", "status", "checks"}.issubset(body["compatibility"])


def test_sketch_workspace_compatibility_adapts_legacy_linode_inputs(tmp_path: Path) -> None:
    workspace = tmp_path / "linode"
    workspace.mkdir()
    (workspace / "variables.tf").write_text('variable "engagement_name" {}\n', encoding="utf-8")
    (workspace / "middle.tf").write_text(
        'label = "middle${format("%02g", count.index + 1)}-${var.engagement_name}"\n',
        encoding="utf-8",
    )
    (workspace / "edge.tf").write_text(
        'label = "edge-${var.engagement_name}-${format("%02g", (count.index % var.edge_count_per_region) + 1)}"\n',
        encoding="utf-8",
    )
    (workspace / "firewall.tf").write_text(
        'label = "${var.engagement_name}-firewall"\nlabel = "allow-${var.engagement_name}-host-tcp"\n',
        encoding="utf-8",
    )

    changed = ensure_sketch_resource_name_suffix_compatibility(workspace, "linode")

    assert changed == ["variables.tf", "middle.tf", "edge.tf", "firewall.tf"]
    variables = (workspace / "variables.tf").read_text(encoding="utf-8")
    assert 'variable "resource_name_suffix"' in variables
    assert 'variable "middle_ordinal"' in variables
    assert 'variable "edge_ordinal"' in variables
    assert "var.middle_ordinal" in (workspace / "middle.tf").read_text(encoding="utf-8")
    assert "var.edge_ordinal" in (workspace / "edge.tf").read_text(encoding="utf-8")


def test_linode_firewall_protocol_compatibility_updates_only_linode_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "linode"
    workspace.mkdir()
    firewall = workspace / "firewall.tf"
    firewall.write_text(
        'protocol = "tcp"\nprotocol = "udp"\nprotocol = "icmp"\n'
        'for_each = ["tcp", "udp", "icmp"]\n',
        encoding="utf-8",
    )

    assert ensure_linode_firewall_protocol_compatibility(workspace, "linode") == ["firewall.tf"]
    assert firewall.read_text(encoding="utf-8") == (
        'protocol = "TCP"\nprotocol = "UDP"\nprotocol = "ICMP"\n'
        'for_each = ["TCP", "UDP", "ICMP"]\n'
    )
    assert ensure_linode_firewall_protocol_compatibility(workspace, "digitalocean") == []


def test_sketch_udp_ingress_compatibility_adds_missing_linode_contract(tmp_path: Path) -> None:
    workspace = tmp_path / "linode"
    workspace.mkdir()
    (workspace / "variables.tf").write_text('variable "allowed_tcp_ports" {}\n', encoding="utf-8")
    (workspace / "firewall.tf").write_text(
        'resource "linode_firewall" "firewall" {\n'
        '  dynamic "inbound" {\n    // Allow engagement hosts to access each other\n  }\n'
        '}\n',
        encoding="utf-8",
    )

    assert ensure_sketch_udp_ingress_compatibility(workspace, "linode") == ["variables.tf", "firewall.tf"]
    assert 'variable "allowed_udp_ports"' in (workspace / "variables.tf").read_text(encoding="utf-8")
    assert "for_each = var.allowed_udp_ports" in (workspace / "firewall.tf").read_text(encoding="utf-8")
    assert ensure_sketch_udp_ingress_compatibility(workspace, "linode") == []


def test_sketch_firewall_port_list_compatibility_types_compact_legacy_blocks(tmp_path: Path) -> None:
    workspace = tmp_path / "linode"
    workspace.mkdir()
    variables = workspace / "variables.tf"
    variables.write_text(
        'variable "allowed_tcp_ports" {}\nvariable "allowed_udp_ports" {}\n',
        encoding="utf-8",
    )

    assert ensure_sketch_firewall_port_list_compatibility(workspace, "linode") == ["variables.tf"]
    updated = variables.read_text(encoding="utf-8")
    assert updated.count("type = list(string)") == 2
    assert ensure_sketch_firewall_port_list_compatibility(workspace, "linode") == []


def test_sketch_firewall_port_list_compatibility_preserves_typed_multiline_blocks(tmp_path: Path) -> None:
    workspace = tmp_path / "digitalocean"
    workspace.mkdir()
    variables = workspace / "variables.tf"
    variables.write_text(
        'variable "allowed_tcp_ports" {\n'
        '  description = "Allowed { TCP } ports"\n'
        "}\n"
        'variable "allowed_udp_ports" {\n'
        "  type = list(string)\n"
        "  default = []\n"
        "}\n",
        encoding="utf-8",
    )

    assert ensure_sketch_firewall_port_list_compatibility(workspace, "digitalocean") == ["variables.tf"]
    updated = variables.read_text(encoding="utf-8")
    assert updated.count("type = list(string)") == 2
    assert 'description = "Allowed { TCP } ports"' in updated
    assert updated.count("default = []") == 1
    assert ensure_sketch_firewall_port_list_compatibility(workspace, "digitalocean") == []


def test_legacy_sketch_local_artifacts_are_disabled_in_copied_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "sketch"
    workspace.mkdir()
    output_tf = workspace / "output.tf"
    output_tf.write_text(
        'resource "local_file" "ssh_stanza" {\n}\n\n'
        'resource "local_file" "ansible_inventory" {\n}\n',
        encoding="utf-8",
    )

    assert disable_legacy_sketch_local_artifacts(workspace) == ["output.tf"]
    assert output_tf.read_text(encoding="utf-8").count("count = 0") == 2


def test_sketch_local_artifact_compatibility_disables_existing_conditional_count_guards(tmp_path: Path) -> None:
    workspace = tmp_path / "sketch"
    workspace.mkdir()
    output_tf = workspace / "output.tf"
    original = (
        'resource "local_file" "ssh_stanza" {\n'
        "  count = var.middle_count > 0 && var.edge_count_per_region > 0 ? 1 : 0\n"
        "}\n\n"
        'resource "local_file" "ansible_inventory" {\n'
        "  count = var.middle_count > 0 && var.edge_count_per_region > 0 ? 1 : 0\n"
        "}\n\n"
        'output "middle_public_ips" { value = [] }\n'
        'output "edge_public_ips" { value = [] }\n'
    )
    output_tf.write_text(original, encoding="utf-8")

    assert disable_legacy_sketch_local_artifacts(workspace) == ["output.tf"]
    updated = output_tf.read_text(encoding="utf-8")
    assert updated.count("count = 0") == 2
    assert "var.middle_count > 0" not in updated
    assert 'output "middle_public_ips" { value = [] }' in updated
    assert 'output "edge_public_ips" { value = [] }' in updated
    assert disable_legacy_sketch_local_artifacts(workspace) == []


def test_digitalocean_owned_ssh_key_is_pinned_after_state_establishes_ownership(tmp_path: Path) -> None:
    workspace = _write_digitalocean_key_workspace(
        tmp_path,
        managed_instances=[{"attributes": {"id": "123"}}],
        matching_keys=[{"id": "123", "public_key": "ssh-ed25519 test"}],
    )

    assert stabilize_digitalocean_ssh_key_ownership(workspace) == "owner"
    providers = (workspace / "providers.tf").read_text(encoding="utf-8")
    assert 'data "digitalocean_ssh_keys" "matching_key"' not in providers
    assert "count      = 1" in providers
    assert "sketch_ssh_key_id = digitalocean_ssh_key.key[0].id" in providers
    assert stabilize_digitalocean_ssh_key_ownership(workspace) == "owner"


def test_digitalocean_borrowed_ssh_key_never_flips_to_managed(tmp_path: Path) -> None:
    workspace = _write_digitalocean_key_workspace(
        tmp_path,
        managed_instances=[],
        matching_keys=[{"id": "456", "public_key": "ssh-ed25519 test"}],
    )

    assert stabilize_digitalocean_ssh_key_ownership(workspace) == "borrower"
    providers = (workspace / "providers.tf").read_text(encoding="utf-8")
    assert 'data "digitalocean_ssh_keys" "matching_key"' in providers
    assert "count      = 0" in providers
    assert "sketch_ssh_key_id = data.digitalocean_ssh_keys.matching_key.ssh_keys[0].id" in providers


def test_digitalocean_borrower_teardown_uses_only_cached_state_key_id(tmp_path: Path) -> None:
    workspace = _write_digitalocean_key_workspace(
        tmp_path,
        managed_instances=[],
        matching_keys=[{"id": "456", "public_key": "ssh-ed25519 test"}],
    )
    assert stabilize_digitalocean_ssh_key_ownership(workspace) == "borrower"

    assert prepare_digitalocean_borrower_teardown(workspace) == "borrower"
    providers = (workspace / "providers.tf").read_text(encoding="utf-8")
    assert 'data "digitalocean_ssh_keys" "matching_key"' not in providers
    assert 'resource "digitalocean_ssh_key" "key"' not in providers
    assert "sketch_ssh_key_id = 456" in providers
    assert "ssh-ed25519" not in providers
    assert prepare_digitalocean_borrower_teardown(workspace) == "borrower"

    state = json.loads((workspace / "terraform.tfstate").read_text(encoding="utf-8"))
    state["resources"] = [
        {
            "mode": "managed",
            "type": "digitalocean_droplet",
            "instances": [{"attributes": {"ssh_keys": [456]}}],
        }
    ]
    (workspace / "terraform.tfstate").write_text(json.dumps(state), encoding="utf-8")
    static_before_retry = (workspace / "providers.tf").read_text(encoding="utf-8")

    assert prepare_digitalocean_borrower_teardown(workspace) == "borrower"
    assert (workspace / "providers.tf").read_text(encoding="utf-8") == static_before_retry


def test_digitalocean_borrower_teardown_rejects_ambiguous_cached_key_identity(tmp_path: Path) -> None:
    workspace = _write_digitalocean_key_workspace(
        tmp_path,
        managed_instances=[],
        matching_keys=[{"id": "456"}, {"id": "789"}],
    )
    original = (workspace / "providers.tf").read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="borrower key identity is ambiguous"):
        prepare_digitalocean_borrower_teardown(workspace)

    assert (workspace / "providers.tf").read_text(encoding="utf-8") == original


@pytest.mark.parametrize("droplet_keys", [["not-a-numeric-id"], [True], "456"])
def test_digitalocean_borrower_teardown_rejects_malformed_droplet_key_evidence(
    tmp_path: Path,
    droplet_keys: object,
) -> None:
    workspace = _write_digitalocean_key_workspace(
        tmp_path,
        managed_instances=[],
        matching_keys=[{"id": "456"}],
    )
    state = json.loads((workspace / "terraform.tfstate").read_text(encoding="utf-8"))
    state["resources"].append(
        {
            "mode": "managed",
            "type": "digitalocean_droplet",
            "instances": [{"attributes": {"ssh_keys": droplet_keys}}],
        }
    )
    (workspace / "terraform.tfstate").write_text(json.dumps(state), encoding="utf-8")
    original = (workspace / "providers.tf").read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="borrower key identity is ambiguous"):
        prepare_digitalocean_borrower_teardown(workspace)

    assert (workspace / "providers.tf").read_text(encoding="utf-8") == original


def test_digitalocean_borrower_teardown_rejects_conflicting_droplet_key_evidence(tmp_path: Path) -> None:
    workspace = _write_digitalocean_key_workspace(
        tmp_path,
        managed_instances=[],
        matching_keys=[{"id": "456"}],
    )
    state = json.loads((workspace / "terraform.tfstate").read_text(encoding="utf-8"))
    state["resources"].append(
        {
            "mode": "managed",
            "type": "digitalocean_droplet",
            "instances": [{"attributes": {"ssh_keys": [789]}}],
        }
    )
    (workspace / "terraform.tfstate").write_text(json.dumps(state), encoding="utf-8")
    original = (workspace / "providers.tf").read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="borrower key identity is ambiguous"):
        prepare_digitalocean_borrower_teardown(workspace)

    assert (workspace / "providers.tf").read_text(encoding="utf-8") == original


def test_digitalocean_borrower_teardown_accepts_empty_droplet_key_evidence(tmp_path: Path) -> None:
    workspace = _write_digitalocean_key_workspace(
        tmp_path,
        managed_instances=[],
        matching_keys=[{"id": "456"}],
    )
    state = json.loads((workspace / "terraform.tfstate").read_text(encoding="utf-8"))
    state["resources"].append(
        {
            "mode": "managed",
            "type": "digitalocean_droplet",
            "instances": [{"attributes": {"ssh_keys": []}}],
        }
    )
    (workspace / "terraform.tfstate").write_text(json.dumps(state), encoding="utf-8")

    assert prepare_digitalocean_borrower_teardown(workspace) == "borrower"
    assert "sketch_ssh_key_id = 456" in (workspace / "providers.tf").read_text(encoding="utf-8")


def test_digitalocean_borrower_teardown_leaves_owner_and_unresolved_modes_unchanged(tmp_path: Path) -> None:
    (tmp_path / "owner").mkdir()
    owner = _write_digitalocean_key_workspace(
        tmp_path / "owner",
        managed_instances=[{"attributes": {"id": "123"}}],
        matching_keys=[{"id": "123"}],
    )
    owner_before = (owner / "providers.tf").read_text(encoding="utf-8")
    assert prepare_digitalocean_borrower_teardown(owner) == "owner"
    assert (owner / "providers.tf").read_text(encoding="utf-8") == owner_before

    (tmp_path / "unresolved").mkdir()
    unresolved = _write_digitalocean_key_workspace(
        tmp_path / "unresolved", managed_instances=[], matching_keys=[]
    )
    unresolved_before = (unresolved / "providers.tf").read_text(encoding="utf-8")
    assert prepare_digitalocean_borrower_teardown(unresolved) == "unresolved"
    assert (unresolved / "providers.tf").read_text(encoding="utf-8") == unresolved_before


def test_digitalocean_ssh_key_mode_remains_unresolved_before_first_apply(tmp_path: Path) -> None:
    workspace = _write_digitalocean_key_workspace(tmp_path, managed_instances=[], matching_keys=[])
    original = (workspace / "providers.tf").read_text(encoding="utf-8")

    assert stabilize_digitalocean_ssh_key_ownership(workspace) == "unresolved"
    assert (workspace / "providers.tf").read_text(encoding="utf-8") == original


def test_digitalocean_existing_resource_key_is_pinned_as_owner(tmp_path: Path) -> None:
    workspace = tmp_path / "digitalocean"
    workspace.mkdir()
    (workspace / "providers.tf").write_text(
        'provider "digitalocean" {}\n\n'
        'resource "digitalocean_ssh_key" "key" {\n'
        '  name = "do-key"\n'
        "  public_key = chomp(file(local.ssh_pub_key_path))\n"
        "}\n\n"
        'provider "local" {}\n',
        encoding="utf-8",
    )
    (workspace / "terraform.tfstate").write_text(
        json.dumps({"resources": [{"mode": "managed", "type": "digitalocean_ssh_key", "name": "key", "instances": [{"attributes": {"id": "123"}}]}]}),
        encoding="utf-8",
    )

    assert stabilize_digitalocean_ssh_key_ownership(workspace) == "owner"
    providers = (workspace / "providers.tf").read_text(encoding="utf-8")
    assert 'data "digitalocean_ssh_keys" "matching_key"' not in providers
    assert "count      = 1" in providers
    assert "sketch_ssh_key_id = digitalocean_ssh_key.key[0].id" in providers


def test_digitalocean_fresh_resource_workspace_uses_conditional_key_reuse(tmp_path: Path) -> None:
    workspace = tmp_path / "digitalocean"
    workspace.mkdir()
    (workspace / "providers.tf").write_text(
        'provider "digitalocean" {}\n\n'
        'resource "digitalocean_ssh_key" "key" {\n'
        '  name = "do-key"\n'
        "  public_key = chomp(file(local.ssh_pub_key_path))\n"
        "}\n\n"
        'provider "local" {}\n',
        encoding="utf-8",
    )
    (workspace / "edge.tf").write_text(
        "ssh_keys = [digitalocean_ssh_key.key.id]\n",
        encoding="utf-8",
    )
    (workspace / "middle.tf").write_text(
        "ssh_keys = [digitalocean_ssh_key.key.id]\n",
        encoding="utf-8",
    )

    assert prepare_digitalocean_ssh_key_reuse(workspace) == "conditional"
    providers = (workspace / "providers.tf").read_text(encoding="utf-8")
    assert 'data "digitalocean_ssh_keys" "matching_key"' in providers
    assert "count      = length(data.digitalocean_ssh_keys.matching_key.ssh_keys) == 0 ? 1 : 0" in providers
    assert (workspace / "edge.tf").read_text(encoding="utf-8") == "ssh_keys = [local.sketch_ssh_key_id]\n"
    assert (workspace / "middle.tf").read_text(encoding="utf-8") == "ssh_keys = [local.sketch_ssh_key_id]\n"
    assert prepare_digitalocean_ssh_key_reuse(workspace) == "conditional"


def _write_digitalocean_key_workspace(
    tmp_path: Path,
    *,
    managed_instances: list[dict[str, object]],
    matching_keys: list[dict[str, object]],
) -> Path:
    workspace = tmp_path / "digitalocean"
    workspace.mkdir()
    (workspace / "providers.tf").write_text(
        'provider "digitalocean" {}\n\n'
        'data "digitalocean_ssh_keys" "matching_key" {\n'
        "  filter {\n"
        '    key = "public_key"\n'
        "    values = [chomp(file(local.ssh_pub_key_path))]\n"
        "  }\n"
        "}\n\n"
        'resource "digitalocean_ssh_key" "key" {\n'
        "  count = length(data.digitalocean_ssh_keys.matching_key.ssh_keys) == 0 ? 1 : 0\n"
        '  name = "do-key"\n'
        "  public_key = chomp(file(local.ssh_pub_key_path))\n"
        "}\n\n"
        "locals {\n"
        "  sketch_ssh_key_id = length(data.digitalocean_ssh_keys.matching_key.ssh_keys) > 0 ? data.digitalocean_ssh_keys.matching_key.ssh_keys[0].id : digitalocean_ssh_key.key[0].id\n"
        "}\n\n"
        'provider "local" {}\n',
        encoding="utf-8",
    )
    resources = [
        {
            "mode": "managed",
            "type": "digitalocean_ssh_key",
            "name": "key",
            "instances": managed_instances,
        },
        {
            "mode": "data",
            "type": "digitalocean_ssh_keys",
            "name": "matching_key",
            "instances": [{"attributes": {"ssh_keys": matching_keys}}],
        },
    ]
    (workspace / "terraform.tfstate").write_text(json.dumps({"resources": resources}), encoding="utf-8")
    return workspace


def _write_minimal_template(root: Path, *, include_udp: bool, inventory_user: str) -> None:
    for role in ("google-chrome", "firefox", "keepassxc", "libreoffice", "vs-code", "backflips"):
        (root / "ansible" / "roles" / role).mkdir(parents=True, exist_ok=True)
    for provider in ("linode", "digitalocean"):
        template_dir = root / "external" / "sketch" / provider
        (template_dir / "templates").mkdir(parents=True, exist_ok=True)
        (template_dir / "templates" / "inventory.tftpl").write_text(
            f"ansible_ssh_user={inventory_user}\n",
            encoding="utf-8",
        )
    (root / "external" / "sketch" / "digitalocean" / "variables.tf").write_text(
        'variable "allowed_tcp_ports" {}\n'
        + ('variable "allowed_udp_ports" {}\n' if include_udp else ""),
        encoding="utf-8",
    )
    (root / "external" / "sketch" / "digitalocean" / "firewall.tf").write_text(
        "for_each = var.allowed_tcp_ports\n"
        + ("for_each = var.allowed_udp_ports\n" if include_udp else ""),
        encoding="utf-8",
    )


def _fake_git(_root: Path, args: list[str]) -> str:
    command = " ".join(args)
    if command == "branch --show-current":
        return "master\n"
    if command == "rev-parse HEAD":
        return "abc123\n"
    if command == "status --porcelain":
        return " M external/sketch/digitalocean/firewall.tf\n"
    raise AssertionError(f"unexpected git command: {command}")
