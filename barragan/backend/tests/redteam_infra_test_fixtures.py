# Copyright (c) 2026, Oracle and/or its affiliates.
import os
import re
import subprocess
from pathlib import Path


def checkout_local_pinned_source(source: Path, target: Path, revision: str) -> Path:
    """Materialize one approved commit from a local cache, including unadvertised objects."""
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("approved upstream revision must be a full commit SHA")
    source = source.resolve(strict=True)
    if not source.is_dir():
        raise ValueError("upstream object cache must be a local Git directory")
    if target.exists():
        raise ValueError("pinned fixture target must be fresh")
    environment = {**os.environ, "GIT_ALLOW_PROTOCOL": "file", "GIT_TERMINAL_PROMPT": "0"}

    def git(*arguments: str) -> str:
        return subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", *arguments],
            check=True, capture_output=True, text=True, env=environment, timeout=30,
        ).stdout.strip()

    try:
        object_type = git("-C", str(source), "cat-file", "-t", revision)
    except subprocess.CalledProcessError as exc:
        raise ValueError(f"approved upstream commit {revision} is unavailable in the local cache") from exc
    if object_type != "commit":
        raise ValueError("approved upstream revision must identify a commit object")
    git("init", "--quiet", str(target))
    # Unlike cloning refs, this transfers the exact object even when no source
    # branch/tag advertises it. Only its shallow commit/tree is materialized.
    git("-C", str(target), "fetch", "--quiet", "--depth=1", "--no-tags", "--no-write-fetch-head",
        "--no-recurse-submodules", str(source), revision)
    git("-C", str(target), "checkout", "--quiet", "--detach", revision)
    if git("-C", str(target), "rev-parse", "HEAD") != revision:
        raise ValueError("pinned fixture HEAD differs from the approved upstream revision")
    return target


def write_sketch_template_fixture(root: Path, *, providers: tuple[str, ...] = ("linode", "digitalocean")) -> None:
    """Create a minimal redteam-infra checkout fixture for template-content tests."""

    (root / ".git").mkdir(parents=True, exist_ok=True)
    (root / "ansible").mkdir(parents=True, exist_ok=True)
    (root / "README.md").write_text("redteam-infra fixture\n", encoding="utf-8")

    tooling = root / "external" / "sketch" / "tooling"
    tooling.mkdir(parents=True, exist_ok=True)
    tooling.joinpath("README.md").write_text("Sketch operator tooling.\n", encoding="utf-8")
    tooling.joinpath("sketch-json-config.py").write_text(
        "#!/usr/bin/env python3\n"
        "print('sketch operator config')\n",
        encoding="utf-8",
    )

    for provider in providers:
        provider_root = root / "external" / "sketch" / provider
        templates = provider_root / "templates"
        templates.mkdir(parents=True, exist_ok=True)
        provider_root.joinpath("output.tf").write_text(_output_tf(provider), encoding="utf-8")
        provider_root.joinpath("variables.tf").write_text(_variables_tf(), encoding="utf-8")
        provider_root.joinpath("firewall.tf").write_text(_firewall_tf(provider), encoding="utf-8")
        provider_root.joinpath("main.tf").write_text(_main_tf(provider), encoding="utf-8")
        provider_root.joinpath("middle.tf").write_text(_node_tf(provider), encoding="utf-8")
        provider_root.joinpath("edge.tf").write_text(_node_tf(provider), encoding="utf-8")
        templates.joinpath("inventory.tftpl").write_text(
            "[sketch]\n${hostname} ansible_ssh_user=${ansible_user}\n",
            encoding="utf-8",
        )
        templates.joinpath("ssh-stanza.tftpl").write_text(
            "Host ${middle.hostname}\n"
            "  HostName ${middle.public_ip}\n"
            "  User user\n\n"
            "Host ${edge.hostname}\n"
            "  HostName ${edge.public_ip}\n"
            "  User user\n",
            encoding="utf-8",
        )
        templates.joinpath("sketch-bootstrap-cloud-init.tftpl").write_text(_cloud_init(), encoding="utf-8")


def _output_tf(provider: str) -> str:
    common = (
        'output "middle_public_ips" { value = [] }\n'
        'output "edge_public_ips" { value = [] }\n'
        'output "middle_instance_ids" { value = [] }\n'
        'output "edge_instance_ids" { value = [] }\n'
    )
    if provider == "linode":
        return common + 'output "inventory" { value = { middles = local.middle_hosts, edges = local.edge_hosts } }\n'
    return common


def _variables_tf() -> str:
    return (
        'variable "edge_regions" {\n'
        "  type = list(string)\n"
        "}\n"
        'variable "middle_count" {\n'
        "  type        = number\n"
        "}\n"
        'variable "edge_count_per_region" {\n'
        "  type        = number\n"
        "}\n"
        'variable "allowed_tcp_ports" {}\n'
        'variable "allowed_udp_ports" {}\n'
    )


def _firewall_tf(provider: str) -> str:
    if provider == "linode":
        return (
            'resource "linode_firewall" "firewall" {\n'
            '  dynamic "inbound" {\n'
            "    for_each = var.allowed_tcp_ports\n"
            "  }\n"
            '  dynamic "inbound" {\n'
            "    // Allow engagement hosts to access each other\n"
            "  }\n"
            "}\n"
        )
    return (
        'resource "digitalocean_firewall" "firewall" {\n'
        '  dynamic "inbound_rule" {\n'
        "    for_each = var.allowed_tcp_ports\n"
        "  }\n"
        '  dynamic "inbound_rule" {\n'
        "    // Allow all UDP ports specified in the allowed_udp_ports variable from anywhere\n"
        "    for_each = var.allowed_udp_ports\n"
        '    protocol              = "udp"\n'
        '    destination_addresses = ["0.0.0.0/0"]\n'
        '    destination_addresses = ["::/0"]\n'
        "  }\n"
        "}\n"
    )


def _main_tf(provider: str) -> str:
    if provider != "linode":
        return 'locals { ssh_pub_key_path = "sketch.pub" }\n'
    return (
        "locals {\n"
        "  ssh_pub_key_path = \"sketch.pub\"\n"
        "  middle_hosts = { for name, node in {} : name => { public_ip = tolist(node.ipv4)[0] } }\n"
        "  edge_hosts = { for name, node in {} : name => { public_ip = tolist(node.ipv4)[0] } }\n"
        "}\n"
    )


def _node_tf(provider: str) -> str:
    if provider == "linode":
        return (
            "resource \"linode_instance\" \"node\" {\n"
            "  metadata {\n"
            "    user_data = base64encode(templatefile(\"${path.module}/templates/sketch-bootstrap-cloud-init.tftpl\", {\n"
            "      sketch_ssh_public_key = chomp(file(local.ssh_pub_key_path))\n"
            "    }))\n"
            "  }\n"
            "}\n"
        )
    return (
        "resource \"digitalocean_droplet\" \"node\" {\n"
        "  user_data = templatefile(\"${path.module}/templates/sketch-bootstrap-cloud-init.tftpl\", {\n"
        "    sketch_ssh_public_key = chomp(file(local.ssh_pub_key_path))\n"
        "  })\n"
        "}\n"
    )


def _cloud_init() -> str:
    return (
        "#cloud-config\n"
        "users:\n"
        "  - name: user\n"
        "    gecos: Sketch Management\n"
        "    groups:\n"
        "      - sudo\n"
        '    sudo: "ALL=(ALL) NOPASSWD:ALL"\n'
        "    shell: /bin/bash\n"
        "    lock_passwd: true\n"
        "    ssh_authorized_keys:\n"
        "      - ${sketch_ssh_public_key}\n"
        "  - name: sketchssh\n"
        "    gecos: Sketch SSH\n"
        "    shell: /bin/bash\n"
        "    lock_passwd: true\n"
    )
