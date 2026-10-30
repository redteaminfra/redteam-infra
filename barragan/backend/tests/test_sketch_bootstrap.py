# Copyright (c) 2026, Oracle and/or its affiliates.
import json
from dataclasses import replace

import pytest

from app.services.sketch_bootstrap import (
    SketchBootstrapCoreHost,
    SketchBootstrapNode,
    SketchBootstrapSpec,
    SketchBootstrapValidationError,
    render_strict_v2_sketch_identity_ssh_config,
    render_sketch_bootstrap_workspace,
)
from app.services.provider_keyed_host_policy import (
    ChannelRoute,
    Edge,
    Middle,
    Topology,
    render_sketch_host_policy,
)


def _spec(**overrides):
    values = {
        "homebase": SketchBootstrapCoreHost("homebase", "10.0.0.10", "ubuntu", "/run/keys/core"),
        "proxy": SketchBootstrapCoreHost("proxy", "10.0.2.11", "ubuntu", "/run/keys/core"),
        "middle": SketchBootstrapNode("middle-01", "198.51.100.10", "10.20.0.10"),
        "edges": (SketchBootstrapNode("edge-01", "203.0.113.20", "10.21.0.10"),),
        "admin_private_key_path": "/run/keys/engagement-sketch",
        "admin_public_key_path": "/run/keys/engagement-sketch.pub",
        "transport_public_key_path": "/run/keys/engagement-sketch-transport.pub",
        "ssh_config_path": "/run/barragan-bootstrap/ansible/ssh_config",
        "upstream_root_playbook_path": "/opt/redteam-infra/external/sketch/ansible/sketch-playbook.yml",
    }
    values.update(overrides)
    return SketchBootstrapSpec(**values)


def _v2_spec(**overrides):
    edges = (
        SketchBootstrapNode("edge-01", "203.0.113.20", "10.21.0.10"),
        SketchBootstrapNode("edge-02", "203.0.113.21", "10.21.0.11"),
    )
    policies = render_sketch_host_policy(
        Topology(
            proxy_egress_ips={"proxy01": "192.0.2.10"},
            middles={"middle-01": Middle("198.51.100.10", "proxy01")},
            edges={node.name: Edge(node.public_ip, "middle-01") for node in edges},
        ),
        (ChannelRoute("edge-01", "middle-01", 18085, "tcp", ("0.0.0.0/0",)),),
    )
    values = {"edges": edges, "host_policies": policies, "proxy_egress_ip": "192.0.2.10"}
    values.update(overrides)
    return _spec(**values)


def test_default_split_v1_workspace_has_no_host_vars():
    workspace = render_sketch_bootstrap_workspace(_spec())
    assert workspace.host_vars == ()
    assert "hostVars" not in workspace.to_dict()
    assert "ControlMaster no" not in workspace.ssh_config.content


def test_v2_every_ssh_alias_disables_multiplexing():
    config = render_sketch_bootstrap_workspace(_v2_spec()).ssh_config.content
    assert config.count("\nHost ") == 8
    assert config.count("  ControlMaster no") == 8
    assert config.count("  ControlPersist no") == 8


def test_v2_transport_restarts_and_reconnects_after_policy_validation():
    transport = render_sketch_bootstrap_workspace(_v2_spec()).transport_playbook.content
    assert "  hosts: sketch\n  serial: 1\n" in transport
    ordered = (
        "ansible.builtin.command: /usr/sbin/sshd -t",
        "ansible.builtin.pause:\n        seconds: 3",
        "ansible.builtin.service:\n        name: ssh\n        state: restarted",
        "ansible.builtin.meta: reset_connection",
        "ansible.builtin.wait_for_connection:",
    )
    assert all(part in transport for part in ordered)
    assert [transport.index(part) for part in ordered] == sorted(
        transport.index(part) for part in ordered
    )
    assert "state: reloaded" not in transport


def test_v2_initial_known_hosts_enrollment_renders_distinct_core_and_sketch_trust():
    sketch_file = "/durable/sketch-known-hosts"
    core_file = "/durable/core-known-hosts"
    workspace = render_sketch_bootstrap_workspace(_v2_spec(
        proxy=SketchBootstrapCoreHost("proxy", "10.0.2.11", "ubuntu", "/run/keys/core", "8.8.8.8"),
        initial_sketch_known_hosts_path=sketch_file,
        pinned_core_known_hosts_path=core_file,
    ))
    config = workspace.ssh_config.content
    assert config.count(f"UserKnownHostsFile {core_file}") == 2
    assert config.count(f"UserKnownHostsFile {sketch_file}") == 6
    assert config.count("StrictHostKeyChecking yes") == 2
    assert config.count("StrictHostKeyChecking accept-new") == 6
    assert "HostKeyAlias barragan-bootstrap-homebase" not in config
    assert "HostKeyAlias 8.8.8.8" in config
    for name in ("middle-01", "edge-01", "edge-02"):
        assert config.count(f"HostKeyAlias barragan-bootstrap-sketch-{name}") == 2
    assert "ProxyJump barragan-bootstrap-proxy,barragan-bootstrap-root-middle-01" in config
    assert "ProxyJump barragan-bootstrap-proxy,barragan-bootstrap-user-middle-01" in config
    for inventory in (workspace.inventory.content, workspace.user_inventory.content):
        assert f"UserKnownHostsFile={sketch_file}" in inventory
        assert "StrictHostKeyChecking=accept-new" in inventory


def test_strict_v2_identity_config_uses_pinned_user_route_without_enrollment():
    spec = _v2_spec(
        proxy=SketchBootstrapCoreHost("proxy", "10.0.2.11", "ubuntu", "/run/keys/core", "8.8.8.8"),
        proxy_egress_ip="8.8.8.8",
        initial_sketch_known_hosts_path="/durable/sketch-known-hosts",
        pinned_core_known_hosts_path="/durable/core-known-hosts",
    )
    policies = {name: dict(policy) for name, policy in spec.host_policies.items()}
    policies[spec.middle.name]["sketch_firewall_v2_ssh_sources"] = ["8.8.8.8/32"]
    spec = replace(spec, host_policies=policies)
    config = render_strict_v2_sketch_identity_ssh_config(spec)
    assert config.count("StrictHostKeyChecking yes") == 8
    assert "StrictHostKeyChecking accept-new" not in config
    assert config.count("ControlMaster no") == config.count("ControlPersist no") == 8
    assert "ProxyJump barragan-bootstrap-proxy,barragan-bootstrap-user-middle-01" in config
    # The ordinary first-contact renderer remains enrollment-capable.
    ordinary = render_sketch_bootstrap_workspace(spec).ssh_config.content
    assert ordinary.count("StrictHostKeyChecking accept-new") == 6


def test_strict_v2_identity_config_rejects_legacy_spec():
    with pytest.raises(SketchBootstrapValidationError) as raised:
        render_strict_v2_sketch_identity_ssh_config(_spec())
    assert "strict v2 proof requires separate pinned trust files" in raised.value.errors


@pytest.mark.parametrize("override", [
    {"initial_sketch_known_hosts_path": "/durable/sketch-known-hosts"},
    {"pinned_core_known_hosts_path": "/durable/core-known-hosts"},
    {"initial_sketch_known_hosts_path": "/durable/same",
     "pinned_core_known_hosts_path": "/durable/same"},
    {"initial_sketch_known_hosts_path": "/durable/bad'path",
     "pinned_core_known_hosts_path": "/durable/core-known-hosts"},
])
def test_v2_initial_enrollment_requires_two_distinct_safe_paths(override):
    with pytest.raises(SketchBootstrapValidationError):
        render_sketch_bootstrap_workspace(_v2_spec(
            proxy=SketchBootstrapCoreHost("proxy", "10.0.2.11", "ubuntu", "/run/keys/core", "8.8.8.8"),
            **override,
        ))


def test_split_v1_cannot_request_initial_enrollment():
    with pytest.raises(SketchBootstrapValidationError):
        render_sketch_bootstrap_workspace(_spec(
            initial_sketch_known_hosts_path="/durable/sketch-known-hosts",
            pinned_core_known_hosts_path="/durable/core-known-hosts",
        ))


def test_v2_host_vars_are_isolated_per_inventory_host():
    workspace = render_sketch_bootstrap_workspace(_v2_spec())
    artifacts = {artifact.target: json.loads(artifact.content) for artifact in workspace.host_vars}
    assert set(artifacts) == {
        "ansible/host_vars/middle-01.json",
        "ansible/host_vars/edge-01.json",
        "ansible/host_vars/edge-02.json",
    }
    middle = artifacts["ansible/host_vars/middle-01.json"]
    edge = artifacts["ansible/host_vars/edge-01.json"]
    sibling = artifacts["ansible/host_vars/edge-02.json"]
    assert middle["sketch_firewall_v2_ssh_sources"] == ["192.0.2.10/32"]
    assert middle["sketch_firewall_v2_rules"] == [{"from_ip": "203.0.113.20/32", "port": 18085, "proto": "tcp"}]
    assert edge["sketch_firewall_v2_ssh_sources"] == ["198.51.100.10/32"]
    assert edge["sketch_firewall_v2_rules"] == [{"from_ip": "0.0.0.0/0", "port": 18085, "proto": "tcp"}]
    assert sibling["sketch_firewall_v2_rules"] == []
    assert "203.0.113.21" not in workspace.host_vars[1].content
    assert "192.0.2.10" not in workspace.host_vars[1].content


@pytest.mark.parametrize("mutation", ["missing", "extra", "predecessor", "route"])
def test_v2_policy_rejects_incomplete_or_unsafe_coverage(mutation):
    spec = _v2_spec()
    policies = {name: dict(policy) for name, policy in spec.host_policies.items()}
    if mutation == "missing":
        del policies["edge-02"]
    elif mutation == "extra":
        policies["edge-03"] = dict(policies["edge-02"])
    elif mutation == "predecessor":
        policies["edge-01"]["sketch_firewall_v2_ssh_sources"] = ["0.0.0.0/0"]
    else:
        policies["edge-01"]["sketch_firewall_v2_rules"] = [{"from_ip": "0.0.0.0/0", "port": 22, "proto": "tcp"}]
    with pytest.raises(SketchBootstrapValidationError):
        render_sketch_bootstrap_workspace(_v2_spec(host_policies=policies))


def test_v2_host_vars_reject_unsafe_inventory_name():
    with pytest.raises(SketchBootstrapValidationError):
        render_sketch_bootstrap_workspace(_v2_spec(edges=(SketchBootstrapNode("../edge", "203.0.113.20"),)))


def test_renders_two_phase_inventory_and_full_management_hop_path():
    workspace = render_sketch_bootstrap_workspace(_spec())

    assert workspace.inventory.target == "ansible/inventory.ini"
    assert "[sketch]" in workspace.inventory.content
    assert "[sketch:vars]" in workspace.inventory.content
    assert "[sketch_bootstrap:vars]" not in workspace.inventory.content
    assert "ansible_ssh_common_args='-F ansible/ssh_config" in workspace.inventory.content
    assert "middle-01 ansible_host=barragan-bootstrap-root-middle-01 ansible_user=root" in workspace.inventory.content
    assert "edge-01 ansible_host=barragan-bootstrap-root-edge-01 ansible_user=root" in workspace.inventory.content
    assert "middle-01 ansible_host=barragan-bootstrap-user-middle-01 ansible_user=user" in workspace.user_inventory.content
    assert "edge-01 ansible_host=barragan-bootstrap-user-edge-01 ansible_user=user" in workspace.user_inventory.content

    ssh_config = workspace.ssh_config.content
    assert "Host barragan-bootstrap-homebase" in ssh_config
    assert "Host barragan-bootstrap-proxy" in ssh_config
    assert "ProxyJump barragan-bootstrap-homebase" in ssh_config
    assert "Host barragan-bootstrap-root-middle-01" in ssh_config
    assert "ProxyJump barragan-bootstrap-proxy" in ssh_config
    assert "Host barragan-bootstrap-root-edge-01" in ssh_config
    assert "ProxyJump barragan-bootstrap-proxy,barragan-bootstrap-root-middle-01" in ssh_config
    assert "Host barragan-bootstrap-user-middle-01" in ssh_config
    assert "Host barragan-bootstrap-user-edge-01" in ssh_config
    assert "ProxyJump barragan-bootstrap-proxy,barragan-bootstrap-user-middle-01" in ssh_config
    assert "HostName 203.0.113.20" in ssh_config
    # The host-level policy is essential: nested SSH processes created by
    # ProxyJump do not inherit Ansible's final-client common args.
    assert ssh_config.count("UserKnownHostsFile /dev/null") == 6
    assert ssh_config.count("StrictHostKeyChecking no") == 6
    assert ssh_config.count("BatchMode yes") == 6
    assert ssh_config.count("ConnectTimeout 15") == 6

    readiness = workspace.readiness_playbook.content
    assert "hosts: sketch" in readiness
    assert "serial: 1" in readiness
    assert "any_errors_fatal: true" in readiness
    assert "ansible.builtin.wait_for_connection:" in readiness
    assert "timeout: 45" in readiness
    user_readiness = workspace.user_readiness_playbook.content
    assert "Verify serial post-root sketch user readiness" in user_readiness
    assert "Verify the upstream root-to-user identity handoff" in user_readiness
    assert "hosts: sketch" in user_readiness
    assert "serial: 1" in user_readiness
    assert "any_errors_fatal: true" in user_readiness


def test_user_edge_aliases_route_through_user_middle_for_every_edge():
    workspace = render_sketch_bootstrap_workspace(
        _spec(
            edges=(
                SketchBootstrapNode("edge-01", "203.0.113.20", "10.21.0.10"),
                SketchBootstrapNode("edge-02", "203.0.113.21", "10.21.0.11"),
            )
        )
    )

    assert workspace.user_inventory.content.count("ansible_user=user") == 3
    assert "Host barragan-bootstrap-user-edge-01" in workspace.ssh_config.content
    assert "Host barragan-bootstrap-user-edge-02" in workspace.ssh_config.content
    assert workspace.ssh_config.content.count(
        "ProxyJump barragan-bootstrap-proxy,barragan-bootstrap-user-middle-01"
    ) == 2


def test_root_phase_uses_pinned_upstream_playbook_and_transport_phase_uses_user():
    workspace = render_sketch_bootstrap_workspace(_spec())

    root = workspace.root_variables.content
    assert "configured upstream external/sketch/ansible/sketch-playbook.yml" in root
    assert "ssh_pub_key: /run/keys/engagement-sketch.pub" in root
    assert "ssh_config_path: /run/barragan-bootstrap/ansible/ssh_config" in root
    assert workspace.execution.root_command[-2:] == (
        "-e",
        "@ansible/upstream-bootstrap-vars.yml",
    )
    assert workspace.execution.root_command[:5] == (
        "ansible-playbook",
        "-f",
        "1",
        "-i",
        "ansible/inventory.ini",
    )
    assert workspace.execution.readiness_command == (
        "ansible-playbook",
        "-f",
        "1",
        "-i",
        "ansible/inventory.ini",
        "ansible/wait_for_sketch_readiness.yml",
    )
    assert "/opt/redteam-infra/external/sketch/ansible/sketch-playbook.yml" in workspace.execution.root_command
    assert workspace.execution.user_readiness_command == (
        "ansible-playbook",
        "-f",
        "1",
        "-i",
        "ansible/user_inventory.ini",
        "ansible/wait_for_sketch_user_readiness.yml",
    )
    assert workspace.execution.transport_command[:5] == (
        "ansible-playbook",
        "-f",
        "1",
        "-i",
        "ansible/user_inventory.ini",
    )

    transport = workspace.transport_playbook.content
    assert "hosts: sketch" in transport
    assert "remote_user: user" in transport
    assert "ansible_user: user" in transport
    assert "become: true" in transport
    assert "path: /home/sketchssh/.ssh" in transport
    assert "owner: sketchssh" in transport
    assert "mode: '0700'" in transport
    assert "path: /home/sketchssh/.ssh/authorized_keys" in transport
    assert "mode: '0600'" in transport
    assert "lineinfile:" in transport
    assert "state: present" in transport
    assert "bootstrap_transport_public_key_path: /run/keys/engagement-sketch-transport.pub" in transport
    assert "path: /etc/ssh/sshd_config.d" in transport
    assert "dest: /etc/ssh/sshd_config.d/90-barragan-sketch-forwarding.conf" in transport
    assert "when: inventory_hostname == \"middle-01\"" in transport
    assert "AllowTcpForwarding local" in transport
    assert "GatewayPorts no" in transport
    assert "when: inventory_hostname != \"middle-01\"" in transport
    assert "AllowTcpForwarding yes" in transport
    assert "GatewayPorts yes" in transport
    assert "name: Ensure OpenSSH privilege-separation runtime directory exists" in transport
    assert "path: /run/sshd" in transport
    assert "mode: '0755'" in transport
    assert "ansible.builtin.command: /usr/sbin/sshd -t" in transport
    assert transport.index("path: /run/sshd") < transport.index(
        "ansible.builtin.command: /usr/sbin/sshd -t"
    )
    assert "name: ssh" in transport
    assert "state: reloaded" in transport
    assert "state: absent" not in transport


def test_rendered_artifacts_reference_paths_without_private_key_content():
    workspace = render_sketch_bootstrap_workspace(_spec())
    rendered = "\n".join(
        artifact.content
        for artifact in (
            workspace.inventory,
            workspace.user_inventory,
            workspace.ssh_config,
            workspace.readiness_playbook,
            workspace.user_readiness_playbook,
            workspace.root_variables,
            workspace.transport_playbook,
            workspace.manifest,
        )
    )

    assert "/run/keys/engagement-sketch" in rendered
    assert "BEGIN OPENSSH PRIVATE KEY" not in rendered
    assert "PRIVATE KEY\n" not in rendered
    assert workspace.execution.to_dict() == {
        "readinessCommand": [
            "ansible-playbook",
            "-f",
            "1",
            "-i",
            "ansible/inventory.ini",
            "ansible/wait_for_sketch_readiness.yml",
        ],
        "rootCommand": [
            "ansible-playbook",
            "-f",
            "1",
            "-i",
            "ansible/inventory.ini",
            "/opt/redteam-infra/external/sketch/ansible/sketch-playbook.yml",
            "-e",
            "@ansible/upstream-bootstrap-vars.yml",
        ],
        "userReadinessCommand": [
            "ansible-playbook",
            "-f",
            "1",
            "-i",
            "ansible/user_inventory.ini",
            "ansible/wait_for_sketch_user_readiness.yml",
        ],
        "transportCommand": [
            "ansible-playbook",
            "-f",
            "1",
            "-i",
            "ansible/user_inventory.ini",
            "ansible/install_sketch_transport.yml",
        ],
    }


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ({"edges": ()}, "at least one edge is required"),
        ({"admin_private_key_path": "relative-key"}, "administration private key path is invalid"),
        ({"middle": SketchBootstrapNode("middle-01", "not-an-ip")}, "sketch node public IP is invalid: middle-01"),
        ({"edges": (SketchBootstrapNode("middle-01", "203.0.113.20"),)}, "sketch node names must be unique"),
    ],
)
def test_rejects_incomplete_or_unsafe_bootstrap_specs(override, expected):
    with pytest.raises(SketchBootstrapValidationError) as exc:
        render_sketch_bootstrap_workspace(_spec(**override))

    assert expected in exc.value.errors
