# Copyright (c) 2026, Oracle and/or its affiliates.
from pathlib import Path
from types import SimpleNamespace
import os
import stat
import subprocess
import shutil
from dataclasses import replace
import json

import pytest

from app.domain import JobEvent
from app.services.sketch_bootstrap_apply import SketchBootstrapApplyError, apply_sketch_bootstrap, _write_workspace
from app.services.sketch_bootstrap import (
    SketchBootstrapCoreHost,
    SketchBootstrapNode,
    SketchBootstrapSpec,
    render_sketch_bootstrap_workspace,
)
from app.services.provider_keyed_host_policy import Edge, Middle, Topology, render_sketch_host_policy
from app.services.outbound_channel_apply import OutboundChannelApplyValidationError, _require_bootstrapped_chain
from app.storage.job_repository import StoredJobRun
from app.storage.sketch_chain_repository import StoredSketchChain


class _Repository:
    def list_for_engagement(self, engagement_id):
        return [job for job in self.list() if job.input.get("engagementId") == engagement_id]

    def list(self):
        return [
            SimpleNamespace(
                id="job-core",
                action="pilot_standard_rti_guarded_execute",
                input={"engagementId": "eng-test"},
                status="succeeded",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "core deployed",
                        {
                            "connectionDetails": [
                                {"role": "homebase", "publicIp": "10.0.0.10", "sshUser": "user"},
                                {"role": "proxy", "name": "proxy01", "privateIp": "10.0.2.10", "sshUser": "user"},
                            ],
                            "mutationStatus": "deployed",
                        },
                    )
                ],
            )
        ]


class _RepositoryWithPublicProxy(_Repository):
    def list(self):
        jobs = super().list()
        jobs[0].events[0].data["connectionDetails"][1]["publicIp"] = "8.8.8.8"
        return jobs


def test_v2_core_proxy_alias_requires_unique_reviewed_public_ip():
    from app.services import sketch_bootstrap_apply as subject

    assert subject._core_hosts(_Repository(), "eng-test", "proxy01")[1].host == "10.0.2.10"
    with pytest.raises(SketchBootstrapApplyError, match="public IP"):
        subject._core_hosts(_Repository(), "eng-test", "proxy01", require_proxy_public_alias=True)

    class _Ambiguous(_RepositoryWithPublicProxy):
        def list(self):
            jobs = super().list()
            details = jobs[0].events[0].data["connectionDetails"]
            details.append({**details[1]})
            return jobs

    with pytest.raises(SketchBootstrapApplyError, match="ambiguous"):
        subject._core_hosts(_Ambiguous(), "eng-test", "proxy01", require_proxy_public_alias=True)
    reviewed = subject._core_hosts(_RepositoryWithPublicProxy(), "eng-test", "proxy01",
                                   require_proxy_public_alias=True)[1]
    assert reviewed.host == "10.0.2.10" and reviewed.host_key_alias == "8.8.8.8"


def _v2_workspace():
    policies = render_sketch_host_policy(
        Topology(
            proxy_egress_ips={"proxy01": "192.0.2.10"},
            middles={"middle-01": Middle("198.51.100.10", "proxy01")},
            edges={"edge-01": Edge("203.0.113.20", "middle-01")},
        ),
        (),
    )
    return render_sketch_bootstrap_workspace(SketchBootstrapSpec(
        homebase=SketchBootstrapCoreHost("homebase", "10.0.0.10", "ubuntu", "/run/keys/core"),
        proxy=SketchBootstrapCoreHost("proxy", "10.0.2.11", "ubuntu", "/run/keys/core"),
        middle=SketchBootstrapNode("middle-01", "198.51.100.10", "10.20.0.10"),
        edges=(SketchBootstrapNode("edge-01", "203.0.113.20", "10.21.0.10"),),
        admin_private_key_path="/run/keys/engagement-sketch",
        admin_public_key_path="/run/keys/engagement-sketch.pub",
        transport_public_key_path="/run/keys/engagement-sketch-transport.pub",
        ssh_config_path="/run/barragan-bootstrap/ansible/ssh_config",
        upstream_root_playbook_path="/opt/redteam-infra/external/sketch/ansible/sketch-playbook.yml",
        host_policies=policies,
        proxy_egress_ip="192.0.2.10",
    ))


def test_v2_workspace_materializes_private_exact_host_vars(tmp_path):
    workspace = _v2_workspace()
    _write_workspace(tmp_path, workspace, expected_host_names={"middle-01", "edge-01"})
    host_vars = tmp_path / "ansible" / "host_vars"
    assert {path.name for path in host_vars.iterdir()} == {"middle-01.json", "edge-01.json"}
    assert host_vars.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in host_vars.iterdir())
    assert json.loads((host_vars / "edge-01.json").read_text())["sketch_firewall_v2_ssh_sources"] == ["198.51.100.10/32"]


def test_default_workspace_materializes_without_host_vars(tmp_path):
    workspace = replace(_v2_workspace(), host_vars=())
    _write_workspace(tmp_path, workspace, expected_host_names={"middle-01", "edge-01"})
    assert (tmp_path / "ansible" / "inventory.ini").exists()
    assert not (tmp_path / "ansible" / "host_vars").exists()


@pytest.mark.parametrize("condition", ["missing", "extra", "symlink", "redirected"])
def test_v2_workspace_materialization_fails_closed(tmp_path, condition):
    workspace = _v2_workspace()
    if condition == "missing":
        workspace = replace(workspace, host_vars=workspace.host_vars[:1])
    elif condition == "extra":
        host_vars = tmp_path / "ansible" / "host_vars"
        host_vars.mkdir(parents=True)
        (host_vars / "extra.json").write_text("{}")
    elif condition == "symlink":
        (tmp_path / "ansible").mkdir()
        (tmp_path / "ansible" / "host_vars").symlink_to(tmp_path)
    else:
        workspace = replace(workspace, host_vars=(
            replace(workspace.host_vars[0], target="ansible/host_vars/../edge-01.json"),
            workspace.host_vars[1],
        ))
    with pytest.raises(SketchBootstrapApplyError):
        _write_workspace(tmp_path, workspace, expected_host_names={"middle-01", "edge-01"})


@pytest.mark.parametrize("extra_role", ["middle", "unknown"])
def test_v2_bootstrap_rejects_extra_node_before_workspace_write(monkeypatch, tmp_path, extra_role):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    chain = _chain()
    chain.nodes.append({"role": extra_role, "hostname": "unexpected", "publicIp": "203.0.113.30"})
    workspace = tmp_path / "workspace"
    with pytest.raises(SketchBootstrapApplyError, match="exactly one middle and only middle/edge"):
        apply_sketch_bootstrap(
            "eng-test", chain, repository=_RepositoryWithPublicProxy(), workspace_root=workspace,
            host_policies={}, proxy_egress_ip="8.8.8.8",
        )
    assert not workspace.exists()


@pytest.mark.parametrize("path_kind", ["symlink", "dotdot", "relative"])
def test_v2_bootstrap_rejects_noncanonical_workspace_before_write(tmp_path, path_kind):
    workspace = tmp_path / "workspace"
    if path_kind == "symlink":
        workspace.symlink_to(tmp_path / "target")
    elif path_kind == "dotdot":
        workspace = tmp_path / "subdir" / ".." / "workspace"
    else:
        workspace = Path("relative-workspace")
    with pytest.raises(SketchBootstrapApplyError, match="canonical path"):
        apply_sketch_bootstrap(
            "eng-test", _chain(), repository=_Repository(), workspace_root=workspace,
            host_policies={}, proxy_egress_ip="192.0.2.10",
        )
    assert not (tmp_path / "target").exists()
    assert not (tmp_path / "workspace" / "ansible").exists()


@pytest.mark.parametrize("child", ["ansible", "keys"])
def test_v2_bootstrap_rejects_symlinked_workspace_child_before_write(monkeypatch, tmp_path, child):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / child).symlink_to(tmp_path / "outside")
    with pytest.raises(SketchBootstrapApplyError, match="fresh workspace root"):
        apply_sketch_bootstrap(
            "eng-test", _chain(), repository=_Repository(), workspace_root=workspace,
            host_policies={}, proxy_egress_ip="192.0.2.10",
        )
    assert not (tmp_path / "outside").exists()


def test_v2_workspace_rejects_symlinked_ordinary_artifact(tmp_path):
    workspace = _v2_workspace()
    outside = tmp_path / "outside"
    outside.write_text("preserve")
    ansible = tmp_path / "ansible"
    ansible.mkdir()
    (ansible / "inventory.ini").symlink_to(outside)
    with pytest.raises(SketchBootstrapApplyError, match="artifact path is unsafe"):
        _write_workspace(tmp_path, workspace, expected_host_names={"middle-01", "edge-01"})
    assert outside.read_text() == "preserve"


def _chain():
    return SimpleNamespace(
        assigned_proxy="proxy01",
        nodes=[
            {"role": "middle", "hostname": "middle-01", "publicIp": "198.51.100.10"},
            {"role": "edge", "hostname": "edge-01", "publicIp": "203.0.113.10"},
        ],
    )


def _retained_provider_nodes():
    return [
        {
            "role": "middle",
            "hostname": "middle-01",
            "name": "middle-01",
            "provider": "linode",
            "providerResourceId": "linode-middle-101",
            "instanceId": 101,
            "region": "us-sea",
            "size": "g6-nanode-1",
            "publicIp": "198.51.100.10",
            "privateIp": "10.20.0.10",
            "status": "running",
            "chainId": "proxy01-sea-01",
            "assignedProxy": "proxy01",
            "proxy": "proxy01",
            "burned": False,
            "burnedNote": "",
        },
        {
            "role": "edge",
            "hostname": "edge-01",
            "name": "edge-01",
            "provider": "linode",
            "providerResourceId": "linode-edge-202",
            "instanceId": 202,
            "region": "us-sea",
            "size": "g6-nanode-1",
            "publicIp": "203.0.113.10",
            "privateIp": "10.20.0.20",
            "status": "running",
            "chainId": "proxy01-sea-01",
            "assignedProxy": "proxy01",
            "proxy": "proxy01",
            "burned": False,
            "burnedNote": "",
        },
    ]


def _retained_failed_provider_job():
    provider_identity = {
        "terraformWorkingDirectory": "/var/lib/barragan/devtest-data/sketch/eng-test/proxy01-sea-01",
        "providerResourceIds": ["linode-middle-101", "linode-edge-202"],
        "middleProvider": "linode",
        "middleRegion": "us-sea",
        "edgeProvider": "linode",
        "edgeRegions": ["us-sea"],
    }
    return replace(
        _provider_job(),
        status="failed",
        input=provider_identity,
        artifact_refs=["artifact-provider-plan", "terraform:linode-sketch:eng-test:proxy01-sea-01"],
        events=[
            JobEvent(1, "info", "terraform output recorded", {"sketchInfrastructure": _retained_provider_nodes()}),
            JobEvent(
                2,
                "error",
                "sketch bootstrap failed; provider infrastructure retained for retry",
                {"bootstrap": "failed", "error": "apt lock retry exhausted"},
            ),
        ],
    )


def _forbid_provider_deployment_adapters(monkeypatch, subject):
    monkeypatch.setattr(subject, "get_engagement", lambda _id: SimpleNamespace(sketch_state_schema="split-v1"))
    monkeypatch.setattr(
        subject, "start_guarded_linode_sketch_run", lambda *_args, **_kwargs: pytest.fail("Linode provider must not rerun")
    )
    monkeypatch.setattr(
        subject,
        "start_guarded_digitalocean_sketch_run",
        lambda *_args, **_kwargs: pytest.fail("DigitalOcean provider must not rerun"),
    )
    monkeypatch.setattr(
        subject, "start_guarded_mixed_sketch_run", lambda *_args, **_kwargs: pytest.fail("mixed provider must not rerun")
    )


def _durable_chain_identity(chain):
    identity = chain.to_dict()
    identity.pop("status")
    identity.pop("updatedAt")
    return identity


def _durable_job_identity(job):
    return {
        "id": job.id,
        "action": job.action,
        "target": job.target,
        "target_type": job.target_type,
        "target_id": job.target_id,
        "requested_by": job.requested_by,
        "input": job.input,
        "artifact_refs": job.artifact_refs,
        "created_at": job.created_at,
    }


def _materializer(name: str):
    def write(_engagement_id: str, directory: Path):
        directory.mkdir(parents=True, exist_ok=True)
        private = directory / name
        public = directory / f"{name}.pub"
        private.write_text("PRIVATE", encoding="utf-8")
        public.write_text("ssh-ed25519 AAAA test", encoding="utf-8")
        return str(private), str(public)

    return write


def _upstream(tmp_path: Path):
    root = tmp_path / "redteam-infra"
    playbook = root / "external/sketch/ansible/sketch-playbook.yml"
    playbook.parent.mkdir(parents=True, exist_ok=True)
    playbook.write_text(
        """---
- name: compatibility fixture
  tasks:
    - name: Update apt and upgrade
      apt:
        update_cache: yes
        upgrade: dist

    - name: Install required packages
      apt:
        name:
          - unattended-upgrades
          - nginx
        state: present

    - authorized_key:
        key: \"{{ lookup('file', '{{ ssh_pub_key }}') }}\"
    - name: Clean up temporary file
      local_action:
        module: file
        path: \"ansible_ips.txt\"
        state: absent
      become: no
  handlers:
    - name: Reload sshd
      service:
        name: sshd
        state: reloaded
""",
        encoding="utf-8",
    )
    roles = root / "ansible/roles"
    roles.mkdir(parents=True, exist_ok=True)
    disable_ipv6 = root / "external/sketch/ansible/roles/disable-ipv6"
    (disable_ipv6 / "tasks").mkdir(parents=True, exist_ok=True)
    (disable_ipv6 / "tasks/main.yml").write_text(
        """---
- name: Query metadata service
  uri:
    url: "http://169.254.169.254/v1/instance"
    return_content: yes
    status_code: 400
""",
        encoding="utf-8",
    )
    return SimpleNamespace(path=lambda *parts: root.joinpath(*parts), ansible_roles_root=roles)


def test_runs_pinned_upstream_then_transport_and_scrubs_staged_keys(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    commands = []

    def runner(command, cwd, env):
        commands.append((command, cwd, env))
        return subprocess.CompletedProcess(command, 0, "", "")

    workspace = tmp_path / "workspace"
    result = apply_sketch_bootstrap("eng-test", _chain(), repository=_Repository(), runner=runner, workspace_root=workspace)

    assert result.node_count == 2
    assert len(commands) == 4
    assert commands[0][0][-1] == "ansible/wait_for_sketch_readiness.yml"
    assert commands[1][0][5].endswith("ansible/upstream-sketch-playbook.compat.yml")
    assert commands[2][0][-1] == "ansible/wait_for_sketch_user_readiness.yml"
    assert commands[3][0][1:4] == ["-f", "1", "-i"]
    assert commands[3][0][-1] == "ansible/install_sketch_transport.yml"
    assert str(_upstream(tmp_path).path("external", "sketch", "ansible", "roles")) in commands[0][2]["ANSIBLE_ROLES_PATH"]
    assert str(_upstream(tmp_path).ansible_roles_root) in commands[0][2]["ANSIBLE_ROLES_PATH"]
    assert str(workspace / "ansible/roles") == commands[0][2]["ANSIBLE_ROLES_PATH"].split(":")[0]
    control_path_dirs = {command_env["ANSIBLE_SSH_CONTROL_PATH_DIR"] for _, _, command_env in commands}
    assert len(control_path_dirs) == 1
    assert {command_env["ANSIBLE_SSH_CONTROL_PATH"] for _, _, command_env in commands} == {
        "%(directory)s/%%C"
    }
    assert {command_env["ANSIBLE_SSH_ARGS"] for _, _, command_env in commands} == {
        "-C -o ControlMaster=auto -o ControlPersist=60s"
    }
    for variable in (
        "ANSIBLE_SSH_COMMON_ARGS",
        "ANSIBLE_SSH_EXTRA_ARGS",
        "ANSIBLE_SFTP_EXTRA_ARGS",
        "ANSIBLE_SCP_EXTRA_ARGS",
    ):
        assert {command_env[variable] for _, _, command_env in commands} == {""}
    control_path_dir = Path(control_path_dirs.pop())
    assert control_path_dir.parent == Path("/tmp").resolve()
    assert control_path_dir.name.startswith("bcp-")
    assert not control_path_dir.exists()
    assert not (workspace / "keys").exists()


def test_identical_alias_workspaces_isolate_control_paths_and_preserve_safe_inherited_config(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    phase_environments = {"first": [], "second": []}

    def runner_for(workspace_name):
        def runner(command, _cwd, command_env):
            phase_environments[workspace_name].append(dict(command_env))
            return subprocess.CompletedProcess(command, 0, "", "")

        return runner

    inherited_config = tmp_path / "global-ansible.cfg"
    inherited_config.write_text("[defaults]\nforks = 5\n", encoding="utf-8")
    safe_arguments = {
        "ANSIBLE_SSH_ARGS": "-C -o ControlMaster=auto -o ControlPersist=30s",
        "ANSIBLE_SSH_COMMON_ARGS": "-o ServerAliveInterval=15",
        "ANSIBLE_SSH_EXTRA_ARGS": "-o LogLevel=ERROR",
        "ANSIBLE_SFTP_EXTRA_ARGS": "-o ConnectTimeout=20",
        "ANSIBLE_SCP_EXTRA_ARGS": "-o ConnectTimeout=25",
    }
    inherited_env = {
        "ANSIBLE_SSH_CONTROL_PATH": "/tmp/shared-explicit-socket",
        "ANSIBLE_SSH_CONTROL_PATH_DIR": "/tmp/shared-control-directory",
        "ANSIBLE_CONFIG": str(inherited_config),
        **safe_arguments,
    }
    for workspace_name in phase_environments:
        apply_sketch_bootstrap(
            "eng-test",
            _chain(),
            repository=_Repository(),
            runner=runner_for(workspace_name),
            env=inherited_env,
            workspace_root=tmp_path / workspace_name,
        )

    isolated_dirs = {}
    for workspace_name, environments in phase_environments.items():
        assert len(environments) == 4
        invocation_dirs = {environment["ANSIBLE_SSH_CONTROL_PATH_DIR"] for environment in environments}
        assert len(invocation_dirs) == 1
        isolated_dirs[workspace_name] = invocation_dirs.pop()
        assert {environment["ANSIBLE_SSH_CONTROL_PATH"] for environment in environments} == {
            "%(directory)s/%%C"
        }
        assert {environment["ANSIBLE_CONFIG"] for environment in environments} == {str(inherited_config)}
        for variable, value in safe_arguments.items():
            assert {environment[variable] for environment in environments} == {value}
    assert isolated_dirs["first"] != isolated_dirs["second"]
    assert all(not Path(directory).exists() for directory in isolated_dirs.values())


def test_control_socket_path_stays_within_conservative_unix_budget(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    observed_dirs = []

    def runner(command, _cwd, command_env):
        control_dir = Path(command_env["ANSIBLE_SSH_CONTROL_PATH_DIR"])
        observed_dirs.append(control_dir)
        assert control_dir.is_dir()
        assert control_dir.stat().st_mode & 0o777 == 0o700
        return subprocess.CompletedProcess(command, 0, "", "")

    apply_sketch_bootstrap(
        "eng-test",
        _chain(),
        repository=_Repository(),
        runner=runner,
        workspace_root=tmp_path / "workspace",
    )

    assert len(set(observed_dirs)) == 1
    final_socket = observed_dirs[0] / ("c" * 40)
    conservative_openssh_temporary_suffix = "." + ("t" * 32)
    assert len(f"{final_socket}{conservative_openssh_temporary_suffix}") < 100
    assert not observed_dirs[0].exists()


@pytest.mark.parametrize(
    "variable",
    [
        "ANSIBLE_SSH_ARGS",
        "ANSIBLE_SSH_COMMON_ARGS",
        "ANSIBLE_SSH_EXTRA_ARGS",
        "ANSIBLE_SFTP_EXTRA_ARGS",
        "ANSIBLE_SCP_EXTRA_ARGS",
    ],
)
def test_control_path_bearing_connection_arguments_fail_closed(monkeypatch, tmp_path: Path, variable: str):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    workspace = tmp_path / "workspace"

    with pytest.raises(SketchBootstrapApplyError, match=rf"{variable} must not override"):
        apply_sketch_bootstrap(
            "eng-test",
            _chain(),
            repository=_Repository(),
            runner=lambda *_args: pytest.fail("unsafe SSH arguments must fail before Ansible runs"),
            env={variable: "-o cOnTrOlPaTh=/tmp/shared-argument-socket"},
            workspace_root=workspace,
        )

    assert not (workspace / "keys").exists()


def test_recovery_bootstrap_pins_every_hop_to_reviewed_known_hosts(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    known_hosts = tmp_path / "reviewed_known_hosts"
    known_hosts.write_text("placeholder ssh-ed25519 AAAA\n", encoding="utf-8")

    workspace = tmp_path / "workspace"
    apply_sketch_bootstrap(
        "eng-test",
        _chain(),
        repository=_Repository(),
        runner=lambda command, cwd, env: subprocess.CompletedProcess(command, 0, "", ""),
        workspace_root=workspace,
        strict_known_hosts_path=known_hosts,
    )

    ssh_config = (workspace / "ansible/ssh_config").read_text(encoding="utf-8")
    inventory = (workspace / "ansible/inventory.ini").read_text(encoding="utf-8")
    user_inventory = (workspace / "ansible/user_inventory.ini").read_text(encoding="utf-8")
    assert ssh_config.count(f"UserKnownHostsFile {known_hosts}") == 6
    assert ssh_config.count("StrictHostKeyChecking yes") == 6
    assert ssh_config.count("HostKeyAlias barragan-bootstrap-") == 6
    assert "StrictHostKeyChecking no" not in ssh_config
    assert f"UserKnownHostsFile={known_hosts}" in inventory
    assert "StrictHostKeyChecking=yes" in inventory
    assert "accept-new" not in inventory
    assert f"UserKnownHostsFile={known_hosts}" in user_inventory
    assert "StrictHostKeyChecking=yes" in user_inventory
    assert "accept-new" not in user_inventory


def _fresh_v2_policy():
    return render_sketch_host_policy(
        Topology(
            proxy_egress_ips={"proxy01": "8.8.8.8"},
            middles={"middle-01": Middle("198.51.100.10", "proxy01")},
            edges={"edge-01": Edge("203.0.113.10", "middle-01")},
        ), (),
    )


def test_v2_append_bootstrap_commands_target_only_new_edge(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook",
                        lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    chain = _chain()
    chain.nodes.append({"role": "edge", "hostname": "edge-02", "publicIp": "203.0.113.11"})
    policies = render_sketch_host_policy(Topology(
        proxy_egress_ips={"proxy01": "8.8.8.8"},
        middles={"middle-01": Middle("198.51.100.10", "proxy01")},
        edges={"edge-01": Edge("203.0.113.10", "middle-01"),
               "edge-02": Edge("203.0.113.11", "middle-01")},
    ), ())
    calls = []

    def runner(command, _cwd, _env):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    result = apply_sketch_bootstrap(
        "eng-test", chain, repository=_RepositoryWithPublicProxy(), runner=runner,
        workspace_root=tmp_path / "append-scratch", host_policies=policies,
        proxy_egress_ip="8.8.8.8", only_edge_name="edge-02",
    )
    assert result.node_count == 1
    assert len(calls) == 4
    assert all(command[-2:] == ["--limit", "edge-02"] for command in calls)
    assert all("middle-01" not in command and "edge-01" not in command for command in calls)
    with pytest.raises(SketchBootstrapApplyError, match="one-edge bootstrap target"):
        apply_sketch_bootstrap(
            "eng-test", chain, repository=_RepositoryWithPublicProxy(),
            runner=lambda *_args: pytest.fail("must not contact retained hosts"),
            workspace_root=tmp_path / "bad-scratch", host_policies=policies,
            proxy_egress_ip="8.8.8.8", only_edge_name="middle-01",
        )


@pytest.mark.parametrize("mismatch", ["proxy_egress", "middle_source"])
def test_v2_bootstrap_rejects_proxy_policy_identity_drift_before_workspace_or_ansible(
    monkeypatch, tmp_path: Path, mismatch: str,
):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", lambda *_args: pytest.fail("keys must not be staged"))
    policies = _fresh_v2_policy()
    egress = "9.9.9.9" if mismatch == "proxy_egress" else "8.8.8.8"
    if mismatch == "middle_source":
        policies["middle-01"]["sketch_firewall_v2_ssh_sources"] = ["9.9.9.9/32"]
    workspace = tmp_path / "workspace"
    with pytest.raises(SketchBootstrapApplyError, match="active core identity"):
        apply_sketch_bootstrap(
            "eng-test", _chain(), repository=_RepositoryWithPublicProxy(),
            runner=lambda *_args: pytest.fail("Ansible must not run"),
            workspace_root=workspace, host_policies=policies, proxy_egress_ip=egress,
        )
    assert not workspace.exists()


def test_v2_initial_enrollment_preserves_both_retained_known_hosts_files(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    sketch_file = tmp_path / "sketch-known-hosts"
    core_file = tmp_path / "core-known-hosts"
    sketch_text = "barragan-bootstrap-sketch-middle-01 ssh-ed25519 retained-key\n"
    core_text = "8.8.8.8 ssh-ed25519 pinned-key\n"
    if shutil.which("ssh-keygen"):
        host_key = tmp_path / "test-host-key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)], check=True)
        algorithm, public_key = host_key.with_suffix(".pub").read_text().split()[:2]
        core_text = f"8.8.8.8 {algorithm} {public_key}\n"
    sketch_file.write_text(sketch_text)
    core_file.write_text(core_text)
    sketch_file.chmod(0o644)
    core_file.chmod(0o644)
    calls = []
    workspace = tmp_path / "workspace"
    apply_sketch_bootstrap(
        "eng-test", _chain(), repository=_RepositoryWithPublicProxy(),
        runner=lambda command, _cwd, _env: (calls.append(command), subprocess.CompletedProcess(command, 0, "", ""))[1],
        workspace_root=workspace, host_policies=_fresh_v2_policy(), proxy_egress_ip="8.8.8.8",
        initial_sketch_known_hosts_path=sketch_file, pinned_core_known_hosts_path=core_file,
    )
    assert len(calls) == 4
    assert sketch_file.read_text() == sketch_text
    assert core_file.read_text() == core_text
    config = (workspace / "ansible/ssh_config").read_text()
    inventory = (workspace / "ansible/inventory.ini").read_text()
    user_inventory = (workspace / "ansible/user_inventory.ini").read_text()
    assert config.count(f"UserKnownHostsFile {core_file}") == 2
    assert config.count(f"UserKnownHostsFile {sketch_file}") == 4
    assert config.count("StrictHostKeyChecking yes") == 2
    assert config.count("StrictHostKeyChecking accept-new") == 4
    assert "HostKeyAlias barragan-bootstrap-homebase" not in config
    assert "HostName 10.0.2.10" in config
    assert "HostKeyAlias 8.8.8.8" in config
    assert config.count("HostKeyAlias barragan-bootstrap-sketch-middle-01") == 2
    assert config.count("HostKeyAlias barragan-bootstrap-sketch-edge-01") == 2
    assert "ProxyJump barragan-bootstrap-proxy,barragan-bootstrap-root-middle-01" in config
    assert "ProxyJump barragan-bootstrap-proxy,barragan-bootstrap-user-middle-01" in config
    for rendered in (inventory, user_inventory):
        assert f"UserKnownHostsFile={sketch_file}" in rendered
        assert "StrictHostKeyChecking=accept-new" in rendered
    if shutil.which("ssh"):
        proxy_config = subprocess.run(
            ["ssh", "-G", "-F", str(workspace / "ansible/ssh_config"), "barragan-bootstrap-proxy"],
            text=True, capture_output=True, check=True,
        ).stdout.lower()
        assert "hostname 10.0.2.10" in proxy_config
        assert "hostkeyalias 8.8.8.8" in proxy_config
        assert f"userknownhostsfile {core_file}".lower() in proxy_config
        assert "stricthostkeychecking true" in proxy_config
        for user in ("root", "user"):
            edge_config = subprocess.run(
                ["ssh", "-G", "-F", str(workspace / "ansible/ssh_config"),
                 f"barragan-bootstrap-{user}-edge-01"],
                text=True, capture_output=True, check=True,
            ).stdout.lower()
            assert "hostkeyalias barragan-bootstrap-sketch-edge-01" in edge_config
            assert f"userknownhostsfile {sketch_file}".lower() in edge_config
            assert "stricthostkeychecking accept-new" in edge_config
    if shutil.which("ssh-keygen"):
        lookup = subprocess.run(
            ["ssh-keygen", "-F", "8.8.8.8", "-f", str(core_file)],
            text=True, capture_output=True,
        )
        assert lookup.returncode == 0 and "8.8.8.8" in lookup.stdout


def test_v2_bootstrap_normalizes_sgid_and_umask_0002_before_host_contact(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    collaborator_root = tmp_path / "collaborator"
    collaborator_root.mkdir()
    collaborator_root.chmod(0o2750)
    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook",
                        lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    scratch = collaborator_root / "scratch"
    commands = []

    def runner(command, cwd, _env):
        assert cwd == scratch and scratch.stat().st_mode & 0o7777 == 0o700
        for directory, directories, files in os.walk(scratch, followlinks=False):
            for name in (*directories, *files):
                mode = (Path(directory) / name).lstat().st_mode
                assert stat.S_ISDIR(mode) or stat.S_ISREG(mode)
                assert not mode & 0o022
                if stat.S_ISDIR(mode):
                    assert mode & 0o500 == 0o500
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    old_umask = os.umask(0o002)
    try:
        apply_sketch_bootstrap(
            "eng-test", _chain(), repository=_RepositoryWithPublicProxy(), runner=runner,
            workspace_root=scratch, host_policies=_fresh_v2_policy(), proxy_egress_ip="8.8.8.8",
        )
    finally:
        os.umask(old_umask)
    assert len(commands) == 4
    assert scratch.stat().st_mode & 0o7777 == 0o700


def test_v2_bootstrap_disables_multiplexing_in_effective_env_and_every_hop(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    original_mkdtemp = subject.tempfile.mkdtemp
    def no_control_path_directory(*args, **kwargs):
        assert kwargs.get("prefix") != "bcp-"
        return original_mkdtemp(*args, **kwargs)
    monkeypatch.setattr(subject.tempfile, "mkdtemp", no_control_path_directory)
    calls = []
    workspace = tmp_path / "workspace"
    def runner(command, _cwd, command_env):
        calls.append(dict(command_env))
        return subprocess.CompletedProcess(command, 0, "", "")
    apply_sketch_bootstrap(
        "eng-test", _chain(), repository=_RepositoryWithPublicProxy(), runner=runner,
        workspace_root=workspace, host_policies=_fresh_v2_policy(), proxy_egress_ip="8.8.8.8",
        env={
            "ANSIBLE_SSH_ARGS": "-C -o ControlMaster=auto -o ControlPersist=60s",
            "ANSIBLE_SSH_CONTROL_PATH": "/tmp/legacy-socket",
            "ANSIBLE_SSH_CONTROL_PATH_DIR": "/tmp/legacy-dir",
        },
    )
    assert len(calls) == 4
    for command_env in calls:
        assert command_env["ANSIBLE_SSH_ARGS"] == "-C -o ControlMaster=no -o ControlPersist=no"
        assert all(command_env[name] == "" for name in (
            "ANSIBLE_SSH_COMMON_ARGS", "ANSIBLE_SSH_EXTRA_ARGS",
            "ANSIBLE_SFTP_EXTRA_ARGS", "ANSIBLE_SCP_EXTRA_ARGS"))
        assert "ANSIBLE_SSH_CONTROL_PATH" not in command_env
        assert "ANSIBLE_SSH_CONTROL_PATH_DIR" not in command_env
    config_path = workspace / "ansible/ssh_config"
    config = config_path.read_text()
    for inventory_name in ("inventory.ini", "user_inventory.ini"):
        inventory = (workspace / "ansible" / inventory_name).read_text().lower()
        assert "ansible_ssh_executable" not in inventory
        assert "ansible_sftp_executable" not in inventory
        assert "ansible_scp_executable" not in inventory
    assert config.count("  ControlMaster no") == 6
    assert config.count("  ControlPersist no") == 6
    if shutil.which("ssh"):
        for alias in ("barragan-bootstrap-homebase", "barragan-bootstrap-proxy",
                      "barragan-bootstrap-root-middle-01", "barragan-bootstrap-user-middle-01",
                      "barragan-bootstrap-root-edge-01", "barragan-bootstrap-user-edge-01"):
            effective = subprocess.run(["ssh", "-G", "-F", str(config_path), alias],
                                       capture_output=True, text=True, check=True).stdout.lower()
            assert "controlmaster false" in effective or "controlmaster no" in effective
            assert "controlpersist no" in effective


@pytest.mark.parametrize(("variable", "value"), [
    ("ANSIBLE_SSH_ARGS", "-C -o ControlMaster=yes"),
    ("ANSIBLE_SSH_ARGS", "-F /tmp/unsafe-config"),
    ("ANSIBLE_SSH_COMMON_ARGS", "-o ControlPath=/tmp/socket"),
    ("ANSIBLE_SSH_EXTRA_ARGS", "-oControlMaster=yes"),
    ("ANSIBLE_SFTP_EXTRA_ARGS", "-o ControlPersist=60s"),
    ("ANSIBLE_SCP_EXTRA_ARGS", "-S /tmp/socket"),
    ("ANSIBLE_SSH_COMMON_ARGS", "-o ProxyJump=unexpected"),
    ("ANSIBLE_SSH_EXTRA_ARGS", "-o ProxyCommand=nc attacker 22"),
    ("ANSIBLE_SFTP_EXTRA_ARGS", "-o StrictHostKeyChecking=no"),
])
def test_v2_competing_ssh_arguments_fail_before_ansible(monkeypatch, tmp_path: Path,
                                                          variable: str, value: str):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    with pytest.raises(SketchBootstrapApplyError, match="SSH.*(?:unsafe|competing)|competing SSH"):
        apply_sketch_bootstrap(
            "eng-test", _chain(), repository=_RepositoryWithPublicProxy(),
            runner=lambda *_args: pytest.fail("unsafe v2 arguments reached Ansible"),
            workspace_root=tmp_path / "workspace", host_policies=_fresh_v2_policy(),
            proxy_egress_ip="8.8.8.8", env={variable: value},
        )


@pytest.mark.parametrize(("variable", "value"), [
    ("ANSIBLE_CONFIG", "/tmp/unsafe-ansible.cfg"),
    ("ANSIBLE_SSH_EXECUTABLE", "/tmp/ssh-wrapper"),
    ("ANSIBLE_SFTP_EXECUTABLE", "/tmp/sftp-wrapper"),
    ("ANSIBLE_SCP_EXECUTABLE", "/tmp/scp-wrapper"),
    ("ANSIBLE_TRANSPORT", "paramiko"),
    ("ANSIBLE_CONNECTION_PLUGINS", "/tmp/connection-plugins"),
])
def test_v2_connection_plugin_and_executable_overrides_are_rejected_before_command(
    monkeypatch, tmp_path: Path, variable: str, value: str,
):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    with pytest.raises(SketchBootstrapApplyError, match=variable):
        apply_sketch_bootstrap(
            "eng-test", _chain(), repository=_RepositoryWithPublicProxy(),
            runner=lambda *_args: pytest.fail("connection override reached command"),
            workspace_root=tmp_path / "workspace", host_policies=_fresh_v2_policy(),
            proxy_egress_ip="8.8.8.8", env={variable: value},
        )


@pytest.mark.parametrize("unsafe", [
    "missing_sketch", "missing_core", "symlink_sketch", "symlink_core",
    "group_writable_sketch", "group_writable_core", "read_only_sketch",
    "directory_sketch", "same_file", "strict_conflict", "legacy_mode",
])
def test_v2_enrollment_rejects_unsafe_known_hosts_before_any_command(tmp_path: Path, unsafe: str):
    sketch_file = tmp_path / "sketch-known-hosts"
    core_file = tmp_path / "core-known-hosts"
    sketch_file.write_text("")
    core_file.write_text("barragan-bootstrap-homebase ssh-ed25519 pinned-key\n")
    sketch_file.chmod(0o600)
    core_file.chmod(0o644)
    if unsafe == "missing_sketch":
        sketch_file.unlink()
    elif unsafe == "missing_core":
        core_file.unlink()
    elif unsafe == "symlink_sketch":
        sketch_file.unlink()
        sketch_file.symlink_to(core_file)
    elif unsafe == "symlink_core":
        core_file.unlink()
        core_file.symlink_to(sketch_file)
    elif unsafe == "group_writable_sketch":
        sketch_file.chmod(0o620)
    elif unsafe == "group_writable_core":
        core_file.chmod(0o664)
    elif unsafe == "read_only_sketch":
        sketch_file.chmod(0o400)
    elif unsafe == "directory_sketch":
        sketch_file.unlink()
        sketch_file.mkdir()
    elif unsafe == "same_file":
        core_file = sketch_file
    kwargs = {
        "host_policies": _fresh_v2_policy(), "proxy_egress_ip": "8.8.8.8",
        "initial_sketch_known_hosts_path": sketch_file,
        "pinned_core_known_hosts_path": core_file,
    }
    if unsafe == "strict_conflict":
        kwargs["strict_known_hosts_path"] = core_file
    if unsafe == "legacy_mode":
        kwargs["host_policies"] = None
    workspace = tmp_path / "workspace"
    with pytest.raises(SketchBootstrapApplyError):
        apply_sketch_bootstrap(
            "eng-test", _chain(), repository=_Repository(),
            runner=lambda *_args: pytest.fail("Ansible must not run"),
            workspace_root=workspace, **kwargs,
        )
    assert not workspace.exists()


def test_v2_root_playbook_failure_never_retries_after_readiness(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    commands = []
    def runner(command, _cwd, _env):
        commands.append(command)
        if any(part.endswith("upstream-sketch-playbook.compat.yml") for part in command):
            return subprocess.CompletedProcess(command, 2, "", "unreachable: connection refused")
        return subprocess.CompletedProcess(command, 0, "", "")

    with pytest.raises(SketchBootstrapApplyError, match="upstream sketch bootstrap failed"):
        apply_sketch_bootstrap(
            "eng-test", _chain(), repository=_RepositoryWithPublicProxy(), runner=runner,
            workspace_root=tmp_path / "workspace", host_policies=_fresh_v2_policy(),
            proxy_egress_ip="8.8.8.8", wait=lambda _seconds: pytest.fail("v2 root play must not retry"),
        )
    assert len(commands) == 2
    assert sum(any(part.endswith("upstream-sketch-playbook.compat.yml") for part in command)
               for command in commands) == 1


def test_copies_only_required_upstream_playbook_syntax_compatibility(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    upstream = _upstream(tmp_path)
    compatible = subject._write_upstream_playbook_compatibility(
        upstream.path("external", "sketch", "ansible", "sketch-playbook.yml"), tmp_path / "workspace"
    )

    rendered = compatible.read_text(encoding="utf-8")
    original = upstream.path("external", "sketch", "ansible", "sketch-playbook.yml").read_text(encoding="utf-8")
    assert "lookup('file', ssh_pub_key)" in rendered
    assert "ansible.builtin.file:" in rendered
    assert "delegate_to: localhost" in rendered
    assert "local_action:" not in rendered
    assert "name: \"{{ 'ssh' if ansible_os_family == 'Debian' else 'sshd' }}\"" in rendered
    assert "register: sketch_apt_update_upgrade" in rendered
    assert "until: sketch_apt_update_upgrade is succeeded" in rendered
    assert "register: sketch_apt_required_packages" in rendered
    assert "until: sketch_apt_required_packages is succeeded" in rendered
    assert rendered.count("retries: 20") == 2
    assert rendered.count("delay: 30") == 2
    assert "Wait for serial sketch management readiness" not in rendered
    assert "lookup('file', '{{ ssh_pub_key }}')" in original
    assert "name: sshd" in original


def test_playbook_compatibility_preserves_canonical_retried_apt_tasks(tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    upstream = _upstream(tmp_path)
    source = upstream.path("external", "sketch", "ansible", "sketch-playbook.yml")
    legacy = source.read_text(encoding="utf-8")
    fixed = subject._normalize_upstream_apt_tasks(legacy)
    source.write_text(fixed, encoding="utf-8")

    compatible = subject._write_upstream_playbook_compatibility(source, tmp_path / "workspace")
    rendered = compatible.read_text(encoding="utf-8")

    assert subject._normalize_upstream_apt_tasks(fixed) == fixed
    assert rendered.count("register: sketch_apt_update_upgrade") == 1
    assert rendered.count("register: sketch_apt_required_packages") == 1
    assert rendered.count("retries: 20") == 2


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "partial", "drift"])
def test_playbook_compatibility_rejects_apt_task_drift_before_keys_or_runner(
    monkeypatch, tmp_path: Path, mutation: str
):
    from app.services import sketch_bootstrap_apply as subject

    upstream = _upstream(tmp_path)
    source = upstream.path("external", "sketch", "ansible", "sketch-playbook.yml")
    content = source.read_text(encoding="utf-8")
    if mutation == "missing":
        content = content.replace("Update apt and upgrade", "Upgrade packages")
    elif mutation == "duplicate":
        task = subject._LEGACY_APT_UPDATE_TASK
        content = content.replace(task, f"{task}\n\n{task}")
    elif mutation == "partial":
        content = content.replace("        upgrade: dist", "        upgrade: dist\n      retries: 20")
    else:
        content = content.replace("        upgrade: dist", "        upgrade: full")
    source.write_text(content, encoding="utf-8")
    materialized = []
    invoked = []
    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: upstream)
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", lambda *_args: materialized.append(True))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", lambda *_args: materialized.append(True))

    with pytest.raises(SketchBootstrapApplyError, match="apt compatibility forms were not found exactly once"):
        subject.apply_sketch_bootstrap(
            "eng-test",
            _chain(),
            repository=_Repository(),
            runner=lambda *_args: invoked.append(True),
            workspace_root=tmp_path / "workspace",
        )

    assert materialized == []
    assert invoked == []


def test_copies_only_required_upstream_role_provider_compatibility(tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    upstream = _upstream(tmp_path)
    source_roles = upstream.path("external", "sketch", "ansible", "roles")
    compatible_roles = subject._write_upstream_role_compatibility(source_roles, tmp_path / "workspace")

    rendered = (compatible_roles / "disable-ipv6/tasks/main.yml").read_text(encoding="utf-8")
    original = (source_roles / "disable-ipv6/tasks/main.yml").read_text(encoding="utf-8")
    assert "status_code: [400, 404]" in rendered
    assert "status_code: 400" in original
    assert rendered != original


@pytest.mark.parametrize("mutation", ["missing", "duplicate"])
def test_role_compatibility_fails_closed_on_upstream_metadata_drift(tmp_path: Path, mutation: str):
    from app.services import sketch_bootstrap_apply as subject

    upstream = _upstream(tmp_path)
    source_roles = upstream.path("external", "sketch", "ansible", "roles")
    tasks = source_roles / "disable-ipv6/tasks/main.yml"
    content = tasks.read_text(encoding="utf-8")
    if mutation == "missing":
        content = content.replace("/v1/instance", "/v2/instance")
    else:
        content = f"{content}\n{content}"
    tasks.write_text(content, encoding="utf-8")

    with pytest.raises(SketchBootstrapApplyError, match="metadata compatibility form was not found exactly once"):
        subject._write_upstream_role_compatibility(source_roles, tmp_path / "workspace")


def test_root_failure_does_not_attempt_transport_and_still_scrubs_keys(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    calls = []
    control_path_dirs = []

    def runner(command, cwd, env):
        calls.append(command)
        control_path_dirs.append(Path(env["ANSIBLE_SSH_CONTROL_PATH_DIR"]))
        return subprocess.CompletedProcess(command, 1, "", "failure")

    workspace = tmp_path / "workspace"
    with pytest.raises(SketchBootstrapApplyError, match="sketch root management readiness failed"):
        apply_sketch_bootstrap("eng-test", _chain(), repository=_Repository(), runner=runner, workspace_root=workspace)

    assert len(calls) == 1
    assert len(control_path_dirs) == 1
    assert not control_path_dirs[0].exists()
    assert not (workspace / "keys").exists()


def test_transient_apt_lock_retries_resolved_by_ansible_complete_bootstrap(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    calls = []

    def runner(command, _cwd, _env):
        calls.append(command)
        stdout = ""
        if any(part.endswith("upstream-sketch-playbook.compat.yml") for part in command):
            stdout = "FAILED - RETRYING: [middle]: Update apt and upgrade (19 retries left)\nchanged: [middle]"
        return subprocess.CompletedProcess(command, 0, stdout, "")

    result = subject.apply_sketch_bootstrap(
        "eng-test", _chain(), repository=_Repository(), runner=runner, workspace_root=tmp_path / "workspace"
    )

    assert result.root_returncode == 0
    assert result.transport_returncode == 0
    assert len(calls) == 4


def test_exhausted_apt_lock_retry_reports_task_evidence_and_skips_transport(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    calls = []

    def runner(command, _cwd, _env):
        calls.append(command)
        if any(part.endswith("upstream-sketch-playbook.compat.yml") for part in command):
            return subprocess.CompletedProcess(
                command,
                2,
                "TASK [Update apt and upgrade]\n"
                'fatal: [middle]: FAILED! => {"msg": "Could not get lock /var/lib/dpkg/lock-frontend"}\n'
                "PLAY RECAP\nmiddle : ok=3 failed=1",
                "",
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    with pytest.raises(SketchBootstrapApplyError) as exc:
        subject.apply_sketch_bootstrap(
            "eng-test", _chain(), repository=_Repository(), runner=runner, workspace_root=tmp_path / "workspace"
        )

    assert "TASK [Update apt and upgrade]" in str(exc.value)
    assert "/var/lib/dpkg/lock-frontend" in str(exc.value)
    assert len(calls) == 2


def test_readiness_retries_transient_ssh_unreachable_before_upstream_mutation(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    calls = []

    def runner(command, _cwd, _env):
        calls.append(command)
        if len(calls) == 1:
            return subprocess.CompletedProcess(
                command,
                4,
                'fatal: [middle]: UNREACHABLE! => {"msg": "Failed to connect to the host via ssh: Connection refused"}',
                "",
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = subject.apply_sketch_bootstrap(
        "eng-test", _chain(), repository=_Repository(), runner=runner, workspace_root=tmp_path / "workspace", wait=lambda _seconds: None
    )

    assert result.root_returncode == 0
    assert len(calls) == 5  # retry gate succeeds, then root, user readiness, and transport each run once
    assert calls[0][-1] == "ansible/wait_for_sketch_readiness.yml"
    assert calls[1][-1] == "ansible/wait_for_sketch_readiness.yml"
    assert calls[2][5].endswith("ansible/upstream-sketch-playbook.compat.yml")


def test_readiness_retries_connection_task_failure(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    calls = []

    def runner(command, _cwd, _env):
        calls.append(command)
        if len(calls) == 1:
            return subprocess.CompletedProcess(
                command,
                2,
                "TASK [Wait for the approved sketch SSH hop path]\\n"
                "fatal: [edge]: UNREACHABLE! => {\\\"msg\\\": \\\"Failed to connect to the host via ssh: Connection timed out\\\"}",
                "",
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = subject.apply_sketch_bootstrap(
        "eng-test", _chain(), repository=_Repository(), runner=runner, workspace_root=tmp_path / "workspace", wait=lambda _seconds: None
    )

    assert result.root_returncode == 0
    assert len(calls) == 5  # readiness retry succeeds, then root, user readiness, and transport run once


def test_transport_key_install_rechecks_readiness_before_retry(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    calls = []

    def runner(command, _cwd, _env):
        calls.append(command)
        if len(calls) == 4:
            return subprocess.CompletedProcess(
                command,
                4,
                'fatal: [edge]: UNREACHABLE! => {"msg": "Failed to connect to the host via ssh: Connection reset by peer"}',
                "",
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = subject.apply_sketch_bootstrap(
        "eng-test", _chain(), repository=_Repository(), runner=runner, workspace_root=tmp_path / "workspace", wait=lambda _seconds: None
    )

    assert result.transport_returncode == 0
    assert len(calls) == 6
    assert calls[3][-1] == "ansible/install_sketch_transport.yml"
    assert calls[4][-1] == "ansible/wait_for_sketch_user_readiness.yml"
    assert calls[5][-1] == "ansible/install_sketch_transport.yml"


def test_v2_transport_reconnect_failure_does_not_repeat_ssh_restart(tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    calls = []
    commands = [[name] for name in ("root-ready", "root-play", "user-ready", "transport")]

    def runner(command, _cwd, _env):
        calls.append(command[0])
        if command[0] == "transport":
            return subprocess.CompletedProcess(
                command, 4,
                'fatal: [edge]: UNREACHABLE! => {"msg": "Connection reset by peer"}',
                "",
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    _, _, transport = subject._run_bootstrap_phases_with_readiness(
        runner, *commands, tmp_path, {}, reporter=None,
        wait=lambda _seconds: pytest.fail("v2 transport must not be retried"),
        monotonic=lambda: 0.0, retry_root_playbook=False,
        retry_transport_playbook=False,
    )
    assert transport.returncode == 4
    assert calls == ["root-ready", "root-play", "user-ready", "transport"]


def test_post_root_public_key_denial_is_terminal_without_unchanged_retries(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    calls = []
    waits = []
    progress = []

    def runner(command, _cwd, _env):
        calls.append(command)
        if command[-1] == "ansible/wait_for_sketch_user_readiness.yml":
            return subprocess.CompletedProcess(
                command,
                4,
                'fatal: [edge-01]: UNREACHABLE! => {"msg": "user@edge: Permission denied (publickey)."}',
                "",
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    with pytest.raises(SketchBootstrapApplyError, match="post-root sketch user readiness failed") as exc:
        subject.apply_sketch_bootstrap(
            "eng-test",
            _chain(),
            repository=_Repository(),
            runner=runner,
            workspace_root=tmp_path / "workspace",
            progress_reporter=lambda status, data: progress.append((status, data)),
            wait=waits.append,
        )

    assert "Permission denied (publickey)" in str(exc.value)
    assert [command[-1] for command in calls] == [
        "ansible/wait_for_sketch_readiness.yml",
        "@ansible/upstream-bootstrap-vars.yml",
        "ansible/wait_for_sketch_user_readiness.yml",
    ]
    assert waits == []
    assert any(
        status == "completed" and data["phase"] == "upstream-root-bootstrap"
        for status, data in progress
    )
    assert any(
        status == "failed"
        and data["phase"] == "post-root-user-readiness"
        and data["failureClass"] == "authentication"
        and data["identityBoundary"] == "user-admin"
        for status, data in progress
    )


def test_partial_multi_edge_user_failure_stops_before_transport(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    chain = SimpleNamespace(
        assigned_proxy="proxy01",
        nodes=[
            {"role": "middle", "hostname": "middle-01", "publicIp": "198.51.100.10"},
            {"role": "edge", "hostname": "edge-01", "publicIp": "203.0.113.10"},
            {"role": "edge", "hostname": "edge-02", "publicIp": "203.0.113.11"},
        ],
    )
    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    calls = []

    def runner(command, _cwd, _env):
        calls.append(command)
        if command[-1] == "ansible/wait_for_sketch_user_readiness.yml":
            return subprocess.CompletedProcess(
                command,
                4,
                'ok: [edge-01]\nfatal: [edge-02]: UNREACHABLE! => {"msg": "Permission denied (publickey,password)."}',
                "",
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    with pytest.raises(SketchBootstrapApplyError, match="post-root sketch user readiness failed") as exc:
        subject.apply_sketch_bootstrap(
            "eng-test",
            chain,
            repository=_Repository(),
            runner=runner,
            workspace_root=tmp_path / "workspace",
            wait=lambda _seconds: pytest.fail("authentication failure must not wait"),
        )

    assert "edge-02" in str(exc.value)
    assert all(command[-1] != "ansible/install_sketch_transport.yml" for command in calls)


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ('fatal: [edge]: UNREACHABLE! => {"msg": "Permission denied (publickey)."}', "authentication"),
        ('fatal: [edge]: UNREACHABLE! => {"msg": "Permission denied (password)."}', "authentication"),
        ('fatal: [edge]: UNREACHABLE! => {"msg": "Permission denied (keyboard-interactive)."}', "authentication"),
        ('fatal: [edge]: UNREACHABLE! => {"msg": "Too many authentication failures"}', "authentication"),
        ('fatal: [edge]: UNREACHABLE! => {"msg": "Connection refused"}', "settling"),
        ('fatal: [edge]: UNREACHABLE! => {"msg": "Connection timed out"}', "settling"),
        ('fatal: [edge]: UNREACHABLE! => {"msg": "Host key verification failed"}', "terminal"),
        ('fatal: [edge]: UNREACHABLE! => {"msg": "unknown ssh failure"}', "terminal"),
    ],
)
def test_ssh_failure_classifier_is_auth_first_and_unknown_terminal(output: str, expected: str):
    from app.services.sketch_bootstrap_apply import _classify_ssh_failure

    assert _classify_ssh_failure(subprocess.CompletedProcess(["ansible-playbook"], 4, output, "")) == expected


def test_transient_post_root_user_readiness_retries_without_reapplying_root(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    calls = []

    def runner(command, _cwd, _env):
        calls.append(command)
        if command[-1] == "ansible/wait_for_sketch_user_readiness.yml" and sum(
            call[-1] == "ansible/wait_for_sketch_user_readiness.yml" for call in calls
        ) == 1:
            return subprocess.CompletedProcess(
                command,
                4,
                'fatal: [edge-01]: UNREACHABLE! => {"msg": "kex_exchange_identification: Connection closed by remote host"}',
                "",
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = subject.apply_sketch_bootstrap(
        "eng-test",
        _chain(),
        repository=_Repository(),
        runner=runner,
        workspace_root=tmp_path / "workspace",
        wait=lambda _seconds: None,
    )

    assert result.user_readiness_returncode == 0
    assert sum(any(part.endswith("upstream-sketch-playbook.compat.yml") for part in call) for call in calls) == 1
    assert [call[-1] for call in calls].count("ansible/wait_for_sketch_user_readiness.yml") == 2
    assert calls[-1][-1] == "ansible/install_sketch_transport.yml"


def test_late_root_success_does_not_consume_user_readiness_retry_budget(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    root_readiness_calls = 0
    user_readiness_calls = 0
    calls = []

    def runner(command, _cwd, _env):
        nonlocal root_readiness_calls, user_readiness_calls
        calls.append(command)
        if command[-1] == "ansible/wait_for_sketch_readiness.yml":
            root_readiness_calls += 1
            if root_readiness_calls < 8:
                return subprocess.CompletedProcess(
                    command,
                    4,
                    'fatal: [middle-01]: UNREACHABLE! => {"msg": "Connection refused"}',
                    "",
                )
        if command[-1] == "ansible/wait_for_sketch_user_readiness.yml":
            user_readiness_calls += 1
            if user_readiness_calls == 1:
                return subprocess.CompletedProcess(
                    command,
                    4,
                    'fatal: [edge-01]: UNREACHABLE! => {"msg": "Connection closed by remote host"}',
                    "",
                )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = subject.apply_sketch_bootstrap(
        "eng-test",
        _chain(),
        repository=_Repository(),
        runner=runner,
        workspace_root=tmp_path / "workspace",
        wait=lambda _seconds: None,
    )

    assert result.transport_returncode == 0
    assert root_readiness_calls == 8
    assert user_readiness_calls == 2
    assert sum(any(part.endswith("upstream-sketch-playbook.compat.yml") for part in call) for call in calls) == 1


def test_late_user_success_does_not_consume_transport_retry_budget(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    user_readiness_calls = 0
    transport_calls = 0

    def runner(command, _cwd, _env):
        nonlocal user_readiness_calls, transport_calls
        if command[-1] == "ansible/wait_for_sketch_user_readiness.yml":
            user_readiness_calls += 1
            if user_readiness_calls < 8:
                return subprocess.CompletedProcess(
                    command,
                    4,
                    'fatal: [edge-01]: UNREACHABLE! => {"msg": "Connection refused"}',
                    "",
                )
        if command[-1] == "ansible/install_sketch_transport.yml":
            transport_calls += 1
            if transport_calls == 1:
                return subprocess.CompletedProcess(
                    command,
                    4,
                    'fatal: [edge-01]: UNREACHABLE! => {"msg": "Connection reset by peer"}',
                    "",
                )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = subject.apply_sketch_bootstrap(
        "eng-test",
        _chain(),
        repository=_Repository(),
        runner=runner,
        workspace_root=tmp_path / "workspace",
        wait=lambda _seconds: None,
    )

    assert result.transport_returncode == 0
    assert user_readiness_calls == 9  # eight initial checks plus the required transport retry recheck
    assert transport_calls == 2


def test_explicit_second_bootstrap_invocation_reruns_root_before_user_and_transport(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    invocation = 1
    calls = []

    def runner(command, _cwd, _env):
        calls.append((invocation, command))
        if invocation == 1 and command[-1] == "ansible/wait_for_sketch_user_readiness.yml":
            return subprocess.CompletedProcess(
                command,
                4,
                'fatal: [edge-01]: UNREACHABLE! => {"msg": "Permission denied (publickey)."}',
                "",
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    with pytest.raises(SketchBootstrapApplyError, match="post-root sketch user readiness failed"):
        subject.apply_sketch_bootstrap(
            "eng-test",
            _chain(),
            repository=_Repository(),
            runner=runner,
            workspace_root=tmp_path / "workspace-1",
            wait=lambda _seconds: None,
        )
    invocation = 2
    result = subject.apply_sketch_bootstrap(
        "eng-test",
        _chain(),
        repository=_Repository(),
        runner=runner,
        workspace_root=tmp_path / "workspace-2",
        wait=lambda _seconds: None,
    )

    assert result.transport_returncode == 0
    for number in (1, 2):
        invocation_calls = [command for call_invocation, command in calls if call_invocation == number]
        assert sum(any(part.endswith("upstream-sketch-playbook.compat.yml") for part in command) for command in invocation_calls) == 1
    assert calls[-1][1][-1] == "ansible/install_sketch_transport.yml"


@pytest.mark.parametrize(
    ("middle_provider", "edge_provider"),
    [("linode", "linode"), ("digitalocean", "digitalocean"), ("linode", "digitalocean")],
)
def test_provider_pairs_preserve_user_admin_and_transport_identity_roles(
    monkeypatch, tmp_path: Path, middle_provider: str, edge_provider: str
):
    from app.services import sketch_bootstrap_apply as subject

    chain = SimpleNamespace(
        assigned_proxy="proxy01",
        nodes=[
            {"role": "middle", "provider": middle_provider, "hostname": "middle-01", "publicIp": "198.51.100.10"},
            {"role": "edge", "provider": edge_provider, "hostname": "edge-01", "publicIp": "203.0.113.10"},
        ],
    )
    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))
    workspace = tmp_path / f"workspace-{middle_provider}-{edge_provider}"

    result = subject.apply_sketch_bootstrap(
        "eng-test",
        chain,
        repository=_Repository(),
        runner=lambda command, _cwd, _env: subprocess.CompletedProcess(command, 0, "", ""),
        workspace_root=workspace,
    )

    assert result.node_count == 2
    assert "ansible_user=root" in (workspace / "ansible/inventory.ini").read_text(encoding="utf-8")
    assert "ansible_user=user" in (workspace / "ansible/user_inventory.ini").read_text(encoding="utf-8")
    transport = (workspace / "ansible/install_sketch_transport.yml").read_text(encoding="utf-8")
    assert "remote_user: user" in transport
    assert "owner: sketchssh" in transport


def test_failure_includes_bounded_redacted_ansible_diagnostic(monkeypatch, tmp_path: Path):
    from app.services import sketch_bootstrap_apply as subject

    monkeypatch.setattr(subject, "resolve_redteam_infra_template_source", lambda **_kwargs: _upstream(tmp_path))
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "write_existing_sketch_ssh_key_files", _materializer("admin"))
    monkeypatch.setattr(subject, "write_existing_sketch_transport_ssh_key_files", _materializer("transport"))

    def runner(command, cwd, env):
        if command[-1] == "ansible/wait_for_sketch_readiness.yml":
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(
            command,
            2,
            "",
            "fatal: unreachable token=token-sensitive password=password-sensitive "
            "Authorization: Bearer bearer-sensitive\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret-key-body\n-----END OPENSSH PRIVATE KEY-----\n"
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPublicSensitive operator@test",
        )

    with pytest.raises(SketchBootstrapApplyError) as exc:
        subject.apply_sketch_bootstrap("eng-test", _chain(), repository=_Repository(), runner=runner, workspace_root=tmp_path / "workspace")

    assert "upstream sketch bootstrap failed (exit 2)" in str(exc.value)
    assert "fatal: unreachable" in str(exc.value)
    assert "PRIVATE KEY" not in str(exc.value)
    assert "secret-key-body" not in str(exc.value)
    assert "token-sensitive" not in str(exc.value)
    assert "password-sensitive" not in str(exc.value)
    assert "bearer-sensitive" not in str(exc.value)
    assert "AAAAC3NzaC1lZDI1NTE5AAAAIPublicSensitive" not in str(exc.value)


@pytest.mark.parametrize(
    "unsafe",
    [
        "token=token-sensitive",
        "password=password-sensitive",
        "Authorization: Bearer bearer-sensitive",
        "-----BEGIN OPENSSH PRIVATE KEY----- private-sensitive -----END OPENSSH PRIVATE KEY-----",
        "-----BEGIN PUBLIC KEY----- public-pem-sensitive -----END PUBLIC KEY-----",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPublicSensitive operator@test",
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABPublicSensitive operator@test",
        "ssh-ed25519-cert-v01@openssh.com AAAAC3NzaCertPublicSensitive operator@test",
        "ssh-rsa-cert-v01@openssh.com AAAAB3NzaCertPublicSensitive operator@test",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAE2VjZHNhCertPublicSensitive operator@test",
        "sk-ecdsa-sha2-nistp256@openssh.com-cert-v01@openssh.com AAAAC3NrCertPublicSensitive operator@test",
        "sk-ssh-ed25519@openssh.com-cert-v01@openssh.com AAAAC3NrEdCertPublicSensitive operator@test",
    ],
)
def test_command_failure_uses_broad_safe_redaction_for_external_diagnostics(unsafe: str):
    from app.services.sketch_bootstrap_apply import _command_failure

    detail = _command_failure(
        "post-root sketch user readiness",
        subprocess.CompletedProcess(
            ["ansible-playbook", "ansible/wait_for_sketch_user_readiness.yml"],
            4,
            f'TASK [Verify identity]\nfatal: [edge-01]: UNREACHABLE! => {{"msg": "{unsafe}"}}',
            "",
        ),
    )

    assert "Sensitive" not in detail
    assert "sensitive" not in detail
    assert "operator@test" not in detail


def test_failure_prefers_late_stdout_task_error_over_stderr_warning():
    from app.services.sketch_bootstrap_apply import _command_failure

    result = subprocess.CompletedProcess(
        ["ansible-playbook"],
        4,
        "fatal: [edge]: FAILED! => {\"msg\": \"real task failure\"}",
        "[WARNING]: irrelevant deprecation warning",
    )

    detail = _command_failure("upstream sketch bootstrap", result)

    assert "real task failure" in detail
    assert "irrelevant deprecation warning" in detail


def test_failure_preserves_task_heading_when_recap_would_hide_it():
    from app.services.sketch_bootstrap_apply import _command_failure

    result = subprocess.CompletedProcess(
        ["ansible-playbook"],
        2,
        "\n".join(
            (
                "TASK [Open required ports] ****************************************",
                'fatal: [middle]: FAILED! => {"msg": "unsupported parameter"}',
                "PLAY RECAP ********************************************************",
                "middle : ok=16 changed=10 failed=1",
            )
        ),
        "[WARNING]: Python interpreter discovery warning",
    )

    detail = _command_failure("upstream sketch bootstrap", result)

    assert "TASK [Open required ports]" in detail
    assert "unsupported parameter" in detail
    assert "middle : ok=16 changed=10 failed=1" in detail


def test_failure_prioritizes_task_over_repeated_long_warnings():
    from app.services.sketch_bootstrap_apply import _command_failure

    warning = "[WARNING]: " + ("interpreter discovery " * 100)
    result = subprocess.CompletedProcess(
        ["ansible-playbook"],
        2,
        "TASK [Enable ufw]\nfatal: [middle]: FAILED! => important cause\nPLAY RECAP\nmiddle : failed=1",
        "\n".join((warning, warning, warning)),
    )

    detail = _command_failure("upstream sketch bootstrap", result)

    assert "TASK [Enable ufw]" in detail
    assert "important cause" in detail
    assert len(detail) < 1_350


def test_lifecycle_marks_provider_job_failed_when_bootstrap_fails(monkeypatch):
    from app.services import sketch_chains as subject

    job = _provider_job()
    chain = _stored_chain(job.id)
    jobs = _JobStore(job)
    monkeypatch.setattr(subject, "apply_sketch_bootstrap", lambda *_args, **_kwargs: (_ for _ in ()).throw(SketchBootstrapApplyError("no core")))

    subject._bootstrap_provider_job("eng-test", chain.chain_id, _ChainStore(chain), jobs)

    assert jobs.current.status == "failed"
    assert jobs.current.events[-1].data == {"bootstrap": "failed", "error": "no core"}


def test_lifecycle_records_bootstrap_before_allowing_deployed_state(monkeypatch):
    from app.services import sketch_chains as subject
    from app.services.sketch_bootstrap_apply import SketchBootstrapApplyResult

    job = _provider_job()
    chain = _stored_chain(job.id)
    jobs = _JobStore(job)
    monkeypatch.setattr(
        subject,
        "apply_sketch_bootstrap",
        lambda *_args, **_kwargs: SketchBootstrapApplyResult(0, 0, 2),
    )

    subject._bootstrap_provider_job("eng-test", chain.chain_id, _ChainStore(chain), jobs)

    assert jobs.current.status == "succeeded"
    assert jobs.current.events[-1].message == "upstream-compatible sketch bootstrap completed"
    assert jobs.current.events[-1].data["bootstrap"] == "succeeded"
    assert [phase["name"] for phase in jobs.current.events[-1].data["phases"]] == [
        "root-management-readiness",
        "upstream-root-bootstrap",
        "post-root-user-readiness",
        "transport-key-install",
    ]


def test_lifecycle_persists_operator_safe_readiness_progress(monkeypatch):
    from app.services import sketch_chains as subject
    from app.services.sketch_bootstrap_apply import SketchBootstrapApplyResult

    job = _provider_job()
    chain = _stored_chain(job.id)
    jobs = _JobStore(job)

    def bootstrap(*_args, progress_reporter, **_kwargs):
        progress_reporter(
            "waiting",
            {
                "bootstrap": "readiness",
                "status": "waiting",
                "phase": "root-management-readiness",
                "attempt": 1,
                "maxAttempts": 8,
                "elapsedSeconds": 45,
                "nextBackoffSeconds": 30,
                "privateKey": "must-not-survive",
            },
        )
        progress_reporter(
            "completed",
            {
                "bootstrap": "readiness",
                "status": "completed",
                "phase": "upstream-root-bootstrap",
                "attempt": 2,
                "maxAttempts": 8,
                "elapsedSeconds": 76,
                "nodeCount": 2,
                "nodeRefs": ["middle-01", "edge-01", "ssh-ed25519 AAAA-secret"],
                "credential": "must-not-survive",
            },
        )
        return SketchBootstrapApplyResult(0, 0, 2)

    monkeypatch.setattr(subject, "apply_sketch_bootstrap", bootstrap)
    subject._bootstrap_provider_job("eng-test", chain.chain_id, _ChainStore(chain), jobs)

    progress = jobs.current.events[-3]
    assert progress.message == "sketch root-management-readiness pending; retry scheduled"
    assert progress.data == {
        "bootstrap": "readiness",
        "status": "waiting",
        "phase": "root-management-readiness",
        "attempt": 1,
        "maxAttempts": 8,
        "elapsedSeconds": 45,
        "nextBackoffSeconds": 30,
    }
    root_complete = jobs.current.events[-2]
    assert root_complete.message == "upstream root bootstrap completed; verifying normal user identity"
    assert root_complete.data == {
        "bootstrap": "readiness",
        "status": "completed",
        "phase": "upstream-root-bootstrap",
        "attempt": 2,
        "maxAttempts": 8,
        "elapsedSeconds": 76,
        "nodeCount": 2,
        "nodeRefs": ["middle-01", "edge-01"],
    }
    assert jobs.current.events[-1].data["bootstrap"] == "succeeded"


@pytest.mark.parametrize(
    ("failure_class", "identity_boundary", "retry_exhausted"),
    [
        ("authentication", "user-admin", False),
        ("settling", "user-admin", True),
        ("terminal", "transport-runtime", False),
    ],
)
def test_lifecycle_persists_safe_failure_class_and_identity_boundary(
    failure_class: str, identity_boundary: str, retry_exhausted: bool
):
    from app.services import sketch_chains as subject

    jobs = _JobStore(replace(_provider_job(), status="running", finished_at=""))
    subject._record_bootstrap_readiness_progress(
        jobs,
        jobs.current.id,
        "failed",
        {
            "phase": "post-root-user-readiness" if identity_boundary == "user-admin" else "transport-key-install",
            "failureClass": failure_class,
            "identityBoundary": identity_boundary,
            "retryExhausted": retry_exhausted,
            "attempt": 1,
            "maxAttempts": 8,
            "nodeCount": 2,
            "nodeRefs": ["middle-01", "edge-01"],
            "secret": "must-not-survive",
        },
    )

    event = jobs.current.events[-1]
    assert event.level == "error"
    assert event.data["failureClass"] == failure_class
    assert event.data["identityBoundary"] == identity_boundary
    assert event.data["retryExhausted"] is retry_exhausted
    assert "secret" not in event.data


def test_provider_terminal_wait_does_not_race_async_terraform_completion():
    from app.services import sketch_chains as subject

    queued = replace(_provider_job(), status="running", finished_at="")
    jobs = _JobStore(queued)
    waits = []

    def wait(_seconds):
        waits.append(True)
        jobs.current = _provider_job()

    completed = subject._wait_for_provider_job_terminal(queued.id, jobs, wait=wait)

    assert completed is not None
    assert completed.status == "succeeded"
    assert waits == [True]


def test_lifecycle_recovery_resumes_unbootstrapped_provider_without_terraform(monkeypatch):
    from app.services import sketch_chains as subject
    from app.services.sketch_bootstrap_apply import SketchBootstrapApplyResult

    job = _provider_job()
    jobs = _JobStore(job)
    chains = _ChainStore(_stored_chain(job.id))
    monkeypatch.setattr(subject, "apply_sketch_bootstrap", lambda *_args, **_kwargs: SketchBootstrapApplyResult(0, 0, 2))
    started = []
    monkeypatch.setattr(subject, "start_runtime_task", lambda task, **kwargs: (started.append(kwargs["name"]), task()))

    resumed = subject.resume_pending_sketch_bootstrap(
        "eng-test",
        chains.chain.chain_id,
        repository=chains,
        job_repository=jobs,
        requested_by="operator",
    )

    assert resumed is True
    assert started == ["barragan-sketch-bootstrap-recovery-proxy01-sea-01"]
    assert jobs.current.status == "succeeded"
    assert jobs.current.events[-2].data["bootstrap"] == "starting"
    assert jobs.current.events[-2].data["terraformCompletedAt"] == "2026-08-22T00:01:00+00:00"
    assert jobs.current.events[-1].data["bootstrap"] == "succeeded"
    assert chains.chain.status == "deployed"


def test_refresh_keeps_fresh_provider_success_deploying_until_bootstrap_is_recorded(monkeypatch):
    from app.services import sketch_chains as subject

    job = _provider_job()
    jobs = _JobStore(job)
    chains = _ChainStore(_stored_chain(job.id))
    calls = []
    monkeypatch.setattr(subject, "_start_outbound_auto_configuration", lambda *_args, **_kwargs: calls.append(True))

    pending = subject.refresh_sketch_chain_from_job(
        "eng-test", chains.chain.chain_id, repository=chains, job_repository=jobs
    )

    assert pending["sketchChain"]["status"] == "deploying"
    assert calls == []

    jobs.current = replace(
        job,
        events=job.events + [JobEvent(2, "info", "bootstrap", {"bootstrap": "succeeded"})],
    )
    completed = subject.refresh_sketch_chain_from_job(
        "eng-test", chains.chain.chain_id, repository=chains, job_repository=jobs
    )

    assert completed["sketchChain"]["status"] == "deployed"
    assert calls == [True]


def test_failed_bootstrap_retry_reuses_retained_nodes_without_rerunning_terraform(monkeypatch):
    from app.services import sketch_chains as subject
    from app.services.sketch_bootstrap_apply import SketchBootstrapApplyResult

    job = _retained_failed_provider_job()
    retained_nodes = _retained_provider_nodes()
    retained_chain = replace(
        _stored_chain(job.id),
        status="failed",
        terraform_working_directory=job.input["terraformWorkingDirectory"],
        nodes=retained_nodes,
    )
    jobs = _JobStore(job)
    chains = _ChainStore(retained_chain)
    monkeypatch.setattr(subject, "SqlAlchemyJobRepository", lambda: jobs)
    monkeypatch.setattr(subject, "apply_sketch_bootstrap", lambda *_args, **_kwargs: SketchBootstrapApplyResult(0, 0, 2))
    started = []
    monkeypatch.setattr(subject, "start_runtime_task", lambda task, **_kwargs: (started.append(_kwargs["name"]), task()))
    _forbid_provider_deployment_adapters(monkeypatch, subject)

    result = subject.deploy_sketch_chain(
        "eng-test", retained_chain.chain_id, {"retryBootstrapOnly": True}, repository=chains
    )

    assert started == ["barragan-sketch-bootstrap-retry-proxy01-sea-01"]
    assert result["job"]["id"] == job.id
    assert jobs.current.status == "succeeded"
    assert jobs.current.events[-2].data == {"bootstrap": "retrying", "retry": "bootstrap_only"}
    assert jobs.current.events[-1].data["bootstrap"] == "succeeded"
    assert chains.chain.status == "deployed"
    assert _durable_chain_identity(chains.chain) == _durable_chain_identity(retained_chain)
    assert chains.chain.deploy_job_id == retained_chain.deploy_job_id
    assert chains.chain.terraform_working_directory == retained_chain.terraform_working_directory
    assert chains.chain.nodes == retained_nodes
    assert _durable_job_identity(jobs.current) == _durable_job_identity(job)


@pytest.mark.parametrize("parent_case", ["missing", "succeeded", "missing_marker", "wrong_marker"])
def test_bootstrap_only_intent_fails_closed_before_provider_deployment(monkeypatch, parent_case):
    from app.services import sketch_chains as subject

    job = _retained_failed_provider_job()
    if parent_case == "succeeded":
        job = replace(job, status="succeeded")
    elif parent_case == "missing_marker":
        job = replace(job, events=[])
    elif parent_case == "wrong_marker":
        job = replace(job, events=[JobEvent(1, "info", "bootstrap starting", {"bootstrap": "starting"})])
    retained_chain = replace(
        _stored_chain(job.id),
        status="failed",
        terraform_working_directory=job.input["terraformWorkingDirectory"],
        nodes=_retained_provider_nodes(),
    )
    chains = _ChainStore(retained_chain)
    jobs = _JobStore(job)
    if parent_case == "missing":
        jobs.get = lambda _job_id: None
    monkeypatch.setattr(subject, "SqlAlchemyJobRepository", lambda: jobs)
    _forbid_provider_deployment_adapters(monkeypatch, subject)

    with pytest.raises(subject.SketchChainValidationError) as exc_info:
        subject.deploy_sketch_chain(
            "eng-test",
            retained_chain.chain_id,
            {"retryBootstrapOnly": True},
            repository=chains,
        )

    assert exc_info.value.errors == [
        f"chain {retained_chain.chain_id} is no longer eligible for retained bootstrap-only recovery"
    ]
    assert chains.chain == retained_chain


def test_exhausted_bootstrap_only_retry_retains_full_provider_identity_and_recovery_paths(monkeypatch):
    from app.services import sketch_chains as subject

    job = _retained_failed_provider_job()
    retained_nodes = _retained_provider_nodes()
    retained_chain = replace(
        _stored_chain(job.id),
        status="failed",
        terraform_working_directory=job.input["terraformWorkingDirectory"],
        nodes=retained_nodes,
    )
    jobs = _JobStore(job)
    chains = _ChainStore(retained_chain)
    monkeypatch.setattr(subject, "SqlAlchemyJobRepository", lambda: jobs)
    monkeypatch.setattr(
        subject,
        "apply_sketch_bootstrap",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(SketchBootstrapApplyError("apt lock retry exhausted")),
    )
    started = []
    outbound = []
    monkeypatch.setattr(subject, "start_runtime_task", lambda task, **_kwargs: (started.append(_kwargs["name"]), task()))
    monkeypatch.setattr(subject, "_start_outbound_auto_configuration", lambda *_args, **_kwargs: outbound.append(True))
    _forbid_provider_deployment_adapters(monkeypatch, subject)

    result = subject.deploy_sketch_chain("eng-test", retained_chain.chain_id, {}, repository=chains)

    assert started == ["barragan-sketch-bootstrap-retry-proxy01-sea-01"]
    assert result["job"]["id"] == job.id
    assert jobs.current.status == "failed"
    assert chains.chain.status == "failed"
    assert _durable_chain_identity(chains.chain) == _durable_chain_identity(retained_chain)
    assert chains.chain.deploy_job_id == retained_chain.deploy_job_id
    assert chains.chain.terraform_working_directory == retained_chain.terraform_working_directory
    assert chains.chain.nodes == retained_nodes
    assert _durable_job_identity(jobs.current) == _durable_job_identity(job)
    assert sum(event.data == {"bootstrap": "retrying", "retry": "bootstrap_only"} for event in jobs.current.events) == 1
    assert jobs.current.events[-1].data == {"bootstrap": "failed", "error": "apt lock retry exhausted"}
    assert subject._failed_bootstrap_job(jobs.current) is True
    assert outbound == []

    teardown_job = replace(
        _provider_job(),
        id="job-teardown",
        action="linode_sketch_teardown",
        status="running",
        input={"deployJobId": job.id, "terraformWorkingDirectory": job.input["terraformWorkingDirectory"]},
        events=[],
    ).to_detail()
    teardown_deploy_jobs = []
    monkeypatch.setattr(
        subject,
        "start_guarded_linode_sketch_teardown",
        lambda deploy_job_id, **_kwargs: teardown_deploy_jobs.append(deploy_job_id) or teardown_job,
    )
    monkeypatch.setattr(
        subject,
        "start_guarded_digitalocean_sketch_teardown",
        lambda *_args, **_kwargs: pytest.fail("DigitalOcean teardown must not claim a Linode deploy job"),
    )
    monkeypatch.setattr(
        subject,
        "start_guarded_mixed_sketch_teardown",
        lambda *_args, **_kwargs: pytest.fail("mixed teardown must not claim a Linode deploy job"),
    )
    monkeypatch.setattr(subject, "_start_sketch_teardown_sequence", lambda *_args, **_kwargs: None)

    teardown = subject.teardown_sketch_chain(
        "eng-test",
        retained_chain.chain_id,
        {"confirmation": f"teardown-{retained_chain.chain_id}"},
        repository=chains,
    )

    assert teardown_deploy_jobs == [job.id]
    assert teardown["chain"]["status"] == "tearing_down"
    assert teardown["chain"]["nodes"] == retained_nodes


def test_failed_or_unrecorded_bootstrap_blocks_manual_outbound_work(monkeypatch):
    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda _: SimpleNamespace(sketch_state_schema="split-v1"))
    job = _provider_job()
    failed_chain = replace(_stored_chain(job.id), status="failed")
    with pytest.raises(OutboundChannelApplyValidationError) as exc:
        _require_bootstrapped_chain(_JobStore(job), "eng-test", failed_chain.chain_id, chain_repository=_ChainStore(failed_chain))
    assert exc.value.errors == ["sketch chain proxy01-sea-01 is failed; bootstrap must complete before outbound work"]

    deployed_chain = replace(failed_chain, status="deployed")
    with pytest.raises(OutboundChannelApplyValidationError) as exc:
        _require_bootstrapped_chain(_JobStore(job), "eng-test", deployed_chain.chain_id, chain_repository=_ChainStore(deployed_chain))
    assert exc.value.errors == ["sketch chain proxy01-sea-01 has no successful bootstrap record"]


def test_current_legacy_outbound_validation_does_not_replace_bootstrap_evidence(monkeypatch):
    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda _: SimpleNamespace(sketch_state_schema="split-v1"))
    provider_job = _provider_job()
    chain = replace(_stored_chain(provider_job.id), status="deployed", nodes=_chain().nodes)
    validation = replace(
        provider_job,
        id="job-validation",
        action="outbound_channel_validation",
        input={"engagementId": "eng-test", "chainId": chain.chain_id},
        events=[
            JobEvent(
                1,
                "info",
                "validated",
                {
                    "outboundChannels": [
                        {
                            "chainId": chain.chain_id,
                            "status": "Validated",
                            "validation": {"expectedPublicIp": "203.0.113.10"},
                        }
                    ]
                },
            )
        ],
    )

    with pytest.raises(OutboundChannelApplyValidationError) as exc:
        _require_bootstrapped_chain(
            _JobStore(provider_job, history=[validation]),
            "eng-test",
            chain.chain_id,
            chain_repository=_ChainStore(chain),
        )
    assert exc.value.errors == ["sketch chain proxy01-sea-01 has no successful bootstrap record"]


def test_stale_legacy_outbound_validation_does_not_satisfy_bootstrap_gate(monkeypatch):
    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda _: SimpleNamespace(sketch_state_schema="split-v1"))
    provider_job = _provider_job()
    chain = replace(_stored_chain(provider_job.id), status="deployed", nodes=_chain().nodes)
    stale_validation = replace(
        provider_job,
        id="job-validation",
        action="outbound_channel_validation",
        events=[
            JobEvent(
                1,
                "info",
                "validated old edge",
                {
                    "outboundChannels": [
                        {
                            "chainId": chain.chain_id,
                            "status": "Validated",
                            "validation": {"expectedPublicIp": "203.0.113.99"},
                        }
                    ]
                },
            )
        ],
    )

    with pytest.raises(OutboundChannelApplyValidationError) as exc:
        _require_bootstrapped_chain(
            _JobStore(provider_job, history=[stale_validation]),
            "eng-test",
            chain.chain_id,
            chain_repository=_ChainStore(chain),
        )
    assert exc.value.errors == ["sketch chain proxy01-sea-01 has no successful bootstrap record"]


def test_public_outbound_apply_observes_bootstrap_gate_before_rendering(monkeypatch):
    from app.services import outbound_channel_apply as subject

    job = _provider_job()
    channel = {"channelId": "channel-1", "chainId": "proxy01-sea-01", "artifacts": {}}
    monkeypatch.setattr(subject, "get_engagement", lambda _id: object())
    monkeypatch.setattr(subject, "resolve_ansible_playbook", lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    monkeypatch.setattr(subject, "_latest_outbound_channel_with_artifacts", lambda *_args: channel)
    monkeypatch.setattr(subject, "_artifacts_from_channel", lambda _channel: (_ for _ in ()).throw(RuntimeError("after-gate")))

    failed = replace(_stored_chain(job.id), status="failed")
    with pytest.raises(OutboundChannelApplyValidationError) as exc:
        subject.apply_outbound_channel(
            "eng-test",
            "channel-1",
            confirmation="apply-outbound-channel-1",
            repository=_JobStore(job),
            chain_repository=_ChainStore(failed),
        )
    assert exc.value.errors == ["sketch chain proxy01-sea-01 is failed; bootstrap must complete before outbound work"]

    bootstrapped = replace(_stored_chain(job.id), status="deployed")
    successful_job = replace(
        job,
        events=job.events + [JobEvent(2, "info", "bootstrap", {"bootstrap": "succeeded"})],
    )
    with pytest.raises(RuntimeError, match="after-gate"):
        subject.apply_outbound_channel(
            "eng-test",
            "channel-1",
            confirmation="apply-outbound-channel-1",
            repository=_JobStore(successful_job),
            chain_repository=_ChainStore(bootstrapped),
        )


def _provider_job() -> StoredJobRun:
    return StoredJobRun(
        id="job-provider",
        action="linode_sketch_deploy",
        status="succeeded",
        target="engagement:eng-test",
        target_type="engagement",
        target_id="eng-test",
        requested_by="operator",
        input={},
        artifact_refs=[],
        created_at="2026-08-22T00:00:00+00:00",
        started_at="2026-08-22T00:00:00+00:00",
        finished_at="2026-08-22T00:01:00+00:00",
        events=[
            JobEvent(
                1,
                "info",
                "terraform output recorded",
                {"sketchInfrastructure": _chain().nodes},
            )
        ],
    )


def _stored_chain(job_id: str) -> StoredSketchChain:
    return StoredSketchChain(
        chain_id="proxy01-sea-01",
        engagement_id="eng-test",
        assigned_proxy="proxy01",
        middle_provider="linode",
        middle_region="us-sea",
        middle_size="g6-nanode-1",
        edge_provider="linode",
        edge_region="us-sea",
        edge_size="g6-nanode-1",
        status="deploying",
        burned=False,
        burned_note="",
        deploy_job_id=job_id,
        teardown_job_id="",
        terraform_working_directory="/tmp/sketch",
        nodes=[],
        created_at="2026-08-22T00:00:00+00:00",
        updated_at="2026-08-22T00:00:00+00:00",
    )


class _ChainStore:
    def __init__(self, chain):
        self.chain = chain

    def get(self, _engagement_id, _chain_id):
        return self.chain

    def save(self, chain):
        self.chain = chain
        return chain


class _JobStore:
    def __init__(self, job, *, history=None):
        self.current = job
        self.history = list(history or [])

    def get(self, _job_id):
        return self.current

    def save(self, job):
        self.current = job
        return job

    def list_for_engagement(self, _engagement_id, *, limit=None):
        jobs = [self.current, *self.history]
        return jobs if limit is None else jobs[:limit]
