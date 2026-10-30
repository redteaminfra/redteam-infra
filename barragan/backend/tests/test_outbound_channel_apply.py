# Copyright (c) 2026, Oracle and/or its affiliates.
import subprocess
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services.outbound_channel_apply import (
    APPLY_PREVIEW_STATUS,
    APPLY_SUCCESS_STATUS,
    CoreApplyHost,
    OutboundChannelApplyValidationError,
    VALIDATION_FAILED_STATUS,
    VALIDATION_SUCCESS_STATUS,
    VALIDATION_WARNING_STATUS,
    apply_outbound_channel,
    preview_outbound_channel_apply,
    remove_outbound_channel,
    render_outbound_apply_plan,
    render_outbound_apply_workspace,
    render_outbound_remove_workspace,
    validate_outbound_channel,
)
from app.services.outbound_channel_artifacts import (
    CoreHost,
    OutboundChannelArtifactSpec,
    OutboundChannelArtifacts,
    OutboundChannelArtifactValidationError,
    RenderedArtifact,
    SketchNodeOpsecBoundary,
    render_outbound_channel_artifacts,
)
from app.storage.job_repository import StoredJobRun


def test_renders_ordered_core_only_outbound_apply_plan():
    plan = render_outbound_apply_plan(
        _artifacts(),
        homebase=CoreApplyHost("homebase", "203.0.113.10"),
        proxy=CoreApplyHost("proxy01", "192.168.2.11"),
    )

    body = plan.to_dict()
    assert body["status"] == APPLY_PREVIEW_STATUS
    assert body["mutation"] is False
    assert [step["order"] for step in body["steps"]] == [1, 2, 3, 4, 5, 6, 7, 8, 9]
    assert [step["id"] for step in body["steps"]] == [
        "apply-core-hosts",
        "publish-homebase-proxychains",
        "write-proxy-ssh-config",
        "write-proxy-systemd-unit",
        "open-proxy-socks-port",
        "reload-proxy-systemd",
        "enable-restart-proxy-service",
        "wait-proxy-socks-listener",
        "validate-from-homebase",
    ]
    assert all(step["status"] == "pending" for step in body["steps"])


def test_apply_plan_targets_core_hosts_homebase_proxy_and_validation_origin():
    plan = render_outbound_apply_plan(
        _artifacts(),
        homebase=CoreApplyHost("homebase", "203.0.113.10"),
        proxy=CoreApplyHost("proxy01", "192.168.2.11"),
    )
    steps = {step["id"]: step for step in plan.to_dict()["steps"]}

    assert steps["apply-core-hosts"]["targets"] == [
        {"name": "homebase", "role": "homebase", "host": "203.0.113.10"},
        {"name": "proxy01", "role": "proxy", "host": "192.168.2.11"},
    ]
    assert steps["apply-core-hosts"]["artifact"] == {"name": "coreHosts", "path": "/etc/hosts"}
    assert steps["publish-homebase-proxychains"]["targets"] == [
        {"name": "homebase", "role": "homebase", "host": "203.0.113.10"}
    ]
    assert steps["publish-homebase-proxychains"]["artifact"] == {
        "name": "homebaseProxychains",
        "path": "/opt/proxy01/oci-rx-socks5.conf",
    }
    assert steps["write-proxy-ssh-config"]["targets"] == [
        {"name": "proxy01", "role": "proxy", "host": "192.168.2.11"}
    ]
    assert steps["write-proxy-ssh-config"]["artifact"] == {
        "name": "proxySshConfig",
        "path": "/opt/ssh-proxy/config-3333",
    }
    assert steps["write-proxy-systemd-unit"]["artifact"] == {
        "name": "proxySystemdService",
        "path": "/etc/systemd/system/ssh-proxy-3333.service",
    }
    assert steps["open-proxy-socks-port"]["targets"] == [
        {"name": "proxy01", "role": "proxy", "host": "192.168.2.11"}
    ]
    assert steps["open-proxy-socks-port"]["firewall"] == {
        "source": "192.168.0.0/16",
        "protocol": "tcp",
        "port": 3333,
        "state": "present",
    }
    assert steps["reload-proxy-systemd"]["systemd"] == {"daemonReload": True}
    assert steps["enable-restart-proxy-service"]["systemd"] == {
        "unit": "ssh-proxy-3333.service",
        "enabled": True,
        "state": "restarted",
    }
    assert steps["wait-proxy-socks-listener"]["validation"] == {
        "host": "127.0.0.1",
        "port": 3333,
        "timeoutSeconds": 90,
    }
    assert steps["validate-from-homebase"]["targets"] == [
        {"name": "homebase", "role": "homebase", "host": "203.0.113.10"}
    ]
    assert steps["validate-from-homebase"]["validation"]["origin"] == "homebase"
    assert steps["validate-from-homebase"]["validation"]["shellDisplay"] == "curl -sS --connect-timeout 10 -x socks5h://proxy01:3333 https://ipv4.icanhazip.com"
    assert steps["validate-from-homebase"]["validation"]["expectedPublicIp"] == "172.236.225.137"


def test_apply_plan_never_targets_middle_or_edge_nodes():
    plan = render_outbound_apply_plan(
        _artifacts(),
        homebase=CoreApplyHost("homebase", "203.0.113.10"),
        proxy=CoreApplyHost("proxy01", "192.168.2.11"),
    )

    rendered_plan = str(plan.to_dict())
    target_names = [
        target["name"]
        for step in plan.to_dict()["steps"]
        for target in step["targets"]
    ]
    assert target_names == [
        "homebase",
        "proxy01",
        "homebase",
        "proxy01",
        "proxy01",
        "proxy01",
        "proxy01",
        "proxy01",
        "proxy01",
        "homebase",
    ]
    assert "middle01-of02-prod" not in target_names
    assert "edge-of02-prod-us-lax-01" not in target_names
    assert "BEGIN OPENSSH PRIVATE KEY" not in rendered_plan
    assert "LINODE_TOKEN" not in rendered_plan
    assert "DIGITALOCEAN_TOKEN" not in rendered_plan


def test_apply_plan_rejects_sketch_node_artifact_enrichment():
    artifacts = _artifacts(
        sketch_node_boundary=SketchNodeOpsecBoundary(
            sketch_hosts_content=None,
            middle_node_artifacts=[],
            edge_node_artifacts=[RenderedArtifact("/etc/hosts", "192.168.2.11 proxy01\n")],
            reason="bad enrichment",
        )
    )

    with pytest.raises(OutboundChannelApplyValidationError) as exc:
        render_outbound_apply_plan(
            artifacts,
            homebase=CoreApplyHost("homebase", "203.0.113.10"),
            proxy=CoreApplyHost("proxy01", "192.168.2.11"),
        )

    assert "edge node artifacts must not be rendered" in exc.value.errors


def test_renders_core_only_outbound_apply_workspace():
    workspace = render_outbound_apply_workspace(
        _artifacts(),
        homebase=CoreApplyHost("homebase", "203.0.113.10", "ubuntu", "/var/lib/barragan/.ssh/barragan_testing"),
        proxy=CoreApplyHost("proxy01", "192.168.2.11", "ubuntu", "/var/lib/barragan/.ssh/barragan_testing"),
    )

    assert workspace.to_dict()["status"] == APPLY_PREVIEW_STATUS
    assert workspace.to_dict()["mutation"] is False
    assert workspace.inventory.target == "ansible/inventory.ini"
    assert "[homebase]" in workspace.inventory.content
    assert "homebase ansible_host=203.0.113.10 ansible_user=ubuntu" in workspace.inventory.content
    assert "ansible_ssh_private_key_file=/var/lib/barragan/.ssh/barragan_testing" in workspace.inventory.content
    assert "[selected_proxy]" in workspace.inventory.content
    assert "proxy01 ansible_host=192.168.2.11 ansible_user=ubuntu" in workspace.inventory.content
    assert "ProxyJump" not in workspace.inventory.content
    assert "middle01-of02-prod ansible_host" not in workspace.inventory.content
    assert "edge-of02-prod-us-lax-01 ansible_host" not in workspace.inventory.content

    assert workspace.playbook.target == "ansible/apply_outbound_channel.yml"
    assert "hosts: barragan_core" in workspace.playbook.content
    assert "Read core hostname before outbound configuration" in workspace.playbook.content
    assert "Assert selected core host identity" in workspace.playbook.content
    assert "No outbound configuration was applied." in workspace.playbook.content
    assert "path: /etc/hosts" in workspace.playbook.content
    assert "path: /opt/proxy01" in workspace.playbook.content
    assert "dest: /opt/proxy01/oci-rx-socks5.conf" in workspace.playbook.content
    assert "socks5 192.168.2.11 3333" in workspace.playbook.content
    assert "1080" not in workspace.playbook.content
    assert "dest: /opt/ssh-proxy/config-3333" in workspace.playbook.content
    assert "dest: /etc/systemd/system/ssh-proxy-3333.service" in workspace.playbook.content
    assert "Open selected proxy SOCKS port from core VCN" in workspace.playbook.content
    assert "destination_port: '3333'" in workspace.playbook.content
    assert "source: 192.168.0.0/16" in workspace.playbook.content
    assert "iptables-save -f /etc/iptables/rules.v4" in workspace.playbook.content
    assert "Enforce IPv4-first address selection" not in workspace.playbook.content
    assert "precedence ::ffff:0:0/96  100" not in workspace.playbook.content
    assert "name: ssh-proxy-3333.service" in workspace.playbook.content
    assert "systemctl is-active ssh-proxy-3333.service" in workspace.playbook.content
    assert "Wait for selected proxy SOCKS listener" in workspace.playbook.content
    assert "port: '3333'" in workspace.playbook.content
    assert "timeout: 90" in workspace.playbook.content
    assert "curl -sS --connect-timeout 10 -x socks5h://proxy01:3333 https://ipv4.icanhazip.com" in workspace.playbook.content

    assert "middle01-of02-prod" in workspace.playbook.content
    assert "edge-of02-prod-us-lax-01" in workspace.playbook.content
    assert "ProxyJump middle01-of02-prod" in workspace.playbook.content
    assert "hosts: middle01-of02-prod" not in workspace.playbook.content
    assert "hosts: edge-of02-prod-us-lax-01" not in workspace.playbook.content


def test_preview_uses_active_core_not_newer_channel_connection_snapshot(monkeypatch):
    stale_channel_snapshot = StoredJobRun(
        id="job-stale-channel-snapshot",
        action="outbound_channel_validation",
        status="failed",
        target="engagement:eng-zy01",
        target_type="engagement",
        target_id="eng-zy01",
        requested_by="operator",
        input={"engagementId": "eng-zy01"},
        artifact_refs=[],
        created_at="2026-06-05T12:00:00+00:00",
        started_at="2026-06-05T12:00:00+00:00",
        finished_at="2026-06-05T12:00:00+00:00",
        events=[
            JobEvent(
                1,
                "error",
                "stale cross-VCN evidence",
                {
                    "connectionDetails": [
                        {"role": "homebase", "displayName": "homebase-other", "publicIp": "203.0.113.99", "privateIp": "192.168.0.10"},
                        {"role": "proxy", "displayName": "proxy01-other", "publicIp": "203.0.113.98", "privateIp": "192.168.2.11"},
                    ]
                },
            )
        ],
    )
    repository = _FakeJobRepository([stale_channel_snapshot, *_apply_prerequisite_jobs()])
    monkeypatch.setattr(
        "app.services.outbound_channel_apply.get_engagement",
        lambda engagement_id: SimpleNamespace(name="ZY01"),
    )

    preview = preview_outbound_channel_apply("eng-zy01", "chain-1", repository=repository)

    assert preview is not None
    inventory = preview["workspace"]["inventory"]["content"]
    assert "homebase ansible_host=203.0.113.10" in inventory
    assert "barragan_expected_hostname=homebase" in inventory
    assert "UserKnownHostsFile=/var/tmp/barragan-core/job-core/ssh/known_hosts" in inventory
    assert "StrictHostKeyChecking=yes" in inventory
    assert "HostKeyAlias=203.0.113.10" in inventory
    assert "203.0.113.99" not in inventory


def test_renders_core_proxy_jump_and_sketch_key_install_when_available():
    workspace = render_outbound_apply_workspace(
        _artifacts(),
        homebase=CoreApplyHost("homebase", "203.0.113.10", "ubuntu", "/keys/core"),
        proxy=CoreApplyHost("proxy01", "192.168.2.11", "ubuntu", "/keys/core", "ubuntu@203.0.113.10"),
        sketch_private_key_src="/tmp/barragan-linode-sketch/keys/zy01-sketch",
    )

    assert "ProxyCommand='ssh -i /keys/core -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10 -W %h:%p ubuntu@203.0.113.10'" in workspace.inventory.content
    assert "proxy01 ansible_host=192.168.2.11 ansible_user=ubuntu ansible_ssh_private_key_file=/keys/core" in workspace.inventory.content
    assert "Install engagement sketch SSH key on selected proxy" in workspace.playbook.content
    assert "src: /tmp/barragan-linode-sketch/keys/zy01-sketch" in workspace.playbook.content
    assert "dest: /opt/ssh-proxy/keys/of02-sketch" in workspace.playbook.content
    assert "mode: '0600'" in workspace.playbook.content
    assert "Install autossh for outbound channel service" in workspace.playbook.content
    assert "name: autossh" in workspace.playbook.content
    assert "hosts: middle" not in workspace.playbook.content
    assert "hosts: edge" not in workspace.playbook.content


def test_preview_binds_outbound_management_to_active_core_host_keys(monkeypatch):
    jobs = _apply_prerequisite_jobs()
    details = jobs[0].events[0].data["connectionDetails"]
    details[0]["sshAlias"] = "homebase-zy01-alias"
    details[1]["sshAlias"] = "proxy01-zy01-alias"
    repository = _FakeJobRepository(jobs)
    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda _engagement_id: object())

    preview = preview_outbound_channel_apply("eng-zy01", "chain-1", repository=repository)

    assert preview is not None
    inventory = preview["workspace"]["inventory"]["content"]
    assert "UserKnownHostsFile=/var/tmp/barragan-core/job-core/ssh/known_hosts" in inventory
    assert "StrictHostKeyChecking=yes" in inventory
    assert "HostKeyAlias=203.0.113.10" in inventory
    assert "HostKeyAlias=203.0.113.11" in inventory
    assert "barragan_expected_hostname=homebase" in inventory
    assert "barragan_expected_hostname=proxy01" in inventory
    assert "homebase-zy01-alias" not in inventory
    assert "proxy01-zy01-alias" not in inventory


def test_preview_uses_explicit_persisted_hostnames_for_audited_legacy_core(monkeypatch):
    jobs = _apply_prerequisite_jobs()
    details = jobs[0].events[0].data["connectionDetails"]
    details[0]["hostname"] = "homebase-sk02-dev"
    details[0]["sshAlias"] = "ignored-homebase-alias"
    details[1]["hostname"] = "proxy01-sk02-dev"
    details[1]["sshAlias"] = "ignored-proxy-alias"
    repository = _FakeJobRepository(jobs)
    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda _engagement_id: object())

    preview = preview_outbound_channel_apply("eng-zy01", "chain-1", repository=repository)

    assert preview is not None
    inventory = preview["workspace"]["inventory"]["content"]
    assert "barragan_expected_hostname=homebase-sk02-dev" in inventory
    assert "barragan_expected_hostname=proxy01-sk02-dev" in inventory
    assert "ignored-homebase-alias" not in inventory
    assert "ignored-proxy-alias" not in inventory


def test_preview_rejects_historical_validation_without_bootstrap_evidence(monkeypatch):
    jobs = _apply_prerequisite_jobs()
    historical_channel = _channel_with_artifacts()
    historical_channel.update(
        {
            "status": VALIDATION_SUCCESS_STATUS,
            "validation": {"expectedPublicIp": "172.236.225.137"},
        }
    )
    jobs.insert(
        0,
        StoredJobRun(
            id="job-historical-validation",
            action="outbound_channel_validation",
            status="succeeded",
            target="engagement:eng-zy01",
            target_type="engagement",
            target_id="eng-zy01",
            requested_by="operator",
            input={"engagementId": "eng-zy01"},
            artifact_refs=[],
            created_at="2026-06-04T12:20:00+00:00",
            started_at="2026-06-04T12:20:00+00:00",
            finished_at="2026-06-04T12:21:00+00:00",
            events=[JobEvent(1, "info", "validated", {"outboundChannels": [historical_channel]})],
        ),
    )
    repository = _FakeJobRepository(jobs)
    chain_repository = _FakeChainRepository(
        SimpleNamespace(status="deployed", deploy_job_id="job-outbound")
    )
    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda _engagement_id: object())

    with pytest.raises(OutboundChannelApplyValidationError) as exc:
        preview_outbound_channel_apply(
            "eng-zy01",
            "chain-1",
            repository=repository,
            chain_repository=chain_repository,
        )

    assert exc.value.errors == ["sketch chain chain-1 has no successful bootstrap record"]


def test_preview_rejects_active_core_without_known_hosts_evidence(monkeypatch):
    jobs = _apply_prerequisite_jobs()
    jobs[0].events[0].data.pop("workspaceDir")
    repository = _FakeJobRepository(jobs)
    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda _engagement_id: object())

    with pytest.raises(OutboundChannelApplyValidationError) as exc:
        preview_outbound_channel_apply("eng-zy01", "chain-1", repository=repository)

    assert exc.value.errors == ["active core deployment known-hosts evidence is required before outbound configuration"]


def test_renders_core_only_outbound_remove_workspace():
    workspace = render_outbound_remove_workspace(
        _artifacts(),
        homebase=CoreApplyHost("homebase", "203.0.113.10", "ubuntu", "/keys/core"),
        proxy=CoreApplyHost("proxy01", "192.168.2.11", "ubuntu", "/keys/core", "ubuntu@203.0.113.10"),
    )

    assert workspace.playbook.target == "ansible/remove_outbound_channel.yml"
    assert "hosts: homebase" in workspace.playbook.content
    assert "path: /opt/proxy01/oci-rx-socks5.conf" in workspace.playbook.content
    assert "hosts: selected_proxy" in workspace.playbook.content
    assert "name: ssh-proxy-3333.service" in workspace.playbook.content
    assert "path: /opt/ssh-proxy/config-3333" in workspace.playbook.content
    assert "path: /etc/systemd/system/ssh-proxy-3333.service" in workspace.playbook.content
    assert "Remove engagement sketch SSH key from selected proxy" not in workspace.playbook.content
    assert "path: /opt/ssh-proxy/keys/of02-sketch" not in workspace.playbook.content
    assert "--dport 3333" in workspace.playbook.content
    assert "hosts: middle" not in workspace.playbook.content
    assert "hosts: edge" not in workspace.playbook.content
    assert '"mode": "outbound_channel_remove"' in workspace.manifest.content
    assert "proxySketchKey" not in workspace.manifest.content


def test_apply_workspace_rejects_multiple_proxy_identity_files():
    artifacts = _artifacts(
        proxy_ssh_config=RenderedArtifact(
            "/opt/ssh-proxy/config-3333",
            "\n".join(
                [
                    "Host middle01-of02-prod",
                    "    Hostname 172.239.52.174",
                    "    IdentityFile /opt/ssh-proxy/keys/of02-sketch",
                    "    User sketchssh",
                    "Host edge-of02-prod-us-lax-01",
                    "    Hostname 172.236.225.137",
                    "    DynamicForward 0.0.0.0:3333",
                    "    ProxyJump middle01-of02-prod",
                    "    IdentityFile /opt/ssh-proxy/keys/other-engagement-sketch",
                    "    User sketchssh",
                    "",
                ]
            ),
        )
    )

    with pytest.raises(OutboundChannelApplyValidationError) as exc:
        render_outbound_apply_workspace(
            artifacts,
            homebase=CoreApplyHost("homebase", "203.0.113.10"),
            proxy=CoreApplyHost("proxy01", "192.168.2.11"),
        )

    assert exc.value.errors == ["proxy ssh config must use one shared engagement sketch IdentityFile"]


def test_apply_workspace_normalizes_legacy_proxy_ssh_config_options():
    artifacts = _artifacts(
        proxy_ssh_config=RenderedArtifact(
            "/opt/ssh-proxy/config-3333",
            "\n".join(
                [
                    "Host middle01-of02-prod",
                    "    Hostname 172.239.52.174",
                    "    IdentityFile /opt/ssh-proxy/keys/of02-sketch",
                    "    User sketchssh",
                    "Host edge-of02-prod-us-lax-01",
                    "    Hostname 172.236.225.137",
                    "    DynamicForward 0.0.0.0:3333",
                    "    ProxyJump middle01-of02-prod",
                    "    IdentityFile /opt/ssh-proxy/keys/of02-sketch",
                    "    User sketchssh",
                    "    RequestTTY no",
                    "",
                ]
            ),
        )
    )

    workspace = render_outbound_apply_workspace(
        artifacts,
        homebase=CoreApplyHost("homebase", "203.0.113.10"),
        proxy=CoreApplyHost("proxy01", "192.168.2.11"),
    )

    assert workspace.playbook.content.count("UserKnownHostsFile /dev/null") == 2
    assert workspace.playbook.content.count("StrictHostKeyChecking no") == 2
    assert workspace.playbook.content.count("BatchMode yes") == 2


def test_manifest_records_preview_status_targets_validation_and_opsec_boundary():
    workspace = render_outbound_apply_workspace(
        _artifacts(),
        homebase=CoreApplyHost("homebase", "203.0.113.10"),
        proxy=CoreApplyHost("proxy01", "192.168.2.11"),
    )

    assert '"mode": "outbound_channel_apply_preview"' in workspace.manifest.content
    assert f'"status": "{APPLY_PREVIEW_STATUS}"' in workspace.manifest.content
    assert '"mutation": false' in workspace.manifest.content
    assert '"homebaseProxychains": "/opt/proxy01/oci-rx-socks5.conf"' in workspace.manifest.content
    assert '"expectedPublicIp": "172.236.225.137"' in workspace.manifest.content
    assert '"middleNodeArtifacts": []' in workspace.manifest.content
    assert '"edgeNodeArtifacts": []' in workspace.manifest.content
    assert "Validation is planned from homebase and has not run" in workspace.manifest.content
    assert "validated" not in workspace.to_dict()["status"].lower()
    assert "deployed" not in workspace.to_dict()["status"].lower()
    assert "ready" not in workspace.to_dict()["status"].lower()


def test_rejects_inventory_targets_that_are_not_core_hosts():
    with pytest.raises(OutboundChannelApplyValidationError) as exc:
        render_outbound_apply_workspace(
            _artifacts(),
            homebase=CoreApplyHost("homebase", "203.0.113.10"),
            proxy=CoreApplyHost("middle01-of02-prod", "172.239.52.174"),
        )

    assert "proxy host name must look like proxy01" in exc.value.errors
    assert "core apply host middle01-of02-prod must be homebase or proxyNN" in exc.value.errors


def test_rejects_proxy_target_mismatch():
    with pytest.raises(OutboundChannelApplyValidationError) as exc:
        render_outbound_apply_workspace(
            _artifacts(),
            homebase=CoreApplyHost("homebase", "203.0.113.10"),
            proxy=CoreApplyHost("proxy02", "192.168.2.12"),
        )

    assert "proxy host must match outbound artifact target proxy01" in exc.value.errors


def test_rejects_sketch_node_artifact_enrichment():
    artifacts = _artifacts(
        sketch_node_boundary=SketchNodeOpsecBoundary(
            sketch_hosts_content="192.168.2.11 proxy01\n",
            middle_node_artifacts=[RenderedArtifact("/etc/hosts", "192.168.2.11 proxy01\n")],
            edge_node_artifacts=[],
            reason="bad enrichment",
        )
    )

    with pytest.raises(OutboundChannelApplyValidationError) as exc:
        render_outbound_apply_workspace(
            artifacts,
            homebase=CoreApplyHost("homebase", "203.0.113.10"),
            proxy=CoreApplyHost("proxy01", "192.168.2.11"),
        )

    assert "sketch hosts content must not be rendered" in exc.value.errors
    assert "middle node artifacts must not be rendered" in exc.value.errors


def test_rejects_secret_material_in_workspace():
    artifacts = _artifacts(
        proxy_ssh_config=RenderedArtifact(
            "/opt/ssh-proxy/config-3333",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nnot allowed\n-----END OPENSSH PRIVATE KEY-----\n",
        )
    )

    with pytest.raises(OutboundChannelArtifactValidationError) as exc:
        render_outbound_apply_workspace(
            artifacts,
            homebase=CoreApplyHost("homebase", "203.0.113.10"),
            proxy=CoreApplyHost("proxy01", "192.168.2.11"),
        )

    assert "forbidden secret marker" in exc.value.errors[0]


def test_apply_requires_confirmation_before_job_or_command(monkeypatch):
    repository = _FakeJobRepository([])
    calls = []
    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda engagement_id: object())
    monkeypatch.setattr(
        "app.services.outbound_channel_apply.write_existing_sketch_transport_ssh_key_files",
        lambda _engagement_id, directory: (str(directory / "transport"), str(directory / "transport.pub")),
    )

    with pytest.raises(OutboundChannelApplyValidationError) as exc:
        apply_outbound_channel(
            "eng-zy01",
            "chain-1",
            confirmation="wrong",
            repository=repository,
            runner=lambda command, cwd: calls.append((command, cwd)) or subprocess.CompletedProcess(command, 0, "", ""),
        )

    assert exc.value.errors == ["confirmation must be apply-outbound-chain-1"]
    assert calls == []
    assert repository.saved == []


def test_apply_runs_one_core_only_ansible_command_and_records_pending_validation(tmp_path, monkeypatch):
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    repository = _FakeJobRepository(_apply_prerequisite_jobs())
    calls = []
    observed_inventory = ""

    def runner(command, cwd):
        nonlocal observed_inventory
        calls.append((command, cwd))
        observed_inventory = (cwd / "ansible" / "inventory.ini").read_text(encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="apply ok", stderr="")

    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda engagement_id: object())
    monkeypatch.setattr(
        "app.services.outbound_channel_apply.write_existing_sketch_transport_ssh_key_files",
        lambda _engagement_id, directory: (str(directory / "transport"), str(directory / "transport.pub")),
    )

    result = apply_outbound_channel(
        "eng-zy01",
        "chain-1",
        confirmation="apply-outbound-chain-1",
        requested_by="operator",
        repository=repository,
        runner=runner,
        env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook), "PATH": ""},
        workspace_root=tmp_path,
    )

    assert result is not None
    assert result["status"] == APPLY_SUCCESS_STATUS
    assert len(calls) == 1
    assert calls[0][0] == [
        str(ansible_playbook),
        "-i",
        "ansible/inventory.ini",
        "ansible/apply_outbound_channel.yml",
    ]
    assert calls[0][1] is not None
    assert "[homebase]" in observed_inventory
    assert "[selected_proxy]" in observed_inventory
    assert "homebase ansible_host=203.0.113.10 ansible_user=ubuntu" in observed_inventory
    assert "barragan_expected_hostname=homebase" in observed_inventory
    assert "proxy01 ansible_host=192.168.2.11 ansible_user=ubuntu" in observed_inventory
    assert "middle-zy01-chain-1 ansible_host" not in observed_inventory
    assert "edge-zy01-chain-1 ansible_host" not in observed_inventory

    saved_job = _saved_action(repository, "outbound_channel_apply")
    assert saved_job.action == "outbound_channel_apply"
    assert saved_job.status == "succeeded"
    assert saved_job.input["mutation"] is True
    assert saved_job.input["confirmation"] == "redacted"
    assert [event.message for event in saved_job.events] == [
        "outbound channel apply workspace rendered",
        "outbound channel Ansible apply started",
        "outbound channel Ansible apply succeeded",
        "outbound channel validation pending",
    ]
    assert saved_job.events[-1].data["status"] == "Pending Validation"
    assert saved_job.events[-1].data["validationRan"] is False
    updated_channel = saved_job.events[-1].data["outboundChannels"][0]
    assert updated_channel["status"] == "Pending Validation"
    assert updated_channel["validation"]["status"] == "Pending Validation"
    assert updated_channel["validation"]["detail"] == "Core channel config applied; homebase validation has not run yet."
    assert "artifacts" not in updated_channel
    workspace_dir = saved_job.events[0].data["workspaceDir"]
    assert (tmp_path / workspace_dir.split("/")[-1] / "ansible" / "inventory.ini").exists()
    workspace_evidence = saved_job.events[0].data["workspaceEvidence"]
    assert workspace_evidence["inventory"]["path"] == "ansible/inventory.ini"
    assert workspace_evidence["playbook"]["path"] == "ansible/apply_outbound_channel.yml"
    assert workspace_evidence["manifest"]["path"] == "MANIFEST.json"
    assert workspace_evidence["inventory"]["sha256"]
    assert "[homebase]" in workspace_evidence["inventory"]["content"]
    assert "hosts: barragan_core" in workspace_evidence["playbook"]["content"]
    assert '"mode": "outbound_channel_apply_preview"' in workspace_evidence["manifest"]["content"]
    assert saved_job.events[1].data["command"] == [
        str(ansible_playbook),
        "-i",
        "ansible/inventory.ini",
        "ansible/apply_outbound_channel.yml",
    ]
    assert "Validated" not in str(saved_job.events)
    assert "Ready" not in str(saved_job.events)


def test_apply_reconciles_provider_firewall_before_ansible_and_fails_closed(tmp_path, monkeypatch):
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    repository = _FakeJobRepository(_apply_prerequisite_jobs())
    phases = []

    def firewall_sync(*args, **kwargs):
        phases.append(("firewall", args, kwargs))
        return SimpleNamespace(ok=True, events=())

    def runner(command, cwd):
        phases.append(("ansible", command, cwd))
        return subprocess.CompletedProcess(command, 0, stdout="apply ok", stderr="")

    monkeypatch.setattr(
        "app.services.outbound_channel_apply.get_engagement",
        lambda engagement_id: SimpleNamespace(name="ZY01"),
    )
    monkeypatch.setattr(
        "app.services.outbound_channel_apply.get_operations_overview",
        lambda *args, **kwargs: {},
    )
    monkeypatch.setattr(
        "app.services.outbound_channel_apply.write_existing_sketch_transport_ssh_key_files",
        lambda _engagement_id, directory: (str(directory / "transport"), str(directory / "transport.pub")),
    )

    result = apply_outbound_channel(
        "eng-zy01",
        "chain-1",
        confirmation="apply-outbound-chain-1",
        repository=repository,
        runner=runner,
        env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook), "PATH": ""},
        workspace_root=tmp_path,
        provider_firewall_sync=firewall_sync,
    )

    assert result is not None
    assert [phase[0] for phase in phases] == ["firewall", "ansible"]
    assert phases[0][1][:3] == ("eng-zy01", "ZY01", "chain-1")
    assert phases[0][2]["overview"] == {}

    failed_repository = _FakeJobRepository(_apply_prerequisite_jobs())
    failed_calls = []

    def failed_firewall_sync(*args, **kwargs):
        failed_calls.append("firewall")
        return SimpleNamespace(
            ok=False,
            events=(SimpleNamespace(level="error", data={"detail": "terraform firewall apply failed"}),),
        )

    with pytest.raises(OutboundChannelApplyValidationError) as exc:
        apply_outbound_channel(
            "eng-zy01",
            "chain-1",
            confirmation="apply-outbound-chain-1",
            repository=failed_repository,
            runner=lambda command, cwd: failed_calls.append("ansible") or subprocess.CompletedProcess(command, 0, "", ""),
            env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook), "PATH": ""},
            workspace_root=tmp_path,
            provider_firewall_sync=failed_firewall_sync,
        )

    assert exc.value.errors == ["terraform firewall apply failed"]
    assert failed_calls == ["firewall"]
    assert failed_repository.saved == []


def test_apply_uses_staged_durable_transport_key_not_historical_admin_key(tmp_path, monkeypatch):
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    mixed_job = StoredJobRun(
        id="job-mixed",
        action="mixed_provider_sketch_deploy",
        status="succeeded",
        target="engagement:eng-zy01",
        target_type="engagement",
        target_id="eng-zy01",
        requested_by="operator",
        input={
            "engagementId": "eng-zy01",
            "chainId": "chain-1",
            "childInputs": {
                "middle": {
                    "sshPrivateKeyPath": "/tmp/keys/infrastructure-admin",
                    "sketchTransportSshPrivateKeyPath": "/tmp/keys/sketch-transport",
                },
                "edges": {
                    "sshPrivateKeyPath": "/tmp/keys/infrastructure-admin",
                    "sketchTransportSshPrivateKeyPath": "/tmp/keys/sketch-transport",
                },
            },
        },
        artifact_refs=[],
        created_at="2026-07-31T00:00:00+00:00",
        started_at="2026-07-31T00:00:01+00:00",
        finished_at="2026-07-31T00:01:00+00:00",
        events=[],
    )
    repository = _FakeJobRepository([mixed_job, *_apply_prerequisite_jobs()])
    observed_playbook = ""

    def runner(command, cwd):
        nonlocal observed_playbook
        observed_playbook = (cwd / "ansible" / "apply_outbound_channel.yml").read_text(encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="apply ok", stderr="")

    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda engagement_id: object())
    monkeypatch.setattr(
        "app.services.outbound_channel_apply.write_existing_sketch_transport_ssh_key_files",
        lambda _engagement_id, directory: (str(directory / "durable-transport"), str(directory / "durable-transport.pub")),
    )

    result = apply_outbound_channel(
        "eng-zy01",
        "chain-1",
        confirmation="apply-outbound-chain-1",
        repository=repository,
        runner=runner,
        env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook), "PATH": ""},
        workspace_root=tmp_path,
    )

    assert result is not None
    assert result["status"] == APPLY_SUCCESS_STATUS
    assert "src: " in observed_playbook
    assert "durable-transport" in observed_playbook
    assert "src: /tmp/keys/infrastructure-admin" not in observed_playbook
    assert "dest: /opt/ssh-proxy/keys/of02-sketch" in observed_playbook


def test_apply_failure_records_failed_job_and_redacts_command_output(tmp_path, monkeypatch):
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    repository = _FakeJobRepository(_apply_prerequisite_jobs())

    def runner(command, cwd):
        return subprocess.CompletedProcess(
            command,
            2,
            stdout="BEGIN OPENSSH PRIVATE KEY\n" + ("x" * 5000),
            stderr="LINODE_TOKEN=secret\nprovider_token=secret\n",
        )

    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda engagement_id: object())
    monkeypatch.setattr(
        "app.services.outbound_channel_apply.write_existing_sketch_transport_ssh_key_files",
        lambda _engagement_id, directory: (str(directory / "transport"), str(directory / "transport.pub")),
    )

    result = apply_outbound_channel(
        "eng-zy01",
        "chain-1",
        confirmation="apply-outbound-chain-1",
        repository=repository,
        runner=runner,
        env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook), "PATH": ""},
        workspace_root=tmp_path,
    )

    assert result is not None
    assert result["status"] == "Apply Failed"
    saved_job = _saved_action(repository, "outbound_channel_apply")
    assert saved_job.status == "failed"
    assert saved_job.events[-2].message == "outbound channel Ansible apply failed"
    assert saved_job.events[-1].message == "outbound channel validation not run"
    persisted = str(saved_job.to_detail().to_dict())
    assert "BEGIN OPENSSH PRIVATE KEY" not in persisted
    assert "LINODE_TOKEN" not in persisted
    assert "provider_token" not in persisted
    assert "workspaceEvidence" in persisted
    assert "[truncated]" in persisted


def test_apply_requires_resolved_ansible_playbook(monkeypatch):
    repository = _FakeJobRepository(_apply_prerequisite_jobs())
    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda engagement_id: object())

    with pytest.raises(OutboundChannelApplyValidationError) as exc:
        apply_outbound_channel(
            "eng-zy01",
            "chain-1",
            confirmation="apply-outbound-chain-1",
            repository=repository,
            runner=lambda command, cwd: subprocess.CompletedProcess(command, 0, "", ""),
            env={"PATH": ""},
        )

    assert "Could not resolve ansible-playbook executable" in exc.value.errors[0]
    assert repository.saved == []


def test_validate_requires_confirmation_before_job_or_command(monkeypatch):
    repository = _FakeJobRepository([])
    calls = []
    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda engagement_id: object())

    with pytest.raises(OutboundChannelApplyValidationError) as exc:
        validate_outbound_channel(
            "eng-zy01",
            "chain-1",
            confirmation="wrong",
            repository=repository,
            runner=lambda command, cwd: calls.append((command, cwd)) or subprocess.CompletedProcess(command, 0, "", ""),
        )

    assert exc.value.errors == ["confirmation must be validate-outbound-chain-1"]
    assert calls == []
    assert repository.saved == []


def test_validate_requires_resolved_ansible(monkeypatch):
    repository = _FakeJobRepository(_apply_prerequisite_jobs())
    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda engagement_id: object())

    with pytest.raises(OutboundChannelApplyValidationError) as exc:
        validate_outbound_channel(
            "eng-zy01",
            "chain-1",
            confirmation="validate-outbound-chain-1",
            repository=repository,
            runner=lambda command, cwd: subprocess.CompletedProcess(command, 0, "", ""),
            env={"PATH": ""},
        )

    assert "Could not resolve Ansible executable" in exc.value.errors[0]
    assert repository.saved == []


def test_validate_runs_homebase_only_ansible_command_and_records_success(tmp_path, monkeypatch):
    ansible = _executable(tmp_path, "ansible")
    repository = _FakeJobRepository(_apply_prerequisite_jobs())
    calls = []
    observed_inventory = ""

    def runner(command, cwd):
        nonlocal observed_inventory
        calls.append((command, cwd))
        observed_inventory = (cwd / "ansible" / "inventory.ini").read_text(encoding="utf-8")
        if "%{http_code}" in command[-1]:
            return subprocess.CompletedProcess(command, 0, stdout="200\n", stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="172.236.225.137\n", stderr="")

    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda engagement_id: object())

    result = validate_outbound_channel(
        "eng-zy01",
        "chain-1",
        confirmation="validate-outbound-chain-1",
        requested_by="operator",
        repository=repository,
        runner=runner,
        env={"ANSIBLE_BIN": str(ansible), "PATH": ""},
        workspace_root=tmp_path,
    )

    assert result is not None
    assert result["status"] == VALIDATION_SUCCESS_STATUS
    assert len(calls) == 6
    assert calls[0][0] == [
        str(ansible),
        "-i",
        "ansible/inventory.ini",
        "homebase",
        "-m",
        "ansible.builtin.command",
        "-a",
        "curl -sS --connect-timeout 10 -x socks5h://proxy01:3333 https://ipv4.icanhazip.com",
    ]
    assert calls[1][0][-1] == (
        "curl -sS -L -o /dev/null -w %{http_code} --connect-timeout 10 --max-time 20 "
        "-x socks5h://proxy01:3333 https://ifconfig.me"
    )
    assert calls[2][0][-1] == (
        "curl -sS -L -o /dev/null -w %{http_code} --connect-timeout 10 --max-time 20 "
        "-x socks5h://proxy01:3333 https://www.google.com"
    )
    assert calls[3][0][-1] == (
        "curl -sS -L -o /dev/null -w %{http_code} --connect-timeout 10 --max-time 20 "
        "-x socks5h://proxy01:3333 https://www.cnn.com"
    )
    assert calls[4][0][-1] == (
        "curl -sS -L -o /dev/null -w %{http_code} --connect-timeout 10 --max-time 20 "
        "-x socks5h://proxy01:3333 https://www.amazon.com"
    )
    assert calls[5][0][-1] == (
        "curl -sS -L -o /dev/null -w %{http_code} --connect-timeout 10 --max-time 20 "
        "-x socks5h://proxy01:3333 https://www.facebook.com"
    )
    assert "[homebase]" in observed_inventory
    assert "homebase ansible_host=203.0.113.10 ansible_user=ubuntu" in observed_inventory
    assert "[selected_proxy]" not in observed_inventory
    assert "proxy01 ansible_host" not in observed_inventory
    assert "middle-zy01-chain-1 ansible_host" not in observed_inventory
    assert "edge-zy01-chain-1 ansible_host" not in observed_inventory

    saved_job = _saved_action(repository, "outbound_channel_validation")
    assert saved_job.action == "outbound_channel_validation"
    assert saved_job.status == "succeeded"
    assert [event.message for event in saved_job.events] == [
        "outbound channel validation workspace rendered",
        "outbound channel homebase validation started",
        "outbound channel validation succeeded",
    ]
    evidence = saved_job.events[-1].data["validationEvidence"]
    assert evidence["origin"] == "homebase"
    assert evidence["inventoryTargets"] == ["homebase"]
    assert evidence["expectedPublicIp"] == "172.236.225.137"
    assert evidence["observedPublicIp"] == "172.236.225.137"
    assert evidence["status"] == VALIDATION_SUCCESS_STATUS
    assert [probe["url"] for probe in evidence["httpProbes"]] == [
        "https://ifconfig.me",
        "https://www.google.com",
        "https://www.cnn.com",
        "https://www.amazon.com",
        "https://www.facebook.com",
    ]
    assert all(probe["ok"] for probe in evidence["httpProbes"])
    assert {probe["httpStatus"] for probe in evidence["httpProbes"]} == {"200"}
    updated_channel = saved_job.events[-1].data["outboundChannels"][0]
    assert updated_channel["status"] == VALIDATION_SUCCESS_STATUS
    assert updated_channel["validation"]["status"] == VALIDATION_SUCCESS_STATUS
    assert updated_channel["validation"]["checkedAt"]
    assert "artifacts" not in updated_channel


def test_validate_accepts_ansible_wrapped_remote_stdout(tmp_path, monkeypatch):
    ansible = _executable(tmp_path, "ansible")
    repository = _FakeJobRepository(_apply_prerequisite_jobs())

    def runner(command, cwd):
        if "%{http_code}" in command[-1]:
            return subprocess.CompletedProcess(command, 0, stdout="homebase | CHANGED | rc=0 >>\n200\n", stderr="")
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="homebase | CHANGED | rc=0 >>\n172.236.225.137\n",
            stderr="",
        )

    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda engagement_id: object())

    result = validate_outbound_channel(
        "eng-zy01",
        "chain-1",
        confirmation="validate-outbound-chain-1",
        repository=repository,
        runner=runner,
        env={"ANSIBLE_BIN": str(ansible), "PATH": ""},
        workspace_root=tmp_path,
    )

    assert result is not None
    assert result["status"] == VALIDATION_SUCCESS_STATUS
    evidence = _saved_action(repository, "outbound_channel_validation").events[-1].data["validationEvidence"]
    assert evidence["observedPublicIp"] == "172.236.225.137"
    assert evidence["observedOutput"] == "homebase | CHANGED | rc=0 >>\n172.236.225.137"


def test_validate_accepts_json_stdout_value(tmp_path, monkeypatch):
    ansible = _executable(tmp_path, "ansible")
    repository = _FakeJobRepository(_apply_prerequisite_jobs())

    def runner(command, cwd):
        if "%{http_code}" in command[-1]:
            return subprocess.CompletedProcess(command, 0, stdout='{"changed": true, "stdout": "200\\n"}', stderr="")
        return subprocess.CompletedProcess(
            command,
            0,
            stdout='{"changed": true, "stdout": "172.236.225.137\\n"}',
            stderr="",
        )

    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda engagement_id: object())

    result = validate_outbound_channel(
        "eng-zy01",
        "chain-1",
        confirmation="validate-outbound-chain-1",
        repository=repository,
        runner=runner,
        env={"ANSIBLE_BIN": str(ansible), "PATH": ""},
        workspace_root=tmp_path,
    )

    assert result is not None
    assert result["status"] == VALIDATION_SUCCESS_STATUS
    evidence = _saved_action(repository, "outbound_channel_validation").events[-1].data["validationEvidence"]
    assert evidence["observedPublicIp"] == "172.236.225.137"


def test_validate_normalizes_legacy_ifconfig_me_targets(tmp_path, monkeypatch):
    ansible = _executable(tmp_path, "ansible")
    channel = _channel_with_artifacts()
    channel["artifacts"]["validation"]["command"] = [
        "curl",
        "-sS",
        "-x",
        "socks5h://proxy01:3333",
        "ifconfig.me",
    ]
    repository = _FakeJobRepository(_apply_prerequisite_jobs([channel]))
    calls = []

    def runner(command, cwd):
        calls.append((command, cwd))
        if "%{http_code}" in command[-1]:
            return subprocess.CompletedProcess(command, 0, stdout="200\n", stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="172.236.225.137\n", stderr="")

    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda engagement_id: object())

    result = validate_outbound_channel(
        "eng-zy01",
        "chain-1",
        confirmation="validate-outbound-chain-1",
        repository=repository,
        runner=runner,
        env={"ANSIBLE_BIN": str(ansible), "PATH": ""},
        workspace_root=tmp_path,
    )

    assert result is not None
    assert result["status"] == VALIDATION_SUCCESS_STATUS
    assert calls[0][0][-1] == "curl -sS --connect-timeout 10 -x socks5h://proxy01:3333 https://ipv4.icanhazip.com"


def test_validate_warns_when_identity_matches_but_popular_site_probe_fails(tmp_path, monkeypatch):
    ansible = _executable(tmp_path, "ansible")
    repository = _FakeJobRepository(_apply_prerequisite_jobs())

    def runner(command, cwd):
        shell_display = command[-1]
        if "https://www.google.com" in shell_display:
            return subprocess.CompletedProcess(command, 7, stdout="", stderr="curl: (7) Couldn't connect to server")
        if "%{http_code}" in shell_display:
            return subprocess.CompletedProcess(command, 0, stdout="200\n", stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="172.236.225.137\n", stderr="")

    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda engagement_id: object())

    result = validate_outbound_channel(
        "eng-zy01",
        "chain-1",
        confirmation="validate-outbound-chain-1",
        repository=repository,
        runner=runner,
        env={"ANSIBLE_BIN": str(ansible), "PATH": ""},
        workspace_root=tmp_path,
    )

    assert result is not None
    assert result["status"] == VALIDATION_WARNING_STATUS
    saved_job = _saved_action(repository, "outbound_channel_validation")
    assert saved_job.status == "succeeded"
    evidence = saved_job.events[-1].data["validationEvidence"]
    assert evidence["observedPublicIp"] == "172.236.225.137"
    google_probe = next(probe for probe in evidence["httpProbes"] if probe["url"] == "https://www.google.com")
    assert google_probe["ok"] is False
    assert google_probe["commandResult"]["returncode"] == 7
    assert "auxiliary HTTP probes failed for https://www.google.com" in evidence["detail"]


def test_validate_warns_when_identity_matches_and_all_auxiliary_probes_fail(tmp_path, monkeypatch):
    ansible = _executable(tmp_path, "ansible")
    repository = _FakeJobRepository(_apply_prerequisite_jobs())

    def runner(command, cwd):
        shell_display = command[-1]
        if "%{http_code}" in shell_display:
            return subprocess.CompletedProcess(command, 7, stdout="", stderr="curl: (7) Couldn't connect")
        return subprocess.CompletedProcess(command, 0, stdout="172.236.225.137\n", stderr="")

    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda engagement_id: object())

    result = validate_outbound_channel(
        "eng-zy01",
        "chain-1",
        confirmation="validate-outbound-chain-1",
        repository=repository,
        runner=runner,
        env={"ANSIBLE_BIN": str(ansible), "PATH": ""},
        workspace_root=tmp_path,
    )

    assert result is not None and result["status"] == VALIDATION_WARNING_STATUS
    saved_job = _saved_action(repository, "outbound_channel_validation")
    evidence = saved_job.events[-1].data["validationEvidence"]
    assert saved_job.status == "succeeded"
    assert evidence["observedPublicIp"] == "172.236.225.137"
    assert len(evidence["httpProbes"]) == 5
    assert all(probe["ok"] is False for probe in evidence["httpProbes"])


def test_validate_does_not_accept_expected_ip_from_wrapper_noise(tmp_path, monkeypatch):
    ansible = _executable(tmp_path, "ansible")
    repository = _FakeJobRepository(_apply_prerequisite_jobs())

    def runner(command, cwd):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="homebase | CHANGED | expected=172.236.225.137 >>\n198.51.100.99\n",
            stderr="",
        )

    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda engagement_id: object())

    result = validate_outbound_channel(
        "eng-zy01",
        "chain-1",
        confirmation="validate-outbound-chain-1",
        repository=repository,
        runner=runner,
        env={"ANSIBLE_BIN": str(ansible), "PATH": ""},
        workspace_root=tmp_path,
    )

    assert result is not None
    assert result["status"] == VALIDATION_FAILED_STATUS
    evidence = repository.saved[-1].events[-1].data["validationEvidence"]
    assert evidence["observedPublicIp"] == "198.51.100.99"


def test_validate_records_failed_status_on_ip_mismatch(tmp_path, monkeypatch):
    ansible = _executable(tmp_path, "ansible")
    repository = _FakeJobRepository(_apply_prerequisite_jobs())

    def runner(command, cwd):
        return subprocess.CompletedProcess(command, 0, stdout="198.51.100.99\n", stderr="")

    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda engagement_id: object())

    result = validate_outbound_channel(
        "eng-zy01",
        "chain-1",
        confirmation="validate-outbound-chain-1",
        repository=repository,
        runner=runner,
        env={"ANSIBLE_BIN": str(ansible), "PATH": ""},
        workspace_root=tmp_path,
    )

    assert result is not None
    assert result["status"] == VALIDATION_FAILED_STATUS
    saved_job = _saved_action(repository, "outbound_channel_validation")
    assert saved_job.status == "failed"
    assert saved_job.events[-1].message == "outbound channel validation failed"
    evidence = saved_job.events[-1].data["validationEvidence"]
    assert evidence["expectedPublicIp"] == "172.236.225.137"
    assert evidence["observedPublicIp"] == "198.51.100.99"
    assert evidence["status"] == VALIDATION_FAILED_STATUS
    assert "Expected edge public IP 172.236.225.137" in evidence["detail"]
    assert saved_job.events[-1].data["outboundChannels"][0]["status"] == VALIDATION_FAILED_STATUS


def test_remove_requires_confirmation_before_job_or_command(monkeypatch):
    repository = _FakeJobRepository(_apply_prerequisite_jobs())
    calls = []
    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda engagement_id: object())

    with pytest.raises(OutboundChannelApplyValidationError) as exc:
        remove_outbound_channel(
            "eng-zy01",
            "chain-1",
            confirmation="wrong",
            repository=repository,
            runner=lambda command, cwd: calls.append((command, cwd)) or subprocess.CompletedProcess(command, 0, "", ""),
        )

    assert exc.value.errors == ["confirmation must be remove-outbound-chain-1"]
    assert calls == []
    assert repository.saved == []


def test_remove_runs_core_only_ansible_and_records_removed_channel(tmp_path, monkeypatch):
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    repository = _FakeJobRepository(_apply_prerequisite_jobs())
    calls = []
    observed_playbook = ""

    def runner(command, cwd):
        nonlocal observed_playbook
        calls.append((command, cwd))
        observed_playbook = (cwd / "ansible" / "remove_outbound_channel.yml").read_text(encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="remove ok", stderr="")

    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda engagement_id: object())

    result = remove_outbound_channel(
        "eng-zy01",
        "chain-1",
        confirmation="remove-outbound-chain-1",
        requested_by="operator",
        repository=repository,
        runner=runner,
        env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook), "PATH": ""},
        workspace_root=tmp_path,
    )

    assert result is not None
    assert result["status"] == "Removed"
    assert calls[0][0] == [
        str(ansible_playbook),
        "-i",
        "ansible/inventory.ini",
        "ansible/remove_outbound_channel.yml",
    ]
    assert "path: /opt/proxy01/oci-rx-socks5.conf" in observed_playbook
    assert "name: ssh-proxy-3333.service" in observed_playbook
    assert "path: /opt/ssh-proxy/keys/of02-sketch" not in observed_playbook
    assert "--dport 3333" in observed_playbook
    assert "middle-zy01-chain-1 ansible_host" not in observed_playbook
    assert "edge-zy01-chain-1 ansible_host" not in observed_playbook

    saved_job = _saved_action(repository, "outbound_channel_remove")
    assert saved_job.action == "outbound_channel_remove"
    assert saved_job.status == "succeeded"
    assert [event.message for event in saved_job.events] == [
        "outbound channel remove workspace rendered",
        "outbound channel Ansible remove started",
        "outbound channel Ansible remove succeeded",
    ]
    updated_channel = saved_job.events[-1].data["outboundChannels"][0]
    assert updated_channel["status"] == "Removed"
    assert "proxySketchKey" not in updated_channel["artifactTargets"]
    assert updated_channel["validation"]["status"] == "Removed"
    assert "Shared sketch key material was left in place" in updated_channel["validation"]["detail"]
    assert "artifacts" not in updated_channel


def test_remove_one_multi_edge_channel_preserves_sibling(tmp_path, monkeypatch):
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    repository = _FakeJobRepository(_apply_prerequisite_jobs(_multi_edge_channels()))

    def runner(command, cwd):
        return subprocess.CompletedProcess(command, 0, stdout="remove ok", stderr="")

    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda engagement_id: object())

    result = remove_outbound_channel(
        "eng-zy01",
        "chain-1-edge-02",
        confirmation="remove-outbound-chain-1-edge-02",
        requested_by="operator",
        repository=repository,
        runner=runner,
        env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook), "PATH": ""},
        workspace_root=tmp_path,
    )

    assert result is not None
    saved_job = _saved_action(repository, "outbound_channel_remove")
    updated_channels = saved_job.events[-1].data["outboundChannels"]
    assert [channel["channelId"] for channel in updated_channels] == ["chain-1-edge-01", "chain-1-edge-02"]
    assert updated_channels[0]["status"] == "Pending Proxy Configuration"
    assert updated_channels[0]["edge"] == "edge-zy01-us-sea-01"
    assert updated_channels[1]["status"] == "Removed"
    assert updated_channels[1]["edge"] == "edge-zy01-us-sea-02"
    assert updated_channels[1]["artifactTargets"]["proxySshConfig"] == "/opt/ssh-proxy/config-3334"


def test_validate_requires_validation_metadata(tmp_path, monkeypatch):
    ansible = _executable(tmp_path, "ansible")
    jobs = _apply_prerequisite_jobs()
    channel = jobs[1].events[0].data["outboundChannels"][0]
    del channel["artifacts"]["validation"]
    repository = _FakeJobRepository(jobs)
    monkeypatch.setattr("app.services.outbound_channel_apply.get_engagement", lambda engagement_id: object())

    with pytest.raises(OutboundChannelApplyValidationError) as exc:
        validate_outbound_channel(
            "eng-zy01",
            "chain-1",
            confirmation="validate-outbound-chain-1",
            repository=repository,
            runner=lambda command, cwd: subprocess.CompletedProcess(command, 0, "", ""),
            env={"ANSIBLE_BIN": str(ansible), "PATH": ""},
            workspace_root=tmp_path,
        )

    assert exc.value.errors == ["outbound artifact validation metadata is required"]
    assert repository.saved == []


def _artifacts(**overrides):
    artifacts = render_outbound_channel_artifacts(
        OutboundChannelArtifactSpec(
            engagement="of02",
            profile_name="oci-rx",
            proxy_id="proxy01",
            proxy_private_ip="192.168.2.11",
            socks_port=3333,
            middle_hostname="middle01-of02-prod",
            middle_ip="172.239.52.174",
            edge_hostname="edge-of02-prod-us-lax-01",
            edge_ip="172.236.225.137",
            expected_edge_public_ip="172.236.225.137",
        ),
        [
            CoreHost("homebase", "192.168.0.10"),
            CoreHost("proxy01", "192.168.2.11"),
            CoreHost("proxy02", "192.168.2.12"),
        ],
    )
    values = {
        "core_hosts": artifacts.core_hosts,
        "homebase_proxychains": artifacts.homebase_proxychains,
        "proxy_ssh_config": artifacts.proxy_ssh_config,
        "proxy_systemd_service": artifacts.proxy_systemd_service,
        "validation": artifacts.validation,
        "sketch_node_boundary": artifacts.sketch_node_boundary,
    }
    values.update(overrides)
    return OutboundChannelArtifacts(**values)


def _apply_prerequisite_jobs(outbound_channels=None):
    channels = outbound_channels or [_channel_with_artifacts()]
    return [
        StoredJobRun(
            id="job-core",
            action="pilot_standard_rti_guarded_execute",
            status="succeeded",
            target="oci-compartment:barragan-testing",
            target_type="oci_compartment",
            target_id="ocid1.compartment.oc1..testing",
            requested_by="operator",
            input={"engagementId": "eng-zy01"},
            artifact_refs=[],
            created_at="2026-06-04T12:00:00+00:00",
            started_at="2026-06-04T12:01:00+00:00",
            finished_at="2026-06-04T12:05:00+00:00",
            events=[
                JobEvent(
                    1,
                    "info",
                    "operator inspection ready",
                    {
                        "workspaceDir": "/var/tmp/barragan-core/job-core",
                        "connectionDetails": [
                            {
                                "role": "homebase",
                                "displayName": "homebase-zy01",
                                "publicIp": "203.0.113.10",
                                "privateIp": "192.168.0.10",
                                "sshUser": "ubuntu",
                            },
                            {
                                "role": "proxy01",
                                "displayName": "proxy01-zy01",
                                "publicIp": "203.0.113.11",
                                "privateIp": "192.168.2.11",
                                "sshUser": "ubuntu",
                            },
                        ]
                    },
                )
            ],
        ),
        StoredJobRun(
            id="job-outbound",
            action="linode_sketch_deploy",
            status="succeeded",
            target="engagement:eng-zy01",
            target_type="engagement",
            target_id="eng-zy01",
            requested_by="operator",
            input={"engagementId": "eng-zy01"},
            artifact_refs=[],
            created_at="2026-06-04T12:10:00+00:00",
            started_at="2026-06-04T12:11:00+00:00",
            finished_at="2026-06-04T12:15:00+00:00",
            events=[
                JobEvent(
                    1,
                    "info",
                    "pending outbound channel artifacts derived",
                    {"outboundChannels": channels},
                )
            ],
        ),
    ]


def _channel_with_artifacts():
    channel = {
        "chainId": "chain-1",
        "proxy": "proxy01",
        "middle": "middle-zy01-chain-1",
        "edge": "edge-zy01-chain-1",
        "status": "Pending Proxy Configuration",
        "artifacts": _artifacts().to_dict(),
    }
    return channel


def _multi_edge_channels():
    first = _channel_with_artifacts()
    first.update(
        {
            "channelId": "chain-1-edge-01",
            "chainId": "chain-1",
            "edge": "edge-zy01-us-sea-01",
            "edgeIndex": "1",
            "edgeCount": "2",
        }
    )
    first["artifacts"] = render_outbound_channel_artifacts(
        OutboundChannelArtifactSpec(
            engagement="zy01",
            profile_name="chain-1-edge-01",
            proxy_id="proxy01",
            proxy_private_ip="192.168.2.11",
            socks_port=3333,
            middle_hostname="middle-zy01-chain-1",
            middle_ip="172.239.52.174",
            edge_hostname="edge-zy01-us-sea-01",
            edge_ip="172.236.225.137",
            expected_edge_public_ip="172.236.225.137",
        ),
        [
            CoreHost("homebase", "192.168.0.10"),
            CoreHost("proxy01", "192.168.2.11"),
            CoreHost("proxy02", "192.168.2.12"),
        ],
    ).to_dict()
    second = _channel_with_artifacts()
    second.update(
        {
            "channelId": "chain-1-edge-02",
            "chainId": "chain-1",
            "edge": "edge-zy01-us-sea-02",
            "edgeIndex": "2",
            "edgeCount": "2",
        }
    )
    second["artifacts"] = render_outbound_channel_artifacts(
        OutboundChannelArtifactSpec(
            engagement="zy01",
            profile_name="chain-1-edge-02",
            proxy_id="proxy01",
            proxy_private_ip="192.168.2.11",
            socks_port=3334,
            middle_hostname="middle-zy01-chain-1",
            middle_ip="172.239.52.174",
            edge_hostname="edge-zy01-us-sea-02",
            edge_ip="172.236.225.138",
            expected_edge_public_ip="172.236.225.138",
        ),
        [
            CoreHost("homebase", "192.168.0.10"),
            CoreHost("proxy01", "192.168.2.11"),
            CoreHost("proxy02", "192.168.2.12"),
        ],
    ).to_dict()
    return [first, second]


def _executable(tmp_path, name):
    path = tmp_path / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


class _FakeJobRepository:
    def __init__(self, jobs):
        self.jobs = list(jobs)
        self.saved = []

    def list(self):
        return list(self.jobs)

    def list_for_engagement(self, engagement_id, *, limit=None):
        jobs = [job for job in self.list() if (
            job.target_id == engagement_id or job.target == f"engagement:{engagement_id}"
            or job.input.get("engagementId") == engagement_id
        )]
        jobs.sort(key=lambda job: job.created_at, reverse=True)
        return jobs if limit is None else jobs[:limit]

    def get(self, job_id):
        for job in self.jobs:
            if job.id == job_id:
                return job
        return None

    def save(self, job):
        self.jobs = [existing for existing in self.jobs if existing.id != job.id]
        self.jobs.insert(0, job)
        self.saved.append(job)
        return job


class _FakeChainRepository:
    def __init__(self, chain):
        self.chain = chain

    def get(self, engagement_id, chain_id):
        return self.chain


def _saved_action(repository: _FakeJobRepository, action: str) -> StoredJobRun:
    for job in reversed(repository.saved):
        if job.action == action:
            return job
    raise AssertionError(f"saved action not found: {action}")
