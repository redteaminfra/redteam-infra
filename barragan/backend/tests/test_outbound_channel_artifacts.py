# Copyright (c) 2026, Oracle and/or its affiliates.
import pytest

from app.services.outbound_channel_artifacts import (
    DEFAULT_SKETCH_OUTBOUND_PORT,
    CoreHost,
    OutboundChannelArtifactSpec,
    OutboundChannelArtifactValidationError,
    PENDING_PROXY_CONFIGURATION_STATUS,
    derive_pending_outbound_channel_from_sketch_rows,
    derive_pending_outbound_channels_from_sketch_rows,
    render_homebase_validation_command,
    render_outbound_channel_artifacts,
    render_sketch_node_opsec_boundary,
)


def test_renders_core_homebase_proxy_and_validation_artifacts():
    artifacts = render_outbound_channel_artifacts(_spec(), _core_hosts())

    assert artifacts.core_hosts.target == "/etc/hosts"
    assert "192.168.0.10 homebase-of02.infra.redteam homebase-of02 homebase" in artifacts.core_hosts.content
    assert "192.168.2.11 proxy01-of02.infra.redteam proxy01-of02 proxy01" in artifacts.core_hosts.content
    assert "192.168.2.12 proxy02-of02.infra.redteam proxy02-of02 proxy02" in artifacts.core_hosts.content

    assert artifacts.homebase_proxychains.target == "/opt/proxy01/oci-rx-socks5.conf"
    assert "strict_chain" in artifacts.homebase_proxychains.content
    assert "proxy_dns" in artifacts.homebase_proxychains.content
    assert "socks5 192.168.2.11 3333" in artifacts.homebase_proxychains.content

    assert artifacts.proxy_ssh_config.target == "/opt/ssh-proxy/config-3333"
    assert "Host middle01-of02-prod" in artifacts.proxy_ssh_config.content
    assert "    Hostname 172.239.52.174" in artifacts.proxy_ssh_config.content
    assert "Host edge-of02-prod-us-lax-01" in artifacts.proxy_ssh_config.content
    assert "    Hostname 172.236.225.137" in artifacts.proxy_ssh_config.content
    assert "    DynamicForward 0.0.0.0:3333" in artifacts.proxy_ssh_config.content
    assert "    ProxyJump middle01-of02-prod" in artifacts.proxy_ssh_config.content
    assert "    IdentityFile /opt/ssh-proxy/keys/of02-sketch" in artifacts.proxy_ssh_config.content
    assert "    User sketchssh" in artifacts.proxy_ssh_config.content
    assert artifacts.proxy_ssh_config.content.count("    UserKnownHostsFile /dev/null") == 2
    assert artifacts.proxy_ssh_config.content.count("    StrictHostKeyChecking no") == 2
    assert artifacts.proxy_ssh_config.content.count("    BatchMode yes") == 2
    assert "    RequestTTY no" in artifacts.proxy_ssh_config.content

    assert artifacts.proxy_systemd_service.target == "/etc/systemd/system/ssh-proxy-3333.service"
    assert "Description=ssh forward socks proxy for 3333 through middle01-of02-prod -> edge-of02-prod-us-lax-01" in artifacts.proxy_systemd_service.content
    assert "ExecStart=/usr/bin/autossh -M0 -F /opt/ssh-proxy/config-3333 -N edge-of02-prod-us-lax-01" in artifacts.proxy_systemd_service.content

    assert artifacts.validation.origin == "homebase"
    assert artifacts.validation.command == [
        "curl",
        "-sS",
        "--connect-timeout",
        "10",
        "-x",
        "socks5h://proxy01:3333",
        "https://ipv4.icanhazip.com",
    ]
    assert artifacts.validation.shell_display() == "curl -sS --connect-timeout 10 -x socks5h://proxy01:3333 https://ipv4.icanhazip.com"
    assert artifacts.validation.expected_public_ip == "172.236.225.137"


def test_sketch_node_opsec_boundary_renders_no_hosts_or_topology_to_middle_or_edge():
    artifacts = render_outbound_channel_artifacts(_spec(), _core_hosts())
    boundary = artifacts.sketch_node_boundary

    assert boundary.sketch_hosts_content is None
    assert boundary.middle_node_artifacts == []
    assert boundary.edge_node_artifacts == []
    assert "sketch nodes do not receive /etc/hosts enrichment" in boundary.reason

    artifact_dict = artifacts.to_dict()
    assert artifact_dict["sketchNodeBoundary"]["sketchHostsContent"] is None
    assert artifact_dict["sketchNodeBoundary"]["middleNodeArtifacts"] == []
    assert artifact_dict["sketchNodeBoundary"]["edgeNodeArtifacts"] == []


def test_validation_rejects_default_socks_port_for_named_sketch_profile():
    with pytest.raises(OutboundChannelArtifactValidationError) as exc:
        render_outbound_channel_artifacts(_spec(socks_port=1080), _core_hosts())

    assert "socks_port 1080 is reserved for default proxy egress" in exc.value.errors


def test_validation_rejects_invalid_proxy_id_and_tcp_port():
    with pytest.raises(OutboundChannelArtifactValidationError) as exc:
        render_outbound_channel_artifacts(_spec(proxy_id="proxy1", socks_port=70000), _core_hosts())

    assert "proxy_id must look like proxy01" in exc.value.errors
    assert "socks_port must be in the valid TCP range" in exc.value.errors


def test_validation_requires_core_hosts_and_required_ips_and_hostnames():
    with pytest.raises(OutboundChannelArtifactValidationError) as exc:
        render_outbound_channel_artifacts(
            _spec(middle_hostname="", edge_ip=""),
            [CoreHost("homebase", "192.168.0.10"), CoreHost("proxy01", "192.168.2.11")],
        )

    assert "middle_hostname is required" in exc.value.errors
    assert "edge_ip is required" in exc.value.errors
    assert "core host proxy02 is required" in exc.value.errors


def test_validation_rejects_duplicate_core_host_names():
    with pytest.raises(OutboundChannelArtifactValidationError) as exc:
        render_outbound_channel_artifacts(
            _spec(),
            [
                CoreHost("homebase", "192.168.0.10"),
                CoreHost("proxy01", "192.168.2.11"),
                CoreHost("proxy01", "192.168.2.12"),
                CoreHost("proxy02", "192.168.2.13"),
            ],
        )

    assert "core host proxy01 is duplicated" in exc.value.errors


def test_validation_rejects_core_hosts_with_conflicting_private_ips():
    with pytest.raises(OutboundChannelArtifactValidationError) as exc:
        render_outbound_channel_artifacts(
            _spec(),
            [
                CoreHost("homebase", "192.168.0.10"),
                CoreHost("proxy01", "192.168.2.11"),
                CoreHost("proxy02", "192.168.2.11"),
            ],
        )

    assert "core host IP 192.168.2.11 is assigned to both proxy01 and proxy02" in exc.value.errors


def test_returned_artifacts_do_not_include_private_key_material_or_provider_tokens():
    artifacts = render_outbound_channel_artifacts(_spec(), _core_hosts())
    rendered = "\n".join(
        [
            artifacts.core_hosts.content,
            artifacts.homebase_proxychains.content,
            artifacts.proxy_ssh_config.content,
            artifacts.proxy_systemd_service.content,
            artifacts.validation.shell_display(),
        ]
    )

    assert "BEGIN OPENSSH PRIVATE KEY" not in rendered
    assert "LINODE_TOKEN" not in rendered
    assert "OCI_CLI_AUTH" not in rendered
    assert "provider_token" not in rendered
    assert "/opt/ssh-proxy/keys/of02-sketch" in rendered


def test_individual_validation_command_renderer_uses_homebase_origin_and_proxy_alias():
    validation = render_homebase_validation_command(_spec(proxy_id="proxy02", socks_port=4336))

    assert validation.origin == "homebase"
    assert validation.shell_display() == "curl -sS --connect-timeout 10 -x socks5h://proxy02:4336 https://ipv4.icanhazip.com"
    assert validation.expected_public_ip == "172.236.225.137"


def test_named_profile_supports_operator_proxychains_validation_command():
    artifacts = render_outbound_channel_artifacts(
        _spec(profile_name="proxy01-sea-01", proxy_id="proxy01", proxy_private_ip="192.168.2.11", socks_port=3333),
        _core_hosts(),
    )

    operator_command = [
        "proxychains4",
        "-f",
        artifacts.homebase_proxychains.target,
        "curl",
        "-sS",
        "--connect-timeout",
        "10",
        "https://ipv4.icanhazip.com",
    ]

    assert artifacts.homebase_proxychains.target == "/opt/proxy01/proxy01-sea-01-socks5.conf"
    assert "socks5 192.168.2.11 3333" in artifacts.homebase_proxychains.content
    assert "1080" not in artifacts.homebase_proxychains.content
    assert "/opt/proxy01/proxychains.conf" not in artifacts.homebase_proxychains.target
    assert " ".join(operator_command) == (
        "proxychains4 -f /opt/proxy01/proxy01-sea-01-socks5.conf "
        "curl -sS --connect-timeout 10 https://ipv4.icanhazip.com"
    )


def test_sketch_boundary_can_be_rendered_explicitly_without_artifact_bundle():
    boundary = render_sketch_node_opsec_boundary()

    assert boundary.sketch_hosts_content is None
    assert boundary.middle_node_artifacts == []
    assert boundary.edge_node_artifacts == []


def test_derives_pending_outbound_channel_from_complete_sketch_rows():
    channel = derive_pending_outbound_channel_from_sketch_rows(
        "of02-dev",
        "chain-1",
        [
            {
                "chainId": "chain-1",
                "hostname": "middle-of02-dev-chain-1",
                "provider": "linode",
                "role": "middle",
                "publicIp": "203.0.113.10",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
            {
                "chainId": "chain-1",
                "hostname": "edge-of02-dev-us-sea-chain-1",
                "provider": "linode",
                "role": "edge",
                "publicIp": "203.0.113.20",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
        ],
    )

    assert channel is not None
    assert channel["chainId"] == "chain-1"
    assert channel["proxy"] == "proxy01"
    assert channel["middle"] == "middle-of02-dev-chain-1"
    assert channel["edge"] == "edge-of02-dev-us-sea-chain-1"
    assert channel["port"] == str(DEFAULT_SKETCH_OUTBOUND_PORT)
    assert channel["provider"] == "linode"
    assert channel["region"] == "us-sea"
    assert channel["status"] == PENDING_PROXY_CONFIGURATION_STATUS
    assert channel["profileName"] == "chain-1"
    assert channel["publicationPath"] == "/opt/proxy01/chain-1-socks5.conf"
    assert channel["validation"]["origin"] == "homebase"
    assert channel["validation"]["shellDisplay"] == "curl -sS --connect-timeout 10 -x socks5h://proxy01:3333 https://ipv4.icanhazip.com"
    assert channel["validation"]["expectedPublicIp"] == "203.0.113.20"
    assert channel["artifactTargets"] == {
        "homebaseProxychains": "/opt/proxy01/chain-1-socks5.conf",
        "proxySshConfig": "/opt/ssh-proxy/config-3333",
        "proxySystemdService": "/etc/systemd/system/ssh-proxy-3333.service",
    }
    assert "socks5 192.168.2.11 3333" in channel["artifacts"]["homebaseProxychains"]["content"]
    assert "Hostname 203.0.113.10" in channel["artifacts"]["proxySshConfig"]["content"]
    assert "Hostname 203.0.113.20" in channel["artifacts"]["proxySshConfig"]["content"]
    assert "DynamicForward 0.0.0.0:3333" in channel["artifacts"]["proxySshConfig"]["content"]
    assert "ExecStart=/usr/bin/autossh -M0 -F /opt/ssh-proxy/config-3333 -N edge-of02-dev-us-sea-chain-1" in channel["artifacts"]["proxySystemdService"]["content"]
    assert channel["artifacts"]["sketchNodeBoundary"]["middleNodeArtifacts"] == []
    assert channel["artifacts"]["sketchNodeBoundary"]["edgeNodeArtifacts"] == []
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(channel)
    assert "linode-token" not in str(channel)


def test_derives_one_outbound_channel_per_edge_for_multi_edge_chain():
    channels = derive_pending_outbound_channels_from_sketch_rows(
        "of02-dev",
        "chain-1",
        [
            {
                "chainId": "chain-1",
                "hostname": "middle-of02-dev-chain-1",
                "provider": "linode",
                "role": "middle",
                "publicIp": "203.0.113.10",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
            {
                "chainId": "chain-1",
                "hostname": "edge-of02-dev-us-sea-01",
                "edgeIndex": "1",
                "edgeCount": "2",
                "provider": "linode",
                "role": "edge",
                "publicIp": "203.0.113.20",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
            {
                "chainId": "chain-1",
                "hostname": "edge-of02-dev-us-sea-02",
                "edgeIndex": "2",
                "edgeCount": "2",
                "provider": "linode",
                "role": "edge",
                "publicIp": "203.0.113.21",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
        ],
    )

    assert [channel["channelId"] for channel in channels] == ["chain-1-edge-01", "chain-1-edge-02"]
    assert [channel["chainId"] for channel in channels] == ["chain-1", "chain-1"]
    assert [channel["edge"] for channel in channels] == ["edge-of02-dev-us-sea-01", "edge-of02-dev-us-sea-02"]
    assert [channel["port"] for channel in channels] == ["3333", "3334"]
    assert channels[0]["publicationPath"] == "/opt/proxy01/chain-1-edge-01-socks5.conf"
    assert channels[1]["publicationPath"] == "/opt/proxy01/chain-1-edge-02-socks5.conf"
    assert channels[0]["validation"]["expectedPublicIp"] == "203.0.113.20"
    assert channels[1]["validation"]["expectedPublicIp"] == "203.0.113.21"
    assert "DynamicForward 0.0.0.0:3334" in channels[1]["artifacts"]["proxySshConfig"]["content"]


def test_same_proxy_allocates_next_ports_after_existing_channels():
    channels = derive_pending_outbound_channels_from_sketch_rows(
        "of02-dev",
        "chain-2",
        [
            {
                "chainId": "chain-2",
                "hostname": "middle-of02-dev-chain-2",
                "provider": "linode",
                "role": "middle",
                "publicIp": "203.0.113.10",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
            {
                "chainId": "chain-2",
                "hostname": "edge-of02-dev-us-sea-chain-2",
                "provider": "linode",
                "role": "edge",
                "publicIp": "203.0.113.22",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
        ],
        existing_outbound_channels=[
            {"channelId": "chain-1-edge-01", "chainId": "chain-1", "proxy": "proxy01", "port": "3333"},
            {"channelId": "chain-1-edge-02", "chainId": "chain-1", "proxy": "proxy01", "port": "3334"},
        ],
    )

    assert [channel["channelId"] for channel in channels] == ["chain-2"]
    assert channels[0]["port"] == "3335"
    assert channels[0]["artifactTargets"]["proxySshConfig"] == "/opt/ssh-proxy/config-3335"
    assert "socks5h://proxy01:3335" in channels[0]["validation"]["shellDisplay"]


def test_undeployed_core_outbound_placeholder_does_not_reserve_first_port():
    channels = derive_pending_outbound_channels_from_sketch_rows(
        "test-05",
        "proxy01-sea-02",
        [
            {
                "chainId": "proxy01-sea-02",
                "hostname": "middle01-test-05",
                "provider": "linode",
                "role": "middle",
                "publicIp": "203.0.113.10",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
            {
                "chainId": "proxy01-sea-02",
                "hostname": "edge-test-05-us-sea-01",
                "edgeIndex": "1",
                "edgeCount": "2",
                "provider": "linode",
                "role": "edge",
                "publicIp": "203.0.113.20",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
            {
                "chainId": "proxy01-sea-02",
                "hostname": "edge-test-05-us-sea-02",
                "edgeIndex": "2",
                "edgeCount": "2",
                "provider": "linode",
                "role": "edge",
                "publicIp": "203.0.113.21",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
        ],
        existing_outbound_channels=[
            {
                "channelId": "chain-1",
                "chainId": "chain-1",
                "proxy": "proxy01",
                "middle": "Not Deployed",
                "edge": "Not Deployed",
                "port": "3333",
                "status": "Not Ready",
            }
        ],
    )

    assert [channel["channelId"] for channel in channels] == ["proxy01-sea-02-edge-01", "proxy01-sea-02-edge-02"]
    assert [channel["port"] for channel in channels] == ["3333", "3334"]


def test_pre_apply_pending_channel_rows_do_not_freeze_bad_port_assignment():
    channels = derive_pending_outbound_channels_from_sketch_rows(
        "test-05",
        "proxy01-sea-02",
        [
            {
                "chainId": "proxy01-sea-02",
                "hostname": "middle01-test-05",
                "provider": "linode",
                "role": "middle",
                "publicIp": "203.0.113.10",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
            {
                "chainId": "proxy01-sea-02",
                "hostname": "edge-test-05-us-sea-01",
                "edgeIndex": "1",
                "edgeCount": "2",
                "provider": "linode",
                "role": "edge",
                "publicIp": "203.0.113.20",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
            {
                "chainId": "proxy01-sea-02",
                "hostname": "edge-test-05-us-sea-02",
                "edgeIndex": "2",
                "edgeCount": "2",
                "provider": "linode",
                "role": "edge",
                "publicIp": "203.0.113.21",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
        ],
        existing_outbound_channels=[
            {
                "channelId": "proxy01-sea-02-edge-01",
                "chainId": "proxy01-sea-02",
                "proxy": "proxy01",
                "middle": "middle01-test-05",
                "edge": "edge-test-05-us-sea-01",
                "port": "3334",
                "status": "Pending Proxy Configuration",
            },
            {
                "channelId": "proxy01-sea-02-edge-02",
                "chainId": "proxy01-sea-02",
                "proxy": "proxy01",
                "middle": "middle01-test-05",
                "edge": "edge-test-05-us-sea-02",
                "port": "3335",
                "status": "Pending Proxy Configuration",
            },
        ],
    )

    assert [channel["port"] for channel in channels] == ["3333", "3334"]


def test_removed_channel_tombstones_older_port_assignment_when_collecting_history():
    from app.domain import JobEvent
    from app.storage.job_repository import StoredJobRun
    from app.services.outbound_channel_artifacts import collect_existing_outbound_channels_from_jobs

    newer_remove = StoredJobRun(
        id="job-remove",
        action="outbound_channel_remove",
        status="succeeded",
        target="engagement:eng-1",
        target_type="engagement",
        target_id="eng-1",
        requested_by="operator",
        input={"engagementId": "eng-1"},
        artifact_refs=[],
        created_at="2026-07-07T00:01:00+00:00",
        started_at=None,
        finished_at=None,
        events=[
            JobEvent(
                1,
                "info",
                "outbound channel removed",
                {"outboundChannels": [{"channelId": "chain-1-edge-01", "chainId": "chain-1", "status": "Removed"}]},
            )
        ],
    )
    older_apply = StoredJobRun(
        id="job-apply",
        action="outbound_channel_apply",
        status="succeeded",
        target="engagement:eng-1",
        target_type="engagement",
        target_id="eng-1",
        requested_by="operator",
        input={"engagementId": "eng-1"},
        artifact_refs=[],
        created_at="2026-07-07T00:00:00+00:00",
        started_at=None,
        finished_at=None,
        events=[
            JobEvent(
                1,
                "info",
                "outbound channel applied",
                {
                    "outboundChannels": [
                        {"channelId": "chain-1-edge-01", "chainId": "chain-1", "proxy": "proxy01", "port": "3333", "status": "Validated"}
                    ]
                },
            )
        ],
    )

    assert collect_existing_outbound_channels_from_jobs([newer_remove, older_apply], "eng-1") == []


def test_different_proxy_can_reuse_same_outbound_port():
    channels = derive_pending_outbound_channels_from_sketch_rows(
        "of02-dev",
        "proxy02-chain-1",
        [
            {
                "chainId": "proxy02-chain-1",
                "hostname": "middle-of02-dev-proxy02-chain-1",
                "provider": "digitalocean",
                "role": "middle",
                "publicIp": "203.0.113.30",
                "region": "sfo3",
                "proxy": "proxy02",
                "status": "deployed",
            },
            {
                "chainId": "proxy02-chain-1",
                "hostname": "edge-of02-dev-sfo3-proxy02-chain-1",
                "provider": "digitalocean",
                "role": "edge",
                "publicIp": "203.0.113.31",
                "region": "sfo3",
                "proxy": "proxy02",
                "status": "deployed",
            },
        ],
        existing_outbound_channels=[
            {"channelId": "chain-1", "chainId": "chain-1", "proxy": "proxy01", "port": "3333"},
            {"channelId": "chain-2", "chainId": "chain-2", "proxy": "proxy01", "port": "3334"},
        ],
    )

    assert [channel["channelId"] for channel in channels] == ["proxy02-chain-1"]
    assert channels[0]["port"] == "3333"
    assert channels[0]["artifactTargets"]["proxySshConfig"] == "/opt/ssh-proxy/config-3333"
    assert "socks5h://proxy02:3333" in channels[0]["validation"]["shellDisplay"]


def test_existing_channel_port_is_preserved_on_refresh():
    channels = derive_pending_outbound_channels_from_sketch_rows(
        "of02-dev",
        "chain-1",
        [
            {
                "chainId": "chain-1",
                "hostname": "middle-of02-dev-chain-1",
                "provider": "linode",
                "role": "middle",
                "publicIp": "203.0.113.10",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
            {
                "chainId": "chain-1",
                "hostname": "edge-of02-dev-us-sea-chain-1",
                "provider": "linode",
                "role": "edge",
                "publicIp": "203.0.113.20",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
        ],
        existing_outbound_channels=[
            {"channelId": "chain-1", "chainId": "chain-1", "proxy": "proxy01", "port": "3340"},
            {"channelId": "other-chain", "chainId": "other-chain", "proxy": "proxy01", "port": "3333"},
        ],
    )

    assert channels[0]["port"] == "3340"
    assert channels[0]["artifactTargets"]["proxySshConfig"] == "/opt/ssh-proxy/config-3340"


def test_standalone_chain_derivation_starts_at_first_available_proxy_port():
    channel = derive_pending_outbound_channel_from_sketch_rows(
        "of02-dev",
        "proxy02-chain-2",
        [
            {
                "chainId": "proxy02-chain-2",
                "hostname": "middle-of02-dev-proxy02-chain-2",
                "provider": "linode",
                "role": "middle",
                "publicIp": "203.0.113.10",
                "region": "us-sea",
                "proxy": "proxy02",
                "status": "deployed",
            },
            {
                "chainId": "proxy02-chain-2",
                "hostname": "edge-of02-dev-us-sea-proxy02-chain-2",
                "provider": "linode",
                "role": "edge",
                "publicIp": "203.0.113.20",
                "region": "us-sea",
                "proxy": "proxy02",
                "status": "deployed",
            },
        ],
    )

    assert channel is not None
    assert channel["port"] == "3333"
    assert channel["validation"]["shellDisplay"] == "curl -sS --connect-timeout 10 -x socks5h://proxy02:3333 https://ipv4.icanhazip.com"
    assert channel["artifactTargets"]["proxySshConfig"] == "/opt/ssh-proxy/config-3333"


def test_proxy02_first_chain_uses_first_socks_port_for_that_proxy():
    channel = derive_pending_outbound_channel_from_sketch_rows(
        "bg01",
        "proxy02-sea-01",
        [
            {
                "chainId": "proxy02-sea-01",
                "hostname": "middle-bg01-proxy02-sea-01",
                "provider": "digitalocean",
                "role": "middle",
                "publicIp": "203.0.113.40",
                "region": "sfo3",
                "proxy": "proxy02",
                "status": "deployed",
            },
            {
                "chainId": "proxy02-sea-01",
                "hostname": "edge-bg01-sfo3-proxy02-sea-01",
                "provider": "digitalocean",
                "role": "edge",
                "publicIp": "203.0.113.50",
                "region": "sfo3",
                "proxy": "proxy02",
                "status": "deployed",
            },
        ],
    )

    assert channel is not None
    assert channel["port"] == "3333"
    assert channel["validation"]["shellDisplay"] == "curl -sS --connect-timeout 10 -x socks5h://proxy02:3333 https://ipv4.icanhazip.com"
    assert channel["artifactTargets"]["proxySshConfig"] == "/opt/ssh-proxy/config-3333"


def test_pending_channels_slugify_human_engagement_name_for_rendered_artifacts():
    channels = derive_pending_outbound_channels_from_sketch_rows(
        "WI251 Uniform Regions",
        "proxy01-sfo3-01",
        [
            {
                "role": "middle",
                "hostname": "middle01-wi251-uniform-regions",
                "publicIp": "203.0.113.10",
                "proxy": "proxy01",
            },
            {
                "role": "edge",
                "hostname": "edge-wi251-uniform-regions-sfo3-01",
                "publicIp": "203.0.113.20",
                "proxy": "proxy01",
                "provider": "digitalocean",
                "region": "sfo3",
            },
        ],
    )

    assert len(channels) == 1
    artifacts = channels[0]["artifacts"]
    assert "/opt/ssh-proxy/keys/wi251-uniform-regions-sketch" in artifacts["proxySshConfig"]["content"]
    assert "proxy01-wi251-uniform-regions.infra.redteam" in artifacts["coreHosts"]["content"]


def test_does_not_derive_outbound_channel_from_incomplete_sketch_rows():
    channel = derive_pending_outbound_channel_from_sketch_rows(
        "of02-dev",
        "chain-1",
        [
            {
                "chainId": "chain-1",
                "hostname": "middle-of02-dev-chain-1",
                "provider": "linode",
                "role": "middle",
                "publicIp": "203.0.113.10",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
            {
                "chainId": "chain-1",
                "hostname": "edge-of02-dev-us-sea-chain-1",
                "provider": "linode",
                "role": "edge",
                "publicIp": "",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
        ],
    )

    assert channel is None


def _spec(**overrides):
    values = {
        "engagement": "of02",
        "profile_name": "oci-rx",
        "proxy_id": "proxy01",
        "proxy_private_ip": "192.168.2.11",
        "socks_port": 3333,
        "middle_hostname": "middle01-of02-prod",
        "middle_ip": "172.239.52.174",
        "edge_hostname": "edge-of02-prod-us-lax-01",
        "edge_ip": "172.236.225.137",
        "expected_edge_public_ip": "172.236.225.137",
    }
    values.update(overrides)
    return OutboundChannelArtifactSpec(**values)


def _core_hosts():
    return [
        CoreHost("proxy02", "192.168.2.12"),
        CoreHost("homebase", "192.168.0.10"),
        CoreHost("proxy01", "192.168.2.11"),
    ]
