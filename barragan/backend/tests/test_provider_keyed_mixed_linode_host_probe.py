# Copyright (c) 2026, Oracle and/or its affiliates.
"""Linode metadata observations remain diagnostic until a raw policy pin exists."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_mixed_linode_host_probe import (
    LinodeHostDiagnosticPrerequisite, LinodeHostProbeError, _parse_identity,
    probe_linode_host_identity, require_reviewed_linode_host_policy,
)
from test_provider_keyed_host_identity_probe import BOOT, _fixture


def _inputs(tmp_path, role="edge"):
    args = _fixture(tmp_path)
    args["ssh_spec"] = replace(args["ssh_spec"], edges=args["ssh_spec"].edges[:1], host_policies={
        name: {**policy, "sketch_firewall_v2_rules": []}
        for name, policy in args["ssh_spec"].host_policies.items()
        if name in {args["ssh_spec"].middle.name, args["ssh_spec"].edges[0].name}})
    manifest = args["manifest"]
    manifest["schema"] = "mixed-initial-host-binding-v1"
    for row in manifest["nodes"]:
        row["provider"] = "linode"
        row["hostname"] = row.pop("name")
        row["terraformAddress"] = row["terraformAddress"].replace(
            "digitalocean_droplet", "linode_instance")
        row["region"] = "us-east"
    target = next(row for row in manifest["nodes"] if row["role"] == role)
    manifest_sha = hashlib.sha256(json.dumps(
        manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    observations = []
    args.update(node=target, expected_image="linode/ubuntu24.04",
                manifest_sha256=manifest_sha,
                core_known_hosts_sha256=manifest["coreKnownHostsSha256"],
                fence=lambda: observations.append("fence"),
                scratch_intent_callback=lambda path: observations.append(("scratch", path)),
                intent_callback=lambda event: observations.append(("intent", event)),
                started_callback=lambda event: observations.append(("started", event)),
                heartbeat_callback=lambda event: observations.append(("heartbeat", event)),
                result_callback=lambda event: observations.append(("result", event)))
    args.pop("expected")
    args.pop("chain_id")
    return args, observations


def _metadata(node, predecessor):
    return json.dumps({"instance": {"id": int(node["providerInstanceId"]),
                                    "label": node["hostname"], "region": node["region"],
                                    "image": {"id": "linode/ubuntu24.04"}},
                       "hostname": node["hostname"], "boot_id": BOOT,
                       "ssh_connection": f"{predecessor} 40000 {node['publicIp']} 22"})


@pytest.mark.parametrize("role", ["middle", "edge"])
def test_routed_linode_identity_capture_is_diagnostic_only(tmp_path, role):
    args, events = _inputs(tmp_path, role)
    node = args["node"]
    predecessor = (args["ssh_spec"].proxy_egress_ip if role == "middle"
                   else args["ssh_spec"].middle.public_ip)

    def runner(command, *, scratch_path, provider_keyed_v2, env,
               intent_callback, started_callback, heartbeat_callback, result_callback):
        assert provider_keyed_v2 is True
        assert command[1] == "-F" and command[3] == f"barragan-bootstrap-user-{node['hostname']}"
        assert "169.254.169.254/v1/" in command[6]
        config = Path(command[2]).read_text()
        block = config.split(f"Host {command[3]}\n", 1)[1].split("\nHost ", 1)[0]
        assert ("ProxyJump barragan-bootstrap-proxy,barragan-bootstrap-user-middle-01"
                if role == "edge" else "ProxyJump barragan-bootstrap-proxy") in block
        assert "StrictHostKeyChecking yes" in block
        intent = CommandIntent("invocation-1", str(scratch_path), "a" * 64)
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 99))
        started_callback(started)
        heartbeat_callback(started)
        raw = _metadata(node, predecessor)
        result_callback(CommandAuditResult(started, 0, len(raw.encode()), 0, False, False))
        return CommandResult(started, 0, raw, "", False, False)

    result = probe_linode_host_identity(**{**args, "runner": runner})
    assert result.provider_instance_id == node["providerInstanceId"]
    assert result.ssh_connection == (predecessor, 40000, node["publicIp"], 22)
    assert [kind for kind, *_ in events if isinstance(kind, str) and kind in {
        "scratch", "intent", "started", "heartbeat", "result"}] == [
            "scratch", "intent", "started", "heartbeat", "result"]
    with pytest.raises(LinodeHostDiagnosticPrerequisite, match="independent review"):
        require_reviewed_linode_host_policy(result)


@pytest.mark.parametrize("change", [
    lambda data: data["instance"].update(id=67891),
    lambda data: data["instance"].update(region="us-west"),
    lambda data: data["instance"]["image"].update(id="linode/ubuntu22.04"),
    lambda data: data.update(ssh_connection="1.1.1.1 40000 203.0.113.20 22"),
])
def test_metadata_mismatch_is_not_identity(change, tmp_path):
    args, _ = _inputs(tmp_path)
    data = json.loads(_metadata(args["node"], args["ssh_spec"].middle.public_ip))
    change(data)
    with pytest.raises(ValueError):
        _parse_identity(json.dumps(data), expected=args["node"],
                        image=args["expected_image"],
                        predecessor=args["ssh_spec"].middle.public_ip)


def test_unbound_node_never_contacts_host(tmp_path):
    args, events = _inputs(tmp_path)
    calls = []
    args["node"] = {**args["node"], "providerInstanceId": "67891"}
    args["runner"] = lambda *_a, **_k: calls.append("contact")
    with pytest.raises(LinodeHostProbeError):
        probe_linode_host_identity(**args)
    assert calls == [] and events == []
