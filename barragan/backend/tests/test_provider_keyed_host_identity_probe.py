# Copyright (c) 2026, Oracle and/or its affiliates.
"""One-host strict identity observation with no SSH or metadata network calls."""

import hashlib
import io
import json
import os
import shlex
import signal
import stat
import subprocess
import sys
import builtins
import socket
import contextlib
import time
import threading
import urllib.request
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.provider_keyed_digitalocean_attachment import ExpectedDigitalOceanNode
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
    UnreapedGatedCommandError,
)
from app.services import provider_keyed_host_identity_probe as probe_module
from app.services.provider_keyed_host_identity_probe import (
    DigitalOceanRawFirewallEvidence, DigitalOceanRawHostCollection,
    _FIREWALL_COMMANDS, _FIREWALL_REMOTE_SCRIPT, _HOST_SURFACE_SCRIPT,
    _FIREWALL_OPTIONAL_FILES,
    ProviderKeyedHostIdentityCleanupUnprovedError, ProviderKeyedHostIdentityProbeError,
    _REMOTE_SCRIPT, collect_digitalocean_edge_firewall_evidence,
    collect_digitalocean_middle_firewall_evidence,
    collect_digitalocean_middle_host_evidence, collect_digitalocean_edge_host_evidence,
    probe_digitalocean_edge_identity, probe_digitalocean_middle_identity,
)
from app.services.sketch_bootstrap import SketchBootstrapCoreHost
from test_sketch_bootstrap import _v2_spec


BOOT = "3f690ec1-f65f-48ae-8550-2be994d60e39"


def _fake_proc_stat(pid, *, group=919191, state="Z", start=42):
    tail = [state, "0", str(group), *(["0"] * 16), str(start)]
    return f"{pid} (fixed reader) " + " ".join(tail)


def _fixture(tmp_path):
    core = tmp_path / "core-known-hosts"
    sketch = tmp_path / "sketch-known-hosts"
    host_key = tmp_path / "fixture-host-key"
    subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)],
                   check=True, capture_output=True)
    algorithm, encoded = host_key.with_suffix(".pub").read_text().split()[:2]
    core.write_text("".join(f"{alias} {algorithm} {encoded}\n"
                            for alias in ("10.0.0.10", "8.8.8.8")))
    sketch.write_text("".join(f"{alias} {algorithm} {encoded}\n"
                              for alias in ("barragan-bootstrap-sketch-middle-01",
                                            "barragan-bootstrap-sketch-edge-01")))
    core.chmod(0o644)
    sketch.chmod(0o600)
    spec = _v2_spec(
        proxy=SketchBootstrapCoreHost("proxy", "10.0.2.11", "ubuntu", "/run/keys/core", "8.8.8.8"),
        proxy_egress_ip="8.8.8.8",
        initial_sketch_known_hosts_path=str(sketch),
        pinned_core_known_hosts_path=str(core),
    )
    # The existing fixture builds policies for 192.0.2.10, so regenerate
    # only its middle predecessor to match this selected proxy.
    policies = {name: dict(policy) for name, policy in spec.host_policies.items()}
    policies[spec.middle.name]["sketch_firewall_v2_ssh_sources"] = ["8.8.8.8/32"]
    spec = replace(spec, host_policies=policies)
    expected = ExpectedDigitalOceanNode("digitalocean_droplet.edge[\"sfo3-01\"]", "12345",
                                        "edge-01", "sfo3", "203.0.113.20")
    manifest = {
        "schema": "provider-keyed-v2",
        "engagementId": "eng-opaque",
        "nodes": [
            {"chainId": "chain-1", "role": "middle", "name": spec.middle.name,
             "publicIp": spec.middle.public_ip, "region": "nyc3",
             "terraformAddress": 'digitalocean_droplet.middle["middle_01"]',
             "providerInstanceId": "67890"},
            {"chainId": "chain-1", "role": "edge", "name": expected.name,
             "publicIp": expected.public_ipv4, "region": expected.region,
             "terraformAddress": expected.address, "providerInstanceId": expected.droplet_id},
        ],
        "hostPolicies": [{"chainId": "chain-1", "proxyEgressIp": "8.8.8.8", "hosts": policies}],
        "coreKnownHostsPath": str(core),
        "coreKnownHostsSha256": hashlib.sha256(core.read_bytes()).hexdigest(),
        "sketchKnownHostsPath": str(sketch),
    }
    digest = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    executable = tmp_path / "fake-ssh"
    executable.write_text("no executable network use\n")
    executable.chmod(0o700)
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    scratch.chmod(0o700)
    def materialize(engagement_id, key_dir):
        assert engagement_id == "eng-opaque"
        key_dir.mkdir(mode=0o700)
        private = key_dir / "admin"
        public = key_dir / "admin.pub"
        private.write_text("test-private-key")
        public.write_text("test-public-key")
        private.chmod(0o600)
        public.chmod(0o600)
        return private, public
    return dict(manifest=manifest, manifest_sha256=digest, chain_id="chain-1", expected=expected,
                ssh_spec=spec, sketch_known_hosts_sha256=hashlib.sha256(sketch.read_bytes()).hexdigest(),
                reviewed_core_route={"homebasePublicIp": spec.homebase.host,
                                     "homebaseUser": spec.homebase.user,
                                     "proxyPrivateIp": spec.proxy.host,
                                     "proxyPublicIp": spec.proxy.host_key_alias,
                                     "proxyUser": spec.proxy.user,
                                     "coreSshKeyPath": spec.homebase.ssh_private_key_path},
                scratch_path=scratch, ssh_executable=executable,
                admin_key_materializer=materialize)


def _callbacks(events):
    return dict(
        fence=lambda: events.append("fence"),
        scratch_intent_callback=lambda value: events.append(("scratch", value)),
        intent_callback=lambda value: events.append(("intent", value)),
        started_callback=lambda value: events.append(("started", value)),
        heartbeat_callback=lambda value: events.append(("heartbeat", value)),
        result_callback=lambda value: events.append(("result", value)),
    )


def _fake_runner(*, metadata=None, alter=None, commands=None,
                 alias="barragan-bootstrap-user-edge-01"):
    def run(command, *, scratch_path, intent_callback, started_callback,
            heartbeat_callback, result_callback, provider_keyed_v2, env):
        assert provider_keyed_v2
        assert env["SHELL"] == "/bin/sh"
        if commands is not None:
            commands.append(command)
        config = Path(command[2]).read_text()
        assert command[1] == "-F" and command[3] == alias
        assert command[4:6] == ["python3", "-c"]
        assert "169.254.169.254/metadata/v1/" in command[6]
        selected_block = config.split(f"Host {alias}\n", 1)[1].split("\nHost ", 1)[0]
        assert ("HostName 203.0.113.20" if alias.endswith("edge-01")
                else "HostName 198.51.100.10") in selected_block
        assert str(scratch_path / "keys" / "admin") in config
        if alias.endswith("edge-01"):
            assert "ProxyJump barragan-bootstrap-proxy,barragan-bootstrap-user-middle-01" in selected_block
        else:
            assert "ProxyJump barragan-bootstrap-proxy" in selected_block
            assert "ProxyJump barragan-bootstrap-proxy," not in selected_block
            effective = subprocess.run(
                ["/usr/bin/ssh", "-G", "-F", str(command[2]), alias],
                capture_output=True, text=True, check=True,
            ).stdout.lower()
            assert "proxyjump barragan-bootstrap-proxy\n" in effective
            assert "stricthostkeychecking true\n" in effective
            assert "controlmaster false\n" in effective
        assert config.count("StrictHostKeyChecking yes") == 8
        assert "StrictHostKeyChecking accept-new" not in config
        assert config.count("ControlMaster no") == 8
        assert config.count("ControlPersist no") == 8
        assert config.count("ServerAliveInterval 10") == 8
        assert config.count("ServerAliveCountMax 3") == 8
        intent = CommandIntent("probe-1", str(scratch_path), "opaque-digest")
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity("test-boot", 4321, 4321, 1))
        started_callback(started)
        heartbeat_callback(started)
        if alter:
            alter()
        result_callback(CommandAuditResult(started, 0, 100, 0, False, False))
        observation = metadata or {"id": "12345", "region": "sfo3", "public_ipv4": "203.0.113.20",
                                   "hostname": "edge-01", "boot_id": BOOT}
        return CommandResult(started, 0, json.dumps(observation), "", False, False)
    return run


def _middle_inputs(tmp_path):
    inputs = _fixture(tmp_path)
    inputs["expected"] = ExpectedDigitalOceanNode(
        'digitalocean_droplet.middle["middle_01"]', "67890", "middle-01",
        "nyc3", "198.51.100.10",
    )
    inputs["manifest_sha256"] = hashlib.sha256(json.dumps(
        inputs["manifest"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return inputs


def test_strict_middle_probe_stops_at_selected_middle_and_binds_metadata(tmp_path):
    inputs = _middle_inputs(tmp_path)
    sketch_path = Path(inputs["ssh_spec"].initial_sketch_known_hosts_path)
    sketch_path.write_text("".join(line for line in sketch_path.read_text().splitlines(keepends=True)
                                   if line.startswith("barragan-bootstrap-sketch-middle-01 ")))
    inputs["sketch_known_hosts_sha256"] = hashlib.sha256(sketch_path.read_bytes()).hexdigest()
    events = []
    commands = []
    observation = {"id": "67890", "region": "nyc3", "public_ipv4": "198.51.100.10",
                   "hostname": "middle-01", "boot_id": BOOT}
    evidence = probe_digitalocean_middle_identity(
        **inputs, **_callbacks(events), runner=_fake_runner(
            metadata=observation, alias="barragan-bootstrap-user-middle-01",
            commands=commands,
        ),
    )
    assert evidence.terraform_address == inputs["expected"].address
    assert evidence.provider_instance_id == "67890" and evidence.region == "nyc3"
    assert evidence.ssh_alias == "barragan-bootstrap-user-middle-01"
    assert len(commands) == 1 and "198.51.100.10" not in commands[0][:4]
    assert [item[0] for item in events if isinstance(item, tuple)] == [
        "scratch", "intent", "started", "heartbeat", "result"]
    assert not (inputs["scratch_path"] / "keys").exists()


def test_middle_probe_requires_its_preexisting_host_pin(tmp_path):
    inputs = _middle_inputs(tmp_path)
    sketch = Path(inputs["ssh_spec"].initial_sketch_known_hosts_path)
    sketch.write_text(sketch.read_text().replace("barragan-bootstrap-sketch-middle-01", "other"))
    inputs["sketch_known_hosts_sha256"] = hashlib.sha256(sketch.read_bytes()).hexdigest()
    commands = []
    with pytest.raises(ProviderKeyedHostIdentityProbeError):
        probe_digitalocean_middle_identity(
            **inputs, **_callbacks([]), runner=_fake_runner(
                alias="barragan-bootstrap-user-middle-01", commands=commands,
            ),
        )
    assert commands == []


@pytest.mark.parametrize("swap", ["edge_expected", "edge_role", "middle_alias", "middle_identity"])
def test_middle_probe_rejects_role_or_alias_swap_before_contact(tmp_path, swap):
    inputs = _middle_inputs(tmp_path)
    if swap == "edge_expected":
        inputs["expected"] = ExpectedDigitalOceanNode(
            'digitalocean_droplet.edge["sfo3-01"]', "12345", "edge-01", "sfo3", "203.0.113.20")
    elif swap == "edge_role":
        inputs["manifest"]["nodes"][0]["role"] = "edge"
    elif swap == "middle_alias":
        inputs["ssh_spec"] = replace(inputs["ssh_spec"], middle=replace(
            inputs["ssh_spec"].middle, name="edge-01"))
    else:
        inputs["manifest"]["nodes"][0]["providerInstanceId"] = "12345"
    inputs["manifest_sha256"] = hashlib.sha256(json.dumps(
        inputs["manifest"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    commands = []
    with pytest.raises(ProviderKeyedHostIdentityProbeError):
        probe_digitalocean_middle_identity(
            **inputs, **_callbacks([]), runner=_fake_runner(
                alias="barragan-bootstrap-user-middle-01", commands=commands,
            ),
        )
    assert commands == []


def test_strict_probe_binds_selected_alias_metadata_and_unchanged_trust(tmp_path):
    inputs = _fixture(tmp_path)
    events = []
    commands = []
    original_materialize = inputs["admin_key_materializer"]
    def materialize_after_audit(engagement_id, key_dir):
        assert any(isinstance(item, tuple) and item[0] == "scratch"
                   and item[1].scratch_path == str(inputs["scratch_path"]) for item in events)
        return original_materialize(engagement_id, key_dir)
    inputs["admin_key_materializer"] = materialize_after_audit
    evidence = probe_digitalocean_edge_identity(
        **inputs, **_callbacks(events), runner=_fake_runner(commands=commands),
    )
    assert evidence.provider_instance_id == "12345" and evidence.boot_id == BOOT
    assert evidence.ssh_alias == "barragan-bootstrap-user-edge-01"
    assert evidence.manifest_sha256 == inputs["manifest_sha256"]
    assert len(commands) == 1 and "203.0.113.20" not in commands[0][:4]
    assert [item[0] for item in events if isinstance(item, tuple)] == [
        "scratch", "intent", "started", "heartbeat", "result"]
    assert events.count("fence") >= 6
    assert not (inputs["scratch_path"] / "keys").exists()
    assert not list(inputs["scratch_path"].glob("identity-ssh-*.conf"))


@pytest.mark.parametrize("drift", ["id", "region", "public_ipv4", "hostname", "boot_id"])
def test_strict_probe_rejects_metadata_drift(tmp_path, drift):
    inputs = _fixture(tmp_path)
    observation = {"id": "12345", "region": "sfo3", "public_ipv4": "203.0.113.20",
                   "hostname": "edge-01", "boot_id": BOOT}
    observation[drift] = "different"
    with pytest.raises(ProviderKeyedHostIdentityProbeError):
        probe_digitalocean_edge_identity(**inputs, **_callbacks([]),
                                         runner=_fake_runner(metadata=observation))


@pytest.mark.parametrize("drift", ["manifest", "core_key", "sketch_key", "route"])
def test_strict_probe_rejects_binding_or_trust_drift_before_or_after_command(tmp_path, drift):
    inputs = _fixture(tmp_path)
    commands = []
    alter = None
    if drift == "manifest":
        inputs["manifest"]["schema"] = "changed"
    elif drift == "core_key":
        Path(inputs["ssh_spec"].pinned_core_known_hosts_path).write_text("different key\n")
    elif drift == "sketch_key":
        alter = lambda: Path(inputs["ssh_spec"].initial_sketch_known_hosts_path).write_text("changed key\n")
    else:
        inputs["manifest"]["nodes"][1]["publicIp"] = "203.0.113.99"
        inputs["manifest_sha256"] = hashlib.sha256(json.dumps(inputs["manifest"], sort_keys=True,
                                                          separators=(",", ":")).encode()).hexdigest()
    with pytest.raises(ProviderKeyedHostIdentityProbeError):
        probe_digitalocean_edge_identity(**inputs, **_callbacks([]),
                                         runner=_fake_runner(alter=alter, commands=commands))
    assert len(commands) == (1 if drift == "sketch_key" else 0)


def test_strict_probe_requires_selected_middle_and_edge_host_pins(tmp_path):
    inputs = _fixture(tmp_path)
    sketch = Path(inputs["ssh_spec"].initial_sketch_known_hosts_path)
    sketch.write_text(sketch.read_text().replace("barragan-bootstrap-sketch-middle-01", "other-middle"))
    inputs["sketch_known_hosts_sha256"] = hashlib.sha256(sketch.read_bytes()).hexdigest()
    commands = []
    with pytest.raises(ProviderKeyedHostIdentityProbeError):
        probe_digitalocean_edge_identity(**inputs, **_callbacks([]),
                                         runner=_fake_runner(commands=commands))
    assert commands == []


def test_unreaped_probe_retains_staged_key_and_config_for_manual_reconciliation(tmp_path):
    inputs = _fixture(tmp_path)
    def uncertain(_command, *, scratch_path, intent_callback, started_callback, **_kwargs):
        intent = CommandIntent("unreaped", str(scratch_path), "digest")
        intent_callback(intent)
        started_callback(StartedCommand(intent, ProcessIdentity("boot", 123, 123, 1)))
        raise UnreapedGatedCommandError("group identity unproved")
    with pytest.raises(UnreapedGatedCommandError):
        probe_digitalocean_edge_identity(**inputs, **_callbacks([]), runner=uncertain)
    assert (inputs["scratch_path"] / "keys/admin").exists()
    assert len(list(inputs["scratch_path"].glob("identity-ssh-*.conf"))) == 1


def test_proven_probe_cleanup_failure_is_distinct(tmp_path, monkeypatch):
    inputs = _fixture(tmp_path)
    original = probe_module.shutil.rmtree
    def fail_keys(path, *args, **kwargs):
        if Path(path).name == "keys":
            raise OSError("cleanup fixture")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(probe_module.shutil, "rmtree", fail_keys)
    with pytest.raises(ProviderKeyedHostIdentityCleanupUnprovedError):
        probe_digitalocean_edge_identity(**inputs, **_callbacks([]), runner=_fake_runner())
    assert (inputs["scratch_path"] / "keys/admin").exists()


@pytest.mark.parametrize("invalid", ["redirect", "oversized"])
def test_remote_metadata_script_rejects_redirect_or_oversized_body_without_network(
    monkeypatch, invalid,
):
    class Response:
        status = 200
        def __init__(self, url):
            self.url = url
            self.value = b"x" * 129 if invalid == "oversized" else b"12345"
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
        def geturl(self):
            return "http://other.invalid/" if invalid == "redirect" else self.url
        def read(self, size):
            part, self.value = self.value[:min(size, 3)], self.value[min(size, 3):]
            return part
    class Opener:
        def open(self, url, timeout):
            assert url.startswith("http://169.254.169.254/metadata/v1/") and timeout == 2
            return Response(url)
    def build_opener(*handlers):
        assert any(type(handler).__name__ == "NoRedirect" for handler in handlers)
        return Opener()
    original_open = builtins.open
    def guarded_open(path, *args, **kwargs):
        if path == "/proc/sys/kernel/random/boot_id":
            return io.StringIO(BOOT)
        return original_open(path, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(urllib.request, "build_opener", build_opener)
        patch.setattr(builtins, "open", guarded_open)
        patch.setattr(socket, "gethostname", lambda: "edge-01")
        with pytest.raises(ValueError):
            exec(_REMOTE_SCRIPT, {})


@pytest.mark.skipif(not Path("/proc/sys/kernel/random/boot_id").exists(),
                    reason="real gated fake-SSH test requires Linux /proc identity")
def test_linux_real_gated_runner_uses_fake_ssh_without_network(tmp_path):
    inputs = _fixture(tmp_path)
    observation = {"id": "12345", "region": "sfo3", "public_ipv4": "203.0.113.20",
                   "hostname": "edge-01", "boot_id": BOOT}
    executable = inputs["ssh_executable"]
    executable.write_text(f"#!{sys.executable}\nprint({json.dumps(json.dumps(observation))})\n")
    executable.chmod(0o700)
    events = []
    evidence = probe_digitalocean_edge_identity(**inputs, **_callbacks(events))
    assert evidence.provider_instance_id == "12345"
    assert [item[0] for item in events if isinstance(item, tuple)] == [
        "scratch", "intent", "started", "result"]
    assert not (inputs["scratch_path"] / "keys").exists()


@pytest.mark.skipif(not Path("/proc/sys/kernel/random/boot_id").exists(),
                    reason="real gated middle fake-SSH test requires Linux /proc identity")
def test_linux_real_gated_runner_middle_alias_uses_fake_ssh_without_network(tmp_path):
    inputs = _middle_inputs(tmp_path)
    observation = {"id": "67890", "region": "nyc3", "public_ipv4": "198.51.100.10",
                   "hostname": "middle-01", "boot_id": BOOT}
    executable = inputs["ssh_executable"]
    executable.write_text(f"#!{sys.executable}\nprint({json.dumps(json.dumps(observation))})\n")
    executable.chmod(0o700)
    events = []
    evidence = probe_digitalocean_middle_identity(**inputs, **_callbacks(events))
    assert evidence.provider_instance_id == "67890"
    assert evidence.ssh_alias == "barragan-bootstrap-user-middle-01"
    assert [item[0] for item in events if isinstance(item, tuple)] == [
        "scratch", "intent", "started", "result"]
    assert not (inputs["scratch_path"] / "keys").exists()


def _firewall_runner(*, bad_name=None, failure=None, reboot=False, command_log=None,
                     alias="barragan-bootstrap-user-edge-01", metadata=None):
    counter = 0
    def run(command, *, scratch_path, intent_callback, started_callback,
            heartbeat_callback, result_callback, provider_keyed_v2, **kwargs):
        nonlocal counter
        assert provider_keyed_v2
        assert kwargs.pop("env")["SHELL"] == "/bin/sh"
        assert command[1:4] == ["-F", command[2], alias]
        remote = tuple(shlex.split(" ".join(command[4:])))
        if command_log is not None:
            command_log.append(remote)
        counter += 1
        if remote[0] == "python3":
            output = json.dumps(metadata or {"id": "12345", "region": "sfo3",
                                             "public_ipv4": "203.0.113.20",
                                             "hostname": "edge-01", "boot_id": BOOT})
        else:
            assert remote[:6] == ("/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-B", "-c")
            assert remote[6] == _FIREWALL_REMOTE_SCRIPT
            assert kwargs == {"max_output_bytes": 1048576}
            rows = [[name, f"observed {name}\n"] for name, _ in _FIREWALL_COMMANDS]
            if bad_name is not None and failure in {"oversized", "empty", "lossy"}:
                next(row for row in rows if row[0] == bad_name)[1] = (
                    "x" * 65537 if failure == "oversized" else
                    "\ufffd" if failure == "lossy" else "")
            if failure == "total":
                for row in rows:
                    row[1] = "x" * 20000
            if failure == "missing":
                rows.pop()
            files = [[name, path, "present", f"observed {name}\n", 0, 0, 0o644]
                     for name, path in _FIREWALL_OPTIONAL_FILES]
            if failure == "absent":
                files[0][2:] = ["absent", None, None, None, None]
            if failure == "missing_optional":
                files.pop()
            if failure == "oversized_optional":
                files[0][3] = "x" * 65537
            if failure == "malformed_optional":
                files[0][2:] = ["absent", "hidden content", None, None, None]
            if failure == "malformed_owner":
                files[0][4] = True
            if failure == "malformed_mode":
                files[0][6] = 0o10000
            if failure == "nonroot":
                files[0][4] = 1234
            output = json.dumps({"boot_id": "00000000-0000-4000-8000-000000000001"
                                 if reboot else BOOT,
                                 "started_at_ns": 1_000_000_000,
                                 "completed_at_ns": 301_100_000_000 if failure == "time_jump"
                                 else 1_100_000_000,
                                 "commands": rows, "files": files})
        intent = CommandIntent(f"firewall-{counter}", str(scratch_path), f"digest-{counter}")
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity("test-boot", 4321, 4321, counter))
        started_callback(started)
        heartbeat_callback(started)
        if failure == "unreaped" and counter == 2:
            raise UnreapedGatedCommandError("group identity unproved")
        stderr = "sudo: error" if failure == "stderr" and counter == 2 else ""
        truncated = failure == "truncated" and counter == 2
        returncode = 1 if failure == "nonzero" and counter == 2 else 0
        result_callback(CommandAuditResult(started, returncode, len(output.encode()),
                                           len(stderr.encode()), truncated, False))
        return CommandResult(started, returncode, output, stderr, truncated, False)
    return run


def _host_collection_runner(*, changed_firewall=False, counter_drift=False,
                            iptables_policy_changed=False, nft_policy_changed=False,
                            bad_surface=False, long_collection=False,
                            alias="barragan-bootstrap-user-edge-01", metadata=None,
                            commands=None, connection=None, surface_payload=None):
    calls = 0
    def run(command, *, scratch_path, intent_callback, started_callback,
            heartbeat_callback, result_callback, provider_keyed_v2, **kwargs):
        nonlocal calls
        assert provider_keyed_v2
        assert kwargs.pop("env")["SHELL"] == "/bin/sh"
        calls += 1
        remote = tuple(shlex.split(" ".join(command[4:])))
        if commands is not None:
            commands.append(remote)
        assert command[3] == alias
        if calls == 1:
            assert remote[:2] == ("python3", "-c")
            output = json.dumps(metadata or {"id": "12345", "region": "sfo3",
                "public_ipv4": "203.0.113.20", "hostname": "edge-01", "boot_id": BOOT})
        elif calls in (2, 4):
            assert remote[:6] == ("/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-B", "-c")
            assert remote[6] == _FIREWALL_REMOTE_SCRIPT
            assert kwargs == {"max_output_bytes": 1048576}
            rows = [[name, f"observed {name}\n"] for name, _ in _FIREWALL_COMMANDS]
            if changed_firewall and calls == 4:
                rows[0][1] = "changed effective traversal\n"
            if counter_drift:
                for row in rows:
                    if row[0] in {"iptables_save", "ip6tables_save"}:
                        count = 2 if calls == 4 else 1
                        row[1] = (f"# Generated by {row[0]} on observation {count}\n"
                                  f":INPUT DROP [{count}:{count * 60}]\n"
                                  f"-A INPUT -j {'ACCEPT' if iptables_policy_changed and calls == 4 else 'DROP'}\n"
                                  f"# Completed on observation {count}\n")
                    elif row[0] == "nft_ruleset":
                        row[1] = json.dumps({"nftables": [{"rule": {"expr": [
                            {"counter": {"packets": 2 if calls == 4 else 1,
                                         "bytes": 120 if calls == 4 else 60}},
                            {"drop" if nft_policy_changed and calls == 4 else "accept": None},
                        ]}}]})
            files = [[name, path, "present", f"observed {name}\n", 0, 0, 0o644]
                     for name, path in _FIREWALL_OPTIONAL_FILES]
            start = (1_000_000_000 if calls == 2 else
                     302_000_000_000 if long_collection else 1_400_000_000)
            output = json.dumps({"boot_id": BOOT, "started_at_ns": start,
                                 "completed_at_ns": start + 100_000_000,
                                 "commands": rows, "files": files})
        else:
            assert calls == 3 and remote[:6] == (
                "/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-B", "-c")
            assert remote[6] == _HOST_SURFACE_SCRIPT
            assert kwargs == {"max_output_bytes": 262144}
            predecessor = "8.8.8.8" if alias.endswith("middle-01") else "198.51.100.10"
            assert remote[7] == predecessor
            assert remote[8] == ("198.51.100.10" if alias.endswith("middle-01") else "203.0.113.20")
            assert remote[9] == "$SSH_CONNECTION"
            actual_connection = connection if connection is not None else [
                predecessor, 54321, remote[8], 22]
            output = json.dumps({"boot_id": BOOT, "started_at_ns": 1_200_000_000,
                "completed_at_ns": 1_300_000_000, "predecessor_ipv4": predecessor,
                "ssh_connection": actual_connection,
                "accounts": [[name, "ssh-ed25519 AAAA fixture\n", 1000, 1000, 0o600]
                             for name in ("user", "sketchssh")],
                "effective_sshd": [[name, "passwordauthentication no\nusedns no\n"]
                                   for name in ("user", "sketchssh")],
                "alternate_authorized_keys_absent": ["user", "sketchssh"],
                "listeners": "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((sshd,pid=1,fd=3))\n"})
            if surface_payload is not None:
                output = json.dumps({**json.loads(output), **surface_payload})
            if bad_surface:
                output = output.replace('"sketchssh"', '"root"')
        intent = CommandIntent(f"host-{calls}", str(scratch_path), f"digest-{calls}")
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity("test-boot", 4321, 4321, calls))
        started_callback(started)
        heartbeat_callback(started)
        result_callback(CommandAuditResult(started, 0, len(output.encode()), 0, False, False))
        return CommandResult(started, 0, output, "", False, False)
    return run


@pytest.mark.parametrize("middle", [False, True])
def test_host_collection_brackets_raw_firewall_and_uses_selected_strict_route(tmp_path, middle):
    inputs = _middle_inputs(tmp_path) if middle else _fixture(tmp_path)
    if middle:
        sketch = Path(inputs["ssh_spec"].initial_sketch_known_hosts_path)
        sketch.write_text("".join(line for line in sketch.read_text().splitlines(keepends=True)
                                  if line.startswith("barragan-bootstrap-sketch-middle-01 ")))
        inputs["sketch_known_hosts_sha256"] = hashlib.sha256(sketch.read_bytes()).hexdigest()
    events, commands = [], []
    alias = "barragan-bootstrap-user-middle-01" if middle else "barragan-bootstrap-user-edge-01"
    metadata = ({"id": "67890", "region": "nyc3", "public_ipv4": "198.51.100.10",
                 "hostname": "middle-01", "boot_id": BOOT} if middle else None)
    collector = collect_digitalocean_middle_host_evidence if middle else collect_digitalocean_edge_host_evidence
    result = collector(**inputs, **_callbacks(events), runner=_host_collection_runner(
        alias=alias, metadata=metadata, commands=commands))
    assert isinstance(result, DigitalOceanRawHostCollection)
    assert result.policy_interpreted is False and result.surface.policy_interpreted is False
    assert result.firewall_before.commands == result.firewall_after.commands
    assert [row.name for row in result.firewall_before.commands] == [name for name, _ in _FIREWALL_COMMANDS]
    assert len(commands) == 4 and commands[1][6] == commands[3][6] == _FIREWALL_REMOTE_SCRIPT
    assert commands[2][6] == _HOST_SURFACE_SCRIPT
    assert result.surface.ssh_connection == (
        ("8.8.8.8" if middle else "198.51.100.10"), 54321,
        ("198.51.100.10" if middle else "203.0.113.20"), 22)
    assert result.surface.alternate_authorized_keys_absent == ("user", "sketchssh")
    assert "54321" not in repr(result.surface)
    assert "ssh-ed25519" not in repr(result)
    assert [item[0] for item in events if isinstance(item, tuple)].count("result") == 4
    assert not (inputs["scratch_path"] / "keys").exists()


def test_collected_versioned_payload_reaches_complete_ssh_interpreter(tmp_path, monkeypatch):
    from test_provider_keyed_host_surface_interpreter import _fixture as interpreted_fixture
    from test_provider_keyed_host_surface_interpreter import _versioned_proof
    from app.services.provider_keyed_host_surface_interpreter import interpret_digitalocean_host_surface

    fixture, _, admin, transport = interpreted_fixture(monkeypatch, role="edge")
    fixture = _versioned_proof(fixture)
    surface = fixture.surface
    payload = {
        "accounts": [list(row) for row in surface.accounts],
        "effective_sshd": [list(row) for row in surface.effective_sshd],
        "listeners": surface.listeners_raw,
        "ssh_proof_version": surface.ssh_proof_version,
        "ssh_proof": surface.ssh_proof,
    }
    collection = collect_digitalocean_edge_host_evidence(
        **_fixture(tmp_path), **_callbacks([]),
        runner=_host_collection_runner(surface_payload=payload))
    assert collection.surface.ssh_proof_version == 1
    assert collection.surface.ssh_proof["start_ticks"] == 5000
    result = interpret_digitalocean_host_surface(
        collection, expected_identity=collection.identity,
        expected_predecessor_ipv4="198.51.100.10", expected_role="edge",
        expected_admin_key_sha256=admin, expected_transport_key_sha256=transport,
        expected_policy={"sketch_firewall_v2_enabled": True,
                         "sketch_firewall_v2_ssh_sources": ["198.51.100.10/32"],
                         "sketch_firewall_v2_rules": []})
    assert result.complete_ssh_policy is True


def test_host_collection_accepts_counter_drift_but_preserves_raw_snapshots(tmp_path):
    inputs = _fixture(tmp_path)
    result = collect_digitalocean_edge_host_evidence(
        **inputs, **_callbacks([]), runner=_host_collection_runner(counter_drift=True))
    before = {row.name: row for row in result.firewall_before.commands}
    after = {row.name: row for row in result.firewall_after.commands}
    assert before["iptables_save"].raw_output != after["iptables_save"].raw_output
    assert before["nft_ruleset"].raw_output != after["nft_ruleset"].raw_output
    assert result.policy_interpreted is False


def test_host_collection_rejects_nft_policy_change_amid_counter_drift(tmp_path):
    inputs = _fixture(tmp_path)
    with pytest.raises(ProviderKeyedHostIdentityProbeError):
        collect_digitalocean_edge_host_evidence(
            **inputs, **_callbacks([]),
            runner=_host_collection_runner(counter_drift=True, nft_policy_changed=True))


def test_host_collection_rejects_iptables_policy_change_amid_counter_drift(tmp_path):
    inputs = _fixture(tmp_path)
    with pytest.raises(ProviderKeyedHostIdentityProbeError):
        collect_digitalocean_edge_host_evidence(
            **inputs, **_callbacks([]),
            runner=_host_collection_runner(counter_drift=True, iptables_policy_changed=True))


@pytest.mark.parametrize("failure", ["firewall_changed", "surface_malformed", "long_collection"])
def test_host_collection_rejects_incomplete_or_changed_capture(tmp_path, failure):
    inputs = _fixture(tmp_path)
    with pytest.raises(ProviderKeyedHostIdentityProbeError):
        collect_digitalocean_edge_host_evidence(
            **inputs, **_callbacks([]), runner=_host_collection_runner(
                changed_firewall=failure == "firewall_changed",
                bad_surface=failure == "surface_malformed",
                long_collection=failure == "long_collection"),
        )


def test_middle_host_collection_rejects_proxy_egress_route_mismatch(tmp_path):
    inputs = _middle_inputs(tmp_path)
    spec = inputs["ssh_spec"]
    inputs["ssh_spec"] = replace(spec, proxy_egress_ip="9.9.9.9")
    with pytest.raises(ProviderKeyedHostIdentityProbeError):
        collect_digitalocean_middle_host_evidence(
            **inputs, **_callbacks([]), runner=_host_collection_runner(
                alias="barragan-bootstrap-user-middle-01"),
        )


@pytest.mark.parametrize("connection", [
    [], ["198.51.100.10", 54321, "203.0.113.20"],
    ["203.0.113.99", 54321, "203.0.113.20", 22],
    ["198.51.100.10", 54321, "203.0.113.99", 22],
    ["198.51.100.10", 54321, "203.0.113.20", 2222],
    ["198.51.100.10", "54321", "203.0.113.20", 22],
])
def test_host_collection_rejects_missing_or_changed_ssh_connection(tmp_path, connection):
    inputs = _fixture(tmp_path)
    with pytest.raises(ProviderKeyedHostIdentityProbeError):
        collect_digitalocean_edge_host_evidence(
            **inputs, **_callbacks([]), runner=_host_collection_runner(connection=connection))


@pytest.mark.parametrize("connection", [
    "", "198.51.100.10 54321 203.0.113.20",
    "203.0.113.99 54321 203.0.113.20 22",
    "198.51.100.10 54321 203.0.113.99 22",
    "198.51.100.10 54321 203.0.113.20 2222",
    "198.51.100.10 +54321 203.0.113.20 22",
    "198.51.100.10 54321 203.0.113.20 22 extra",
])
def test_remote_host_surface_rejects_missing_or_forged_session_before_reads(
        monkeypatch, connection):
    monkeypatch.setattr(sys, "argv", ["-c", "198.51.100.10", "203.0.113.20", connection])
    with pytest.raises(ValueError, match="SSH connection"):
        exec(compile(_HOST_SURFACE_SCRIPT, "<remote-host-surface>", "exec"), {"__name__": "__main__"})


def _surface_script_with_stubbed_daemon():
    """Keep older account/Match tests focused; daemon proof has separate tests."""
    return (_HOST_SURFACE_SCRIPT
            .replace("daemon_before = daemon()", "daemon_before = {'fixture': True}")
            .replace("daemon_after = daemon()", "daemon_after = {'fixture': True}"))


def _remote_surface_functions(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["-c", "198.51.100.10", "203.0.113.20",
        "198.51.100.10 54321 203.0.113.20 22"])
    namespace = {"__name__": "__main__"}
    prefix = _HOST_SURFACE_SCRIPT.split("first_boot, started = boot(), time.time_ns()", 1)[0]
    exec(compile(prefix, "<remote-host-functions>", "exec"), namespace)
    return namespace


@pytest.mark.parametrize("root,included", [
    ("Include /tmp/other.conf\n", "PasswordAuthentication no\n"),
    ("Include /etc/ssh/sshd_config.d/*.conf\n", "Match RDomain corp\n"),
    ("Include /etc/ssh/sshd_config.d/*.conf\n", "Include /tmp/other.conf\n"),
])
def test_remote_configuration_rejects_unknown_include_or_rdomain(monkeypatch, root, included):
    namespace = _remote_surface_functions(monkeypatch)
    namespace["private_file"] = lambda path, limit=65536, with_changed_ns=False: [
        root if path == "/etc/ssh/sshd_config" else included, 100_000_000_000]
    monkeypatch.setattr(namespace["glob"], "glob", lambda pattern: [
        "/etc/ssh/sshd_config.d/90-barragan-sketch-forwarding.conf"])
    with pytest.raises(ValueError, match="Include|RDomain"):
        namespace["configuration"]()


def test_remote_configuration_bounds_real_include_graph(monkeypatch):
    namespace = _remote_surface_functions(monkeypatch)
    root = "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n"
    include = "/etc/ssh/sshd_config.d/90-barragan-sketch-forwarding.conf"
    namespace["private_file"] = lambda path, limit=65536, with_changed_ns=False: [
        root if path == "/etc/ssh/sshd_config" else "Match User sketchssh\n", 100_000_000_000]
    monkeypatch.setattr(namespace["glob"], "glob", lambda pattern: [include])
    assert namespace["configuration"]() == [
        ["/etc/ssh/sshd_config", root, 100_000_000_000],
        [include, "Match User sketchssh\n", 100_000_000_000]]


@pytest.mark.parametrize("environment_changed_ns", [100_000_000_000, 222_000_000_000])
def test_remote_daemon_binds_service_pid_executable_and_config(monkeypatch, environment_changed_ns):
    namespace = _remote_surface_functions(monkeypatch)
    service = ("MainPID=10\nActiveState=active\nSubState=running\n"
        "ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $SSHD_OPTS ; }\n"
        "EnvironmentFiles=/etc/default/ssh\nEnvironment=\n"
        "FragmentPath=/usr/lib/systemd/system/ssh.service\nDropInPaths=\n")
    namespace["checked"] = lambda argv: (
        service if "ssh.service" in argv else "ActiveState=active\nListen=[::]:22 (Stream)\n")
    namespace["private_file"] = lambda path, limit=65536, with_changed_ns=False: [
        "SSHD_OPTS=\n" if path == "/etc/default/ssh" else "[Service]\n",
        environment_changed_ns if path == "/etc/default/ssh" else 100_000_000_000]
    namespace["configuration"] = lambda: [["/etc/ssh/sshd_config",
        "Include /etc/ssh/sshd_config.d/*.conf\n", 100_000_000_000]]
    namespace["private_directory"] = lambda path: [path, 100_000_000_000]
    original_open = builtins.open
    def fake_open(path, *args, **kwargs):
        if path == "/proc/10/stat":
            return io.StringIO("10 (sshd) " + " ".join(["S"] + ["0"] * 18 + ["12345"]))
        if path == "/proc/10/cmdline":
            return io.BytesIO(b"sshd -D [listener] 0 of 10-100 startups\x00")
        if path == "/proc/stat":
            return io.StringIO("btime 100\n")
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", fake_open)
    monkeypatch.setattr(os, "readlink", lambda path: "/usr/sbin/sshd")
    monkeypatch.setattr(os, "sysconf", lambda name: 100)
    if environment_changed_ns == 222_000_000_000:
        with pytest.raises(ValueError, match="predates loaded inputs"):
            namespace["daemon"]()
        return
    proof = namespace["daemon"]()
    assert proof["pid"] == 10 and proof["start_ticks"] == 12345
    assert proof["birth_wall_ns"] == 223_450_000_000
    assert proof["cmdline"] == ["sshd -D [listener] 0 of 10-100 startups"]
    assert proof["service"]["MainPID"] == "10"


def test_remote_surface_rejects_configuration_drift_across_effective_reads(tmp_path, monkeypatch):
    import pwd
    home = tmp_path / "home"
    keys = home / ".ssh"
    keys.mkdir(parents=True, mode=0o700)
    home.chmod(0o700)
    keys.chmod(0o700)
    primary = keys / "authorized_keys"
    primary.write_text("ssh-ed25519 AAAA fixture\n")
    primary.chmod(0o600)
    original_open = builtins.open
    monkeypatch.setattr(builtins, "open", lambda path, *args, **kwargs: (
        io.StringIO(BOOT) if path == "/proc/sys/kernel/random/boot_id"
        else original_open(path, *args, **kwargs)))
    monkeypatch.setattr(pwd, "getpwnam", lambda _: SimpleNamespace(
        pw_dir=str(home), pw_uid=os.getuid()))
    monkeypatch.setattr(sys, "argv", ["-c", "198.51.100.10", "203.0.113.20",
        "198.51.100.10 54321 203.0.113.20 22"])
    monkeypatch.setattr(subprocess, "run", lambda argv, **kwargs: SimpleNamespace(
        returncode=0, stderr=b"", stdout=(
            b"usedns no\npasswordauthentication no\n" if argv[0] == "/usr/sbin/sshd"
            else b"tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n")))
    script = (_HOST_SURFACE_SCRIPT
        .replace("daemon_before = daemon()", "daemon_before = {'configuration': 'before'}")
        .replace("daemon_after = daemon()", "daemon_after = {'configuration': 'after'}"))
    with pytest.raises(ValueError, match="SSH daemon or configuration changed"):
        exec(compile(script, "<remote-host-surface>", "exec"), {"__name__": "__main__"})


@pytest.mark.parametrize("usedns", ["no", "yes"])
def test_remote_host_surface_uses_actual_local_address_and_port_for_match(
        tmp_path, monkeypatch, usedns):
    import pwd

    home = tmp_path / "home"
    keys = home / ".ssh"
    keys.mkdir(parents=True, mode=0o700)
    home.chmod(0o700)
    keys.chmod(0o700)
    authorized_keys = keys / "authorized_keys"
    authorized_keys.write_text("ssh-ed25519 AAAA fixture\n")
    authorized_keys.chmod(0o600)
    original_open = builtins.open
    def fake_open(path, *args, **kwargs):
        if path == "/proc/sys/kernel/random/boot_id":
            return io.StringIO(BOOT)
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", fake_open)
    monkeypatch.setattr(pwd, "getpwnam", lambda _: SimpleNamespace(pw_dir=str(home), pw_uid=os.getuid()))
    monkeypatch.setattr(sys, "argv", ["-c", "198.51.100.10", "203.0.113.20",
                                          "198.51.100.10 54321 203.0.113.20 22"])
    calls = []
    def fake_run(argv, **kwargs):
        calls.append(argv)
        output = (f"usedns {usedns}\npasswordauthentication no\n" if argv[0] == "/usr/sbin/sshd"
                  else "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n")
        return SimpleNamespace(returncode=0, stderr=b"", stdout=output.encode())
    monkeypatch.setattr(subprocess, "run", fake_run)
    out = io.StringIO()
    if usedns == "yes":
        with pytest.raises(ValueError, match="Match Host"):
            with contextlib.redirect_stdout(out):
                exec(compile(_surface_script_with_stubbed_daemon(), "<remote-host-surface>", "exec"),
                     {"__name__": "__main__"})
        assert not out.getvalue()
    else:
        with contextlib.redirect_stdout(out):
            exec(compile(_surface_script_with_stubbed_daemon(), "<remote-host-surface>", "exec"),
                 {"__name__": "__main__"})
        assert json.loads(out.getvalue())["ssh_connection"] == [
            "198.51.100.10", 54321, "203.0.113.20", 22]
        assert len(calls) == 3
    assert calls[0] == ("/usr/sbin/sshd", "-T", "-C",
                        "user=user,addr=198.51.100.10,host=198.51.100.10,laddr=203.0.113.20,lport=22")


@pytest.mark.parametrize("alternate", ["regular", "symlink", "directory_changed"])
def test_remote_surface_rejects_alternate_authorized_key_or_parent_race(
        tmp_path, monkeypatch, alternate):
    import pwd

    home = tmp_path / "home"
    keys = home / ".ssh"
    keys.mkdir(parents=True, mode=0o700)
    home.chmod(0o700)
    keys.chmod(0o700)
    primary = keys / "authorized_keys"
    primary.write_text("ssh-ed25519 AAAA fixture\n")
    primary.chmod(0o600)
    second = keys / "authorized_keys2"
    if alternate == "regular":
        second.write_text("ssh-ed25519 BBBB fixture\n")
    elif alternate == "symlink":
        second.symlink_to(primary)
    original_open = builtins.open
    original_lstat = os.lstat
    visits = 0

    def fake_open(path, *args, **kwargs):
        if path == "/proc/sys/kernel/random/boot_id":
            return io.StringIO(BOOT)
        return original_open(path, *args, **kwargs)

    def fake_lstat(path, *args, **kwargs):
        nonlocal visits
        result = original_lstat(path, *args, **kwargs)
        if alternate == "directory_changed" and str(path) == str(keys):
            visits += 1
            if visits == 5:
                return SimpleNamespace(st_mode=result.st_mode, st_uid=result.st_uid,
                    st_gid=result.st_gid, st_dev=result.st_dev, st_ino=result.st_ino,
                    st_mtime_ns=result.st_mtime_ns, st_ctime_ns=result.st_ctime_ns + 1)
        return result

    monkeypatch.setattr(builtins, "open", fake_open)
    monkeypatch.setattr(os, "lstat", fake_lstat)
    monkeypatch.setattr(pwd, "getpwnam", lambda _: SimpleNamespace(pw_dir=str(home), pw_uid=os.getuid()))
    monkeypatch.setattr(sys, "argv", ["-c", "198.51.100.10", "203.0.113.20",
                                         "198.51.100.10 54321 203.0.113.20 22"])

    def fake_run(argv, **kwargs):
        output = ("usedns no\npasswordauthentication no\n" if argv[0] == "/usr/sbin/sshd"
                  else "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n")
        return SimpleNamespace(returncode=0, stderr=b"", stdout=output.encode())

    monkeypatch.setattr(subprocess, "run", fake_run)
    out = io.StringIO()
    with pytest.raises(ValueError, match="alternate"):
        with contextlib.redirect_stdout(out):
            exec(compile(_surface_script_with_stubbed_daemon(), "<remote-host-surface>", "exec"),
                 {"__name__": "__main__"})
    assert out.getvalue() == ""


@pytest.mark.parametrize("connection", [
    "198.51.100.10 54321 203.0.113.20 22", "",
    "203.0.113.99 54321 203.0.113.20 22",
])
def test_fake_ssh_shell_expands_session_before_sudo_scrubs_environment(tmp_path, connection):
    inputs = _fixture(tmp_path)
    commands = []
    fixture_runner = _host_collection_runner()
    def recorder(command, **kwargs):
        commands.append(command)
        return fixture_runner(command, **kwargs)
    collect_digitalocean_edge_host_evidence(
        **inputs, **_callbacks([]), runner=recorder)
    assert len(commands) == 4
    assert commands[2][-1] == '"$SSH_CONNECTION"'
    if connection:
        assert connection not in " ".join(commands[2])

    # A fake SSH executable invokes a local remote shell; a fake sudo drops
    # SSH_CONNECTION before exec. Neither invokes SSH, sudo, nor a real host.
    fake_ssh = tmp_path / "shell-ssh"
    fake_ssh.write_text(
        f"#!{sys.executable}\n"
        "import subprocess, sys\n"
        "result = subprocess.run(['/bin/sh', '-c', ' '.join(sys.argv[4:])], check=False)\n"
        "sys.exit(result.returncode)\n")
    fake_ssh.chmod(0o700)
    fake_sudo = tmp_path / "scrub-sudo"
    fake_sudo.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        "assert sys.argv[1] == '-n'\n"
        "os.environ.pop('SSH_CONNECTION', None)\n"
        "os.execv(sys.argv[2], sys.argv[2:])\n")
    fake_sudo.chmod(0o700)
    capture = ("import json,os,sys;print(json.dumps("
               "{'args':sys.argv[1:],'environment':os.environ.get('SSH_CONNECTION')}))")
    remote = commands[2].copy()
    remote[0] = str(fake_ssh)
    remote[4] = str(fake_sudo)
    remote[6] = sys.executable
    remote[10] = shlex.quote(capture)
    env = os.environ.copy()
    env["SSH_CONNECTION"] = connection
    result = subprocess.run(remote, env=env, capture_output=True, text=True, check=True)
    observed = json.loads(result.stdout)
    assert observed == {"args": ["198.51.100.10", "203.0.113.20", connection],
                        "environment": None}


def test_middle_raw_firewall_snapshot_uses_same_boot_and_selected_two_hop_route(tmp_path):
    inputs = _middle_inputs(tmp_path)
    commands = []
    evidence = collect_digitalocean_middle_firewall_evidence(
        **inputs, **_callbacks([]), runner=_firewall_runner(
            alias="barragan-bootstrap-user-middle-01",
            metadata={"id": "67890", "region": "nyc3", "public_ipv4": "198.51.100.10",
                      "hostname": "middle-01", "boot_id": BOOT},
            command_log=commands,
        ),
    )
    assert evidence.identity.provider_instance_id == "67890"
    assert evidence.boot_id == evidence.identity.boot_id == BOOT
    assert len(commands) == 2
    assert commands[1][:6] == ("/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-B", "-c")
    assert all(item.raw_output == f"observed {item.name}\n" for item in evidence.commands)
    assert not (inputs["scratch_path"] / "keys").exists()


def test_middle_raw_firewall_snapshot_rejects_boot_change(tmp_path):
    inputs = _middle_inputs(tmp_path)
    with pytest.raises(ProviderKeyedHostIdentityProbeError):
        collect_digitalocean_middle_firewall_evidence(
            **inputs, **_callbacks([]), runner=_firewall_runner(
                alias="barragan-bootstrap-user-middle-01",
                metadata={"id": "67890", "region": "nyc3", "public_ipv4": "198.51.100.10",
                          "hostname": "middle-01", "boot_id": BOOT}, reboot=True,
            ),
        )


def test_raw_firewall_collection_reuses_strict_route_and_returns_only_bounded_private_raw(tmp_path):
    inputs = _fixture(tmp_path)
    events = []
    commands = []
    evidence = collect_digitalocean_edge_firewall_evidence(
        **inputs, **_callbacks(events), runner=_firewall_runner(command_log=commands),
    )
    assert isinstance(evidence, DigitalOceanRawFirewallEvidence)
    assert evidence.identity.provider_instance_id == "12345"
    assert evidence.boot_id == BOOT
    assert evidence.omitted_inputs == () and evidence.policy_interpreted is False
    assert [item.name for item in evidence.commands] == [name for name, _ in _FIREWALL_COMMANDS]
    assert all(item.raw_output == f"observed {item.name}\n" for item in evidence.commands)
    assert all(item.sha256 == hashlib.sha256(item.raw_output.encode()).hexdigest()
               and item.byte_count == len(item.raw_output.encode()) for item in evidence.commands)
    assert [(item.name, item.path) for item in evidence.files] == list(_FIREWALL_OPTIONAL_FILES)
    assert all(item.status == "present" and item.raw_output == f"observed {item.name}\n"
               and item.sha256 == hashlib.sha256(item.raw_output.encode()).hexdigest()
               and (item.uid, item.gid, item.mode) == (0, 0, 0o644)
               for item in evidence.files)
    assert len(commands) == 2  # identity then one fixed sudo snapshot
    assert commands[1][:6] == ("/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-B", "-c")
    assert "observed ufw_status_verbose" not in repr(evidence)
    assert [item[0] for item in events if isinstance(item, tuple)].count("intent") == 2
    assert not (inputs["scratch_path"] / "keys").exists()
    assert not list(inputs["scratch_path"].glob("identity-ssh-*.conf"))


@pytest.mark.parametrize("failure", ["stderr", "truncated", "nonzero", "oversized", "empty",
                                      "lossy", "total", "missing", "time_jump", "unreaped",
                                      "missing_optional", "oversized_optional", "malformed_optional",
                                      "malformed_owner", "malformed_mode"])
def test_raw_firewall_collection_fails_closed_on_incomplete_read(tmp_path, failure):
    inputs = _fixture(tmp_path)
    commands = []
    runner = _firewall_runner(bad_name="iptables_save", failure=failure,
                              command_log=commands)
    error = UnreapedGatedCommandError if failure == "unreaped" else ProviderKeyedHostIdentityProbeError
    with pytest.raises(error):
        collect_digitalocean_edge_firewall_evidence(
            **inputs, **_callbacks([]), runner=runner,
        )
    assert len(commands) == 2
    assert (inputs["scratch_path"] / "keys").exists() == (failure == "unreaped")


def test_raw_firewall_collection_rejects_reboot_spanning_snapshot(tmp_path):
    inputs = _fixture(tmp_path)
    with pytest.raises(ProviderKeyedHostIdentityProbeError):
        collect_digitalocean_edge_firewall_evidence(
            **inputs, **_callbacks([]), runner=_firewall_runner(reboot=True),
        )


def test_optional_ufw_hook_absence_is_explicit_and_distinct_from_empty_file(tmp_path):
    inputs = _fixture(tmp_path)
    evidence = collect_digitalocean_edge_firewall_evidence(
        **inputs, **_callbacks([]), runner=_firewall_runner(failure="absent"),
    )
    missing = evidence.files[0]
    assert (missing.path, missing.status, missing.raw_output, missing.sha256,
            missing.byte_count, missing.uid, missing.gid, missing.mode) == (
        "/etc/ufw/before.init", "absent", None, None, 0, None, None, None,
    )
    assert all(item.status == "present" for item in evidence.files[1:])


def test_raw_optional_ufw_metadata_records_nonroot_without_interpretation(tmp_path):
    inputs = _fixture(tmp_path)
    evidence = collect_digitalocean_edge_firewall_evidence(
        **inputs, **_callbacks([]), runner=_firewall_runner(failure="nonroot"),
    )
    assert evidence.files[0].uid == 1234
    assert evidence.policy_interpreted is False


@pytest.mark.parametrize("failure", ["oversized", "invalid_utf8", "stderr", "nonzero",
                                      "timeout", "reboot", "time_jump"])
def test_fixed_remote_firewall_script_emits_no_partial_snapshot_on_failure(monkeypatch, failure):
    """Exercise the shipped remote script with fake local processes only."""
    seen = []
    open_writers = []
    writers = []
    boot_reads = 0
    killed = []
    original_open = builtins.open
    def fake_open(path, *args, **kwargs):
        nonlocal boot_reads
        if path == "/proc/sys/kernel/random/boot_id":
            boot_reads += 1
            return io.StringIO("00000000-0000-4000-8000-000000000001"
                               if failure == "reboot" and boot_reads > 1 else BOOT)
        if path == "/proc/919191/stat":
            return io.StringIO(_fake_proc_stat(919191, state="Z" if killed or failure != "timeout"
                                              else "S"))
        return original_open(path, *args, **kwargs)

    class FakeProcess:
        pid = 919191
        def __init__(self, argv, **kwargs):
            seen.append(tuple(argv))
            assert kwargs["start_new_session"] is True
            assert kwargs["env"] == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
            out_read, out_write = os.pipe()
            err_read, err_write = os.pipe()
            self.stdout = os.fdopen(out_read, "rb", buffering=0)
            self.stderr = os.fdopen(err_read, "rb", buffering=0)
            if failure == "timeout":
                open_writers.extend((out_write, err_write))
            elif failure == "oversized":
                os.close(err_write)
                def feed():
                    try:
                        os.write(out_write, b"x" * 65537)
                    except BrokenPipeError:
                        pass
                    finally:
                        os.close(out_write)
                writer = threading.Thread(target=feed, daemon=True)
                writers.append(writer)
                writer.start()
            else:
                os.write(out_write, b"\xff" if failure == "invalid_utf8" else b"fixture\n")
                if failure == "stderr":
                    os.write(err_write, b"warning")
                os.close(out_write)
                os.close(err_write)
        def poll(self):
            return None if failure == "timeout" else (1 if failure == "nonzero" else 0)
        def wait(self, **_kwargs):
            return 1 if failure == "nonzero" else 0

    clock_calls = 0
    def fast_monotonic():
        nonlocal clock_calls
        clock_calls += 1
        return clock_calls * 20.0

    remote_output = io.StringIO()
    try:
        with monkeypatch.context() as patch:
            patch.setattr(builtins, "open", fake_open)
            patch.setattr(subprocess, "Popen", FakeProcess)
            patch.setattr(os, "killpg", lambda *_args: killed.append(_args))
            patch.setattr(os, "listdir", lambda path: ["919191"] if path == "/proc" else [])
            patch.setattr(os, "waitid", lambda *_args: object())
            patch.setattr(os, "WNOWAIT", getattr(os, "WNOWAIT", 0x01000000), raising=False)
            if failure == "timeout":
                patch.setattr(time, "monotonic", fast_monotonic)
            if failure == "time_jump":
                moments = iter((2_000_000_000, 1_000_000_000))
                patch.setattr(time, "time_ns", lambda: next(moments))
            with contextlib.redirect_stdout(remote_output), pytest.raises(Exception):
                exec(_FIREWALL_REMOTE_SCRIPT, {})
    finally:
        for descriptor in open_writers:
            os.close(descriptor)
        for writer in writers:
            writer.join(timeout=1)
    assert remote_output.getvalue() == ""
    assert seen and seen[0] == _FIREWALL_COMMANDS[0][1][2:]


@pytest.mark.parametrize("optional_state", ["present", "absent", "symlink", "oversized",
                                           "metadata_flip"])
def test_fixed_remote_firewall_script_collects_all_reads_once_without_network(
    monkeypatch, tmp_path, optional_state,
):
    seen = []
    original_open = builtins.open
    original_os_open = os.open
    original_fstat = os.fstat
    file_targets = {}
    watched_descriptors = {}
    for index, (_name, path) in enumerate(_FIREWALL_OPTIONAL_FILES):
        target = tmp_path / f"optional-{index}"
        target.write_bytes(b"" if index == 0 else b"fixed optional input\n")
        if optional_state == "symlink" and index == 0:
            linked = tmp_path / "linked-optional"
            linked.symlink_to(target)
            target = linked
        if optional_state == "oversized" and index == 0:
            target.write_bytes(b"x" * 65537)
        file_targets[path] = target
    def fake_os_open(path, *args, **kwargs):
        if path in file_targets:
            if optional_state == "absent":
                raise FileNotFoundError(path)
            descriptor = original_os_open(file_targets[path], *args, **kwargs)
            if optional_state == "metadata_flip" and path == _FIREWALL_OPTIONAL_FILES[0][1]:
                watched_descriptors[descriptor] = 0
            return descriptor
        return original_os_open(path, *args, **kwargs)
    def fake_fstat(descriptor):
        result = original_fstat(descriptor)
        if descriptor not in watched_descriptors:
            return result
        watched_descriptors[descriptor] += 1
        if watched_descriptors[descriptor] != 2:
            return result
        return SimpleNamespace(
            st_dev=result.st_dev, st_ino=result.st_ino, st_size=result.st_size,
            st_mtime_ns=result.st_mtime_ns, st_ctime_ns=result.st_ctime_ns + 1,
            st_uid=result.st_uid + 1, st_gid=result.st_gid,
            st_mode=result.st_mode ^ 0o020, st_nlink=result.st_nlink,
        )
    def fake_open(path, *args, **kwargs):
        if path == "/proc/sys/kernel/random/boot_id":
            return io.StringIO(BOOT)
        if path == "/proc/919191/stat":
            return io.StringIO(_fake_proc_stat(919191))
        return original_open(path, *args, **kwargs)

    class FakeProcess:
        pid = 919191
        def __init__(self, argv, **kwargs):
            seen.append(tuple(argv))
            assert kwargs["start_new_session"] is True
            assert kwargs["env"] == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
            out_read, out_write = os.pipe()
            err_read, err_write = os.pipe()
            os.write(out_write, b"fixed raw observation\n")
            os.close(out_write)
            os.close(err_write)
            self.stdout = os.fdopen(out_read, "rb", buffering=0)
            self.stderr = os.fdopen(err_read, "rb", buffering=0)
        def wait(self, **_kwargs):
            return 0

    output = io.StringIO()
    with monkeypatch.context() as patch:
        patch.setattr(builtins, "open", fake_open)
        patch.setattr(os, "open", fake_os_open)
        patch.setattr(os, "fstat", fake_fstat)
        patch.setattr(subprocess, "Popen", FakeProcess)
        patch.setattr(os, "listdir", lambda path: ["919191"] if path == "/proc" else [])
        patch.setattr(os, "waitid", lambda *_args: object())
        patch.setattr(os, "WNOWAIT", getattr(os, "WNOWAIT", 0x01000000), raising=False)
        with contextlib.redirect_stdout(output):
            if optional_state in {"symlink", "oversized", "metadata_flip"}:
                with pytest.raises((OSError, ValueError)):
                    exec(_FIREWALL_REMOTE_SCRIPT, {})
            else:
                exec(_FIREWALL_REMOTE_SCRIPT, {})
    if optional_state in {"symlink", "oversized", "metadata_flip"}:
        assert output.getvalue() == ""
        return
    parsed = json.loads(output.getvalue())
    assert parsed["boot_id"] == BOOT
    assert parsed["completed_at_ns"] >= parsed["started_at_ns"]
    assert parsed["commands"] == [[name, "fixed raw observation\n"]
                                  for name, _ in _FIREWALL_COMMANDS]
    assert parsed["files"] == [
        [name, path, "absent", None, None, None, None] if optional_state == "absent" else
        [name, path, "present", "" if index == 0 else "fixed optional input\n",
         file_targets[path].stat().st_uid, file_targets[path].stat().st_gid,
         stat.S_IMODE(file_targets[path].stat().st_mode)]
        for index, (name, path) in enumerate(_FIREWALL_OPTIONAL_FILES)
    ]
    assert seen == [argv[2:] for _, argv in _FIREWALL_COMMANDS]


@pytest.mark.parametrize("descendant_holds_pipe", [True, False])
def test_remote_firewall_reader_rejects_exited_leader_with_live_descendant(
    monkeypatch, descendant_holds_pipe,
):
    killed = []
    waiting = []
    held_writers = []
    original_open = builtins.open
    def fake_open(path, *args, **kwargs):
        if path == "/proc/sys/kernel/random/boot_id":
            return io.StringIO(BOOT)
        if path == "/proc/919191/stat":
            return io.StringIO(_fake_proc_stat(919191))  # unreaped zombie leader
        if path == "/proc/919192/stat":
            return io.StringIO(_fake_proc_stat(919192, state="Z" if killed else "S"))
        return original_open(path, *args, **kwargs)

    class FakeProcess:
        pid = 919191
        def __init__(self, _argv, **_kwargs):
            out_read, out_write = os.pipe()
            err_read, err_write = os.pipe()
            self.stdout = os.fdopen(out_read, "rb", buffering=0)
            self.stderr = os.fdopen(err_read, "rb", buffering=0)
            os.write(out_write, b"leader output\n")
            os.close(err_write)
            if descendant_holds_pipe:
                held_writers.append(out_write)
            else:
                os.close(out_write)
        def wait(self, **_kwargs):
            waiting.append(True)
            return 0

    clock_calls = 0
    def fast_monotonic():
        nonlocal clock_calls
        clock_calls += 1
        return clock_calls * 5.0

    output = io.StringIO()
    try:
        with monkeypatch.context() as patch:
            patch.setattr(builtins, "open", fake_open)
            patch.setattr(subprocess, "Popen", FakeProcess)
            patch.setattr(os, "listdir", lambda path: ["919191", "919192"] if path == "/proc" else [])
            patch.setattr(os, "waitid", lambda *_args: object())
            patch.setattr(os, "WNOWAIT", getattr(os, "WNOWAIT", 0x01000000), raising=False)
            patch.setattr(os, "killpg", lambda pid, sig: killed.append((pid, sig)))
            if descendant_holds_pipe:
                patch.setattr(time, "monotonic", fast_monotonic)
            with contextlib.redirect_stdout(output), pytest.raises(Exception):
                exec(_FIREWALL_REMOTE_SCRIPT, {})
    finally:
        for descriptor in held_writers:
            os.close(descriptor)
    assert output.getvalue() == ""
    assert killed == [(919191, signal.SIGKILL)]
    assert waiting == [True]


@pytest.mark.skipif(sys.platform != "linux" or not Path("/proc/sys/kernel/random/boot_id").exists(),
                    reason="requires real Linux /proc and waitid(WNOWAIT)")
def test_linux_remote_firewall_script_uses_real_proc_waitid_with_fixed_printf_read(tmp_path):
    """Run the shipped reader locally with fixed test command and file paths."""
    printf = Path("/usr/bin/printf")
    if not printf.is_file():
        pytest.skip("/usr/bin/printf is unavailable")
    original = "COMMANDS = " + repr(tuple((name, argv[2:]) for name, argv in _FIREWALL_COMMANDS))
    replacement = "COMMANDS = " + repr((("fixture_read", (str(printf), "fixture firewall\n")),))
    assert _FIREWALL_REMOTE_SCRIPT.count(original) == 1
    script = _FIREWALL_REMOTE_SCRIPT.replace(original, replacement, 1)
    file_paths = tuple((name, str(tmp_path / name)) for name, _path in _FIREWALL_OPTIONAL_FILES)
    Path(file_paths[0][1]).write_text("fixed init hook\n")
    Path(file_paths[1][1]).write_text("")
    optional_original = "OPTIONAL_FILES = " + repr(_FIREWALL_OPTIONAL_FILES)
    assert script.count(optional_original) == 1
    script = script.replace(optional_original, "OPTIONAL_FILES = " + repr(file_paths), 1)
    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script],
        capture_output=True, text=True, timeout=10, check=True,
    )
    assert completed.stderr == ""
    snapshot = json.loads(completed.stdout)
    assert snapshot["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    assert snapshot["commands"] == [["fixture_read", "fixture firewall\n"]]
    assert snapshot["files"] == [
        [file_paths[0][0], file_paths[0][1], "present", "fixed init hook\n",
         Path(file_paths[0][1]).stat().st_uid, Path(file_paths[0][1]).stat().st_gid,
         stat.S_IMODE(Path(file_paths[0][1]).stat().st_mode)],
        [file_paths[1][0], file_paths[1][1], "present", "",
         Path(file_paths[1][1]).stat().st_uid, Path(file_paths[1][1]).stat().st_gid,
         stat.S_IMODE(Path(file_paths[1][1]).stat().st_mode)],
        [file_paths[2][0], file_paths[2][1], "absent", None, None, None, None],
    ]
    assert snapshot["started_at_ns"] > 0
    assert snapshot["completed_at_ns"] >= snapshot["started_at_ns"]
