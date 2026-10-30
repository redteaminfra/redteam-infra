# Copyright (c) 2026, Oracle and/or its affiliates.
"""Only the identity-bound Linode sudo warning may accompany raw observations."""

import json
from dataclasses import asdict
from pathlib import Path

import pytest

import app.services.provider_keyed_host_identity_probe as collector
import app.services.provider_keyed_mixed_linode_diagnostic as diagnostic
from app.domain import JobEvent
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_mixed_linode_host_probe import (
    LinodeRawHostIdentity, _sudo_hostname_warning,
)


BOOT = "00000000-0000-4000-8000-000000000001"
HOSTNAME = "middle01-5dc26ee4"
WARNING = _sudo_hostname_warning(HOSTNAME)


def _output(kind):
    if kind == "firewall":
        return json.dumps({
            "boot_id": BOOT, "started_at_ns": 1, "completed_at_ns": 2,
            "commands": [[name, "observed\n"] for name, _ in collector._FIREWALL_COMMANDS],
            "files": [[name, path, "absent", None, None, None, None]
                      for name, path in collector._FIREWALL_OPTIONAL_FILES],
        })
    return json.dumps({
        "boot_id": BOOT, "started_at_ns": 1, "completed_at_ns": 2,
        "predecessor_ipv4": "198.51.100.10",
        "ssh_connection": ["198.51.100.10", 12345, "203.0.113.20", 22],
        "accounts": [[name, "ssh-ed25519 AAAA\n", 1000, 1000, 0o600]
                     for name in ("user", "sketchssh")],
        "effective_sshd": [[name, "passwordauthentication no\n"]
                           for name in ("user", "sketchssh")],
        "alternate_authorized_keys_absent": ["user", "sketchssh"],
        "listeners": "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n",
    })


def _collect(tmp_path, monkeypatch, *, kind, stderr, expected_stderr=None,
             audit_bytes=None, truncated=False):
    monkeypatch.setattr(collector, "_regular_file_digest", lambda *a, **k: "digest")
    monkeypatch.setattr(collector, "_sketch_file_snapshot", lambda *a: ("pin", 0, "digest"))
    identity = collector.DigitalOceanHostIdentityEvidence(
        "a" * 64, "chain", "address", "123", "region", "203.0.113.20",
        HOSTNAME, BOOT, "alias", "metadata-invocation", "a" * 64, "b" * 64)
    output = _output(kind)

    def runner(command, **kwargs):
        intent = CommandIntent("raw-invocation", str(tmp_path), "b" * 64)
        kwargs["intent_callback"](intent)
        started = StartedCommand(intent, ProcessIdentity("boot", 100, 100, 1))
        kwargs["started_callback"](started)
        kwargs["heartbeat_callback"](started)
        kwargs["result_callback"](CommandAuditResult(
            started, 0, len(output.encode()),
            len(stderr.encode()) if audit_bytes is None else audit_bytes,
            False, truncated))
        return CommandResult(started, 0, output, stderr, False, truncated)

    args = (identity, Path("/usr/bin/ssh"), tmp_path / "config", "alias", tmp_path,
            tmp_path / "core", "digest", tmp_path / "sketch", ("pin", 0, "digest"),
            lambda: None, lambda _: None, lambda _: None, lambda _: None,
            lambda _: None, runner)
    if kind == "surface":
        args = (identity, "198.51.100.10", *args[1:])
    kwargs = {} if expected_stderr is None else {"expected_stderr": expected_stderr}
    fn = (collector._collect_raw_firewall if kind == "firewall"
          else collector._collect_raw_host_surface)
    return fn(*args, **kwargs)


@pytest.mark.parametrize("kind", ["firewall", "surface"])
@pytest.mark.parametrize("stderr", ["", WARNING])
def test_linode_raw_collector_accepts_zero_or_exact_warning(tmp_path, monkeypatch, kind, stderr):
    result = _collect(tmp_path, monkeypatch, kind=kind, stderr=stderr,
                      expected_stderr=WARNING)
    assert result.boot_id == BOOT


@pytest.mark.parametrize("kind", ["firewall", "surface"])
@pytest.mark.parametrize("stderr", [
    _sudo_hostname_warning("middle01-other"), WARNING + "another warning\n",
    WARNING[:-1], "sudo warning\n",
])
def test_linode_raw_collector_rejects_other_stderr(tmp_path, monkeypatch, kind, stderr):
    with pytest.raises(ValueError, match="incomplete"):
        _collect(tmp_path, monkeypatch, kind=kind, stderr=stderr,
                 expected_stderr=WARNING)


@pytest.mark.parametrize("kind", ["firewall", "surface"])
@pytest.mark.parametrize("change", ["audit", "truncated", "digitalocean"])
def test_linode_warning_never_relaxes_audit_or_digitalocean(
    tmp_path, monkeypatch, kind, change,
):
    kwargs = {"expected_stderr": WARNING}
    if change == "audit":
        kwargs["audit_bytes"] = len(WARNING.encode()) - 1
    elif change == "truncated":
        kwargs["truncated"] = True
    else:
        kwargs.pop("expected_stderr")  # DigitalOcean's default remains zero-stderr.
    with pytest.raises(ValueError, match="incomplete"):
        _collect(tmp_path, monkeypatch, kind=kind, stderr=WARNING, **kwargs)


def _journal():
    events = [JobEvent(0, "info", "header", {}), JobEvent(1, "info", "header", {})]
    expected, identities = [], []
    for index in range(2):
        hostname = f"middle01-{index}"
        node = {"hostname": hostname, "terraformAddress": f"address-{index}",
                "providerInstanceId": str(index + 1)}
        identity = LinodeRawHostIdentity(
            "a" * 64, "chain", node["terraformAddress"], node["providerInstanceId"],
            "linode/ubuntu24.04", "us-sea", "203.0.113.20", hostname, BOOT,
            ("198.51.100.10", 12345, "203.0.113.20", 22),
            f"invocation-{index}-0", "b" * 64, "c" * 64)
        expected.append(node)
        identities.append(identity)
        fields = {**node}
        scratch = f"/private/scratch-{index}"
        events.append(JobEvent(len(events), "info", "Linode diagnostic scratch intended",
                               {**fields, "scratchPath": scratch}))
        for command in range(4):
            invocation = f"invocation-{index}-{command}"
            data = {**fields, "invocationId": invocation}
            events.extend([
                JobEvent(len(events), "info", "Linode diagnostic command intended",
                         {**data, "scratchPath": scratch}),
                JobEvent(len(events) + 1, "info", "Linode diagnostic command started before GO", data),
                JobEvent(len(events) + 2, "info", "Linode diagnostic command result fenced",
                         {**data, "returnCode": 0, "stdoutTruncated": False,
                          "stderrTruncated": False,
                          "stderrBytes": (0 if command == 0 else
                                          len(_sudo_hostname_warning(hostname).encode()))}),
            ])
        events.append(JobEvent(len(events), "info", "Linode diagnostic identity captured",
                               {**fields, "identitySha256": diagnostic._sha(asdict(identity))}))
    return events, expected, identities


def test_linode_raw_journal_allows_only_warning_length_on_raw_commands():
    events, expected, identities = _journal()
    diagnostic._verify_command_journal(events, expected, identities, collect_raw=True)
    zero = list(events)
    for offset in (8, 11, 14, 22, 25, 28):
        event = zero[offset]
        zero[offset] = JobEvent(event.sequence, event.level, event.message,
                                {**event.data, "stderrBytes": 0})
    diagnostic._verify_command_journal(zero, expected, identities, collect_raw=True)
    for offset, count in [(5, len(_sudo_hostname_warning("middle01-0").encode())),
                          (8, 1)]:
        changed = list(events)
        event = changed[offset]
        changed[offset] = JobEvent(event.sequence, event.level, event.message,
                                   {**event.data, "stderrBytes": count})
        with pytest.raises(diagnostic.MixedLinodeDiagnosticAttention):
            diagnostic._verify_command_journal(changed, expected, identities,
                                               collect_raw=True)
    with pytest.raises(diagnostic.MixedLinodeDiagnosticAttention):
        diagnostic._verify_command_journal(events, expected,
                                           [identities[1], identities[0]], collect_raw=True)
