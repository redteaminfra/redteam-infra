# Copyright (c) 2026, Oracle and/or its affiliates.
"""Opt-in Inspector command fences surround every local subprocess."""

import subprocess
from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.services import observer_checks as service


HOST = service.ObserverHost(
    "linode", "instance", "123", "inspector-" + "a" * 32, "us-east",
    "1.1.1.1", ssh_user="barragan",
)
KEY = service.ObserverSshKey("/private/test-key", "ssh-ed25519 AAAA")
POLICY = "permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\n"


def _fake_prepare(monkeypatch, *, returncode=0, allow_first_root=False):
    commands = []

    def run(command, **kwargs):
        commands.append((command, kwargs))
        assert kwargs["timeout"] == 120 and kwargs["check"] is False
        if command[0] == "ssh" and "-T" in command:
            return subprocess.CompletedProcess(command, 0, POLICY, "")
        if command[0] == "ssh" and any(item.startswith("root@") for item in command):
            if allow_first_root and sum(any(item.startswith("root@") for item in prior)
                                        for prior, _ in commands) == 1 and command[-1] == "true":
                return subprocess.CompletedProcess(command, 0, "", "")
            return subprocess.CompletedProcess(command, 1, "", "denied")
        return subprocess.CompletedProcess(command, returncode, "", "")

    monkeypatch.setattr(service.subprocess, "run", run)
    monkeypatch.setattr(service, "resolve_ansible_playbook",
                        lambda: SimpleNamespace(ok=True, command="/usr/bin/ansible-playbook"))
    return commands


def test_full_preparation_fences_before_and_after_each_subprocess(monkeypatch):
    commands = _fake_prepare(monkeypatch)
    checkpoints = []

    def fence():
        checkpoints.append(len(commands))

    result = service.SshObserverRunner(readiness_attempts=1).prepare_support_host(
        host=HOST, ssh_key=KEY, packages=("nmap",), fence=fence,
    )
    assert result.ssh_user == "barragan"
    assert len(commands) == 6
    assert checkpoints == [value for index in range(6) for value in (index, index + 1)]
    assert sum(command[0][0] == "/usr/bin/ansible-playbook" for command in commands) == 2


def test_lost_fence_during_mutating_playbook_stops_next_command(monkeypatch):
    commands = _fake_prepare(monkeypatch)
    checkpoints = []

    def fence():
        checkpoints.append(len(commands))
        if len(commands) == 2:
            raise RuntimeError("claim lost")

    with pytest.raises(RuntimeError, match="claim lost"):
        service.SshObserverRunner(readiness_attempts=1).prepare_support_host(
            host=HOST, ssh_key=KEY, packages=("nmap",), fence=fence,
        )
    assert len(commands) == 2
    assert commands[-1][0][0] == "/usr/bin/ansible-playbook"
    assert checkpoints[-1] == 2


def test_root_identity_migration_fences_bootstrap_and_each_later_command(monkeypatch):
    commands = _fake_prepare(monkeypatch, allow_first_root=True)
    checkpoints = []
    result = service.SshObserverRunner(readiness_attempts=1).prepare_support_host(
        host=replace(HOST, ssh_user="root"), ssh_key=KEY, packages=("nmap",),
        fence=lambda: checkpoints.append(len(commands)),
    )
    assert result.ssh_user == "barragan"
    assert len(commands) == 8
    assert [command[-1] for command, _ in commands if command[0] == "/usr/bin/ansible-playbook"] == [
        "ansible/bootstrap_inspector_admin.yml",
        "ansible/harden_inspector_ssh.yml",
        "ansible/prepare_inspector.yml",
    ]
    assert checkpoints == [value for index in range(8) for value in (index, index + 1)]


def test_timeout_calls_final_fence(monkeypatch):
    calls = []

    def timeout(_command, **kwargs):
        assert kwargs["timeout"] == 120
        calls.append("run")
        raise subprocess.TimeoutExpired("ssh", 120)

    monkeypatch.setattr(service.subprocess, "run", timeout)
    with pytest.raises(subprocess.TimeoutExpired):
        service._run_checked(["ssh", "test"], fence=lambda: calls.append("fence"))
    assert calls == ["fence", "run", "fence"]


def test_retry_fences_each_attempt_and_legacy_needs_no_fence(monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append("run")
        return subprocess.CompletedProcess(command, 0 if calls.count("run") == 2 else 1, "", "")

    monkeypatch.setattr(service.subprocess, "run", run)
    assert service._run_checked_with_retries(
        ["ssh", "test"], attempts=2, delay_seconds=0, description="not ready",
        fence=lambda: calls.append("fence"),
    ).returncode == 0
    assert calls == ["fence", "run", "fence", "fence", "run", "fence"]
    calls.clear()
    assert service._run_checked(["ssh", "test"], check=False).returncode == 1
    assert calls == ["run"]
