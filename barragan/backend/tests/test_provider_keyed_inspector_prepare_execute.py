# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network, one-shot Inspector support preparation driver tests."""

from dataclasses import replace
import hashlib

import pytest

from app.services import observer_checks
from app.services.observer_checks import SshObserverRunner
from app.services.provider_keyed_inspector_prepare_execute import (
    InspectorPreparationExecutionAttention, execute_reserved_keyed_inspector_preparation,
)
from app.storage.database import db
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from test_provider_keyed_inspector_prepare_binder import _ready, Transport
from test_provider_keyed_inspector_prepare_intent import _begin
from test_provider_keyed_inspector_provider_proof import linode_responses


PUBLIC = "ssh-ed25519 " + "A" * 68


def _case(tmp_path):
    state, parent, receipt, _submitted, key, private = _ready(tmp_path)
    assert key[0] == hashlib.sha256(PUBLIC.encode()).hexdigest()
    public = private.with_name(private.name + ".pub")
    public.write_text(PUBLIC + "\n", encoding="ascii")
    public.chmod(0o644)
    capability = _begin(state, parent, receipt, key, private, Transport(linode_responses()))
    return state, parent, receipt, key, private, capability


def _execute(state, parent, key, private, capability, *, runner=None):
    with db.bind(state):
        return execute_reserved_keyed_inspector_preparation(
            capability, environment="devtest", runner=runner,
            key_identity_reader=lambda: (private, key[0]),
            key_pair_verifier=lambda _path, _fingerprint: None,
        )


def _prepared(host):
    metadata = {**host.metadata, "adminIdentityVersion": 1,
                "rootLoginDisabled": True, "supportPreparationVersion": 1,
                "supportPreparedPackages": ["nmap"]}
    return replace(host, metadata=metadata)


def test_one_runner_call_with_command_fences_keeps_durable_rows_unprepared(tmp_path, monkeypatch):
    state, parent, receipt, key, private, capability = _case(tmp_path)
    calls = []

    def prepare(_self, *, host, ssh_key, fence, **_kwargs):
        calls.append((host, ssh_key))
        assert ssh_key.public_key == PUBLIC and ssh_key.private_key_path == str(private)
        for _ in range(6):
            fence()  # before one local subprocess
            fence()  # finally after it
        return _prepared(host)

    monkeypatch.setattr(SshObserverRunner, "prepare_support_host", prepare)
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        before = jobs.get(receipt.coordinator_job_id)
        settings = SqlAlchemyObserverSettingsRepository().get(parent.target_id)
        rows = SqlAlchemyProviderResourceRepository().list_for_engagement(parent.target_id)
    result = _execute(state, parent, key, private, capability)
    assert result.status == "prepared_unverified" and result.host_id == "123"
    assert len(calls) == 1
    with db.bind(state):
        after = SqlAlchemyJobRepository().get(receipt.coordinator_job_id)
        assert after.events == before.events and after.input["phase"] == "inspector_prepare_started"
        assert SqlAlchemyObserverSettingsRepository().get(parent.target_id) == settings
        assert SqlAlchemyProviderResourceRepository().list_for_engagement(parent.target_id) == rows
    with pytest.raises(InspectorPreparationExecutionAttention):
        _execute(state, parent, key, private, capability)
    assert len(calls) == 1


@pytest.mark.parametrize("drift", ["host_name", "firewall_policy"])
def test_row_drift_before_first_contact_consumes_capability(tmp_path, monkeypatch, drift):
    state, parent, receipt, key, private, capability = _case(tmp_path)
    calls = []
    monkeypatch.setattr(SshObserverRunner, "prepare_support_host",
                        lambda *_args, **_kwargs: calls.append("ssh"))
    with db.bind(state):
        resources = SqlAlchemyProviderResourceRepository()
        if drift == "host_name":
            host = resources.get("linode:inspector:123")
            resources.save(replace(host, name="wrong-name"))
        else:
            firewall = resources.get("linode:inspector-firewall:42")
            resources.save(replace(firewall, metadata={**firewall.metadata,
                                                       "managementSourceCidr": "0.0.0.0/0"}))
    with pytest.raises(InspectorPreparationExecutionAttention):
        _execute(state, parent, key, private, capability)
    assert calls == []


def test_post_command_firewall_drift_blocks_next_command(tmp_path, monkeypatch):
    state, parent, receipt, key, private, capability = _case(tmp_path)
    calls = []

    def prepare(_self, *, fence, **_kwargs):
        fence()
        calls.append("first")
        with db.bind(state):
            resources = SqlAlchemyProviderResourceRepository()
            firewall = resources.get("linode:inspector-firewall:42")
            resources.save(replace(firewall, name="changed-policy"))
        fence()
        calls.append("second")

    monkeypatch.setattr(SshObserverRunner, "prepare_support_host", prepare)
    with pytest.raises(InspectorPreparationExecutionAttention):
        _execute(state, parent, key, private, capability)
    assert calls == ["first"]


def test_lost_claim_after_first_command_stops_second_and_never_replays(tmp_path, monkeypatch):
    state, parent, receipt, key, private, capability = _case(tmp_path)
    commands = []

    def prepare(_self, *, host, fence, **_kwargs):
        fence()
        commands.append("first")
        with db.bind(state):
            jobs = SqlAlchemyJobRepository()
            child = jobs.get(receipt.coordinator_job_id)
            jobs.save(replace(child, input={**child.input, "claimToken": "b" * 32}))
        fence()
        commands.append("second")
        return _prepared(host)

    monkeypatch.setattr(SshObserverRunner, "prepare_support_host", prepare)
    with pytest.raises(InspectorPreparationExecutionAttention):
        _execute(state, parent, key, private, capability)
    assert commands == ["first"]
    with pytest.raises(InspectorPreparationExecutionAttention):
        _execute(state, parent, key, private, capability)
    assert commands == ["first"]


def test_timeout_still_runs_postcommand_fence_and_stops(tmp_path, monkeypatch):
    state, parent, receipt, key, private, capability = _case(tmp_path)
    calls = []

    def prepare(_self, *, fence, **_kwargs):
        fence()
        calls.append("command")
        try:
            raise TimeoutError("SSH command timed out")
        finally:
            fence()

    monkeypatch.setattr(SshObserverRunner, "prepare_support_host", prepare)
    with pytest.raises(InspectorPreparationExecutionAttention):
        _execute(state, parent, key, private, capability)
    assert calls == ["command"]


def test_subclass_runner_cannot_bypass_command_fences(tmp_path):
    state, parent, receipt, key, private, capability = _case(tmp_path)

    class Bypass(SshObserverRunner):
        def prepare_support_host(self, **_kwargs):
            raise AssertionError("must not run")

    with pytest.raises(InspectorPreparationExecutionAttention):
        _execute(state, parent, key, private, capability, runner=Bypass())


def test_real_runner_fences_all_six_local_commands_without_network(tmp_path, monkeypatch):
    state, parent, receipt, key, private, capability = _case(tmp_path)
    commands = []
    heartbeats = []
    original = SqlAlchemyJobRepository.heartbeat_keyed_inspector_preparation_if_running_claimed

    def heartbeat(self, *args, **kwargs):
        heartbeats.append(kwargs["expected_event_digest"])
        return original(self, *args, **kwargs)

    def run(command, **kwargs):
        commands.append(command)
        assert kwargs["timeout"] == 120
        if command[0] == "ssh" and "-T" in command:
            output = ("permitrootlogin no\npasswordauthentication no\n"
                      "kbdinteractiveauthentication no\n")
            return observer_checks.subprocess.CompletedProcess(command, 0, output, "")
        if command[0] == "ssh" and any(part.startswith("root@") for part in command):
            return observer_checks.subprocess.CompletedProcess(command, 1, "", "denied")
        return observer_checks.subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(SqlAlchemyJobRepository,
                        "heartbeat_keyed_inspector_preparation_if_running_claimed", heartbeat)
    monkeypatch.setattr(observer_checks.subprocess, "run", run)
    monkeypatch.setattr(observer_checks, "resolve_ansible_playbook",
                        lambda: type("Resolution", (), {"ok": True,
                                                         "command": "/usr/bin/ansible-playbook"})())
    result = _execute(state, parent, key, private, capability)
    assert result.status == "prepared_unverified"
    assert len(commands) == 6 and len(heartbeats) == 15
    assert sum(command[0] == "/usr/bin/ansible-playbook" for command in commands) == 2


def test_changed_public_key_bytes_veto_before_ssh(tmp_path, monkeypatch):
    state, parent, receipt, key, private, capability = _case(tmp_path)
    private.with_name(private.name + ".pub").write_text(
        "ssh-ed25519 " + "B" * 68 + "\n", encoding="ascii")
    commands = []
    monkeypatch.setattr(observer_checks.subprocess, "run",
                        lambda *_args, **_kwargs: commands.append("ssh"))
    with pytest.raises(InspectorPreparationExecutionAttention):
        _execute(state, parent, key, private, capability)
    assert commands == []
