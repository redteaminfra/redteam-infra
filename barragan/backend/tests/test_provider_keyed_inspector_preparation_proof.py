# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network independent Inspector provider/SSH support proof."""

from dataclasses import replace
import subprocess

import pytest

from app.services import observer_checks
from app.services import provider_keyed_inspector_preparation_proof as service
from app.services.provider_keyed_inspector_prepare_execute import InspectorPreparedUnverified
from app.services.observer_checks import ObserverHost, ObserverSshKey, SshObserverRunner
from app.storage.database import db
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from test_provider_keyed_inspector_prepare_binder import Transport
from test_provider_keyed_inspector_prepare_execute import _case, _execute, _prepared
from test_provider_keyed_inspector_provider_proof import linode_responses


def _started(tmp_path, monkeypatch):
    state, parent, receipt, key, private, capability = _case(tmp_path)

    def prepare(_self, *, host, fence, **_kwargs):
        for _ in range(6):
            fence()
            fence()
        return _prepared(host)

    monkeypatch.setattr(SshObserverRunner, "prepare_support_host", prepare)
    evidence = _execute(state, parent, key, private, capability)
    return state, parent, receipt, key, private, evidence


def _run(state, parent, key, private, evidence, *, transport=None, environment="devtest"):
    transport = transport or Transport(linode_responses())
    with db.bind(state):
        return service.prove_prepared_keyed_inspector_support_host(
            evidence, parent.target_id, environment=environment,
            key_identity_reader=lambda: (private, key[0]),
            key_pair_verifier=lambda _path, _fingerprint: None,
            transport_factory=lambda _provider: transport,
            decrypt_secret=lambda _encrypted: "private-token",
        )


def _ssh_fake(monkeypatch, *, root_stderr="Permission denied (publickey)",
              root_returncode=255, policy=None, peer="8.8.8.8 55444 1.1.1.1 22\n",
              nmap="Nmap version 7.94 ( https://nmap.org )\n", after_command=None,
              timeout_seconds=120):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        assert kwargs["timeout"] == timeout_seconds
        if after_command:
            after_command(command)
        if "root@" in " ".join(command):
            return subprocess.CompletedProcess(command, root_returncode, "", root_stderr)
        if command[-2:] == ["/usr/bin/printenv", "SSH_CONNECTION"]:
            return subprocess.CompletedProcess(command, 0, peer, "")
        if "/usr/sbin/sshd" in command:
            assert command[-2:] == ["-C", "user=root,addr=8.8.8.8,host=8.8.8.8"]
            return subprocess.CompletedProcess(
                command, 0, policy if policy is not None else
                "permitrootlogin no\npasswordauthentication no\n"
                "kbdinteractiveauthentication no\n", "")
        if command[-2:] == ["/usr/bin/nmap", "--version"]:
            return subprocess.CompletedProcess(command, 0, nmap, "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(observer_checks.subprocess, "run", run)
    return calls


def test_selected_source_ssh_timeout_override_is_local_to_destroy(monkeypatch):
    calls = _ssh_fake(monkeypatch, timeout_seconds=25)
    host = ObserverHost("linode", "instance", "123", "inspector", "us-east",
                        "1.1.1.1", ssh_user="barragan", status="running")
    key = ObserverSshKey("/tmp/existing-inspector-key", "ssh-ed25519 AAAA")
    service.verify_inspector_selected_source_ssh(
        host, key, "8.8.8.8/32", lambda: None, SshObserverRunner(),
        timeout_seconds=25)
    assert len(calls) == 5


def test_fresh_provider_get_and_five_fenced_read_only_ssh_commands(tmp_path, monkeypatch):
    state, parent, receipt, key, private, evidence = _started(tmp_path, monkeypatch)
    calls = _ssh_fake(monkeypatch)
    transport = Transport(linode_responses())
    with db.bind(state):
        before = SqlAlchemyJobRepository().get(receipt.coordinator_job_id)
        settings = SqlAlchemyObserverSettingsRepository().get(parent.target_id)
        rows = SqlAlchemyProviderResourceRepository().list_for_engagement(parent.target_id)
    result = _run(state, parent, key, private, evidence, transport=transport)
    assert result.evidence.status == "support_host_proved_unpublished"
    assert result.evidence.settings_published is False
    assert result.evidence.nmap_version.startswith("Nmap version 7.94")
    assert len(calls) == 5 and transport.calls
    assert calls[-1][-2:] == ["/usr/bin/nmap", "--version"]
    assert all(command[0] == "ssh" for command in calls)
    with db.bind(state):
        after = SqlAlchemyJobRepository().get(receipt.coordinator_job_id)
        assert after.events == before.events and after.input["phase"] == "inspector_prepare_started"
        assert SqlAlchemyObserverSettingsRepository().get(parent.target_id) == settings
        assert SqlAlchemyProviderResourceRepository().list_for_engagement(parent.target_id) == rows


@pytest.mark.parametrize("drift", ["prod", "wrong_type", "wrong_status", "host_name",
                                    "firewall_policy", "claim", "lease", "key"])
def test_drift_or_wrong_environment_vetoes_before_get_or_ssh(tmp_path, monkeypatch, drift):
    state, parent, receipt, key, private, evidence = _started(tmp_path, monkeypatch)
    calls = _ssh_fake(monkeypatch)
    transport = Transport(linode_responses())
    if drift in {"wrong_type", "wrong_status"}:
        evidence = (object() if drift == "wrong_type"
                    else replace(evidence, status="ready"))
    elif drift == "key":
        key[0] = "0" * 64
    elif drift not in {"prod"}:
        with db.bind(state):
            if drift in {"host_name", "firewall_policy"}:
                resources = SqlAlchemyProviderResourceRepository()
                identifier = ("linode:inspector:123" if drift == "host_name"
                              else "linode:inspector-firewall:42")
                row = resources.get(identifier)
                resources.save(replace(row, name="wrong"))
            elif drift == "claim":
                jobs = SqlAlchemyJobRepository()
                child = jobs.get(receipt.coordinator_job_id)
                jobs.save(replace(child, input={**child.input, "claimToken": "b" * 32}))
            else:
                child = SqlAlchemyJobRepository().get(receipt.coordinator_job_id)
                SqlAlchemyDeploymentPlanRepository().retag(
                    parent.target_id, child.input["corePlanId"], "wrong-operation")
    with pytest.raises(service.InspectorPreparationProofAttention):
        _run(state, parent, key, private, evidence, transport=transport,
             environment="prod" if drift == "prod" else "devtest")
    assert transport.calls == [] and calls == []


def test_root_transport_error_cannot_prove_root_login_denied(tmp_path, monkeypatch):
    state, parent, receipt, key, private, evidence = _started(tmp_path, monkeypatch)
    calls = _ssh_fake(monkeypatch, root_stderr="Connection timed out")
    with pytest.raises(service.InspectorPreparationProofAttention):
        _run(state, parent, key, private, evidence)
    assert len(calls) == 4


def test_provider_identity_drift_stops_before_ssh(tmp_path, monkeypatch):
    state, parent, receipt, key, private, evidence = _started(tmp_path, monkeypatch)
    calls = _ssh_fake(monkeypatch)
    responses = linode_responses()
    responses["/linode/instances/123"]["label"] = "wrong"
    with pytest.raises(service.InspectorPreparationProofAttention):
        _run(state, parent, key, private, evidence, transport=Transport(responses))
    assert calls == []


def test_lease_loss_during_provider_get_stops_before_ssh(tmp_path, monkeypatch):
    state, parent, receipt, key, private, evidence = _started(tmp_path, monkeypatch)
    calls = _ssh_fake(monkeypatch)
    changed = False

    def after_get():
        nonlocal changed
        if not changed:
            changed = True
            with db.bind(state):
                child = SqlAlchemyJobRepository().get(receipt.coordinator_job_id)
                SqlAlchemyDeploymentPlanRepository().retag(
                    parent.target_id, child.input["corePlanId"], "wrong-operation")

    transport = Transport(linode_responses(), after_get=after_get)
    with pytest.raises(service.InspectorPreparationProofAttention):
        _run(state, parent, key, private, evidence, transport=transport)
    assert changed and transport.calls and calls == []


def test_claim_loss_after_first_ssh_stops_remaining_commands(tmp_path, monkeypatch):
    state, parent, receipt, key, private, evidence = _started(tmp_path, monkeypatch)
    changed = False

    def after_command(_command):
        nonlocal changed
        if not changed:
            changed = True
            with db.bind(state):
                jobs = SqlAlchemyJobRepository()
                child = jobs.get(receipt.coordinator_job_id)
                jobs.save(replace(child, input={**child.input, "claimToken": "b" * 32}))

    calls = _ssh_fake(monkeypatch, after_command=after_command)
    with pytest.raises(service.InspectorPreparationProofAttention):
        _run(state, parent, key, private, evidence)
    assert changed and len(calls) == 1


@pytest.mark.parametrize("kwargs,expected_calls", [
    ({"root_returncode": 0, "root_stderr": ""}, 4),
    ({"policy": "permitrootlogin yes\npasswordauthentication no\n"
                "kbdinteractiveauthentication no\n"}, 3),
    ({"nmap": "not an nmap version\n"}, 5),
    ({"peer": "9.9.9.9 55444 1.1.1.1 22\n"}, 2),
])
def test_read_only_ssh_mismatch_never_publishes(tmp_path, monkeypatch, kwargs, expected_calls):
    state, parent, receipt, key, private, evidence = _started(tmp_path, monkeypatch)
    calls = _ssh_fake(monkeypatch, **kwargs)
    with pytest.raises(service.InspectorPreparationProofAttention):
        _run(state, parent, key, private, evidence)
    assert len(calls) == expected_calls
