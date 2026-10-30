# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network vertical proof through the real pinned upstream bootstrap adapter."""

from dataclasses import replace
import os
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
import time

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_initial_bootstrap as caller
from app.services import sketch_bootstrap_apply as helper
from app.services.credentials import test_master_key as _test_master_key
from app.services.provider_keyed_host_binding import bind_initial_digitalocean_host_identity
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
    UnreapedGatedCommandError,
    run_gated_command,
)
from app.services.redteam_infra_template import TEMPLATE_ROOT_ENV
from app.services.sketch_ssh_keys import _new_stored_key
from app.storage.database import db
from app.storage.sketch_ssh_key_repository import SqlAlchemySketchSshKeyRepository
from app.storage.sketch_transport_ssh_key_repository import SqlAlchemySketchTransportSshKeyRepository
from test_provider_keyed_host_binding import _setup


PINNED_REVISION = "90b6895d9eccc0cf19524396b528a289f5f22fb1"


def _clean_pinned_checkout(tmp_path: Path) -> Path:
    configured = os.environ.get(TEMPLATE_ROOT_ENV, "").strip()
    candidates = ((Path(configured),) if configured else (
        Path.cwd().parent / "redteam-infra",
        Path("/opt/redteam-infra"),
        Path("/Users/example_operator/Development/SCM/redteam-infra"),
    ))
    source = None
    for candidate in candidates:
        if not candidate.is_dir():
            continue
        exists = subprocess.run(
            ["git", "-C", str(candidate), "cat-file", "-e", f"{PINNED_REVISION}^{{commit}}"],
            check=False, capture_output=True,
        )
        if exists.returncode == 0:
            source = candidate
            break
    if source is None:
        if configured:
            pytest.fail(f"configured {TEMPLATE_ROOT_ENV} lacks pinned Redteam-infra d52cce5")
        pytest.skip("pinned Redteam-infra d52cce5 Git object is unavailable locally")
    root = tmp_path / "redteam-infra"
    subprocess.run(["git", "clone", "-q", "--no-checkout", str(source), str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "checkout", "-q", "--detach", PINNED_REVISION], check=True)
    assert root.resolve(strict=True) == root
    return root


def _bound_fixture(tmp_path: Path):
    root = _clean_pinned_checkout(tmp_path)
    jobs, parent_id, options, _calls, workspace, core_hosts = _setup(tmp_path)
    workspace.source_revision = PINNED_REVISION
    core = jobs.get("job-core")
    details = [
        {"role": "homebase", "publicIp": "203.0.113.2", "sshUser": "user"},
        {"role": "proxy", "name": "proxy01", "privateIp": "10.0.2.10", "publicIp": "8.8.8.8", "sshUser": "user"},
        {"role": "proxy", "name": "proxy02", "privateIp": "10.0.2.11", "publicIp": "9.9.9.9", "sshUser": "user"},
    ]
    first = core.events[0]
    jobs.save(replace(core, events=[JobEvent(first.sequence, first.level, first.message,
                                             {**first.data, "connectionDetails": details}), *core.events[1:]]))
    core_hosts.write_text("8.8.8.8 ssh-ed25519 pinned-proxy01\n9.9.9.9 ssh-ed25519 pinned-proxy02\n")
    bound = bind_initial_digitalocean_host_identity(parent_id, **options)
    assert bound.input["phase"] == "host_identity_bound"
    return root, jobs, parent_id, options, workspace, core_hosts


def _seed_durable_keys():
    admin = _new_stored_key("eng-opaque", "opaque")
    transport = _new_stored_key("eng-opaque", "opaque-transport")
    SqlAlchemySketchSshKeyRepository().save(admin)
    SqlAlchemySketchTransportSshKeyRepository().save(transport)


def test_caller_runs_real_render_and_key_cleanup_with_fake_no_network_commands(tmp_path, monkeypatch):
    root, jobs, parent_id, options, workspace, core_hosts = _bound_fixture(tmp_path)
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", _test_master_key())
    monkeypatch.setattr(helper, "resolve_ansible_playbook",
                        lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    state = db.configure("sqlite:///:memory:")
    commands = []
    sketch_hosts = workspace.path / ".barragan-sketch-known-hosts"
    original_inode = sketch_hosts.stat().st_ino

    def runner(command, cwd, _env):
        parent = jobs.get(parent_id)
        prepared = next(event.data for event in parent.events
                        if event.message == "provider bootstrap preparation fenced")
        index = prepared["scratchPaths"].index(str(cwd))
        chain_id = prepared["chainIds"][index]
        name = str(command[-1])
        if name.endswith("wait_for_sketch_readiness.yml"):
            phase = "readiness"
            assert parent.input["phase"] == "bootstrap_contacted"
            assert any(event.message == "provider bootstrap first host contact fenced" for event in parent.events)
            if index == 1:
                assert [event.data["chainId"] for event in parent.events
                        if event.message == "provider chain bootstrap completed; host proof pending"] == [prepared["chainIds"][0]]
                assert "pinned-first-chain" in sketch_hosts.read_text()
        elif any(str(part).endswith("upstream-sketch-playbook.compat.yml") for part in command):
            phase = "root"
            assert parent.input["phase"] == "bootstrap_root_started"
            assert any(event.message == "provider upstream root bootstrap start fenced"
                       and event.data["chainId"] == chain_id for event in parent.events)
        elif name.endswith("wait_for_sketch_user_readiness.yml"):
            phase = "user"
            assert parent.input["phase"] == "bootstrap_root_started"
        elif name.endswith("install_sketch_transport.yml"):
            phase = "transport"
            assert parent.input["phase"] == "bootstrap_root_started"
        else:
            pytest.fail(f"unexpected Ansible command: {name}")
        assert parent.events[-1].message == "provider bootstrap command started before GO"
        assert parent.events[-1].data["chainId"] == chain_id
        config = (cwd / "ansible/ssh_config").read_text()
        assert "ProxyJump barragan-bootstrap-proxy,barragan-bootstrap-root-" in config
        assert "StrictHostKeyChecking accept-new" in config
        assert "StrictHostKeyChecking yes" in config
        assert f"UserKnownHostsFile {sketch_hosts}" in config
        assert f"UserKnownHostsFile {core_hosts}" in config
        expected_alias, expected_private = (("8.8.8.8", "10.0.2.10") if index == 0
                                            else ("9.9.9.9", "10.0.2.11"))
        assert f"HostKeyAlias {expected_alias}" in config
        assert f"HostName {expected_private}" in config
        assert (cwd / "keys").is_dir()
        admin_keys = [path for path in (cwd / "keys").iterdir() if path.name == "opaque-sketch"]
        assert len(admin_keys) == 1 and admin_keys[0].stat().st_mode & 0o777 == 0o600
        commands.append((chain_id, phase))
        if index == 0 and phase == "readiness":
            with sketch_hosts.open("a") as stream:
                stream.write("pinned-first-chain ssh-ed25519 test-key\n")
        return subprocess.CompletedProcess(command, 0, "", "")

    invocations = []
    def gated(command, *, scratch_path, intent_callback, started_callback,
              heartbeat_callback, result_callback, provider_keyed_v2, env, execution_timeout_seconds):
        assert execution_timeout_seconds == 1800
        assert provider_keyed_v2
        number = len(invocations) + 1
        intent = CommandIntent(f"fixture-{number}", str(scratch_path), f"digest-{number}")
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity("fixture-boot", 1000 + number, 1000 + number, number))
        started_callback(started)
        heartbeat_callback(started)
        completed = runner(command, scratch_path, env)
        result_callback(CommandAuditResult(started, completed.returncode, 0, 0, False, False))
        invocations.append(intent)
        return CommandResult(started, completed.returncode, completed.stdout, completed.stderr, False, False)

    with db.bind(state):
        db.create_all()
        _seed_durable_keys()
        result = caller.bootstrap_initial_digitalocean_chains(
            parent_id, **options,
            bootstrap_env={TEMPLATE_ROOT_ENV: str(root)},
            bootstrap_helper=helper.apply_sketch_bootstrap,
            gated_command_runner=gated,
        )
    assert result.status == "running" and result.input["phase"] == "awaiting_strict_host_proof", [(event.message, event.data) for event in result.events[-3:]]
    ids = result.events[-1].data["chainIds"]
    assert commands == [(ids[0], phase) for phase in ("readiness", "root", "user", "transport")] + [
        (ids[1], phase) for phase in ("readiness", "root", "user", "transport")]
    assert len(invocations) == 8
    for number, event in enumerate((event for event in result.events
                                    if event.message == "provider bootstrap command intent fenced"), 1):
        assert event.data["invocationId"] == f"fixture-{number}"
        assert event.data["sequence"] == (number - 1) % 4 + 1
        assert event.data["attempt"] == 1
    assert sum(event.message == "provider bootstrap command result fenced" for event in result.events) == 8
    assert sketch_hosts.stat().st_ino == original_inode
    assert core_hosts.read_text().count("pinned-proxy") == 2
    assert "pinned-proxy" not in sketch_hosts.read_text()
    scratch = next(event.data["scratchPaths"] for event in result.events
                   if event.message == "provider bootstrap preparation fenced")
    assert len(set(scratch)) == 2
    for raw_path in scratch:
        path = Path(raw_path)
        assert path.stat().st_mode & 0o777 == 0o700
        assert not (path / "keys").exists()
        assert (path / "ansible/ssh_config").is_file()
    assert all(not chain.nodes and chain.status == "pending"
               for chain in options["sketch_repository"].list_for_engagement("eng-opaque"))


def test_wrong_pinned_source_fails_before_any_fake_runner_command(tmp_path, monkeypatch):
    root, jobs, parent_id, options, _workspace, _core_hosts = _bound_fixture(tmp_path)
    playbook = root / "external/sketch/ansible/sketch-playbook.yml"
    playbook.write_text(playbook.read_text() + "\n# dirty test\n")
    commands = []
    result = caller.bootstrap_initial_digitalocean_chains(
        parent_id, **options, bootstrap_env={TEMPLATE_ROOT_ENV: str(root)},
        bootstrap_helper=helper.apply_sketch_bootstrap,
        gated_command_runner=lambda *_args, **_kwargs: commands.append("unexpected"),
    )
    assert result.status == "failed" and result.input["phase"] == "attention"
    assert not any(event.message == "provider bootstrap preparation fenced" for event in result.events)
    assert commands == []


def test_unproved_gated_group_retains_keys_and_stops_before_next_command(tmp_path, monkeypatch):
    root, jobs, parent_id, options, workspace, _core_hosts = _bound_fixture(tmp_path)
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", _test_master_key())
    monkeypatch.setattr(helper, "resolve_ansible_playbook",
                        lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    state = db.configure("sqlite:///:memory:")
    attempted = []
    def uncertain(command, *, scratch_path, intent_callback, started_callback, **_kwargs):
        attempted.append(command)
        intent = CommandIntent("uncertain-1", str(scratch_path), "opaque-digest")
        intent_callback(intent)
        started_callback(StartedCommand(intent, ProcessIdentity("boot", 4321, 4321, 9)))
        raise UnreapedGatedCommandError("possibly live group")
    with db.bind(state):
        db.create_all()
        _seed_durable_keys()
        result = caller.bootstrap_initial_digitalocean_chains(
            parent_id, **options, bootstrap_env={TEMPLATE_ROOT_ENV: str(root)},
            bootstrap_helper=helper.apply_sketch_bootstrap,
            gated_command_runner=uncertain,
        )
    assert result.status == "failed" and result.input["phase"] == "attention"
    assert result.events[-1].message == "provider bootstrap process-group quiescence unproved; staged keys retained"
    assert len(attempted) == 1
    assert sum(event.message == "provider bootstrap command started before GO" for event in result.events) == 1
    assert not any(event.message == "provider bootstrap command result fenced" for event in result.events)
    prepared = next(event.data for event in result.events
                    if event.message == "provider bootstrap preparation fenced")
    first = Path(prepared["scratchPaths"][0])
    assert (first / "keys/opaque-sketch").exists()
    assert not Path(prepared["scratchPaths"][1]).exists()
    assert all(not chain.nodes and chain.status == "pending"
               for chain in options["sketch_repository"].list_for_engagement("eng-opaque"))


@pytest.mark.parametrize("cleanup_failure", [False, True])
def test_proven_nonzero_root_command_cleans_keys_and_stops_before_sibling(
    tmp_path, monkeypatch, cleanup_failure,
):
    root, jobs, parent_id, options, _workspace, _core_hosts = _bound_fixture(tmp_path)
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", _test_master_key())
    monkeypatch.setattr(helper, "resolve_ansible_playbook",
                        lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook"))
    if cleanup_failure:
        original_rmtree = helper.shutil.rmtree
        def fail_key_removal(path, *args, **kwargs):
            if Path(path).name == "keys":
                raise OSError("simulated cleanup failure")
            return original_rmtree(path, *args, **kwargs)
        monkeypatch.setattr(helper.shutil, "rmtree", fail_key_removal)
    state = db.configure("sqlite:///:memory:")
    attempted = []
    def bounded(command, *, scratch_path, intent_callback, started_callback,
                heartbeat_callback, result_callback, **_kwargs):
        phase = "root" if any(str(part).endswith("upstream-sketch-playbook.compat.yml") for part in command) else "readiness"
        attempted.append(phase)
        intent = CommandIntent(f"bounded-{len(attempted)}", str(scratch_path), "opaque-digest")
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity("boot", 4321, 4321, len(attempted)))
        started_callback(started)
        heartbeat_callback(started)
        code = 2 if phase == "root" else 0
        result_callback(CommandAuditResult(started, code, 0, 0, False, False))
        return CommandResult(started, code, "", "fixture failure" if code else "", False, False)
    with db.bind(state):
        db.create_all()
        _seed_durable_keys()
        result = caller.bootstrap_initial_digitalocean_chains(
            parent_id, **options, bootstrap_env={TEMPLATE_ROOT_ENV: str(root)},
            bootstrap_helper=helper.apply_sketch_bootstrap,
            gated_command_runner=bounded,
        )
    assert result.status == "failed" and result.input["phase"] == "attention"
    assert attempted == ["readiness", "root"]
    assert sum(event.message == "provider bootstrap command result fenced" for event in result.events) == 2
    assert (result.events[-1].message == "provider bootstrap key cleanup unproved; manual read-only reconciliation required"
            if cleanup_failure else result.events[-1].message.startswith(
                "provider bootstrap stopped; manual read-only reconciliation required; "
                "upstream sketch bootstrap failed (exit 2)"))
    if not cleanup_failure:
        assert "upstream sketch bootstrap failed (exit 2)" in result.events[-1].data["failureDetail"]
        assert "fixture failure" in result.events[-1].data["failureDetail"]
    prepared = next(event.data for event in result.events
                    if event.message == "provider bootstrap preparation fenced")
    first = Path(prepared["scratchPaths"][0])
    assert first.is_dir() and (first / "keys").exists() == cleanup_failure
    assert not Path(prepared["scratchPaths"][1]).exists()


def test_real_local_gated_child_loses_lease_and_stops_before_sibling(tmp_path, monkeypatch):
    root, jobs, parent_id, options, _workspace, _core_hosts = _bound_fixture(tmp_path)
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", _test_master_key())
    delayed = tmp_path / "must-not-run-after-cancel"
    executable = tmp_path / "fake-ansible-playbook"
    executable.write_text(
        f"#!{sys.executable}\nimport time\nfrom pathlib import Path\n"
        f"time.sleep(1)\nPath({str(delayed)!r}).write_text('unsafe continuation')\n"
    )
    executable.chmod(0o700)
    monkeypatch.setattr(helper, "resolve_ansible_playbook",
                        lambda **_kwargs: SimpleNamespace(ok=True, command=str(executable)))
    original_lookup = options["lease_lookup"]
    def lease(engagement_id):
        parent = jobs.get(parent_id)
        if any(event.message == "provider bootstrap command started before GO" for event in parent.events):
            return None
        return original_lookup(engagement_id)
    options["lease_lookup"] = lease
    def gated(command, **kwargs):
        return run_gated_command(
            command, identity_reader=lambda pid: ProcessIdentity("local-test", pid, pid, 1),
            group_members_reader=lambda _identity: set(), heartbeat_interval=0.05,
            **kwargs,
        )
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        _seed_durable_keys()
        result = caller.bootstrap_initial_digitalocean_chains(
            parent_id, **options, bootstrap_env={TEMPLATE_ROOT_ENV: str(root)},
            bootstrap_helper=helper.apply_sketch_bootstrap,
            gated_command_runner=gated,
        )
    assert result.status == "failed" and result.input["phase"] == "attention"
    assert sum(event.message == "provider bootstrap command started before GO" for event in result.events) == 1
    assert not any(event.message == "provider bootstrap command result fenced" for event in result.events)
    prepared = next(event.data for event in result.events
                    if event.message == "provider bootstrap preparation fenced")
    first = Path(prepared["scratchPaths"][0])
    assert first.is_dir() and not (first / "keys").exists()
    assert not Path(prepared["scratchPaths"][1]).exists()
    time.sleep(1.1)
    assert not delayed.exists()


@pytest.mark.skipif(not Path("/proc/sys/kernel/random/boot_id").exists(),
                    reason="real gated bootstrap requires Linux /proc identity")
def test_linux_two_chains_use_real_gated_runner_with_no_network_executable(tmp_path, monkeypatch):
    root, jobs, parent_id, options, workspace, _core_hosts = _bound_fixture(tmp_path)
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", _test_master_key())
    executable = tmp_path / "fake-ansible-playbook"
    executable.write_text(
        f"#!{sys.executable}\n"
        "print('no-network bootstrap fixture')\n"
    )
    executable.chmod(0o700)
    monkeypatch.setattr(helper, "resolve_ansible_playbook",
                        lambda **_kwargs: SimpleNamespace(ok=True, command=str(executable)))
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        _seed_durable_keys()
        result = caller.bootstrap_initial_digitalocean_chains(
            parent_id, **options, bootstrap_env={TEMPLATE_ROOT_ENV: str(root)},
            bootstrap_helper=helper.apply_sketch_bootstrap,
        )
    assert result.status == "running" and result.input["phase"] == "awaiting_strict_host_proof"
    phases = ("root_management_readiness", "upstream_root_bootstrap", "user_readiness", "transport_install")
    prepared = next(event.data for event in result.events
                    if event.message == "provider bootstrap preparation fenced")
    chain_ids = prepared["chainIds"]
    command_events = [event for event in result.events
                      if event.message in (
                          "provider bootstrap command intent fenced",
                          "provider bootstrap command started before GO",
                          "provider bootstrap command result fenced",
                      )]
    assert len(command_events) == 24
    for index, chain_id in enumerate(chain_ids):
        for sequence, phase in enumerate(phases, 1):
            intent, started, outcome = command_events[(index * 4 + sequence - 1) * 3:
                                                       (index * 4 + sequence) * 3]
            assert [event.message for event in (intent, started, outcome)] == [
                "provider bootstrap command intent fenced",
                "provider bootstrap command started before GO",
                "provider bootstrap command result fenced",
            ]
            assert all(event.data["chainId"] == chain_id and event.data["phase"] == phase
                       and event.data["sequence"] == sequence and event.data["attempt"] == 1
                       for event in (intent, started, outcome))
            assert started.data["invocationId"] == outcome.data["invocationId"] == intent.data["invocationId"]
            assert started.data["pid"] == started.data["pgid"] > 0
            assert started.data["bootId"] and started.data["startTicks"] > 0
            assert outcome.data["returnCode"] == 0 and outcome.data["stdoutBytes"] > 0
        scratch = Path(prepared["scratchPaths"][index])
        assert scratch.is_dir() and not (scratch / "keys").exists()
    assert sum(event.message == "provider chain bootstrap completed; host proof pending"
               for event in result.events) == 2
    assert (workspace.path / ".barragan-sketch-known-hosts").is_file()
    assert all(not chain.nodes and chain.status == "pending"
               for chain in options["sketch_repository"].list_for_engagement("eng-opaque"))
