# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline command-path checks for the retained keyed ingress adapter."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services import provider_keyed_ingress_plan_gate as gate
from app.services import provider_keyed_ingress_update as runtime
from app.services.provider_keyed_ingress_update import (
    KeyedIngressUpdate, KeyedIngressUpdateAttention,
    apply_keyed_ingress_update, plan_keyed_ingress_update,
)
from test_provider_keyed_ingress_plan_gate import _case


class Credentials:
    def __init__(self, provider: str):
        self.row = SimpleNamespace(id="connection", provider=provider, status="active",
                                   encrypted_secret="sealed", updated_at="now")

    def get(self, identity):
        return self.row if identity == "connection" else None

    def get_default(self, provider):
        return self.row if provider == self.row.provider else None


def _state(resources):
    rows = []
    for address, values in resources.items():
        match = re.fullmatch(r'([^.]+)\.([^[]+)(?:\["([^"]+)"\])?', address)
        assert match is not None
        instance = {"attributes": values}
        if match.group(3) is not None:
            instance["index_key"] = match.group(3)
        rows.append({"mode": "managed", "type": match.group(1),
                     "name": match.group(2), "instances": [instance]})
    return {"version": 4, "resources": rows}


def _setup(tmp_path: Path, monkeypatch, provider: str = "digitalocean"):
    plan, args, firewall, field, _ = _case(provider)
    root = tmp_path / "keyed"
    root.mkdir()
    (root / ".terraform-data").mkdir()
    (root / ".terraform.lock.hcl").write_text("pinned", encoding="utf-8")
    (root / ".barragan-topology.json").write_text(json.dumps({"schema": "provider-keyed-v2"}), encoding="utf-8")
    (root / "terraform.tfstate").write_text(json.dumps(_state(args["retained_resources"])), encoding="utf-8")
    binary = tmp_path / "terraform"
    binary.write_text("reviewed binary", encoding="utf-8")
    binary.chmod(0o700)
    retained = {**args["reviewed_variables"], "allowed_tcp_ports": ["22", "80", "443", "2222"],
                "ssh_pub_key_path": "/kept/public", "ssh_priv_key_path": "/kept/private",
                "ssh_config_path": "/kept/output"}
    reviewed = {**retained, "allowed_tcp_ports": ["22", "80", "443", "2222", "3333"]}
    input_path = tmp_path / "original-inputs.json"
    input_path.write_text(json.dumps(retained), encoding="utf-8")
    plan["variables"] = {key: {"value": value} for key, value in reviewed.items()}
    plan["variables"]["do_pat" if provider == "digitalocean" else "linode_api_token"] = {"value": "token"}
    workspace = replace(args["workspace"], path=root, state_path=root / "terraform.tfstate",
                        terraform_data_dir=root / ".terraform-data")
    update = KeyedIngressUpdate(
        workspace, "job-1234", args["selected_channel_id"], args["retained_resources"],
        args["prior_routes"], args["next_routes"], args["attached_node_addresses"],
        args["observed_host_ports"], retained, reviewed, input_path,
        hashlib.sha256(input_path.read_bytes()).hexdigest(),
        hashlib.sha256(workspace.state_path.read_bytes()).hexdigest(),
        runtime._digest({"schema": "provider-keyed-v2"}),
    )
    monkeypatch.setattr(runtime, "_audit", lambda _: None)
    monkeypatch.setattr(runtime, "decrypt_secret_value", lambda _: "token")
    monkeypatch.setattr(gate, "require_digitalocean_workspace", lambda _: None)
    monkeypatch.setattr(gate, "require_linode_workspace", lambda _: None)
    validator = lambda **_: SimpleNamespace(path=binary, sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                                             version="1.15.5")
    calls = []

    def run(argv, cwd, env):
        calls.append(argv[1])
        if argv[1] == "plan":
            Path(next(part[5:] for part in argv if part.startswith("-out="))).write_bytes(b"saved-binary")
        if argv[1] == "apply":
            after = dict(args["retained_resources"])
            after[firewall] = plan["resource_changes"][0]["change"]["after"]
            workspace.state_path.write_text(json.dumps(_state(after)), encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, json.dumps(plan) if argv[1] == "show" else "", "")

    return update, Credentials(provider), validator, run, calls


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_real_command_path_plans_shows_and_applies_once(tmp_path, monkeypatch, provider):
    update, credentials, validator, run, calls = _setup(tmp_path, monkeypatch, provider)
    authority = []
    # Exercise the real writer, including every atomic status replacement.
    from app.services.provider_keyed_mixed_append_pair_plan_worker import _read
    phases = []
    original_replace = Path.replace
    def replace_private(path, target):
        if str(target).endswith("-status.json"):
            assert path.stat().st_mode & 0o777 == 0o600
            phases.append(json.loads(_read(path))["phase"])
        return original_replace(path, target)
    monkeypatch.setattr(Path, "replace", replace_private)
    planned = plan_keyed_ingress_update(
        update, credentials=credentials, recheck_authority=lambda: authority.append("checked"),
        command_environment={}, command_runner=run, release_validator=validator)
    assert planned["phase"] == "planned"
    assert calls == ["init", "plan", "show"]
    assert "token" not in json.dumps(planned)
    assert "token" not in next(update.workspace.path.glob("*-status.json")).read_text()
    completed = apply_keyed_ingress_update(
        update, credentials=credentials, recheck_authority=lambda: authority.append("checked"),
        post_apply_proof=lambda: authority.append("post-proof"),
        command_environment={}, command_runner=run, release_validator=validator)
    assert completed["phase"] == "applied"
    status_path = next(update.workspace.path.glob("*-status.json"))
    assert json.loads(_read(status_path)) == completed
    assert phases == ["planning", "planned", "apply_intent", "apply_result", "applied"]
    assert calls == ["init", "plan", "show", "show", "apply"]
    assert "post-proof" in authority
    with pytest.raises(KeyedIngressUpdateAttention):
        apply_keyed_ingress_update(
            update, credentials=credentials, recheck_authority=lambda: None,
            post_apply_proof=lambda: None, command_environment={},
            command_runner=run, release_validator=validator)
    assert calls.count("apply") == 1


@pytest.mark.parametrize("tamper", ["binary", "state", "input", "credential"])
def test_apply_rejects_drift_before_go(tmp_path, monkeypatch, tamper):
    update, credentials, validator, run, calls = _setup(tmp_path, monkeypatch)
    plan_keyed_ingress_update(update, credentials=credentials, recheck_authority=lambda: None,
                              command_environment={}, command_runner=run,
                              release_validator=validator)
    if tamper == "binary":
        next(update.workspace.path.glob("*.tfplan")).write_bytes(b"changed")
    elif tamper == "state":
        update.workspace.state_path.write_text("{}", encoding="utf-8")
    elif tamper == "input":
        update.retained_input_path.write_text("{}", encoding="utf-8")
    else:
        credentials.row.encrypted_secret = "rotated"
    with pytest.raises(KeyedIngressUpdateAttention):
        apply_keyed_ingress_update(update, credentials=credentials, recheck_authority=lambda: None,
                                   post_apply_proof=lambda: None, command_environment={},
                                   command_runner=run, release_validator=validator)
    assert calls.count("apply") == 0


def test_uncertain_apply_intent_is_never_replayed(tmp_path, monkeypatch):
    update, credentials, validator, run, calls = _setup(tmp_path, monkeypatch)
    plan_keyed_ingress_update(update, credentials=credentials, recheck_authority=lambda: None,
                              command_environment={}, command_runner=run,
                              release_validator=validator)

    def uncertain(argv, cwd, env):
        if argv[1] == "apply":
            calls.append("apply")
            raise RuntimeError("worker vanished")
        return run(argv, cwd, env)

    with pytest.raises(RuntimeError, match="worker vanished"):
        apply_keyed_ingress_update(update, credentials=credentials, recheck_authority=lambda: None,
                                   post_apply_proof=lambda: None, command_environment={},
                                   command_runner=uncertain, release_validator=validator)
    with pytest.raises(KeyedIngressUpdateAttention):
        apply_keyed_ingress_update(update, credentials=credentials, recheck_authority=lambda: None,
                                   post_apply_proof=lambda: None, command_environment={},
                                   command_runner=run, release_validator=validator)
    assert calls.count("apply") == 1


def test_apply_success_without_reviewed_state_change_remains_uncertain(tmp_path, monkeypatch):
    update, credentials, validator, run, calls = _setup(tmp_path, monkeypatch)
    plan_keyed_ingress_update(update, credentials=credentials, recheck_authority=lambda: None,
                              command_environment={}, command_runner=run,
                              release_validator=validator)

    def no_write(argv, cwd, env):
        if argv[1] == "apply":
            calls.append("apply")
            return subprocess.CompletedProcess(argv, 0, "", "")
        return run(argv, cwd, env)

    with pytest.raises(KeyedIngressUpdateAttention, match="applied state differs"):
        apply_keyed_ingress_update(update, credentials=credentials, recheck_authority=lambda: None,
                                   post_apply_proof=lambda: None, command_environment={},
                                   command_runner=no_write, release_validator=validator)
    assert json.loads(next(update.workspace.path.glob("*-status.json")).read_text())["phase"] == "apply_intent"


@pytest.mark.parametrize("failed_command", ["init", "plan"])
def test_definite_preapply_failure_cleans_token_and_allows_new_reviewed_job(
        tmp_path, monkeypatch, failed_command):
    update, credentials, validator, run, calls = _setup(tmp_path, monkeypatch)

    def fail_once(argv, cwd, env):
        if argv[1] == failed_command:
            calls.append(argv[1])
            if failed_command == "plan":
                Path(next(part[5:] for part in argv if part.startswith("-out="))).write_bytes(
                    b"partial binary")
            return subprocess.CompletedProcess(argv, 1, "secret output must not persist", "")
        return run(argv, cwd, env)

    with pytest.raises(KeyedIngressUpdateAttention, match="plan command failed"):
        plan_keyed_ingress_update(
            update, credentials=credentials, recheck_authority=lambda: None,
            command_environment={}, command_runner=fail_once,
            release_validator=validator)
    from app.services.provider_keyed_mixed_append_pair_plan_worker import _read
    status_path = next(update.workspace.path.glob("*-status.json"))
    assert status_path.stat().st_mode & 0o777 == 0o600
    status = json.loads(_read(status_path))
    assert {key: status[key] for key in ("phase", "failedCommand", "returnCode",
                                             "retryableWithNewJob")} == {
        "phase": "failed_pre_apply", "failedCommand": failed_command,
        "returnCode": 1, "retryableWithNewJob": True}
    assert not list(update.workspace.path.glob("*-credential.json"))
    assert not list(update.workspace.path.glob("*.tfplan"))
    assert "secret output" not in json.dumps(status)
    new_job = replace(update, job_id="job-5678")
    assert plan_keyed_ingress_update(
        new_job, credentials=credentials, recheck_authority=lambda: None,
        command_environment={}, command_runner=run,
        release_validator=validator)["phase"] == "planned"


def test_uncertain_preapply_command_keeps_token_and_fence(tmp_path, monkeypatch):
    update, credentials, validator, run, _ = _setup(tmp_path, monkeypatch)

    def uncertain(argv, cwd, env):
        raise RuntimeError("no command result")

    with pytest.raises(RuntimeError, match="no command result"):
        plan_keyed_ingress_update(
            update, credentials=credentials, recheck_authority=lambda: None,
            command_environment={}, command_runner=uncertain,
            release_validator=validator)
    status = json.loads(next(update.workspace.path.glob("*-status.json")).read_text())
    assert status["phase"] == "planning"
    assert len(list(update.workspace.path.glob("*-credential.json"))) == 1
    with pytest.raises(KeyedIngressUpdateAttention, match="already started"):
        plan_keyed_ingress_update(
            update, credentials=credentials, recheck_authority=lambda: None,
            command_environment={}, command_runner=run,
            release_validator=validator)


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_post_apply_proof_failure_preserves_exact_result_without_authorizing_replay(tmp_path, monkeypatch, provider):
    update, credentials, validator, run, calls = _setup(tmp_path, monkeypatch, provider)
    plan_keyed_ingress_update(update, credentials=credentials, recheck_authority=lambda: None,
                              command_environment={}, command_runner=run, release_validator=validator)
    status_path, inputs_path, _, plan_path = runtime._paths(update)
    planned = json.loads(status_path.read_text())
    def unavailable():
        assert calls.count("apply") == 1
        from app.services.provider_keyed_mixed_append_pair_plan_worker import _read
        receipt = json.loads(_read(status_path))
        assert receipt == {**planned, "phase": "apply_result", "returnCode": 0,
                           "postStateSha256": hashlib.sha256(update.workspace.state_path.read_bytes()).hexdigest()}
        after = Path(str(status_path).replace("-status.json", "-after.tfstate"))
        assert _read(after) == update.workspace.state_path.read_bytes()
        assert hashlib.sha256(_read(after)).hexdigest() == receipt["postStateSha256"]
        assert "token" not in json.dumps(receipt)
        raise ValueError("provider is still settling")
    with pytest.raises(ValueError, match="still settling"):
        apply_keyed_ingress_update(update, credentials=credentials, recheck_authority=lambda: None,
                                   post_apply_proof=unavailable, command_environment={},
                                   command_runner=run, release_validator=validator)
    assert json.loads(status_path.read_text())["phase"] == "apply_result"
    # The existing Apply entry point remains fail closed even after a durable rc0.
    with pytest.raises(KeyedIngressUpdateAttention):
        apply_keyed_ingress_update(update, credentials=credentials, recheck_authority=lambda: None,
                                   post_apply_proof=lambda: pytest.fail("must not publish"), command_environment={},
                                   command_runner=run, release_validator=validator)
    assert calls.count("apply") == 1


def test_changed_state_during_post_apply_proof_cannot_publish_result(tmp_path, monkeypatch):
    update, credentials, validator, run, calls = _setup(tmp_path, monkeypatch)
    plan_keyed_ingress_update(update, credentials=credentials, recheck_authority=lambda: None,
                              command_environment={}, command_runner=run, release_validator=validator)
    def drift():
        update.workspace.state_path.write_text("{}")
    with pytest.raises(KeyedIngressUpdateAttention, match="changed during post-Apply proof"):
        apply_keyed_ingress_update(update, credentials=credentials, recheck_authority=lambda: None,
                                   post_apply_proof=drift, command_environment={},
                                   command_runner=run, release_validator=validator)
    status_path, _, _, _ = runtime._paths(update)
    assert json.loads(status_path.read_text())["phase"] == "apply_result"
    assert calls.count("apply") == 1
