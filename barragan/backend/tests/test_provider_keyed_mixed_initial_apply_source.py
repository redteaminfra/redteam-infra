# Copyright (c) 2026, Oracle and/or its affiliates.
"""Locked pre-GO mixed saved-plan source, with no provider writes."""

import hashlib
import fcntl
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.services.provider_keyed_mixed_initial_apply_source as source_service
from app.services.provider_keyed_mixed_initial_plan_parent import seal_mixed_initial_apply
from app.services.provider_keyed_mixed_initial_apply_child import (
    MixedInitialApplyAttention, _child_id, run_mixed_initial_provider_apply,
)
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from test_provider_keyed_mixed_zero_apply_teardown_source import case


@pytest.fixture
def sealed(case, monkeypatch):
    parent = seal_mixed_initial_apply(**case.plan_args)
    monkeypatch.setattr(source_service, "_default_state_root", lambda: case.state_root)
    args = {key: value for key, value in case.plan_args.items() if key not in {
        "core_job_id", "engagement_id", "lease_owner", "template_root",
        "linode_runner", "digitalocean_runner"}}
    terraform = Path(__import__("sys").executable).resolve(strict=True)
    args.update(release_check=lambda **kwargs: SimpleNamespace(
        path=terraform, sha256=hashlib.sha256(terraform.read_bytes()).hexdigest()),
        token_decoder=lambda encrypted: "ephemeral-test-token")
    locks = {}
    for provider in ("linode", "digitalocean"):
        root = next((case.state_root / "eng-opaque" / "provider-keyed-v2" / provider).iterdir())
        name = (".barragan-linode-plan.lock" if provider == "linode"
                else ".barragan-digitalocean-plan.lock")
        lock = root / name
        lock.write_bytes(b"")
        lock.chmod(0o600)
        locks[provider] = lock
    return SimpleNamespace(parent=parent, case=case, args=args, locks=locks)


def test_both_orders_reopen_exact_receipt_under_existing_lock(sealed):
    for provider in sealed.parent.input["orderedProviders"]:
        public = (sealed.locks[provider].parent.parents[1] / ".plan-material"
                  / provider / "admin-public")
        assert not public.exists()
        with source_service.audited_mixed_initial_apply_source(
                sealed.parent, provider, lambda: None, **sealed.args) as source:
            source.lock_fence()
            assert public.read_text().startswith("ssh-")
            assert public.stat().st_mode & 0o077 == 0
            assert source.workspace.provider == provider
            assert source.command[1] == "apply"
            assert source.receipt_sha256 in sealed.parent.events[5].data["receiptSha256"]
            if provider == "digitalocean":
                assert source.selector_tag == sealed.parent.events[5].data["reviewedPolicy"][provider]["selector_tag"]
        assert not public.exists()


def test_apply_public_key_is_removed_after_failure_and_stale_key_blocks_write(sealed):
    provider = sealed.parent.input["orderedProviders"][0]
    public = (sealed.locks[provider].parent.parents[1] / ".plan-material"
              / provider / "admin-public")
    with pytest.raises(RuntimeError, match="failed Apply"):
        with source_service.audited_mixed_initial_apply_source(
                sealed.parent, provider, lambda: None, **sealed.args):
            assert public.exists()
            raise RuntimeError("failed Apply")
    assert not public.exists()
    public.write_text("stale")
    public.chmod(0o600)
    with pytest.raises(FileExistsError):
        with source_service.audited_mixed_initial_apply_source(
                sealed.parent, provider, lambda: None, **sealed.args):
            pytest.fail("stale key must block before Apply")
    assert public.read_text() == "stale"


def test_missing_or_replaced_saved_plan_lock_rejects(sealed):
    provider = sealed.parent.input["orderedProviders"][0]
    lock = sealed.locks[provider]
    lock.unlink()
    with pytest.raises(source_service.MixedInitialApplySourceError, match="lock is missing"):
        with source_service.audited_mixed_initial_apply_source(
                sealed.parent, provider, lambda: None, **sealed.args):
            pass
    lock.write_bytes(b"")
    lock.chmod(0o600)
    with source_service.audited_mixed_initial_apply_source(
            sealed.parent, provider, lambda: None, **sealed.args) as source:
        lock.unlink()
        lock.write_bytes(b"")
        lock.chmod(0o600)
        with pytest.raises(source_service.MixedInitialApplySourceError, match="changed inode"):
            source.lock_fence()


def test_changed_saved_plan_bytes_reject_before_yield(sealed):
    provider = sealed.parent.input["orderedProviders"][0]
    root = sealed.locks[provider].parent
    name = (".barragan-linode-initial-full.tfplan" if provider == "linode"
            else ".barragan-digitalocean-initial-full.tfplan")
    (root / name).write_bytes(b"changed after saved receipt")
    with pytest.raises(Exception):
        with source_service.audited_mixed_initial_apply_source(
                sealed.parent, provider, lambda: None, **sealed.args):
            pass


def test_audited_source_stays_locked_through_private_first_apply(sealed):
    provider = sealed.parent.input["orderedProviders"][0]
    lock = sealed.locks[provider]
    calls = []

    def assert_locked(stage):
        descriptor = os.open(lock, os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)
        calls.append(stage)

    def source_session(parent, selected, renew):
        return source_service.audited_mixed_initial_apply_source(
            parent, selected, renew, **sealed.args)

    def reserve(selector, token, *, fence, on_intent, on_receipt,
                get_transport, post_transport):
        assert_locked("selector POST")
        fence()
        on_intent()
        on_receipt(201, selector)
        return (selector,)

    def runner(command, *, scratch_path, provider_keyed_v2, gate_timeout_seconds,
               intent_callback, started_callback, heartbeat_callback, result_callback, env):
        assert provider_keyed_v2 and gate_timeout_seconds == 1200
        assert env["TF_DATA_DIR"] == str(scratch_path / ".terraform-data")
        assert env["TF_CLI_CONFIG_FILE"] == "/dev/null"
        digest = hashlib.sha256(json.dumps(command, separators=(",", ":")).encode()).hexdigest()
        intent = CommandIntent("invocation", str(scratch_path), digest)
        assert_locked("command intent")
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 99))
        assert_locked("command start")
        started_callback(started)
        heartbeat_callback(started)
        (scratch_path / "terraform.tfstate").write_text("{}")
        assert_locked("command result")
        result_callback(CommandAuditResult(started, 0, 4, 0, False, False))
        return CommandResult(started, 0, "done", "", False, False)

    run_args = dict(engagement_id="eng-opaque", core_job_id=sealed.parent.input["coreJobId"],
                    provider=provider, environment="devtest", job_repository=sealed.case.jobs,
                    lease_lookup=sealed.args["lease_lookup"], source_session=source_session,
                    selector_absence_prover=lambda source, fence: (fence(), "a" * 64)[1],
                    selector_get_transport=object(), selector_post_transport=object(),
                    selector_reserver=reserve, gated_command_runner=runner,
                    release_check=sealed.args["release_check"])
    child = run_mixed_initial_provider_apply(**run_args)
    assert child.events[-1].message == "mixed provider awaiting exact observation"
    assert calls == (["selector POST"] if provider == "digitalocean" else []) + [
        "command intent", "command start", "command result"]


@pytest.mark.parametrize("drift", ["credential", "plan"])
def test_audited_source_rejects_drift_before_provider_write(sealed, drift):
    provider = sealed.parent.input["orderedProviders"][0]
    if drift == "credential":
        sealed.args["credential_repository"] = SimpleNamespace(get=lambda connection_id: None)
    else:
        plan_name = (".barragan-linode-initial-full.tfplan" if provider == "linode"
                     else ".barragan-digitalocean-initial-full.tfplan")
        (sealed.locks[provider].parent / plan_name).write_bytes(b"changed-after-review")
    calls = []
    with pytest.raises(Exception):
        run_mixed_initial_provider_apply(
            "eng-opaque", sealed.parent.input["coreJobId"], provider,
            environment="devtest", job_repository=sealed.case.jobs,
            lease_lookup=sealed.args["lease_lookup"],
            source_session=lambda parent, selected, renew:
                source_service.audited_mixed_initial_apply_source(
                    parent, selected, renew, **sealed.args),
            selector_absence_prover=lambda *_: calls.append("absence"),
            selector_get_transport=object(), selector_post_transport=object(),
            selector_reserver=lambda *args, **kwargs: calls.append("POST"),
            gated_command_runner=lambda *args, **kwargs: calls.append("Apply"),
            release_check=sealed.args["release_check"])
    assert calls == []


def test_lock_replacement_during_command_callback_prevents_go(sealed):
    provider = sealed.parent.input["orderedProviders"][0]
    lock = sealed.locks[provider]
    calls = []

    def runner(command, *, scratch_path, provider_keyed_v2, gate_timeout_seconds,
               intent_callback, started_callback, heartbeat_callback, result_callback, env):
        assert env["TF_DATA_DIR"] == str(scratch_path / ".terraform-data")
        assert env["TF_CLI_CONFIG_FILE"] == "/dev/null"
        digest = hashlib.sha256(json.dumps(command, separators=(",", ":")).encode()).hexdigest()
        intent = CommandIntent("invocation", str(scratch_path), digest)
        intent_callback(intent)
        lock.unlink()
        lock.write_bytes(b"")
        lock.chmod(0o600)
        calls.append("lock replaced")
        started_callback(StartedCommand(intent, ProcessIdentity("boot", 123, 123, 99)))
        calls.append("GO")

    with pytest.raises(source_service.MixedInitialApplySourceError, match="changed inode"):
        run_mixed_initial_provider_apply(
            "eng-opaque", sealed.parent.input["coreJobId"], provider,
            environment="devtest", job_repository=sealed.case.jobs,
            lease_lookup=sealed.args["lease_lookup"],
            source_session=lambda parent, selected, renew:
                source_service.audited_mixed_initial_apply_source(
                    parent, selected, renew, **sealed.args),
            selector_absence_prover=lambda source, fence: (fence(), "a" * 64)[1],
            selector_get_transport=object(), selector_post_transport=object(),
            selector_reserver=lambda selector, token, *, fence, on_intent, on_receipt,
                                     get_transport, post_transport:
                (on_intent(), on_receipt(201, selector), (selector,))[2],
            gated_command_runner=runner, release_check=sealed.args["release_check"])
    assert calls == ["lock replaced"]
    assert not (lock.parent / "terraform.tfstate").exists()
    child = sealed.case.jobs.get(_child_id(sealed.parent.input["coreJobId"], provider))
    assert any(event.message == "mixed provider Apply command intended" for event in child.events)
    assert not any(event.message == "mixed provider Apply command started before GO"
                   for event in child.events)
