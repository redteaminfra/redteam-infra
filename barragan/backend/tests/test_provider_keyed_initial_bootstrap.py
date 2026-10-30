# Copyright (c) 2026, Oracle and/or its affiliates.
"""Two-chain bootstrap is fenced before contact and never automatically replayed."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.services import provider_keyed_initial_bootstrap as service
from app.services.provider_keyed_host_binding import bind_initial_digitalocean_host_identity
from app.services.provider_keyed_digitalocean_attachment import DigitalOceanAttachmentStillSettling
from app.services.provider_keyed_gated_runner import CommandIntent, CommandResult, ProcessIdentity, StartedCommand
from app.services.redteam_infra_template import TEMPLATE_ROOT_ENV
from app.services.sketch_bootstrap_apply import SketchBootstrapApplyResult
from test_provider_keyed_host_binding import _setup


def _ready(tmp_path):
    jobs, parent_id, options, _calls, workspace, core_hosts = _setup(tmp_path)
    bound = bind_initial_digitalocean_host_identity(parent_id, **options)
    assert bound.input["phase"] == "host_identity_bound"
    return jobs, parent_id, options, workspace, core_hosts


def _bootstrap_options(options, helper):
    root = options["state_root"].parent / "upstream"
    root.mkdir(mode=0o700, exist_ok=True)
    root.chmod(0o700)
    env = {TEMPLATE_ROOT_ENV: str(root)}
    def verify(*, env, required_source_root, required_source_revision):
        assert env[TEMPLATE_ROOT_ENV] == str(root)
        assert required_source_root == root
        assert required_source_revision == "a" * 40
        return root
    return {**options, "bootstrap_helper": helper, "bootstrap_env": env,
            "source_verifier": verify}


def _success_helper(commands, *, add_pin=False):
    def helper(_engagement_id, chain, **kwargs):
        path = kwargs["workspace_root"]
        assert not path.exists()
        assert kwargs["host_policies"] and kwargs["proxy_egress_ip"]
        assert kwargs["initial_sketch_known_hosts_path"].is_file()
        assert kwargs["pinned_core_known_hosts_path"].is_file()
        assert kwargs["required_source_root"] == service.Path(kwargs["env"][TEMPLATE_ROOT_ENV])
        assert kwargs["required_source_revision"] == "a" * 40
        assert chain.status == "pending" and chain.nodes and not chain.deploy_job_id
        path.mkdir(mode=0o700)
        keys = path / "keys"
        keys.mkdir(mode=0o700)
        (keys / "admin-private").write_text("staged test secret")
        reporter = kwargs["progress_reporter"]
        reporter("checking", {"phase": "root-management-readiness"})
        commands.append((chain.chain_id, "readiness"))
        reporter("starting", {"phase": "upstream-root-bootstrap"})
        commands.append((chain.chain_id, "root"))
        if add_pin:
            with kwargs["initial_sketch_known_hosts_path"].open("a") as stream:
                stream.write(f"{chain.chain_id} ssh-ed25519 pinned-test-key\n")
        (keys / "admin-private").unlink()
        keys.rmdir()
        return SketchBootstrapApplyResult(0, 0, len(chain.nodes))
    return helper


def test_two_chains_bootstrap_in_order_with_private_scratch_and_shared_pins(tmp_path):
    jobs, parent_id, options, workspace, _core_hosts = _ready(tmp_path)
    commands = []
    first_pin = None
    first_inode = None
    base = _success_helper(commands, add_pin=True)
    def helper(engagement_id, chain, **kwargs):
        nonlocal first_pin, first_inode
        inode = kwargs["initial_sketch_known_hosts_path"].stat().st_ino
        if first_pin is None:
            assert kwargs["initial_sketch_known_hosts_path"].read_bytes() == b""
        else:
            assert kwargs["initial_sketch_known_hosts_path"].read_text() == first_pin
            assert inode == first_inode
        result = base(engagement_id, chain, **kwargs)
        if first_pin is None:
            first_pin = kwargs["initial_sketch_known_hosts_path"].read_text()
            first_inode = inode
        return result
    result = service.bootstrap_initial_digitalocean_chains(
        parent_id, **_bootstrap_options(options, helper),
    )
    assert result.status == "running" and result.input["phase"] == "awaiting_strict_host_proof"
    assert result.events[-1].data["hostProofPending"] is True
    ids = result.events[-1].data["chainIds"]
    assert commands == [(ids[0], "readiness"), (ids[0], "root"),
                        (ids[1], "readiness"), (ids[1], "root")]
    messages = [event.message for event in result.events]
    assert messages.index("provider bootstrap preparation fenced") < messages.index(
        "provider bootstrap first host contact fenced") < messages.index(
        "provider upstream root bootstrap start fenced")
    completions = [event.data["chainId"] for event in result.events
                   if event.message == "provider chain bootstrap completed; host proof pending"]
    assert completions == ids
    prepared = next(event.data for event in result.events
                    if event.message == "provider bootstrap preparation fenced")
    assert prepared["chainIds"] == ids and len(set(prepared["scratchPaths"])) == 2
    for raw_path in prepared["scratchPaths"]:
        path = workspace.path / raw_path.rsplit("/", 1)[-1]
        assert str(path) == raw_path and path.stat().st_mode & 0o777 == 0o700
        assert not (path / "keys").exists()
    assert all(not chain.nodes for chain in options["sketch_repository"].list_for_engagement("eng-opaque"))
    assert len((workspace.path / ".barragan-sketch-known-hosts").read_text().splitlines()) == 2
    with pytest.raises(service.ProviderKeyedInitialBootstrapError):
        service.bootstrap_initial_digitalocean_chains(parent_id, **_bootstrap_options(options, helper))
    assert len(commands) == 4


def test_corrected_initial_plan_bootstraps_only_current_pair(tmp_path):
    jobs, parent_id, options, _calls, _workspace, _core_hosts = _setup(tmp_path)
    current = options["sketch_repository"].list_for_engagement("eng-opaque")
    ghost = replace(current[0], chain_id="proxy01-nyc3-01", status="aborted")
    options["sketch_repository"] = SimpleNamespace(
        list_for_engagement=lambda _key: [ghost, *current])
    bound = bind_initial_digitalocean_host_identity(parent_id, **options)
    assert bound.input["phase"] == "host_identity_bound"
    commands = []
    bootstrapped = service.bootstrap_initial_digitalocean_chains(
        parent_id, **_bootstrap_options(options, _success_helper(commands)))
    assert bootstrapped.input["phase"] == "awaiting_strict_host_proof"
    assert bootstrapped.events[-1].data["chainIds"] == [chain.chain_id for chain in current]
    assert len(commands) == 4


def test_gated_result_without_durable_callbacks_cannot_complete_or_start_sibling(tmp_path):
    jobs, parent_id, options, _workspace, _core_hosts = _ready(tmp_path)
    attempts = []
    def helper(_engagement_id, _chain, **kwargs):
        kwargs["workspace_root"].mkdir(mode=0o700)
        kwargs["progress_reporter"]("checking", {"phase": "root-management-readiness"})
        kwargs["runner"](["ansible-playbook", "ansible/wait_for_sketch_readiness.yml"],
                           kwargs["workspace_root"], {})
        pytest.fail("incomplete command audit must stop helper")
    def incomplete(_command, *, scratch_path, **_kwargs):
        attempts.append(str(scratch_path))
        intent = CommandIntent("incomplete", str(scratch_path), "digest")
        started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 1))
        return CommandResult(started, 0, "", "", False, False)
    inputs = _bootstrap_options(options, helper)
    inputs["gated_command_runner"] = incomplete
    stopped = service.bootstrap_initial_digitalocean_chains(parent_id, **inputs)
    assert stopped.status == "failed" and stopped.input["phase"] == "attention"
    assert len(attempts) == 1
    assert not any(event.message == "provider bootstrap command intent fenced" for event in stopped.events)


def test_changed_binding_evidence_or_transient_get_never_contacts_hosts(tmp_path):
    jobs, parent_id, options, workspace, _core_hosts = _ready(tmp_path)
    commands = []
    original = options["attachment_reconciler"]
    options["attachment_reconciler"] = lambda *_a, **_kw: (_ for _ in ()).throw(
        DigitalOceanAttachmentStillSettling("secret transient"))
    pending = service.bootstrap_initial_digitalocean_chains(
        parent_id, **_bootstrap_options(options, _success_helper(commands)),
    )
    assert pending.status == "running" and pending.input["phase"] == "host_identity_bound"
    assert "secret transient" not in str(pending.events)
    assert commands == []
    options["attachment_reconciler"] = original
    path = workspace.path / ".barragan-sketch-known-hosts"
    path.write_text("unreviewed key\n")
    stopped = service.bootstrap_initial_digitalocean_chains(
        parent_id, **_bootstrap_options(options, _success_helper(commands)),
    )
    assert stopped.status == "failed" and stopped.input["phase"] == "attention"
    assert commands == []


def test_source_guard_failure_precedes_nonreclaimable_preparation(tmp_path):
    jobs, parent_id, options, _workspace, _core_hosts = _ready(tmp_path)
    commands = []
    inputs = _bootstrap_options(options, _success_helper(commands))
    inputs["source_verifier"] = lambda **_kwargs: (_ for _ in ()).throw(ValueError("source drift"))
    stopped = service.bootstrap_initial_digitalocean_chains(parent_id, **inputs)
    assert stopped.status == "failed" and stopped.input["phase"] == "attention"
    assert not any(event.message == "provider bootstrap preparation fenced" for event in stopped.events)
    assert commands == []


def test_source_env_switch_after_chain_one_blocks_sibling_contact(tmp_path):
    jobs, parent_id, options, _workspace, _core_hosts = _ready(tmp_path)
    commands = []
    inputs = _bootstrap_options(options, None)
    env = inputs["bootstrap_env"]
    first = _success_helper(commands)
    def helper(engagement_id, chain, **kwargs):
        result = first(engagement_id, chain, **kwargs)
        env[TEMPLATE_ROOT_ENV] = "/tmp/switched-checkout"
        return result
    inputs["bootstrap_helper"] = helper
    stopped = service.bootstrap_initial_digitalocean_chains(parent_id, **inputs)
    assert stopped.status == "failed" and stopped.input["phase"] == "attention"
    assert commands == [("proxy01-sfo-01", "readiness"), ("proxy01-sfo-01", "root")]


@pytest.mark.parametrize("boundary", ["contact", "root"])
def test_failed_callback_persistence_prevents_corresponding_command(tmp_path, boundary):
    jobs, parent_id, options, _workspace, _core_hosts = _ready(tmp_path)
    real_save = jobs.save_if_leased
    target = "bootstrap_contacted" if boundary == "contact" else "bootstrap_root_started"
    def failing_save(job, *, owner, token):
        if job.input["phase"] == target:
            return None
        return real_save(job, owner=owner, token=token)
    jobs.save_if_leased = failing_save
    commands = []
    result = service.bootstrap_initial_digitalocean_chains(
        parent_id, **_bootstrap_options(options, _success_helper(commands)),
    )
    assert result.status == "failed" and result.input["phase"] == "attention"
    assert commands == ([] if boundary == "contact" else [("proxy01-sfo-01", "readiness")])
    with pytest.raises(service.ProviderKeyedInitialBootstrapError):
        service.bootstrap_initial_digitalocean_chains(
            parent_id, **_bootstrap_options(options, _success_helper(commands)),
        )


def test_stolen_claim_during_contact_callback_cannot_run_readiness(tmp_path):
    jobs, parent_id, options, _workspace, _core_hosts = _ready(tmp_path)
    original = jobs.save_if_leased
    def steal(job, *, owner, token):
        if job.input["phase"] == "bootstrap_contacted":
            current = jobs.get(parent_id)
            jobs.save(replace(current, input={**current.input,
                                              "claimOwner": "other", "claimToken": "other-token"}))
            return None
        return original(job, owner=owner, token=token)
    jobs.save_if_leased = steal
    commands = []
    with pytest.raises(service.ProviderKeyedInitialBootstrapError, match="manual read-only reconciliation"):
        service.bootstrap_initial_digitalocean_chains(
            parent_id, **_bootstrap_options(options, _success_helper(commands)),
        )
    assert commands == []
    assert jobs.get(parent_id).input["phase"] == "bootstrap_preparing"
    assert jobs.get(parent_id).input["claimToken"] == "other-token"


def test_crash_after_preparation_records_nonexistent_scratch_and_never_replays(tmp_path):
    jobs, parent_id, options, _workspace, _core_hosts = _ready(tmp_path)
    def crash(_engagement_id, _chain, **_kwargs):
        raise SystemExit("worker died before contact")
    with pytest.raises(SystemExit):
        service.bootstrap_initial_digitalocean_chains(parent_id, **_bootstrap_options(options, crash))
    parent = jobs.get(parent_id)
    assert parent.input["phase"] == "bootstrap_preparing"
    prepared = parent.events[-1].data
    assert len(prepared["scratchPaths"]) == 2
    assert all(not service.Path(path).exists() for path in prepared["scratchPaths"])
    jobs.save(replace(parent, input={**parent.input, "claimExpiresAt": (
        datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()}))
    with pytest.raises(service.ProviderKeyedInitialBootstrapError):
        service.bootstrap_initial_digitalocean_chains(parent_id, **_bootstrap_options(options, crash))


def test_crash_after_contact_retains_exact_scratch_for_manual_key_reconciliation(tmp_path):
    jobs, parent_id, options, _workspace, _core_hosts = _ready(tmp_path)
    def crash(_engagement_id, _chain, **kwargs):
        path = kwargs["workspace_root"]
        path.mkdir(mode=0o700)
        keys = path / "keys"
        keys.mkdir(mode=0o700)
        (keys / "admin-private").write_text("staged secret for crash test")
        kwargs["progress_reporter"]("checking", {"phase": "root-management-readiness"})
        raise SystemExit("simulated abrupt worker death")
    with pytest.raises(SystemExit):
        service.bootstrap_initial_digitalocean_chains(parent_id, **_bootstrap_options(options, crash))
    parent = jobs.get(parent_id)
    assert parent.input["phase"] == "bootstrap_contacted"
    prepared = next(event.data for event in parent.events
                    if event.message == "provider bootstrap preparation fenced")
    retained = service.Path(prepared["scratchPaths"][0]) / "keys" / "admin-private"
    assert retained.exists()  # No automatic scavenging can assume descendants died.
    with pytest.raises(service.ProviderKeyedInitialBootstrapError):
        service.bootstrap_initial_digitalocean_chains(parent_id, **_bootstrap_options(options, crash))


def test_crash_between_chains_keeps_first_completion_and_no_auto_replay(tmp_path):
    jobs, parent_id, options, _workspace, _core_hosts = _ready(tmp_path)
    commands = []
    first = _success_helper(commands)
    def helper(engagement_id, chain, **kwargs):
        if chain.chain_id == "proxy02-sfo-01":
            raise SystemExit("worker died before second chain")
        return first(engagement_id, chain, **kwargs)
    with pytest.raises(SystemExit):
        service.bootstrap_initial_digitalocean_chains(parent_id, **_bootstrap_options(options, helper))
    parent = jobs.get(parent_id)
    assert parent.input["phase"] == "bootstrap_chain_completed"
    completed = [event.data["chainId"] for event in parent.events
                 if event.message == "provider chain bootstrap completed; host proof pending"]
    assert completed == ["proxy01-sfo-01"]
    assert commands == [("proxy01-sfo-01", "readiness"), ("proxy01-sfo-01", "root")]
    with pytest.raises(service.ProviderKeyedInitialBootstrapError):
        service.bootstrap_initial_digitalocean_chains(parent_id, **_bootstrap_options(options, helper))


def test_second_root_start_callback_blocks_second_root_command(tmp_path):
    jobs, parent_id, options, _workspace, _core_hosts = _ready(tmp_path)
    commands = []
    def helper(_engagement_id, chain, **kwargs):
        reporter = kwargs["progress_reporter"]
        reporter("checking", {"phase": "root-management-readiness"})
        commands.append("readiness")
        reporter("starting", {"phase": "upstream-root-bootstrap"})
        commands.append("root")
        reporter("starting", {"phase": "upstream-root-bootstrap"})
        commands.append("second root")
        return SketchBootstrapApplyResult(0, 0, len(chain.nodes))
    stopped = service.bootstrap_initial_digitalocean_chains(
        parent_id, **_bootstrap_options(options, helper),
    )
    assert stopped.status == "failed" and stopped.input["phase"] == "attention"
    assert commands == ["readiness", "root"]


def test_lease_loss_after_root_start_blocks_user_and_transport_commands(tmp_path):
    jobs, parent_id, options, _workspace, _core_hosts = _ready(tmp_path)
    lease = {"value": ("plan-core", "provider_keyed_initial")}
    options["lease_lookup"] = lambda _engagement: lease["value"]
    commands = []
    def helper(_engagement_id, chain, **kwargs):
        report = kwargs["progress_reporter"]
        report("checking", {"phase": "root-management-readiness"})
        commands.append("readiness")
        report("starting", {"phase": "upstream-root-bootstrap"})
        commands.append("root")
        lease["value"] = ("other-plan", "provider_keyed_initial")
        report("completed", {"phase": "upstream-root-bootstrap"})
        commands.append("user-readiness")
        report("starting", {"phase": "transport-key-install"})
        commands.append("transport")
        return SketchBootstrapApplyResult(0, 0, len(chain.nodes))
    stopped = service.bootstrap_initial_digitalocean_chains(
        parent_id, **_bootstrap_options(options, helper),
    )
    assert stopped.status == "failed" and stopped.input["phase"] == "attention"
    assert commands == ["readiness", "root"]


def test_helper_claiming_success_with_staged_key_left_is_not_a_completed_chain(tmp_path):
    jobs, parent_id, options, _workspace, _core_hosts = _ready(tmp_path)
    def unsafe(_engagement_id, chain, **kwargs):
        path = kwargs["workspace_root"]
        path.mkdir(mode=0o700)
        (path / "keys").mkdir(mode=0o700)
        kwargs["progress_reporter"]("checking", {"phase": "root-management-readiness"})
        kwargs["progress_reporter"]("starting", {"phase": "upstream-root-bootstrap"})
        return SketchBootstrapApplyResult(0, 0, len(chain.nodes))
    stopped = service.bootstrap_initial_digitalocean_chains(
        parent_id, **_bootstrap_options(options, unsafe),
    )
    assert stopped.status == "failed" and stopped.input["phase"] == "attention"
    assert not any(event.message == "provider chain bootstrap completed; host proof pending"
                   for event in stopped.events)


def test_sketch_pins_changed_between_chains_block_second_contact(tmp_path, monkeypatch):
    jobs, parent_id, options, workspace, _core_hosts = _ready(tmp_path)
    commands = []
    original_save = service._save
    def edit_after_completion(*args, **kwargs):
        stored = original_save(*args, **kwargs)
        if stored.input["phase"] == "bootstrap_chain_completed":
            with (workspace.path / ".barragan-sketch-known-hosts").open("a") as stream:
                stream.write("unreviewed-key ssh-ed25519 injected\n")
        return stored
    monkeypatch.setattr(service, "_save", edit_after_completion)
    stopped = service.bootstrap_initial_digitalocean_chains(
        parent_id, **_bootstrap_options(options, _success_helper(commands, add_pin=True)),
    )
    assert stopped.status == "failed" and stopped.input["phase"] == "attention"
    assert commands == [("proxy01-sfo-01", "readiness"), ("proxy01-sfo-01", "root")]


def test_timeout_requires_attention_without_phase_replay(tmp_path):
    from app.services.sketch_bootstrap_apply import SketchBootstrapTimeoutError
    jobs, parent_id, options, _workspace, _core_hosts = _ready(tmp_path)
    calls = []
    def timeout(*args, **kwargs):
        calls.append(True)
        raise SketchBootstrapTimeoutError("local bootstrap execution timed out")
    inputs = _bootstrap_options(options, timeout)
    stopped = service.bootstrap_initial_digitalocean_chains(parent_id, **inputs)
    assert stopped.status == "failed" and stopped.input["phase"] == "attention"
    assert stopped.events[-1].data["timedOut"] is True
    assert stopped.events[-1].data["bootstrap"] == "reconciliation_required"
    with pytest.raises(service.ProviderKeyedInitialBootstrapError):
        service.bootstrap_initial_digitalocean_chains(parent_id, **inputs)
    assert calls == [True]
