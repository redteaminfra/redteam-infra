# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only terminal audit over actual two-chain bootstrap job events."""

from dataclasses import replace
import os
from pathlib import Path

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_initial_bootstrap as bootstrap
from app.services import provider_keyed_teardown_quiescence as audit
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.sketch_bootstrap_apply import SketchBootstrapApplyResult
from test_provider_keyed_initial_bootstrap import _bootstrap_options, _ready


def _completed(tmp_path):
    jobs, parent_id, options, workspace, _core_hosts = _ready(tmp_path)
    number = 0

    def gated(command, *, scratch_path, intent_callback, started_callback,
              heartbeat_callback, result_callback, provider_keyed_v2, env, execution_timeout_seconds):
        assert execution_timeout_seconds == 1800
        nonlocal number
        assert provider_keyed_v2 and command and scratch_path.is_dir()
        number += 1
        intended = CommandIntent(f"fixture-{number}", str(scratch_path), f"{number:064x}")
        intent_callback(intended)
        started = StartedCommand(intended, ProcessIdentity(
            "11111111-1111-4111-8111-111111111111", 1000 + number, 1000 + number, number))
        started_callback(started)
        heartbeat_callback(started)
        result_callback(CommandAuditResult(started, 0, 12, 0, False, False,
                                          execution_timeout_seconds=1800, command_elapsed_seconds=0.5))
        return CommandResult(started, 0, "complete", "", False, False)

    def helper(_engagement_id, chain, **kwargs):
        scratch = kwargs["workspace_root"]
        scratch.mkdir(mode=0o700)
        scratch.chmod(0o700)
        keys = scratch / "keys"
        keys.mkdir(mode=0o700)
        (keys / "admin-private").write_text("staged fixture key")
        reporter = kwargs["progress_reporter"]
        reporter("checking", {"phase": "root-management-readiness"})
        run = kwargs["runner"]
        for play in ("wait_for_sketch_readiness.yml",):
            run(["ansible-playbook", play], scratch, {})
        reporter("starting", {"phase": "upstream-root-bootstrap"})
        for play in ("upstream-sketch-playbook.compat.yml", "wait_for_sketch_user_readiness.yml",
                     "install_sketch_transport.yml"):
            run(["ansible-playbook", play], scratch, {})
        (keys / "admin-private").unlink()
        keys.rmdir()
        return SketchBootstrapApplyResult(0, 0, len(chain.nodes), 0)

    inputs = _bootstrap_options(options, helper)
    inputs["gated_command_runner"] = gated
    parent = bootstrap.bootstrap_initial_digitalocean_chains(parent_id, **inputs)
    assert parent.input["phase"] == "awaiting_strict_host_proof"
    manifest = next(event.data for event in parent.events
                    if event.message == "provider host identity binding intended")
    core = jobs.get("job-core")
    scope = {
        "schema": "provider-keyed-v2", "coreJobId": core.id,
        "corePlanId": core.input["corePlanId"], "workspace": str(workspace.path),
        "stateSha256": manifest["stateSha256"],
        "sourceRevision": manifest["sourceRevision"],
        "providerConnectionId": manifest["providerConnectionId"],
        "chainIds": core.input["pendingSketchChainIds"],
        "chainFingerprints": core.input["pendingSketchChainFingerprints"],
    }
    return jobs, parent, workspace.path, scope


def _audit(rows):
    jobs, _parent, root, scope = rows
    return audit.audit_terminal_provider_keyed_bootstrap(
        "job-core", confirmed_scope=scope, workspace_root=root, job_repository=jobs)


def test_terminal_two_chain_bootstrap_audit_proves_complete_journals_and_clean_keys(tmp_path):
    rows = _completed(tmp_path)
    proof = _audit(rows)
    assert proof.chain_ids == tuple(rows[3]["chainIds"])
    assert proof.command_count == 8
    assert len(proof.scratch_paths) == 2
    assert all(not (Path(path) / "keys").exists() for path in proof.scratch_paths)


@pytest.mark.parametrize("mode,gid_offset,accepted", [
    (0o2750, 0, True), (0o2750, 1, False), (0o2770, 0, False), (0o750, 0, False),
])
def test_workspace_root_collaborator_policy_keeps_scratch_private(
    tmp_path, monkeypatch, mode, gid_offset, accepted,
):
    rows = _completed(tmp_path)
    root = rows[2]
    real_lstat = Path.lstat
    actual = real_lstat(root)
    synthetic = list(actual)
    synthetic[0] = (actual.st_mode & ~0o7777) | mode
    synthetic[5] = actual.st_gid + gid_offset

    def lstat_with_reviewed_mode(path, *args, **kwargs):
        return os.stat_result(synthetic) if path == root else real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", lstat_with_reviewed_mode)
    monkeypatch.setattr(audit, "_collaborator_group_gid", lambda: actual.st_gid)
    if accepted:
        proof = _audit(rows)
        assert proof.command_count == 8
        assert all(audit._private_directory(Path(path)) for path in proof.scratch_paths)
        assert all((Path(path).stat().st_mode & 0o7777) == 0o700 for path in proof.scratch_paths)
    else:
        with pytest.raises(audit.ProviderKeyedTeardownQuiescenceError):
            _audit(rows)


def test_real_trusted_02750_workspace_root_when_filesystem_supports_it(tmp_path, monkeypatch):
    rows = _completed(tmp_path)
    root = rows[2]
    root.chmod(0o2750)
    if (root.stat().st_mode & 0o7777) != 0o2750:
        pytest.skip("filesystem does not retain setgid on owner-created directories")
    monkeypatch.setattr(audit, "_collaborator_group_gid", lambda: root.stat().st_gid)
    assert _audit(rows).command_count == 8


@pytest.mark.parametrize("phase", ["bootstrap_preparing", "bootstrap_contacted",
                                   "bootstrap_root_started", "bootstrap_chain_completed", "attention"])
def test_nonterminal_or_attention_phase_is_not_quiescence(tmp_path, phase):
    rows = _completed(tmp_path)
    jobs, parent, _root, _scope = rows
    jobs.save(replace(parent, input={**parent.input, "phase": phase}))
    with pytest.raises(audit.ProviderKeyedTeardownQuiescenceError):
        _audit(rows)


def test_unmatched_started_command_or_later_host_command_blocks(tmp_path):
    rows = _completed(tmp_path)
    jobs, parent, _root, _scope = rows
    events = [event for event in parent.events
              if not (event.message == audit._RESULT and event.data.get("invocationId") == "fixture-1")]
    events = [replace(event, sequence=index) for index, event in enumerate(events, 1)]
    jobs.save(replace(parent, events=events))
    with pytest.raises(audit.ProviderKeyedTeardownQuiescenceError):
        _audit(rows)
    late = [*parent.events, JobEvent(len(parent.events) + 1, "info", audit._INTENT, {
        "chainId": rows[3]["chainIds"][0], "phase": "root_management_readiness",
    })]
    jobs.save(replace(parent, events=late))
    with pytest.raises(audit.ProviderKeyedTeardownQuiescenceError):
        _audit(rows)


def test_early_unmatched_start_before_preparation_blocks(tmp_path):
    rows = _completed(tmp_path)
    jobs, parent, _root, _scope = rows
    preparation = next(index for index, event in enumerate(parent.events)
                       if event.message == audit._PREPARED)
    early = JobEvent(0, "info", audit._STARTED, {
        "chainId": rows[3]["chainIds"][0], "phase": "root_management_readiness",
        "sequence": 1, "attempt": 1, "invocationId": "unmatched-early",
        "bootId": "11111111-1111-4111-8111-111111111111",
        "pid": 901, "pgid": 901, "startTicks": 1,
    })
    events = list(parent.events)
    events.insert(preparation, early)
    jobs.save(replace(parent, events=[replace(event, sequence=index)
                                      for index, event in enumerate(events, 1)]))
    with pytest.raises(audit.ProviderKeyedTeardownQuiescenceError):
        _audit(rows)


def test_duplicate_final_before_last_final_blocks(tmp_path):
    rows = _completed(tmp_path)
    jobs, parent, _root, _scope = rows
    events = [*parent.events[:-1], parent.events[-1], parent.events[-1]]
    jobs.save(replace(parent, events=[replace(event, sequence=index)
                                      for index, event in enumerate(events, 1)]))
    with pytest.raises(audit.ProviderKeyedTeardownQuiescenceError):
        _audit(rows)


def test_staged_key_or_unsafe_scratch_blocks(tmp_path):
    rows = _completed(tmp_path)
    path = Path(_audit(rows).scratch_paths[0])
    (path / "keys").mkdir()
    with pytest.raises(audit.ProviderKeyedTeardownQuiescenceError):
        _audit(rows)
    (path / "keys").rmdir()
    path.chmod(0o775)
    with pytest.raises(audit.ProviderKeyedTeardownQuiescenceError):
        _audit(rows)


def test_unreadable_nested_scratch_directory_blocks(tmp_path):
    rows = _completed(tmp_path)
    path = Path(_audit(rows).scratch_paths[0])
    nested = path / "unreadable"
    nested.mkdir(mode=0o700)
    nested.chmod(0o000)
    try:
        with pytest.raises(audit.ProviderKeyedTeardownQuiescenceError):
            _audit(rows)
    finally:
        nested.chmod(0o700)


def test_manifest_or_chain_scope_drift_blocks(tmp_path):
    rows = _completed(tmp_path)
    rows[3]["stateSha256"] = "f" * 64
    with pytest.raises(audit.ProviderKeyedTeardownQuiescenceError):
        _audit(rows)
