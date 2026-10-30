# Copyright (c) 2026, Oracle and/or its affiliates.
import json
from contextvars import copy_context
import os
from pathlib import Path
import sqlite3
import subprocess
import threading
import time

import pytest

from app.services.provider_keyed_readonly_verification import (
    ReadonlyVerificationChanged, readonly_verification_scope,
    run_readonly_verification,
)


@pytest.fixture
def command(tmp_path):
    binary = tmp_path / "terraform"
    binary.write_bytes(b"reviewed executable")
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "main.tf").write_text("reviewed source")
    (root / ".barragan-provider-keyed-state.json").write_text(json.dumps({
        "source_files": {"main.tf": "reviewed"}, "rendered_files": {"main.tf": "reviewed"}}))
    (root / ".barragan-topology.json").write_text("{}")
    (root / ".terraform.lock.hcl").write_text("reviewed lock")
    plan = root / "saved.tfplan"
    plan.write_bytes(b"reviewed plan")
    plugins = root / ".terraform-data" / "providers"
    plugins.mkdir(parents=True)
    external = tmp_path / "plugin-cache"
    external.mkdir()
    plugin = external / "provider"
    plugin.write_bytes(b"reviewed plugin")
    (plugins / "release").symlink_to(external, target_is_directory=True)
    calls = []

    def runner(argv, **options):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, '{"verified":true}', "")

    def run(**changes):
        values = dict(argv=[str(binary), "show", "-json", str(plan)], cwd=root,
                      env={"TF_DATA_DIR": str(root / ".terraform-data")}, runner=runner,
                      capture_output=True, text=True, check=False, timeout=60)
        values.update(changes)
        return run_readonly_verification(**values)

    return run, calls, root, binary, plan, plugin, runner


def test_scoped_transcript_preserves_output_and_has_no_global_reuse(command):
    run, calls, *_ = command
    run()
    run()
    assert len(calls) == 2
    with readonly_verification_scope() as scope:
        first = run()
        scope.require_hits_only()
        for _ in range(41):
            result = run()
            assert result is not first
            assert (result.returncode, result.stdout, result.stderr) == (0, first.stdout, "")
    assert len(calls) == 3
    with readonly_verification_scope():
        run()
    assert len(calls) == 4


@pytest.mark.parametrize("change", ["binary", "plan", "plugin", "lock", "source",
                                    "membership", "environment", "mode"])
def test_hit_only_rereads_every_input_and_never_launches_on_drift(command, change):
    run, calls, root, binary, plan, plugin, _ = command
    with readonly_verification_scope() as scope:
        run()
        scope.require_hits_only()
        extra = {}
        if change in {"binary", "plan", "plugin"}:
            path = {"binary": binary, "plan": plan, "plugin": plugin}[change]
            prior = path.stat()
            raw = path.read_bytes()
            path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
            os.utime(path, ns=(prior.st_atime_ns, prior.st_mtime_ns))
        elif change == "lock":
            (root / ".terraform.lock.hcl").write_text("different lock")
        elif change == "source":
            (root / "main.tf").write_text("different source")
        elif change == "membership":
            (plugin.parent / "additional-provider").write_bytes(b"unexpected")
        elif change == "environment":
            extra["env"] = {"TF_DATA_DIR": str(root / ".terraform-data"), "TF_CLI_ARGS": "changed"}
        else:
            plan.chmod(0o644 if plan.stat().st_mode & 0o077 == 0 else 0o600)
        with pytest.raises(ReadonlyVerificationChanged):
            run(**extra)
    assert len(calls) == 1


def test_change_and_restore_during_capture_is_not_a_transcript(command):
    run, calls, root, binary, plan, plugin, _ = command

    def changed(argv, **options):
        prior = plan.stat()
        original = plan.read_bytes()
        plan.write_bytes(b"x" * len(original))
        plan.write_bytes(original)
        os.utime(plan, ns=(prior.st_atime_ns, prior.st_mtime_ns))
        return subprocess.CompletedProcess(argv, 0, "output", "")

    with readonly_verification_scope() as scope:
        with pytest.raises(ReadonlyVerificationChanged):
            run(runner=changed)
        scope.require_hits_only()
        with pytest.raises(ReadonlyVerificationChanged):
            run(runner=changed)


def test_failed_commands_are_not_cached_and_nested_scope_cannot_reopen_learning(command):
    run, calls, *_ = command

    def failed(argv, **options):
        return subprocess.CompletedProcess(argv, 1, "", "failed")

    with readonly_verification_scope() as scope:
        with pytest.raises(ReadonlyVerificationChanged):
            run(runner=failed)
        scope.require_hits_only()
        with readonly_verification_scope():
            with pytest.raises(ReadonlyVerificationChanged):
                run()
    assert not calls
    with readonly_verification_scope():
        run()
    assert len(calls) == 1


def test_inherited_hit_only_context_rejects_before_execution(command):
    run, calls, *_ = command
    errors = []
    with readonly_verification_scope() as scope:
        run()
        scope.require_hits_only()
        inherited = copy_context()

        def other_thread():
            try:
                inherited.run(run)
            except ReadonlyVerificationChanged:
                errors.append("rejected")

        thread = threading.Thread(target=other_thread)
        thread.start()
        thread.join(2)
        assert not thread.is_alive()
    assert errors == ["rejected"]
    assert len(calls) == 1


def test_slow_prime_does_not_hold_sqlite_writer_and_writer_uses_only_transcript(command, tmp_path):
    run, calls, *_ = command
    database = tmp_path / "claims.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE claim (heartbeat INTEGER)")
        connection.execute("INSERT INTO claim VALUES (0)")
    priming = threading.Event()
    renewed = threading.Event()

    def heartbeat():
        assert priming.wait(2)
        with sqlite3.connect(database, timeout=0.2) as other:
            other.execute("UPDATE claim SET heartbeat = 1")
        renewed.set()

    def slow(argv, **options):
        priming.set()
        assert renewed.wait(2), "prewriter capture blocked independent heartbeat"
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "reviewed", "")

    thread = threading.Thread(target=heartbeat)
    thread.start()
    with readonly_verification_scope() as scope:
        run(runner=slow)
        scope.require_hits_only()
        connection = sqlite3.connect(database)
        started = time.monotonic()
        connection.execute("BEGIN IMMEDIATE")
        try:
            assert run(runner=slow).stdout == "reviewed"
            assert len(calls) == 1
            connection.commit()
        finally:
            connection.close()
        assert time.monotonic() - started < 1
    thread.join(2)
    assert not thread.is_alive()
    assert renewed.is_set()


def test_release_version_parser_still_checks_a_reused_transcript(tmp_path, monkeypatch):
    from hashlib import sha256
    from app.services import provider_keyed_terraform_release as release
    binary = tmp_path / "terraform"
    binary.write_bytes(b"reviewed executable")
    binary.chmod(0o700)
    monkeypatch.setattr(release, "_REVIEWED_PATH", binary)
    monkeypatch.setattr(release, "_REVIEWED_SHA256", sha256(binary.read_bytes()).hexdigest())
    monkeypatch.setattr(release.platform, "system", lambda: "Linux")
    monkeypatch.setattr(release.platform, "machine", lambda: "x86_64")
    calls = []

    def wrong_version(argv, **options):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, json.dumps({
            "terraform_version": "wrong", "platform": "linux_amd64"}), "")

    monkeypatch.setattr(release.subprocess, "run", wrong_version)
    with readonly_verification_scope() as scope:
        with pytest.raises(release.ProviderKeyedTerraformReleaseError, match="version differs"):
            release.require_devtest_terraform_release(environment="devtest", terraform=binary)
        scope.require_hits_only()
        with pytest.raises(release.ProviderKeyedTerraformReleaseError, match="version differs"):
            release.require_devtest_terraform_release(environment="devtest", terraform=binary)
    assert len(calls) == 1


def test_capture_detaches_caller_command_inputs(command):
    run, _, root, binary, plan, _, _ = command
    argv = [str(binary), "show", "-json", str(plan)]
    env = {"TF_DATA_DIR": str(root / ".terraform-data")}
    expected = dict(env)

    def runner(actual, **options):
        argv[1] = "apply"
        env["TF_DATA_DIR"] = "changed"
        assert actual == [str(binary), "show", "-json", str(plan)]
        assert options["env"] == expected
        return subprocess.CompletedProcess(actual, 0, "{}", "")

    with readonly_verification_scope():
        assert run(argv=argv, env=env, runner=runner).returncode == 0


def test_marker_names_and_manifest_bind_same_consumed_bytes(command, monkeypatch):
    run, _, root, *_ = command
    marker = root / ".barragan-provider-keyed-state.json"
    original = Path.read_bytes

    def altered(path):
        raw = original(path)
        if path == marker:
            data = json.loads(raw)
            data["rendered_files"] = {}
            return json.dumps(data).encode()
        return raw

    monkeypatch.setattr(Path, "read_bytes", altered)
    with readonly_verification_scope(), pytest.raises(ReadonlyVerificationChanged, match="inventory changed"):
        run()
