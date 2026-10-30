# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline proof that fixture checkout does not depend on advertised source refs."""

from pathlib import Path
import subprocess

import pytest

from redteam_infra_test_fixtures import checkout_local_pinned_source


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(["git", "-C", str(root), *arguments], check=True,
                          capture_output=True, text=True, timeout=30).stdout.strip()


@pytest.fixture()
def cache(tmp_path):
    source = tmp_path / "local-cache"
    source.mkdir()
    _git(source, "init", "--quiet", "--initial-branch=main")
    _git(source, "config", "user.name", "Fixture")
    _git(source, "config", "user.email", "fixture@example.invalid")
    _git(source, "config", "commit.gpgsign", "false")
    (source / "template.tf").write_text("initial\n")
    _git(source, "add", "template.tf")
    _git(source, "commit", "--quiet", "-m", "initial")
    initial = _git(source, "rev-parse", "HEAD")
    (source / "template.tf").write_text("approved\n")
    _git(source, "commit", "--quiet", "-am", "approved")
    approved = _git(source, "rev-parse", "HEAD")
    _git(source, "reset", "--hard", initial)
    # The approved commit exists only in the object cache/reflog. Source work
    # and remote configuration are deliberately unrelated to the pinned tree.
    (source / "template.tf").write_text("operator changes\n")
    (source / "local-only.txt").write_text("do not copy\n")
    _git(source, "remote", "add", "origin", "ssh://network.example.invalid/upstream")
    assert _git(source, "for-each-ref", "--contains", approved) == ""
    return source, approved


def test_fresh_targets_fetch_exact_unadvertised_commit_offline_without_touching_source(cache, tmp_path, monkeypatch):
    source, approved = cache
    before = {field: _git(source, *arguments) for field, arguments in {
        "refs": ("show-ref",), "head": ("rev-parse", "HEAD"),
        "status": ("status", "--porcelain"), "config": ("config", "--local", "--list"),
    }.items()}
    original_run = subprocess.run
    commands = []

    def observe(*args, **kwargs):
        commands.append((args[0], kwargs))
        return original_run(*args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(subprocess, "run", observe)
        targets = [checkout_local_pinned_source(source, tmp_path / name, approved) for name in ("first", "second")]
    for target in targets:
        assert _git(target, "rev-parse", "HEAD") == approved
        assert _git(target, "cat-file", "-t", approved) == "commit"
        assert _git(target, "rev-parse", "--is-shallow-repository") == "true"
        assert (target / "template.tf").read_text() == "approved\n"
        assert not (target / "local-only.txt").exists()
        assert _git(target, "remote") == ""
        assert not (target / ".git" / "FETCH_HEAD").exists()
        assert _git(target, "for-each-ref") == ""
    for field, arguments in {
        "refs": ("show-ref",), "head": ("rev-parse", "HEAD"),
        "status": ("status", "--porcelain"), "config": ("config", "--local", "--list"),
    }.items():
        assert _git(source, *arguments) == before[field]
    assert (source / "template.tf").read_text() == "operator changes\n"
    assert (source / "local-only.txt").read_text() == "do not copy\n"
    assert all(options["env"]["GIT_ALLOW_PROTOCOL"] == "file" for _, options in commands)
    assert all(options["env"]["GIT_TERMINAL_PROMPT"] == "0" for _, options in commands)
    assert all(options["timeout"] == 30 for _, options in commands)
    fetches = [command for command, _ in commands if "fetch" in command]
    assert len(fetches) == 2
    assert all(command[-2:] == [str(source), approved] for command in fetches)


@pytest.mark.parametrize("revision", ["HEAD", "abc123", "f" * 39, "z" * 40])
def test_rejects_revision_expressions_and_incomplete_pins_before_git(cache, tmp_path, monkeypatch, revision):
    def unexpected(*args, **kwargs):
        pytest.fail("invalid revision must not invoke Git")
    monkeypatch.setattr(subprocess, "run", unexpected)
    with pytest.raises(ValueError, match="full commit SHA"):
        checkout_local_pinned_source(cache[0], tmp_path / "target", revision)
    assert not (tmp_path / "target").exists()


def test_missing_approved_commit_fails_without_creating_target_or_fetching(cache, tmp_path):
    with pytest.raises(ValueError, match="unavailable in the local cache"):
        checkout_local_pinned_source(cache[0], tmp_path / "target", "0" * 40)
    assert not (tmp_path / "target").exists()


def test_rejects_blob_object_instead_of_silently_peeling_or_substituting(cache, tmp_path):
    source, approved = cache
    blob = _git(source, "rev-parse", f"{approved}:template.tf")
    with pytest.raises(ValueError, match="commit object"):
        checkout_local_pinned_source(source, tmp_path / "target", blob)
    assert not (tmp_path / "target").exists()


def test_existing_target_is_never_overwritten(cache, tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep.txt").write_text("existing work\n")
    with pytest.raises(ValueError, match="must be fresh"):
        checkout_local_pinned_source(cache[0], target, cache[1])
    assert (target / "keep.txt").read_text() == "existing work\n"


def test_git_timeout_stops_without_retry_or_target_creation(cache, tmp_path, monkeypatch):
    calls = []
    def timeout(command, **kwargs):
        calls.append(command)
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])
    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(subprocess.TimeoutExpired):
        checkout_local_pinned_source(cache[0], tmp_path / "target", cache[1])
    assert len(calls) == 1
    assert not (tmp_path / "target").exists()
