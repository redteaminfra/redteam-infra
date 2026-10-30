# Copyright (c) 2026, Oracle and/or its affiliates.
"""The dormant v2 handoff binds source and never dispatches by default."""

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from app.services import provider_keyed_core_source as source
from app.services.provider_keyed_initial_dispatch import recover_fresh_keyed_initial_dispatches


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=True,
    )
    return completed.stdout.strip()


def test_source_pin_requires_exact_clean_checkout(tmp_path, monkeypatch):
    root = tmp_path / "source"
    template = root / "external" / "sketch" / "digitalocean"
    template.mkdir(parents=True)
    (template / "main.tf").write_text("terraform {}\n")
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "-c", "user.email=test@example.invalid", "-c", "user.name=Test", "commit", "-qm", "pin")
    digest = hashlib.sha256(json.dumps({
        "main.tf": hashlib.sha256((template / "main.tf").read_bytes()).hexdigest(),
    }, sort_keys=True).encode()).hexdigest()
    monkeypatch.setattr(source, "_SOURCE_REVISION", _git(root, "rev-parse", "HEAD"))
    monkeypatch.setattr(source, "_SOURCE_SHA256", digest)
    assert source.require_keyed_core_source(root) == {
        "root": str(root), "revision": _git(root, "rev-parse", "HEAD"),
        "templateSha256": digest,
    }
    (template / "main.tf").write_text("terraform { required_version = \"1.0\" }\n")
    with pytest.raises(source.ProviderKeyedCoreSourceError, match="unavailable or changed"):
        source.require_keyed_core_source(root)


def test_recovery_gate_off_never_inspects_database_or_schedules():
    called = []
    assert recover_fresh_keyed_initial_dispatches(
        environment="devtest", rollout_enabled=False,
        schedule=lambda task: called.append(task),
    ) == []
    assert called == []
