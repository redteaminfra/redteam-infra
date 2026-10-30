# Copyright (c) 2026, Oracle and/or its affiliates.
"""Fresh v2 bootstrap reads only the exact clean upstream Ansible checkout."""

import subprocess
from pathlib import Path

import pytest

from app.services import sketch_bootstrap_apply as service
from app.services.redteam_infra_template import TEMPLATE_ROOT_ENV


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def _checkout(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "redteam-infra"
    (root / "external/sketch/ansible/roles/disable-ipv6/tasks").mkdir(parents=True)
    (root / "ansible/roles/core/tasks").mkdir(parents=True)
    (root / "external/sketch/ansible/sketch-playbook.yml").write_text("---\n- hosts: all\n")
    (root / "external/sketch/ansible/roles/disable-ipv6/tasks/main.yml").write_text("---\n")
    (root / "ansible/roles/core/tasks/main.yml").write_text("---\n")
    (root / ".gitignore").write_text("external/sketch/ansible/ignored-generated.yml\n")
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
         "commit", "-qm", "pinned fixture")
    return root, _git(root, "rev-parse", "HEAD")


def _check(root: Path, revision: str, *, env_root: Path | None = None) -> Path:
    return service.require_pinned_sketch_ansible_source(
        env={TEMPLATE_ROOT_ENV: str(env_root or root)}, required_source_root=root,
        required_source_revision=revision,
    )


def test_exact_clean_checkout_is_accepted(tmp_path):
    root, revision = _checkout(tmp_path)
    assert _check(root, revision) == root


@pytest.mark.parametrize("drift", ["wrong_head", "dirty", "untracked", "ignored", "env_switch", "nested_root"])
def test_rejects_changed_or_ambiguous_upstream_ansible_before_read(tmp_path, drift):
    root, revision = _checkout(tmp_path)
    checked_root = root
    env_root = root
    if drift == "wrong_head":
        revision = "b" * 40
    elif drift == "dirty":
        (root / "external/sketch/ansible/sketch-playbook.yml").write_text("changed\n")
    elif drift == "untracked":
        (root / "external/sketch/ansible/roles/disable-ipv6/extra.yml").write_text("extra\n")
    elif drift == "ignored":
        (root / "external/sketch/ansible/ignored-generated.yml").write_text("ignored\n")
    elif drift == "env_switch":
        env_root = tmp_path / "other-checkout"
        subprocess.run(["git", "clone", "-q", str(root), str(env_root)], check=True)
    else:
        checked_root = root / "external"
        env_root = checked_root
    with pytest.raises(service.SketchBootstrapApplyError, match="pinned upstream Ansible source"):
        _check(checked_root, revision, env_root=env_root)


def test_v2_apply_source_guard_runs_before_workspace_or_upstream_read(tmp_path, monkeypatch):
    root, _revision = _checkout(tmp_path)
    monkeypatch.setattr(service, "resolve_redteam_infra_template_source",
                        lambda **_kwargs: pytest.fail("upstream source must not be read"))
    monkeypatch.setattr(service, "write_existing_sketch_ssh_key_files",
                        lambda *_args: pytest.fail("keys must not be staged"))
    workspace = tmp_path / "workspace"
    with pytest.raises(service.SketchBootstrapApplyError, match="pinned upstream Ansible source"):
        service.apply_sketch_bootstrap(
            "eng-opaque", object(), repository=object(),
            env={TEMPLATE_ROOT_ENV: str(root)}, workspace_root=workspace,
            host_policies={}, required_source_root=root, required_source_revision="b" * 40,
        )
    assert not workspace.exists()
