# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from app.services.capability_lock_rendering import CAPABILITY_LOCK_RELATIVE_PATH, render_capability_lock
from app.services.engagement_workspaces import EngagementWorkspaceValidationError, prepare_engagement_workspace
from app.services.redteam_infra_template import RedteamInfraTemplateSource
from app.storage.engagement_workspace_repository import StoredEngagementWorkspace


class _EmptyServiceRepository:
    def list_for_engagement(self, _engagement_id: str):
        return []


STANDARD_RTI_ROLES = (
    "common",
    "molly-guard",
    "logstash",
    "yama",
    "oci",
    "nfs-server",
    "homebase",
    "go_simple_upload_server",
    "etherpad",
    "google-chrome",
    "firefox",
    "keepassxc",
    "vs-code",
    "docker",
    "nmap",
    "nfs-client",
    "ssh-proxy",
    "dante-server",
    "unattended-upgrades",
    "proxies",
    "elk",
)


def test_render_capability_lock_writes_execution_aware_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _template_source(tmp_path)
    root = tmp_path / "engagements"
    repo = _FakeWorkspaceRepository()
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))
    monkeypatch.setattr("app.services.capability_lock_rendering.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))

    prepared = prepare_engagement_workspace(
        "eng-abc123",
        root=root,
        repository=repo,
        source=RedteamInfraTemplateSource(source, "test"),
    )
    assert prepared is not None

    rendered = render_capability_lock(
        "eng-abc123",
        root=root,
        repository=repo,
        service_repository=_EmptyServiceRepository(),
    )

    assert rendered is not None
    lock_path = Path(prepared.workspace.path) / CAPABILITY_LOCK_RELATIVE_PATH
    assert rendered.path == lock_path
    assert lock_path.is_file()
    payload = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    assert payload["schema"] == "barragan/capability-lock/v1"
    assert payload["metadata"]["engagementId"] == "eng-abc123"
    assert payload["metadata"]["workspaceSlug"] == "demo-01-engabc123"
    assert payload["status"] == "passed"
    assert payload["summary"] == {
        "total": 26,
        "essential": 15,
        "default": 7,
        "optional": 4,
        "catalog": 26,
        "missingManifest": 0,
        "missingTemplatePath": 0,
    }
    assert payload["executionPolicy"] == {
        "terraform": False,
        "ansible": True,
        "providerMutation": False,
        "reason": "Selected executable Ansible role capabilities are applied during core infrastructure deployment.",
    }
    assert payload["renderedArtifacts"]["playbooks"] == ["ansible/apply_capabilities.yml"]
    firefox = next(entry for entry in payload["capabilities"]["homebase"]["default"] if entry["id"] == "firefox")
    assert firefox["resolution"] == "catalog"
    assert firefox["executable"] is True
    assert repo.workspace is not None
    assert repo.workspace.status == "capability-lock-rendered"
    assert repo.workspace.metadata["capabilityLockPath"] == "barragan/capability-lock.yml"


def test_render_capability_lock_requires_prepared_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))

    with pytest.raises(EngagementWorkspaceValidationError) as exc:
        render_capability_lock("eng-abc123", root=tmp_path / "engagements", repository=_FakeWorkspaceRepository())

    assert exc.value.errors == ["engagement workspace must be prepared before rendering capability artifacts"]


def test_render_capability_lock_rejects_stored_path_outside_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _FakeWorkspaceRepository(
        StoredEngagementWorkspace(
            engagement_id="eng-abc123",
            slug="demo-01-engabc123",
            path=str(tmp_path / "outside"),
            status="prepared",
            profile_id="standard-rti",
            template_source={},
            metadata={},
        )
    )
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))

    with pytest.raises(EngagementWorkspaceValidationError) as exc:
        render_capability_lock("eng-abc123", root=tmp_path / "engagements", repository=repo)

    assert exc.value.errors == ["stored engagement workspace path escapes configured root"]


def test_render_capability_lock_validates_local_manifest_against_workspace_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _template_source(tmp_path)
    root = tmp_path / "engagements"
    repo = _FakeWorkspaceRepository()
    manifest_root = tmp_path / "barragan-manifests"
    _write_role_manifest(manifest_root / "capabilities" / "firefox.yml", "firefox")
    monkeypatch.setattr("app.services.capability_catalog.DEFAULT_CAPABILITY_MANIFEST_ROOT", manifest_root)
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))
    monkeypatch.setattr("app.services.capability_lock_rendering.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))

    prepared = prepare_engagement_workspace(
        "eng-abc123",
        root=root,
        repository=repo,
        source=RedteamInfraTemplateSource(source, "test"),
    )
    assert prepared is not None
    (Path(prepared.workspace.path) / "ansible" / "roles" / "firefox").rmdir()

    rendered = render_capability_lock(
        "eng-abc123",
        root=root,
        repository=repo,
        service_repository=_EmptyServiceRepository(),
    )

    assert rendered is not None
    firefox = next(entry for entry in rendered.lock["capabilities"]["homebase"]["default"] if entry["id"] == "firefox")
    assert rendered.lock["status"] == "failed"
    assert firefox["resolution"] == "missing-template-path"
    assert firefox["executable"] is False


def _template_source(tmp_path: Path) -> Path:
    source = tmp_path / "redteam-infra"
    (source / "external").mkdir(parents=True, exist_ok=True)
    (source / "ansible").mkdir(parents=True, exist_ok=True)
    (source / "ansible" / "site.yml").write_text("---\n", encoding="utf-8")
    for role in STANDARD_RTI_ROLES:
        (source / "ansible" / "roles" / role).mkdir(parents=True)
    return source


def _write_role_manifest(path: Path, role: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            (
                "apiVersion: barragan/v1",
                "kind: AnsibleCapability",
                "metadata:",
                f"  id: {role}",
                f"  name: {role}",
                "  description: Reviewed local capability.",
                "implementation:",
                "  type: role",
                f"  role: {role}",
                f"  path: ansible/roles/{role}",
                "placement:",
                "  allowedHostClasses:",
                "    - homebase",
                "operator:",
                "  visible: true",
                "  selectable: true",
            )
        )
        + "\n",
        encoding="utf-8",
    )


class _FakeWorkspaceRepository:
    def __init__(self, workspace: StoredEngagementWorkspace | None = None) -> None:
        self.workspace = workspace

    def get(self, engagement_id: str) -> StoredEngagementWorkspace | None:
        if self.workspace is not None and self.workspace.engagement_id == engagement_id:
            return self.workspace
        return None

    def save(self, workspace: StoredEngagementWorkspace) -> StoredEngagementWorkspace:
        self.workspace = workspace
        return workspace
