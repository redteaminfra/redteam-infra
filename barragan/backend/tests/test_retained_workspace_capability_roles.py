# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.services.retained_workspace_capability_roles as retained_roles
from app.services.engagement_capabilities import (
    EngagementCapabilityValidationError,
    engagement_capability_workspace,
    update_engagement_capability_selection,
)
from app.services.engagement_workspaces import (
    WORKSPACE_MARKER_RELATIVE_PATH,
    EngagementWorkspaceValidationError,
    prepare_engagement_workspace,
)
from app.services.redteam_infra_template import RedteamInfraTemplateSource
from app.services.retained_workspace_capability_roles import CAPABILITY_ROLE_IMPORTS_METADATA_KEY
from app.storage.engagement_workspace_repository import StoredEngagementWorkspace


ENGAGEMENT_ID = "eng-old123"
GOFS_SELECTION = [{"hostClass": "homebase", "id": "go-simple-upload-server"}]


def test_old_workspace_imports_exact_selected_role_and_dependency_with_git_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _prepared_old_workspace(tmp_path, monkeypatch)
    source = _committed_redteam_infra(tmp_path, dependency=True)
    expected_commit = _git(source, "rev-parse", "HEAD")
    expected_tree = _git(source, "rev-parse", "HEAD^{tree}")

    result = update_engagement_capability_selection(
        ENGAGEMENT_ID,
        {"selectedOptionals": GOFS_SELECTION},
        root=tmp_path / "engagements",
        repository=repo,
        service_repository=_EmptyServiceRepository(),
        template_source=RedteamInfraTemplateSource(source, "configured-test"),
    )

    assert result is not None
    workspace = Path(repo.workspace.path)
    assert (workspace / "ansible/roles/go_simple_upload_server/tasks/main.yml").is_file()
    assert (workspace / "ansible/roles/upload_helper/tasks/main.yml").is_file()
    assert not (workspace / "external/never-copy-this").exists()
    selected = result["profileResolution"]["hostClasses"]["homebase"]["optional"]
    gofs = next(entry for entry in selected if entry["id"] == "go-simple-upload-server")
    assert gofs["implementation"]["role"] == "go_simple_upload_server"
    assert gofs["selected"] is True

    records = repo.workspace.metadata[CAPABILITY_ROLE_IMPORTS_METADATA_KEY]
    assert len(records) == 1
    record = records[0]
    assert record["capabilityId"] == "go-simple-upload-server"
    assert record["role"] == "go_simple_upload_server"
    assert record["roles"] == ["go_simple_upload_server", "upload_helper"]
    assert record["importedRoles"] == ["go_simple_upload_server", "upload_helper"]
    assert record["source"]["commit"] == expected_commit
    assert record["source"]["tree"] == expected_tree
    assert set(record["source"]["roleTrees"]) == {"go_simple_upload_server", "upload_helper"}
    marker = json.loads((workspace / WORKSPACE_MARKER_RELATIVE_PATH).read_text(encoding="utf-8"))
    assert marker[CAPABILITY_ROLE_IMPORTS_METADATA_KEY] == records


def test_import_rejects_dirty_source_without_mutating_old_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _prepared_old_workspace(tmp_path, monkeypatch)
    source = _committed_redteam_infra(tmp_path)
    (source / "dirty.txt").write_text("not committed\n", encoding="utf-8")
    workspace = Path(repo.workspace.path)
    marker_before = (workspace / WORKSPACE_MARKER_RELATIVE_PATH).read_bytes()

    with pytest.raises(EngagementWorkspaceValidationError) as exc:
        update_engagement_capability_selection(
            ENGAGEMENT_ID,
            {"selectedOptionals": GOFS_SELECTION},
            root=tmp_path / "engagements",
            repository=repo,
            service_repository=_EmptyServiceRepository(),
            template_source=RedteamInfraTemplateSource(source, "configured-test"),
        )

    assert "source is dirty" in exc.value.errors[0]
    assert not (workspace / "ansible/roles/go_simple_upload_server").exists()
    assert (workspace / WORKSPACE_MARKER_RELATIVE_PATH).read_bytes() == marker_before
    assert CAPABILITY_ROLE_IMPORTS_METADATA_KEY not in repo.workspace.metadata


def test_invalid_mixed_selection_is_rejected_before_valid_role_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _prepared_old_workspace(tmp_path, monkeypatch)
    source = _committed_redteam_infra(tmp_path)
    workspace = Path(repo.workspace.path)
    marker_before = (workspace / WORKSPACE_MARKER_RELATIVE_PATH).read_bytes()

    with pytest.raises(EngagementCapabilityValidationError) as exc:
        update_engagement_capability_selection(
            ENGAGEMENT_ID,
            {
                "selectedOptionals": [
                    *GOFS_SELECTION,
                    {"hostClass": "homebase", "id": "not-a-real-capability"},
                ]
            },
            root=tmp_path / "engagements",
            repository=repo,
            service_repository=_EmptyServiceRepository(),
            template_source=RedteamInfraTemplateSource(source, "configured-test"),
        )

    assert exc.value.errors == ["unknown optional capability: homebase/not-a-real-capability"]
    assert not (workspace / "ansible/roles/go_simple_upload_server").exists()
    assert (workspace / WORKSPACE_MARKER_RELATIVE_PATH).read_bytes() == marker_before
    assert CAPABILITY_ROLE_IMPORTS_METADATA_KEY not in repo.workspace.metadata


def test_import_rejects_missing_source_with_clear_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _prepared_old_workspace(tmp_path, monkeypatch)

    with pytest.raises(EngagementWorkspaceValidationError) as exc:
        update_engagement_capability_selection(
            ENGAGEMENT_ID,
            {"selectedOptionals": GOFS_SELECTION},
            root=tmp_path / "engagements",
            repository=repo,
            service_repository=_EmptyServiceRepository(),
            template_source=RedteamInfraTemplateSource(
                tmp_path / "missing-redteam-infra",
                "missing",
                "configured Redteam-infra checkout is unavailable",
            ),
        )

    assert exc.value.errors == ["configured Redteam-infra checkout is unavailable"]


def test_existing_retained_role_is_never_overwritten_or_claimed_as_imported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _prepared_old_workspace(tmp_path, monkeypatch, existing_gofs=True)
    source = _committed_redteam_infra(tmp_path)
    retained_task = Path(repo.workspace.path) / "ansible/roles/go_simple_upload_server/tasks/main.yml"
    sentinel = retained_task.read_text(encoding="utf-8")

    result = update_engagement_capability_selection(
        ENGAGEMENT_ID,
        {"selectedOptionals": GOFS_SELECTION},
        root=tmp_path / "engagements",
        repository=repo,
        service_repository=_EmptyServiceRepository(),
        template_source=RedteamInfraTemplateSource(source, "configured-test"),
    )

    assert result is not None
    assert retained_task.read_text(encoding="utf-8") == sentinel
    assert CAPABILITY_ROLE_IMPORTS_METADATA_KEY not in repo.workspace.metadata


def test_capability_get_does_not_import_selected_role_into_old_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _prepared_old_workspace(tmp_path, monkeypatch)
    repo.workspace = replace(
        repo.workspace,
        metadata={
            **repo.workspace.metadata,
            "capabilityOverrides": {"deselectedDefaults": [], "selectedOptionals": GOFS_SELECTION},
        },
    )
    workspace = Path(repo.workspace.path)
    marker_before = (workspace / WORKSPACE_MARKER_RELATIVE_PATH).read_bytes()
    saves_before = repo.save_count

    result = engagement_capability_workspace(
        ENGAGEMENT_ID,
        root=tmp_path / "engagements",
        repository=repo,
        service_repository=_EmptyServiceRepository(),
    )

    assert result is not None
    assert not (workspace / "ansible/roles/go_simple_upload_server").exists()
    assert (workspace / WORKSPACE_MARKER_RELATIVE_PATH).read_bytes() == marker_before
    assert repo.save_count == saves_before


def test_import_rejects_symlinked_role_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _prepared_old_workspace(tmp_path, monkeypatch)
    source = _committed_redteam_infra(tmp_path)
    role = source / "ansible/roles/go_simple_upload_server"
    target = tmp_path / "outside-role"
    role.rename(target)
    role.symlink_to(target, target_is_directory=True)

    with pytest.raises(EngagementWorkspaceValidationError) as exc:
        update_engagement_capability_selection(
            ENGAGEMENT_ID,
            {"selectedOptionals": GOFS_SELECTION},
            root=tmp_path / "engagements",
            repository=repo,
            service_repository=_EmptyServiceRepository(),
            template_source=RedteamInfraTemplateSource(source, "configured-test"),
        )

    # The checkout is dirty after replacing a tracked tree with a symlink, so
    # it is rejected before any path can be followed or copied.
    assert "source is dirty" in exc.value.errors[0]


def test_retry_recovers_crash_between_role_promotions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _prepared_old_workspace(tmp_path, monkeypatch)
    source = _committed_redteam_infra(tmp_path, dependency=True)
    workspace = Path(repo.workspace.path)
    roles_root = workspace / "ansible/roles"
    original_replace = retained_roles.os.replace

    def interrupt_before_dependency(source_path, destination_path) -> None:
        destination = Path(destination_path)
        if destination.parent == roles_root and destination.name == "upload_helper":
            raise KeyboardInterrupt("simulated process exit")
        original_replace(source_path, destination_path)

    monkeypatch.setattr(retained_roles.os, "replace", interrupt_before_dependency)
    with pytest.raises(KeyboardInterrupt):
        update_engagement_capability_selection(
            ENGAGEMENT_ID,
            {"selectedOptionals": GOFS_SELECTION},
            root=tmp_path / "engagements",
            repository=repo,
            service_repository=_EmptyServiceRepository(),
            template_source=RedteamInfraTemplateSource(source, "configured-test"),
        )

    assert (roles_root / "go_simple_upload_server").is_dir()
    assert not (roles_root / "upload_helper").exists()
    assert (workspace / "barragan/capability-role-import-pending.json").is_file()

    monkeypatch.setattr(retained_roles.os, "replace", original_replace)
    result = update_engagement_capability_selection(
        ENGAGEMENT_ID,
        {"selectedOptionals": GOFS_SELECTION},
        root=tmp_path / "engagements",
        repository=repo,
        service_repository=_EmptyServiceRepository(),
        template_source=RedteamInfraTemplateSource(source, "configured-test"),
    )

    assert result is not None
    assert (roles_root / "upload_helper").is_dir()
    assert not (workspace / "barragan/capability-role-import-pending.json").exists()
    assert len(repo.workspace.metadata[CAPABILITY_ROLE_IMPORTS_METADATA_KEY]) == 1


def test_retry_recovers_crash_after_roles_before_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _prepared_old_workspace(tmp_path, monkeypatch)
    source = _committed_redteam_infra(tmp_path, dependency=True)
    workspace = Path(repo.workspace.path)
    original_write = retained_roles._write_json_atomically

    def interrupt_marker(path: Path, payload: dict) -> None:
        if path.name == WORKSPACE_MARKER_RELATIVE_PATH.name:
            raise KeyboardInterrupt("simulated process exit")
        original_write(path, payload)

    monkeypatch.setattr(retained_roles, "_write_json_atomically", interrupt_marker)
    with pytest.raises(KeyboardInterrupt):
        update_engagement_capability_selection(
            ENGAGEMENT_ID,
            {"selectedOptionals": GOFS_SELECTION},
            root=tmp_path / "engagements",
            repository=repo,
            service_repository=_EmptyServiceRepository(),
            template_source=RedteamInfraTemplateSource(source, "configured-test"),
        )

    assert (workspace / "ansible/roles/go_simple_upload_server").is_dir()
    assert (workspace / "ansible/roles/upload_helper").is_dir()
    assert (workspace / "barragan/capability-role-import-pending.json").is_file()
    assert CAPABILITY_ROLE_IMPORTS_METADATA_KEY not in repo.workspace.metadata

    monkeypatch.setattr(retained_roles, "_write_json_atomically", original_write)
    result = update_engagement_capability_selection(
        ENGAGEMENT_ID,
        {"selectedOptionals": GOFS_SELECTION},
        root=tmp_path / "engagements",
        repository=repo,
        service_repository=_EmptyServiceRepository(),
        template_source=RedteamInfraTemplateSource(source, "configured-test"),
    )

    assert result is not None
    assert not (workspace / "barragan/capability-role-import-pending.json").exists()
    assert len(repo.workspace.metadata[CAPABILITY_ROLE_IMPORTS_METADATA_KEY]) == 1
    marker = json.loads((workspace / WORKSPACE_MARKER_RELATIVE_PATH).read_text(encoding="utf-8"))
    assert marker[CAPABILITY_ROLE_IMPORTS_METADATA_KEY] == repo.workspace.metadata[CAPABILITY_ROLE_IMPORTS_METADATA_KEY]


def test_empty_selection_recovers_pending_import_without_selecting_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _prepared_old_workspace(tmp_path, monkeypatch)
    source = _committed_redteam_infra(tmp_path, dependency=True)
    workspace = Path(repo.workspace.path)
    roles_root = workspace / "ansible/roles"
    original_replace = retained_roles.os.replace

    def interrupt_before_dependency(source_path, destination_path) -> None:
        destination = Path(destination_path)
        if destination.parent == roles_root and destination.name == "upload_helper":
            raise KeyboardInterrupt("simulated process exit")
        original_replace(source_path, destination_path)

    monkeypatch.setattr(retained_roles.os, "replace", interrupt_before_dependency)
    with pytest.raises(KeyboardInterrupt):
        update_engagement_capability_selection(
            ENGAGEMENT_ID,
            {"selectedOptionals": GOFS_SELECTION},
            root=tmp_path / "engagements",
            repository=repo,
            service_repository=_EmptyServiceRepository(),
            template_source=RedteamInfraTemplateSource(source, "configured-test"),
        )

    monkeypatch.setattr(retained_roles.os, "replace", original_replace)
    result = update_engagement_capability_selection(
        ENGAGEMENT_ID,
        {"selectedOptionals": []},
        root=tmp_path / "engagements",
        repository=repo,
        service_repository=_EmptyServiceRepository(),
        template_source=RedteamInfraTemplateSource(source, "configured-test"),
    )

    assert result is not None
    assert result["overrides"]["selectedOptionals"] == []
    assert (roles_root / "go_simple_upload_server").is_dir()
    assert (roles_root / "upload_helper").is_dir()
    assert not (workspace / "barragan/capability-role-import-pending.json").exists()
    assert len(repo.workspace.metadata[CAPABILITY_ROLE_IMPORTS_METADATA_KEY]) == 1


def _prepared_old_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    existing_gofs: bool = False,
) -> "_FakeWorkspaceRepository":
    engagement = SimpleNamespace(id=ENGAGEMENT_ID, name="Old Workspace", input_parameters={})
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.engagement_capabilities.get_engagement", lambda _id: engagement)
    source = tmp_path / "old-redteam-infra"
    (source / "external").mkdir(parents=True)
    (source / "ansible").mkdir(parents=True)
    if existing_gofs:
        tasks = source / "ansible/roles/go_simple_upload_server/tasks"
        tasks.mkdir(parents=True)
        (tasks / "main.yml").write_text("---\n# retained sentinel\n", encoding="utf-8")
    repo = _FakeWorkspaceRepository()
    prepared = prepare_engagement_workspace(
        ENGAGEMENT_ID,
        root=tmp_path / "engagements",
        repository=repo,
        source=RedteamInfraTemplateSource(source, "old-template"),
    )
    assert prepared is not None and repo.workspace is not None
    return repo


def _committed_redteam_infra(tmp_path: Path, *, dependency: bool = False) -> Path:
    source = tmp_path / "current-redteam-infra"
    (source / "external").mkdir(parents=True)
    tasks = source / "ansible/roles/go_simple_upload_server/tasks"
    tasks.mkdir(parents=True)
    (tasks / "main.yml").write_text("---\n- debug:\n    msg: current\n", encoding="utf-8")
    if dependency:
        meta = source / "ansible/roles/go_simple_upload_server/meta"
        meta.mkdir(parents=True)
        (meta / "main.yml").write_text("---\ndependencies:\n  - role: upload_helper\n", encoding="utf-8")
        helper = source / "ansible/roles/upload_helper/tasks"
        helper.mkdir(parents=True)
        (helper / "main.yml").write_text("---\n- debug:\n    msg: helper\n", encoding="utf-8")
    (source / "external/never-copy-this").write_text("outside selected roles\n", encoding="utf-8")
    _git(source, "init", "-q")
    _git(source, "config", "user.email", "tests@example.invalid")
    _git(source, "config", "user.name", "Barragan Tests")
    _git(source, "add", ".")
    _git(source, "commit", "-qm", "fixture")
    return source


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True)
    return result.stdout.strip()


class _FakeWorkspaceRepository:
    def __init__(self) -> None:
        self.workspace: StoredEngagementWorkspace | None = None
        self.save_count = 0

    def get(self, engagement_id: str) -> StoredEngagementWorkspace | None:
        if self.workspace is not None and self.workspace.engagement_id == engagement_id:
            return self.workspace
        return None

    def save(self, workspace: StoredEngagementWorkspace) -> StoredEngagementWorkspace:
        self.save_count += 1
        self.workspace = workspace
        return workspace


class _EmptyServiceRepository:
    def list_for_engagement(self, _engagement_id: str):
        return []
