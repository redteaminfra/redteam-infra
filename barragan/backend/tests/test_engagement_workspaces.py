# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.engagement_workspaces import (
    EngagementWorkspaceValidationError,
    prepare_core_deployment_run,
    prepare_engagement_workspace,
    workspace_slug,
)
from app.services.redteam_infra_template import RedteamInfraTemplateSource
from app.storage.engagement_workspace_repository import StoredEngagementWorkspace


def test_workspace_slug_sanitizes_traversal_shell_and_hidden_names() -> None:
    assert workspace_slug("../../etc/passwd", "eng-abc123") == "etc-passwd-engabc123"
    assert workspace_slug("/tmp/test; rm -rf /", "eng-deadbeef") == "tmp-test-rm-rf-engdeadbeef"
    assert workspace_slug(".ssh", "eng-123") == "ssh-eng123"
    assert workspace_slug("!!!", "eng-123") == "engagement-eng123"


def test_prepare_workspace_copies_template_and_writes_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _template_source(tmp_path)
    root = tmp_path / "engagements"
    repo = _FakeWorkspaceRepository()
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))

    result = prepare_engagement_workspace(
        "eng-abc123",
        root=root,
        repository=repo,
        source=RedteamInfraTemplateSource(source, "test"),
        git_runner=_fake_git,
    )

    assert result is not None
    assert result.created is True
    workspace = result.workspace
    assert workspace.slug == "demo-01-engabc123"
    assert Path(workspace.path) == root / "demo-01-engabc123"
    assert (Path(workspace.path) / "ansible" / "site.yml").read_text(encoding="utf-8") == "---\n"
    marker = json.loads((Path(workspace.path) / "barragan" / "workspace-manifest.json").read_text(encoding="utf-8"))
    assert marker["managedBy"] == "barragan"
    assert marker["engagementId"] == "eng-abc123"
    assert marker["profileId"] == "standard-rti"
    assert marker["templateSource"]["git"]["commit"] == "abc123"
    assert "managedHostImageProfile" not in workspace.metadata
    assert not (Path(workspace.path) / ".git").exists()


def test_prepare_workspace_is_idempotent_for_owned_existing_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _template_source(tmp_path)
    root = tmp_path / "engagements"
    repo = _FakeWorkspaceRepository()
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))

    first = prepare_engagement_workspace("eng-abc123", root=root, repository=repo, source=RedteamInfraTemplateSource(source, "test"))
    second = prepare_engagement_workspace("eng-abc123", root=root, repository=repo, source=RedteamInfraTemplateSource(source, "test"))

    assert first is not None
    assert second is not None
    assert first.created is True
    assert second.created is False
    assert second.workspace.path == first.workspace.path


def test_prepare_workspace_refuses_unmanaged_existing_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _template_source(tmp_path)
    root = tmp_path / "engagements"
    (root / "demo-01-engabc123").mkdir(parents=True)
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))

    with pytest.raises(EngagementWorkspaceValidationError) as exc:
        prepare_engagement_workspace("eng-abc123", root=root, repository=_FakeWorkspaceRepository(), source=RedteamInfraTemplateSource(source, "test"))

    assert exc.value.errors == ["engagement workspace target already exists and is not Barragan-owned"]


def test_prepare_workspace_refuses_symlink_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _template_source(tmp_path)
    root = tmp_path / "engagements"
    root.mkdir()
    (root / "demo-01-engabc123").symlink_to(tmp_path)
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))

    with pytest.raises(EngagementWorkspaceValidationError) as exc:
        prepare_engagement_workspace("eng-abc123", root=root, repository=_FakeWorkspaceRepository(), source=RedteamInfraTemplateSource(source, "test"))

    assert exc.value.errors == ["engagement workspace target must not be a symlink"]


def test_prepare_workspace_refuses_template_symlink(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _template_source(tmp_path)
    (source / "leak").symlink_to("/etc/passwd")
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))

    with pytest.raises(EngagementWorkspaceValidationError) as exc:
        prepare_engagement_workspace(
            "eng-abc123",
            root=tmp_path / "engagements",
            repository=_FakeWorkspaceRepository(),
            source=RedteamInfraTemplateSource(source, "test"),
        )

    assert exc.value.errors == ["template source contains unsupported symlink: leak"]


def test_prepare_workspace_refuses_existing_stored_path_outside_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
        prepare_engagement_workspace(
            "eng-abc123",
            root=tmp_path / "engagements",
            repository=repo,
            source=RedteamInfraTemplateSource(_template_source(tmp_path), "test"),
        )

    assert exc.value.errors == ["stored engagement workspace path escapes configured root"]


def test_prepared_core_run_keeps_state_private_and_writes_sanitized_provenance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _template_source(tmp_path)
    (source / "secrets.tfvars").write_text('token = "do-not-copy"\n', encoding="utf-8")
    root = tmp_path / "engagements"
    state_root = tmp_path / "private-state"
    repo = _FakeWorkspaceRepository()
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))
    prepared = prepare_engagement_workspace("eng-abc123", root=root, repository=repo, source=RedteamInfraTemplateSource(source, "test"))
    assert prepared is not None

    run = prepare_core_deployment_run(
        "eng-abc123",
        root=root,
        state_root=state_root,
        run_id="core-abc123",
        repository=repo,
        provider_resource_repository=SimpleNamespace(list_for_engagement=lambda _engagement_id: []),
    )

    assert run.run_directory == Path(prepared.workspace.path) / "barragan" / "runs" / "core-abc123"
    assert run.state_path == state_root / prepared.workspace.slug / "core" / "terraform.tfstate"
    assert not run.state_path.exists()
    assert stat.S_IMODE(run.terraform_data_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(run.run_directory.stat().st_mode) == 0o700
    assert not (Path(prepared.workspace.path) / "secrets.tfvars").exists()
    manifest = json.loads((run.run_directory / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["terraformState"]["storedOutsideEngagementWorkspace"] is True
    assert manifest["terraformState"]["locator"] == "engagement/eng-abc123/core/terraform.tfstate"
    assert manifest["managedHostImageProfile"] == "ubuntu-24.04"
    assert "do-not-copy" not in (run.run_directory / "run-manifest.json").read_text(encoding="utf-8")


def test_core_run_refuses_missing_or_tampered_workspace_before_creating_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "engagements"
    state_root = tmp_path / "private-state"
    repo = _FakeWorkspaceRepository()
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))
    with pytest.raises(EngagementWorkspaceValidationError):
        prepare_core_deployment_run("eng-abc123", root=root, state_root=state_root, run_id="core-missing", repository=repo)
    assert not state_root.exists()


def test_core_run_refuses_to_pin_default_over_unprofiled_retained_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _template_source(tmp_path)
    root = tmp_path / "engagements"
    state_root = tmp_path / "private-state"
    repo = _FakeWorkspaceRepository()
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))
    prepared = prepare_engagement_workspace(
        "eng-abc123",
        root=root,
        repository=repo,
        source=RedteamInfraTemplateSource(source, "test"),
    )
    assert prepared is not None
    repo.workspace = StoredEngagementWorkspace(
        **{**prepared.workspace.__dict__, "metadata": {"markerPath": "barragan/workspace-manifest.json"}}
    )
    state_path = state_root / prepared.workspace.slug / "core" / "terraform.tfstate"
    state_path.parent.mkdir(parents=True)
    state_path.write_text(
        json.dumps(
            {
                "version": 4,
                "serial": 1,
                "lineage": "unprofiled-retained",
                "outputs": {},
                "resources": [
                    {
                        "mode": "managed",
                        "type": "oci_core_instance",
                        "instances": [
                            {"attributes": {"source_details": [{"source_id": "ocid1.image.oc1.iad.legacy"}]}}
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(EngagementWorkspaceValidationError) as exc:
        prepare_core_deployment_run(
            "eng-abc123",
            root=root,
            state_root=state_root,
            run_id="core-retained",
            repository=repo,
        )

    assert exc.value.errors == [
        "engagement has retained managed infrastructure but no image profile; review state before adoption"
    ]


def test_core_run_threads_exact_retained_oci_image_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "engagements"
    state_root = tmp_path / "private-state"
    repo = _FakeWorkspaceRepository()
    monkeypatch.setattr(
        "app.services.engagement_workspaces.get_engagement",
        lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"),
    )
    prepared = prepare_engagement_workspace(
        "eng-abc123",
        root=root,
        repository=repo,
        source=RedteamInfraTemplateSource(_template_source(tmp_path), "test"),
    )
    assert prepared is not None
    repo.workspace = StoredEngagementWorkspace(
        **{
            **prepared.workspace.__dict__,
            "metadata": {
                **prepared.workspace.metadata,
                "managedHostImageProfile": "ubuntu-22.04",
            },
        }
    )
    source_image = "ocid1.image.oc1.iad.exact-retained"
    state_path = state_root / prepared.workspace.slug / "core" / "terraform.tfstate"
    state_path.parent.mkdir(parents=True)
    state_path.write_text(
        json.dumps(
            {
                "version": 4,
                "serial": 2,
                "lineage": "exact-retained",
                "outputs": {},
                "resources": [
                    {
                        "mode": "managed",
                        "type": "oci_core_instance",
                        "instances": [
                            {"attributes": {"source_details": [{"source_id": source_image}]}}
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    run = prepare_core_deployment_run(
        "eng-abc123",
        root=root,
        state_root=state_root,
        run_id="core-retained-exact",
        repository=repo,
    )

    assert run.retained_oci_source_image_id == source_image
    assert run.managed_host_image_profile_name == "ubuntu-22.04"


def test_verified_clean_core_state_allows_retry_with_existing_profile_pin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _template_source(tmp_path)
    root = tmp_path / "engagements"
    state_root = tmp_path / "private-state"
    repo = _FakeWorkspaceRepository()
    provider_resources = SimpleNamespace(list_for_engagement=lambda _engagement_id: [])
    monkeypatch.setattr(
        "app.services.engagement_workspaces.get_engagement",
        lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"),
    )
    prepared = prepare_engagement_workspace(
        "eng-abc123",
        root=root,
        repository=repo,
        source=RedteamInfraTemplateSource(source, "test"),
    )
    assert prepared is not None

    first = prepare_core_deployment_run(
        "eng-abc123",
        root=root,
        state_root=state_root,
        run_id="core-first-plan",
        repository=repo,
        provider_resource_repository=provider_resources,
    )
    assert first.managed_host_image_profile_name == "ubuntu-24.04"
    assert repo.workspace.metadata["managedHostImageProfile"] == "ubuntu-24.04"
    first.state_path.write_text(
        json.dumps(
            {
                "version": 4,
                "terraform_version": "1.9.0",
                "serial": 4,
                "lineage": "verified-clean-retry",
                "outputs": {},
                "resources": [],
            }
        ),
        encoding="utf-8",
    )

    verified_clean_job = SimpleNamespace(
        id="job-cleaned",
        action="pilot_standard_rti_guarded_execute",
        status="failed",
        input={"engagementId": "eng-abc123"},
        events=[
            SimpleNamespace(
                message="cleanup verification completed",
                data={
                    "mutationStatus": "ansible_failed",
                    "finalCleanupStatus": "verified_clean",
                    "remainingCount": 0,
                },
            )
        ],
    )
    retry = prepare_core_deployment_run(
        "eng-abc123",
        root=root,
        state_root=state_root,
        run_id="core-retry-plan",
        repository=repo,
        provider_resource_repository=provider_resources,
        job_repository=SimpleNamespace(list_for_engagement=lambda _engagement_id: [verified_clean_job]),
        sketch_chain_repository=SimpleNamespace(list_for_engagement=lambda _engagement_id: []),
    )

    assert retry.retained_oci_source_image_id == ""
    assert retry.managed_host_image_profile_name == "ubuntu-24.04"
    assert repo.workspace.metadata["managedHostImageProfile"] == "ubuntu-24.04"


def test_unpinned_verified_clean_core_state_still_blocks_profile_adoption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "engagements"
    state_root = tmp_path / "private-state"
    repo = _FakeWorkspaceRepository()
    monkeypatch.setattr(
        "app.services.engagement_workspaces.get_engagement",
        lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"),
    )
    prepared = prepare_engagement_workspace(
        "eng-abc123",
        root=root,
        repository=repo,
        source=RedteamInfraTemplateSource(_template_source(tmp_path), "test"),
    )
    assert prepared is not None
    state_path = state_root / prepared.workspace.slug / "core" / "terraform.tfstate"
    state_path.parent.mkdir(parents=True)
    state_path.write_text(
        json.dumps(
            {
                "version": 4,
                "serial": 1,
                "lineage": "unpinned-clean",
                "outputs": {},
                "resources": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(EngagementWorkspaceValidationError) as exc:
        prepare_core_deployment_run(
            "eng-abc123",
            root=root,
            state_root=state_root,
            run_id="core-unpinned-clean-state",
            repository=repo,
        )

    assert exc.value.errors == [
        "engagement has retained managed infrastructure but no image profile; review state before adoption"
    ]
    assert not (Path(prepared.workspace.path) / "barragan" / "runs" / "core-unpinned-clean-state").exists()


def test_pinned_retry_rejects_malformed_clean_state_before_creating_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "engagements"
    state_root = tmp_path / "private-state"
    repo = _FakeWorkspaceRepository()
    monkeypatch.setattr(
        "app.services.engagement_workspaces.get_engagement",
        lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"),
    )
    prepared = prepare_engagement_workspace(
        "eng-abc123",
        root=root,
        repository=repo,
        source=RedteamInfraTemplateSource(_template_source(tmp_path), "test"),
    )
    assert prepared is not None
    repo.workspace = StoredEngagementWorkspace(
        **{
            **prepared.workspace.__dict__,
            "metadata": {**prepared.workspace.metadata, "managedHostImageProfile": "ubuntu-24.04"},
        }
    )
    state_path = state_root / prepared.workspace.slug / "core" / "terraform.tfstate"
    state_path.parent.mkdir(parents=True)
    state_path.write_text(
        json.dumps(
            {
                "version": 4,
                "serial": 1,
                "lineage": "malformed-clean",
                "outputs": {},
                "resources": "not-a-list",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(EngagementWorkspaceValidationError) as exc:
        prepare_core_deployment_run(
            "eng-abc123",
            root=root,
            state_root=state_root,
            run_id="core-malformed-clean-state",
            repository=repo,
        )

    assert exc.value.errors == ["retained core Terraform state is invalid"]
    assert not (Path(prepared.workspace.path) / "barragan" / "runs" / "core-malformed-clean-state").exists()


@pytest.mark.parametrize("active_provider", [False, True], ids=["no-cleanup-job", "active-owned-oci"])
def test_pinned_empty_core_state_requires_destroyed_lifecycle_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    active_provider: bool,
) -> None:
    root = tmp_path / "engagements"
    state_root = tmp_path / "private-state"
    repo = _FakeWorkspaceRepository()
    monkeypatch.setattr(
        "app.services.engagement_workspaces.get_engagement",
        lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"),
    )
    prepared = prepare_engagement_workspace(
        "eng-abc123",
        root=root,
        repository=repo,
        source=RedteamInfraTemplateSource(_template_source(tmp_path), "test"),
    )
    assert prepared is not None
    repo.workspace = StoredEngagementWorkspace(
        **{
            **prepared.workspace.__dict__,
            "metadata": {**prepared.workspace.metadata, "managedHostImageProfile": "ubuntu-24.04"},
        }
    )
    state_path = state_root / prepared.workspace.slug / "core" / "terraform.tfstate"
    state_path.parent.mkdir(parents=True)
    state_path.write_text(
        json.dumps(
            {
                "version": 4,
                "serial": 2,
                "lineage": "cleanup-proof-required",
                "outputs": {},
                "resources": [],
            }
        ),
        encoding="utf-8",
    )
    clean_job = SimpleNamespace(
        id="job-cleaned",
        action="pilot_standard_rti_guarded_execute",
        status="failed",
        input={"engagementId": "eng-abc123"},
        events=[
            SimpleNamespace(
                message="cleanup verification completed",
                data={"finalCleanupStatus": "verified_clean"},
            )
        ],
    )
    active_record = SimpleNamespace(
        id="oci:compute_instance:active",
        provider="oci",
        resource_type="compute_instance",
        status="active",
        source="barragan",
        metadata={"barraganOwned": True},
    )

    with pytest.raises(EngagementWorkspaceValidationError) as exc:
        prepare_core_deployment_run(
            "eng-abc123",
            root=root,
            state_root=state_root,
            run_id="core-cleanup-proof-blocked",
            repository=repo,
            job_repository=SimpleNamespace(
                list_for_engagement=lambda _engagement_id: [clean_job] if active_provider else []
            ),
            provider_resource_repository=SimpleNamespace(
                list_for_engagement=lambda _engagement_id: [active_record] if active_provider else []
            ),
            sketch_chain_repository=SimpleNamespace(list_for_engagement=lambda _engagement_id: []),
        )

    assert exc.value.errors == [
        "empty retained core state requires authoritative verified-clean lifecycle evidence"
    ]


def test_template_copy_excludes_secret_and_transient_material(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _template_source(tmp_path)
    for name in (".env", "credentials", "terraform.tfstate", "operator.log", "id_ed25519"):
        (source / name).write_text("must-not-be-copied", encoding="utf-8")
    root = tmp_path / "engagements"
    repo = _FakeWorkspaceRepository()
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))

    prepared = prepare_engagement_workspace("eng-abc123", root=root, repository=repo, source=RedteamInfraTemplateSource(source, "test"))

    workspace_root = Path(prepared.workspace.path)
    assert stat.S_IMODE(workspace_root.stat().st_mode) == 0o700
    assert stat.S_IMODE((workspace_root / "barragan").stat().st_mode) == 0o700
    assert stat.S_IMODE((workspace_root / "barragan" / "workspace-manifest.json").stat().st_mode) == 0o600
    assert not any((workspace_root / name).exists() for name in (".env", "credentials", "terraform.tfstate", "operator.log", "id_ed25519"))


def _template_source(tmp_path: Path) -> Path:
    source = tmp_path / "redteam-infra"
    (source / "ansible").mkdir(parents=True, exist_ok=True)
    (source / "external").mkdir(parents=True, exist_ok=True)
    (source / ".git").mkdir(exist_ok=True)
    (source / "ansible" / "site.yml").write_text("---\n", encoding="utf-8")
    return source


def _fake_git(_root: Path, args: list[str]) -> str:
    command = " ".join(args)
    if command == "branch --show-current":
        return "main\n"
    if command == "rev-parse HEAD":
        return "abc123\n"
    if command == "status --porcelain":
        return ""
    raise AssertionError(f"unexpected git command: {command}")


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
