# Copyright (c) 2026, Oracle and/or its affiliates.
from pathlib import Path
import json
import stat

import pytest

from app.services import sketch_state_workspaces
from app.services.sketch_state_workspaces import (
    SketchStateWorkspaceError,
    grant_collaborator_access_to_existing_sketch_state_workspace,
    prepare_sketch_state_workspace,
    retained_compute_image_for_workspace,
    validate_existing_sketch_state_workspace,
)


def _template(root: Path) -> Path:
    template = root / "template"
    template.mkdir()
    (template / "main.tf").write_text("terraform {}\n", encoding="utf-8")
    return template


def test_prepares_private_durable_chain_workspace(tmp_path: Path):
    result = prepare_sketch_state_workspace(
        "eng-abc123", "proxy01-sea-01", "linode", template_directory=_template(tmp_path), root=tmp_path / "state"
    )

    assert result.path == tmp_path / "state" / "eng-abc123" / "proxy01-sea-01" / "linode"
    assert result.locator == "sketch/eng-abc123/proxy01-sea-01/linode/terraform.tfstate"
    assert (result.path / "main.tf").is_file()
    assert stat.S_IMODE(result.path.stat().st_mode) == 0o700
    assert stat.S_IMODE((result.path / "main.tf").stat().st_mode) == 0o600
    assert stat.S_IMODE(result.terraform_data_dir.stat().st_mode) == 0o700


def test_reuses_only_its_owned_state_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    template = _template(tmp_path)
    first = prepare_sketch_state_workspace("eng-abc123", "proxy01-sea-01", "linode", template_directory=template, root=tmp_path / "state")
    (first.path / "terraform.tfstate").write_text("existing-state", encoding="utf-8")
    monkeypatch.setattr(
        sketch_state_workspaces, "_collaborator_group_gid", lambda: sketch_state_workspaces.os.getgid()
    )
    second = prepare_sketch_state_workspace("eng-abc123", "proxy01-sea-01", "linode", template_directory=template, root=tmp_path / "state")

    assert second.path == first.path
    assert second.state_path.read_text(encoding="utf-8") == "existing-state"


def test_reuse_rejects_unsafe_existing_workspace_descendant(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    template = _template(tmp_path)
    monkeypatch.setattr(sketch_state_workspaces, "_collaborator_group_gid", lambda: None)
    prepared = prepare_sketch_state_workspace(
        "eng-abc123", "proxy01-sea-01", "linode", template_directory=template, root=tmp_path / "state"
    )
    state_root = tmp_path / "state"
    state_root.chmod(0o750)
    (prepared.path / "main.tf").chmod(0o666)

    with pytest.raises(SketchStateWorkspaceError, match="ownership or file permissions are unsafe"):
        prepare_sketch_state_workspace(
            "eng-abc123", "proxy01-sea-01", "linode", template_directory=template, root=tmp_path / "state"
        )
    assert stat.S_IMODE(state_root.stat().st_mode) == 0o750


def test_refuses_unowned_or_unsafe_state_target(tmp_path: Path):
    template = _template(tmp_path)
    target = tmp_path / "state" / "eng-abc123" / "proxy01-sea-01" / "linode"
    target.mkdir(parents=True)
    (tmp_path / "state").chmod(0o700)
    for directory in [target.parent.parent, target.parent, target]:
        directory.chmod(0o700)

    with pytest.raises(SketchStateWorkspaceError, match="ownership marker is invalid"):
        prepare_sketch_state_workspace("eng-abc123", "proxy01-sea-01", "linode", template_directory=template, root=tmp_path / "state")
    with pytest.raises(SketchStateWorkspaceError, match="safe filesystem token"):
        prepare_sketch_state_workspace("../unsafe", "proxy01-sea-01", "linode", template_directory=template, root=tmp_path / "state")


def test_fresh_target_rejects_world_writable_existing_root_without_mutation(tmp_path: Path):
    template = _template(tmp_path)
    state_root = tmp_path / "state"
    state_root.mkdir()
    state_root.chmod(0o777)
    target = state_root / "eng-abc123" / "proxy01-sea-01" / "linode"

    with pytest.raises(SketchStateWorkspaceError, match="root ownership or permissions are unsafe"):
        prepare_sketch_state_workspace(
            "eng-abc123", "proxy01-sea-01", "linode", template_directory=template, root=state_root
        )

    assert stat.S_IMODE(state_root.stat().st_mode) == 0o777
    assert not target.exists()


def test_fresh_target_rejects_wrong_owner_existing_root_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    template = _template(tmp_path)
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    original_mode = stat.S_IMODE(state_root.stat().st_mode)
    target = state_root / "eng-abc123" / "proxy01-sea-01" / "linode"
    monkeypatch.setattr(sketch_state_workspaces.os, "geteuid", lambda: state_root.stat().st_uid + 1)

    with pytest.raises(SketchStateWorkspaceError, match="root ownership or permissions are unsafe"):
        prepare_sketch_state_workspace(
            "eng-abc123", "proxy01-sea-01", "linode", template_directory=template, root=state_root
        )

    assert stat.S_IMODE(state_root.stat().st_mode) == original_mode
    assert not target.exists()


@pytest.mark.parametrize("root_mode", [0o700, 0o750, 0o2750])
def test_fresh_target_accepts_safe_existing_root_modes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    root_mode: int,
):
    template = _template(tmp_path)
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    state_root.chmod(root_mode)
    monkeypatch.setattr(sketch_state_workspaces, "_collaborator_group_gid", lambda: None)

    prepared = prepare_sketch_state_workspace(
        "eng-abc123", "proxy01-sea-01", "linode", template_directory=template, root=state_root
    )

    assert prepared.path.is_dir()


def test_validates_canonical_component_workspace_without_writing(tmp_path: Path):
    prepared = prepare_sketch_state_workspace(
        "eng-abc123",
        "proxy01-sea-01",
        "linode",
        component_id="middle",
        template_directory=_template(tmp_path),
        root=tmp_path / "state",
    )
    prepared.state_path.write_text('{"resources": []}', encoding="utf-8")
    prepared.state_path.chmod(0o600)
    before = {path: path.stat().st_mtime_ns for path in prepared.path.rglob("*")}

    validated = validate_existing_sketch_state_workspace(
        "eng-abc123",
        "proxy01-sea-01",
        "linode",
        prepared.path,
        component_id="middle",
        root=tmp_path / "state",
    )

    assert validated == prepared
    assert {path: path.stat().st_mtime_ns for path in prepared.path.rglob("*")} == before
    assert validated.locator == "sketch/eng-abc123/proxy01-sea-01/components/middle/linode/terraform.tfstate"


def test_retained_validator_rejects_mismatched_missing_and_symlinked_state(tmp_path: Path):
    template = _template(tmp_path)
    prepared = prepare_sketch_state_workspace(
        "eng-abc123", "proxy01-sea-01", "linode", component_id="middle", template_directory=template, root=tmp_path / "state"
    )
    with pytest.raises(SketchStateWorkspaceError, match="state is unavailable"):
        validate_existing_sketch_state_workspace(
            "eng-abc123", "proxy01-sea-01", "linode", prepared.path, component_id="middle", root=tmp_path / "state"
        )
    prepared.state_path.write_text('{"resources": []}', encoding="utf-8")
    prepared.state_path.chmod(0o600)
    with pytest.raises(SketchStateWorkspaceError, match="canonical workspace"):
        validate_existing_sketch_state_workspace(
            "eng-abc123", "proxy01-sea-01", "linode", tmp_path / "elsewhere", component_id="middle", root=tmp_path / "state"
        )
    prepared.state_path.unlink()
    external = tmp_path / "external-state"
    external.write_text('{"resources": []}', encoding="utf-8")
    external.chmod(0o600)
    prepared.state_path.symlink_to(external)
    with pytest.raises(SketchStateWorkspaceError, match="symlinks"):
        validate_existing_sketch_state_workspace(
            "eng-abc123", "proxy01-sea-01", "linode", prepared.path, component_id="middle", root=tmp_path / "state"
        )


def test_reads_exact_retained_compute_image_and_fails_closed_on_ambiguity(tmp_path: Path):
    prepared = prepare_sketch_state_workspace(
        "eng-abc123", "proxy01-sea-01", "linode", component_id="middle", template_directory=_template(tmp_path), root=tmp_path / "state"
    )
    state = {
        "resources": [{
            "mode": "managed",
            "type": "linode_instance",
            "instances": [{"attributes": {"image": "linode/ubuntu22.04"}}],
        }]
    }
    prepared.state_path.write_text(json.dumps(state), encoding="utf-8")
    prepared.state_path.chmod(0o600)
    assert retained_compute_image_for_workspace(
        "eng-abc123", "proxy01-sea-01", "linode", prepared.path, component_id="middle", root=tmp_path / "state"
    ) == "linode/ubuntu22.04"

    state["resources"][0]["instances"] = [{"attributes": {}}]
    prepared.state_path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(SketchStateWorkspaceError, match="missing or conflicting"):
        retained_compute_image_for_workspace(
            "eng-abc123", "proxy01-sea-01", "linode", prepared.path, component_id="middle", root=tmp_path / "state"
        )

    state["resources"][0]["instances"] = [{"attributes": {"image": "linode/ubuntu22.04"}}]
    state["resources"][0]["instances"].append({"attributes": {"image": "linode/ubuntu24.04"}})
    prepared.state_path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(SketchStateWorkspaceError, match="missing or conflicting"):
        retained_compute_image_for_workspace(
            "eng-abc123", "proxy01-sea-01", "linode", prepared.path, component_id="middle", root=tmp_path / "state"
        )


def test_retained_validator_rejects_supplied_symlink_alias_and_open_permissions(tmp_path: Path):
    prepared = prepare_sketch_state_workspace(
        "eng-abc123", "proxy01-sea-01", "linode", component_id="middle", template_directory=_template(tmp_path), root=tmp_path / "state"
    )
    prepared.state_path.write_text('{"resources": []}', encoding="utf-8")
    prepared.state_path.chmod(0o600)
    alias = tmp_path / "workspace-alias"
    alias.symlink_to(prepared.path, target_is_directory=True)

    with pytest.raises(SketchStateWorkspaceError, match="supplied path.*symlinks"):
        validate_existing_sketch_state_workspace(
            "eng-abc123", "proxy01-sea-01", "linode", alias, component_id="middle", root=tmp_path / "state"
        )

    prepared.path.chmod(0o755)
    with pytest.raises(SketchStateWorkspaceError, match="workspace permissions"):
        validate_existing_sketch_state_workspace(
            "eng-abc123", "proxy01-sea-01", "linode", prepared.path, component_id="middle", root=tmp_path / "state"
        )
    prepared.path.chmod(0o700)
    prepared.state_path.chmod(0o644)
    validated = validate_existing_sketch_state_workspace(
        "eng-abc123", "proxy01-sea-01", "linode", prepared.path, component_id="middle", root=tmp_path / "state"
    )
    assert validated.state_path == prepared.state_path

    prepared.state_path.chmod(0o666)
    with pytest.raises(SketchStateWorkspaceError, match="state permissions"):
        validate_existing_sketch_state_workspace(
            "eng-abc123", "proxy01-sea-01", "linode", prepared.path, component_id="middle", root=tmp_path / "state"
        )


def test_retained_validator_rejects_writable_source_and_wrong_file_type(tmp_path: Path):
    prepared = prepare_sketch_state_workspace(
        "eng-abc123", "proxy01-sea-01", "linode", template_directory=_template(tmp_path), root=tmp_path / "state"
    )
    prepared.state_path.write_text('{"resources": []}', encoding="utf-8")
    prepared.state_path.chmod(0o644)
    source = prepared.path / "main.tf"
    source.chmod(0o664)
    with pytest.raises(SketchStateWorkspaceError, match="file permissions"):
        validate_existing_sketch_state_workspace(
            "eng-abc123", "proxy01-sea-01", "linode", prepared.path, root=tmp_path / "state"
        )

    source.chmod(0o644)
    unsupported = prepared.path / "terraform.pipe"
    sketch_state_workspaces.os.mkfifo(unsupported)
    with pytest.raises(SketchStateWorkspaceError, match="file permissions"):
        validate_existing_sketch_state_workspace(
            "eng-abc123", "proxy01-sea-01", "linode", prepared.path, root=tmp_path / "state"
        )


def test_new_workspace_uses_barragan_group_read_and_traversal_when_available(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(sketch_state_workspaces, "_collaborator_group_gid", lambda: sketch_state_workspaces.os.getgid())
    prepared = prepare_sketch_state_workspace(
        "eng-abc123", "proxy01-sea-01", "linode", template_directory=_template(tmp_path), root=tmp_path / "state"
    )

    assert stat.S_IMODE(prepared.path.stat().st_mode) in {0o750, 0o2750}
    assert prepared.path.stat().st_gid == sketch_state_workspaces.os.getgid()
    assert stat.S_IMODE((prepared.path / "main.tf").stat().st_mode) == 0o640
    assert stat.S_IMODE(prepared.terraform_data_dir.stat().st_mode) in {0o750, 0o2750}


def test_existing_workspace_transitions_to_collaborator_access_after_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(sketch_state_workspaces, "_collaborator_group_gid", lambda: None)
    prepared = prepare_sketch_state_workspace(
        "eng-abc123", "proxy01-sea-01", "linode", template_directory=_template(tmp_path), root=tmp_path / "state"
    )
    prepared.state_path.write_text('{"resources": []}', encoding="utf-8")
    prepared.state_path.chmod(0o644)
    executable = prepared.path / "terraform-provider-test"
    executable.write_text("binary", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setattr(
        sketch_state_workspaces, "_collaborator_group_gid", lambda: sketch_state_workspaces.os.getgid()
    )

    grant_collaborator_access_to_existing_sketch_state_workspace(
        "eng-abc123", "proxy01-sea-01", "linode", prepared.path, root=tmp_path / "state"
    )

    assert stat.S_IMODE((tmp_path / "state").stat().st_mode) in {0o750, 0o2750}
    assert stat.S_IMODE(prepared.path.stat().st_mode) in {0o750, 0o2750}
    assert stat.S_IMODE((prepared.path / "main.tf").stat().st_mode) == 0o640
    assert stat.S_IMODE(executable.stat().st_mode) == 0o750
    assert stat.S_IMODE(prepared.state_path.stat().st_mode) == 0o644


def test_collaborator_transition_preflights_all_paths_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(sketch_state_workspaces, "_collaborator_group_gid", lambda: None)
    prepared = prepare_sketch_state_workspace(
        "eng-abc123", "proxy01-sea-01", "linode", template_directory=_template(tmp_path), root=tmp_path / "state"
    )
    prepared.state_path.write_text('{"resources": []}', encoding="utf-8")
    prepared.state_path.chmod(0o644)
    safe_file = prepared.path / "safe.tf"
    safe_file.write_text("safe", encoding="utf-8")
    safe_file.chmod(0o600)
    unsafe_file = prepared.path / "unsafe.tf"
    unsafe_file.write_text("unsafe", encoding="utf-8")
    unsafe_file.chmod(0o666)
    before = {path: stat.S_IMODE(path.stat().st_mode) for path in [tmp_path / "state", prepared.path, safe_file]}
    monkeypatch.setattr(
        sketch_state_workspaces, "_collaborator_group_gid", lambda: sketch_state_workspaces.os.getgid()
    )

    with pytest.raises(SketchStateWorkspaceError, match="ownership or file permissions are unsafe"):
        grant_collaborator_access_to_existing_sketch_state_workspace(
            "eng-abc123", "proxy01-sea-01", "linode", prepared.path, root=tmp_path / "state"
        )

    assert {path: stat.S_IMODE(path.stat().st_mode) for path in before} == before


def test_existing_transition_fails_without_collaborator_group_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(sketch_state_workspaces, "_collaborator_group_gid", lambda: None)
    prepared = prepare_sketch_state_workspace(
        "eng-abc123", "proxy01-sea-01", "linode", template_directory=_template(tmp_path), root=tmp_path / "state"
    )
    prepared.state_path.write_text('{"resources": []}', encoding="utf-8")
    prepared.state_path.chmod(0o644)
    before = {path: stat.S_IMODE(path.stat().st_mode) for path in [tmp_path / "state", prepared.path, prepared.state_path]}

    with pytest.raises(SketchStateWorkspaceError, match="collaborator group is unavailable"):
        grant_collaborator_access_to_existing_sketch_state_workspace(
            "eng-abc123", "proxy01-sea-01", "linode", prepared.path, root=tmp_path / "state"
        )

    assert {path: stat.S_IMODE(path.stat().st_mode) for path in before} == before


def test_retained_validator_rejects_component_parent_and_source_symlinks(tmp_path: Path):
    prepared = prepare_sketch_state_workspace(
        "eng-abc123", "proxy01-sea-01", "linode", component_id="middle", template_directory=_template(tmp_path), root=tmp_path / "state"
    )
    prepared.state_path.write_text('{"resources": []}', encoding="utf-8")
    prepared.state_path.chmod(0o600)
    component_parent = prepared.path.parent
    component_parent.chmod(0o777)
    with pytest.raises(SketchStateWorkspaceError, match="workspace ancestor permissions"):
        validate_existing_sketch_state_workspace(
            "eng-abc123", "proxy01-sea-01", "linode", prepared.path, component_id="middle", root=tmp_path / "state"
        )

    component_parent.chmod(0o700)
    outside = tmp_path / "outside.tf"
    outside.write_text("outside\n", encoding="utf-8")
    (prepared.path / "linked.tf").symlink_to(outside)
    with pytest.raises(SketchStateWorkspaceError, match="workspace must not contain symlinks"):
        validate_existing_sketch_state_workspace(
            "eng-abc123", "proxy01-sea-01", "linode", prepared.path, component_id="middle", root=tmp_path / "state"
        )


def test_retained_image_requires_managed_compute(tmp_path: Path):
    prepared = prepare_sketch_state_workspace(
        "eng-abc123", "proxy01-sea-01", "digitalocean", component_id="edge-01", template_directory=_template(tmp_path), root=tmp_path / "state"
    )
    prepared.state_path.write_text('{"resources": []}', encoding="utf-8")
    prepared.state_path.chmod(0o600)

    with pytest.raises(SketchStateWorkspaceError, match="missing or conflicting"):
        retained_compute_image_for_workspace(
            "eng-abc123", "proxy01-sea-01", "digitalocean", prepared.path, component_id="edge-01", root=tmp_path / "state"
        )


def test_retained_image_rejects_provider_invalid_identity(tmp_path: Path):
    prepared = prepare_sketch_state_workspace(
        "eng-abc123", "proxy01-sea-01", "linode", component_id="middle", template_directory=_template(tmp_path), root=tmp_path / "state"
    )
    prepared.state_path.write_text(
        json.dumps({
            "resources": [{
                "mode": "managed",
                "type": "linode_instance",
                "instances": [{"attributes": {"image": 2204}}],
            }]
        }),
        encoding="utf-8",
    )
    prepared.state_path.chmod(0o600)

    with pytest.raises(SketchStateWorkspaceError, match="no valid image identity"):
        retained_compute_image_for_workspace(
            "eng-abc123", "proxy01-sea-01", "linode", prepared.path, component_id="middle", root=tmp_path / "state"
        )
