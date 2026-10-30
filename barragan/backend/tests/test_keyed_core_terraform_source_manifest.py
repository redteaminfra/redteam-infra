# Copyright (c) 2026, Oracle and/or its affiliates.
"""Exact source authority for a provider-keyed OCI core plan."""

import json

import pytest

from app.domain.deployment_plan import DeploymentPlan
from app.services.core_deployment_plans import (
    CoreDeploymentPlanError,
    KEYED_CORE_TERRAFORM_INPUT_FILES,
    _verify_plan_evidence,
    build_keyed_core_terraform_source_manifest,
    require_keyed_core_terraform_source_manifest,
)


def _inputs(root):
    for name in KEYED_CORE_TERRAFORM_INPUT_FILES:
        (root / name).write_text(f'private-token-for-{name}', encoding="utf-8")


def test_keyed_core_source_manifest_contains_only_exact_hashes(tmp_path):
    _inputs(tmp_path)
    manifest = build_keyed_core_terraform_source_manifest(tmp_path)

    assert manifest["schema"] == "keyed-core-terraform-inputs-v1"
    assert set(manifest["sha256"]) == set(KEYED_CORE_TERRAFORM_INPUT_FILES)
    assert "private-token" not in json.dumps(manifest)
    assert str(tmp_path) not in json.dumps(manifest)
    require_keyed_core_terraform_source_manifest(tmp_path, manifest)

    (tmp_path / "main.tf").write_text("changed", encoding="utf-8")
    with pytest.raises(CoreDeploymentPlanError) as error:
        require_keyed_core_terraform_source_manifest(tmp_path, manifest)
    assert "source inputs changed" in error.value.errors[0]


@pytest.mark.parametrize("extra", [
    "extra.tf", "other.tf.json", "terraform.tfvars", "terraform.tfvars.backup",
    "extra.auto.tfvars", "extra.auto.tfvars.json", "a b.tf", "é.tf",
])
def test_keyed_core_manifest_rejects_extra_loadable_root_file(tmp_path, extra):
    _inputs(tmp_path)
    (tmp_path / extra).write_text("extra", encoding="utf-8")
    with pytest.raises(CoreDeploymentPlanError) as error:
        build_keyed_core_terraform_source_manifest(tmp_path)
    assert "missing or unsafe" in error.value.errors[0]


@pytest.mark.parametrize("name", KEYED_CORE_TERRAFORM_INPUT_FILES)
def test_keyed_core_manifest_rejects_missing_or_nonregular_required_input(tmp_path, name):
    _inputs(tmp_path)
    (tmp_path / name).unlink()
    with pytest.raises(CoreDeploymentPlanError):
        build_keyed_core_terraform_source_manifest(tmp_path)
    (tmp_path / name).symlink_to(tmp_path / "main.tf")
    with pytest.raises(CoreDeploymentPlanError):
        build_keyed_core_terraform_source_manifest(tmp_path)
    (tmp_path / name).unlink()
    (tmp_path / name).mkdir()
    with pytest.raises(CoreDeploymentPlanError):
        build_keyed_core_terraform_source_manifest(tmp_path)


def test_keyed_core_manifest_rejects_symlinked_root(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    _inputs(root)
    link = tmp_path / "link"
    link.symlink_to(root)
    with pytest.raises(CoreDeploymentPlanError):
        build_keyed_core_terraform_source_manifest(link)


@pytest.mark.parametrize("manifest", [None, {}, {"schema": "keyed-core-terraform-inputs-v1", "sha256": {}},
                                      {"schema": "keyed-core-terraform-inputs-v1", "sha256": {"main.tf": "not-a-digest"}}])
def test_keyed_core_manifest_fails_closed_for_unsealed_legacy_evidence(tmp_path, manifest):
    _inputs(tmp_path)
    with pytest.raises(CoreDeploymentPlanError) as error:
        require_keyed_core_terraform_source_manifest(tmp_path, manifest)
    assert "manifest is missing or invalid" in error.value.errors[0]


def test_original_keyed_plan_apply_validation_requires_source_manifest(tmp_path):
    _inputs(tmp_path)
    plan = DeploymentPlan(
        "plan", "engagement", "revision", "ready", "ready",
        evidence={"sketchStateSchema": "provider-keyed-v2", "runDirectory": str(tmp_path)},
    )
    with pytest.raises(CoreDeploymentPlanError) as error:
        _verify_plan_evidence(plan)
    assert "manifest is missing or invalid" in error.value.errors[0]
