# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import subprocess

import pytest
import yaml

from app.services import inference_proxy_capability as inference
from app.services.capability_execution import CapabilityRoleApplyPlan, copy_core_capability_roles, render_core_capability_apply_playbook
from app.services.engagement_capabilities import (
    EngagementCapabilityValidationError,
    _preparing_apply_state,
    _rendered_input_fingerprint,
    update_engagement_capability_selection,
)
from app.services.redteam_infra_template import RedteamInfraTemplateSource
from app.storage.engagement_workspace_repository import StoredEngagementWorkspace

CONFIG = {"region": "us-chicago-1", "compartmentId": "ocid1.compartment.oc1..exampled56cc1888fe73e064037bb7f", "port": 8787}


@pytest.fixture
def source(tmp_path, monkeypatch):
    root = tmp_path / "application"
    root.mkdir()
    def git(*args):
        return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
    git("init")
    git("config", "user.name", "Test")
    git("config", "user.email", "test@example.invalid")
    (root / "pyproject.toml").write_text('[project]\nname = "test-inference"\nversion = "0.0.0"\n')
    git("add", "pyproject.toml")
    git("commit", "-m", "Fixture source")
    revision = git("rev-parse", "HEAD")
    monkeypatch.setattr(inference, "SOURCE_REVISION", revision)
    monkeypatch.setenv(inference.SOURCE_ROOT_ENV, str(root))
    return root, revision


@pytest.mark.parametrize("configuration", [
    {**CONFIG, "port": True}, {**CONFIG, "port": "8787"}, {**CONFIG, "port": 1023},
    {**CONFIG, "port": 65536}, {**CONFIG, "region": "us-chicago-1\n[server]"},
    {**CONFIG, "compartmentId": "ocid1.tenancy.oc1..wrongkind"}, {**CONFIG, "apiToken": "must-not-be-accepted"},
    {**CONFIG, "compartmentId": "ocid1.compartment.x"},
    {**CONFIG, "compartmentId": "ocid1.compartment..suffix"},
    {**CONFIG, "compartmentId": "ocid1.compartment.oc1."},
    {**CONFIG, "region": "a" * 64},
    {**CONFIG, "region": "a"},
])
def test_rejects_unsafe_or_unrecognized_configuration(configuration):
    with pytest.raises(inference.InferenceProxyConfigurationError):
        inference.normalize_configuration(configuration, required=True)


def test_configuration_defaults_and_required_selection():
    assert inference.normalize_configuration(None) == {"region": "", "compartmentId": "", "port": 8787}
    with pytest.raises(inference.InferenceProxyConfigurationError, match="before selecting"):
        inference.normalize_configuration(None, required=True)
    assert inference.normalize_configuration(CONFIG, required=True) == CONFIG
    state = inference.public_state({inference.CONFIGURATION_KEY: CONFIG})
    assert state["configuration"] == CONFIG
    assert state["accessStatus"] == "not_verified"
    assert "does not modify IAM" in state["policyGuidance"]["notes"][0]


def test_archive_is_pinned_committed_source_without_scm_credentials(source, tmp_path):
    root, revision = source
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    archive = inference.source_archive()
    artifact = inference.prepare_source(workspace, archive)
    assert artifact["revision"] == revision
    assert artifact["sha256"] == hashlib.sha256(archive).hexdigest()
    import io
    import tarfile
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        assert tar.getnames() == ["pyproject.toml"]
        assert tar.pax_headers["comment"] == revision
    assert inference.prepare_source(workspace, inference.source_archive()) == artifact
    (root / "untracked-secret").write_text("not copied")
    with pytest.raises(inference.InferenceProxyConfigurationError, match="clean"):
        inference.source_archive()
    # The already prepared immutable archive remains usable without re-cloning
    # source or retaining credentials in the execution workspace.
    metadata = {inference.CONFIGURATION_KEY: CONFIG, inference.SOURCE_KEY: artifact}
    assert inference.execution_inputs(workspace, metadata)["source"] == artifact


def test_source_missing_wrong_revision_and_tampered_archive_fail_closed(source, tmp_path, monkeypatch):
    _, revision = source
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    prepared = inference.prepare_source(workspace, inference.source_archive())
    metadata = {inference.CONFIGURATION_KEY: CONFIG, inference.SOURCE_KEY: prepared}
    target = workspace / prepared["relativePath"]
    target.write_bytes(b"tampered")
    with pytest.raises(inference.InferenceProxyConfigurationError, match="missing or changed"):
        inference.execution_inputs(workspace, metadata)
    monkeypatch.setattr(inference, "SOURCE_REVISION", "0" * 40)
    with pytest.raises(inference.InferenceProxyConfigurationError, match="pinned"):
        inference.source_archive()
    monkeypatch.delenv(inference.SOURCE_ROOT_ENV)
    with pytest.raises(inference.InferenceProxyConfigurationError, match=inference.SOURCE_ROOT_ENV):
        inference.source_archive()


def test_artifact_symlinks_are_rejected(source, tmp_path):
    workspace = tmp_path / "workspace"
    elsewhere = tmp_path / "elsewhere"
    workspace.mkdir()
    elsewhere.mkdir()
    (workspace / "barragan").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(inference.InferenceProxyConfigurationError, match="symlinks"):
        inference.prepare_source(workspace, inference.source_archive())
    assert list(elsewhere.iterdir()) == []


def test_role_vars_and_archive_survive_execution_workspace_copy(source, tmp_path):
    workspace = tmp_path / "workspace"
    role = workspace / "ansible/roles/inference_proxy/tasks"
    role.mkdir(parents=True)
    (role / "main.yml").write_text("---\n[]\n")
    artifact = inference.prepare_source(workspace, inference.source_archive())
    inputs = inference.execution_inputs(workspace, {inference.CONFIGURATION_KEY: CONFIG, inference.SOURCE_KEY: artifact})
    plan = CapabilityRoleApplyPlan(
        source=RedteamInfraTemplateSource(workspace, "engagement-workspace"),
        roles_by_host_class={"homebase": [{"id": inference.CAPABILITY_ID, "role": "inference_proxy"}]},
        selected_count=1, executable_count=1, skipped=[], warnings=[], errors=[], inference_proxy_inputs=inputs,
    )
    playbook = yaml.safe_load(render_core_capability_apply_playbook(plan))
    task = next(task for task in playbook[1]["tasks"] if task.get("ansible.builtin.include_role"))
    assert task["vars"] == inference.role_variables(inputs)
    assert task["vars"]["inference_proxy_source_archive"].startswith("{{ playbook_dir }}/../barragan/artifacts/")
    assert task["vars"]["inference_proxy_port"] == 8787
    destination = tmp_path / "execution"
    copy_core_capability_roles(destination, plan)
    assert (destination / artifact["relativePath"]).read_bytes() == (workspace / artifact["relativePath"]).read_bytes()
    assert (destination / "ansible/roles/inference_proxy/tasks/main.yml").exists()
    (workspace / artifact["relativePath"]).write_bytes(b"changed after plan")
    with pytest.raises(inference.InferenceProxyConfigurationError):
        copy_core_capability_roles(tmp_path / "another-execution", plan)


def test_configuration_and_source_change_both_fingerprints(source, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = inference.prepare_source(workspace, inference.source_archive())
    record = StoredEngagementWorkspace("eng-test", "test", str(workspace), "ready", "standard-rti", {},
        {inference.CONFIGURATION_KEY: CONFIG, inference.SOURCE_KEY: artifact})
    selected = {"selectedOptionals": [{"id": inference.CAPABILITY_ID, "hostClass": "homebase"}], "deselectedDefaults": []}
    resolution = {"hostClasses": {}, "selection": {}}
    before = _preparing_apply_state(record, resolution, selected)["selectionFingerprint"]
    changed = replace(record, metadata={**record.metadata, inference.CONFIGURATION_KEY: {**CONFIG, "port": 8788}})
    assert _preparing_apply_state(changed, resolution, selected)["selectionFingerprint"] != before
    inputs = inference.execution_inputs(workspace, record.metadata)
    lock = {"inferenceProxy": inputs}
    changed_lock = {"inferenceProxy": {**inputs, "source": {**artifact, "sha256": "0" * 64}}}
    assert _rendered_input_fingerprint(lock) != _rendered_input_fingerprint(changed_lock)


def test_invalid_input_fails_before_preparing_or_saving_workspace(monkeypatch, tmp_path):
    class Repository:
        def get(self, _id): return None
        def save(self, _record): raise AssertionError("no save")
    monkeypatch.setattr("app.services.engagement_capabilities.prepare_engagement_workspace", lambda *args, **kwargs: pytest.fail("must not prepare"))
    body = {"selectedOptionals": [{"id": inference.CAPABILITY_ID, "hostClass": "homebase"}], "inferenceProxy": CONFIG}
    monkeypatch.delenv(inference.SOURCE_ROOT_ENV, raising=False)
    with pytest.raises(EngagementCapabilityValidationError, match="validation failed") as exc:
        update_engagement_capability_selection("eng-test", body, root=tmp_path, repository=Repository())
    assert inference.SOURCE_ROOT_ENV in exc.value.errors[0]


def test_reconciliation_rejects_changed_configuration_before_writing_runtime(tmp_path):
    from app.services.capability_reconciliation import _write_reconciliation_workspace, CapabilityReconciliationValidationError
    inputs = {"configuration": CONFIG, "source": {"revision": "a" * 40, "sha256": "b" * 64, "relativePath": "ignored"}}
    plan = CapabilityRoleApplyPlan(RedteamInfraTemplateSource(tmp_path, "test"), {"homebase": [{"id": "inference-proxy", "role": "inference_proxy"}]}, 1, 1, [], [], [], inputs)
    destination = tmp_path / "execution"
    with pytest.raises(CapabilityReconciliationValidationError):
        _write_reconciliation_workspace(destination, plan, (), "deployment-test", capability_lock=yaml.safe_dump({"inferenceProxy": {**inputs, "configuration": {**CONFIG, "port": 8788}}}))
    assert not destination.exists()


@pytest.mark.parametrize("port", [True, "8787", 1023, 65536])
def test_deselected_configuration_still_validates_port(port):
    with pytest.raises(inference.InferenceProxyConfigurationError, match="loopback port"):
        inference.normalize_configuration({"port": port}, required=False)


def test_configuration_accepts_role_region_and_port_boundaries():
    for port in (1024, 65535):
        assert inference.normalize_configuration({**CONFIG, "region": "a" * 63, "port": port}, required=True)["port"] == port
