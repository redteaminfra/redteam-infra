# Copyright (c) 2026, Oracle and/or its affiliates.
"""Failed/no-apply keyed plan abandonment refuses uncertain local state."""

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

import app.services.provider_keyed_initial_plan_recovery as recovery
from app.domain import JobEvent
from app.storage.job_repository import StoredJobRun


class Jobs:
    def __init__(self, job):
        self.job = job

    def get(self, job_id):
        return self.job if job_id == self.job.id else None

    def list_for_engagement(self, engagement_id):
        return [self.job] if engagement_id == self.job.target_id else []


def _fixture(tmp_path, monkeypatch):
    state_root = tmp_path / "state"
    connection = "central-opaque"
    fingerprint = hashlib.sha256(f"digitalocean\0{connection}".encode()).hexdigest()
    engagement_root = state_root / "eng-opaque"
    schema = engagement_root / recovery.SCHEMA
    root = schema / "digitalocean" / fingerprint
    root.mkdir(parents=True, mode=0o700)
    (root / ".terraform-data").mkdir(mode=0o700)
    (schema / ".plan-material" / "digitalocean" / "ssh-output").mkdir(parents=True, mode=0o700)
    for path in (state_root, engagement_root, schema, root.parent, schema / ".plan-material",
                 schema / ".plan-material" / "digitalocean"):
        path.chmod(0o700)

    def write(path, content=""):
        path.write_text(content)
        path.chmod(0o600)

    marker = {
        "schema": recovery.SCHEMA, "engagement_id": "eng-opaque", "provider": "digitalocean",
        "provider_connection_id": connection, "connection_fingerprint": fingerprint,
        "source_revision": recovery._SOURCE_REVISION, "rendered_files": {"main.tf": "unused"},
    }
    write(root / ".barragan-provider-keyed-state.json", json.dumps(marker))
    write(root / "main.tf", "")
    write(root / ".barragan-topology.json", "{}")
    write(root / ".barragan-initial-full-plan.lock")
    write(schema / ".regional-ordinals.lock")
    write(schema / "regional-ordinals.json", "{}")
    write(schema / ".plan-material" / "digitalocean" / "inputs.json", "{}")
    owner = {
        "schema": recovery.SCHEMA, "engagementId": "eng-opaque", "provider": "digitalocean",
        "providerConnectionId": connection, "coreJobId": "job-core-opaque",
        "planJobId": "job-plan-opaque", "sourceRevision": recovery._SOURCE_REVISION,
    }
    write(root / recovery._OWNER_FILE, json.dumps(owner))
    job = StoredJobRun(
        id="job-plan-opaque", action="provider_keyed_initial_plan", status="failed",
        target="engagement:eng-opaque", target_type="engagement", target_id="eng-opaque",
        requested_by="example_operator_three", input={"engagementId": "eng-opaque", "coreJobId": "job-core-opaque", "mutation": False},
        artifact_refs=[], created_at="2026-10-02T00:00:00Z", started_at="2026-10-02T00:01:00Z",
        finished_at="2026-10-02T00:02:00Z", events=[JobEvent(1, "error", "plan failed", {})],
    )
    monkeypatch.setattr(recovery, "_default_state_root", lambda: state_root)
    monkeypatch.setattr(recovery, "_verify_audited_workspace", lambda workspace: None)
    return state_root, engagement_root, root, Jobs(job)


def _recover(state_root, jobs):
    recovery.abandon_failed_digitalocean_initial_plan(
        "eng-opaque", "job-plan-opaque", lease_owner="job-recovery-opaque",
        environment="devtest", state_root=state_root, job_repository=jobs,
        lease_lookup=lambda _: ("job-recovery-opaque", "provider_keyed_initial"),
    )


def test_failed_plan_workspace_can_be_abandoned_without_deleting_job(tmp_path, monkeypatch):
    state_root, engagement_root, root, jobs = _fixture(tmp_path, monkeypatch)
    _recover(state_root, jobs)
    assert not engagement_root.exists()
    assert jobs.job.status == "failed"


def test_failure_before_plan_lock_can_be_abandoned(tmp_path, monkeypatch):
    state_root, engagement_root, root, jobs = _fixture(tmp_path, monkeypatch)
    (root / ".barragan-initial-full-plan.lock").unlink()
    _recover(state_root, jobs)
    assert not engagement_root.exists()


def test_team_readable_workspace_modes_are_accepted(tmp_path, monkeypatch):
    state_root, engagement_root, root, jobs = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(recovery, "_collaborator_group_gid", lambda: os.getgid())
    schema = engagement_root / recovery.SCHEMA
    for directory in (state_root, engagement_root, schema, root.parent, root):
        directory.chmod(0o2750)
    for path in (root / "main.tf", root / ".barragan-provider-keyed-state.json",
                 root / ".barragan-topology.json", schema / ".regional-ordinals.lock",
                 schema / "regional-ordinals.json"):
        path.chmod(0o640)
    _recover(state_root, jobs)
    assert not engagement_root.exists()


def test_team_readable_workspace_with_wrong_group_is_preserved(tmp_path, monkeypatch):
    state_root, engagement_root, root, jobs = _fixture(tmp_path, monkeypatch)
    state_root.chmod(0o2750)
    monkeypatch.setattr(recovery, "_collaborator_group_gid", lambda: os.getgid() + 1)
    with pytest.raises(recovery.ProviderKeyedPlanRecoveryError, match="outside barragan group"):
        _recover(state_root, jobs)
    assert engagement_root.exists()


def test_private_plan_material_must_not_be_group_readable(tmp_path, monkeypatch):
    state_root, engagement_root, root, jobs = _fixture(tmp_path, monkeypatch)
    key = engagement_root / recovery.SCHEMA / ".plan-material" / "digitalocean" / "admin-private"
    key.write_text("private fixture")
    key.chmod(0o640)
    with pytest.raises(recovery.ProviderKeyedPlanRecoveryError, match="not private"):
        _recover(state_root, jobs)
    assert key.exists()


def test_interrupted_private_key_is_removed_only_for_terminal_failed_job(tmp_path, monkeypatch):
    state_root, engagement_root, root, jobs = _fixture(tmp_path, monkeypatch)
    key = engagement_root / recovery.SCHEMA / ".plan-material" / "digitalocean" / "admin-private"
    key.write_text("secret fixture")
    key.chmod(0o600)
    jobs.job = replace(jobs.job, status="running", finished_at=None)
    with pytest.raises(recovery.ProviderKeyedPlanRecoveryError, match="terminal failed"):
        _recover(state_root, jobs)
    assert key.read_text() == "secret fixture"
    jobs.job = replace(jobs.job, status="failed", finished_at="2026-10-02T00:02:00Z")
    _recover(state_root, jobs)
    assert not engagement_root.exists()


@pytest.mark.parametrize("artifact", ["terraform.tfstate", ".barragan-apply-phase.json", ".barragan-initial-full.tfplan"])
def test_execution_evidence_is_preserved(tmp_path, monkeypatch, artifact):
    state_root, engagement_root, root, jobs = _fixture(tmp_path, monkeypatch)
    (root / artifact).write_text("evidence")
    with pytest.raises(recovery.ProviderKeyedPlanRecoveryError, match="evidence"):
        _recover(state_root, jobs)
    assert (root / artifact).exists()


def test_foreign_artifact_is_preserved(tmp_path, monkeypatch):
    state_root, engagement_root, root, jobs = _fixture(tmp_path, monkeypatch)
    (root / "unknown.txt").write_text("manual")
    with pytest.raises(recovery.ProviderKeyedPlanRecoveryError, match="unrecognized"):
        _recover(state_root, jobs)
    assert engagement_root.exists()


def test_owned_executable_provider_cache_is_discarded(tmp_path, monkeypatch):
    state_root, engagement_root, root, jobs = _fixture(tmp_path, monkeypatch)
    provider = (root / ".terraform-data" / "providers" / "registry.terraform.io"
                / "digitalocean" / "digitalocean" / "2.103.0" / "linux_amd64")
    provider.mkdir(parents=True)
    binary = provider / "terraform-provider-digitalocean_v2.103.0"
    binary.write_text("fixture")
    binary.chmod(0o755)
    for name in ("README.md", "CHANGELOG.md", "LICENSE"):
        package_file = provider / name
        package_file.write_text("fixture")
        package_file.chmod(0o644)
    local = (root / ".terraform-data" / "providers" / "registry.terraform.io"
             / "hashicorp" / "local" / "2.9.1" / "linux_amd64")
    local.mkdir(parents=True)
    for directory in (root / ".terraform-data").rglob("*"):
        if directory.is_dir():
            directory.chmod(0o700)
    local_binary = local / "terraform-provider-local_v2.9.1_x5"
    local_binary.write_text("fixture")
    local_binary.chmod(0o755)
    license_file = local / "LICENSE.txt"
    license_file.write_text("fixture")
    license_file.chmod(0o644)
    _recover(state_root, jobs)
    assert not engagement_root.exists()


def test_unknown_provider_cache_file_is_preserved(tmp_path, monkeypatch):
    state_root, engagement_root, root, jobs = _fixture(tmp_path, monkeypatch)
    cache = root / ".terraform-data"
    (cache / "surprise").write_text("manual")
    with pytest.raises(recovery.ProviderKeyedPlanRecoveryError, match="unrecognized"):
        _recover(state_root, jobs)
    assert engagement_root.exists()


def test_symlinked_key_is_preserved(tmp_path, monkeypatch):
    state_root, engagement_root, root, jobs = _fixture(tmp_path, monkeypatch)
    key = engagement_root / recovery.SCHEMA / ".plan-material" / "digitalocean" / "admin-private"
    key.symlink_to(tmp_path / "outside")
    with pytest.raises(recovery.ProviderKeyedPlanRecoveryError, match="symlinked"):
        _recover(state_root, jobs)
    assert key.is_symlink()


def test_wrong_owner_marker_is_preserved(tmp_path, monkeypatch):
    state_root, engagement_root, root, jobs = _fixture(tmp_path, monkeypatch)
    path = root / recovery._OWNER_FILE
    marker = json.loads(path.read_text())
    marker["planJobId"] = "other-job"
    path.write_text(json.dumps(marker))
    with pytest.raises(recovery.ProviderKeyedPlanRecoveryError, match="ownership differs"):
        _recover(state_root, jobs)
    assert engagement_root.exists()
