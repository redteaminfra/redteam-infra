# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from app.domain import JobEvent
from app.services.opsec_network_restrictions import (
    OPSEC_MANAGED_COMMENT,
    OpsecCoreHost,
    OpsecNetworkRestrictionsValidationError,
    OpsecRestrictionsSpec,
    apply_opsec_network_restrictions,
    render_opsec_apply_workspace,
)
from app.storage.job_repository import StoredJobRun
from app.storage.service_repository import StoredEngagementService


def test_renders_homebase_only_opsec_workspace_with_expected_cidrs() -> None:
    workspace = render_opsec_apply_workspace(
        spec=OpsecRestrictionsSpec(enabled=True, destinations=("10.10.0.0/16", "203.0.113.7")),
        homebase=OpsecCoreHost("homebase", "203.0.113.10", "ubuntu", "/keys/core", "/tmp/known_hosts"),
    )

    assert "[selected_homebase]" in workspace.inventory.content
    assert "homebase ansible_host=203.0.113.10 ansible_user=ubuntu" in workspace.inventory.content
    assert "[selected_proxy]" not in workspace.inventory.content
    assert "middle-" not in workspace.inventory.content
    assert "edge-" not in workspace.inventory.content

    assert "hosts: selected_homebase" in workspace.playbook.content
    assert 'cidrs: ["10.10.0.0/16", "203.0.113.7"]' in workspace.playbook.content
    assert "Add Barragan-managed OPSEC outbound blocks" in workspace.playbook.content
    assert f"barragan_opsec_comment: {OPSEC_MANAGED_COMMENT!r}".replace("'", '"') in workspace.playbook.content
    assert '"proxyTargets": []' in workspace.manifest.content
    assert '"sketchMiddleTargets": []' in workspace.manifest.content
    assert '"sketchEdgeTargets": []' in workspace.manifest.content


def test_opsec_apply_rejects_invalid_destinations_before_job_creation(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("app.services.opsec_network_restrictions.get_engagement", lambda engagement_id: object())
    jobs = _FakeJobRepository(_core_jobs())
    services = _FakeServiceRepository()

    with pytest.raises(OpsecNetworkRestrictionsValidationError) as exc:
        apply_opsec_network_restrictions(
            "eng-zy01",
            {"enabled": True, "destinations": ["10.10.0.0/24", "not a cidr"]},
            job_repository=jobs,
            service_repository=services,
            runner=_successful_runner,
            env={"ANSIBLE_PLAYBOOK_BIN": str(_executable(tmp_path, "ansible-playbook"))},
            workspace_root=tmp_path,
        )

    assert "destinations[1] must be an IPv4/IPv6 address or CIDR" in exc.value.errors
    assert [job.id for job in jobs.jobs] == ["job-core"]
    assert services.services == {}


def test_opsec_apply_targets_homebase_and_persists_active_service(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("app.services.opsec_network_restrictions.get_engagement", lambda engagement_id: object())
    jobs = _FakeJobRepository(_core_jobs())
    services = _FakeServiceRepository()

    result = apply_opsec_network_restrictions(
        "eng-zy01",
        {"enabled": True, "destinations": ["10.10.0.1", "10.10.0.0/24", "10.10.0.0/24"], "notes": "client ranges"},
        job_repository=jobs,
        service_repository=services,
        runner=_successful_runner,
        env={"ANSIBLE_PLAYBOOK_BIN": str(_executable(tmp_path, "ansible-playbook"))},
        workspace_root=tmp_path,
    )

    assert result is not None
    assert result["status"] == "Active"
    assert result["configuration"]["destinations"] == ["10.10.0.1", "10.10.0.0/24"]
    job = jobs.jobs[-1]
    assert job.action == "opsec_network_restrictions_apply"
    assert job.input["cidrs"] == ["10.10.0.1", "10.10.0.0/24"]
    workspace = job.events[0].data["workspaceEvidence"]
    assert "selected_homebase" in workspace["inventory"]["content"]
    assert "selected_proxy" not in workspace["inventory"]["content"]
    assert 'cidrs: ["10.10.0.1", "10.10.0.0/24"]' in workspace["playbook"]["content"]


def test_opsec_disable_removes_only_barragan_managed_rules(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("app.services.opsec_network_restrictions.get_engagement", lambda engagement_id: object())
    jobs = _FakeJobRepository(_core_jobs())
    services = _FakeServiceRepository()
    services.save(
        StoredEngagementService(
            engagement_id="eng-zy01",
            service_id="opsec-network-restrictions",
            service_type="opsec-network-restrictions",
            name="OPSEC Network Restrictions",
            proxy_id="homebase",
            status="Active",
            config={"enabled": True, "destinations": ["10.10.0.0/24", "203.0.113.7"], "notes": "", "purpose": ""},
        )
    )

    result = apply_opsec_network_restrictions(
        "eng-zy01",
        {"enabled": False, "destinations": []},
        job_repository=jobs,
        service_repository=services,
        runner=_successful_runner,
        env={"ANSIBLE_PLAYBOOK_BIN": str(_executable(tmp_path, "ansible-playbook"))},
        workspace_root=tmp_path,
    )

    assert result is not None
    assert result["status"] == "Disabled"
    playbook = jobs.jobs[-1].events[0].data["workspaceEvidence"]["playbook"]["content"]
    assert 'barragan_opsec_remove_cidrs: ["10.10.0.0/24", "203.0.113.7"]' in playbook
    assert "state: absent" in playbook
    assert f'comment: "{{{{ barragan_opsec_comment }}}}"' in playbook
    assert OPSEC_MANAGED_COMMENT in playbook


def _core_jobs() -> list[StoredJobRun]:
    return [
        StoredJobRun(
            id="job-core",
            action="pilot_standard_rti_guarded_execute",
            status="succeeded",
            target="oci-compartment:barragan-testing",
            target_type="oci_compartment",
            target_id="ocid1.compartment.oc1..testing",
            requested_by="operator",
            input={"engagementId": "eng-zy01"},
            artifact_refs=[],
            created_at="2026-06-04T12:00:00+00:00",
            started_at="2026-06-04T12:01:00+00:00",
            finished_at="2026-06-04T12:05:00+00:00",
            events=[
                JobEvent(
                    1,
                    "info",
                    "operator inspection ready",
                    {
                        "connectionDetails": [
                            {
                                "role": "homebase",
                                "displayName": "homebase-zy01",
                                "publicIp": "203.0.113.10",
                                "privateIp": "192.168.0.10",
                                "sshUser": "ubuntu",
                            }
                        ]
                    },
                )
            ],
        )
    ]


def _successful_runner(command: list[str], cwd: Path | None) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")


def _executable(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


class _FakeJobRepository:
    def __init__(self, jobs: list[StoredJobRun]):
        self.jobs = list(jobs)

    def list(self) -> list[StoredJobRun]:
        return list(self.jobs)

    def list_for_engagement(self, engagement_id: str, *, limit: int | None = None) -> list[StoredJobRun]:
        return [job for job in self.jobs if job.input.get("engagementId") == engagement_id]

    def list_summaries(self, *, limit: int, offset: int):
        return [], 0

    def count(self) -> int:
        return len(self.jobs)

    def get(self, job_id: str) -> StoredJobRun | None:
        return next((job for job in self.jobs if job.id == job_id), None)

    def save(self, job: StoredJobRun) -> StoredJobRun:
        self.jobs = [existing for existing in self.jobs if existing.id != job.id]
        self.jobs.append(job)
        return job


class _FakeServiceRepository:
    def __init__(self) -> None:
        self.services: dict[tuple[str, str], StoredEngagementService] = {}

    def list_for_engagement(self, engagement_id: str) -> list[StoredEngagementService]:
        return [service for (stored_engagement_id, _), service in self.services.items() if stored_engagement_id == engagement_id]

    def list_for_engagement_and_proxy(self, engagement_id: str, proxy_id: str) -> list[StoredEngagementService]:
        return [service for service in self.list_for_engagement(engagement_id) if service.proxy_id == proxy_id]

    def get(self, engagement_id: str, service_id: str) -> StoredEngagementService | None:
        return self.services.get((engagement_id, service_id))

    def save(self, service: StoredEngagementService) -> StoredEngagementService:
        self.services[(service.engagement_id, service.service_id)] = service
        return service
