# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import subprocess

import pytest

from app.domain import JobEvent
from app.services.capability_reconciliation import (
    CAPABILITY_RECONCILIATION_ACTION,
    CapabilityReconciliationValidationError,
    assert_capability_reconciliation_idle,
    get_capability_reconciliation,
    recover_interrupted_capability_reconciliations,
    start_capability_reconciliation,
)
from app.services.engagement_capabilities import update_engagement_capability_selection
from app.services.engagement_workspaces import prepare_engagement_workspace
from app.services.redteam_infra_template import RedteamInfraTemplateSource
from app.storage.engagement_workspace_repository import StoredEngagementWorkspace
from app.storage.job_repository import StoredJobRun


ENGAGEMENT_ID = "eng-abc123"


def test_active_core_reconciliation_applies_only_selected_optional_role(tmp_path: Path, monkeypatch) -> None:
    workspace_repo = _selected_gofs_workspace(tmp_path, monkeypatch)
    jobs = _FakeJobRepository([_core_job()])
    leases = _FakeLeaseRepository()
    command_calls: list[tuple[list[str], Path]] = []

    def runner(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
        command_calls.append((command, cwd))
        return subprocess.CompletedProcess(command, 0, stdout="token=must-not-be-persisted", stderr="")

    result = start_capability_reconciliation(
        ENGAGEMENT_ID,
        engagement_repos_root=tmp_path / "engagements",
        repository=jobs,
        workspace_repository=workspace_repo,
        service_repository=_FakeServiceRepository(),
        lease_repository=leases,
        runner=runner,
        background_runner=lambda task: task(),
        workspace_root=tmp_path / "runs",
        env={"ANSIBLE_PLAYBOOK_BIN": "/usr/bin/true", "PATH": "/usr/bin"},
    )

    assert result is not None
    assert result["status"] == "succeeded"
    job = jobs.get(result["job"]["id"])
    assert job is not None and job.status == "succeeded"
    assert job.input["execution"] == {"terraform": False, "ansible": True, "providerMutation": False}
    assert job.input["selectedRoles"]["homebase"] == [{"id": "go-simple-upload-server", "role": "go_simple_upload_server"}]
    assert not any("token=must-not-be-persisted" in str(event.data) for event in job.events)
    assert command_calls and command_calls[0][0][0] == "/usr/bin/true"
    assert all("terraform" not in argument for argument in command_calls[0][0])
    run_dir = command_calls[0][1]
    playbook = (run_dir / "ansible" / "apply_optional_capabilities.yml").read_text(encoding="utf-8")
    assert "Apply capability go-simple-upload-server" in playbook
    assert "Apply capability homebase" not in playbook
    assert "Apply capability common" not in playbook
    assert (run_dir / "ansible" / "roles" / "go_simple_upload_server" / "tasks" / "main.yml").is_file()
    assert (run_dir / "barragan" / "capability-lock.yml").is_file()
    assert len(job.input["capabilityLockSha256"]) == 64
    assert leases.acquired == [(ENGAGEMENT_ID, job.id, "capability_reconciliation")]
    assert leases.released == [(ENGAGEMENT_ID, job.id)]


def test_reconciliation_imports_selected_role_missing_from_old_retained_workspace(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace_repo = _old_selected_gofs_workspace(tmp_path, monkeypatch)
    current_source = _committed_gofs_source(tmp_path)
    jobs = _FakeJobRepository([_core_job()])

    result = start_capability_reconciliation(
        ENGAGEMENT_ID,
        engagement_repos_root=tmp_path / "engagements",
        repository=jobs,
        workspace_repository=workspace_repo,
        service_repository=_FakeServiceRepository(),
        lease_repository=_FakeLeaseRepository(),
        runner=lambda command, cwd: subprocess.CompletedProcess(command, 0, stdout="ok", stderr=""),
        background_runner=lambda task: task(),
        workspace_root=tmp_path / "runs",
        env={"ANSIBLE_PLAYBOOK_BIN": "/usr/bin/true", "PATH": "/usr/bin"},
        template_source=RedteamInfraTemplateSource(current_source, "configured-test"),
    )

    assert result is not None and result["status"] == "succeeded"
    retained_role = Path(workspace_repo.workspace.path) / "ansible/roles/go_simple_upload_server/tasks/main.yml"
    assert retained_role.is_file()
    assert result["plan"]["rolesByHostClass"]["homebase"] == [
        {"id": "go-simple-upload-server", "role": "go_simple_upload_server"}
    ]
    imports = workspace_repo.workspace.metadata["capabilityRoleImports"]
    assert imports[0]["source"]["commit"]
    assert imports[0]["source"]["tree"]


def test_reconciliation_requires_retained_workspace_and_active_core(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("app.services.capability_reconciliation.get_engagement", lambda _id: _engagement())
    monkeypatch.setattr("app.services.capability_execution.get_engagement", lambda _id: _engagement())
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: _engagement())
    with pytest.raises(Exception) as missing_workspace:
        start_capability_reconciliation(
            ENGAGEMENT_ID,
            engagement_repos_root=tmp_path / "missing",
            repository=_FakeJobRepository([_core_job()]),
            workspace_repository=_FakeWorkspaceRepository(),
            background_runner=lambda task: task(),
        )
    assert "workspace must be prepared" in getattr(missing_workspace.value, "errors", [""])[0]

    workspace_repo = _selected_gofs_workspace(tmp_path, monkeypatch)
    with pytest.raises(CapabilityReconciliationValidationError) as missing_core:
        start_capability_reconciliation(
            ENGAGEMENT_ID,
            engagement_repos_root=tmp_path / "engagements",
            repository=_FakeJobRepository([]),
            workspace_repository=workspace_repo,
            service_repository=_FakeServiceRepository(),
            background_runner=lambda task: task(),
        )
    assert "active core infrastructure inventory is required" in missing_core.value.errors[0]


def test_reconciliation_serializes_against_core_host_mutations(tmp_path: Path, monkeypatch) -> None:
    workspace_repo = _selected_gofs_workspace(tmp_path, monkeypatch)
    active_team_job = replace(
        _core_job(),
        id="job-team",
        action="engagement_access_apply",
        status="running",
        events=[],
    )
    with pytest.raises(CapabilityReconciliationValidationError) as exc:
        start_capability_reconciliation(
            ENGAGEMENT_ID,
            engagement_repos_root=tmp_path / "engagements",
            repository=_FakeJobRepository([active_team_job, _core_job()]),
            workspace_repository=workspace_repo,
            service_repository=_FakeServiceRepository(),
        )
    assert "engagement_access_apply" in exc.value.errors[0]


def test_scheduler_failure_is_persisted_as_retry_required(tmp_path: Path, monkeypatch) -> None:
    workspace_repo = _selected_gofs_workspace(tmp_path, monkeypatch)
    jobs = _FakeJobRepository([_core_job()])
    leases = _FakeLeaseRepository()

    def fail_to_schedule(_task) -> None:
        raise RuntimeError("scheduler unavailable token=do-not-store")

    result = start_capability_reconciliation(
        ENGAGEMENT_ID,
        engagement_repos_root=tmp_path / "engagements",
        repository=jobs,
        workspace_repository=workspace_repo,
        service_repository=_FakeServiceRepository(),
        lease_repository=leases,
        background_runner=fail_to_schedule,
        workspace_root=tmp_path / "runs",
        env={"ANSIBLE_PLAYBOOK_BIN": "/usr/bin/true", "PATH": "/usr/bin"},
    )

    assert result is not None and result["status"] == "retry_required"
    job = jobs.get(result["job"]["id"])
    assert job is not None and job.status == "failed" and job.input["retryRequired"] is True
    assert "do-not-store" not in str(job.to_detail().to_dict())
    assert leases.released == [(ENGAGEMENT_ID, job.id)]


def test_failed_ansible_result_persists_only_a_redacted_actionable_excerpt(tmp_path: Path, monkeypatch) -> None:
    workspace_repo = _selected_gofs_workspace(tmp_path, monkeypatch)
    jobs = _FakeJobRepository([_core_job()])

    def runner(command: list[str], _cwd: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command,
            2,
            stdout="""TASK [Apply capability go-simple-upload-server] ***
fatal: [homebase]: FAILED! => {\"msg\": \"Go compiler unavailable\", \"token\": \"do-not-store\"}
PLAY RECAP ***
""",
            stderr="routine warning that should not displace the failed task",
        )

    result = start_capability_reconciliation(
        ENGAGEMENT_ID,
        engagement_repos_root=tmp_path / "engagements",
        repository=jobs,
        workspace_repository=workspace_repo,
        service_repository=_FakeServiceRepository(),
        lease_repository=_FakeLeaseRepository(),
        runner=runner,
        background_runner=lambda task: task(),
        workspace_root=tmp_path / "runs",
        env={"ANSIBLE_PLAYBOOK_BIN": "/usr/bin/false", "PATH": "/usr/bin"},
    )

    assert result is not None and result["status"] == "retry_required"
    event = jobs.get(result["job"]["id"]).events[-1]
    assert "TASK [Apply capability go-simple-upload-server]" in event.data["error"]
    assert "Go compiler unavailable" in event.data["error"]
    assert "do-not-store" not in event.data["error"]
    assert "routine warning" not in event.data["error"]


def test_external_secret_markers_never_reach_repository_save(tmp_path: Path, monkeypatch) -> None:
    workspace_repo = _selected_gofs_workspace(tmp_path, monkeypatch)
    jobs = _FakeJobRepository([_core_job()])

    def runner(command: list[str], _cwd: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command,
            2,
            stdout="""TASK [Unsafe failure] ***
fatal: [homebase]: FAILED! => {"password": "correct horse battery staple", "secret": 'multi word value', "authorization": "Bearer quoted auth value"} LINODE_TOKEN unquoted-value go_simple_upload_server_token=another-value -----BEGIN EC PRIVATE KEY----- private-material-without-an-end-marker
""",
            stderr="",
        )

    result = start_capability_reconciliation(
        ENGAGEMENT_ID,
        engagement_repos_root=tmp_path / "engagements",
        repository=jobs,
        workspace_repository=workspace_repo,
        service_repository=_FakeServiceRepository(),
        lease_repository=_FakeLeaseRepository(),
        runner=runner,
        background_runner=lambda task: task(),
        workspace_root=tmp_path / "runs",
        env={"ANSIBLE_PLAYBOOK_BIN": "/usr/bin/false", "PATH": "/usr/bin"},
    )

    assert result is not None and result["status"] == "retry_required"
    encoded_saves = " ".join(str(job.to_detail().to_dict()) for job in jobs.saved)
    assert "unquoted-value" not in encoded_saves
    assert "another-value" not in encoded_saves
    assert "private-material" not in encoded_saves
    assert "correct horse battery staple" not in encoded_saves
    assert "multi word value" not in encoded_saves
    assert "quoted auth value" not in encoded_saves
    assert "LINODE_TOKEN" not in encoded_saves
    assert "go_simple_upload_server_token" not in encoded_saves


def test_ansible_failure_excerpt_is_bounded_and_keeps_latest_unreachable_task() -> None:
    from app.services.capability_reconciliation import _ansible_failure_excerpt

    result = subprocess.CompletedProcess(
        ["ansible-playbook"],
        4,
        stdout="TASK [Wait for latest hop] ***\nedge: UNREACHABLE! => " + ("network-settling " * 200),
        stderr="",
    )

    excerpt = _ansible_failure_excerpt(result)
    assert len(excerpt) <= 1_012
    assert "TASK [Wait for latest hop]" in excerpt
    assert "UNREACHABLE!" in excerpt


def test_restart_recovery_marks_orphaned_job_retry_required() -> None:
    orphan = StoredJobRun(
        id="job-orphan",
        action=CAPABILITY_RECONCILIATION_ACTION,
        status="running",
        target=f"engagement:{ENGAGEMENT_ID}",
        target_type="engagement",
        target_id=ENGAGEMENT_ID,
        requested_by="operator",
        input={"engagementId": ENGAGEMENT_ID, "retryRequired": False},
        artifact_refs=["ansible/inventory.ini"],
        created_at="2026-08-19T00:00:00+00:00",
        started_at="2026-08-19T00:00:01+00:00",
        finished_at=None,
        events=[JobEvent(1, "info", "started", {})],
    )
    jobs = _FakeJobRepository([orphan])
    leases = _FakeLeaseRepository()

    assert recover_interrupted_capability_reconciliations(repository=jobs, lease_repository=leases) == 1
    recovered = jobs.get(orphan.id)
    assert recovered is not None and recovered.status == "failed"
    assert recovered.input["retryRequired"] is True
    assert "application restart" in recovered.events[-1].message
    assert leases.released == [(ENGAGEMENT_ID, orphan.id)]


def test_active_reconciliation_fences_other_core_host_mutations() -> None:
    active = StoredJobRun(
        id="job-active-reconcile",
        action=CAPABILITY_RECONCILIATION_ACTION,
        status="running",
        target=f"engagement:{ENGAGEMENT_ID}",
        target_type="engagement",
        target_id=ENGAGEMENT_ID,
        requested_by="operator",
        input={"engagementId": ENGAGEMENT_ID},
        artifact_refs=[],
        created_at="2026-08-19T00:00:00+00:00",
        started_at="2026-08-19T00:00:00+00:00",
        finished_at=None,
        events=[],
    )

    with pytest.raises(CapabilityReconciliationValidationError) as exc:
        assert_capability_reconciliation_idle(
            ENGAGEMENT_ID,
            repository=_FakeJobRepository([active]),
        )

    assert active.id in exc.value.errors[0]


def test_get_reconciliation_projects_retry_required_latest_job(tmp_path: Path, monkeypatch) -> None:
    workspace_repo = _selected_gofs_workspace(tmp_path, monkeypatch)
    jobs = _FakeJobRepository([_core_job()])
    result = start_capability_reconciliation(
        ENGAGEMENT_ID,
        engagement_repos_root=tmp_path / "engagements",
        repository=jobs,
        workspace_repository=workspace_repo,
        service_repository=_FakeServiceRepository(),
        background_runner=lambda _task: (_ for _ in ()).throw(RuntimeError("not started")),
        workspace_root=tmp_path / "runs",
        env={"ANSIBLE_PLAYBOOK_BIN": "/usr/bin/true", "PATH": "/usr/bin"},
    )
    assert result is not None

    projected = get_capability_reconciliation(
        ENGAGEMENT_ID,
        engagement_repos_root=tmp_path / "engagements",
        repository=jobs,
        workspace_repository=workspace_repo,
    )
    assert projected is not None
    assert projected["status"] == "retry_required"
    assert projected["plan"]["rolesByHostClass"]["homebase"] == [
        {"id": "go-simple-upload-server", "role": "go_simple_upload_server"}
    ]


def test_fastapi_reconciliation_routes_wrap_service_payload(client, monkeypatch) -> None:
    payload = {"status": "ready", "plan": {"roleCount": 1}, "job": None}
    monkeypatch.setattr("app.asgi.get_capability_reconciliation", lambda *_args, **_kwargs: payload)
    monkeypatch.setattr("app.asgi.start_capability_reconciliation", lambda *_args, **_kwargs: payload)

    shown = client.get(f"/api/engagements/{ENGAGEMENT_ID}/capabilities/reconciliation")
    started = client.post(
        f"/api/engagements/{ENGAGEMENT_ID}/capabilities/reconciliation",
        json={"requestedBy": "example_operator_three"},
    )

    assert shown.status_code == 200
    assert shown.get_json() == {"reconciliation": payload}
    assert started.status_code == 202
    assert started.get_json() == {"reconciliation": payload}


def _selected_gofs_workspace(tmp_path: Path, monkeypatch) -> "_FakeWorkspaceRepository":
    engagement = _engagement()
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.engagement_capabilities.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.capability_execution.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.capability_reconciliation.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.capability_lock_rendering.get_engagement", lambda _id: engagement)
    source = tmp_path / "redteam-infra"
    (source / "external").mkdir(parents=True)
    (source / "ansible").mkdir(parents=True)
    (source / "ansible" / "site.yml").write_text("---\n", encoding="utf-8")
    role_tasks = source / "ansible" / "roles" / "go_simple_upload_server" / "tasks"
    role_tasks.mkdir(parents=True)
    (role_tasks / "main.yml").write_text("---\n- debug:\n    msg: go-simple-upload-server\n", encoding="utf-8")
    repo = _FakeWorkspaceRepository()
    prepared = prepare_engagement_workspace(
        ENGAGEMENT_ID,
        root=tmp_path / "engagements",
        repository=repo,
        source=RedteamInfraTemplateSource(source, "stock"),
    )
    assert prepared is not None
    selected = update_engagement_capability_selection(
        ENGAGEMENT_ID,
        {"selectedOptionals": [{"hostClass": "homebase", "id": "go-simple-upload-server"}]},
        root=tmp_path / "engagements",
        repository=repo,
        service_repository=_FakeServiceRepository(),
    )
    assert selected is not None
    return repo


def _old_selected_gofs_workspace(tmp_path: Path, monkeypatch) -> "_FakeWorkspaceRepository":
    engagement = _engagement()
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.engagement_capabilities.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.capability_execution.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.capability_reconciliation.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.capability_lock_rendering.get_engagement", lambda _id: engagement)
    source = tmp_path / "old-redteam-infra"
    (source / "external").mkdir(parents=True)
    (source / "ansible").mkdir(parents=True)
    repo = _FakeWorkspaceRepository()
    prepared = prepare_engagement_workspace(
        ENGAGEMENT_ID,
        root=tmp_path / "engagements",
        repository=repo,
        source=RedteamInfraTemplateSource(source, "old-stock"),
    )
    assert prepared is not None and repo.workspace is not None
    repo.workspace = replace(
        repo.workspace,
        metadata={
            **repo.workspace.metadata,
            "capabilityOverrides": {
                "deselectedDefaults": [],
                "selectedOptionals": [{"hostClass": "homebase", "id": "go-simple-upload-server"}],
            },
        },
    )
    return repo


def _committed_gofs_source(tmp_path: Path) -> Path:
    source = tmp_path / "current-redteam-infra"
    (source / "external").mkdir(parents=True)
    tasks = source / "ansible/roles/go_simple_upload_server/tasks"
    tasks.mkdir(parents=True)
    (tasks / "main.yml").write_text("---\n- debug:\n    msg: go-simple-upload-server\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(source), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.email", "tests@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.name", "Barragan Tests"], check=True)
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
    return source


def _engagement():
    return SimpleNamespace(id=ENGAGEMENT_ID, name="Example", input_parameters={"proxyCount": 1})


def _core_job() -> StoredJobRun:
    details = [
        {"role": "homebase", "displayName": "homebase-example", "publicIp": "192.0.2.10", "sshUser": "user"},
        {
            "role": "proxy",
            "displayName": "proxy01-example",
            "sshAlias": "proxy01",
            "publicIp": "192.0.2.11",
            "privateIp": "10.0.0.11",
            "sshUser": "user",
        },
    ]
    return StoredJobRun(
        id="job-core",
        action="pilot_standard_rti_guarded_execute",
        status="succeeded",
        target=f"engagement:{ENGAGEMENT_ID}",
        target_type="engagement",
        target_id=ENGAGEMENT_ID,
        requested_by="operator",
        input={"engagementId": ENGAGEMENT_ID},
        artifact_refs=[],
        created_at="2026-08-19T00:00:00+00:00",
        started_at="2026-08-19T00:00:00+00:00",
        finished_at="2026-08-19T00:10:00+00:00",
        events=[JobEvent(1, "info", "deployed", {"connectionDetails": details, "mutationStatus": "deployed"})],
    )


class _FakeWorkspaceRepository:
    def __init__(self) -> None:
        self.workspace: StoredEngagementWorkspace | None = None

    def get(self, engagement_id: str) -> StoredEngagementWorkspace | None:
        if self.workspace is not None and self.workspace.engagement_id == engagement_id:
            return self.workspace
        return None

    def save(self, workspace: StoredEngagementWorkspace) -> StoredEngagementWorkspace:
        self.workspace = workspace
        return workspace


class _FakeJobRepository:
    def __init__(self, jobs: list[StoredJobRun]) -> None:
        self.jobs = {job.id: job for job in jobs}
        self.saved: list[StoredJobRun] = []

    def list(self) -> list[StoredJobRun]:
        return list(reversed(list(self.jobs.values())))

    def list_for_engagement(self, engagement_id: str, *, limit: int | None = None) -> list[StoredJobRun]:
        rows = [job for job in reversed(list(self.jobs.values())) if job.target_id == engagement_id]
        return rows[:limit] if limit is not None else rows

    def get(self, job_id: str) -> StoredJobRun | None:
        return self.jobs.get(job_id)

    def save(self, job: StoredJobRun) -> StoredJobRun:
        self.saved.append(job)
        self.jobs[job.id] = job
        return job


class _FakeLeaseRepository:
    def __init__(self) -> None:
        self.acquired: list[tuple[str, str, str]] = []
        self.released: list[tuple[str, str]] = []

    def acquire(self, engagement_id: str, owner_id: str, operation: str) -> bool:
        self.acquired.append((engagement_id, owner_id, operation))
        return True

    def release(self, engagement_id: str, owner_id: str) -> None:
        self.released.append((engagement_id, owner_id))


class _FakeServiceRepository:
    def list_for_engagement(self, _engagement_id: str):
        return []
