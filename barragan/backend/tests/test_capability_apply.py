# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import json

import pytest

from app.domain import JobEvent
from app.services.capability_apply import (
    CAPABILITY_APPLY_ACTION,
    CapabilityApplyValidationError,
    _apply_preflight,
    recover_interrupted_capability_applies,
    start_capability_apply,
)
from app.services.engagement_capabilities import save_capability_apply_state
from app.storage.engagement_workspace_repository import StoredEngagementWorkspace
from app.storage.job_repository import StoredJobRun


ENGAGEMENT_ID = "eng-apply123"


class _WorkspaceRepository:
    def __init__(self, workspace: StoredEngagementWorkspace) -> None:
        self.workspace = workspace

    def get(self, engagement_id: str) -> StoredEngagementWorkspace | None:
        return self.workspace if engagement_id == self.workspace.engagement_id else None

    def save(self, workspace: StoredEngagementWorkspace) -> StoredEngagementWorkspace:
        self.workspace = workspace
        return workspace


class _JobRepository:
    def __init__(self, jobs: list[StoredJobRun] | None = None) -> None:
        self.jobs = {job.id: job for job in jobs or []}
        self.saved: list[StoredJobRun] = []

    def get(self, job_id: str) -> StoredJobRun | None:
        return self.jobs.get(job_id)

    def save(self, job: StoredJobRun) -> StoredJobRun:
        self.saved.append(job)
        self.jobs[job.id] = job
        return job

    def list(self) -> list[StoredJobRun]:
        return list(self.jobs.values())


@pytest.fixture(autouse=True)
def _engagement_exists(monkeypatch: pytest.MonkeyPatch) -> None:
    engagement = SimpleNamespace(id=ENGAGEMENT_ID)
    monkeypatch.setattr("app.services.capability_apply.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: engagement)


def test_optional_only_apply_records_durable_parent_and_child_outcome(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace_repo = _prepared_workspace(tmp_path)
    jobs = _JobRepository()
    monkeypatch.setattr("app.services.capability_apply.get_engagement", lambda _id: SimpleNamespace(id=ENGAGEMENT_ID))
    monkeypatch.setattr(
        "app.services.capability_apply._apply_preflight",
        lambda *_args, **_kwargs: ([], True, [], {"kind": "selection"}),
    )

    result = start_capability_apply(
        ENGAGEMENT_ID,
        engagement_repos_root=tmp_path,
        repository=jobs,
        workspace_repository=workspace_repo,
        background_runner=lambda task: task(),
        reconciliation_starter=lambda *_args, **_kwargs: {"status": "succeeded", "job": {"id": "job-optional"}},
        desktop_starter=lambda *_args, **_kwargs: pytest.fail("Desktop must not run for optional-only apply"),
    )

    assert result is not None
    assert result["status"] == "applied"
    assert result["applyState"]["children"] == [
        {"kind": "optional_roles", "status": "succeeded", "jobId": "job-optional", "detail": ""},
        {"kind": "desktop", "status": "not_required", "jobId": "", "detail": ""},
    ]
    parent = result["job"]
    assert parent["action"] == CAPABILITY_APPLY_ACTION
    assert parent["status"] == "succeeded"
    assert workspace_repo.workspace.metadata["capabilityApplyState"]["parentJobId"] == parent["id"]


def test_desktop_only_apply_uses_saved_desktop_input(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace_repo = _prepared_workspace(tmp_path)
    jobs = _JobRepository()
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr("app.services.capability_apply.get_engagement", lambda _id: SimpleNamespace(id=ENGAGEMENT_ID))
    desired_apps = [{"slug": "firefox", "enabled": True}]
    monkeypatch.setattr(
        "app.services.capability_apply._apply_preflight",
        lambda *_args, **_kwargs: ([], False, desired_apps, {"kind": "saved-selection"}),
    )

    result = start_capability_apply(
        ENGAGEMENT_ID,
        engagement_repos_root=tmp_path,
        repository=jobs,
        workspace_repository=workspace_repo,
        background_runner=lambda task: task(),
        reconciliation_starter=lambda *_args, **_kwargs: pytest.fail("optional roles must not run for desktop-only apply"),
        desktop_starter=lambda _engagement, apps, **kwargs: (
            calls.append(("desktop", {"apps": apps, "source": kwargs["desired_state_source"]}))
            or {"status": "Configured", "job": {"id": "job-desktop"}}
        ),
    )

    assert result is not None and result["status"] == "applied"
    assert calls == [
        ("desktop", {"apps": desired_apps, "source": {"kind": "saved-selection", "parentApplyJobId": result["job"]["id"]}})
    ]
    assert result["applyState"]["children"][0]["status"] == "not_required"
    assert result["applyState"]["children"][1] == {
        "kind": "desktop", "status": "succeeded", "jobId": "job-desktop", "detail": ""
    }


def test_mixed_apply_runs_optional_roles_before_desktop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace_repo = _prepared_workspace(tmp_path)
    jobs = _JobRepository()
    order: list[str] = []
    monkeypatch.setattr("app.services.capability_apply.get_engagement", lambda _id: SimpleNamespace(id=ENGAGEMENT_ID))
    monkeypatch.setattr(
        "app.services.capability_apply._apply_preflight",
        lambda *_args, **_kwargs: ([], True, [{"slug": "firefox", "enabled": True}], {}),
    )

    result = start_capability_apply(
        ENGAGEMENT_ID,
        engagement_repos_root=tmp_path,
        repository=jobs,
        workspace_repository=workspace_repo,
        background_runner=lambda task: task(),
        reconciliation_starter=lambda *_args, **_kwargs: order.append("optional") or {"status": "succeeded", "job": {"id": "job-optional"}},
        desktop_starter=lambda *_args, **_kwargs: order.append("desktop") or {"status": "Configured", "job": {"id": "job-desktop"}},
    )

    assert result is not None and result["status"] == "applied"
    assert order == ["optional", "desktop"]


def test_failed_optional_child_blocks_desktop_and_retry_does_not_silently_skip_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace_repo = _prepared_workspace(tmp_path)
    jobs = _JobRepository()
    desktop_calls: list[str] = []
    monkeypatch.setattr("app.services.capability_apply.get_engagement", lambda _id: SimpleNamespace(id=ENGAGEMENT_ID))
    monkeypatch.setattr(
        "app.services.capability_apply._apply_preflight",
        lambda *_args, **_kwargs: ([], True, [{"slug": "firefox", "enabled": True}], {}),
    )

    failed = start_capability_apply(
        ENGAGEMENT_ID,
        engagement_repos_root=tmp_path,
        repository=jobs,
        workspace_repository=workspace_repo,
        background_runner=lambda task: task(),
        reconciliation_starter=lambda *_args, **_kwargs: {
            "status": "failed",
            "job": {
                "id": "job-optional-failed",
                "events": [{"data": {"error": "TASK [GoSUS build] fatal: compiler unavailable"}}],
            },
        },
        desktop_starter=lambda *_args, **_kwargs: desktop_calls.append("desktop") or {"status": "Configured", "job": {"id": "unexpected"}},
    )

    assert failed is not None and failed["status"] == "failed"
    assert desktop_calls == []
    assert failed["applyState"]["children"][0]["detail"] == "TASK [GoSUS build] fatal: compiler unavailable"
    assert failed["applyState"]["children"][1] == {
        "kind": "desktop",
        "status": "blocked",
        "jobId": "",
        "detail": "not started because optional role reconciliation failed",
    }

    retried = start_capability_apply(
        ENGAGEMENT_ID,
        engagement_repos_root=tmp_path,
        repository=jobs,
        workspace_repository=workspace_repo,
        background_runner=lambda task: task(),
        reconciliation_starter=lambda *_args, **_kwargs: {"status": "succeeded", "job": {"id": "job-optional-retry"}},
        desktop_starter=lambda *_args, **_kwargs: desktop_calls.append("desktop") or {"status": "Configured", "job": {"id": "job-desktop-retry"}},
    )

    assert retried is not None and retried["status"] == "applied"
    assert desktop_calls == ["desktop"]


def test_parent_redacts_external_child_failure_before_any_save(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace_repo = _prepared_workspace(tmp_path)
    jobs = _JobRepository()
    monkeypatch.setattr(
        "app.services.capability_apply._apply_preflight",
        lambda *_args, **_kwargs: ([], True, [], {}),
    )

    result = start_capability_apply(
        ENGAGEMENT_ID,
        engagement_repos_root=tmp_path,
        repository=jobs,
        workspace_repository=workspace_repo,
        background_runner=lambda task: task(),
        reconciliation_starter=lambda *_args, **_kwargs: {
            "status": "failed",
            "job": {
                "id": "job-unsafe-child",
                "events": [{"data": {"error": "LINODE_TOKEN unsafe-value"}}],
            },
        },
        desktop_starter=lambda *_args, **_kwargs: pytest.fail("Desktop must remain blocked"),
    )

    assert result is not None and result["status"] == "failed"
    assert "unsafe-value" not in str(jobs.saved)
    assert "LINODE_TOKEN" not in str(jobs.saved)


def test_repeat_of_persisted_applied_state_does_not_create_another_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace_repo = _prepared_workspace(tmp_path, status="applied", parent_job_id="job-existing")
    existing = _parent_job("job-existing", status="succeeded")
    jobs = _JobRepository([existing])
    monkeypatch.setattr("app.services.capability_apply.get_engagement", lambda _id: SimpleNamespace(id=ENGAGEMENT_ID))

    result = start_capability_apply(
        ENGAGEMENT_ID,
        engagement_repos_root=tmp_path,
        repository=jobs,
        workspace_repository=workspace_repo,
    )

    assert result is not None and result["status"] == "applied"
    assert result["job"]["id"] == "job-existing"
    assert len(jobs.jobs) == 1


def test_recovery_marks_orphaned_parent_failed(tmp_path: Path) -> None:
    workspace_repo = _prepared_workspace(tmp_path, status="applying", parent_job_id="job-orphan")
    jobs = _JobRepository([_parent_job("job-orphan", status="running")])

    assert recover_interrupted_capability_applies(repository=jobs, workspace_repository=workspace_repo) == 1
    assert jobs.get("job-orphan").status == "failed"
    assert workspace_repo.workspace.metadata["capabilityApplyState"]["status"] == "failed"


def test_apply_requires_saved_ready_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace_repo = _prepared_workspace(tmp_path, status="blocked")
    monkeypatch.setattr("app.services.capability_apply.get_engagement", lambda _id: SimpleNamespace(id=ENGAGEMENT_ID))

    with pytest.raises(CapabilityApplyValidationError):
        start_capability_apply(
            ENGAGEMENT_ID,
            engagement_repos_root=tmp_path,
            repository=_JobRepository(),
            workspace_repository=workspace_repo,
        )


def test_static_web_selection_without_a_site_is_a_durable_apply_blocker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace_repo = _prepared_workspace(tmp_path)
    monkeypatch.setattr(
        "app.services.capability_apply.build_optional_core_capability_role_apply_plan",
        lambda **_kwargs: SimpleNamespace(role_names=[]),
    )
    monkeypatch.setattr(
        "app.services.capability_apply.desktop_capability_reconciliation_input",
        lambda *_args, **_kwargs: ([{"slug": "firefox", "enabled": True}], {}),
    )
    monkeypatch.setattr(
        "app.services.capability_apply.engagement_capability_workspace",
        lambda *_args, **_kwargs: {"nativeState": {"staticWeb": {"selected": True, "claimed": False}}},
    )
    monkeypatch.setattr(
        "app.services.capability_apply.active_core_connection_details",
        lambda *_args, **_kwargs: ("job-core", [{"role": "homebase"}]),
    )

    blockers, optional_required, desired_apps, _source = _apply_preflight(
        ENGAGEMENT_ID,
        engagement_repos_root=tmp_path,
        repository=_JobRepository(),
        workspace_repository=workspace_repo,
        service_repository=None,
    )

    assert optional_required is False
    assert desired_apps == [{"slug": "firefox", "enabled": True}]
    assert blockers == ["Static Web needs at least one configured site before applying saved capability changes"]


def test_fastapi_aggregate_apply_route_wraps_parent_payload(client, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "status": "applying",
        "applyState": {"status": "applying", "children": []},
        "job": {"id": "job-parent", "status": "queued"},
    }
    monkeypatch.setattr("app.asgi.start_capability_apply", lambda *_args, **_kwargs: payload)

    response = client.post(f"/api/engagements/{ENGAGEMENT_ID}/capabilities/apply", json={"requestedBy": "example_operator_three"})

    assert response.status_code == 202
    assert response.get_json() == {"capabilityApply": payload}


def _prepared_workspace(tmp_path: Path, *, status: str = "saved_ready", parent_job_id: str = "") -> _WorkspaceRepository:
    workspace_path = tmp_path / "apply-demo"
    (workspace_path / "barragan").mkdir(parents=True)
    (workspace_path / "barragan" / "capability-lock.yml").write_text("---\n", encoding="utf-8")
    (workspace_path / "barragan" / "workspace-manifest.json").write_text(
        json.dumps({"engagementId": ENGAGEMENT_ID, "managedBy": "barragan"}),
        encoding="utf-8",
    )
    workspace = StoredEngagementWorkspace(
        engagement_id=ENGAGEMENT_ID,
        slug="apply-demo",
        path=str(workspace_path),
        status="capability-lock-rendered",
        profile_id="standard-rti",
        template_source={},
        metadata={},
    )
    repo = _WorkspaceRepository(workspace)
    save_capability_apply_state(
        workspace,
        {
            "status": status,
            "selectionFingerprint": "selection-fingerprint",
            "renderedInputFingerprint": "rendered-input-fingerprint",
            "preparedAt": "2026-08-20T00:00:00+00:00",
            "startedAt": "" if status != "applying" else "2026-08-20T00:01:00+00:00",
            "finishedAt": "",
            "parentJobId": parent_job_id,
            "errors": ["preparation blocked"] if status == "blocked" else [],
            "children": [],
        },
        repository=repo,
    )
    return repo


def _parent_job(job_id: str, *, status: str) -> StoredJobRun:
    return StoredJobRun(
        id=job_id,
        action=CAPABILITY_APPLY_ACTION,
        status=status,
        target=f"engagement:{ENGAGEMENT_ID}",
        target_type="engagement",
        target_id=ENGAGEMENT_ID,
        requested_by="operator",
        input={"engagementId": ENGAGEMENT_ID, "selectionFingerprint": "selection-fingerprint", "children": []},
        artifact_refs=[],
        created_at="2026-08-20T00:00:00+00:00",
        started_at=None,
        finished_at=None,
        events=[JobEvent(1, "info", "queued", {})],
    )
