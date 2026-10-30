# Copyright (c) 2026, Oracle and/or its affiliates.
"""Durable page-level capability apply orchestration.

The existing optional-role reconciler and Desktop workflow remain the workers
that perform Ansible mutations.  This module adds the missing durable parent
record: it owns the saved selection fingerprint, starts those workers in their
required order, and records every child outcome so a browser reload never has
to infer what happened from transient UI state.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import uuid4

from app.core.runtime import start_runtime_task
from app.domain import JobEvent
from app.services.capability_execution import (
    CapabilityRoleApplyPlanValidationError,
    build_optional_core_capability_role_apply_plan,
)
from app.services.capability_reconciliation import (
    FORBIDDEN_CAPABILITY_OUTPUT_MARKERS,
    safe_capability_failure_detail,
    start_capability_reconciliation,
)
from app.services.core_ssh import active_core_connection_details
from app.services.engagement_capabilities import (
    EngagementCapabilityValidationError,
    capability_apply_state_for_workspace,
    desktop_capability_reconciliation_input,
    engagement_capability_workspace,
    save_capability_apply_state,
)
from app.services.engagement_workspaces import EngagementWorkspaceValidationError, load_prepared_engagement_workspace
from app.services.engagements import get_engagement
from app.services.legacy_homebase_role_service import (
    apply_desktop_service,
)
from app.storage.engagement_workspace_repository import (
    EngagementWorkspaceRepository,
    SqlAlchemyEngagementWorkspaceRepository,
)
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.service_repository import EngagementServiceRepository


CAPABILITY_APPLY_ACTION = "engagement_capability_apply"
_DESKTOP_CHILD = "desktop"
_OPTIONAL_ROLES_CHILD = "optional_roles"

CommandRunner = Callable[..., Any]
BackgroundRunner = Callable[[Callable[[], None]], None]


class CapabilityApplyValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("capability apply validation failed")
        self.errors = errors


def start_capability_apply(
    engagement_id: str,
    *,
    engagement_repos_root: Path,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    workspace_repository: EngagementWorkspaceRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
    runner: CommandRunner | None = None,
    background_runner: BackgroundRunner | None = None,
    workspace_root: Path | None = None,
    env: Mapping[str, str] | None = None,
    reconciliation_starter: Callable[..., dict[str, Any] | None] | None = None,
    desktop_starter: Callable[..., dict[str, Any] | None] | None = None,
) -> dict[str, Any] | None:
    """Start a durable apply for the currently saved-and-prepared selection.

    The parent is intentionally asynchronous even when one child is absent.
    Optional role reconciliation runs first; Desktop only runs after it has
    succeeded.  A failed first child explicitly marks Desktop blocked rather
    than pretending it was applied or silently skipping it.
    """

    if get_engagement(engagement_id) is None:
        return None
    job_repo = repository or SqlAlchemyJobRepository()
    workspace_repo = workspace_repository or SqlAlchemyEngagementWorkspaceRepository()
    workspace = load_prepared_engagement_workspace(
        engagement_id,
        root=engagement_repos_root,
        repository=workspace_repo,
    )
    if workspace is None:
        raise CapabilityApplyValidationError(["save capability changes before applying them"])
    state = capability_apply_state_for_workspace(workspace)
    if state["status"] == "applying":
        return _response_for_existing_parent(job_repo, state)
    if state["status"] == "applied":
        return _response_for_existing_parent(job_repo, state)
    if state["status"] not in {"saved_ready", "failed", "partial"}:
        raise CapabilityApplyValidationError(
            state["errors"] or ["save and prepare capability changes before applying them"]
        )
    if not state["selectionFingerprint"] or not state["renderedInputFingerprint"]:
        raise CapabilityApplyValidationError(["save and prepare capability changes before applying them"])
    if not (Path(workspace.path) / "barragan" / "capability-lock.yml").is_file():
        _persist_state_if_current(
            workspace_repo,
            engagement_id,
            state["selectionFingerprint"],
            {**state, "status": "blocked", "errors": ["saved capability changes need to be prepared again before applying"]},
        )
        raise CapabilityApplyValidationError(["saved capability changes need to be prepared again before applying"])

    blockers, optional_required, desired_apps, desktop_source = _apply_preflight(
        engagement_id,
        engagement_repos_root=engagement_repos_root,
        repository=job_repo,
        workspace_repository=workspace_repo,
        service_repository=service_repository,
    )
    if blockers:
        blocked_state = {
            **state,
            "status": "blocked",
            "errors": blockers,
            "children": _initial_children(optional_required=optional_required, desktop_required=bool(desired_apps)),
        }
        _persist_state_if_current(workspace_repo, engagement_id, state["selectionFingerprint"], blocked_state)
        raise CapabilityApplyValidationError(blockers)

    parent_id = f"job-{uuid4().hex[:12]}"
    now = _now()
    children = _initial_children(optional_required=optional_required, desktop_required=bool(desired_apps))
    parent = job_repo.save(
        StoredJobRun(
            id=parent_id,
            action=CAPABILITY_APPLY_ACTION,
            status="queued",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={
                "engagementId": engagement_id,
                "selectionFingerprint": state["selectionFingerprint"],
                "renderedInputFingerprint": state["renderedInputFingerprint"],
                "children": children,
                "mutation": True,
                "retryRequired": False,
            },
            artifact_refs=["barragan/capability-lock.yml"],
            created_at=now,
            started_at=None,
            finished_at=None,
            events=[
                JobEvent(
                    1,
                    "info",
                    "saved capability apply queued",
                    {"children": children, "selectionFingerprint": state["selectionFingerprint"]},
                )
            ],
        )
    )
    applying_state = {
        **state,
        "status": "applying",
        "startedAt": now,
        "finishedAt": "",
        "parentJobId": parent.id,
        "errors": [],
        "children": children,
    }
    _persist_state_if_current(workspace_repo, engagement_id, state["selectionFingerprint"], applying_state)

    task = lambda: _run_parent_apply(
        parent_id,
        engagement_id=engagement_id,
        selection_fingerprint=state["selectionFingerprint"],
        desired_apps=desired_apps,
        desktop_source=desktop_source,
        optional_required=optional_required,
        engagement_repos_root=engagement_repos_root,
        repository=job_repo,
        workspace_repository=workspace_repo,
        service_repository=service_repository,
        runner=runner,
        workspace_root=workspace_root,
        env=env,
        reconciliation_starter=reconciliation_starter or start_capability_reconciliation,
        desktop_starter=desktop_starter or apply_desktop_service,
    )
    try:
        if background_runner is not None:
            background_runner(task)
        elif runner is not None:
            task()
        else:
            start_runtime_task(task, name="barragan-capability-apply-runner")
    except Exception:
        _finish_parent_failure(
            job_repo,
            parent_id,
            engagement_id=engagement_id,
            selection_fingerprint=state["selectionFingerprint"],
            workspace_repository=workspace_repo,
            message="capability apply scheduler failed to start; retry is required",
        )

    saved = job_repo.get(parent.id) or parent
    current = _current_state(workspace_repo, engagement_id)
    return _response(saved, current)


def recover_interrupted_capability_applies(
    *,
    repository: JobRepository | None = None,
    workspace_repository: EngagementWorkspaceRepository | None = None,
) -> int:
    """Fail orphaned aggregate jobs after a process restart, preserving retry evidence."""

    repo = repository or SqlAlchemyJobRepository()
    workspace_repo = workspace_repository or SqlAlchemyEngagementWorkspaceRepository()
    recovered = 0
    for job in repo.list():
        if job.action != CAPABILITY_APPLY_ACTION or job.status not in {"queued", "running"}:
            continue
        _finish_parent_failure(
            repo,
            job.id,
            engagement_id=job.target_id,
            selection_fingerprint=str(job.input.get("selectionFingerprint") or ""),
            workspace_repository=workspace_repo,
            message="capability apply was interrupted by an application restart; retry is required",
        )
        recovered += 1
    return recovered


def _apply_preflight(
    engagement_id: str,
    *,
    engagement_repos_root: Path,
    repository: JobRepository,
    workspace_repository: EngagementWorkspaceRepository,
    service_repository: EngagementServiceRepository | None,
) -> tuple[list[str], bool, list[dict[str, Any]], dict[str, Any]]:
    errors: list[str] = []
    optional_required = False
    try:
        plan = build_optional_core_capability_role_apply_plan(
            engagement_id=engagement_id,
            engagement_repos_root=engagement_repos_root,
            repository=workspace_repository,
            elk_enabled=True,
        )
        optional_required = bool(plan.role_names)
    except (CapabilityRoleApplyPlanValidationError, EngagementWorkspaceValidationError) as exc:
        errors.extend(_errors_from(exc))

    try:
        desktop = desktop_capability_reconciliation_input(
            engagement_id,
            root=engagement_repos_root,
            repository=workspace_repository,
            service_repository=service_repository,
        )
        if desktop is None:
            errors.append("engagement not found")
            desired_apps, desktop_source = [], {}
        else:
            desired_apps, desktop_source = desktop
    except (EngagementCapabilityValidationError, EngagementWorkspaceValidationError) as exc:
        errors.extend(_errors_from(exc))
        desired_apps, desktop_source = [], {}

    workspace_payload = engagement_capability_workspace(
        engagement_id,
        root=engagement_repos_root,
        repository=workspace_repository,
        service_repository=service_repository,
    )
    native_state = (workspace_payload or {}).get("nativeState") if isinstance(workspace_payload, dict) else {}
    static_web = native_state.get("staticWeb") if isinstance(native_state, dict) else {}
    if isinstance(static_web, dict) and static_web.get("selected") and not static_web.get("claimed"):
        errors.append("Static Web needs at least one configured site before applying saved capability changes")

    # Both child workflows require a current core generation.  Validate it
    # before starting either so missing infrastructure never becomes a hidden
    # partial apply.
    if optional_required or desired_apps:
        core_deployment_id, details = active_core_connection_details(repository, engagement_id)
        has_homebase = any(str(detail.get("role") or "") == "homebase" for detail in details)
        if not core_deployment_id or not has_homebase:
            errors.append("active core infrastructure inventory with a homebase is required before applying saved capability changes")
    return _dedupe(errors), optional_required, desired_apps, desktop_source


def _run_parent_apply(
    parent_id: str,
    *,
    engagement_id: str,
    selection_fingerprint: str,
    desired_apps: list[dict[str, Any]],
    desktop_source: dict[str, Any],
    optional_required: bool,
    engagement_repos_root: Path,
    repository: JobRepository,
    workspace_repository: EngagementWorkspaceRepository,
    service_repository: EngagementServiceRepository | None,
    runner: CommandRunner | None,
    workspace_root: Path | None,
    env: Mapping[str, str] | None,
    reconciliation_starter: Callable[..., dict[str, Any] | None],
    desktop_starter: Callable[..., dict[str, Any] | None],
) -> None:
    parent = repository.get(parent_id)
    if parent is None or parent.status != "queued":
        return
    children = _children_from_job(parent)
    running = repository.save(
        replace(
            parent,
            status="running",
            started_at=_now(),
            events=[*parent.events, JobEvent(len(parent.events) + 1, "info", "saved capability apply started", {"children": children})],
        )
    )
    _persist_state_if_current(
        workspace_repository,
        engagement_id,
        selection_fingerprint,
        {**_current_state(workspace_repository, engagement_id), "status": "applying", "children": children},
    )

    try:
        if optional_required:
            children = _set_child(children, _OPTIONAL_ROLES_CHILD, status="running")
            _update_parent_children(repository, parent_id, children, "optional role reconciliation started")
            _persist_children(workspace_repository, engagement_id, selection_fingerprint, children)
            optional = reconciliation_starter(
                engagement_id,
                engagement_repos_root=engagement_repos_root,
                requested_by=running.requested_by,
                repository=repository,
                workspace_repository=workspace_repository,
                service_repository=service_repository,
                runner=runner,
                background_runner=lambda task: task(),
                workspace_root=workspace_root,
                env=env,
                parent_apply_job_id=parent_id,
            )
            optional_job = (optional or {}).get("job") if isinstance(optional, dict) else None
            optional_status = str((optional or {}).get("status") or "failed")
            child_status = "succeeded" if optional_status == "succeeded" else "failed"
            failure_detail = _child_failure_detail(optional_job, "optional role reconciliation failed; retry is required")
            children = _set_child(
                children,
                _OPTIONAL_ROLES_CHILD,
                status=child_status,
                jobId=str((optional_job or {}).get("id") or ""),
                detail="" if child_status == "succeeded" else failure_detail,
            )
            _update_parent_children(repository, parent_id, children, "optional role reconciliation finished")
            _persist_children(workspace_repository, engagement_id, selection_fingerprint, children)
            if child_status != "succeeded":
                children = _set_child(
                    children,
                    _DESKTOP_CHILD,
                    status="blocked",
                    detail="not started because optional role reconciliation failed",
                )
                _finish_parent(
                    repository,
                    parent_id,
                    engagement_id=engagement_id,
                    selection_fingerprint=selection_fingerprint,
                    workspace_repository=workspace_repository,
                    children=children,
                    state_status="failed",
                    job_status="failed",
                    message="saved capability apply failed before Desktop could start",
                )
                return

        desktop_child = next((child for child in children if child["kind"] == _DESKTOP_CHILD), None)
        if desktop_child is not None and desktop_child["status"] != "not_required":
            children = _set_child(children, _DESKTOP_CHILD, status="running")
            _update_parent_children(repository, parent_id, children, "Desktop capability reconciliation started")
            _persist_children(workspace_repository, engagement_id, selection_fingerprint, children)
            desktop = desktop_starter(
                engagement_id,
                desired_apps,
                requested_by=running.requested_by,
                repository=repository,
                runner=runner,
                background_runner=lambda task: task(),
                workspace_root=workspace_root,
                env=env,
                desired_state_source={**desktop_source, "parentApplyJobId": parent_id},
            )
            desktop_job = (desktop or {}).get("job") if isinstance(desktop, dict) else None
            desktop_status = str((desktop or {}).get("status") or "Failed")
            child_status = "succeeded" if desktop_status.lower() in {"configured", "succeeded"} else "failed"
            children = _set_child(
                children,
                _DESKTOP_CHILD,
                status=child_status,
                jobId=str((desktop_job or {}).get("id") or ""),
                detail="" if child_status == "succeeded" else "Desktop capability reconciliation failed; retry is required",
            )

        any_failed = any(child["status"] in {"failed", "blocked"} for child in children)
        any_succeeded = any(child["status"] == "succeeded" for child in children)
        state_status = "partial" if any_failed and any_succeeded else "failed" if any_failed else "applied"
        _finish_parent(
            repository,
            parent_id,
            engagement_id=engagement_id,
            selection_fingerprint=selection_fingerprint,
            workspace_repository=workspace_repository,
            children=children,
            state_status=state_status,
            job_status="failed" if any_failed else "succeeded",
            message="saved capability apply completed" if not any_failed else "saved capability apply completed with failed child work",
        )
    except Exception:
        _finish_parent_failure(
            repository,
            parent_id,
            engagement_id=engagement_id,
            selection_fingerprint=selection_fingerprint,
            workspace_repository=workspace_repository,
            message="saved capability apply failed; retry is required",
        )


def _response_for_existing_parent(repository: JobRepository, state: dict[str, Any]) -> dict[str, Any]:
    parent = repository.get(state["parentJobId"]) if state["parentJobId"] else None
    return _response(parent, state)


def _response(parent: StoredJobRun | None, state: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": state["status"],
        "applyState": state,
        "job": parent.to_detail().to_dict() if parent is not None else None,
    }


def _current_state(repository: EngagementWorkspaceRepository, engagement_id: str) -> dict[str, Any]:
    return capability_apply_state_for_workspace(repository.get(engagement_id))


def _persist_state_if_current(
    repository: EngagementWorkspaceRepository,
    engagement_id: str,
    selection_fingerprint: str,
    state: dict[str, Any],
) -> None:
    workspace = repository.get(engagement_id)
    if workspace is None:
        return
    current = capability_apply_state_for_workspace(workspace)
    if current["selectionFingerprint"] != selection_fingerprint:
        return
    save_capability_apply_state(workspace, state, repository=repository)


def _persist_children(
    repository: EngagementWorkspaceRepository,
    engagement_id: str,
    selection_fingerprint: str,
    children: list[dict[str, Any]],
) -> None:
    current = _current_state(repository, engagement_id)
    _persist_state_if_current(
        repository,
        engagement_id,
        selection_fingerprint,
        {**current, "status": "applying", "children": children},
    )


def _update_parent_children(repository: JobRepository, parent_id: str, children: list[dict[str, Any]], message: str) -> None:
    parent = repository.get(parent_id)
    if parent is None:
        return
    _assert_safe_children(children)
    repository.save(
        replace(
            parent,
            input={**parent.input, "children": children},
            events=[*parent.events, JobEvent(len(parent.events) + 1, "info", message, {"children": children})],
        )
    )


def _finish_parent(
    repository: JobRepository,
    parent_id: str,
    *,
    engagement_id: str,
    selection_fingerprint: str,
    workspace_repository: EngagementWorkspaceRepository,
    children: list[dict[str, Any]],
    state_status: str,
    job_status: str,
    message: str,
) -> None:
    parent = repository.get(parent_id)
    if parent is None:
        return
    _assert_safe_children(children)
    finished_at = _now()
    saved = repository.save(
        replace(
            parent,
            status=job_status,
            finished_at=finished_at,
            input={**parent.input, "children": children, "retryRequired": job_status != "succeeded"},
            events=[*parent.events, JobEvent(len(parent.events) + 1, "info" if job_status == "succeeded" else "error", message, {"children": children})],
        )
    )
    current = _current_state(workspace_repository, engagement_id)
    _persist_state_if_current(
        workspace_repository,
        engagement_id,
        selection_fingerprint,
        {
            **current,
            "status": state_status,
            "parentJobId": saved.id,
            "finishedAt": finished_at,
            "errors": _child_errors(children),
            "children": children,
        },
    )


def _finish_parent_failure(
    repository: JobRepository,
    parent_id: str,
    *,
    engagement_id: str,
    selection_fingerprint: str,
    workspace_repository: EngagementWorkspaceRepository,
    message: str,
) -> None:
    parent = repository.get(parent_id)
    if parent is None:
        return
    children = _children_from_job(parent)
    if not any(child["status"] == "failed" for child in children):
        children = _set_first_runnable_child_failed(children, "apply orchestration failed; retry is required")
    _finish_parent(
        repository,
        parent_id,
        engagement_id=engagement_id,
        selection_fingerprint=selection_fingerprint,
        workspace_repository=workspace_repository,
        children=children,
        state_status="failed",
        job_status="failed",
        message=message,
    )


def _initial_children(*, optional_required: bool, desktop_required: bool) -> list[dict[str, Any]]:
    return [
        {"kind": _OPTIONAL_ROLES_CHILD, "status": "pending" if optional_required else "not_required", "jobId": "", "detail": ""},
        {"kind": _DESKTOP_CHILD, "status": "pending" if desktop_required else "not_required", "jobId": "", "detail": ""},
    ]


def _children_from_job(job: StoredJobRun) -> list[dict[str, Any]]:
    raw = job.input.get("children")
    if isinstance(raw, list):
        children = [dict(value) for value in raw if isinstance(value, dict)]
        if children:
            return children
    return _initial_children(optional_required=False, desktop_required=False)


def _set_child(children: list[dict[str, Any]], kind: str, **changes: Any) -> list[dict[str, Any]]:
    updated: list[dict[str, Any]] = []
    found = False
    for child in children:
        current = dict(child)
        if current.get("kind") == kind:
            current.update(changes)
            found = True
        updated.append(current)
    if not found:
        updated.append({"kind": kind, "status": "pending", "jobId": "", "detail": "", **changes})
    return updated


def _child_failure_detail(job: Any, fallback: str) -> str:
    if not isinstance(job, dict):
        return fallback
    events = job.get("events")
    if not isinstance(events, list):
        return fallback
    for event in reversed(events):
        if not isinstance(event, dict):
            continue
        data = event.get("data")
        if not isinstance(data, dict):
            continue
        error = str(data.get("error") or "").strip()
        if error:
            return safe_capability_failure_detail(error)
    return safe_capability_failure_detail(fallback)


def _assert_safe_children(children: list[dict[str, Any]]) -> None:
    encoded = str(children)
    if any(marker in encoded for marker in FORBIDDEN_CAPABILITY_OUTPUT_MARKERS):
        raise CapabilityApplyValidationError(["capability apply child detail contains sensitive output"])


def _set_first_runnable_child_failed(children: list[dict[str, Any]], detail: str) -> list[dict[str, Any]]:
    for child in children:
        if child.get("status") in {"pending", "running"}:
            return _set_child(children, str(child.get("kind") or "unknown"), status="failed", detail=detail)
    return children


def _child_errors(children: list[dict[str, Any]]) -> list[str]:
    return [str(child.get("detail") or f"{child.get('kind')} did not complete") for child in children if child.get("status") in {"failed", "blocked"}]


def _errors_from(exc: Exception) -> list[str]:
    values = getattr(exc, "errors", None)
    if isinstance(values, list):
        return [str(value.get("reason") if isinstance(value, dict) else value) for value in values]
    return [str(exc)]


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value.strip()))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
