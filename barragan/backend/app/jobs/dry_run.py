# Copyright (c) 2026, Oracle and/or its affiliates.
from app.domain import JobEvent, transition_job_status


PLAN_ONLY_ACTIONS = {
    "compile_revision",
    "render_git_artifacts",
    "deploy_plan",
    "archive_plan",
    "route_repair_plan",
}


def run_plan_only_job(action: str) -> tuple[str, list[JobEvent], list[str]]:
    if action not in PLAN_ONLY_ACTIONS:
        raise ValueError(f"unsupported plan-only action: {action}")

    status = transition_job_status("queued", "running")
    events = [
        JobEvent(1, "info", "job started", {"action": action, "mode": "dry_run"}),
        JobEvent(2, "info", "no live infrastructure mutation performed", {"mutation": False}),
    ]
    status = transition_job_status(status, "succeeded")
    events.append(JobEvent(3, "info", "job succeeded", {"status": status}))
    return status, events, [f"dry-run:{action}"]
