# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from pathlib import Path

from app.services.git_renderer import RenderResult, render_revision_plan
from app.services.revision_compiler import deployment_revision_from_dict
from app.services.revisions import get_revision


class RevisionRenderNotFoundError(LookupError):
    pass


def render_stored_revision(
    revision_id: str,
    destination: Path,
    render_job_id: str | None = None,
) -> RenderResult:
    revision = get_revision(revision_id)
    if revision is None:
        raise RevisionRenderNotFoundError("revision not found")

    plan = deployment_revision_from_dict(revision)
    return render_revision_plan(
        plan,
        destination,
        render_job_id=render_job_id or f"job-render-{revision_id}",
    )
