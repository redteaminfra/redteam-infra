# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from app.services.access_plans import PlatformAccessUser
from app.services.deployment_orchestrator import plan_standard_rti_deployment
from app.services.engagements import create_draft_engagement
from app.services.jobs import enqueue_job, run_job
from app.services.revisions import create_revision
from app.storage.engagement_repository import SqliteEngagementRepository
from app.storage.job_repository import SqliteJobRepository
from app.storage.revision_repository import SqliteRevisionRepository


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a dependency-free Barragan local workflow smoke.")
    parser.add_argument("--database", required=True, type=Path, help="SQLite database path for persisted workflow state.")
    parser.add_argument("--input", required=True, type=Path, help="Standard RTI JSON input fixture.")
    parser.add_argument("--render-dir", type=Path, help="Optional destination for local Git-visible artifacts.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args(argv)

    body = run_local_workflow(
        database_path=args.database,
        input_path=args.input,
        render_dir=args.render_dir,
    )
    print(json.dumps(body, indent=2 if args.pretty else None, sort_keys=True))
    return 0


def run_local_workflow(
    database_path: Path,
    input_path: Path,
    render_dir: Path | None = None,
) -> dict[str, Any]:
    input_parameters = _load_input(input_path)
    engagements = SqliteEngagementRepository(database_path)
    revisions = SqliteRevisionRepository(database_path)
    jobs = SqliteJobRepository(database_path)

    engagement = create_draft_engagement(
        {
            "templateId": "standard-rti",
            "owner": "operator@example.invalid",
            "inputParameters": input_parameters,
        },
        repository=engagements,
    )
    revision = create_revision(
        engagement.id,
        revision_repository=revisions,
        engagement_repository=engagements,
    )
    queued_job = enqueue_job(
        action="deploy_plan",
        target_type="revision",
        target_id=revision["id"],
        requested_by="operator@example.invalid",
        input_data={"mode": "dry_run"},
        repository=jobs,
    )
    completed_job = run_job(queued_job.id, repository=jobs)
    plan = plan_standard_rti_deployment(
        engagement_id=engagement.id,
        input_parameters=input_parameters,
        access_users=[
            PlatformAccessUser(
                user_id="user-local-workflow",
                username="operator",
                credential_ref="secret://users/operator",
                privileges=["view", "operate"],
            )
        ],
        render_destination=render_dir,
        render_job_id=completed_job.id,
    )

    return {
        "engagement": engagement.to_dict(),
        "revision": revision,
        "job": completed_job.to_dict(),
        "plan": plan.to_dict(),
        "database": str(database_path),
    }


def _load_input(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("input JSON must be an object")
    return data


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
