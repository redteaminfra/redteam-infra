# Copyright (c) 2026, Oracle and/or its affiliates.
"""One-shot, read-only DevTest Linode raw capture for a held mixed build.

Run as the Barragan service user from a clean deployed checkout. This module
does not initialize or migrate the database, and never marks hosts ready.
"""

from __future__ import annotations

import os
import sys


def capture_mixed_linode_raw_diagnostic(engagement_id: str, core_job_id: str, **kwargs):
    from app.services.provider_keyed_mixed_linode_diagnostic import (
        capture_mixed_linode_identity_diagnostic,
    )

    return capture_mixed_linode_identity_diagnostic(
        engagement_id, core_job_id, environment="devtest", collect_raw=True, **kwargs)


def main(argv: list[str] | None = None) -> int:
    values = sys.argv[1:] if argv is None else argv
    if len(values) != 2 or not values[0].startswith("eng-") or not values[1].startswith("job-"):
        raise SystemExit("usage: python -m app.services.provider_keyed_mixed_linode_raw_diagnostic ENG_ID CORE_JOB_ID")
    expected_dir = "/var/lib/barragan/devtest-data"
    expected_uri = "sqlite:////var/lib/barragan/devtest-data/barragan.sqlite3"
    if os.environ.get("BARRAGAN_ENV") != "devtest" or os.environ.get("BARRAGAN_DATA_DIR") != expected_dir:
        raise SystemExit("explicit DevTest environment and data directory are required")
    from app.core.config import Config
    from app.core.runtime import configure_runtime, runtime_context
    from app.storage.database import db

    if Config.SQLALCHEMY_DATABASE_URI != expected_uri:
        raise SystemExit("DevTest database URI differs")
    state = configure_runtime(Config, db.configure(expected_uri))
    with runtime_context(state):
        result = capture_mixed_linode_raw_diagnostic(*values)
    print(f"{result.id} {result.status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
