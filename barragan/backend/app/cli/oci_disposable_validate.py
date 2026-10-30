# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.integrations.oci_disposable_terraform import (
    EXECUTION_CONFIRMATION,
    build_disposable_terraform_workspace,
    execute_disposable_terraform_validation,
    render_disposable_terraform_workspace,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Preview or render the disposable OCI Terraform validation workspace."
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    parser.add_argument(
        "--include-content",
        action="store_true",
        help="Include rendered artifact content in JSON preview output.",
    )
    parser.add_argument(
        "--render-dir",
        type=Path,
        help="Optional destination directory for the local Terraform validation workspace.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help=(
            "Run the guarded Terraform create/destroy validation. Requires --render-dir, "
            "--confirm-mutation, and --confirm-destroy-cleanup."
        ),
    )
    parser.add_argument(
        "--confirm-mutation",
        help=f"Required exact value for --execute: {EXECUTION_CONFIRMATION}",
    )
    parser.add_argument(
        "--confirm-destroy-cleanup",
        action="store_true",
        help="Required with --execute to confirm the disposable resource will be destroyed.",
    )
    args = parser.parse_args(argv)

    if args.execute:
        if not args.render_dir:
            parser.error("--execute requires --render-dir")
        if args.confirm_mutation != EXECUTION_CONFIRMATION:
            parser.error(f"--execute requires --confirm-mutation {EXECUTION_CONFIRMATION}")
        if not args.confirm_destroy_cleanup:
            parser.error("--execute requires --confirm-destroy-cleanup")
        body = execute_disposable_terraform_validation(args.render_dir).to_dict()
    elif args.render_dir:
        workspace = render_disposable_terraform_workspace(args.render_dir)
        body = workspace.to_dict(include_content=args.include_content)
        body["renderResult"] = {
            "root": str(args.render_dir),
            "artifactCount": len(workspace.artifacts),
            "mutation": False,
        }
    else:
        body = build_disposable_terraform_workspace().to_dict(include_content=args.include_content)
        body["renderResult"] = None

    print(json.dumps(body, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if body["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
