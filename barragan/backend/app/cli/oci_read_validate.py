# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import argparse
import json
import sys

from app.integrations.oci_read_validation import (
    OciDevelopmentTarget,
    build_read_checks,
    resolve_oci_cli,
    run_read_validation,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run non-mutating OCI instance-principal read validation for Barragan."
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    parser.add_argument(
        "--print-commands",
        action="store_true",
        help="Print the read-only OCI commands without running them.",
    )
    args = parser.parse_args(argv)

    target = OciDevelopmentTarget()
    if args.print_commands:
        oci_resolution = resolve_oci_cli()
        body = {
            "ok": oci_resolution.ok,
            "mode": "read_only",
            "mutation": False,
            "target": target.to_dict(),
            "commandResolution": {
                "binaryName": oci_resolution.binary_name,
                "command": oci_resolution.command,
                "source": oci_resolution.source,
                "overrideVariables": list(oci_resolution.override_variables),
                "ok": oci_resolution.ok,
                "error": oci_resolution.error,
            },
            "checks": [
                check.to_dict()
                for check in build_read_checks(target, oci_resolution.command or "oci")
            ],
        }
    else:
        body = run_read_validation(target).to_dict()

    print(json.dumps(body, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if body["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
