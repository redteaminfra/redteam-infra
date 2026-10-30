# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import argparse
import json
import sys

from app.core.config import Config
from app.core.runtime import initialize_runtime, runtime_context
from app.integrations.ubuntu_image_inventory import collect_ubuntu_image_inventory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only Ubuntu 24.04 image inventory for OCI, Linode, and DigitalOcean."
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args(argv)

    runtime = initialize_runtime(Config, make_default=True)
    with runtime_context(runtime):
        result = collect_ubuntu_image_inventory()
    print(json.dumps(result.to_dict(), indent=2 if args.pretty else None, sort_keys=True))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
