# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from app.core.config import Config
from app.core.runtime import initialize_runtime, runtime_context
from app.integrations.digitalocean_validation import (
    DEFAULT_IMAGE,
    DEFAULT_REGION,
    DEFAULT_SIZE,
    VALIDATION_CONFIRMATION,
    validate_digitalocean_sketch_create_destroy,
)
from app.services.credentials import resolve_credential_secret


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run guarded DigitalOcean sketch create/destroy validation.")
    parser.add_argument("--alias", default="do-barragan", help="Barragan DigitalOcean credential alias.")
    parser.add_argument("--region", default=DEFAULT_REGION, help="DigitalOcean region for the disposable validation droplet.")
    parser.add_argument("--size", default=DEFAULT_SIZE, help="DigitalOcean droplet size for validation.")
    parser.add_argument("--image", default=DEFAULT_IMAGE, help="DigitalOcean image for validation.")
    parser.add_argument("--name", help="Optional disposable DigitalOcean droplet name.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    parser.add_argument(
        "--confirm-create-destroy",
        help=f"Required exact value: {VALIDATION_CONFIRMATION}",
    )
    args = parser.parse_args(argv)

    if args.confirm_create_destroy != VALIDATION_CONFIRMATION:
        parser.error(f"--confirm-create-destroy must be {VALIDATION_CONFIRMATION}")

    name = args.name or f"barragan-do-validation-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    runtime = initialize_runtime(Config, make_default=True)
    with runtime_context(runtime):
        token = resolve_credential_secret("digitalocean", args.alias)
        result = validate_digitalocean_sketch_create_destroy(
            token=token,
            credential_alias=args.alias,
            name=name,
            region=args.region,
            image=args.image,
            size=args.size,
        )

    body = result.to_dict()
    print(json.dumps(body, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if body["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
