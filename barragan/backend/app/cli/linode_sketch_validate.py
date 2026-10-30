# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import argparse
import json
import secrets
import string
import sys
from datetime import datetime, timezone

from app.core.config import Config
from app.core.runtime import initialize_runtime, runtime_context
from app.integrations.linode_validation import (
    VALIDATION_CONFIRMATION,
    validate_linode_sketch_create_destroy,
)
from app.integrations.managed_host_images import managed_host_image_profile
from app.services.credentials import resolve_credential_secret


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run guarded Linode sketch create/destroy validation.")
    parser.add_argument("--alias", default="linode-barragan", help="Barragan Linode credential alias.")
    parser.add_argument("--region", default="us-sea", help="Linode region for the disposable validation instance.")
    parser.add_argument("--type", default="g6-nanode-1", help="Linode instance type for validation.")
    parser.add_argument(
        "--image",
        default=managed_host_image_profile().linode_image,
        help="Linode image for validation.",
    )
    parser.add_argument("--label", help="Optional disposable Linode label.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    parser.add_argument(
        "--confirm-create-destroy",
        help=f"Required exact value: {VALIDATION_CONFIRMATION}",
    )
    args = parser.parse_args(argv)

    if args.confirm_create_destroy != VALIDATION_CONFIRMATION:
        parser.error(f"--confirm-create-destroy must be {VALIDATION_CONFIRMATION}")

    label = args.label or f"barragan-validation-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    runtime = initialize_runtime(Config, make_default=True)
    with runtime_context(runtime):
        token = resolve_credential_secret("linode", args.alias)
        result = validate_linode_sketch_create_destroy(
            token=token,
            credential_alias=args.alias,
            label=label,
            region=args.region,
            image=args.image,
            linode_type=args.type,
            root_pass=_random_root_password(),
        )

    body = result.to_dict()
    print(json.dumps(body, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if body["ok"] else 1


def _random_root_password() -> str:
    alphabet = string.ascii_letters + string.digits + "-_!."
    return "Barragan-" + "".join(secrets.choice(alphabet) for _ in range(32))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
