# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import argparse
import json
import os

from app.core.config import Config
from app.core.runtime import initialize_runtime, runtime_context
from app.services.engagement_dns import set_dns01_challenge, wait_for_dns01_challenge


def main() -> int:
    parser = argparse.ArgumentParser(description="Barragan Certbot DNS-01 hook")
    parser.add_argument("operation", choices=("auth", "cleanup"))
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument("--identifier", default="")
    parser.add_argument("--credential-alias", default="default")
    parser.add_argument("--propagation-timeout", type=int, default=600)
    args = parser.parse_args()

    identifier = (args.identifier or os.environ.get("CERTBOT_IDENTIFIER") or os.environ.get("CERTBOT_DOMAIN") or "").strip().lower()
    validation = (os.environ.get("CERTBOT_VALIDATION") or "").strip()
    if not identifier or not validation:
        parser.error("Certbot did not provide an identifier and validation value")

    os.environ.setdefault("BARRAGAN_INSPECTOR_SCHEDULER_ENABLED", "0")
    os.environ.setdefault("BARRAGAN_CERTIFICATE_SCHEDULER_ENABLED", "0")
    runtime = initialize_runtime(Config, make_default=True)
    with runtime_context(runtime):
        result = set_dns01_challenge(
            args.engagement_id,
            identifier,
            validation,
            present=args.operation == "auth",
            credential_alias=args.credential_alias,
        )
        if args.operation == "auth":
            try:
                propagation = wait_for_dns01_challenge(
                    identifier,
                    validation,
                    zone=str(result["domainName"]),
                    timeout_seconds=args.propagation_timeout,
                )
            except Exception:
                # Certbot may not invoke its cleanup hook when the auth hook
                # itself fails, so retire the exact value before surfacing the
                # propagation error.
                set_dns01_challenge(
                    args.engagement_id,
                    identifier,
                    validation,
                    present=False,
                    credential_alias=args.credential_alias,
                )
                raise
            result = {**result, **propagation}
    # Never print CERTBOT_VALIDATION. Certbot feeds this output back only to cleanup.
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
