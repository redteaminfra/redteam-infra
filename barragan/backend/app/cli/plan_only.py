# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from app.services.access_plans import PlatformAccessUser
from app.services.deployment_orchestrator import plan_standard_rti_deployment


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a Barragan Standard RTI plan-only deployment smoke.")
    parser.add_argument("--engagement-id", default="eng-cli-smoke")
    parser.add_argument("--input", type=Path, help="Optional JSON file with Standard RTI input parameters.")
    parser.add_argument("--render-dir", type=Path, help="Optional destination for local Git-visible artifacts.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    parser.add_argument(
        "--run-provider-preflight",
        action="store_true",
        help="Run the read-only OCI provider preflight instead of emitting the default preview.",
    )
    args = parser.parse_args(argv)

    input_parameters = _load_input(args.input) if args.input else standard_rti_baseline_input()
    access_users = [
        PlatformAccessUser(
            user_id="user-cli-operator",
            username="operator",
            credential_ref="secret://users/operator",
            privileges=["view", "operate"],
        )
    ]
    result = plan_standard_rti_deployment(
        engagement_id=args.engagement_id,
        input_parameters=input_parameters,
        access_users=access_users,
        render_destination=args.render_dir,
        render_job_id="job-cli-render",
        run_provider_preflight=args.run_provider_preflight,
    )
    print(json.dumps(result.to_dict(), indent=2 if args.pretty else None, sort_keys=True))
    return 0


def standard_rti_baseline_input() -> dict[str, Any]:
    return {
        "engagementName": "cli-smoke",
        "proxyCount": 2,
        "elkEnabled": False,
        "sketchChains": [
            {
                "id": "chain-1",
                "assignedProxy": "proxy01",
                "middleProvider": "linode",
                "edgeProvider": "digitalocean",
            }
        ],
        "egressProfiles": [
            {
                "name": "default-sketch-egress",
                "sketchChainId": "chain-1",
                "listenerPort": 3333,
            }
        ],
        "ingressRoutes": [
            {
                "name": "default-ingress",
                "sketchChainId": "chain-1",
                "domain": "example.invalid",
            }
        ],
        "reverseChannels": [],
    }


def _load_input(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("input JSON must be an object")
    return data


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
