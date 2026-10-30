# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import argparse
import json
import sys

from app.core.config import Config
from app.core.runtime import initialize_runtime, runtime_context
from app.services.sketch_provider_contract_capture import (
    CaptureRequest,
    SketchProviderContractCaptureError,
    capture_sketch_provider_contract,
)


class OpaqueArgumentError(ValueError):
    pass


class OpaqueArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise OpaqueArgumentError("invalid command arguments")


def main(argv: list[str] | None = None) -> int:
    parser = OpaqueArgumentParser(description="Capture a DevTest sketch provider plan contract without applying it.")
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument("--chain-id", required=True)
    parser.add_argument("--channel-id", required=True)
    parser.add_argument("--scenario", required=True, choices=("add", "no-op", "remove"))
    parser.add_argument("--capture-id", required=True)
    try:
        args = parser.parse_args(argv)
    except OpaqueArgumentError:
        print(json.dumps({"status": "rejected", "reason": "invalid command arguments"}, sort_keys=True), file=sys.stderr)
        return 2
    try:
        runtime = initialize_runtime(Config, make_default=True)
        with runtime_context(runtime):
            result = capture_sketch_provider_contract(
                CaptureRequest(args.engagement_id, args.chain_id, args.channel_id, args.scenario, args.capture_id),
                data_dir=Config.DATA_DIR,
                environment=Config.ENVIRONMENT,
            )
    except SketchProviderContractCaptureError:
        print(json.dumps({"status": "rejected", "reason": "capture request rejected"}, sort_keys=True), file=sys.stderr)
        return 1
    except Exception:
        # Do not let provider diagnostics, credentials, variables, or host
        # paths escape through an unhandled CLI traceback.
        print(json.dumps({"status": "failed", "reason": "capture failed; inspect private host artifacts"}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps({"status": "captured", **result.to_dict()}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
