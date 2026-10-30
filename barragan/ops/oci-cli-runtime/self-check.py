#!/usr/bin/env python3
# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only CLI output-shape check for the isolated DevTest OCI runtime.

Run as the barragan service user with a scrubbed environment. Exact live and
retired IDs must come from a separately reviewed, owned disposable engagement.
"""

import argparse
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys


KINDS = {
    "vcn": ("network", "vcn", "--vcn-id", "ocid1.vcn."),
    "dhcp-options": ("network", "dhcp-options", "--dhcp-id", "ocid1.dhcpoptions."),
    "internet-gateway": ("network", "internet-gateway", "--ig-id", "ocid1.internetgateway."),
    "nat-gateway": ("network", "nat-gateway", "--nat-gateway-id", "ocid1.natgateway."),
    "route-table": ("network", "route-table", "--rt-id", "ocid1.routetable."),
    "security-list": ("network", "security-list", "--security-list-id", "ocid1.securitylist."),
    "subnet": ("network", "subnet", "--subnet-id", "ocid1.subnet."),
    "instance": ("compute", "instance", "--instance-id", "ocid1.instance."),
}
CLI_WARNING_FILTER = "ignore:The 'strict' parameter is no longer needed on Python 3+:FutureWarning:urllib3.poolmanager"
EXPECTED_ENVIRONMENT = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "PYTHONWARNINGS": CLI_WARNING_FILTER,
}


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oci", required=True, type=Path)
    parser.add_argument("--region", required=True)
    parser.add_argument("--compartment-id", required=True)
    parser.add_argument("--live-kind", required=True, choices=KINDS)
    parser.add_argument("--live-id", required=True)
    parser.add_argument("--retired-kind", required=True, choices=KINDS)
    parser.add_argument("--retired-id", required=True)
    return parser.parse_args()


def run(argv):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=60, check=False)
    return result.returncode, result.stdout, result.stderr


def check_json(code, stdout, stderr, expected_type):
    if code != 0 or stderr.strip():
        raise ValueError("OCI read failed or emitted unexpected stderr")
    value = json.loads(stdout)
    if type(value) is not dict or type(value.get("data")) is not expected_type:
        raise ValueError("OCI response data shape differs")
    return value["data"]


def require_service_environment():
    try:
        service_uid = pwd.getpwnam("barragan").pw_uid
    except KeyError:
        raise ValueError("barragan service user is unavailable") from None
    if os.geteuid() != service_uid:
        raise ValueError("self-check must run as barragan")
    if dict(os.environ) != EXPECTED_ENVIRONMENT:
        raise ValueError("self-check requires the documented clean environment")


def main():
    require_service_environment()
    args = parse_args()
    if not args.oci.is_absolute() or args.oci.is_symlink() or not args.oci.is_file():
        raise ValueError("OCI executable must be a real absolute file")
    if not re.fullmatch(r"[a-z]{2}-[a-z]+-[0-9]+", args.region):
        raise ValueError("region differs")
    if not re.fullmatch(r"ocid1.compartment.oc[0-9]+.[A-Za-z0-9_.-]+", args.compartment_id):
        raise ValueError("compartment ID differs")
    for kind, resource_id in ((args.live_kind, args.live_id), (args.retired_kind, args.retired_id)):
        if not resource_id.startswith(KINDS[kind][3]) or not re.fullmatch(r"ocid1\.[A-Za-z0-9_.-]+", resource_id):
            raise ValueError("resource ID kind differs")
    if args.live_id == args.retired_id:
        raise ValueError("live and retired IDs must differ")
    base = (str(args.oci), "--auth", "instance_principal", "--region", args.region,
            "--output", "json", "--no-retry")
    version = run((str(args.oci), "--version"))
    if version[0] != 0 or version[1].strip() != "3.84.0" or version[2].strip():
        raise ValueError("OCI CLI version differs")
    lists = {}
    for kind in KINDS:
        service, name, _, _ = KINDS[kind]
        data = check_json(*run(base + (service, name, "list", "--compartment-id",
                                      args.compartment_id, "--all")), list)
        if any(type(row) is not dict or not isinstance(row.get("id"), str) for row in data):
            raise ValueError("OCI list row shape differs")
        lists[kind] = {row["id"] for row in data}
        if len(lists[kind]) != len(data):
            raise ValueError("OCI list contains duplicate IDs")
    if args.live_id not in lists[args.live_kind] or args.retired_id in lists[args.retired_kind]:
        raise ValueError("exact ID and complete list visibility differ")
    service, name, flag, _ = KINDS[args.live_kind]
    live = check_json(*run(base + (service, name, "get", flag, args.live_id)), dict)
    if live.get("id") != args.live_id or live.get("compartment-id") != args.compartment_id:
        raise ValueError("live exact GET identity differs")
    service, name, flag, _ = KINDS[args.retired_kind]
    code, stdout, stderr = run(base + (service, name, "get", flag, args.retired_id))
    match = re.fullmatch(r"\s*ServiceError:\s*(\{.*\})\s*", stderr, re.S)
    if code == 0 or stdout.strip() or not match:
        raise ValueError("retired exact GET 404 shape differs")
    error = json.loads(match.group(1))
    if type(error) is not dict or error.get("status") != 404 or error.get("code") != "NotAuthorizedOrNotFound":
        raise ValueError("retired exact GET 404 status differs")
    print("OCI CLI 3.84.0 list/get/404 shapes compatible for the supplied owned IDs")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print(f"OCI CLI self-check failed: {exc}", file=sys.stderr)
        sys.exit(1)
