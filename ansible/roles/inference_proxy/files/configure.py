#!/usr/bin/env python3
# Copyright (c) 2026, Oracle and/or its affiliates.
"""Update role-owned TOML keys, retaining operator limits, aliases and policy."""

import json
import os
from pathlib import Path
import re
import sys
import tempfile

def configure(path, example, region, compartment, port, *, check_only=False):
    target = Path(path)
    if target.is_symlink():
        raise ValueError("configuration path must not be a symlink")
    if check_only and not target.exists():
        # Fresh-host preflight needs no TOML dependency or staged source files.
        return {"changed": False}
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib
    text = target.read_text() if target.exists() else Path(example).read_text()
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        raise ValueError("existing configuration is invalid; review it before repair") from None
    if any(not isinstance(parsed.get(section, {}), dict) for section in ("server", "oci", "storage")):
        raise ValueError("existing configuration sections must be tables")
    if target.exists() and parsed.get("oci", {}).get("auth", "instance_principal") != "instance_principal":
        raise ValueError("existing OCI authentication requires operator migration; credentials were not changed")
    expected_storage = {
        "database": "/var/lib/inference-proxy/proxy.db",
        "pepper": "/etc/inference-proxy/pepper",
        "catalog_cache": "/var/lib/inference-proxy/model-catalog.json",
    }
    for key, value in expected_storage.items():
        if parsed.get("storage", {}).get(key, value) != value:
            raise ValueError("existing nonstandard storage paths require operator migration; data was not moved")
    managed = {
        "server": {"host": "127.0.0.1", "port": int(port)},
        "oci": {"region": region, "compartment_id": compartment, "auth": "instance_principal"},
        "storage": expected_storage,
    }
    if target.exists():
        existing_server = parsed.get("server", {})
        existing_oci = parsed.get("oci", {})
        if (
            existing_server.get("host", "127.0.0.1") != "127.0.0.1"
            or existing_server.get("port", 8787) != int(port)
            or existing_oci.get("region", "us-chicago-1") != region
            or existing_oci.get("compartment_id") != compartment
        ):
            raise ValueError("existing listener, region or model compartment requires explicit operator migration")
    if check_only:
        return {"changed": False}
    # JSON string quoting is valid TOML basic-string quoting for these validated values.
    output = []
    section = None
    seen_sections = set()
    seen_keys = set()

    def finish():
        if section in managed:
            for key, value in managed[section].items():
                if key not in seen_keys:
                    output.append(f"{key} = {json.dumps(value)}\n")

    for line in text.splitlines(keepends=True):
        match = re.match(r"^\s*\[([^\[\]]+)\]\s*(?:#.*)?$", line.rstrip("\n"))
        if match:
            finish()
            section = match.group(1).strip()
            seen_sections.add(section)
            seen_keys = set()
        assignment = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*=", line)
        if section in managed and assignment and assignment.group(1) in managed[section]:
            key = assignment.group(1)
            seen_keys.add(key)
            output.append(f"{key} = {json.dumps(managed[section][key])}\n")
        else:
            output.append(line if line.endswith("\n") else line + "\n")
    finish()
    for name, values in managed.items():
        if name not in seen_sections:
            output.append(f"\n[{name}]\n")
            output.extend(f"{key} = {json.dumps(value)}\n" for key, value in values.items())
    updated = "".join(output)
    tomllib.loads(updated)  # Fail closed before replacing an existing file.
    if target.exists() and updated == text:
        return {"changed": False}
    descriptor, temporary = tempfile.mkstemp(prefix=".config-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "w") as handle:
            os.fchmod(handle.fileno(), 0o640)
            if target.exists():
                original = target.stat()
                os.fchown(handle.fileno(), original.st_uid, original.st_gid)
            handle.write(updated)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {"changed": True}


if __name__ == "__main__":
    try:
        arguments = sys.argv[1:]
        check = bool(arguments and arguments[0] == "--check")
        print(json.dumps(configure(*(arguments[1:] if check else arguments), check_only=check)))
    except (ValueError, OSError) as exc:
        sys.exit(str(exc))
