# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_teardown_targets(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    canonical: list[dict[str, Any]] = []
    for target in targets:
        target_type = str(target.get("type") or "")
        host = str(target.get("host") or "").strip()
        if target_type == "tcp-forbidden" and host:
            try:
                port = int(target.get("port"))
            except (TypeError, ValueError):
                continue
            canonical.append({"id": str(target.get("id") or f"tcp:{host}:{port}"), "type": target_type, "host": host, "port": port})
        elif target_type == "dns-absent" and host:
            expected_ip = str(target.get("expectedIp") or "")
            canonical.append({"id": str(target.get("id") or f"dns:{host}" + (f":{expected_ip}" if expected_ip else "")), "type": target_type, "host": host, **({"expectedIp": expected_ip} if expected_ip else {})})
    return sorted(canonical, key=lambda row: json.dumps(row, sort_keys=True))


def teardown_target_sha256(targets: list[dict[str, Any]]) -> str:
    payload = canonical_teardown_targets(targets)
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
