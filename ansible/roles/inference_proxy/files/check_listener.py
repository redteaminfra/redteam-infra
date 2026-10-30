#!/usr/bin/env python3
# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only Linux socket ownership guard; requires no installed application."""

import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys


CONFIG_PATH = Path("/etc/inference-proxy/config.toml")
SERVER_PATH = "/opt/inference-proxy/venv/bin/inference-proxy-server"
CONFIG_ENV = f"INFERENCE_PROXY_CONFIG={CONFIG_PATH}"


def service_properties():
    result = subprocess.run(
        ["systemctl", "show", "inference-proxy.service",
         "--property=LoadState,MainPID,ExecStart,Environment,EnvironmentFiles"],
        capture_output=True, text=True, timeout=5, check=False,
    )
    properties = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    if result.returncode != 0 and properties.get("LoadState") != "not-found":
        raise ValueError("cannot verify existing service identity")
    return properties


def verify_binding(properties, proc_root, main_pid, config_path):
    # A named unit's socket is not proof that it reads the canonical config.
    # Inspect both the next-start definition and the running process environment:
    # EnvironmentFile/UnsetEnvironment or a daemon-reload can make them differ.
    expected_exec = re.escape(SERVER_PATH)
    if not re.fullmatch(
        r"\{ path=" + expected_exec + r" ; argv\[\]=" + expected_exec + r" ; [^{}]* \}",
        properties.get("ExecStart", ""),
    ):
        raise ValueError("existing service command requires operator migration")
    environment = shlex.split(properties.get("Environment", ""))
    if [entry for entry in environment if entry.startswith("INFERENCE_PROXY_CONFIG=")] != [CONFIG_ENV]:
        raise ValueError("existing service configuration binding requires operator migration")
    if properties.get("EnvironmentFiles", ""):
        raise ValueError("existing service environment files require operator migration")
    if config_path.resolve(strict=True) != config_path or not stat.S_ISREG(config_path.stat().st_mode):
        raise ValueError("existing service needs its original canonical configuration")
    if main_pid == 0:
        return  # A stopped unit still needs a compatible definition and config.
    with (proc_root / str(main_pid) / "environ").open("rb") as handle:
        raw = handle.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024 or not raw.endswith(b"\0"):
        raise ValueError("cannot verify running service configuration binding")
    if [entry for entry in raw.split(b"\0") if entry.startswith(b"INFERENCE_PROXY_CONFIG=")] != [CONFIG_ENV.encode()]:
        raise ValueError("running service configuration binding requires operator migration")


def check_listener(port, *, proc_root=Path("/proc"), properties=None, config_path=CONFIG_PATH):
    port = int(port)
    sockets = []
    for protocol in ("tcp", "tcp6"):
        table = proc_root / "net" / protocol
        if protocol == "tcp6" and not table.exists():
            continue
        # An unreadable or malformed table must not be treated as an idle port.
        for line in table.read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10:
                raise ValueError("cannot verify local listener table")
            address, local_port = fields[1].rsplit(":", 1)
            if fields[3] == "0A" and int(local_port, 16) == port:
                sockets.append((protocol, address, fields[9]))
    live_query = properties is None
    properties = service_properties() if live_query else properties
    value = properties.get("MainPID", "")
    if not value.isdigit():
        raise ValueError("cannot verify existing service identity")
    main_pid = int(value)
    load_state = properties.get("LoadState")
    if load_state == "loaded":
        verify_binding(properties, proc_root, main_pid, config_path)
    elif load_state != "not-found" or main_pid != 0:
        raise ValueError("existing service unit state requires operator recovery")
    if not sockets:
        if main_pid > 0:
            raise ValueError("running service does not own the requested listener; operator migration required")
        if live_query and service_properties() != properties:
            raise ValueError("existing service identity changed during preflight")
        return {"occupied": False, "owned_by_service": False}
    if main_pid <= 0:
        raise ValueError("requested port is occupied without a running inference-proxy service")
    try:
        descriptors = proc_root / str(main_pid) / "fd"
        owned = set()
        for descriptor in descriptors.iterdir():
            try:
                owned.add(os.readlink(descriptor))
            except FileNotFoundError:
                continue  # A descriptor may close during inspection.
    except OSError:
        raise ValueError("cannot verify existing service socket ownership") from None
    if any(
        protocol != "tcp" or address != "0100007F" or f"socket:[{inode}]" not in owned
        for protocol, address, inode in sockets
    ):
        raise ValueError("requested port is occupied by a foreign or non-loopback listener")
    if live_query and service_properties() != properties:
        raise ValueError("existing service identity changed during preflight")
    return {"occupied": True, "owned_by_service": True}


if __name__ == "__main__":
    try:
        print(json.dumps(check_listener(sys.argv[1])))
    except (ValueError, OSError, subprocess.SubprocessError):
        sys.exit("listener preflight failed; preserve existing services and resolve service/config identity and port ownership before applying")
