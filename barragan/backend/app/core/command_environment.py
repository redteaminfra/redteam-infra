# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import os
from collections.abc import Mapping


DEFAULT_SUBPROCESS_SHELL = "/bin/sh"


def barragan_subprocess_env(
    base: Mapping[str, str] | None = None,
    *,
    shell: str = DEFAULT_SUBPROCESS_SHELL,
) -> dict[str, str]:
    """Return a safe default environment for Barragan-launched subprocesses.

    Barragan production jobs run as the local ``barragan`` service user. That
    Unix account intentionally has ``/usr/sbin/nologin`` as its login shell.
    OpenSSH executes ``ProxyCommand`` through the local user's shell, so SSH and
    Ansible subprocesses must receive a real shell in their environment even
    though the service account itself remains non-login.
    """

    env = dict(base or os.environ)
    env["SHELL"] = shell
    return env
