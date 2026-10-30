# Copyright (c) 2026, Oracle and/or its affiliates.
"""Pin the reviewed Terraform executable for the disposable keyed pilot.

This is a release gate, not a binary discovery mechanism. A later plan/apply
boundary must revalidate the mutable executable path; an earlier result is
not durable authorization.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
import subprocess
from app.services.provider_keyed_readonly_verification import run_readonly_verification
from dataclasses import dataclass
from pathlib import Path


_REVIEWED_PATH = Path("/usr/bin/terraform")
_REVIEWED_SHA256 = "d42b544fbd42bfab4f0ddfe1bd8ec985fbd59fb4fb7ff339d5f134c73e177279"
_REVIEWED_VERSION = "1.15.5"
_REVIEWED_PLATFORM = "linux_amd64"


class ProviderKeyedTerraformReleaseError(ValueError):
    """The DevTest Terraform executable is not the reviewed release."""


@dataclass(frozen=True)
class ProviderKeyedTerraformRelease:
    path: Path
    sha256: str
    version: str
    platform: str


def require_devtest_terraform_release(
    *, environment: str, terraform: str | Path = _REVIEWED_PATH,
) -> ProviderKeyedTerraformRelease:
    """Reject every runtime except the reviewed DevTest linux_amd64 binary.

    The digest is part of reviewed source, never supplied by the caller or
    learned from whatever executable happens to be installed.
    """

    if environment != "devtest":
        raise ProviderKeyedTerraformReleaseError("keyed Terraform requires DevTest")
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ProviderKeyedTerraformReleaseError("keyed Terraform requires linux_amd64")
    if not isinstance(terraform, (str, Path)) or str(terraform) != str(_REVIEWED_PATH):
        raise ProviderKeyedTerraformReleaseError("Terraform executable path is not reviewed")
    path = _REVIEWED_PATH
    try:
        if path.is_symlink():
            raise ProviderKeyedTerraformReleaseError("Terraform executable path is a symlink")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as binary:
            before = os.fstat(binary.fileno())
            if not stat.S_ISREG(before.st_mode) or not os.access(path, os.X_OK):
                raise ProviderKeyedTerraformReleaseError("Terraform executable is not a regular executable file")
            hasher = hashlib.sha256()
            for chunk in iter(lambda: binary.read(1024 * 1024), b""):
                hasher.update(chunk)
            digest = hasher.hexdigest()
            after = os.fstat(binary.fileno())
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
            ):
                raise ProviderKeyedTerraformReleaseError("Terraform executable changed during validation")
        current = path.stat()
        if digest != _REVIEWED_SHA256 or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise ProviderKeyedTerraformReleaseError("Terraform executable digest differs from reviewed release")
        result = run_readonly_verification(
            [str(path), "version", "-json"], capture_output=True, text=True,
            timeout=10, check=False, cwd="/",
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "TF_CLI_CONFIG_FILE": "/dev/null"},
            runner=subprocess.run,
        )
        if result.returncode != 0:
            raise ProviderKeyedTerraformReleaseError("Terraform executable version check failed")
        version = json.loads(result.stdout)
        if not isinstance(version, dict) or (
            version.get("terraform_version") != _REVIEWED_VERSION
            or version.get("platform") != _REVIEWED_PLATFORM
        ):
            raise ProviderKeyedTerraformReleaseError("Terraform executable version differs from reviewed release")
        # A path replacement during the version command must not pass.
        current = path.stat()
        if (path.is_symlink() or (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
                != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)):
            raise ProviderKeyedTerraformReleaseError("Terraform executable changed during validation")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, UnicodeError) as exc:
        raise ProviderKeyedTerraformReleaseError("Terraform executable validation failed") from exc
    return ProviderKeyedTerraformRelease(path, digest, _REVIEWED_VERSION, _REVIEWED_PLATFORM)
