# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping


MANAGED_HOST_IMAGE_PROFILE_ENV = "BARRAGAN_MANAGED_HOST_IMAGE_PROFILE"
DEFAULT_MANAGED_HOST_IMAGE_PROFILE = "ubuntu-24.04"
ROLLBACK_MANAGED_HOST_IMAGE_PROFILE = "ubuntu-22.04"


@dataclass(frozen=True)
class ManagedHostImageProfile:
    name: str
    ubuntu_version: str
    linode_image: str
    digitalocean_image: str


MANAGED_HOST_IMAGE_PROFILES = {
    DEFAULT_MANAGED_HOST_IMAGE_PROFILE: ManagedHostImageProfile(
        name=DEFAULT_MANAGED_HOST_IMAGE_PROFILE,
        ubuntu_version="24.04",
        linode_image="linode/ubuntu24.04",
        digitalocean_image="ubuntu-24-04-x64",
    ),
    ROLLBACK_MANAGED_HOST_IMAGE_PROFILE: ManagedHostImageProfile(
        name=ROLLBACK_MANAGED_HOST_IMAGE_PROFILE,
        ubuntu_version="22.04",
        linode_image="linode/ubuntu22.04",
        digitalocean_image="ubuntu-22-04-x64",
    ),
}


def managed_host_image_profile(
    env: Mapping[str, str] | None = None,
) -> ManagedHostImageProfile:
    source = os.environ if env is None else env
    name = str(source.get(MANAGED_HOST_IMAGE_PROFILE_ENV) or DEFAULT_MANAGED_HOST_IMAGE_PROFILE).strip()
    try:
        return MANAGED_HOST_IMAGE_PROFILES[name]
    except KeyError as exc:
        supported = ", ".join(sorted(MANAGED_HOST_IMAGE_PROFILES))
        raise ValueError(
            f"{MANAGED_HOST_IMAGE_PROFILE_ENV} must be one of: {supported}"
        ) from exc
