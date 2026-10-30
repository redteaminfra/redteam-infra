# Copyright (c) 2026, Oracle and/or its affiliates.
import pytest

from app.integrations.managed_host_images import (
    DEFAULT_MANAGED_HOST_IMAGE_PROFILE,
    MANAGED_HOST_IMAGE_PROFILE_ENV,
    ROLLBACK_MANAGED_HOST_IMAGE_PROFILE,
    managed_host_image_profile,
)
from app.integrations.ansible_disposable_validation import _variables_tf as validation_variables_tf
from app.integrations.oci_read_validation import OciDevelopmentTarget
from app.integrations.pilot_standard_rti import _variables_tf as core_variables_tf


def test_managed_hosts_default_to_ubuntu_2404():
    profile = managed_host_image_profile({})

    assert profile.name == DEFAULT_MANAGED_HOST_IMAGE_PROFILE
    assert profile.ubuntu_version == "24.04"
    assert profile.linode_image == "linode/ubuntu24.04"
    assert profile.digitalocean_image == "ubuntu-24-04-x64"


def test_managed_hosts_have_complete_ubuntu_2204_rollback_profile():
    profile = managed_host_image_profile(
        {MANAGED_HOST_IMAGE_PROFILE_ENV: ROLLBACK_MANAGED_HOST_IMAGE_PROFILE}
    )

    assert profile.ubuntu_version == "22.04"
    assert profile.linode_image == "linode/ubuntu22.04"
    assert profile.digitalocean_image == "ubuntu-22-04-x64"


def test_unknown_managed_host_image_profile_fails_closed():
    with pytest.raises(ValueError, match=MANAGED_HOST_IMAGE_PROFILE_ENV):
        managed_host_image_profile({MANAGED_HOST_IMAGE_PROFILE_ENV: "ubuntu-latest"})


def test_oci_renderers_use_default_managed_host_image_profile(monkeypatch):
    monkeypatch.delenv(MANAGED_HOST_IMAGE_PROFILE_ENV, raising=False)

    assert 'default     = "24.04"' in validation_variables_tf()
    assert 'default     = "24.04"' in core_variables_tf(OciDevelopmentTarget())


def test_oci_renderers_honor_complete_rollback_profile(monkeypatch):
    monkeypatch.setenv(
        MANAGED_HOST_IMAGE_PROFILE_ENV,
        ROLLBACK_MANAGED_HOST_IMAGE_PROFILE,
    )

    assert 'default     = "22.04"' in validation_variables_tf()
    assert 'default     = "22.04"' in core_variables_tf(OciDevelopmentTarget())
