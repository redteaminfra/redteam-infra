# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json

import pytest

from app.asgi import create_app
from app.core.config import TestConfig
from app.integrations.oci_compute_profiles import (
    OciComputeProfileError,
    canonical_oci_compute_profiles,
    load_oci_compute_profiles,
    resolve_oci_compute_profile,
)


def _registry() -> dict:
    profiles = canonical_oci_compute_profiles()
    return {"version": 1, "profiles": {key: value.to_dict() for key, value in profiles.items()}}


def test_external_registry_resolves_exact_template_profiles(tmp_path) -> None:
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps(_registry()), encoding="utf-8")

    standard = resolve_oci_compute_profile("standard-rti", env={"BARRAGAN_OCI_COMPUTE_PROFILES_FILE": str(path)})
    dev = resolve_oci_compute_profile("dev-infra", env={"BARRAGAN_OCI_COMPUTE_PROFILES_FILE": str(path)})
    small = resolve_oci_compute_profile("small-dev-infra", env={"BARRAGAN_OCI_COMPUTE_PROFILES_FILE": str(path)})

    assert standard.homebase.to_dict() == {"shape": "BM.Standard3.64", "ocpus": 64, "memoryInGbs": 1024}
    assert dev.homebase.to_dict() == {"shape": "VM.Standard.E4.Flex", "ocpus": 16, "memoryInGbs": 512}
    assert standard.proxy.to_dict() == dev.proxy.to_dict() == {
        "shape": "VM.Standard.E4.Flex", "ocpus": 2, "memoryInGbs": 32
    }
    assert standard.boot_volume_size_in_gbs == dev.boot_volume_size_in_gbs == 512
    assert small.homebase.to_dict() == {"shape": "VM.Standard.E4.Flex", "ocpus": 4, "memoryInGbs": 64}
    assert small.proxy.to_dict() == {"shape": "VM.Standard.E4.Flex", "ocpus": 1, "memoryInGbs": 8}
    assert small.boot_volume_size_in_gbs == 128
    assert standard.fingerprint != dev.fingerprint
    assert small.fingerprint not in {standard.fingerprint, dev.fingerprint}


def test_registry_rejects_unknown_fields_and_incomplete_template_mapping(tmp_path) -> None:
    payload = _registry()
    payload["profiles"]["standard-rti"]["homebase"]["arbitrary"] = True
    del payload["profiles"]["dev-infra"]
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(OciComputeProfileError):
        load_oci_compute_profiles(path)


def test_production_resolution_and_startup_fail_closed_without_registry(tmp_path) -> None:
    with pytest.raises(OciComputeProfileError, match="required in production"):
        resolve_oci_compute_profile("standard-rti", env={}, environment="production")

    class MissingRegistryConfig(TestConfig):
        ENVIRONMENT = "production"
        OCI_COMPUTE_PROFILES_FILE = ""

    with pytest.raises(OciComputeProfileError, match="required in production"):
        create_app(MissingRegistryConfig)

    class InvalidRegistryConfig(TestConfig):
        ENVIRONMENT = "production"
        OCI_COMPUTE_PROFILES_FILE = str(tmp_path / "missing.json")

    with pytest.raises(OciComputeProfileError, match="could not be loaded"):
        create_app(InvalidRegistryConfig)
