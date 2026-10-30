# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


PROFILE_FILE_ENV = "BARRAGAN_OCI_COMPUTE_PROFILES_FILE"
SUPPORTED_TEMPLATES = ("standard-rti", "dev-infra", "small-dev-infra")
_ROLE_NAMES = ("homebase", "proxy", "elk")


class OciComputeProfileError(ValueError):
    pass


@dataclass(frozen=True)
class OciComputeRole:
    shape: str
    ocpus: int
    memory_in_gbs: int

    @property
    def is_flex(self) -> bool:
        return self.shape.endswith(".Flex")

    def to_dict(self) -> dict[str, Any]:
        return {"shape": self.shape, "ocpus": self.ocpus, "memoryInGbs": self.memory_in_gbs}


@dataclass(frozen=True)
class OciComputeProfile:
    template_id: str
    homebase: OciComputeRole
    proxy: OciComputeRole
    elk: OciComputeRole
    boot_volume_size_in_gbs: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "templateId": self.template_id,
            "homebase": self.homebase.to_dict(),
            "proxy": self.proxy.to_dict(),
            "elk": self.elk.to_dict(),
            "bootVolumeSizeInGbs": self.boot_volume_size_in_gbs,
        }

    @property
    def fingerprint(self) -> str:
        encoded = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


def load_oci_compute_profiles(path: str | Path) -> dict[str, OciComputeProfile]:
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OciComputeProfileError(f"OCI compute profile registry could not be loaded: {exc}") from exc
    if not isinstance(payload, Mapping) or set(payload) != {"version", "profiles"} or payload.get("version") != 1:
        raise OciComputeProfileError("OCI compute profile registry must contain only version=1 and profiles")
    raw_profiles = payload.get("profiles")
    if not isinstance(raw_profiles, Mapping) or set(raw_profiles) != set(SUPPORTED_TEMPLATES):
        raise OciComputeProfileError(
            "OCI compute profile registry must define exactly standard-rti, dev-infra, and small-dev-infra"
        )
    return {template_id: _parse_profile(template_id, raw_profiles[template_id]) for template_id in SUPPORTED_TEMPLATES}


def resolve_oci_compute_profile(
    template_id: str,
    *,
    env: Mapping[str, str] | None = None,
    environment: str | None = None,
) -> OciComputeProfile:
    if template_id not in SUPPORTED_TEMPLATES:
        raise OciComputeProfileError(f"no OCI compute profile is allowed for template {template_id}")
    lookup = env if env is not None else os.environ
    configured = str(lookup.get(PROFILE_FILE_ENV) or "").strip()
    runtime_environment = environment if environment is not None else str(lookup.get("BARRAGAN_ENV") or "local")
    if not configured:
        if runtime_environment == "production":
            raise OciComputeProfileError(f"{PROFILE_FILE_ENV} is required in production")
        # Local/dev compatibility is deliberately deterministic. Deployed units
        # always configure the root-managed registry, while isolated tests may
        # inject a registry or use this identical canonical contract.
        return canonical_oci_compute_profiles()[template_id]
    return load_oci_compute_profiles(configured)[template_id]


def canonical_oci_compute_profiles() -> dict[str, OciComputeProfile]:
    flex_2_32 = OciComputeRole("VM.Standard.E4.Flex", 2, 32)
    return {
        "standard-rti": OciComputeProfile(
            "standard-rti", OciComputeRole("BM.Standard3.64", 64, 1024), flex_2_32, flex_2_32, 512
        ),
        "dev-infra": OciComputeProfile(
            "dev-infra", OciComputeRole("VM.Standard.E4.Flex", 16, 512), flex_2_32, flex_2_32, 512
        ),
        # ELK is unavailable on this template.  The schema still carries an
        # unused ELK role so every profile has one stable, validated shape.
        "small-dev-infra": OciComputeProfile(
            "small-dev-infra",
            OciComputeRole("VM.Standard.E4.Flex", 4, 64),
            OciComputeRole("VM.Standard.E4.Flex", 1, 8),
            OciComputeRole("VM.Standard.E4.Flex", 1, 8),
            128,
        ),
    }


def oci_compute_profile_from_snapshot(value: Mapping[str, Any]) -> OciComputeProfile:
    template_id = str(value.get("templateId") or "")
    if template_id not in SUPPORTED_TEMPLATES:
        raise OciComputeProfileError("OCI compute profile snapshot has an unsupported templateId")
    return _parse_profile(template_id, value)


def _parse_profile(template_id: str, value: Any) -> OciComputeProfile:
    if not isinstance(value, Mapping):
        raise OciComputeProfileError(f"profile {template_id} must be an object")
    allowed = {"templateId", "homebase", "proxy", "elk", "bootVolumeSizeInGbs"}
    if set(value) != allowed or value.get("templateId") != template_id:
        raise OciComputeProfileError(f"profile {template_id} has invalid fields or templateId")
    roles = {role: _parse_role(template_id, role, value.get(role)) for role in _ROLE_NAMES}
    boot = value.get("bootVolumeSizeInGbs")
    if not isinstance(boot, int) or isinstance(boot, bool) or boot < 50:
        raise OciComputeProfileError(f"profile {template_id} bootVolumeSizeInGbs must be an integer of at least 50")
    return OciComputeProfile(template_id, roles["homebase"], roles["proxy"], roles["elk"], boot)


def _parse_role(template_id: str, role: str, value: Any) -> OciComputeRole:
    if not isinstance(value, Mapping) or set(value) != {"shape", "ocpus", "memoryInGbs"}:
        raise OciComputeProfileError(f"profile {template_id} role {role} has invalid fields")
    shape = value.get("shape")
    ocpus = value.get("ocpus")
    memory = value.get("memoryInGbs")
    if not isinstance(shape, str) or not shape.strip():
        raise OciComputeProfileError(f"profile {template_id} role {role} shape is required")
    for label, number in (("ocpus", ocpus), ("memoryInGbs", memory)):
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            raise OciComputeProfileError(f"profile {template_id} role {role} {label} must be a positive integer")
    return OciComputeRole(shape.strip(), ocpus, memory)
