# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.services.capability_catalog import CapabilityCatalog, discover_capability_catalog
from app.services.redteam_infra_template import RedteamInfraTemplateSource


STANDARD_RTI_PROFILE_ID = "standard-rti"
STANDARD_RTI_PROFILE_NAME = "Standard RTI"
CORE_PROVIDER_CAPABILITIES = {"aws", "oci"}
DEFAULT_CORE_PROVIDER = "oci"

STANDARD_RTI_POLICY: dict[str, dict[str, tuple[str, ...]]] = {
    "common": {
        "essential": ("common", "molly-guard", "logstash", "yama"),
        "default": (),
        "optional": (),
    },
    "homebase": {
        "essential": ("nfs-server", "engagement-workspace", "homebase"),
        "default": ("etherpad", "google-chrome", "firefox", "keepassxc", "vs-code"),
        "optional": (),
    },
    "proxy": {
        "essential": ("docker", "nfs-client", "nmap", "ssh-proxy", "dante-server", "unattended-upgrades", "proxies"),
        "default": (),
        "optional": (),
    },
    "elk": {
        "essential": (),
        "default": ("elk", "unattended-upgrades"),
        "optional": (),
    },
}


@dataclass(frozen=True)
class CapabilityProfileResolution:
    catalog: CapabilityCatalog
    profile: dict[str, Any]
    status: str
    host_classes: dict[str, dict[str, list[dict[str, Any]]]]
    summary: dict[str, int]
    warnings: tuple[dict[str, str], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": {
                "path": str(self.catalog.source.root),
                "kind": self.catalog.source.source,
                "warning": self.catalog.source.warning,
            },
            "profile": self.profile,
            "status": self.status,
            "hostClasses": self.host_classes,
            "summary": self.summary,
            "warnings": list(self.warnings),
        }


def resolve_standard_rti_profile(
    *,
    source: RedteamInfraTemplateSource | None = None,
    catalog: CapabilityCatalog | None = None,
    core_provider: str | None = None,
    manifest_root: Path | None = None,
) -> CapabilityProfileResolution:
    resolved_catalog = catalog or discover_capability_catalog(source=source, manifest_root=manifest_root)
    profile = _profile_metadata(resolved_catalog)
    policy = _profile_policy(core_provider=core_provider)
    capability_index = _capability_index(resolved_catalog)
    host_classes: dict[str, dict[str, list[dict[str, Any]]]] = {}
    all_entries: list[dict[str, Any]] = []
    used: set[tuple[str, str]] = set()

    for host_class, host_policy in policy.items():
        host_classes[host_class] = {}
        for classification in ("essential", "default", "optional"):
            entries = [
                _resolve_entry(
                    resolved_catalog.source,
                    capability_index,
                    capability_id,
                    host_class=host_class,
                    classification=classification,
                )
                for capability_id in host_policy[classification]
            ]
            host_classes[host_class][classification] = entries
            all_entries.extend(entries)
            for entry in entries:
                used.update(_entry_identities(host_class, entry))

    optional_entries = _visible_optional_entries(resolved_catalog, used=used)
    for host_class, entries in optional_entries.items():
        host_classes.setdefault(host_class, {}).setdefault("optional", []).extend(entries)
        all_entries.extend(entries)

    summary = {
        "total": len(all_entries),
        "essential": sum(1 for entry in all_entries if entry["classification"] == "essential"),
        "default": sum(1 for entry in all_entries if entry["classification"] == "default"),
        "optional": sum(1 for entry in all_entries if entry["classification"] == "optional"),
        "catalog": sum(1 for entry in all_entries if entry["resolution"] == "catalog"),
        "missingManifest": sum(1 for entry in all_entries if entry["resolution"] == "missing-manifest"),
        "missingTemplatePath": sum(1 for entry in all_entries if entry["resolution"] == "missing-template-path"),
    }
    warnings = tuple(_warnings(all_entries))
    return CapabilityProfileResolution(
        catalog=resolved_catalog,
        profile=profile,
        status="failed" if resolved_catalog.invalid_manifests else _status(all_entries),
        host_classes=host_classes,
        summary=summary,
        warnings=warnings,
    )


def _profile_metadata(catalog: CapabilityCatalog) -> dict[str, str]:
    existing = next((profile for profile in catalog.profiles if profile.get("id") == STANDARD_RTI_PROFILE_ID), None)
    if existing:
        return {
            "id": str(existing.get("id") or STANDARD_RTI_PROFILE_ID),
            "name": str(existing.get("name") or STANDARD_RTI_PROFILE_NAME),
            "description": str(existing.get("description") or "Standard Red Team Infrastructure capability profile."),
            "source": "manifest",
        }
    return {
        "id": STANDARD_RTI_PROFILE_ID,
        "name": STANDARD_RTI_PROFILE_NAME,
        "description": "Built-in Standard Red Team Infrastructure capability profile.",
        "source": "builtin",
    }


def _profile_policy(*, core_provider: str | None) -> dict[str, dict[str, tuple[str, ...]]]:
    provider = _core_provider_capability(core_provider)
    policy: dict[str, dict[str, tuple[str, ...]]] = {
        host_class: {classification: tuple(values) for classification, values in host_policy.items()}
        for host_class, host_policy in STANDARD_RTI_POLICY.items()
    }
    common_essentials = tuple(
        capability_id
        for capability_id in policy["common"]["essential"]
        if capability_id not in CORE_PROVIDER_CAPABILITIES
    )
    policy["common"]["essential"] = (*common_essentials, provider)
    return policy


def _core_provider_capability(value: str | None) -> str:
    normalized = str(value or DEFAULT_CORE_PROVIDER).strip().lower()
    if normalized in CORE_PROVIDER_CAPABILITIES:
        return normalized
    return DEFAULT_CORE_PROVIDER


def _capability_index(catalog: CapabilityCatalog) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for capability in catalog.capabilities:
        capability_id = str(capability.get("id") or "").strip()
        if capability_id:
            index[capability_id] = capability
        implementation = capability.get("implementation") if isinstance(capability.get("implementation"), dict) else {}
        role = str(implementation.get("role") or "").strip()
        if role and role not in index:
            index[role] = capability
    return index


def _visible_optional_entries(
    catalog: CapabilityCatalog,
    *,
    used: set[tuple[str, str]],
) -> dict[str, list[dict[str, Any]]]:
    entries_by_host_class: dict[str, list[dict[str, Any]]] = {}
    for capability in catalog.capabilities:
        operator = capability.get("operator") if isinstance(capability.get("operator"), dict) else {}
        if not operator.get("visible"):
            continue
        capability_id = str(capability.get("id") or "").strip()
        if capability_id in CORE_PROVIDER_CAPABILITIES:
            continue
        if capability.get("classification") in {"internal", "unsupported"}:
            continue
        if not capability_id:
            continue
        implementation = capability.get("implementation") if isinstance(capability.get("implementation"), dict) else {}
        role = str(implementation.get("role") or "").strip()
        placement = capability.get("placement") if isinstance(capability.get("placement"), dict) else {}
        allowed_host_classes = placement.get("allowedHostClasses") if isinstance(placement.get("allowedHostClasses"), list) else []
        for host_class_value in allowed_host_classes:
            host_class = str(host_class_value or "").strip()
            if not host_class:
                continue
            if (host_class, capability_id) in used or (role and (host_class, role) in used):
                continue
            entry = _catalog_entry(capability, capability_id, host_class=host_class, classification="optional")
            entries_by_host_class.setdefault(host_class, []).append(entry)
            used.update(_entry_identities(host_class, entry))
    return {
        host_class: sorted(entries, key=lambda entry: str(entry.get("name") or entry.get("id") or ""))
        for host_class, entries in entries_by_host_class.items()
    }


def _resolve_entry(
    source: RedteamInfraTemplateSource,
    capability_index: dict[str, dict[str, Any]],
    capability_id: str,
    *,
    host_class: str,
    classification: str,
) -> dict[str, Any]:
    capability = capability_index.get(capability_id)
    if capability is not None:
        return _catalog_entry(capability, capability_id, host_class=host_class, classification=classification)

    role_path = source.path("ansible", "roles", capability_id)
    if role_path.exists():
        return {
            "id": capability_id,
            "name": _display_name(capability_id),
            "description": "Role exists in the template source, but no Barragan capability manifest describes safe execution yet.",
            "hostClass": host_class,
            "classification": classification,
            "resolution": "missing-manifest",
            "executable": False,
            "implementation": {"type": "role", "role": capability_id, "path": f"ansible/roles/{capability_id}"},
            "operator": {"visible": True, "selectable": classification != "essential"},
        }

    return {
        "id": capability_id,
        "name": _display_name(capability_id),
        "description": "Role is named by the Standard RTI profile but was not found in the template source.",
        "hostClass": host_class,
        "classification": classification,
        "resolution": "missing-template-path",
        "executable": False,
        "implementation": {"type": "role", "role": capability_id, "path": f"ansible/roles/{capability_id}"},
        "operator": {"visible": True, "selectable": classification != "essential"},
    }


def _catalog_entry(
    capability: dict[str, Any],
    capability_id: str,
    *,
    host_class: str,
    classification: str,
) -> dict[str, Any]:
    operator = dict(capability.get("operator") or {})
    if classification == "essential":
        operator["selectable"] = False
    return {
        "id": capability_id,
        "name": str(capability.get("name") or capability_id),
        "description": str(capability.get("description") or ""),
        "hostClass": host_class,
        "classification": classification,
        "resolution": "catalog",
        "executable": True,
        "implementation": dict(capability.get("implementation") or {}),
        "operator": operator,
    }


def _entry_identities(host_class: str, entry: dict[str, Any]) -> set[tuple[str, str]]:
    identities = {(host_class, str(entry.get("id") or ""))}
    implementation = entry.get("implementation") if isinstance(entry.get("implementation"), dict) else {}
    role = str(implementation.get("role") or "").strip()
    if role:
        identities.add((host_class, role))
    return identities


def _warnings(entries: list[dict[str, Any]]) -> list[dict[str, str]]:
    warnings: list[dict[str, str]] = []
    for entry in entries:
        if entry["resolution"] == "missing-manifest":
            warnings.append(
                {
                    "severity": "warning",
                    "capabilityId": entry["id"],
                    "message": "Capability exists as a template role but has no Barragan manifest, so it is not executable through the capability system yet.",
                }
            )
        elif entry["resolution"] == "missing-template-path":
            warnings.append(
                {
                    "severity": "error" if entry["classification"] == "essential" else "warning",
                    "capabilityId": entry["id"],
                    "message": "Capability is named by the Standard RTI profile but the role path is missing from the template source.",
                }
            )
    return warnings


def _status(entries: list[dict[str, Any]]) -> str:
    if any(entry["classification"] == "essential" and entry["resolution"] == "missing-template-path" for entry in entries):
        return "failed"
    if any(entry["resolution"] in {"missing-manifest", "missing-template-path"} for entry in entries):
        return "warning"
    return "passed"


def _display_name(value: str) -> str:
    return " ".join(part.upper() if part in {"oci", "elk"} else part.capitalize() for part in value.replace("_", "-").split("-"))
