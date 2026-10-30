# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.services.redteam_infra_template import (
    RedteamInfraTemplateSource,
    resolve_redteam_infra_template_source,
)


MANIFEST_SUFFIXES = {".json", ".yaml", ".yml"}
DEFAULT_CAPABILITY_MANIFEST_ROOT = Path(__file__).resolve().parents[1] / "capability_manifests"
SUPPORTED_API_VERSION = "barragan/v1"
CAPABILITY_KINDS = {"Capability", "AnsibleCapability"}
PROFILE_KIND = "CapabilityProfile"
IMPLEMENTATION_TYPES_REQUIRING_PATH = {"playbook", "role", "composed-playbook", "generated-playbook"}
SUPPORTED_IMPLEMENTATION_TYPES = {
    "playbook",
    "role",
    "composed-playbook",
    "generated-playbook",
    "barragan-native",
}
CLASSIFICATIONS = {"essential", "default", "optional", "internal", "unsupported"}
NATIVE_STATIC_WEB_CAPABILITY_ID = "barragan.static-web-site"
NATIVE_CUSTOM_LISTENER_CAPABILITY_ID = "barragan.custom-listener"
NATIVE_BACKFLIPS_CAPABILITY_ID = "barragan.backflips-v2"
OPENRESTY_CAPABILITY_ID = "openresty"
OPENRESTY_V2_CAPABILITY_ID = "redteam-infra.openresty-v2"
STANDARD_RTI_KNOWN_ROLE_CAPABILITIES: tuple[dict[str, Any], ...] = (
    {
        "role": "common",
        "name": "Common baseline",
        "description": "Apply the common Red Team Infrastructure baseline packages and configuration to core nodes.",
        "category": "core/baseline",
        "allowed_host_classes": ["common"],
        "visible": True,
        "selectable": False,
        "classification": "essential",
    },
    {
        "role": "molly-guard",
        "name": "Molly guard",
        "description": "Install molly-guard safeguards on core nodes to reduce accidental reboot/shutdown mistakes.",
        "category": "core/safety",
        "allowed_host_classes": ["common"],
        "visible": True,
        "selectable": False,
        "classification": "essential",
    },
    {
        "role": "logstash",
        "name": "Logstash forwarder",
        "description": "Apply the legacy log forwarding role used by Red Team Infrastructure core nodes.",
        "category": "core/logging",
        "allowed_host_classes": ["common"],
        "visible": True,
        "selectable": False,
        "classification": "essential",
    },
    {
        "role": "yama",
        "name": "Yama ptrace hardening",
        "description": "Apply the legacy Yama ptrace hardening role to core nodes.",
        "category": "core/hardening",
        "allowed_host_classes": ["common"],
        "visible": True,
        "selectable": False,
        "classification": "essential",
    },
    {
        "role": "oci",
        "name": "OCI tooling",
        "description": "Provider-specific resolver and DNS hardening role for OCI-backed core RTI nodes.",
        "category": "core/provider",
        "allowed_host_classes": ["common"],
        "visible": False,
        "selectable": False,
        "classification": "internal",
    },
    {
        "role": "aws",
        "name": "AWS tooling",
        "description": "Provider-specific resolver and DNS hardening role for AWS-backed core RTI nodes.",
        "category": "core/provider",
        "allowed_host_classes": ["common"],
        "visible": False,
        "selectable": False,
        "classification": "internal",
    },
    {
        "role": "nfs-server",
        "name": "NFS server",
        "description": "Configure the homebase NFS export used by proxy nodes and shared operator workflows.",
        "category": "homebase/storage",
        "allowed_host_classes": ["homebase"],
        "visible": True,
        "selectable": False,
        "classification": "essential",
    },
    {
        "role": "homebase",
        "name": "Homebase baseline",
        "description": "Apply the legacy homebase workstation baseline, including desktop/VNC support and operator tooling.",
        "category": "homebase/baseline",
        "allowed_host_classes": ["homebase"],
        "visible": True,
        "selectable": False,
        "classification": "essential",
    },
    {
        "role": "etherpad",
        "name": "Etherpad",
        "description": "Install Etherpad on homebase for shared operator notes.",
        "category": "homebase/collaboration",
        "allowed_host_classes": ["homebase"],
        "visible": True,
        "selectable": True,
        "classification": "default",
    },
    {
        "role": "google-chrome",
        "name": "Google Chrome",
        "description": "Install Google Chrome on homebase for operator browser workflows.",
        "category": "homebase/desktop",
        "allowed_host_classes": ["homebase"],
        "visible": True,
        "selectable": True,
        "classification": "default",
    },
    {
        "role": "firefox",
        "name": "Firefox",
        "description": "Install Firefox on homebase with the legacy Red Team Infrastructure browser policy.",
        "category": "homebase/desktop",
        "allowed_host_classes": ["homebase"],
        "visible": True,
        "selectable": True,
        "classification": "default",
    },
    {
        "role": "keepassxc",
        "name": "KeePassXC",
        "description": "Install KeePassXC on homebase for local credential database workflows.",
        "category": "homebase/desktop",
        "allowed_host_classes": ["homebase"],
        "visible": True,
        "selectable": True,
        "classification": "default",
    },
    {
        "role": "vs-code",
        "name": "VS Code",
        "description": "Install Visual Studio Code on homebase for operator development workflows.",
        "category": "homebase/desktop",
        "allowed_host_classes": ["homebase"],
        "visible": True,
        "selectable": True,
        "classification": "default",
    },
    {
        "role": "docker",
        "name": "Docker runtime",
        "description": "Install the upstream Red Team Infrastructure Docker runtime required by proxy-hosted container capabilities.",
        "category": "proxy/runtime",
        "allowed_host_classes": ["proxy"],
        "visible": True,
        "selectable": False,
        "classification": "essential",
    },
    {
        "role": "nmap",
        "name": "Nmap",
        "description": "Install nmap for Red Team Infrastructure operator and proxy diagnostics.",
        "category": "operator/tools",
        "allowed_host_classes": ["homebase", "proxy"],
        "visible": False,
        "selectable": False,
        "classification": "default",
    },
    {
        "role": "nfs-client",
        "name": "NFS client",
        "description": "Mount the homebase NFS export on proxy nodes.",
        "category": "proxy/storage",
        "allowed_host_classes": ["proxy"],
        "visible": True,
        "selectable": False,
        "classification": "essential",
    },
    {
        "role": "ssh-proxy",
        "name": "SSH proxy",
        "description": "Configure the proxy-node SSH jump behavior used by Red Team Infrastructure.",
        "category": "proxy/access",
        "allowed_host_classes": ["proxy"],
        "visible": True,
        "selectable": False,
        "classification": "essential",
    },
    {
        "role": "dante-server",
        "name": "Dante SOCKS proxy",
        "description": "Install and configure Dante SOCKS proxy on proxy nodes. Traffic egresses from the proxy host IP.",
        "category": "proxy/outbound",
        "allowed_host_classes": ["proxy"],
        "visible": True,
        "selectable": False,
        "classification": "essential",
    },
    {
        "role": "unattended-upgrades",
        "name": "Unattended upgrades",
        "description": "Configure unattended OS security updates on infrastructure nodes.",
        "category": "core/maintenance",
        "allowed_host_classes": ["proxy", "elk"],
        "visible": True,
        "selectable": True,
        "classification": "essential",
    },
    {
        "role": "proxies",
        "name": "Proxy baseline",
        "description": "Apply the legacy proxy-node baseline role.",
        "category": "proxy/baseline",
        "allowed_host_classes": ["proxy"],
        "visible": True,
        "selectable": False,
        "classification": "essential",
    },
    {
        "role": "elk",
        "name": "ELK",
        "description": "Apply the legacy ELK stack role when ELK infrastructure is part of the deployment.",
        "category": "elk/baseline",
        "allowed_host_classes": ["elk"],
        "visible": True,
        "selectable": True,
        "classification": "default",
    },
)


@dataclass(frozen=True)
class CapabilityCatalogIssue:
    path: str
    severity: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "severity": self.severity, "message": self.message}


@dataclass(frozen=True)
class CapabilityCatalog:
    source: RedteamInfraTemplateSource
    status: str
    capabilities: tuple[dict[str, Any], ...]
    profiles: tuple[dict[str, Any], ...]
    invalid_manifests: tuple[CapabilityCatalogIssue, ...]
    warnings: tuple[CapabilityCatalogIssue, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": {
                "path": str(self.source.root),
                "kind": self.source.source,
                "warning": self.source.warning,
            },
            "status": self.status,
            "capabilities": list(self.capabilities),
            "profiles": list(self.profiles),
            "invalidManifests": [issue.to_dict() for issue in self.invalid_manifests],
            "warnings": [issue.to_dict() for issue in self.warnings],
        }


def discover_capability_catalog(
    *,
    source: RedteamInfraTemplateSource | None = None,
    manifest_root: Path | None = None,
) -> CapabilityCatalog:
    resolved = source or resolve_redteam_infra_template_source()
    resolved_manifest_root = (manifest_root or DEFAULT_CAPABILITY_MANIFEST_ROOT).resolve(strict=False)
    capability_files = _manifest_files(resolved_manifest_root / "capabilities")
    profile_files = _manifest_files(resolved_manifest_root / "profiles")

    capabilities: list[dict[str, Any]] = []
    profiles: list[dict[str, Any]] = []
    invalid: list[CapabilityCatalogIssue] = []
    warnings: list[CapabilityCatalogIssue] = []

    capabilities.extend(_barragan_native_capabilities())
    declared_manifest_implementations: set[str] = set()

    for manifest_path in capability_files:
        payload, issue = _load_manifest(resolved_manifest_root, manifest_path)
        if issue is not None:
            invalid.append(issue)
            continue
        declared_manifest_implementations.update(_declared_capability_implementations(payload))
        normalized, issues = _normalize_capability(resolved, resolved_manifest_root, manifest_path, payload)
        invalid.extend(issue for issue in issues if issue.severity == "error")
        warnings.extend(issue for issue in issues if issue.severity != "error")
        if normalized is not None and not any(issue.severity == "error" for issue in issues):
            capabilities.append(normalized)

    capabilities.extend(
        _known_template_capabilities(
            resolved,
            existing_ids={str(item.get("id") or "") for item in capabilities} | declared_manifest_implementations,
        )
    )

    for manifest_path in profile_files:
        payload, issue = _load_manifest(resolved_manifest_root, manifest_path)
        if issue is not None:
            invalid.append(issue)
            continue
        normalized, issues = _normalize_profile(resolved_manifest_root, manifest_path, payload)
        invalid.extend(issue for issue in issues if issue.severity == "error")
        warnings.extend(issue for issue in issues if issue.severity != "error")
        if normalized is not None and not any(issue.severity == "error" for issue in issues):
            profiles.append(normalized)

    if not capability_files and not profile_files:
        warnings.append(
            CapabilityCatalogIssue(
                "barragan/",
                "warning",
                "No capability or profile manifests were found in the Barragan manifest source.",
            )
        )

    return CapabilityCatalog(
        source=resolved,
        status=_catalog_status(invalid, warnings),
        capabilities=tuple(sorted(capabilities, key=lambda item: item["id"])),
        profiles=tuple(sorted(profiles, key=lambda item: item["id"])),
        invalid_manifests=tuple(invalid),
        warnings=tuple(warnings),
    )


def _manifest_files(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    return sorted(path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in MANIFEST_SUFFIXES)


def _declared_capability_implementations(payload: dict[str, Any]) -> set[str]:
    metadata = _dict(payload.get("metadata"))
    implementation = _dict(payload.get("implementation"))
    return {
        value
        for value in (_string(metadata.get("id")), _string(implementation.get("role")))
        if value
    }


def _barragan_native_capabilities() -> list[dict[str, Any]]:
    return [
        {
            "id": NATIVE_STATIC_WEB_CAPABILITY_ID,
            "name": "Static Web Site",
            "description": (
                "Preferred Barragan-native workflow for managing proxy-local static websites with "
                "per-site lifecycle, inbound-channel binding, DNS-01 certificate binding, jobs, and logs."
            ),
            "category": "proxy/web-delivery",
            "manifestPath": "",
            "apiVersion": SUPPORTED_API_VERSION,
            "kind": "Capability",
            "implementation": {
                "type": "barragan-native",
                "path": "",
                "role": "",
            },
            "placement": {"allowedHostClasses": ["proxy"]},
            "classification": "optional",
            "profiles": {},
            "operator": {"visible": True, "selectable": True, "preferred": True},
            "lifecycle": {"apply": "supported", "remove": "supported", "managedBy": "barragan"},
            "conflictsWith": [OPENRESTY_CAPABILITY_ID, OPENRESTY_V2_CAPABILITY_ID],
            "status": "valid",
        },
        {
            "id": NATIVE_CUSTOM_LISTENER_CAPABILITY_ID,
            "name": "Custom Listener",
            "description": (
                "Track an operator-managed listener and publish its placement for inbound-channel routing. "
                "Barragan does not install, start, or health-manage the listener process."
            ),
            "category": "proxy/listener-routing",
            "manifestPath": "",
            "apiVersion": SUPPORTED_API_VERSION,
            "kind": "Capability",
            "implementation": {"type": "barragan-native", "path": "", "role": ""},
            "placement": {"allowedHostClasses": ["proxy"]},
            "classification": "optional",
            "profiles": {},
            "operator": {"visible": True, "selectable": False, "configurable": True, "preferred": False},
            "lifecycle": {"apply": "configuration", "remove": "supported", "managedBy": "barragan"},
            "conflictsWith": [],
            "status": "valid",
        },
        {
            "id": NATIVE_BACKFLIPS_CAPABILITY_ID,
            "name": "Backflips V2",
            "description": (
                "Install Backflips V2 role and configuration prerequisites on an eligible proxy. "
                "Operators manage listener lifecycle with the Backflips CLI."
            ),
            "category": "proxy/listener-prerequisite",
            "manifestPath": "",
            "apiVersion": SUPPORTED_API_VERSION,
            "kind": "Capability",
            "implementation": {"type": "barragan-native", "path": "", "role": ""},
            "placement": {"allowedHostClasses": ["proxy"]},
            "classification": "optional",
            "profiles": {},
            "operator": {"visible": True, "selectable": False, "configurable": True, "preferred": True},
            "lifecycle": {"apply": "configuration", "remove": "unsupported", "managedBy": "barragan"},
            "conflictsWith": [],
            "status": "valid",
        },
    ]


def _known_template_capabilities(source: RedteamInfraTemplateSource, *, existing_ids: set[str]) -> list[dict[str, Any]]:
    capabilities: list[dict[str, Any]] = []
    engagement_workspace = _engagement_workspace_capability(source, existing_ids=existing_ids)
    if engagement_workspace is not None:
        capabilities.append(engagement_workspace)
    for capability in STANDARD_RTI_KNOWN_ROLE_CAPABILITIES:
        projected = _known_role_capability(
            source,
            existing_ids=existing_ids,
            role=str(capability["role"]),
            name=str(capability["name"]),
            description=str(capability["description"]),
            category=str(capability["category"]),
            allowed_host_classes=list(capability["allowed_host_classes"]),
            visible=bool(capability["visible"]),
            selectable=bool(capability["selectable"]),
            classification=str(capability["classification"]),
            lifecycle={"apply": "supported", "remove": "manual", "managedBy": "redteam-infra"},
        )
        if projected is not None:
            capabilities.append(projected)
            existing_ids.add(str(projected.get("id") or ""))
    for projected in (
        _known_role_capability(
            source,
            existing_ids=existing_ids,
            role="libreoffice",
            name="LibreOffice",
            description=(
                "Install LibreOffice on homebase for operator document workflows. "
                "Deselecting it removes only the libreoffice meta-package; component packages may remain installed."
            ),
            category="homebase/desktop",
            allowed_host_classes=["homebase"],
            visible=True,
            selectable=True,
            classification="optional",
            lifecycle={"apply": "supported", "remove": "manual", "managedBy": "redteam-infra"},
        ),
        _known_role_capability(
            source,
            existing_ids=existing_ids,
            role="opsec",
            name="OPSEC network restrictions",
            description=(
                "Optionally block Homebase outbound connections to engagement-defined IPs or CIDRs. "
                "Barragan provides the safer configurable workflow and only removes Barragan-managed rules."
            ),
            category="homebase/opsec",
            allowed_host_classes=["homebase"],
            visible=True,
            selectable=True,
            classification="optional",
            lifecycle={"apply": "supported", "remove": "supported", "managedBy": "barragan"},
        ),
        _known_role_capability(
            source,
            existing_ids=existing_ids,
            role="web-check",
            name="Web-check",
            description=(
                "Run the containerized web-check utility on a proxy so operators can inspect "
                "Red Team-controlled websites, DNS records, and exposed web services for OPSEC leaks. "
                "Do not use this capability to scan target or customer websites from RTI."
            ),
            category="proxy/opsec",
            allowed_host_classes=["proxy"],
            visible=True,
            selectable=True,
            classification="optional",
            lifecycle={"apply": "supported", "remove": "manual", "managedBy": "redteam-infra"},
        ),
        _known_role_capability(
            source,
            existing_ids=existing_ids,
            role="mythic",
            name="Mythic",
            description=(
                "Install and start Mythic C2 on homebase using the legacy redteam-infra role. "
                "Operators complete Mythic agents, C2 profiles, users, and application configuration inside Mythic after installation."
            ),
            category="homebase/c2",
            allowed_host_classes=["homebase"],
            visible=True,
            selectable=True,
            classification="optional",
            lifecycle={"apply": "supported", "remove": "manual", "managedBy": "redteam-infra"},
        ),
        _known_role_capability(
            source,
            existing_ids=existing_ids,
            role="loot",
            name="Legacy loot directory",
            description=(
                "Legacy role that creates /loot. Barragan treats it as superseded by "
                "engagement-workspace, which creates /engagement/loot."
            ),
            category="homebase/workspace",
            allowed_host_classes=["homebase"],
            visible=False,
            selectable=False,
            classification="unsupported",
            lifecycle={"apply": "unsupported", "remove": "manual", "managedBy": "redteam-infra"},
        ),
    ):
        if projected is not None:
            capabilities.append(projected)

    openresty_v2_path = source.path("ansible", "roles", "openresty-v2")
    if openresty_v2_path.exists() and OPENRESTY_V2_CAPABILITY_ID not in existing_ids:
        capabilities.append(
            {
                "id": OPENRESTY_V2_CAPABILITY_ID,
                "name": "OpenResty v2",
                "description": (
                    "Legacy redteam-infra Ansible role that deploys a containerized /opt/web OpenResty stack. "
                    "This role is incompatible with Barragan's native Static Web Site capability and is not "
                    "operator-selectable in Barragan."
                ),
                "category": "proxy/web-delivery",
                "manifestPath": "ansible/roles/openresty-v2",
                "apiVersion": SUPPORTED_API_VERSION,
                "kind": "AnsibleCapability",
                "implementation": {
                    "type": "role",
                    "path": "ansible/roles/openresty-v2",
                    "role": "openresty-v2",
                },
                "placement": {"allowedHostClasses": ["proxy"]},
                "classification": "unsupported",
                "profiles": {},
                "operator": {"visible": False, "selectable": False, "preferred": False},
                "lifecycle": {"apply": "unsupported", "remove": "manual", "managedBy": "redteam-infra"},
                "conflictsWith": [NATIVE_STATIC_WEB_CAPABILITY_ID],
                "status": "valid",
            }
        )
    return capabilities


def _engagement_workspace_capability(source: RedteamInfraTemplateSource, *, existing_ids: set[str]) -> dict[str, Any] | None:
    role = "engagement-workspace"
    if role in existing_ids:
        return None
    description = (
        "Create the standard Homebase /engagement workspace and /engagement/loot tree for "
        "operators, tooling, and generated orientation artifacts."
    )
    role_capability = _known_role_capability(
        source,
        existing_ids=existing_ids,
        role=role,
        name="Engagement workspace",
        description=description,
        category="homebase/workspace",
        allowed_host_classes=["homebase"],
        visible=True,
        selectable=False,
        classification="essential",
        lifecycle={"apply": "supported", "remove": "manual", "managedBy": "redteam-infra"},
    )
    if role_capability is not None:
        return role_capability
    if not source.path("ansible").exists():
        return None
    return {
        "id": role,
        "name": "Engagement workspace",
        "description": (
            "Compatibility fallback for older template sources before the redteam-infra "
            "engagement-workspace role is available. Barragan still creates /engagement as "
            "part of the generated INFRA.md refresh."
        ),
        "category": "homebase/workspace",
        "manifestPath": "",
        "apiVersion": SUPPORTED_API_VERSION,
        "kind": "Capability",
        "implementation": {
            "type": "barragan-native",
            "path": "",
            "role": "",
        },
        "placement": {"allowedHostClasses": ["homebase"]},
        "classification": "essential",
        "profiles": {},
        "operator": {"visible": True, "selectable": False},
        "lifecycle": {"apply": "supported", "remove": "manual", "managedBy": "barragan"},
        "status": "valid",
    }


def _known_role_capability(
    source: RedteamInfraTemplateSource,
    *,
    existing_ids: set[str],
    role: str,
    name: str,
    description: str,
    category: str,
    allowed_host_classes: list[str],
    visible: bool,
    selectable: bool,
    classification: str,
    lifecycle: dict[str, str],
) -> dict[str, Any] | None:
    if role in existing_ids:
        return None
    role_path = source.path("ansible", "roles", role)
    if not role_path.exists():
        return None
    return {
        "id": role,
        "name": name,
        "description": description,
        "category": category,
        "manifestPath": f"ansible/roles/{role}",
        "apiVersion": SUPPORTED_API_VERSION,
        "kind": "AnsibleCapability",
        "implementation": {
            "type": "role",
            "path": f"ansible/roles/{role}",
            "role": role,
        },
        "placement": {"allowedHostClasses": allowed_host_classes},
        "classification": classification,
        "profiles": {},
        "operator": {"visible": visible, "selectable": selectable},
        "lifecycle": lifecycle,
        "status": "valid",
    }


def _load_manifest(
    manifest_root: Path,
    path: Path,
) -> tuple[dict[str, Any], CapabilityCatalogIssue | None]:
    try:
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".json":
            payload = json.loads(text)
        else:
            payload = yaml.safe_load(text)
    except Exception as exc:
        return {}, CapabilityCatalogIssue(_manifest_relative_path(manifest_root, path), "error", f"Manifest could not be parsed: {exc}")

    if not isinstance(payload, dict):
        return {}, CapabilityCatalogIssue(_manifest_relative_path(manifest_root, path), "error", "Manifest root must be an object.")
    return payload, None


def _normalize_capability(
    source: RedteamInfraTemplateSource,
    manifest_root: Path,
    path: Path,
    payload: dict[str, Any],
) -> tuple[dict[str, Any] | None, list[CapabilityCatalogIssue]]:
    relpath = _manifest_relative_path(manifest_root, path)
    issues = _base_manifest_issues(payload, relpath, CAPABILITY_KINDS)
    metadata = _dict(payload.get("metadata"))
    implementation = _dict(payload.get("implementation"))
    operator = _dict(payload.get("operator"))
    placement = _dict(payload.get("placement"))
    scope = _dict(payload.get("scope"))
    profiles = _dict(payload.get("profiles"))

    capability_id = _string(metadata.get("id"))
    name = _string(metadata.get("name"))
    description = _string(metadata.get("description"))
    implementation_type = _string(implementation.get("type"))
    implementation_path = _string(implementation.get("path"))
    role = _string(implementation.get("role"))
    allowed_host_classes = _string_list(placement.get("allowedHostClasses")) or _string_list(scope.get("hostClasses"))
    visible = operator.get("visible")
    selectable = operator.get("selectable")

    for field_name, value in (
        ("metadata.id", capability_id),
        ("metadata.name", name),
        ("metadata.description", description),
        ("implementation.type", implementation_type),
    ):
        if not value:
            issues.append(CapabilityCatalogIssue(relpath, "error", f"Capability manifest is missing {field_name}."))

    if implementation_type and implementation_type not in SUPPORTED_IMPLEMENTATION_TYPES:
        issues.append(CapabilityCatalogIssue(relpath, "error", f"Unsupported implementation.type: {implementation_type}."))

    if implementation_type in IMPLEMENTATION_TYPES_REQUIRING_PATH and not implementation_path:
        issues.append(CapabilityCatalogIssue(relpath, "error", "Capability implementation must declare path."))

    if implementation_path and not _implementation_path_exists(source, implementation_path):
        if _is_retained_workspace_import_candidate(
            source=source,
            implementation_type=implementation_type,
            implementation_path=implementation_path,
            role=role,
            classification=_string(payload.get("classification")),
            visible=visible,
            selectable=selectable,
        ):
            issues.append(
                CapabilityCatalogIssue(
                    relpath,
                    "warning",
                    f"Capability role is not retained yet and will be imported when selected: {implementation_path}.",
                )
            )
        else:
            issues.append(
                CapabilityCatalogIssue(
                    relpath,
                    "error",
                    f"Capability implementation path does not exist: {implementation_path}.",
                )
            )

    if not allowed_host_classes:
        issues.append(CapabilityCatalogIssue(relpath, "error", "Capability manifest must declare allowed host classes."))

    if not isinstance(visible, bool):
        issues.append(CapabilityCatalogIssue(relpath, "error", "Capability operator.visible must be boolean."))
    if not isinstance(selectable, bool):
        issues.append(CapabilityCatalogIssue(relpath, "error", "Capability operator.selectable must be boolean."))

    capability_profiles = _normalize_capability_profiles(relpath, profiles, issues)
    classification = _string(payload.get("classification"))
    if classification and classification not in CLASSIFICATIONS:
        issues.append(CapabilityCatalogIssue(relpath, "error", f"Unsupported classification: {classification}."))

    if not capability_id:
        return None, issues

    normalized = {
        "id": capability_id,
        "name": name,
        "description": description,
        "category": _string(metadata.get("category")),
        "manifestPath": relpath,
        "apiVersion": _string(payload.get("apiVersion")),
        "kind": "Capability",
        "implementation": {
            "type": implementation_type,
            "path": implementation_path,
            "role": role,
        },
        "placement": {"allowedHostClasses": allowed_host_classes},
        "classification": classification,
        "profiles": capability_profiles,
        "operator": {"visible": visible, "selectable": selectable},
        "lifecycle": _dict(payload.get("lifecycle")),
        "status": "valid" if not any(issue.severity == "error" for issue in issues) else "invalid",
    }
    return normalized, issues


def _is_retained_workspace_import_candidate(
    *,
    source: RedteamInfraTemplateSource,
    implementation_type: str,
    implementation_path: str,
    role: str,
    classification: str,
    visible: Any,
    selectable: Any,
) -> bool:
    return (
        source.source == "engagement-workspace"
        and implementation_type == "role"
        and bool(role)
        and implementation_path == f"ansible/roles/{role}"
        and classification == "optional"
        and visible is True
        and selectable is True
    )


def _normalize_profile(
    manifest_root: Path,
    path: Path,
    payload: dict[str, Any],
) -> tuple[dict[str, Any] | None, list[CapabilityCatalogIssue]]:
    relpath = _manifest_relative_path(manifest_root, path)
    issues = _base_manifest_issues(payload, relpath, {PROFILE_KIND})
    metadata = _dict(payload.get("metadata"))
    host_classes = _dict(payload.get("hostClasses"))
    profile_id = _string(metadata.get("id"))
    name = _string(metadata.get("name"))
    description = _string(metadata.get("description"))

    for field_name, value in (("metadata.id", profile_id), ("metadata.name", name)):
        if not value:
            issues.append(CapabilityCatalogIssue(relpath, "error", f"Profile manifest is missing {field_name}."))
    if not host_classes:
        issues.append(CapabilityCatalogIssue(relpath, "error", "Profile manifest must declare hostClasses."))

    normalized_host_classes: dict[str, dict[str, list[str]]] = {}
    for host_class, policy in host_classes.items():
        if not isinstance(host_class, str) or not isinstance(policy, dict):
            issues.append(CapabilityCatalogIssue(relpath, "error", "Profile hostClasses entries must be objects."))
            continue
        normalized_host_classes[host_class] = {}
        for classification, values in policy.items():
            if classification not in CLASSIFICATIONS:
                issues.append(CapabilityCatalogIssue(relpath, "error", f"Unsupported profile classification: {classification}."))
                continue
            normalized_host_classes[host_class][classification] = _string_list(values)

    if not profile_id:
        return None, issues

    normalized = {
        "id": profile_id,
        "name": name,
        "description": description,
        "manifestPath": relpath,
        "apiVersion": _string(payload.get("apiVersion")),
        "kind": PROFILE_KIND,
        "hostClasses": normalized_host_classes,
        "status": "valid" if not any(issue.severity == "error" for issue in issues) else "invalid",
    }
    return normalized, issues


def _base_manifest_issues(
    payload: dict[str, Any],
    relpath: str,
    allowed_kinds: set[str],
) -> list[CapabilityCatalogIssue]:
    issues: list[CapabilityCatalogIssue] = []
    api_version = _string(payload.get("apiVersion"))
    kind = _string(payload.get("kind"))
    if api_version != SUPPORTED_API_VERSION:
        issues.append(CapabilityCatalogIssue(relpath, "error", f"Unsupported apiVersion: {api_version or '<missing>'}."))
    if kind not in allowed_kinds:
        issues.append(CapabilityCatalogIssue(relpath, "error", f"Unsupported kind: {kind or '<missing>'}."))
    if not isinstance(payload.get("metadata"), dict):
        issues.append(CapabilityCatalogIssue(relpath, "error", "Manifest must include metadata object."))
    return issues


def _normalize_capability_profiles(
    relpath: str,
    profiles: dict[str, Any],
    issues: list[CapabilityCatalogIssue],
) -> dict[str, dict[str, str]]:
    normalized: dict[str, dict[str, str]] = {}
    for profile_id, profile_policy in profiles.items():
        if not isinstance(profile_id, str) or not isinstance(profile_policy, dict):
            issues.append(CapabilityCatalogIssue(relpath, "error", "Capability profiles entries must be objects."))
            continue
        classification = _string(profile_policy.get("classification"))
        if classification and classification not in CLASSIFICATIONS:
            issues.append(CapabilityCatalogIssue(relpath, "error", f"Unsupported profile classification: {classification}."))
        normalized[profile_id] = {"classification": classification}
    return normalized


def _catalog_status(
    invalid: list[CapabilityCatalogIssue],
    warnings: list[CapabilityCatalogIssue],
) -> str:
    if invalid:
        return "failed"
    if warnings:
        return "warning"
    return "passed"


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _string(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _manifest_relative_path(root: Path, path: Path) -> str:
    relative = _relative_path(root, path)
    return f"barragan/{relative}"


def _implementation_path_exists(source: RedteamInfraTemplateSource, implementation_path: str) -> bool:
    relative_path = Path(implementation_path)
    if relative_path.is_absolute():
        return False
    root = source.root.resolve(strict=False)
    candidate = (root / relative_path).resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return candidate.exists()


def _relative_path(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
