# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from pathlib import Path

from app.asgi import create_app
from app.core.config import TestConfig
from app.services.capability_profile_resolution import resolve_standard_rti_profile
from app.services.redteam_infra_template import RedteamInfraTemplateSource


STANDARD_RTI_ROLES = (
    "common",
    "molly-guard",
    "logstash",
    "yama",
    "aws",
    "oci",
    "nfs-server",
    "engagement-workspace",
    "homebase",
    "go_simple_upload_server",
    "etherpad",
    "google-chrome",
    "firefox",
    "keepassxc",
    "vs-code",
    "docker",
    "nmap",
    "nfs-client",
    "ssh-proxy",
    "dante-server",
    "unattended-upgrades",
    "proxies",
    "elk",
)


def test_standard_rti_profile_resolves_builtin_policy_and_missing_manifests(tmp_path: Path) -> None:
    root = tmp_path / "redteam-infra"
    for role in STANDARD_RTI_ROLES:
        (root / "ansible" / "roles" / role).mkdir(parents=True)

    resolution = resolve_standard_rti_profile(source=RedteamInfraTemplateSource(root, "test")).to_dict()

    assert resolution["profile"] == {
        "id": "standard-rti",
        "name": "Standard RTI",
        "description": "Built-in Standard Red Team Infrastructure capability profile.",
        "source": "builtin",
    }
    assert resolution["status"] == "passed"
    assert [entry["id"] for entry in resolution["hostClasses"]["common"]["essential"]] == [
        "common",
        "molly-guard",
        "logstash",
        "yama",
        "oci",
    ]
    assert resolution["hostClasses"]["common"]["default"] == []
    assert resolution["hostClasses"]["common"]["optional"] == []
    assert [entry["id"] for entry in resolution["hostClasses"]["homebase"]["essential"]] == ["nfs-server", "engagement-workspace", "homebase"]
    assert [entry["id"] for entry in resolution["hostClasses"]["homebase"]["default"]] == [
        "etherpad",
        "google-chrome",
        "firefox",
        "keepassxc",
        "vs-code",
    ]
    assert [entry["id"] for entry in resolution["hostClasses"]["homebase"]["optional"]] == ["go-simple-upload-server"]
    assert [entry["id"] for entry in resolution["hostClasses"]["proxy"]["essential"]] == [
        "docker",
        "nfs-client",
        "nmap",
        "ssh-proxy",
        "dante-server",
        "unattended-upgrades",
        "proxies",
    ]
    assert resolution["hostClasses"]["proxy"]["default"] == []
    assert [entry["id"] for entry in resolution["hostClasses"]["proxy"]["optional"]] == [
        "barragan.backflips-v2",
        "barragan.custom-listener",
        "barragan.static-web-site",
    ]
    assert resolution["hostClasses"]["elk"]["essential"] == []
    assert [entry["id"] for entry in resolution["hostClasses"]["elk"]["default"]] == ["elk", "unattended-upgrades"]
    assert resolution["hostClasses"]["elk"]["optional"] == []
    assert resolution["summary"] == {
        "total": 26,
        "essential": 15,
        "default": 7,
        "optional": 4,
        "catalog": 26,
        "missingManifest": 0,
        "missingTemplatePath": 0,
    }
    assert resolution["hostClasses"]["proxy"]["optional"][0]["resolution"] == "catalog"
    assert all(
        entry["id"] != "go-simple-upload-server"
        for host_class, rows in resolution["hostClasses"].items()
        if host_class != "homebase"
        for entries in rows.values()
        for entry in entries
    )


def test_old_retained_workspace_surfaces_packaged_optional_before_import(tmp_path: Path) -> None:
    root = tmp_path / "old-engagement-workspace"
    for role in STANDARD_RTI_ROLES:
        if role != "go_simple_upload_server":
            (root / "ansible" / "roles" / role).mkdir(parents=True)

    resolution = resolve_standard_rti_profile(
        source=RedteamInfraTemplateSource(root, "engagement-workspace")
    ).to_dict()

    go_simple_upload_server = next(
        entry for entry in resolution["hostClasses"]["homebase"]["optional"]
        if entry["id"] == "go-simple-upload-server"
    )
    assert go_simple_upload_server["resolution"] == "catalog"
    assert go_simple_upload_server["executable"] is True
    assert go_simple_upload_server["operator"]["selectable"] is True
    assert all(
        entry["resolution"] == "catalog"
        for rows in resolution["hostClasses"].values()
        for classification, group in rows.items()
        if classification != "optional"
        for entry in group
    )


def test_standard_rti_profile_uses_aws_core_provider_role(tmp_path: Path) -> None:
    root = tmp_path / "redteam-infra"
    for role in STANDARD_RTI_ROLES:
        (root / "ansible" / "roles" / role).mkdir(parents=True)

    resolution = resolve_standard_rti_profile(source=RedteamInfraTemplateSource(root, "test"), core_provider="aws").to_dict()

    assert [entry["id"] for entry in resolution["hostClasses"]["common"]["essential"]] == [
        "common",
        "molly-guard",
        "logstash",
        "yama",
        "aws",
    ]
    assert "oci" not in [entry["id"] for entry in resolution["hostClasses"]["common"]["essential"]]
    aws = resolution["hostClasses"]["common"]["essential"][-1]
    assert aws["resolution"] == "catalog"
    assert aws["operator"]["selectable"] is False
    assert "oci" not in [entry["id"] for entry in resolution["hostClasses"]["common"]["optional"]]


def test_standard_rti_profile_tolerates_missing_engagement_workspace_during_rollout(tmp_path: Path) -> None:
    root = tmp_path / "redteam-infra"
    for role in STANDARD_RTI_ROLES:
        if role != "engagement-workspace":
            (root / "ansible" / "roles" / role).mkdir(parents=True)

    resolution = resolve_standard_rti_profile(source=RedteamInfraTemplateSource(root, "test")).to_dict()

    engagement_workspace = next(entry for entry in resolution["hostClasses"]["homebase"]["essential"] if entry["id"] == "engagement-workspace")
    assert resolution["status"] == "passed"
    assert engagement_workspace["resolution"] == "catalog"
    assert engagement_workspace["implementation"]["type"] == "barragan-native"
    assert engagement_workspace["operator"]["selectable"] is False


def test_standard_rti_profile_surfaces_libreoffice_as_homebase_optional(tmp_path: Path) -> None:
    root = tmp_path / "redteam-infra"
    for role in (*STANDARD_RTI_ROLES, "libreoffice"):
        (root / "ansible" / "roles" / role).mkdir(parents=True)

    resolution = resolve_standard_rti_profile(source=RedteamInfraTemplateSource(root, "test")).to_dict()

    homebase_optionals = {entry["id"]: entry for entry in resolution["hostClasses"]["homebase"]["optional"]}
    assert "libreoffice" in homebase_optionals
    assert homebase_optionals["libreoffice"]["resolution"] == "catalog"
    assert homebase_optionals["libreoffice"]["operator"]["selectable"] is True


def test_standard_rti_profile_uses_catalog_manifest_for_capability(tmp_path: Path) -> None:
    root = tmp_path / "redteam-infra"
    manifest_root = tmp_path / "barragan-manifests"
    for role in STANDARD_RTI_ROLES:
        (root / "ansible" / "roles" / role).mkdir(parents=True)
    _write(
        manifest_root / "capabilities" / "desktop" / "firefox.yml",
        """
apiVersion: barragan/v1
kind: Capability
metadata:
  id: firefox
  name: Firefox
  category: desktop
  description: Install Firefox using the reviewed role.
implementation:
  type: role
  role: firefox
  path: ansible/roles/firefox
placement:
  allowedHostClasses:
    - homebase
profiles:
  standard-rti:
    classification: default
operator:
  visible: true
  selectable: true
lifecycle:
  apply: supported
""",
    )

    resolution = resolve_standard_rti_profile(
        source=RedteamInfraTemplateSource(root, "test"),
        manifest_root=manifest_root,
    ).to_dict()
    firefox = next(entry for entry in resolution["hostClasses"]["homebase"]["default"] if entry["id"] == "firefox")

    assert firefox["resolution"] == "catalog"
    assert firefox["executable"] is True
    assert firefox["description"] == "Install Firefox using the reviewed role."
    assert resolution["summary"]["catalog"] == 25
    assert resolution["summary"]["missingManifest"] == 0


def test_standard_rti_profile_locks_catalog_essential_capabilities(tmp_path: Path) -> None:
    root = tmp_path / "redteam-infra"
    manifest_root = tmp_path / "barragan-manifests"
    for role in STANDARD_RTI_ROLES:
        (root / "ansible" / "roles" / role).mkdir(parents=True)
    _write(
        manifest_root / "capabilities" / "core" / "common.yml",
        """
apiVersion: barragan/v1
kind: AnsibleCapability
metadata:
  id: common
  name: Common
  category: core
  description: Apply the shared baseline.
implementation:
  type: role
  role: common
  path: ansible/roles/common
placement:
  allowedHostClasses:
    - common
operator:
  visible: true
  selectable: true
lifecycle:
  apply: supported
""",
    )

    resolution = resolve_standard_rti_profile(
        source=RedteamInfraTemplateSource(root, "test"),
        manifest_root=manifest_root,
    ).to_dict()
    common = resolution["hostClasses"]["common"]["essential"][0]

    assert common["resolution"] == "catalog"
    assert common["operator"]["selectable"] is False


def test_standard_rti_profile_fails_closed_for_invalid_local_standard_capability(tmp_path: Path) -> None:
    root = tmp_path / "redteam-infra"
    manifest_root = tmp_path / "barragan-manifests"
    for role in STANDARD_RTI_ROLES:
        (root / "ansible" / "roles" / role).mkdir(parents=True)
    _write(
        manifest_root / "capabilities" / "desktop" / "firefox.yml",
        """
apiVersion: barragan/v1
kind: AnsibleCapability
metadata:
  id: firefox
  name: Firefox
  category: desktop
  description: Install Firefox using the reviewed role.
implementation:
  type: role
  role: firefox
  path: ansible/roles/missing-firefox
placement:
  allowedHostClasses:
    - homebase
operator:
  visible: true
  selectable: true
""",
    )

    resolution = resolve_standard_rti_profile(
        source=RedteamInfraTemplateSource(root, "test"),
        manifest_root=manifest_root,
    ).to_dict()
    firefox = next(entry for entry in resolution["hostClasses"]["homebase"]["default"] if entry["id"] == "firefox")

    assert resolution["status"] == "failed"
    assert firefox["resolution"] == "missing-manifest"
    assert firefox["executable"] is False


def test_standard_rti_profile_fails_when_essential_role_missing(tmp_path: Path) -> None:
    root = tmp_path / "redteam-infra"
    for role in STANDARD_RTI_ROLES:
        if role != "common":
            (root / "ansible" / "roles" / role).mkdir(parents=True)

    resolution = resolve_standard_rti_profile(source=RedteamInfraTemplateSource(root, "test")).to_dict()
    common = resolution["hostClasses"]["common"]["essential"][0]

    assert resolution["status"] == "failed"
    assert common["id"] == "common"
    assert common["resolution"] == "missing-template-path"
    assert resolution["summary"]["missingTemplatePath"] == 1


def test_standard_rti_profile_api_preserves_read_only_shape() -> None:
    client = create_app(TestConfig).test_client()

    response = client.get("/api/templates/redteam-infra/profiles/standard-rti")

    assert response.status_code == 200
    body = response.json()
    assert "profileResolution" in body
    assert {"source", "profile", "status", "hostClasses", "summary", "warnings"}.issubset(body["profileResolution"])


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.strip() + "\n", encoding="utf-8")
