# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
from pathlib import Path

from app.asgi import create_app
from app.core.config import TestConfig
from app.services.capability_catalog import discover_capability_catalog
from app.services.redteam_infra_template import RedteamInfraTemplateSource


def test_capability_catalog_discovers_valid_yaml_capability_and_profile(tmp_path: Path) -> None:
    root = tmp_path / "redteam-infra"
    manifest_root = tmp_path / "barragan-manifests"
    (root / "ansible" / "roles" / "firefox").mkdir(parents=True)
    _write(
        manifest_root / "capabilities" / "desktop" / "firefox.yml",
        """
apiVersion: barragan/v1
kind: Capability
metadata:
  id: firefox
  name: Firefox
  category: desktop
  description: Install Firefox on homebase using the existing role.
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
  remove: supported
""",
    )
    _write(
        manifest_root / "profiles" / "standard-rti.yml",
        """
apiVersion: barragan/v1
kind: CapabilityProfile
metadata:
  id: standard-rti
  name: Standard RTI
  description: Default Red Team Infrastructure profile.
hostClasses:
  homebase:
    essential:
      - homebase
    default:
      - firefox
""",
    )

    catalog = discover_capability_catalog(
        source=RedteamInfraTemplateSource(root, "test"),
        manifest_root=manifest_root,
    ).to_dict()

    assert catalog["status"] == "passed"
    assert catalog["invalidManifests"] == []
    assert catalog["warnings"] == []
    capabilities = {capability["id"]: capability for capability in catalog["capabilities"]}
    assert capabilities["barragan.static-web-site"]["operator"]["preferred"] is True
    assert capabilities["barragan.static-web-site"]["conflictsWith"] == ["openresty", "redteam-infra.openresty-v2"]
    assert capabilities["barragan.custom-listener"]["operator"] == {
        "visible": True,
        "selectable": False,
        "configurable": True,
        "preferred": False,
    }
    assert capabilities["barragan.custom-listener"]["placement"]["allowedHostClasses"] == ["proxy"]
    assert capabilities["barragan.backflips-v2"]["operator"] == {
        "visible": True,
        "selectable": False,
        "configurable": True,
        "preferred": True,
    }
    assert capabilities["barragan.backflips-v2"]["lifecycle"]["managedBy"] == "barragan"
    assert capabilities["firefox"] == {
        "id": "firefox",
        "name": "Firefox",
        "description": "Install Firefox on homebase using the existing role.",
        "category": "desktop",
        "manifestPath": "barragan/capabilities/desktop/firefox.yml",
        "apiVersion": "barragan/v1",
        "kind": "Capability",
        "implementation": {
            "type": "role",
            "path": "ansible/roles/firefox",
            "role": "firefox",
        },
        "placement": {"allowedHostClasses": ["homebase"]},
        "classification": "",
        "profiles": {"standard-rti": {"classification": "default"}},
        "operator": {"visible": True, "selectable": True},
        "lifecycle": {"apply": "supported", "remove": "supported"},
        "status": "valid",
    }
    assert catalog["profiles"][0]["id"] == "standard-rti"
    assert catalog["profiles"][0]["hostClasses"]["homebase"]["default"] == ["firefox"]


def test_capability_catalog_supports_json_and_reports_missing_implementation_path(tmp_path: Path) -> None:
    root = tmp_path / "redteam-infra"
    manifest_root = tmp_path / "barragan-manifests"
    payload = {
        "apiVersion": "barragan/v1",
        "kind": "Capability",
        "metadata": {
            "id": "missing-role",
            "name": "Missing Role",
            "description": "References a role path that is not present.",
        },
        "implementation": {"type": "role", "role": "missing-role", "path": "ansible/roles/missing-role"},
        "placement": {"allowedHostClasses": ["homebase"]},
        "operator": {"visible": True, "selectable": False},
    }
    _write(manifest_root / "capabilities" / "missing-role.json", json.dumps(payload))

    catalog = discover_capability_catalog(
        source=RedteamInfraTemplateSource(root, "test"),
        manifest_root=manifest_root,
    ).to_dict()

    assert catalog["status"] == "failed"
    assert [capability["id"] for capability in catalog["capabilities"]] == [
        "barragan.backflips-v2",
        "barragan.custom-listener",
        "barragan.static-web-site",
    ]
    assert catalog["invalidManifests"] == [
        {
            "path": "barragan/capabilities/missing-role.json",
            "severity": "error",
            "message": "Capability implementation path does not exist: ansible/roles/missing-role.",
        }
    ]


def test_capability_catalog_reports_no_manifests_as_warning(tmp_path: Path) -> None:
    root = tmp_path / "redteam-infra"
    manifest_root = tmp_path / "empty-barragan-manifests"

    catalog = discover_capability_catalog(
        source=RedteamInfraTemplateSource(root, "test"),
        manifest_root=manifest_root,
    ).to_dict()

    assert catalog["status"] == "warning"
    assert [capability["id"] for capability in catalog["capabilities"]] == [
        "barragan.backflips-v2",
        "barragan.custom-listener",
        "barragan.static-web-site",
    ]
    assert catalog["profiles"] == []
    assert catalog["warnings"] == [
        {
            "path": "barragan/",
            "severity": "warning",
            "message": "No capability or profile manifests were found in the Barragan manifest source.",
        }
    ]


def test_capability_catalog_loads_packaged_go_simple_upload_server_manifest_against_stock_role(tmp_path: Path) -> None:
    root = tmp_path / "redteam-infra"
    (root / "ansible" / "roles" / "go_simple_upload_server").mkdir(parents=True)

    catalog = discover_capability_catalog(source=RedteamInfraTemplateSource(root, "stock")).to_dict()

    go_simple_upload_server = next(capability for capability in catalog["capabilities"] if capability["id"] == "go-simple-upload-server")
    assert catalog["status"] == "passed"
    assert go_simple_upload_server["manifestPath"] == "barragan/capabilities/go-simple-upload-server.yml"
    assert go_simple_upload_server["implementation"] == {
        "type": "role",
        "path": "ansible/roles/go_simple_upload_server",
        "role": "go_simple_upload_server",
    }
    assert go_simple_upload_server["classification"] == "optional"
    assert go_simple_upload_server["placement"] == {"allowedHostClasses": ["homebase"]}
    assert go_simple_upload_server["operator"] == {"visible": True, "selectable": True}
    assert go_simple_upload_server["lifecycle"] == {
        "apply": "supported",
        "remove": "manual",
        "managedBy": "redteam-infra",
    }


def test_packaged_optional_role_remains_selectable_before_retained_workspace_import(tmp_path: Path) -> None:
    root = tmp_path / "old-engagement-workspace"
    (root / "ansible" / "roles").mkdir(parents=True)

    catalog = discover_capability_catalog(
        source=RedteamInfraTemplateSource(root, "engagement-workspace")
    ).to_dict()

    go_simple_upload_server = next(
        capability for capability in catalog["capabilities"]
        if capability["id"] == "go-simple-upload-server"
    )
    assert go_simple_upload_server["status"] == "valid"
    assert go_simple_upload_server["operator"] == {"visible": True, "selectable": True}
    assert go_simple_upload_server["implementation"]["role"] == "go_simple_upload_server"
    assert not any(
        issue["path"].endswith("go-simple-upload-server.yml")
        for issue in catalog["invalidManifests"]
    )
    assert any(
        issue["path"].endswith("go-simple-upload-server.yml")
        and "will be imported when selected" in issue["message"]
        for issue in catalog["warnings"]
    )


def test_capability_catalog_ignores_upstream_barragan_manifests(tmp_path: Path) -> None:
    root = tmp_path / "redteam-infra"
    manifest_root = tmp_path / "barragan-manifests"
    (root / "ansible" / "roles" / "common").mkdir(parents=True)
    _write(
        root / "barragan" / "capabilities" / "roles" / "common.yml",
        _role_manifest("common", description="unreviewed upstream override"),
    )

    catalog = discover_capability_catalog(
        source=RedteamInfraTemplateSource(root, "test"),
        manifest_root=manifest_root,
    ).to_dict()

    common = next(capability for capability in catalog["capabilities"] if capability["id"] == "common")
    assert common["description"] != "unreviewed upstream override"
    assert common["manifestPath"] == "ansible/roles/common"


def test_invalid_local_manifest_suppresses_same_role_builtin_projection(tmp_path: Path) -> None:
    root = tmp_path / "redteam-infra"
    manifest_root = tmp_path / "barragan-manifests"
    (root / "ansible" / "roles" / "firefox").mkdir(parents=True)
    _write(
        manifest_root / "capabilities" / "desktop" / "firefox.yml",
        _role_manifest("firefox", path="ansible/roles/missing-firefox"),
    )

    catalog = discover_capability_catalog(
        source=RedteamInfraTemplateSource(root, "test"),
        manifest_root=manifest_root,
    ).to_dict()

    assert catalog["status"] == "failed"
    assert "firefox" not in {capability["id"] for capability in catalog["capabilities"]}
    assert catalog["invalidManifests"] == [
        {
            "path": "barragan/capabilities/desktop/firefox.yml",
            "severity": "error",
            "message": "Capability implementation path does not exist: ansible/roles/missing-firefox.",
        }
    ]


def test_capability_catalog_marks_openresty_v2_unsupported_when_role_exists(tmp_path: Path) -> None:
    root = tmp_path / "redteam-infra"
    (root / "ansible" / "roles" / "openresty-v2").mkdir(parents=True)

    catalog = discover_capability_catalog(source=RedteamInfraTemplateSource(root, "test")).to_dict()

    capabilities = {capability["id"]: capability for capability in catalog["capabilities"]}
    assert capabilities["redteam-infra.openresty-v2"]["name"] == "OpenResty v2"
    assert capabilities["redteam-infra.openresty-v2"]["implementation"] == {
        "type": "role",
        "path": "ansible/roles/openresty-v2",
        "role": "openresty-v2",
    }
    assert capabilities["redteam-infra.openresty-v2"]["classification"] == "unsupported"
    assert capabilities["redteam-infra.openresty-v2"]["operator"] == {
        "visible": False,
        "selectable": False,
        "preferred": False,
    }
    assert capabilities["redteam-infra.openresty-v2"]["conflictsWith"] == ["barragan.static-web-site"]
    assert capabilities["redteam-infra.openresty-v2"]["lifecycle"]["apply"] == "unsupported"
    assert capabilities["redteam-infra.openresty-v2"]["lifecycle"]["managedBy"] == "redteam-infra"


def test_capability_catalog_projects_reviewed_known_roles_without_exposing_dependencies(tmp_path: Path) -> None:
    root = tmp_path / "redteam-infra"
    for role in ("aws", "docker", "engagement-workspace", "libreoffice", "loot", "mythic", "opsec", "template", "web-check"):
        (root / "ansible" / "roles" / role).mkdir(parents=True)

    catalog = discover_capability_catalog(source=RedteamInfraTemplateSource(root, "test")).to_dict()

    capabilities = {capability["id"]: capability for capability in catalog["capabilities"]}
    assert capabilities["engagement-workspace"]["operator"] == {"visible": True, "selectable": False}
    assert capabilities["engagement-workspace"]["classification"] == "essential"
    assert capabilities["engagement-workspace"]["placement"] == {"allowedHostClasses": ["homebase"]}
    assert capabilities["aws"]["operator"] == {"visible": False, "selectable": False}
    assert capabilities["aws"]["placement"] == {"allowedHostClasses": ["common"]}
    assert capabilities["aws"]["implementation"]["role"] == "aws"
    assert capabilities["libreoffice"]["operator"] == {"visible": True, "selectable": True}
    assert capabilities["libreoffice"]["placement"] == {"allowedHostClasses": ["homebase"]}
    assert capabilities["libreoffice"]["implementation"]["role"] == "libreoffice"
    assert "removes only the libreoffice meta-package" in capabilities["libreoffice"]["description"]
    assert capabilities["opsec"]["operator"] == {"visible": True, "selectable": True}
    assert capabilities["opsec"]["placement"] == {"allowedHostClasses": ["homebase"]}
    assert capabilities["opsec"]["lifecycle"]["managedBy"] == "barragan"
    assert capabilities["web-check"]["operator"] == {"visible": True, "selectable": True}
    assert capabilities["web-check"]["name"] == "Web-check"
    assert capabilities["web-check"]["placement"] == {"allowedHostClasses": ["proxy"]}
    assert capabilities["web-check"]["classification"] == "optional"
    assert capabilities["web-check"]["implementation"]["role"] == "web-check"
    assert "target or customer websites" in capabilities["web-check"]["description"]
    assert capabilities["mythic"]["operator"] == {"visible": True, "selectable": True}
    assert capabilities["mythic"]["name"] == "Mythic"
    assert capabilities["mythic"]["placement"] == {"allowedHostClasses": ["homebase"]}
    assert capabilities["mythic"]["classification"] == "optional"
    assert capabilities["mythic"]["implementation"]["role"] == "mythic"
    assert "Operators complete Mythic agents" in capabilities["mythic"]["description"]
    assert capabilities["loot"]["operator"] == {"visible": False, "selectable": False}
    assert capabilities["loot"]["classification"] == "unsupported"
    assert capabilities["loot"]["lifecycle"]["apply"] == "unsupported"
    assert capabilities["docker"]["operator"] == {"visible": True, "selectable": False}
    assert capabilities["docker"]["classification"] == "essential"
    assert capabilities["docker"]["placement"] == {"allowedHostClasses": ["proxy"]}
    assert capabilities["docker"]["implementation"]["role"] == "docker"
    assert "template" not in capabilities


def test_capability_catalog_api_preserves_read_only_shape() -> None:
    client = create_app(TestConfig).test_client()

    response = client.get("/api/templates/redteam-infra/capabilities")

    assert response.status_code == 200
    body = response.json()
    assert "catalog" in body
    assert {"source", "status", "capabilities", "profiles", "invalidManifests", "warnings"}.issubset(body["catalog"])


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.strip() + "\n", encoding="utf-8")


def _role_manifest(role: str, *, path: str | None = None, description: str | None = None) -> str:
    return f"""
apiVersion: barragan/v1
kind: AnsibleCapability
metadata:
  id: {role}
  name: {role}
  category: test
  description: {description or f'{role} capability'}
implementation:
  type: role
  role: {role}
  path: {path or f'ansible/roles/{role}'}
placement:
  allowedHostClasses:
    - common
operator:
  visible: true
  selectable: false
"""
