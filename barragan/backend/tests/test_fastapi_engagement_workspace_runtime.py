# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from pathlib import Path

from app.asgi import create_app
from app.core.config import TestConfig
from app.storage.engagement_repository import SqlAlchemyEngagementRepository, StoredEngagement


def test_engagement_workspace_api_prepares_and_reads_workspace(tmp_path, monkeypatch):
    template = _template_source(tmp_path)
    monkeypatch.setenv("BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT", str(template))

    class WorkspaceTestConfig(TestConfig):
        ENGAGEMENT_REPOS_ROOT = tmp_path / "engagements"

    app = create_app(WorkspaceTestConfig)
    with app.storage_context():
        SqlAlchemyEngagementRepository().save(
            StoredEngagement(
                id="eng-api123",
                name="API Demo",
                status="draft",
                owner="operator",
                template_id="standard-rti",
                active_revision=None,
                input_parameters={},
            )
        )
    client = app.test_client()

    initial = client.get("/api/engagements/eng-api123/workspace")
    assert initial.status_code == 200
    assert initial.json()["workspace"] is None

    created = client.post("/api/engagements/eng-api123/workspace")
    assert created.status_code == 201
    body = created.json()
    workspace = body["workspace"]
    assert body["created"] is True
    assert workspace["slug"] == "api-demo-engapi123"
    assert Path(workspace["path"]).is_dir()
    assert str(workspace["path"]).startswith(str(tmp_path / "engagements"))
    assert (Path(workspace["path"]) / "barragan" / "workspace-manifest.json").is_file()

    repeated = client.post("/api/engagements/eng-api123/workspace")
    assert repeated.status_code == 200
    assert repeated.json()["created"] is False
    assert repeated.json()["workspace"]["path"] == workspace["path"]

    fetched = client.get("/api/engagements/eng-api123/workspace")
    assert fetched.status_code == 200
    assert fetched.json()["workspace"]["path"] == workspace["path"]


def test_metadata_creation_prepares_draft_workspace(tmp_path, monkeypatch):
    template = _template_source(tmp_path)
    monkeypatch.setenv("BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT", str(template))

    class WorkspaceTestConfig(TestConfig):
        ENGAGEMENT_REPOS_ROOT = tmp_path / "engagements"

    app = create_app(WorkspaceTestConfig)
    client = app.test_client()
    created = client.post("/api/engagements", json={"name": "Metadata Only", "owner": "operator"})

    assert created.status_code == 201
    engagement = created.json()["engagement"]
    assert engagement["status"] == "draft"
    assert engagement["templateId"] is None
    workspace = client.get(f"/api/engagements/{engagement['id']}/workspace")
    assert workspace.status_code == 200
    assert workspace.json()["workspace"]["status"] == "prepared"
    root = Path(workspace.json()["workspace"]["path"])
    assert (root / "barragan" / "workspace-manifest.json").is_file()
    assert not list(root.rglob("*.tfstate"))
    assert not list(root.rglob(".terraform"))


def test_engagement_workspace_api_renders_capability_lock(tmp_path, monkeypatch):
    template = _template_source(tmp_path)
    for role in (
        "common",
        "molly-guard",
        "logstash",
        "yama",
        "oci",
        "nfs-server",
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
    ):
        (template / "ansible" / "roles" / role).mkdir(parents=True)
    monkeypatch.setenv("BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT", str(template))

    class WorkspaceTestConfig(TestConfig):
        ENGAGEMENT_REPOS_ROOT = tmp_path / "engagements"

    app = create_app(WorkspaceTestConfig)
    with app.storage_context():
        SqlAlchemyEngagementRepository().save(
            StoredEngagement(
                id="eng-api123",
                name="API Demo",
                status="draft",
                owner="operator",
                template_id="standard-rti",
                active_revision=None,
                input_parameters={},
            )
        )
    client = app.test_client()

    missing = client.post("/api/engagements/eng-api123/workspace/capability-lock")
    assert missing.status_code == 400
    assert missing.json()["errors"] == ["engagement workspace must be prepared before rendering capability artifacts"]

    prepared = client.post("/api/engagements/eng-api123/workspace")
    assert prepared.status_code == 201
    workspace_path = Path(prepared.json()["workspace"]["path"])

    rendered = client.post("/api/engagements/eng-api123/workspace/capability-lock")
    assert rendered.status_code == 200
    body = rendered.json()["render"]
    assert body["capabilityLock"]["relativePath"] == "barragan/capability-lock.yml"
    assert body["capabilityLock"]["status"] == "passed"
    assert body["capabilityLock"]["summary"]["missingManifest"] == 0
    assert (workspace_path / "barragan" / "capability-lock.yml").is_file()
    assert body["workspace"]["status"] == "capability-lock-rendered"


def test_engagement_capabilities_api_updates_overrides_and_lock(tmp_path, monkeypatch):
    template = _template_source(tmp_path)
    for role in (
        "common",
        "molly-guard",
        "logstash",
        "yama",
        "oci",
        "nfs-server",
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
    ):
        (template / "ansible" / "roles" / role).mkdir(parents=True)
        _write_manifest(template / "barragan" / "capabilities" / "roles" / f"{role}.yml", role)
    _write_profile(template / "barragan" / "profiles" / "standard-rti.yml")
    monkeypatch.setenv("BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT", str(template))

    class WorkspaceTestConfig(TestConfig):
        ENGAGEMENT_REPOS_ROOT = tmp_path / "engagements"

    app = create_app(WorkspaceTestConfig)
    with app.storage_context():
        SqlAlchemyEngagementRepository().save(
            StoredEngagement(
                id="eng-api123",
                name="API Demo",
                status="draft",
                owner="operator",
                template_id="standard-rti",
                active_revision=None,
                input_parameters={},
            )
        )
    client = app.test_client()

    initial = client.get("/api/engagements/eng-api123/capabilities")
    assert initial.status_code == 200
    assert initial.json()["capabilities"]["workspace"] is None
    firefox_initial = next(
        entry
        for entry in initial.json()["capabilities"]["profileResolution"]["hostClasses"]["homebase"]["default"]
        if entry["id"] == "firefox"
    )
    assert firefox_initial["selected"] is True

    updated = client.patch(
        "/api/engagements/eng-api123/capabilities",
        json={"deselectedDefaults": [{"hostClass": "homebase", "id": "firefox"}]},
    )
    assert updated.status_code == 200
    body = updated.json()["capabilities"]
    assert body["workspace"]["status"] == "capability-lock-rendered"
    assert body["applyState"]["status"] == "saved_ready"
    firefox = next(entry for entry in body["profileResolution"]["hostClasses"]["homebase"]["default"] if entry["id"] == "firefox")
    assert firefox["selected"] is False
    assert body["overrides"]["deselectedDefaults"] == [{"hostClass": "homebase", "id": "firefox"}]

    rejected = client.patch(
        "/api/engagements/eng-api123/capabilities",
        json={"deselectedDefaults": [{"hostClass": "common", "id": "common"}]},
    )
    assert rejected.status_code == 400
    assert rejected.json()["errors"] == ["essential capability cannot be deselected: common/common"]

    rendered = client.post("/api/engagements/eng-api123/workspace/capability-lock")
    assert rendered.status_code == 200
    lock = rendered.json()["render"]["capabilityLock"]
    assert lock["status"] == "passed"
    assert "- id: firefox" in lock["content"]
    assert "deselectedDefaults:" in lock["content"]
    assert "selected: false" in lock["content"]


def test_engagement_workspace_api_returns_404_for_missing_engagement(tmp_path, monkeypatch):
    monkeypatch.setenv("BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT", str(_template_source(tmp_path)))

    class WorkspaceTestConfig(TestConfig):
        ENGAGEMENT_REPOS_ROOT = tmp_path / "engagements"

    client = create_app(WorkspaceTestConfig).test_client()

    assert client.get("/api/engagements/eng-missing/workspace").status_code == 404
    assert client.post("/api/engagements/eng-missing/workspace").status_code == 404
    assert client.post("/api/engagements/eng-missing/workspace/capability-lock").status_code == 404
    assert client.get("/api/engagements/eng-missing/capabilities").status_code == 404
    assert client.patch("/api/engagements/eng-missing/capabilities", json={}).status_code == 404


def _template_source(tmp_path: Path) -> Path:
    source = tmp_path / "redteam-infra"
    (source / "ansible").mkdir(parents=True, exist_ok=True)
    (source / "external").mkdir(parents=True, exist_ok=True)
    (source / "ansible" / "site.yml").write_text("---\n", encoding="utf-8")
    return source


def _write_manifest(path: Path, role: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    selectable = role in {"etherpad", "google-chrome", "firefox", "keepassxc", "vs-code", "nmap", "elk", "unattended-upgrades"}
    host_classes = ["homebase", "proxy"] if role == "nmap" else ["proxy", "elk"] if role == "unattended-upgrades" else ["common"]
    if role in {"nfs-server", "homebase", "etherpad", "google-chrome", "firefox", "keepassxc", "vs-code"}:
        host_classes = ["homebase"]
    elif role in {"nfs-client", "ssh-proxy", "dante-server", "proxies"}:
        host_classes = ["proxy"]
    elif role == "elk":
        host_classes = ["elk"]
    path.write_text(
        "\n".join(
            [
                "apiVersion: barragan/v1",
                "kind: AnsibleCapability",
                "metadata:",
                f"  id: {role}",
                f"  name: {role}",
                "  category: test",
                f"  description: {role} capability.",
                "implementation:",
                "  type: role",
                f"  role: {role}",
                f"  path: ansible/roles/{role}",
                "placement:",
                "  allowedHostClasses:",
                *[f"    - {host_class}" for host_class in host_classes],
                "operator:",
                "  visible: true",
                f"  selectable: {str(selectable).lower()}",
                "lifecycle:",
                "  apply: supported",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_profile(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """
apiVersion: barragan/v1
kind: CapabilityProfile
metadata:
  id: standard-rti
  name: Standard RTI
  description: Standard Red Team Infrastructure baseline capability profile.
hostClasses:
  common:
    essential: [common, molly-guard, logstash, yama, oci]
    default: []
  homebase:
    essential: [nfs-server, homebase]
    default: [etherpad, google-chrome, firefox, keepassxc, vs-code, nmap]
  proxy:
    essential: [docker, nfs-client, ssh-proxy, dante-server, unattended-upgrades, proxies]
    default: []
  elk:
    essential: []
    default: [elk, unattended-upgrades]
""".strip()
        + "\n",
        encoding="utf-8",
    )
