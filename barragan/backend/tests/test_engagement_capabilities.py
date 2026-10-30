# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.engagement_capabilities import (
    CapabilityPreparationError,
    EngagementCapabilityValidationError,
    _backflips_readiness,
    desktop_capability_reconciliation_input,
    engagement_capability_workspace,
    update_engagement_capability_selection,
)
from app.domain import JobEvent
from app.storage.job_repository import StoredJobRun
from app.services.engagement_workspaces import EngagementWorkspaceValidationError, prepare_engagement_workspace
from app.services.redteam_infra_template import RedteamInfraTemplateSource
from app.storage.engagement_workspace_repository import StoredEngagementWorkspace
from app.storage.service_repository import StoredEngagementService


@pytest.fixture(autouse=True)
def isolated_capability_read_dependencies(monkeypatch):
    # These unit tests supply in-memory workspaces/services. Keep the lock
    # renderer and readiness reader on the same synthetic engagement authority.
    engagement = SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={})
    monkeypatch.setattr("app.services.capability_lock_rendering.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.engagement_capabilities.get_engagement", lambda _id: engagement)
    monkeypatch.setattr(
        "app.services.engagement_capabilities.SqlAlchemyJobRepository",
        lambda: SimpleNamespace(list_for_engagement=lambda _id: []),
    )


class _EmptyServiceRepository:
    def list_for_engagement(self, _engagement_id: str):
        return []


class _ServiceRepository(_EmptyServiceRepository):
    def __init__(self, services):
        self.services = services

    def list_for_engagement(self, engagement_id: str):
        return [service for service in self.services if service.engagement_id == engagement_id]


def _static_site(status: str) -> StoredEngagementService:
    return StoredEngagementService(
        engagement_id="eng-abc123",
        service_id="web-static-demo",
        service_type="web-static",
        name="Static Web",
        proxy_id="proxy01",
        status=status,
        config={},
    )


STANDARD_RTI_ROLES = (
    "common",
    "molly-guard",
    "logstash",
    "yama",
    "aws",
    "oci",
    "nfs-server",
    "homebase",
    "go_simple_upload_server",
    "etherpad",
    "google-chrome",
    "firefox",
    "keepassxc",
    "vs-code",
    "libreoffice",
    "nmap",
    "nfs-client",
    "ssh-proxy",
    "dante-server",
    "unattended-upgrades",
    "proxies",
    "elk",
)


def test_update_capability_selection_persists_deselected_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _FakeWorkspaceRepository()
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))
    monkeypatch.setattr(
        "app.services.engagement_workspaces.resolve_redteam_infra_template_source",
        lambda: RedteamInfraTemplateSource(_template_source(tmp_path), "test"),
    )

    result = update_engagement_capability_selection(
        "eng-abc123",
        {"deselectedDefaults": [{"hostClass": "homebase", "id": "firefox"}]},
        root=tmp_path / "engagements",
        repository=repo,
        service_repository=_EmptyServiceRepository(),
    )

    assert result is not None
    assert result["workspace"]["status"] == "capability-lock-rendered"
    assert result["applyState"]["status"] == "saved_ready"
    assert result["overrides"]["deselectedDefaults"] == [{"hostClass": "homebase", "id": "firefox"}]
    firefox = next(entry for entry in result["profileResolution"]["hostClasses"]["homebase"]["default"] if entry["id"] == "firefox")
    chrome = next(entry for entry in result["profileResolution"]["hostClasses"]["homebase"]["default"] if entry["id"] == "google-chrome")
    assert firefox["selected"] is False
    assert chrome["selected"] is True
    assert repo.workspace is not None
    assert repo.workspace.metadata["capabilityOverrides"]["deselectedDefaults"] == [{"hostClass": "homebase", "id": "firefox"}]


def test_prepare_failure_preserves_saved_selection_and_durable_blocker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _FakeWorkspaceRepository()
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))
    monkeypatch.setattr(
        "app.services.engagement_workspaces.resolve_redteam_infra_template_source",
        lambda: RedteamInfraTemplateSource(_template_source(tmp_path), "test"),
    )
    monkeypatch.setattr(
        "app.services.capability_lock_rendering.render_capability_lock",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(EngagementWorkspaceValidationError(["render input is invalid"])),
    )

    with pytest.raises(CapabilityPreparationError) as exc:
        update_engagement_capability_selection(
            "eng-abc123",
            {"deselectedDefaults": [{"hostClass": "homebase", "id": "firefox"}]},
            root=tmp_path / "engagements",
            repository=repo,
            service_repository=_EmptyServiceRepository(),
        )

    assert exc.value.errors == ["render input is invalid"]
    assert repo.workspace is not None
    assert repo.workspace.metadata["capabilityOverrides"]["deselectedDefaults"] == [{"hostClass": "homebase", "id": "firefox"}]
    assert repo.workspace.metadata["capabilityApplyState"]["status"] == "blocked"
    assert repo.workspace.metadata["capabilityApplyState"]["errors"] == ["render input is invalid"]


def test_go_simple_upload_server_selection_is_optional_and_persisted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _FakeWorkspaceRepository()
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))
    monkeypatch.setattr("app.services.engagement_capabilities.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={}))
    monkeypatch.setattr(
        "app.services.engagement_workspaces.resolve_redteam_infra_template_source",
        lambda: RedteamInfraTemplateSource(_template_source(tmp_path), "test"),
    )

    unselected = update_engagement_capability_selection(
        "eng-abc123",
        {"selectedOptionals": []},
        root=tmp_path / "engagements",
        repository=repo,
        service_repository=_EmptyServiceRepository(),
    )
    assert unselected is not None
    go_simple_upload_server = next(
        entry
        for entry in unselected["profileResolution"]["hostClasses"]["homebase"]["optional"]
        if entry["id"] == "go-simple-upload-server"
    )
    assert go_simple_upload_server["selected"] is False

    selected = update_engagement_capability_selection(
        "eng-abc123",
        {"selectedOptionals": [{"hostClass": "homebase", "id": "go-simple-upload-server"}]},
        root=tmp_path / "engagements",
        repository=repo,
        service_repository=_EmptyServiceRepository(),
    )

    assert selected is not None
    assert selected["overrides"]["selectedOptionals"] == [{"hostClass": "homebase", "id": "go-simple-upload-server"}]
    go_simple_upload_server = next(
        entry
        for entry in selected["profileResolution"]["hostClasses"]["homebase"]["optional"]
        if entry["id"] == "go-simple-upload-server"
    )
    assert go_simple_upload_server["selected"] is True
    assert go_simple_upload_server["executable"] is True


def test_update_capability_selection_rejects_essential_deselection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _FakeWorkspaceRepository()
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))
    monkeypatch.setattr(
        "app.services.engagement_workspaces.resolve_redteam_infra_template_source",
        lambda: RedteamInfraTemplateSource(_template_source(tmp_path), "test"),
    )
    prepared = prepare_engagement_workspace("eng-abc123", root=tmp_path / "engagements", repository=repo)
    assert prepared is not None

    with pytest.raises(EngagementCapabilityValidationError) as exc:
        update_engagement_capability_selection(
            "eng-abc123",
            {"deselectedDefaults": [{"hostClass": "common", "id": "common"}]},
            root=tmp_path / "engagements",
            repository=repo,
            service_repository=_EmptyServiceRepository(),
        )

    assert exc.value.errors == ["essential capability cannot be deselected: common/common"]


def test_desktop_reconciliation_is_derived_from_saved_capability_selection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _FakeWorkspaceRepository()
    engagement = SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={})
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.engagement_capabilities.get_engagement", lambda _id: engagement)
    monkeypatch.setattr(
        "app.services.engagement_workspaces.resolve_redteam_infra_template_source",
        lambda: RedteamInfraTemplateSource(_template_source(tmp_path), "test"),
    )
    updated = update_engagement_capability_selection(
        "eng-abc123",
        {
            "deselectedDefaults": [{"hostClass": "homebase", "id": "firefox"}],
            "selectedOptionals": [{"hostClass": "homebase", "id": "libreoffice"}],
        },
        root=tmp_path / "engagements",
        repository=repo,
        service_repository=_EmptyServiceRepository(),
    )
    assert updated is not None

    resolved = desktop_capability_reconciliation_input(
        "eng-abc123",
        root=tmp_path / "engagements",
        repository=repo,
        service_repository=_EmptyServiceRepository(),
    )

    assert resolved is not None
    desired_apps, source = resolved
    assert desired_apps == [
        {"slug": "google-chrome", "enabled": True},
        {"slug": "firefox", "enabled": False},
        {"slug": "vs-code", "enabled": True},
        {"slug": "libreoffice", "enabled": True},
        {"slug": "keepassxc", "enabled": True},
    ]
    assert source["kind"] == "engagement-capability-selection"
    assert "firefox" not in source["selectedCapabilityIds"]


def test_active_static_site_implies_selection_without_writing_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _FakeWorkspaceRepository()
    engagement = SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={})
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.engagement_capabilities.get_engagement", lambda _id: engagement)
    monkeypatch.setattr(
        "app.services.engagement_workspaces.resolve_redteam_infra_template_source",
        lambda: RedteamInfraTemplateSource(_template_source(tmp_path), "test"),
    )
    prepared = prepare_engagement_workspace("eng-abc123", root=tmp_path / "engagements", repository=repo)
    assert prepared is not None
    before = repo.workspace

    result = engagement_capability_workspace(
        "eng-abc123",
        root=tmp_path / "engagements",
        repository=repo,
        service_repository=_ServiceRepository([_static_site("Active")]),
    )

    assert result is not None
    assert repo.workspace is before
    assert result["nativeState"]["staticWeb"]["implied"] is True
    assert result["nativeState"]["backflips"] == {
        "configureRoute": "backflips",
        "proxies": [
            {"proxyId": "proxy01", "status": "Waiting", "jobId": ""},
            {"proxyId": "proxy02", "status": "Waiting", "jobId": ""},
        ],
    }
    assert {"hostClass": "proxy", "id": "barragan.static-web-site"} in result["overrides"]["selectedOptionals"]


def test_active_static_site_cannot_be_explicitly_deselected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _FakeWorkspaceRepository()
    engagement = SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={})
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: engagement)
    monkeypatch.setattr(
        "app.services.engagement_workspaces.resolve_redteam_infra_template_source",
        lambda: RedteamInfraTemplateSource(_template_source(tmp_path), "test"),
    )
    selected = update_engagement_capability_selection(
        "eng-abc123",
        {"selectedOptionals": [{"hostClass": "proxy", "id": "barragan.static-web-site"}]},
        root=tmp_path / "engagements",
        repository=repo,
        service_repository=_EmptyServiceRepository(),
    )
    assert selected is not None

    with pytest.raises(EngagementCapabilityValidationError) as exc:
        update_engagement_capability_selection(
            "eng-abc123",
            {"selectedOptionals": []},
            root=tmp_path / "engagements",
            repository=repo,
            service_repository=_ServiceRepository([_static_site("Configured")]),
        )

    assert "Remove those sites before deselecting" in exc.value.errors[0]


def test_removed_static_site_does_not_force_selection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _FakeWorkspaceRepository()
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))
    monkeypatch.setattr(
        "app.services.engagement_workspaces.resolve_redteam_infra_template_source",
        lambda: RedteamInfraTemplateSource(_template_source(tmp_path), "test"),
    )

    result = update_engagement_capability_selection(
        "eng-abc123",
        {"selectedOptionals": []},
        root=tmp_path / "engagements",
        repository=repo,
        service_repository=_ServiceRepository([_static_site("Removed")]),
    )

    assert result is not None
    assert result["nativeState"]["staticWeb"]["claimed"] is False
    assert result["overrides"]["selectedOptionals"] == []


def test_backflips_readiness_only_uses_current_core_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    old_core = _core_job("job-core-old", "proxy01-old", "192.0.2.10", "2026-08-01T00:00:00+00:00")
    current_core = _core_job("job-core-current", "proxy01-current", "192.0.2.20", "2026-08-02T00:00:00+00:00")
    old_apply = _backflips_job(
        "job-backflips-old",
        "job-core-old",
        {"displayName": "proxy01-old", "publicIp": "", "privateIp": "192.0.2.10", "sshAlias": "proxy01"},
    )

    class Repository:
        def list(self):
            return [current_core, old_apply, old_core]

        def list_for_engagement(self, _engagement_id):
            return self.list()

    monkeypatch.setattr("app.services.engagement_capabilities.SqlAlchemyJobRepository", Repository)
    engagement = SimpleNamespace(id="eng-abc123", input_parameters={"proxyCount": 1})

    assert _backflips_readiness(engagement)["proxies"] == [
        {"proxyId": "proxy01", "status": "Waiting", "jobId": ""}
    ]

    current_apply = _backflips_job(
        "job-backflips-current",
        "job-core-current",
        {"displayName": "proxy01-current", "publicIp": "", "privateIp": "192.0.2.20", "sshAlias": "proxy01"},
    )
    repository = Repository()
    repository.list = lambda: [current_apply, current_core, old_apply, old_core]
    repository.list_for_engagement = lambda _engagement_id: repository.list()
    monkeypatch.setattr("app.services.engagement_capabilities.SqlAlchemyJobRepository", lambda: repository)

    assert _backflips_readiness(engagement)["proxies"] == [
        {"proxyId": "proxy01", "status": "Ready", "jobId": "job-backflips-current"}
    ]


def _core_job(job_id: str, display_name: str, private_ip: str, created_at: str) -> StoredJobRun:
    return StoredJobRun(
        id=job_id,
        action="pilot_standard_rti_guarded_execute",
        status="succeeded",
        target="engagement:eng-abc123",
        target_type="engagement",
        target_id="eng-abc123",
        requested_by="operator",
        input={"engagementId": "eng-abc123"},
        artifact_refs=[],
        created_at=created_at,
        started_at=created_at,
        finished_at=created_at,
        events=[JobEvent(1, "info", "deployed", {"mutationStatus": "deployed", "connectionDetails": [
            {"role": "homebase", "displayName": "homebase", "publicIp": "198.51.100.1"},
            {"role": "proxy", "displayName": display_name, "privateIp": private_ip},
        ]})],
    )


def _backflips_job(job_id: str, deployment_id: str, proxy_identity: dict[str, str]) -> StoredJobRun:
    return StoredJobRun(
        id=job_id,
        action="backflips_service_apply",
        status="succeeded",
        target="engagement:eng-abc123",
        target_type="engagement",
        target_id="eng-abc123",
        requested_by="operator",
        input={
            "engagementId": "eng-abc123",
            "proxyId": "proxy01",
            "coreDeploymentId": deployment_id,
            "coreProxyIdentity": proxy_identity,
        },
        artifact_refs=[],
        created_at="2026-08-03T00:00:00+00:00",
        started_at=None,
        finished_at=None,
        events=[],
    )


def _template_source(tmp_path: Path) -> Path:
    source = tmp_path / "redteam-infra"
    (source / "external").mkdir(parents=True, exist_ok=True)
    (source / "ansible").mkdir(parents=True, exist_ok=True)
    (source / "ansible" / "site.yml").write_text("---\n", encoding="utf-8")
    for role in STANDARD_RTI_ROLES:
        (source / "ansible" / "roles" / role).mkdir(parents=True)
    for role in STANDARD_RTI_ROLES:
        _write_manifest(source / "barragan" / "capabilities" / "roles" / f"{role}.yml", role)
    _write_profile(source / "barragan" / "profiles" / "standard-rti.yml")
    return source


def _write_manifest(path: Path, role: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    selectable = role in {"etherpad", "google-chrome", "firefox", "keepassxc", "vs-code", "libreoffice", "nmap", "elk", "unattended-upgrades"}
    host_classes = ["homebase", "proxy"] if role == "nmap" else ["proxy", "elk"] if role == "unattended-upgrades" else ["common"]
    if role in {"nfs-server", "homebase", "etherpad", "google-chrome", "firefox", "keepassxc", "vs-code", "libreoffice"}:
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


class _FakeWorkspaceRepository:
    def __init__(self, workspace: StoredEngagementWorkspace | None = None) -> None:
        self.workspace = workspace

    def get(self, engagement_id: str) -> StoredEngagementWorkspace | None:
        if self.workspace is not None and self.workspace.engagement_id == engagement_id:
            return self.workspace
        return None

    def save(self, workspace: StoredEngagementWorkspace) -> StoredEngagementWorkspace:
        self.workspace = workspace
        return workspace
