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


def test_inference_configuration_roundtrip_and_changed_input_requires_reapply(tmp_path, monkeypatch):
    from app.services import inference_proxy_capability as inference
    from app.services.capability_execution import build_optional_core_capability_role_apply_plan, render_core_capability_apply_playbook
    import yaml
    template = _template_source(tmp_path)
    role = template / "ansible/roles/inference_proxy/tasks"
    role.mkdir(parents=True)
    (role / "main.yml").write_text("---\n[]\n")
    repo = _FakeWorkspaceRepository()
    engagement = SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={})
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.capability_execution.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.engagement_workspaces.resolve_redteam_infra_template_source", lambda: RedteamInfraTemplateSource(template, "test"))
    monkeypatch.setattr(inference, "source_archive", lambda: b"controller-verified-fixture-archive")
    config = {"region": "us-chicago-1", "compartmentId": "ocid1.compartment.oc1..models", "port": 8787}
    body = {"selectedOptionals": [{"hostClass": "homebase", "id": "inference-proxy"}], "inferenceProxy": config}
    result = update_engagement_capability_selection("eng-abc123", body, root=tmp_path / "engagements", repository=repo, service_repository=_EmptyServiceRepository())
    assert result["inferenceProxy"]["configuration"] == config
    assert result["inferenceProxy"]["accessStatus"] == "not_verified"
    first = result["applyState"]
    loaded = engagement_capability_workspace("eng-abc123", root=tmp_path / "engagements", repository=repo, service_repository=_EmptyServiceRepository())
    assert loaded["inferenceProxy"] == result["inferenceProxy"]
    plan = build_optional_core_capability_role_apply_plan(engagement_id="eng-abc123", engagement_repos_root=tmp_path / "engagements", repository=repo)
    tasks = yaml.safe_load(render_core_capability_apply_playbook(plan))[1]["tasks"]
    role_task = next(task for task in tasks if task.get("ansible.builtin.include_role", {}).get("name") == "inference_proxy")
    assert role_task["vars"]["inference_proxy_region"] == config["region"]
    changed = update_engagement_capability_selection("eng-abc123", {**body, "inferenceProxy": {**config, "port": 8788}}, root=tmp_path / "engagements", repository=repo, service_repository=_EmptyServiceRepository())
    assert changed["applyState"]["selectionFingerprint"] != first["selectionFingerprint"]
    assert changed["applyState"]["renderedInputFingerprint"] != first["renderedInputFingerprint"]
    deselected = update_engagement_capability_selection("eng-abc123", {}, root=tmp_path / "engagements", repository=repo, service_repository=_EmptyServiceRepository())
    assert deselected["inferenceProxy"]["configuration"]["port"] == 8788


@pytest.fixture
def c2_workspace(tmp_path, monkeypatch):
    import hashlib
    from app.services import c2_observer_capability as c2
    template = _template_source(tmp_path)
    role = template / 'ansible/roles/c2_observer/tasks'
    role.mkdir(parents=True)
    (role / 'main.yml').write_text('---\n[]\n')
    repo = _FakeWorkspaceRepository()
    engagement = SimpleNamespace(id='eng-abc123', name='Demo 01', input_parameters={})
    monkeypatch.setattr('app.services.engagement_workspaces.get_engagement', lambda _id: engagement)
    monkeypatch.setattr('app.services.capability_execution.get_engagement', lambda _id: engagement)
    monkeypatch.setattr('app.services.engagement_workspaces.resolve_redteam_infra_template_source', lambda: RedteamInfraTemplateSource(template, 'test'))
    artifacts = {'source': b'controller-verified-c2-source-fixture', 'dependencyLock': b'fixture-package==1 --hash=sha256:fixture\n'}
    monkeypatch.setattr(c2, 'DEPENDENCY_SHA256', hashlib.sha256(artifacts['dependencyLock']).hexdigest())
    monkeypatch.setattr(c2, 'controller_artifacts', lambda: dict(artifacts))
    body = {'selectedOptionals': [{'hostClass': 'homebase', 'id': 'c2-observer'}]}
    return SimpleNamespace(adapter=c2, artifacts=artifacts, repo=repo, body=body, root=tmp_path/'engagements', tmp=tmp_path)


def _save_c2(fixture):
    return update_engagement_capability_selection('eng-abc123', fixture.body, root=fixture.root,
        repository=fixture.repo, service_repository=_EmptyServiceRepository())


def test_c2_save_binds_both_artifacts_to_lock_role_task_and_runtime(c2_workspace):
    import yaml
    from app.services.capability_execution import build_optional_core_capability_role_apply_plan, copy_core_capability_roles, render_core_capability_apply_playbook
    from app.services.capability_reconciliation import _public_plan
    f = c2_workspace
    result = _save_c2(f)
    assert result['applyState']['status'] == 'saved_ready'
    workspace = f.repo.workspace
    expected = f.adapter.execution_inputs(Path(workspace.path), workspace.metadata)
    lock = yaml.safe_load((Path(workspace.path)/'barragan/capability-lock.yml').read_text())
    assert lock['c2Observer'] == expected
    plan = build_optional_core_capability_role_apply_plan(engagement_id='eng-abc123', engagement_repos_root=f.root, repository=f.repo)
    assert plan.c2_observer_inputs == expected
    assert plan.to_summary()['c2Observer'] == expected
    assert _public_plan(plan, 'core-current', [{'role': 'homebase'}])['c2Observer'] == expected
    plays = yaml.safe_load(render_core_capability_apply_playbook(plan))
    task = next(task for play in plays for task in play['tasks'] if task.get('ansible.builtin.include_role', {}).get('name') == 'c2_observer')
    assert task['vars'] == f.adapter.role_variables(expected)
    assert len(task['vars']) == 5
    assert all(key.startswith('c2_observer_') for key in task['vars'])
    destination = f.tmp/'runtime'
    copy_core_capability_roles(destination, plan)
    for kind in ('source', 'dependencyLock'):
        assert (destination/expected[kind]['relativePath']).read_bytes() == f.artifacts[kind]
    assert (destination/'ansible/roles/c2_observer/tasks/main.yml').is_file()


def test_c2_same_save_noop_and_changed_source_or_lock_requires_reapply(c2_workspace, monkeypatch):
    import hashlib
    f = c2_workspace
    first = _save_c2(f)['applyState']
    unchanged = _save_c2(f)['applyState']
    assert unchanged['selectionFingerprint'] == first['selectionFingerprint']
    assert unchanged['renderedInputFingerprint'] == first['renderedInputFingerprint']
    f.artifacts['source'] = b'new-controller-verified-source-encoding'
    source_changed = _save_c2(f)['applyState']
    assert source_changed['selectionFingerprint'] != first['selectionFingerprint']
    assert source_changed['renderedInputFingerprint'] != first['renderedInputFingerprint']
    f.artifacts['dependencyLock'] = b'another-reviewed-lock-fixture\n'
    monkeypatch.setattr(f.adapter, 'DEPENDENCY_SHA256', hashlib.sha256(f.artifacts['dependencyLock']).hexdigest())
    lock_changed = _save_c2(f)['applyState']
    assert lock_changed['selectionFingerprint'] != source_changed['selectionFingerprint']
    assert lock_changed['renderedInputFingerprint'] != source_changed['renderedInputFingerprint']


def test_c2_deselection_retains_artifacts_without_selecting_a_role(c2_workspace):
    from app.services.capability_execution import build_optional_core_capability_role_apply_plan
    f = c2_workspace
    _save_c2(f)
    before = f.repo.workspace.metadata[f.adapter.ARTIFACTS_KEY]
    update_engagement_capability_selection('eng-abc123', {}, root=f.root, repository=f.repo, service_repository=_EmptyServiceRepository())
    assert f.repo.workspace.metadata[f.adapter.ARTIFACTS_KEY] == before
    plan = build_optional_core_capability_role_apply_plan(engagement_id='eng-abc123', engagement_repos_root=f.root, repository=f.repo)
    assert plan.c2_observer_inputs == {} and 'c2_observer' not in plan.role_names


@pytest.mark.parametrize('artifact', ['source', 'dependencyLock'])
def test_c2_tampered_artifact_blocks_render_plan_and_execution_copy(c2_workspace, artifact):
    from app.services.capability_execution import build_optional_core_capability_role_apply_plan, copy_core_capability_roles, CapabilityRoleApplyPlanValidationError
    from app.services.capability_lock_rendering import render_capability_lock
    f = c2_workspace
    _save_c2(f)
    plan = build_optional_core_capability_role_apply_plan(engagement_id='eng-abc123', engagement_repos_root=f.root, repository=f.repo)
    identity = plan.c2_observer_inputs[artifact]
    (Path(f.repo.workspace.path)/identity['relativePath']).write_bytes(b'tampered')
    with pytest.raises(CapabilityRoleApplyPlanValidationError):
        build_optional_core_capability_role_apply_plan(engagement_id='eng-abc123', engagement_repos_root=f.root, repository=f.repo)
    with pytest.raises(EngagementWorkspaceValidationError):
        render_capability_lock('eng-abc123', root=f.root, repository=f.repo, service_repository=_EmptyServiceRepository())
    destination = f.tmp/'unsafe-runtime'
    with pytest.raises(f.adapter.C2ObserverArtifactError):
        copy_core_capability_roles(destination, plan)
    assert not destination.exists()


@pytest.mark.parametrize('missing', ['source', 'dependencyLock'])
def test_c2_invalid_controller_inputs_fail_before_prepare_or_save(tmp_path, monkeypatch, missing):
    from app.services import c2_observer_capability as c2
    class Repository:
        def get(self, _id): return None
        def save(self, _record): pytest.fail('invalid artifacts must not save a selection')
    def invalid():
        raise c2.C2ObserverArtifactError('Controller must configure the pinned ' + missing)
    monkeypatch.setattr(c2, 'controller_artifacts', invalid)
    monkeypatch.setattr('app.services.engagement_capabilities.prepare_engagement_workspace', lambda *a, **k: pytest.fail('invalid artifacts must not prepare workspace'))
    with pytest.raises(EngagementCapabilityValidationError) as exc:
        update_engagement_capability_selection('eng-abc123', {'selectedOptionals':[{'id':'c2-observer','hostClass':'homebase'}]}, root=tmp_path, repository=Repository())
    assert missing in exc.value.errors[0]


def test_c2_reconciliation_rejects_stale_lock_before_runtime_writes(c2_workspace):
    import copy
    import yaml
    from app.services.capability_execution import build_optional_core_capability_role_apply_plan
    from app.services.capability_reconciliation import _write_reconciliation_workspace, _plan_fingerprint, CapabilityReconciliationValidationError
    f = c2_workspace
    _save_c2(f)
    plan = build_optional_core_capability_role_apply_plan(engagement_id='eng-abc123', engagement_repos_root=f.root, repository=f.repo)
    changed = copy.deepcopy(plan.c2_observer_inputs)
    changed['dependencyLock']['sha256'] = '0'*64
    destination = f.tmp/'stale-runtime'
    with pytest.raises(CapabilityReconciliationValidationError):
        _write_reconciliation_workspace(destination, plan, (), 'core-current', capability_lock=yaml.safe_dump({'c2Observer':changed}))
    assert not destination.exists()
    current = {'coreDeploymentId':'core-current','rolesByHostClass':plan.roles_by_host_class,'c2Observer':plan.c2_observer_inputs}
    assert _plan_fingerprint(current) != _plan_fingerprint({**current,'c2Observer':changed})


@pytest.fixture
def loot_workspace(tmp_path, monkeypatch):
    import hashlib
    from app.services import loottool_capability as loot
    template = _template_source(tmp_path)
    role = template / 'ansible/roles/loottool_v2/tasks'
    role.mkdir(parents=True)
    (role / 'main.yml').write_text('---\n[]\n')
    docker_role = template / 'ansible/roles/docker/tasks'
    docker_role.mkdir(parents=True)
    (docker_role / 'main.yml').write_text('---\n[]\n')
    repo = _FakeWorkspaceRepository()
    engagement = SimpleNamespace(id='eng-abc123', name='Demo 01', input_parameters={})
    monkeypatch.setattr('app.services.engagement_workspaces.get_engagement', lambda _id: engagement)
    monkeypatch.setattr('app.services.capability_execution.get_engagement', lambda _id: engagement)
    monkeypatch.setattr('app.services.engagement_workspaces.resolve_redteam_infra_template_source', lambda: RedteamInfraTemplateSource(template, 'test'))
    artifacts = {'source': b'controller-verified-loot-source-fixture', 'imageArchive': tmp_path/'reviewed-image.tar'}
    artifacts['imageArchive'].write_bytes(b'reviewed-docker-save-fixture')
    monkeypatch.setattr(loot, 'IMAGE_ARCHIVE_SHA256', hashlib.sha256(artifacts['imageArchive'].read_bytes()).hexdigest())
    monkeypatch.setattr(loot, 'controller_artifacts', lambda: dict(artifacts))
    body = {'selectedOptionals': [{'hostClass': 'homebase', 'id': 'loottool-v2'}]}
    return SimpleNamespace(adapter=loot, artifacts=artifacts, repo=repo, body=body, root=tmp_path/'engagements', tmp=tmp_path)


def _save_loot(fixture):
    return update_engagement_capability_selection('eng-abc123', fixture.body, root=fixture.root,
        repository=fixture.repo, service_repository=_EmptyServiceRepository())


def test_loot_save_binds_both_artifacts_to_lock_role_task_and_runtime(loot_workspace):
    import yaml
    from app.services.capability_execution import build_optional_core_capability_role_apply_plan, copy_core_capability_roles, render_core_capability_apply_playbook
    from app.services.capability_reconciliation import _public_plan
    f = loot_workspace
    result = _save_loot(f)
    assert result['applyState']['status'] == 'saved_ready'
    workspace = f.repo.workspace
    expected = f.adapter.execution_inputs(Path(workspace.path), workspace.metadata, engagement_id='eng-abc123')
    lock = yaml.safe_load((Path(workspace.path)/'barragan/capability-lock.yml').read_text())
    assert lock['loottool'] == expected
    plan = build_optional_core_capability_role_apply_plan(engagement_id='eng-abc123', engagement_repos_root=f.root, repository=f.repo)
    assert plan.loottool_inputs == expected
    assert plan.to_summary()['loottool'] == expected
    assert _public_plan(plan, 'core-current', [{'role': 'homebase'}])['loottool'] == expected
    plays = yaml.safe_load(render_core_capability_apply_playbook(plan))
    task = next(task for play in plays for task in play['tasks'] if task.get('ansible.builtin.include_role', {}).get('name') == 'loottool_v2')
    assert task['vars'] == f.adapter.role_variables(expected)
    assert len(task['vars']) == 13
    assert all(key.startswith('loottool_v2_') for key in task['vars'])
    destination = f.tmp/'runtime'
    copy_core_capability_roles(destination, plan)
    for kind in ('source', 'imageArchive'):
        assert (destination/expected[kind]['relativePath']).read_bytes() == (f.artifacts[kind].read_bytes() if kind == 'imageArchive' else f.artifacts[kind])
    assert (destination/'ansible/roles/loottool_v2/tasks/main.yml').is_file()


def test_loot_same_save_noop_and_changed_source_or_archive_requires_reapply(loot_workspace, monkeypatch):
    import hashlib
    f = loot_workspace
    first = _save_loot(f)['applyState']
    unchanged = _save_loot(f)['applyState']
    assert unchanged['selectionFingerprint'] == first['selectionFingerprint']
    assert unchanged['renderedInputFingerprint'] == first['renderedInputFingerprint']
    f.artifacts['source'] = b'new-controller-verified-source-encoding'
    source_changed = _save_loot(f)['applyState']
    assert source_changed['selectionFingerprint'] != first['selectionFingerprint']
    assert source_changed['renderedInputFingerprint'] != first['renderedInputFingerprint']
    f.artifacts['imageArchive'].write_bytes(b'another-reviewed-image-fixture')
    monkeypatch.setattr(f.adapter, 'IMAGE_ARCHIVE_SHA256', hashlib.sha256(f.artifacts['imageArchive'].read_bytes()).hexdigest())
    lock_changed = _save_loot(f)['applyState']
    assert lock_changed['selectionFingerprint'] != source_changed['selectionFingerprint']
    assert lock_changed['renderedInputFingerprint'] != source_changed['renderedInputFingerprint']


def test_loot_deselection_retains_artifacts_without_selecting_a_role(loot_workspace):
    from app.services.capability_execution import build_optional_core_capability_role_apply_plan
    f = loot_workspace
    _save_loot(f)
    before = f.repo.workspace.metadata[f.adapter.ARTIFACTS_KEY]
    update_engagement_capability_selection('eng-abc123', {}, root=f.root, repository=f.repo, service_repository=_EmptyServiceRepository())
    assert f.repo.workspace.metadata[f.adapter.ARTIFACTS_KEY] == before
    plan = build_optional_core_capability_role_apply_plan(engagement_id='eng-abc123', engagement_repos_root=f.root, repository=f.repo)
    assert plan.loottool_inputs == {} and 'loottool_v2' not in plan.role_names


@pytest.mark.parametrize('artifact', ['source', 'imageArchive'])
def test_loot_tampered_artifact_blocks_render_plan_and_execution_copy(loot_workspace, artifact):
    from app.services.capability_execution import build_optional_core_capability_role_apply_plan, copy_core_capability_roles, CapabilityRoleApplyPlanValidationError
    from app.services.capability_lock_rendering import render_capability_lock
    f = loot_workspace
    _save_loot(f)
    plan = build_optional_core_capability_role_apply_plan(engagement_id='eng-abc123', engagement_repos_root=f.root, repository=f.repo)
    identity = plan.loottool_inputs[artifact]
    (Path(f.repo.workspace.path)/identity['relativePath']).write_bytes(b'tampered')
    with pytest.raises(CapabilityRoleApplyPlanValidationError):
        build_optional_core_capability_role_apply_plan(engagement_id='eng-abc123', engagement_repos_root=f.root, repository=f.repo)
    with pytest.raises(EngagementWorkspaceValidationError):
        render_capability_lock('eng-abc123', root=f.root, repository=f.repo, service_repository=_EmptyServiceRepository())
    destination = f.tmp/'unsafe-runtime'
    with pytest.raises(f.adapter.LootToolArtifactError):
        copy_core_capability_roles(destination, plan)
    assert not destination.exists()


@pytest.mark.parametrize('missing', ['source', 'imageArchive'])
def test_loot_invalid_controller_inputs_fail_before_prepare_or_save(tmp_path, monkeypatch, missing):
    from app.services import loottool_capability as loot
    class Repository:
        def get(self, _id): return None
        def save(self, _record): pytest.fail('invalid artifacts must not save a selection')
    def invalid():
        raise loot.LootToolArtifactError('Controller must configure the pinned ' + missing)
    monkeypatch.setattr(loot, 'controller_artifacts', invalid)
    monkeypatch.setattr('app.services.engagement_capabilities.prepare_engagement_workspace', lambda *a, **k: pytest.fail('invalid artifacts must not prepare workspace'))
    with pytest.raises(EngagementCapabilityValidationError) as exc:
        update_engagement_capability_selection('eng-abc123', {'selectedOptionals':[{'id':'loottool-v2','hostClass':'homebase'}]}, root=tmp_path, repository=Repository())
    assert missing in exc.value.errors[0]


def test_loot_reconciliation_rejects_stale_lock_before_runtime_writes(loot_workspace):
    import copy
    import yaml
    from app.services.capability_execution import build_optional_core_capability_role_apply_plan
    from app.services.capability_reconciliation import _write_reconciliation_workspace, _plan_fingerprint, CapabilityReconciliationValidationError
    f = loot_workspace
    _save_loot(f)
    plan = build_optional_core_capability_role_apply_plan(engagement_id='eng-abc123', engagement_repos_root=f.root, repository=f.repo)
    changed = copy.deepcopy(plan.loottool_inputs)
    changed['imageArchive']['sha256'] = '0'*64
    destination = f.tmp/'stale-runtime'
    with pytest.raises(CapabilityReconciliationValidationError):
        _write_reconciliation_workspace(destination, plan, (), 'core-current', capability_lock=yaml.safe_dump({'loottool':changed}))
    assert not destination.exists()
    current = {'coreDeploymentId':'core-current','rolesByHostClass':plan.roles_by_host_class,'loottool':plan.loottool_inputs}
    assert _plan_fingerprint(current) != _plan_fingerprint({**current,'loottool':changed})


def test_loot_initial_core_plan_and_cross_engagement_metadata_fail_closed(loot_workspace):
    from dataclasses import replace
    from app.services.capability_execution import build_core_capability_role_apply_plan, build_optional_core_capability_role_apply_plan, copy_core_capability_roles, CapabilityRoleApplyPlanValidationError
    f = loot_workspace
    _save_loot(f)
    plan = build_core_capability_role_apply_plan(engagement_id='eng-abc123', engagement_repos_root=f.root, repository=f.repo)
    assert plan.errors == []
    assert plan.loottool_inputs['configuration']['evidenceScope'] == 'eng-abc123'
    assert plan.engagement_id == 'eng-abc123'
    with pytest.raises(f.adapter.LootToolArtifactError):
        copy_core_capability_roles(f.tmp/'wrong-engagement', replace(plan, engagement_id='eng-other'))
    assert not (f.tmp/'wrong-engagement').exists()
    f.repo.workspace.metadata[f.adapter.ARTIFACTS_KEY]['configuration']['evidenceScope'] = 'eng-other'
    with pytest.raises(CapabilityRoleApplyPlanValidationError):
        build_optional_core_capability_role_apply_plan(engagement_id='eng-abc123', engagement_repos_root=f.root, repository=f.repo)


@pytest.fixture
def atc_workspace(tmp_path, monkeypatch):
    import hashlib
    from app.services import atc_capability as atc
    template = _template_source(tmp_path)
    for name in ('atc', 'docker'):
        role = template / 'ansible/roles' / name / 'tasks'
        role.mkdir(parents=True)
        (role / 'main.yml').write_text('---\n[]\n')
    repo = _FakeWorkspaceRepository()
    engagement = SimpleNamespace(id='eng-abc123', name='Demo 01', input_parameters={})
    for module in ('engagement_workspaces', 'engagement_capabilities', 'capability_execution', 'capability_lock_rendering'):
        monkeypatch.setattr('app.services.'+module+'.get_engagement', lambda _id: engagement)
    monkeypatch.setattr('app.services.engagement_workspaces.resolve_redteam_infra_template_source', lambda: RedteamInfraTemplateSource(template, 'test'))
    archive = tmp_path/'native-release.tar.gz'
    archive.write_bytes(b'app-built-native-release-fixture')
    identity = {'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(), 'sourceRevision':atc.SOURCE_REVISION,
        'version':atc.RELEASE_VERSION, 'postgresImage':'docker.io/library/postgres:16@sha256:'+'a'*64, 'migrationLevel':'b'*64}
    release = {'path':str(archive), 'identity':identity}
    monkeypatch.setattr(atc, 'controller_release', lambda: release)
    monkeypatch.setattr(atc, '_verify_release', lambda *a: dict(identity))
    body = {'selectedOptionals':[{'hostClass':'homebase','id':'atc'}], 'atc':{'operatorId':'operator-one','operatorName':'Operator One','port':8790}}
    return SimpleNamespace(adapter=atc, archive=archive, release=release, identity=identity, engagement=engagement,
        repo=repo, body=body, root=tmp_path/'engagements', tmp=tmp_path)


def _save_atc(f):
    return update_engagement_capability_selection('eng-abc123', f.body, root=f.root,
        repository=f.repo, service_repository=_EmptyServiceRepository())


def test_atc_save_binds_config_trusted_context_release_to_both_plans_and_runtime(atc_workspace):
    import yaml
    from app.services.capability_execution import build_optional_core_capability_role_apply_plan, build_core_capability_role_apply_plan, copy_core_capability_roles, render_core_capability_apply_playbook
    from app.services.capability_reconciliation import _public_plan
    f = atc_workspace
    result = _save_atc(f)
    assert result['applyState']['status'] == 'saved_ready'
    assert result['atc'] == {'configuration': f.body['atc']}
    assert str(f.archive) not in str(result['atc'])
    workspace = f.repo.workspace
    expected = f.adapter.execution_inputs(Path(workspace.path), workspace.metadata)
    assert expected['engagement'] == {'id':'eng-abc123','codename':'Demo 01'}
    lock = yaml.safe_load((Path(workspace.path)/'barragan/capability-lock.yml').read_text())
    assert lock['atc'] == expected
    for build in (build_optional_core_capability_role_apply_plan, build_core_capability_role_apply_plan):
        plan = build(engagement_id='eng-abc123', engagement_repos_root=f.root, repository=f.repo)
        assert plan.atc_inputs == expected
        assert plan.to_summary()['atc'] == expected
        assert _public_plan(plan,'core-current',[{'role':'homebase'}])['atc'] == expected
        plays = yaml.safe_load(render_core_capability_apply_playbook(plan))
        task = next(task for play in plays for task in play['tasks'] if task.get('ansible.builtin.include_role',{}).get('name') == 'atc')
        assert task['vars'] == f.adapter.role_variables(expected)
        assert len(task['vars']) == 14
    destination = f.tmp/'runtime'
    copy_core_capability_roles(destination, plan)
    assert (destination/expected['release']['relativePath']).read_bytes() == f.archive.read_bytes()
    assert (destination/'ansible/roles/atc/tasks/main.yml').is_file()


def test_atc_same_save_noop_configuration_and_release_changes_require_reapply(atc_workspace):
    import hashlib
    f = atc_workspace
    first = _save_atc(f)['applyState']
    unchanged = _save_atc(f)['applyState']
    assert unchanged['selectionFingerprint'] == first['selectionFingerprint']
    assert unchanged['renderedInputFingerprint'] == first['renderedInputFingerprint']
    f.body['atc']['port'] = 8791
    changed = _save_atc(f)['applyState']
    assert changed['selectionFingerprint'] != first['selectionFingerprint']
    assert changed['renderedInputFingerprint'] != first['renderedInputFingerprint']
    f.archive.write_bytes(b'another-reviewed-native-release-fixture')
    f.identity['sha256'] = hashlib.sha256(f.archive.read_bytes()).hexdigest()
    release_changed = _save_atc(f)['applyState']
    assert release_changed['selectionFingerprint'] != changed['selectionFingerprint']
    assert release_changed['renderedInputFingerprint'] != changed['renderedInputFingerprint']


def test_atc_deselection_retains_saved_config_and_release_without_role(atc_workspace):
    from app.services.capability_execution import build_optional_core_capability_role_apply_plan
    f = atc_workspace
    _save_atc(f)
    before = dict(f.repo.workspace.metadata)
    result = update_engagement_capability_selection('eng-abc123', {}, root=f.root, repository=f.repo, service_repository=_EmptyServiceRepository())
    assert result['atc']['configuration'] == f.body['atc']
    for key in (f.adapter.CONFIGURATION_KEY,f.adapter.CONTEXT_KEY,f.adapter.RELEASE_KEY):
        assert f.repo.workspace.metadata[key] == before[key]
    plan = build_optional_core_capability_role_apply_plan(engagement_id='eng-abc123', engagement_repos_root=f.root, repository=f.repo)
    assert plan.atc_inputs == {} and 'atc' not in plan.role_names


def test_atc_tamper_blocks_render_planning_and_copy_before_runtime_writes(atc_workspace):
    from app.services.capability_execution import build_optional_core_capability_role_apply_plan, copy_core_capability_roles, CapabilityRoleApplyPlanValidationError
    from app.services.capability_lock_rendering import render_capability_lock
    f = atc_workspace
    _save_atc(f)
    plan = build_optional_core_capability_role_apply_plan(engagement_id='eng-abc123', engagement_repos_root=f.root, repository=f.repo)
    (Path(f.repo.workspace.path)/plan.atc_inputs['release']['relativePath']).write_bytes(b'tampered')
    with pytest.raises(CapabilityRoleApplyPlanValidationError):
        build_optional_core_capability_role_apply_plan(engagement_id='eng-abc123', engagement_repos_root=f.root, repository=f.repo)
    with pytest.raises(EngagementWorkspaceValidationError):
        render_capability_lock('eng-abc123',root=f.root,repository=f.repo,service_repository=_EmptyServiceRepository())
    with pytest.raises(f.adapter.ATCCapabilityError):
        copy_core_capability_roles(f.tmp/'unsafe-runtime',plan)
    assert not (f.tmp/'unsafe-runtime').exists()


@pytest.mark.parametrize('changed', ['id','name'])
def test_atc_authoritative_context_drift_blocks_saved_plan_and_copy(atc_workspace, changed):
    from app.services.capability_execution import build_optional_core_capability_role_apply_plan, copy_core_capability_roles, CapabilityRoleApplyPlanValidationError
    f = atc_workspace
    _save_atc(f)
    plan = build_optional_core_capability_role_apply_plan(engagement_id='eng-abc123',engagement_repos_root=f.root,repository=f.repo)
    setattr(f.engagement, changed, 'another-engagement')
    with pytest.raises(CapabilityRoleApplyPlanValidationError):
        build_optional_core_capability_role_apply_plan(engagement_id='eng-abc123',engagement_repos_root=f.root,repository=f.repo)
    with pytest.raises(f.adapter.ATCCapabilityError):
        copy_core_capability_roles(f.tmp/'wrong-context',plan)
    assert not (f.tmp/'wrong-context').exists()


def test_atc_reconciliation_rejects_stale_config_before_runtime_writes(atc_workspace):
    import copy
    import yaml
    from app.services.capability_execution import build_optional_core_capability_role_apply_plan
    from app.services.capability_reconciliation import _write_reconciliation_workspace, _plan_fingerprint, CapabilityReconciliationValidationError
    f = atc_workspace
    _save_atc(f)
    plan = build_optional_core_capability_role_apply_plan(engagement_id='eng-abc123',engagement_repos_root=f.root,repository=f.repo)
    changed = copy.deepcopy(plan.atc_inputs)
    changed['configuration']['port'] = 8791
    with pytest.raises(CapabilityReconciliationValidationError):
        _write_reconciliation_workspace(f.tmp/'stale',plan,(),'core-current',capability_lock=yaml.safe_dump({'atc':changed}))
    assert not (f.tmp/'stale').exists()
    current = {'coreDeploymentId':'core-current','rolesByHostClass':plan.roles_by_host_class,'atc':plan.atc_inputs}
    assert _plan_fingerprint(current) != _plan_fingerprint({**current,'atc':changed})


@pytest.mark.parametrize('invalid', ['config','release'])
def test_atc_invalid_inputs_fail_before_workspace_prepare(tmp_path,monkeypatch,invalid):
    from app.services import atc_capability as atc
    class Repository:
        def get(self,_id): return None
        def save(self,_record): pytest.fail('invalid inputs must not save')
    monkeypatch.setattr('app.services.engagement_capabilities.get_engagement',lambda _:SimpleNamespace(id='eng-abc123',name='Demo 01'))
    def invalid_release(): raise atc.ATCCapabilityError('Controller release unavailable')
    monkeypatch.setattr(atc,'controller_release',invalid_release)
    monkeypatch.setattr('app.services.engagement_capabilities.prepare_engagement_workspace',lambda *a,**k:pytest.fail('invalid inputs must not prepare'))
    body={'selectedOptionals':[{'id':'atc','hostClass':'homebase'}],'atc':{'operatorId':'operator-one','operatorName':'Operator One'}}
    if invalid == 'config': body['atc']['port']=True
    with pytest.raises(EngagementCapabilityValidationError):
        update_engagement_capability_selection('eng-abc123',body,root=tmp_path,repository=Repository())


def test_atc_concurrent_save_invalidates_old_plan_before_runtime_copy(atc_workspace):
    from app.services.capability_execution import build_optional_core_capability_role_apply_plan, copy_core_capability_roles
    f = atc_workspace
    _save_atc(f)
    plan = build_optional_core_capability_role_apply_plan(engagement_id='eng-abc123', engagement_repos_root=f.root, repository=f.repo)
    f.body['atc']['operatorName'] = 'Another Operator'
    _save_atc(f)
    with pytest.raises(f.adapter.ATCCapabilityError,match='changed'):
        copy_core_capability_roles(f.tmp/'outdated-plan',plan)
    assert not (f.tmp/'outdated-plan').exists()
