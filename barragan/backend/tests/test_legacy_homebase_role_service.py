# Copyright (c) 2026, Oracle and/or its affiliates.
import subprocess

import pytest

from app.domain import JobEvent
from app.services.legacy_homebase_role_service import (
    SUPPORTED_LEGACY_HOMEBASEROLES,
    LegacyHomebaseRoleServiceValidationError,
    LegacyRoleHost,
    _ansible_task_name,
    _ansible_task_result,
    apply_desktop_service,
    apply_legacy_homebase_role_service,
    list_desktop_service_catalog,
    preview_desktop_service_apply,
    preview_legacy_homebase_role_service_apply,
    render_desktop_apply_workspace,
    render_legacy_homebase_role_apply_workspace,
)
from app.storage.job_repository import StoredJobRun


def test_renders_keepassxc_workspace_for_homebase_only():
    workspace = render_legacy_homebase_role_apply_workspace(
        spec=SUPPORTED_LEGACY_HOMEBASEROLES["keepassxc"],
        homebase=LegacyRoleHost("homebase", "203.0.113.10", "ubuntu", "/keys/core", "/tmp/known_hosts"),
    )

    assert workspace.to_dict()["status"] == "Pending Service Apply"
    assert workspace.to_dict()["mutation"] is False
    assert workspace.inventory.target == "ansible/inventory.ini"
    assert "[selected_homebase]" in workspace.inventory.content
    assert "homebase ansible_host=203.0.113.10 ansible_user=ubuntu" in workspace.inventory.content
    assert "UserKnownHostsFile=/tmp/known_hosts" in workspace.inventory.content
    assert "[selected_proxy]" not in workspace.inventory.content
    assert "middle-" not in workspace.inventory.content
    assert "edge-" not in workspace.inventory.content

    assert workspace.playbook.target == "ansible/apply_keepassxc.yml"
    assert "hosts: selected_homebase" in workspace.playbook.content
    assert "role: keepassxc" in workspace.playbook.content
    assert "hosts: selected_proxy" not in workspace.playbook.content

    assert '"proxyTargets": []' in workspace.manifest.content
    assert '"sketchMiddleTargets": []' in workspace.manifest.content
    assert '"sketchEdgeTargets": []' in workspace.manifest.content
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(workspace.to_dict())


def test_preview_keepassxc_uses_latest_homebase_connection_details(monkeypatch):
    monkeypatch.setattr("app.services.legacy_homebase_role_service.get_engagement", lambda engagement_id: object())
    repo = _FakeJobRepository(_core_jobs())

    result = preview_legacy_homebase_role_service_apply("eng-zy01", "keepassxc", repository=repo)

    assert result is not None
    assert result["job"]["action"] == "legacy_homebase_role_service_apply_preview"
    assert result["workspace"]["inventory"]["target"] == "ansible/inventory.ini"
    assert "homebase ansible_host=203.0.113.10" in result["workspace"]["inventory"]["content"]
    assert "role: keepassxc" in result["workspace"]["playbook"]["content"]
    assert result["service"]["service"] == "KeePassXC"
    assert result["service"]["hostId"] == "homebase"
    assert result["service"]["status"] == "Pending Service Apply"


def test_preview_keepassxc_rejects_missing_homebase_connection_details(monkeypatch):
    monkeypatch.setattr("app.services.legacy_homebase_role_service.get_engagement", lambda engagement_id: object())

    with pytest.raises(LegacyHomebaseRoleServiceValidationError) as exc:
        preview_legacy_homebase_role_service_apply("eng-zy01", "keepassxc", repository=_FakeJobRepository([]))

    assert "latest core deployment connectionDetails must include homebase" in exc.value.errors


def test_apply_keepassxc_requires_confirmation_before_resolving_ansible(monkeypatch):
    monkeypatch.setattr("app.services.legacy_homebase_role_service.get_engagement", lambda engagement_id: object())

    with pytest.raises(LegacyHomebaseRoleServiceValidationError) as exc:
        apply_legacy_homebase_role_service("eng-zy01", "keepassxc", confirmation="wrong", repository=_FakeJobRepository(_core_jobs()))

    assert 'confirmation must equal "apply-service-keepassxc"' in exc.value.errors


def test_apply_keepassxc_writes_workspace_and_runs_one_playbook(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.legacy_homebase_role_service.get_engagement", lambda engagement_id: object())
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    commands = []

    def runner(command, cwd):
        commands.append((command, cwd))
        inventory = (cwd / "ansible" / "inventory.ini").read_text(encoding="utf-8")
        assert inventory.count("[selected_homebase]") == 1
        assert "selected_proxy" not in inventory
        assert "middle-" not in inventory
        assert "edge-" not in inventory
        return subprocess.CompletedProcess(command, 0, "ok", "")

    result = apply_legacy_homebase_role_service(
        "eng-zy01",
        "keepassxc",
        confirmation="apply-service-keepassxc",
        repository=_FakeJobRepository(_core_jobs()),
        runner=runner,
        env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
        workspace_root=tmp_path / "workspaces",
    )

    assert result is not None
    assert result["status"] == "Configured"
    assert result["job"]["status"] == "succeeded"
    assert commands[0][0] == [str(ansible_playbook), "-i", "ansible/inventory.ini", "ansible/apply_keepassxc.yml"]
    final_event = result["job"]["events"][-1]["data"]
    assert final_event["servicePlacements"][0]["service"] == "KeePassXC"
    assert final_event["servicePlacements"][0]["hostId"] == "homebase"
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(result)


def test_desktop_catalog_groups_gui_apps_without_nmap(monkeypatch):
    monkeypatch.setattr("app.services.legacy_homebase_role_service.get_engagement", lambda engagement_id: object())

    result = list_desktop_service_catalog()

    assert result["service"]["serviceId"] == "desktop"
    slugs = [app["slug"] for app in result["apps"]]
    assert slugs == ["google-chrome", "firefox", "vs-code", "libreoffice", "keepassxc"]
    assert "nmap" not in slugs


def test_desktop_workspace_installs_enabled_apps_and_removes_disabled_apps():
    workspace = render_desktop_apply_workspace(
        intents=[
            {"spec": SUPPORTED_LEGACY_HOMEBASEROLES["google-chrome"], "enabled": True},
            {"spec": SUPPORTED_LEGACY_HOMEBASEROLES["firefox"], "enabled": False},
        ],
        homebase=LegacyRoleHost("homebase", "203.0.113.10", "ubuntu", "/keys/core", "/tmp/known_hosts"),
    )

    assert workspace.playbook.target == "ansible/apply_desktop.yml"
    assert "name: google-chrome" in workspace.playbook.content
    assert "name: firefox" in workspace.playbook.content
    assert "state: absent" in workspace.playbook.content
    assert "/etc/firefox/policies/policies.json" in workspace.playbook.content
    assert "selected_proxy" not in workspace.inventory.content
    assert '"service": "Desktop"' in workspace.manifest.content


def test_preview_desktop_service_uses_desired_app_matrix(monkeypatch):
    monkeypatch.setattr("app.services.legacy_homebase_role_service.get_engagement", lambda engagement_id: object())
    repo = _FakeJobRepository(_core_jobs())

    result = preview_desktop_service_apply(
        "eng-zy01",
        desired_apps=[{"slug": "google-chrome", "enabled": True}, {"slug": "firefox", "enabled": False}],
        repository=repo,
    )

    assert result["job"]["action"] == "desktop_service_apply_preview"
    assert result["confirmation"] == "apply-service-desktop"
    assert "name: google-chrome" in result["workspace"]["playbook"]["content"]
    assert "Remove Desktop app package Firefox" in result["workspace"]["playbook"]["content"]
    assert "autoremove: false" in result["workspace"]["playbook"]["content"]
    assert [placement["service"] for placement in result["servicePlacements"]] == ["Google Chrome", "Firefox"]
    assert result["servicePlacements"][0]["status"] == "Pending Install"
    assert result["servicePlacements"][1]["status"] == "Pending Removal"


def test_apply_desktop_service_writes_workspace_and_runs_one_playbook(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.legacy_homebase_role_service.get_engagement", lambda engagement_id: object())
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    commands = []

    def runner(command, cwd):
        commands.append((command, cwd))
        playbook = (cwd / "ansible" / "apply_desktop.yml").read_text(encoding="utf-8")
        assert "name: google-chrome" in playbook
        assert "name: libreoffice" in playbook
        assert "selected_proxy" not in (cwd / "ansible" / "inventory.ini").read_text(encoding="utf-8")
        chrome_tasks = (cwd / "ansible" / "roles" / "google-chrome" / "tasks" / "main.yml").read_text(encoding="utf-8")
        assert "register: google_chrome_gpg_key_result" in chrome_tasks
        assert "until: google_chrome_gpg_key_result is succeeded" in chrome_tasks
        assert "until: result is succeeded" not in chrome_tasks
        return subprocess.CompletedProcess(command, 0, "ok", "")

    result = apply_desktop_service(
        "eng-zy01",
        desired_apps=[{"slug": "google-chrome", "enabled": True}, {"slug": "libreoffice", "enabled": False}],
        repository=_FakeJobRepository(_core_jobs()),
        runner=runner,
        env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
        workspace_root=tmp_path / "workspaces",
    )

    assert result["status"] == "Configured"
    assert commands[0][0] == [str(ansible_playbook), "-i", "ansible/inventory.ini", "ansible/apply_desktop.yml"]
    assert result["servicePlacements"][0]["service"] == "Google Chrome"
    assert result["servicePlacements"][0]["status"] == "Configured"
    assert result["servicePlacements"][1]["service"] == "LibreOffice"
    assert result["servicePlacements"][1]["status"] == "Removed"
    assert "meta-package was removed without autoremove" in result["servicePlacements"][1]["detail"]
    assert "component packages may remain installed" in result["servicePlacements"][1]["disableNote"]


def test_libreoffice_deselection_is_an_explicit_meta_package_only_contract(monkeypatch):
    monkeypatch.setattr("app.services.legacy_homebase_role_service.get_engagement", lambda engagement_id: object())
    result = preview_desktop_service_apply(
        "eng-zy01",
        desired_apps=[{"slug": "libreoffice", "enabled": False}],
        repository=_FakeJobRepository(_core_jobs()),
    )

    playbook = result["workspace"]["playbook"]["content"]
    placement = result["servicePlacements"][0]
    assert "name: libreoffice" in playbook
    assert "state: absent" in playbook
    assert "purge: false" in playbook
    assert "autoremove: false" in playbook
    assert "libreoffice-common" not in playbook
    assert "libreoffice-core" not in playbook
    assert "apt-get autoremove" not in playbook
    assert "component packages may remain installed" in placement["disableNote"]


def test_apply_desktop_service_can_return_running_job_before_background_work(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.legacy_homebase_role_service.get_engagement", lambda engagement_id: object())
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    tasks = []
    repo = _FakeJobRepository(_core_jobs())

    result = apply_desktop_service(
        "eng-zy01",
        desired_apps=[{"slug": "google-chrome", "enabled": True}],
        repository=repo,
        background_runner=tasks.append,
        env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
        workspace_root=tmp_path / "workspaces",
    )

    assert result["status"] == "Running"
    assert result["job"]["status"] == "running"
    assert result["job"]["events"][-1]["message"] == "Desktop service Ansible apply started"
    assert len(tasks) == 1


def test_ansible_task_progress_parsers():
    assert _ansible_task_name("TASK [Install Desktop app Google Chrome] ****************") == "Install Desktop app Google Chrome"
    assert _ansible_task_result("ok: [homebase]") == "ok"
    assert _ansible_task_result("changed: [homebase]") == "changed"
    assert _ansible_task_result("skipped: [homebase]") == "skipped"
    assert _ansible_task_result("fatal: [homebase]: FAILED! => {}") == "failed"


def _core_jobs():
    return [
        StoredJobRun(
            id="job-core",
            action="pilot_standard_rti_guarded_execute",
            status="succeeded",
            target="oci-compartment:barragan-testing",
            target_type="oci_compartment",
            target_id="ocid1.compartment.oc1..testing",
            requested_by="operator",
            input={"engagementId": "eng-zy01"},
            artifact_refs=[],
            created_at="2026-06-04T12:00:00+00:00",
            started_at="2026-06-04T12:01:00+00:00",
            finished_at="2026-06-04T12:05:00+00:00",
            events=[
                JobEvent(
                    1,
                    "info",
                    "operator inspection ready",
                    {
                        "connectionDetails": [
                            {
                                "role": "homebase",
                                "displayName": "homebase-zy01",
                                "publicIp": "203.0.113.10",
                                "privateIp": "192.168.0.10",
                                "sshUser": "ubuntu",
                            }
                        ]
                    },
                )
            ],
        )
    ]


def _executable(tmp_path, name):
    path = tmp_path / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


class _FakeJobRepository:
    def __init__(self, jobs):
        self.jobs = list(jobs)

    def list(self):
        return list(self.jobs)

    def list_for_engagement(self, engagement_id, *, limit=None):
        jobs = [job for job in self.list() if (
            job.target_id == engagement_id or job.target == f"engagement:{engagement_id}"
            or job.input.get("engagementId") == engagement_id
        )]
        jobs.sort(key=lambda job: job.created_at, reverse=True)
        return jobs if limit is None else jobs[:limit]

    def get(self, job_id):
        return next((job for job in self.jobs if job.id == job_id), None)

    def save(self, job):
        self.jobs = [existing for existing in self.jobs if existing.id != job.id]
        self.jobs.append(job)
        return job
