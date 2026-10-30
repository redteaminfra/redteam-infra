# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.capability_execution import (
    CapabilityRoleApplyPlanValidationError,
    build_core_capability_role_apply_plan,
    build_optional_core_capability_role_apply_plan,
    copy_core_capability_roles,
    render_core_capability_apply_playbook,
    _plan_from_resolution,
    OPTIONAL_RECONCILIATION_EXCLUDED_CAPABILITY_IDS,
    _insert_apt_lock_settle_tasks,
    _normalize_role_for_barragan_runtime,
)
from app.services.engagement_capabilities import update_engagement_capability_selection
from app.services.engagement_workspaces import prepare_engagement_workspace
from app.services.redteam_infra_template import RedteamInfraTemplateSource
from app.storage.engagement_workspace_repository import StoredEngagementWorkspace


STANDARD_RTI_ROLES = (
    "common",
    "molly-guard",
    "logstash",
    "yama",
    "oci",
    "nfs-server",
    "homebase",
    "docker",
    "go_simple_upload_server",
    "etherpad",
    "google-chrome",
    "firefox",
    "keepassxc",
    "vs-code",
    "nmap",
    "nfs-client",
    "ssh-proxy",
    "dante-server",
    "unattended-upgrades",
    "proxies",
    "elk",
)


def test_core_capability_apply_plan_uses_selected_role_capabilities(tmp_path: Path, monkeypatch) -> None:
    repo = _FakeWorkspaceRepository()
    template = _template_source(tmp_path)
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))
    monkeypatch.setattr("app.services.engagement_capabilities.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={}))
    monkeypatch.setattr("app.services.capability_lock_rendering.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={}))
    monkeypatch.setattr("app.services.capability_execution.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={}))

    prepared = prepare_engagement_workspace(
        "eng-abc123",
        root=tmp_path / "engagements",
        repository=repo,
        source=RedteamInfraTemplateSource(template, "test"),
    )
    assert prepared is not None
    update_engagement_capability_selection(
        "eng-abc123",
        {"deselectedDefaults": [{"hostClass": "homebase", "id": "firefox"}]},
        root=tmp_path / "engagements",
        repository=repo,
        service_repository=_FakeServiceRepository(),
    )

    plan = build_core_capability_role_apply_plan(
        engagement_id="eng-abc123",
        engagement_repos_root=tmp_path / "engagements",
        repository=repo,
    )
    playbook = render_core_capability_apply_playbook(plan)
    workspace = tmp_path / "workspace"
    copy_core_capability_roles(workspace, plan)

    assert "common" in plan.role_names
    assert "homebase" in plan.role_names
    assert "google-chrome" in plan.role_names
    assert "docker" in plan.role_names
    assert "firefox" not in plan.role_names
    assert "go_simple_upload_server" not in plan.role_names
    assert "unattended-upgrades" in plan.role_names
    assert [entry["role"] for entry in plan.roles_by_host_class["common"]].count("common") == 1
    assert [entry["role"] for entry in plan.roles_by_host_class["common"]].count("oci") == 1
    assert "elk" not in plan.role_names
    assert "- name: Apply common selected capabilities" in playbook
    assert "hosts: pilot_rti" in playbook
    assert "Quiesce apt background services before common capabilities" in playbook
    assert "apt-daily-upgrade.service" in playbook
    assert "Wait for apt and dpkg locks to remain clear before common capabilities" in playbook
    assert "Wait for apt and dpkg locks before capability google-chrome" in playbook
    assert "/var/lib/dpkg/lock-frontend" in playbook
    assert "- name: Apply capability google-chrome" in playbook
    assert "- name: Apply capability firefox" not in playbook
    assert [entry["role"] for entry in plan.roles_by_host_class["homebase"]].count("nmap") == 0
    assert [entry["role"] for entry in plan.roles_by_host_class["proxy"]].count("nmap") == 1
    assert playbook.count("- name: Apply capability homebase") == 1
    assert playbook.count("- name: Apply capability oci") == 1
    assert playbook.index("- name: Apply capability common") < playbook.index("- name: Apply capability oci")
    assert playbook.index("Canonicalize Dante-oriented homebase user profiles") > playbook.index(
        "- name: Apply capability homebase"
    )
    assert (workspace / "ansible" / "roles" / "google-chrome" / "tasks" / "main.yml").is_file()
    assert (workspace / "ansible" / "roles" / "docker" / "tasks" / "main.yml").is_file()
    assert not (workspace / "ansible" / "roles" / "go_simple_upload_server").exists()
    vscode_tasks = workspace / "ansible" / "roles" / "vs-code" / "tasks" / "main.yml"
    assert "ansible.builtin.systemd:" in vscode_tasks.read_text(encoding="utf-8")
    assert "systemd_service:" not in vscode_tasks.read_text(encoding="utf-8")


def test_core_capability_apply_plan_projects_standard_roles_without_manifest_files(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = _FakeWorkspaceRepository()
    template = _template_source_without_manifests(tmp_path)
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))
    monkeypatch.setattr("app.services.engagement_capabilities.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={}))
    monkeypatch.setattr("app.services.capability_lock_rendering.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={}))
    monkeypatch.setattr("app.services.capability_execution.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={}))

    prepared = prepare_engagement_workspace(
        "eng-abc123",
        root=tmp_path / "engagements",
        repository=repo,
        source=RedteamInfraTemplateSource(template, "test"),
    )
    assert prepared is not None

    plan = build_core_capability_role_apply_plan(
        engagement_id="eng-abc123",
        engagement_repos_root=tmp_path / "engagements",
        repository=repo,
    )

    assert "firefox" in plan.role_names
    assert "google-chrome" in plan.role_names
    assert "homebase" in plan.role_names
    assert not plan.errors


def test_core_capability_apply_plan_applies_selected_go_simple_upload_server_only_to_homebase(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = _FakeWorkspaceRepository()
    template = _template_source_without_manifests(tmp_path)
    engagement = SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={})
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.engagement_capabilities.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.capability_lock_rendering.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.capability_execution.get_engagement", lambda _id: engagement)

    prepared = prepare_engagement_workspace(
        "eng-abc123",
        root=tmp_path / "engagements",
        repository=repo,
        source=RedteamInfraTemplateSource(template, "stock"),
    )
    assert prepared is not None

    unselected_plan = build_core_capability_role_apply_plan(
        engagement_id="eng-abc123",
        engagement_repos_root=tmp_path / "engagements",
        repository=repo,
    )
    unselected_playbook = render_core_capability_apply_playbook(unselected_plan)
    copy_core_capability_roles(tmp_path / "unselected", unselected_plan)
    assert "go_simple_upload_server" not in unselected_plan.role_names
    assert "Apply capability go-simple-upload-server" not in unselected_playbook
    assert not (tmp_path / "unselected" / "ansible" / "roles" / "go_simple_upload_server").exists()

    update_engagement_capability_selection(
        "eng-abc123",
        {"selectedOptionals": [{"hostClass": "homebase", "id": "go-simple-upload-server"}]},
        root=tmp_path / "engagements",
        repository=repo,
        service_repository=_FakeServiceRepository(),
    )
    selected_plan = build_core_capability_role_apply_plan(
        engagement_id="eng-abc123",
        engagement_repos_root=tmp_path / "engagements",
        repository=repo,
    )
    selected_playbook = render_core_capability_apply_playbook(selected_plan)
    copy_core_capability_roles(tmp_path / "selected", selected_plan)

    assert {"id": "go-simple-upload-server", "role": "go_simple_upload_server"} in selected_plan.roles_by_host_class["homebase"]
    assert all(
        entry["id"] != "go-simple-upload-server"
        for host_class, entries in selected_plan.roles_by_host_class.items()
        if host_class != "homebase"
        for entry in entries
    )
    assert selected_playbook.count("- name: Apply capability go-simple-upload-server") == 1
    assert (tmp_path / "selected" / "ansible" / "roles" / "go_simple_upload_server" / "tasks" / "main.yml").is_file()


def test_optional_core_reconciliation_plan_excludes_defaults_and_desktop(tmp_path: Path, monkeypatch) -> None:
    repo = _FakeWorkspaceRepository()
    template = _template_source_without_manifests(tmp_path)
    engagement = SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={})
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.engagement_capabilities.get_engagement", lambda _id: engagement)
    monkeypatch.setattr("app.services.capability_execution.get_engagement", lambda _id: engagement)
    prepared = prepare_engagement_workspace(
        "eng-abc123",
        root=tmp_path / "engagements",
        repository=repo,
        source=RedteamInfraTemplateSource(template, "stock"),
    )
    assert prepared is not None
    update_engagement_capability_selection(
        "eng-abc123",
        {
            "selectedOptionals": [
                {"hostClass": "homebase", "id": "go-simple-upload-server"},
            ]
        },
        root=tmp_path / "engagements",
        repository=repo,
        service_repository=_FakeServiceRepository(),
    )

    plan = build_optional_core_capability_role_apply_plan(
        engagement_id="eng-abc123",
        engagement_repos_root=tmp_path / "engagements",
        repository=repo,
        elk_enabled=True,
    )

    assert plan.role_names == ["go_simple_upload_server"]
    assert plan.roles_by_host_class["homebase"] == [{"id": "go-simple-upload-server", "role": "go_simple_upload_server"}]
    assert "common" not in plan.role_names
    assert "homebase" not in plan.role_names
    assert "firefox" not in plan.role_names


def test_optional_core_reconciliation_plan_excludes_desktop_dedicated_workflow(tmp_path: Path) -> None:
    source_path = _template_source_without_manifests(tmp_path)
    source = RedteamInfraTemplateSource(source_path, "stock")
    resolution = {
        "hostClasses": {
            "homebase": {
                "optional": [
                    {
                        "id": "go-simple-upload-server",
                        "selected": True,
                        "executable": True,
                        "implementation": {"type": "role", "role": "go_simple_upload_server"},
                    },
                    {
                        "id": "firefox",
                        "selected": True,
                        "executable": True,
                        "implementation": {"type": "role", "role": "firefox"},
                    },
                ]
            }
        }
    }

    plan = _plan_from_resolution(
        source,
        resolution,
        selected_classifications={"optional"},
        excluded_capability_ids=OPTIONAL_RECONCILIATION_EXCLUDED_CAPABILITY_IDS,
    )

    assert plan.role_names == ["go_simple_upload_server"]
    assert any(entry["id"] == "firefox" for entry in plan.skipped)


def test_role_normalization_inserts_apt_lock_settle_tasks_after_package_tasks() -> None:
    content = """---
- name: Add repository
  ansible.builtin.apt_repository:
    repo: ppa:example/example

- name: Install package
  apt:
    name: example
    state: present

- name: Copy config
  copy:
    src: example
    dest: /tmp/example
"""

    normalized = _insert_apt_lock_settle_tasks(content)

    assert normalized.count("Barragan wait for apt locks after package task") == 2
    assert normalized.index("Add repository") < normalized.index("Barragan wait for apt locks after package task")
    assert "fuser /var/lib/dpkg/lock-frontend" in normalized
    assert _insert_apt_lock_settle_tasks(normalized) == normalized

    no_trailing_newline = """- name: Install package
  apt:
    name: example
    state: present"""
    normalized_no_newline = _insert_apt_lock_settle_tasks(no_trailing_newline)
    assert "state: present\n- name: Barragan wait for apt locks after package task" in normalized_no_newline


def test_google_chrome_runtime_copy_registers_the_upstream_retry_result(tmp_path: Path) -> None:
    role = tmp_path / "google-chrome"
    tasks = role / "tasks/main.yml"
    tasks.parent.mkdir(parents=True)
    tasks.write_text(
        """---
- name: Import Google Chrome's GPG key
  apt_key:
    url: example
    state: present
  retries: 3
  delay: 5
  until: result is succeeded
""",
        encoding="utf-8",
    )

    _normalize_role_for_barragan_runtime(role)

    rendered = tasks.read_text(encoding="utf-8")
    assert "register: google_chrome_gpg_key_result" in rendered
    assert "until: google_chrome_gpg_key_result is succeeded" in rendered
    assert "until: result is succeeded" not in rendered


def test_google_chrome_runtime_copy_fails_closed_on_ambiguous_legacy_retry(tmp_path: Path) -> None:
    role = tmp_path / "google-chrome"
    tasks = role / "tasks/main.yml"
    tasks.parent.mkdir(parents=True)
    tasks.write_text("until: result is succeeded\nuntil: result is succeeded\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="compatibility form was not found exactly once"):
        _normalize_role_for_barragan_runtime(role)


def test_firefox_runtime_copy_retries_only_the_pinned_ppa_task(tmp_path: Path) -> None:
    import yaml

    role = tmp_path / "firefox"
    tasks = role / "tasks/main.yml"
    tasks.parent.mkdir(parents=True)
    original = """---
- name: Add mozzila repository from PPA and install its signing key
  ansible.builtin.apt_repository:
    repo: ppa:mozillateam/ppa

- name: Update package cache and install Firefox
  ansible.builtin.apt:
    name: firefox
    state: present
    update_cache: yes

- name: Copy firefox-policies.json to /etc/firefox/policies
  copy:
    src: files/firefox-policies.json
    dest: /etc/firefox/policies/policies.json
    mode: 0644
"""
    tasks.write_text(original)
    other = role / "tasks/other.yml"
    other.write_text(original)

    _normalize_role_for_barragan_runtime(role)
    rendered = tasks.read_text()
    parsed = yaml.safe_load(rendered)
    lookup = parsed[0]
    assert lookup["ansible.builtin.uri"] == {
        "url": "https://api.launchpad.net/1.0/~mozillateam/+archive/ppa",
        "headers": {"Accept": "application/json"}, "return_content": True,
        "validate_certs": True, "follow_redirects": "none", "timeout": 60,
        "status_code": 200,
    }
    assert {key: lookup[key] for key in ("register", "retries", "delay", "until")} == {
        "register": "firefox_ppa_result", "retries": 3, "delay": 5,
        "until": "firefox_ppa_result is succeeded",
    }
    assert all("ignore_errors" not in task and "failed_when" not in task for task in parsed)
    assert all("retries" not in task for task in parsed[1:])
    assert parsed[1]["ansible.builtin.assert"]["that"] == [
        "firefox_ppa_result.json.signing_key_fingerprint is string",
        "firefox_ppa_result.json.signing_key_fingerprint is match('^[0-9A-F]{40}$')",
    ]
    assert parsed[2]["ansible.builtin.apt_key"] == {
        "id": "{{ firefox_ppa_result.json.signing_key_fingerprint }}",
        "keyserver": "hkp://keyserver.ubuntu.com:80", "state": "present",
    }
    assert parsed[4]["ansible.builtin.apt_repository"] == {
        "repo": "deb https://ppa.launchpadcontent.net/mozillateam/ppa/ubuntu {{ ansible_distribution_release }} main",
        "filename": "ppa_mozillateam_ppa_{{ ansible_distribution_release }}",
        "state": "present",
    }
    assert parsed[6] == yaml.safe_load(original)[1]
    assert parsed[-1] == yaml.safe_load(original)[-1]
    assert "firefox_ppa_result" not in other.read_text()
    _normalize_role_for_barragan_runtime(role)
    assert tasks.read_text() == rendered


@pytest.mark.parametrize("mutation", ["duplicate", "changed-repo", "existing-retry"])
def test_firefox_ppa_retry_rejects_changed_or_ambiguous_task(tmp_path: Path, mutation: str) -> None:
    role = tmp_path / "firefox"
    tasks = role / "tasks/main.yml"
    tasks.parent.mkdir(parents=True)
    content = """- name: Add mozzila repository from PPA and install its signing key
  ansible.builtin.apt_repository:
    repo: ppa:mozillateam/ppa
"""
    content = (content * 2 if mutation == "duplicate" else
               content.replace("mozillateam/ppa", "other/ppa") if mutation == "changed-repo" else
               content + "  retries: 99\n")
    tasks.write_text(content)
    with pytest.raises(RuntimeError, match="Firefox PPA compatibility"):
        _normalize_role_for_barragan_runtime(role)
    assert tasks.read_text() == content


def test_core_capability_apply_plan_fails_when_selected_standard_role_path_is_missing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = _FakeWorkspaceRepository()
    template = _template_source_without_manifests(tmp_path)
    _remove_role(template, "firefox")
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))
    monkeypatch.setattr("app.services.engagement_capabilities.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={}))
    monkeypatch.setattr("app.services.capability_lock_rendering.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={}))
    monkeypatch.setattr("app.services.capability_execution.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={}))

    prepared = prepare_engagement_workspace(
        "eng-abc123",
        root=tmp_path / "engagements",
        repository=repo,
        source=RedteamInfraTemplateSource(template, "test"),
    )
    assert prepared is not None

    with pytest.raises(CapabilityRoleApplyPlanValidationError) as exc:
        build_core_capability_role_apply_plan(
            engagement_id="eng-abc123",
            engagement_repos_root=tmp_path / "engagements",
            repository=repo,
        )

    assert any(
        error["id"] == "firefox"
        and error["reason"] == "selected core capability is not an executable Ansible role"
        for error in exc.value.errors
    )


def test_core_capability_apply_plan_validates_local_manifest_against_workspace_copy(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = _FakeWorkspaceRepository()
    template = _template_source_without_manifests(tmp_path)
    manifest_root = tmp_path / "barragan-manifests"
    _write_manifest(manifest_root / "capabilities" / "roles" / "firefox.yml", "firefox")
    monkeypatch.setattr("app.services.capability_catalog.DEFAULT_CAPABILITY_MANIFEST_ROOT", manifest_root)
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))
    monkeypatch.setattr("app.services.capability_execution.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={}))

    prepared = prepare_engagement_workspace(
        "eng-abc123",
        root=tmp_path / "engagements",
        repository=repo,
        source=RedteamInfraTemplateSource(template, "test"),
    )
    assert prepared is not None
    _remove_role(Path(prepared.workspace.path), "firefox")

    with pytest.raises(CapabilityRoleApplyPlanValidationError) as exc:
        build_core_capability_role_apply_plan(
            engagement_id="eng-abc123",
            engagement_repos_root=tmp_path / "engagements",
            repository=repo,
        )

    assert any(
        error["id"] == "firefox"
        and error["reason"] == "selected core capability is not an executable Ansible role"
        for error in exc.value.errors
    )


def test_core_capability_apply_plan_allows_barragan_native_core_workflow(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = _FakeWorkspaceRepository()
    template = _template_source(tmp_path)
    _remove_manifest(template, "engagement-workspace")
    _remove_role(template, "engagement-workspace")
    monkeypatch.setattr("app.services.engagement_workspaces.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01"))
    monkeypatch.setattr("app.services.engagement_capabilities.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={}))
    monkeypatch.setattr("app.services.capability_lock_rendering.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={}))
    monkeypatch.setattr("app.services.capability_execution.get_engagement", lambda _id: SimpleNamespace(id="eng-abc123", name="Demo 01", input_parameters={}))

    prepared = prepare_engagement_workspace(
        "eng-abc123",
        root=tmp_path / "engagements",
        repository=repo,
        source=RedteamInfraTemplateSource(template, "test"),
    )
    assert prepared is not None

    plan = build_core_capability_role_apply_plan(
        engagement_id="eng-abc123",
        engagement_repos_root=tmp_path / "engagements",
        repository=repo,
    )

    assert "engagement-workspace" not in plan.role_names
    assert any(
        skipped["id"] == "engagement-workspace"
        and skipped["reason"] == "capability is managed by a Barragan-native workflow"
        for skipped in plan.skipped
    )
    assert not plan.errors


def _template_source(tmp_path: Path) -> Path:
    source = tmp_path / "redteam-infra"
    (source / "external").mkdir(parents=True, exist_ok=True)
    (source / "ansible").mkdir(parents=True, exist_ok=True)
    (source / "ansible" / "site.yml").write_text("---\n", encoding="utf-8")
    for role in STANDARD_RTI_ROLES:
        role_tasks = source / "ansible" / "roles" / role / "tasks"
        role_tasks.mkdir(parents=True)
        task_body = "---\n- debug:\n    msg: {role}\n"
        if role == "vs-code":
            task_body = "---\n- name: Disable snapd\n  systemd_service:\n    name: snapd\n    state: stopped\n"
        (role_tasks / "main.yml").write_text(task_body.format(role=role), encoding="utf-8")
        if role == "etherpad":
            role_meta = source / "ansible" / "roles" / role / "meta"
            role_meta.mkdir(parents=True)
            (role_meta / "main.yml").write_text("---\ndependencies:\n  - { role: docker }\n", encoding="utf-8")
        _write_manifest(source / "barragan" / "capabilities" / "roles" / f"{role}.yml", role)
    _write_profile(source / "barragan" / "profiles" / "standard-rti.yml")
    return source


def _template_source_without_manifests(tmp_path: Path) -> Path:
    source = tmp_path / "redteam-infra"
    (source / "external").mkdir(parents=True, exist_ok=True)
    (source / "ansible").mkdir(parents=True, exist_ok=True)
    (source / "ansible" / "site.yml").write_text("---\n", encoding="utf-8")
    for role in STANDARD_RTI_ROLES:
        role_tasks = source / "ansible" / "roles" / role / "tasks"
        role_tasks.mkdir(parents=True)
        (role_tasks / "main.yml").write_text(f"---\n- debug:\n    msg: {role}\n", encoding="utf-8")
        if role == "etherpad":
            role_meta = source / "ansible" / "roles" / role / "meta"
            role_meta.mkdir(parents=True)
            (role_meta / "main.yml").write_text("---\ndependencies:\n  - { role: docker }\n", encoding="utf-8")
    return source


def _remove_manifest(source: Path, role: str) -> None:
    path = source / "barragan" / "capabilities" / "roles" / f"{role}.yml"
    if path.exists():
        path.unlink()


def _remove_role(source: Path, role: str) -> None:
    role_path = source / "ansible" / "roles" / role
    if role_path.exists():
        import shutil

        shutil.rmtree(role_path)


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
    default: [etherpad, google-chrome, firefox, keepassxc, vs-code]
  proxy:
    essential: [docker, nfs-client, nmap, ssh-proxy, dante-server, unattended-upgrades, proxies]
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


class _FakeServiceRepository:
    def list_for_engagement(self, _engagement_id: str):
        return []
