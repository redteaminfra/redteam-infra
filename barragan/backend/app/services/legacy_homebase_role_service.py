# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import os
import subprocess
import threading
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import uuid4

from app.core.command_environment import barragan_subprocess_env
from app.core.runtime import start_runtime_task
from app.domain import JobEvent
from app.integrations.ansible_disposable_validation import resolve_ansible_playbook
from app.integrations.oci_disposable_terraform import DisposableCommandResult
from app.services.core_ssh import deployment_known_hosts_file, ensure_known_hosts_file, latest_core_connection_details
from app.services.engagements import get_engagement
from app.services.redteam_infra_template import redteam_infra_ansible_role_path
from app.services.capability_execution import copy_capability_role_for_runtime
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun


LEGACY_HOMEBASEROLE_APPLY_PREVIEW_ACTION = "legacy_homebase_role_service_apply_preview"
LEGACY_HOMEBASEROLE_APPLY_ACTION = "legacy_homebase_role_service_apply"
DESKTOP_SERVICE_APPLY_PREVIEW_ACTION = "desktop_service_apply_preview"
DESKTOP_SERVICE_APPLY_ACTION = "desktop_service_apply"
DESKTOP_SERVICE_APPLY_CONFIRMATION = "apply-service-desktop"
DEFAULT_WORKSPACE_ROOT = Path("/tmp/barragan-legacy-homebase-role-service-apply")
DEFAULT_KNOWN_HOSTS_ROOT = Path("/tmp/barragan-legacy-homebase-role-known-hosts")
DEFAULT_CORE_SSH_PRIVATE_KEY = "/var/lib/barragan/.ssh/barragan_testing"
CORE_SSH_KEY_ENV = "BARRAGAN_VALIDATION_SSH_PRIVATE_KEY"
CORE_SSH_OPTIONS = (
    "-o StrictHostKeyChecking=accept-new",
    "-o IdentitiesOnly=yes",
    "-o BatchMode=yes",
    "-o ConnectTimeout=10",
)

CommandRunner = Callable[[list[str], Path | None], subprocess.CompletedProcess[str]]
BackgroundRunner = Callable[[Callable[[], None]], None]


class LegacyHomebaseRoleServiceValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("legacy homebase role service validation failed")
        self.errors = errors


@dataclass(frozen=True)
class LegacyHomebaseRoleSpec:
    slug: str
    name: str
    role_name: str
    confirmation: str
    detail: str
    package_name: str
    disable_paths: tuple[str, ...] = ()
    disable_note: str = ""

    @property
    def role_path(self) -> Path:
        return redteam_infra_ansible_role_path(self.role_name)


SUPPORTED_LEGACY_HOMEBASEROLES = {
    "google-chrome": LegacyHomebaseRoleSpec(
        slug="google-chrome",
        name="Google Chrome",
        role_name="google-chrome",
        confirmation="apply-service-google-chrome",
        detail="Legacy redteam-infra role installs Google Chrome and managed browser policies.",
        package_name="google-chrome-stable",
        disable_paths=("/etc/opt/chrome/policies/managed/policies.json",),
    ),
    "firefox": LegacyHomebaseRoleSpec(
        slug="firefox",
        name="Firefox",
        role_name="firefox",
        confirmation="apply-service-firefox",
        detail="Legacy redteam-infra role installs Firefox from the Mozilla PPA and managed browser policies.",
        package_name="firefox",
        disable_paths=(
            "/etc/firefox/policies/policies.json",
            "/etc/apt/apt.conf.d/51unattended-upgrades-firefox",
            "/etc/apt/preferences.d/mozilla-firefox",
        ),
        disable_note="Disable removes Firefox and legacy policy files but does not re-enable or unmask Snap.",
    ),
    "keepassxc": LegacyHomebaseRoleSpec(
        slug="keepassxc",
        name="KeePassXC",
        role_name="keepassxc",
        confirmation="apply-service-keepassxc",
        detail="Legacy redteam-infra role installs the keepassxc package on homebase.",
        package_name="keepassxc",
    ),
    "libreoffice": LegacyHomebaseRoleSpec(
        slug="libreoffice",
        name="LibreOffice",
        role_name="libreoffice",
        confirmation="apply-service-libreoffice",
        detail=(
            "Legacy redteam-infra role installs LibreOffice on demand. "
            "Deselecting it removes only the libreoffice meta-package; component packages may remain installed."
        ),
        package_name="libreoffice",
        disable_note=(
            "The libreoffice meta-package was removed without autoremove. "
            "LibreOffice component packages may remain installed."
        ),
    ),
    "vs-code": LegacyHomebaseRoleSpec(
        slug="vs-code",
        name="VS Code",
        role_name="vs-code",
        confirmation="apply-service-vs-code",
        detail="Legacy redteam-infra role installs Microsoft VS Code from the Microsoft apt repository.",
        package_name="code",
    )
}

DESKTOP_ROLE_SLUGS = ("google-chrome", "firefox", "vs-code", "libreoffice", "keepassxc")


@dataclass(frozen=True)
class LegacyRoleHost:
    name: str
    ansible_host: str
    ansible_user: str = "ubuntu"
    ssh_private_key_file: str = ""
    known_hosts_file: str = ""

    def to_inventory_line(self) -> str:
        parts = [
            self.name,
            f"ansible_host={self.ansible_host}",
            f"ansible_user={self.ansible_user}",
        ]
        if self.ssh_private_key_file:
            parts.append(f"ansible_ssh_private_key_file={self.ssh_private_key_file}")
        ssh_args = list(CORE_SSH_OPTIONS)
        if self.known_hosts_file:
            ssh_args.append(f"-o UserKnownHostsFile={self.known_hosts_file}")
        parts.append(f"ansible_ssh_common_args={json.dumps(' '.join(ssh_args))}")
        return " ".join(parts)

    def to_dict(self) -> dict[str, str]:
        body = {
            "name": self.name,
            "ansibleHost": self.ansible_host,
            "ansibleUser": self.ansible_user,
        }
        if self.ssh_private_key_file:
            body["sshPrivateKeyFile"] = self.ssh_private_key_file
        if self.known_hosts_file:
            body["knownHostsFile"] = self.known_hosts_file
        return body


@dataclass(frozen=True)
class RenderedLegacyRoleArtifact:
    target: str
    content: str

    def to_dict(self) -> dict[str, str]:
        return {"target": self.target, "content": self.content}


@dataclass(frozen=True)
class LegacyHomebaseRoleApplyWorkspace:
    inventory: RenderedLegacyRoleArtifact
    playbook: RenderedLegacyRoleArtifact
    manifest: RenderedLegacyRoleArtifact

    def to_dict(self) -> dict[str, object]:
        return {
            "status": "Pending Service Apply",
            "mutation": False,
            "inventory": self.inventory.to_dict(),
            "playbook": self.playbook.to_dict(),
            "manifest": self.manifest.to_dict(),
        }


def list_legacy_homebase_role_catalog() -> dict[str, list[dict[str, str]]]:
    return {
        "services": [
            {
                "slug": spec.slug,
                "name": spec.name,
                "targetHost": "homebase",
                "role": spec.role_name,
                "detail": spec.detail,
                "confirmation": spec.confirmation,
            }
            for spec in SUPPORTED_LEGACY_HOMEBASEROLES.values()
        ]
    }


def list_desktop_service_catalog() -> dict[str, Any]:
    return {
        "service": {
            "serviceId": "desktop",
            "serviceType": "desktop",
            "name": "Desktop",
            "targetHost": "homebase",
            "confirmation": DESKTOP_SERVICE_APPLY_CONFIRMATION,
        },
        "apps": [_spec_catalog_entry(_role_spec(slug)) for slug in DESKTOP_ROLE_SLUGS],
    }


def preview_desktop_service_apply(
    engagement_id: str,
    desired_apps: list[dict[str, Any]] | dict[str, Any] | None,
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    intents = _desktop_intents(desired_apps)
    repo = repository or SqlAlchemyJobRepository()
    homebase = _core_homebase(repo, engagement_id)
    workspace = render_desktop_apply_workspace(intents=intents, homebase=homebase)
    job = _save_desktop_preview_job(repo, engagement_id, requested_by, intents, workspace)
    return {
        "job": job.to_detail().to_dict(),
        "workspace": workspace.to_dict(),
        "servicePlacements": [_desktop_service_state(intent["spec"], "Pending Install" if intent["enabled"] else "Pending Removal")["placement"] for intent in intents],
        "confirmation": DESKTOP_SERVICE_APPLY_CONFIRMATION,
    }


def apply_desktop_service(
    engagement_id: str,
    desired_apps: list[dict[str, Any]] | dict[str, Any] | None,
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    runner: CommandRunner | None = None,
    background_runner: BackgroundRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
    desired_state_source: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None

    intents = _desktop_intents(desired_apps)
    ansible_resolution = resolve_ansible_playbook(env=env)
    if not ansible_resolution.ok:
        raise LegacyHomebaseRoleServiceValidationError([ansible_resolution.message])

    repo = repository or SqlAlchemyJobRepository()
    homebase = _core_homebase(repo, engagement_id)
    workspace = render_desktop_apply_workspace(intents=intents, homebase=homebase)
    workspace_dir = _write_workspace(
        workspace,
        workspace_root or DEFAULT_WORKSPACE_ROOT,
        "desktop",
        [intent["spec"] for intent in intents if intent["enabled"]],
    )
    ensure_known_hosts_file(homebase.known_hosts_file)
    command = [ansible_resolution.command or "ansible-playbook", "-i", "ansible/inventory.ini", "ansible/apply_desktop.yml"]
    timestamp = _now()
    applying_placements = [_desktop_service_state(intent["spec"], "Installing" if intent["enabled"] else "Removing")["placement"] for intent in intents]
    job = _save_binding_job(repo,
        StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=DESKTOP_SERVICE_APPLY_ACTION,
            status="running",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={
                "engagementId": engagement_id,
                "desiredApps": _desktop_input(intents),
                "mutation": True,
                **({"desiredStateSource": desired_state_source} if desired_state_source else {}),
            },
            artifact_refs=["ansible/inventory.ini", "ansible/apply_desktop.yml", "MANIFEST.json"],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=None,
            events=[
                JobEvent(
                    1,
                    "info",
                    "Desktop service apply workspace rendered",
                    {
                        "workspaceDir": str(workspace_dir),
                        "inventoryTargets": ["selected_homebase"],
                        "workspaceEvidence": _workspace_evidence(workspace),
                        "servicePlacements": applying_placements,
                        "mutation": True,
                    },
                ),
                JobEvent(
                    2,
                    "info",
                    "Desktop service Ansible apply started",
                    {
                        "command": command,
                        "cwd": str(workspace_dir),
                        "inventoryTargets": ["selected_homebase"],
                    },
                ),
            ],
        )
    )
    _assert_no_forbidden_markers(json.dumps([event.data for event in job.events], sort_keys=True), "desktop service job events")

    task = lambda: _run_desktop_apply_job(repo, job.id, command, workspace_dir, intents, runner)
    if background_runner is not None:
        background_runner(task)
    elif runner is not None:
        task()
    else:
        _start_background_task(task)

    saved = repo.get(job.id) or job
    latest_placements = _desktop_service_placements_from_events(saved.events) or applying_placements
    return {
        "job": saved.to_detail().to_dict(),
        "status": "Configured" if saved.status == "succeeded" else "Failed" if saved.status == "failed" else "Running",
        "servicePlacements": latest_placements,
    }


def preview_legacy_homebase_role_service_apply(
    engagement_id: str,
    role_slug: str,
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    spec = _role_spec(role_slug)
    repo = repository or SqlAlchemyJobRepository()
    homebase = _core_homebase(repo, engagement_id)
    workspace = render_legacy_homebase_role_apply_workspace(spec=spec, homebase=homebase)
    job = _save_preview_job(repo, engagement_id, requested_by, spec, workspace)
    return {"job": job.to_detail().to_dict(), "workspace": workspace.to_dict(), "service": _service_state(spec, "Pending Service Apply")["placement"]}


def apply_legacy_homebase_role_service(
    engagement_id: str,
    role_slug: str,
    *,
    confirmation: str,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    runner: CommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    spec = _role_spec(role_slug)
    if confirmation != spec.confirmation:
        raise LegacyHomebaseRoleServiceValidationError([f'confirmation must equal "{spec.confirmation}"'])

    ansible_resolution = resolve_ansible_playbook(env=env)
    if not ansible_resolution.ok:
        raise LegacyHomebaseRoleServiceValidationError([ansible_resolution.message])

    repo = repository or SqlAlchemyJobRepository()
    homebase = _core_homebase(repo, engagement_id)
    workspace = render_legacy_homebase_role_apply_workspace(spec=spec, homebase=homebase)
    workspace_dir = _write_workspace(workspace, workspace_root or DEFAULT_WORKSPACE_ROOT, spec.slug, [spec])
    ensure_known_hosts_file(homebase.known_hosts_file)
    command = [ansible_resolution.command or "ansible-playbook", "-i", "ansible/inventory.ini", f"ansible/apply_{spec.slug}.yml"]
    timestamp = _now()
    applying_state = _service_state(spec, "Applying")
    job = _save_binding_job(repo,
        StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=LEGACY_HOMEBASEROLE_APPLY_ACTION,
            status="running",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={"engagementId": engagement_id, "role": spec.slug, "confirmation": "redacted", "mutation": True},
            artifact_refs=["ansible/inventory.ini", f"ansible/apply_{spec.slug}.yml", "MANIFEST.json"],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=None,
            events=[
                JobEvent(
                    1,
                    "info",
                    f"{spec.name} service apply workspace rendered",
                    {
                        "role": spec.slug,
                        "workspaceDir": str(workspace_dir),
                        "inventoryTargets": ["selected_homebase"],
                        "workspaceEvidence": _workspace_evidence(workspace),
                        "servicePlacements": [applying_state["placement"]],
                        "mutation": True,
                    },
                ),
                JobEvent(
                    2,
                    "info",
                    f"{spec.name} service Ansible apply started",
                    {
                        "role": spec.slug,
                        "command": command,
                        "cwd": str(workspace_dir),
                        "inventoryTargets": ["selected_homebase"],
                    },
                ),
            ],
        )
    )
    _assert_no_forbidden_markers(json.dumps([event.data for event in job.events], sort_keys=True), "legacy homebase role job events")
    result = _run_guarded_command(command, workspace_dir, runner)
    command_result = _safe_command_result(result)
    final_status = "succeeded" if result.ok else "failed"
    final_service_state = _service_state(spec, "Configured" if result.ok else "Failed")
    final_event = JobEvent(
        3,
        "info" if result.ok else "error",
        f"{spec.name} service Ansible apply succeeded" if result.ok else f"{spec.name} service Ansible apply failed",
        {
            "role": spec.slug,
            "commandResult": command_result,
            "servicePlacements": [final_service_state["placement"]],
            "status": "Configured" if result.ok else "Failed",
        },
    )
    saved = _save_binding_job(repo, replace(job, status=final_status, finished_at=_now(), events=job.events + [final_event]))
    return {"job": saved.to_detail().to_dict(), "status": "Configured" if result.ok else "Failed", "service": final_service_state["placement"]}


def render_legacy_homebase_role_apply_workspace(
    *,
    spec: LegacyHomebaseRoleSpec,
    homebase: LegacyRoleHost,
) -> LegacyHomebaseRoleApplyWorkspace:
    _validate_homebase(homebase)
    inventory = RenderedLegacyRoleArtifact("ansible/inventory.ini", _render_inventory(homebase))
    playbook = RenderedLegacyRoleArtifact(f"ansible/apply_{spec.slug}.yml", _render_playbook(spec))
    manifest = RenderedLegacyRoleArtifact("MANIFEST.json", _render_manifest(spec, homebase))
    workspace = LegacyHomebaseRoleApplyWorkspace(inventory, playbook, manifest)
    _assert_no_forbidden_markers(json.dumps(workspace.to_dict(), sort_keys=True), "legacy homebase role workspace")
    return workspace


def render_desktop_apply_workspace(
    *,
    intents: list[dict[str, Any]],
    homebase: LegacyRoleHost,
) -> LegacyHomebaseRoleApplyWorkspace:
    _validate_homebase(homebase)
    inventory = RenderedLegacyRoleArtifact("ansible/inventory.ini", _render_inventory(homebase))
    playbook = RenderedLegacyRoleArtifact("ansible/apply_desktop.yml", _render_desktop_playbook(intents))
    manifest = RenderedLegacyRoleArtifact("MANIFEST.json", _render_desktop_manifest(intents, homebase))
    workspace = LegacyHomebaseRoleApplyWorkspace(inventory, playbook, manifest)
    _assert_no_forbidden_markers(json.dumps(workspace.to_dict(), sort_keys=True), "desktop service workspace")
    return workspace


def _core_homebase(repository: JobRepository, engagement_id: str) -> LegacyRoleHost:
    deployment_id, details = latest_core_connection_details(repository, engagement_id)
    homebase = next((entry for entry in details if str(entry.get("role") or "") == "homebase"), None)
    if homebase is None:
        raise LegacyHomebaseRoleServiceValidationError(["latest core deployment connectionDetails must include homebase"])
    ssh_key = os.environ.get(CORE_SSH_KEY_ENV, DEFAULT_CORE_SSH_PRIVATE_KEY)
    known_hosts_file = deployment_known_hosts_file(DEFAULT_KNOWN_HOSTS_ROOT, engagement_id, deployment_id)
    return LegacyRoleHost(
        "homebase",
        _required_text(homebase, "publicIp"),
        _entry_user(homebase),
        ssh_key,
        known_hosts_file,
    )


def _render_inventory(homebase: LegacyRoleHost) -> str:
    return "\n".join(
        [
            "# Managed by Barragan legacy homebase role service apply.",
            "# Target selected homebase only. Do not add proxy, middle, or edge sketch nodes here.",
            "[selected_homebase]",
            homebase.to_inventory_line(),
            "",
        ]
    )


def _render_playbook(spec: LegacyHomebaseRoleSpec) -> str:
    return "\n".join(
        [
            "---",
            f"- name: Apply {spec.name} service to homebase",
            "  hosts: selected_homebase",
            "  become: true",
            "  roles:",
            f"    - role: {spec.role_name}",
            "",
        ]
    )


def _render_desktop_playbook(intents: list[dict[str, Any]]) -> str:
    lines = [
        "---",
        "- name: Apply Desktop service to homebase",
        "  hosts: selected_homebase",
        "  become: true",
        "  tasks:",
    ]
    if not intents:
        lines.extend(
            [
                "    - name: No Desktop app changes requested",
                "      ansible.builtin.debug:",
                '        msg: "No Desktop app changes requested."',
            ]
        )
        return "\n".join(lines) + "\n"
    for intent in intents:
        spec = intent["spec"]
        if intent["enabled"]:
            lines.extend(
                [
                    f"    - name: Install Desktop app {spec.name}",
                    "      ansible.builtin.include_role:",
                    f"        name: {spec.role_name}",
                    "",
                ]
            )
        else:
            lines.extend(_render_desktop_disable_tasks(spec))
    return "\n".join(lines) + "\n"


def _render_desktop_disable_tasks(spec: LegacyHomebaseRoleSpec) -> list[str]:
    lines = [
        f"    - name: Remove Desktop app package {spec.name}",
        "      ansible.builtin.apt:",
        f"        name: {spec.package_name}",
        "        state: absent",
        "        purge: false",
        "        autoremove: false",
        "        update_cache: true",
        "",
    ]
    if spec.disable_paths:
        lines.extend(
            [
                f"    - name: Remove legacy Desktop app policy files for {spec.name}",
                "      ansible.builtin.file:",
                '        path: "{{ item }}"',
                "        state: absent",
                "      loop:",
                *[f"        - {path}" for path in spec.disable_paths],
                "",
            ]
        )
    if spec.disable_note:
        lines.extend(
            [
                f"    - name: Record Desktop disable caveat for {spec.name}",
                "      ansible.builtin.debug:",
                f"        msg: {json.dumps(spec.disable_note)}",
                "",
            ]
        )
    return lines


def _render_manifest(spec: LegacyHomebaseRoleSpec, homebase: LegacyRoleHost) -> str:
    return json.dumps(
        {
            "mode": "legacy_homebase_role_service_apply_preview",
            "mutation": False,
            "service": spec.name,
            "role": spec.role_name,
            "rolePath": str(spec.role_path),
            "targets": {
                "selectedHomebase": homebase.to_dict(),
            },
            "opsecBoundary": {
                "inventoryTargets": ["selected_homebase"],
                "proxyTargets": [],
                "sketchMiddleTargets": [],
                "sketchEdgeTargets": [],
                "reason": f"{spec.name} service configuration targets homebase only.",
            },
            "legacyBehavior": spec.detail,
        },
        indent=2,
        sort_keys=True,
    )


def _render_desktop_manifest(intents: list[dict[str, Any]], homebase: LegacyRoleHost) -> str:
    return json.dumps(
        {
            "mode": "desktop_service_apply_preview",
            "mutation": False,
            "service": "Desktop",
            "targets": {
                "selectedHomebase": homebase.to_dict(),
            },
            "apps": [
                {
                    "slug": intent["spec"].slug,
                    "name": intent["spec"].name,
                    "role": intent["spec"].role_name,
                    "enabled": intent["enabled"],
                    "package": intent["spec"].package_name,
                    "disableNote": intent["spec"].disable_note,
                }
                for intent in intents
            ],
            "opsecBoundary": {
                "inventoryTargets": ["selected_homebase"],
                "proxyTargets": [],
                "sketchMiddleTargets": [],
                "sketchEdgeTargets": [],
                "reason": "Desktop service configuration targets homebase only.",
            },
        },
        indent=2,
        sort_keys=True,
    )


def _save_preview_job(
    repository: JobRepository,
    engagement_id: str,
    requested_by: str,
    spec: LegacyHomebaseRoleSpec,
    workspace: LegacyHomebaseRoleApplyWorkspace,
) -> StoredJobRun:
    timestamp = _now()
    service_state = _service_state(spec, "Pending Service Apply")
    return _save_binding_job(repository,
        StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=LEGACY_HOMEBASEROLE_APPLY_PREVIEW_ACTION,
            status="succeeded",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={"engagementId": engagement_id, "role": spec.slug, "mutation": False},
            artifact_refs=["ansible/inventory.ini", f"ansible/apply_{spec.slug}.yml", "MANIFEST.json"],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=timestamp,
            events=[
                JobEvent(
                    1,
                    "info",
                    f"{spec.name} service apply preview rendered",
                    {
                        "role": spec.slug,
                        "workspace": workspace.to_dict(),
                        "workspaceEvidence": _workspace_evidence(workspace),
                        "servicePlacements": [service_state["placement"]],
                        "mutation": False,
                    },
                )
            ],
        )
    )


def _save_desktop_preview_job(
    repository: JobRepository,
    engagement_id: str,
    requested_by: str,
    intents: list[dict[str, Any]],
    workspace: LegacyHomebaseRoleApplyWorkspace,
) -> StoredJobRun:
    timestamp = _now()
    placements = [_desktop_service_state(intent["spec"], "Pending Install" if intent["enabled"] else "Pending Removal")["placement"] for intent in intents]
    return _save_binding_job(repository,
        StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=DESKTOP_SERVICE_APPLY_PREVIEW_ACTION,
            status="succeeded",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={"engagementId": engagement_id, "desiredApps": _desktop_input(intents), "mutation": False},
            artifact_refs=["ansible/inventory.ini", "ansible/apply_desktop.yml", "MANIFEST.json"],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=timestamp,
            events=[
                JobEvent(
                    1,
                    "info",
                    "Desktop service apply preview rendered",
                    {
                        "workspace": workspace.to_dict(),
                        "workspaceEvidence": _workspace_evidence(workspace),
                        "servicePlacements": placements,
                        "mutation": False,
                    },
                )
            ],
        )
    )


def _write_workspace(
    workspace: LegacyHomebaseRoleApplyWorkspace,
    root: Path,
    role_slug: str,
    role_specs: list[LegacyHomebaseRoleSpec],
) -> Path:
    workspace_dir = root / f"{role_slug}-{uuid4().hex[:12]}"
    (workspace_dir / "ansible").mkdir(parents=True, exist_ok=True)
    for artifact in (workspace.inventory, workspace.playbook, workspace.manifest):
        path = workspace_dir / artifact.target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(artifact.content, encoding="utf-8")
    for spec in role_specs:
        copy_capability_role_for_runtime(
            spec.role_path,
            workspace_dir / "ansible" / "roles" / spec.role_name,
        )
    return workspace_dir


def _workspace_evidence(workspace: LegacyHomebaseRoleApplyWorkspace) -> dict[str, dict[str, object]]:
    return {
        "inventory": _artifact_evidence(workspace.inventory),
        "playbook": _artifact_evidence(workspace.playbook),
        "manifest": _artifact_evidence(workspace.manifest),
    }


def _artifact_evidence(artifact: RenderedLegacyRoleArtifact) -> dict[str, object]:
    return {
        "path": artifact.target,
        "bytes": len(artifact.content.encode("utf-8")),
        "content": artifact.content,
    }


def _service_state(spec: LegacyHomebaseRoleSpec, status: str) -> dict[str, dict[str, Any]]:
    return {
        "placement": {
            "hostId": "homebase",
            "hostRole": "homebase",
            "serviceId": spec.slug,
            "serviceType": "legacy-homebase-role",
            "service": spec.name,
            "status": status,
            "detail": _service_detail(spec, status),
            "role": spec.role_name,
        }
    }


def _desktop_service_state(spec: LegacyHomebaseRoleSpec, status: str) -> dict[str, dict[str, Any]]:
    return {
        "placement": {
            "hostId": "homebase",
            "hostRole": "homebase",
            "serviceId": f"desktop-{spec.slug}",
            "serviceType": "desktop-app",
            "service": spec.name,
            "status": status,
            "detail": _desktop_service_detail(spec, status),
            "role": spec.role_name,
            "package": spec.package_name,
            "disableNote": spec.disable_note,
        }
    }


def _desktop_service_detail(spec: LegacyHomebaseRoleSpec, status: str) -> str:
    if status == "Configured":
        return f"{spec.name} is installed on homebase."
    if status == "Removed":
        detail = f"{spec.name} package has been removed from homebase."
        return f"{detail} {spec.disable_note}" if spec.disable_note else detail
    if status == "Installing":
        return f"{spec.name} install is running on homebase."
    if status == "Removing":
        return f"{spec.name} removal is running on homebase."
    if status == "Failed":
        return f"{spec.name} Desktop app change failed."
    return spec.detail


def _service_detail(spec: LegacyHomebaseRoleSpec, status: str) -> str:
    if status == "Configured":
        return f"Homebase legacy {spec.role_name} role applied."
    if status == "Failed":
        return f"Homebase legacy {spec.role_name} role apply failed."
    if status == "Applying":
        return f"Homebase legacy {spec.role_name} role apply is running."
    return spec.detail


def _run_guarded_command(
    command: list[str],
    cwd: Path,
    runner: CommandRunner | None,
) -> DisposableCommandResult:
    if runner is None:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=barragan_subprocess_env(),
            check=False,
            capture_output=True,
            text=True,
        )
    else:
        completed = runner(command, cwd)
    return DisposableCommandResult(
        command=list(command),
        cwd=str(cwd),
        returncode=int(completed.returncode),
        stdout=str(completed.stdout or ""),
        stderr=str(completed.stderr or ""),
        ok=int(completed.returncode) == 0,
    )


def _run_desktop_apply_job(
    repository: JobRepository,
    job_id: str,
    command: list[str],
    cwd: Path,
    intents: list[dict[str, Any]],
    runner: CommandRunner | None,
) -> None:
    job = repository.get(job_id)
    if job is None:
        return
    try:
        if runner is None:
            result = _run_guarded_command_streaming(command, cwd, repository, job_id)
        else:
            result = _run_guarded_command(command, cwd, runner)
    except Exception as exc:
        current = repository.get(job_id) or job
        event = JobEvent(
            len(current.events) + 1,
            "error",
            "Desktop service Ansible apply failed",
            {"error": _sanitize_output(str(exc)), "status": "Failed"},
        )
        _save_binding_job(repository, replace(current, status="failed", finished_at=_now(), events=[*current.events, event]))
        return

    current = repository.get(job_id) or job
    final_placements = [
        _desktop_service_state(intent["spec"], "Configured" if intent["enabled"] and result.ok else "Removed" if result.ok else "Failed")["placement"]
        for intent in intents
    ]
    final_event = JobEvent(
        len(current.events) + 1,
        "info" if result.ok else "error",
        "Desktop service Ansible apply succeeded" if result.ok else "Desktop service Ansible apply failed",
        {
            "commandResult": _safe_command_result(result),
            "servicePlacements": final_placements,
            "status": "Configured" if result.ok else "Failed",
        },
    )
    saved = replace(current, status="succeeded" if result.ok else "failed", finished_at=_now(), events=[*current.events, final_event])
    _assert_no_forbidden_markers(json.dumps([event.data for event in saved.events], sort_keys=True), "desktop service job events")
    _save_binding_job(repository, saved)


def _run_guarded_command_streaming(
    command: list[str],
    cwd: Path,
    repository: JobRepository,
    job_id: str,
) -> DisposableCommandResult:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=barragan_subprocess_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    stdout_lines: list[str] = []
    current_task = ""
    if process.stdout is not None:
        for raw_line in process.stdout:
            line = raw_line.rstrip("\n")
            stdout_lines.append(raw_line)
            task_name = _ansible_task_name(line)
            if task_name:
                current_task = task_name
                _append_desktop_job_event(
                    repository,
                    job_id,
                    "info",
                    "Desktop service Ansible task started",
                    {"taskName": task_name},
                )
                continue
            task_result = _ansible_task_result(line)
            if task_result and current_task:
                _append_desktop_job_event(
                    repository,
                    job_id,
                    "error" if task_result == "failed" else "info",
                    "Desktop service Ansible task failed" if task_result == "failed" else "Desktop service Ansible task completed",
                    {"taskName": current_task, "result": task_result, "line": _sanitize_output(line)},
                )
                if task_result in {"ok", "changed", "skipped", "failed"}:
                    current_task = ""
    returncode = process.wait()
    return DisposableCommandResult(
        command=list(command),
        cwd=str(cwd),
        returncode=int(returncode),
        stdout="".join(stdout_lines),
        stderr="",
        ok=int(returncode) == 0,
    )


def _append_desktop_job_event(
    repository: JobRepository,
    job_id: str,
    level: str,
    message: str,
    data: dict[str, Any],
) -> None:
    job = repository.get(job_id)
    if job is None or job.status not in {"queued", "running"}:
        return
    updated = replace(job, events=[*job.events, JobEvent(len(job.events) + 1, level, message, data)])
    _assert_no_forbidden_markers(json.dumps([event.data for event in updated.events], sort_keys=True), "desktop service job events")
    _save_binding_job(repository, updated)


def _ansible_task_name(line: str) -> str:
    stripped = line.strip()
    prefix = "TASK ["
    if not stripped.startswith(prefix):
        return ""
    end = stripped.find("]", len(prefix))
    if end == -1:
        return ""
    return stripped[len(prefix):end].strip()


def _ansible_task_result(line: str) -> str:
    stripped = line.strip()
    if stripped.startswith("fatal:") and "FAILED!" in stripped:
        return "failed"
    for candidate in ("changed", "ok", "skipped", "failed", "unreachable"):
        if stripped.startswith(f"{candidate}:"):
            return "failed" if candidate in {"failed", "unreachable"} else candidate
    return ""


def _desktop_service_placements_from_events(events: list[JobEvent]) -> list[dict[str, Any]]:
    for event in reversed(events):
        placements = event.data.get("servicePlacements") if isinstance(event.data, dict) else None
        if isinstance(placements, list):
            return [placement for placement in placements if isinstance(placement, dict)]
    return []


def _safe_command_result(result: DisposableCommandResult) -> dict[str, Any]:
    return {
        "command": result.command,
        "cwd": result.cwd,
        "returncode": result.returncode,
        "ok": result.ok,
        "stdout": _sanitize_output(result.stdout),
        "stderr": _sanitize_output(result.stderr),
    }


def _role_spec(role_slug: str) -> LegacyHomebaseRoleSpec:
    spec = SUPPORTED_LEGACY_HOMEBASEROLES.get(role_slug)
    if spec is None:
        raise LegacyHomebaseRoleServiceValidationError([f"unsupported legacy homebase role service {role_slug}"])
    if not spec.role_path.exists():
        raise LegacyHomebaseRoleServiceValidationError([f"legacy role path does not exist for {role_slug}"])
    return spec


def _start_background_task(task: Callable[[], None]) -> None:
    start_runtime_task(task, name="barragan-desktop-service-runner")


def _spec_catalog_entry(spec: LegacyHomebaseRoleSpec) -> dict[str, str]:
    return {
        "slug": spec.slug,
        "name": spec.name,
        "targetHost": "homebase",
        "role": spec.role_name,
        "detail": spec.detail,
        "confirmation": spec.confirmation,
        "package": spec.package_name,
        "disableNote": spec.disable_note,
    }


def _desktop_intents(body: list[dict[str, Any]] | dict[str, Any] | None) -> list[dict[str, Any]]:
    raw_apps: Any
    if isinstance(body, dict):
        raw_apps = body.get("desiredApps", body.get("apps", []))
    else:
        raw_apps = body
    if raw_apps is None:
        raw_apps = []
    if not isinstance(raw_apps, list):
        raise LegacyHomebaseRoleServiceValidationError(["desiredApps must be a list"])
    intents = []
    seen = set()
    for index, entry in enumerate(raw_apps):
        if not isinstance(entry, dict):
            raise LegacyHomebaseRoleServiceValidationError([f"desiredApps[{index}] must be an object"])
        slug = str(entry.get("slug") or "").strip()
        if not slug:
            raise LegacyHomebaseRoleServiceValidationError([f"desiredApps[{index}].slug is required"])
        if slug not in DESKTOP_ROLE_SLUGS:
            raise LegacyHomebaseRoleServiceValidationError([f"unsupported Desktop app {slug}"])
        if slug in seen:
            raise LegacyHomebaseRoleServiceValidationError([f"duplicate Desktop app {slug}"])
        seen.add(slug)
        intents.append({"spec": _role_spec(slug), "enabled": bool(entry.get("enabled"))})
    return intents


def _desktop_input(intents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"slug": intent["spec"].slug, "enabled": intent["enabled"]} for intent in intents]


def _validate_homebase(homebase: LegacyRoleHost) -> None:
    errors = []
    if homebase.name != "homebase":
        errors.append("homebase host name must be homebase")
    if not homebase.ansible_host:
        errors.append("homebase ansible_host is required")
    if errors:
        raise LegacyHomebaseRoleServiceValidationError(errors)


def _entry_user(entry: dict[str, Any]) -> str:
    return str(entry.get("sshUser") or "user")


def _required_text(entry: dict[str, Any], key: str) -> str:
    return str(entry.get(key) or "").strip()


def _sanitize_output(value: str) -> str:
    redacted = value
    for marker in ("BEGIN OPENSSH PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "LINODE_TOKEN", "DIGITALOCEAN_TOKEN", "password", "secret", "token"):
        redacted = redacted.replace(marker, "[REDACTED]")
    return redacted[:4000] + ("\n[truncated]" if len(redacted) > 4000 else "")


def _assert_no_forbidden_markers(value: str, context: str) -> None:
    forbidden = ["BEGIN OPENSSH PRIVATE KEY", "LINODE_TOKEN", "DIGITALOCEAN_TOKEN"]
    found = [marker for marker in forbidden if marker in value]
    if found:
        raise LegacyHomebaseRoleServiceValidationError([f"{context} contains forbidden marker {found[0]}"])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _save_binding_job(repository: JobRepository, job: StoredJobRun) -> StoredJobRun:
    from app.storage.job_repository import MixedAppendBindingFenceError
    try:
        return repository.save(job)
    except MixedAppendBindingFenceError as exc:
        raise LegacyHomebaseRoleServiceValidationError([str(exc)]) from exc
