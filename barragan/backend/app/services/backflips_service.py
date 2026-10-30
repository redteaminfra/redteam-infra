# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import os
import ipaddress
import shutil
import subprocess
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import uuid4

from app.core.command_environment import barragan_subprocess_env
from app.domain import JobEvent
from app.integrations.ansible_disposable_validation import resolve_ansible_playbook
from app.integrations.oci_disposable_terraform import DisposableCommandResult
from app.services.core_ssh import (
    active_core_connection_details,
    core_proxy_identity,
    deployment_known_hosts_file,
    ensure_known_hosts_file,
)
from app.services.engagements import get_engagement
from app.services.infra_orientation import try_enqueue_infra_orientation_refresh
from app.services.outbound_channel_artifacts import engagement_sketch_identity_file_path
from app.services.redteam_infra_template import redteam_infra_ansible_role_path
from app.services.sketch_ssh_keys import SketchSshKeyNotFoundError
from app.services.sketch_transport_ssh_keys import write_existing_sketch_transport_ssh_key_files
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.sketch_chain_repository import SketchChainRepository, SqlAlchemySketchChainRepository


BACKFLIPS_APPLY_PREVIEW_ACTION = "backflips_service_apply_preview"
BACKFLIPS_APPLY_ACTION = "backflips_service_apply"
BACKFLIPS_APPLY_CONFIRMATION = "apply-service-backflips"
BACKFLIPS_SERVICE_NAME = "SSH Backflips"
BACKFLIPS_PORT = "2222"
DEFAULT_WORKSPACE_ROOT = Path("/tmp/barragan-backflips-service-apply")
DEFAULT_KNOWN_HOSTS_ROOT = Path("/tmp/barragan-backflips-known-hosts")
DEFAULT_CORE_SSH_PRIVATE_KEY = "/var/lib/barragan/.ssh/barragan_testing"
CORE_SSH_KEY_ENV = "BARRAGAN_VALIDATION_SSH_PRIVATE_KEY"
BACKFLIPS_ROLE_PATH = redteam_infra_ansible_role_path("backflips_v2")
CORE_SSH_OPTIONS = (
    "-o StrictHostKeyChecking=accept-new",
    "-o IdentitiesOnly=yes",
    "-o BatchMode=yes",
    "-o ConnectTimeout=10",
)

CommandRunner = Callable[[list[str], Path | None], subprocess.CompletedProcess[str]]


class BackflipsServiceValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("backflips service validation failed")
        self.errors = errors


@dataclass(frozen=True)
class BackflipsCoreHost:
    name: str
    ansible_host: str
    ansible_user: str = "ubuntu"
    ssh_private_key_file: str = ""
    proxy_jump: str = ""
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
        if self.proxy_jump:
            proxy_known_hosts_option = (
                [f"-o UserKnownHostsFile={self.known_hosts_file}"]
                if self.known_hosts_file
                else []
            )
            proxy_command = [
                "ssh",
                "-i",
                self.ssh_private_key_file,
                *CORE_SSH_OPTIONS,
                *proxy_known_hosts_option,
                "-W",
                "%h:%p",
                self.proxy_jump,
            ]
            ssh_args.append(f"-o ProxyCommand='{' '.join(proxy_command)}'")
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
        if self.proxy_jump:
            body["proxyJump"] = self.proxy_jump
        if self.known_hosts_file:
            body["knownHostsFile"] = self.known_hosts_file
        return body


@dataclass(frozen=True)
class RenderedServiceArtifact:
    target: str
    content: str

    def to_dict(self) -> dict[str, str]:
        return {"target": self.target, "content": self.content}


@dataclass(frozen=True)
class BackflipsApplyWorkspace:
    inventory: RenderedServiceArtifact
    playbook: RenderedServiceArtifact
    manifest: RenderedServiceArtifact

    def to_dict(self) -> dict[str, object]:
        return {
            "status": "Pending Service Apply",
            "mutation": False,
            "inventory": self.inventory.to_dict(),
            "playbook": self.playbook.to_dict(),
            "manifest": self.manifest.to_dict(),
        }


def preview_backflips_service_apply(
    engagement_id: str,
    *,
    proxy_id: str = "proxy01",
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    sketch_repository: SketchChainRepository | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    repo = repository or SqlAlchemyJobRepository()
    homebase, proxy = _core_apply_hosts(repo, engagement_id, proxy_id)
    sketch_key_path = engagement_sketch_identity_file_path(engagement.name)
    middle_ip = _middle_ip_for_proxy(engagement_id, proxy_id, sketch_repository)
    workspace = render_backflips_apply_workspace(
        homebase=homebase,
        proxy=proxy,
        sketch_key_path=sketch_key_path,
        middle_ip=middle_ip,
        sketch_private_key_src="/run/barragan/secure-material/sketch-transport-key",
    )
    job = _save_preview_job(repo, engagement_id, proxy_id, requested_by, workspace)
    return {"job": job.to_detail().to_dict(), "workspace": workspace.to_dict()}


def apply_backflips_service(
    engagement_id: str,
    *,
    confirmation: str,
    proxy_id: str = "proxy01",
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    runner: CommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
    sketch_repository: SketchChainRepository | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    if confirmation != BACKFLIPS_APPLY_CONFIRMATION:
        raise BackflipsServiceValidationError([f'confirmation must equal "{BACKFLIPS_APPLY_CONFIRMATION}"'])

    ansible_resolution = resolve_ansible_playbook(env=env)
    if not ansible_resolution.ok:
        raise BackflipsServiceValidationError([ansible_resolution.message])

    repo = repository or SqlAlchemyJobRepository()
    homebase, proxy = _core_apply_hosts(repo, engagement_id, proxy_id)
    core_deployment_id, core_details = active_core_connection_details(repo, engagement_id)
    proxy_identity = core_proxy_identity(core_details, proxy_id)
    sketch_key_path = engagement_sketch_identity_file_path(engagement.name)
    middle_ip = _middle_ip_for_proxy(engagement_id, proxy_id, sketch_repository)
    workspace_dir = _new_workspace_dir(workspace_root or DEFAULT_WORKSPACE_ROOT, proxy_id)
    try:
        sketch_private_key_src, _ = write_existing_sketch_transport_ssh_key_files(
            engagement_id,
            workspace_dir / "keys",
        )
    except SketchSshKeyNotFoundError as exc:
        shutil.rmtree(workspace_dir, ignore_errors=True)
        raise BackflipsServiceValidationError([str(exc)]) from exc
    try:
        workspace = render_backflips_apply_workspace(
            homebase=homebase,
            proxy=proxy,
            sketch_key_path=sketch_key_path,
            middle_ip=middle_ip,
            sketch_private_key_src=sketch_private_key_src,
        )
        _write_workspace(workspace, workspace_dir)
        _ensure_known_hosts_file(homebase.known_hosts_file)
    except Exception:
        shutil.rmtree(workspace_dir / "keys", ignore_errors=True)
        raise
    command = [ansible_resolution.command or "ansible-playbook", "-i", "ansible/inventory.ini", "ansible/apply_backflips.yml"]
    timestamp = _now()
    applying_state = _service_state(proxy_id, status="Applying")
    try:
        job = _save_binding_job(repo,
            StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=BACKFLIPS_APPLY_ACTION,
            status="running",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={
                "engagementId": engagement_id,
                "proxyId": proxy_id,
                "coreDeploymentId": core_deployment_id,
                "coreProxyIdentity": proxy_identity,
                "confirmation": "redacted",
                "mutation": True,
            },
            artifact_refs=["ansible/inventory.ini", "ansible/apply_backflips.yml", "MANIFEST.json"],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=None,
            events=[
                JobEvent(
                    1,
                    "info",
                    "backflips service apply workspace rendered",
                    {
                        "proxyId": proxy_id,
                        "workspaceDir": str(workspace_dir),
                        "inventoryTargets": ["selected_proxy"],
                        "workspaceEvidence": _workspace_evidence(workspace),
                        "servicePlacements": [applying_state["placement"]],
                        "mutation": True,
                    },
                ),
                JobEvent(
                    2,
                    "info",
                    "backflips service Ansible apply started",
                    {
                        "proxyId": proxy_id,
                        "command": command,
                        "cwd": str(workspace_dir),
                        "inventoryTargets": ["selected_proxy"],
                    },
                ),
            ],
            )
        )
        _assert_no_forbidden_markers(json.dumps([event.data for event in job.events], sort_keys=True), "backflips job events")
    except Exception:
        shutil.rmtree(workspace_dir / "keys", ignore_errors=True)
        raise
    try:
        result = _run_guarded_command(command, workspace_dir, runner)
    finally:
        shutil.rmtree(workspace_dir / "keys", ignore_errors=True)
    command_result = _safe_command_result(result)
    finished_at = _now()
    final_status = "succeeded" if result.ok else "failed"
    final_service_state = _service_state(proxy_id, status="Configured" if result.ok else "Failed")
    final_event = JobEvent(
        3,
        "info" if result.ok else "error",
        "backflips service Ansible apply succeeded" if result.ok else "backflips service Ansible apply failed",
        {
            "proxyId": proxy_id,
            "commandResult": command_result,
            "servicePlacements": [final_service_state["placement"]],
            "status": "Configured" if result.ok else "Failed",
        },
    )
    saved = _save_binding_job(repo, replace(job, status=final_status, finished_at=finished_at, events=job.events + [final_event]))
    if saved.status == "succeeded":
        try_enqueue_infra_orientation_refresh(engagement_id, repository=repo)
    return {"job": saved.to_detail().to_dict(), "status": "Configured" if result.ok else "Failed"}


def render_backflips_apply_workspace(
    *,
    homebase: BackflipsCoreHost,
    proxy: BackflipsCoreHost,
    sketch_key_path: str = "/opt/ssh-proxy/keys/sketchkey",
    middle_ip: str = "",
    sketch_private_key_src: str = "",
) -> BackflipsApplyWorkspace:
    _validate_core_hosts(homebase, proxy)
    _validate_sketch_defaults(sketch_key_path, middle_ip)
    inventory = RenderedServiceArtifact("ansible/inventory.ini", _render_inventory(proxy))
    playbook = RenderedServiceArtifact(
        "ansible/apply_backflips.yml",
        _render_playbook(
            sketch_key_path=sketch_key_path,
            middle_ip=middle_ip,
            sketch_private_key_src=sketch_private_key_src,
        ),
    )
    manifest = RenderedServiceArtifact(
        "MANIFEST.json",
        _render_manifest(homebase, proxy, sketch_key_path=sketch_key_path, middle_ip=middle_ip),
    )
    workspace = BackflipsApplyWorkspace(inventory, playbook, manifest)
    _assert_no_forbidden_markers(json.dumps(workspace.to_dict(), sort_keys=True), "backflips workspace")
    return workspace


def _core_apply_hosts(
    repository: JobRepository,
    engagement_id: str,
    proxy_id: str,
) -> tuple[BackflipsCoreHost, BackflipsCoreHost]:
    if not _is_proxy_id(proxy_id):
        raise BackflipsServiceValidationError(["proxyId must look like proxy01"])
    deployment_id, details = active_core_connection_details(repository, engagement_id)
    homebase = next((entry for entry in details if str(entry.get("role") or "") == "homebase"), None)
    proxy = next((entry for entry in details if _entry_matches_proxy(entry, proxy_id)), None)
    if homebase is None:
        raise BackflipsServiceValidationError(["latest core deployment connectionDetails must include homebase"])
    if proxy is None:
        raise BackflipsServiceValidationError([f"latest core deployment connectionDetails must include {proxy_id}"])
    ssh_key = _core_ssh_private_key_path()
    known_hosts_file = _known_hosts_file(engagement_id, deployment_id)
    homebase_host = BackflipsCoreHost(
        "homebase",
        _required_text(homebase, "publicIp"),
        _entry_user(homebase),
        ssh_key,
        "",
        known_hosts_file,
    )
    proxy_host = BackflipsCoreHost(
        proxy_id,
        _required_text(proxy, "privateIp") or _required_text(proxy, "publicIp"),
        _entry_user(proxy),
        ssh_key,
        f"{homebase_host.ansible_user}@{homebase_host.ansible_host}",
        known_hosts_file,
    )
    return homebase_host, proxy_host


def _render_inventory(proxy: BackflipsCoreHost) -> str:
    return "\n".join(
        [
            "# Managed by Barragan Backflips service apply.",
            "# Target selected proxy only. Do not add middle or edge sketch nodes here.",
            "[selected_proxy]",
            proxy.to_inventory_line(),
            "",
        ]
    )


def _render_playbook(*, sketch_key_path: str, middle_ip: str, sketch_private_key_src: str) -> str:
    tasks = [
        "  tasks:",
        "    - name: Create engagement sketch key directory",
        "      ansible.builtin.file:",
        "        path: /opt/ssh-proxy/keys",
        "        state: directory",
        "        owner: root",
        "        group: root",
        "        mode: '0700'",
    ]
    if sketch_private_key_src:
        tasks.extend(
            [
                "    - name: Install engagement sketch transport identity",
                "      ansible.builtin.copy:",
                f"        src: {sketch_private_key_src}",
                f"        dest: {sketch_key_path}",
                "        owner: root",
                "        group: root",
                "        mode: '0600'",
            ]
        )
    if middle_ip:
        tasks.extend(
            [
                "    - name: Configure default Backflips middle",
                "      ansible.builtin.lineinfile:",
                "        path: /opt/backflips/etc/backflips.conf",
                "        regexp: '^middleIP\\s*='",
                f"        line: 'middleIP = {middle_ip}'",
            ]
        )
    tasks.extend(
        [
            "    - name: Reload systemd after Backflips role",
            "      ansible.builtin.systemd:",
            "        daemon_reload: true",
            "",
            "    - name: Restart and enable Docker socket",
            "      ansible.builtin.systemd:",
            "        name: docker.socket",
            "        enabled: true",
            "        state: restarted",
            "",
            "    - name: Restart and enable Docker service",
            "      ansible.builtin.systemd:",
            "        name: docker.service",
            "        enabled: true",
            "        state: restarted",
            "",
            "    - name: Wait for Docker daemon readiness",
            "      ansible.builtin.command:",
            "        argv:",
            "          - docker",
            "          - info",
            "      register: backflips_docker_readiness",
            "      changed_when: false",
            "      retries: 10",
            "      delay: 3",
            "      until: backflips_docker_readiness.rc == 0",
        ]
    )
    return "\n".join(
        [
            "---",
            "- name: Apply SSH Backflips service to selected proxy",
            "  hosts: selected_proxy",
            "  become: true",
            "  roles:",
            f"    - role: {BACKFLIPS_ROLE_PATH}",
            "      vars:",
            f"        sketchkey: {sketch_key_path}",
            *tasks,
            "",
        ]
    )


def _render_manifest(
    homebase: BackflipsCoreHost,
    proxy: BackflipsCoreHost,
    *,
    sketch_key_path: str,
    middle_ip: str,
) -> str:
    return json.dumps(
        {
            "mode": "backflips_service_apply_preview",
            "mutation": False,
            "service": BACKFLIPS_SERVICE_NAME,
            "rolePath": str(BACKFLIPS_ROLE_PATH),
            "targets": {
                "selectedProxy": proxy.to_dict(),
                "homebaseJump": homebase.to_dict(),
            },
            "operatorDefaults": {
                "middleIp": middle_ip,
                "middleUser": "sketchssh",
                "middleKeyPath": sketch_key_path,
                "cliPath": "/opt/backflips/sshbackflip.py",
            },
            "opsecBoundary": {
                "inventoryTargets": ["selected_proxy"],
                "sketchMiddleTargets": [],
                "sketchEdgeTargets": [],
                "reason": "Barragan deploys Backflips readiness on the proxy; operators manage listeners with the Backflips CLI.",
            },
            "inboundChannel": _service_state(proxy.name, status="Pending Service Apply")["inboundChannel"],
        },
        indent=2,
        sort_keys=True,
    )


def _save_preview_job(
    repository: JobRepository,
    engagement_id: str,
    proxy_id: str,
    requested_by: str,
    workspace: BackflipsApplyWorkspace,
) -> StoredJobRun:
    timestamp = _now()
    service_state = _service_state(proxy_id, status="Pending Service Apply")
    return _save_binding_job(repository,
        StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=BACKFLIPS_APPLY_PREVIEW_ACTION,
            status="succeeded",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={"engagementId": engagement_id, "proxyId": proxy_id, "mutation": False},
            artifact_refs=["ansible/inventory.ini", "ansible/apply_backflips.yml", "MANIFEST.json"],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=timestamp,
            events=[
                JobEvent(
                    1,
                    "info",
                    "backflips service apply preview rendered",
                    {
                        "proxyId": proxy_id,
                        "workspace": workspace.to_dict(),
                        "workspaceEvidence": _workspace_evidence(workspace),
                        "servicePlacements": [service_state["placement"]],
                        "mutation": False,
                    },
                )
            ],
        )
    )


def _new_workspace_dir(root: Path, proxy_id: str) -> Path:
    workspace_dir = root / f"{proxy_id}-{uuid4().hex[:12]}"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    return workspace_dir


def _write_workspace(
    workspace: BackflipsApplyWorkspace,
    root_or_workspace: Path,
    proxy_id: str | None = None,
) -> Path:
    workspace_dir = _new_workspace_dir(root_or_workspace, proxy_id) if proxy_id else root_or_workspace
    workspace_dir.mkdir(parents=True, exist_ok=True)
    (workspace_dir / "ansible").mkdir(parents=True, exist_ok=True)
    for artifact in (workspace.inventory, workspace.playbook, workspace.manifest):
        path = workspace_dir / artifact.target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(artifact.content, encoding="utf-8")
    return workspace_dir


def _middle_ip_for_proxy(
    engagement_id: str,
    proxy_id: str,
    sketch_repository: SketchChainRepository | None,
) -> str:
    repo = sketch_repository or SqlAlchemySketchChainRepository()
    middle_ips = {
        str(node.get("publicIp") or "").strip()
        for chain in repo.list_for_engagement(engagement_id)
        if chain.assigned_proxy == proxy_id and chain.status == "deployed" and not chain.burned
        for node in chain.nodes
        if str(node.get("role") or "") == "middle" and str(node.get("publicIp") or "").strip()
    }
    if len(middle_ips) > 1:
        raise BackflipsServiceValidationError(
            [f"{proxy_id} has multiple deployed middles; Backflips bootstrap requires one default middle per proxy"]
        )
    return next(iter(middle_ips), "")


def _validate_sketch_defaults(sketch_key_path: str, middle_ip: str) -> None:
    if not sketch_key_path.startswith("/opt/ssh-proxy/keys/"):
        raise BackflipsServiceValidationError(["sketchkey must live under /opt/ssh-proxy/keys"])
    if middle_ip:
        try:
            ipaddress.ip_address(middle_ip)
        except ValueError:
            raise BackflipsServiceValidationError(["middleIp must be an IP address"])


def _workspace_evidence(workspace: BackflipsApplyWorkspace) -> dict[str, dict[str, object]]:
    return {
        "inventory": _artifact_evidence(workspace.inventory),
        "playbook": _artifact_evidence(workspace.playbook),
        "manifest": _artifact_evidence(workspace.manifest),
    }


def _artifact_evidence(artifact: RenderedServiceArtifact) -> dict[str, object]:
    return {
        "path": artifact.target,
        "bytes": len(artifact.content.encode("utf-8")),
        "content": artifact.content,
    }


def _service_state(proxy_id: str, *, status: str) -> dict[str, dict[str, Any]]:
    proxy_host = proxy_id
    return {
        "placement": {
            "hostId": proxy_id,
            "hostRole": "proxy",
            "service": BACKFLIPS_SERVICE_NAME,
            "status": status,
            "port": BACKFLIPS_PORT,
            "detail": _service_detail(status),
        },
        "inboundChannel": {
            "channelId": "default-backflip",
            "domain": "Not Deployed",
            "protocol": "TCP",
            "externalPort": "443",
            "edge": "Not Deployed",
            "middle": "Not Deployed",
            "proxy": proxy_host,
            "terminatesOn": proxy_host,
            "service": BACKFLIPS_SERVICE_NAME,
            "internalPort": BACKFLIPS_PORT,
            "purpose": "SSH Backflips service listener on selected proxy; edge/middle ingress routing remains separate.",
            "status": status,
        },
    }


def _service_detail(status: str) -> str:
    if status == "Configured":
        return "Proxy-host SSH Backflips role applied."
    if status == "Failed":
        return "Proxy-host SSH Backflips role apply failed."
    if status == "Applying":
        return "Proxy-host SSH Backflips role apply is running."
    return "Proxy-host SSH Backflips role apply has not run yet."


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


def _safe_command_result(result: DisposableCommandResult) -> dict[str, Any]:
    return {
        "command": result.command,
        "cwd": result.cwd,
        "returncode": result.returncode,
        "ok": result.ok,
        "stdout": _sanitize_output(result.stdout),
        "stderr": _sanitize_output(result.stderr),
    }


def _validate_core_hosts(homebase: BackflipsCoreHost, proxy: BackflipsCoreHost) -> None:
    errors = []
    if homebase.name != "homebase":
        errors.append("homebase host name must be homebase")
    if not _is_proxy_id(proxy.name):
        errors.append("proxy host name must look like proxy01")
    if not homebase.ansible_host:
        errors.append("homebase ansible_host is required")
    if not proxy.ansible_host:
        errors.append("proxy ansible_host is required")
    if not proxy.proxy_jump:
        errors.append("proxy target must be reached through homebase ProxyCommand")
    if errors:
        raise BackflipsServiceValidationError(errors)


def _entry_matches_proxy(entry: dict[str, Any], proxy_id: str) -> bool:
    role = str(entry.get("role") or "")
    display = str(entry.get("displayName") or entry.get("sshAlias") or "")
    return role in {"proxy", proxy_id} and (display == proxy_id or display.startswith(f"{proxy_id}-"))


def _entry_user(entry: dict[str, Any]) -> str:
    return str(entry.get("sshUser") or "user")


def _required_text(entry: dict[str, Any], key: str) -> str:
    return str(entry.get(key) or "").strip()


def _is_proxy_id(value: str) -> bool:
    return bool(value) and value.startswith("proxy") and len(value) == 7 and value[-2:].isdigit()


def _core_ssh_private_key_path() -> str:
    return os.environ.get(CORE_SSH_KEY_ENV, DEFAULT_CORE_SSH_PRIVATE_KEY)


def _known_hosts_file(engagement_id: str, deployment_id: str = "unknown-core") -> str:
    return deployment_known_hosts_file(DEFAULT_KNOWN_HOSTS_ROOT, engagement_id, deployment_id)


def _ensure_known_hosts_file(path: str) -> None:
    ensure_known_hosts_file(path)


def _sanitize_output(value: str) -> str:
    redacted = value
    for marker in ("BEGIN OPENSSH PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "LINODE_TOKEN", "DIGITALOCEAN_TOKEN", "password", "secret", "token"):
        redacted = redacted.replace(marker, "[REDACTED]")
    return redacted[:4000] + ("\n[truncated]" if len(redacted) > 4000 else "")


def _assert_no_forbidden_markers(value: str, context: str) -> None:
    forbidden = ["BEGIN OPENSSH PRIVATE KEY", "LINODE_TOKEN", "DIGITALOCEAN_TOKEN"]
    found = [marker for marker in forbidden if marker in value]
    if found:
        raise BackflipsServiceValidationError([f"{context} contains forbidden marker {found[0]}"])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _save_binding_job(repository: JobRepository, job: StoredJobRun) -> StoredJobRun:
    from app.storage.job_repository import MixedAppendBindingFenceError
    try:
        return repository.save(job)
    except MixedAppendBindingFenceError as exc:
        raise BackflipsServiceValidationError([str(exc)]) from exc
