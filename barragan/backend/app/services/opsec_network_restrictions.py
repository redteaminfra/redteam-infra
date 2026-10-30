# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import ipaddress
import json
import os
import subprocess
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
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.service_repository import EngagementServiceRepository, SqlAlchemyEngagementServiceRepository, StoredEngagementService


OPSEC_SERVICE_ID = "opsec-network-restrictions"
OPSEC_SERVICE_TYPE = "opsec-network-restrictions"
OPSEC_SERVICE_NAME = "OPSEC Network Restrictions"
OPSEC_APPLY_ACTION = "opsec_network_restrictions_apply"
OPSEC_MANAGED_COMMENT = "barragan-opsec-network-restrictions"
MAX_DESTINATIONS = 200
MAX_NOTES_LENGTH = 5000
DEFAULT_WORKSPACE_ROOT = Path("/tmp/barragan-opsec-network-restrictions-apply")
DEFAULT_KNOWN_HOSTS_ROOT = Path("/tmp/barragan-opsec-network-restrictions-known-hosts")
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


class OpsecNetworkRestrictionsValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("OPSEC network restrictions validation failed")
        self.errors = errors


@dataclass(frozen=True)
class OpsecCoreHost:
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
class OpsecRestrictionsSpec:
    enabled: bool
    destinations: tuple[str, ...]
    notes: str = ""
    purpose: str = ""

    def to_config(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "destinations": list(self.destinations),
            "notes": self.notes,
            "purpose": self.purpose,
            "managedComment": OPSEC_MANAGED_COMMENT,
        }


@dataclass(frozen=True)
class RenderedOpsecArtifact:
    target: str
    content: str

    def to_dict(self) -> dict[str, str]:
        return {"target": self.target, "content": self.content}


@dataclass(frozen=True)
class OpsecApplyWorkspace:
    inventory: RenderedOpsecArtifact
    playbook: RenderedOpsecArtifact
    manifest: RenderedOpsecArtifact

    def to_dict(self) -> dict[str, object]:
        return {
            "status": "Pending OPSEC Apply",
            "mutation": True,
            "inventory": self.inventory.to_dict(),
            "playbook": self.playbook.to_dict(),
            "manifest": self.manifest.to_dict(),
        }


def get_opsec_network_restrictions(
    engagement_id: str,
    *,
    service_repository: EngagementServiceRepository | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    service = (service_repository or SqlAlchemyEngagementServiceRepository()).get(engagement_id, OPSEC_SERVICE_ID)
    if service is None:
        service = _service_from_spec(engagement_id, OpsecRestrictionsSpec(enabled=False, destinations=()), status="Disabled")
    return {"service": _service_payload(service), "configuration": _configuration_from_service(service)}


def apply_opsec_network_restrictions(
    engagement_id: str,
    body: Mapping[str, Any] | None,
    *,
    requested_by: str = "operator",
    job_repository: JobRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
    runner: CommandRunner | None = None,
    background_runner: BackgroundRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    spec = _spec_from_body(body)
    ansible_resolution = resolve_ansible_playbook(env=env)
    if not ansible_resolution.ok:
        raise OpsecNetworkRestrictionsValidationError([ansible_resolution.message])

    jobs = job_repository or SqlAlchemyJobRepository()
    services = service_repository or SqlAlchemyEngagementServiceRepository()
    previous = services.get(engagement_id, OPSEC_SERVICE_ID)
    previous_destinations = tuple(_configuration_from_service(previous).get("destinations") or []) if previous else ()
    remove_destinations = tuple(destination for destination in previous_destinations if destination not in spec.destinations or not spec.enabled)
    add_destinations = spec.destinations if spec.enabled else ()

    homebase = _core_homebase(jobs, engagement_id)
    workspace = render_opsec_apply_workspace(
        spec=spec,
        homebase=homebase,
        add_destinations=add_destinations,
        remove_destinations=remove_destinations,
    )
    workspace_dir = _write_workspace(workspace, workspace_root or DEFAULT_WORKSPACE_ROOT)
    ensure_known_hosts_file(homebase.known_hosts_file)
    command = [ansible_resolution.command or "ansible-playbook", "-i", "ansible/inventory.ini", "ansible/apply_opsec_network_restrictions.yml"]
    timestamp = _now()
    status = "Applying" if spec.enabled else "Removing"
    service = services.save(_service_from_spec(engagement_id, spec, status=status))
    placement = _service_placement(service)
    job = jobs.save(
        StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=OPSEC_APPLY_ACTION,
            status="running",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={
                "engagementId": engagement_id,
                "enabled": spec.enabled,
                "cidrs": list(spec.destinations),
                "mutation": True,
            },
            artifact_refs=["ansible/inventory.ini", "ansible/apply_opsec_network_restrictions.yml", "MANIFEST.json"],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=None,
            events=[
                JobEvent(
                    1,
                    "info",
                    "OPSEC network restrictions workspace rendered",
                    {
                        "workspaceDir": str(workspace_dir),
                        "inventoryTargets": ["selected_homebase"],
                        "workspaceEvidence": _workspace_evidence(workspace),
                        "servicePlacements": [placement],
                        "mutation": True,
                    },
                ),
                JobEvent(
                    2,
                    "info",
                    "OPSEC network restrictions Ansible apply started",
                    {
                        "command": command,
                        "cwd": str(workspace_dir),
                        "inventoryTargets": ["selected_homebase"],
                    },
                ),
            ],
        )
    )
    _assert_no_forbidden_markers(json.dumps([event.data for event in job.events], sort_keys=True), "OPSEC job events")

    task = lambda: _run_opsec_apply_job(jobs, services, job.id, command, workspace_dir, spec, runner)
    if background_runner is not None:
        background_runner(task)
    elif runner is not None:
        task()
    else:
        start_runtime_task(task, name="barragan-opsec-network-restrictions-runner")

    saved = jobs.get(job.id) or job
    latest_service = services.get(engagement_id, OPSEC_SERVICE_ID) or service
    return {
        "job": saved.to_detail().to_dict(),
        "status": _public_status(latest_service.status),
        "service": _service_payload(latest_service),
        "configuration": _configuration_from_service(latest_service),
    }


def render_opsec_apply_workspace(
    *,
    spec: OpsecRestrictionsSpec,
    homebase: OpsecCoreHost,
    add_destinations: tuple[str, ...] | None = None,
    remove_destinations: tuple[str, ...] | None = None,
) -> OpsecApplyWorkspace:
    _validate_homebase(homebase)
    add_values = tuple(spec.destinations if add_destinations is None and spec.enabled else add_destinations or ())
    remove_values = tuple(remove_destinations or ())
    inventory = RenderedOpsecArtifact("ansible/inventory.ini", _render_inventory(homebase))
    playbook = RenderedOpsecArtifact(
        "ansible/apply_opsec_network_restrictions.yml",
        _render_playbook(spec=spec, add_destinations=add_values, remove_destinations=remove_values),
    )
    manifest = RenderedOpsecArtifact(
        "MANIFEST.json",
        _render_manifest(spec=spec, homebase=homebase, add_destinations=add_values, remove_destinations=remove_values),
    )
    workspace = OpsecApplyWorkspace(inventory, playbook, manifest)
    _assert_no_forbidden_markers(json.dumps(workspace.to_dict(), sort_keys=True), "OPSEC workspace")
    return workspace


def _run_opsec_apply_job(
    jobs: JobRepository,
    services: EngagementServiceRepository,
    job_id: str,
    command: list[str],
    cwd: Path,
    spec: OpsecRestrictionsSpec,
    runner: CommandRunner | None,
) -> None:
    job = jobs.get(job_id)
    if job is None:
        return
    try:
        result = _run_guarded_command(command, cwd, runner)
    except Exception as exc:
        current = jobs.get(job_id) or job
        event = JobEvent(
            len(current.events) + 1,
            "error",
            "OPSEC network restrictions Ansible apply failed",
            {"error": _sanitize_output(str(exc)), "status": "Failed"},
        )
        jobs.save(replace(current, status="failed", finished_at=_now(), events=[*current.events, event]))
        services.save(_service_from_spec(current.target_id, spec, status="Failed", apply_job_id=job_id))
        return

    current = jobs.get(job_id) or job
    final_status = "Active" if spec.enabled and result.ok else "Disabled" if result.ok else "Failed"
    service = services.save(_service_from_spec(current.target_id, spec, status=final_status, apply_job_id=job_id))
    final_event = JobEvent(
        len(current.events) + 1,
        "info" if result.ok else "error",
        "OPSEC network restrictions Ansible apply succeeded" if result.ok else "OPSEC network restrictions Ansible apply failed",
        {
            "commandResult": _safe_command_result(result),
            "servicePlacements": [_service_placement(service)],
            "status": final_status,
        },
    )
    saved = replace(current, status="succeeded" if result.ok else "failed", finished_at=_now(), events=[*current.events, final_event])
    _assert_no_forbidden_markers(json.dumps([event.data for event in saved.events], sort_keys=True), "OPSEC job events")
    jobs.save(saved)


def _spec_from_body(body: Mapping[str, Any] | None) -> OpsecRestrictionsSpec:
    body = body or {}
    enabled = bool(body.get("enabled"))
    notes = _bounded_text(body.get("notes"), "notes", MAX_NOTES_LENGTH)
    purpose = _bounded_text(body.get("purpose"), "purpose", 1000)
    destinations = _normalize_destinations(body.get("destinations", body.get("cidrs", [])), enabled=enabled)
    return OpsecRestrictionsSpec(enabled=enabled, destinations=tuple(destinations), notes=notes, purpose=purpose)


def _normalize_destinations(raw: Any, *, enabled: bool) -> list[str]:
    errors: list[str] = []
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise OpsecNetworkRestrictionsValidationError(["destinations must be a list"])
    if len(raw) > MAX_DESTINATIONS:
        raise OpsecNetworkRestrictionsValidationError([f"destinations may contain at most {MAX_DESTINATIONS} entries"])
    normalized: list[str] = []
    seen: set[str] = set()
    for index, value in enumerate(raw):
        text = str(value or "").strip()
        if not text:
            continue
        try:
            candidate = _normalize_destination(text)
        except ValueError:
            errors.append(f"destinations[{index}] must be an IPv4/IPv6 address or CIDR")
            continue
        if candidate not in seen:
            normalized.append(candidate)
            seen.add(candidate)
    if enabled and not normalized:
        errors.append("at least one destination is required when OPSEC restrictions are enabled")
    if errors:
        raise OpsecNetworkRestrictionsValidationError(errors)
    return normalized


def _normalize_destination(value: str) -> str:
    if "/" in value:
        return str(ipaddress.ip_network(value, strict=False))
    return str(ipaddress.ip_address(value))


def _bounded_text(value: Any, field: str, max_length: int) -> str:
    text = str(value or "").strip()
    if len(text) > max_length:
        raise OpsecNetworkRestrictionsValidationError([f"{field} must be {max_length} characters or fewer"])
    return text


def _core_homebase(repository: JobRepository, engagement_id: str) -> OpsecCoreHost:
    deployment_id, details = latest_core_connection_details(repository, engagement_id)
    homebase = next((entry for entry in details if str(entry.get("role") or "") == "homebase"), None)
    if homebase is None:
        raise OpsecNetworkRestrictionsValidationError(["latest core deployment connectionDetails must include homebase"])
    ssh_key = os.environ.get(CORE_SSH_KEY_ENV, DEFAULT_CORE_SSH_PRIVATE_KEY)
    known_hosts_file = deployment_known_hosts_file(DEFAULT_KNOWN_HOSTS_ROOT, engagement_id, deployment_id)
    return OpsecCoreHost(
        "homebase",
        _required_text(homebase, "publicIp"),
        _entry_user(homebase),
        ssh_key,
        known_hosts_file,
    )


def _render_inventory(homebase: OpsecCoreHost) -> str:
    return "\n".join(
        [
            "# Managed by Barragan OPSEC network restrictions.",
            "# Target selected homebase only. Do not add proxy, middle, or edge sketch nodes here.",
            "[selected_homebase]",
            homebase.to_inventory_line(),
            "",
        ]
    )


def _render_playbook(
    *,
    spec: OpsecRestrictionsSpec,
    add_destinations: tuple[str, ...],
    remove_destinations: tuple[str, ...],
) -> str:
    lines = [
        "---",
        "- name: Apply OPSEC network restrictions to homebase",
        "  hosts: selected_homebase",
        "  become: true",
        "  gather_facts: false",
        "  vars:",
        f"    cidrs: {json.dumps(list(add_destinations))}",
        f"    barragan_opsec_remove_cidrs: {json.dumps(list(remove_destinations))}",
        f"    barragan_opsec_comment: {json.dumps(OPSEC_MANAGED_COMMENT)}",
        "  tasks:",
    ]
    if not add_destinations and not remove_destinations:
        lines.extend(
            [
                "    - name: No OPSEC network restriction changes requested",
                "      ansible.builtin.debug:",
                '        msg: "No OPSEC network restriction changes requested."',
            ]
        )
    if remove_destinations:
        lines.extend(
            [
                "    - name: Remove Barragan-managed OPSEC outbound blocks",
                "      ansible.builtin.iptables:",
                "        chain: OUTPUT",
                '        destination: "{{ item }}"',
                "        jump: DROP",
                "        comment: \"{{ barragan_opsec_comment }}\"",
                "        state: absent",
                "      loop: \"{{ barragan_opsec_remove_cidrs }}\"",
                "",
            ]
        )
    if add_destinations:
        lines.extend(
            [
                "    - name: Add Barragan-managed OPSEC outbound blocks",
                "      ansible.builtin.iptables:",
                "        chain: OUTPUT",
                '        destination: "{{ item }}"',
                "        jump: DROP",
                "        comment: \"{{ barragan_opsec_comment }}\"",
                "        state: present",
                "      loop: \"{{ cidrs }}\"",
                "",
            ]
        )
    lines.extend(
        [
            "    - name: Persist OPSEC iptables rules",
            "      ansible.builtin.command: iptables-save -f /etc/iptables/rules.v4",
            "      changed_when: false",
            "",
        ]
    )
    return "\n".join(lines)


def _render_manifest(
    *,
    spec: OpsecRestrictionsSpec,
    homebase: OpsecCoreHost,
    add_destinations: tuple[str, ...],
    remove_destinations: tuple[str, ...],
) -> str:
    return json.dumps(
        {
            "mode": OPSEC_APPLY_ACTION,
            "mutation": True,
            "service": OPSEC_SERVICE_NAME,
            "legacyRole": {
                "role": "opsec",
                "rolePath": str(redteam_infra_ansible_role_path("opsec")),
                "semantics": "Drop configured destinations from homebase OUTPUT.",
            },
            "targets": {
                "selectedHomebase": homebase.to_dict(),
            },
            "cidrs": list(spec.destinations),
            "addCidrs": list(add_destinations),
            "removeCidrs": list(remove_destinations),
            "enabled": spec.enabled,
            "managedComment": OPSEC_MANAGED_COMMENT,
            "opsecBoundary": {
                "inventoryTargets": ["selected_homebase"],
                "proxyTargets": [],
                "sketchMiddleTargets": [],
                "sketchEdgeTargets": [],
                "reason": "OPSEC network restrictions target homebase only.",
            },
        },
        indent=2,
        sort_keys=True,
    )


def _write_workspace(workspace: OpsecApplyWorkspace, root: Path) -> Path:
    workspace_dir = root / f"opsec-{uuid4().hex[:12]}"
    (workspace_dir / "ansible").mkdir(parents=True, exist_ok=True)
    for artifact in (workspace.inventory, workspace.playbook, workspace.manifest):
        path = workspace_dir / artifact.target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(artifact.content, encoding="utf-8")
    return workspace_dir


def _workspace_evidence(workspace: OpsecApplyWorkspace) -> dict[str, dict[str, object]]:
    return {
        "inventory": _artifact_evidence(workspace.inventory),
        "playbook": _artifact_evidence(workspace.playbook),
        "manifest": _artifact_evidence(workspace.manifest),
    }


def _artifact_evidence(artifact: RenderedOpsecArtifact) -> dict[str, object]:
    return {
        "path": artifact.target,
        "bytes": len(artifact.content.encode("utf-8")),
        "content": artifact.content,
    }


def _service_from_spec(
    engagement_id: str,
    spec: OpsecRestrictionsSpec,
    *,
    status: str,
    apply_job_id: str = "",
) -> StoredEngagementService:
    return StoredEngagementService(
        engagement_id=engagement_id,
        service_id=OPSEC_SERVICE_ID,
        service_type=OPSEC_SERVICE_TYPE,
        name=OPSEC_SERVICE_NAME,
        proxy_id="homebase",
        status=status,
        config=spec.to_config(),
        apply_job_id=apply_job_id,
    )


def _configuration_from_service(service: StoredEngagementService | None) -> dict[str, Any]:
    config = dict(service.config if service else {})
    return {
        "enabled": bool(config.get("enabled")),
        "destinations": [str(value) for value in config.get("destinations", []) if str(value or "").strip()],
        "notes": str(config.get("notes") or ""),
        "purpose": str(config.get("purpose") or ""),
        "managedComment": str(config.get("managedComment") or OPSEC_MANAGED_COMMENT),
    }


def _service_payload(service: StoredEngagementService) -> dict[str, Any]:
    payload = service.to_dict()
    payload["placement"] = _service_placement(service)
    return payload


def _service_placement(service: StoredEngagementService) -> dict[str, Any]:
    config = _configuration_from_service(service)
    return {
        "hostId": "homebase",
        "hostRole": "homebase",
        "serviceId": OPSEC_SERVICE_ID,
        "serviceType": OPSEC_SERVICE_TYPE,
        "service": OPSEC_SERVICE_NAME,
        "status": service.status,
        "detail": _service_detail(service.status, config),
        "destinations": config["destinations"],
        "managedComment": OPSEC_MANAGED_COMMENT,
    }


def _service_detail(status: str, config: dict[str, Any]) -> str:
    count = len(config.get("destinations") or [])
    if status == "Active":
        return f"Homebase outbound traffic is blocked to {count} configured destination{'s' if count != 1 else ''}."
    if status == "Disabled":
        return "Barragan-managed Homebase OPSEC network restrictions are disabled."
    if status in {"Applying", "Removing"}:
        return "Homebase OPSEC network restriction changes are running."
    if status == "Failed":
        return "Homebase OPSEC network restriction apply failed."
    return "Configurable Homebase outbound destination blocks."


def _public_status(status: str) -> str:
    if status in {"Active", "Disabled", "Applying", "Removing", "Failed"}:
        return status
    return "Unknown"


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


def _validate_homebase(homebase: OpsecCoreHost) -> None:
    errors = []
    if homebase.name != "homebase":
        errors.append("homebase host name must be homebase")
    if not homebase.ansible_host:
        errors.append("homebase ansible_host is required")
    if errors:
        raise OpsecNetworkRestrictionsValidationError(errors)


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
        raise OpsecNetworkRestrictionsValidationError([f"{context} contains forbidden marker {found[0]}"])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
