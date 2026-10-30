# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from uuid import uuid4

from app.core.command_environment import barragan_subprocess_env
from app.core.runtime import start_runtime_task
from app.domain import JobEvent
from app.integrations.ansible_disposable_validation import resolve_ansible_playbook
from app.services.capability_execution import (
    CapabilityRoleApplyPlan,
    CapabilityRoleApplyPlanValidationError,
    build_optional_core_capability_role_apply_plan,
    copy_core_capability_roles,
    render_core_capability_apply_playbook,
)
from app.services.capability_lock_rendering import render_capability_lock
from app.services.core_ssh import (
    active_core_connection_details,
    deployment_known_hosts_file,
    ensure_known_hosts_file,
)
from app.services.engagement_capabilities import capability_overrides_for_workspace
from app.services.engagement_workspaces import (
    EngagementWorkspaceValidationError,
    load_prepared_engagement_workspace,
)
from app.services.engagements import get_engagement
from app.services.redteam_infra_template import RedteamInfraTemplateSource
from app.services.retained_workspace_capability_roles import import_selected_optional_capability_roles
from app.storage.deployment_plan_repository import (
    DeploymentPlanConflictError,
    DeploymentPlanRepository,
    SqlAlchemyDeploymentPlanRepository,
)
from app.storage.engagement_workspace_repository import (
    EngagementWorkspaceRepository,
    SqlAlchemyEngagementWorkspaceRepository,
)
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.service_repository import EngagementServiceRepository


CAPABILITY_RECONCILIATION_ACTION = "engagement_capability_reconciliation"
DEFAULT_WORKSPACE_ROOT = Path("/tmp/barragan-capability-reconciliation")
DEFAULT_KNOWN_HOSTS_ROOT = Path("/tmp/barragan-capability-reconciliation-known-hosts")
DEFAULT_CORE_SSH_PRIVATE_KEY = "/var/lib/barragan/.ssh/barragan_testing"
CORE_SSH_KEY_ENV = "BARRAGAN_VALIDATION_SSH_PRIVATE_KEY"
FORBIDDEN_CAPABILITY_OUTPUT_MARKERS = (
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "PRIVATE KEY-----",
    "LINODE_TOKEN",
    "DIGITALOCEAN_TOKEN",
    "go_simple_upload_server_token",
)
CORE_SSH_OPTIONS = (
    "-o StrictHostKeyChecking=accept-new",
    "-o IdentitiesOnly=yes",
    "-o BatchMode=yes",
    "-o ConnectTimeout=10",
)

# These jobs mutate the same core hosts or own the engagement-wide core
# lifecycle. Reconciliation must wait rather than racing another Ansible or
# core lifecycle operation.
CONFLICTING_CORE_MUTATION_ACTIONS = frozenset(
    {
        CAPABILITY_RECONCILIATION_ACTION,
        "pilot_standard_rti_guarded_execute",
        "engagement_comprehensive_teardown",
        "engagement_access_apply",
        "desktop_service_apply",
        "legacy_homebase_role_service_apply",
        "backflips_service_apply",
        "opsec_network_restrictions_apply",
        "outbound_channel_apply",
        "outbound_channel_remove",
        "inbound_channel_apply",
        "inbound_channel_remove",
        "inbound_request_header_gate_apply",
        "web_static_service_apply",
        "web_static_service_remove",
    }
)

CommandRunner = Callable[[list[str], Path], subprocess.CompletedProcess[str]]
BackgroundRunner = Callable[[Callable[[], None]], None]


class CapabilityReconciliationValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("capability reconciliation validation failed")
        self.errors = errors


class _LeaseRepository(Protocol):
    def acquire(self, engagement_id: str, owner_id: str, operation: str) -> bool: ...

    def release(self, engagement_id: str, owner_id: str) -> None: ...


@dataclass(frozen=True)
class CoreCapabilityHost:
    name: str
    host_class: str
    ansible_host: str
    ansible_user: str
    ssh_private_key_file: str
    known_hosts_file: str
    proxy_jump: str = ""

    def to_inventory_line(self) -> str:
        parts = [
            self.name,
            f"ansible_host={self.ansible_host}",
            f"ansible_user={self.ansible_user}",
            f"ansible_ssh_private_key_file={self.ssh_private_key_file}",
        ]
        ssh_args = [*CORE_SSH_OPTIONS, f"-o UserKnownHostsFile={self.known_hosts_file}"]
        if self.proxy_jump:
            proxy_command = [
                "ssh",
                "-i",
                self.ssh_private_key_file,
                *CORE_SSH_OPTIONS,
                f"-o UserKnownHostsFile={self.known_hosts_file}",
                "-W",
                "%h:%p",
                self.proxy_jump,
            ]
            ssh_args.append(f"-o ProxyCommand='{' '.join(proxy_command)}'")
        parts.append(f"ansible_ssh_common_args={json.dumps(' '.join(ssh_args))}")
        return " ".join(parts)


def get_capability_reconciliation(
    engagement_id: str,
    *,
    engagement_repos_root: Path,
    repository: JobRepository | None = None,
    workspace_repository: EngagementWorkspaceRepository | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    repo = repository or SqlAlchemyJobRepository()
    latest = _latest_reconciliation_job(repo, engagement_id)
    errors: list[str] = []
    plan_summary: dict[str, Any] = _empty_plan_summary()
    try:
        plan, core_deployment_id, details = _resolve_plan_and_core(
            engagement_id,
            engagement_repos_root=engagement_repos_root,
            repository=repo,
            workspace_repository=workspace_repository,
        )
        plan_summary = _public_plan(plan, core_deployment_id, details)
    except (
        CapabilityReconciliationValidationError,
        CapabilityRoleApplyPlanValidationError,
        EngagementWorkspaceValidationError,
    ) as exc:
        errors = _validation_messages(exc)
        plan_summary = {**plan_summary, "errors": errors}

    status = "blocked" if errors else "no_selection" if not plan_summary.get("roleCount") else "ready"
    if latest is not None and not errors:
        current_fingerprint = _plan_fingerprint(plan_summary)
        if latest.input.get("planFingerprint") == current_fingerprint:
            status = _status_from_job(latest)
    return {
        "status": status,
        "plan": plan_summary,
        "job": latest.to_detail().to_dict() if latest is not None else None,
    }


def start_capability_reconciliation(
    engagement_id: str,
    *,
    engagement_repos_root: Path,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    workspace_repository: EngagementWorkspaceRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
    lease_repository: DeploymentPlanRepository | None = None,
    runner: CommandRunner | None = None,
    background_runner: BackgroundRunner | None = None,
    workspace_root: Path | None = None,
    env: Mapping[str, str] | None = None,
    template_source: RedteamInfraTemplateSource | None = None,
    parent_apply_job_id: str = "",
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    repo = repository or SqlAlchemyJobRepository()
    _assert_no_conflicting_mutation(repo, engagement_id)
    workspace_repo = workspace_repository or SqlAlchemyEngagementWorkspaceRepository()
    retained_workspace = load_prepared_engagement_workspace(
        engagement_id,
        root=engagement_repos_root,
        repository=workspace_repo,
    )
    if retained_workspace is None:
        raise EngagementWorkspaceValidationError(
            ["engagement workspace must be prepared before reconciling optional capabilities"]
        )
    import_selected_optional_capability_roles(
        retained_workspace,
        capability_overrides_for_workspace(retained_workspace).get("selectedOptionals", []),
        repository=workspace_repo,
        template_source=template_source,
    )
    rendered_lock = render_capability_lock(
        engagement_id,
        root=engagement_repos_root,
        repository=workspace_repo,
        service_repository=service_repository,
    )
    if rendered_lock is None:
        raise CapabilityReconciliationValidationError(
            ["retained capability lock could not be rendered for this engagement workspace"]
        )
    plan, core_deployment_id, details = _resolve_plan_and_core(
        engagement_id,
        engagement_repos_root=engagement_repos_root,
        repository=repo,
        workspace_repository=workspace_repo,
    )
    if not plan.role_names:
        raise CapabilityReconciliationValidationError(
            ["select and save at least one optional executable role-backed core capability before applying"]
        )
    ansible = resolve_ansible_playbook(env=env)
    if not ansible.ok:
        raise CapabilityReconciliationValidationError(
            [ansible.error or ansible.message or "Could not resolve ansible-playbook executable"]
        )

    hosts = _core_hosts_for_plan(
        engagement_id,
        core_deployment_id,
        details,
        required_host_classes={host_class for host_class, entries in plan.roles_by_host_class.items() if entries},
    )
    job_id = f"job-{uuid4().hex[:12]}"
    workspace_dir = (workspace_root or DEFAULT_WORKSPACE_ROOT) / job_id
    _write_reconciliation_workspace(
        workspace_dir,
        plan,
        hosts,
        core_deployment_id,
        capability_lock=rendered_lock.content,
    )
    ensure_known_hosts_file(hosts[0].known_hosts_file)
    plan_summary = _public_plan(plan, core_deployment_id, details)
    fingerprint = _plan_fingerprint(plan_summary)
    command = [
        ansible.command or "ansible-playbook",
        "-i",
        "ansible/inventory.ini",
        "ansible/apply_optional_capabilities.yml",
    ]

    leases: _LeaseRepository | None = lease_repository
    if leases is None and repository is None:
        leases = SqlAlchemyDeploymentPlanRepository()
    if leases is not None:
        try:
            leases.acquire(engagement_id, job_id, "capability_reconciliation")
        except DeploymentPlanConflictError as exc:
            raise CapabilityReconciliationValidationError(
                ["a core plan, apply, teardown, or role reconciliation is running; wait for it to finish"]
            ) from exc

    timestamp = _now()
    job = StoredJobRun(
        id=job_id,
        action=CAPABILITY_RECONCILIATION_ACTION,
        status="queued",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by=requested_by,
        input={
            "engagementId": engagement_id,
            "coreDeploymentId": core_deployment_id,
            "planFingerprint": fingerprint,
            "capabilityLockSha256": hashlib.sha256(rendered_lock.content.encode("utf-8")).hexdigest(),
            "selectedRoles": plan_summary["rolesByHostClass"],
            **({"parentApplyJobId": parent_apply_job_id} if parent_apply_job_id else {}),
            "execution": {"terraform": False, "ansible": True, "providerMutation": False},
            "mutation": True,
            "retryRequired": False,
        },
        artifact_refs=[
            "ansible/inventory.ini",
            "ansible/apply_optional_capabilities.yml",
            "barragan/capability-lock.yml",
            "MANIFEST.json",
        ],
        created_at=timestamp,
        started_at=None,
        finished_at=None,
        events=[
            JobEvent(
                1,
                "info",
                "optional core capability reconciliation queued",
                {
                    "rolesByHostClass": plan_summary["rolesByHostClass"],
                    "targetHostClasses": plan_summary["targetHostClasses"],
                    "coreDeploymentId": core_deployment_id,
                    "capabilityLock": "barragan/capability-lock.yml",
                    "execution": {"terraform": False, "ansible": True, "providerMutation": False},
                },
            )
        ],
    )
    try:
        job = repo.save(job)
    except Exception:
        if leases is not None:
            leases.release(engagement_id, job_id)
        raise

    task_runner = background_runner or _start_background_task
    try:
        task_runner(
            lambda: _run_reconciliation_job(
                repo,
                job_id,
                engagement_id,
                command,
                workspace_dir,
                runner,
                leases,
            )
        )
    except Exception as exc:
        job = _mark_retry_required(
            repo,
            job,
            "capability reconciliation scheduler failed to start; retry is required",
            safe_capability_failure_detail(str(exc)),
        )
        if leases is not None:
            leases.release(engagement_id, job_id)

    job = repo.get(job_id) or job

    return {"status": _status_from_job(job), "plan": plan_summary, "job": job.to_detail().to_dict()}


def recover_interrupted_capability_reconciliations(
    *,
    repository: JobRepository | None = None,
    lease_repository: DeploymentPlanRepository | None = None,
) -> int:
    repo = repository or SqlAlchemyJobRepository()
    leases: _LeaseRepository | None = lease_repository
    if leases is None and repository is None:
        leases = SqlAlchemyDeploymentPlanRepository()
    recovered = 0
    for job in repo.list():
        if job.action != CAPABILITY_RECONCILIATION_ACTION or job.status not in {"queued", "running"}:
            continue
        _mark_retry_required(
            repo,
            job,
            "capability reconciliation was interrupted by an application restart; retry is required",
            "background execution did not survive restart",
        )
        if leases is not None:
            leases.release(job.target_id, job.id)
        recovered += 1
    return recovered


def assert_capability_reconciliation_idle(
    engagement_id: str,
    *,
    repository: JobRepository | None = None,
) -> None:
    active = next(
        (
            job
            for job in (repository or SqlAlchemyJobRepository()).list_for_engagement(engagement_id)
            if job.action in {CAPABILITY_RECONCILIATION_ACTION, "engagement_capability_apply"}
            and job.status in {"queued", "running"}
        ),
        None,
    )
    if active is not None:
        label = (
            "optional core capability reconciliation"
            if active.action == CAPABILITY_RECONCILIATION_ACTION
            else "capability apply"
        )
        raise CapabilityReconciliationValidationError(
            [f"{label} {active.id} is running; wait for it to finish"]
        )


def _resolve_plan_and_core(
    engagement_id: str,
    *,
    engagement_repos_root: Path,
    repository: JobRepository,
    workspace_repository: EngagementWorkspaceRepository | None,
) -> tuple[CapabilityRoleApplyPlan, str, list[dict[str, Any]]]:
    plan = build_optional_core_capability_role_apply_plan(
        engagement_id=engagement_id,
        engagement_repos_root=engagement_repos_root,
        repository=workspace_repository or SqlAlchemyEngagementWorkspaceRepository(),
        elk_enabled=True,
    )
    core_deployment_id, details = active_core_connection_details(repository, engagement_id)
    if not core_deployment_id or not details:
        raise CapabilityReconciliationValidationError(
            ["active core infrastructure inventory is required before applying role-backed capabilities"]
        )
    return plan, core_deployment_id, details


def _core_hosts_for_plan(
    engagement_id: str,
    core_deployment_id: str,
    details: list[dict[str, Any]],
    *,
    required_host_classes: set[str],
) -> tuple[CoreCapabilityHost, ...]:
    homebase = next((entry for entry in details if str(entry.get("role") or "") == "homebase"), None)
    if homebase is None:
        raise CapabilityReconciliationValidationError(
            ["active core deployment connectionDetails must include homebase"]
        )
    ssh_key = os.environ.get(CORE_SSH_KEY_ENV, DEFAULT_CORE_SSH_PRIVATE_KEY)
    known_hosts = deployment_known_hosts_file(DEFAULT_KNOWN_HOSTS_ROOT, engagement_id, core_deployment_id)
    homebase_host = CoreCapabilityHost(
        name="homebase",
        host_class="homebase",
        ansible_host=_required_connection_value(homebase, "publicIp", "homebase"),
        ansible_user=_connection_user(homebase),
        ssh_private_key_file=ssh_key,
        known_hosts_file=known_hosts,
    )
    hosts: list[CoreCapabilityHost] = [homebase_host]
    for index, entry in enumerate(details, start=1):
        role = str(entry.get("role") or "")
        if role not in {"proxy", "elk"}:
            continue
        host_class = role
        alias = _core_alias(entry, role, index)
        address = str(entry.get("privateIp") or entry.get("publicIp") or "").strip()
        if not address:
            raise CapabilityReconciliationValidationError(
                [f"active core deployment connectionDetails must include an address for {alias}"]
            )
        hosts.append(
            CoreCapabilityHost(
                name=alias,
                host_class=host_class,
                ansible_host=address,
                ansible_user=_connection_user(entry),
                ssh_private_key_file=ssh_key,
                known_hosts_file=known_hosts,
                proxy_jump=f"{homebase_host.ansible_user}@{homebase_host.ansible_host}",
            )
        )
    present = {host.host_class for host in hosts}
    if "common" in required_host_classes:
        required_host_classes = {*required_host_classes, "homebase"}
    missing = sorted(host_class for host_class in required_host_classes if host_class != "common" and host_class not in present)
    if missing:
        raise CapabilityReconciliationValidationError(
            [f"active core deployment inventory is missing required host class: {host_class}" for host_class in missing]
        )
    return tuple(hosts)


def _write_reconciliation_workspace(
    workspace: Path,
    plan: CapabilityRoleApplyPlan,
    hosts: tuple[CoreCapabilityHost, ...],
    core_deployment_id: str,
    *,
    capability_lock: str,
) -> None:
    ansible_dir = workspace / "ansible"
    ansible_dir.mkdir(parents=True, exist_ok=False)
    (ansible_dir / "inventory.ini").write_text(_render_inventory(hosts), encoding="utf-8")
    (ansible_dir / "apply_optional_capabilities.yml").write_text(
        render_core_capability_apply_playbook(plan),
        encoding="utf-8",
    )
    copy_core_capability_roles(workspace, plan)
    lock_path = workspace / "barragan" / "capability-lock.yml"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(capability_lock, encoding="utf-8")
    manifest = {
        "kind": "active-core-optional-capability-reconciliation",
        "coreDeploymentId": core_deployment_id,
        "rolesByHostClass": _roles_by_host_class(plan),
        "execution": {"terraform": False, "ansible": True, "providerMutation": False},
        "source": "retained-engagement-workspace",
    }
    (workspace / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _render_inventory(hosts: tuple[CoreCapabilityHost, ...]) -> str:
    groups = {
        "homebase": [host for host in hosts if host.host_class == "homebase"],
        "proxies": [host for host in hosts if host.host_class == "proxy"],
        "elk": [host for host in hosts if host.host_class == "elk"],
    }
    lines = [
        "# Managed by Barragan optional core capability reconciliation.",
        "# Core hosts only. Middle and edge sketch nodes are intentionally omitted.",
    ]
    for group, members in groups.items():
        lines.extend([f"[{group}]", *[host.to_inventory_line() for host in members], ""])
    lines.extend(["[pilot_rti:children]", "homebase", "proxies", "elk", ""])
    return "\n".join(lines)


def _run_reconciliation_job(
    repository: JobRepository,
    job_id: str,
    engagement_id: str,
    command: list[str],
    workspace: Path,
    runner: CommandRunner | None,
    leases: _LeaseRepository | None,
) -> None:
    job = repository.get(job_id)
    if job is None or job.status != "queued":
        if leases is not None:
            leases.release(engagement_id, job_id)
        return
    try:
        running = repository.save(
            replace(
                job,
                status="running",
                started_at=_now(),
                events=[
                    *job.events,
                    JobEvent(
                        len(job.events) + 1,
                        "info",
                        "optional core capability Ansible apply started",
                        {
                            "rolesByHostClass": job.input.get("selectedRoles", {}),
                            "command": ["ansible-playbook", "-i", "ansible/inventory.ini", "ansible/apply_optional_capabilities.yml"],
                        },
                    ),
                ],
            )
        )
        result = _run_ansible(command, workspace, runner)
        level = "info" if result.returncode == 0 else "error"
        message = (
            "optional core capability Ansible apply succeeded"
            if result.returncode == 0
            else "optional core capability Ansible apply failed; saved selection was preserved"
        )
        result_data: dict[str, Any] = {
            "commandResult": {"returncode": int(result.returncode), "ok": result.returncode == 0},
            "rolesByHostClass": running.input.get("selectedRoles", {}),
            "retryRequired": result.returncode != 0,
        }
        if result.returncode != 0:
            result_data["error"] = _ansible_failure_excerpt(result)
        candidate = replace(
            running,
            status="succeeded" if result.returncode == 0 else "failed",
            finished_at=_now(),
            events=[
                *running.events,
                JobEvent(
                    len(running.events) + 1,
                    level,
                    message,
                    result_data,
                ),
            ],
            input={**running.input, "retryRequired": result.returncode != 0},
        )
        _assert_safe_job(candidate)
        terminal = repository.save(candidate)
        _assert_safe_job(terminal)
    except Exception as exc:
        current = repository.get(job_id) or job
        terminal = _mark_retry_required(
            repository,
            current,
            "optional core capability Ansible apply failed; retry is required",
            safe_capability_failure_detail(str(exc)),
        )
        _assert_safe_job(terminal)
    finally:
        if leases is not None:
            leases.release(engagement_id, job_id)


def _run_ansible(command: list[str], workspace: Path, runner: CommandRunner | None) -> subprocess.CompletedProcess[str]:
    if runner is not None:
        return runner(command, workspace)
    return subprocess.run(
        command,
        cwd=workspace,
        env=barragan_subprocess_env(),
        check=False,
        capture_output=True,
        text=True,
    )


def _assert_no_conflicting_mutation(repository: JobRepository, engagement_id: str) -> None:
    for job in repository.list_for_engagement(engagement_id):
        if job.status in {"queued", "running"} and job.action in CONFLICTING_CORE_MUTATION_ACTIONS:
            raise CapabilityReconciliationValidationError(
                [f"core-host mutation {job.id} ({job.action}) is running; wait for it to finish"]
            )


def _mark_retry_required(
    repository: JobRepository,
    job: StoredJobRun,
    message: str,
    error: str,
) -> StoredJobRun:
    current = repository.get(job.id) or job
    event = JobEvent(
        len(current.events) + 1,
        "error",
        message,
        {"error": error, "retryRequired": True},
    )
    candidate = replace(
        current,
        status="failed",
        finished_at=_now(),
        input={**current.input, "retryRequired": True},
        events=[*current.events, event],
    )
    _assert_safe_job(candidate)
    saved = repository.save(candidate)
    _assert_safe_job(saved)
    return saved


def _public_plan(
    plan: CapabilityRoleApplyPlan,
    core_deployment_id: str,
    details: list[dict[str, Any]],
) -> dict[str, Any]:
    roles = _roles_by_host_class(plan)
    target_classes = [host_class for host_class, entries in roles.items() if entries]
    available_classes = sorted(
        {str(row.get("role") or "") for row in details if str(row.get("role") or "") in {"homebase", "proxy", "elk"}}
    )
    return {
        "source": {"kind": "retained-engagement-workspace", "immutableSnapshot": True},
        "coreDeploymentId": core_deployment_id,
        "selectedCount": plan.selected_count,
        "executableCount": plan.executable_count,
        "roleCount": len(plan.role_names),
        "rolesByHostClass": roles,
        "targetHostClasses": target_classes,
        "availableHostClasses": available_classes,
        "skipped": [dict(entry) for entry in plan.skipped],
        "warnings": [dict(entry) for entry in plan.warnings],
        "errors": [dict(entry) for entry in plan.errors],
        "execution": {"terraform": False, "ansible": True, "providerMutation": False, "uninstall": False},
    }


def _empty_plan_summary() -> dict[str, Any]:
    return {
        "source": {"kind": "retained-engagement-workspace", "immutableSnapshot": True},
        "coreDeploymentId": "",
        "selectedCount": 0,
        "executableCount": 0,
        "roleCount": 0,
        "rolesByHostClass": {host_class: [] for host_class in ("common", "homebase", "proxy", "elk")},
        "targetHostClasses": [],
        "availableHostClasses": [],
        "skipped": [],
        "warnings": [],
        "errors": [],
        "execution": {"terraform": False, "ansible": True, "providerMutation": False, "uninstall": False},
    }


def _roles_by_host_class(plan: CapabilityRoleApplyPlan) -> dict[str, list[dict[str, str]]]:
    return {
        host_class: [dict(entry) for entry in plan.roles_by_host_class.get(host_class, [])]
        for host_class in ("common", "homebase", "proxy", "elk")
    }


def _plan_fingerprint(plan: dict[str, Any]) -> str:
    payload = {
        "coreDeploymentId": plan.get("coreDeploymentId"),
        "rolesByHostClass": plan.get("rolesByHostClass"),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _latest_reconciliation_job(repository: JobRepository, engagement_id: str) -> StoredJobRun | None:
    return next(
        (
            job
            for job in repository.list_for_engagement(engagement_id)
            if job.action == CAPABILITY_RECONCILIATION_ACTION
        ),
        None,
    )


def _status_from_job(job: StoredJobRun) -> str:
    if bool(job.input.get("retryRequired")):
        return "retry_required"
    return job.status


def _validation_messages(exc: Exception) -> list[str]:
    values = getattr(exc, "errors", None)
    if isinstance(values, list):
        messages = []
        for value in values:
            if isinstance(value, dict):
                messages.append(str(value.get("reason") or "capability validation failed"))
            else:
                messages.append(str(value))
        return messages
    return [str(exc)]


def _core_alias(entry: dict[str, Any], role: str, index: int) -> str:
    for candidate in (entry.get("sshAlias"), entry.get("name"), entry.get("displayName")):
        token = str(candidate or "").strip().split("-", 1)[0]
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", token):
            return token
    return "elk" if role == "elk" else f"proxy{index:02d}"


def _required_connection_value(entry: dict[str, Any], key: str, name: str) -> str:
    value = str(entry.get(key) or "").strip()
    if not value:
        raise CapabilityReconciliationValidationError(
            [f"active core deployment connectionDetails must include {key} for {name}"]
        )
    return value


def _connection_user(entry: dict[str, Any]) -> str:
    return str(entry.get("sshUser") or "user")


def safe_capability_failure_detail(value: str) -> str:
    redacted = value
    value_pattern = r'''(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^,\s}"']+)'''
    for marker in ("LINODE_TOKEN", "DIGITALOCEAN_TOKEN", "go_simple_upload_server_token"):
        redacted = re.sub(
            rf"(?i)[\"']?{re.escape(marker)}[\"']?(?:\s*[:=]\s*|\s+){value_pattern}",
            "[REDACTED]",
            redacted,
        )
        redacted = re.sub(rf"(?i){re.escape(marker)}", "[REDACTED]", redacted)
    for pattern in (
        rf'''(?i)["']?\b(?:password|secret|token|authorization)\b["']?\s*[:=]\s*{value_pattern}''',
        r"(?i)\bbearer\s+\S+",
        r"-----BEGIN [^-\n]*PRIVATE KEY-----.*?(?:-----END [^-\n]*PRIVATE KEY-----|\Z)",
    ):
        redacted = re.sub(pattern, "[REDACTED]", redacted, flags=re.DOTALL)
    return redacted[:1000] + (" [truncated]" if len(redacted) > 1000 else "")


def _ansible_failure_excerpt(result: subprocess.CompletedProcess[str]) -> str:
    output = "\n".join(part for part in (result.stdout, result.stderr) if part)
    diagnostic: list[str] = []
    latest_task = ""
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("TASK ["):
            latest_task = stripped
        if "FAILED!" in stripped or "UNREACHABLE!" in stripped:
            if latest_task and latest_task not in diagnostic:
                diagnostic.append(latest_task)
            diagnostic.append(stripped)
    if not diagnostic:
        diagnostic = output.splitlines()[-12:]
    excerpt = " ".join(" ".join(line.split()) for line in diagnostic).strip()
    return safe_capability_failure_detail(excerpt or f"ansible-playbook exited {result.returncode}")


def _assert_safe_job(job: StoredJobRun) -> None:
    encoded = json.dumps(job.to_detail().to_dict(), sort_keys=True)
    if any(marker in encoded for marker in FORBIDDEN_CAPABILITY_OUTPUT_MARKERS):
        raise CapabilityReconciliationValidationError(["capability reconciliation job contains sensitive output"])


def _start_background_task(task: Callable[[], None]) -> None:
    start_runtime_task(task, name="barragan-capability-reconciliation-runner")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
