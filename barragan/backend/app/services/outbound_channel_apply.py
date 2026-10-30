# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import os
import re
import hashlib
import shutil
import subprocess
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Callable, Mapping
from uuid import uuid4

from app.core.command_environment import barragan_subprocess_env
from app.domain import JobEvent
from app.integrations.ansible_disposable_validation import resolve_ansible, resolve_ansible_playbook
from app.integrations.oci_disposable_terraform import DisposableCommandResult
from app.services.engagements import get_engagement
from app.services.core_ssh import active_core_connection_details
from app.services.infra_orientation import try_enqueue_infra_orientation_refresh
from app.services.engagement_operations import get_operations_overview
from app.services.outbound_channel_artifacts import (
    OutboundChannelArtifacts,
    OutboundChannelArtifactValidationError,
    RenderedArtifact,
    SketchNodeOpsecBoundary,
    ValidationCommand,
)
from app.services.sketch_ssh_keys import SketchSshKeyNotFoundError
from app.services.sketch_transport_ssh_keys import write_existing_sketch_transport_ssh_key_files
from app.services.sketch_provider_firewall import sync_provider_ingress_for_transport
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


CORE_HOST_PATTERN = re.compile(r"^(homebase|proxy\d{2})$")
SECRET_MARKERS = (
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "LINODE_TOKEN",
    "DIGITALOCEAN_TOKEN",
    "OCI_CLI_AUTH",
    "provider_token",
    "private_key_material",
)
APPLY_PREVIEW_STATUS = "Pending Core Apply"
APPLY_SUCCESS_STATUS = "Pending Validation"
VALIDATION_SUCCESS_STATUS = "Validated"
VALIDATION_WARNING_STATUS = "Validated with warnings"
VALIDATION_FAILED_STATUS = "Validation Failed"
OUTBOUND_APPLY_PREVIEW_ACTION = "outbound_channel_apply_preview"
OUTBOUND_APPLY_ACTION = "outbound_channel_apply"
OUTBOUND_VALIDATE_ACTION = "outbound_channel_validation"
OUTBOUND_REMOVE_ACTION = "outbound_channel_remove"
ANSIBLE_APPLY_COMMAND = ["ansible-playbook", "-i", "ansible/inventory.ini", "ansible/apply_outbound_channel.yml"]
ANSIBLE_REMOVE_COMMAND = ["ansible-playbook", "-i", "ansible/inventory.ini", "ansible/remove_outbound_channel.yml"]
MAX_COMMAND_OUTPUT_CHARS = 4000
DEFAULT_WORKSPACE_ROOT = Path("/tmp/barragan-outbound-channel-apply")
DEFAULT_CORE_SSH_PRIVATE_KEY = "/var/lib/barragan/.ssh/barragan_testing"
CORE_SSH_KEY_ENV = "BARRAGAN_VALIDATION_SSH_PRIVATE_KEY"
OUTBOUND_HTTP_PROBE_URLS = (
    "https://ifconfig.me",
    "https://www.google.com",
    "https://www.cnn.com",
    "https://www.amazon.com",
    "https://www.facebook.com",
)
CommandRunner = Callable[[list[str], Path | None], subprocess.CompletedProcess[str]]
ProviderFirewallSync = Callable[..., Any]


class OutboundChannelApplyValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("outbound channel apply workspace validation failed")
        self.errors = errors


@dataclass(frozen=True)
class CoreApplyHost:
    name: str
    ansible_host: str
    ansible_user: str = "ubuntu"
    ssh_private_key_file: str = ""
    proxy_jump: str = ""
    expected_hostname: str = ""
    known_hosts_path: str = ""
    host_key_alias: str = ""
    proxy_jump_host_key_alias: str = ""

    def to_inventory_line(self) -> str:
        parts = [
            self.name,
            f"ansible_host={self.ansible_host}",
            f"ansible_user={self.ansible_user}",
        ]
        if self.ssh_private_key_file:
            parts.append(f"ansible_ssh_private_key_file={self.ssh_private_key_file}")
        if self.expected_hostname:
            parts.append(f"barragan_expected_hostname={self.expected_hostname}")
        ssh_args = _core_ssh_options(self.known_hosts_path, self.host_key_alias)
        if self.proxy_jump:
            proxy_command_parts = [
                "ssh",
                "-i",
                self.ssh_private_key_file,
                *_core_ssh_options(self.known_hosts_path, self.proxy_jump_host_key_alias),
                "-W",
                "%h:%p",
                self.proxy_jump,
            ]
            ssh_args.append(f"-o ProxyCommand='{' '.join(proxy_command_parts)}'")
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
        if self.expected_hostname:
            body["expectedHostname"] = self.expected_hostname
        if self.host_key_alias:
            body["hostKeyAlias"] = self.host_key_alias
        return body


@dataclass(frozen=True)
class OutboundApplyWorkspace:
    inventory: RenderedArtifact
    playbook: RenderedArtifact
    manifest: RenderedArtifact

    def to_dict(self) -> dict[str, object]:
        return {
            "status": APPLY_PREVIEW_STATUS,
            "mutation": False,
            "inventory": self.inventory.to_dict(),
            "playbook": self.playbook.to_dict(),
            "manifest": self.manifest.to_dict(),
        }


@dataclass(frozen=True)
class OutboundApplyTarget:
    name: str
    role: str
    host: str

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "role": self.role,
            "host": self.host,
        }


@dataclass(frozen=True)
class OutboundApplyStep:
    order: int
    step_id: str
    label: str
    status: str
    targets: list[OutboundApplyTarget]
    artifact: dict[str, str] | None = None
    firewall: dict[str, object] | None = None
    systemd: dict[str, object] | None = None
    validation: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        body: dict[str, object] = {
            "order": self.order,
            "id": self.step_id,
            "label": self.label,
            "status": self.status,
            "targets": [target.to_dict() for target in self.targets],
        }
        if self.artifact is not None:
            body["artifact"] = self.artifact
        if self.firewall is not None:
            body["firewall"] = self.firewall
        if self.systemd is not None:
            body["systemd"] = self.systemd
        if self.validation is not None:
            body["validation"] = self.validation
        return body


@dataclass(frozen=True)
class OutboundApplyPlan:
    status: str
    mutation: bool
    steps: list[OutboundApplyStep]

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "mutation": self.mutation,
            "steps": [step.to_dict() for step in self.steps],
        }


def preview_outbound_channel_apply(
    engagement_id: str,
    chain_id: str,
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    chain_repository=None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    repo = repository or SqlAlchemyJobRepository()
    channel = _latest_outbound_channel_with_artifacts(repo, engagement_id, chain_id)
    if channel is None:
        raise OutboundChannelApplyValidationError([f"outbound channel {chain_id} with rendered artifacts was not found"])
    backing_chain_id = _backing_chain_id(channel, chain_id)
    _require_bootstrapped_chain(repo, engagement_id, backing_chain_id, chain_repository=chain_repository)
    artifacts = _artifacts_from_channel(channel)
    homebase, proxy = _core_apply_hosts(repo, engagement_id, str(channel.get("proxy") or ""))
    # A preview must not materialize credentials.  The source is only used by
    # the generated copy task during a real apply.
    sketch_private_key_src = "/run/barragan/secure-material/sketch-transport-key"
    workspace = render_outbound_apply_workspace(
        artifacts,
        homebase=homebase,
        proxy=proxy,
        sketch_private_key_src=sketch_private_key_src,
    )
    job = _save_preview_job(repo, engagement_id, chain_id, requested_by, channel, workspace)
    return {"job": job.to_detail().to_dict(), "workspace": workspace.to_dict()}


def apply_outbound_channel(
    engagement_id: str,
    chain_id: str,
    *,
    confirmation: str,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    runner: CommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
    chain_repository=None,
    provider_firewall_sync: ProviderFirewallSync | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    expected_confirmation = f"apply-outbound-{chain_id}"
    if confirmation != expected_confirmation:
        raise OutboundChannelApplyValidationError([f"confirmation must be {expected_confirmation}"])

    ansible_resolution = resolve_ansible_playbook(env=env)
    if not ansible_resolution.ok or not ansible_resolution.command:
        raise OutboundChannelApplyValidationError([ansible_resolution.error or "Could not resolve ansible-playbook executable"])

    repo = repository or SqlAlchemyJobRepository()
    channel = _latest_outbound_channel_with_artifacts(repo, engagement_id, chain_id)
    if channel is None:
        raise OutboundChannelApplyValidationError([f"outbound channel {chain_id} with rendered artifacts was not found"])
    selected_channel_id = _channel_id(channel, chain_id)
    backing_chain_id = _backing_chain_id(channel, chain_id)
    _require_bootstrapped_chain(repo, engagement_id, backing_chain_id, chain_repository=chain_repository)
    if isinstance(repo, SqlAlchemyJobRepository) or provider_firewall_sync is not None:
        _reconcile_provider_firewall_for_outbound_apply(
            engagement_id,
            engagement.name,
            backing_chain_id,
            repository=repo,
            chain_repository=chain_repository,
            provider_firewall_sync=provider_firewall_sync,
        )
    artifacts = _artifacts_from_channel(channel)
    homebase, proxy = _core_apply_hosts(repo, engagement_id, str(channel.get("proxy") or ""))
    workspace_dir = _apply_workspace_dir(chain_id, workspace_root)
    try:
        sketch_private_key_src, _ = write_existing_sketch_transport_ssh_key_files(
            engagement_id, workspace_dir / "keys"
        )
    except SketchSshKeyNotFoundError as exc:
        shutil.rmtree(workspace_dir, ignore_errors=True)
        raise OutboundChannelApplyValidationError([str(exc)]) from exc
    try:
        workspace = render_outbound_apply_workspace(
            artifacts,
            homebase=homebase,
            proxy=proxy,
            sketch_private_key_src=sketch_private_key_src,
        )
    except Exception:
        shutil.rmtree(workspace_dir / "keys", ignore_errors=True)
        raise
    command = [ansible_resolution.command, *ANSIBLE_APPLY_COMMAND[1:]]
    command_runner = runner or _run_command

    timestamp = _now()
    job = StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=OUTBOUND_APPLY_ACTION,
        status="running",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by=requested_by,
        input={
            "engagementId": engagement_id,
            "channelId": selected_channel_id,
            "chainId": backing_chain_id,
            "mutation": True,
            "confirmation": "redacted",
        },
        artifact_refs=[
            workspace.inventory.target,
            workspace.playbook.target,
            workspace.manifest.target,
        ],
        created_at=timestamp,
        started_at=timestamp,
        finished_at=None,
        events=[],
    )

    try:
        _write_workspace(workspace, workspace_dir)
        manifest = json.loads(workspace.manifest.content)
    except Exception:
        shutil.rmtree(workspace_dir / "keys", ignore_errors=True)
        raise
    events = [
        JobEvent(
            1,
            "info",
            "outbound channel apply workspace rendered",
            {
                "channelId": selected_channel_id,
                "chainId": backing_chain_id,
                "proxy": channel.get("proxy"),
                "workspaceDir": str(workspace_dir),
                "workspaceEvidence": _workspace_evidence(workspace),
                "artifactTargets": manifest["artifactTargets"],
                "validation": manifest["validation"],
                "mutation": True,
                "status": APPLY_PREVIEW_STATUS,
            },
        ),
        JobEvent(
            2,
            "info",
            "outbound channel Ansible apply started",
            {
                "channelId": selected_channel_id,
                "chainId": backing_chain_id,
                "command": _command_display(command),
                "cwd": str(workspace_dir),
                "inventoryTargets": ["homebase", str(channel.get("proxy") or "")],
            },
        ),
    ]
    try:
        _assert_no_forbidden_markers(json.dumps([event.data for event in events], sort_keys=True), "outbound apply job event")
        job = repo.save(replace(job, events=events))
    except Exception:
        shutil.rmtree(workspace_dir / "keys", ignore_errors=True)
        raise
    try:
        result = _run_guarded_command(command, workspace_dir, command_runner)
    finally:
        shutil.rmtree(workspace_dir / "keys", ignore_errors=True)

    command_result = _safe_command_result(result)
    finished_at = _now()
    if result.ok:
        updated_channel = _channel_with_apply_state(channel, manifest["validation"])
        events = job.events + [
            JobEvent(
                len(job.events) + 1,
                "info",
                "outbound channel Ansible apply succeeded",
                {
                    "channelId": selected_channel_id,
                    "chainId": backing_chain_id,
                    "commandResult": command_result,
                    "status": APPLY_SUCCESS_STATUS,
                },
            ),
            JobEvent(
                len(job.events) + 2,
                "info",
                "outbound channel validation pending",
                {
                    "channelId": selected_channel_id,
                    "chainId": backing_chain_id,
                    "status": APPLY_SUCCESS_STATUS,
                    "validation": manifest["validation"],
                    "validationRan": False,
                    "outboundChannels": _merged_outbound_channels(repo, engagement_id, chain_id, updated_channel),
                },
            ),
        ]
        final_job = _replace_job(job, status="succeeded", finished_at=finished_at, events=events)
    else:
        events = job.events + [
            JobEvent(
                len(job.events) + 1,
                "error",
                "outbound channel Ansible apply failed",
                {
                    "channelId": selected_channel_id,
                    "chainId": backing_chain_id,
                    "commandResult": command_result,
                    "status": "Apply Failed",
                },
            ),
            JobEvent(
                len(job.events) + 2,
                "warning",
                "outbound channel validation not run",
                {
                    "channelId": selected_channel_id,
                    "chainId": backing_chain_id,
                    "status": "Validation Not Run",
                    "validationRan": False,
                },
            ),
        ]
        final_job = _replace_job(job, status="failed", finished_at=finished_at, events=events)
    saved = repo.save(final_job)
    if saved.status == "succeeded":
        try_enqueue_infra_orientation_refresh(engagement_id, repository=repo)
    return {"job": saved.to_detail().to_dict(), "status": APPLY_SUCCESS_STATUS if result.ok else "Apply Failed"}


def validate_outbound_channel(
    engagement_id: str,
    chain_id: str,
    *,
    confirmation: str,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    runner: CommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
    chain_repository=None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    expected_confirmation = f"validate-outbound-{chain_id}"
    if confirmation != expected_confirmation:
        raise OutboundChannelApplyValidationError([f"confirmation must be {expected_confirmation}"])

    ansible_resolution = resolve_ansible(env=env)
    if not ansible_resolution.ok or not ansible_resolution.command:
        raise OutboundChannelApplyValidationError([ansible_resolution.error or "Could not resolve Ansible executable"])

    repo = repository or SqlAlchemyJobRepository()
    channel = _latest_outbound_channel_with_artifacts(repo, engagement_id, chain_id)
    if channel is None:
        raise OutboundChannelApplyValidationError([f"outbound channel {chain_id} with rendered artifacts was not found"])
    selected_channel_id = _channel_id(channel, chain_id)
    backing_chain_id = _backing_chain_id(channel, chain_id)
    _require_bootstrapped_chain(repo, engagement_id, backing_chain_id, chain_repository=chain_repository)
    artifacts = _artifacts_from_channel(channel)
    _validate_homebase_validation_metadata(artifacts.validation)
    homebase = _homebase_validation_host(repo, engagement_id)
    workspace = render_outbound_validation_workspace(artifacts, homebase=homebase)
    command = _homebase_ansible_command(ansible_resolution.command, workspace.inventory.target, artifacts.validation.shell_display())
    probes = _outbound_http_probes(artifacts.validation)
    probe_commands = [
        _homebase_ansible_command(ansible_resolution.command, workspace.inventory.target, probe.shell_display())
        for probe in probes
    ]
    command_runner = runner or _run_command

    timestamp = _now()
    workspace_dir = _apply_workspace_dir(f"{chain_id}-validation", workspace_root)
    _write_validation_workspace(workspace, workspace_dir)
    job = StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=OUTBOUND_VALIDATE_ACTION,
        status="running",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by=requested_by,
        input={
            "engagementId": engagement_id,
            "channelId": selected_channel_id,
            "chainId": backing_chain_id,
            "mutation": False,
            "confirmation": "redacted",
        },
        artifact_refs=[workspace.inventory.target],
        created_at=timestamp,
        started_at=timestamp,
        finished_at=None,
        events=[
            JobEvent(
                1,
                "info",
                "outbound channel validation workspace rendered",
                {
                    "channelId": selected_channel_id,
                    "chainId": backing_chain_id,
                    "workspaceDir": str(workspace_dir),
                    "workspaceEvidence": {"inventory": _artifact_evidence(workspace.inventory)},
                    "inventoryTargets": ["homebase"],
                    "origin": artifacts.validation.origin,
                    "validation": artifacts.validation.to_dict(),
                    "mutation": False,
                },
            ),
            JobEvent(
                2,
                "info",
                "outbound channel homebase validation started",
                {
                    "channelId": selected_channel_id,
                    "chainId": backing_chain_id,
                    "command": _command_display(command),
                    "probeCommands": [_command_display(probe_command) for probe_command in probe_commands],
                    "cwd": str(workspace_dir),
                    "inventoryTargets": ["homebase"],
                    "origin": artifacts.validation.origin,
                },
            ),
        ],
    )
    _assert_no_forbidden_markers(json.dumps([event.data for event in job.events], sort_keys=True), "outbound validation job event")
    job = repo.save(job)
    result = _run_guarded_command(command, workspace_dir, command_runner)
    probe_results: list[dict[str, object]] = []
    for probe, probe_command in zip(probes, probe_commands):
        probe_result = _run_guarded_command(probe_command, workspace_dir, command_runner)
        probe_results.append(_http_probe_evidence(probe, probe_result))

    finished_at = _now()
    observed_output = _sanitize_command_output(result.stdout.strip())
    expected_public_ip = artifacts.validation.expected_public_ip.strip()
    observed_public_ip = _observed_public_ip(observed_output, expected_public_ip)
    command_result = _safe_command_result(result)
    failed_probes = [probe for probe in probe_results if not probe.get("ok")]
    identity_matched = result.ok and observed_public_ip == expected_public_ip
    if identity_matched and failed_probes:
        validation_status = VALIDATION_WARNING_STATUS
    elif identity_matched:
        validation_status = VALIDATION_SUCCESS_STATUS
    else:
        validation_status = VALIDATION_FAILED_STATUS
    if validation_status == VALIDATION_SUCCESS_STATUS:
        detail = f"Observed expected edge public IP {expected_public_ip} from homebase and HTTP probes succeeded."
    elif validation_status == VALIDATION_WARNING_STATUS:
        failed_urls = ", ".join(str(probe.get("url") or "unknown") for probe in failed_probes)
        detail = f"Expected edge public IP {expected_public_ip} was observed; auxiliary HTTP probes failed for {failed_urls}."
    else:
        detail = f"Expected edge public IP {expected_public_ip}, observed {observed_public_ip or 'no output'}."
    validation_evidence = {
        "channelId": selected_channel_id,
        "chainId": backing_chain_id,
        "origin": artifacts.validation.origin,
        "inventoryTargets": ["homebase"],
        "command": artifacts.validation.command,
        "shellDisplay": artifacts.validation.shell_display(),
        "expectedPublicIp": expected_public_ip,
        "observedPublicIp": observed_public_ip,
        "observedOutput": observed_output,
        "httpProbes": probe_results,
        "checkedAt": finished_at,
        "status": validation_status,
        "detail": detail,
        "commandResult": command_result,
    }
    _assert_no_forbidden_markers(json.dumps(validation_evidence, sort_keys=True), "outbound validation evidence")
    updated_channel = _channel_with_validation_state(channel, validation_evidence)
    final_events = job.events + [
        JobEvent(
            len(job.events) + 1,
            "info" if identity_matched else "error",
            "outbound channel validation succeeded with warnings"
            if validation_status == VALIDATION_WARNING_STATUS
            else "outbound channel validation succeeded"
            if identity_matched
            else "outbound channel validation failed",
            {
                "channelId": selected_channel_id,
                "chainId": backing_chain_id,
                "status": validation_status,
                "validationEvidence": validation_evidence,
                "outboundChannels": _merged_outbound_channels(repo, engagement_id, chain_id, updated_channel),
            },
        )
    ]
    final_job = _replace_job(
        job,
        status="succeeded" if identity_matched else "failed",
        finished_at=finished_at,
        events=final_events,
    )
    saved = repo.save(final_job)
    if saved.status == "succeeded":
        try_enqueue_infra_orientation_refresh(engagement_id, repository=repo)
    return {"job": saved.to_detail().to_dict(), "status": validation_status}


def remove_outbound_channel(
    engagement_id: str,
    chain_id: str,
    *,
    confirmation: str = "",
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    runner: CommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
    require_confirmation: bool = True,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    expected_confirmation = f"remove-outbound-{chain_id}"
    if require_confirmation and confirmation != expected_confirmation:
        raise OutboundChannelApplyValidationError([f"confirmation must be {expected_confirmation}"])

    ansible_resolution = resolve_ansible_playbook(env=env)
    if not ansible_resolution.ok or not ansible_resolution.command:
        raise OutboundChannelApplyValidationError([ansible_resolution.error or "Could not resolve ansible-playbook executable"])

    repo = repository or SqlAlchemyJobRepository()
    channel = _latest_outbound_channel_with_artifacts(repo, engagement_id, chain_id)
    if channel is None:
        raise OutboundChannelApplyValidationError([f"outbound channel {chain_id} with rendered artifacts was not found"])
    selected_channel_id = _channel_id(channel, chain_id)
    backing_chain_id = _backing_chain_id(channel, chain_id)
    artifacts = _artifacts_from_channel(channel)
    homebase, proxy = _core_apply_hosts(repo, engagement_id, str(channel.get("proxy") or ""))
    workspace = render_outbound_remove_workspace(artifacts, homebase=homebase, proxy=proxy)
    command = [ansible_resolution.command, *ANSIBLE_REMOVE_COMMAND[1:]]
    command_runner = runner or _run_command

    timestamp = _now()
    job = StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=OUTBOUND_REMOVE_ACTION,
        status="running",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by=requested_by,
        input={
            "engagementId": engagement_id,
            "channelId": selected_channel_id,
            "chainId": backing_chain_id,
            "mutation": True,
            "confirmation": "redacted" if require_confirmation else "not-required-internal-lifecycle",
        },
        artifact_refs=[
            workspace.inventory.target,
            workspace.playbook.target,
            workspace.manifest.target,
        ],
        created_at=timestamp,
        started_at=timestamp,
        finished_at=None,
        events=[],
    )

    workspace_dir = _apply_workspace_dir(f"{chain_id}-remove", workspace_root)
    _write_workspace(workspace, workspace_dir)
    manifest = json.loads(workspace.manifest.content)
    events = [
        JobEvent(
            1,
            "info",
            "outbound channel remove workspace rendered",
            {
                "channelId": selected_channel_id,
                "chainId": backing_chain_id,
                "proxy": channel.get("proxy"),
                "workspaceDir": str(workspace_dir),
                "workspaceEvidence": _workspace_evidence(workspace),
                "artifactTargets": manifest["artifactTargets"],
                "mutation": True,
                "status": "Removing",
            },
        ),
        JobEvent(
            2,
            "info",
            "outbound channel Ansible remove started",
            {
                "channelId": selected_channel_id,
                "chainId": backing_chain_id,
                "command": _command_display(command),
                "cwd": str(workspace_dir),
                "inventoryTargets": ["homebase", str(channel.get("proxy") or "")],
            },
        ),
    ]
    _assert_no_forbidden_markers(json.dumps([event.data for event in events], sort_keys=True), "outbound remove job event")
    job = repo.save(replace(job, events=events))
    result = _run_guarded_command(command, workspace_dir, command_runner)

    command_result = _safe_command_result(result)
    finished_at = _now()
    if result.ok:
        updated_channel = _channel_with_remove_state(channel, manifest["artifactTargets"])
        events = job.events + [
            JobEvent(
                len(job.events) + 1,
                "info",
                "outbound channel Ansible remove succeeded",
                {
                    "channelId": selected_channel_id,
                    "chainId": backing_chain_id,
                    "commandResult": command_result,
                    "status": "Removed",
                    "outboundChannels": _merged_outbound_channels(repo, engagement_id, chain_id, updated_channel),
                },
            )
        ]
        final_job = _replace_job(job, status="succeeded", finished_at=finished_at, events=events)
    else:
        events = job.events + [
            JobEvent(
                len(job.events) + 1,
                "error",
                "outbound channel Ansible remove failed",
                {
                    "channelId": selected_channel_id,
                    "chainId": backing_chain_id,
                    "commandResult": command_result,
                    "status": "Remove Failed",
                },
            )
        ]
        final_job = _replace_job(job, status="failed", finished_at=finished_at, events=events)
    saved = repo.save(final_job)
    if saved.status == "succeeded":
        try_enqueue_infra_orientation_refresh(engagement_id, repository=repo)
    return {"job": saved.to_detail().to_dict(), "status": "Removed" if result.ok else "Remove Failed"}


def render_outbound_apply_plan(
    artifacts: OutboundChannelArtifacts,
    *,
    homebase: CoreApplyHost,
    proxy: CoreApplyHost,
) -> OutboundApplyPlan:
    _validate_core_hosts(homebase, proxy)
    _validate_artifact_boundary(artifacts)
    proxy_id = _proxy_id_from_artifacts(artifacts)
    if proxy.name != proxy_id:
        raise OutboundChannelApplyValidationError([f"proxy host must match outbound artifact target {proxy_id}"])

    homebase_target = OutboundApplyTarget(homebase.name, "homebase", homebase.ansible_host)
    proxy_target = OutboundApplyTarget(proxy.name, "proxy", proxy.ansible_host)
    service_name = _systemd_unit_name(artifacts.proxy_systemd_service.target)
    socks_port = _socks_port_from_validation(artifacts.validation)
    plan = OutboundApplyPlan(
        status=APPLY_PREVIEW_STATUS,
        mutation=False,
        steps=[
            OutboundApplyStep(
                1,
                "apply-core-hosts",
                "Apply managed core /etc/hosts entries",
                "pending",
                [homebase_target, proxy_target],
                artifact={"name": "coreHosts", "path": artifacts.core_hosts.target},
            ),
            OutboundApplyStep(
                2,
                "publish-homebase-proxychains",
                "Publish named outbound proxychains profile on homebase",
                "pending",
                [homebase_target],
                artifact={"name": "homebaseProxychains", "path": artifacts.homebase_proxychains.target},
            ),
            OutboundApplyStep(
                3,
                "write-proxy-ssh-config",
                "Write proxy-owned ssh-proxy config",
                "pending",
                [proxy_target],
                artifact={"name": "proxySshConfig", "path": artifacts.proxy_ssh_config.target},
            ),
            OutboundApplyStep(
                4,
                "write-proxy-systemd-unit",
                "Write proxy-owned ssh-proxy systemd unit",
                "pending",
                [proxy_target],
                artifact={"name": "proxySystemdService", "path": artifacts.proxy_systemd_service.target},
            ),
            OutboundApplyStep(
                5,
                "open-proxy-socks-port",
                "Open selected proxy SOCKS port from core VCN",
                "pending",
                [proxy_target],
                firewall={"source": "192.168.0.0/16", "protocol": "tcp", "port": socks_port, "state": "present"},
            ),
            OutboundApplyStep(
                6,
                "reload-proxy-systemd",
                "Reload systemd on selected proxy",
                "pending",
                [proxy_target],
                systemd={"daemonReload": True},
            ),
            OutboundApplyStep(
                7,
                "enable-restart-proxy-service",
                "Enable and restart proxy ssh-proxy service",
                "pending",
                [proxy_target],
                systemd={"unit": service_name, "enabled": True, "state": "restarted"},
            ),
            OutboundApplyStep(
                8,
                "wait-proxy-socks-listener",
                "Wait for selected proxy SOCKS listener",
                "pending",
                [proxy_target],
                validation={"host": "127.0.0.1", "port": socks_port, "timeoutSeconds": 90},
            ),
            OutboundApplyStep(
                9,
                "validate-from-homebase",
                "Validate outbound egress from homebase",
                "pending",
                [homebase_target],
                validation=artifacts.validation.to_dict(),
            ),
        ],
    )
    _assert_no_secret_material(plan)
    _assert_apply_plan_opsec(plan)
    return plan


def render_outbound_apply_workspace(
    artifacts: OutboundChannelArtifacts,
    *,
    homebase: CoreApplyHost,
    proxy: CoreApplyHost,
    sketch_private_key_src: str = "",
) -> OutboundApplyWorkspace:
    artifacts = replace(artifacts, proxy_ssh_config=_normalized_proxy_ssh_config(artifacts.proxy_ssh_config))
    _validate_core_hosts(homebase, proxy)
    _validate_artifact_boundary(artifacts)
    _assert_no_forbidden_markers(json.dumps(artifacts.to_dict(), sort_keys=True), "outbound apply artifacts")
    proxy_id = _proxy_id_from_artifacts(artifacts)
    if proxy.name != proxy_id:
        raise OutboundChannelApplyValidationError([f"proxy host must match outbound artifact target {proxy_id}"])

    inventory = RenderedArtifact(
        "ansible/inventory.ini",
        _render_inventory(homebase, proxy),
    )
    playbook = RenderedArtifact(
        "ansible/apply_outbound_channel.yml",
        _render_playbook(
            artifacts,
            homebase=homebase,
            proxy=proxy,
            sketch_private_key_src=sketch_private_key_src,
        ),
    )
    manifest = RenderedArtifact(
        "MANIFEST.json",
        _render_manifest(artifacts, homebase, proxy),
    )
    workspace = OutboundApplyWorkspace(inventory=inventory, playbook=playbook, manifest=manifest)
    _assert_no_secret_material(workspace)
    return workspace


def render_outbound_remove_workspace(
    artifacts: OutboundChannelArtifacts,
    *,
    homebase: CoreApplyHost,
    proxy: CoreApplyHost,
) -> OutboundApplyWorkspace:
    artifacts = replace(artifacts, proxy_ssh_config=_normalized_proxy_ssh_config(artifacts.proxy_ssh_config))
    _validate_core_hosts(homebase, proxy)
    _validate_artifact_boundary(artifacts)
    _assert_no_forbidden_markers(json.dumps(artifacts.to_dict(), sort_keys=True), "outbound remove artifacts")
    proxy_id = _proxy_id_from_artifacts(artifacts)
    if proxy.name != proxy_id:
        raise OutboundChannelApplyValidationError([f"proxy host must match outbound artifact target {proxy_id}"])

    inventory = RenderedArtifact(
        "ansible/inventory.ini",
        _render_inventory(homebase, proxy),
    )
    playbook = RenderedArtifact(
        "ansible/remove_outbound_channel.yml",
        _render_remove_playbook(artifacts),
    )
    manifest = RenderedArtifact(
        "MANIFEST.json",
        _render_remove_manifest(artifacts, homebase, proxy),
    )
    workspace = OutboundApplyWorkspace(inventory=inventory, playbook=playbook, manifest=manifest)
    _assert_no_secret_material(workspace)
    return workspace


def render_outbound_validation_workspace(
    artifacts: OutboundChannelArtifacts,
    *,
    homebase: CoreApplyHost,
) -> OutboundApplyWorkspace:
    if homebase.name != "homebase":
        raise OutboundChannelApplyValidationError(["validation host name must be homebase"])
    _validate_artifact_boundary(artifacts)
    _validate_homebase_validation_metadata(artifacts.validation)
    inventory = RenderedArtifact(
        "ansible/inventory.ini",
        "\n".join(
            [
                "# Managed by Barragan outbound channel validation.",
                "# Validation target is homebase only. Do not add proxy, middle, or edge hosts here.",
                "[homebase]",
                homebase.to_inventory_line(),
                "",
            ]
        ),
    )
    manifest = RenderedArtifact(
        "MANIFEST.json",
        json.dumps(
            {
                "mode": "outbound_channel_validation",
                "status": "Pending Validation",
                "mutation": False,
                "targets": {"homebase": homebase.to_dict()},
                "validation": artifacts.validation.to_dict(),
                "opsecBoundary": artifacts.sketch_node_boundary.to_dict(),
                "notes": [
                    "Validation runs from homebase through the selected proxy SOCKS listener.",
                    "Middle and edge sketch nodes are not inventory targets.",
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )
    workspace = OutboundApplyWorkspace(
        inventory=inventory,
        playbook=RenderedArtifact("ansible/validation-not-playbook.yml", "# Validation uses Ansible ad hoc command.\n"),
        manifest=manifest,
    )
    _assert_no_secret_material(workspace)
    return workspace


def _latest_outbound_channel_with_artifacts(
    repository: JobRepository,
    engagement_id: str,
    chain_id: str,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    keyed = getattr(engagement, "sketch_state_schema", None) == "provider-keyed-v2"
    for job in repository.list():
        if keyed:
            break  # Re-render authenticated durable topology after append.
        if _job_engagement_id(job) != engagement_id:
            continue
        for event in reversed(job.events):
            channels = event.data.get("outboundChannels")
            if not isinstance(channels, list):
                continue
            for channel in channels:
                if not isinstance(channel, dict):
                    continue
                if _channel_matches(channel, chain_id) and isinstance(channel.get("artifacts"), dict):
                    return channel
    if keyed:
        from app.services.sketch_provider_firewall import _keyed_transport_publication
        from app.services.outbound_channel_artifacts import derive_pending_outbound_channels_from_sketch_rows
        sketches = SqlAlchemySketchChainRepository()
        _keyed_transport_publication(engagement_id, repository, sketches)
        existing = _latest_outbound_rows(repository, engagement_id)
        rows = []
        for chain in sketches.list_for_engagement(engagement_id):
            generated = derive_pending_outbound_channels_from_sketch_rows(
                engagement.name, chain.chain_id,
                [{**node, "chainId": chain.chain_id, "proxy": chain.assigned_proxy,
                  "assignedProxy": chain.assigned_proxy, "status": chain.status}
                 for node in chain.nodes], existing_outbound_channels=[*existing, *rows])
            rows.extend(generated)
        return next((row for row in rows if _channel_matches(row, chain_id)), None)
    return None


def _merged_outbound_channels(
    repository: JobRepository,
    engagement_id: str,
    chain_id: str,
    updated_channel: dict[str, Any] | dict[str, object],
) -> list[dict[str, Any]]:
    current_channels = _latest_outbound_rows(repository, engagement_id)
    merged: list[dict[str, Any]] = []
    found = False
    for channel in current_channels:
        if not isinstance(channel, dict):
            continue
        if _channel_matches(channel, chain_id):
            found = True
            merged.append(dict(updated_channel))
            continue
        merged.append(dict(channel))
    if not found:
        merged.append(dict(updated_channel))
    return merged


def _latest_outbound_rows(repository: JobRepository, engagement_id: str) -> list[dict[str, Any]]:
    for job in repository.list():
        if _job_engagement_id(job) != engagement_id:
            continue
        for event in reversed(job.events):
            channels = event.data.get("outboundChannels")
            if isinstance(channels, list):
                return [dict(channel) for channel in channels if isinstance(channel, dict)]
    return []


def _channel_matches(channel: dict[str, Any], requested_id: str) -> bool:
    requested = str(requested_id or "").strip()
    return requested in {
        str(channel.get("channelId") or "").strip(),
        str(channel.get("chainId") or "").strip(),
    }


def _channel_id(channel: dict[str, Any], fallback: str) -> str:
    return str(channel.get("channelId") or fallback).strip()


def _backing_chain_id(channel: dict[str, Any], fallback: str) -> str:
    return str(channel.get("chainId") or fallback).strip()


def _require_bootstrapped_chain(
    repository: JobRepository,
    engagement_id: str,
    chain_id: str,
    *,
    chain_repository=None,
) -> None:
    """Reject channel work until both sketch bootstrap phases are durable."""

    if chain_repository is None and not isinstance(repository, SqlAlchemyJobRepository):
        # Non-production injected job repositories are used by unit tests and
        # render-only callers. API calls use the durable SQL repository below.
        return
    chain = (chain_repository or SqlAlchemySketchChainRepository()).get(engagement_id, chain_id)
    if chain is None:
        raise OutboundChannelApplyValidationError([f"sketch chain {chain_id} was not found"])
    if chain.status != "deployed":
        raise OutboundChannelApplyValidationError([f"sketch chain {chain_id} is {chain.status}; bootstrap must complete before outbound work"])
    job = repository.get(chain.deploy_job_id) if chain.deploy_job_id else None
    engagement = get_engagement(engagement_id)
    if getattr(engagement, "sketch_state_schema", None) == "provider-keyed-v2":
        from app.services.sketch_provider_firewall import _keyed_transport_publication
        reviewed = _keyed_transport_publication(engagement_id, repository,
            chain_repository or SqlAlchemySketchChainRepository())
        if chain_id in reviewed.review.source.chain_ids:
            return
        raise OutboundChannelApplyValidationError(["keyed outbound chain differs from publication"])
    if job is not None and any(event.data.get("bootstrap") == "succeeded" for event in job.events):
        return
    raise OutboundChannelApplyValidationError([f"sketch chain {chain_id} has no successful bootstrap record"])


def _reconcile_provider_firewall_for_outbound_apply(
    engagement_id: str,
    engagement_name: str,
    chain_id: str,
    *,
    repository: JobRepository,
    chain_repository=None,
    provider_firewall_sync: ProviderFirewallSync | None = None,
) -> None:
    """Restore the upstream firewall contract before opening proxy transport.

    Unit-test repositories are render fixtures rather than provider-capable
    controller runtimes, so they intentionally do not invoke Terraform. Live
    API calls always use the durable SQL repository and do reconcile before
    Ansible can start an autossh service against stale firewall state.
    """

    overview = get_operations_overview(
        engagement_id,
        job_repository=repository,
        include_provider_findings=False,
    )
    sync = provider_firewall_sync or sync_provider_ingress_for_transport
    result = sync(
        engagement_id,
        engagement_name,
        chain_id,
        overview=overview or {},
        job_repository=repository,
        chain_repository=chain_repository,
    )
    if result.ok:
        return
    detail = next(
        (
            str(event.data.get("detail") or event.data.get("reason") or "")
            for event in reversed(result.events)
            if event.level == "error"
        ),
        "",
    )
    raise OutboundChannelApplyValidationError(
        [detail or f"sketch provider firewall reconciliation failed for chain {chain_id}"]
    )


def _core_apply_hosts(
    repository: JobRepository,
    engagement_id: str,
    proxy_id: str,
) -> tuple[CoreApplyHost, CoreApplyHost]:
    deployment_id, details = active_core_connection_details(repository, engagement_id)
    homebase = next((entry for entry in details if _entry_role(entry) == "homebase"), None)
    proxy = next((entry for entry in details if _matches_proxy(entry, proxy_id)), None)
    errors: list[str] = []
    if homebase is None:
        errors.append("homebase connection details are required before outbound apply preview")
    if proxy is None:
        errors.append(f"{proxy_id} connection details are required before outbound apply preview")
    if errors:
        raise OutboundChannelApplyValidationError(errors)
    assert homebase is not None
    assert proxy is not None
    known_hosts_path = _active_core_known_hosts_path(repository, deployment_id)
    ssh_key = _core_ssh_private_key_path()
    homebase_public_ip = _first_detail_value(homebase, "publicIp", "privateIp")
    homebase_user = _first_detail_value(homebase, "sshUser") or "user"
    proxy_public_ip = _first_detail_value(proxy, "publicIp")
    if not homebase_public_ip:
        errors.append("homebase public connection identity is required before outbound apply preview")
    if not proxy_public_ip:
        errors.append(f"{proxy_id} public host-key identity is required before outbound apply preview")
    if errors:
        raise OutboundChannelApplyValidationError(errors)
    homebase_hostname = _first_detail_value(homebase, "hostname") or "homebase"
    proxy_hostname = _first_detail_value(proxy, "hostname") or proxy_id
    return (
        CoreApplyHost(
            "homebase",
            homebase_public_ip,
            homebase_user,
            ssh_key,
            expected_hostname=homebase_hostname,
            known_hosts_path=known_hosts_path,
            host_key_alias=homebase_public_ip,
        ),
        CoreApplyHost(
            proxy_id,
            _first_detail_value(proxy, "privateIp", "publicIp"),
            _first_detail_value(proxy, "sshUser") or "user",
            ssh_key,
            f"{homebase_user}@{homebase_public_ip}",
            proxy_hostname,
            known_hosts_path,
            proxy_public_ip,
            homebase_public_ip,
        ),
    )


def _homebase_validation_host(repository: JobRepository, engagement_id: str) -> CoreApplyHost:
    deployment_id, details = active_core_connection_details(repository, engagement_id)
    homebase = next((entry for entry in details if _entry_role(entry) == "homebase"), None)
    if homebase is None:
        raise OutboundChannelApplyValidationError(["homebase connection details are required before outbound validation"])
    public_ip = _first_detail_value(homebase, "publicIp", "privateIp")
    if not public_ip:
        raise OutboundChannelApplyValidationError(["homebase public connection identity is required before outbound validation"])
    return CoreApplyHost(
        "homebase",
        public_ip,
        _first_detail_value(homebase, "sshUser") or "user",
        _core_ssh_private_key_path(),
        expected_hostname=_first_detail_value(homebase, "hostname") or "homebase",
        known_hosts_path=_active_core_known_hosts_path(repository, deployment_id),
        host_key_alias=public_ip,
    )


def _active_core_known_hosts_path(repository: JobRepository, deployment_id: str) -> str:
    job = repository.get(deployment_id) if deployment_id else None
    if job is not None:
        for event in job.events:
            workspace_dir = str(event.data.get("workspaceDir") or "").strip()
            if workspace_dir:
                return str(Path(workspace_dir) / "ssh" / "known_hosts")
    raise OutboundChannelApplyValidationError(
        ["active core deployment known-hosts evidence is required before outbound configuration"]
    )


def _core_ssh_private_key_path() -> str:
    return os.environ.get(CORE_SSH_KEY_ENV, "").strip() or DEFAULT_CORE_SSH_PRIVATE_KEY


def _core_ssh_options(known_hosts_path: str, host_key_alias: str = "") -> list[str]:
    options = [
        f"-o UserKnownHostsFile={known_hosts_path or '/dev/null'}",
        f"-o StrictHostKeyChecking={'yes' if known_hosts_path else 'no'}",
        "-o IdentitiesOnly=yes",
        "-o BatchMode=yes",
        "-o ConnectTimeout=10",
    ]
    if host_key_alias:
        options.append(f"-o HostKeyAlias={host_key_alias}")
    return options


def _artifacts_from_channel(channel: dict[str, Any]) -> OutboundChannelArtifacts:
    raw = channel.get("artifacts")
    if not isinstance(raw, dict):
        raise OutboundChannelApplyValidationError(["outbound channel artifacts are required"])
    return OutboundChannelArtifacts(
        core_hosts=_rendered_artifact(raw, "coreHosts"),
        homebase_proxychains=_rendered_artifact(raw, "homebaseProxychains"),
        proxy_ssh_config=_normalized_proxy_ssh_config(_rendered_artifact(raw, "proxySshConfig")),
        proxy_systemd_service=_rendered_artifact(raw, "proxySystemdService"),
        validation=_validation(raw.get("validation")),
        sketch_node_boundary=_sketch_boundary(raw.get("sketchNodeBoundary")),
    )


def _rendered_artifact(raw: dict[str, Any], key: str) -> RenderedArtifact:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise OutboundChannelApplyValidationError([f"outbound artifact {key} is required"])
    target = str(value.get("target") or "").strip()
    content = str(value.get("content") or "")
    if not target:
        raise OutboundChannelApplyValidationError([f"outbound artifact {key}.target is required"])
    return RenderedArtifact(target, content)


def _normalized_proxy_ssh_config(artifact: RenderedArtifact) -> RenderedArtifact:
    if "StrictHostKeyChecking" in artifact.content and "UserKnownHostsFile" in artifact.content:
        return artifact
    lines: list[str] = []
    for line in artifact.content.splitlines():
        lines.append(line)
        if line.strip() == "User sketchssh":
            lines.extend(
                [
                    "    UserKnownHostsFile /dev/null",
                    "    StrictHostKeyChecking no",
                    "    BatchMode yes",
                ]
            )
    return RenderedArtifact(artifact.target, "\n".join(lines) + "\n")


def _validation(value: Any) -> ValidationCommand:
    if not isinstance(value, dict):
        raise OutboundChannelApplyValidationError(["outbound artifact validation metadata is required"])
    command = value.get("command")
    if not isinstance(command, list) or not all(isinstance(item, str) and item for item in command):
        raise OutboundChannelApplyValidationError(["outbound artifact validation.command is required"])
    return ValidationCommand(
        origin=str(value.get("origin") or "").strip() or "homebase",
        command=_normalized_validation_command(command),
        expected_public_ip=str(value.get("expectedPublicIp") or "").strip(),
    )


def _normalized_validation_command(command: list[str]) -> list[str]:
    normalized = [
        "https://ipv4.icanhazip.com" if part in {"ifconfig.me", "http://ifconfig.me", "https://ifconfig.me"} else part
        for part in command
    ]
    if normalized[:2] == ["curl", "-sS"] and "--connect-timeout" not in normalized:
        normalized = [*normalized[:2], "--connect-timeout", "10", *normalized[2:]]
    return normalized


def _validate_homebase_validation_metadata(validation: ValidationCommand) -> None:
    errors: list[str] = []
    if validation.origin != "homebase":
        errors.append("outbound validation origin must be homebase")
    if not validation.command:
        errors.append("outbound validation command is required")
    if not validation.expected_public_ip:
        errors.append("outbound validation expectedPublicIp is required")
    if errors:
        raise OutboundChannelApplyValidationError(errors)


def _sketch_boundary(value: Any) -> SketchNodeOpsecBoundary:
    if not isinstance(value, dict):
        raise OutboundChannelApplyValidationError(["outbound artifact sketchNodeBoundary is required"])
    middle_artifacts = value.get("middleNodeArtifacts") or []
    edge_artifacts = value.get("edgeNodeArtifacts") or []
    return SketchNodeOpsecBoundary(
        sketch_hosts_content=value.get("sketchHostsContent"),
        middle_node_artifacts=[_rendered_artifact({"artifact": item}, "artifact") for item in middle_artifacts if isinstance(item, dict)],
        edge_node_artifacts=[_rendered_artifact({"artifact": item}, "artifact") for item in edge_artifacts if isinstance(item, dict)],
        reason=str(value.get("reason") or ""),
    )


def _save_preview_job(
    repository: JobRepository,
    engagement_id: str,
    chain_id: str,
    requested_by: str,
    channel: dict[str, Any],
    workspace: OutboundApplyWorkspace,
) -> StoredJobRun:
    timestamp = _now()
    workspace_dict = workspace.to_dict()
    artifact_targets = json.loads(workspace.manifest.content)["artifactTargets"]
    job = StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=OUTBOUND_APPLY_PREVIEW_ACTION,
        status="succeeded",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by=requested_by,
        input={
            "engagementId": engagement_id,
            "channelId": _channel_id(channel, chain_id),
            "chainId": _backing_chain_id(channel, chain_id),
            "mutation": False,
        },
        artifact_refs=[
            workspace.inventory.target,
            workspace.playbook.target,
            workspace.manifest.target,
        ],
        created_at=timestamp,
        started_at=timestamp,
        finished_at=timestamp,
        events=[
            JobEvent(
                1,
                "info",
                "outbound channel apply preview rendered",
                {
                    "channelId": _channel_id(channel, chain_id),
                    "chainId": _backing_chain_id(channel, chain_id),
                    "proxy": channel.get("proxy"),
                    "status": APPLY_PREVIEW_STATUS,
                    "mutation": False,
                    "workspace": workspace_dict,
                    "artifactTargets": artifact_targets,
                    "validation": json.loads(workspace.manifest.content)["validation"],
                },
            )
        ],
    )
    return repository.save(job)


def _write_workspace(workspace: OutboundApplyWorkspace, workspace_dir: Path) -> None:
    for artifact in (workspace.inventory, workspace.playbook, workspace.manifest):
        path = workspace_dir / artifact.target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(artifact.content, encoding="utf-8")


def _write_validation_workspace(workspace: OutboundApplyWorkspace, workspace_dir: Path) -> None:
    for artifact in (workspace.inventory, workspace.manifest):
        path = workspace_dir / artifact.target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(artifact.content, encoding="utf-8")


def _apply_workspace_dir(chain_id: str, workspace_root: Path | None) -> Path:
    root = workspace_root or DEFAULT_WORKSPACE_ROOT
    safe_chain = re.sub(r"[^a-zA-Z0-9._-]+", "-", chain_id).strip("-") or "channel"
    return root / f"{safe_chain}-{uuid4().hex[:12]}"


def _run_command(command: list[str], cwd: Path | None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=barragan_subprocess_env(),
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def _run_guarded_command(
    command: list[str],
    cwd: Path | None,
    runner: CommandRunner,
) -> DisposableCommandResult:
    try:
        completed = runner(command, cwd)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return DisposableCommandResult.from_error(command, cwd, exc)
    return DisposableCommandResult.from_completed(command, cwd, completed)


def _replace_job(
    job: StoredJobRun,
    *,
    status: str,
    finished_at: str,
    events: list[JobEvent],
) -> StoredJobRun:
    return replace(job, status=status, finished_at=finished_at, events=events)


def _safe_command_result(result: DisposableCommandResult) -> dict[str, Any]:
    body = result.to_dict()
    body["command"] = _command_display([str(part) for part in body.get("command", [])])
    body["stdout"] = _sanitize_command_output(str(body.get("stdout") or ""))
    body["stderr"] = _sanitize_command_output(str(body.get("stderr") or ""))
    _assert_no_forbidden_markers(json.dumps(body, sort_keys=True), "outbound apply command result")
    return body


def _observed_public_ip(output: str, expected_public_ip: str) -> str:
    trimmed = output.strip()
    if trimmed == expected_public_ip:
        return trimmed

    json_stdout = _json_stdout_value(trimmed)
    if json_stdout:
        return _observed_public_ip(json_stdout, expected_public_ip)

    for line in reversed([line.strip() for line in trimmed.splitlines() if line.strip()]):
        if line.startswith("homebase | ") or line.startswith("homebase "):
            continue
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", line):
            return line
    return trimmed


def _json_stdout_value(output: str) -> str:
    try:
        decoded = json.loads(output)
    except json.JSONDecodeError:
        return ""
    if isinstance(decoded, dict):
        value = decoded.get("stdout")
        if isinstance(value, str):
            return value
    return ""


def _workspace_evidence(workspace: OutboundApplyWorkspace) -> dict[str, Any]:
    evidence = {
        "inventory": _artifact_evidence(workspace.inventory),
        "playbook": _artifact_evidence(workspace.playbook),
        "manifest": _artifact_evidence(workspace.manifest),
    }
    _assert_no_forbidden_markers(json.dumps(evidence, sort_keys=True), "outbound apply workspace evidence")
    return evidence


def _artifact_evidence(artifact: RenderedArtifact) -> dict[str, str | int]:
    content = _sanitize_command_output(artifact.content)
    return {
        "path": artifact.target,
        "sha256": hashlib.sha256(artifact.content.encode("utf-8")).hexdigest(),
        "bytes": len(artifact.content.encode("utf-8")),
        "content": content,
    }


def _channel_with_apply_state(channel: dict[str, Any], validation: dict[str, Any]) -> dict[str, Any]:
    safe_channel = {
        key: value
        for key, value in channel.items()
        if key != "artifacts" and key != "sketchNodeBoundary"
    }
    prior_validation = safe_channel.get("validation")
    validation_state = dict(prior_validation) if isinstance(prior_validation, dict) else {}
    validation_state.update(
        {
            "origin": validation.get("origin"),
            "command": validation.get("command"),
            "shellDisplay": validation.get("shellDisplay"),
            "expectedPublicIp": validation.get("expectedPublicIp"),
            "status": APPLY_SUCCESS_STATUS,
            "detail": "Core channel config applied; homebase validation has not run yet.",
        }
    )
    safe_channel["validation"] = {key: value for key, value in validation_state.items() if value not in (None, "")}
    safe_channel["status"] = APPLY_SUCCESS_STATUS
    _assert_no_forbidden_markers(json.dumps(safe_channel, sort_keys=True), "outbound apply channel state")
    return safe_channel


def _channel_with_validation_state(channel: dict[str, Any], validation_evidence: dict[str, Any]) -> dict[str, Any]:
    safe_channel = {
        key: value
        for key, value in channel.items()
        if key != "artifacts" and key != "sketchNodeBoundary"
    }
    prior_validation = safe_channel.get("validation")
    validation = dict(prior_validation) if isinstance(prior_validation, dict) else {}
    validation.update(
        {
            "origin": validation_evidence["origin"],
            "command": validation_evidence["command"],
            "shellDisplay": validation_evidence["shellDisplay"],
            "expectedPublicIp": validation_evidence["expectedPublicIp"],
            "status": validation_evidence["status"],
            "checkedAt": validation_evidence["checkedAt"],
            "lastCheckedAt": validation_evidence["checkedAt"],
            "detail": validation_evidence["detail"],
        }
    )
    safe_channel["validation"] = validation
    safe_channel["status"] = validation_evidence["status"]
    _assert_no_forbidden_markers(json.dumps(safe_channel, sort_keys=True), "outbound validation channel state")
    return safe_channel


def _channel_with_remove_state(channel: dict[str, Any], artifact_targets: dict[str, Any]) -> dict[str, Any]:
    safe_channel = {
        key: value
        for key, value in channel.items()
        if key != "artifacts" and key != "sketchNodeBoundary"
    }
    safe_channel["status"] = "Removed"
    safe_channel["removedAt"] = _now()
    safe_channel["artifactTargets"] = artifact_targets
    prior_validation = safe_channel.get("validation")
    validation = dict(prior_validation) if isinstance(prior_validation, dict) else {}
    validation.update(
        {
            "status": "Removed",
            "detail": (
                "Outbound proxychains profile, ssh-proxy service, and listener firewall rule were removed. "
                "Shared sketch key material was left in place for sibling channels."
            ),
        }
    )
    safe_channel["validation"] = validation
    _assert_no_forbidden_markers(json.dumps(safe_channel, sort_keys=True), "outbound remove channel state")
    return safe_channel


def _command_display(command: list[str]) -> list[str]:
    return [_sanitize_command_output(str(part)) for part in command]


def _sanitize_command_output(value: str) -> str:
    redacted = value
    for marker in SECRET_MARKERS:
        redacted = redacted.replace(marker, "[REDACTED]")
    if len(redacted) <= MAX_COMMAND_OUTPUT_CHARS:
        return redacted
    return redacted[:MAX_COMMAND_OUTPUT_CHARS] + "\n[truncated]"


def _render_inventory(homebase: CoreApplyHost, proxy: CoreApplyHost) -> str:
    return "\n".join(
        [
            "# Managed by Barragan outbound channel apply preview.",
            "# Core hosts only. Do not add middle or edge sketch nodes here.",
            "[homebase]",
            homebase.to_inventory_line(),
            "",
            "[selected_proxy]",
            proxy.to_inventory_line(),
            "",
            "[barragan_core:children]",
            "homebase",
            "selected_proxy",
            "",
        ]
    )


def _render_playbook(
    artifacts: OutboundChannelArtifacts,
    *,
    homebase: CoreApplyHost,
    proxy: CoreApplyHost,
    sketch_private_key_src: str = "",
) -> str:
    socks_port = _socks_port_from_validation(artifacts.validation)
    sketch_private_key_dest = _sketch_private_key_dest(artifacts)
    proxy_tasks = [
        "    - name: Install autossh for outbound channel service",
        "      ansible.builtin.apt:",
        "        name: autossh",
        "        state: present",
        "        update_cache: true",
        "    - name: Create ssh-proxy directory",
        "      ansible.builtin.file:",
        "        path: /opt/ssh-proxy",
        "        state: directory",
        "        mode: '0750'",
        "    - name: Create ssh-proxy key directory",
        "      ansible.builtin.file:",
        "        path: /opt/ssh-proxy/keys",
        "        state: directory",
        "        mode: '0700'",
    ]
    if sketch_private_key_src:
        proxy_tasks.extend(
            [
                "    - name: Install engagement sketch SSH key on selected proxy",
                "      ansible.builtin.copy:",
                f"        src: {sketch_private_key_src}",
                f"        dest: {sketch_private_key_dest}",
                "        owner: root",
                "        group: root",
                "        mode: '0600'",
            ]
        )
    proxy_tasks.extend(
        [
            "    - name: Write ssh-proxy config",
            "      ansible.builtin.copy:",
            f"        dest: {artifacts.proxy_ssh_config.target}",
            "        mode: '0640'",
            "        content: |",
            _indent_block(artifacts.proxy_ssh_config.content, 10),
            "    - name: Write ssh-proxy systemd unit",
            "      ansible.builtin.copy:",
            f"        dest: {artifacts.proxy_systemd_service.target}",
            "        mode: '0644'",
            "        content: |",
            _indent_block(artifacts.proxy_systemd_service.content, 10),
            "    - name: Open selected proxy SOCKS port from core VCN",
            "      ansible.builtin.iptables:",
            "        action: insert",
            "        chain: INPUT",
            "        rule_num: '1'",
            "        protocol: tcp",
            f"        destination_port: '{socks_port}'",
            "        source: 192.168.0.0/16",
            "        jump: ACCEPT",
            "        comment: Barragan outbound channel SOCKS listener",
            "    - name: Save proxy iptables rules",
            "      ansible.builtin.command: iptables-save -f /etc/iptables/rules.v4",
            "    - name: Reload systemd for ssh-proxy",
            "      ansible.builtin.systemd:",
            "        daemon_reload: true",
            "    - name: Enable and restart ssh-proxy service",
            "      ansible.builtin.systemd:",
            f"        name: {_systemd_unit_name(artifacts.proxy_systemd_service.target)}",
            "        enabled: true",
            "        state: restarted",
            "    - name: Confirm ssh-proxy service is active",
            f"      ansible.builtin.command: systemctl is-active {_systemd_unit_name(artifacts.proxy_systemd_service.target)}",
            "      changed_when: false",
            "    - name: Wait for selected proxy SOCKS listener",
            "      ansible.builtin.wait_for:",
            "        host: 127.0.0.1",
            f"        port: '{socks_port}'",
            "        state: started",
            "        timeout: 90",
        ]
    )
    return "\n".join(
        [
            "---",
            "- name: Apply Barragan outbound channel core host aliases",
            "  hosts: barragan_core",
            "  become: true",
            "  pre_tasks:",
            "    - name: Read core hostname before outbound configuration",
            "      ansible.builtin.command: hostname --short",
            "      register: barragan_core_hostname",
            "      changed_when: false",
            "    - name: Assert selected core host identity",
            "      ansible.builtin.assert:",
            "        that:",
            "          - (barragan_core_hostname.stdout | trim) == barragan_expected_hostname",
            "        fail_msg: >-",
            "          Core connection identity mismatch. No outbound configuration was applied.",
            "  tasks:",
            "    - name: Install managed core host aliases",
            "      ansible.builtin.blockinfile:",
            "        path: /etc/hosts",
            "        marker: '# {mark} BARRAGAN MANAGED CORE HOSTS'",
            "        block: |",
            _indent_block(_strip_managed_comments(artifacts.core_hosts.content), 10),
            "",
            "- name: Publish Barragan outbound profile on homebase",
            "  hosts: homebase",
            "  become: true",
            "  tasks:",
            "    - name: Create outbound profile directory",
            "      ansible.builtin.file:",
            f"        path: {_parent_path(artifacts.homebase_proxychains.target)}",
            "        state: directory",
            "        mode: '0755'",
            "    - name: Write outbound proxychains profile",
            "      ansible.builtin.copy:",
            f"        dest: {artifacts.homebase_proxychains.target}",
            "        mode: '0644'",
            "        content: |",
            _indent_block(artifacts.homebase_proxychains.content, 10),
            "    - name: Record outbound validation command",
            "      ansible.builtin.debug:",
            f"        msg: {json.dumps(artifacts.validation.shell_display())}",
            "",
            "- name: Configure Barragan outbound ssh-proxy on selected proxy",
            "  hosts: selected_proxy",
            "  become: true",
            "  tasks:",
            *proxy_tasks,
            "",
        ]
    )


def _sketch_private_key_dest(artifacts: OutboundChannelArtifacts) -> str:
    matches = re.findall(r"^\s*IdentityFile\s+(\S+)\s*$", artifacts.proxy_ssh_config.content, flags=re.MULTILINE)
    if not matches:
        raise OutboundChannelApplyValidationError(["proxy ssh config must declare an IdentityFile"])
    unique_matches = sorted(set(matches))
    if len(unique_matches) != 1:
        raise OutboundChannelApplyValidationError(["proxy ssh config must use one shared engagement sketch IdentityFile"])
    path = unique_matches[0]
    if not path.startswith("/opt/ssh-proxy/keys/"):
        raise OutboundChannelApplyValidationError(["proxy ssh config IdentityFile must live under /opt/ssh-proxy/keys"])
    return path


def _render_remove_playbook(artifacts: OutboundChannelArtifacts) -> str:
    socks_port = _socks_port_from_validation(artifacts.validation)
    service_name = _systemd_unit_name(artifacts.proxy_systemd_service.target)
    return "\n".join(
        [
            "---",
            "- name: Remove Barragan outbound profile from homebase",
            "  hosts: homebase",
            "  become: true",
            "  tasks:",
            "    - name: Remove outbound proxychains profile",
            "      ansible.builtin.file:",
            f"        path: {artifacts.homebase_proxychains.target}",
            "        state: absent",
            "",
            "- name: Remove Barragan outbound ssh-proxy from selected proxy",
            "  hosts: selected_proxy",
            "  become: true",
            "  tasks:",
            "    - name: Stop and disable ssh-proxy service",
            "      ansible.builtin.systemd:",
            f"        name: {service_name}",
            "        enabled: false",
            "        state: stopped",
            "      failed_when: false",
            "    - name: Remove ssh-proxy config",
            "      ansible.builtin.file:",
            f"        path: {artifacts.proxy_ssh_config.target}",
            "        state: absent",
            "    - name: Remove ssh-proxy systemd unit",
            "      ansible.builtin.file:",
            f"        path: {artifacts.proxy_systemd_service.target}",
            "        state: absent",
            "    - name: Close selected proxy SOCKS port from core VCN",
            "      ansible.builtin.shell: |",
            "        set -eu",
            f"        while iptables -C INPUT -s 192.168.0.0/16 -p tcp --dport {socks_port} -m comment --comment 'Barragan outbound channel SOCKS listener' -j ACCEPT 2>/dev/null; do",
            f"          iptables -D INPUT -s 192.168.0.0/16 -p tcp --dport {socks_port} -m comment --comment 'Barragan outbound channel SOCKS listener' -j ACCEPT",
            "        done",
            "      args:",
            "        executable: /bin/bash",
            "      changed_when: false",
            "    - name: Persist selected proxy firewall rules",
            "      ansible.builtin.shell: |",
            "        set -eu",
            "        if command -v netfilter-persistent >/dev/null 2>&1; then",
            "          netfilter-persistent save",
            "        elif command -v iptables-save >/dev/null 2>&1 && [ -d /etc/iptables ]; then",
            "          iptables-save -f /etc/iptables/rules.v4",
            "        fi",
            "      args:",
            "        executable: /bin/bash",
            "      changed_when: false",
            "    - name: Reload systemd after ssh-proxy removal",
            "      ansible.builtin.systemd:",
            "        daemon_reload: true",
            "",
        ]
    )


def _render_manifest(artifacts: OutboundChannelArtifacts, homebase: CoreApplyHost, proxy: CoreApplyHost) -> str:
    body: dict[str, Any] = {
        "mode": "outbound_channel_apply_preview",
        "status": APPLY_PREVIEW_STATUS,
        "mutation": False,
        "targets": {
            "homebase": homebase.to_dict(),
            "proxy": proxy.to_dict(),
        },
        "artifactTargets": {
            "coreHosts": artifacts.core_hosts.target,
            "homebaseProxychains": artifacts.homebase_proxychains.target,
            "proxySshConfig": artifacts.proxy_ssh_config.target,
            "proxySystemdService": artifacts.proxy_systemd_service.target,
        },
        "validation": artifacts.validation.to_dict(),
        "opsecBoundary": artifacts.sketch_node_boundary.to_dict(),
        "notes": [
            "Apply preview targets core hosts only.",
            "Middle and edge sketch nodes are not Ansible inventory targets.",
            "Validation is planned from homebase and has not run in this preview.",
        ],
    }
    return json.dumps(body, indent=2, sort_keys=True) + "\n"


def _render_remove_manifest(artifacts: OutboundChannelArtifacts, homebase: CoreApplyHost, proxy: CoreApplyHost) -> str:
    body: dict[str, Any] = {
        "mode": "outbound_channel_remove",
        "status": "Removing",
        "mutation": True,
        "targets": {
            "homebase": homebase.to_dict(),
            "proxy": proxy.to_dict(),
        },
        "artifactTargets": {
            "homebaseProxychains": artifacts.homebase_proxychains.target,
            "proxySshConfig": artifacts.proxy_ssh_config.target,
            "proxySystemdService": artifacts.proxy_systemd_service.target,
        },
        "notes": [
            "Remove targets core hosts only.",
            "Middle and edge sketch nodes are not Ansible inventory targets.",
        ],
    }
    return json.dumps(body, indent=2, sort_keys=True) + "\n"


def _validate_core_hosts(homebase: CoreApplyHost, proxy: CoreApplyHost) -> None:
    errors: list[str] = []
    if homebase.name != "homebase":
        errors.append("homebase host name must be homebase")
    if not CORE_HOST_PATTERN.fullmatch(proxy.name) or proxy.name == "homebase":
        errors.append("proxy host name must look like proxy01")
    for host in (homebase, proxy):
        if not CORE_HOST_PATTERN.fullmatch(host.name):
            errors.append(f"core apply host {host.name} must be homebase or proxyNN")
        if not str(host.ansible_host or "").strip():
            errors.append(f"{host.name}.ansible_host is required")
        if not str(host.ansible_user or "").strip():
            errors.append(f"{host.name}.ansible_user is required")
    if errors:
        raise OutboundChannelApplyValidationError(errors)


def _validate_artifact_boundary(artifacts: OutboundChannelArtifacts) -> None:
    boundary = artifacts.sketch_node_boundary
    errors: list[str] = []
    if boundary.sketch_hosts_content is not None:
        errors.append("sketch hosts content must not be rendered")
    if boundary.middle_node_artifacts:
        errors.append("middle node artifacts must not be rendered")
    if boundary.edge_node_artifacts:
        errors.append("edge node artifacts must not be rendered")
    if errors:
        raise OutboundChannelApplyValidationError(errors)


def _proxy_id_from_artifacts(artifacts: OutboundChannelArtifacts) -> str:
    path = PurePosixPath(artifacts.homebase_proxychains.target)
    parts = path.parts
    if len(parts) < 4 or parts[1] != "opt":
        raise OutboundChannelApplyValidationError(["homebase proxychains target must live under /opt/proxyNN"])
    proxy_id = parts[2]
    if not CORE_HOST_PATTERN.fullmatch(proxy_id) or proxy_id == "homebase":
        raise OutboundChannelApplyValidationError(["homebase proxychains target must include proxyNN"])
    return proxy_id


def _parent_path(path: str) -> str:
    return str(PurePosixPath(path).parent)


def _systemd_unit_name(path: str) -> str:
    return PurePosixPath(path).name


def _homebase_ansible_command(ansible_command: str, inventory_path: str, shell_display: str) -> list[str]:
    return [
        ansible_command,
        "-i",
        inventory_path,
        "homebase",
        "-m",
        "ansible.builtin.command",
        "-a",
        shell_display,
    ]


def _outbound_http_probes(validation: ValidationCommand) -> list[ValidationCommand]:
    proxy_url = _socks_proxy_url_from_validation(validation)
    return [
        ValidationCommand(
            origin=validation.origin,
            command=[
                "curl",
                "-sS",
                "-L",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--connect-timeout",
                "10",
                "--max-time",
                "20",
                "-x",
                proxy_url,
                url,
            ],
            expected_public_ip=validation.expected_public_ip,
        )
        for url in OUTBOUND_HTTP_PROBE_URLS
    ]


def _socks_proxy_url_from_validation(validation: ValidationCommand) -> str:
    for part in validation.command:
        if re.fullmatch(r"socks5h?://[^:]+:\d+", part):
            return part.replace("socks5://", "socks5h://", 1)
    raise OutboundChannelApplyValidationError(["outbound validation command must include a socks5h://proxyNN:PORT target"])


def _http_probe_evidence(probe: ValidationCommand, result: DisposableCommandResult) -> dict[str, object]:
    observed_output = _sanitize_command_output(result.stdout.strip())
    http_status = _observed_http_status(observed_output)
    ok = result.ok and bool(http_status) and http_status != "000"
    return {
        "url": probe.command[-1],
        "shellDisplay": probe.shell_display(),
        "httpStatus": http_status,
        "observedOutput": observed_output,
        "ok": ok,
        "commandResult": _safe_command_result(result),
    }


def _observed_http_status(observed_output: str) -> str:
    json_stdout = _json_stdout_value(observed_output.strip())
    if json_stdout:
        return _observed_http_status(json_stdout)
    for line in reversed(observed_output.splitlines()):
        text = line.strip()
        if re.fullmatch(r"[1-5][0-9]{2}|000", text):
            return text
    return ""


def _socks_port_from_validation(validation: ValidationCommand) -> int:
    for part in validation.command:
        match = re.fullmatch(r"socks5h?://[^:]+:(\d+)", part)
        if match:
            port = int(match.group(1))
            if 1 <= port <= 65535:
                return port
    raise OutboundChannelApplyValidationError(["outbound validation command must include a socks5h://proxyNN:PORT target"])


def _strip_managed_comments(content: str) -> str:
    lines = [line for line in content.splitlines() if not line.startswith("#")]
    return "\n".join(lines).strip() + "\n"


def _indent_block(content: str, spaces: int) -> str:
    prefix = " " * spaces
    return "\n".join(f"{prefix}{line}" if line else prefix for line in content.rstrip("\n").splitlines())


def _assert_no_secret_material(workspace: OutboundApplyWorkspace) -> None:
    if isinstance(workspace, OutboundApplyWorkspace):
        rendered = "\n".join(
            [
                workspace.inventory.content,
                workspace.playbook.content,
                workspace.manifest.content,
            ]
        )
    else:
        rendered = json.dumps(workspace.to_dict(), sort_keys=True)
    _assert_no_forbidden_markers(rendered, "outbound apply workspace")


def _assert_no_forbidden_markers(rendered: str, label: str) -> None:
    matches = [marker for marker in SECRET_MARKERS if marker in rendered]
    if matches:
        raise OutboundChannelArtifactValidationError([f"{label} contains forbidden secret marker: {matches[0]}"])


def _assert_apply_plan_opsec(plan: OutboundApplyPlan) -> None:
    forbidden = {"middle", "edge", "sketch", "middle01", "edge01"}
    for step in plan.steps:
        for target in step.targets:
            normalized = f"{target.name} {target.role}".lower()
            if any(marker in normalized for marker in forbidden):
                raise OutboundChannelApplyValidationError([f"outbound apply step {step.step_id} targets non-core host {target.name}"])


def _job_engagement_id(job: StoredJobRun) -> str:
    return str(job.input.get("engagementId") or job.target_id or "")


def _entry_role(entry: dict[str, Any]) -> str:
    return str(entry.get("role") or "").strip()


def _matches_proxy(entry: dict[str, Any], proxy_id: str) -> bool:
    if not proxy_id:
        return False
    values = [
        entry.get("role"),
        entry.get("displayName"),
        entry.get("sshAlias"),
        entry.get("hostname"),
    ]
    return any(str(value or "").strip() == proxy_id or str(value or "").strip().startswith(f"{proxy_id}-") for value in values)


def _first_detail_value(entry: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = str(entry.get(key) or "").strip()
        if value:
            return value
    return ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
