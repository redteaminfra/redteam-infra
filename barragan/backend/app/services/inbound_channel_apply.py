# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import signal
import shlex
import shutil
import subprocess
import tempfile
import threading
from typing import Any, Callable, Mapping
from uuid import uuid4

from app.core.command_environment import barragan_subprocess_env
from app.core.runtime import start_runtime_task, has_runtime_context
from app.domain import JobEvent
from app.integrations.ansible_disposable_validation import resolve_ansible_playbook
from app.services.engagements import get_engagement
from app.services.engagement_operations import get_operations_overview
from app.services.infra_orientation import try_enqueue_infra_orientation_refresh
from app.services.inbound_backend_authorization import (
    InboundBackendAuthorization,
    InboundBackendAuthorizationValidationError,
    render_backend_authorization_fact_play,
    resolve_selected_inbound_backend_authorization,
)
from app.services.inbound_channel_artifacts import (
    HTTP_ROUTE_HEALTH_EXPECTATION,
    InboundChannelArtifacts,
    InboundChannelArtifactSpec,
    InboundChannelArtifactValidationError,
    InboundValidationPlan,
    compact_inbound_channel_from_spec,
    http_backend_service_name,
    is_managed_http_backend_site,
    is_native_static_web_route,
    is_shared_web_ingress,
    managed_http_backend_service_id,
    normalize_inbound_validation_profile,
    render_inbound_channel_artifacts,
)
from app.services.inbound_raw_route_plan import (
    InboundRawRoutePlanError,
    apply_plan_to_channel,
    assert_raw_route_plan_available,
    is_raw_route,
    validate_persisted_raw_route_plan,
)
from app.services.inbound_mutation_fence import (
    InboundMutationLeaseConflict,
    InboundMutationLeaseRepository,
    acquire_inbound_mutation,
    active_inbound_batch,
    active_inbound_mutation_owner,
    bind_inbound_mutation,
    release_inbound_mutation,
)
from app.services.outbound_channel_artifacts import RenderedArtifact
from app.services.sketch_provider_firewall import (
    ProviderIngressSyncResult,
    sync_provider_ingress_for_inbound_channel,
)
from app.services.shared_proxy_stack import SharedProxyStackMutationConflict, reserve_shared_proxy_stack_mutation
from app.services.sketch_ssh_keys import (
    SketchSshKeyNotFoundError,
    write_existing_sketch_ssh_key_files,
)


def _reject_active_inbound_batch(engagement_id: str, repository: JobRepository | None) -> None:
    active = active_inbound_batch(engagement_id, repository)
    if active is not None:
        raise InboundChannelApplyValidationError([f"inbound channel batch {active.id} is already running for this engagement"])


def _keyed_engagement(engagement_id: str) -> bool:
    return bool(engagement_id and has_runtime_context() and
                getattr(get_engagement(engagement_id), "sketch_state_schema", "split-v1") == "provider-keyed-v2")


def _acquire_inbound_lease(
    engagement_id: str,
    owner: str,
    operation: str,
) -> InboundMutationLeaseRepository | None:
    try:
        return acquire_inbound_mutation(engagement_id, owner, operation)
    except InboundMutationLeaseConflict as exc:
        raise InboundChannelApplyValidationError([str(exc)]) from exc
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.service_repository import SqlAlchemyEngagementServiceRepository, StoredEngagementService


INBOUND_APPLY_PREVIEW_ACTION = "inbound_channel_apply_preview"
INBOUND_APPLY_ACTION = "inbound_channel_apply"
INBOUND_VALIDATE_ACTION = "inbound_channel_validation"
INBOUND_REMOVE_ACTION = "inbound_channel_remove"
DEFAULT_CORE_SSH_PRIVATE_KEY = "/var/lib/barragan/.ssh/barragan_testing"
DEFAULT_LOCAL_SKETCH_KEY = "/var/lib/barragan/sketch-keys/{engagement}-sketch"
GO_SIMPLE_UPLOAD_SERVER_BACKEND_PORT = 9999
CORE_DEFAULT_SSH_USER = "user"
# Barragan uses the deployment admin identity only for privileged inbound
# configuration. Backflips and outbound runtime transport remain sketchssh.
SKETCH_INFRASTRUCTURE_ADMIN_USER = "root"
SKETCH_RUNTIME_USER = "sketchssh"
MANAGEMENT_SSH_WAIT_TIMEOUT_SECONDS = 420
CORE_SSH_OPTIONS = (
    "-o UserKnownHostsFile=/dev/null",
    "-o StrictHostKeyChecking=no",
    "-o IdentitiesOnly=yes",
    "-o BatchMode=yes",
    "-o ConnectTimeout=10",
)
ANSIBLE_APPLY_COMMAND = ["ansible-playbook", "-i", "ansible/inventory.ini", "ansible/apply_inbound_channel.yml"]
ANSIBLE_VALIDATE_COMMAND = ["ansible-playbook", "-i", "ansible/inventory.ini", "ansible/validate_inbound_channel.yml"]
INBOUND_APPLY_PHASES = (
    ("preflight", "Preflight management paths", "ansible/preflight_inbound_channel.yml", False),
    ("apply", "Apply inbound channel route", "ansible/apply_inbound_channel.yml", True),
)
CORE_PROXY_TCP_INGRESS_PORTS = (80, 443, 2222)
CORE_PROXY_TCP_INGRESS_PORT_RANGES = ((8000, 8080),)
CORE_PROXY_TCP_INGRESS_POOL_LABEL = "80/tcp, 443/tcp, 2222/tcp, and 8000-8080/tcp"
CORE_PROXY_UDP_INGRESS_PORTS: tuple[int, ...] = ()
CORE_PROXY_UDP_INGRESS_PORT_RANGES = ((8000, 8080),)
CORE_PROXY_UDP_INGRESS_POOL_LABEL = "8000-8080/udp"
BACKFLIPS_PORT = 2222
DEFAULT_WORKSPACE_ROOT = Path("/tmp/barragan-inbound-channel-apply")
APPLY_PREVIEW_STATUS = "Pending Apply"
APPLY_SUCCESS_STATUS = "Pending Validation"
APPLY_FAILED_STATUS = "Apply Failed"
VALIDATION_SUCCESS_STATUS = "Validated"
VALIDATION_FAILED_STATUS = "Validation Failed"
REMOVE_SUCCESS_STATUS = "Removed"
REMOVE_FAILED_STATUS = "Remove Failed"
EDGE_LOCAL_VALIDATION_SCOPE = "edge-local ingress route"
EXTERNAL_INGRESS_VERIFIED = False
MAX_COMMAND_OUTPUT_CHARS = 4000
COMMAND_TIMEOUT_SECONDS = 900
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
SECRET_OUTPUT_REDACTIONS = (
    (re.compile(r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-api-token)\s*:\s*).+$"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(bearer|basic)\s+\S+"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)\b(api[_ -]?key|private[_ -]?key|password|passwd|token|secret|access[_ -]?token|refresh[_ -]?token|client[_ -]?secret)\s*[:=]\s*([^\s&;]+)"), r"\1=[REDACTED]"),
)
PROXY_RUNTIME_REGISTRY_DIR = "/var/lib/barragan/managed-runtime"
PROXY_RUNTIME_REGISTRY_PATH = f"{PROXY_RUNTIME_REGISTRY_DIR}/barragan-routes.json"
PROXY_RUNTIME_REGISTRY_LOCK_PATH = f"{PROXY_RUNTIME_REGISTRY_DIR}/.barragan-routes.lock"

CommandRunner = Callable[[list[str], Path | None], subprocess.CompletedProcess[str]]
BackgroundRunner = Callable[[Callable[[], None]], None]


class InboundChannelApplyValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("inbound channel apply validation failed")
        self.errors = errors


class InboundApplyWorkspace:
    def __init__(
        self,
        inventory: RenderedArtifact,
        playbooks: list[RenderedArtifact],
        manifest: RenderedArtifact,
        ssh_config: RenderedArtifact,
    ):
        self.inventory = inventory
        self.playbooks = tuple(playbooks)
        self.manifest = manifest
        self.ssh_config = ssh_config

    @property
    def playbook(self) -> RenderedArtifact:
        return self.playbooks[-1]

    def to_dict(self) -> dict[str, object]:
        return {
            "status": "Pending Apply",
            "mutation": False,
            "inventory": self.inventory.to_dict(),
            "sshConfig": self.ssh_config.to_dict(),
            "playbook": self.playbook.to_dict(),
            "playbooks": [playbook.to_dict() for playbook in self.playbooks],
            "manifest": self.manifest.to_dict(),
        }


@dataclass(frozen=True)
class InboundApplyCommand:
    phase: str
    label: str
    mutation: bool
    command: list[str]


class InboundValidationWorkspace:
    def __init__(self, inventory: RenderedArtifact, playbook: RenderedArtifact, manifest: RenderedArtifact, ssh_config: RenderedArtifact):
        self.inventory = inventory
        self.playbook = playbook
        self.manifest = manifest
        self.ssh_config = ssh_config

    def to_dict(self) -> dict[str, object]:
        return {
            "status": "Pending Validation",
            "mutation": False,
            "inventory": self.inventory.to_dict(),
            "sshConfig": self.ssh_config.to_dict(),
            "playbook": self.playbook.to_dict(),
            "manifest": self.manifest.to_dict(),
        }


@dataclass(frozen=True)
class InboundRouteTarget:
    name: str
    ansible_host: str
    public_ip: str = ""
    private_ip: str = ""
    chain_id: str = ""
    ssh_user: str = ""


@dataclass(frozen=True)
class InboundResolvedRoute:
    homebase: InboundRouteTarget
    proxy: InboundRouteTarget
    middle: InboundRouteTarget
    edge: InboundRouteTarget
    termination: InboundRouteTarget | None

    def to_dict(self) -> dict[str, object]:
        return {
            "homebase": _target_dict(self.homebase),
            "proxy": _target_dict(self.proxy),
            "middle": _target_dict(self.middle),
            "edge": _target_dict(self.edge),
            **({"termination": _target_dict(self.termination)} if self.termination else {}),
        }


class InboundRemoveWorkspace:
    def __init__(self, inventory: RenderedArtifact, playbook: RenderedArtifact, manifest: RenderedArtifact, ssh_config: RenderedArtifact):
        self.inventory = inventory
        self.playbook = playbook
        self.manifest = manifest
        self.ssh_config = ssh_config

    def to_dict(self) -> dict[str, object]:
        return {
            "status": "Pending Remove",
            "mutation": False,
            "inventory": self.inventory.to_dict(),
            "sshConfig": self.ssh_config.to_dict(),
            "playbook": self.playbook.to_dict(),
            "manifest": self.manifest.to_dict(),
        }


def preview_inbound_channel_apply(
    engagement_id: str,
    channel_id: str,
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    overview = get_operations_overview(engagement_id)
    channel = _inbound_channel_by_id(overview, channel_id)
    if not channel:
        raise InboundChannelApplyValidationError([f"inbound channel {channel_id} was not found"])
    try:
        spec, route = _resolved_spec_from_channel(engagement.name, overview, channel)
        artifacts = render_inbound_channel_artifacts(spec)
        workspace = render_inbound_apply_workspace(spec, artifacts, route=route)
    except InboundChannelApplyValidationError:
        raise
    except (InboundChannelArtifactValidationError, ValueError) as exc:
        errors = exc.errors if isinstance(exc, InboundChannelArtifactValidationError) else [str(exc)]
        raise InboundChannelApplyValidationError(errors) from exc
    ingress_assessment = _assess_inbound_ingress(spec, route)
    compact_channel = _compact_channel_with_ingress_assessment(spec, artifacts, route, ingress_assessment)
    inbound_channels = _merged_inbound_channels(engagement_id, channel_id, compact_channel)
    job = _save_preview_job(
        repository or SqlAlchemyJobRepository(),
        engagement_id,
        channel_id,
        requested_by,
        inbound_channels,
        artifacts.to_dict(),
        workspace.to_dict(),
        ingress_assessment,
    )
    return {
        "job": job.to_detail().to_dict(),
        "workspace": {
            "status": "Pending Apply",
            "mutation": False,
            "artifacts": artifacts.to_dict(),
            "applyWorkspace": workspace.to_dict(),
            "ingressAssessment": ingress_assessment,
            "channel": compact_channel,
        },
    }


def preflight_inbound_channel_apply(
    engagement_name: str,
    overview: dict[str, Any] | None,
    channel: dict[str, Any],
) -> dict[str, Any]:
    """Render and validate an inbound route without recording it or creating a job."""
    try:
        spec, route = _resolved_spec_from_channel(engagement_name, overview, channel)
        artifacts = render_inbound_channel_artifacts(spec)
        render_inbound_apply_workspace(spec, artifacts, route=route)
    except InboundChannelApplyValidationError:
        raise
    except (InboundChannelArtifactValidationError, ValueError) as exc:
        errors = exc.errors if isinstance(exc, InboundChannelArtifactValidationError) else [str(exc)]
        raise InboundChannelApplyValidationError(errors) from exc
    _validate_literal_previous_hop_sources(route, require_private_proxy_source=is_managed_http_backend_site(spec))
    ingress_assessment = _assess_inbound_ingress(spec, route)
    _validate_ingress_assessment_for_apply(ingress_assessment)
    return {
        **channel,
        **_compact_channel_with_ingress_assessment(spec, artifacts, route, ingress_assessment),
    }


def apply_inbound_channel(
    engagement_id: str,
    channel_id: str,
    **kwargs: Any,
) -> dict[str, Any] | None:
    owner = active_inbound_mutation_owner() or f"inbound-{uuid4().hex}"
    leases = _acquire_inbound_lease(engagement_id, owner, INBOUND_APPLY_ACTION)
    try:
        with bind_inbound_mutation(owner):
            return _apply_inbound_channel(engagement_id, channel_id, **kwargs)
    finally:
        release_inbound_mutation(engagement_id, owner, leases)


def _apply_inbound_channel(
    engagement_id: str,
    channel_id: str,
    *,
    confirmation: str,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    runner: CommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any] | None:
    _reject_active_inbound_batch(engagement_id, repository)
    prepared = _prepare_inbound_apply_job(
        engagement_id,
        channel_id,
        confirmation=confirmation,
        requested_by=requested_by,
        repository=repository,
        runner=runner,
        env=env,
        workspace_root=workspace_root,
    )
    if prepared is None:
        return None
    repo, job, command, workspace_dir, command_runner, pending_channel, provider_chain_id, engagement_name = prepared
    saved = _finish_inbound_apply_job(repo, job, engagement_id, channel_id, command, workspace_dir, command_runner, pending_channel, provider_chain_id, engagement_name)
    if saved.status == "succeeded":
        try_enqueue_infra_orientation_refresh(engagement_id, repository=repo)
    return {"job": saved.to_detail().to_dict(), "status": APPLY_SUCCESS_STATUS if saved.status == "succeeded" else APPLY_FAILED_STATUS}


def start_inbound_channel_apply(
    engagement_id: str,
    channel_id: str,
    *,
    confirmation: str,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    runner: CommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
    background_runner: BackgroundRunner | None = None,
    auto_validate: bool = False,
    channel: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    _reject_active_inbound_batch(engagement_id, repository)
    owner = active_inbound_mutation_owner() or f"inbound-{uuid4().hex}"
    leases = _acquire_inbound_lease(engagement_id, owner, INBOUND_APPLY_ACTION)
    try:
        with bind_inbound_mutation(owner):
            prepared = _prepare_inbound_apply_job(
                engagement_id,
                channel_id,
                confirmation=confirmation,
                requested_by=requested_by,
                repository=repository,
                runner=runner,
                env=env,
                workspace_root=workspace_root,
                channel=channel,
            )
    except Exception:
        release_inbound_mutation(engagement_id, owner, leases)
        raise
    if prepared is None:
        release_inbound_mutation(engagement_id, owner, leases)
        return None
    repo, job, command, workspace_dir, command_runner, pending_channel, provider_chain_id, engagement_name = prepared
    task_runner = background_runner or _start_background_task
    try:
        task_runner(lambda: _finish_inbound_apply_with_lease(
            repo, job, engagement_id, channel_id, command, workspace_dir,
            command_runner, pending_channel, provider_chain_id, engagement_name,
            requested_by=requested_by, env=env, workspace_root=workspace_root,
            auto_validate=auto_validate, owner=owner, leases=leases,
        ))
    except Exception as exc:
        _discard_inbound_apply_execution_workspace(workspace_dir)
        failed_channel = _channel_with_job_status(
            pending_channel,
            APPLY_FAILED_STATUS,
            "Inbound channel apply could not be started; no route mutation ran.",
        )
        failed = replace(
            job,
            status="failed",
            finished_at=_now(),
            events=[
                *job.events,
                JobEvent(
                    len(job.events) + 1,
                    "error",
                    "inbound channel background apply could not be started",
                    {
                        "channelId": channel_id,
                        "errorType": type(exc).__name__,
                        "status": APPLY_FAILED_STATUS,
                        "inboundChannels": _merged_inbound_channels(
                            engagement_id,
                            channel_id,
                            failed_channel,
                        ),
                    },
                ),
            ],
        )
        _assert_no_secret_material(failed.to_detail().to_dict())
        repo.save(failed)
        release_inbound_mutation(engagement_id, owner, leases)
        raise InboundChannelApplyValidationError(
            ["Inbound channel apply could not be started; the job was marked failed and no route mutation ran."]
        ) from exc
    return {"job": job.to_detail().to_dict(), "status": APPLY_PREVIEW_STATUS}


def _finish_inbound_apply_with_lease(
    repo: JobRepository,
    job: StoredJobRun,
    engagement_id: str,
    channel_id: str,
    commands: list[InboundApplyCommand],
    workspace_dir: Path,
    command_runner: CommandRunner,
    pending_channel: dict[str, object],
    provider_chain_id: str,
    engagement_name: str,
    *,
    requested_by: str,
    env: Mapping[str, str] | None,
    workspace_root: Path | None,
    auto_validate: bool,
    owner: str,
    leases: InboundMutationLeaseRepository | None,
) -> None:
    try:
        with bind_inbound_mutation(owner):
            _finish_inbound_apply_job_and_maybe_validate(
                repo, job, engagement_id, channel_id, commands, workspace_dir,
                command_runner, pending_channel, provider_chain_id, engagement_name,
                requested_by=requested_by, env=env, workspace_root=workspace_root,
                auto_validate=auto_validate,
            )
    finally:
        release_inbound_mutation(engagement_id, owner, leases)


def _finish_inbound_apply_job_and_maybe_validate(
    repo: JobRepository,
    job: StoredJobRun,
    engagement_id: str,
    channel_id: str,
    commands: list[InboundApplyCommand],
    workspace_dir: Path,
    command_runner: CommandRunner,
    pending_channel: dict[str, object],
    provider_chain_id: str,
    engagement_name: str,
    *,
    requested_by: str,
    env: Mapping[str, str] | None,
    workspace_root: Path | None,
    auto_validate: bool,
) -> StoredJobRun:
    saved = _finish_inbound_apply_job(repo, job, engagement_id, channel_id, commands, workspace_dir, command_runner, pending_channel, provider_chain_id, engagement_name)
    if saved.status == "succeeded":
        try_enqueue_infra_orientation_refresh(engagement_id, repository=repo)
    if (
        not auto_validate
        or saved.status != "succeeded"
        # A typed TLS backend is intentionally not validated until an active
        # certificate has been bound.  Its prepared 443 path must not be
        # represented as a working public service before that point.
        or str(pending_channel.get("validationProfile", {}).get("type") if isinstance(pending_channel.get("validationProfile"), Mapping) else "") == "manual"
    ):
        return saved
    try:
        validate_inbound_channel(
            engagement_id,
            channel_id,
            confirmation=f"validate-inbound-{channel_id}",
            requested_by=requested_by,
            repository=repo,
            runner=command_runner,
            env=env,
            workspace_root=workspace_root,
        )
    except InboundChannelApplyValidationError as exc:
        return _append_job_event(
            repo,
            saved,
            "error",
            "inbound channel automatic validation failed to start",
            {"channelId": channel_id, "errors": exc.errors},
        )
    return saved


def _prepare_inbound_apply_job(
    engagement_id: str,
    channel_id: str,
    *,
    confirmation: str,
    requested_by: str,
    repository: JobRepository | None,
    runner: CommandRunner | None,
    env: Mapping[str, str] | None,
    workspace_root: Path | None,
    channel: dict[str, Any] | None = None,
) -> tuple[JobRepository, StoredJobRun, list[InboundApplyCommand], Path, CommandRunner, dict[str, object], str, str] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    expected_confirmation = f"apply-inbound-{channel_id}"
    if confirmation != expected_confirmation:
        raise InboundChannelApplyValidationError([f"confirmation must be {expected_confirmation}"])

    repo = repository or SqlAlchemyJobRepository()
    staged_create = channel is not None
    if not staged_create:
        channel, spec, artifacts, workspace, route = _render_channel_workspace(
            engagement.name,
            engagement_id,
            channel_id,
            repository=repo,
            include_request_header_gate=True,
        )
    else:
        if str(channel.get("channelId") or "") != channel_id:
            raise InboundChannelApplyValidationError([f"inbound channel payload does not match {channel_id}"])
        try:
            overview = get_operations_overview(engagement_id)
            spec, artifacts, workspace, route = _render_apply_workspace_for_channel(
                engagement.name,
                engagement_id,
                channel,
                overview,
                include_request_header_gate=True,
            )
        except InboundChannelApplyValidationError:
            raise
        except (InboundChannelArtifactValidationError, ValueError) as exc:
            errors = exc.errors if isinstance(exc, InboundChannelArtifactValidationError) else [str(exc)]
            raise InboundChannelApplyValidationError(errors) from exc
    _validate_literal_previous_hop_sources(route, require_private_proxy_source=is_managed_http_backend_site(spec))
    ingress_assessment = _assess_inbound_ingress(spec, route)
    _validate_ingress_assessment_for_apply(ingress_assessment)
    ansible_resolution = resolve_ansible_playbook(env=env)
    if not ansible_resolution.ok or not ansible_resolution.command:
        raise InboundChannelApplyValidationError([ansible_resolution.error or "Could not resolve ansible-playbook executable"])

    command_runner = runner or _run_command
    workspace_dir = _apply_workspace_dir(channel_id, workspace_root)
    try:
        local_sketch_key, _ = write_existing_sketch_ssh_key_files(
            engagement_id, workspace_dir / "keys"
        )
    except SketchSshKeyNotFoundError as exc:
        _discard_inbound_apply_execution_workspace(workspace_dir)
        raise InboundChannelApplyValidationError([str(exc)]) from exc
    try:
        if not staged_create:
            channel, spec, artifacts, workspace, route = _render_channel_workspace(
                engagement.name,
                engagement_id,
                channel_id,
                repository=repo,
                include_request_header_gate=True,
                local_sketch_key_file=local_sketch_key,
            )
        else:
            overview = get_operations_overview(engagement_id)
            spec, artifacts, workspace, route = _render_apply_workspace_for_channel(
                engagement.name,
                engagement_id,
                channel,
                overview,
                include_request_header_gate=True,
                local_sketch_key_file=local_sketch_key,
            )
        commands = _apply_phase_commands(ansible_resolution.command, workspace)
        _write_workspace(workspace, workspace_dir)
    except Exception:
        _discard_inbound_apply_execution_workspace(workspace_dir)
        raise
    pending_channel = _channel_with_apply_state(spec, artifacts, route=route, ingress_assessment=ingress_assessment)
    # Compaction renders the transport artifacts but does not know the saved
    # planner provenance. Keep that immutable plan and exact component IDs on
    # every apply, including first apply before an Operations row exists.
    for key in ("rawRoutePlan", "rawRouteLegacy", "edgeComponentId", "middleComponentId"):
        if key in channel:
            pending_channel[key] = channel[key]
    timestamp = _now()
    job = StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=INBOUND_APPLY_ACTION,
        status="running",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by=requested_by,
        input={"engagementId": engagement_id, "channelId": channel_id, "proxyId": route.proxy.name, "mutation": True, "confirmation": "redacted"},
        artifact_refs=[workspace.inventory.target, workspace.ssh_config.target, *[playbook.target for playbook in workspace.playbooks], workspace.manifest.target],
        created_at=timestamp,
        started_at=timestamp,
        finished_at=None,
        events=[
            JobEvent(
                1,
                "info",
                "inbound channel apply workspace rendered",
                {
                    "channelId": channel_id,
                    "workspaceDir": str(workspace_dir),
                    "workspaceEvidence": _secret_free_workspace_evidence(workspace),
                    "ingressAssessment": ingress_assessment,
                    "mutation": True,
                    "status": APPLY_PREVIEW_STATUS,
                    **(
                        {"inboundChannels": _merged_inbound_channels(engagement_id, channel_id, channel)}
                        if staged_create
                        else {}
                    ),
                    "inventoryTargets": _inventory_targets(channel),
                    "resolvedRoute": route.to_dict(),
                    "opsecBoundary": {
                        "middleAccess": "proxy jump required",
                        "edgeAccess": "proxy-middle jump required",
                        "directSketchAccessFromAppHost": False,
                    },
                },
            ),
            JobEvent(
                2,
                "info",
                "inbound channel Ansible apply started",
                {
                    "channelId": channel_id,
                    "commands": [_phase_command_dict(phase_command) for phase_command in commands],
                    "cwd": str(workspace_dir),
                    "inventoryTargets": _inventory_targets(channel),
                },
            ),
        ],
    )
    try:
        _assert_no_secret_material(job.to_detail().to_dict())
    except Exception:
        _discard_inbound_apply_execution_workspace(workspace_dir)
        raise
    if spec.mode in {"http-openresty", "https-openresty"}:
        try:
            job = reserve_shared_proxy_stack_mutation(
                repo,
                job,
                engagement_id=engagement_id,
                proxy_id=route.proxy.name,
            )
        except SharedProxyStackMutationConflict as exc:
            _discard_inbound_apply_execution_workspace(workspace_dir)
            raise InboundChannelApplyValidationError(
                [f"Shared proxy web-stack mutation already running on {route.proxy.name}: {exc.job.id} ({exc.job.action})"]
            ) from exc
        except Exception:
            _discard_inbound_apply_execution_workspace(workspace_dir)
            raise
    else:
        try:
            job = repo.save(job)
        except Exception:
            _discard_inbound_apply_execution_workspace(workspace_dir)
            raise
    return repo, job, commands, workspace_dir, command_runner, pending_channel, route.edge.chain_id, engagement.name


def _finish_inbound_apply_job(
    repo: JobRepository,
    job: StoredJobRun,
    engagement_id: str,
    channel_id: str,
    commands: list[InboundApplyCommand],
    workspace_dir: Path,
    command_runner: CommandRunner,
    pending_channel: dict[str, object],
    provider_chain_id: str,
    engagement_name: str,
) -> StoredJobRun:
    try:
        return _finish_inbound_apply_job_with_execution_workspace(
            repo,
            job,
            engagement_id,
            channel_id,
            commands,
            workspace_dir,
            command_runner,
            pending_channel,
            provider_chain_id,
            engagement_name,
        )
    finally:
        _scrub_request_header_gate_execution_workspace(workspace_dir)


def _finish_inbound_apply_job_with_execution_workspace(
    repo: JobRepository,
    job: StoredJobRun,
    engagement_id: str,
    channel_id: str,
    commands: list[InboundApplyCommand],
    workspace_dir: Path,
    command_runner: CommandRunner,
    pending_channel: dict[str, object],
    provider_chain_id: str,
    engagement_name: str,
) -> StoredJobRun:
    current_job = job
    keyed = _keyed_engagement(engagement_id)
    if keyed:
        from app.services.provider_keyed_channel_apply import sync_keyed_channel_apply
        from app.services.sketch_provider_firewall import ProviderIngressSyncResult

        def record(message, data):
            nonlocal current_job
            current_job = _append_job_event(repo, current_job, "info", message, data)
        record.job_id = job.id
        try:
            sync_keyed_channel_apply(engagement_id, pending_channel, jobs=repo, record=record)
            provider_sync = ProviderIngressSyncResult("applied", True, "mixed", provider_chain_id, ())
        except Exception as exc:
            # Preserve failing frames without logging provider output or secrets
            # which an unexpected exception message might contain.
            logging.getLogger(__name__).exception(
                "Keyed channel ingress stopped (%s)", type(exc).__name__,
                exc_info=(RuntimeError, RuntimeError("exception details redacted"), exc.__traceback__),
            )
            # Do not replay or undo a possibly completed provider write. Its
            # exact receipt remains available to engagement-level teardown.
            record("keyed channel ingress requires observation", {"errorType": type(exc).__name__})
            provider_sync = ProviderIngressSyncResult("attention", False, "mixed", provider_chain_id, ())
    else:
        provider_sync = sync_provider_ingress_for_inbound_channel(
            engagement_id,
            engagement_name,
            provider_chain_id,
            operation="apply",
            channel=dict(pending_channel),
            overview=get_operations_overview(engagement_id),
            job_repository=repo,
        )
    current_job = _append_provider_ingress_events(repo, current_job, provider_sync)
    if not provider_sync.ok:
        failed_channel = _channel_with_job_status(
            pending_channel,
            APPLY_FAILED_STATUS,
            "Provider firewall update failed; inbound route apply did not start.",
        )
        final_job = replace(
            current_job,
            status="failed",
            finished_at=_now(),
            events=[
                *current_job.events,
                JobEvent(
                    len(current_job.events) + 1,
                    "error",
                    "inbound channel provider ingress sync failed",
                    {
                        "channelId": channel_id,
                        "status": APPLY_FAILED_STATUS,
                        "providerIngressStatus": provider_sync.status,
                        "inboundChannels": _merged_inbound_channels(engagement_id, channel_id, failed_channel),
                    },
                ),
            ],
        )
        _assert_no_secret_material(final_job.to_detail().to_dict())
        return repo.save(final_job)

    phase_results: list[dict[str, Any]] = []
    for phase_command in commands:
        current_job = _append_job_event(
            repo,
            current_job,
            "info",
            "inbound channel apply phase started",
            {
                "channelId": channel_id,
                "phase": phase_command.phase,
                "phaseLabel": phase_command.label,
                "mutation": phase_command.mutation,
                "command": _command_display(phase_command.command),
                "cwd": str(workspace_dir),
            },
        )
        result = _run_guarded_command(phase_command.command, workspace_dir, command_runner)
        command_result = _safe_command_result(result)
        phase_results.append({"phase": phase_command.phase, "result": command_result})
        if result.returncode != 0:
            failed_job = _append_job_event(
                repo,
                current_job,
                "error",
                "inbound channel apply phase failed",
                {
                    "channelId": channel_id,
                    "phase": phase_command.phase,
                    "phaseLabel": phase_command.label,
                    "commandResult": command_result,
                    "status": APPLY_FAILED_STATUS,
                },
            )
            if phase_command.mutation and not keyed:
                return _rollback_failed_inbound_apply(
                    repo,
                    failed_job,
                    engagement_id,
                    channel_id,
                    pending_channel,
                    provider_chain_id,
                    engagement_name,
                    workspace_dir,
                    command_runner,
                    commands[0].command[0],
                    failed_phase=phase_command.phase,
                    phase_results=phase_results,
                )
            final_job = replace(
                failed_job,
                status="failed",
                finished_at=_now(),
                events=[
                    *failed_job.events,
                    JobEvent(
                        len(failed_job.events) + 1,
                        "error",
                        "inbound channel Ansible apply failed",
                        {
                            "channelId": channel_id,
                            "failedPhase": phase_command.phase,
                            "phaseResults": phase_results,
                            "status": APPLY_FAILED_STATUS,
                            **({"inboundChannels": _merged_inbound_channels(
                                engagement_id, channel_id, _channel_with_job_status(
                                    pending_channel, APPLY_FAILED_STATUS,
                                    "Route apply failed after keyed ingress; review retained evidence or tear down the engagement."))}
                               if keyed else {}),
                        },
                    ),
                ],
            )
            _assert_no_secret_material(final_job.to_detail().to_dict())
            return repo.save(final_job)
        current_job = _append_job_event(
            repo,
            current_job,
            "info",
            "inbound channel apply phase succeeded",
            {
                "channelId": channel_id,
                "phase": phase_command.phase,
                "phaseLabel": phase_command.label,
                "commandResult": command_result,
                "status": APPLY_PREVIEW_STATUS if phase_command.phase != "apply" else APPLY_SUCCESS_STATUS,
            },
        )
    managed_site = _save_managed_http_backend_site(engagement_id, pending_channel, job.id)
    finished_at = _now()
    events = current_job.events + [
        JobEvent(
            len(current_job.events) + 1,
            "info",
            "inbound channel Ansible apply succeeded",
            {
                "channelId": channel_id,
                "phaseResults": phase_results,
                "status": APPLY_SUCCESS_STATUS,
            },
        ),
        JobEvent(
            len(current_job.events) + 2,
            "info",
            "inbound channel validation pending",
            {
                "channelId": channel_id,
                "status": APPLY_SUCCESS_STATUS,
                "validationRan": False,
                "inboundChannels": _merged_inbound_channels(engagement_id, channel_id, pending_channel),
                **({"servicePlacements": [_managed_http_backend_service_placement(managed_site)]} if managed_site else {}),
            },
        ),
    ]
    final_job = replace(current_job, status="succeeded", finished_at=finished_at, events=events)
    _assert_no_secret_material(final_job.to_detail().to_dict())
    return repo.save(final_job)


def _save_managed_http_backend_site(
    engagement_id: str,
    channel: Mapping[str, object],
    apply_job_id: str,
) -> StoredEngagementService | None:
    """Persist the proxy-site ownership record after route convergence only.

    This record ties a single hostname/channel to the generated OpenResty site
    and lets later certificate actions validate exact ownership rather than
    reconstructing a route from arbitrary channel fields. The final private
    HTTP backend does not own or terminate the certificate.
    """

    if str(channel.get("serviceType") or "") != "web-http-backend":
        return None
    service_id = str(channel.get("serviceId") or "")
    site_name = service_id.removeprefix("http-site-")
    channel_id = str(channel.get("channelId") or "")
    proxy_id = str(channel.get("proxy") or "")
    domain = str(channel.get("domain") or "").lower().rstrip(".")
    if (
        not re.fullmatch(r"http-site-[a-f0-9]{16}", service_id)
        or not re.fullmatch(r"[a-f0-9]{16}", site_name)
        or not channel_id
        or not proxy_id
        or not domain
    ):
        raise InboundChannelApplyValidationError(["managed HTTP backend route metadata is invalid"])
    service_name = http_backend_service_name(channel_id)
    backend_name = str(channel.get("service") or "HTTP backend").strip() or "HTTP backend"
    return SqlAlchemyEngagementServiceRepository().save(
        StoredEngagementService(
            engagement_id=engagement_id,
            service_id=service_id,
            service_type="web-http-backend",
            name=f"{backend_name} HTTPS site",
            proxy_id=proxy_id,
            status="Configured",
            config={
                "channelId": channel_id,
                "domain": domain,
                "siteName": site_name,
                "siteService": service_name,
                "siteConfigPath": f"/opt/web/inbound/{site_name}/conf/default.conf",
                "unboundConfigPath": f"/opt/web/inbound/{site_name}/conf/default.conf.barragan-unbound",
                "siteComposePath": f"/opt/web/sites/{site_name}.compose.yml",
                "composePath": "/opt/web/docker-compose.yml",
                "stackOwnershipPath": "/opt/web/.barragan-stack.json",
                "stackModel": "containerized-openresty-v1",
                "frontProxyService": "reverse-proxy",
            },
            apply_job_id=apply_job_id,
        )
    )


def _managed_http_backend_service_placement(service: StoredEngagementService) -> dict[str, str]:
    return {
        "hostId": service.proxy_id,
        "hostRole": "proxy",
        "service": service.name,
        "status": service.status,
        "port": "8081",
        "detail": "Barragan-owned TLS-terminating OpenResty site forwarding to a private Homebase HTTP backend.",
        "serviceId": service.service_id,
        "serviceType": service.service_type,
        "domain": str(service.config.get("domain") or ""),
        "siteName": str(service.config.get("siteName") or ""),
    }


def _rollback_failed_inbound_apply(
    repo: JobRepository,
    job: StoredJobRun,
    engagement_id: str,
    channel_id: str,
    pending_channel: dict[str, object],
    provider_chain_id: str,
    engagement_name: str,
    workspace_dir: Path,
    command_runner: CommandRunner,
    ansible_playbook: str,
    *,
    failed_phase: str,
    phase_results: list[dict[str, Any]],
) -> StoredJobRun:
    current_job = job
    rollback_status = "failed"
    rollback_result: dict[str, Any] = {}
    try:
        _channel, spec, artifacts, _workspace, route = _render_channel_workspace(
            engagement_name, engagement_id, channel_id, repository=repo
        )
        local_sketch_key, _ = write_existing_sketch_ssh_key_files(
            engagement_id, workspace_dir / "keys"
        )
        remove_workspace = render_inbound_remove_workspace(
            spec, artifacts, route=route, local_sketch_key_file=local_sketch_key
        )
        _write_remove_workspace(remove_workspace, workspace_dir)
        result = _run_guarded_command(
            [ansible_playbook, "-i", "ansible/inventory.ini", "ansible/remove_inbound_channel.yml"],
            workspace_dir,
            command_runner,
        )
        rollback_result = _safe_command_result(result)
        rollback_status = "succeeded" if result.returncode == 0 else "failed"
    except Exception as exc:
        rollback_result = {"errorType": type(exc).__name__}
    current_job = _append_job_event(
        repo,
        current_job,
        "info" if rollback_status == "succeeded" else "error",
        f"inbound channel apply rollback {rollback_status}",
        {"channelId": channel_id, "ansibleRollback": rollback_result},
    )
    provider_sync = sync_provider_ingress_for_inbound_channel(
        engagement_id,
        engagement_name,
        provider_chain_id,
        operation="remove",
        channel=dict(pending_channel),
        overview=get_operations_overview(engagement_id),
        job_repository=repo,
    )
    current_job = _append_provider_ingress_events(repo, current_job, provider_sync)
    if not provider_sync.ok:
        rollback_status = "failed"
    failed_channel = _channel_with_job_status(
        pending_channel,
        APPLY_FAILED_STATUS,
        f"Inbound apply failed during {failed_phase}; cleanup {rollback_status}. Remove this channel to retry cleanup before reusing its relay port.",
    )
    final_job = replace(
        current_job,
        status="failed",
        finished_at=_now(),
        events=[
            *current_job.events,
            JobEvent(
                len(current_job.events) + 1,
                "error",
                "inbound channel Ansible apply failed",
                {
                    "channelId": channel_id,
                    "failedPhase": failed_phase,
                    "phaseResults": phase_results,
                    "rollbackStatus": rollback_status,
                    "status": APPLY_FAILED_STATUS,
                    "inboundChannels": _merged_inbound_channels(engagement_id, channel_id, failed_channel),
                },
            ),
        ],
    )
    _assert_no_secret_material(final_job.to_detail().to_dict())
    return repo.save(final_job)


def validate_inbound_channel(
    engagement_id: str,
    channel_id: str,
    **kwargs: Any,
) -> dict[str, Any] | None:
    owner = f"inbound-{uuid4().hex}"
    leases = _acquire_inbound_lease(engagement_id, owner, INBOUND_VALIDATE_ACTION)
    try:
        with bind_inbound_mutation(owner):
            return _validate_inbound_channel(engagement_id, channel_id, **kwargs)
    finally:
        release_inbound_mutation(engagement_id, owner, leases)


def _validate_inbound_channel(
    engagement_id: str,
    channel_id: str,
    *,
    confirmation: str,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    runner: CommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any] | None:
    _reject_active_inbound_batch(engagement_id, repository)
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    expected_confirmation = f"validate-inbound-{channel_id}"
    if confirmation != expected_confirmation:
        raise InboundChannelApplyValidationError([f"confirmation must be {expected_confirmation}"])

    ansible_resolution = resolve_ansible_playbook(env=env)
    if not ansible_resolution.ok or not ansible_resolution.command:
        raise InboundChannelApplyValidationError([ansible_resolution.error or "Could not resolve ansible-playbook executable"])

    repo = repository or SqlAlchemyJobRepository()
    channel, spec, artifacts, _workspace, route = _render_channel_workspace(engagement.name, engagement_id, channel_id, repository=repo)
    command = [ansible_resolution.command, *ANSIBLE_VALIDATE_COMMAND[1:]]
    command_runner = runner or _run_command
    workspace_dir = _apply_workspace_dir(f"{channel_id}-validation", workspace_root)
    try:
        local_sketch_key, _ = write_existing_sketch_ssh_key_files(
            engagement_id, workspace_dir / "keys"
        )
    except SketchSshKeyNotFoundError as exc:
        _discard_inbound_apply_execution_workspace(workspace_dir)
        raise InboundChannelApplyValidationError([str(exc)]) from exc
    try:
        validation_workspace = render_inbound_validation_workspace(
            spec, artifacts, route=route, local_sketch_key_file=local_sketch_key
        )
        _write_validation_workspace(validation_workspace, workspace_dir)
    except Exception:
        _discard_inbound_apply_execution_workspace(workspace_dir)
        raise
    timestamp = _now()
    job = StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=INBOUND_VALIDATE_ACTION,
        status="running",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by=requested_by,
        input={"engagementId": engagement_id, "channelId": channel_id, "mutation": False, "confirmation": "redacted"},
        artifact_refs=[validation_workspace.inventory.target, validation_workspace.ssh_config.target, validation_workspace.playbook.target, validation_workspace.manifest.target],
        created_at=timestamp,
        started_at=timestamp,
        finished_at=None,
        events=[
            JobEvent(
                1,
                "info",
                "inbound channel validation workspace rendered",
                {
                    "channelId": channel_id,
                    "workspaceDir": str(workspace_dir),
                    "workspaceEvidence": validation_workspace.to_dict(),
                    "mutation": False,
                    "inventoryTargets": _inventory_targets(channel),
                    "resolvedRoute": route.to_dict(),
                    "validation": artifacts.validation.to_dict(),
                    "opsecBoundary": {
                        "listenerAccess": "termination host reached through core jump path when required",
                        "probeOrigin": "selected edge reached through homebase, selected proxy, and selected middle",
                        "directSketchAccessFromAppHost": False,
                        "directEdgeProbeFromAppHost": False,
                    },
                },
            ),
            JobEvent(
                2,
                "info",
                "inbound channel validation started",
                {
                    "channelId": channel_id,
                    "command": _command_display(command),
                    "cwd": str(workspace_dir),
                    "inventoryTargets": _inventory_targets(channel),
                },
            ),
        ],
    )
    try:
        _assert_no_secret_material(job.to_detail().to_dict())
        job = repo.save(job)
    except Exception:
        _discard_inbound_apply_execution_workspace(workspace_dir)
        raise
    try:
        result = _run_guarded_command(command, workspace_dir, command_runner)
    finally:
        shutil.rmtree(workspace_dir / "keys", ignore_errors=True)
    command_result = _safe_command_result(result)
    finished_at = _now()
    observed_output = _sanitize_command_output(str(result.stdout or ""))
    validation_plan = artifacts.validation
    expected_text = _validation_expected_text(validation_plan)
    # HTTP validation semantics are enforced by the generated Ansible
    # assertion. Its successful exit proves that the selected edge observed a
    # syntactically valid non-5xx response; route health must not depend on a
    # service-specific response body or status code.
    matched = result.returncode == 0 and (
        validation_plan.profile_type == "http" or expected_text in observed_output
    )
    validation_status = VALIDATION_SUCCESS_STATUS if matched else VALIDATION_FAILED_STATUS
    probe_host = _validation_probe_host(route)
    detail = _validation_evidence_detail(validation_plan, expected_text, spec.terminates_on, probe_host, spec.external_port, matched)
    validation_evidence = {
        "channelId": channel_id,
        "profileType": validation_plan.profile_type,
        "profileLabel": validation_plan.profile_label,
        "validationProfile": validation_plan.profile_to_dict(),
        "validationScope": EDGE_LOCAL_VALIDATION_SCOPE,
        "externalIngressVerified": EXTERNAL_INGRESS_VERIFIED,
        "ingressEndpoint": f"{probe_host}:{spec.external_port}",
        "listenerOrigin": validation_plan.listener_origin,
        "listenerShellDisplay": validation_plan.listener_shell_display,
        "probeOrigin": "selected_edge",
        "probeShellDisplay": _validation_probe_shell_display(spec, validation_plan, probe_host),
        "expectedMarker": validation_plan.expected_marker,
        "expectedResponse": expected_text,
        "observedResponse": _validation_observed_response(validation_plan, expected_text, matched),
        "checkedAt": finished_at,
        "status": validation_status,
        "detail": detail,
        "commandResult": command_result,
    }
    _assert_no_secret_material(validation_evidence)
    updated_channel = _channel_with_validation_state(spec, artifacts, validation_evidence, route=route)
    final_events = job.events + [
        JobEvent(
            len(job.events) + 1,
            "info" if matched else "error",
            "inbound channel validation succeeded" if matched else "inbound channel validation failed",
            {
                "channelId": channel_id,
                "status": validation_status,
                "validationEvidence": validation_evidence,
                "inboundChannels": _merged_inbound_channels(engagement_id, channel_id, updated_channel),
            },
        )
    ]
    final_job = replace(
        job,
        status="succeeded" if matched else "failed",
        finished_at=finished_at,
        events=final_events,
    )
    saved = repo.save(final_job)
    if saved.status == "succeeded":
        try_enqueue_infra_orientation_refresh(engagement_id, repository=repo)
    return {"job": saved.to_detail().to_dict(), "status": validation_status}


def remove_inbound_channel(
    engagement_id: str,
    channel_id: str,
    **kwargs: Any,
) -> dict[str, Any] | None:
    owner = f"inbound-{uuid4().hex}"
    leases = _acquire_inbound_lease(engagement_id, owner, INBOUND_REMOVE_ACTION)
    try:
        with bind_inbound_mutation(owner):
            return _remove_inbound_channel(engagement_id, channel_id, **kwargs)
    finally:
        release_inbound_mutation(engagement_id, owner, leases)


def _remove_inbound_channel(
    engagement_id: str,
    channel_id: str,
    *,
    confirmation: str = "",
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    runner: CommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any] | None:
    _reject_active_inbound_batch(engagement_id, repository)
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    repo = repository or SqlAlchemyJobRepository()
    overview = get_operations_overview(engagement_id)
    channel = _inbound_channel_by_id(overview, channel_id)
    if channel is None:
        raise InboundChannelApplyValidationError([f"inbound channel {channel_id} was not found"])
    applied = str(channel.get("status") or "").strip() in {APPLY_SUCCESS_STATUS, APPLY_FAILED_STATUS, VALIDATION_SUCCESS_STATUS, VALIDATION_FAILED_STATUS}
    expected_confirmation = f"remove-inbound-{channel_id}"
    if applied and confirmation != expected_confirmation:
        raise InboundChannelApplyValidationError([f"confirmation must be {expected_confirmation}"])

    if not applied:
        updated_channel = {**channel, "status": REMOVE_SUCCESS_STATUS, "validation": {**dict(channel.get("validation") or {}), "status": REMOVE_SUCCESS_STATUS, "detail": "Record-only inbound channel removed."}}
        job = _save_remove_record_job(repo, engagement_id, channel_id, requested_by, _merged_inbound_channels(engagement_id, channel_id, updated_channel))
        try_enqueue_infra_orientation_refresh(engagement_id, repository=repo)
        return {"job": job.to_detail().to_dict(), "status": REMOVE_SUCCESS_STATUS}

    channel, spec, artifacts, _workspace, route = _render_channel_workspace(engagement.name, engagement_id, channel_id, repository=repo)
    # Generic and native Static Web HTTPS bindings only own records: their
    # front pass-through and provider ingress may be shared by sibling sites.
    # They still run the narrow registry mutation below. A typed GoSUS backend
    # is different: it owns a generated proxy site and the narrow Homebase
    # TCP/9999 authorization, so it runs the full Ansible teardown.
    registry_only_remove = (
        is_shared_web_ingress(spec)
        and spec.mode != "http-openresty"
        and not is_managed_http_backend_site(spec)
    )

    ansible_resolution = resolve_ansible_playbook(env=env)
    if not ansible_resolution.ok or not ansible_resolution.command:
        raise InboundChannelApplyValidationError([ansible_resolution.error or "Could not resolve ansible-playbook executable"])
    command = [ansible_resolution.command, *ANSIBLE_APPLY_COMMAND[1:-1], "ansible/remove_inbound_channel.yml"]
    command_runner = runner or _run_command
    workspace_dir = _apply_workspace_dir(f"{channel_id}-remove", workspace_root)
    try:
        local_sketch_key, _ = write_existing_sketch_ssh_key_files(
            engagement_id, workspace_dir / "keys"
        )
    except SketchSshKeyNotFoundError as exc:
        _discard_inbound_apply_execution_workspace(workspace_dir)
        raise InboundChannelApplyValidationError([str(exc)]) from exc
    try:
        remove_workspace = render_inbound_remove_workspace(
            spec, artifacts, route=route, local_sketch_key_file=local_sketch_key
        )
        if registry_only_remove:
            remove_workspace = _registry_only_remove_workspace(remove_workspace, spec.channel_id)
        _write_remove_workspace(remove_workspace, workspace_dir)
    except Exception:
        _discard_inbound_apply_execution_workspace(workspace_dir)
        raise
    timestamp = _now()
    job = StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=INBOUND_REMOVE_ACTION,
        status="running",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by=requested_by,
        input={"engagementId": engagement_id, "channelId": channel_id, "proxyId": route.proxy.name, "mutation": True, "confirmation": "redacted"},
        artifact_refs=[remove_workspace.inventory.target, remove_workspace.ssh_config.target, remove_workspace.playbook.target, remove_workspace.manifest.target],
        created_at=timestamp,
        started_at=timestamp,
        finished_at=None,
        events=[
            JobEvent(
                1,
                "info",
                "inbound channel remove workspace rendered",
                {"channelId": channel_id, "workspaceDir": str(workspace_dir), "workspaceEvidence": remove_workspace.to_dict(), "resolvedRoute": route.to_dict(), "mutation": True},
            ),
            JobEvent(2, "info", "inbound channel Ansible remove started", {"channelId": channel_id, "command": _command_display(command), "cwd": str(workspace_dir)}),
        ],
    )
    try:
        _assert_no_secret_material(job.to_detail().to_dict())
    except Exception:
        _discard_inbound_apply_execution_workspace(workspace_dir)
        raise
    if is_shared_web_ingress(spec):
        try:
            job = reserve_shared_proxy_stack_mutation(
                repo,
                job,
                engagement_id=engagement_id,
                proxy_id=route.proxy.name,
            )
        except SharedProxyStackMutationConflict as exc:
            _discard_inbound_apply_execution_workspace(workspace_dir)
            raise InboundChannelApplyValidationError(
                [f"Shared proxy web-stack mutation already running on {route.proxy.name}: {exc.job.id} ({exc.job.action})"]
            ) from exc
        except Exception:
            _discard_inbound_apply_execution_workspace(workspace_dir)
            raise
    else:
        try:
            job = repo.save(job)
        except Exception:
            _discard_inbound_apply_execution_workspace(workspace_dir)
            raise
    try:
        result = _run_guarded_command(command, workspace_dir, command_runner)
    finally:
        shutil.rmtree(workspace_dir / "keys", ignore_errors=True)
    command_result = _safe_command_result(result)
    finished_at = _now()
    if result.returncode == 0:
        removed_channel = _channel_with_remove_state(spec, artifacts, route=route)
        if registry_only_remove:
            validation = dict(removed_channel.get("validation") or {})
            validation["detail"] = "Shared web inbound channel record and managed registry entry removed; baseline edge/middle web pass-through and provider web ingress were retained for sibling routes."
            removed_channel["validation"] = validation
        current_job = replace(
            job,
            events=[
                *job.events,
                JobEvent(len(job.events) + 1, "info", "inbound channel Ansible remove succeeded", {"channelId": channel_id, "commandResult": command_result, "status": REMOVE_SUCCESS_STATUS}),
            ],
        )
        current_job = repo.save(current_job)
        provider_sync = (
            ProviderIngressSyncResult("retained", True, "shared-web", route.edge.chain_id, ())
            if is_shared_web_ingress(spec)
            else sync_provider_ingress_for_inbound_channel(
                engagement_id,
                engagement.name,
                route.edge.chain_id,
                operation="remove",
                channel=channel,
                overview=get_operations_overview(engagement_id),
                job_repository=repo,
            )
        )
        current_job = _append_provider_ingress_events(repo, current_job, provider_sync)
        if not provider_sync.ok:
            failed_channel = _channel_with_job_status(
                removed_channel,
                REMOVE_FAILED_STATUS,
                "Inbound route was removed, but provider firewall cleanup failed.",
            )
            final_job = replace(
                current_job,
                status="failed",
                finished_at=finished_at,
                events=[
                    *current_job.events,
                    JobEvent(
                        len(current_job.events) + 1,
                        "error",
                        "inbound channel provider ingress cleanup failed",
                        {
                            "channelId": channel_id,
                            "status": REMOVE_FAILED_STATUS,
                            "providerIngressStatus": provider_sync.status,
                            "inboundChannels": _merged_inbound_channels(engagement_id, channel_id, failed_channel),
                        },
                    ),
                ],
            )
        else:
            events = current_job.events + [
                JobEvent(
                    len(current_job.events) + 1,
                    "info",
                    "inbound channel removed",
                    {"channelId": channel_id, "status": REMOVE_SUCCESS_STATUS, "inboundChannels": _merged_inbound_channels(engagement_id, channel_id, removed_channel)},
                ),
            ]
            final_job = replace(current_job, status="succeeded", finished_at=finished_at, events=events)
    else:
        events = job.events + [
            JobEvent(len(job.events) + 1, "error", "inbound channel Ansible remove failed", {"channelId": channel_id, "commandResult": command_result, "status": REMOVE_FAILED_STATUS})
        ]
        final_job = replace(job, status="failed", finished_at=finished_at, events=events)
    _assert_no_secret_material(final_job.to_detail().to_dict())
    saved = repo.save(final_job)
    if saved.status == "succeeded":
        try_enqueue_infra_orientation_refresh(engagement_id, repository=repo)
    return {"job": saved.to_detail().to_dict(), "status": REMOVE_SUCCESS_STATUS if saved.status == "succeeded" else REMOVE_FAILED_STATUS}


def render_inbound_apply_workspace(
    spec: InboundChannelArtifactSpec,
    artifacts: InboundChannelArtifacts,
    *,
    core_ssh_private_key_file: str = DEFAULT_CORE_SSH_PRIVATE_KEY,
    local_sketch_key_file: str | None = None,
    route: InboundResolvedRoute | None = None,
    request_header_gate: Mapping[str, Any] | None = None,
    request_header_gate_playbook: str = "",
    backend_authorization: InboundBackendAuthorization | None = None,
    backend_request_gate_policy_path: str | None = None,
    retained_gate_engagement_id: str | None = None,
    keyed_sketch_policy: bool = False,
) -> InboundApplyWorkspace:
    local_sketch_key = _local_sketch_key_path(spec, local_sketch_key_file)
    resolved_route = route or _route_from_spec_names(spec)
    termination = _termination_host(spec, core_ssh_private_key_file, resolved_route)
    ssh_config = RenderedArtifact("ansible/ssh_config", _render_ssh_config(spec, core_ssh_private_key_file, local_sketch_key, termination, resolved_route))
    inventory = RenderedArtifact("ansible/inventory.ini", _render_inventory(spec, core_ssh_private_key_file, local_sketch_key, termination, resolved_route, keyed_sketch_policy=keyed_sketch_policy))
    playbooks = [
        RenderedArtifact("ansible/preflight_inbound_channel.yml", _render_preflight_playbook(spec, termination)),
        RenderedArtifact("ansible/prepare_inbound_hosts.yml", _render_prepare_playbook(spec)),
        RenderedArtifact(
            "ansible/apply_inbound_channel.yml",
            _render_apply_playbook(
                spec,
                artifacts,
                termination,
                resolved_route,
                request_header_gate=request_header_gate,
                request_header_gate_playbook=request_header_gate_playbook,
                backend_authorization=backend_authorization,
                backend_request_gate_policy_path=backend_request_gate_policy_path,
                retained_gate_engagement_id=retained_gate_engagement_id,
            ),
        ),
    ]
    manifest = RenderedArtifact("MANIFEST.json", _render_manifest(spec, artifacts, core_ssh_private_key_file, local_sketch_key, termination, resolved_route))
    workspace = InboundApplyWorkspace(inventory=inventory, playbooks=playbooks, manifest=manifest, ssh_config=ssh_config)
    _assert_workspace_opsec(workspace)
    return workspace


def render_inbound_validation_workspace(
    spec: InboundChannelArtifactSpec,
    artifacts: InboundChannelArtifacts,
    *,
    core_ssh_private_key_file: str = DEFAULT_CORE_SSH_PRIVATE_KEY,
    local_sketch_key_file: str | None = None,
    route: InboundResolvedRoute | None = None,
) -> InboundValidationWorkspace:
    local_sketch_key = _local_sketch_key_path(spec, local_sketch_key_file)
    resolved_route = route or _route_from_spec_names(spec)
    termination = _termination_host(spec, core_ssh_private_key_file, resolved_route)
    ssh_config = RenderedArtifact("ansible/ssh_config", _render_ssh_config(spec, core_ssh_private_key_file, local_sketch_key, termination, resolved_route))
    inventory = RenderedArtifact("ansible/inventory.ini", _render_inventory(spec, core_ssh_private_key_file, local_sketch_key, termination, resolved_route))
    playbook = RenderedArtifact("ansible/validate_inbound_channel.yml", _render_validation_playbook(spec, artifacts, termination, resolved_route))
    manifest = RenderedArtifact("MANIFEST.json", _render_validation_manifest(spec, artifacts, termination, resolved_route))
    workspace = InboundValidationWorkspace(inventory=inventory, playbook=playbook, manifest=manifest, ssh_config=ssh_config)
    _assert_validation_workspace_opsec(workspace)
    return workspace


def render_inbound_remove_workspace(
    spec: InboundChannelArtifactSpec,
    artifacts: InboundChannelArtifacts,
    *,
    core_ssh_private_key_file: str = DEFAULT_CORE_SSH_PRIVATE_KEY,
    local_sketch_key_file: str | None = None,
    route: InboundResolvedRoute | None = None,
) -> InboundRemoveWorkspace:
    local_sketch_key = _local_sketch_key_path(spec, local_sketch_key_file)
    resolved_route = route or _route_from_spec_names(spec)
    termination = _termination_host(spec, core_ssh_private_key_file, resolved_route)
    ssh_config = RenderedArtifact("ansible/ssh_config", _render_ssh_config(spec, core_ssh_private_key_file, local_sketch_key, termination, resolved_route))
    inventory = RenderedArtifact("ansible/inventory.ini", _render_inventory(spec, core_ssh_private_key_file, local_sketch_key, termination, resolved_route))
    playbook = RenderedArtifact("ansible/remove_inbound_channel.yml", _render_remove_playbook(spec, artifacts, resolved_route))
    manifest = RenderedArtifact("MANIFEST.json", _render_remove_manifest(spec, artifacts, resolved_route))
    workspace = InboundRemoveWorkspace(inventory=inventory, playbook=playbook, manifest=manifest, ssh_config=ssh_config)
    _assert_workspace_opsec(InboundApplyWorkspace(inventory=inventory, playbooks=[playbook], manifest=manifest, ssh_config=ssh_config))
    return workspace


def _registry_only_remove_workspace(
    workspace: InboundRemoveWorkspace,
    channel_id: str,
) -> InboundRemoveWorkspace:
    """Limit a shared HTTPS record removal to its proxy registry mutation."""

    playbook = RenderedArtifact(
        "ansible/remove_inbound_channel.yml",
        "\n".join(["---", *_proxy_runtime_registry_remove_play(channel_id), ""]),
    )
    narrowed = InboundRemoveWorkspace(
        inventory=workspace.inventory,
        playbook=playbook,
        manifest=workspace.manifest,
        ssh_config=workspace.ssh_config,
    )
    _assert_workspace_opsec(
        InboundApplyWorkspace(
            inventory=narrowed.inventory,
            playbooks=[narrowed.playbook],
            manifest=narrowed.manifest,
            ssh_config=narrowed.ssh_config,
        )
    )
    return narrowed


def _render_channel_workspace(
    engagement_name: str,
    engagement_id: str,
    channel_id: str,
    *,
    repository: JobRepository | None = None,
    include_request_header_gate: bool = False,
    local_sketch_key_file: str | None = None,
) -> tuple[dict[str, Any], InboundChannelArtifactSpec, InboundChannelArtifacts, InboundApplyWorkspace, InboundResolvedRoute]:
    overview = get_operations_overview(engagement_id)
    channel = _inbound_channel_by_id(overview, channel_id)
    if channel is None:
        raise InboundChannelApplyValidationError([f"inbound channel {channel_id} was not found"])
    spec, artifacts, workspace, route = _render_apply_workspace_for_channel(
        engagement_name,
        engagement_id,
        channel,
        overview,
        include_request_header_gate=include_request_header_gate,
        local_sketch_key_file=local_sketch_key_file,
    )
    return channel, spec, artifacts, workspace, route


def _render_apply_workspace_for_channel(
    engagement_name: str,
    engagement_id: str,
    channel: Mapping[str, Any],
    overview: Mapping[str, Any],
    *,
    include_request_header_gate: bool,
    local_sketch_key_file: str | None = None,
) -> tuple[InboundChannelArtifactSpec, InboundChannelArtifacts, InboundApplyWorkspace, InboundResolvedRoute]:
    """Render an apply workspace for either a stored or browser-staged route.

    Initial browser creation has not yet persisted the channel in Operations,
    but it must receive exactly the same selected-capability integration as a
    later reapply. In particular, a public request-header gate and a private
    backend authorization are distinct parts of a GoSUS HTTP route.
    """

    channel_id = str(channel.get("channelId") or "")
    try:
        spec, route = _resolved_spec_from_channel(engagement_name, dict(overview), dict(channel))
        artifacts = render_inbound_channel_artifacts(spec)
        request_header_gate = None
        request_header_gate_playbook = ""
        backend_authorization = None
        backend_request_gate_policy_path = None
        if (spec.mode == "http-openresty" and route.termination is not None) or is_managed_http_backend_site(spec):
            try:
                backend_authorization = resolve_selected_inbound_backend_authorization(
                    engagement_id,
                    host_class="homebase" if is_managed_http_backend_site(spec) else _termination_host_class(route),
                    port=_backend_port(spec) if is_managed_http_backend_site(spec) else spec.internal_port,
                )
            except InboundBackendAuthorizationValidationError as exc:
                raise InboundChannelApplyValidationError(exc.errors) from exc
        if include_request_header_gate and spec.mode in {"http-openresty", "https-openresty"}:
            from app.services.inbound_request_header_gate import (
                InboundRequestHeaderGateValidationError,
                load_active_request_header_gate,
                render_retained_https_request_header_gate_playbook,
            )

            try:
                request_header_gate = load_active_request_header_gate(engagement_id, channel_id)
                if (
                    request_header_gate is None
                    and backend_authorization is not None
                    and backend_authorization.capability_id == "go-simple-upload-server"
                ):
                    from app.services.inbound_request_header_gate import request_header_gate_policy_path

                    backend_request_gate_policy_path = str(
                        request_header_gate_policy_path(engagement_id, channel_id)
                    )
                # A typed GoSUS HTTPS route renders its retained gate directly
                # into the route/site transaction below.  It may be restoring
                # after an earlier failed first apply, before the derived site
                # ownership record is persisted, so it must not also invoke the
                # generic managed-site gate workflow.
                if (
                    request_header_gate is not None
                    and spec.mode == "https-openresty"
                    and not is_managed_http_backend_site(spec)
                ):
                    request_header_gate_playbook = render_retained_https_request_header_gate_playbook(
                        engagement_name,
                        engagement_id,
                        channel_id,
                        request_header_gate,
                    )
            except InboundRequestHeaderGateValidationError as exc:
                raise InboundChannelApplyValidationError(exc.errors) from exc
        workspace = render_inbound_apply_workspace(
            spec,
            artifacts,
            route=route,
            local_sketch_key_file=local_sketch_key_file,
            request_header_gate=request_header_gate if (spec.mode == "http-openresty" or is_managed_http_backend_site(spec)) else None,
            request_header_gate_playbook=request_header_gate_playbook,
            backend_authorization=backend_authorization,
            backend_request_gate_policy_path=backend_request_gate_policy_path,
            retained_gate_engagement_id=engagement_id if backend_request_gate_policy_path else None,
            keyed_sketch_policy=_keyed_engagement(engagement_id),
        )
    except InboundChannelApplyValidationError:
        raise
    except (InboundChannelArtifactValidationError, ValueError) as exc:
        errors = exc.errors if isinstance(exc, InboundChannelArtifactValidationError) else [str(exc)]
        raise InboundChannelApplyValidationError(errors) from exc
    return spec, artifacts, workspace, route


def _job_engagement_id(job: StoredJobRun) -> str:
    value = str(job.input.get("engagementId") or "").strip()
    if value:
        return value
    if job.target_type == "engagement":
        return job.target_id
    if job.target.startswith("engagement:"):
        return job.target.split(":", 1)[1]
    return ""


def _inbound_channel_by_id(overview: dict[str, Any] | None, channel_id: str) -> dict[str, Any] | None:
    channels = overview.get("inboundChannels", []) if isinstance(overview, dict) else []
    for channel in channels:
        if isinstance(channel, dict) and str(channel.get("channelId") or "") == channel_id:
            return channel
    return None


def _termination_host_class(route: InboundResolvedRoute) -> str:
    if route.termination is None:
        return ""
    for host_class, target in (("homebase", route.homebase), ("proxy", route.proxy)):
        if (
            route.termination.name == target.name
            and route.termination.ansible_host == target.ansible_host
        ):
            return host_class
    return ""


def _spec_from_channel(engagement_name: str, channel: dict[str, Any]) -> InboundChannelArtifactSpec:
    channel_id = _required(channel, "channelId")
    mode = _optional(channel, "mode") or "tcp-forward"
    service_type = _optional(channel, "serviceType")
    service_id = _optional(channel, "serviceId")
    backend_port = _optional_port(channel, "backendPort")
    validation_profile = normalize_inbound_validation_profile(channel.get("validationProfile"), channel_id=channel_id)
    # Early typed GoSUS HTTPS records omitted backendPort.  They terminate at
    # proxy :443, but their generated site still targets the fixed Homebase
    # GoSUS listener.  Preserve recovery/reapply compatibility rather than
    # accidentally forwarding the site back to the shared front port.
    if service_type == "web-http-backend" and backend_port is None:
        backend_port = GO_SIMPLE_UPLOAD_SERVER_BACKEND_PORT
    internal_port = _port(channel, "internalPort")
    terminates_on = _required(channel, "terminatesOn")
    proxy_hostname = _required(channel, "proxy")
    # Before WI-0374, generic HTTPS-to-Homebase records retained the backend as
    # their apparent transport termination and had no managed site identity.
    # Reapply normalizes only that legacy shape into the fixed shared TLS-front
    # contract. Proxy-terminated/static routes and raw TCP remain unchanged.
    if mode == "https-openresty" and not service_type and terminates_on != proxy_hostname:
        service_type = "web-http-backend"
        service_id = managed_http_backend_service_id(channel_id)
        backend_port = internal_port
        internal_port = 443
        terminates_on = proxy_hostname
        validation_profile = normalize_inbound_validation_profile(
            {
                "type": "manual",
                "label": "Bind TLS certificate, then validate HTTPS from Inspector",
            },
            channel_id=channel_id,
        )
    return InboundChannelArtifactSpec(
        engagement=engagement_name.lower(),
        channel_id=channel_id,
        domain=_required(channel, "domain"),
        protocol=(_optional(channel, "protocol") or "TCP").upper(),
        mode=mode,
        external_port=_port(channel, "externalPort"),
        relay_port=_optional_port(channel, "relayPort") or _optional_port(channel, "proxyRelayPort") or _optional_port(channel, "middleRelayPort"),
        middle_relay_port=_optional_port(channel, "middleRelayPort"),
        proxy_relay_port=_optional_port(channel, "proxyRelayPort"),
        edge_hostname=_required(channel, "edge"),
        middle_hostname=_required(channel, "middle"),
        proxy_hostname=proxy_hostname,
        terminates_on=terminates_on,
        service=_required(channel, "service"),
        internal_port=internal_port,
        backend_port=backend_port,
        purpose=_optional(channel, "purpose") or "Inbound channel",
        service_id=service_id,
        service_type=service_type,
        validation_profile=validation_profile,
        sketch_chain_id=_optional(channel, "chainId"),
    )


def _resolved_spec_from_channel(
    engagement_name: str,
    overview: dict[str, Any] | None,
    channel: dict[str, Any],
) -> tuple[InboundChannelArtifactSpec, InboundResolvedRoute]:
    if is_raw_route(channel) and isinstance(channel.get("rawRoutePlan"), Mapping):
        try:
            validated_plan = validate_persisted_raw_route_plan(
                channel,
                channel["rawRoutePlan"],
                infrastructure=overview or {},
            )
            assert_raw_route_plan_available(
                validated_plan,
                list((overview or {}).get("inboundChannels", [])),
                exclude_channel_id=str(channel.get("channelId") or ""),
            )
            channel = apply_plan_to_channel(
                channel,
                validated_plan,
            )
        except InboundRawRoutePlanError as exc:
            raise InboundChannelApplyValidationError(exc.errors) from exc
    spec = _spec_from_channel(engagement_name, channel)
    route = _resolve_route(overview or {}, spec)
    resolved_spec = replace(
        spec,
        sketch_chain_id=spec.sketch_chain_id or route.edge.chain_id,
        edge_upstream_host=route.middle.public_ip or route.middle.ansible_host,
        middle_upstream_host=route.proxy.public_ip or route.proxy.ansible_host or route.proxy.private_ip,
        proxy_upstream_host=_proxy_upstream_host(spec, route),
    )
    return resolved_spec, route


def _resolve_route(overview: dict[str, Any], spec: InboundChannelArtifactSpec) -> InboundResolvedRoute:
    core_hosts = overview.get("coreInfrastructure", []) if isinstance(overview, dict) else []
    sketch_hosts = overview.get("sketchInfrastructure", []) if isinstance(overview, dict) else []
    homebase = _core_target(core_hosts, "homebase", "homebase")
    proxy = _core_target(core_hosts, spec.proxy_hostname, "proxy")
    edge = _sketch_target(sketch_hosts, spec.edge_hostname, "edge", chain_id=spec.sketch_chain_id)
    chain_id = spec.sketch_chain_id or edge.chain_id
    if not chain_id:
        raise InboundChannelApplyValidationError([f"edge host {spec.edge_hostname} does not have a sketch chain ID"])
    middle = _sketch_target(sketch_hosts, spec.middle_hostname, "middle", chain_id=chain_id)
    termination = None if spec.terminates_on == spec.proxy_hostname else _core_target(core_hosts, spec.terminates_on, "termination")
    return InboundResolvedRoute(homebase=homebase, proxy=proxy, middle=middle, edge=edge, termination=termination)


def _core_target(rows: Any, name: str, label: str) -> InboundRouteTarget:
    row = _row_by_name(rows, name, core=True)
    if row is None:
        raise InboundChannelApplyValidationError([f"{label} host {name} was not found in core infrastructure"])
    public_ip = _text(row.get("publicIp"))
    private_ip = _text(row.get("privateIp"))
    ssh_user = _core_ssh_user(row, label)
    ansible_host = private_ip if label == "proxy" else public_ip or private_ip
    if not ansible_host or ansible_host in {"Not Deployed", "Not Ready", "N/A"}:
        raise InboundChannelApplyValidationError([f"{label} host {name} does not have a usable IP"])
    return InboundRouteTarget(name=_target_name(row, name), ansible_host=ansible_host, public_ip=public_ip, private_ip=private_ip, ssh_user=ssh_user)


def _core_ssh_user(row: dict[str, Any], label: str) -> str:
    ssh_user = _text(row.get("sshUser")) or CORE_DEFAULT_SSH_USER
    if ssh_user == "root":
        raise InboundChannelApplyValidationError([f"{label} host {row.get('displayName') or row.get('sshAlias') or row.get('role') or 'core'} is recorded with root SSH; Barragan requires a non-root management user"])
    return ssh_user


def _sketch_target(rows: Any, name: str, role: str, *, chain_id: str = "") -> InboundRouteTarget:
    candidates = _sketch_rows_by_name(rows, name, role=role, chain_id=chain_id)
    if not candidates:
        raise InboundChannelApplyValidationError([f"{role} host {name} was not found in sketch infrastructure"])
    if len(candidates) > 1:
        suffix = f" for chain {chain_id}" if chain_id else ""
        raise InboundChannelApplyValidationError([
            f"{role} host {name} is ambiguous{suffix}; record the selected sketch chain before applying this route"
        ])
    row = candidates[0]
    public_ip = _text(row.get("publicIp"))
    if not public_ip or public_ip in {"Not Deployed", "Not Ready", "N/A"}:
        raise InboundChannelApplyValidationError([f"{role} host {name} does not have a usable public IP"])
    return InboundRouteTarget(name=_target_name(row, name), ansible_host=public_ip, public_ip=public_ip, chain_id=_text(row.get("chainId")))


def _sketch_rows_by_name(rows: Any, name: str, *, role: str, chain_id: str = "") -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        return []
    candidates = {_text(name), _short_host(_text(name))}
    matching = []
    for row in rows:
        if not isinstance(row, dict) or _text(row.get("role")) != role:
            continue
        if chain_id and _text(row.get("chainId")) != chain_id:
            continue
        aliases = {
            _text(row.get("hostname")),
            _text(row.get("displayName")),
            _text(row.get("sshAlias")),
        }
        aliases.update(_short_host(alias) for alias in list(aliases))
        if candidates & aliases:
            matching.append(row)
    return matching


def _row_by_name(rows: Any, name: str, *, core: bool, role: str = "") -> dict[str, Any] | None:
    if not isinstance(rows, list):
        return None
    candidates = {_text(name), _short_host(_text(name))}
    for row in rows:
        if not isinstance(row, dict):
            continue
        if role and _text(row.get("role")) != role:
            continue
        aliases = {
            _text(row.get("hostname")),
            _text(row.get("displayName")),
            _text(row.get("sshAlias")),
            _text(row.get("role")) if core else "",
        }
        aliases.update(_short_host(alias) for alias in list(aliases))
        if candidates & aliases:
            return row
    return None


def _target_name(row: dict[str, Any], fallback: str) -> str:
    return _text(row.get("hostname")) or _text(row.get("displayName")) or _text(row.get("sshAlias")) or fallback


def _short_host(value: str) -> str:
    return value.split(".", 1)[0] if value else ""


def _proxy_upstream_host(spec: InboundChannelArtifactSpec, route: InboundResolvedRoute) -> str:
    if spec.terminates_on == spec.proxy_hostname:
        return "127.0.0.1"
    if route.termination is None:
        return spec.terminates_on
    return route.termination.private_ip or route.termination.public_ip or route.termination.ansible_host


def _termination_firewall_source(route: InboundResolvedRoute) -> str:
    return route.proxy.private_ip or route.proxy.public_ip or route.proxy.ansible_host


def _managed_http_backend_firewall_source(route: InboundResolvedRoute) -> str:
    """Return the literal selected-proxy private address for Homebase rules."""

    source = _literal_ip(route.proxy.private_ip)
    if not source:
        raise InboundChannelApplyValidationError(
            ["The selected proxy does not have a literal private IP for the managed HTTP backend Homebase firewall."]
        )
    return source


def _target_dict(target: InboundRouteTarget | None) -> dict[str, str]:
    if target is None:
        return {}
    return {
        "name": target.name,
        "ansibleHost": target.ansible_host,
        "publicIp": target.public_ip,
        "privateIp": target.private_ip,
        "chainId": target.chain_id,
        "sshUser": target.ssh_user,
    }


def _compact_channel_with_ingress_assessment(
    spec: InboundChannelArtifactSpec,
    artifacts: InboundChannelArtifacts,
    route: InboundResolvedRoute,
    ingress_assessment: dict[str, Any] | None = None,
) -> dict[str, object]:
    channel = compact_inbound_channel_from_spec(spec, artifacts)
    channel["ingressAssessment"] = ingress_assessment or _assess_inbound_ingress(spec, route)
    return channel


def _assess_inbound_ingress(spec: InboundChannelArtifactSpec, route: InboundResolvedRoute) -> dict[str, Any]:
    transport = _transport_protocol(spec)
    middle_relay_port = _middle_relay_port(spec)
    proxy_relay_port = _proxy_relay_port(spec)
    edge_source_ip = _literal_ip(route.edge.public_ip or route.edge.ansible_host)
    middle_source_ip = _literal_ip(route.middle.public_ip or route.middle.ansible_host)
    proxy_source = _managed_http_backend_firewall_source(route) if is_managed_http_backend_site(spec) else _termination_firewall_source(route)
    proxy_source_ip = _literal_ip(proxy_source)
    checks = [
        _ingress_check(
            check_id="edge-provider-ingress",
            scope="edgeProviderIngress",
            label="Edge provider ingress",
            status="managed",
            protocol=transport,
            port=spec.external_port,
            host=route.edge.name,
            detail=(
                f"Barragan syncs selected edge provider ingress for {spec.external_port}/{transport} "
                "before applying the inbound route."
            ),
        ),
        _ingress_check(
            check_id="edge-host-firewall",
            scope="edgeHostFirewall",
            label="Edge host firewall",
            status="managed",
            protocol=transport,
            port=spec.external_port,
            host=route.edge.name,
            detail=f"Barragan apply manages the selected edge host firewall for {spec.external_port}/{transport}.",
        ),
        _ingress_check(
            check_id="middle-host-firewall",
            scope="middleHostFirewall",
            label="Middle host firewall",
            status="managed",
            protocol=transport,
            port=middle_relay_port,
            host=route.middle.name,
            source=edge_source_ip or route.edge.public_ip or route.edge.ansible_host,
            detail=f"Barragan apply restricts the selected middle host firewall for {middle_relay_port}/{transport} to the selected edge.",
        ),
        _ingress_check(
            check_id="proxy-host-firewall",
            scope="proxyHostFirewall",
            label="Proxy host firewall",
            status="managed",
            protocol=transport,
            port=proxy_relay_port,
            host=route.proxy.name,
            source=middle_source_ip or route.middle.public_ip or route.middle.ansible_host,
            detail=f"Barragan apply restricts the selected proxy host firewall for {proxy_relay_port}/{transport} to the selected middle.",
        ),
    ]
    if route.termination is not None:
        checks.append(
            _ingress_check(
                check_id="termination-host-firewall",
                scope="terminationHostFirewall",
                label="Termination host firewall",
                status="managed",
                protocol=transport,
                port=spec.internal_port,
                host=route.termination.name,
                source=proxy_source_ip or proxy_source,
                detail=(
                    "Barragan apply requires a restrictive core input baseline and manages only the channel allow "
                    f"from selected proxy {route.proxy.name} to {spec.internal_port}/{transport}."
                ),
            )
        )
    if is_managed_http_backend_site(spec):
        backend_port = _backend_port(spec)
        checks.append(
            _ingress_check(
                check_id="managed-http-backend-homebase-firewall",
                scope="managedHttpBackendHomebaseFirewall",
                label="Managed HTTP backend Homebase firewall",
                status="managed",
                protocol="tcp",
                port=backend_port,
                host=route.homebase.name,
                source=proxy_source_ip or proxy_source,
                detail=(
                    "Barragan apply requires a restrictive Homebase input baseline and manages only the "
                    f"selected proxy {route.proxy.name} allow to the private HTTP backend on {backend_port}/tcp."
                ),
            )
        )
    checks.append(
        _ingress_check(
            check_id="termination-listener-expectation",
            scope="terminationListenerExpectation",
            label="Termination listener expectation",
            status="unknown",
            protocol=transport,
            port=spec.internal_port,
            host=spec.terminates_on,
            detail=(
                f"Barragan expects {spec.terminates_on} to receive traffic on {spec.internal_port}/{transport}; "
                "this slice does not prove the service listener until validation."
            ),
            corrective_action="Run inbound validation after apply or select a termination service and port that are already listening.",
        )
    )
    proxy_service_socket_check = _proxy_service_socket_check(spec, route, transport)
    if proxy_service_socket_check is not None:
        checks.insert(4, proxy_service_socket_check)
    checks.insert(5 if proxy_service_socket_check is not None else 4, _core_proxy_cloud_ingress_check(spec, route, transport))
    blocked_checks = [check for check in checks if check["status"] == "blocked"]
    return {
        "status": "blocked" if blocked_checks else "allowed",
        "applyAllowed": not blocked_checks,
        "protocol": transport,
        "externalPort": spec.external_port,
        "relayPort": _relay_port(spec),
        "middleRelayPort": middle_relay_port,
        "proxyRelayPort": proxy_relay_port,
        "terminationPort": spec.internal_port,
        "checks": checks,
        "blockedChecks": [check["id"] for check in blocked_checks],
        "blockingReasons": [str(check["detail"]) for check in blocked_checks],
        "summary": _ingress_assessment_summary(blocked_checks),
    }


def _proxy_service_socket_check(
    spec: InboundChannelArtifactSpec,
    route: InboundResolvedRoute,
    transport: str,
) -> dict[str, Any] | None:
    if not _has_backflips_proxy_socket_collision(spec, route, transport):
        return None
    return _ingress_check(
        check_id="proxy-service-port-collision",
        scope="proxyServiceSocket",
        label="Proxy service socket ownership",
        status="blocked",
        protocol=transport,
        port=spec.internal_port,
        host=route.proxy.name,
        detail=(
            f"SSH Backflips owns {route.proxy.name}:{BACKFLIPS_PORT}. "
            f"A generic inbound channel cannot also bind {route.proxy.name}:{BACKFLIPS_PORT} as its proxy relay listener."
        ),
        corrective_action="Use the SSH Backflips capability configuration, or choose a separate proxy relay port for a generic TCP route.",
    )


def _has_backflips_proxy_socket_collision(
    spec: InboundChannelArtifactSpec,
    route: InboundResolvedRoute,
    transport: str,
) -> bool:
    if transport != "tcp":
        return False
    if spec.terminates_on != spec.proxy_hostname and spec.terminates_on != route.proxy.name:
        return False
    if _proxy_relay_port(spec) != spec.internal_port:
        return False
    if spec.internal_port != BACKFLIPS_PORT:
        return False
    return _is_backflips_like(spec)


def _is_backflips_like(spec: InboundChannelArtifactSpec) -> bool:
    identities = {
        re.sub(r"[^a-z0-9]+", "", value.lower())
        for value in (spec.service, spec.purpose)
        if value
    }
    return bool(identities & {"backflips", "backflipsv2", "barraganbackflipsv2", "sshbackflips"})


def _core_proxy_cloud_ingress_check(
    spec: InboundChannelArtifactSpec,
    route: InboundResolvedRoute,
    transport: str,
) -> dict[str, Any]:
    proxy_relay_port = _proxy_relay_port(spec)
    if transport == "tcp":
        if _core_proxy_tcp_ingress_port_allowed(proxy_relay_port):
            return _ingress_check(
                check_id="core-proxy-cloud-ingress",
                scope="coreProxyCloudIngress",
                label="Core proxy cloud ingress",
                status="allowed",
                protocol=transport,
                port=proxy_relay_port,
                host=route.proxy.name,
                detail=(
                    f"Selected core proxy relay port {proxy_relay_port}/tcp is inside the current pilot core proxy ingress pool "
                    f"({CORE_PROXY_TCP_INGRESS_POOL_LABEL})."
                ),
            )

        return _ingress_check(
            check_id="core-proxy-cloud-ingress",
            scope="coreProxyCloudIngress",
            label="Core proxy cloud ingress",
            status="blocked",
            protocol=transport,
            port=proxy_relay_port,
            host=route.proxy.name,
            detail=(
                f"Core proxy cloud ingress for {route.proxy.name} allows only {CORE_PROXY_TCP_INGRESS_POOL_LABEL}; "
                f"selected core proxy relay port {proxy_relay_port}/tcp is blocked."
            ),
            corrective_action="Select an allowed relay port or wait for core cloud ingress mutation support in a later slice.",
        )

    if transport == "udp":
        if _core_proxy_udp_ingress_port_allowed(proxy_relay_port):
            return _ingress_check(
                check_id="core-proxy-cloud-ingress",
                scope="coreProxyCloudIngress",
                label="Core proxy cloud ingress",
                status="allowed",
                protocol=transport,
                port=proxy_relay_port,
                host=route.proxy.name,
                detail=(
                    f"Selected core proxy relay port {proxy_relay_port}/udp is inside the current pilot core proxy ingress pool "
                    f"({CORE_PROXY_UDP_INGRESS_POOL_LABEL})."
                ),
            )

        return _ingress_check(
            check_id="core-proxy-cloud-ingress",
            scope="coreProxyCloudIngress",
            label="Core proxy cloud ingress",
            status="blocked",
            protocol=transport,
            port=proxy_relay_port,
            host=route.proxy.name,
            detail=(
                f"Core proxy cloud ingress for {route.proxy.name} allows only {CORE_PROXY_UDP_INGRESS_POOL_LABEL}; "
                f"selected core proxy relay port {proxy_relay_port}/udp is blocked."
            ),
            corrective_action="Select an allowed UDP relay port or wait for core cloud ingress mutation support in a later slice.",
        )

    return _ingress_check(
        check_id="core-proxy-cloud-ingress",
        scope="coreProxyCloudIngress",
        label="Core proxy cloud ingress",
        status="unknown",
        protocol=transport,
        port=proxy_relay_port,
        host=route.proxy.name,
        detail=f"Core proxy cloud ingress is not modeled for {proxy_relay_port}/{transport} in this slice.",
    )


def _ingress_check(
    *,
    check_id: str,
    scope: str,
    label: str,
    status: str,
    protocol: str,
    port: int,
    host: str,
    detail: str,
    source: str = "",
    corrective_action: str = "",
) -> dict[str, Any]:
    check: dict[str, Any] = {
        "id": check_id,
        "scope": scope,
        "label": label,
        "status": status,
        "protocol": protocol,
        "port": port,
        "host": host,
        "detail": detail,
    }
    if source:
        check["source"] = source
    if corrective_action:
        check["correctiveAction"] = corrective_action
    return check


def _validate_ingress_assessment_for_apply(assessment: dict[str, Any]) -> None:
    errors = []
    for check in assessment.get("checks", []):
        if not isinstance(check, dict) or check.get("status") != "blocked":
            continue
        detail = str(check.get("detail") or "Inbound channel ingress is blocked.")
        corrective_action = str(check.get("correctiveAction") or "").strip()
        errors.append(f"{detail} {corrective_action}".strip())
    if errors:
        raise InboundChannelApplyValidationError(errors)


def _ingress_assessment_summary(blocked_checks: list[dict[str, Any]]) -> str:
    if blocked_checks:
        return "Inbound channel apply is blocked because one or more ingress checks cannot pass with the selected relay port."
    return "No blocking ingress checks were found; provider ingress will be synced during apply and the termination listener is validated after apply."


def _literal_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return ""


def _validate_literal_previous_hop_sources(
    route: InboundResolvedRoute,
    *,
    require_private_proxy_source: bool = False,
) -> None:
    errors = []
    if not _literal_ip(route.edge.public_ip or route.edge.ansible_host):
        errors.append("The selected edge does not have a literal previous-hop IP for the middle firewall.")
    if not _literal_ip(route.middle.public_ip or route.middle.ansible_host):
        errors.append("The selected middle does not have a literal previous-hop IP for the proxy firewall.")
    if route.termination is not None and not _literal_ip(_termination_firewall_source(route)):
        errors.append("The selected proxy does not have a literal previous-hop IP for the termination firewall.")
    if require_private_proxy_source and not _literal_ip(route.proxy.private_ip):
        errors.append("The selected proxy does not have a literal private IP for the managed HTTP backend Homebase firewall.")
    if errors:
        raise InboundChannelApplyValidationError(errors)


def _core_proxy_tcp_ingress_port_allowed(port: int) -> bool:
    return port in CORE_PROXY_TCP_INGRESS_PORTS or any(start <= port <= end for start, end in CORE_PROXY_TCP_INGRESS_PORT_RANGES)


def _core_proxy_udp_ingress_port_allowed(port: int) -> bool:
    return port in CORE_PROXY_UDP_INGRESS_PORTS or any(start <= port <= end for start, end in CORE_PROXY_UDP_INGRESS_PORT_RANGES)


def _transport_protocol(spec: InboundChannelArtifactSpec) -> str:
    if spec.mode.strip().lower() == "udp-forward" or spec.protocol.upper() == "UDP":
        return "udp"
    return "tcp"


def _relay_port(spec: InboundChannelArtifactSpec) -> int:
    if spec.relay_port is not None:
        return spec.relay_port
    return spec.internal_port if _transport_protocol(spec) == "udp" else spec.external_port


def _middle_relay_port(spec: InboundChannelArtifactSpec) -> int:
    return spec.middle_relay_port if spec.middle_relay_port is not None else _relay_port(spec)


def _proxy_relay_port(spec: InboundChannelArtifactSpec) -> int:
    return spec.proxy_relay_port if spec.proxy_relay_port is not None else _relay_port(spec)


def _backend_port(spec: InboundChannelArtifactSpec) -> int:
    """Return the private application port for a typed HTTPS backend site."""

    return spec.backend_port or spec.internal_port


def _save_preview_job(
    repository: JobRepository,
    engagement_id: str,
    channel_id: str,
    requested_by: str,
    inbound_channels: list[dict[str, Any]],
    artifacts: dict[str, object],
    workspace: dict[str, object],
    ingress_assessment: dict[str, Any],
) -> StoredJobRun:
    timestamp = datetime.now(timezone.utc).isoformat()
    job = StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=INBOUND_APPLY_PREVIEW_ACTION,
        status="succeeded",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by=requested_by,
        input={"engagementId": engagement_id, "channelId": channel_id, "mutation": False},
        artifact_refs=[],
        created_at=timestamp,
        started_at=timestamp,
        finished_at=timestamp,
        events=[
            JobEvent(
                1,
                "info",
                "inbound channel apply preview rendered",
                {
                    "phase": "preview",
                    "mutation": False,
                    "inboundChannels": inbound_channels,
                    "workspaceEvidence": artifacts,
                    "applyWorkspaceEvidence": workspace,
                    "ingressAssessment": ingress_assessment,
                },
            )
        ],
    )
    return repository.save(job)


def _save_remove_record_job(
    repository: JobRepository,
    engagement_id: str,
    channel_id: str,
    requested_by: str,
    inbound_channels: list[dict[str, Any]],
    *,
    event_message: str = "record-only inbound channel removed",
) -> StoredJobRun:
    timestamp = datetime.now(timezone.utc).isoformat()
    job = StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=INBOUND_REMOVE_ACTION,
        status="succeeded",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by=requested_by,
        input={"engagementId": engagement_id, "channelId": channel_id, "mutation": False},
        artifact_refs=[],
        created_at=timestamp,
        started_at=timestamp,
        finished_at=timestamp,
        events=[
            JobEvent(
                1,
                "info",
                event_message,
                {"channelId": channel_id, "status": REMOVE_SUCCESS_STATUS, "inboundChannels": inbound_channels},
            )
        ],
    )
    _assert_no_secret_material(job.to_detail().to_dict())
    return repository.save(job)


def _write_workspace(workspace: InboundApplyWorkspace, workspace_dir: Path) -> None:
    for artifact in (workspace.inventory, workspace.ssh_config, *workspace.playbooks, workspace.manifest):
        path = workspace_dir / artifact.target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(artifact.content, encoding="utf-8")


def _secret_free_workspace_evidence(workspace: InboundApplyWorkspace) -> dict[str, object]:
    evidence = _redact_request_header_gate_values(workspace.to_dict())
    rendered = json.dumps(evidence, sort_keys=True)
    if "Bearer " in rendered:
        raise InboundChannelApplyValidationError(
            ["inbound apply workspace evidence contains a request-header gate value"]
        )
    return evidence


def _redact_request_header_gate_values(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _redact_request_header_gate_values(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_request_header_gate_values(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_request_header_gate_values(item) for item in value)
    if not isinstance(value, str) or "Bearer " not in value:
        return value
    lines = []
    for line in value.splitlines(keepends=True):
        if "Bearer " in line:
            newline = "\n" if line.endswith("\n") else ""
            indent = line[: len(line) - len(line.lstrip())]
            lines.append(f"{indent}# Request-header gate value omitted from job evidence.{newline}")
        else:
            lines.append(line)
    return "".join(lines)


def _scrub_request_header_gate_execution_workspace(workspace_dir: Path) -> None:
    path = workspace_dir / "ansible" / "apply_inbound_channel.yml"
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        shutil.rmtree(workspace_dir / "keys", ignore_errors=True)
        return
    scrubbed = _redact_request_header_gate_values(content)
    if scrubbed == content:
        shutil.rmtree(workspace_dir / "keys", ignore_errors=True)
        return
    temp = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        temp.write_text(str(scrubbed), encoding="utf-8")
        os.chmod(temp, path.stat().st_mode & 0o777)
        os.replace(temp, path)
    except OSError:
        # The route mutation has already finished. If an atomic scrub cannot be
        # completed, remove the transient playbook rather than retaining its
        # request-header value or changing the completed job outcome.
        try:
            path.unlink()
        except OSError:
            pass
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        shutil.rmtree(workspace_dir / "keys", ignore_errors=True)


def _discard_inbound_apply_execution_workspace(workspace_dir: Path) -> None:
    _scrub_request_header_gate_execution_workspace(workspace_dir)
    shutil.rmtree(workspace_dir, ignore_errors=True)


def _write_validation_workspace(workspace: InboundValidationWorkspace, workspace_dir: Path) -> None:
    for artifact in (workspace.inventory, workspace.ssh_config, workspace.playbook, workspace.manifest):
        path = workspace_dir / artifact.target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(artifact.content, encoding="utf-8")


def _write_remove_workspace(workspace: InboundRemoveWorkspace, workspace_dir: Path) -> None:
    for artifact in (workspace.inventory, workspace.ssh_config, workspace.playbook, workspace.manifest):
        path = workspace_dir / artifact.target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(artifact.content, encoding="utf-8")


def _apply_workspace_dir(channel_id: str, workspace_root: Path | None) -> Path:
    safe_channel = re.sub(r"[^a-zA-Z0-9._-]+", "-", channel_id).strip("-") or "channel"
    if workspace_root is None:
        return Path(tempfile.mkdtemp(prefix=f"barragan-inbound-channel-{safe_channel}-"))
    root = workspace_root
    return root / f"{safe_channel}-{uuid4().hex[:12]}"


def _apply_phase_commands(ansible_playbook: str, workspace: InboundApplyWorkspace) -> list[InboundApplyCommand]:
    playbooks_by_target = {playbook.target: playbook for playbook in workspace.playbooks}
    commands: list[InboundApplyCommand] = []
    for phase, label, target, mutation in INBOUND_APPLY_PHASES:
        if target not in playbooks_by_target:
            raise InboundChannelApplyValidationError([f"inbound apply workspace missing {target}"])
        commands.append(
            InboundApplyCommand(
                phase=phase,
                label=label,
                mutation=mutation,
                command=[ansible_playbook, "-i", "ansible/inventory.ini", target],
            )
        )
    return commands


def _phase_command_dict(phase_command: InboundApplyCommand) -> dict[str, object]:
    return {
        "phase": phase_command.phase,
        "label": phase_command.label,
        "mutation": phase_command.mutation,
        "command": _command_display(phase_command.command),
    }


def _append_job_event(
    repository: JobRepository,
    job: StoredJobRun,
    level: str,
    message: str,
    data: dict[str, Any],
) -> StoredJobRun:
    updated = replace(job, events=[*job.events, JobEvent(len(job.events) + 1, level, message, data)])
    _assert_no_secret_material(updated.to_detail().to_dict())
    return repository.save(updated)


def _start_background_task(task: Callable[[], None]) -> None:
    start_runtime_task(task, name="barragan-inbound-channel-runner")


def _run_command(command: list[str], cwd: Path | None) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=barragan_subprocess_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=COMMAND_TIMEOUT_SECONDS)
        return subprocess.CompletedProcess(command, process.returncode, stdout=stdout, stderr=stderr)
    except subprocess.TimeoutExpired as exc:
        _terminate_process_group(process)
        stdout, stderr = process.communicate()
        return subprocess.CompletedProcess(
            command,
            124,
            stdout=_timeout_text(exc.stdout) + (stdout or ""),
            stderr=_timeout_text(exc.stderr) + (stderr or "") + f"\ncommand timed out after {COMMAND_TIMEOUT_SECONDS} seconds",
        )


def _terminate_process_group(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass


def _timeout_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _run_guarded_command(
    command: list[str],
    cwd: Path | None,
    runner: CommandRunner,
) -> subprocess.CompletedProcess[str]:
    try:
        return runner(command, cwd)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(command, 124, stdout=exc.stdout or "", stderr=exc.stderr or "command timed out")
    except OSError as exc:
        return subprocess.CompletedProcess(command, 1, stdout="", stderr=str(exc))


def _append_provider_ingress_events(
    repository: JobRepository,
    job: StoredJobRun,
    result: ProviderIngressSyncResult,
) -> StoredJobRun:
    current = job
    for event in result.events:
        current = _append_job_event(repository, current, event.level, event.message, event.data)
    return current


def _channel_with_job_status(
    channel: dict[str, Any] | dict[str, object],
    status: str,
    detail: str,
) -> dict[str, Any]:
    updated = dict(channel)
    validation = dict(updated.get("validation") or {})
    validation["status"] = status
    validation["detail"] = detail
    validation["lastCheckedAt"] = _now()
    updated["validation"] = validation
    updated["status"] = status
    _assert_no_secret_material(updated)
    return updated


def _channel_with_apply_state(
    spec: InboundChannelArtifactSpec,
    artifacts: InboundChannelArtifacts,
    *,
    route: InboundResolvedRoute,
    ingress_assessment: dict[str, Any] | None = None,
) -> dict[str, object]:
    safe_channel = _compact_channel_with_ingress_assessment(spec, artifacts, route, ingress_assessment)
    validation = dict(safe_channel.get("validation") or {})
    validation.update(
        {
            "status": APPLY_SUCCESS_STATUS,
            "detail": _pending_validation_detail(artifacts.validation),
        }
    )
    safe_channel["validation"] = validation
    safe_channel["status"] = APPLY_SUCCESS_STATUS
    _assert_no_secret_material(safe_channel)
    return safe_channel


def _channel_with_validation_state(
    spec: InboundChannelArtifactSpec,
    artifacts: InboundChannelArtifacts,
    validation_evidence: dict[str, Any],
    *,
    route: InboundResolvedRoute,
) -> dict[str, object]:
    safe_channel = _compact_channel_with_ingress_assessment(spec, artifacts, route)
    validation = dict(safe_channel.get("validation") or {})
    validation.update(
        _compact_validation_evidence(validation_evidence)
    )
    safe_channel["validation"] = validation
    safe_channel["status"] = validation_evidence["status"]
    _assert_no_secret_material(safe_channel)
    return safe_channel


def _channel_with_remove_state(
    spec: InboundChannelArtifactSpec,
    artifacts: InboundChannelArtifacts,
    *,
    route: InboundResolvedRoute,
) -> dict[str, object]:
    safe_channel = _compact_channel_with_ingress_assessment(spec, artifacts, route)
    validation = dict(safe_channel.get("validation") or {})
    validation.update(
        {
            "status": REMOVE_SUCCESS_STATUS,
            "detail": "Inbound channel nginx stream config and Barragan-owned firewall rules were removed.",
            "lastCheckedAt": _now(),
        }
    )
    safe_channel["validation"] = validation
    safe_channel["status"] = REMOVE_SUCCESS_STATUS
    _assert_no_secret_material(safe_channel)
    return safe_channel


def _inventory_targets(channel: dict[str, Any]) -> list[str]:
    targets = [
        _required(channel, "proxy"),
        _required(channel, "middle"),
        _required(channel, "edge"),
    ]
    terminates_on = _required(channel, "terminatesOn")
    if terminates_on not in targets:
        targets.append(terminates_on)
    return targets


def _merged_inbound_channels(
    engagement_id: str,
    channel_id: str,
    updated_channel: dict[str, Any] | dict[str, object] | None,
) -> list[dict[str, Any]]:
    overview = get_operations_overview(engagement_id)
    current_channels = overview.get("inboundChannels", []) if isinstance(overview, dict) else []
    merged: list[dict[str, Any]] = []
    found = False
    for channel in current_channels:
        if not isinstance(channel, dict):
            continue
        if str(channel.get("channelId") or "") == channel_id:
            found = True
            if updated_channel is not None:
                merged.append({**channel, **dict(updated_channel)})
            continue
        merged.append(dict(channel))
    if not found and updated_channel is not None:
        merged.append(dict(updated_channel))
    return merged


def _safe_command_result(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    body = {
        "command": _command_display([str(part) for part in result.args]),
        "returncode": result.returncode,
        "stdout": _sanitize_command_output(str(result.stdout or "")),
        "stderr": _sanitize_command_output(str(result.stderr or "")),
    }
    _assert_no_secret_material(body)
    return body


def _command_display(command: list[str]) -> list[str]:
    return [_sanitize_command_output(str(part)) for part in command]


def _sanitize_command_output(value: str) -> str:
    redacted = value
    for marker in SECRET_MARKERS:
        redacted = redacted.replace(marker, "[REDACTED]")
    for pattern, replacement in SECRET_OUTPUT_REDACTIONS:
        redacted = pattern.sub(replacement, redacted)
    if len(redacted) <= MAX_COMMAND_OUTPUT_CHARS:
        return redacted
    return redacted[:MAX_COMMAND_OUTPUT_CHARS] + "\n[truncated]"


def _validation_expected_text(validation: InboundValidationPlan) -> str:
    if validation.profile_type == "http":
        return HTTP_ROUTE_HEALTH_EXPECTATION
    return validation.expected_response or validation.expected_marker


def _validation_probe_host(route: InboundResolvedRoute) -> str:
    return "127.0.0.1"


def _validation_probe_shell_display(
    spec: InboundChannelArtifactSpec,
    validation: InboundValidationPlan,
    probe_host: str,
) -> str:
    request_text = validation.request_text or validation.expected_marker
    request = shlex.quote(request_text)
    safe_host = shlex.quote(probe_host)
    if validation.profile_type == "udp-send-receive":
        command = f"printf %s {request} | nc -u -w 5 {safe_host} {spec.external_port}"
    else:
        command = f"printf %s {request} | nc -w 5 {safe_host} {spec.external_port}"
    return _sanitize_command_output(command)


def _validation_evidence_detail(
    validation: InboundValidationPlan,
    expected_text: str,
    terminates_on: str,
    probe_host: str,
    external_port: int,
    matched: bool,
) -> str:
    endpoint = f"{probe_host}:{external_port}"
    if validation.profile_type == "temporary-listener":
        return (
            f"Observed expected marker {expected_text} on {terminates_on} after the selected edge probed ingress endpoint {endpoint}. External internet-to-edge ingress was not verified."
            if matched
            else f"Expected marker {expected_text} was not observed on {terminates_on}."
        )
    if validation.profile_type == "http":
        return (
            f"Observed a non-5xx HTTP response after the selected edge probed ingress endpoint {endpoint}. External internet-to-edge ingress was not verified."
            if matched
            else f"A non-5xx HTTP response was not observed after the selected edge probed ingress endpoint {endpoint}."
        )
    return (
        f"Observed expected {validation.profile_label} response text after the selected edge probed ingress endpoint {endpoint}. External internet-to-edge ingress was not verified."
        if matched
        else f"Expected {validation.profile_label} response text was not observed after the selected edge probed ingress endpoint {endpoint}."
    )


def _validation_observed_response(validation: InboundValidationPlan, expected_text: str, matched: bool) -> str:
    if validation.profile_type == "http":
        return "Observed a non-5xx HTTP response." if matched else "A non-5xx HTTP response was not observed."
    if matched:
        expected_kind = "marker" if validation.profile_type == "temporary-listener" else "response text"
        return _sanitize_command_output(f"Matched expected {expected_kind}: {expected_text}")
    expected_kind = "marker" if validation.profile_type == "temporary-listener" else "response text"
    return f"Expected {expected_kind} was not observed."


def _pending_validation_detail(validation: InboundValidationPlan) -> str:
    if validation.profile_type == "temporary-listener":
        return (
            "Inbound channel config applied; live validation has not run yet. "
            "Validate with a temporary listener on the termination host and a marker probe through the edge."
        )
    return (
        "Inbound channel config applied; live validation has not run yet. "
        f"Validate with the {validation.profile_label} transport-level send/expect probe from the selected edge through the inbound route."
    )


def _compact_validation_evidence(validation_evidence: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "profileType",
        "profileLabel",
        "validationProfile",
        "validationScope",
        "externalIngressVerified",
        "ingressEndpoint",
        "listenerOrigin",
        "listenerShellDisplay",
        "probeOrigin",
        "probeShellDisplay",
        "expectedMarker",
        "expectedResponse",
        "observedResponse",
        "status",
        "checkedAt",
        "lastCheckedAt",
        "detail",
    )
    compact = {}
    for key in keys:
        if key not in validation_evidence:
            continue
        value = validation_evidence.get(key)
        if value is None or value == "" or value == [] or value == {}:
            continue
        compact[key] = value
    compact["lastCheckedAt"] = validation_evidence["checkedAt"]
    return compact


def _termination_host(spec: InboundChannelArtifactSpec, core_ssh_private_key_file: str, route: InboundResolvedRoute) -> dict[str, str] | None:
    if spec.terminates_on == spec.proxy_hostname:
        return None
    termination = route.termination or InboundRouteTarget(spec.terminates_on, spec.terminates_on)
    proxy_jump = ""
    if termination.name != route.homebase.name and termination.ansible_host != route.homebase.ansible_host:
        proxy_jump = f"{_route_ssh_user(route.homebase)}@{route.homebase.ansible_host}"
    return {
        "name": spec.terminates_on,
        "ansibleHost": termination.ansible_host,
        "ansibleUser": _route_ssh_user(termination),
        "sshPrivateKeyFile": core_ssh_private_key_file,
        "proxyJump": proxy_jump,
    }


def _route_from_spec_names(spec: InboundChannelArtifactSpec) -> InboundResolvedRoute:
    return InboundResolvedRoute(
        homebase=InboundRouteTarget("homebase", "homebase", ssh_user=CORE_DEFAULT_SSH_USER),
        proxy=InboundRouteTarget(spec.proxy_hostname, spec.proxy_hostname, ssh_user=CORE_DEFAULT_SSH_USER),
        middle=InboundRouteTarget(spec.middle_hostname, spec.middle_hostname),
        edge=InboundRouteTarget(spec.edge_hostname, spec.edge_hostname),
        termination=None if spec.terminates_on == spec.proxy_hostname else InboundRouteTarget(spec.terminates_on, spec.terminates_on, ssh_user=CORE_DEFAULT_SSH_USER),
    )


def _local_sketch_key_path(spec: InboundChannelArtifactSpec, explicit_path: str | None) -> str:
    if explicit_path:
        return explicit_path
    return DEFAULT_LOCAL_SKETCH_KEY.format(engagement=spec.engagement)


def _render_inventory(
    spec: InboundChannelArtifactSpec,
    core_key: str,
    local_sketch_key: str,
    termination: dict[str, str] | None,
    route: InboundResolvedRoute,
    *, keyed_sketch_policy: bool = False,
) -> str:
    lines = [
        "# Managed by Barragan inbound channel apply preview.",
        "# Sketch access must use jump paths: homebase-proxy for middle, homebase-proxy-middle for edge.",
        "[selected_proxy]",
        _core_inventory_line(spec.proxy_hostname, route.proxy.ansible_host, core_key, user=_route_ssh_user(route.proxy), proxy_jump=f"{_route_ssh_user(route.homebase)}@{route.homebase.ansible_host}"),
        "",
        "[selected_middle]",
        _middle_inventory_line(spec, core_key, local_sketch_key, route),
        "",
        "[selected_edge]",
        _edge_inventory_line(spec, core_key, local_sketch_key, route),
        "",
    ]
    if is_managed_http_backend_site(spec):
        lines.extend([
            "[homebase_backend]",
            _core_inventory_line(
                route.homebase.name,
                route.homebase.ansible_host,
                core_key,
                user=_route_ssh_user(route.homebase),
            ),
            "",
        ])
    if termination is not None:
        lines.extend(["[termination_host]", _core_inventory_line(termination["name"], termination["ansibleHost"], core_key, user=termination["ansibleUser"], proxy_jump=termination["proxyJump"]), ""])
    lines.extend(
        [
            "[inbound_channel_targets:children]",
            "selected_proxy",
            "selected_middle",
            "selected_edge",
        ]
    )
    lines.extend(["", "[inbound_firewall_targets:children]",
                  "selected_proxy" if keyed_sketch_policy else "inbound_channel_targets"])
    if is_managed_http_backend_site(spec):
        lines.append("homebase_backend")
    if termination is not None:
        lines.append("termination_host")
    lines.append("")
    return "\n".join(lines)


def _render_ssh_config(
    spec: InboundChannelArtifactSpec,
    core_key: str,
    local_sketch_key: str,
    termination: dict[str, str] | None,
    route: InboundResolvedRoute,
) -> str:
    hosts = [
        _ssh_config_host(route.homebase.name, route.homebase.ansible_host, _route_ssh_user(route.homebase), core_key),
        _ssh_config_host(route.proxy.name, route.proxy.ansible_host, _route_ssh_user(route.proxy), core_key, proxy_jump=route.homebase.name),
        _ssh_config_host(route.middle.name, route.middle.ansible_host, SKETCH_INFRASTRUCTURE_ADMIN_USER, local_sketch_key, proxy_jump=route.proxy.name, allow_root=True),
        _ssh_config_host(route.edge.name, route.edge.ansible_host, SKETCH_INFRASTRUCTURE_ADMIN_USER, local_sketch_key, proxy_jump=route.middle.name, allow_root=True),
    ]
    if termination is not None and termination["name"] not in {route.homebase.name, route.proxy.name, route.middle.name, route.edge.name}:
        hosts.append(
            _ssh_config_host(
                termination["name"],
                termination["ansibleHost"],
                termination["ansibleUser"],
                termination["sshPrivateKeyFile"],
                proxy_jump=termination["proxyJump"] or "",
            )
        )
    return "\n\n".join(hosts) + "\n"


def _ssh_config_host(name: str, hostname: str, user: str, identity_file: str, *, proxy_jump: str = "", allow_root: bool = False) -> str:
    if not allow_root:
        _assert_non_root_ssh_user(user, name)
    lines = [
        f"Host {name}",
        f"    HostName {hostname}",
        f"    User {user}",
        f"    IdentityFile {identity_file}",
        "    IdentitiesOnly yes",
        "    UserKnownHostsFile /dev/null",
        "    StrictHostKeyChecking no",
        "    BatchMode yes",
        "    ConnectTimeout 10",
    ]
    if proxy_jump:
        lines.append(f"    ProxyJump {proxy_jump}")
    return "\n".join(lines)


def _render_preflight_playbook(spec: InboundChannelArtifactSpec, termination: dict[str, str] | None) -> str:
    sections = [
        "---",
        *_management_path_preflight_play("selected_proxy"),
        "",
        *_management_path_preflight_play("selected_middle"),
        "",
        *_management_path_preflight_play("selected_edge"),
    ]
    if termination is not None:
        sections.extend(["", *_management_path_preflight_play("termination_host")])
    if is_managed_http_backend_site(spec):
        sections.extend(["", *_management_path_preflight_play("homebase_backend")])
    return "\n".join(sections) + "\n"


def _render_prepare_playbook(spec: InboundChannelArtifactSpec) -> str:
    sections = ["---"]
    if not is_shared_web_ingress(spec):
        sections.extend(["", *_nginx_prepare_play("selected_proxy")])
    sections.extend([
        "",
        *_nginx_prepare_play("selected_middle"),
        "",
        *_nginx_prepare_play("selected_edge"),
    ])
    return "\n".join(sections) + "\n"


def _managed_http_backend_firewall_apply_play(
    spec: InboundChannelArtifactSpec,
    route: InboundResolvedRoute,
) -> list[str]:
    """Converge the private Homebase allowance for a typed proxy-side site.

    A typed HTTPS site terminates at the selected proxy front, so it has no
    generic ``termination_host`` entry.  Its service still runs on Homebase,
    however, and needs one narrow proxy-to-backend INPUT allowance.
    """

    backend_port = _backend_port(spec)
    proxy_ip = _managed_http_backend_firewall_source(route)
    return [
        "- name: Open managed HTTP backend Homebase firewall path",
        "  hosts: homebase_backend",
        "  gather_facts: false",
        "  become: true",
        "  vars:",
        f"    barragan_channel_id: {json.dumps(spec.channel_id)}",
        f"    barragan_backend_listen_port: {backend_port}",
        f"    barragan_backend_proxy_ip: {json.dumps(proxy_ip)}",
        "    barragan_backend_firewall_comment: barragan-inbound-{{ barragan_channel_id }}-backend",
        "  tasks:",
        *_wait_for_connection_task(),
        "    - name: Check Homebase UFW status",
        "      ansible.builtin.command: ufw status",
        "      register: barragan_backend_ufw_status",
        "      changed_when: false",
        "      failed_when: false",
        "    - name: Require restrictive managed HTTP backend Homebase input baseline",
        "      ansible.builtin.shell:",
        "        cmd: |",
        "          set -eu",
        "          if printf '%s\\n' \"{{ barragan_backend_ufw_status.stdout }}\" | grep -Fq 'Status: active'; then",
        "            ufw status verbose | grep -Eq '^Default: (deny|reject) \\(incoming\\)(,|$)'",
        "          else",
        "            iptables -S INPUT | grep -Fx -- '-P INPUT DROP' >/dev/null || iptables -S INPUT | grep -Eq '^-A INPUT -j (DROP|REJECT)([[:space:]]|$)'",
        "          fi",
        "      changed_when: false",
        "    - name: Allow selected proxy to managed HTTP backend with UFW",
        "      ansible.builtin.shell:",
        "        cmd: |",
        "          set -eu",
        "          ufw status numbered | grep -F \"{{ barragan_backend_firewall_comment }}\" | sed -n 's/^\\[[[:space:]]*\\([0-9][0-9]*\\)\\].*/\\1/p' | sort -rn | while read -r rule; do",
        "            [ -n \"${rule}\" ] && yes | ufw delete \"${rule}\"",
        "          done",
        "          ufw insert 1 allow proto tcp from {{ barragan_backend_proxy_ip }} to any port {{ barragan_backend_listen_port }} comment {{ barragan_backend_firewall_comment }}",
        "      when: \"'Status: active' in barragan_backend_ufw_status.stdout\"",
        "    - name: Apply selected proxy managed HTTP backend allow with iptables",
        "      ansible.builtin.shell:",
        "        cmd: |",
        "          set -eu",
        "          comment='{{ barragan_backend_firewall_comment }}'",
        "          for owned_comment in \"${comment}\" \"${comment}-deny\"; do",
        "            while rule_number=$(iptables -S INPUT | grep -F -- '-A INPUT ' | grep -n -F -e \"--comment ${owned_comment} \" -e \"--comment \\\"${owned_comment}\\\" \" | head -n 1 | cut -d: -f1); do",
        "              [ -n \"${rule_number}\" ] || break",
        "              iptables -D INPUT \"${rule_number}\"",
        "            done",
        "          done",
        "          iptables -I INPUT 1 -s {{ barragan_backend_proxy_ip }} -p tcp --dport {{ barragan_backend_listen_port }} -m comment --comment \"${comment}\" -j ACCEPT",
        "      when: \"'Status: active' not in barragan_backend_ufw_status.stdout\"",
        "    - name: Persist managed HTTP backend Homebase iptables rules",
        "      ansible.builtin.shell: |",
        "        set -eu",
        "        if command -v netfilter-persistent >/dev/null 2>&1; then",
        "          netfilter-persistent save",
        "        elif command -v iptables-save >/dev/null 2>&1 && [ -d /etc/iptables ]; then",
        "          iptables-save -f /etc/iptables/rules.v4",
        "        fi",
        "      changed_when: false",
        "      when: \"'Status: active' not in barragan_backend_ufw_status.stdout\"",
        "",
    ]


def _render_apply_playbook(
    spec: InboundChannelArtifactSpec,
    artifacts: InboundChannelArtifacts,
    termination: dict[str, str] | None,
    route: InboundResolvedRoute,
    *,
    request_header_gate: Mapping[str, Any] | None = None,
    request_header_gate_playbook: str = "",
    backend_authorization: InboundBackendAuthorization | None = None,
    backend_request_gate_policy_path: str | None = None,
    retained_gate_engagement_id: str | None = None,
) -> str:
    if (spec.mode == "http-openresty" and not is_native_static_web_route(spec)) or is_managed_http_backend_site(spec):
        nginx_plays = [
            *_openresty_http_route_apply_play(
                spec,
                artifacts,
                route,
                request_header_gate=request_header_gate,
                backend_authorization=backend_authorization,
                backend_request_gate_policy_path=backend_request_gate_policy_path,
                retained_gate_engagement_id=retained_gate_engagement_id,
            ),
            "",
        ]
    else:
        nginx_plays = [] if is_shared_web_ingress(spec) else [*_nginx_prepare_play("selected_proxy"), "", *_nginx_channel_apply_play("selected_proxy", artifacts.proxy_stream), ""]
    nginx_plays.extend([
        *_nginx_prepare_play("selected_middle"),
        "",
        *_nginx_channel_apply_play("selected_middle", artifacts.middle_stream),
        "",
        *_nginx_prepare_play("selected_edge"),
        "",
        *_nginx_channel_apply_play("selected_edge", artifacts.edge_stream),
    ])
    nginx_plays.extend(["", *_proxy_runtime_registry_upsert_play(spec, artifacts)])
    if request_header_gate_playbook:
        gate_lines = request_header_gate_playbook.splitlines()
        if gate_lines and gate_lines[0].strip() == "---":
            gate_lines = gate_lines[1:]
        nginx_plays.extend(["", *gate_lines])
    sections = ["---"]
    if is_managed_http_backend_site(spec):
        sections.extend([*_managed_http_backend_firewall_apply_play(spec, route)])
    sections.extend([
        "- name: Open inbound channel firewall paths",
        "  hosts: inbound_firewall_targets",
        "  gather_facts: false",
        "  become: true",
        "  vars:",
        f"    barragan_channel_id: {json.dumps(spec.channel_id)}",
        f"    barragan_external_port: {spec.external_port}",
        f"    barragan_transport_protocol: {json.dumps(_transport_protocol(spec))}",
        f"    barragan_edge_listen_port: {spec.external_port}",
        f"    barragan_middle_listen_port: {_middle_relay_port(spec)}",
        f"    barragan_proxy_listen_port: {_proxy_relay_port(spec)}",
        f"    barragan_edge_ip: {json.dumps(route.edge.public_ip or route.edge.ansible_host)}",
        f"    barragan_middle_ip: {json.dumps(route.middle.public_ip or route.middle.ansible_host)}",
        *(
            [
                f"    barragan_termination_listen_port: {spec.internal_port}",
                f"    barragan_proxy_ip: {json.dumps(_termination_firewall_source(route))}",
            ]
            if termination is not None
            else []
        ),
        "  tasks:",
        *_wait_for_connection_task(),
        "    - name: Check UFW status",
        "      ansible.builtin.command: ufw status",
        "      register: barragan_ufw_status",
        "      changed_when: false",
        "      failed_when: false",
        *(
            [
                "    - name: Require restrictive termination host input baseline",
                "      ansible.builtin.shell:",
                "        cmd: |",
                "          set -eu",
                "          if printf '%s\\n' \"{{ barragan_ufw_status.stdout }}\" | grep -Fq 'Status: active'; then",
                "            ufw status verbose | grep -Eq '^Default: (deny|reject) \\(incoming\\)(,|$)'",
                "          else",
                "            iptables -S INPUT | grep -Fx -- '-P INPUT DROP' >/dev/null || iptables -S INPUT | grep -Eq '^-A INPUT -j (DROP|REJECT)([[:space:]]|$)'",
                "          fi",
                "      changed_when: false",
                "      when: inventory_hostname in groups['termination_host']",
            ]
            if termination is not None
            else []
        ),
        "    - name: Allow public edge listener with UFW",
        "      ansible.builtin.command: \"ufw allow proto {{ barragan_transport_protocol }} to any port {{ barragan_edge_listen_port }} comment barragan-inbound-{{ barragan_channel_id }}-edge\"",
        "      when: \"inventory_hostname in groups['selected_edge'] and 'Status: active' in barragan_ufw_status.stdout\"",
        "    - name: Restrict middle listener to the selected edge with UFW",
        "      ansible.builtin.shell:",
        "        cmd: |",
        "          set -eu",
        "          ufw status numbered | grep -F 'barragan-inbound-{{ barragan_channel_id }}-middle' | sed -n 's/^\\[[[:space:]]*\\([0-9][0-9]*\\)\\].*/\\1/p' | sort -rn | while read -r rule; do",
        "            [ -n \"${rule}\" ] && yes | ufw delete \"${rule}\"",
        "          done",
        "          ufw insert 1 deny proto {{ barragan_transport_protocol }} to any port {{ barragan_middle_listen_port }} comment barragan-inbound-{{ barragan_channel_id }}-middle-deny",
        "          ufw insert 1 allow proto {{ barragan_transport_protocol }} from {{ barragan_edge_ip }} to any port {{ barragan_middle_listen_port }} comment barragan-inbound-{{ barragan_channel_id }}-middle",
        "      when: \"inventory_hostname in groups['selected_middle'] and 'Status: active' in barragan_ufw_status.stdout\"",
        "    - name: Restrict proxy listener to the selected middle with UFW",
        "      ansible.builtin.shell:",
        "        cmd: |",
        "          set -eu",
        "          ufw status numbered | grep -F 'barragan-inbound-{{ barragan_channel_id }}-proxy' | sed -n 's/^\\[[[:space:]]*\\([0-9][0-9]*\\)\\].*/\\1/p' | sort -rn | while read -r rule; do",
        "            [ -n \"${rule}\" ] && yes | ufw delete \"${rule}\"",
        "          done",
        "          ufw insert 1 deny proto {{ barragan_transport_protocol }} to any port {{ barragan_proxy_listen_port }} comment barragan-inbound-{{ barragan_channel_id }}-proxy-deny",
        "          ufw insert 1 allow proto {{ barragan_transport_protocol }} from {{ barragan_middle_ip }} to any port {{ barragan_proxy_listen_port }} comment barragan-inbound-{{ barragan_channel_id }}-proxy",
        "      when: \"inventory_hostname in groups['selected_proxy'] and 'Status: active' in barragan_ufw_status.stdout\"",
        *(
            [
                "    - name: Restrict termination listener to the selected proxy with UFW",
                "      ansible.builtin.shell:",
                "        cmd: |",
                "          set -eu",
                "          ufw status numbered | grep -F 'barragan-inbound-{{ barragan_channel_id }}-termination' | sed -n 's/^\\[[[:space:]]*\\([0-9][0-9]*\\)\\].*/\\1/p' | sort -rn | while read -r rule; do",
                "            [ -n \"${rule}\" ] && yes | ufw delete \"${rule}\"",
                "          done",
                "          ufw insert 1 allow proto {{ barragan_transport_protocol }} from {{ barragan_proxy_ip }} to any port {{ barragan_termination_listen_port }} comment barragan-inbound-{{ barragan_channel_id }}-termination",
                "      when: \"inventory_hostname in groups['termination_host'] and 'Status: active' in barragan_ufw_status.stdout\"",
            ]
            if termination is not None
            else []
        ),
        "    - name: Allow channel listener with iptables when UFW is inactive",
        "      ansible.builtin.shell:",
        "        cmd: |",
        "          set -eu",
        "          source_arg=''",
        "          rule_role='edge'",
        "          rule_port='{{ barragan_edge_listen_port }}'",
        "          if printf '%s\\n' \"{{ groups['selected_middle'] | default([]) | join('\\n') }}\" | grep -Fx -- \"{{ inventory_hostname }}\" >/dev/null; then",
        "            source_arg='-s {{ barragan_edge_ip }}'",
        "            rule_role='middle'",
        "            rule_port='{{ barragan_middle_listen_port }}'",
        "          elif printf '%s\\n' \"{{ groups['selected_proxy'] | default([]) | join('\\n') }}\" | grep -Fx -- \"{{ inventory_hostname }}\" >/dev/null; then",
        "            source_arg='-s {{ barragan_middle_ip }}'",
        "            rule_role='proxy'",
        "            rule_port='{{ barragan_proxy_listen_port }}'",
        "          fi",
        "          comment=\"barragan-inbound-{{ barragan_channel_id }}-${rule_role}\"",
        "          deny_comment=\"${comment}-deny\"",
        "          if [ -n \"${source_arg}\" ] && ! iptables -C INPUT -p {{ barragan_transport_protocol }} --dport ${rule_port} -m comment --comment \"${deny_comment}\" -j DROP 2>/dev/null; then",
        "            while iptables -C INPUT ${source_arg} -p {{ barragan_transport_protocol }} --dport ${rule_port} -m comment --comment \"${comment}\" -j ACCEPT 2>/dev/null; do",
        "              iptables -D INPUT ${source_arg} -p {{ barragan_transport_protocol }} --dport ${rule_port} -m comment --comment \"${comment}\" -j ACCEPT",
        "            done",
        "            iptables -I INPUT 1 -p {{ barragan_transport_protocol }} --dport ${rule_port} -m comment --comment \"${deny_comment}\" -j DROP",
        "          fi",
        "          if ! iptables -C INPUT ${source_arg} -p {{ barragan_transport_protocol }} --dport ${rule_port} -m comment --comment \"${comment}\" -j ACCEPT 2>/dev/null; then",
        "            iptables -I INPUT 1 ${source_arg} -p {{ barragan_transport_protocol }} --dport ${rule_port} -m comment --comment \"${comment}\" -j ACCEPT",
        "          fi",
        "      when: \"'Status: active' not in barragan_ufw_status.stdout and inventory_hostname in groups['inbound_channel_targets']\"",
        *(
            [
                "    - name: Apply selected proxy termination allow with iptables",
                "      ansible.builtin.shell:",
                "        cmd: |",
                "          set -eu",
                "          comment='barragan-inbound-{{ barragan_channel_id }}-termination'",
                "          for owned_comment in \"${comment}\" \"${comment}-deny\"; do",
                "            while rule_number=$(iptables -S INPUT | grep -F -- '-A INPUT ' | grep -n -F -e \"--comment ${owned_comment} \" -e \"--comment \\\"${owned_comment}\\\" \" | head -n 1 | cut -d: -f1); do",
                "              [ -n \"${rule_number}\" ] || break",
                "              iptables -D INPUT \"${rule_number}\"",
                "            done",
                "          done",
                "          iptables -I INPUT 1 -s {{ barragan_proxy_ip }} -p {{ barragan_transport_protocol }} --dport {{ barragan_termination_listen_port }} -m comment --comment \"${comment}\" -j ACCEPT",
                "      when: \"inventory_hostname in groups['termination_host'] and 'Status: active' not in barragan_ufw_status.stdout\"",
            ]
            if termination is not None
            else []
        ),
        "    - name: Persist iptables rules when netfilter-persistent is available",
        "      ansible.builtin.command: netfilter-persistent save",
        "      changed_when: true",
        "      failed_when: false",
        "      when: \"'Status: active' not in barragan_ufw_status.stdout\"",
        "",
        *nginx_plays,
        "",
        "- name: Verify inbound channel listeners",
        "  hosts: inbound_channel_targets",
        "  gather_facts: false",
        "  become: true",
        "  vars:",
        f"    barragan_transport_protocol: {json.dumps(_transport_protocol(spec))}",
        f"    barragan_edge_listen_port: {spec.external_port}",
        f"    barragan_middle_listen_port: {_middle_relay_port(spec)}",
        f"    barragan_proxy_listen_port: {_proxy_relay_port(spec)}",
        "  tasks:",
        "    - name: Select inbound listener port for this host",
        "      ansible.builtin.set_fact:",
        "        barragan_role_listen_port: \"{{ barragan_edge_listen_port if inventory_hostname in groups['selected_edge'] else barragan_middle_listen_port if inventory_hostname in groups['selected_middle'] else barragan_proxy_listen_port }}\"",
        "    - name: Verify TCP inbound listener is bound",
        "      ansible.builtin.shell:",
        "        cmd: |",
        "          for attempt in $(seq 1 10); do",
        "            ss -H -ltn | awk '{print $4}' | grep -Eq '(^|:){{ barragan_role_listen_port }}$' && exit 0",
        "            sleep 1",
        "          done",
        "          ss -ltn",
        "          exit 1",
        "      changed_when: false",
        "      when: barragan_transport_protocol == 'tcp'",
        "    - name: Verify UDP inbound listener",
        "      ansible.builtin.shell:",
        "        cmd: |",
        "          for attempt in $(seq 1 10); do",
        "            ss -H -lun | awk '{print $4}' | grep -Eq '(^|:){{ barragan_role_listen_port }}$' && exit 0",
        "            sleep 1",
        "          done",
        "          ss -lun",
        "          exit 1",
        "      changed_when: false",
        "      when: barragan_transport_protocol == 'udp'",
    ])
    return "\n".join(sections) + "\n"


def _openresty_http_route_apply_play(
    spec: InboundChannelArtifactSpec,
    artifacts: InboundChannelArtifacts,
    route: InboundResolvedRoute,
    *,
    request_header_gate: Mapping[str, Any] | None = None,
    backend_authorization: InboundBackendAuthorization | None = None,
    backend_request_gate_policy_path: str | None = None,
    retained_gate_engagement_id: str | None = None,
) -> list[str]:
    route_name = _managed_http_backend_site_name(spec) if is_managed_http_backend_site(spec) else _safe_http_route_name(spec.channel_id)
    service_name = http_backend_service_name(spec.channel_id)
    managed_tls_site = is_managed_http_backend_site(spec)
    backend_host = (
        route.homebase.private_ip or route.homebase.public_ip or route.homebase.ansible_host
        if managed_tls_site
        else _proxy_upstream_host(spec, route) if route.termination is not None else "host.docker.internal"
    )
    authorization_inventory_group = "homebase_backend" if managed_tls_site else "termination_host"
    site_config = _render_http_route_site_config(
        backend_host,
        _backend_port(spec) if managed_tls_site else spec.internal_port,
        request_header_gate=request_header_gate,
        backend_authorization=backend_authorization,
        backend_authorization_inventory_group=authorization_inventory_group,
    )
    from app.services.inbound_request_header_gate import (
        render_http_backend_effective_config_assertion_tasks,
        render_request_header_gate_http_runtime,
    )

    max_request_body_mb = int((request_header_gate or {}).get("maxRequestBodyMb", 500))
    site_compose = _render_http_route_site_compose(route_name, service_name)
    sections: list[str] = []
    if backend_authorization is not None:
        sections.extend(
            [
                *render_backend_authorization_fact_play(
                    backend_authorization,
                    inventory_group=authorization_inventory_group,
                ),
                "",
            ]
        )
    if (
        backend_request_gate_policy_path is not None
        and retained_gate_engagement_id is not None
        and backend_authorization is not None
        and backend_authorization.capability_id == "go-simple-upload-server"
        and request_header_gate is None
    ):
        policy_path = Path(backend_request_gate_policy_path)
        policy_directory = policy_path.parent
        sections.extend(
            [
                "- name: Retain GoSUS request gate for operator use",
                "  hosts: selected_proxy",
                "  gather_facts: false",
                "  become: true",
                "  tasks:",
                "    - name: Prepare retained GoSUS request gate directory",
                "      ansible.builtin.file:",
                f"        path: {json.dumps(str(policy_directory))}",
                "        state: directory",
                "        mode: '0700'",
                "      delegate_to: localhost",
                "      become: false",
                "      no_log: true",
                "    - name: Retain resolved GoSUS request gate",
                "      ansible.builtin.copy:",
                f"        dest: {json.dumps(str(policy_path))}",
                "        mode: '0600'",
                "        content: |",
                "          {",
                "            \"schema\": \"barragan/inbound-request-header-gate/v1\",",
                "            \"managedBy\": \"barragan\",",
                f"            \"engagementId\": {json.dumps(retained_gate_engagement_id)},",
                f"            \"channelId\": {json.dumps(spec.channel_id)},",
                "            \"active\": {",
                "              \"enabled\": true,",
                "              \"headerName\": \"Authorization\",",
                f"              \"token\": \"{{{{ hostvars[groups['{authorization_inventory_group}'][0]].barragan_inbound_backend_authorization | regex_replace('^Bearer ', '') }}}}\",",
                "              \"updatedAt\": \"managed-go-sus-route\",",
                "              \"maxRequestBodyMb\": 500",
                "            },",
                "            \"pending\": null,",
                "            \"pendingJobId\": null",
                "          }",
                "      delegate_to: localhost",
                "      become: false",
                "      no_log: true",
                "    - name: Verify retained GoSUS request gate",
                "      ansible.builtin.stat:",
                f"        path: {json.dumps(str(policy_path))}",
                "      register: barragan_gosus_gate_retained_file",
                "      delegate_to: localhost",
                "      become: false",
                "      no_log: true",
                "    - name: Require retained GoSUS request gate",
                "      ansible.builtin.assert:",
                "        that:",
                "          - barragan_gosus_gate_retained_file.stat.isreg | default(false)",
                "          - not (barragan_gosus_gate_retained_file.stat.islnk | default(false))",
                "        fail_msg: GoSUS request gate could not be retained for operator use.",
                "      delegate_to: localhost",
                "      become: false",
                "      no_log: true",
                "",
            ]
        )
    sections.extend([
        "- name: Bind HTTP backend route on shared proxy OpenResty stack",
        "  hosts: selected_proxy",
        "  gather_facts: false",
        "  become: true",
        "  tasks:",
        *_wait_for_connection_task(),
        "    - name: Check shared front ownership before mutation",
        "      ansible.builtin.shell:",
        "        cmd: python3 -c \"import json,pathlib,sys; root=pathlib.Path('/opt/web'); owner=root/'.barragan-stack.json'; expected={'managedBy':'barragan','stackModel':'containerized-openresty-v1'}; nonempty=root.exists() and any(root.iterdir()); ok=(not nonempty) or (owner.exists() and json.loads(owner.read_text()) == expected); sys.exit(0 if ok else 1)\"",
        "      register: barragan_front_ownership",
        "      changed_when: false",
        "      failed_when: false",
        "    - name: Refuse to mutate an unowned shared front stack",
        "      ansible.builtin.assert:",
        "        that:",
        "          - barragan_front_ownership.rc == 0",
        "        fail_msg: Barragan will not mutate /opt/web unless its stack manifest declares Barragan ownership.",
        "    - name: Refuse shared front TCP port collision",
        "      ansible.builtin.shell:",
        "        cmd: |",
        "          set -eu",
        "          # A previous Barragan web route may already have converged",
        "          # the owned front container.  Its listeners are the stack we",
        "          # are updating, not a foreign host-process collision.",
        "          if [ -f /opt/web/.barragan-stack.json ]; then",
        "            exit 0",
        "          fi",
        "          if ss -H -ltn '( sport = :80 or sport = :443 )' | grep -q .; then",
        "            echo 'A host process already owns TCP port 80 or 443; Barragan will not stop it to start the shared OpenResty front.' >&2",
        "            exit 1",
        "          fi",
        "      changed_when: false",
        "    - name: Verify upstream Docker Compose runtime",
        "      ansible.builtin.command:",
        "        argv: [docker, compose, version]",
        "      changed_when: false",
        "    - name: Ensure Docker service is running",
        "      ansible.builtin.systemd:",
        "        name: docker",
        "        state: started",
        "        enabled: true",
        "    - name: Wait for selected backend listener",
        "      ansible.builtin.wait_for:",
        f"        host: {json.dumps(backend_host) if managed_tls_site or route.termination is not None else '127.0.0.1'}",
        f"        port: {_backend_port(spec) if managed_tls_site else spec.internal_port}",
        "        timeout: 15",
        "    - name: Create shared OpenResty route directories",
        "      ansible.builtin.file:",
        "        path: \"{{ item }}\"",
        "        state: directory",
        "        owner: root",
        "        group: redteam",
        "        mode: '0775'",
        "      loop:",
        "        - /opt/web",
        "        - /opt/web/http",
        "        - /opt/web/streams",
        "        - /opt/web/tls",
        "        - /opt/web/sites",
        f"        - /opt/web/inbound/{route_name}/conf",
        "    - name: Write shared front OpenResty config",
        "      ansible.builtin.copy:",
        "        dest: /opt/web/nginx.conf",
        "        mode: '0644'",
        "        content: |",
        _indent_block(_render_shared_front_openresty_config(), 10),
        "    - name: Write shared front compose file",
        "      ansible.builtin.copy:",
        "        dest: /opt/web/docker-compose.yml",
        "        mode: '0644'",
        "        content: |",
        _indent_block(_render_shared_front_compose(), 10),
        "    - name: Write HTTP backend proxy config",
        "      ansible.builtin.copy:",
        f"        dest: /opt/web/inbound/{route_name}/conf/default.conf",
        "        mode: '0644'",
        "        content: |",
        _indent_block(site_config, 10),
        "    - name: Write HTTP backend request-header gate runtime",
        "      ansible.builtin.copy:",
        f"        dest: /opt/web/inbound/{route_name}/conf/00-request-header-gate-00-runtime.conf",
        "        owner: root",
        "        group: redteam",
        "        mode: '0640'",
        "        content: |",
        _indent_block(render_request_header_gate_http_runtime(), 10),
        *(
            [
                "    - name: Retain the typed HTTP backend's unbound configuration",
                "      ansible.builtin.copy:",
                f"        src: /opt/web/inbound/{route_name}/conf/default.conf",
                f"        dest: /opt/web/inbound/{route_name}/conf/default.conf.barragan-unbound",
                "        remote_src: true",
                "        force: false",
                "        owner: root",
                "        group: redteam",
                "        mode: '0640'",
            ]
            if managed_tls_site
            else []
        ),
        "    - name: Write HTTP backend proxy compose fragment",
        "      ansible.builtin.copy:",
        f"        dest: /opt/web/sites/{route_name}.compose.yml",
        "        mode: '0644'",
        "        content: |",
        _indent_block(site_compose, 10),
        "    - name: Write HTTP Host route",
        "      ansible.builtin.copy:",
        f"        dest: {artifacts.proxy_stream.target}",
        "        mode: '0644'",
        "        content: |",
        _indent_block(artifacts.proxy_stream.content, 10),
        "    - name: Record shared front ownership",
        "      ansible.builtin.copy:",
        "        dest: /opt/web/.barragan-stack.json",
        "        mode: '0640'",
        "        content: '{\"managedBy\":\"barragan\",\"stackModel\":\"containerized-openresty-v1\"}'",
        "    - name: Converge shared front OpenResty",
        "      ansible.builtin.command:",
        "        argv: [docker, compose, -f, /opt/web/docker-compose.yml, up, -d, reverse-proxy]",
        "    - name: Remove only the selected generic HTTP backend containers before convergence",
        "      ansible.builtin.command:",
        f"        argv: [docker, rm, -f, {service_name}, web_{service_name}_1]",
        "      register: barragan_selected_http_backend_remove",
        "      changed_when: barragan_selected_http_backend_remove.rc == 0",
        "      failed_when: false",
        "    - name: Find renamed selected generic HTTP backend Compose containers",
        "      ansible.builtin.command:",
        f"        argv: [docker, ps, -aq, --filter, \"label=com.docker.compose.project=web\", --filter, \"label=com.docker.compose.service={service_name}\"]",
        "      register: barragan_selected_http_backend_compose_containers",
        "      changed_when: false",
        "    - name: Remove renamed selected generic HTTP backend Compose containers",
        "      ansible.builtin.command:",
        "        argv: [docker, rm, -f, \"{{ item }}\"]",
        "      loop: \"{{ barragan_selected_http_backend_compose_containers.stdout_lines }}\"",
        "      when: item | length > 0",
        "    - name: Converge generic HTTP backend proxy",
        "      ansible.builtin.command:",
        f"        argv: [docker, compose, -f, /opt/web/docker-compose.yml, -f, /opt/web/sites/{route_name}.compose.yml, up, -d, {service_name}]",
        "    - name: Validate shared front route config",
        "      ansible.builtin.command:",
        "        argv: [docker, compose, -f, /opt/web/docker-compose.yml, exec, -T, reverse-proxy, openresty, -t]",
        "    - name: Reload shared front routes",
        "      ansible.builtin.command:",
        "        argv: [docker, compose, -f, /opt/web/docker-compose.yml, exec, -T, reverse-proxy, openresty, -s, reload]",
        "    - name: Validate generic HTTP backend proxy",
        "      ansible.builtin.command:",
        f"        argv: [docker, exec, {service_name}, openresty, -t]",
        "      changed_when: false",
        *render_http_backend_effective_config_assertion_tasks(
            service_name=service_name,
            config_path=f"/opt/web/inbound/{route_name}/conf/default.conf",
            expected_body_size_bytes=max_request_body_mb * 1_000_000,
            register_prefix="barragan_http_route",
        ),
        "    - name: Reload generic HTTP backend proxy",
        "      ansible.builtin.command:",
        f"        argv: [docker, exec, {service_name}, openresty, -s, reload]",
    ])
    return sections


def _proxy_runtime_registry_entry(
    spec: InboundChannelArtifactSpec,
    artifacts: InboundChannelArtifacts,
) -> dict[str, Any]:
    """Describe only proxy-local, nonsecret Barragan-owned route output."""

    shared_web = is_shared_web_ingress(spec)
    artifact_paths = [artifacts.proxy_stream.target, PROXY_RUNTIME_REGISTRY_PATH]
    entry: dict[str, Any] = {
        "routeId": spec.channel_id,
        "domain": spec.domain if shared_web else None,
        "mode": spec.mode,
        "ownership": {
            "managedBy": "barragan",
            "routingOwner": "shared-web-ingress" if shared_web else "dedicated-stream",
        },
        "sharedListeners": (
            [{"protocol": _transport_protocol(spec), "port": spec.external_port}]
            if shared_web
            else []
        ),
        "artifactPaths": artifact_paths,
    }
    if shared_web:
        if is_native_static_web_route(spec):
            site_name = spec.service_id.removeprefix("web-")
            service_name = f"web_{site_name.replace('-', '_')}"
            backend = {"kind": "static-content", "containerPort": 8081}
        else:
            route_name = (
                _managed_http_backend_site_name(spec)
                if is_managed_http_backend_site(spec)
                else _safe_http_route_name(spec.channel_id)
            )
            service_name = http_backend_service_name(spec.channel_id)
            artifact_paths.extend(
                [
                    f"/opt/web/sites/{route_name}.compose.yml",
                    f"/opt/web/inbound/{route_name}/conf/default.conf",
                ]
            )
            backend = {
                "kind": "private-http-service",
                "hostRole": "homebase" if is_managed_http_backend_site(spec) else "termination",
                "port": _backend_port(spec) if is_managed_http_backend_site(spec) else spec.internal_port,
            }
        entry["site"] = {
            "serviceName": service_name,
            "containerPort": 8081,
            "backend": backend,
        }
        entry["failClosedDefault"] = "127.0.0.1:9"
    return entry


def _proxy_runtime_registry_upsert_play(
    spec: InboundChannelArtifactSpec,
    artifacts: InboundChannelArtifacts,
) -> list[str]:
    entry = _proxy_runtime_registry_entry(spec, artifacts)
    command = _proxy_runtime_registry_command(
        operation="upsert",
        channel_id=spec.channel_id,
        entry=entry,
    )
    return [
        "- name: Record sanitized Barragan-managed proxy routes",
        "  hosts: selected_proxy",
        "  gather_facts: false",
        "  become: true",
        "  vars:",
        f"    barragan_route_entry: {json.dumps(entry, sort_keys=True)}",
        "  tasks:",
        *_wait_for_connection_task(),
        *_proxy_runtime_registry_update_tasks(command),
    ]


def _proxy_runtime_registry_remove_play(channel_id: str) -> list[str]:
    command = _proxy_runtime_registry_command(operation="remove", channel_id=channel_id)
    return [
        "- name: Remove selected route from sanitized proxy registry",
        "  hosts: selected_proxy",
        "  gather_facts: false",
        "  become: true",
        "  tasks:",
        *_wait_for_connection_task(),
        *_proxy_runtime_registry_update_tasks(command),
    ]


def _proxy_runtime_registry_update_tasks(command: str) -> list[str]:
    return [
        "    - name: Ensure root-owned Barragan managed-runtime directory exists",
        "      ansible.builtin.file:",
        f"        path: {PROXY_RUNTIME_REGISTRY_DIR}",
        "        state: directory",
        "        owner: root",
        "        group: root",
        "        mode: '0755'",
        "      failed_when: false",
        "    - name: Converge sanitized proxy route registry under a dedicated lock",
        "      ansible.builtin.shell:",
        "        executable: /bin/bash",
        "        cmd: |",
        *[f"          {line}" for line in command.splitlines()],
        "      register: barragan_route_registry_update",
        "      changed_when: barragan_route_registry_update.rc == 0 and 'unchanged' not in barragan_route_registry_update.stdout",
        # Route/firewall convergence is authoritative. This operator-facing
        # registry is best-effort metadata and must never strand rollback.
        "      failed_when: false",
        "    - name: Report sanitized proxy route registry convergence warning",
        "      ansible.builtin.debug:",
        "        msg: Barragan route metadata could not be updated; route convergence was not rolled back.",
        "      when: barragan_route_registry_update.rc != 0",
    ]


def _proxy_runtime_registry_command(
    *,
    operation: str,
    channel_id: str,
    entry: Mapping[str, Any] | None = None,
    registry_path: str = PROXY_RUNTIME_REGISTRY_PATH,
    lock_path: str = PROXY_RUNTIME_REGISTRY_LOCK_PATH,
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> str:
    """Render the proxy-local atomic registry updater.

    Every inbound mode uses this same dedicated lock.  The encoded payload is
    sanitized before rendering and avoids shell interpolation of route data.
    Optional paths exist only so focused tests can exercise the exact script.
    """

    if operation not in {"upsert", "remove"}:
        raise ValueError(f"Unsupported proxy route registry operation: {operation}")
    if operation == "upsert" and entry is None:
        raise ValueError("Proxy route registry upsert requires an entry")
    payload = base64.b64encode(
        json.dumps(
            {"operation": operation, "routeId": channel_id, "entry": entry},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).decode("ascii")
    python_script = f'''import base64
import fcntl
import json
import os
from pathlib import Path
import stat
import tempfile

target = Path({json.dumps(registry_path)})
lock_path = Path({json.dumps(lock_path)})
request = json.loads(base64.b64decode({json.dumps(payload)}).decode("utf-8"))
if target.parent != lock_path.parent:
    raise OSError("registry and lock must share one trusted directory")
parent_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
parent_stat = os.fstat(parent_fd)
if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != {owner_uid} or parent_stat.st_gid != {owner_gid} or (parent_stat.st_mode & 0o022):
    os.close(parent_fd)
    raise OSError("registry directory is not owned and writable only by its trusted owner")
lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
try:
    if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
        raise OSError("registry lock is not a regular file")
    os.fchmod(lock_fd, 0o600)
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    recovered = False
    existing_bytes = b""
    routes = []
    try:
        existing_fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            if not stat.S_ISREG(os.fstat(existing_fd).st_mode):
                raise OSError("registry is not a regular file")
            with os.fdopen(existing_fd, "rb", closefd=False) as stream:
                existing_bytes = stream.read()
        finally:
            os.close(existing_fd)
        document = json.loads(existing_bytes.decode("utf-8"))
        if not isinstance(document, dict) or document.get("schemaVersion") != 1 or document.get("managedBy") != "barragan" or not isinstance(document.get("routes"), list):
            raise ValueError("unsupported registry document")
        routes = [row for row in document["routes"] if isinstance(row, dict) and isinstance(row.get("routeId"), str) and row["routeId"]]
    except FileNotFoundError:
        pass
    except (OSError, UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError):
        recovered = True
        routes = []

    route_id = request["routeId"]
    routes = [row for row in routes if row["routeId"] != route_id]
    if request["operation"] == "upsert":
        routes.append(request["entry"])
    routes.sort(key=lambda row: row["routeId"])
    document = {{"schemaVersion": 1, "managedBy": "barragan", "routes": routes}}
    desired_bytes = (json.dumps(document, indent=2, sort_keys=True) + "\\n").encode("utf-8")

    if existing_bytes == desired_bytes and target.exists():
        existing_fd = os.open(target, os.O_RDWR | os.O_NOFOLLOW)
        try:
            before = os.fstat(existing_fd)
            if not stat.S_ISREG(before.st_mode):
                raise OSError("registry is not a regular file")
            os.fchown(existing_fd, {owner_uid}, {owner_gid})
            os.fchmod(existing_fd, 0o644)
        finally:
            os.close(existing_fd)
        print("unchanged" if before.st_uid == {owner_uid} and before.st_gid == {owner_gid} and (before.st_mode & 0o777) == 0o644 else "updated")
        raise SystemExit(0)

    fd, temporary_name = tempfile.mkstemp(prefix=".barragan-routes.", dir=target.parent)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("registry staging file is not a regular file")
        os.fchown(fd, {owner_uid}, {owner_gid})
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb") as stream:
            stream.write(desired_bytes)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, target)
        directory_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
    print("recovered" if recovered else "updated")
finally:
    os.close(lock_fd)
    os.close(parent_fd)
'''
    return "\n".join(
        [
            "set -u",
            "umask 077",
            "python3 - <<'PY'",
            python_script.rstrip(),
            "PY",
        ]
    )


def _safe_http_route_name(channel_id: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", channel_id.lower()).strip("_") or "route"


def _managed_http_backend_site_name(spec: InboundChannelArtifactSpec) -> str:
    """Return the filesystem-safe site name fixed by the typed service id."""
    return spec.service_id.removeprefix("http-site-")


def _render_http_route_site_config(
    backend_host: str,
    backend_port: int,
    *,
    request_header_gate: Mapping[str, Any] | None = None,
    backend_authorization: InboundBackendAuthorization | None = None,
    backend_authorization_inventory_group: str = "termination_host",
) -> str:
    from app.services.inbound_request_header_gate import render_http_backend_site_config

    return render_http_backend_site_config(
        backend_host,
        backend_port,
        request_header_gate,
        backend_authorization=backend_authorization,
        backend_authorization_inventory_group=backend_authorization_inventory_group,
    )


def _render_http_route_site_compose(route_name: str, service_name: str) -> str:
    return "\n".join([
        "services:",
        f"  {service_name}:",
        "    image: openresty/openresty:latest",
        f"    container_name: {service_name}",
        "    restart: unless-stopped",
        "    expose:",
        "      - '8081'",
        "    extra_hosts:",
        "      - 'host.docker.internal:host-gateway'",
        "    volumes:",
        f"      - /opt/web/inbound/{route_name}/conf:/etc/nginx/conf.d:ro",
        "      - certbot-etc:/etc/letsencrypt",
        "    networks:",
        "      - web_webnet",
        "networks:",
        "  web_webnet:",
        "volumes:",
        "  certbot-etc:",
        "",
    ])


def _render_shared_front_compose() -> str:
    return """services:
  reverse-proxy:
    image: openresty/openresty:latest
    container_name: proxy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /opt/web/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf:ro
      - /opt/web/http:/etc/openresty/http:ro
      - /opt/web/streams:/etc/openresty/streams:ro
      - /opt/web/tls:/etc/openresty/tls:ro
      - certbot-etc:/etc/letsencrypt
    networks:
      - web_webnet
networks:
  web_webnet:
volumes:
  certbot-etc:
"""


def _render_shared_front_openresty_config() -> str:
    return """user www-data;
worker_processes auto;
events { worker_connections 1024; }
http {
    map $host $barragan_http_backend {
        include /etc/openresty/http/*.map;
        include /etc/openresty/streams/*.map;
        default 127.0.0.1:9;
    }
    server {
        listen 80 proxy_protocol;
        server_name _;
        resolver 127.0.0.11;
        client_max_body_size 10240000000;
        location / {
            proxy_request_buffering off;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $proxy_protocol_addr;
            proxy_set_header X-Forwarded-For $proxy_protocol_addr;
            proxy_set_header X-Forwarded-Proto http;
            proxy_pass http://$barragan_http_backend;
        }
    }
}
stream {
    map $ssl_preread_server_name $barragan_tls_backend {
        include /etc/openresty/streams/*.map;
        include /etc/openresty/tls/*.map;
        default 127.0.0.1:9;
    }
    server {
        listen 443 proxy_protocol;
        resolver 127.0.0.11;
        ssl_preread on;
        proxy_protocol on;
        proxy_pass $barragan_tls_backend;
    }
}
"""


def _wait_for_connection_task() -> list[str]:
    return [
        "    - name: Wait for inbound channel management SSH path",
        "      ansible.builtin.wait_for_connection:",
        f"        timeout: {MANAGEMENT_SSH_WAIT_TIMEOUT_SECONDS}",
        "        sleep: 5",
        "        connect_timeout: 10",
    ]


def _management_path_preflight_play(host_group: str) -> list[str]:
    return [
        f"- name: Preflight inbound management path for {host_group}",
        f"  hosts: {host_group}",
        "  gather_facts: false",
        "  become: false",
        "  tasks:",
        *_wait_for_connection_task(),
        "    - name: Require a host firewall before inbound configuration",
        "      ansible.builtin.shell:",
        "        cmd: command -v ufw >/dev/null 2>&1 || command -v iptables >/dev/null 2>&1",
        "      changed_when: false",
    ]


def _nginx_prepare_play(host_group: str) -> list[str]:
    tasks = [
        f"- name: Prepare inbound nginx stream host {host_group}",
        f"  hosts: {host_group}",
        "  gather_facts: false",
        "  become: true",
        "  tasks:",
        *_wait_for_connection_task(),
        "    - name: Install nginx stream support",
        "      ansible.builtin.apt:",
        "        name:",
        "          - nginx",
        "          - libnginx-mod-stream",
        "        state: present",
        "        update_cache: true",
        "    - name: Check whether nginx stream block already exists",
        "      ansible.builtin.shell:",
        "        cmd: grep -Eq '^stream[[:space:]]*\\{' /etc/nginx/nginx.conf",
        "      changed_when: false",
        "      failed_when: false",
        "      register: barragan_nginx_stream_block",
        "    - name: Ensure existing nginx stream block includes Barragan stream directory",
        "      ansible.builtin.lineinfile:",
        "        path: /etc/nginx/nginx.conf",
        "        insertafter: '^stream[[:space:]]*\\{'",
        "        line: '    include streams/*.conf;'",
        "        state: present",
        "      when: barragan_nginx_stream_block.rc == 0",
        "    - name: Add Barragan nginx stream include block when missing",
        "      ansible.builtin.blockinfile:",
        "        path: /etc/nginx/nginx.conf",
        "        marker: '# {mark} BARRAGAN MANAGED STREAM INCLUDE'",
        "        block: |",
        "          stream {",
        "              include streams/*.conf;",
        "          }",
        "      when: barragan_nginx_stream_block.rc != 0",
        "    - name: Ensure nginx streams directory exists",
        "      ansible.builtin.file:",
        "        path: /etc/nginx/streams",
        "        state: directory",
        "        mode: '0755'",
        "    - name: Disable distro default HTTP site on inbound stream host",
        "      ansible.builtin.file:",
        "        path: /etc/nginx/sites-enabled/default",
        "        state: absent",
    ]
    tasks.extend(
        [
            "    - name: Test nginx base stream config",
            "      ansible.builtin.command: nginx -t",
            "      changed_when: false",
        ]
    )
    return tasks


def _nginx_channel_apply_play(host_group: str, artifact: RenderedArtifact) -> list[str]:
    return [
        f"- name: Apply inbound channel stream on {host_group}",
        f"  hosts: {host_group}",
        "  gather_facts: false",
        "  become: true",
        "  tasks:",
        *_wait_for_connection_task(),
        "    - name: Write Barragan inbound stream config",
        "      ansible.builtin.copy:",
        f"        dest: {artifact.target}",
        "        mode: '0644'",
        "        content: |",
        _indent_block(artifact.content, 10),
        "    - name: Test nginx config",
        "      ansible.builtin.command: nginx -t",
        "      changed_when: false",
        "    - name: Reload nginx",
        "      ansible.builtin.service:",
        "        name: nginx",
        "        state: reloaded",
        "        enabled: true",
    ]


def _nginx_stream_config() -> str:
    return "\n".join(
        [
            "include modules-enabled/50-mod-stream.conf;",
            "",
            "user  www-data;",
            "worker_processes  auto;",
            "",
            "error_log  /var/log/nginx/error.log notice;",
            "pid        /var/run/nginx.pid;",
            "",
            "events {",
            "    worker_connections  1024;",
            "}",
            "",
            "stream {",
            "    include streams/*.conf;",
            "}",
            "",
        ]
    )


def _edge_validation_probe_command(transport: str, request_text: str, host: str, port: int) -> str:
    if transport == "udp":
        source = (
            "import socket,sys;"
            "payload=sys.argv[1].encode();"
            "host=sys.argv[2];"
            "port=int(sys.argv[3]);"
            "sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
            "sock.settimeout(5);"
            "sock.sendto(payload,(host,port));"
            "data,_addr=sock.recvfrom(65535);"
            "sock.close();"
            "sys.stdout.write(data.decode('utf-8','replace'))"
        )
    else:
        source = (
            "import socket,sys;"
            "payload=sys.argv[1].encode();"
            "host=sys.argv[2];"
            "port=int(sys.argv[3]);"
            "sock=socket.create_connection((host,port),5);"
            "sock.settimeout(5);"
            "sock.sendall(payload);"
            "chunks=[];"
            "\nwhile True:\n"
            "    try:\n"
            "        data=sock.recv(8192)\n"
            "    except socket.timeout:\n"
            "        break\n"
            "    if not data:\n"
            "        break\n"
            "    chunks.append(data)\n"
            "sock.close();"
            "sys.stdout.write(b''.join(chunks).decode('utf-8','replace'))"
        )
    return " ".join(
        [
            "timeout",
            "15",
            "python3",
            "-c",
            shlex.quote(source),
            shlex.quote(request_text),
            shlex.quote(host),
            str(port),
        ]
    )


def _render_validation_playbook(
    spec: InboundChannelArtifactSpec,
    artifacts: InboundChannelArtifacts,
    termination: dict[str, str] | None,
    route: InboundResolvedRoute,
) -> str:
    if artifacts.validation.profile_type == "tcp-connect":
        return _render_tcp_connect_validation_playbook(spec, artifacts.validation, route)
    if artifacts.validation.profile_type == "manual":
        return _render_manual_validation_playbook(artifacts.validation)
    if artifacts.validation.profile_type != "temporary-listener":
        return _render_send_receive_validation_playbook(spec, artifacts.validation, route)
    return _render_temporary_listener_validation_playbook(
        spec,
        artifacts,
        termination,
        route,
    )


def _render_temporary_listener_validation_playbook(
    spec: InboundChannelArtifactSpec,
    artifacts: InboundChannelArtifacts,
    termination: dict[str, str] | None,
    route: InboundResolvedRoute,
) -> str:
    termination_group = "selected_proxy" if termination is None else "termination_host"
    marker_file = _validation_marker_file(spec)
    marker = artifacts.validation.expected_marker
    listener_source = (
        "import pathlib,socket,time;"
        f"marker=pathlib.Path({marker_file!r});"
        f"port={spec.internal_port};"
        "deadline=time.time()+25;"
        "sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        "sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
        "sock.bind(('0.0.0.0',port));"
        "sock.listen(1);"
        "sock.settimeout(1);"
        "matched=False;"
        f"expected={marker!r}.encode();"
        "\nwhile time.time()<deadline:\n"
        "    try:\n"
        "        conn,_addr=sock.accept()\n"
        "    except socket.timeout:\n"
        "        continue\n"
        "    data=conn.recv(8192)\n"
        "    conn.close()\n"
        "    if data:\n"
        "        marker.write_bytes(data)\n"
        "        matched=expected in data\n"
        "        break\n"
        "sock.close();"
        "raise SystemExit(0 if matched else 1)"
    )
    listener_command = (
        f"rm -f {marker_file}; "
        f"timeout 30 python3 -c {shlex.quote(listener_source)}"
    )
    probe_host = _validation_probe_host(route)
    probe_command = _edge_validation_probe_command("tcp", marker, probe_host, spec.external_port)
    return "\n".join(
        [
            "---",
            "- name: Start temporary inbound validation listener",
            f"  hosts: {termination_group}",
            "  gather_facts: false",
            "  become: true",
            "  tasks:",
            *_wait_for_connection_task(),
            "    - name: Remove stale inbound validation marker",
            "      ansible.builtin.file:",
            f"        path: {marker_file}",
            "        state: absent",
            "    - name: Start temporary listener on termination host",
            "      ansible.builtin.shell:",
            f"        cmd: {json.dumps(listener_command)}",
            "      async: 35",
            "      poll: 0",
            "      changed_when: true",
            "    - name: Wait for temporary listener port",
            "      ansible.builtin.wait_for:",
            "        host: 127.0.0.1",
            f"        port: {spec.internal_port}",
            "        timeout: 10",
            "",
            "- name: Probe inbound channel from selected edge through ingress route",
            "  hosts: selected_edge",
            "  gather_facts: false",
            "  become: false",
            "  tasks:",
            *_wait_for_connection_task(),
            "    - name: Send validation marker from selected edge through inbound route",
            "      ansible.builtin.shell:",
            f"        cmd: {json.dumps(probe_command)}",
            "      register: inbound_validation_probe",
            "      changed_when: false",
            "      failed_when: false",
            "    - name: Show validation probe evidence",
            "      ansible.builtin.debug:",
            "        var: inbound_validation_probe",
            "",
            "- name: Verify temporary inbound validation marker",
            f"  hosts: {termination_group}",
            "  gather_facts: false",
            "  become: true",
            "  tasks:",
            *_wait_for_connection_task(),
            "    - name: Read validation marker from termination host",
            "      ansible.builtin.shell:",
            f"        cmd: {json.dumps(f'grep -F {marker!r} {marker_file}')}",
            "      register: inbound_validation_marker",
            "      changed_when: false",
            "    - name: Show validation marker evidence",
            "      ansible.builtin.debug:",
            "        var: inbound_validation_marker.stdout",
            "    - name: Remove temporary inbound validation marker",
            "      ansible.builtin.file:",
            f"        path: {marker_file}",
            "        state: absent",
            "",
        ]
    )


def _render_send_receive_validation_playbook(
    spec: InboundChannelArtifactSpec,
    validation: InboundValidationPlan,
    route: InboundResolvedRoute,
) -> str:
    probe_host = _validation_probe_host(route)
    transport = "udp" if validation.profile_type == "udp-send-receive" else "tcp"
    request_text = validation.request_text or validation.expected_marker
    probe_command = _edge_validation_probe_command(transport, request_text, probe_host, spec.external_port)
    expected_response = _validation_expected_text(validation)
    transport_label = "UDP" if validation.profile_type == "udp-send-receive" else "TCP"
    verification_tasks = (
        [
            "    - name: Verify non-5xx HTTP response",
            "      ansible.builtin.assert:",
            "        that:",
            "          - inbound_validation_probe.rc == 0",
            "          - inbound_validation_probe.stdout | regex_search('^HTTP/[0-9]+\\.[0-9]+ [1-4][0-9]{2}(?:[ \\r\\n]|$)') is not none",
            "        fail_msg: A non-5xx HTTP response was not observed from the selected edge through the inbound route.",
        ]
        if validation.profile_type == "http"
        else [
            "    - name: Verify expected response text",
            "      ansible.builtin.assert:",
            "        that:",
            "          - inbound_validation_probe.rc == 0",
            "          - barragan_expected_response in inbound_validation_probe.stdout",
            "        fail_msg: Expected response text was not observed from the selected edge through the inbound route.",
        ]
    )
    return "\n".join(
        [
            "---",
            "- name: Probe inbound channel from selected edge through ingress route",
            "  hosts: selected_edge",
            "  gather_facts: false",
            "  become: false",
            "  vars:",
            f"    barragan_validation_profile_type: {json.dumps(validation.profile_type)}",
            f"    barragan_validation_profile_label: {json.dumps(validation.profile_label)}",
            f"    barragan_expected_response: {json.dumps(expected_response)}",
            "  tasks:",
            *_wait_for_connection_task(),
            f"    - name: Send {transport_label} validation probe from selected edge through inbound route",
            "      ansible.builtin.shell:",
            f"        cmd: {json.dumps(probe_command)}",
            "      register: inbound_validation_probe",
            "      changed_when: false",
            "      failed_when: false",
            "    - name: Show validation probe evidence",
            "      ansible.builtin.debug:",
            "        var: inbound_validation_probe",
            *verification_tasks,
            "",
        ]
    )


def _render_tcp_connect_validation_playbook(
    spec: InboundChannelArtifactSpec,
    validation: InboundValidationPlan,
    route: InboundResolvedRoute,
) -> str:
    probe_host = _validation_probe_host(route)
    probe_command = f"nc -z -w 5 {shlex.quote(probe_host)} {spec.external_port}"
    return "\n".join(
        [
            "---",
            "- name: Probe inbound channel TCP reachability from selected edge",
            "  hosts: selected_edge",
            "  gather_facts: false",
            "  become: false",
            "  vars:",
            f"    barragan_validation_profile_type: {json.dumps(validation.profile_type)}",
            f"    barragan_validation_profile_label: {json.dumps(validation.profile_label)}",
            "  tasks:",
            *_wait_for_connection_task(),
            "    - name: Open TCP connection from selected edge through inbound route",
            "      ansible.builtin.shell:",
            f"        cmd: {json.dumps(probe_command)}",
            "      register: inbound_validation_probe",
            "      changed_when: false",
            "      failed_when: false",
            "    - name: Show validation probe evidence",
            "      ansible.builtin.debug:",
            "        var: inbound_validation_probe",
            "    - name: Verify TCP connect succeeded",
            "      ansible.builtin.assert:",
            "        that:",
            "          - inbound_validation_probe.rc == 0",
            "        fail_msg: TCP reachability was not observed from the selected edge through the inbound route.",
            "",
        ]
    )


def _render_manual_validation_playbook(validation: InboundValidationPlan) -> str:
    return "\n".join(
        [
            "---",
            "- name: Record manual inbound channel validation profile",
            "  hosts: localhost",
            "  gather_facts: false",
            "  tasks:",
            "    - name: Manual validation selected",
            "      ansible.builtin.debug:",
            f"        msg: {json.dumps(f'{validation.profile_label}: no automatic application probe configured')}",
            "",
        ]
    )


def _openresty_http_route_remove_play(spec: InboundChannelArtifactSpec, artifacts: InboundChannelArtifacts) -> list[str]:
    route_name = _safe_http_route_name(spec.channel_id)
    service_name = http_backend_service_name(spec.channel_id)
    return [
        "- name: Remove HTTP backend route from shared proxy OpenResty stack",
        "  hosts: selected_proxy",
        "  gather_facts: false",
        "  become: true",
        "  tasks:",
        *_wait_for_connection_task(),
        "    - name: Classify shared front ownership before route removal",
        "      ansible.builtin.shell:",
        "        cmd: python3 -c \"import json,pathlib,sys; stack=pathlib.Path('/opt/web/docker-compose.yml'); owner=pathlib.Path('/opt/web/.barragan-stack.json'); expected={'managedBy':'barragan','stackModel':'containerized-openresty-v1'}; absent=not stack.exists() and not owner.exists(); owned=stack.exists() and owner.exists() and json.loads(owner.read_text()) == expected; sys.exit(2 if absent else 0 if owned else 1)\"",
        "      register: barragan_front_ownership",
        "      changed_when: false",
        "      failed_when: false",
        "    - name: Record absent shared front stack as pre-bootstrap cleanup",
        "      ansible.builtin.debug:",
        "        msg: No shared front stack exists; this failed route made no proxy-side web changes to remove.",
        "      when: barragan_front_ownership.rc == 2",
        "    - name: Refuse to mutate an existing unowned shared front stack",
        "      ansible.builtin.assert:",
        "        that:",
        "          - barragan_front_ownership.rc in [0, 2]",
        "        fail_msg: Barragan will not mutate an existing /opt/web stack unless its manifest declares Barragan ownership.",
        "    - name: Remove generic HTTP backend proxy",
        "      ansible.builtin.command:",
        f"        argv: [docker, compose, -f, /opt/web/docker-compose.yml, -f, /opt/web/sites/{route_name}.compose.yml, rm, -s, -f, {service_name}]",
        "      failed_when: false",
        "      when: barragan_front_ownership.rc == 0",
        "    - name: Remove HTTP Host route",
        "      ansible.builtin.file:",
        f"        path: {artifacts.proxy_stream.target}",
        "        state: absent",
        "      when: barragan_front_ownership.rc == 0",
        "    - name: Remove generated HTTP backend files",
        "      ansible.builtin.file:",
        "        path: \"{{ item }}\"",
        "        state: absent",
        "      loop:",
        f"        - /opt/web/sites/{route_name}.compose.yml",
        f"        - /opt/web/inbound/{route_name}",
        "      when: barragan_front_ownership.rc == 0",
        "    - name: Validate remaining shared front routes",
        "      ansible.builtin.command:",
        "        argv: [docker, compose, -f, /opt/web/docker-compose.yml, exec, -T, reverse-proxy, openresty, -t]",
        "      when: barragan_front_ownership.rc == 0",
        "    - name: Reload remaining shared front routes",
        "      ansible.builtin.command:",
        "        argv: [docker, compose, -f, /opt/web/docker-compose.yml, exec, -T, reverse-proxy, openresty, -s, reload]",
        "      when: barragan_front_ownership.rc == 0",
    ]


def _managed_http_backend_firewall_remove_play(spec: InboundChannelArtifactSpec) -> list[str]:
    return [
        "- name: Close managed HTTP backend Homebase firewall path",
        "  hosts: homebase_backend",
        "  gather_facts: false",
        "  become: true",
        "  vars:",
        f"    barragan_channel_id: {json.dumps(spec.channel_id)}",
        "    barragan_backend_firewall_comment: barragan-inbound-{{ barragan_channel_id }}-backend",
        "  tasks:",
        *_wait_for_connection_task(),
        "    - name: Check Homebase UFW status",
        "      ansible.builtin.command: ufw status",
        "      register: barragan_backend_ufw_status",
        "      changed_when: false",
        "      failed_when: false",
        "    - name: Delete selected proxy managed HTTP backend UFW rule",
        "      ansible.builtin.shell:",
        "        cmd: |",
        "          set -eu",
        "          ufw status numbered | grep -F \"{{ barragan_backend_firewall_comment }}\" | sed -n 's/^\\[[[:space:]]*\\([0-9][0-9]*\\)\\].*/\\1/p' | sort -rn | while read -r rule; do",
        "            [ -n \"${rule}\" ] && yes | ufw delete \"${rule}\"",
        "          done",
        "      failed_when: false",
        "      when: \"'Status: active' in barragan_backend_ufw_status.stdout\"",
        "    - name: Delete selected proxy managed HTTP backend allow with iptables",
        "      ansible.builtin.shell:",
        "        cmd: |",
        "          set -eu",
        "          comment='{{ barragan_backend_firewall_comment }}'",
        "          for owned_comment in \"${comment}\" \"${comment}-deny\"; do",
        "            while rule_number=$(iptables -S INPUT | grep -F -- '-A INPUT ' | grep -n -F -e \"--comment ${owned_comment} \" -e \"--comment \\\"${owned_comment}\\\" \" | head -n 1 | cut -d: -f1); do",
        "              [ -n \"${rule_number}\" ] || break",
        "              iptables -D INPUT \"${rule_number}\"",
        "            done",
        "          done",
        "      when: \"'Status: active' not in barragan_backend_ufw_status.stdout\"",
        "    - name: Persist managed HTTP backend Homebase iptables removal",
        "      ansible.builtin.shell: |",
        "        set -eu",
        "        if command -v netfilter-persistent >/dev/null 2>&1; then",
        "          netfilter-persistent save",
        "        elif command -v iptables-save >/dev/null 2>&1 && [ -d /etc/iptables ]; then",
        "          iptables-save -f /etc/iptables/rules.v4",
        "        fi",
        "      changed_when: false",
        "      when: \"'Status: active' not in barragan_backend_ufw_status.stdout\"",
        "",
    ]


def _render_remove_playbook(
    spec: InboundChannelArtifactSpec,
    artifacts: InboundChannelArtifacts,
    route: InboundResolvedRoute,
) -> str:
    targets = [] if is_shared_web_ingress(spec) else [
        ("selected_edge", artifacts.edge_stream),
        ("selected_middle", artifacts.middle_stream),
        ("selected_proxy", artifacts.proxy_stream),
    ]
    sections = ["---"]
    if is_managed_http_backend_site(spec):
        sections.extend([*_managed_http_backend_firewall_remove_play(spec)])
    if spec.mode == "http-openresty" and not is_native_static_web_route(spec):
        sections.extend([*_openresty_http_route_remove_play(spec, artifacts), ""])
    for host_group, artifact in targets:
        sections.extend(
            [
                f"- name: Remove inbound nginx stream on {host_group}",
                f"  hosts: {host_group}",
                "  gather_facts: false",
                "  become: true",
                "  tasks:",
                *_wait_for_connection_task(),
                "    - name: Remove Barragan inbound stream config",
                "      ansible.builtin.file:",
                f"        path: {artifact.target}",
                "        state: absent",
                "    - name: Test nginx config",
                "      ansible.builtin.command: nginx -t",
                "      changed_when: false",
                "      failed_when: false",
                "      register: barragan_nginx_test",
                "    - name: Reload nginx after channel removal",
                "      ansible.builtin.service:",
                "        name: nginx",
                "        state: reloaded",
                "      when: barragan_nginx_test.rc == 0",
                "",
            ]
        )
    sections.extend([*_proxy_runtime_registry_remove_play(spec.channel_id), ""])
    sections.extend(
        [
            "- name: Close inbound channel firewall paths",
            "  hosts: inbound_firewall_targets",
            "  gather_facts: false",
            "  become: true",
        "  vars:",
        f"    barragan_channel_id: {json.dumps(spec.channel_id)}",
        f"    barragan_external_port: {spec.external_port}",
        f"    barragan_transport_protocol: {json.dumps(_transport_protocol(spec))}",
        f"    barragan_shared_https_front: {json.dumps(is_shared_web_ingress(spec))}",
        f"    barragan_edge_listen_port: {spec.external_port}",
        f"    barragan_middle_listen_port: {_middle_relay_port(spec)}",
        f"    barragan_proxy_listen_port: {_proxy_relay_port(spec)}",
        f"    barragan_edge_ip: {json.dumps(route.edge.public_ip or route.edge.ansible_host)}",
        f"    barragan_middle_ip: {json.dumps(route.middle.public_ip or route.middle.ansible_host)}",
        *(
            [
                f"    barragan_termination_listen_port: {spec.internal_port}",
                f"    barragan_proxy_ip: {json.dumps(_termination_firewall_source(route))}",
            ]
            if spec.terminates_on != spec.proxy_hostname
            else []
        ),
        "  tasks:",
            *_wait_for_connection_task(),
            "    - name: Check UFW status",
            "      ansible.builtin.command: ufw status",
            "      register: barragan_ufw_status",
            "      changed_when: false",
            "      failed_when: false",
            "    - name: Delete public edge UFW rule",
            "      ansible.builtin.shell:",
            "        cmd: |",
            "          set -eu",
            "          ufw status numbered | grep 'barragan-inbound-{{ barragan_channel_id }}-edge' | sed -n 's/^\\[[[:space:]]*\\([0-9][0-9]*\\)\\].*/\\1/p' | sort -rn | while read -r rule; do",
            "            [ -n \"${rule}\" ] && yes | ufw delete \"${rule}\"",
            "          done",
            "      failed_when: false",
            "      when: \"inventory_hostname in groups['selected_edge'] and 'Status: active' in barragan_ufw_status.stdout and not barragan_shared_https_front\"",
            "    - name: Delete edge to middle UFW rule",
            "      ansible.builtin.shell:",
            "        cmd: |",
            "          set -eu",
            "          ufw status numbered | grep 'barragan-inbound-{{ barragan_channel_id }}-middle' | sed -n 's/^\\[[[:space:]]*\\([0-9][0-9]*\\)\\].*/\\1/p' | sort -rn | while read -r rule; do",
            "            [ -n \"${rule}\" ] && yes | ufw delete \"${rule}\"",
            "          done",
            "      failed_when: false",
            "      when: \"inventory_hostname in groups['selected_middle'] and 'Status: active' in barragan_ufw_status.stdout and not barragan_shared_https_front\"",
            "    - name: Delete middle to proxy UFW rule",
            "      ansible.builtin.shell:",
            "        cmd: |",
            "          set -eu",
            "          ufw status numbered | grep 'barragan-inbound-{{ barragan_channel_id }}-proxy' | sed -n 's/^\\[[[:space:]]*\\([0-9][0-9]*\\)\\].*/\\1/p' | sort -rn | while read -r rule; do",
            "            [ -n \"${rule}\" ] && yes | ufw delete \"${rule}\"",
            "          done",
            "      failed_when: false",
            "      when: \"inventory_hostname in groups['selected_proxy'] and 'Status: active' in barragan_ufw_status.stdout and not barragan_shared_https_front\"",
            *(
                [
                    "    - name: Delete proxy to termination UFW rule",
                    "      ansible.builtin.shell:",
                    "        cmd: |",
                    "          set -eu",
                    "          ufw status numbered | grep -F 'barragan-inbound-{{ barragan_channel_id }}-termination' | sed -n 's/^\\[[[:space:]]*\\([0-9][0-9]*\\)\\].*/\\1/p' | sort -rn | while read -r rule; do",
                    "            [ -n \"${rule}\" ] && yes | ufw delete \"${rule}\"",
                    "          done",
                    "      failed_when: false",
                    "      when: \"inventory_hostname in groups['termination_host'] and 'Status: active' in barragan_ufw_status.stdout\"",
                ]
                if spec.terminates_on != spec.proxy_hostname
                else []
            ),
            "    - name: Delete channel iptables rule when UFW is inactive",
            "      ansible.builtin.shell:",
            "        cmd: |",
        "          set -eu",
        "          source_arg=''",
        "          rule_role='edge'",
        "          rule_port='{{ barragan_edge_listen_port }}'",
        "          if printf '%s\\n' \"{{ groups['selected_middle'] | default([]) | join('\\n') }}\" | grep -Fx -- \"{{ inventory_hostname }}\" >/dev/null; then",
        "            source_arg='-s {{ barragan_edge_ip }}'",
        "            rule_role='middle'",
        "            rule_port='{{ barragan_middle_listen_port }}'",
        "          elif printf '%s\\n' \"{{ groups['selected_proxy'] | default([]) | join('\\n') }}\" | grep -Fx -- \"{{ inventory_hostname }}\" >/dev/null; then",
        "            source_arg='-s {{ barragan_middle_ip }}'",
        "            rule_role='proxy'",
        "            rule_port='{{ barragan_proxy_listen_port }}'",
        "          fi",
        "          comment=\"barragan-inbound-{{ barragan_channel_id }}-${rule_role}\"",
        "          while iptables -C INPUT ${source_arg} -p {{ barragan_transport_protocol }} --dport ${rule_port} -m comment --comment \"${comment}\" -j ACCEPT 2>/dev/null; do",
        "            iptables -D INPUT ${source_arg} -p {{ barragan_transport_protocol }} --dport ${rule_port} -m comment --comment \"${comment}\" -j ACCEPT",
        "          done",
        "          deny_comment=\"${comment}-deny\"",
        "          while [ -n \"${source_arg}\" ] && iptables -C INPUT -p {{ barragan_transport_protocol }} --dport ${rule_port} -m comment --comment \"${deny_comment}\" -j DROP 2>/dev/null; do",
        "            iptables -D INPUT -p {{ barragan_transport_protocol }} --dport ${rule_port} -m comment --comment \"${deny_comment}\" -j DROP",
        "          done",
        "      when: \"'Status: active' not in barragan_ufw_status.stdout and inventory_hostname in groups['inbound_channel_targets'] and not barragan_shared_https_front\"",
        *(
            [
                "    - name: Delete selected proxy termination allow with iptables",
                "      ansible.builtin.shell:",
                "        cmd: |",
                "          set -eu",
                "          comment='barragan-inbound-{{ barragan_channel_id }}-termination'",
                "          for owned_comment in \"${comment}\" \"${comment}-deny\"; do",
                "            while rule_number=$(iptables -S INPUT | grep -F -- '-A INPUT ' | grep -n -F -e \"--comment ${owned_comment} \" -e \"--comment \\\"${owned_comment}\\\" \" | head -n 1 | cut -d: -f1); do",
                "              [ -n \"${rule_number}\" ] || break",
                "              iptables -D INPUT \"${rule_number}\"",
                "            done",
                "          done",
                "      when: \"inventory_hostname in groups['termination_host'] and 'Status: active' not in barragan_ufw_status.stdout\"",
            ]
            if spec.terminates_on != spec.proxy_hostname
            else []
        ),
            "    - name: Persist iptables rules when netfilter-persistent is available",
            "      ansible.builtin.command: netfilter-persistent save",
            "      changed_when: true",
            "      failed_when: false",
            "      when: \"'Status: active' not in barragan_ufw_status.stdout\"",
        ]
    )
    return "\n".join(sections)


def _render_manifest(
    spec: InboundChannelArtifactSpec,
    artifacts: InboundChannelArtifacts,
    core_key: str,
    local_sketch_key: str,
    termination: dict[str, str] | None,
    route: InboundResolvedRoute,
) -> str:
    ingress_assessment = _assess_inbound_ingress(spec, route)
    body = {
        "mode": "inbound_channel_apply",
        "status": "Pending Apply",
        "mutation": False,
        "channel": _compact_channel_with_ingress_assessment(spec, artifacts, route, ingress_assessment),
        "ingressAssessment": ingress_assessment,
        "targets": {
            "homebase": {"name": route.homebase.name, "ansibleHost": route.homebase.ansible_host, "ansibleUser": _route_ssh_user(route.homebase), "sshPrivateKeyFile": core_key, "publicIp": route.homebase.public_ip, "privateIp": route.homebase.private_ip},
            "proxy": {"name": route.proxy.name, "ansibleHost": route.proxy.ansible_host, "ansibleUser": _route_ssh_user(route.proxy), "sshPrivateKeyFile": core_key, "publicIp": route.proxy.public_ip, "privateIp": route.proxy.private_ip, "proxyJump": "homebase"},
            "middle": {"name": route.middle.name, "ansibleHost": route.middle.ansible_host, "ansibleUser": SKETCH_INFRASTRUCTURE_ADMIN_USER, "sshPrivateKeyFile": local_sketch_key, "publicIp": route.middle.public_ip, "chainId": route.middle.chain_id, "proxyJump": "homebase->proxy"},
            "edge": {"name": route.edge.name, "ansibleHost": route.edge.ansible_host, "ansibleUser": SKETCH_INFRASTRUCTURE_ADMIN_USER, "sshPrivateKeyFile": local_sketch_key, "publicIp": route.edge.public_ip, "chainId": route.edge.chain_id, "proxyJump": "homebase->proxy->middle"},
            **({"termination": termination} if termination is not None else {}),
        },
        "resolvedRoute": route.to_dict(),
        "phases": [
            {"phase": phase, "label": label, "playbook": target, "mutation": mutation}
            for phase, label, target, mutation in INBOUND_APPLY_PHASES
        ],
        "opsecBoundary": {
            "middleAccess": "ProxyJump through homebase to selected proxy",
            "edgeAccess": "ProxyJump through homebase to selected proxy and selected middle",
            "directSketchAccessFromAppHost": False,
        },
        "validation": artifacts.validation.to_dict(),
    }
    return json.dumps(body, indent=2, sort_keys=True) + "\n"


def _render_validation_manifest(
    spec: InboundChannelArtifactSpec,
    artifacts: InboundChannelArtifacts,
    termination: dict[str, str] | None,
    route: InboundResolvedRoute,
) -> str:
    probe_host = _validation_probe_host(route)
    ingress_assessment = _assess_inbound_ingress(spec, route)
    validation_body = {
        **artifacts.validation.to_dict(),
        "probeOrigin": "selected_edge",
        "probeShellDisplay": _validation_probe_shell_display(spec, artifacts.validation, probe_host),
        "validationScope": EDGE_LOCAL_VALIDATION_SCOPE,
        "externalIngressVerified": EXTERNAL_INGRESS_VERIFIED,
        "ingressEndpoint": f"{probe_host}:{spec.external_port}",
    }
    if artifacts.validation.profile_type == "temporary-listener":
        validation_body["markerFile"] = _validation_marker_file(spec)
    body = {
        "mode": "inbound_channel_validation",
        "status": "Pending Validation",
        "mutation": False,
        "channel": _compact_channel_with_ingress_assessment(spec, artifacts, route, ingress_assessment),
        "ingressAssessment": ingress_assessment,
        "targets": {
            "termination": {"name": spec.terminates_on, "inventoryGroup": "selected_proxy" if termination is None else "termination_host"},
            "edge": {"name": spec.edge_hostname, "inventoryGroup": "selected_edge", "access": f"{spec.proxy_hostname}->{spec.middle_hostname}"},
        },
        "validation": validation_body,
        "opsecBoundary": {
            "listenerAccess": "Core termination host only; non-proxy termination uses proxy jump",
            "probeOrigin": "selected edge via homebase, selected proxy, and selected middle; no app-host direct edge probe",
            "directSketchAccessFromAppHost": False,
            "directEdgeProbeFromAppHost": False,
        },
    }
    return json.dumps(body, indent=2, sort_keys=True) + "\n"


def _render_remove_manifest(
    spec: InboundChannelArtifactSpec,
    artifacts: InboundChannelArtifacts,
    route: InboundResolvedRoute,
) -> str:
    ingress_assessment = _assess_inbound_ingress(spec, route)
    body = {
        "mode": "inbound_channel_remove",
        "status": "Pending Remove",
        "mutation": False,
        "channel": _compact_channel_with_ingress_assessment(spec, artifacts, route, ingress_assessment),
        "ingressAssessment": ingress_assessment,
        "targets": route.to_dict(),
        "removedArtifacts": {
            "edgeStream": artifacts.edge_stream.target,
            "middleStream": artifacts.middle_stream.target,
            "proxyStream": artifacts.proxy_stream.target,
        },
        "opsecBoundary": {
            "middleAccess": "ProxyJump through homebase to selected proxy",
            "edgeAccess": "ProxyJump through homebase to selected proxy and selected middle",
            "directSketchAccessFromAppHost": False,
        },
    }
    return json.dumps(body, indent=2, sort_keys=True) + "\n"


def _core_inventory_line(name: str, host: str, key: str, *, user: str, proxy_jump: str = "") -> str:
    _assert_non_root_ssh_user(user, name)
    parts = [
        name,
        f"ansible_host={name}",
        f"ansible_user={user}",
        f"ansible_ssh_private_key_file={key}",
    ]
    ssh_args = [*CORE_SSH_OPTIONS, "-F ansible/ssh_config"]
    parts.append(f"ansible_ssh_common_args={json.dumps(' '.join(ssh_args))}")
    return " ".join(parts)


def _middle_inventory_line(spec: InboundChannelArtifactSpec, core_key: str, local_sketch_key: str, route: InboundResolvedRoute) -> str:
    ssh_common_args = " ".join([*CORE_SSH_OPTIONS, "-F ansible/ssh_config"])
    return " ".join(
        [
            spec.middle_hostname,
            f"ansible_host={route.middle.name}",
            f"ansible_user={SKETCH_INFRASTRUCTURE_ADMIN_USER}",
            f"ansible_ssh_private_key_file={local_sketch_key}",
            f"ansible_ssh_common_args={json.dumps(ssh_common_args)}",
        ]
    )


def _edge_inventory_line(
    spec: InboundChannelArtifactSpec,
    core_key: str,
    local_sketch_key: str,
    route: InboundResolvedRoute,
) -> str:
    ssh_common_args = " ".join([*CORE_SSH_OPTIONS, "-F ansible/ssh_config"])
    return " ".join(
        [
            spec.edge_hostname,
            f"ansible_host={route.edge.name}",
            f"ansible_user={SKETCH_INFRASTRUCTURE_ADMIN_USER}",
            f"ansible_ssh_private_key_file={local_sketch_key}",
            f"ansible_ssh_common_args={json.dumps(ssh_common_args)}",
        ]
    )


def _homebase_proxy_command(core_key: str, proxy_host: str, homebase_host: str, homebase_user: str) -> str:
    _assert_non_root_ssh_user(homebase_user, "homebase")
    return f"ssh -i {core_key} {' '.join(CORE_SSH_OPTIONS)} -W {proxy_host}:22 {homebase_user}@{homebase_host}"


def _route_ssh_user(target: InboundRouteTarget) -> str:
    user = target.ssh_user or CORE_DEFAULT_SSH_USER
    _assert_non_root_ssh_user(user, target.name)
    return user


def _assert_non_root_ssh_user(user: str, target: str) -> None:
    if user == "root":
        raise InboundChannelApplyValidationError([f"{target} is configured for root SSH; Barragan requires a non-root management user"])


def _indent_block(value: str, spaces: int) -> str:
    prefix = " " * spaces
    return "\n".join(f"{prefix}{line}" if line else prefix for line in value.rstrip("\n").splitlines())


def _assert_workspace_opsec(workspace: InboundApplyWorkspace) -> None:
    body = json.dumps(workspace.to_dict(), sort_keys=True)
    errors: list[str] = []
    if "ProxyJump" not in workspace.ssh_config.content or "-F ansible/ssh_config" not in workspace.inventory.content:
        errors.append("inbound apply inventory must use operator-style SSH config ProxyJump paths")
    if "selected_middle" not in workspace.inventory.content or "selected_edge" not in workspace.inventory.content:
        errors.append("inbound apply inventory must include selected sketch targets")
    if " nc %h %p" in workspace.inventory.content or " nc %h %p" in workspace.ssh_config.content:
        errors.append("inbound apply management SSH must not use runtime tunnel nc patterns")
    if "BEGIN OPENSSH PRIVATE KEY" in body or "LINODE_TOKEN" in body or "DIGITALOCEAN_TOKEN" in body:
        errors.append("inbound apply workspace must not contain private keys or provider tokens")
    if "ansible_user=sketchssh" in body:
        errors.append("inbound apply workspace must use the sketch infrastructure-admin identity, not the runtime tunnel user")
    if workspace.inventory.content.count("ansible_user=root") != 2:
        errors.append("inbound apply workspace must use root only for selected sketch infrastructure configuration")
    if errors:
        raise InboundChannelApplyValidationError(errors)


def _assert_validation_workspace_opsec(workspace: InboundValidationWorkspace) -> None:
    body = json.dumps(workspace.to_dict(), sort_keys=True)
    errors: list[str] = []
    if "hosts: localhost" in workspace.playbook.content or "connection: local" in workspace.playbook.content:
        errors.append("inbound validation must not probe from the Barragan app host or localhost control plane")
    if "hosts: selected_edge" not in workspace.playbook.content:
        errors.append("inbound validation must run the client probe from selected_edge")
    if "ProxyJump" not in workspace.ssh_config.content or "-F ansible/ssh_config" not in workspace.inventory.content:
        errors.append("inbound validation inventory must reach edge through operator-style SSH config ProxyJump paths")
    if "[selected_edge]" not in workspace.inventory.content:
        errors.append("inbound validation inventory must include selected_edge")
    if " nc %h %p" in workspace.inventory.content or " nc %h %p" in workspace.ssh_config.content:
        errors.append("inbound validation management SSH must not use runtime tunnel nc patterns")
    if "barragan-app" in body:
        errors.append("inbound validation workspace must not describe app-host-originated edge probes")
    if "BEGIN OPENSSH PRIVATE KEY" in body or "LINODE_TOKEN" in body or "DIGITALOCEAN_TOKEN" in body:
        errors.append("inbound validation workspace must not contain private keys or provider tokens")
    if "ansible_user=sketchssh" in body:
        errors.append("inbound validation workspace must use the sketch infrastructure-admin identity, not the runtime tunnel user")
    if workspace.inventory.content.count("ansible_user=root") != 2:
        errors.append("inbound validation workspace must use root only for selected sketch infrastructure validation")
    if errors:
        raise InboundChannelApplyValidationError(errors)


def _validation_marker_file(spec: InboundChannelArtifactSpec) -> str:
    safe_channel = re.sub(r"[^a-zA-Z0-9._-]+", "-", spec.channel_id).strip("-") or "channel"
    return f"/tmp/barragan-inbound-{safe_channel}.marker"


def _assert_no_secret_material(value: Any) -> None:
    rendered = json.dumps(value, sort_keys=True) if not isinstance(value, str) else value
    matches = [marker for marker in SECRET_MARKERS if marker in rendered]
    if matches:
        raise InboundChannelApplyValidationError([f"inbound apply data contains forbidden secret marker: {matches[0]}"])


def _required(channel: dict[str, Any], key: str) -> str:
    value = str(channel.get(key) or "").strip()
    if not value:
        raise ValueError(f"{key} is required")
    return value


def _optional(channel: dict[str, Any], key: str) -> str:
    return str(channel.get(key) or "").strip()


def _text(value: Any) -> str:
    return str(value or "").strip()


def _port(channel: dict[str, Any], key: str) -> int:
    value = _required(channel, key)
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{key} must be a number") from exc


def _optional_port(channel: dict[str, Any], key: str) -> int | None:
    value = _optional(channel, key)
    if not value:
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{key} must be a number") from exc


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
