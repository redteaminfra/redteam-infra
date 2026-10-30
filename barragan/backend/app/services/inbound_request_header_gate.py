# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import tempfile
import threading
from typing import Any, Callable, Mapping
from uuid import uuid4

from app.core.command_environment import barragan_subprocess_env
from app.core.request_identity import current_request_identity
from app.core.runtime import start_runtime_task
from app.domain import JobEvent
from app.integrations.ansible_disposable_validation import resolve_ansible_playbook
from app.services.engagement_operations import get_operations_overview
from app.services.engagement_workspaces import (
    EngagementWorkspaceValidationError,
    load_prepared_engagement_workspace,
)
from app.services.engagements import get_engagement
from app.services.inbound_backend_authorization import (
    InboundBackendAuthorization,
    InboundBackendAuthorizationValidationError,
    render_backend_authorization_fact_play,
    resolve_selected_inbound_backend_authorization,
)
from app.services.inbound_channel_apply import (
    DEFAULT_CORE_SSH_PRIVATE_KEY,
    InboundChannelApplyValidationError,
    _backend_port,
    _inbound_channel_by_id,
    _render_inventory,
    _render_ssh_config,
    _resolved_spec_from_channel,
    _safe_http_route_name,
    _termination_host,
    _termination_host_class,
)
from app.services.inbound_channel_artifacts import http_backend_service_name, is_managed_http_backend_site
from app.services.shared_proxy_stack import (
    SharedProxyStackMutationConflict,
    reserve_shared_proxy_stack_mutation,
)
from app.storage.engagement_workspace_repository import (
    EngagementWorkspaceRepository,
    SqlAlchemyEngagementWorkspaceRepository,
)
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.service_repository import (
    EngagementServiceRepository,
    SqlAlchemyEngagementServiceRepository,
    StoredEngagementService,
)


REQUEST_HEADER_GATE_APPLY_ACTION = "inbound_request_header_gate_apply"
REQUEST_HEADER_GATE_SCHEMA = "barragan/inbound-request-header-gate/v1"
DEFAULT_HEADER_NAME = "Authorization"
DEFAULT_MAX_REQUEST_BODY_MB = 500
MIN_MAX_REQUEST_BODY_MB = 1
MAX_MAX_REQUEST_BODY_MB = 10240
BYTES_PER_MB = 1_000_000
REQUEST_HEADER_GATE_LIVE_ROUTE_STATUSES = frozenset(
    {"pending validation", "validated", "validation failed", "applied"}
)
DEFAULT_ENGAGEMENT_REPOS_ROOT = Path(os.environ.get("BARRAGAN_ENGAGEMENT_REPOS_ROOT", "/opt/engagements"))
DEFAULT_APPLY_WORKSPACE_ROOT = Path("/tmp/barragan-inbound-request-header-gate")
SAFE_CHANNEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
HTTP_FIELD_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9._~+/=-]{8,20}$")
UNSAFE_HEADER_NAMES = frozenset(
    {
        "connection",
        "content-length",
        "expect",
        "host",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
_FILE_LOCK = threading.Lock()
_ACTIVE_GATE_JOBS_LOCK = threading.Lock()
_ACTIVE_GATE_JOBS: set[str] = set()

CommandRunner = Callable[[list[str], Path | None], subprocess.CompletedProcess[str]]
BackgroundRunner = Callable[[Callable[[], None]], None]


class InboundRequestHeaderGateValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("inbound request-header gate validation failed")
        self.errors = errors


@dataclass(frozen=True)
class RequestHeaderGatePolicy:
    enabled: bool
    header_name: str
    token: str
    updated_at: str
    max_request_body_mb: int = DEFAULT_MAX_REQUEST_BODY_MB

    def to_retained_dict(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "headerName": self.header_name,
            "token": self.token,
            "updatedAt": self.updated_at,
            "maxRequestBodyMb": self.max_request_body_mb,
        }


@dataclass(frozen=True)
class RetainedRequestHeaderGate:
    engagement_id: str
    channel_id: str
    active: RequestHeaderGatePolicy | None
    pending: RequestHeaderGatePolicy | None
    pending_job_id: str | None = None

    def to_retained_dict(self) -> dict[str, object]:
        return {
            "schema": REQUEST_HEADER_GATE_SCHEMA,
            "managedBy": "barragan",
            "engagementId": self.engagement_id,
            "channelId": self.channel_id,
            "active": self.active.to_retained_dict() if self.active is not None else None,
            "pending": self.pending.to_retained_dict() if self.pending is not None else None,
            "pendingJobId": self.pending_job_id,
        }


@dataclass(frozen=True)
class RequestHeaderGateLiveTarget:
    mode: str
    service_name: str
    route_name: str
    backend_host: str
    backend_port: int
    container_name: str = ""
    site_name: str = ""
    site_compose_path: str = ""
    site_config_root: str = ""
    backend_authorization: InboundBackendAuthorization | None = None


def get_inbound_request_header_gate(
    engagement_id: str,
    channel_id: str,
    *,
    engagement_root: Path | None = None,
    workspace_repository: EngagementWorkspaceRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
    repository: JobRepository | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    channel, spec, route, live_target = _supported_channel(
        engagement.name,
        engagement_id,
        channel_id,
        service_repository=service_repository,
    )
    retained = _load_retained(
        engagement_id,
        channel_id,
        engagement_root=_configured_engagement_root(engagement_root),
        workspace_repository=workspace_repository,
        require_workspace=True,
    )
    pending_job = (
        _pending_job(repository or SqlAlchemyJobRepository(), retained)
        if retained is not None and retained.pending is not None
        else None
    )
    return _detail(
        channel,
        spec.external_port,
        route.edge.public_ip or route.edge.ansible_host,
        retained,
        pending_job=pending_job,
        backend_authorization=live_target.backend_authorization,
    )


def load_active_request_header_gate(
    engagement_id: str,
    channel_id: str,
    *,
    engagement_root: Path | None = None,
    workspace_repository: EngagementWorkspaceRepository | None = None,
    require_workspace: bool = False,
) -> dict[str, object] | None:
    """Return only the active retained policy for route re-rendering.

    The pending policy is deliberately never returned here: a process restart or
    failed convergence must continue rendering the last policy proven live.
    """
    retained = _load_retained(
        engagement_id,
        channel_id,
        engagement_root=_configured_engagement_root(engagement_root),
        workspace_repository=workspace_repository,
        require_workspace=require_workspace,
    )
    return retained.active.to_retained_dict() if retained is not None and retained.active is not None else None


def request_header_gate_policy_path(
    engagement_id: str,
    channel_id: str,
    *,
    engagement_root: Path | None = None,
    workspace_repository: EngagementWorkspaceRepository | None = None,
) -> Path:
    """Return the guarded retained-policy path for an already-prepared engagement."""

    return _policy_path(
        engagement_id,
        channel_id,
        engagement_root=_configured_engagement_root(engagement_root),
        workspace_repository=workspace_repository,
    )


def render_retained_https_request_header_gate_playbook(
    engagement_name: str,
    engagement_id: str,
    channel_id: str,
    policy: Mapping[str, Any],
    *,
    service_repository: EngagementServiceRepository | None = None,
) -> str:
    """Render retained HTTPS gate convergence for an inbound-route rebuild."""
    _channel, _spec, _route, target = _supported_channel(
        engagement_name,
        engagement_id,
        channel_id,
        service_repository=service_repository,
    )
    if target.mode != "https-openresty":
        raise InboundRequestHeaderGateValidationError(
            ["Retained HTTPS request-header gate rendering requires an HTTPS/OpenResty channel."]
        )
    normalized = _policy_from_mapping(policy, label="active")
    if normalized is None:
        raise InboundRequestHeaderGateValidationError(["Retained active request-header gate is missing."])
    return _render_https_gate_apply_playbook(
        channel_id=channel_id,
        target=target,
        policy=normalized,
    )


def load_active_https_request_header_gate_for_service(
    engagement_id: str,
    service_id: str,
    *,
    engagement_root: Path | None = None,
    workspace_repository: EngagementWorkspaceRepository | None = None,
) -> dict[str, object] | None:
    matches = [
        channel
        for channel in get_operations_overview(engagement_id).get("inboundChannels", [])
        if str(channel.get("mode") or "") == "https-openresty"
        and str(channel.get("serviceId") or "") == service_id
        and str(channel.get("status") or "").strip().lower() != "removed"
    ]
    if len(matches) > 1:
        raise InboundRequestHeaderGateValidationError(
            [f"Managed Static Web service {service_id} is attached to more than one active HTTPS inbound channel."]
        )
    if not matches:
        return None
    return load_active_request_header_gate(
        engagement_id,
        str(matches[0].get("channelId") or ""),
        engagement_root=engagement_root,
        workspace_repository=workspace_repository,
        require_workspace=False,
    )


def render_https_request_header_gate_hooks(
    policy: Mapping[str, Any],
) -> tuple[str, str]:
    normalized = _policy_from_mapping(policy, label="active")
    if normalized is None:
        raise InboundRequestHeaderGateValidationError(["Retained active request-header gate is missing."])
    header_var = normalized.header_name.lower().replace("-", "_")
    map_content = (
        "\n".join(
            [
                f"map $http_{header_var} $barragan_request_header_gate {{",
                "    default 0;",
                f'    "Bearer {normalized.token}" 1;',
                "}",
                "",
            ]
        )
        if normalized.enabled
        else "# Barragan request-header gate is disabled.\n"
    )
    server_lines = [f"client_max_body_size {normalized.max_request_body_mb * BYTES_PER_MB};"]
    server_lines.append(
        "if ($barragan_request_header_gate = 0) { return 404; }"
        if normalized.enabled
        else "# Barragan request-header gate is disabled."
    )
    server_include = "\n".join(server_lines) + "\n"
    return map_content, server_include


def render_request_header_gate_http_runtime() -> str:
    """Render the per-site runtime marker for request-header-gate files.

    The stock OpenResty image already declares its global map-hash sizing.
    Declaring it again in a site-mounted ``conf.d`` directory makes Nginx
    reject the site as a duplicate directive.  Gate maps for bounded
    operator-configured headers fit the base image's normal sizing, so the
    per-site file deliberately contains no duplicate global setting.
    """

    return "# Map hash sizing is provided by the stock OpenResty base configuration.\n"


def update_inbound_request_header_gate(
    engagement_id: str,
    channel_id: str,
    body: Mapping[str, Any],
    *,
    requested_by: str = "operator",
    engagement_root: Path | None = None,
    workspace_repository: EngagementWorkspaceRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
    repository: JobRepository | None = None,
    runner: CommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    apply_workspace_root: Path = DEFAULT_APPLY_WORKSPACE_ROOT,
    background_runner: BackgroundRunner | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    channel, spec, route, live_target = _supported_channel(
        engagement.name,
        engagement_id,
        channel_id,
        service_repository=service_repository,
    )
    _require_applied_channel(channel)
    if (
        live_target.backend_authorization is not None
        and live_target.backend_authorization.capability_id == "go-simple-upload-server"
    ):
        raise InboundRequestHeaderGateValidationError(
            [
                "GoSUS uses its retained read/write value as this route's mandatory request gate. "
                "It is displayed for operator use and cannot be changed or disabled here."
            ]
        )
    resolved_engagement_root = _configured_engagement_root(engagement_root)
    repo = repository or SqlAlchemyJobRepository()
    policy_path = _policy_path(
        engagement_id,
        channel_id,
        engagement_root=resolved_engagement_root,
        workspace_repository=workspace_repository,
    )
    current = _load_retained(
        engagement_id,
        channel_id,
        engagement_root=resolved_engagement_root,
        workspace_repository=workspace_repository,
        require_workspace=True,
    )
    inventory = _render_inventory(
        spec,
        DEFAULT_CORE_SSH_PRIVATE_KEY,
        "unused-sketch-key",
        _termination_host(spec, DEFAULT_CORE_SSH_PRIVATE_KEY, route),
        route,
    )
    ssh_config = _render_ssh_config(
        spec,
        DEFAULT_CORE_SSH_PRIVATE_KEY,
        "unused-sketch-key",
        _termination_host(spec, DEFAULT_CORE_SSH_PRIVATE_KEY, route),
        route,
    )
    command_runner = runner or _run_command
    if current is not None and current.pending is not None:
        current = _recover_interrupted_pending(
            current,
            policy_path=policy_path,
            repository=repo,
            target=live_target,
            inventory=inventory,
            ssh_config=ssh_config,
            runner=command_runner,
            env=env,
            apply_workspace_root=apply_workspace_root,
        )
    candidate = _candidate_policy(
        body,
        current.active if current is not None else None,
        backend_max_request_body_mb=(
            live_target.backend_authorization.max_request_body_mb
            if live_target.backend_authorization is not None
            else None
        ),
    )
    staged = RetainedRequestHeaderGate(
        engagement_id=engagement_id,
        channel_id=channel_id,
        active=current.active if current is not None else None,
        pending=candidate,
    )
    playbook = _render_gate_apply_playbook(
        channel_id=channel_id,
        target=live_target,
        policy=candidate,
    )
    rollback_policy = current.active if current is not None and current.active is not None else _disabled_policy()
    rollback_playbook = _render_gate_apply_playbook(
        channel_id=channel_id,
        target=live_target,
        policy=rollback_policy,
    )
    ansible = resolve_ansible_playbook(env=env)
    if not ansible.ok or not ansible.command:
        raise InboundRequestHeaderGateValidationError(
            [ansible.error or "Could not resolve ansible-playbook executable"]
        )
    workdir = _write_apply_workspace(
        apply_workspace_root,
        channel_id,
        inventory=inventory,
        ssh_config=ssh_config,
        playbook=playbook,
        rollback_playbook=rollback_playbook,
    )
    identity = current_request_identity()
    actor = identity.username if identity is not None else requested_by
    now = _now()
    job = StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=REQUEST_HEADER_GATE_APPLY_ACTION,
        status="running",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by=actor,
        input={
            "engagementId": engagement_id,
            "channelId": channel_id,
            "proxyId": route.proxy.name,
            "mutation": True,
        },
        # The transient playbook contains the operator-visible value and is
        # intentionally excluded from ordinary job artifact surfaces.
        artifact_refs=[],
        created_at=now,
        started_at=now,
        finished_at=None,
        events=[
            JobEvent(
                1,
                "info",
                "inbound request-header gate convergence started",
                {"channelId": channel_id, "proxyId": route.proxy.name, "enabled": candidate.enabled},
            )
        ],
    )
    _assert_job_does_not_expose_policy(job, candidate)
    try:
        job = reserve_shared_proxy_stack_mutation(
            repo,
            job,
            engagement_id=engagement_id,
            proxy_id=route.proxy.name,
        )
    except SharedProxyStackMutationConflict as exc:
        shutil.rmtree(workdir, ignore_errors=True)
        raise InboundRequestHeaderGateValidationError(
            [f"Shared proxy web-stack mutation already running on {route.proxy.name}: {exc.job.id} ({exc.job.action})"]
        ) from exc

    staged = replace(staged, pending_job_id=job.id)
    _register_active_gate_job(job.id)
    try:
        _write_retained(policy_path, staged)
    except Exception:
        _unregister_active_gate_job(job.id)
        shutil.rmtree(workdir, ignore_errors=True)
        failed = replace(
            job,
            status="failed",
            finished_at=_now(),
            events=[*job.events, JobEvent(2, "error", "request-header gate policy could not be staged", {"channelId": channel_id})],
        )
        repo.save(failed)
        raise

    command = [ansible.command, "-i", "ansible/inventory.ini", "ansible/apply_request_header_gate.yml"]
    rollback_command = [ansible.command, "-i", "ansible/inventory.ini", "ansible/rollback_request_header_gate.yml"]
    task_runner = background_runner or _start_background_task
    try:
        task_runner(
            lambda: _finish_registered_apply(
                repo,
                job,
                command,
                rollback_command,
                workdir,
                command_runner,
                policy_path,
                staged,
                candidate,
            )
        )
    except Exception as exc:
        _unregister_active_gate_job(job.id)
        _fail_apply_start(repo, job, workdir, policy_path, staged, candidate, exc)
        raise InboundRequestHeaderGateValidationError(
            ["Request-header gate convergence could not be started; the retained active policy was preserved."]
        ) from exc
    response = _detail(
        channel,
        spec.external_port,
        route.edge.public_ip or route.edge.ansible_host,
        staged,
        pending_job=job,
        pending_live=True,
        backend_authorization=live_target.backend_authorization,
    )
    response["job"] = job.to_detail().to_dict()
    return response


def render_http_backend_site_config(
    backend_host: str,
    backend_port: int,
    policy: Mapping[str, Any] | RequestHeaderGatePolicy | None = None,
    *,
    backend_authorization: InboundBackendAuthorization | None = None,
    backend_authorization_inventory_group: str = "termination_host",
) -> str:
    from app.services.managed_site_observability import render_managed_site_observability_config

    normalized = _policy_from_mapping(policy, label="active") if isinstance(policy, Mapping) else policy
    # The shared HTTP front uses http proxy_pass, which forwards the client
    # address in a trusted header but cannot send a PROXY-protocol preface.
    # HTTPS instead uses the stream front and receives PROXY protocol in its
    # separate TLS overlay.
    lines: list[str] = [
        render_managed_site_observability_config(receives_proxy_protocol=False).rstrip(),
        "",
    ]
    # GoSUS's established read/write value is deliberately operator-visible
    # client configuration.  A newly typed GoSUS route must enforce that same
    # value before proxying; otherwise bot traffic reaches the service merely
    # to be rejected there.  The value is resolved only as a no-log Homebase
    # fact by the caller, never rendered into a job record or source artifact.
    backend_gate = (
        backend_authorization is not None
        and backend_authorization.capability_id == "go-simple-upload-server"
        and normalized is None
    )
    if normalized is not None and normalized.enabled:
        header_var = normalized.header_name.lower().replace("-", "_")
        lines.extend(
            [
                f"map $http_{header_var} $barragan_request_header_gate {{",
                "    default 0;",
                f'    "Bearer {normalized.token}" 1;',
                "}",
                "",
            ]
        )
    elif backend_gate:
        lines.extend(
            [
                "map $http_authorization $barragan_request_header_gate {",
                "    default 0;",
                f'    "{{{{ hostvars[groups[\'{backend_authorization_inventory_group}\'][0]].barragan_inbound_backend_authorization }}}}" 1;',
                "}",
                "",
            ]
        )
    max_request_body_mb = (
        normalized.max_request_body_mb if normalized is not None else DEFAULT_MAX_REQUEST_BODY_MB
    )
    lines.extend(
        [
            "server {",
            # HTTP reaches this site through the shared front's HTTP proxy,
            # not its TLS stream listener.  A later TLS overlay changes this
            # to a PROXY-protocol TLS listener for the separate HTTPS path.
            "    listen 8081;",
            "    server_name _;",
            f"    client_max_body_size {max_request_body_mb * BYTES_PER_MB};",
        ]
    )
    if (normalized is not None and normalized.enabled) or backend_gate:
        lines.extend(
            [
                "    if ($barragan_request_header_gate = 0) {",
                "        return 404;",
                "    }",
            ]
        )
    lines.extend(
        [
            "    location / {",
            "        proxy_set_header Host $host;",
            "        proxy_set_header X-Real-IP $barragan_original_client_ip;",
            "        proxy_set_header X-Forwarded-For $barragan_original_client_ip;",
            "        proxy_set_header X-Forwarded-Proto $scheme;",
        ]
    )
    if backend_authorization is not None:
        lines.append(f"        {backend_authorization.proxy_header_line(backend_authorization_inventory_group)}")
    lines.extend(
        [
            f"        proxy_pass http://{backend_host}:{backend_port};",
            "    }",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def render_http_backend_effective_config_assertion_tasks(
    *,
    service_name: str,
    config_path: str,
    expected_body_size_bytes: int,
    register_prefix: str,
) -> list[str]:
    """Render post-convergence checks for the terminating HTTP route container.

    A successful compose invocation is not enough: Docker can retain an older
    container or mount after an interrupted reconciliation.  The public route
    terminates here, so verify both the selected mount and OpenResty's loaded
    configuration before declaring a request policy applied.
    """
    mount_register = f"{register_prefix}_mounts"
    config_register = f"{register_prefix}_effective_config"
    config_directory = str(Path(config_path).parent)
    expected_mount = f"{config_directory}:/etc/nginx/conf.d"
    expected_directive = f"client_max_body_size {expected_body_size_bytes};"
    return [
        "    - name: Inspect selected HTTP backend proxy mounts",
        "      ansible.builtin.command:",
        f"        argv: [docker, inspect, {json.dumps(service_name)}]",
        f"      register: {mount_register}",
        "      changed_when: false",
        "    - name: Require selected HTTP backend proxy configuration mount",
        "      ansible.builtin.assert:",
        "        that:",
        "          - ("
        f"{mount_register}.stdout | from_json | map(attribute='Mounts') | first | "
        f"selectattr('Source', 'equalto', {json.dumps(config_directory)}) | "
        "selectattr('Destination', 'equalto', '/etc/nginx/conf.d') | "
        "selectattr('RW', 'equalto', false) | list | length) == 1",
        f"        fail_msg: Selected HTTP backend proxy is not mounted from {expected_mount}.",
        "    - name: Inspect effective selected HTTP backend proxy configuration",
        "      ansible.builtin.command:",
        f"        argv: [docker, exec, {json.dumps(service_name)}, openresty, -T]",
        f"      register: {config_register}",
        "      changed_when: false",
        "      no_log: true",
        "    - name: Require selected HTTP request-body policy in effective configuration",
        "      ansible.builtin.assert:",
        "        that:",
        f"          - {config_register}.stdout is search({json.dumps(expected_directive)}) or {config_register}.stderr is search({json.dumps(expected_directive)})",
        f"        fail_msg: Selected HTTP backend proxy did not load {expected_directive}.",
        "      no_log: true",
    ]


def _supported_channel(
    engagement_name: str,
    engagement_id: str,
    channel_id: str,
    *,
    service_repository: EngagementServiceRepository | None = None,
):
    if not SAFE_CHANNEL_ID.fullmatch(channel_id):
        raise InboundRequestHeaderGateValidationError(["channelId contains unsupported path characters"])
    overview = get_operations_overview(engagement_id)
    channel = _inbound_channel_by_id(overview, channel_id)
    if channel is None:
        raise InboundRequestHeaderGateValidationError([f"inbound channel {channel_id} was not found"])
    mode = str(channel.get("mode") or "").strip()
    if mode not in {"http-openresty", "https-openresty"}:
        raise InboundRequestHeaderGateValidationError(
            ["Request-header gates and request-body limits are supported only for Barragan-managed HTTP/HTTPS OpenResty inbound channels."]
        )
    try:
        spec, route = _resolved_spec_from_channel(engagement_name, overview, channel)
    except InboundChannelApplyValidationError as exc:
        raise InboundRequestHeaderGateValidationError(exc.errors) from exc
    if mode == "http-openresty":
        try:
            backend_authorization = resolve_selected_inbound_backend_authorization(
                engagement_id,
                host_class=_termination_host_class(route),
                port=spec.internal_port,
            )
        except InboundBackendAuthorizationValidationError as exc:
            raise InboundRequestHeaderGateValidationError(exc.errors) from exc
        live_target = RequestHeaderGateLiveTarget(
            mode=mode,
            service_name=http_backend_service_name(channel_id),
            route_name=_safe_http_route_name(channel_id),
            backend_host=(
                route.termination.private_ip or route.termination.public_ip or route.termination.ansible_host
                if route.termination is not None
                else "host.docker.internal"
            ),
            backend_port=spec.internal_port,
            container_name=http_backend_service_name(channel_id),
            site_compose_path=f"/opt/web/sites/{_safe_http_route_name(channel_id)}.compose.yml",
            backend_authorization=backend_authorization,
        )
    else:
        service = _managed_https_service(
            engagement_id,
            channel,
            service_repository or SqlAlchemyEngagementServiceRepository(),
        )
        config = dict(service.config or {})
        site_service = str(
            config["tlsSiteService"] if service.service_type == "web-static" else config["siteService"]
        )
        backend_authorization = None
        if is_managed_http_backend_site(spec):
            try:
                backend_authorization = resolve_selected_inbound_backend_authorization(
                    engagement_id,
                    host_class="homebase",
                    port=_backend_port(spec),
                )
            except InboundBackendAuthorizationValidationError as exc:
                raise InboundRequestHeaderGateValidationError(exc.errors) from exc
        site_config_path = (
            config.get("tlsSiteConfigPath")
            if service.service_type == "web-static"
            else config.get("siteConfigPath")
        )
        live_target = RequestHeaderGateLiveTarget(
            mode=mode,
            service_name=site_service,
            route_name=str(config["siteName"]),
            backend_host="",
            backend_port=spec.internal_port,
            container_name=f"barragan_{site_service}",
            site_name=str(config["siteName"]),
            site_compose_path=str(config["siteComposePath"]),
            site_config_root=str(site_config_path or "").rsplit("/", 1)[0],
            backend_authorization=backend_authorization,
        )
    return channel, spec, route, live_target


def _managed_https_service(
    engagement_id: str,
    channel: Mapping[str, Any],
    repository: EngagementServiceRepository,
) -> StoredEngagementService:
    service_id = str(channel.get("serviceId") or "").strip()
    service = repository.get(engagement_id, service_id) if service_id else None
    if service is None or service.service_type not in {"web-static", "web-http-backend"}:
        raise InboundRequestHeaderGateValidationError(
            ["HTTPS request-header gates require a Barragan-managed Static Web site or managed HTTP backend site target."]
        )
    if service.status not in {"Configured", "Active"}:
        raise InboundRequestHeaderGateValidationError(
            [f"Managed HTTPS site {service.service_id} is {service.status}; configure it before applying a request gate."]
        )
    config = dict(service.config or {})
    site_name = str(config.get("siteName") or "").strip()
    site_service = str(config.get("siteService") or "").strip()
    tls_site_service = str(config.get("tlsSiteService") or "").strip()
    tls_site_config = str(config.get("tlsSiteConfigPath") or "").strip()
    site_compose = str(config.get("siteComposePath") or "").strip()
    proxy = str(channel.get("proxy") or "").split("-", 1)[0]
    service_proxy = str(service.proxy_id or "").split("-", 1)[0]
    valid = (
        service_proxy == proxy
        and str(config.get("domain") or "").strip().lower().rstrip(".")
        == str(channel.get("domain") or "").strip().lower().rstrip(".")
        and config.get("stackModel") == "containerized-openresty-v1"
        and config.get("composePath") == "/opt/web/docker-compose.yml"
        and config.get("stackOwnershipPath") == "/opt/web/.barragan-stack.json"
        and site_compose == f"/opt/web/sites/{site_name}.compose.yml"
        and bool(re.fullmatch(r"[a-z0-9][a-z0-9-]*", site_name))
        and bool(re.fullmatch(r"[a-z0-9][a-z0-9_-]*", site_service))
        and (
            service.service_type != "web-static"
            or (
                tls_site_service == f"{site_service}_tls"
                and tls_site_config == f"/opt/web/{site_name}/tls-conf/default.conf"
            )
        )
    )
    if not valid:
        raise InboundRequestHeaderGateValidationError(
            ["HTTPS request-header gate target is not a valid Barragan-owned HTTPS site placement."]
        )
    return service


def _require_applied_channel(channel: Mapping[str, Any]) -> None:
    status = str(channel.get("status") or "").strip().lower()
    if status not in REQUEST_HEADER_GATE_LIVE_ROUTE_STATUSES:
        raise InboundRequestHeaderGateValidationError(
            ["The HTTP/HTTPS inbound channel must be applied before configuring its request policy."]
        )


def _candidate_policy(
    body: Mapping[str, Any],
    active: RequestHeaderGatePolicy | None,
    *,
    backend_max_request_body_mb: int | None = None,
) -> RequestHeaderGatePolicy:
    if not isinstance(body.get("enabled"), bool):
        raise InboundRequestHeaderGateValidationError(["enabled must be true or false"])
    enabled = bool(body["enabled"])
    header_name = _validated_header_name(str(body.get("headerName") or DEFAULT_HEADER_NAME).strip())
    action = str(body.get("tokenAction") or "keep").strip().lower()
    if action not in {"keep", "generate", "provide"}:
        raise InboundRequestHeaderGateValidationError(["tokenAction must be keep, generate, or provide"])
    if action == "keep":
        token = active.token if active is not None else ""
    elif action == "generate":
        token = secrets.token_urlsafe(15)
    else:
        token = str(body.get("token") or "").strip()
    if enabled and not token:
        raise InboundRequestHeaderGateValidationError(
            ["Enabling the request-header gate requires an existing, generated, or provided token."]
        )
    if token:
        _validate_token(token)
    max_request_body_mb = _validated_max_request_body_mb(
        body.get(
            "maxRequestBodyMb",
            active.max_request_body_mb if active is not None else DEFAULT_MAX_REQUEST_BODY_MB,
        )
    )
    if backend_max_request_body_mb is not None and max_request_body_mb > backend_max_request_body_mb:
        raise InboundRequestHeaderGateValidationError(
            [
                f"maxRequestBodyMb cannot exceed the selected backend capability limit of {backend_max_request_body_mb} MB"
            ]
        )
    return RequestHeaderGatePolicy(enabled, header_name, token, _now(), max_request_body_mb)


def _validated_max_request_body_mb(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InboundRequestHeaderGateValidationError(
            [f"maxRequestBodyMb must be an integer from {MIN_MAX_REQUEST_BODY_MB} to {MAX_MAX_REQUEST_BODY_MB}"]
        )
    if value < MIN_MAX_REQUEST_BODY_MB or value > MAX_MAX_REQUEST_BODY_MB:
        raise InboundRequestHeaderGateValidationError(
            [f"maxRequestBodyMb must be from {MIN_MAX_REQUEST_BODY_MB} to {MAX_MAX_REQUEST_BODY_MB}"]
        )
    return value


def _validated_header_name(value: str) -> str:
    if "\r" in value or "\n" in value or not HTTP_FIELD_NAME.fullmatch(value) or "_" in value:
        raise InboundRequestHeaderGateValidationError(
            ["headerName must be an HTTP field name using letters, numbers, and hyphens"]
        )
    if value.lower() in UNSAFE_HEADER_NAMES:
        raise InboundRequestHeaderGateValidationError([f"headerName {value} cannot be used as a request gate"])
    return "-".join(part[:1].upper() + part[1:].lower() for part in value.split("-"))


def _validate_token(token: str) -> None:
    if not SAFE_TOKEN.fullmatch(token) or "\r" in token or "\n" in token:
        raise InboundRequestHeaderGateValidationError(
            ["token must be 8-20 characters using letters, numbers, period, underscore, tilde, plus, slash, equals, or hyphen"]
        )


def _policy_path(
    engagement_id: str,
    channel_id: str,
    *,
    engagement_root: Path,
    workspace_repository: EngagementWorkspaceRepository | None,
) -> Path:
    try:
        workspace = load_prepared_engagement_workspace(
            engagement_id,
            root=engagement_root,
            repository=workspace_repository or SqlAlchemyEngagementWorkspaceRepository(),
        )
    except EngagementWorkspaceValidationError as exc:
        raise InboundRequestHeaderGateValidationError(exc.errors) from exc
    if workspace is None:
        raise InboundRequestHeaderGateValidationError(["engagement workspace must be prepared before configuring a request-header gate"])
    root = Path(workspace.path).resolve(strict=True)
    relative = Path("barragan") / "inbound-channels" / channel_id / "request-header-gate.json"
    candidate = root / relative
    _assert_safe_workspace_path(root, candidate)
    return candidate


def _load_retained(
    engagement_id: str,
    channel_id: str,
    *,
    engagement_root: Path,
    workspace_repository: EngagementWorkspaceRepository | None,
    require_workspace: bool,
) -> RetainedRequestHeaderGate | None:
    try:
        path = _policy_path(
            engagement_id,
            channel_id,
            engagement_root=engagement_root,
            workspace_repository=workspace_repository,
        )
    except InboundRequestHeaderGateValidationError:
        if require_workspace:
            raise
        return None
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise InboundRequestHeaderGateValidationError(["retained request-header gate path is not a regular file"])
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise InboundRequestHeaderGateValidationError(["retained request-header gate is not valid JSON"]) from exc
    if (
        not isinstance(raw, dict)
        or raw.get("schema") != REQUEST_HEADER_GATE_SCHEMA
        or raw.get("managedBy") != "barragan"
        or raw.get("engagementId") != engagement_id
        or raw.get("channelId") != channel_id
    ):
        raise InboundRequestHeaderGateValidationError(["retained request-header gate ownership metadata is invalid"])
    active = _policy_from_mapping(raw.get("active"), label="active")
    pending = _policy_from_mapping(raw.get("pending"), label="pending")
    pending_job_id = str(raw.get("pendingJobId") or "").strip() or None
    if pending_job_id is not None and pending is None:
        raise InboundRequestHeaderGateValidationError(
            ["retained request-header gate has a pending job without a pending policy"]
        )
    return RetainedRequestHeaderGate(engagement_id, channel_id, active, pending, pending_job_id)


def _policy_from_mapping(value: Any, *, label: str) -> RequestHeaderGatePolicy | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or not isinstance(value.get("enabled"), bool):
        raise InboundRequestHeaderGateValidationError([f"retained {label} request-header gate is invalid"])
    header_name = _validated_header_name(str(value.get("headerName") or ""))
    token = str(value.get("token") or "")
    if token:
        _validate_token(token)
    if bool(value["enabled"]) and not token:
        raise InboundRequestHeaderGateValidationError([f"retained {label} request-header gate has no token"])
    return RequestHeaderGatePolicy(
        enabled=bool(value["enabled"]),
        header_name=header_name,
        token=token,
        updated_at=str(value.get("updatedAt") or ""),
        max_request_body_mb=_validated_max_request_body_mb(
            value.get("maxRequestBodyMb", DEFAULT_MAX_REQUEST_BODY_MB)
        ),
    )


def _assert_safe_workspace_path(workspace_root: Path, path: Path) -> None:
    if path == workspace_root or workspace_root not in path.resolve(strict=False).parents:
        raise InboundRequestHeaderGateValidationError(["request-header gate path escapes the engagement workspace"])
    current = workspace_root
    for part in path.relative_to(workspace_root).parts:
        current = current / part
        if current.exists() and current.is_symlink():
            raise InboundRequestHeaderGateValidationError(["request-header gate path must not contain symlinks"])


def _write_retained(path: Path, retained: RetainedRequestHeaderGate) -> None:
    if retained.active is not None:
        _policy_from_mapping(retained.active.to_retained_dict(), label="active")
    if retained.pending is not None:
        _policy_from_mapping(retained.pending.to_retained_dict(), label="pending")
    with _FILE_LOCK:
        root = path.parents[3]
        _assert_safe_workspace_path(root, path)
        for directory in (path.parents[2], path.parents[1], path.parent):
            if directory.exists() and (directory.is_symlink() or not directory.is_dir()):
                raise InboundRequestHeaderGateValidationError(["request-header gate parent must be a regular directory"])
            directory.mkdir(exist_ok=True, mode=0o700)
            os.chmod(directory, 0o700)
        if path.exists() and path.is_symlink():
            raise InboundRequestHeaderGateValidationError(["request-header gate path must not be a symlink"])
        payload = json.dumps(retained.to_retained_dict(), indent=2, sort_keys=True) + "\n"
        temp = path.parent / f".{path.name}.{uuid4().hex}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(temp, flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, path)
            os.chmod(path, 0o600)
        finally:
            if temp.exists():
                temp.unlink()


def _write_apply_workspace(
    root: Path,
    channel_id: str,
    *,
    inventory: str,
    ssh_config: str,
    playbook: str,
    rollback_playbook: str | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    workdir = Path(tempfile.mkdtemp(prefix=f"{channel_id}-", dir=root))
    os.chmod(workdir, 0o700)
    ansible_dir = workdir / "ansible"
    ansible_dir.mkdir(mode=0o700)
    files = [
        ("inventory.ini", inventory),
        ("ssh_config", ssh_config),
        ("apply_request_header_gate.yml", playbook),
    ]
    if rollback_playbook is not None:
        files.append(("rollback_request_header_gate.yml", rollback_playbook))
    for name, content in files:
        path = ansible_dir / name
        path.write_text(content, encoding="utf-8")
        os.chmod(path, 0o600)
    return workdir


def _render_gate_apply_playbook(
    *,
    channel_id: str,
    target: RequestHeaderGateLiveTarget,
    policy: RequestHeaderGatePolicy,
) -> str:
    if target.mode == "https-openresty":
        return _render_https_gate_apply_playbook(channel_id=channel_id, target=target, policy=policy)
    config = render_http_backend_site_config(
        target.backend_host,
        target.backend_port,
        policy,
        backend_authorization=target.backend_authorization,
        backend_authorization_inventory_group="termination_host",
    )
    service_name = target.service_name
    route_name = target.route_name
    site_compose_path = target.site_compose_path or f"/opt/web/sites/{route_name}.compose.yml"
    sections: list[str] = ["---"]
    if target.backend_authorization is not None:
        sections.extend(
            [
                *render_backend_authorization_fact_play(
                    target.backend_authorization,
                    inventory_group="termination_host",
                ),
                "",
            ]
        )
    sections.extend(
        [
            "- name: Converge one inbound request-header gate",
            "  hosts: selected_proxy",
            "  gather_facts: false",
            "  become: true",
            "  vars:",
            f"    barragan_gate_channel_id: {json.dumps(channel_id)}",
            f"    barragan_gate_service_name: {json.dumps(service_name)}",
            f"    barragan_gate_site_compose: {json.dumps(site_compose_path)}",
            f"    barragan_gate_config_path: {json.dumps(f'/opt/web/inbound/{route_name}/conf/default.conf')}",
            f"    barragan_gate_backup_path: {json.dumps(f'/opt/web/inbound/{route_name}/conf/.default.conf.barragan-backup')}",
            "  tasks:",
            "    - name: Require Barragan-owned shared proxy stack and selected route",
            "      ansible.builtin.shell:",
            "        cmd: python3 -c \"import json,pathlib,sys; owner=pathlib.Path('/opt/web/.barragan-stack.json'); paths=[pathlib.Path(v) for v in sys.argv[1:]]; expected={'managedBy':'barragan','stackModel':'containerized-openresty-v1'}; ok=owner.is_file() and not owner.is_symlink() and json.loads(owner.read_text()) == expected and all(p.is_file() and not p.is_symlink() for p in paths); sys.exit(0 if ok else 1)\" '{{ barragan_gate_config_path }}' '{{ barragan_gate_site_compose }}'",
            "      changed_when: false",
            "    - name: Apply request-header gate transactionally",
            "      block:",
            "        - name: Back up active route configuration",
            "          ansible.builtin.copy:",
            "            remote_src: true",
            "            src: \"{{ barragan_gate_config_path }}\"",
            "            dest: \"{{ barragan_gate_backup_path }}\"",
            "            mode: '0600'",
            "        - name: Write candidate request-header gate configuration",
            "          ansible.builtin.copy:",
            "            dest: \"{{ barragan_gate_config_path }}\"",
            "            owner: root",
            "            group: redteam",
            "            mode: '0640'",
            "            content: |",
            *_indent_lines(config, 14),
            "          no_log: true",
            "        - name: Remove only the selected HTTP backend containers before candidate start",
            "          ansible.builtin.command:",
            "            argv: [docker, rm, -f, \"{{ barragan_gate_service_name }}\", \"web_{{ barragan_gate_service_name }}_1\"]",
            "          register: barragan_gate_candidate_remove",
            "          changed_when: barragan_gate_candidate_remove.rc == 0",
            "          failed_when: false",
            "        - name: Find renamed selected HTTP backend Compose containers for candidate start",
            "          ansible.builtin.command:",
            "            argv: [docker, ps, -aq, --filter, \"label=com.docker.compose.project=web\", --filter, \"label=com.docker.compose.service={{ barragan_gate_service_name }}\"]",
            "          register: barragan_gate_candidate_compose_containers",
            "          changed_when: false",
            "        - name: Remove renamed selected HTTP backend Compose containers for candidate start",
            "          ansible.builtin.command:",
            "            argv: [docker, rm, -f, \"{{ item }}\"]",
            "          loop: \"{{ barragan_gate_candidate_compose_containers.stdout_lines }}\"",
            "          when: item | length > 0",
            "        - name: Start selected HTTP backend with candidate gate configuration",
            "          ansible.builtin.command:",
            "            argv: [docker, compose, -f, /opt/web/docker-compose.yml, -f, \"{{ barragan_gate_site_compose }}\", up, -d, \"{{ barragan_gate_service_name }}\"]",
            "        - name: Validate candidate route configuration",
            "          ansible.builtin.command:",
            "            argv: [docker, exec, \"{{ barragan_gate_service_name }}\", openresty, -t]",
            "          changed_when: false",
            *[
                f"    {line}" if line else line
                for line in render_http_backend_effective_config_assertion_tasks(
                    service_name="{{ barragan_gate_service_name }}",
                    config_path=f"/opt/web/inbound/{route_name}/conf/default.conf",
                    expected_body_size_bytes=policy.max_request_body_mb * BYTES_PER_MB,
                    register_prefix="barragan_gate_candidate",
                )
            ],
            "        - name: Reload candidate route configuration",
            "          ansible.builtin.command:",
            "            argv: [docker, exec, \"{{ barragan_gate_service_name }}\", openresty, -s, reload]",
            "      rescue:",
            "        - name: Restore prior route configuration",
            "          ansible.builtin.copy:",
            "            remote_src: true",
            "            src: \"{{ barragan_gate_backup_path }}\"",
            "            dest: \"{{ barragan_gate_config_path }}\"",
            "            mode: '0640'",
            "          no_log: true",
            "        - name: Remove only the selected HTTP backend containers before restored start",
            "          ansible.builtin.command:",
            "            argv: [docker, rm, -f, \"{{ barragan_gate_service_name }}\", \"web_{{ barragan_gate_service_name }}_1\"]",
            "          register: barragan_gate_restored_remove",
            "          changed_when: barragan_gate_restored_remove.rc == 0",
            "          failed_when: false",
            "        - name: Find renamed selected HTTP backend Compose containers for restored start",
            "          ansible.builtin.command:",
            "            argv: [docker, ps, -aq, --filter, \"label=com.docker.compose.project=web\", --filter, \"label=com.docker.compose.service={{ barragan_gate_service_name }}\"]",
            "          register: barragan_gate_restored_compose_containers",
            "          changed_when: false",
            "        - name: Remove renamed selected HTTP backend Compose containers for restored start",
            "          ansible.builtin.command:",
            "            argv: [docker, rm, -f, \"{{ item }}\"]",
            "          loop: \"{{ barragan_gate_restored_compose_containers.stdout_lines }}\"",
            "          when: item | length > 0",
            "        - name: Start selected HTTP backend with restored route configuration",
            "          ansible.builtin.command:",
            "            argv: [docker, compose, -f, /opt/web/docker-compose.yml, -f, \"{{ barragan_gate_site_compose }}\", up, -d, \"{{ barragan_gate_service_name }}\"]",
            "        - name: Validate restored route configuration",
            "          ansible.builtin.command:",
            "            argv: [docker, exec, \"{{ barragan_gate_service_name }}\", openresty, -t]",
            "          changed_when: false",
            "        - name: Reload restored route configuration",
            "          ansible.builtin.command:",
            "            argv: [docker, exec, \"{{ barragan_gate_service_name }}\", openresty, -s, reload]",
            "        - name: Report failed gate convergence after rollback",
            "          ansible.builtin.fail:",
            "            msg: Request-header gate convergence failed; the prior route configuration was restored.",
            "      always:",
            "        - name: Remove route configuration backup",
            "          ansible.builtin.file:",
            "            path: \"{{ barragan_gate_backup_path }}\"",
            "            state: absent",
            "          no_log: true",
            "",
        ]
    )
    return "\n".join(sections)


def _render_https_gate_apply_playbook(
    *,
    channel_id: str,
    target: RequestHeaderGateLiveTarget,
    policy: RequestHeaderGatePolicy,
) -> str:
    map_content, server_include = render_https_request_header_gate_hooks(policy.to_retained_dict())
    runtime_content = render_request_header_gate_http_runtime()
    site_root = target.site_config_root or f"/opt/web/{target.site_name}/conf"
    runtime_path = f"{site_root}/00-request-header-gate-00-runtime.conf"
    map_path = f"{site_root}/00-request-header-gate-map.conf"
    include_path = f"{site_root}/request-header-gate.inc"
    default_path = f"{site_root}/default.conf"
    compose_path = target.site_compose_path
    # Older Compose deployments named this container `barragan_<service>`, while
    # current Compose may choose a project-prefixed name.  Keep the old name only
    # as a narrowly-scoped cleanup candidate; resolve the running container by
    # its Compose labels before validating or reloading the selected site.
    legacy_container_name = target.container_name or f"barragan_{target.service_name}"
    old_mount = f"{default_path}:/etc/nginx/conf.d/default.conf:ro"
    new_mount = f"{site_root}:/etc/nginx/conf.d:ro"
    return "\n".join(
        [
            "---",
            "- name: Converge one managed HTTPS request-header gate",
            "  hosts: selected_proxy",
            "  gather_facts: false",
            "  become: true",
            "  vars:",
            f"    barragan_gate_channel_id: {json.dumps(channel_id)}",
            f"    barragan_gate_service_name: {json.dumps(target.service_name)}",
            f"    barragan_gate_legacy_container_name: {json.dumps(legacy_container_name)}",
            f"    barragan_gate_site_compose: {json.dumps(compose_path)}",
            f"    barragan_gate_default_path: {json.dumps(default_path)}",
            f"    barragan_gate_runtime_path: {json.dumps(runtime_path)}",
            f"    barragan_gate_map_path: {json.dumps(map_path)}",
            f"    barragan_gate_include_path: {json.dumps(include_path)}",
            "  tasks:",
            "    - name: Require Barragan-owned HTTPS site files",
            "      ansible.builtin.shell:",
            "        cmd: python3 -c \"import json,pathlib,sys; owner=pathlib.Path('/opt/web/.barragan-stack.json'); paths=[pathlib.Path(v) for v in sys.argv[1:]]; expected={'managedBy':'barragan','stackModel':'containerized-openresty-v1'}; ok=owner.is_file() and not owner.is_symlink() and json.loads(owner.read_text()) == expected and all(p.is_file() and not p.is_symlink() for p in paths); sys.exit(0 if ok else 1)\" '{{ barragan_gate_default_path }}' '{{ barragan_gate_site_compose }}'",
            "      changed_when: false",
            "    - name: Inspect prior gate map",
            "      ansible.builtin.stat:",
            "        path: \"{{ barragan_gate_map_path }}\"",
            "      register: barragan_prior_gate_map",
            "    - name: Inspect prior gate HTTP runtime",
            "      ansible.builtin.stat:",
            "        path: \"{{ barragan_gate_runtime_path }}\"",
            "      register: barragan_prior_gate_runtime",
            "    - name: Inspect prior gate server include",
            "      ansible.builtin.stat:",
            "        path: \"{{ barragan_gate_include_path }}\"",
            "      register: barragan_prior_gate_include",
            "    - name: Apply HTTPS request-header gate transactionally",
            "      block:",
            "        - name: Back up selected site configuration",
            "          ansible.builtin.copy:",
            "            remote_src: true",
            "            src: \"{{ item.src }}\"",
            "            dest: \"{{ item.dest }}\"",
            "            mode: '0600'",
            "          loop:",
            "            - {src: \"{{ barragan_gate_default_path }}\", dest: \"{{ barragan_gate_default_path }}.barragan-backup\"}",
            "            - {src: \"{{ barragan_gate_site_compose }}\", dest: \"{{ barragan_gate_site_compose }}.barragan-backup\"}",
            "        - name: Back up prior optional gate files",
            "          ansible.builtin.copy:",
            "            remote_src: true",
            "            src: \"{{ item.src }}\"",
            "            dest: \"{{ item.dest }}\"",
            "            mode: '0600'",
            "          loop:",
            "            - {src: \"{{ barragan_gate_runtime_path }}\", dest: \"{{ barragan_gate_runtime_path }}.barragan-backup\", present: \"{{ barragan_prior_gate_runtime.stat.exists }}\"}",
            "            - {src: \"{{ barragan_gate_map_path }}\", dest: \"{{ barragan_gate_map_path }}.barragan-backup\", present: \"{{ barragan_prior_gate_map.stat.exists }}\"}",
            "            - {src: \"{{ barragan_gate_include_path }}\", dest: \"{{ barragan_gate_include_path }}.barragan-backup\", present: \"{{ barragan_prior_gate_include.stat.exists }}\"}",
            "          when: item.present | bool",
            "          no_log: true",
            "        - name: Remove prior request gate hook directives from the managed HTTPS server",
            "          ansible.builtin.replace:",
            "            path: \"{{ barragan_gate_default_path }}\"",
            "            regexp: '(?m)^\\s*include /etc/nginx/conf\\.d/request-header-gate(?:\\*|)\\.inc;\\s*\\n?'",
            "            replace: ''",
            "        - name: Write candidate HTTPS gate HTTP runtime",
            "          ansible.builtin.copy:",
            "            dest: \"{{ barragan_gate_runtime_path }}\"",
            "            owner: root",
            "            group: redteam",
            "            mode: '0640'",
            "            content: |",
            *_indent_lines(runtime_content, 14),
            "        - name: Keep one optional request gate hook inside the managed HTTPS server",
            "          ansible.builtin.lineinfile:",
            "            path: \"{{ barragan_gate_default_path }}\"",
            "            insertafter: '^server \\{'",
            "            line: '    include /etc/nginx/conf.d/request-header-gate*.inc;'",
            "            state: present",
            "        - name: Mount the complete managed site configuration directory",
            "          ansible.builtin.replace:",
            "            path: \"{{ barragan_gate_site_compose }}\"",
            f"            regexp: {json.dumps(re.escape(old_mount))}",
            f"            replace: {json.dumps(new_mount)}",
            "        - name: Write candidate HTTPS gate map",
            "          ansible.builtin.copy:",
            "            dest: \"{{ barragan_gate_map_path }}\"",
            "            owner: root",
            "            group: redteam",
            "            mode: '0640'",
            "            content: |",
            *_indent_lines(map_content, 14),
            "          no_log: true",
            "        - name: Write candidate HTTPS gate server hook",
            "          ansible.builtin.copy:",
            "            dest: \"{{ barragan_gate_include_path }}\"",
            "            owner: root",
            "            group: redteam",
            "            mode: '0640'",
            "            content: |",
            *_indent_lines(server_include, 14),
            "          no_log: true",
            "        - name: Remove only the selected HTTPS site container before candidate start",
            "          ansible.builtin.command:",
            "            argv: [docker, rm, -f, \"{{ barragan_gate_legacy_container_name }}\"]",
            "          register: barragan_https_gate_candidate_remove",
            "          changed_when: barragan_https_gate_candidate_remove.rc == 0",
            "          failed_when: false",
            "        - name: Find renamed selected HTTPS site Compose containers for candidate start",
            "          ansible.builtin.command:",
            "            argv: [docker, ps, -aq, --filter, \"label=com.docker.compose.project=web\", --filter, \"label=com.docker.compose.service={{ barragan_gate_service_name }}\"]",
            "          register: barragan_https_gate_candidate_compose_containers",
            "          changed_when: false",
            "        - name: Remove renamed selected HTTPS site Compose containers for candidate start",
            "          ansible.builtin.command:",
            "            argv: [docker, rm, -f, \"{{ item }}\"]",
            "          loop: \"{{ barragan_https_gate_candidate_compose_containers.stdout_lines }}\"",
            "          when: item | length > 0",
            "        - name: Start selected HTTPS site with candidate gate mounts",
            "          ansible.builtin.command:",
            "            argv: [docker, compose, -f, /opt/web/docker-compose.yml, -f, \"{{ barragan_gate_site_compose }}\", up, -d, \"{{ barragan_gate_service_name }}\"]",
            "        - name: Find running selected HTTPS site container for candidate gate",
            "          ansible.builtin.command:",
            "            argv: [docker, ps, -q, --filter, \"label=com.docker.compose.project=web\", --filter, \"label=com.docker.compose.service={{ barragan_gate_service_name }}\"]",
            "          register: barragan_https_gate_candidate_running",
            "          changed_when: false",
            "        - name: Require exactly one running selected HTTPS site container for candidate gate",
            "          ansible.builtin.assert:",
            "            that:",
            "              - barragan_https_gate_candidate_running.stdout_lines | select | list | length == 1",
            "            fail_msg: Selected HTTPS site did not start as exactly one Compose-managed container.",
            "        - name: Select running HTTPS site container for candidate gate",
            "          ansible.builtin.set_fact:",
            "            barragan_https_gate_candidate_container_id: \"{{ (barragan_https_gate_candidate_running.stdout_lines | select | list)[0] }}\"",
            "        - name: Validate candidate HTTPS gate",
            "          ansible.builtin.command:",
            "            argv: [docker, exec, \"{{ barragan_https_gate_candidate_container_id }}\", openresty, -t]",
            "          changed_when: false",
            "        - name: Reload candidate HTTPS gate",
            "          ansible.builtin.command:",
            "            argv: [docker, exec, \"{{ barragan_https_gate_candidate_container_id }}\", openresty, -s, reload]",
            "      rescue:",
            "        - name: Restore selected site and compose files",
            "          ansible.builtin.copy:",
            "            remote_src: true",
            "            src: \"{{ item.src }}\"",
            "            dest: \"{{ item.dest }}\"",
            "            mode: '0640'",
            "          loop:",
            "            - {src: \"{{ barragan_gate_default_path }}.barragan-backup\", dest: \"{{ barragan_gate_default_path }}\"}",
            "            - {src: \"{{ barragan_gate_site_compose }}.barragan-backup\", dest: \"{{ barragan_gate_site_compose }}\"}",
            "        - name: Restore prior optional gate files",
            "          ansible.builtin.copy:",
            "            remote_src: true",
            "            src: \"{{ item.src }}.barragan-backup\"",
            "            dest: \"{{ item.src }}\"",
            "            mode: '0640'",
            "          loop:",
            "            - {src: \"{{ barragan_gate_runtime_path }}\", present: \"{{ barragan_prior_gate_runtime.stat.exists }}\"}",
            "            - {src: \"{{ barragan_gate_map_path }}\", present: \"{{ barragan_prior_gate_map.stat.exists }}\"}",
            "            - {src: \"{{ barragan_gate_include_path }}\", present: \"{{ barragan_prior_gate_include.stat.exists }}\"}",
            "          when: item.present | bool",
            "          no_log: true",
            "        - name: Remove newly introduced optional gate files",
            "          ansible.builtin.file:",
            "            path: \"{{ item.src }}\"",
            "            state: absent",
            "          loop:",
            "            - {src: \"{{ barragan_gate_runtime_path }}\", present: \"{{ barragan_prior_gate_runtime.stat.exists }}\"}",
            "            - {src: \"{{ barragan_gate_map_path }}\", present: \"{{ barragan_prior_gate_map.stat.exists }}\"}",
            "            - {src: \"{{ barragan_gate_include_path }}\", present: \"{{ barragan_prior_gate_include.stat.exists }}\"}",
            "          when: not (item.present | bool)",
            "          no_log: true",
            "        - name: Remove only the selected HTTPS site container before restored start",
            "          ansible.builtin.command:",
            "            argv: [docker, rm, -f, \"{{ barragan_gate_legacy_container_name }}\"]",
            "          register: barragan_https_gate_restored_remove",
            "          changed_when: barragan_https_gate_restored_remove.rc == 0",
            "          failed_when: false",
            "        - name: Find renamed selected HTTPS site Compose containers for restored start",
            "          ansible.builtin.command:",
            "            argv: [docker, ps, -aq, --filter, \"label=com.docker.compose.project=web\", --filter, \"label=com.docker.compose.service={{ barragan_gate_service_name }}\"]",
            "          register: barragan_https_gate_restored_compose_containers",
            "          changed_when: false",
            "        - name: Remove renamed selected HTTPS site Compose containers for restored start",
            "          ansible.builtin.command:",
            "            argv: [docker, rm, -f, \"{{ item }}\"]",
            "          loop: \"{{ barragan_https_gate_restored_compose_containers.stdout_lines }}\"",
            "          when: item | length > 0",
            "        - name: Start restored selected HTTPS site",
            "          ansible.builtin.command:",
            "            argv: [docker, compose, -f, /opt/web/docker-compose.yml, -f, \"{{ barragan_gate_site_compose }}\", up, -d, \"{{ barragan_gate_service_name }}\"]",
            "        - name: Find running restored HTTPS site container",
            "          ansible.builtin.command:",
            "            argv: [docker, ps, -q, --filter, \"label=com.docker.compose.project=web\", --filter, \"label=com.docker.compose.service={{ barragan_gate_service_name }}\"]",
            "          register: barragan_https_gate_restored_running",
            "          changed_when: false",
            "        - name: Require exactly one running restored HTTPS site container",
            "          ansible.builtin.assert:",
            "            that:",
            "              - barragan_https_gate_restored_running.stdout_lines | select | list | length == 1",
            "            fail_msg: Restored HTTPS site did not start as exactly one Compose-managed container.",
            "        - name: Select running restored HTTPS site container",
            "          ansible.builtin.set_fact:",
            "            barragan_https_gate_restored_container_id: \"{{ (barragan_https_gate_restored_running.stdout_lines | select | list)[0] }}\"",
            "        - name: Validate restored selected HTTPS site",
            "          ansible.builtin.command:",
            "            argv: [docker, exec, \"{{ barragan_https_gate_restored_container_id }}\", openresty, -t]",
            "          changed_when: false",
            "        - name: Report failed HTTPS gate convergence after rollback",
            "          ansible.builtin.fail:",
            "            msg: HTTPS request-header gate convergence failed; the prior site configuration was restored.",
            "      always:",
            "        - name: Remove HTTPS gate transaction backups",
            "          ansible.builtin.file:",
            "            path: \"{{ item }}\"",
            "            state: absent",
            "          loop:",
            "            - \"{{ barragan_gate_default_path }}.barragan-backup\"",
            "            - \"{{ barragan_gate_site_compose }}.barragan-backup\"",
            "            - \"{{ barragan_gate_runtime_path }}.barragan-backup\"",
            "            - \"{{ barragan_gate_map_path }}.barragan-backup\"",
            "            - \"{{ barragan_gate_include_path }}.barragan-backup\"",
            "          no_log: true",
            "",
        ]
    )


def _indent_lines(value: str, spaces: int) -> list[str]:
    prefix = " " * spaces
    return [prefix + line if line else prefix for line in value.splitlines()]


def _recover_interrupted_pending(
    retained: RetainedRequestHeaderGate,
    *,
    policy_path: Path,
    repository: JobRepository,
    target: RequestHeaderGateLiveTarget,
    inventory: str,
    ssh_config: str,
    runner: CommandRunner,
    env: Mapping[str, str] | None,
    apply_workspace_root: Path,
) -> RetainedRequestHeaderGate:
    pending_job = _pending_job(repository, retained)
    pending_job_id = retained.pending_job_id or (pending_job.id if pending_job is not None else "")
    if pending_job_id and _active_gate_job(pending_job_id):
        raise InboundRequestHeaderGateValidationError(
            ["A request-header gate mutation is already pending for this inbound channel."]
        )

    rollback_policy = retained.active if retained.active is not None else _disabled_policy()
    ansible = resolve_ansible_playbook(env=env)
    if not ansible.ok or not ansible.command:
        raise InboundRequestHeaderGateValidationError(
            [
                ansible.error
                or "Could not resolve ansible-playbook executable to recover the interrupted request-header gate"
            ]
        )
    rollback_playbook = _render_gate_apply_playbook(
        channel_id=retained.channel_id,
        target=target,
        policy=rollback_policy,
    )
    workdir = _write_apply_workspace(
        apply_workspace_root,
        retained.channel_id,
        inventory=inventory,
        ssh_config=ssh_config,
        playbook=rollback_playbook,
    )
    command = [ansible.command, "-i", "ansible/inventory.ini", "ansible/apply_request_header_gate.yml"]
    try:
        result = runner(command, workdir)
        recovered_live = result.returncode == 0
    except Exception:
        result = None
        recovered_live = False
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    if not recovered_live:
        if pending_job is not None:
            failed = replace(
                pending_job,
                status="failed",
                finished_at=_now(),
                events=[
                    *pending_job.events,
                    JobEvent(
                        len(pending_job.events) + 1,
                        "error",
                        "interrupted request-header gate could not reconverge the retained active policy",
                        {
                            "channelId": retained.channel_id,
                            "interrupted": True,
                            "recoveryRequired": True,
                            "returnCode": result.returncode if result is not None else None,
                        },
                    ),
                ],
            )
            if retained.pending is not None:
                _assert_job_does_not_expose_policy(failed, retained.pending)
            repository.save(failed)
        raise InboundRequestHeaderGateValidationError(
            [
                "The interrupted request-header gate could not restore the retained active policy; retry after correcting the management path."
            ]
        )

    recovered = RetainedRequestHeaderGate(
        retained.engagement_id,
        retained.channel_id,
        retained.active,
        None,
        None,
    )
    _write_retained(policy_path, recovered)
    if pending_job is not None:
        failed = replace(
            pending_job,
            status="failed",
            finished_at=_now(),
            events=[
                *pending_job.events,
                JobEvent(
                    len(pending_job.events) + 1,
                    "error",
                    "request-header gate convergence was interrupted; retained active policy was reconverged",
                    {
                        "channelId": retained.channel_id,
                        "interrupted": True,
                        "retainedPolicyReconverged": True,
                    },
                ),
            ],
        )
        if retained.pending is not None:
            _assert_job_does_not_expose_policy(failed, retained.pending)
        repository.save(failed)
    return recovered


def _disabled_policy() -> RequestHeaderGatePolicy:
    return RequestHeaderGatePolicy(False, DEFAULT_HEADER_NAME, "", _now(), DEFAULT_MAX_REQUEST_BODY_MB)


def _pending_job(
    repository: JobRepository,
    retained: RetainedRequestHeaderGate,
) -> StoredJobRun | None:
    if retained.pending_job_id:
        job = repository.get(retained.pending_job_id)
        if job is not None:
            return job
    try:
        jobs = repository.list_for_engagement(retained.engagement_id, limit=100)
    except (AttributeError, TypeError):
        jobs = repository.list()
    return next(
        (
            job
            for job in jobs
            if job.action == REQUEST_HEADER_GATE_APPLY_ACTION
            and str(job.input.get("channelId") or "") == retained.channel_id
            and job.status in {"queued", "running"}
        ),
        None,
    )


def _register_active_gate_job(job_id: str) -> None:
    with _ACTIVE_GATE_JOBS_LOCK:
        _ACTIVE_GATE_JOBS.add(job_id)


def _unregister_active_gate_job(job_id: str) -> None:
    with _ACTIVE_GATE_JOBS_LOCK:
        _ACTIVE_GATE_JOBS.discard(job_id)


def _active_gate_job(job_id: str) -> bool:
    with _ACTIVE_GATE_JOBS_LOCK:
        return job_id in _ACTIVE_GATE_JOBS


def _finish_registered_apply(
    repo: JobRepository,
    job: StoredJobRun,
    command: list[str],
    rollback_command: list[str],
    workdir: Path,
    runner: CommandRunner,
    policy_path: Path,
    staged: RetainedRequestHeaderGate,
    candidate: RequestHeaderGatePolicy,
) -> None:
    try:
        _finish_apply(
            repo,
            job,
            command,
            rollback_command,
            workdir,
            runner,
            policy_path,
            staged,
            candidate,
        )
    finally:
        _unregister_active_gate_job(job.id)


def _fail_apply_start(
    repo: JobRepository,
    job: StoredJobRun,
    workdir: Path,
    policy_path: Path,
    staged: RetainedRequestHeaderGate,
    candidate: RequestHeaderGatePolicy,
    error: Exception,
) -> None:
    try:
        _write_retained(
            policy_path,
            RetainedRequestHeaderGate(staged.engagement_id, staged.channel_id, staged.active, None),
        )
    finally:
        failed = replace(
            job,
            status="failed",
            finished_at=_now(),
            events=[
                *job.events,
                JobEvent(
                    len(job.events) + 1,
                    "error",
                    "request-header gate convergence could not be started; retained active policy was preserved",
                    {"channelId": staged.channel_id, "errorType": type(error).__name__},
                ),
            ],
        )
        _assert_job_does_not_expose_policy(failed, candidate)
        repo.save(failed)
        shutil.rmtree(workdir, ignore_errors=True)


def _finish_apply(
    repo: JobRepository,
    job: StoredJobRun,
    command: list[str],
    rollback_command: list[str],
    workdir: Path,
    runner: CommandRunner,
    policy_path: Path,
    staged: RetainedRequestHeaderGate,
    candidate: RequestHeaderGatePolicy,
) -> None:
    try:
        try:
            result = runner(command, workdir)
        except Exception as exc:
            _rollback_ambiguous_apply(
                repo,
                job,
                rollback_command,
                workdir,
                runner,
                policy_path,
                staged,
                candidate,
                error_type=type(exc).__name__,
                candidate_return_code=None,
            )
            return
        if result.returncode != 0:
            _rollback_ambiguous_apply(
                repo,
                job,
                rollback_command,
                workdir,
                runner,
                policy_path,
                staged,
                candidate,
                error_type="CommandFailed",
                candidate_return_code=result.returncode,
            )
            return
        try:
            _write_retained(
                policy_path,
                RetainedRequestHeaderGate(
                    staged.engagement_id,
                    staged.channel_id,
                    candidate,
                    None,
                ),
            )
        except Exception as exc:
            _rollback_ambiguous_apply(
                repo,
                job,
                rollback_command,
                workdir,
                runner,
                policy_path,
                staged,
                candidate,
                error_type=type(exc).__name__,
                candidate_return_code=result.returncode,
            )
            return
        final = replace(
            job,
            status="succeeded",
            finished_at=_now(),
            events=[
                *job.events,
                JobEvent(
                    len(job.events) + 1,
                    "info",
                    "inbound request-header gate convergence succeeded",
                    {"channelId": staged.channel_id, "enabled": candidate.enabled, "returnCode": result.returncode},
                ),
            ],
        )
        _assert_job_does_not_expose_policy(final, candidate)
        repo.save(final)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _rollback_ambiguous_apply(
    repo: JobRepository,
    job: StoredJobRun,
    rollback_command: list[str],
    workdir: Path,
    runner: CommandRunner,
    policy_path: Path,
    staged: RetainedRequestHeaderGate,
    candidate: RequestHeaderGatePolicy,
    *,
    error_type: str,
    candidate_return_code: int | None,
) -> None:
    try:
        rollback_result = runner(rollback_command, workdir)
        reconverged = rollback_result.returncode == 0
        rollback_return_code: int | None = rollback_result.returncode
    except Exception:
        reconverged = False
        rollback_return_code = None

    retained_cleared = False
    if reconverged:
        try:
            _write_retained(
                policy_path,
                RetainedRequestHeaderGate(staged.engagement_id, staged.channel_id, staged.active, None),
            )
            retained_cleared = True
        except Exception:
            retained_cleared = False
    recovery_required = not (reconverged and retained_cleared)
    final = replace(
        job,
        status="failed",
        finished_at=_now(),
        events=[
            *job.events,
            JobEvent(
                len(job.events) + 1,
                "error",
                (
                    "request-header gate convergence failed; retained active policy was reconverged"
                    if not recovery_required
                    else "request-header gate convergence is ambiguous; retained active policy requires recovery"
                ),
                {
                    "channelId": staged.channel_id,
                    "errorType": error_type,
                    "candidateReturnCode": candidate_return_code,
                    "rollbackReturnCode": rollback_return_code,
                    "retainedPolicyReconverged": reconverged,
                    "retainedStateCleared": retained_cleared,
                    "recoveryRequired": recovery_required,
                },
            ),
        ],
    )
    _assert_job_does_not_expose_policy(final, candidate)
    repo.save(final)


def _detail(
    channel: Mapping[str, Any],
    external_port: int,
    edge_address: str,
    retained: RetainedRequestHeaderGate | None,
    *,
    pending_job: StoredJobRun | None = None,
    pending_live: bool | None = None,
    backend_authorization: InboundBackendAuthorization | None = None,
) -> dict[str, Any]:
    active = retained.active if retained is not None else None
    pending = retained.pending if retained is not None else None
    configured = active is not None and bool(active.token)
    pending_state = ""
    if pending is not None:
        job_id = retained.pending_job_id if retained is not None else None
        live = (
            pending_live
            if pending_live is not None
            else bool(
                pending_job is not None
                and pending_job.status in {"queued", "running"}
                and _active_gate_job(pending_job.id)
            )
        )
        pending_state = "running" if live else "retry-required"
        status = "Applying" if live else "Retry required"
    else:
        job_id = None
        status = "Active" if active is not None and active.enabled else "Disabled" if configured else "Not configured"
    gate = {
        "configured": configured,
        "enabled": bool(active.enabled) if active is not None else False,
        "headerName": active.header_name if active is not None else DEFAULT_HEADER_NAME,
        "token": active.token if active is not None else "",
        "status": status,
        "maxRequestBodyMb": (
            active.max_request_body_mb if active is not None else DEFAULT_MAX_REQUEST_BODY_MB
        ),
    }
    curl = ""
    if active is not None and active.enabled and active.token:
        domain = str(channel.get("domain") or "").strip()
        header = f"--header {shlex.quote(f'{active.header_name}: Bearer {active.token}')}"
        if str(channel.get("mode") or "") == "https-openresty":
            authority = domain if external_port == 443 else f"{domain}:{external_port}"
            parts = ["curl --include --request GET"]
            if edge_address:
                parts.append(f"--resolve {shlex.quote(f'{domain}:{external_port}:{edge_address}')}")
            parts.extend([header, shlex.quote(f"https://{authority}/")])
        else:
            endpoint = edge_address if external_port == 80 else f"{edge_address}:{external_port}"
            parts = [
                "curl --include --request GET",
                f"--header {shlex.quote(f'Host: {domain}')}",
                header,
                shlex.quote(f"http://{endpoint}/"),
            ]
        curl = " \\\n  ".join(parts)
    response = {
        "channel": dict(channel),
        "edgePublicIp": edge_address,
        "gate": gate,
        "authorizedRequest": {"method": "GET", "curl": curl},
        "backendPolicy": (
            {
                "capabilityId": backend_authorization.capability_id,
                "authorizationManaged": True,
                "maxRequestBodyMb": backend_authorization.max_request_body_mb,
            }
            if backend_authorization is not None
            else None
        ),
    }
    if pending is not None:
        response["pending"] = {
            "state": pending_state,
            "jobId": pending_job.id if pending_job is not None else job_id or "",
            "message": (
                "Request-header gate convergence is running."
                if pending_state == "running"
                else "The prior request-header gate convergence was interrupted. Apply the policy again to retry safely."
            ),
        }
        if pending_job is not None:
            _assert_job_does_not_expose_policy(pending_job, pending)
            response["job"] = pending_job.to_detail().to_dict()
    return response


def _assert_job_does_not_expose_policy(job: StoredJobRun, policy: RequestHeaderGatePolicy) -> None:
    serialized = json.dumps(job.to_detail().to_dict(), sort_keys=True)
    if policy.token and policy.token in serialized:
        raise AssertionError("request-header gate token escaped into ordinary job data")
    if "Bearer " in serialized:
        raise AssertionError("request-header gate value escaped into ordinary job data")


def _run_command(command: list[str], cwd: Path | None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=barragan_subprocess_env(),
        text=True,
        capture_output=True,
        timeout=900,
        check=False,
    )


def _start_background_task(task: Callable[[], None]) -> None:
    start_runtime_task(task, name="barragan-inbound-request-header-gate")


def _configured_engagement_root(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    return Path(os.environ.get("BARRAGAN_ENGAGEMENT_REPOS_ROOT", str(DEFAULT_ENGAGEMENT_REPOS_ROOT)))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
