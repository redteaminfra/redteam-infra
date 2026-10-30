# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from app.core.command_environment import barragan_subprocess_env
from app.core.runtime import current_runtime, start_runtime_task
from app.domain import JobEvent
from app.integrations.ansible_disposable_validation import resolve_ansible_playbook
from app.integrations.oci_disposable_terraform import DisposableCommandResult
from app.services.core_ssh import deployment_known_hosts_file, ensure_known_hosts_file, latest_core_connection_details
from app.services.engagements import get_engagement
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun


INFRA_ORIENTATION_REFRESH_ACTION = "infra_orientation_refresh"
INFRA_ORIENTATION_TARGET = "/engagement/INFRA.md"
DEFAULT_WORKSPACE_ROOT = Path("/tmp/barragan-infra-orientation")
DEFAULT_KNOWN_HOSTS_ROOT = Path("/tmp/barragan-infra-orientation-known-hosts")
DEFAULT_CORE_SSH_PRIVATE_KEY = "/var/lib/barragan/.ssh/barragan_testing"
CORE_SSH_KEY_ENV = "BARRAGAN_VALIDATION_SSH_PRIVATE_KEY"
CORE_SSH_OPTIONS = (
    "-o StrictHostKeyChecking=accept-new",
    "-o IdentitiesOnly=yes",
    "-o BatchMode=yes",
    "-o ConnectTimeout=10",
)
SECRET_MARKERS = (
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "authorization:",
    "bearer ",
    "password=",
    "token=",
    "secret=",
)

CommandRunner = Callable[[list[str], Path | None], subprocess.CompletedProcess[str]]
LOGGER = logging.getLogger(__name__)


class InfraOrientationRefreshError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("infra orientation refresh failed")
        self.errors = errors


def try_enqueue_infra_orientation_refresh(
    engagement_id: str,
    *,
    requested_by: str = "system",
    repository: JobRepository | None = None,
) -> StoredJobRun | None:
    try:
        current_runtime()
    except RuntimeError:
        return None
    try:
        return enqueue_infra_orientation_refresh(engagement_id, requested_by=requested_by, repository=repository)
    except Exception:
        LOGGER.exception("Could not enqueue INFRA.md refresh for engagement %s", engagement_id)
        return None


def enqueue_infra_orientation_refresh(
    engagement_id: str,
    *,
    requested_by: str = "system",
    repository: JobRepository | None = None,
) -> StoredJobRun | None:
    """Best-effort background refresh used by lifecycle hooks.

    If there is no core homebase yet, no job is created. This keeps early draft
    and partial topology updates from surfacing noisy failures.
    """

    repo = repository or SqlAlchemyJobRepository()
    if _homebase_from_latest_core(repo, engagement_id) is None:
        return None

    job = _create_refresh_job(repo, engagement_id, requested_by=requested_by)

    def task() -> None:
        execute_infra_orientation_refresh(job.id, repository=repo)

    start_runtime_task(task, name=f"infra-orientation-refresh-{engagement_id}", synchronous_when_testing=True)
    return job


def execute_infra_orientation_refresh(
    job_id: str,
    *,
    repository: JobRepository | None = None,
    runner: CommandRunner | None = None,
    workspace_root: Path = DEFAULT_WORKSPACE_ROOT,
) -> dict[str, Any]:
    repo = repository or SqlAlchemyJobRepository()
    job = repo.get(job_id)
    if job is None:
        raise InfraOrientationRefreshError([f"job {job_id} not found"])
    engagement_id = str(job.input.get("engagementId") or job.target_id)
    started_at = _now()
    events = [
        *job.events,
        JobEvent(len(job.events) + 1, "info", "Started homebase INFRA.md refresh.", {"phase": "start"}),
    ]
    job = repo.save(replace(job, status="running", started_at=started_at, events=events))

    try:
        overview = _get_operations_overview(engagement_id, repo)
        if overview is None:
            raise InfraOrientationRefreshError([f"engagement {engagement_id} not found"])
        engagement = get_engagement(engagement_id)
        markdown = render_infra_orientation_markdown(
            overview,
            engagement_name=engagement.name if engagement else str(overview.get("engagementId") or engagement_id),
            generated_at=started_at,
        )
        _assert_safe_content(markdown)
        homebase = _homebase_from_latest_core(repo, engagement_id)
        if homebase is None:
            raise InfraOrientationRefreshError(["homebase connection details are not available"])
        workspace = _render_workspace(
            engagement_id,
            job.id,
            markdown,
            homebase=homebase,
            workspace_root=workspace_root,
        )
        command = [resolve_ansible_playbook().command or "ansible-playbook", "-i", "ansible/inventory.ini", "ansible/write_infra_orientation.yml"]
        result = _run_guarded_command(command, workspace, runner)
        event_level = "info" if result.ok else "error"
        event_message = "Wrote /engagement/INFRA.md on homebase." if result.ok else "Failed to write /engagement/INFRA.md on homebase."
        finished_at = _now()
        final_events = [
            *job.events,
            JobEvent(
                len(job.events) + 1,
                event_level,
                event_message,
                {
                    "phase": "ansible",
                    "path": INFRA_ORIENTATION_TARGET,
                    "commandResult": _safe_command_result(result),
                },
            ),
        ]
        final_job = replace(job, status="succeeded" if result.ok else "failed", finished_at=finished_at, events=final_events)
        saved = repo.save(final_job)
        return {"job": saved.to_detail().to_dict(), "status": "Wrote" if result.ok else "Failed", "path": INFRA_ORIENTATION_TARGET}
    except InfraOrientationRefreshError as exc:
        finished_at = _now()
        final_events = [
            *job.events,
            JobEvent(len(job.events) + 1, "error", "; ".join(exc.errors), {"phase": "validation", "errors": exc.errors}),
        ]
        saved = repo.save(replace(job, status="failed", finished_at=finished_at, events=final_events))
        return {"job": saved.to_detail().to_dict(), "status": "Failed", "errors": exc.errors}


def render_infra_orientation_markdown(
    operations: dict[str, Any],
    *,
    engagement_name: str,
    generated_at: str | None = None,
) -> str:
    generated = generated_at or _now()
    core_hosts = _rows(operations, "coreInfrastructure")
    sketch_rows = _rows(operations, "sketchInfrastructure")
    outbound_channels = _rows(operations, "outboundChannels")
    inbound_channels = _rows(operations, "inboundChannels")
    service_placements = _rows(operations, "servicePlacements")
    edge_index = _edge_index(sketch_rows)

    sections = [
        f"# Infrastructure Overview: {engagement_name}",
        "\n".join(
            [
                f"- Generated by Barragan: {generated}",
                f"- Engagement ID: {_value(operations.get('engagementId'))}",
                "- Purpose: compact orientation for agents and operators working from homebase.",
                "- Scope: core hosts, egress mappings, ingress termination, service placements, and burned/avoid warnings.",
            ]
        ),
        "## Core Hosts",
        _markdown_table(
            ["Host", "Role", "Public IP", "Private IP", "Services"],
            [
                [
                    _value(host.get("hostname") or host.get("displayName") or host.get("sshAlias")),
                    _value(host.get("role")),
                    _value(host.get("publicIp")),
                    _value(host.get("privateIp")),
                    _list_value(host.get("services")),
                ]
                for host in core_hosts
            ],
            "_No core hosts have been recorded yet._",
        ),
        "## Outbound Egress",
        "\n".join(
            [
                "Agents on homebase should use the engagement proxy SOCKS listeners for Internet egress.",
                "Each listener maps to a specific public edge node/IP. Intermediate sketch routing is intentionally omitted here.",
                "Proxychains profiles are stored under `/opt/proxy01/` and `/opt/proxy02/` when channels are applied.",
                "",
                _markdown_table(
                    ["Proxy", "SOCKS Port", "Profile", "Egress Edge", "Egress IP", "Domain", "Purpose", "State"],
                    [_outbound_row(channel, edge_index) for channel in outbound_channels],
                    "_No outbound egress channels are configured._",
                ),
            ]
        ),
        "## Inbound Ingress",
        "\n".join(
            [
                "Public inbound traffic reaches the edge node, is carried to the selected proxy, and is routed by proxy OpenResty to the target site or service.",
                "Intermediate sketch routing is intentionally omitted here.",
                "",
                _markdown_table(
                    ["Domain", "Protocol", "Public Port", "Edge", "Edge IP", "Proxy", "Terminates On", "Service/Site", "Internal Port", "Purpose", "State"],
                    [_inbound_row(channel, edge_index) for channel in inbound_channels],
                    "_No inbound ingress channels are configured._",
                ),
            ]
        ),
        "## Static Websites And Services",
        _markdown_table(
            ["Service", "Type", "Host", "Port", "Domain", "Details", "State"],
            [_service_row(placement) for placement in service_placements if _service_visible(placement)],
            "_No static websites or service placements are recorded._",
        ),
        "## Burned Or Avoid",
        _burned_section(sketch_rows, outbound_channels, inbound_channels),
        "## Guardrails",
        "\n".join(
            [
                "- Treat this file as generated orientation, not the durable source of truth.",
                "- Keep rich topology and operator context on homebase, proxies, Barragan, or rendered operator artifacts.",
                "- Do not depend on sketch internals; use the egress/ingress mappings above.",
                "- Do not place provider credentials, private keys, tokens, or target-sensitive notes in this file.",
            ]
        ),
    ]
    return "\n\n".join(sections) + "\n"


def _create_refresh_job(repo: JobRepository, engagement_id: str, *, requested_by: str) -> StoredJobRun:
    now = _now()
    return repo.save(
        StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=INFRA_ORIENTATION_REFRESH_ACTION,
            status="queued",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={"engagementId": engagement_id, "targetPath": INFRA_ORIENTATION_TARGET},
            artifact_refs=[],
            created_at=now,
            started_at=None,
            finished_at=None,
            events=[
                JobEvent(
                    1,
                    "info",
                    "Queued homebase INFRA.md refresh.",
                    {"path": INFRA_ORIENTATION_TARGET},
                )
            ],
        )
    )


def _get_operations_overview(engagement_id: str, repo: JobRepository) -> dict[str, Any] | None:
    from app.services.engagement_operations import get_operations_overview

    return get_operations_overview(engagement_id, job_repository=repo, include_provider_findings=False)


def _render_workspace(
    engagement_id: str,
    job_id: str,
    markdown: str,
    *,
    homebase: dict[str, str],
    workspace_root: Path,
) -> Path:
    workspace = workspace_root / _safe_file_token(engagement_id) / _safe_file_token(job_id)
    (workspace / "ansible").mkdir(parents=True, exist_ok=True)
    (workspace / "files").mkdir(parents=True, exist_ok=True)
    inventory = workspace / "ansible" / "inventory.ini"
    playbook = workspace / "ansible" / "write_infra_orientation.yml"
    content_file = workspace / "files" / "INFRA.md"
    content_file.write_text(markdown, encoding="utf-8")
    inventory.write_text(f"[homebase]\n{_inventory_line(homebase)}\n", encoding="utf-8")
    playbook.write_text(
        "\n".join(
            [
                "---",
                "- name: Write generated homebase infrastructure orientation",
                "  hosts: homebase",
                "  become: true",
                "  gather_facts: false",
                "  tasks:",
                "    - name: Ensure engagement workspace exists as fallback",
                "      ansible.builtin.file:",
                "        path: /engagement",
                "        state: directory",
                "        owner: root",
                "        group: redteam",
                "        mode: '2770'",
                "    - name: Ensure engagement loot directory exists as fallback",
                "      ansible.builtin.file:",
                "        path: /engagement/loot",
                "        state: directory",
                "        owner: root",
                "        group: redteam",
                "        mode: '2770'",
                "    - name: Write generated infrastructure orientation",
                "      ansible.builtin.copy:",
                "        src: ../files/INFRA.md",
                f"        dest: {INFRA_ORIENTATION_TARGET}",
                "        owner: root",
                "        group: redteam",
                "        mode: '0640'",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return workspace


def _homebase_from_latest_core(repo: JobRepository, engagement_id: str) -> dict[str, str] | None:
    deployment_id, details = latest_core_connection_details(repo, engagement_id)
    homebase = next((entry for entry in details if str(entry.get("role") or "") == "homebase"), None)
    if not homebase:
        return None
    ansible_host = str(homebase.get("publicIp") or homebase.get("ansibleHost") or "").strip()
    if not ansible_host:
        return None
    known_hosts_file = deployment_known_hosts_file(DEFAULT_KNOWN_HOSTS_ROOT, engagement_id, deployment_id)
    ensure_known_hosts_file(known_hosts_file)
    return {
        "name": "homebase",
        "ansibleHost": ansible_host,
        "ansibleUser": str(homebase.get("sshUser") or "ubuntu"),
        "sshPrivateKeyFile": os.environ.get(CORE_SSH_KEY_ENV, DEFAULT_CORE_SSH_PRIVATE_KEY),
        "knownHostsFile": known_hosts_file,
    }


def _inventory_line(host: dict[str, str]) -> str:
    ssh_args = [*CORE_SSH_OPTIONS, f"-o UserKnownHostsFile={host['knownHostsFile']}"]
    return " ".join(
        [
            "homebase",
            f"ansible_host={host['ansibleHost']}",
            f"ansible_user={host['ansibleUser']}",
            f"ansible_ssh_private_key_file={host['sshPrivateKeyFile']}",
            f"ansible_ssh_common_args={json.dumps(' '.join(ssh_args))}",
        ]
    )


def _outbound_row(channel: dict[str, Any], edge_index: dict[str, dict[str, Any]]) -> list[str]:
    proxy = _value(channel.get("proxy"))
    chain_id = _value(channel.get("chainId"))
    profile = _value(channel.get("publicationPath") or (f"/opt/{proxy}/{chain_id}-socks5.conf" if proxy != "N/A" and chain_id != "N/A" else "N/A"))
    edge_name = _value(channel.get("edge"))
    edge = edge_index.get(edge_name, {})
    return [
        proxy,
        _value(channel.get("port")),
        profile,
        edge_name,
        _value(edge.get("publicIp")),
        _domain_value(channel.get("domain")),
        _value(channel.get("purpose")),
        _channel_state(channel, edge),
    ]


def _inbound_row(channel: dict[str, Any], edge_index: dict[str, dict[str, Any]]) -> list[str]:
    edge_name = _value(channel.get("edge"))
    edge = edge_index.get(edge_name, {})
    return [
        _domain_value(channel.get("domain")),
        _value(channel.get("protocol")),
        _value(channel.get("externalPort")),
        edge_name,
        _value(edge.get("publicIp")),
        _value(channel.get("proxy")),
        _value(channel.get("terminatesOn")),
        _value(channel.get("service") or channel.get("serviceId")),
        _value(channel.get("internalPort")),
        _value(channel.get("purpose")),
        _channel_state(channel, edge),
    ]


def _service_row(placement: dict[str, Any]) -> list[str]:
    return [
        _value(placement.get("service") or placement.get("siteName")),
        _value(placement.get("serviceType")),
        _value(placement.get("hostId") or placement.get("hostRole")),
        _value(placement.get("port")),
        _domain_value(placement.get("domain")),
        _value(placement.get("detail") or placement.get("purpose")),
        _value(placement.get("status")),
    ]


def _service_visible(placement: dict[str, Any]) -> bool:
    return str(placement.get("status") or "").strip().lower() not in {"removed", "disabled"}


def _burned_section(
    sketch_rows: list[dict[str, Any]],
    outbound_channels: list[dict[str, Any]],
    inbound_channels: list[dict[str, Any]],
) -> str:
    burned_edges = {
        _value(row.get("hostname")): _value(row.get("burnedNote") or row.get("status"))
        for row in sketch_rows
        if _truthy(row.get("burned")) and _value(row.get("role")).lower() == "edge"
    }
    affected = []
    for channel in [*outbound_channels, *inbound_channels]:
        edge = _value(channel.get("edge"))
        if edge in burned_edges:
            affected.append([edge, _value(channel.get("domain") or channel.get("chainId")), burned_edges[edge]])
    if not burned_edges and not affected:
        return "_No burned edge nodes or affected channels are recorded._"
    edge_table = _markdown_table(
        ["Burned Edge", "Note"],
        [[edge, note] for edge, note in burned_edges.items()],
        "",
    )
    affected_table = _markdown_table(
        ["Edge", "Channel", "Note"],
        affected,
        "_No channels currently reference burned edge nodes._",
    )
    return f"{edge_table}\n\n{affected_table}"


def _channel_state(channel: dict[str, Any], edge: dict[str, Any]) -> str:
    status = _value(channel.get("status"))
    if _truthy(edge.get("burned")):
        note = _value(edge.get("burnedNote"))
        return f"AVOID: burned edge{f' ({note})' if note != 'N/A' else ''}"
    return status


def _edge_index(sketch_rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in sketch_rows:
        if _value(row.get("role")).lower() != "edge":
            continue
        hostname = _value(row.get("hostname"))
        if hostname != "N/A":
            result[hostname] = row
    return result


def _markdown_table(headers: list[str], rows: list[list[str]], empty_text: str) -> str:
    if not rows:
        return empty_text
    return "\n".join(
        [
            f"| {' | '.join(_cell(header) for header in headers)} |",
            f"| {' | '.join('---' for _ in headers)} |",
            *[f"| {' | '.join(_cell(value) for value in row)} |" for row in rows],
        ]
    )


def _cell(value: str) -> str:
    return _value(value).replace("\n", "<br>").replace("|", "\\|")


def _rows(operations: dict[str, Any], key: str) -> list[dict[str, Any]]:
    raw = operations.get(key)
    if not isinstance(raw, list):
        return []
    return [row for row in raw if isinstance(row, dict)]


def _value(value: Any, default: str = "N/A") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        text = value.strip()
        return text or default
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def _list_value(value: Any) -> str:
    if not isinstance(value, list) or not value:
        return "N/A"
    return ", ".join(_value(item) for item in value)


def _domain_value(value: Any) -> str:
    text = _value(value)
    return text if text == "N/A" else text.replace(".", "[.]")


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "burned"}


def _safe_file_token(value: str) -> str:
    safe = "".join(character if character.isalnum() or character in {"-", "_"} else "_" for character in str(value or ""))
    return safe or "unknown"


def _assert_safe_content(content: str) -> None:
    lowered = content.lower()
    for marker in SECRET_MARKERS:
        if marker.lower() in lowered:
            raise InfraOrientationRefreshError([f"generated INFRA.md contains forbidden marker {marker!r}"])


def _run_guarded_command(command: list[str], cwd: Path, runner: CommandRunner | None) -> DisposableCommandResult:
    try:
        completed = runner(command, cwd) if runner is not None else subprocess.run(
            command,
            cwd=cwd,
            env=barragan_subprocess_env(),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return DisposableCommandResult.from_error(command, cwd, exc)
    return DisposableCommandResult.from_completed(command, cwd, completed)


def _safe_command_result(result: DisposableCommandResult) -> dict[str, Any]:
    body = result.to_dict()
    body["stdout"] = _sanitize_output(str(body.get("stdout") or ""))
    body["stderr"] = _sanitize_output(str(body.get("stderr") or ""))
    body["command"] = [str(part) for part in body.get("command", [])]
    return body


def _sanitize_output(value: str) -> str:
    text = value[:4000]
    for pattern in (
        re.compile(r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-api-token)\s*:\s*).+$"),
        re.compile(r"(?i)\b(bearer|basic)\s+\S+"),
        re.compile(r"(?i)\b(api[_ -]?key|private[_ -]?key|password|passwd|token|secret)\s*[:=]\s*([^\s&;]+)"),
    ):
        text = pattern.sub("[REDACTED]", text)
    return text


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
