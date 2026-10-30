# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import re
import threading
import time
from contextlib import nullcontext
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from app.core.runtime import start_runtime_task
from app.domain import JobEvent, JobRunDetail
from app.integrations.managed_host_images import managed_host_image_profile
from app.integrations.terraform_runner import (
    LocalTerraformCommandRunner,
    TerraformCommandResult,
    TerraformCommandRunner,
    terraform_failure_diagnostic,
)
from app.services.credentials import resolve_credential_secret, resolve_default_credential_alias
from app.services.engagements import get_engagement
from app.services.managed_host_image_continuity import (
    managed_host_image_profile_named,
    resolve_or_pin_profile_for_new_managed_host,
    retained_managed_compute_image,
)
from app.services.outbound_channel_artifacts import (
    collect_existing_outbound_channels_from_jobs,
    derive_pending_outbound_channels_from_sketch_rows,
)
from app.services.provider_region_policy import get_provider_region_policy
from app.services.redteam_infra_template import redteam_infra_sketch_template_dir
from app.services.sketch_ssh_keys import ensure_sketch_ssh_key
from app.services.sketch_transport_ssh_keys import ensure_sketch_transport_ssh_key
from app.services.sketch_state_workspaces import (
    grant_collaborator_access_to_existing_sketch_state_workspace,
    materialized_sketch_key_files,
    prepare_sketch_state_workspace,
    validate_existing_sketch_state_workspace,
)
from app.services.terraform_plan_gate import TerraformPlanGateError, require_edge_transition_changes
from app.services.template_compatibility import (
    disable_legacy_sketch_local_artifacts,
    ensure_sketch_resource_name_suffix_compatibility,
)
from app.storage.credential_repository import CredentialRepository
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.engagement_workspace_repository import EngagementWorkspaceRepository


LINODE_SKETCH_DEPLOY_ACTION = "linode_sketch_deploy"
LINODE_SKETCH_TEARDOWN_ACTION = "linode_sketch_teardown"
LINODE_SKETCH_RECONCILE_ACTION = "linode_sketch_reconcile"
LINODE_TOKEN_ENV_VAR = "TF_VAR_linode_api_token"
LINODE_SKETCH_CONFIRMATION = "mutate-linode-sketch-testing"
LINODE_SKETCH_WORKSPACE_NAME = "linode-sketch"
LINODE_SKETCH_TEMPLATE_DIR = redteam_infra_sketch_template_dir("linode")
LINODE_SKETCH_NAME_SLUG_MAX_LENGTH = 16

CredentialResolver = Callable[[str, str], str]
BackgroundRunner = Callable[[Callable[[], None]], None]
ProgressCallback = Callable[[JobEvent], None]


class _ProgressEvents(list[JobEvent]):
    def __init__(self, callback: ProgressCallback | None = None):
        super().__init__()
        self._callback = callback

    def append(self, event: JobEvent) -> None:
        super().append(event)
        if self._callback is not None:
            self._callback(event)


class LinodeSketchGuardrailError(ValueError):
    pass


@dataclass(frozen=True)
class LinodeSketchSpec:
    engagement_id: str
    engagement_name: str
    chain_id: str
    assigned_proxy: str
    middle_region: str
    edge_region: str
    middle_size: str
    edge_size: str
    middle_count: int
    edge_count: int
    credential_alias: str
    working_directory: str
    edge_regions: tuple[str, ...] = ()
    edge_count_per_region: int = 0
    edge_ids: tuple[str, ...] = ()
    edge_intents: tuple[tuple[str, str], ...] = ()
    ssh_private_key_path: str = ""
    ssh_public_key_path: str = ""
    sketch_transport_ssh_public_key_path: str = ""
    component_id: str = ""
    edge_id: str = ""
    middle_ordinal: int = 1
    edge_ordinal: int = 1
    resource_name_suffix: str = ""
    managed_host_image_profile_name: str = ""
    retained_image: str = ""


def run_linode_sketch_job(
    job: StoredJobRun,
    *,
    runner: TerraformCommandRunner | None = None,
    credential_repository: CredentialRepository | None = None,
    credential_resolver: CredentialResolver | None = None,
    progress_callback: ProgressCallback | None = None,
    existing_outbound_channels: list[dict[str, object]] | None = None,
) -> tuple[str, list[JobEvent], list[str]]:
    spec = _spec_from_job(job)
    if job.action in {LINODE_SKETCH_RECONCILE_ACTION, LINODE_SKETCH_TEARDOWN_ACTION}:
        validate_existing_sketch_state_workspace(
            spec.engagement_id,
            spec.chain_id,
            "linode",
            Path(spec.working_directory),
            component_id=spec.component_id or None,
        )
        retained_image = retained_managed_compute_image(Path(spec.working_directory), "linode")
        grant_collaborator_access_to_existing_sketch_state_workspace(
            spec.engagement_id,
            spec.chain_id,
            "linode",
            Path(spec.working_directory),
            component_id=spec.component_id or None,
        )
        spec = replace(
            spec,
            retained_image=retained_image,
        )
    terraform = runner or LocalTerraformCommandRunner()
    resolver = credential_resolver or (
        lambda provider, alias: resolve_credential_secret(provider, alias, credential_repository)
    )

    key_context = materialized_sketch_key_files(spec.engagement_id) if job.input.get("materializeKeyFiles") is True else nullcontext(None)
    with key_context as keys:
        materialized = replace(
            spec,
            ssh_private_key_path=keys.administration_private_key_path if keys else spec.ssh_private_key_path,
            ssh_public_key_path=keys.administration_public_key_path if keys else spec.ssh_public_key_path,
            sketch_transport_ssh_public_key_path=keys.transport_public_key_path if keys else spec.sketch_transport_ssh_public_key_path,
        )
        if job.action == LINODE_SKETCH_DEPLOY_ACTION:
            return _deploy(materialized, terraform, resolver, existing_outbound_channels=existing_outbound_channels or [])
        if job.action == LINODE_SKETCH_RECONCILE_ACTION:
            return _reconcile_edges(materialized, terraform, resolver, job.input, existing_outbound_channels=existing_outbound_channels or [])
        if job.action == LINODE_SKETCH_TEARDOWN_ACTION:
            return _teardown(materialized, terraform, resolver, progress_callback=progress_callback)
    raise ValueError(f"unsupported Linode sketch action: {job.action}")


def start_guarded_linode_sketch_run(
    body: dict[str, Any],
    *,
    repository: JobRepository | None = None,
    runner: TerraformCommandRunner | None = None,
    background_runner: BackgroundRunner | None = None,
    workspace_repository: EngagementWorkspaceRepository | None = None,
) -> JobRunDetail:
    spec = _guarded_spec(body)
    repo = repository or SqlAlchemyJobRepository()
    workspace_dir = _prepare_workspace(spec)
    if (workspace_dir / "terraform.tfstate").exists():
        raise LinodeSketchGuardrailError("existing Linode sketch state requires retained reconciliation")
    selected_profile = resolve_or_pin_profile_for_new_managed_host(
        spec.engagement_id,
        repository=workspace_repository,
    )
    spec = replace(spec, managed_host_image_profile_name=selected_profile.name)
    ensure_sketch_ssh_key(spec.engagement_id)
    ensure_sketch_transport_ssh_key(spec.engagement_id)
    spec = replace(spec, working_directory=str(workspace_dir))
    job = repo.save(_new_sketch_job(LINODE_SKETCH_DEPLOY_ACTION, {**body, "materializeKeyFiles": True}, spec, workspace_dir))
    running = repo.save(
        replace(
            job,
            status="running",
            started_at=_now(),
            events=job.events
            + [
                JobEvent(
                    _next_sequence(job.events),
                    "info",
                    "Linode sketch run started",
                    {"workspace": LINODE_SKETCH_WORKSPACE_NAME, "workspaceDir": str(workspace_dir)},
                )
            ],
        )
    )
    executor_runner = runner
    task_runner = background_runner or _start_background_task
    task_runner(lambda: _run_persisted_linode_sketch_job(running.id, repo, executor_runner))
    return running.to_detail()


def start_guarded_linode_sketch_reconcile(
    body: dict[str, Any],
    *,
    repository: JobRepository | None = None,
    runner: TerraformCommandRunner | None = None,
    background_runner: BackgroundRunner | None = None,
) -> JobRunDetail:
    """Reconcile one already-owned Linode chain through its retained state."""

    spec = _guarded_spec(body)
    workspace_dir = _prepare_workspace(spec)
    supplied_workspace = str(body.get("terraformWorkingDirectory") or "").strip()
    if supplied_workspace and Path(supplied_workspace) != workspace_dir:
        raise LinodeSketchGuardrailError("retained Linode sketch state does not match this chain")
    expected_address = str(body.get("expectedEdgeAddress") or "").strip()
    expected_action = str(body.get("expectedEdgeAction") or "").strip()
    if not expected_address or expected_action not in {"create", "delete"}:
        raise LinodeSketchGuardrailError("edge reconcile requires a reviewed final-edge Terraform change")
    ensure_sketch_ssh_key(spec.engagement_id)
    ensure_sketch_transport_ssh_key(spec.engagement_id)
    spec = replace(spec, working_directory=str(workspace_dir))
    repo = repository or SqlAlchemyJobRepository()
    job = repo.save(_new_sketch_job(LINODE_SKETCH_RECONCILE_ACTION, {**body, "materializeKeyFiles": True}, spec, workspace_dir))
    running = repo.save(
        replace(
            job,
            status="running",
            started_at=_now(),
            events=job.events + [
                JobEvent(
                    _next_sequence(job.events),
                    "info",
                    "Linode sketch edge reconciliation started",
                    {"workspace": LINODE_SKETCH_WORKSPACE_NAME, "workspaceDir": str(workspace_dir)},
                )
            ],
        )
    )
    task_runner = background_runner or _start_background_task
    task_runner(lambda: _run_persisted_linode_sketch_job(running.id, repo, runner))
    return running.to_detail()


def get_guarded_linode_sketch_run(job_id: str, *, repository: JobRepository | None = None) -> JobRunDetail | None:
    job = (repository or SqlAlchemyJobRepository()).get(job_id)
    if job is None or job.action not in {LINODE_SKETCH_DEPLOY_ACTION, LINODE_SKETCH_RECONCILE_ACTION, LINODE_SKETCH_TEARDOWN_ACTION}:
        return None
    return job.to_detail()


def teardown_guarded_linode_sketch_run(
    job_id: str,
    *,
    repository: JobRepository | None = None,
    runner: TerraformCommandRunner | None = None,
) -> JobRunDetail | None:
    repo = repository or SqlAlchemyJobRepository()
    existing = repo.get(job_id)
    if existing is None or existing.action not in {LINODE_SKETCH_DEPLOY_ACTION, LINODE_SKETCH_RECONCILE_ACTION}:
        return None
    spec = _spec_from_job(existing)
    workspace = Path(spec.working_directory)
    teardown = repo.save(
        _new_sketch_job(
            LINODE_SKETCH_TEARDOWN_ACTION,
            existing.input,
            spec,
            workspace,
            requested_by=existing.requested_by,
            parent_job_id=existing.id,
        )
    )
    running = repo.save(
        replace(
            teardown,
            status="running",
            started_at=_now(),
            events=teardown.events
            + [
                JobEvent(
                    _next_sequence(teardown.events),
                    "info",
                    "Linode sketch teardown queued",
                    {"workspace": LINODE_SKETCH_WORKSPACE_NAME, "workspaceDir": str(workspace), "parentJobId": existing.id},
                )
            ],
        )
    )
    return _run_persisted_linode_sketch_job(running.id, repo, runner)


def start_guarded_linode_sketch_teardown(
    job_id: str,
    *,
    repository: JobRepository | None = None,
    runner: TerraformCommandRunner | None = None,
    background_runner: BackgroundRunner | None = None,
) -> JobRunDetail | None:
    """Persist and return a running teardown before Terraform executes."""
    repo = repository or SqlAlchemyJobRepository()
    existing = repo.get(job_id)
    if existing is None or existing.action not in {LINODE_SKETCH_DEPLOY_ACTION, LINODE_SKETCH_RECONCILE_ACTION}:
        return None
    spec = _spec_from_job(existing)
    workspace = Path(spec.working_directory)
    teardown = repo.save(
        _new_sketch_job(
            LINODE_SKETCH_TEARDOWN_ACTION,
            existing.input,
            spec,
            workspace,
            requested_by=existing.requested_by,
            parent_job_id=existing.id,
        )
    )
    running = repo.save(
        replace(
            teardown,
            status="running",
            started_at=_now(),
            events=teardown.events
            + [
                JobEvent(
                    _next_sequence(teardown.events),
                    "info",
                    "Linode sketch teardown started",
                    {"workspace": LINODE_SKETCH_WORKSPACE_NAME, "workspaceDir": str(workspace), "parentJobId": existing.id},
                )
            ],
        )
    )
    task_runner = background_runner or _start_background_task
    task_runner(lambda: _run_persisted_linode_sketch_job(running.id, repo, runner))
    return running.to_detail()


def resume_guarded_linode_sketch_teardown(
    job_id: str,
    *,
    repository: JobRepository | None = None,
    runner: TerraformCommandRunner | None = None,
    background_runner: BackgroundRunner | None = None,
) -> JobRunDetail | None:
    """Resume the same persisted teardown child after its runtime was interrupted."""

    repo = repository or SqlAlchemyJobRepository()
    job = repo.get(job_id)
    if job is None or job.action != LINODE_SKETCH_TEARDOWN_ACTION:
        return None
    running = repo.save(
        replace(
            job,
            status="running",
            started_at=job.started_at or _now(),
            finished_at=None,
            events=job.events
            + [
                JobEvent(
                    _next_sequence(job.events),
                    "info",
                    "Linode sketch teardown resumed",
                    {"parentJobId": str(job.input.get("parentJobId") or "")},
                )
            ],
        )
    )
    task_runner = background_runner or _start_background_task
    task_runner(lambda: _run_persisted_linode_sketch_job(running.id, repo, runner))
    return running.to_detail()


def _run_persisted_linode_sketch_job(
    job_id: str,
    repository: JobRepository,
    runner: TerraformCommandRunner | None,
) -> JobRunDetail | None:
    job = repository.get(job_id)
    if job is None:
        return None
    persist_progress = job.action == LINODE_SKETCH_TEARDOWN_ACTION

    def record_progress(event: JobEvent) -> None:
        current = repository.get(job_id)
        if current is None:
            return
        repository.save(
            replace(
                current,
                events=current.events
                + [JobEvent(_next_sequence(current.events), event.level, event.message, event.data)],
            )
        )

    try:
        status, events, artifacts = run_linode_sketch_job(
            job,
            runner=runner,
            progress_callback=record_progress if persist_progress else None,
            existing_outbound_channels=collect_existing_outbound_channels_from_jobs(
                repository.list(),
                job.input.get("engagementId", ""),
                exclude_job_id=job.id,
            ),
        )
    except Exception as exc:
        current = repository.get(job_id) or job
        failed = replace(
            current,
            status="failed",
            finished_at=_now(),
            events=current.events
            + [
                JobEvent(
                    _next_sequence(current.events),
                    "error",
                    "Linode sketch job failed with redacted sensitive details",
                    {"errorType": type(exc).__name__},
                )
            ],
        )
        return repository.save(failed).to_detail()
    current = repository.get(job_id) or job
    finished = replace(
        current,
        status=status,
        finished_at=_now(),
        artifact_refs=artifacts,
        events=current.events if persist_progress else current.events + _renumber_events(events, _next_sequence(current.events)),
    )
    return repository.save(finished).to_detail()


def _guarded_spec(body: dict[str, Any]) -> LinodeSketchSpec:
    if body.get("confirmMutation") != LINODE_SKETCH_CONFIRMATION:
        raise LinodeSketchGuardrailError(f'confirmMutation must equal "{LINODE_SKETCH_CONFIRMATION}"')
    engagement_id = _required_guarded(body, "engagementId")
    engagement = get_engagement(engagement_id)
    if engagement is None:
        raise LinodeSketchGuardrailError("engagementId must reference an existing engagement")
    middle_region = _required_guarded(body, "middleRegion")
    edge_region = _required_guarded(body, "edgeRegion")
    raw_edge_regions = body.get("edgeRegions")
    edge_regions = tuple(str(region).strip() for region in (raw_edge_regions if isinstance(raw_edge_regions, list) else [edge_region]) if str(region).strip())
    edge_count_per_region = _node_count(body.get("edgeCountPerRegion"), field="edgeCountPerRegion", default=_node_count(body.get("edgeCount"), field="edgeCount", default=1))
    allowed_regions = set(get_provider_region_policy("linode").allowed_regions)
    blocked_regions = sorted({middle_region, *edge_regions} - allowed_regions)
    if blocked_regions:
        raise LinodeSketchGuardrailError(
            "Linode sketch deployments are restricted to configured allowed regions; "
            f"blocked: {', '.join(blocked_regions)}"
        )
    middle_alias = _optional_alias(body, "middleCredentialAlias") or _default_alias("linode")
    edge_alias = _optional_alias(body, "edgeCredentialAlias") or _default_alias("linode")
    if not middle_alias or not edge_alias:
        raise LinodeSketchGuardrailError("Linode sketch mutation requires an active default linode credential")
    if middle_alias != edge_alias:
        raise LinodeSketchGuardrailError("Linode sketch development runs require one shared credential alias")
    return LinodeSketchSpec(
        engagement_id=engagement_id,
        engagement_name=engagement.name,
        chain_id=str(body.get("chainId") or "chain-1").strip() or "chain-1",
        assigned_proxy=str(body.get("assignedProxy") or "proxy01").strip() or "proxy01",
        middle_region=middle_region,
        edge_region=edge_region,
        middle_size=str(body.get("middleSize") or "g6-nanode-1").strip() or "g6-nanode-1",
        edge_size=str(body.get("edgeSize") or "g6-nanode-1").strip() or "g6-nanode-1",
        middle_count=_node_count(body.get("middleCount"), field="middleCount", default=1),
        edge_count=_node_count(body.get("edgeCount"), field="edgeCount", default=1),
        edge_regions=edge_regions,
        edge_count_per_region=edge_count_per_region,
        edge_ids=tuple(str(edge.get("id") or f"edge-{index:02d}") for index, edge in enumerate(body.get("edges") or [], start=1)),
        edge_intents=tuple((str(edge.get("id") or f"edge-{index:02d}"), str(edge.get("region") or edge_region)) for index, edge in enumerate(body.get("edges") or [], start=1)),
        credential_alias=middle_alias,
        working_directory="",
    )


def _prepare_workspace(spec: LinodeSketchSpec) -> Path:
    """Use the private chain state root, never a disposable /tmp workspace."""
    destination = prepare_sketch_state_workspace(
        spec.engagement_id,
        spec.chain_id,
        "linode",
        template_directory=redteam_infra_sketch_template_dir("linode"),
    ).path
    return destination


def _new_sketch_job(
    action: str,
    body: dict[str, Any],
    spec: LinodeSketchSpec,
    workspace_dir: Path,
    *,
    requested_by: str | None = None,
    parent_job_id: str | None = None,
) -> StoredJobRun:
    created_at = _now()
    safe_input = {
        "confirmMutation": body.get("confirmMutation"),
        "engagementId": spec.engagement_id,
        "engagementName": spec.engagement_name,
        "chainId": spec.chain_id,
        "assignedProxy": spec.assigned_proxy,
        "middleCredentialAlias": spec.credential_alias,
        "edgeCredentialAlias": spec.credential_alias,
        "middleRegion": spec.middle_region,
        "edgeRegion": spec.edge_region,
        "middleSize": spec.middle_size,
        "edgeSize": spec.edge_size,
        "middleCount": spec.middle_count,
        "edgeCount": spec.edge_count,
        "edgeRegions": list(spec.edge_regions),
        "edgeCountPerRegion": spec.edge_count_per_region,
        "edgeIds": list(spec.edge_ids),
        "edgeIntents": [{"id": edge_id, "region": region} for edge_id, region in spec.edge_intents],
        "terraformEngagementName": _provider_name_slug(spec.engagement_name),
        "resourceNameSuffix": _resource_name_suffix(spec.chain_id),
        "middleOrdinal": spec.middle_ordinal,
        "edgeOrdinal": spec.edge_ordinal,
        "terraformWorkingDirectory": str(workspace_dir),
        "workspace": LINODE_SKETCH_WORKSPACE_NAME,
        "materializeKeyFiles": body.get("materializeKeyFiles") is True,
        "managedHostImageProfile": spec.managed_host_image_profile_name,
        "sshPrivateKeyPath": spec.ssh_private_key_path,
        "sshPublicKeyPath": spec.ssh_public_key_path,
        "infrastructureAdminSshPrivateKeyPath": spec.ssh_private_key_path,
        "infrastructureAdminSshPublicKeyPath": spec.ssh_public_key_path,
        "sketchTransportSshPublicKeyPath": spec.sketch_transport_ssh_public_key_path,
    }
    if parent_job_id:
        safe_input["parentJobId"] = parent_job_id
    if action == LINODE_SKETCH_RECONCILE_ACTION:
        safe_input.update(
            expectedEdgeAddress=str(body.get("expectedEdgeAddress") or "").strip(),
            expectedEdgeAction=str(body.get("expectedEdgeAction") or "").strip(),
            edgeTransition=str(body.get("edgeTransition") or "").strip(),
        )
    return StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=action,
        status="queued",
        target=f"engagement:{spec.engagement_id}",
        target_type="engagement",
        target_id=spec.engagement_id,
        requested_by=str(requested_by or body.get("requestedBy") or "operator"),
        input=safe_input,
        artifact_refs=[],
        created_at=created_at,
        started_at=None,
        finished_at=None,
        events=[
            JobEvent(
                1,
                "info",
                "Linode sketch run queued"
                if action == LINODE_SKETCH_DEPLOY_ACTION
                else "Linode sketch edge reconciliation queued"
                if action == LINODE_SKETCH_RECONCILE_ACTION
                else "Linode sketch teardown queued",
                {
                    "workspace": LINODE_SKETCH_WORKSPACE_NAME,
                    "workspaceDir": str(workspace_dir),
                    "engagementId": spec.engagement_id,
                    "chainId": spec.chain_id,
                    "provider": "linode",
                },
            )
        ],
    )


def _start_background_task(task: Callable[[], None]) -> None:
    start_runtime_task(task, name="barragan-linode-sketch-runner")


def _deploy(
    spec: LinodeSketchSpec,
    runner: TerraformCommandRunner,
    credential_resolver: CredentialResolver,
    *,
    existing_outbound_channels: list[dict[str, object]],
) -> tuple[str, list[JobEvent], list[str]]:
    events = []
    ensure_sketch_resource_name_suffix_compatibility(Path(spec.working_directory), "linode")
    disable_legacy_sketch_local_artifacts(Path(spec.working_directory))
    env = _execution_env(spec, credential_resolver)
    events.append(_event("info", "credential alias resolved", spec, {"phase": "credential"}))
    variables = _terraform_variables(spec)
    events.append(_event("info", "terraform init started", spec, {"phase": "init"}))
    init_result = _run(runner, "init", spec, env, {})
    if init_result.returncode != 0:
        events.append(_event("error", "terraform init failed", spec, _terraform_failure_data(spec, init_result, env, {}, phase="init")))
        return "failed", events, [f"terraform:linode-sketch:{spec.engagement_id}:{spec.chain_id}"]
    events.append(_event("info", "terraform init completed", spec, {"phase": "init"}))

    apply_started_wall = datetime.now(timezone.utc)
    apply_started_monotonic = time.monotonic()
    events.append(_event("info", "terraform apply started", spec, {
        "phase": "apply",
        "startedAt": apply_started_wall.isoformat(),
        "observedAt": apply_started_wall.isoformat(),
    }))
    apply_result = _run(runner, "apply", spec, env, variables)
    apply_finished_wall = datetime.now(timezone.utc)
    apply_timing = {
        "startedAt": apply_started_wall.isoformat(),
        "finishedAt": apply_finished_wall.isoformat(),
        "elapsedSeconds": round(max(0.0, time.monotonic() - apply_started_monotonic), 3),
    }
    if apply_result.returncode != 0:
        events.append(_event("error", "terraform apply failed", spec, {
            **_terraform_failure_data(spec, apply_result, env, variables, phase="apply"),
            **apply_timing,
        }))
        _append_destroy_cleanup_events(events, spec, runner, env, variables)
        return "failed", events, [f"terraform:linode-sketch:{spec.engagement_id}:{spec.chain_id}"]
    events.append(_event("info", "terraform apply completed", spec, {"phase": "apply", **apply_timing}))

    events.append(_event("info", "terraform output started", spec, {"phase": "output"}))
    output = _run(runner, "output", spec, env, {})
    if output.returncode != 0:
        events.append(_event("error", "terraform output failed", spec, _terraform_failure_data(spec, output, env, {}, phase="output")))
        _append_destroy_cleanup_events(events, spec, runner, env, variables)
        return "failed", events, [f"terraform:linode-sketch:{spec.engagement_id}:{spec.chain_id}"]
    try:
        rows = _sketch_infrastructure_rows(spec, _decode_terraform_output(output.stdout))
    except ValueError:
        events.append(_event("error", "terraform output failed", spec, {"phase": "output", "reason": "invalid_json"}))
        _append_destroy_cleanup_events(events, spec, runner, env, variables)
        return "failed", events, [f"terraform:linode-sketch:{spec.engagement_id}:{spec.chain_id}"]
    events.append(
        _event(
            "info",
            "terraform output recorded",
            spec,
            {
                "phase": "output",
                "sketchInfrastructure": rows,
            },
        )
    )
    outbound_channels = derive_pending_outbound_channels_from_sketch_rows(
        spec.engagement_name,
        spec.chain_id,
        rows,
        existing_outbound_channels=existing_outbound_channels,
    )
    if not outbound_channels:
        events.append(
            _event(
                "warning",
                "outbound channel artifacts skipped",
                spec,
                {
                    "phase": "outbound_channel_derivation",
                    "outboundChannels": [],
                    "reason": "incomplete sketch output; middle and edge public IPs are required before proxy/homebase artifacts can be derived",
                },
            )
        )
    else:
        events.append(
            _event(
                "info",
                "pending outbound channel artifacts derived",
                spec,
                {
                    "phase": "outbound_channel_derivation",
                    "outboundChannels": outbound_channels,
                },
            )
        )
    return "succeeded", events, [f"terraform:linode-sketch:{spec.engagement_id}:{spec.chain_id}"]


def _reconcile_edges(
    spec: LinodeSketchSpec,
    runner: TerraformCommandRunner,
    credential_resolver: CredentialResolver,
    input_data: dict[str, Any],
    *,
    existing_outbound_channels: list[dict[str, object]],
) -> tuple[str, list[JobEvent], list[str]]:
    """Apply a narrow, machine-reviewed final-edge transition.

    Unlike initial deploy failure handling, this path never attempts a broad
    destroy on failure: it is mutating an existing retained chain.
    """

    events: list[JobEvent] = []
    ensure_sketch_resource_name_suffix_compatibility(Path(spec.working_directory), "linode")
    disable_legacy_sketch_local_artifacts(Path(spec.working_directory))
    env = _execution_env(spec, credential_resolver)
    variables = _retained_terraform_variables(spec)
    events.append(_event("info", "credential alias resolved", spec, {"phase": "credential"}))
    events.append(_event("info", "terraform init started", spec, {"phase": "init"}))
    init_result = _run(runner, "init", spec, env, {})
    if init_result.returncode != 0:
        events.append(_event("error", "terraform init failed", spec, _terraform_failure_data(spec, init_result, env, {}, phase="init")))
        return "failed", events, [f"terraform:linode-sketch:{spec.engagement_id}:{spec.chain_id}"]
    events.append(_event("info", "terraform init completed", spec, {"phase": "init"}))
    events.append(_event("info", "terraform edge transition plan started", spec, {"phase": "plan"}))
    plan_result = _run(runner, "plan", spec, env, variables)
    if plan_result.returncode not in {0, 2}:
        events.append(_event("error", "terraform edge transition plan failed", spec, _terraform_failure_data(spec, plan_result, env, variables, phase="plan")))
        return "failed", events, [f"terraform:linode-sketch:{spec.engagement_id}:{spec.chain_id}"]
    try:
        changes = require_edge_transition_changes(
            plan_result.stdout,
            provider="linode",
            edge_address=str(input_data.get("expectedEdgeAddress") or ""),
            edge_action=str(input_data.get("expectedEdgeAction") or ""),
        )
    except TerraformPlanGateError as exc:
        events.append(_event("error", "terraform edge transition rejected", spec, {"phase": "plan", "reason": str(exc)}))
        return "failed", events, [f"terraform:linode-sketch:{spec.engagement_id}:{spec.chain_id}"]
    events.append(_event("info", "terraform edge transition plan approved", spec, {"phase": "plan", "changes": [{"address": change.address, "action": change.action} for change in changes]}))
    events.append(_event("info", "terraform edge transition apply started", spec, {"phase": "apply"}))
    apply_result = _run(runner, "apply", spec, env, variables)
    if apply_result.returncode != 0:
        events.append(_event("error", "terraform edge transition apply failed", spec, _terraform_failure_data(spec, apply_result, env, variables, phase="apply")))
        return "failed", events, [f"terraform:linode-sketch:{spec.engagement_id}:{spec.chain_id}"]
    events.append(_event("info", "terraform edge transition apply completed", spec, {"phase": "apply"}))
    return _record_reconciled_output(spec, runner, env, variables, events, existing_outbound_channels)


def _record_reconciled_output(
    spec: LinodeSketchSpec,
    runner: TerraformCommandRunner,
    env: dict[str, str],
    variables: dict[str, Any],
    events: list[JobEvent],
    existing_outbound_channels: list[dict[str, object]],
) -> tuple[str, list[JobEvent], list[str]]:
    events.append(_event("info", "terraform output started", spec, {"phase": "output"}))
    output = _run(runner, "output", spec, env, {})
    if output.returncode != 0:
        events.append(_event("error", "terraform output failed", spec, _terraform_failure_data(spec, output, env, {}, phase="output")))
        return "failed", events, [f"terraform:linode-sketch:{spec.engagement_id}:{spec.chain_id}"]
    try:
        rows = _sketch_infrastructure_rows(spec, _decode_terraform_output(output.stdout))
    except ValueError:
        events.append(_event("error", "terraform output failed", spec, {"phase": "output", "reason": "invalid_json"}))
        return "failed", events, [f"terraform:linode-sketch:{spec.engagement_id}:{spec.chain_id}"]
    events.append(_event("info", "terraform output recorded", spec, {"phase": "output", "sketchInfrastructure": rows}))
    channels = derive_pending_outbound_channels_from_sketch_rows(spec.engagement_name, spec.chain_id, rows, existing_outbound_channels=existing_outbound_channels)
    events.append(_event("info", "pending outbound channel artifacts derived", spec, {"phase": "outbound_channel_derivation", "outboundChannels": channels}))
    return "succeeded", events, [f"terraform:linode-sketch:{spec.engagement_id}:{spec.chain_id}"]


def _teardown(
    spec: LinodeSketchSpec,
    runner: TerraformCommandRunner,
    credential_resolver: CredentialResolver,
    *,
    progress_callback: ProgressCallback | None = None,
) -> tuple[str, list[JobEvent], list[str]]:
    events: list[JobEvent] = _ProgressEvents(progress_callback)
    ensure_sketch_resource_name_suffix_compatibility(Path(spec.working_directory), "linode")
    disable_legacy_sketch_local_artifacts(Path(spec.working_directory))
    env = _execution_env(spec, credential_resolver)
    events.append(_event("info", "credential alias resolved", spec, {"phase": "credential"}))
    variables = _retained_terraform_variables(spec)
    events.append(_event("info", "terraform init started", spec, {"phase": "init"}))
    init_result = _run(runner, "init", spec, env, {})
    if init_result.returncode != 0:
        events.append(_event("error", "terraform init failed", spec, _terraform_failure_data(spec, init_result, env, {}, phase="init")))
        return "failed", events, [f"terraform:linode-sketch-teardown:{spec.engagement_id}:{spec.chain_id}"]
    events.append(_event("info", "terraform init completed", spec, {"phase": "init"}))

    events.append(_event("info", "terraform destroy started", spec, {"phase": "destroy"}))
    destroy_result = _run(runner, "destroy", spec, env, variables)
    if destroy_result.returncode != 0:
        events.append(_event("error", "terraform destroy failed", spec, _terraform_failure_data(spec, destroy_result, env, variables, phase="destroy")))
        return "failed", events, [f"terraform:linode-sketch-teardown:{spec.engagement_id}:{spec.chain_id}"]
    events.append(_event("info", "terraform destroy completed", spec, {"phase": "destroy"}))

    events.append(_event("info", "terraform cleanup verification started", spec, {"phase": "cleanup"}))
    output = _run(runner, "output", spec, env, {})
    if output.returncode != 0:
        events.append(_event("error", "terraform cleanup verification failed", spec, _terraform_failure_data(spec, output, env, {}, phase="cleanup")))
        return "failed", events, [f"terraform:linode-sketch-teardown:{spec.engagement_id}:{spec.chain_id}"]
    try:
        remaining = _remaining_sketch_outputs(_decode_terraform_output(output.stdout))
    except ValueError:
        events.append(
            _event(
                "error",
                "terraform cleanup verification failed",
                spec,
                {"phase": "cleanup", "cleanupVerified": False, "reason": "invalid_json"},
            )
        )
        return "failed", events, [f"terraform:linode-sketch-teardown:{spec.engagement_id}:{spec.chain_id}"]
    if remaining:
        events.append(
            _event(
                "error",
                "terraform cleanup verification failed",
                spec,
                {"phase": "cleanup", "cleanupVerified": False, "remainingOutputs": remaining},
            )
        )
        return "failed", events, [f"terraform:linode-sketch-teardown:{spec.engagement_id}:{spec.chain_id}"]
    events.append(
        _event(
            "info",
            "terraform cleanup verified",
            spec,
            {
                "phase": "cleanup",
                "cleanupVerified": True,
                "sketchInfrastructure": [],
            },
        )
    )
    return "succeeded", events, [f"terraform:linode-sketch-teardown:{spec.engagement_id}:{spec.chain_id}"]


def _spec_from_job(job: StoredJobRun) -> LinodeSketchSpec:
    data = job.input
    middle_alias = _required(data, "middleCredentialAlias")
    edge_alias = _required(data, "edgeCredentialAlias")
    if middle_alias != edge_alias:
        raise ValueError("Linode sketch deployment requires one shared credential alias for middle and edge")
    return LinodeSketchSpec(
        engagement_id=_required(data, "engagementId"),
        engagement_name=_required(data, "engagementName"),
        chain_id=_required(data, "chainId"),
        assigned_proxy=str(data.get("assignedProxy") or "proxy01").strip() or "proxy01",
        middle_region=_required(data, "middleRegion"),
        edge_region=_required(data, "edgeRegion"),
        middle_size=_required(data, "middleSize"),
        edge_size=_required(data, "edgeSize"),
        middle_count=_node_count(data.get("middleCount"), field="middleCount", default=1),
        edge_count=_node_count(data.get("edgeCount"), field="edgeCount", default=1),
        edge_regions=tuple(str(region) for region in (data["edgeRegions"] if isinstance(data.get("edgeRegions"), list) else [_required(data, "edgeRegion")])),
        edge_count_per_region=_node_count(data.get("edgeCountPerRegion"), field="edgeCountPerRegion", default=_node_count(data.get("edgeCount"), field="edgeCount", default=1)),
        edge_ids=tuple(str(edge_id) for edge_id in (data.get("edgeIds") or [])),
        edge_intents=tuple((str(edge.get("id") or ""), str(edge.get("region") or "")) for edge in (data.get("edgeIntents") or [])),
        credential_alias=middle_alias,
        working_directory=_required(data, "terraformWorkingDirectory"),
        ssh_private_key_path=str(data.get("infrastructureAdminSshPrivateKeyPath") or data.get("sshPrivateKeyPath") or "").strip(),
        ssh_public_key_path=str(data.get("infrastructureAdminSshPublicKeyPath") or data.get("sshPublicKeyPath") or "").strip(),
        sketch_transport_ssh_public_key_path=str(data.get("sketchTransportSshPublicKeyPath") or "").strip(),
        component_id=str(data.get("componentId") or "").strip(),
        edge_id=str(data.get("edgeId") or "").strip(),
        middle_ordinal=_node_count(data.get("middleOrdinal"), field="middleOrdinal", default=1) or 1,
        edge_ordinal=_node_count(data.get("edgeOrdinal"), field="edgeOrdinal", default=1) or 1,
        resource_name_suffix=str(data.get("resourceNameSuffix") or "").strip(),
        managed_host_image_profile_name=str(data.get("managedHostImageProfile") or "").strip(),
    )


def _execution_env(spec: LinodeSketchSpec, credential_resolver: CredentialResolver) -> dict[str, str]:
    return {
        LINODE_TOKEN_ENV_VAR: credential_resolver("linode", spec.credential_alias),
        "TF_DATA_DIR": str(Path(spec.working_directory) / ".terraform-data"),
    }


def _terraform_variables(spec: LinodeSketchSpec) -> dict[str, Any]:
    profile = (
        managed_host_image_profile_named(spec.managed_host_image_profile_name)
        if spec.managed_host_image_profile_name
        else managed_host_image_profile()
    )
    variables = {
        "engagement_name": _provider_name_slug(spec.engagement_name),
        "resource_name_suffix": spec.resource_name_suffix or _resource_name_suffix(spec.chain_id),
        "middle_region": spec.middle_region,
        "middle_type": spec.middle_size,
        "edge_regions": list(spec.edge_regions or (spec.edge_region,)),
        "edge_type": spec.edge_size,
        "linode_image": profile.linode_image,
        "middle_count": spec.middle_count,
        "edge_count_per_region": spec.edge_count_per_region or spec.edge_count,
        "middle_ordinal": spec.middle_ordinal,
        "edge_ordinal": spec.edge_ordinal,
    }
    admin_public = spec.ssh_public_key_path or str(Path(spec.working_directory) / "keys" / f"{spec.engagement_name}-sketch.pub")
    admin_private = spec.ssh_private_key_path or str(Path(spec.working_directory) / "keys" / f"{spec.engagement_name}-sketch")
    if _uses_split_ssh_variables(spec.working_directory):
        return {
            **variables,
            "infrastructure_admin_ssh_pub_key_path": admin_public,
            "infrastructure_admin_ssh_priv_key_path": admin_private,
            "sketch_transport_ssh_pub_key_path": spec.sketch_transport_ssh_public_key_path
            or str(Path(spec.working_directory) / "keys" / f"{spec.engagement_name}-sketch-transport.pub"),
        }
    return {**variables, "ssh_pub_key_path": admin_public, "ssh_priv_key_path": admin_private}


def _retained_terraform_variables(spec: LinodeSketchSpec) -> dict[str, Any]:
    if not spec.retained_image:
        raise LinodeSketchGuardrailError("retained Linode image identity was not validated")
    variables = _terraform_variables(spec)
    variables["linode_image"] = spec.retained_image
    return variables


def _uses_split_ssh_variables(working_directory: str) -> bool:
    try:
        return 'variable "infrastructure_admin_ssh_pub_key_path"' in (
            Path(working_directory) / "variables.tf"
        ).read_text(encoding="utf-8")
    except OSError:
        return False


def _provider_name_slug(engagement_name: str, *, max_length: int = LINODE_SKETCH_NAME_SLUG_MAX_LENGTH) -> str:
    slug = re.sub(r"[^a-z0-9-]+", "-", engagement_name.strip().lower()).strip("-")
    slug = re.sub(r"-+", "-", slug)
    if not slug:
        slug = "engagement"
    return slug[:max_length].strip("-") or "engagement"


def _resource_name_suffix(chain_id: str) -> str:
    ordinal = _proxy_ordinal(chain_id)
    return "" if ordinal <= 1 else f"-{ordinal:02d}"


def _proxy_ordinal(chain_id: str) -> int:
    proxy_match = re.search(r"(?:^|[^0-9])proxy0*([1-9][0-9]*)", chain_id.strip().lower())
    if proxy_match:
        return int(proxy_match.group(1))
    return 1


def _append_destroy_cleanup_events(
    events: list[JobEvent],
    spec: LinodeSketchSpec,
    runner: TerraformCommandRunner,
    env: dict[str, str],
    variables: dict[str, Any],
) -> None:
    events.append(_event("info", "terraform destroy started", spec, {"phase": "destroy"}))
    destroy_result = _run(runner, "destroy", spec, env, variables)
    if destroy_result.returncode != 0:
        events.append(_event("error", "terraform destroy failed", spec, _terraform_failure_data(spec, destroy_result, env, variables, phase="destroy")))
        return
    events.append(_event("info", "terraform destroy completed", spec, {"phase": "destroy"}))
    events.append(_event("info", "terraform cleanup verification started", spec, {"phase": "cleanup"}))
    output = _run(runner, "output", spec, env, {})
    if output.returncode != 0:
        events.append(_event("error", "terraform cleanup verification failed", spec, _terraform_failure_data(spec, output, env, {}, phase="cleanup")))
        return
    try:
        remaining = _remaining_sketch_outputs(_decode_terraform_output(output.stdout))
    except ValueError:
        events.append(
            _event(
                "error",
                "terraform cleanup verification failed",
                spec,
                {"phase": "cleanup", "cleanupVerified": False, "reason": "invalid_json"},
            )
        )
        return
    events.append(
        _event(
            "info" if not remaining else "error",
            "terraform cleanup verified" if not remaining else "terraform cleanup verification failed",
            spec,
            {"phase": "cleanup", "cleanupVerified": not remaining, "remainingOutputs": remaining},
        )
    )


def _run(
    runner: TerraformCommandRunner,
    command: str,
    spec: LinodeSketchSpec,
    env: dict[str, str],
    variables: dict[str, Any],
):
    result = runner.run(
        command,
        working_directory=spec.working_directory,
        env=env,
        variables=variables,
    )
    return result


def _terraform_failure_data(
    spec: LinodeSketchSpec,
    result: TerraformCommandResult,
    env: dict[str, str],
    variables: dict[str, Any],
    *,
    phase: str,
) -> dict[str, Any]:
    return {
        "phase": phase,
        "terraformDiagnostic": terraform_failure_diagnostic(
            result,
            provider="linode",
            env=env,
            variables=variables,
        ),
        "workspaceDir": spec.working_directory,
    }


def _decode_terraform_output(stdout: str) -> dict[str, Any]:
    if not stdout.strip():
        return {}
    try:
        body = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("terraform output was not valid JSON") from exc
    return body if isinstance(body, dict) else {}


def _sketch_infrastructure_rows(spec: LinodeSketchSpec, output: dict[str, Any]) -> list[dict[str, Any]]:
    middle_ip = _first_output_value(output, "middle_public_ip", "middle_public_ips")
    middle_instance_id = _first_output_value(output, "middle_instance_id", "middle_instance_ids")
    edge_ips = _edge_values_from_outputs(spec, output, "edge_public_ip", "edge_public_ips")
    edge_instance_ids = _edge_values_from_outputs(spec, output, "edge_instance_id", "edge_instance_ids")
    rows = []
    if spec.middle_count:
        rows.append({
            "chainId": spec.chain_id,
            "hostname": _middle_name(spec.engagement_name, spec.chain_id),
            "componentId": spec.component_id or "middle",
            "middleOrdinal": spec.middle_ordinal,
            "provider": "linode",
            "providerInstanceId": _string(middle_instance_id),
            "role": "middle",
            "publicIp": _string(middle_ip),
            "region": spec.middle_region,
            "assignedProxy": spec.assigned_proxy,
            "proxy": spec.assigned_proxy,
            "status": "deployed",
        })
    edge_index = 0
    regional_occurrences: dict[str, int] = {}
    for region in spec.edge_regions or (spec.edge_region,):
      for _ in range(spec.edge_count_per_region or spec.edge_count):
        edge_ip = edge_ips[edge_index] if edge_index < len(edge_ips) else ""
        edge_instance_id = edge_instance_ids[edge_index] if edge_index < len(edge_instance_ids) else ""
        index = edge_index
        edge_index += 1
        regional_occurrences[region] = regional_occurrences.get(region, 0) + 1
        edge_id = _edge_id_for_region(spec, region, regional_occurrences[region], index)
        rows.append(
            {
            "chainId": spec.chain_id,
            "hostname": _edge_name(spec.engagement_name, region, spec.chain_id, spec.edge_ordinal + index),
            "componentId": spec.component_id or spec.edge_id or edge_id,
            "edgeId": spec.edge_id or edge_id,
            "edgeIndex": str(spec.edge_ordinal + index),
            "edgeCount": str((spec.edge_count_per_region or spec.edge_count) * len(spec.edge_regions or (spec.edge_region,))),
            "provider": "linode",
            "providerInstanceId": _string(edge_instance_id),
            "role": "edge",
            "publicIp": _string(edge_ip),
            "region": region,
            "assignedProxy": spec.assigned_proxy,
            "proxy": spec.assigned_proxy,
            "status": "deployed",
            }
        )
    return rows


def _remaining_sketch_outputs(output: dict[str, Any]) -> list[str]:
    remaining = []
    for key in ("middle_public_ip", "middle_public_ips", "edge_public_ip", "edge_public_ips"):
        value = _output_value(output, key)
        if isinstance(value, dict) and value:
            remaining.append(key)
        elif isinstance(value, list) and value:
            remaining.append(key)
        elif isinstance(value, str) and value.strip():
            remaining.append(key)
    return remaining


def _output_value(output: dict[str, Any], key: str) -> Any:
    value = output.get(key)
    if isinstance(value, dict) and "value" in value:
        return value["value"]
    return value


def _first_output_value(output: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = _output_value(output, key)
        if isinstance(value, list) and value:
            return value[0]
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _edge_values_from_outputs(spec: LinodeSketchSpec, output: dict[str, Any], scalar_key: str, collection_key: str) -> list[Any]:
    value = _output_value(output, collection_key)
    if isinstance(value, dict):
        values: list[Any] = []
        for region in spec.edge_regions or (spec.edge_region,):
            regional = value.get(region)
            if isinstance(regional, list): values.extend(regional)
            elif isinstance(regional, str) and regional.strip(): values.append(regional)
        if values: return values
    if isinstance(value, list):
        return value
    value = _output_value(output, scalar_key)
    if isinstance(value, str) and value.strip():
        return [value]
    return []


def _edge_id_for_region(spec: LinodeSketchSpec, region: str, occurrence: int, index: int) -> str:
    matches = [edge_id for edge_id, edge_region in spec.edge_intents if edge_region == region]
    if occurrence <= len(matches):
        return matches[occurrence - 1]
    return spec.edge_ids[index] if index < len(spec.edge_ids) else f"edge-{spec.edge_ordinal + index:02d}"


def _event(level: str, message: str, spec: LinodeSketchSpec, data: dict[str, Any]) -> JobEvent:
    safe_data = {
        "provider": "linode",
        "engagementId": spec.engagement_id,
        "chainId": spec.chain_id,
        "credentialAlias": spec.credential_alias,
        "credentialRef": f"credential://linode/{spec.credential_alias}",
        "credentialEnvVar": LINODE_TOKEN_ENV_VAR,
        **data,
    }
    return JobEvent(0, level, message, safe_data)


def _middle_name(engagement_name: str, chain_id: str) -> str:
    return f"middle01-{_provider_name_slug(engagement_name)}{_resource_name_suffix(chain_id)}"


def _edge_name(engagement_name: str, region: str, chain_id: str, edge_ordinal: int = 1) -> str:
    return f"edge-{_provider_name_slug(engagement_name)}-{_provider_name_slug(region, max_length=20)}-{edge_ordinal:02d}{_resource_name_suffix(chain_id)}"


def _node_count(value: Any, *, field: str, default: int) -> int:
    try:
        count = default if value in (None, "") else int(value)
    except (TypeError, ValueError) as exc:
        raise LinodeSketchGuardrailError(f"{field} must be an integer from 0 to 10") from exc
    if count < 0 or count > 10:
        raise LinodeSketchGuardrailError(f"{field} must be an integer from 0 to 10")
    return count


def _required(data: dict[str, Any], key: str) -> str:
    value = str(data.get(key) or "").strip()
    if not value:
        raise ValueError(f"{key} is required")
    return value


def _required_guarded(data: dict[str, Any], key: str) -> str:
    value = str(data.get(key) or "").strip()
    if not value:
        raise LinodeSketchGuardrailError(f"{key} is required")
    return value


def _optional_alias(data: dict[str, Any], key: str) -> str | None:
    value = str(data.get(key) or "").strip().lower()
    return value or None


def _default_alias(provider: str) -> str | None:
    try:
        return resolve_default_credential_alias(provider)
    except RuntimeError:
        return None


def _string(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _next_sequence(events: list[JobEvent]) -> int:
    if not events:
        return 1
    return max(event.sequence for event in events) + 1


def _renumber_events(events: list[JobEvent], first_sequence: int) -> list[JobEvent]:
    return [
        JobEvent(first_sequence + index, event.level, event.message, event.data)
        for index, event in enumerate(events)
    ]
