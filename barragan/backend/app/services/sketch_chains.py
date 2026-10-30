# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import os
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from app.core.runtime import current_runtime, runtime_context, start_runtime_task
from app.domain import JobEvent
from app.services.engagements import get_engagement
from app.services.infra_orientation import try_enqueue_infra_orientation_refresh
from app.services.digitalocean_sketch_deployment import (
    DIGITALOCEAN_SKETCH_CONFIRMATION,
    DigitalOceanSketchGuardrailError,
    resume_guarded_digitalocean_sketch_teardown,
    start_guarded_digitalocean_sketch_run,
    start_guarded_digitalocean_sketch_reconcile,
    start_guarded_digitalocean_sketch_teardown,
)
from app.services.linode_sketch_deployment import (
    LINODE_SKETCH_CONFIRMATION,
    LinodeSketchGuardrailError,
    resume_guarded_linode_sketch_teardown,
    start_guarded_linode_sketch_run,
    start_guarded_linode_sketch_reconcile,
    start_guarded_linode_sketch_teardown,
)
from app.services.mixed_sketch_deployment import (
    MIXED_SKETCH_CONFIRMATION,
    MixedSketchGuardrailError,
    resume_guarded_mixed_sketch_teardown,
    start_guarded_mixed_sketch_run,
    start_guarded_mixed_sketch_teardown,
)
from app.services.outbound_channel_apply import (
    OutboundChannelApplyValidationError,
    apply_outbound_channel,
    remove_outbound_channel,
    validate_outbound_channel,
)
from app.services.provider_region_policy import DEFAULT_ALLOWED_REGIONS, is_provider_region_allowed
from app.services.sketch_power import SketchPowerValidationError, run_sketch_power_job
from app.services.bootstrap_command_evidence import TIMING_KEYS, valid_bootstrap_result_keys
from app.services.sketch_bootstrap_apply import (
    SketchBootstrapApplyError, SketchBootstrapReconciliationRequiredError, SketchBootstrapTimeoutError, SketchBootstrapQuiescenceUnprovedError,
    BOOTSTRAP_TIMEOUT_MESSAGE, apply_sketch_bootstrap,
)
from app.services.provider_keyed_gated_runner import UnreapedGatedCommandError
from app.services.sketch_edge_lifecycle import SketchEdgeLifecycleError, append_replacement_edge, retire_final_edge
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.sketch_chain_repository import (
    SketchChainRepository,
    SqlAlchemySketchChainRepository,
    StoredSketchChain,
)

SKETCH_CHAIN_STATUSES = {"pending", "deploying", "reconciling", "deployed", "stopping", "stopped", "starting", "tearing_down", "destroyed", "failed", "aborted"}
DEFAULT_MAX_NON_DESTROYED_SKETCH_CHAINS = 32
TERMINAL_INACTIVE_SKETCH_CHAIN_STATUSES = {"destroyed", "aborted"}
PROXY_PATTERN = re.compile(r"^proxy\d{2}$")
OUTBOUND_AUTO_CONFIGURATION_ACTION = "outbound_channel_auto_configuration"
OUTBOUND_AUTO_LEASE_SECONDS = 5 * 60
OUTBOUND_AUTO_HEARTBEAT_SECONDS = 60
_outbound_auto_configuration_lock = threading.Lock()
_outbound_auto_configuration_active: set[str] = set()
_outbound_auto_configuration_owner = f"runtime-{uuid4().hex}"
_bootstrap_recovery_lock = threading.Lock()
_bootstrap_recovery_active: set[tuple[str, str]] = set()
_BOOTSTRAP_PROGRESS_PHASES = {
    "root-management-readiness",
    "upstream-root-bootstrap",
    "post-root-user-readiness",
    "transport-key-install",
}
_BOOTSTRAP_PROGRESS_STATUSES = {"checking", "waiting", "starting", "completed", "failed"}
_BOOTSTRAP_FAILURE_CLASSES = {"authentication", "settling", "terminal", "execution_timeout"}
_BOOTSTRAP_IDENTITY_BOUNDARIES = {"root-admin", "user-admin", "transport-runtime"}
_BOOTSTRAP_NODE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PROVIDER_DEPLOYMENT_POLL_SECONDS = 1.0
SKETCH_EDGE_RETIRE_ACTION = "sketch_edge_retire"
SKETCH_EDGE_REPLACE_ACTION = "sketch_edge_replace"


class SketchChainValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("sketch chain validation failed")
        self.errors = errors


def _require_split_v1_sketch_dispatch(engagement_id: str) -> None:
    """Never run a provider-scoped state through a chain-scoped Terraform job."""

    engagement = get_engagement(engagement_id)
    if engagement is None or engagement.sketch_state_schema != "split-v1":
        raise SketchChainValidationError([
            "chain-scoped deployment requires an existing split-v1 engagement"
        ])


def list_sketch_chains(
    engagement_id: str,
    repository: SketchChainRepository | None = None,
) -> list[dict[str, Any]] | None:
    if get_engagement(engagement_id) is None:
        return None
    return [chain.to_dict() for chain in _repo(repository).list_for_engagement(engagement_id)]


def create_sketch_chain(
    engagement_id: str,
    body: dict[str, Any],
    repository: SketchChainRepository | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    _assert_core_mutation_allowed(engagement_id, repository)
    repo = _repo(repository)
    existing_chains = repo.list_for_engagement(engagement_id)
    max_chains = _max_non_destroyed_sketch_chains()
    active_count = sum(1 for chain in existing_chains if chain.status not in TERMINAL_INACTIVE_SKETCH_CHAIN_STATUSES)
    if active_count >= max_chains:
        raise SketchChainValidationError(
            [
                "sketch chain limit reached for this engagement; "
                f"{active_count} active chain records exist and the limit is {max_chains}"
            ]
        )
    now = _now()
    assigned_proxy = _required_proxy(body.get("assignedProxy") or body.get("proxy") or "proxy01")
    middle_provider = _provider(body, "middleProvider")
    middle_region = _required_text(body, "middleRegion")
    edges = _normalize_edges(body)
    edge_provider = edges[0]["provider"]
    edge_region = edges[0]["region"]
    _validate_uniform_edge_plan(middle_provider, middle_region, edges)
    chain = StoredSketchChain(
        chain_id=_allocate_chain_id(existing_chains, assigned_proxy, edge_region),
        engagement_id=engagement_id,
        assigned_proxy=assigned_proxy,
        middle_provider=middle_provider,
        middle_region=middle_region,
        middle_size=_text(body.get("middleSize")) or "g6-nanode-1",
        edge_provider=edge_provider,
        edge_region=edge_region,
        edge_size=edges[0]["size"],
        edge_count=len(edges),
        edge_intents=edges,
        status="pending",
        burned=False,
        burned_note="",
        deploy_job_id="",
        teardown_job_id="",
        terraform_working_directory="",
        nodes=[],
        created_at=now,
        updated_at=now,
    )
    return repo.save(chain).to_dict()


def validate_template_sketch_chain_intents(
    input_parameters: dict[str, Any],
    *,
    use_runtime_region_policy: bool = True,
) -> list[str]:
    errors: list[str] = []
    for index, body in enumerate(input_parameters.get("sketchChains") or []):
        if not isinstance(body, dict):
            continue
        prefix = f"sketchChains[{index}]"
        try:
            middle_provider = _provider(body, "middleProvider")
            middle_region = _required_text(body, "middleRegion")
            edges = _normalize_edges(body)
            edge_provider = edges[0]["provider"]
            edge_region = edges[0]["region"]
            _validate_uniform_edge_plan(
                middle_provider, middle_region, edges, use_runtime_region_policy=use_runtime_region_policy
            )
        except SketchChainValidationError as exc:
            errors.extend(f"{prefix}: {error}" for error in exc.errors)
    return errors


def seed_template_sketch_chains(
    engagement_id: str,
    input_parameters: dict[str, Any],
    repository: SketchChainRepository | None = None,
) -> list[dict[str, Any]]:
    if get_engagement(engagement_id) is None:
        return []
    _assert_core_mutation_allowed(engagement_id, repository)
    repo = _repo(repository)
    saved: list[StoredSketchChain] = []
    intent_bodies = [body for body in input_parameters.get("sketchChains") or [] if isinstance(body, dict)]
    desired_intents = [_template_chain_intent(engagement_id, body) for body in intent_bodies]
    # Configuration changes may replace pending, never-deployed intent. Retire
    # only those ghost records; deployed/history-bearing chains are immutable
    # lifecycle evidence and must go through explicit teardown instead.
    for existing in repo.list_for_engagement(engagement_id):
        if (
            existing.status == "pending"
            and not existing.deploy_job_id
            and not existing.teardown_job_id
            and not existing.nodes
            and not any(_same_template_chain_intent(existing, intent) for intent in desired_intents)
        ):
            repo.save(replace(existing, status="aborted", updated_at=_now()))
    for body in intent_bodies:
        existing_chains = repo.list_for_engagement(engagement_id)
        active_chains = [chain for chain in existing_chains if chain.status not in TERMINAL_INACTIVE_SKETCH_CHAIN_STATUSES]
        intent = _template_chain_intent(engagement_id, body)
        existing = next((chain for chain in active_chains if _same_template_chain_intent(chain, intent)), None)
        if existing is not None:
            saved.append(existing)
            continue
        if len(active_chains) >= _max_non_destroyed_sketch_chains():
            raise SketchChainValidationError(
                [
                    "sketch chain limit reached for this engagement; "
                    f"{len(active_chains)} active chain records exist and the limit is {_max_non_destroyed_sketch_chains()}"
                ]
            )
        chain = replace(
            intent,
            chain_id=_allocate_chain_id(existing_chains, intent.assigned_proxy, intent.edge_region),
        )
        saved.append(repo.save(chain))
    return [chain.to_dict() for chain in saved]


def update_sketch_chain(
    engagement_id: str,
    chain_id: str,
    body: dict[str, Any],
    repository: SketchChainRepository | None = None,
) -> dict[str, Any] | None:
    _assert_core_mutation_allowed(engagement_id, repository)
    repo = _repo(repository)
    chain = repo.get(engagement_id, chain_id)
    if chain is None:
        return None
    patch: dict[str, Any] = {}
    if "burned" in body:
        patch["burned"] = bool(body.get("burned"))
        patch["burned_note"] = _text(body.get("burnedNote"))
    if chain.status == "pending":
        for api_key, field_name in (
            ("middleProvider", "middle_provider"),
            ("middleRegion", "middle_region"),
            ("middleSize", "middle_size"),
            ("edgeProvider", "edge_provider"),
            ("edgeRegion", "edge_region"),
            ("edgeSize", "edge_size"),
        ):
            if api_key in body:
                patch[field_name] = _text(body.get(api_key))
        if "edgeCount" in body:
            edge_count = _edge_count(body.get("edgeCount"))
            patch["edge_count"] = edge_count
            if chain.edge_intents:
                edges = [dict(edge) for edge in chain.edge_intents[:edge_count]]
                default = chain.edge_intents[0]
                while len(edges) < edge_count:
                    index = len(edges) + 1
                    edges.append(
                        {"id": f"edge-{index:02d}", "provider": default["provider"], "region": default["region"], "size": default["size"]}
                    )
                patch["edge_intents"] = edges
        if "edges" in body:
            edges = _normalize_edges(body)
            patch.update(
                edge_intents=edges,
                edge_provider=edges[0]["provider"],
                edge_region=edges[0]["region"],
                edge_size=edges[0]["size"],
                edge_count=len(edges),
            )
        candidate_edges = patch.get("edge_intents") or [dict(edge) for edge in (chain.edge_intents or _legacy_edges(chain))]
        # Scalar PATCH remains the compatibility API: apply it to the effective
        # ordered intents rather than validating stale persisted edge rows.
        if "edgeProvider" in body or "edgeRegion" in body or "edgeSize" in body:
            provider = patch.get("edge_provider", chain.edge_provider)
            region = patch.get("edge_region", chain.edge_region)
            size = patch.get("edge_size", chain.edge_size)
            candidate_edges = [
                {**edge, "provider": provider, "region": region, "size": size}
                for edge in candidate_edges
            ]
            patch["edge_intents"] = candidate_edges
        _validate_uniform_edge_plan(
            _provider_from_text(patch.get("middle_provider", chain.middle_provider), "middleProvider"),
            patch.get("middle_region", chain.middle_region),
            candidate_edges,
        )
    elif any(key in body for key in ("middleProvider", "middleRegion", "middleSize", "edgeProvider", "edgeRegion", "edgeSize", "edgeCount", "edges")):
        raise SketchChainValidationError(["deployed sketch chains are locked; only burned metadata can be updated"])

    updated = repo.save(replace(chain, **patch, updated_at=_now()))
    if "burned" in body:
        try_enqueue_infra_orientation_refresh(engagement_id)
    return updated.to_dict()


def cancel_sketch_chain(
    engagement_id: str,
    chain_id: str,
    body: dict[str, Any],
    repository: SketchChainRepository | None = None,
) -> dict[str, Any] | None:
    _assert_core_mutation_allowed(engagement_id, repository)
    repo = _repo(repository)
    chain = repo.get(engagement_id, chain_id)
    if chain is None:
        return None
    expected = f"cancel-{chain.chain_id}"
    if body.get("confirmation") != expected:
        raise SketchChainValidationError([f'confirmation must equal "{expected}"'])
    if chain.status != "pending":
        raise SketchChainValidationError([f"chain {chain.chain_id} is {chain.status} and cannot be canceled"])
    if chain.deploy_job_id or chain.teardown_job_id or chain.nodes:
        raise SketchChainValidationError(["pending chain has deployment state and cannot be canceled"])
    return repo.save(replace(chain, status="aborted", updated_at=_now())).to_dict()


def deploy_sketch_chain(
    engagement_id: str,
    chain_id: str,
    body: dict[str, Any],
    repository: SketchChainRepository | None = None,
    *,
    allow_core_plan_continuation: bool = False,
) -> dict[str, Any] | None:
    _require_split_v1_sketch_dispatch(engagement_id)
    if not allow_core_plan_continuation:
        _assert_core_mutation_allowed(engagement_id, repository)
    repo = _repo(repository)
    chain = repo.get(engagement_id, chain_id)
    if chain is None:
        return None
    if chain.status not in {"pending", "failed"}:
        raise SketchChainValidationError([f"chain {chain.chain_id} is {chain.status} and cannot be deployed"])
    if chain.deploy_job_id:
        _require_bootstrap_reconciled(SqlAlchemyJobRepository().get(chain.deploy_job_id))
    retry = _retry_failed_sketch_bootstrap(
        engagement_id,
        chain,
        repository=repo,
        requested_by=_requested_by(body),
    )
    if retry is not None:
        return retry
    if body.get("retryBootstrapOnly") is True:
        raise SketchChainValidationError([
            f"chain {chain.chain_id} is no longer eligible for retained bootstrap-only recovery"
        ])
    edges = chain.edge_intents or _legacy_edges(chain)
    _validate_uniform_edge_plan(chain.middle_provider, chain.middle_region, edges)
    edge_regions, edge_count_per_region = _edge_batch_plan(edges)
    individual_edge_components = _requires_individual_edge_components(edges)
    provider_tasks: list[Callable[[], None]] = []
    capture_provider_task = provider_tasks.append
    try:
        if individual_edge_components or chain.middle_provider != chain.edge_provider:
            job = start_guarded_mixed_sketch_run(
                {
                    "confirmMutation": body.get("confirmMutation") or MIXED_SKETCH_CONFIRMATION,
                    "engagementId": engagement_id,
                    "coreJobId": body.get("coreJobId") or "",
                    "chainId": chain.chain_id,
                    "assignedProxy": chain.assigned_proxy,
                    "middleProvider": chain.middle_provider,
                    "middleRegion": chain.middle_region,
                    "middleSize": chain.middle_size,
                    "edgeProvider": chain.edge_provider,
                    "edgeRegion": chain.edge_region,
                    "edgeSize": chain.edge_size,
                    "edgeCount": chain.edge_count,
                    "edges": edges,
                    "edgeRegions": edge_regions,
                    "edgeCountPerRegion": edge_count_per_region,
                    "middleOrdinal": _sketch_chain_ordinal(repo.list_for_engagement(engagement_id), chain.chain_id),
                },
                background_runner=capture_provider_task,
            )
        elif chain.middle_provider == "linode":
            job = start_guarded_linode_sketch_run(
                {
                    "confirmMutation": body.get("confirmMutation") or LINODE_SKETCH_CONFIRMATION,
                    "engagementId": engagement_id,
                    "coreJobId": body.get("coreJobId") or "",
                    "chainId": chain.chain_id,
                    "assignedProxy": chain.assigned_proxy,
                    "middleRegion": chain.middle_region,
                    "middleSize": chain.middle_size,
                    "edgeRegion": chain.edge_region,
                    "edgeSize": chain.edge_size,
                    "edgeCount": chain.edge_count,
                    "edges": edges,
                    "edgeRegions": edge_regions,
                    "edgeCountPerRegion": edge_count_per_region,
                },
                background_runner=capture_provider_task,
            )
        elif chain.middle_provider == "digitalocean":
            job = start_guarded_digitalocean_sketch_run(
                {
                    "confirmMutation": body.get("confirmMutation") or DIGITALOCEAN_SKETCH_CONFIRMATION,
                    "engagementId": engagement_id,
                    "coreJobId": body.get("coreJobId") or "",
                    "chainId": chain.chain_id,
                    "assignedProxy": chain.assigned_proxy,
                    "middleRegion": chain.middle_region,
                    "middleSize": chain.middle_size,
                    "edgeRegion": chain.edge_region,
                    "edgeSize": chain.edge_size,
                    "edgeCount": chain.edge_count,
                    "edges": edges,
                    "edgeRegions": edge_regions,
                    "edgeCountPerRegion": edge_count_per_region,
                },
                background_runner=capture_provider_task,
            )
        else:
            raise SketchChainValidationError(["incremental live sketch deployment currently supports Linode and DigitalOcean same-provider chains only"])
    except (LinodeSketchGuardrailError, DigitalOceanSketchGuardrailError, MixedSketchGuardrailError) as exc:
        raise SketchChainValidationError([str(exc)]) from exc
    persisted = repo.save(
        replace(
            chain,
            status=_status_from_job(job.status, running="deploying", success="deployed"),
            deploy_job_id=job.id,
            terraform_working_directory=_job_input(job, "terraformWorkingDirectory"),
            nodes=_nodes_from_job(job, chain),
            updated_at=_now(),
        )
    )
    if provider_tasks:
        _start_sketch_deployment_tasks(
            engagement_id,
            persisted.chain_id,
            job.id,
            provider_tasks,
            requested_by=_requested_by(body),
            chain_repository=repo,
        )
        persisted = repo.get(engagement_id, chain_id) or persisted
        latest_job = SqlAlchemyJobRepository().get(job.id)
        if latest_job is not None:
            job = latest_job.to_detail()
    result = {"chain": persisted.to_dict(), "job": job.to_dict()}
    if persisted.status == "deployed":
        parent = _start_outbound_auto_configuration(
            engagement_id,
            persisted.chain_id,
            deploy_job_id=job.id,
            requested_by=_requested_by(body),
        )
        if parent is not None:
            result["outboundConfigurationJob"] = parent.to_detail().to_dict()
    return result


def refresh_sketch_chain_from_job(
    engagement_id: str,
    chain_id: str,
    repository: SketchChainRepository | None = None,
    job_repository: JobRepository | None = None,
    *,
    start_outbound_continuation: bool = True,
    requested_by: str = "operator",
) -> dict[str, Any] | None:
    repo = _repo(repository)
    jobs = job_repository or SqlAlchemyJobRepository()
    chain = repo.get(engagement_id, chain_id)
    if chain is None or not chain.deploy_job_id:
        return None if chain is None else {"sketchChain": chain.to_dict()}
    if chain.teardown_job_id:
        teardown_job = jobs.get(chain.teardown_job_id)
        if teardown_job is not None:
            candidate = replace(
                chain,
                status=_status_from_job(teardown_job.status, running="tearing_down", success="destroyed"),
                nodes=[] if teardown_job.status == "succeeded" else chain.nodes,
            )
            updated = _save_chain_if_changed(repo, chain, candidate)
            return {"sketchChain": updated.to_dict()}
    if chain.status in {"destroyed", "tearing_down"}:
        return {"sketchChain": chain.to_dict()}
    job = jobs.get(chain.deploy_job_id)
    if job is None:
        return {"sketchChain": chain.to_dict()}
    candidate = replace(
        chain,
        # Terraform output alone does not make a fresh chain usable.  The
        # post-create root bootstrap and transport-key install are a single
        # deployment readiness boundary.  In particular, browser refreshes
        # may observe a successful provider job while that continuation is
        # still running in its background task; keep the chain deploying
        # until its durable bootstrap-success event is present.
        status=_deployment_status_after_bootstrap(chain, job),
        terraform_working_directory=_job_input(job, "terraformWorkingDirectory") or chain.terraform_working_directory,
        nodes=_nodes_from_job(job, chain) or chain.nodes,
    )
    updated = _save_chain_if_changed(repo, chain, candidate)
    result = {"sketchChain": updated.to_dict()}
    if updated.status == "deployed" and start_outbound_continuation:
        parent = _start_outbound_auto_configuration(
            engagement_id,
            updated.chain_id,
            deploy_job_id=job.id,
            requested_by=requested_by,
            repository=jobs,
        )
        if parent is not None:
            result["outboundConfigurationJob"] = parent.to_detail().to_dict()
    return result


def _deployment_status_after_bootstrap(chain: StoredSketchChain, job: StoredJobRun) -> str:
    """Map provider-job state without exposing a pre-bootstrap chain as live.

    Existing legacy chains were recorded as ``deployed`` before the
    bootstrap-gated lifecycle existed, so preserve that durable historical
    state.  Fresh chains begin ``deploying`` and require the explicit event
    written by :func:`_bootstrap_provider_job` before they transition.
    """

    if job.status != "succeeded":
        return _status_from_job(job.status, running="deploying", success="deployed")
    if chain.status == "deployed" or any(event.data.get("bootstrap") == "succeeded" for event in job.events):
        return "deployed"
    return "deploying"


def _start_sketch_deployment_tasks(
    engagement_id: str,
    chain_id: str,
    provider_job_id: str,
    provider_tasks: list[Callable[[], None]],
    *,
    requested_by: str,
    chain_repository: SketchChainRepository,
) -> None:
    """Launch only after the durable chain points at the captured provider job."""

    def run() -> None:
        for provider_task in provider_tasks:
            provider_task()
        jobs = SqlAlchemyJobRepository()
        # Provider runners start their own background work.  Do not infer that
        # calling their launcher means Terraform has completed: wait for the
        # durable child job before beginning the root/user/transport handoff.
        provider_job = _wait_for_provider_job_terminal(provider_job_id, jobs)
        if provider_job is not None and provider_job.status == "succeeded":
            _bootstrap_provider_job(engagement_id, chain_id, chain_repository, jobs)
        refresh_sketch_chain_from_job(
            engagement_id,
            chain_id,
            repository=chain_repository,
            job_repository=jobs,
            requested_by=requested_by,
        )

    start_runtime_task(
        run,
        name=f"barragan-sketch-deploy-{chain_id}",
        synchronous_when_testing=True,
    )


def _wait_for_provider_job_terminal(
    job_id: str,
    repository: JobRepository,
    *,
    wait: Callable[[float], None] = time.sleep,
) -> StoredJobRun | None:
    """Wait in the deployment worker for its provider child to finish.

    This worker is already asynchronous.  Polling the durable job record keeps
    the post-create bootstrap ordered after Terraform without turning a
    successful provider result into an unbootstrapped ``deployed`` chain.
    Runtime restart recovery handles an interrupted worker.
    """

    while True:
        job = repository.get(job_id)
        if job is None or job.status in {"succeeded", "failed"}:
            return job
        wait(PROVIDER_DEPLOYMENT_POLL_SECONDS)


def _bootstrap_provider_job(
    engagement_id: str,
    chain_id: str,
    chain_repository: SketchChainRepository,
    jobs: JobRepository,
) -> None:
    """Make Terraform success conditional on the required post-create handoff."""

    chain = chain_repository.get(engagement_id, chain_id)
    if chain is None or not chain.deploy_job_id:
        return
    provider_job = jobs.get(chain.deploy_job_id)
    if provider_job is None or not _bootstrap_can_run(provider_job):
        return
    if provider_job.status == "succeeded":
        terraform_completed_at = provider_job.finished_at
        provider_job = jobs.save(
            replace(
                provider_job,
                status="running",
                finished_at="",
                events=provider_job.events
                + [
                    JobEvent(
                        len(provider_job.events) + 1,
                        "info",
                        "upstream-compatible sketch bootstrap started",
                        {"bootstrap": "starting", "terraformCompletedAt": terraform_completed_at},
                    )
                ],
            )
        )
    bootstrapping_chain = replace(chain, nodes=_nodes_from_job(provider_job, chain) or chain.nodes)
    def report_readiness(status: str, data: dict[str, object]) -> None:
        _record_bootstrap_readiness_progress(jobs, provider_job.id, status, data)

    try:
        result = apply_sketch_bootstrap(
            engagement_id,
            bootstrapping_chain,
            repository=jobs,
            progress_reporter=report_readiness,
        )
    except (SketchBootstrapReconciliationRequiredError, UnreapedGatedCommandError) as exc:
        current = jobs.get(provider_job.id) or provider_job
        jobs.save(replace(current, status="failed", finished_at=_now(), events=current.events + [
            JobEvent(len(current.events) + 1, "error",
                     BOOTSTRAP_TIMEOUT_MESSAGE if isinstance(exc, SketchBootstrapTimeoutError) else
                     "local bootstrap execution stopped; remote work may remain; reconciliation required",
                     {"bootstrap": "reconciliation_required",
                      "timedOut": isinstance(exc, SketchBootstrapTimeoutError),
                      "localQuiescenceUnproved": isinstance(exc, (SketchBootstrapQuiescenceUnprovedError, UnreapedGatedCommandError))})]))
        return
    except SketchBootstrapApplyError as exc:
        current = jobs.get(provider_job.id) or provider_job
        jobs.save(
            replace(
                current,
                status="failed",
                finished_at=_now(),
                events=current.events
                + [
                    JobEvent(
                        len(current.events) + 1,
                        "error",
                        "sketch bootstrap failed; provider infrastructure retained for retry",
                        {"bootstrap": "failed", "error": str(exc)},
                    )
                ],
            )
        )
        return
    current = jobs.get(provider_job.id) or provider_job
    jobs.save(
        replace(
            current,
            status="succeeded",
            finished_at=_now(),
            events=current.events
            + [
                JobEvent(
                    len(current.events) + 1,
                    "info",
                    "upstream-compatible sketch bootstrap completed",
                    result.to_event_data(),
                )
            ],
        )
    )


def _record_bootstrap_readiness_progress(
    jobs: JobRepository,
    job_id: str,
    status: str,
    data: dict[str, object],
) -> None:
    """Persist bounded, operator-safe bootstrap readiness evidence.

    This callback never changes provider resources or chain status. It gives
    the browser a durable attempt/backoff record while the retained nodes are
    settling, without putting host addresses or key material into job events.
    """

    current = jobs.get(job_id)
    if current is None or current.status != "running":
        return
    requested_phase = str(data.get("phase") or "")
    phase = requested_phase if requested_phase in _BOOTSTRAP_PROGRESS_PHASES else "root-management-readiness"
    status = status if status in _BOOTSTRAP_PROGRESS_STATUSES else "checking"
    message = {
        "checking": f"checking sketch {phase}",
        "waiting": f"sketch {phase} pending; retry scheduled",
        "starting": f"sketch readiness satisfied; starting {phase}",
        "completed": {
            "root-management-readiness": "sketch root management readiness completed",
            "upstream-root-bootstrap": "upstream root bootstrap completed; verifying normal user identity",
            "post-root-user-readiness": "post-root sketch user readiness completed",
            "transport-key-install": "sketch transport-key installation completed",
        }.get(phase, "sketch bootstrap phase completed"),
        "failed": f"sketch {phase} failed",
    }.get(status, "sketch bootstrap readiness progress")
    safe_data: dict[str, object] = {
        "bootstrap": "readiness",
        "status": status,
        "phase": phase,
    }
    for key in ("attempt", "maxAttempts", "elapsedSeconds", "nextBackoffSeconds", "nodeCount"):
        value = data.get(key)
        if type(value) is int and value >= 0:
            safe_data[key] = value
    timing = {key: data[key] for key in TIMING_KEYS if key in data}
    if set(timing) == TIMING_KEYS and valid_bootstrap_result_keys(timing, set()):
        safe_data.update(timing)
    failure_class = data.get("failureClass")
    if failure_class in _BOOTSTRAP_FAILURE_CLASSES:
        safe_data["failureClass"] = failure_class
    identity_boundary = data.get("identityBoundary")
    if identity_boundary in _BOOTSTRAP_IDENTITY_BOUNDARIES:
        safe_data["identityBoundary"] = identity_boundary
    if isinstance(data.get("retryExhausted"), bool):
        safe_data["retryExhausted"] = data["retryExhausted"]
    node_refs = data.get("nodeRefs")
    if isinstance(node_refs, list):
        safe_data["nodeRefs"] = [
            value
            for value in node_refs[:32]
            if isinstance(value, str) and _BOOTSTRAP_NODE_REF.fullmatch(value)
        ]
    jobs.save(
        replace(
            current,
            events=current.events
            + [
                JobEvent(
                    len(current.events) + 1,
                    "error" if status == "failed" else "info",
                    message,
                    safe_data,
                )
            ],
        )
    )


def resume_pending_sketch_bootstrap(
    engagement_id: str,
    chain_id: str,
    *,
    repository: SketchChainRepository,
    job_repository: JobRepository,
    requested_by: str,
) -> bool:
    """Resume a completed provider job whose post-create bootstrap was lost.

    A controller restart between Terraform completion and the bootstrap worker
    must not strand live provider instances.  This only resumes the required
    handoff; it never re-runs Terraform or creates provider resources.
    """

    chain = repository.get(engagement_id, chain_id)
    if chain is None or chain.status == "deployed" or not chain.deploy_job_id:
        return False
    job = job_repository.get(chain.deploy_job_id)
    if job is None or not _bootstrap_can_run(job):
        return False
    key = (engagement_id, chain_id)
    with _bootstrap_recovery_lock:
        if key in _bootstrap_recovery_active:
            return False
        _bootstrap_recovery_active.add(key)

    def run() -> None:
        try:
            _bootstrap_provider_job(engagement_id, chain_id, repository, job_repository)
            refresh_sketch_chain_from_job(
                engagement_id,
                chain_id,
                repository=repository,
                job_repository=job_repository,
                requested_by=requested_by,
            )
        finally:
            with _bootstrap_recovery_lock:
                _bootstrap_recovery_active.discard(key)

    try:
        start_runtime_task(
            run,
            name=f"barragan-sketch-bootstrap-recovery-{chain_id}",
            synchronous_when_testing=True,
        )
    except Exception:
        with _bootstrap_recovery_lock:
            _bootstrap_recovery_active.discard(key)
        raise
    return True


def _retry_failed_sketch_bootstrap(
    engagement_id: str,
    chain: StoredSketchChain,
    *,
    repository: SketchChainRepository,
    requested_by: str,
) -> dict[str, Any] | None:
    """Retry only the post-create bootstrap for retained provider nodes.

    Terraform has already succeeded in this narrowly-defined recovery state.
    Re-running it could create duplicate provider resources, so the existing
    durable provider job is returned to ``running`` while bootstrap is retried.
    """

    if chain.status != "failed" or not chain.nodes or not chain.deploy_job_id:
        return None
    jobs = SqlAlchemyJobRepository()
    provider_job = jobs.get(chain.deploy_job_id)
    _require_bootstrap_reconciled(provider_job)
    if provider_job is None or not _failed_bootstrap_job(provider_job):
        return None
    retrying_job = jobs.save(
        replace(
            provider_job,
            status="running",
            started_at=_now(),
            finished_at="",
            events=provider_job.events
            + [
                JobEvent(
                    len(provider_job.events) + 1,
                    "info",
                    "sketch bootstrap retry started; retained provider infrastructure will be reused",
                    {"bootstrap": "retrying", "retry": "bootstrap_only"},
                )
            ],
        )
    )
    retrying_chain = repository.save(replace(chain, status="deploying", updated_at=_now()))

    def run() -> None:
        _bootstrap_provider_job(engagement_id, retrying_chain.chain_id, repository, jobs)
        refresh_sketch_chain_from_job(
            engagement_id,
            retrying_chain.chain_id,
            repository=repository,
            job_repository=jobs,
            requested_by=requested_by,
        )

    start_runtime_task(
        run,
        name=f"barragan-sketch-bootstrap-retry-{retrying_chain.chain_id}",
        synchronous_when_testing=True,
    )
    latest_chain = repository.get(engagement_id, retrying_chain.chain_id) or retrying_chain
    latest_job = jobs.get(retrying_job.id) or retrying_job
    return {"chain": latest_chain.to_dict(), "job": latest_job.to_detail().to_dict()}


def _bootstrap_needs_reconciliation(job: StoredJobRun | None) -> bool:
    return job is not None and any(event.data.get("bootstrap") == "reconciliation_required" for event in job.events)


def _require_bootstrap_reconciled(job: StoredJobRun | None, *, teardown: bool = False) -> None:
    if job is not None and _bootstrap_needs_reconciliation(job) and (
            not teardown or any(event.data.get("localQuiescenceUnproved") is True for event in job.events)):
        raise SketchChainValidationError(["bootstrap reconciliation is required before further mutation"])


def _failed_bootstrap_job(job: StoredJobRun) -> bool:
    return not _bootstrap_needs_reconciliation(job) and job.status == "failed" and any(event.data.get("bootstrap") == "failed" for event in job.events)


def _bootstrap_can_run(job: StoredJobRun) -> bool:
    if _bootstrap_needs_reconciliation(job):
        return False
    if job.status == "succeeded":
        return _bootstrap_pending(job)
    return job.status == "running" and any(event.data.get("bootstrap") in {"starting", "retrying"} for event in job.events)


def _bootstrap_pending(job: StoredJobRun) -> bool:
    return job.status == "succeeded" and not any(
        event.data.get("bootstrap") in {"starting", "succeeded", "failed", "retrying", "reconciliation_required"}
        for event in job.events
    )


def _save_chain_if_changed(
    repository: SketchChainRepository,
    current: StoredSketchChain,
    candidate: StoredSketchChain,
) -> StoredSketchChain:
    comparable_fields = (
        "status",
        "deploy_job_id",
        "teardown_job_id",
        "terraform_working_directory",
        "nodes",
    )
    if all(getattr(current, field) == getattr(candidate, field) for field in comparable_fields):
        return current
    candidate = replace(candidate, updated_at=_now())
    conditional_save = getattr(repository, "save_if_matches", None)
    if callable(conditional_save):
        saved = conditional_save(
            candidate,
            expected_status=current.status,
            expected_deploy_job_id=current.deploy_job_id,
            expected_teardown_job_id=current.teardown_job_id,
        )
        return saved or repository.get(current.engagement_id, current.chain_id) or current
    return repository.save(candidate)


def teardown_sketch_chain(
    engagement_id: str,
    chain_id: str,
    body: dict[str, Any],
    repository: SketchChainRepository | None = None,
    *,
    core_mutation_lease_owner: str = "",
) -> dict[str, Any] | None:
    _require_split_v1_sketch_dispatch(engagement_id)
    _assert_core_mutation_allowed(
        engagement_id,
        repository,
        authorized_teardown_owner=core_mutation_lease_owner,
    )
    repo = _repo(repository)
    chain = repo.get(engagement_id, chain_id)
    if chain is None:
        return None
    expected = f"teardown-{chain.chain_id}"
    if body.get("confirmation") != expected:
        raise SketchChainValidationError([f'confirmation must equal "{expected}"'])
    if not chain.deploy_job_id:
        raise SketchChainValidationError(["chain has no deploy job to tear down"])
    if chain.status not in {"deployed", "failed", "stopped"}:
        raise SketchChainValidationError([f"chain {chain.chain_id} is {chain.status} and cannot be torn down"])

    _require_bootstrap_reconciled(SqlAlchemyJobRepository().get(chain.deploy_job_id), teardown=True)
    provider_tasks: list[Callable[[], None]] = []
    capture_provider_task = provider_tasks.append
    job = start_guarded_linode_sketch_teardown(
        chain.deploy_job_id,
        background_runner=capture_provider_task,
    ) or start_guarded_digitalocean_sketch_teardown(
        chain.deploy_job_id,
        background_runner=capture_provider_task,
    ) or start_guarded_mixed_sketch_teardown(
        chain.deploy_job_id,
        background_runner=capture_provider_task,
    )
    if job is None:
        raise SketchChainValidationError(["deploy job was not found for chain teardown"])
    updated = repo.save(
        replace(
            chain,
            status=_status_from_job(job.status, running="tearing_down", success="destroyed"),
            teardown_job_id=job.id,
            nodes=[] if job.status == "succeeded" else chain.nodes,
            updated_at=_now(),
        )
    )
    _start_sketch_teardown_sequence(
        engagement_id,
        chain,
        job.id,
        provider_tasks,
        requested_by=_requested_by(body),
        chain_repository=repo,
        outbound_already_removed=body.get("outboundAlreadyRemoved") is True,
    )
    return {"chain": updated.to_dict(), "job": job.to_dict()}


def retire_sketch_chain_final_edge(
    engagement_id: str,
    chain_id: str,
    body: dict[str, Any],
    repository: SketchChainRepository | None = None,
    job_repository: JobRepository | None = None,
) -> dict[str, Any] | None:
    """Remove the only count-safe edge while retaining its middle and core.

    The public operation is intentionally constrained to a fully deployed
    same-provider chain.  It first removes every derived outbound profile and
    rejects active inbound references, then asks the provider adapter to apply
    a reviewed plan containing precisely the final count-indexed edge delete.
    """

    _require_split_v1_sketch_dispatch(engagement_id)
    _assert_core_mutation_allowed(engagement_id, repository)
    repo = _repo(repository)
    chain = repo.get(engagement_id, chain_id)
    if chain is None:
        return None
    edge_id = _text(body.get("edgeId"))
    if body.get("confirmation") != f"retire-edge-{chain_id}-{edge_id}":
        raise SketchChainValidationError([f'confirmation must equal "retire-edge-{chain_id}-{edge_id}"'])
    _assert_edge_transition_ready(engagement_id, chain, operation="retire")
    try:
        transition = retire_final_edge(chain.edge_intents or _legacy_edges(chain), edge_id)
    except SketchEdgeLifecycleError as exc:
        raise SketchChainValidationError([str(exc)]) from exc
    _validate_retained_middle_transition_plan(chain, transition.retained_edges)
    return _start_edge_transition(
        engagement_id,
        chain,
        desired_edges=transition.retained_edges,
        action=SKETCH_EDGE_RETIRE_ACTION,
        expected_edge_action="delete",
        requested_by=_requested_by(body),
        chain_repository=repo,
        job_repository=job_repository,
    )


def replace_sketch_chain_final_edge(
    engagement_id: str,
    chain_id: str,
    body: dict[str, Any],
    repository: SketchChainRepository | None = None,
    job_repository: JobRepository | None = None,
) -> dict[str, Any] | None:
    """Append one replacement edge in a new region to a retained middle."""

    _require_split_v1_sketch_dispatch(engagement_id)
    _assert_core_mutation_allowed(engagement_id, repository)
    repo = _repo(repository)
    chain = repo.get(engagement_id, chain_id)
    if chain is None:
        return None
    region = _text(body.get("region"))
    if body.get("confirmation") != f"replace-edge-{chain_id}-{region}":
        raise SketchChainValidationError([f'confirmation must equal "replace-edge-{chain_id}-{region}"'])
    _assert_edge_transition_ready(engagement_id, chain, operation="replace")
    try:
        transition = append_replacement_edge(chain.edge_intents or _legacy_edges(chain), region=region)
    except SketchEdgeLifecycleError as exc:
        raise SketchChainValidationError([str(exc)]) from exc
    _validate_retained_middle_transition_plan(chain, transition.retained_edges)
    return _start_edge_transition(
        engagement_id,
        chain,
        desired_edges=transition.retained_edges,
        action=SKETCH_EDGE_REPLACE_ACTION,
        expected_edge_action="create",
        requested_by=_requested_by(body),
        chain_repository=repo,
        job_repository=job_repository,
    )


def _assert_edge_transition_ready(engagement_id: str, chain: StoredSketchChain, *, operation: str) -> None:
    if chain.status != "deployed":
        raise SketchChainValidationError([f"chain {chain.chain_id} is {chain.status} and cannot {operation} an edge"])
    if chain.middle_provider != chain.edge_provider or chain.middle_provider not in {"linode", "digitalocean"}:
        raise SketchChainValidationError(["retained-middle edge replacement currently supports same-provider Linode or DigitalOcean chains only"])
    if not chain.terraform_working_directory:
        raise SketchChainValidationError(["chain does not have Barragan-owned retained Terraform state"])
    original_edges = chain.edge_intents or _legacy_edges(chain)
    if {str(edge["provider"]) for edge in original_edges} != {chain.middle_provider}:
        raise SketchChainValidationError(
            ["retained-middle edge transitions require every edge to use the middle provider"]
        )
    if len({str(edge["size"]) for edge in original_edges}) != 1:
        raise SketchChainValidationError(
            ["retained-middle edge transitions require one shared edge size"]
        )
    overview = _edge_transition_operations_overview(engagement_id)
    edges = {str(row.get("hostname") or "") for row in chain.nodes if str(row.get("role") or "") == "edge"}
    for channel in overview.get("inboundChannels", []) if isinstance(overview, dict) else []:
        if not isinstance(channel, dict) or str(channel.get("status") or "").strip().lower() in {"removed", "disabled"}:
            continue
        if str(channel.get("edge") or "") in edges:
            raise SketchChainValidationError(["remove active inbound channels from the selected edge before changing the chain"])


def _validate_retained_middle_transition_plan(chain: StoredSketchChain, edges: list[dict[str, Any]]) -> None:
    """Validate the narrower state-preserving lifecycle boundary.

    Initial heterogeneous and uneven edge lists can use Barragan's independent
    component workspaces.  A retained-middle transition instead must modify
    the original, count-addressed provider state in place, so it can only use
    the uniform batch representation supported by that state.
    """

    _validate_uniform_edge_plan(chain.middle_provider, chain.middle_region, edges)
    providers = {str(edge["provider"]) for edge in edges}
    if providers != {chain.middle_provider}:
        raise SketchChainValidationError(
            ["retained-middle edge transitions require every edge to use the middle provider"]
        )
    sizes = {str(edge["size"]) for edge in edges}
    if len(sizes) != 1:
        raise SketchChainValidationError(
            ["retained-middle edge transitions require one shared edge size"]
        )
    regions, count_per_region = _edge_batch_plan(edges)
    counts = {region: sum(1 for edge in edges if str(edge["region"]) == region) for region in regions}
    if any(count != count_per_region for count in counts.values()):
        rendered = ", ".join(f"{region}={count}" for region, count in counts.items())
        raise SketchChainValidationError(
            [
                "edge regions have unequal counts "
                f"({rendered}); the retained Terraform state requires the same edge count in every selected region"
            ]
        )


def _edge_transition_operations_overview(engagement_id: str) -> dict[str, Any]:
    # Import lazily: the operations projection imports sketch-chain storage and
    # must not form a module import cycle during API startup.
    from app.services.engagement_operations import get_operations_overview

    return get_operations_overview(engagement_id, include_provider_findings=False) or {}


def _start_edge_transition(
    engagement_id: str,
    chain: StoredSketchChain,
    *,
    desired_edges: list[dict[str, str]],
    action: str,
    expected_edge_action: str,
    requested_by: str,
    chain_repository: SketchChainRepository,
    job_repository: JobRepository | None = None,
) -> dict[str, Any]:
    jobs = job_repository or SqlAlchemyJobRepository()
    timestamp = _now()
    parent = jobs.save(
        StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=action,
            status="running",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={
                "engagementId": engagement_id,
                "chainId": chain.chain_id,
                "edgeTransition": "retire" if expected_edge_action == "delete" else "replace",
                "desiredEdges": desired_edges,
                "mutation": True,
            },
            artifact_refs=[],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=None,
            events=[
                JobEvent(
                    1,
                    "info",
                    "retained-middle edge transition started",
                    {"chainId": chain.chain_id, "operation": "retire" if expected_edge_action == "delete" else "replace"},
                )
            ],
        )
    )
    updated = chain_repository.save(replace(chain, status="reconciling", updated_at=_now()))

    def run() -> None:
        try:
            if expected_edge_action == "delete":
                _append_edge_transition_event(jobs, parent.id, "outbound profile removal started", {"phase": "outbound_cleanup"})
                _remove_outbound_channel_for_teardown(engagement_id, chain.chain_id, requested_by=requested_by, repository=jobs)
                _append_edge_transition_event(jobs, parent.id, "outbound profile removal completed", {"phase": "outbound_cleanup"})
            provider_body = _edge_transition_provider_body(chain, desired_edges, expected_edge_action, requested_by)
            provider_job = _start_same_provider_edge_reconcile(chain, provider_body, jobs)
            latest_provider = jobs.get(provider_job.id)
            if latest_provider is None or latest_provider.status != "succeeded":
                raise SketchChainValidationError(["reviewed edge Terraform transition did not complete"])
            candidate = replace(
                chain,
                edge_count=len(desired_edges),
                edge_intents=[dict(edge) for edge in desired_edges],
                edge_provider=desired_edges[0]["provider"],
                edge_region=desired_edges[0]["region"],
                edge_size=desired_edges[0]["size"],
                deploy_job_id=latest_provider.id,
                terraform_working_directory=_job_input(latest_provider, "terraformWorkingDirectory") or chain.terraform_working_directory,
                nodes=_nodes_from_job(latest_provider, chain),
                status="deploying" if expected_edge_action == "create" else "deployed",
                updated_at=_now(),
            )
            candidate = chain_repository.save(candidate)
            if expected_edge_action == "create":
                _bootstrap_provider_job(engagement_id, candidate.chain_id, chain_repository, jobs)
                refreshed = refresh_sketch_chain_from_job(
                    engagement_id,
                    candidate.chain_id,
                    repository=chain_repository,
                    job_repository=jobs,
                    requested_by=requested_by,
                )
                if not refreshed or refreshed.get("sketchChain", {}).get("status") != "deployed":
                    raise SketchChainValidationError(["replacement edge bootstrap did not complete"])
            _finish_edge_transition_job(jobs, parent.id, status="succeeded", message="retained-middle edge transition completed", data={"providerJobId": latest_provider.id})
        except Exception as exc:
            current = chain_repository.get(engagement_id, chain.chain_id) or chain
            if current.status == "reconciling":
                chain_repository.save(replace(current, status="failed", updated_at=_now()))
            errors = exc.errors if isinstance(exc, SketchChainValidationError) else [type(exc).__name__]
            _finish_edge_transition_job(jobs, parent.id, status="failed", message="retained-middle edge transition failed", data={"errors": errors})

    start_runtime_task(run, name=f"barragan-sketch-edge-transition-{chain.chain_id}", synchronous_when_testing=True)
    latest_parent = jobs.get(parent.id) or parent
    latest_chain = chain_repository.get(engagement_id, chain.chain_id) or updated
    return {"chain": latest_chain.to_dict(), "job": latest_parent.to_detail().to_dict()}


def _edge_transition_provider_body(
    chain: StoredSketchChain,
    desired_edges: list[dict[str, str]],
    expected_edge_action: str,
    requested_by: str,
) -> dict[str, Any]:
    edge_regions, edge_count_per_region = _edge_batch_plan(desired_edges)
    # Terraform's count indices are zero-based.  A retirement's desired list
    # is already one entry shorter, so its removed ordinal is ``len``; an
    # append creates the final desired ordinal, ``len - 1``.
    edge_index = len(desired_edges) if expected_edge_action == "delete" else len(desired_edges) - 1
    address_prefix = "linode_instance.edge" if chain.middle_provider == "linode" else "digitalocean_droplet.edge"
    confirmation = LINODE_SKETCH_CONFIRMATION if chain.middle_provider == "linode" else DIGITALOCEAN_SKETCH_CONFIRMATION
    return {
        "confirmMutation": confirmation,
        "engagementId": chain.engagement_id,
        "chainId": chain.chain_id,
        "assignedProxy": chain.assigned_proxy,
        "middleRegion": chain.middle_region,
        "middleSize": chain.middle_size,
        "edgeRegion": desired_edges[0]["region"],
        "edgeSize": desired_edges[0]["size"],
        "edgeCount": len(desired_edges),
        "edges": desired_edges,
        "edgeRegions": edge_regions,
        "edgeCountPerRegion": edge_count_per_region,
        "terraformWorkingDirectory": chain.terraform_working_directory,
        "middleOrdinal": 1,
        "expectedEdgeAddress": f"{address_prefix}[{edge_index}]",
        "expectedEdgeAction": expected_edge_action,
        "edgeTransition": "retire" if expected_edge_action == "delete" else "replace",
        "requestedBy": requested_by,
    }


def _start_same_provider_edge_reconcile(chain: StoredSketchChain, body: dict[str, Any], repository: JobRepository):
    if chain.middle_provider == "linode":
        return start_guarded_linode_sketch_reconcile(body, repository=repository, background_runner=lambda task: task())
    if chain.middle_provider == "digitalocean":
        return start_guarded_digitalocean_sketch_reconcile(body, repository=repository, background_runner=lambda task: task())
    raise SketchChainValidationError(["same-provider edge reconcile supports Linode or DigitalOcean only"])


def _append_edge_transition_event(repository: JobRepository, job_id: str, message: str, data: dict[str, Any]) -> None:
    current = repository.get(job_id)
    if current is not None and current.status == "running":
        repository.save(replace(current, events=current.events + [JobEvent(len(current.events) + 1, "info", message, data)]))


def _finish_edge_transition_job(repository: JobRepository, job_id: str, *, status: str, message: str, data: dict[str, Any]) -> None:
    current = repository.get(job_id)
    if current is not None:
        repository.save(
            replace(
                current,
                status=status,
                finished_at=_now(),
                events=current.events + [JobEvent(len(current.events) + 1, "info" if status == "succeeded" else "error", message, data)],
            )
        )


def ensure_sketch_chain_teardown(
    engagement_id: str,
    chain_id: str,
    body: dict[str, Any],
    repository: SketchChainRepository | None = None,
    job_repository: JobRepository | None = None,
    *,
    core_mutation_lease_owner: str = "",
) -> dict[str, Any] | None:
    """Start or resume the one recorded teardown child for a Barragan-owned chain."""

    _require_split_v1_sketch_dispatch(engagement_id)
    _assert_core_mutation_allowed(
        engagement_id,
        repository,
        authorized_teardown_owner=core_mutation_lease_owner,
    )
    repo = _repo(repository)
    jobs = job_repository or SqlAlchemyJobRepository()
    chain = repo.get(engagement_id, chain_id)
    if chain is None:
        return None
    if chain.deploy_job_id:
        _require_bootstrap_reconciled(jobs.get(chain.deploy_job_id), teardown=True)
    if chain.status == "pending" and not chain.deploy_job_id and not chain.nodes:
        expected = f"teardown-{chain.chain_id}"
        if body.get("confirmation") != expected:
            raise SketchChainValidationError([f'confirmation must equal "{expected}"'])
        canceled = repo.save(replace(chain, status="aborted", updated_at=_now()))
        return {"chain": canceled.to_dict(), "job": None}
    if chain.status in TERMINAL_INACTIVE_SKETCH_CHAIN_STATUSES:
        child = jobs.get(chain.teardown_job_id) if chain.teardown_job_id else None
        return {"chain": chain.to_dict(), "job": child.to_detail().to_dict() if child else None}

    if chain.teardown_job_id:
        child = jobs.get(chain.teardown_job_id)
        if child is not None and child.status == "succeeded":
            refreshed = refresh_sketch_chain_from_job(engagement_id, chain_id, repository=repo) or chain.to_dict()
            return {"chain": refreshed, "job": child.to_detail().to_dict()}
        if child is not None and child.status in {"queued", "running"}:
            return {"chain": chain.to_dict(), "job": child.to_detail().to_dict()}
        if child is not None and child.status == "failed" and chain.status in {"tearing_down", "failed"}:
            provider_tasks: list[Callable[[], None]] = []

            def resume() -> None:
                resumed = (
                    resume_guarded_linode_sketch_teardown(child.id, repository=jobs)
                    or resume_guarded_digitalocean_sketch_teardown(child.id, repository=jobs)
                    or resume_guarded_mixed_sketch_teardown(child.id, repository=jobs)
                )
                if resumed is None:
                    raise SketchChainValidationError(["recorded teardown child cannot be resumed"])

            provider_tasks.append(resume)
            updated = repo.save(replace(chain, status="tearing_down", updated_at=_now()))
            _start_sketch_teardown_sequence(
                engagement_id,
                updated,
                child.id,
                provider_tasks,
                requested_by=_requested_by(body),
                chain_repository=repo,
                outbound_already_removed=body.get("outboundAlreadyRemoved") is True,
            )
            latest = jobs.get(child.id) or child
            return {"chain": updated.to_dict(), "job": latest.to_detail().to_dict()}

    return teardown_sketch_chain(
        engagement_id,
        chain_id,
        body,
        repository=repo,
        core_mutation_lease_owner=core_mutation_lease_owner,
    )


def remove_sketch_chain_outbound_configuration(
    engagement_id: str,
    chain_id: str,
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
) -> dict[str, Any] | None:
    """Strict, idempotent outbound-only phase used before any provider destroy."""

    return _remove_outbound_channel_for_teardown(
        engagement_id,
        chain_id,
        requested_by=requested_by,
        repository=repository,
    )


def _start_sketch_teardown_sequence(
    engagement_id: str,
    chain: StoredSketchChain,
    teardown_job_id: str,
    provider_tasks: list[Callable[[], None]],
    *,
    requested_by: str,
    chain_repository: SketchChainRepository,
    outbound_already_removed: bool = False,
) -> None:
    def run() -> None:
        try:
            if not outbound_already_removed:
                _append_sketch_teardown_progress(
                    teardown_job_id,
                    "outbound channel removal started",
                    {"chainId": chain.chain_id, "phase": "outbound_channel"},
                )
                outbound_result = _remove_outbound_channel_for_teardown(
                    engagement_id,
                    chain.chain_id,
                    requested_by=requested_by,
                )
                _append_sketch_teardown_progress(
                    teardown_job_id,
                    "outbound channel removal completed",
                    {
                        "chainId": chain.chain_id,
                        "phase": "outbound_channel",
                        "outboundJobId": str((outbound_result or {}).get("job", {}).get("id") or ""),
                    },
                )
            _append_sketch_teardown_progress(
                teardown_job_id,
                "provider infrastructure destroy started",
                {"chainId": chain.chain_id, "phase": "provider_destroy"},
            )
            for provider_task in provider_tasks:
                provider_task()
            refresh_sketch_chain_from_job(
                engagement_id,
                chain.chain_id,
                repository=chain_repository,
                job_repository=SqlAlchemyJobRepository(),
                start_outbound_continuation=False,
                requested_by=requested_by,
            )
        except Exception as exc:
            _record_sketch_teardown_failure(
                teardown_job_id,
                chain,
                exc,
                chain_repository=chain_repository,
            )

    start_runtime_task(
        run,
        name=f"barragan-sketch-teardown-{chain.chain_id}",
        synchronous_when_testing=True,
    )


def _append_sketch_teardown_progress(teardown_job_id: str, message: str, data: dict[str, Any]) -> None:
    repository = SqlAlchemyJobRepository()
    job = repository.get(teardown_job_id)
    if job is None:
        return
    repository.save(
        replace(
            job,
            events=job.events + [JobEvent(len(job.events) + 1, "info", message, data)],
        )
    )


def _record_sketch_teardown_failure(
    teardown_job_id: str,
    chain: StoredSketchChain,
    error: Exception,
    *,
    chain_repository: SketchChainRepository,
) -> None:
    job_repository = SqlAlchemyJobRepository()
    job = job_repository.get(teardown_job_id)
    if job is not None:
        detail = "; ".join(error.errors) if isinstance(error, SketchChainValidationError) else type(error).__name__
        job_repository.save(
            replace(
                job,
                status="failed",
                finished_at=_now(),
                events=job.events
                + [
                    JobEvent(
                        len(job.events) + 1,
                        "error",
                        "sketch teardown failed before provider destroy",
                        {"chainId": chain.chain_id, "detail": detail},
                    )
                ],
            )
        )
    chain_repository.save(replace(chain, status="failed", teardown_job_id=teardown_job_id, updated_at=_now()))


def stop_sketch_chain(
    engagement_id: str,
    chain_id: str,
    body: dict[str, Any],
    repository: SketchChainRepository | None = None,
) -> dict[str, Any] | None:
    return _power_sketch_chain(engagement_id, chain_id, body, action="stop", repository=repository)


def start_sketch_chain(
    engagement_id: str,
    chain_id: str,
    body: dict[str, Any],
    repository: SketchChainRepository | None = None,
) -> dict[str, Any] | None:
    return _power_sketch_chain(engagement_id, chain_id, body, action="start", repository=repository)


def _power_sketch_chain(
    engagement_id: str,
    chain_id: str,
    body: dict[str, Any],
    *,
    action: str,
    repository: SketchChainRepository | None = None,
) -> dict[str, Any] | None:
    _assert_core_mutation_allowed(engagement_id, repository)
    repo = _repo(repository)
    chain = repo.get(engagement_id, chain_id)
    if chain is None:
        return None
    expected = f"{action}-{chain.chain_id}"
    if body.get("confirmation") != expected:
        raise SketchChainValidationError([f'confirmation must equal "{expected}"'])
    if action == "stop" and chain.status != "deployed":
        raise SketchChainValidationError([f"chain {chain.chain_id} is {chain.status} and cannot be stopped"])
    if action == "start" and chain.status != "stopped":
        raise SketchChainValidationError([f"chain {chain.chain_id} is {chain.status} and cannot be started"])
    try:
        job = run_sketch_power_job(chain, action=action, requested_by=str(body.get("requestedBy") or "operator"))
    except SketchPowerValidationError as exc:
        raise SketchChainValidationError(exc.errors) from exc
    succeeded = job.status == "succeeded"
    status = "stopped" if action == "stop" and succeeded else "deployed" if action == "start" and succeeded else "failed"
    updated = repo.save(
        replace(
            chain,
            status=status,
            nodes=[{**node, "status": status} for node in chain.nodes],
            updated_at=_now(),
        )
    )
    return {"chain": updated.to_dict(), "job": job.to_dict()}


def _repo(repository: SketchChainRepository | None) -> SketchChainRepository:
    return repository or SqlAlchemySketchChainRepository()


def _assert_core_mutation_allowed(
    engagement_id: str,
    repository: SketchChainRepository | None,
    *,
    authorized_teardown_owner: str = "",
) -> None:
    # In-memory repositories are isolated unit-test/service collaborators and
    # do not share the durable SQL mutation fence. All production calls use
    # the SQL repository (implicitly or explicitly).
    if repository is not None and not isinstance(repository, SqlAlchemySketchChainRepository):
        return
    from app.storage.models import CoreMutationLeaseModel

    lease = CoreMutationLeaseModel.query.get(engagement_id)
    if (
        lease is not None
        and authorized_teardown_owner
        and lease.owner_id == authorized_teardown_owner
        and lease.operation == "teardown"
    ):
        return
    if lease is not None:
        raise SketchChainValidationError(
            [f"core infrastructure {lease.operation} is in progress; sketch chain mutations are temporarily locked"]
        )


def _start_outbound_auto_configuration(
    engagement_id: str,
    chain_id: str,
    *,
    deploy_job_id: str,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
) -> StoredJobRun | None:
    repo = repository or SqlAlchemyJobRepository()
    should_start = False
    claim_token = ""
    parent_id = f"job-outbound-auto-{deploy_job_id.removeprefix('job-')}-{chain_id}"
    with _outbound_auto_configuration_lock:
        existing = repo.get(parent_id)
        if existing is None:
            channel_ids = _latest_outbound_channel_ids_for_chain(repo, engagement_id, chain_id)
            if not channel_ids:
                return None
            timestamp = _now()
            parent = repo.save_if_absent(
                StoredJobRun(
                    id=parent_id,
                    action=OUTBOUND_AUTO_CONFIGURATION_ACTION,
                    status="queued",
                    target=f"engagement:{engagement_id}",
                    target_type="engagement",
                    target_id=engagement_id,
                    requested_by=requested_by,
                    input={
                        "engagementId": engagement_id,
                        "chainId": chain_id,
                        "deployJobId": deploy_job_id,
                        "channelIds": channel_ids,
                        "configurationState": "Waiting",
                        "mutation": True,
                    },
                    artifact_refs=[],
                    created_at=timestamp,
                    started_at=None,
                    finished_at=None,
                    events=[
                        JobEvent(
                            1,
                            "info",
                            "outbound auto-configuration waiting",
                            {"state": "Waiting", "chainId": chain_id, "channelIds": channel_ids},
                        )
                    ],
                )
            )
        else:
            parent = existing

        # The deterministic row is the durable identity; the atomic lease is
        # the cross-process single-flight gate and is reclaimable after expiry.
        if parent.status in {"queued", "running"} and parent.id not in _outbound_auto_configuration_active:
            claimed_at = _now()
            claim_token = uuid4().hex
            expires_at = (
                datetime.fromisoformat(claimed_at) + timedelta(seconds=OUTBOUND_AUTO_LEASE_SECONDS)
            ).isoformat()
            claimed = repo.claim_lease(
                parent.id,
                owner=_outbound_auto_configuration_owner,
                token=claim_token,
                claimed_at=claimed_at,
                expires_at=expires_at,
                eligible_statuses={"queued", "running"},
            )
            if claimed is not None:
                parent = claimed
                _outbound_auto_configuration_active.add(parent.id)
                should_start = True

    if should_start:
        try:
            start_runtime_task(
                lambda: _run_outbound_auto_configuration(
                    parent.id,
                    claim_token=claim_token,
                    repository=repo,
                ),
                name=f"barragan-outbound-auto-{chain_id}",
                synchronous_when_testing=True,
            )
        except Exception:
            with _outbound_auto_configuration_lock:
                _outbound_auto_configuration_active.discard(parent.id)
            raise
    return repo.get(parent.id)


def _run_outbound_auto_configuration(
    parent_job_id: str,
    *,
    claim_token: str,
    repository: JobRepository,
) -> None:
    parent = repository.get(parent_job_id)
    if (
        parent is None
        or parent.status not in {"queued", "running"}
        or parent.input.get("claimOwner") != _outbound_auto_configuration_owner
        or parent.input.get("claimToken") != claim_token
    ):
        with _outbound_auto_configuration_lock:
            _outbound_auto_configuration_active.discard(parent_job_id)
        return
    parent = _renew_outbound_auto_lease(repository, parent_job_id, claim_token)
    if parent is None:
        return
    channel_ids = [str(value) for value in parent.input.get("channelIds", []) if str(value).strip()]
    parent = _save_outbound_auto_if_owned(
        repository,
        replace(
            parent,
            status="running",
            started_at=parent.started_at or _now(),
            input={**parent.input, "configurationState": "Configuring", "claimHeartbeatAt": _now()},
            events=parent.events
            + [
                JobEvent(
                    len(parent.events) + 1,
                    "info",
                    "outbound auto-configuration started",
                    {"state": "Configuring", "channelCount": len(channel_ids)},
                )
            ],
        ),
        claim_token,
    )
    if parent is None:
        return
    try:
        for channel_id in channel_ids:
            parent = _append_outbound_auto_event(
                repository,
                parent,
                claim_token,
                "outbound profile configuration started",
                {"state": "Configuring", "channelId": channel_id},
            )
            if parent is None:
                return
            status = _latest_outbound_channel_status(repository, parent.target_id, channel_id)
            if status in {"Validated", "Validated with warnings"}:
                parent = _append_outbound_auto_event(
                    repository,
                    parent,
                    claim_token,
                    "outbound profile already ready",
                    {"state": "Ready", "channelId": channel_id},
                )
                if parent is None:
                    return
                continue
            apply_result = None
            if status != "Pending Validation":
                with _outbound_auto_lease_heartbeat(repository, parent_job_id, claim_token):
                    apply_result = apply_outbound_channel(
                        parent.target_id,
                        channel_id,
                        confirmation=f"apply-outbound-{channel_id}",
                        requested_by=parent.requested_by,
                        repository=repository,
                    )
                if apply_result is None or apply_result.get("status") != "Pending Validation":
                    raise OutboundChannelApplyValidationError([f"outbound profile {channel_id} apply did not complete"])
                parent = _renew_outbound_auto_lease(repository, parent_job_id, claim_token)
                if parent is None:
                    return
            with _outbound_auto_lease_heartbeat(repository, parent_job_id, claim_token):
                validation_result = validate_outbound_channel(
                    parent.target_id,
                    channel_id,
                    confirmation=f"validate-outbound-{channel_id}",
                    requested_by=parent.requested_by,
                    repository=repository,
                )
            if validation_result is None or validation_result.get("status") not in {"Validated", "Validated with warnings"}:
                raise OutboundChannelApplyValidationError([f"outbound profile {channel_id} validation did not succeed"])
            parent = _renew_outbound_auto_lease(repository, parent_job_id, claim_token)
            if parent is None:
                return
            parent = _append_outbound_auto_event(
                repository,
                parent,
                claim_token,
                "outbound profile ready",
                {
                    "state": "Ready",
                    "channelId": channel_id,
                    "applyJobId": str((apply_result or {}).get("job", {}).get("id") or ""),
                    "validationJobId": str(validation_result.get("job", {}).get("id") or ""),
                },
            )
            if parent is None:
                return
        latest = _renew_outbound_auto_lease(repository, parent_job_id, claim_token)
        if latest is None:
            return
        _save_outbound_auto_if_owned(
            repository,
            replace(
                latest,
                status="succeeded",
                finished_at=_now(),
                input={**latest.input, "configurationState": "Ready", "claimHeartbeatAt": _now()},
                events=latest.events
                + [
                    JobEvent(
                        len(parent.events) + 1,
                        "info",
                        "outbound auto-configuration completed",
                        {"state": "Ready", "channelIds": channel_ids},
                    )
                ],
            ),
            claim_token,
        )
    except Exception as exc:
        errors = exc.errors if isinstance(exc, OutboundChannelApplyValidationError) else [type(exc).__name__]
        latest = _renew_outbound_auto_lease(repository, parent_job_id, claim_token)
        if latest is None:
            return
        _save_outbound_auto_if_owned(
            repository,
            replace(
                latest,
                status="failed",
                finished_at=_now(),
                input={**latest.input, "configurationState": "Failed", "claimHeartbeatAt": _now()},
                events=latest.events
                + [
                    JobEvent(
                        len(latest.events) + 1,
                        "error",
                        "outbound auto-configuration failed",
                        {"state": "Failed", "errors": errors},
                    )
                ],
            ),
            claim_token,
        )
    finally:
        with _outbound_auto_configuration_lock:
            _outbound_auto_configuration_active.discard(parent_job_id)


def _append_outbound_auto_event(
    repository: JobRepository,
    parent: StoredJobRun,
    claim_token: str,
    message: str,
    data: dict[str, Any],
) -> StoredJobRun | None:
    latest = _renew_outbound_auto_lease(repository, parent.id, claim_token)
    if latest is None:
        return None
    return _save_outbound_auto_if_owned(
        repository,
        replace(
            latest,
            input={**latest.input, "claimHeartbeatAt": _now()},
            events=latest.events + [JobEvent(len(latest.events) + 1, "info", message, data)],
        ),
        claim_token,
    )


def _renew_outbound_auto_lease(
    repository: JobRepository,
    parent_job_id: str,
    claim_token: str,
) -> StoredJobRun | None:
    heartbeat_at = _now()
    expires_at = (
        datetime.fromisoformat(heartbeat_at) + timedelta(seconds=OUTBOUND_AUTO_LEASE_SECONDS)
    ).isoformat()
    return repository.renew_lease(
        parent_job_id,
        owner=_outbound_auto_configuration_owner,
        token=claim_token,
        heartbeat_at=heartbeat_at,
        expires_at=expires_at,
    )


def _save_outbound_auto_if_owned(
    repository: JobRepository,
    parent: StoredJobRun,
    claim_token: str,
) -> StoredJobRun | None:
    return repository.save_if_leased(
        parent,
        owner=_outbound_auto_configuration_owner,
        token=claim_token,
    )


@contextmanager
def _outbound_auto_lease_heartbeat(
    repository: JobRepository,
    parent_job_id: str,
    claim_token: str,
):
    """Keep ownership live while a child mutation blocks for several minutes."""

    stop = threading.Event()
    try:
        state = current_runtime()
    except RuntimeError:
        state = None

    def heartbeat() -> None:
        while not stop.wait(OUTBOUND_AUTO_HEARTBEAT_SECONDS):
            if state is None:
                renewed = _renew_outbound_auto_lease(repository, parent_job_id, claim_token)
            else:
                with runtime_context(state):
                    renewed = _renew_outbound_auto_lease(repository, parent_job_id, claim_token)
            if renewed is None:
                return

    worker = threading.Thread(
        target=heartbeat,
        name=f"barragan-outbound-lease-{parent_job_id}",
        daemon=True,
    )
    worker.start()
    try:
        yield
    finally:
        stop.set()
        worker.join(timeout=1)


def _auto_configure_outbound_channel_if_ready(
    engagement_id: str,
    chain_id: str,
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
) -> dict[str, Any]:
    repo = repository or SqlAlchemyJobRepository()
    channel_ids = _latest_outbound_channel_ids_for_chain(repo, engagement_id, chain_id) or [chain_id]
    apply_results: list[dict[str, Any]] = []
    validation_results: list[dict[str, Any]] = []
    try:
        for channel_id in channel_ids:
            status = _latest_outbound_channel_status(repo, engagement_id, channel_id)
            # The apply route records Pending Validation before its synchronous
            # validation begins. Concurrent workspace reads must not treat that
            # brief state as permission to launch duplicate apply/validation jobs.
            if status in {
                "Pending Validation",
                "Validated",
                "Validated with warnings",
                "Validation Failed",
                "Removed",
            }:
                continue
            apply_result = apply_outbound_channel(
                engagement_id,
                channel_id,
                confirmation=f"apply-outbound-{channel_id}",
                requested_by=requested_by,
                repository=repo,
            )
            if apply_result is None:
                continue
            apply_results.append(apply_result)
            if apply_result.get("status") != "Pending Validation":
                continue
            validate_result = validate_outbound_channel(
                engagement_id,
                channel_id,
                confirmation=f"validate-outbound-{channel_id}",
                requested_by=requested_by,
                repository=repo,
            )
            if validate_result is not None:
                validation_results.append(validate_result)
    except OutboundChannelApplyValidationError as exc:
        if any("with rendered artifacts was not found" in error for error in exc.errors):
            return {}
        return {
            "outboundApply": {
                "status": "Auto Configuration Failed",
                "errors": exc.errors,
            }
        }
    result: dict[str, Any] = {}
    if apply_results:
        result["outboundApply"] = apply_results[0]
        result["outboundApplies"] = apply_results
    if validation_results:
        result["outboundValidation"] = validation_results[0]
        result["outboundValidations"] = validation_results
    return result


def _remove_outbound_channel_for_teardown(
    engagement_id: str,
    chain_id: str,
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
) -> dict[str, Any] | None:
    repo = repository or SqlAlchemyJobRepository()
    results: list[dict[str, Any]] = []
    for channel_id in _latest_outbound_channel_ids_for_chain(repo, engagement_id, chain_id) or [chain_id]:
        status = _latest_outbound_channel_status(repo, engagement_id, channel_id)
        if status == "Removed":
            continue
        try:
            result = remove_outbound_channel(
                engagement_id,
                channel_id,
                requested_by=requested_by,
                repository=repo,
                require_confirmation=False,
            )
        except OutboundChannelApplyValidationError as exc:
            if any("with rendered artifacts was not found" in error for error in exc.errors):
                continue
            raise SketchChainValidationError(exc.errors) from exc
        if result is not None and result.get("status") != "Removed":
            raise SketchChainValidationError([f"outbound channel {channel_id} could not be removed before sketch teardown"])
        if result is not None:
            results.append(result)
    if not results:
        return None
    return results[0] if len(results) == 1 else {"status": "Removed", "outboundRemovals": results}


def _latest_outbound_channel_ids_for_chain(repository: JobRepository, engagement_id: str, chain_id: str) -> list[str]:
    list_for_engagement = getattr(repository, "list_for_engagement", None)
    jobs = list_for_engagement(engagement_id) if callable(list_for_engagement) else repository.list()
    channel_ids: list[str] = []
    for job in jobs:
        if str(job.input.get("engagementId") or job.target_id or "") != engagement_id:
            continue
        for event in reversed(job.events):
            channels = event.data.get("outboundChannels")
            if not isinstance(channels, list):
                continue
            for channel in channels:
                if not isinstance(channel, dict):
                    continue
                if str(channel.get("chainId") or "") != chain_id:
                    continue
                channel_id = str(channel.get("channelId") or "").strip()
                if channel_id and channel_id not in channel_ids:
                    channel_ids.append(channel_id)
            if channel_ids:
                return channel_ids
    return channel_ids


def _latest_outbound_channel_status(repository: JobRepository, engagement_id: str, channel_id: str) -> str:
    list_for_engagement = getattr(repository, "list_for_engagement", None)
    jobs = list_for_engagement(engagement_id) if callable(list_for_engagement) else repository.list()
    for job in jobs:
        if str(job.input.get("engagementId") or job.target_id or "") != engagement_id:
            continue
        for event in reversed(job.events):
            channels = event.data.get("outboundChannels")
            if not isinstance(channels, list):
                continue
            for channel in channels:
                if not isinstance(channel, dict):
                    continue
                if channel_id in {
                    str(channel.get("channelId") or "").strip(),
                    str(channel.get("chainId") or "").strip(),
                }:
                    return str(channel.get("status") or "").strip()
    return ""


def _requested_by(body: dict[str, Any]) -> str:
    return _text(body.get("requestedBy")) or "operator"


def _max_non_destroyed_sketch_chains() -> int:
    raw = os.environ.get("BARRAGAN_MAX_SKETCH_CHAINS_PER_ENGAGEMENT", "")
    if not raw:
        return DEFAULT_MAX_NON_DESTROYED_SKETCH_CHAINS
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_NON_DESTROYED_SKETCH_CHAINS
    return max(1, value)


def _allocate_chain_id(existing: list[StoredSketchChain], assigned_proxy: str, edge_region: str) -> str:
    prefix = f"{assigned_proxy}-{_region_code(edge_region)}"
    used = {chain.chain_id for chain in existing}
    counters = []
    for chain in existing:
        match = re.fullmatch(rf"{re.escape(prefix)}-(\d+)", chain.chain_id)
        if match:
            counters.append(int(match.group(1)))
    counter = (max(counters) if counters else 0) + 1
    candidate = f"{prefix}-{counter:02d}"
    while candidate in used:
        counter += 1
        candidate = f"{prefix}-{counter:02d}"
    return candidate


def _template_chain_intent(engagement_id: str, body: dict[str, Any]) -> StoredSketchChain:
    middle_provider = _provider(body, "middleProvider")
    middle_region = _required_text(body, "middleRegion")
    edges = _normalize_edges(body)
    edge_provider, edge_region = edges[0]["provider"], edges[0]["region"]
    _validate_allowed_regions(middle_provider, middle_region, edge_provider, edge_region)
    now = _now()
    return StoredSketchChain(
        chain_id="",
        engagement_id=engagement_id,
        assigned_proxy=_required_proxy(body.get("assignedProxy") or body.get("proxy") or "proxy01"),
        middle_provider=middle_provider,
        middle_region=middle_region,
        middle_size=_text(body.get("middleSize")) or "g6-nanode-1",
        edge_provider=edge_provider,
        edge_region=edge_region,
        edge_size=edges[0]["size"],
        edge_count=len(edges),
        edge_intents=edges,
        status="pending",
        burned=False,
        burned_note="",
        deploy_job_id="",
        teardown_job_id="",
        terraform_working_directory="",
        nodes=[],
        created_at=now,
        updated_at=now,
    )


def _same_template_chain_intent(chain: StoredSketchChain, intent: StoredSketchChain) -> bool:
    return (
        chain.assigned_proxy == intent.assigned_proxy
        and chain.middle_provider == intent.middle_provider
        and chain.middle_region == intent.middle_region
        and chain.middle_size == intent.middle_size
        and chain.edge_provider == intent.edge_provider
        and chain.edge_region == intent.edge_region
        and chain.edge_size == intent.edge_size
        and chain.edge_count == intent.edge_count
        and (chain.edge_intents or []) == (intent.edge_intents or [])
    )


def _region_code(region: str) -> str:
    value = _text(region).lower()
    if not value:
        return "region"
    parts = [part for part in re.split(r"[^a-z0-9]+", value) if part]
    if not parts:
        return "region"
    if parts[-1].isdigit() and len(parts) >= 2:
        return parts[-2]
    return parts[-1]


def _required_proxy(value: Any) -> str:
    proxy = _text(value)
    if not PROXY_PATTERN.fullmatch(proxy):
        raise SketchChainValidationError(["assignedProxy must look like proxy01"])
    return proxy


def _required_text(body: dict[str, Any], key: str) -> str:
    value = _text(body.get(key))
    if not value:
        raise SketchChainValidationError([f"{key} is required"])
    return value


def _provider(body: dict[str, Any], key: str) -> str:
    return _provider_from_text(body.get(key), key)


def _provider_from_text(value: Any, key: str) -> str:
    value = _text(value) or "linode"
    if value not in {"linode", "digitalocean"}:
        raise SketchChainValidationError([f"{key} must be linode or digitalocean"])
    return value


def _validate_allowed_regions(
    middle_provider: str,
    middle_region: str,
    edge_provider: str,
    edge_region: str,
    *,
    use_runtime_region_policy: bool = True,
) -> None:
    errors = []
    for label, provider, region in (
        ("middle", middle_provider, middle_region),
        ("edge", edge_provider, edge_region),
    ):
        allowed = (
            is_provider_region_allowed(provider, region)
            if use_runtime_region_policy
            else region in set(DEFAULT_ALLOWED_REGIONS.get(provider, []))
        )
        if not allowed:
            errors.append(
                f"{label} region {provider}/{region} is not allowed by sketch provider region policy"
            )
    if errors:
        raise SketchChainValidationError(errors)


def _status_from_job(status: str, *, running: str, success: str) -> str:
    if status in {"queued", "running"}:
        return running
    if status == "succeeded":
        return success
    if status == "failed":
        return "failed"
    return status if status in SKETCH_CHAIN_STATUSES else "failed"


def _nodes_from_job(job, chain: StoredSketchChain) -> list[dict[str, Any]]:
    for event in reversed(job.events):
        rows = event.data.get("sketchInfrastructure")
        if isinstance(rows, list):
            normalized = []
            for row in rows:
                if isinstance(row, dict):
                    normalized.append(
                        {
                            **row,
                            "chainId": chain.chain_id,
                            "assignedProxy": chain.assigned_proxy,
                            "proxy": chain.assigned_proxy,
                            "burned": chain.burned,
                            "burnedNote": chain.burned_note,
                        }
                    )
            return normalized
    return []


def _job_input(job, key: str) -> str:
    value = job.input.get(key)
    return str(value) if value else ""


def _text(value: Any) -> str:
    return str(value or "").strip()


def _edge_count(value: Any) -> int:
    try:
        edge_count = 1 if value in (None, "") else int(value)
    except (TypeError, ValueError) as exc:
        raise SketchChainValidationError(["edgeCount must be an integer from 1 to 10"]) from exc
    if edge_count < 1 or edge_count > 10:
        raise SketchChainValidationError(["edgeCount must be an integer from 1 to 10"])
    return edge_count


def _sketch_chain_ordinal(chains: list[StoredSketchChain], chain_id: str) -> int:
    """Stable engagement-local middle ordinal, based on persisted creation order."""
    for index, candidate in enumerate(chains, start=1):
        if candidate.chain_id == chain_id:
            return index
    return 1


def _normalize_edges(body: dict[str, Any]) -> list[dict[str, str]]:
    raw_edges = body.get("edges")
    if raw_edges is None:
        count = _edge_count(body.get("edgeCount"))
        provider = _provider(body, "edgeProvider")
        region = _required_text(body, "edgeRegion")
        size = _text(body.get("edgeSize")) or "g6-nanode-1"
        return [
            {"id": f"edge-{index:02d}", "provider": provider, "region": region, "size": size}
            for index in range(1, count + 1)
        ]
    if not isinstance(raw_edges, list) or not raw_edges or len(raw_edges) > 10:
        raise SketchChainValidationError(["edges must contain 1 to 10 edge intents"])
    normalized: list[dict[str, str]] = []
    for index, edge in enumerate(raw_edges, start=1):
        if not isinstance(edge, dict):
            raise SketchChainValidationError([f"edges[{index - 1}] must be an object"])
        expected_id = f"edge-{index:02d}"
        if _text(edge.get("id")) != expected_id:
            raise SketchChainValidationError([f"edges[{index - 1}].id must equal {expected_id}"])
        provider = _provider(edge, "provider")
        region = _required_text(edge, "region")
        size = _text(edge.get("size"))
        if not size:
            raise SketchChainValidationError([f"edges[{index - 1}].size is required"])
        if not is_provider_region_allowed(provider, region):
            raise SketchChainValidationError([f"edge region {provider}/{region} is not allowed by sketch provider region policy"])
        normalized.append({"id": expected_id, "provider": provider, "region": region, "size": size})
    return normalized


def _legacy_edges(chain: StoredSketchChain) -> list[dict[str, str]]:
    return [
        {"id": f"edge-{index:02d}", "provider": chain.edge_provider, "region": chain.edge_region, "size": chain.edge_size}
        for index in range(1, chain.edge_count + 1)
    ]


def _edge_batch_plan(edges: list[dict[str, Any]]) -> tuple[list[str], int]:
    """Return first-seen regions and their shared upstream count."""
    regions: list[str] = []
    counts: dict[str, int] = {}
    for edge in edges:
        region = str(edge["region"])
        if region not in counts:
            regions.append(region)
            counts[region] = 0
        counts[region] += 1
    return regions, next(iter(counts.values()))


def _validate_uniform_edge_plan(
    middle_provider: str,
    middle_region: str,
    edges: list[dict[str, Any]],
    *,
    use_runtime_region_policy: bool = True,
) -> None:
    if not edges:
        raise SketchChainValidationError(["edges must contain 1 to 10 edge intents"])
    for edge in edges:
        provider = str(edge["provider"])
        if provider not in {"linode", "digitalocean"}:
            raise SketchChainValidationError(["edgeProvider must be linode or digitalocean"])
        _validate_allowed_regions(
            middle_provider, middle_region, provider, str(edge["region"]), use_runtime_region_policy=use_runtime_region_policy
        )


def _requires_individual_edge_components(edges: list[dict[str, Any]]) -> bool:
    """Whether the legacy batched provider module cannot represent this edge list."""

    if len({str(edge["provider"]) for edge in edges}) > 1:
        return True
    if len({str(edge["size"]) for edge in edges}) > 1:
        return True
    _regions, count_per_region = _edge_batch_plan(edges)
    return any(sum(1 for edge in edges if edge["region"] == region) != count_per_region for region in _regions)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
