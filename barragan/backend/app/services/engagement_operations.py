# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
from typing import Any
from uuid import uuid4

from app.domain import JobEvent
from app.services.outbound_channel_artifacts import derive_pending_outbound_channels_from_sketch_rows
from app.services import provider_reconciliation
from app.services.engagement_teardown import comprehensive_teardown_recovery_state
from app.services.engagement_lifecycle import _job_after
from app.storage.engagement_repository import EngagementRepository, SqlAlchemyEngagementRepository
from app.storage.engagement_lifecycle_repository import (
    SqlAlchemyEngagementLifecycleRepository,
    StoredEngagementLifecycle,
)
from app.storage.inspection_run_repository import SqlAlchemyInspectionRunRepository, StoredInspectionRun
from app.storage.job_repository import (
    DashboardSemanticJobBatch,
    JobRepository,
    SemanticJobBatch,
    SqlAlchemyJobRepository,
    StoredJobRun,
)
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository, StoredProviderResourceRecord
from app.storage.service_repository import SqlAlchemyEngagementServiceRepository, StoredEngagementService
from app.services.generic_service import GENERIC_SERVICE_TYPE, generic_service_placement
from app.services.inbound_raw_route_plan import InboundRawRoutePlanError, raw_route_metadata
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository, StoredSketchChain

CORE_MANAGEMENT_SSH_USER = "user"
PROBE_STALE_AFTER = timedelta(minutes=20)
CHANNELS_UPDATE_ACTION = "engagement_channels_update"
OUTBOUND_AUTHORITATIVE_ACTIONS = {
    CHANNELS_UPDATE_ACTION,
    "outbound_channel_apply",
    "outbound_channel_validation",
}
OUTBOUND_CHANNEL_SCOPED_ACTIONS = {"outbound_channel_apply", "outbound_channel_validation"}
CORE_DEPLOYMENT_ACTIONS = {"pilot_standard_rti_guarded_execute"}
ENGAGEMENT_TEARDOWN_ACTION = "engagement_comprehensive_teardown"
MIXED_ZERO_APPLY_TEARDOWN_ACTION = "provider_keyed_mixed_zero_apply_cleanup"
MIXED_INTERRUPTED_TEARDOWN_ACTION = "provider_keyed_mixed_interrupted_cleanup"
MIXED_PUBLISHED_TEARDOWN_ACTION = "provider_keyed_mixed_published_cleanup"
MIXED_PUBLISHED_DISPATCH_CLAIM_ACTION = "provider_keyed_mixed_published_dispatch_claim"
SKETCH_DEPLOY_ACTIONS = {
    "linode_sketch_deploy",
    "digitalocean_sketch_deploy",
    "mixed_provider_sketch_deploy",
    "linode_sketch_reconcile",
    "digitalocean_sketch_reconcile",
}
LIVE_SKETCH_CHAIN_STATUSES = {"pending", "deploying", "reconciling", "deployed", "stopping", "stopped", "starting", "failed"}
OPERATIONS_TIMELINE_LIMIT = 250
OUTBOUND_VALIDATION_SCALAR_FIELDS = ("origin", "shellDisplay", "expectedPublicIp", "status", "checkedAt", "lastCheckedAt", "detail")
INBOUND_VALIDATION_SCALAR_FIELDS = (
    "profileType",
    "profileLabel",
    "validationScope",
    "externalIngressVerified",
    "externalIngressCheckedAt",
    "externalIngressDetail",
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
SUPPORTED_INBOUND_VALIDATION_PROFILE_TYPES = {"temporary-listener", "tcp-send-receive", "udp-send-receive", "tcp-connect", "http", "manual"}
INBOUND_CERTIFICATE_SCALAR_FIELDS = (
    "type",
    "managedBy",
    "status",
    "domain",
    "certName",
    "acmeEmail",
    "acmeEnvironment",
    "challengeType",
    "storageModel",
    "activationStatus",
    "cleanupRequired",
    "issuedAt",
    "expiresAt",
    "revokedAt",
    "renewedAt",
    "lastJobId",
    "lastAttemptStatus",
    "lastAttemptAt",
    "challengeChannelId",
    "detail",
)
INBOUND_CERTIFICATE_PATH_FIELDS = ("liveDir", "fullchain", "privkey", "cert", "chain")
INBOUND_CERTIFICATE_PREREQ_FIELDS = ("status", "summary", "checkedAt", "challengeType", "dnsZone", "domainAssetId")
INBOUND_CERTIFICATE_SUPPORT_FIELDS = ("role", "parentChannelId", "purpose", "dependency", "status")
APPLIED_INBOUND_CHANNEL_STATUSES = {"pending validation", "validated", "validation failed"}
INBOUND_ROUTE_SHAPE_FIELDS = (
    "protocol",
    "mode",
    "externalPort",
    "relayPort",
    "middleRelayPort",
    "proxyRelayPort",
    "edge",
    "edgeComponentId",
    "middle",
    "middleComponentId",
    "proxy",
    "terminatesOn",
    "service",
    "internalPort",
)
SECRETISH_KEY_PARTS = (
    "api_key",
    "apikey",
    "api-token",
    "apitoken",
    "credential",
    "password",
    "private_key",
    "privatekey",
    "provider_token",
    "providertoken",
    "secret",
    "token",
)
SECRETISH_VALUE_MARKERS = (
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "authorization:",
    "proxy-authorization:",
    "cookie:",
    "set-cookie:",
    "x-api-key",
    "x-api-token",
    "api-key:",
    "apikey:",
    "bearer ",
    "basic ",
    "password=",
    "passwd=",
    "token=",
    "secret=",
    "access_token",
    "refresh_token",
    "client_secret",
)
SECRETISH_VALUE_MARKERS_LOWER = tuple(marker.lower() for marker in SECRETISH_VALUE_MARKERS)
SECRETISH_VALUE_PATTERNS = (
    re.compile(r"\b(api[_ -]?key|private[_ -]?key|password|passwd|token|secret|access[_ -]?token|refresh[_ -]?token|client[_ -]?secret)\s*[:=]", re.IGNORECASE),
)


class EngagementOperationsValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("engagement operations validation failed")
        self.errors = errors


@dataclass(frozen=True)
class OperationsReadSnapshot:
    jobs: dict[str, list[StoredJobRun]]
    services: dict[str, list[StoredEngagementService]]
    sketch_chains: dict[str, list[StoredSketchChain]]
    provider_records: dict[str, list[StoredProviderResourceRecord]]
    all_provider_records: list[StoredProviderResourceRecord]
    lifecycles: dict[str, StoredEngagementLifecycle]
    total_job_count: int | None
    seed_job_exists: bool | None


def load_operations_read_snapshot(
    engagement_ids: list[str],
    job_repository: JobRepository,
    *,
    recent_limit: int = OPERATIONS_TIMELINE_LIMIT,
) -> OperationsReadSnapshot:
    """Batch durable Dashboard inputs into one request-local read snapshot."""
    ids = list(dict.fromkeys(value for value in engagement_ids if value))
    dashboard_semantic = getattr(job_repository, "list_dashboard_semantic_for_engagements", None)
    semantic = getattr(job_repository, "list_semantic_for_engagements", None)
    if callable(dashboard_semantic):
        batch: DashboardSemanticJobBatch = dashboard_semantic(ids, recent_limit=recent_limit)
        jobs = batch.jobs_by_engagement
        total_job_count = batch.total_job_count
        seed_job_exists = batch.seed_job_exists
    elif not callable(semantic):
        jobs = {engagement_id: _engagement_jobs(engagement_id, job_repository) for engagement_id in ids}
        total_job_count = None
        seed_job_exists = None
    else:
        batch: SemanticJobBatch = semantic(ids, recent_limit=recent_limit)
        jobs = batch.jobs_by_engagement
        total_job_count = batch.total_job_count
        seed_job_exists = batch.seed_job_exists
    services = SqlAlchemyEngagementServiceRepository().list_for_engagements(ids)
    chains = SqlAlchemySketchChainRepository().list_for_engagements(ids)
    records = SqlAlchemyProviderResourceRepository().list()
    lifecycles = SqlAlchemyEngagementLifecycleRepository().list_for_engagements(ids)
    records_by_engagement = _group_by_engagement(records)
    return OperationsReadSnapshot(
        jobs={engagement_id: list(jobs.get(engagement_id, [])) for engagement_id in ids},
        services=_group_by_engagement(services),
        sketch_chains=_group_by_engagement(chains),
        provider_records={engagement_id: records_by_engagement.get(engagement_id, []) for engagement_id in ids},
        all_provider_records=records,
        lifecycles={row.engagement_id: row for row in lifecycles},
        total_job_count=total_job_count,
        seed_job_exists=seed_job_exists,
    )


def _group_by_engagement(rows: list[Any]) -> dict[str, list[Any]]:
    grouped: dict[str, list[Any]] = {}
    for row in rows:
        grouped.setdefault(row.engagement_id, []).append(row)
    return grouped


def get_operations_overview(
    engagement_id: str,
    engagement_repository: EngagementRepository | None = None,
    job_repository: JobRepository | None = None,
    include_provider_findings: bool = True,
    read_snapshot: OperationsReadSnapshot | None = None,
) -> dict[str, Any] | None:
    engagement = _engagement_repository(engagement_repository).get(engagement_id)
    if engagement is None:
        return None

    jobs_repository = _job_repository(job_repository)
    jobs = _engagement_jobs(engagement_id, jobs_repository)
    job = jobs[0] if jobs else None
    core_deployment_job = _latest_job_with_action(jobs, CORE_DEPLOYMENT_ACTIONS)
    core_job = _latest_successful_core_deployment_with_connections(jobs)
    teardown_job = _latest_job_with_action(jobs, {
        ENGAGEMENT_TEARDOWN_ACTION, MIXED_ZERO_APPLY_TEARDOWN_ACTION,
        MIXED_INTERRUPTED_TEARDOWN_ACTION, MIXED_PUBLISHED_TEARDOWN_ACTION})
    if (teardown_job is not None
            and teardown_job.status == "succeeded"
            and teardown_job.finished_at is not None
            and core_deployment_job is not None
            and core_deployment_job.status in {"queued", "running", "succeeded"}
            and isinstance(core_deployment_job.input.get("corePlanId"), str)
            and core_deployment_job.input["corePlanId"]
            and _job_after(core_deployment_job.created_at, teardown_job.finished_at)):
        teardown_job = None
    teardown_job, teardown_selection = _current_teardown_selection(
        jobs, core_deployment_job, teardown_job, engagement_id)
    mixed_initial_job = _mixed_initial_job_summary(
        jobs, core_deployment_job, core_job, teardown_job, engagement_id,
        job_repository=jobs_repository)
    sketch_job = _latest_job_with_event_key(jobs, "sketchInfrastructure")
    outbound_job = _latest_job_with_event_key(jobs, "outboundChannels")
    inbound_job = _latest_job_with_event_key(jobs, "inboundChannels")
    service_job = _latest_job_with_event_key(jobs, "servicePlacements")
    connection_details = _connection_details(core_job)
    housekeeping_items = (
        ""
        if read_snapshot is not None
        else _housekeeping_items(engagement_id)
    )
    last_checked_at = _last_checked_at(core_job or job)
    fallback_region = _job_region(core_job or job)
    lifecycle = _engagement_lifecycle(engagement.id, engagement.status, jobs, read_snapshot)
    teardown_summary = _teardown_job_summary(teardown_job, jobs, job_repository=jobs_repository)
    core_lifecycle = _core_lifecycle(core_deployment_job or core_job)
    if (teardown_selection == {"state": "exact"}
            and teardown_job is not None
            and core_job is not None and core_deployment_job is not None
            and core_job.id == core_deployment_job.id == teardown_job.input.get("coreJobId")
            and lifecycle.get("state") == "destroyed"
            and teardown_summary is not None and teardown_summary.get("recoveryState") == "complete"
            and teardown_job.finished_at is not None
            and teardown_job.input.get("remainingOwnedResources") == []
            and teardown_job.events[-1].data.get("state") == "destroyed"
            and (teardown_job.action == MIXED_PUBLISHED_TEARDOWN_ACTION
                 or _sealed_initial_terminal_projection(teardown_job, core_job, jobs_repository))):
        # Published cleanup keeps the successful core journal immutable. Its
        # exact current-generation terminal result supersedes that historical
        # deployment status only in this read projection.
        core_lifecycle = _core_lifecycle(teardown_job)
    core_hosts = [_core_host(entry, core_job, last_checked_at, fallback_region, core_lifecycle) for entry in connection_details]
    durable_services = (
        read_snapshot.services.get(engagement_id, [])
        if read_snapshot is not None
        else SqlAlchemyEngagementServiceRepository().list_for_engagement(engagement_id)
    )
    service_placements = _merge_service_placement_rows(
        _event_rows(service_job, "servicePlacements", _service_placement),
        _durable_service_placements(durable_services),
        _capability_service_placements(jobs),
    )
    core_hosts = _merge_service_placements(core_hosts, connection_details, service_placements)
    durable_sketch_chains = (
        read_snapshot.sketch_chains.get(engagement_id, [])
        if read_snapshot is not None
        else SqlAlchemySketchChainRepository().list_for_engagement(engagement_id)
    )
    durable_sketch_rows = _durable_sketch_rows(durable_sketch_chains)
    sketch_infrastructure = durable_sketch_rows or _event_rows(sketch_job, "sketchInfrastructure", _sketch_row)
    adopted_provider_records = (
        read_snapshot.provider_records.get(engagement_id, [])
        if read_snapshot is not None
        else SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id)
    )
    from app.services.provider_resource_reporting import reported_provider_resource
    reported_resources = {record.id: reported_provider_resource(record, jobs) for record in adopted_provider_records}
    live_provider_resources = provider_reconciliation.discover_provider_resources() if include_provider_findings else []
    provider_health = _provider_health_by_record(adopted_provider_records, live_provider_resources)
    core_hosts.extend(_adopted_core_resource_rows(adopted_provider_records, core_hosts, provider_health))
    sketch_infrastructure.extend(_adopted_sketch_resource_rows(adopted_provider_records, sketch_infrastructure, provider_health))
    provider_findings = (
        provider_reconciliation.orphan_candidates_for_engagement(
            engagement_id,
            [engagement],
            jobs,
            provider_resources=live_provider_resources,
            local_provider_resources=list(reported_resources.values()),
        )
        if include_provider_findings
        else []
    )
    outbound_channels = _outbound_channel_rows(
        jobs,
        outbound_job,
        durable_sketch_chains,
        engagement.name,
        core_deployment_job or core_job,
    )
    inbound_event_rows = _filter_unconfigured_default_backflips(_event_rows(inbound_job, "inboundChannels", _inbound_channel))
    inbound_channels = _merge_service_readiness(
        _merge_inspector_public_ingress(
            inbound_event_rows,
            engagement_id,
            inspection_runs=([] if read_snapshot is not None else None),
        ),
        durable_services,
    )
    inbound_channels = _mark_stranded_pending_inbound_channels(inbound_channels, jobs)

    return {
        "engagementId": engagement.id,
        "lifecycle": lifecycle,
        "housekeepingItems": housekeeping_items,
        "activeJob": _job_summary(job),
        "coreJob": _job_summary(core_job),
        "mixedInitialJob": mixed_initial_job,
        "teardownJob": teardown_summary,
        "teardownSelection": teardown_selection,
        "healthSummary": _health_summary(core_hosts, last_checked_at),
        "coreInfrastructure": core_hosts,
        "sketchInfrastructure": sketch_infrastructure,
        "providerFindings": provider_findings,
        "servicePlacements": service_placements,
        "outboundChannels": outbound_channels,
        "inboundChannels": inbound_channels,
        "sshConfig": _ssh_config(connection_details),
    }


def _mark_stranded_pending_inbound_channels(
    channels: list[dict[str, Any]],
    jobs: list[StoredJobRun],
) -> list[dict[str, Any]]:
    applied_channel_ids = {
        str(job.input.get("channelId") or "").strip()
        for job in jobs
        if job.action == "inbound_channel_apply" and job.status in {"queued", "running"}
    }
    result = []
    for channel in channels:
        channel_id = _string(channel.get("channelId")).strip()
        validation = dict(channel.get("validation") or {})
        claims_apply_started = "apply is starting" in _string(validation.get("detail")).strip().lower()
        if (
            _string(channel.get("status")).strip().lower() != "pending apply"
            or channel_id in applied_channel_ids
            or not claims_apply_started
        ):
            result.append(channel)
            continue
        detail = "No apply job exists for this channel. Remove it and create the inbound channel again."
        result.append({
            **channel,
            "status": "Apply Blocked",
            "validation": {**validation, "status": "Apply Blocked", "detail": detail},
        })
    return result


def _engagement_lifecycle(
    engagement_id: str,
    administrative_status: str,
    jobs: list[StoredJobRun],
    read_snapshot: OperationsReadSnapshot | None = None,
) -> dict[str, Any]:
    from app.services.engagement_lifecycle import get_engagement_lifecycle

    return get_engagement_lifecycle(
        engagement_id,
        administrative_status=administrative_status,
        job_repository=_BoundedJobSnapshot(jobs),
        lifecycle_repository=(
            _SnapshotLifecycleRepository(read_snapshot.lifecycles)
            if read_snapshot is not None
            else None
        ),
        provider_resource_repository=(
            _SnapshotListRepository(read_snapshot.provider_records)
            if read_snapshot is not None
            else None
        ),
        sketch_chain_repository=(
            _SnapshotListRepository(read_snapshot.sketch_chains)
            if read_snapshot is not None
            else None
        ),
    )


class _BoundedJobSnapshot:
    """Lifecycle adapter over the overview's already-bounded job projection."""

    def __init__(self, jobs: list[StoredJobRun]):
        self._jobs = jobs

    def list_for_engagement(self, engagement_id: str, *, limit: int | None = None) -> list[StoredJobRun]:
        selected = [job for job in self._jobs if _job_engagement_id(job) == engagement_id]
        return selected if limit is None else selected[:limit]


class _SnapshotListRepository:
    def __init__(self, rows: dict[str, list[Any]]):
        self._rows = rows

    def list_for_engagement(self, engagement_id: str) -> list[Any]:
        return self._rows.get(engagement_id, [])


class _SnapshotLifecycleRepository:
    def __init__(self, rows: dict[str, StoredEngagementLifecycle]):
        self._rows = rows

    def get(self, engagement_id: str) -> StoredEngagementLifecycle | None:
        return self._rows.get(engagement_id)


def update_operations_overview(engagement_id: str, body: dict[str, Any]) -> dict[str, Any] | None:
    engagement = _engagement_repository(None).get(engagement_id)
    if engagement is None:
        return None

    if "housekeepingItems" in body:
        _save_housekeeping_items(engagement_id, str(body.get("housekeepingItems", "")))

    if "outboundChannels" in body or "inboundChannels" in body:
        previous_inbound_channels = _normalize_inbound_channels(_latest_raw_event_rows(engagement_id, "inboundChannels"))
        outbound_channels = _normalize_outbound_channels(
            body.get("outboundChannels", _latest_raw_event_rows(engagement_id, "outboundChannels"))
        )
        inbound_channels = _normalize_inbound_channels(
            body.get("inboundChannels", previous_inbound_channels)
        )
        if "inboundChannels" in body:
            _validate_applied_inbound_channel_updates(previous_inbound_channels, inbound_channels)
        _record_channels_update(engagement_id, outbound_channels, inbound_channels)

    return get_operations_overview(engagement_id)


def _engagement_repository(repository: EngagementRepository | None) -> EngagementRepository:
    return repository or SqlAlchemyEngagementRepository()


def _job_repository(repository: JobRepository | None) -> JobRepository:
    return repository or SqlAlchemyJobRepository()


def _engagement_jobs(engagement_id: str, repository: JobRepository) -> list[StoredJobRun]:
    semantic = getattr(repository, "list_semantic_for_engagement", None)
    if callable(semantic):
        rows = semantic(engagement_id, recent_limit=OPERATIONS_TIMELINE_LIMIT)
        return [row for row in rows
                if row.action != MIXED_PUBLISHED_DISPATCH_CLAIM_ACTION]
    list_for_engagement = getattr(repository, "list_for_engagement", None)
    if callable(list_for_engagement):
        rows = list_for_engagement(engagement_id)
    else:
        rows = [job for job in repository.list()
                if _job_engagement_id(job) == engagement_id]
    return [row for row in rows
            if row.action != MIXED_PUBLISHED_DISPATCH_CLAIM_ACTION]


def _latest_job_with_event_key(jobs: list[StoredJobRun], key: str) -> StoredJobRun | None:
    for job in jobs:
        # Inspector runs carry a point-in-time channel snapshot for evidence,
        # but they are not topology mutations. Treating that snapshot as the
        # authoritative row source can resurrect a channel removed while an
        # inspection was still running. Public-ingress results are merged from
        # the durable inspection repository by _merge_inspector_public_ingress.
        if key == "inboundChannels" and job.action == "inspector_inspection":
            continue
        # Older Backflips jobs emitted a synthetic default-backflip row even
        # though listener and ingress lifecycle belongs to the operator CLI.
        # Do not let that placeholder replace the latest real inbound topology.
        if key == "inboundChannels" and _job_has_only_default_backflip_rows(job):
            continue
        if any(isinstance(event.data.get(key), list) for event in job.events):
            return job
    return None


def _latest_job_with_action(jobs: list[StoredJobRun], actions: set[str]) -> StoredJobRun | None:
    return next((job for job in jobs if job.action in actions), None)


def _latest_successful_core_deployment_with_connections(jobs: list[StoredJobRun]) -> StoredJobRun | None:
    return next(
        (
            job for job in jobs
            if job.action in CORE_DEPLOYMENT_ACTIONS
            and job.status == "succeeded"
            and any(isinstance(event.data.get("connectionDetails"), list) for event in job.events)
        ),
        None,
    )


def _job_has_only_default_backflip_rows(job: StoredJobRun) -> bool:
    rows = [
        row
        for event in job.events
        if isinstance(event.data.get("inboundChannels"), list)
        for row in event.data["inboundChannels"]
        if isinstance(row, dict)
    ]
    return bool(rows) and all(_is_default_backflip(row) for row in rows)


def _job_engagement_id(job: StoredJobRun) -> str | None:
    value = job.input.get("engagementId")
    return str(value) if value else None


def _connection_details(job: StoredJobRun | None) -> list[dict[str, Any]]:
    if job is None:
        return []
    for event in reversed(job.events):
        details = event.data.get("connectionDetails")
        if isinstance(details, list):
            return [entry for entry in details if isinstance(entry, dict)]
    return []


def _event_rows(
    job: StoredJobRun | None,
    key: str,
    normalizer: Any,
) -> list[dict[str, Any]]:
    if job is None:
        return []
    for event in reversed(job.events):
        rows = event.data.get(key)
        if isinstance(rows, list):
            return [normalizer(row) for row in rows if isinstance(row, dict)]
    return []


def _filter_unconfigured_default_backflips(channels: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [channel for channel in channels if not _is_default_backflip(channel)]


def _is_default_backflip(channel: dict[str, Any]) -> bool:
    if _string(channel.get("channelId")) != "default-backflip":
        return False
    return "backflip" in _string(channel.get("service")).lower()


def _outbound_channel_rows(
    jobs: list[StoredJobRun],
    latest_job: StoredJobRun | None,
    durable_sketch_chains: list[StoredSketchChain],
    engagement_name: str,
    core_job: StoredJobRun | None,
) -> list[dict[str, Any]]:
    durable_chain_ids = _live_durable_chain_ids(durable_sketch_chains)
    latest_rows = _event_rows(latest_job, "outboundChannels", _outbound_channel) if latest_job else []
    latest_core_timestamp = _last_checked_at(core_job)
    if durable_sketch_chains and not durable_chain_ids:
        return latest_rows
    sketch_rows = _latest_event_rows_by_id(
        jobs,
        key="outboundChannels",
        id_key="chainId",
        normalizer=_outbound_channel,
        actions=SKETCH_DEPLOY_ACTIONS,
        allowed_ids=durable_chain_ids if durable_sketch_chains else None,
    )
    authoritative_rows = _latest_event_rows_by_id(
        jobs,
        key="outboundChannels",
        id_key="channelId",
        normalizer=_outbound_channel,
        actions=OUTBOUND_AUTHORITATIVE_ACTIONS,
        allowed_chain_ids=durable_chain_ids if durable_sketch_chains else None,
        after=latest_core_timestamp if durable_sketch_chains else None,
    )

    if durable_sketch_chains:
        derived_rows = _durable_outbound_channel_rows(
            engagement_name,
            durable_sketch_chains,
            existing_outbound_channels=[*sketch_rows, *authoritative_rows],
        )
        authoritative_rows = _authoritative_outbound_rows_for_current_topology(
            authoritative_rows,
            derived_rows,
        )
        merged_rows = _merge_outbound_rows_by_chain(sketch_rows, derived_rows, authoritative_rows)
        return _order_rows_by_durable_chain(merged_rows, durable_sketch_chains)

    if latest_job is None:
        return []

    if latest_job.action in OUTBOUND_AUTHORITATIVE_ACTIONS:
        return latest_rows

    if latest_job.action in SKETCH_DEPLOY_ACTIONS:
        return _merge_outbound_rows_by_chain(sketch_rows, authoritative_rows)

    return latest_rows


def _durable_outbound_channel_rows(
    engagement_name: str,
    durable_chains: list[StoredSketchChain],
    *,
    existing_outbound_channels: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    existing_rows = list(existing_outbound_channels or [])
    for chain in durable_chains:
        if chain.status != "deployed" or not chain.nodes:
            continue
        channels = derive_pending_outbound_channels_from_sketch_rows(
            engagement_name,
            chain.chain_id,
            [
                {
                    **node,
                    "chainId": chain.chain_id,
                    "proxy": chain.assigned_proxy,
                    "assignedProxy": chain.assigned_proxy,
                    "status": chain.status,
                }
                for node in chain.nodes
            ],
            existing_outbound_channels=[*existing_rows, *rows],
        )
        for channel in channels:
            rows.append(_outbound_channel(channel))
    return rows


def _merge_outbound_rows_by_chain(*row_groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows_by_id: dict[str, dict[str, Any]] = {}
    for rows in row_groups:
        for row in rows:
            channel_id = _outbound_row_identity(row)
            if not channel_id:
                continue
            rows_by_id[channel_id] = row
    return list(rows_by_id.values())


def _authoritative_outbound_rows_for_current_topology(
    authoritative_rows: list[dict[str, Any]],
    derived_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    derived_by_id = {_outbound_row_identity(row): row for row in derived_rows}
    current_rows: list[dict[str, Any]] = []
    for row in authoritative_rows:
        derived = derived_by_id.get(_outbound_row_identity(row))
        if derived is None:
            continue
        recorded_ip = _string((row.get("validation") or {}).get("expectedPublicIp")).strip()
        current_ip = _string((derived.get("validation") or {}).get("expectedPublicIp")).strip()
        if not recorded_ip or recorded_ip != current_ip:
            continue
        current_rows.append(row)
    return current_rows


def _latest_event_rows_by_id(
    jobs: list[StoredJobRun],
    *,
    key: str,
    id_key: str,
    normalizer: Any,
    actions: set[str],
    allowed_ids: set[str] | None = None,
    allowed_chain_ids: set[str] | None = None,
    after: str | None = None,
) -> list[dict[str, Any]]:
    rows_by_id: dict[str, dict[str, Any]] = {}
    for job in jobs:
        if job.action not in actions:
            continue
        if after is not None and not _job_is_after(job, after):
            continue
        for event in reversed(job.events):
            rows = event.data.get(key)
            if not isinstance(rows, list):
                continue
            for raw_row in rows:
                if not isinstance(raw_row, dict):
                    continue
                row = normalizer(raw_row)
                row_id = _string(row.get(id_key)).strip()
                if not row_id or row_id == "N/A" or row_id in rows_by_id:
                    continue
                if (
                    key == "outboundChannels"
                    and id_key == "channelId"
                    and job.action in OUTBOUND_CHANNEL_SCOPED_ACTIONS
                    and row_id != _string(job.input.get("channelId")).strip()
                ):
                    # Apply/validation events include a merged point-in-time
                    # channel snapshot. Only the channel targeted by that job
                    # is new evidence; sibling rows may already be stale.
                    continue
                if allowed_ids is not None and row_id not in allowed_ids:
                    continue
                if allowed_chain_ids is not None and _string(row.get("chainId")).strip() not in allowed_chain_ids:
                    continue
                rows_by_id[row_id] = row
    return list(rows_by_id.values())


def _job_is_after(job: StoredJobRun, timestamp: str) -> bool:
    job_time = _parse_timestamp(job.created_at)
    reference_time = _parse_timestamp(timestamp)
    if job_time is None or reference_time is None:
        return True
    return job_time > reference_time


def _live_durable_chain_ids(chains: list[StoredSketchChain]) -> set[str]:
    return {
        chain.chain_id
        for chain in chains
        if chain.status in LIVE_SKETCH_CHAIN_STATUSES and chain.status != "pending"
    }


def _filter_rows_to_durable_chains(
    rows: list[dict[str, Any]],
    durable_chains: list[StoredSketchChain],
    durable_chain_ids: set[str],
) -> list[dict[str, Any]]:
    if not durable_chains:
        return rows
    return [row for row in rows if _string(row.get("chainId")).strip() in durable_chain_ids]


def _order_rows_by_durable_chain(
    rows: list[dict[str, Any]],
    durable_chains: list[StoredSketchChain],
) -> list[dict[str, Any]]:
    if not durable_chains:
        return rows
    order = {chain.chain_id: index for index, chain in enumerate(durable_chains)}
    return sorted(rows, key=lambda row: order.get(_string(row.get("chainId")).strip(), len(order)))


def _core_host(
    entry: dict[str, Any],
    job: StoredJobRun | None,
    last_checked_at: str | None,
    fallback_region: str,
    lifecycle: dict[str, Any],
) -> dict[str, Any]:
    status = str(lifecycle.get("healthStatus") or ("healthy" if job and job.status == "succeeded" else "unknown"))
    lifecycle_state = str(lifecycle.get("state") or "unknown")
    source = str(lifecycle.get("source") or ("deployment validation" if status == "healthy" else "not probed"))
    detail = str(
        lifecycle.get("detail")
        or ("Last deployment validation succeeded." if status == "healthy" else "No recorded probe result.")
    )
    result = {
        "hostname": _string(entry.get("displayName")) or _string(entry.get("sshAlias")) or "unknown",
        "role": _string(entry.get("role")) or "host",
        "status": lifecycle_state,
        "lifecycleState": lifecycle_state,
        "lastKnown": bool(lifecycle.get("lastKnown", False)),
        "publicIp": _string(entry.get("publicIp")),
        "privateIp": _string(entry.get("privateIp")),
        "sshUser": _ssh_user(entry),
        "region": _string(entry.get("region")) or fallback_region or "not recorded",
        "compartment": _string(entry.get("compartment")) or "barragan-testing",
        "services": _string_list(entry.get("services")) or ["SSH"],
        "health": {
            "status": status,
            "source": source,
            "lastCheckedAt": last_checked_at,
            "stale": False if lifecycle_state == "destroyed" else _is_stale(last_checked_at),
            "detail": detail,
        },
    }
    identity = _core_identity(entry, job)
    if identity:
        logical_name, expected_hostname = identity
        result["hostId"] = logical_name
        result["logicalName"] = logical_name
        result["expectedHostname"] = expected_hostname
    if job is not None:
        result["deploymentJobId"] = job.id
        workspace_revision = _string(
            job.input.get("workspaceRevision")
            or job.input.get("workspaceFingerprint")
            or job.input.get("planFingerprint")
        ).strip()
        if workspace_revision:
            result["workspaceRevision"] = workspace_revision
    provider_resource_id = _string(
        entry.get("providerResourceId") or entry.get("providerInstanceId") or entry.get("resourceId") or entry.get("instanceId")
    ).strip()
    if provider_resource_id:
        result["providerResourceId"] = provider_resource_id
    return result


def _core_identity(entry: dict[str, Any], job: StoredJobRun | None) -> tuple[str, str] | None:
    """Join a connection row to immutable resource names from its deploy job.

    Qualified SSH/display names are operator artifacts.  The semantic host ID
    comes from the key in the persisted deployment input, never by parsing a
    hostname or re-slugging the engagement's current display name.
    """
    if job is None or job.action not in CORE_DEPLOYMENT_ACTIONS or job.status != "succeeded":
        return None
    resource_names = job.input.get("resourceNames")
    if not isinstance(resource_names, dict):
        return None
    proxy_count = job.input.get("proxyCount")
    if type(proxy_count) is not int or proxy_count not in {1, 2}:
        return None
    expected_keys = {"homebase", "proxy01", "vcn"} | ({"proxy02"} if proxy_count == 2 else set())
    if set(resource_names) != expected_keys:
        return None
    identities: dict[str, str] = {}
    for key, value in resource_names.items():
        if key == "vcn":
            if type(value) is not str or not value.strip():
                return None
            continue
        if key != "homebase" and not re.fullmatch(r"proxy[0-9]+", key):
            return None
        if type(value) is not str or not re.fullmatch(rf"{re.escape(key)}-[a-z0-9]+(?:-[a-z0-9]+)*", value):
            return None
        identities[key] = value
    if "homebase" not in identities or not identities or len(set(identities.values())) != len(identities):
        return None
    display_name = _string(entry.get("displayName")).strip()
    ssh_alias = _string(entry.get("sshAlias")).strip()
    matches = [(logical_name, qualified_name) for logical_name, qualified_name in identities.items()
               if display_name == qualified_name and ssh_alias == qualified_name]
    return matches[0] if len(matches) == 1 else None


def _core_lifecycle(job: StoredJobRun | None) -> dict[str, Any]:
    if job is None:
        return {
            "state": "unknown",
            "healthStatus": "unknown",
            "source": "not probed",
            "detail": "No recorded core deployment job.",
            "lastKnown": False,
        }

    final_cleanup_status = _latest_event_value(job, "finalCleanupStatus")
    mutation_status = _latest_event_value(job, "mutationStatus")
    cleanup_remaining = _latest_event_value(job, "remainingCount")
    if final_cleanup_status == "verified_clean":
        return {
            "state": "destroyed",
            "healthStatus": "destroyed",
            "source": "cleanup verification",
            "detail": "Infrastructure has been torn down; host/IP values are last-known historical deployment data.",
            "lastKnown": True,
        }
    if final_cleanup_status == "cleanup_not_verified":
        detail = "Terraform destroy ran, but cleanup verification did not prove all provider resources are gone."
        if cleanup_remaining:
            detail = f"{detail} Remaining resource count: {cleanup_remaining}."
        return {
            "state": "cleanup_not_verified",
            "healthStatus": "attention",
            "source": "cleanup verification",
            "detail": detail,
            "lastKnown": True,
        }
    if final_cleanup_status == "pending_operator_teardown" or mutation_status == "deployed":
        return {
            "state": "active",
            "healthStatus": "healthy" if job.status == "succeeded" else "unknown",
            "source": "deployment validation" if job.status == "succeeded" else "not probed",
            "detail": "Last deployment validation succeeded." if job.status == "succeeded" else "No recorded probe result.",
            "lastKnown": False,
        }
    if mutation_status == "destroyed":
        return {
            "state": "destroyed",
            "healthStatus": "destroyed",
            "source": "deployment lifecycle",
            "detail": "Infrastructure is recorded as destroyed; host/IP values are last-known historical deployment data.",
            "lastKnown": True,
        }
    if job.status == "succeeded":
        return {
            "state": "active",
            "healthStatus": "healthy",
            "source": "deployment validation",
            "detail": "Last deployment validation succeeded.",
            "lastKnown": False,
        }
    return {
        "state": "unknown",
        "healthStatus": "unknown",
        "source": "not probed",
        "detail": "No current core lifecycle state has been recorded.",
        "lastKnown": False,
    }


def _latest_event_value(job: StoredJobRun | None, key: str) -> str:
    if job is None:
        return ""
    for event in reversed(job.events):
        value = event.data.get(key)
        if value is not None:
            return _string(value).strip()
    return ""


def _job_region(job: StoredJobRun | None) -> str:
    if job is None:
        return ""
    target = job.input.get("target")
    if isinstance(target, dict):
        region = _string(target.get("region")).strip()
        if region:
            return region
    for event in reversed(job.events):
        region = _string(event.data.get("region")).strip()
        if region:
            return region
        event_target = event.data.get("target")
        if isinstance(event_target, dict):
            region = _string(event_target.get("region")).strip()
            if region:
                return region
    return ""


def _sketch_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        "chainId": _field(row, "chainId", "id", fallback="N/A"),
        "hostname": _field(row, "hostname", "displayName", "name", fallback="Not Deployed"),
        "provider": _field(row, "provider", fallback="N/A"),
        "role": _field(row, "role", fallback="N/A"),
        "publicIp": _field(row, "publicIp", fallback="Not Deployed"),
        "region": _field(row, "region", fallback="N/A"),
        "proxy": _field(row, "proxy", "assignedProxy", fallback="N/A"),
        "status": _field(row, "status", fallback="Not Ready"),
        "burned": bool(row.get("burned", False)),
        "burnedNote": _field(row, "burnedNote", fallback=""),
    }
    component_id = _safe_compact_text(row.get("componentId"))
    if component_id:
        normalized["componentId"] = component_id
    edge_id = _safe_compact_text(row.get("edgeId"))
    if edge_id:
        normalized["edgeId"] = edge_id
    assigned_proxy_id = _safe_compact_text(row.get("assignedProxyId"))
    if assigned_proxy_id:
        normalized["assignedProxyId"] = assigned_proxy_id
    for source_key, target_key in (
        ("providerResourceId", "providerResourceId"),
        ("providerInstanceId", "providerResourceId"),
        ("resourceId", "providerResourceId"),
        ("instanceId", "providerResourceId"),
        ("deploymentJobId", "deploymentJobId"),
        ("deployJobId", "deploymentJobId"),
        ("workspaceRevision", "workspaceRevision"),
        ("workspaceId", "workspaceRevision"),
    ):
        value = _safe_compact_text(row.get(source_key))
        if value and target_key not in normalized:
            normalized[target_key] = value
    return normalized


def _durable_sketch_rows(chains: list[StoredSketchChain]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for chain in chains:
        if chain.nodes:
            for node in chain.nodes:
                row = _sketch_row(
                    {
                        **node,
                        "chainId": chain.chain_id,
                        "proxy": chain.assigned_proxy,
                        "assignedProxy": chain.assigned_proxy,
                        "assignedProxyId": chain.assigned_proxy,
                        "deploymentJobId": chain.deploy_job_id,
                        "workspaceRevision": chain.updated_at,
                        "status": chain.status,
                        "burned": chain.burned,
                        "burnedNote": chain.burned_note,
                    }
                )
                rows.append(row)
            continue
    return rows


def _provider_health_by_record(
    records: list[StoredProviderResourceRecord],
    live_provider_resources: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    checked_at = datetime.now(timezone.utc).isoformat()
    resources_by_key: dict[str, dict[str, Any]] = {}
    providers_seen = {_string(resource.get("provider")).strip().lower() for resource in live_provider_resources}
    for resource in live_provider_resources:
        for key in _provider_resource_match_keys(resource):
            if key:
                resources_by_key[key] = resource

    health_by_record: dict[str, dict[str, Any]] = {}
    for record in records:
        match = None
        for key in (_record_key(record), _record_name_key(record)):
            match = resources_by_key.get(key)
            if match is not None:
                break
        if match is not None:
            state = _string(match.get("lifecycleState") or match.get("status")).strip() or "present"
            normalized_state = state.lower()
            if normalized_state in provider_reconciliation.TERMINAL_PROVIDER_STATES:
                status = "destroyed"
                stale = False
                detail = f"Provider API reports tracked resource as {state}."
            else:
                status = "present"
                stale = False
                detail = f"Provider API reports tracked resource as {state}."
            health_by_record[record.id] = {
                "status": status,
                "source": f"{record.provider} api",
                "lastCheckedAt": checked_at,
                "stale": stale,
                "detail": detail,
            }
            continue

        if record.provider in providers_seen:
            health_by_record[record.id] = {
                "status": "attention",
                "source": f"{record.provider} api",
                "lastCheckedAt": checked_at,
                "stale": False,
                "detail": "Provider API did not report this tracked resource in the current Barragan development scope.",
            }
        else:
            health_by_record[record.id] = _default_provider_tracking_health(record)
    return health_by_record


def _provider_resource_match_keys(resource: dict[str, Any]) -> set[str]:
    provider = _string(resource.get("provider")).strip().lower()
    resource_type = _string(resource.get("resourceType")).strip().lower()
    resource_id = _string(resource.get("resourceId")).strip().lower()
    name = _string(resource.get("name")).strip().lower()
    keys = set()
    if provider and resource_type and resource_id:
        keys.add(f"{provider}:{resource_type}:{resource_id}")
    if provider and resource_type and name:
        keys.add(f"{provider}:{resource_type}:{name}")
    return keys


def _default_provider_tracking_health(record: StoredProviderResourceRecord) -> dict[str, Any]:
    status = record.status.lower()
    return {
        "status": "unknown" if status in {"adopted", "tracked"} else record.status,
        "source": "provider tracking record",
        "lastCheckedAt": record.updated_at,
        "stale": True,
        "detail": "Resource is tracked from provider reconciliation for visibility; live provider health has not been recorded yet.",
    }


def _adopted_core_resource_rows(
    records: list[StoredProviderResourceRecord],
    existing_rows: list[dict[str, Any]],
    provider_health: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    existing_keys = _existing_resource_keys(existing_rows, provider="oci", resource_type="compute_instance")
    rows = []
    for record in records:
        if record.provider != "oci" or record.resource_type != "compute_instance":
            continue
        if _record_key(record) in existing_keys or _record_name_key(record) in existing_keys:
            continue
        health = provider_health.get(record.id, _default_provider_tracking_health(record))
        rows.append(
            {
                "hostname": record.name or record.resource_id or "tracked-oci-resource",
                "role": _infer_core_role(record.name),
                "status": record.status,
                "lifecycleState": record.status,
                "lastKnown": record.status in {"destroyed", "deleted", "retired", "absent"},
                "publicIp": _first_public_ip(record),
                "privateIp": _metadata_text(record, "privateIp"),
                "sshUser": CORE_MANAGEMENT_SSH_USER,
                "region": record.region or "not recorded",
                "compartment": _metadata_text(record, "compartmentId") or "barragan-testing",
                "services": ["SSH"],
                "providerResourceId": record.resource_id,
                "health": health,
            }
        )
    return rows


def _adopted_sketch_resource_rows(
    records: list[StoredProviderResourceRecord],
    existing_rows: list[dict[str, Any]],
    provider_health: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    existing_keys = _existing_resource_keys(existing_rows)
    rows = []
    for record in records:
        if record.provider not in {"linode", "digitalocean"}:
            continue
        if _is_support_provider_resource(record):
            continue
        if _record_key(record) in existing_keys or _record_name_key(record) in existing_keys:
            continue
        health = provider_health.get(record.id, _default_provider_tracking_health(record))
        rows.append(
            {
                "chainId": _metadata_text(record, "chainId") or _infer_chain_id(record.name),
                "hostname": record.name or record.resource_id or "tracked-sketch-resource",
                "provider": record.provider,
                "providerInstanceId": record.resource_id,
                "role": _infer_sketch_role(record.name),
                "publicIp": _first_public_ip(record) or "Not Recorded",
                "region": record.region or "N/A",
                "proxy": _metadata_text(record, "proxy") or _infer_proxy(record.name) or "N/A",
                "status": health.get("status") or record.status,
                "health": health,
                "burned": False,
                "burnedNote": "",
            }
        )
    return rows


def _existing_resource_keys(
    rows: list[dict[str, Any]],
    provider: str = "",
    resource_type: str = "",
) -> set[str]:
    keys = set()
    for row in rows:
        name = _string(row.get("hostname") or row.get("displayName") or row.get("name")).strip()
        resource_id = _string(row.get("providerResourceId") or row.get("providerInstanceId") or row.get("resourceId")).strip()
        row_provider = provider or _string(row.get("provider")).strip()
        row_resource_type = resource_type or _resource_type_for_row(row)
        if row_provider and row_resource_type and resource_id:
            keys.add(f"{row_provider}:{row_resource_type}:{resource_id}".lower())
        if row_provider and row_resource_type and name:
            keys.add(f"{row_provider}:{row_resource_type}:{name}".lower())
    return keys


def _record_key(record: StoredProviderResourceRecord) -> str:
    return f"{record.provider}:{record.resource_type}:{record.resource_id}".lower()


def _record_name_key(record: StoredProviderResourceRecord) -> str:
    return f"{record.provider}:{record.resource_type}:{record.name}".lower()


def _is_support_provider_resource(record: StoredProviderResourceRecord) -> bool:
    metadata_role = _metadata_text(record, "role").lower()
    resource_type = record.resource_type.lower()
    source = record.source.lower()
    name = record.name.lower()
    record_id = record.id.lower()
    return (
        metadata_role in {"inspector", "observer"}
        or resource_type.startswith(("inspector_", "observer_"))
        or source in {"inspector", "observer", "barragan_inspector", "barragan_observer"}
        or name.startswith(("inspector-", "observer-"))
        or ":inspector:" in record_id
        or ":observer:" in record_id
    )


def _resource_type_for_row(row: dict[str, Any]) -> str:
    provider = _string(row.get("provider")).strip()
    if provider == "linode":
        return "instance"
    if provider == "digitalocean":
        return "droplet"
    return _string(row.get("resourceType")).strip() or "resource"


def _first_public_ip(record: StoredProviderResourceRecord) -> str:
    public_ips = record.metadata.get("publicIps") if isinstance(record.metadata, dict) else []
    if isinstance(public_ips, list):
        for value in public_ips:
            text = _string(value).strip()
            if text:
                return text
    return _metadata_text(record, "publicIp")


def _metadata_text(record: StoredProviderResourceRecord, key: str) -> str:
    value = record.metadata.get(key) if isinstance(record.metadata, dict) else ""
    return _string(value).strip()


def _infer_core_role(name: str) -> str:
    lowered = name.lower()
    if lowered.startswith("homebase-"):
        return "homebase"
    match = re.match(r"^(proxy[0-9]+)-", lowered)
    return match.group(1) if match else "core"


def _infer_sketch_role(name: str) -> str:
    lowered = name.lower()
    if lowered.startswith("middle"):
        return "middle"
    if lowered.startswith("edge-"):
        return "edge"
    return "sketch"


def _infer_proxy(name: str) -> str:
    match = re.search(r"(proxy[0-9]+)", name.lower())
    return match.group(1) if match else ""


def _infer_chain_id(name: str) -> str:
    proxy = _infer_proxy(name)
    region_match = re.search(r"-([a-z]{2,}-[a-z0-9]+)-proxy[0-9]+-", name.lower())
    sequence_match = re.search(r"-([0-9]{2})$", name)
    if proxy and region_match and sequence_match:
        return f"{proxy}-{region_match.group(1)}-{sequence_match.group(1)}"
    return "tracked"


def _outbound_channel(row: dict[str, Any]) -> dict[str, Any]:
    channel: dict[str, Any] = {
        "channelId": _field(row, "channelId", "id", fallback=_field(row, "chainId", fallback="N/A")),
        "chainId": _field(row, "chainId", "id", fallback="N/A"),
        "proxy": _field(row, "proxy", fallback="Not Deployed"),
        "middle": _field(row, "middle", fallback="Not Deployed"),
        "edge": _field(row, "edge", fallback="Not Deployed"),
        "port": _field(row, "port", "listenerPort", fallback="N/A"),
        "region": _field(row, "region", fallback="N/A"),
        "provider": _field(row, "provider", fallback="N/A"),
        "domain": _field(row, "domain", fallback="N/A"),
        "purpose": _field(row, "purpose", fallback="N/A"),
        "status": _field(row, "status", fallback="Not Ready"),
    }
    channel.update(_outbound_compact_metadata(row))
    return channel


def _inbound_channel(row: dict[str, Any]) -> dict[str, Any]:
    channel: dict[str, Any] = {
        "channelId": _field(row, "channelId", "id", "name", fallback="N/A"),
        "domain": _field(row, "domain", fallback="N/A"),
        "protocol": _field(row, "protocol", fallback="N/A"),
        "externalPort": _field(row, "externalPort", "port", fallback="N/A"),
        "edge": _field(row, "edge", fallback="Not Deployed"),
        "edgeComponentId": _field(row, "edgeComponentId", fallback=""),
        "middle": _field(row, "middle", fallback="Not Deployed"),
        "middleComponentId": _field(row, "middleComponentId", fallback=""),
        "proxy": _field(row, "proxy", fallback="Not Deployed"),
        "terminatesOn": _field(row, "terminatesOn", "destinationHost", "targetHost", fallback="Not Deployed"),
        "service": _field(row, "service", "destinationService", fallback="N/A"),
        "internalPort": _field(row, "internalPort", "destinationPort", fallback="N/A"),
        "purpose": _field(row, "purpose", fallback="N/A"),
        "status": _field(row, "status", fallback="Not Ready"),
    }
    mode = _safe_compact_text(row.get("mode"))
    if mode:
        channel["mode"] = mode
    service_id = _safe_compact_text(row.get("serviceId"))
    if service_id:
        channel["serviceId"] = service_id
    service_type = _safe_compact_text(row.get("serviceType"))
    if service_type:
        channel["serviceType"] = service_type
    relay_port = _field(row, "relayPort", "proxyRelayPort", fallback="")
    if relay_port:
        channel["relayPort"] = relay_port
    middle_relay_port = _field(row, "middleRelayPort", "relayPort", "proxyRelayPort", fallback="")
    if middle_relay_port:
        channel["middleRelayPort"] = middle_relay_port
    proxy_relay_port = _field(row, "proxyRelayPort", "relayPort", fallback="")
    if proxy_relay_port:
        channel["proxyRelayPort"] = proxy_relay_port
    channel.update(_inbound_compact_metadata(row))
    return channel


def _merge_inspector_public_ingress(
    channels: list[dict[str, Any]],
    engagement_id: str,
    inspection_runs: list[StoredInspectionRun] | None = None,
) -> list[dict[str, Any]]:
    if not channels:
        return channels
    inspector_results = (
        _latest_inspector_public_ingress_by_channel(engagement_id)
        if inspection_runs is None
        else _latest_inspector_public_ingress_by_channel(
            engagement_id,
            inspection_runs=inspection_runs,
        )
    )
    if not inspector_results:
        return channels
    merged = []
    for channel in channels:
        if _string(channel.get("status")).strip().lower() in {"removed", "disabled", "pending apply", "not deployed"}:
            merged.append(channel)
            continue
        channel_id = _string(channel.get("channelId")).strip()
        result = inspector_results.get(channel_id)
        if result is None:
            merged.append(channel)
            continue
        validation = dict(channel.get("validation") or {})
        route_status = _string(validation.get("status") or channel.get("status")).strip()
        validation["externalIngressVerified"] = bool(result["ok"])
        validation["externalIngressCheckedAt"] = result["checkedAt"]
        validation["externalIngressDetail"] = result["detail"]
        if route_status:
            validation["status"] = route_status
        merged.append({**channel, "validation": validation})
    return merged


def _latest_inspector_public_ingress_by_channel(
    engagement_id: str,
    *,
    inspection_runs: list[StoredInspectionRun] | None = None,
) -> dict[str, dict[str, Any]]:
    if inspection_runs is None:
        try:
            runs = SqlAlchemyInspectionRunRepository().list_for_engagement(engagement_id)
        except Exception:
            return {}
    else:
        runs = inspection_runs
    results_by_channel: dict[str, dict[str, Any]] = {}
    for run in runs:
        for channel_id, route_results in _inspection_route_results(run).items():
            if channel_id in results_by_channel:
                continue
            authoritative_results = _authoritative_public_ingress_results(route_results)
            ok = all(result.get("ok") is True for result in authoritative_results)
            results_by_channel[channel_id] = {
                "ok": ok,
                "checkedAt": run.finished_at or run.started_at or run.created_at,
                "detail": _inspector_public_ingress_detail(run, channel_id, ok, authoritative_results),
            }
    return results_by_channel


def _authoritative_public_ingress_results(route_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for result_type in ("https", "http", "udp", "tcp-send-expect", "tcp"):
        selected = [result for result in route_results if _string(result.get("type")).lower() == result_type]
        if selected:
            return selected
    return route_results


def _inspection_route_results(run: StoredInspectionRun) -> dict[str, list[dict[str, Any]]]:
    evidence = run.evidence if isinstance(run.evidence, dict) else {}
    raw_results = evidence.get("results")
    if not isinstance(raw_results, list):
        return {}
    grouped: dict[str, list[dict[str, Any]]] = {}
    for raw_result in raw_results:
        if not isinstance(raw_result, dict):
            continue
        result_type = _string(raw_result.get("type")).lower()
        if result_type not in {"tcp", "tcp-send-expect", "udp", "http", "https"}:
            continue
        channel_id = _string(raw_result.get("channelId") or raw_result.get("id")).strip()
        if not channel_id:
            continue
        grouped.setdefault(channel_id, []).append(raw_result)
    return grouped


def _inspector_public_ingress_detail(
    run: StoredInspectionRun,
    channel_id: str,
    ok: bool,
    route_results: list[dict[str, Any]],
) -> str:
    if ok:
        result_type = _string(route_results[0].get("type")).upper() if route_results else ""
        check_label = f" {result_type}" if result_type else ""
        return f"Public{check_label} ingress verified by Inspector run {run.job_id}."
    failed = next((result for result in route_results if result.get("ok") is not True), None)
    observed = _string(failed.get("observed")) if isinstance(failed, dict) else ""
    suffix = f" Observed: {observed[:240]}" if observed else ""
    return f"Public ingress check failed for {channel_id} in Inspector run {run.job_id}.{suffix}"


def _service_placement(row: dict[str, Any]) -> dict[str, str]:
    placement = {
        "hostId": _field(row, "hostId", "host", "hostname", fallback=""),
        "hostRole": _field(row, "hostRole", "role", fallback=""),
        "service": _field(row, "service", "name", fallback=""),
        "status": _field(row, "status", fallback="Not Ready"),
        "port": _field(row, "port", fallback=""),
        "detail": _field(row, "detail", fallback=""),
    }
    for key in ("serviceId", "serviceType", "domain", "siteName", "protocol", "transport", "purpose", "scriptPath", "notes"):
        value = _field(row, key, fallback="")
        if value:
            placement[key] = value
    tags = row.get("tags")
    if isinstance(tags, list):
        placement["tags"] = tags
    validation_profile = row.get("validationProfile")
    if isinstance(validation_profile, dict):
        placement["validationProfile"] = validation_profile
    return placement


def _durable_service_placements(services: list[StoredEngagementService]) -> list[dict[str, str]]:
    rows = []
    for service in services:
        if service.service_type == "web-static":
            rows.append(
                {
                    "hostId": service.proxy_id,
                    "hostRole": "proxy",
                    "service": "Static Web",
                    "status": service.status,
                    "port": _string(service.config.get("internalPort")),
                    "detail": _web_static_detail(service),
                    "serviceId": service.service_id,
                    "serviceType": service.service_type,
                    "domain": _string(service.config.get("domain")),
                    "siteName": _string(service.config.get("siteName") or service.name),
                }
            )
            continue
        if service.service_type == "web-http-backend":
            rows.append(
                {
                    "hostId": service.proxy_id,
                    "hostRole": "proxy",
                    "service": service.name,
                    "status": service.status,
                    "port": "8081",
                    "detail": "TLS-terminating OpenResty site forwarding privately to its selected homebase backend.",
                    "serviceId": service.service_id,
                    "serviceType": service.service_type,
                    "domain": _string(service.config.get("domain")),
                    "siteName": _string(service.config.get("siteName") or service.name),
                }
            )
            continue
        if service.service_type == GENERIC_SERVICE_TYPE:
            rows.append(generic_service_placement(service))
            continue
        rows.append(
            {
                "hostId": service.proxy_id,
                "hostRole": "proxy",
                "service": service.name,
                "status": service.status,
                "port": _string(service.config.get("port")),
                "detail": _string(service.config.get("detail")),
                "serviceId": service.service_id,
                "serviceType": service.service_type,
            }
        )
    return rows


def _capability_service_placements(jobs: list[StoredJobRun]) -> list[dict[str, Any]]:
    """Expose installed Homebase HTTP backends before their first route exists."""

    reconciliation = next(
        (
            job
            for job in jobs
            if job.action == "engagement_capability_reconciliation" and job.status == "succeeded"
        ),
        None,
    )
    if reconciliation is None:
        return []
    selected = reconciliation.input.get("selectedRoles")
    homebase_roles = selected.get("homebase", []) if isinstance(selected, dict) else []
    if not any(
        isinstance(role, dict) and str(role.get("id") or "") == "go-simple-upload-server"
        for role in homebase_roles
    ):
        return []
    return [
        {
            "hostId": "homebase",
            "hostRole": "homebase",
            "service": "Go Simple Upload Server",
            "status": "Active",
            "port": "9999",
            "protocol": "tcp",
            "purpose": "file uploads",
            "detail": "Capability-backed Homebase service; publish through a managed HTTPS site.",
            "serviceId": "capability-go-simple-upload-server",
            "serviceType": "capability-http-backend",
            "validationProfile": {
                "type": "manual",
                "label": "Bind TLS certificate, then validate HTTPS upload from Inspector",
            },
        }
    ]


def _merge_service_readiness(
    inbound_channels: list[dict[str, Any]],
    services: list[StoredEngagementService],
) -> list[dict[str, Any]]:
    if not inbound_channels:
        return inbound_channels
    service_by_id = {service.service_id: service for service in services}
    merged = []
    for channel in inbound_channels:
        if _string(channel.get("status")).strip() in {"Removed", "Disabled", "Pending Apply", "Not Deployed"}:
            merged.append(channel)
            continue
        service_id = _string(channel.get("serviceId")).strip()
        service = service_by_id.get(service_id)
        if service is None or service.status in {"Active", "Configured", "Applying"}:
            merged.append(channel)
            continue
        validation = dict(channel.get("validation") or {})
        validation["status"] = "Service Not Ready"
        validation["detail"] = f"Service {service.name or service.service_id} is {service.status}; inbound channel is not ready."
        merged.append({**channel, "status": "Not Ready", "validation": validation})
    return merged


def _merge_service_placement_rows(*row_groups: list[dict[str, str]]) -> list[dict[str, str]]:
    rows_by_id: dict[str, dict[str, str]] = {}
    anonymous_rows: list[dict[str, str]] = []
    for rows in row_groups:
        for row in rows:
            service_id = row.get("serviceId", "").strip()
            host_id = row.get("hostId", "").strip()
            service = row.get("service", "").strip()
            key = service_id or (f"{host_id}:{service}" if host_id and service else "")
            if key:
                rows_by_id[key] = row
            else:
                anonymous_rows.append(row)
    return list(rows_by_id.values()) + anonymous_rows


def _web_static_detail(service: StoredEngagementService) -> str:
    site_name = _string(service.config.get("siteName") or service.name)
    port = _string(service.config.get("internalPort"))
    status = service.status
    if status == "Configured":
        return f"Static web site {site_name} is configured on 127.0.0.1:{port}."
    if status == "Failed":
        return f"Static web site {site_name} apply failed."
    if status == "Applying":
        return f"Static web site {site_name} apply is running."
    return f"Static web site {site_name} apply has not run yet."


def _merge_service_placements(
    core_hosts: list[dict[str, Any]],
    connection_details: list[dict[str, Any]],
    service_placements: list[dict[str, str]],
) -> list[dict[str, Any]]:
    if not core_hosts or not service_placements:
        return core_hosts

    for placement in service_placements:
        service = placement.get("service", "").strip()
        if not service or placement.get("status") not in {"Configured", "Active"}:
            continue
        if service == "Static Web" and not placement.get("serviceId", "").strip():
            continue
        host_index = _core_host_index_for_placement(connection_details, placement)
        if host_index is None:
            continue
        services = list(core_hosts[host_index].get("services", []))
        if service not in services:
            services.append(service)
        core_hosts[host_index]["services"] = services
    return core_hosts


def _core_host_index_for_placement(
    connection_details: list[dict[str, Any]],
    placement: dict[str, str],
) -> int | None:
    host_id = placement.get("hostId", "").strip()
    host_role = placement.get("hostRole", "").strip()
    for index, entry in enumerate(connection_details):
        aliases = {
            _string(entry.get("displayName")).strip(),
            _string(entry.get("sshAlias")).strip(),
            _string(entry.get("role")).strip(),
        }
        if host_id and host_id in aliases:
            return index
        display_name = _string(entry.get("displayName")).strip()
        if host_id and display_name.startswith(f"{host_id}-"):
            return index
        if host_role and host_role == _string(entry.get("role")).strip():
            return index
    return None


def _ssh_config(connection_details: list[dict[str, Any]]) -> dict[str, Any]:
    hosts = []
    homebase = next((_host_for_ssh(entry) for entry in connection_details if entry.get("role") == "homebase"), None)
    if homebase is None and connection_details:
        homebase = _host_for_ssh(connection_details[0])
    for entry in connection_details:
        host = _host_for_ssh(entry)
        hostname = _core_ssh_hostname(host)
        lines = [
            f"Host {host['sshAlias']}",
            f"    HostName {hostname}",
        ]
        if host["role"] == "homebase":
            lines.extend(
                [
                    "    ## Uncomment AddressFamily if you have WSL errors to force ipv4",
                    "    # AddressFamily inet",
                    "    ## Etherpad",
                    "    # LocalForward 9001 127.0.0.1:9001",
                    "    ## Mythic",
                    "    # LocalForward 7443 127.0.0.1:7443",
                    "    ## ELK",
                    "    # LocalForward 5601 192.168.1.13:5601",
                    "    ## Keep 5901 as your local listener unless it conflicts; change 59xx to your remote VNC port.",
                    "    ## Your port number is (5900 + (UID - 6000) + 1)",
                    "    # LocalForward 5901 127.0.0.1:59xx",
                ]
            )
        if homebase and host["role"] != "homebase":
            lines.append(f"    ProxyJump {homebase['sshAlias']}")
        hosts.append("\n".join(lines))
    stanza = "\n\n".join(hosts)
    return {
        "stanza": stanza,
        "downloadName": "engagement-ssh-config",
    }


def _core_ssh_hostname(host: dict[str, str]) -> str:
    if host["role"] == "homebase":
        return host["publicIp"]
    proxy_alias = re.match(r"^(proxy\d+)(?:-|$)", host["sshAlias"])
    if proxy_alias:
        # Keep the engagement-qualified Host label for workstation uniqueness,
        # but target the semantic proxy alias exposed by the upstream RTI core
        # host-resolution contract from Homebase.
        return f"{proxy_alias.group(1)}.infra.redteam"
    return host["privateIp"] or host["publicIp"]


def _host_for_ssh(entry: dict[str, Any]) -> dict[str, str]:
    display = _string(entry.get("displayName")) or _string(entry.get("sshAlias")) or "host"
    return {
        "role": _string(entry.get("role")) or display,
        "sshAlias": _string(entry.get("sshAlias")) or display,
        "publicIp": _string(entry.get("publicIp")),
        "privateIp": _string(entry.get("privateIp")),
        "sshUser": _ssh_user(entry),
    }


def _ssh_user(entry: dict[str, Any]) -> str:
    return _string(entry.get("sshUser")) or CORE_MANAGEMENT_SSH_USER


def _job_summary(job: StoredJobRun | None) -> dict[str, Any] | None:
    if job is None:
        return None
    return {
        "id": job.id,
        "action": job.action,
        "status": job.status,
        "createdAt": job.created_at,
        "finishedAt": job.finished_at,
    }


def _mixed_initial_job_summary(
    jobs: list[StoredJobRun], latest_core: StoredJobRun | None,
    active_core: StoredJobRun | None, teardown: StoredJobRun | None,
    engagement_id: str,
    *, job_repository: JobRepository | None = None,
) -> dict[str, Any] | None:
    """Show only the exact current core's retained mixed Deploy checkpoint."""
    from app.services.provider_keyed_mixed_initial_plan_parent import (
        ACTION, _PHASES, _parent_id,
    )

    if (teardown is not None or latest_core is None or active_core is None
            or latest_core.id != active_core.id or active_core.status != "succeeded"
            or active_core.input.get("sketchStateSchema") != "provider-keyed-v2"
            or not isinstance(active_core.input.get("corePlanId"), str)
            or not active_core.input["corePlanId"]):
        return None
    parent_id = _parent_id(active_core.id)
    matches = [row for row in jobs if row.id == parent_id]
    if not matches and job_repository is not None:
        # A long job timeline can evict this parent from the bounded semantic
        # projection. Fetch only the deterministic current-core identity.
        get = getattr(job_repository, "get", None)
        candidate = get(parent_id) if callable(get) else None
        if candidate is not None:
            matches = [candidate]
    if len(matches) != 1:
        return None
    parent = matches[0]
    data = parent.input if isinstance(parent.input, dict) else {}
    phase = data.get("phase")
    if (parent.action != ACTION or parent.target_id != engagement_id
            or parent.target_type != "engagement"
            or parent.target != f"engagement:{engagement_id}"
            or parent.status not in {"queued", "running"}
            or parent.finished_at is not None
            or data.get("engagementId") != engagement_id
            or data.get("coreJobId") != active_core.id
            or data.get("corePlanId") != active_core.input["corePlanId"]
            or phase not in {*_PHASES, "awaiting_mixed_host_proof"}):
        return None
    return {**_job_summary(parent), "phase": phase}


def _mixed_cleanup_progress(parent: StoredJobRun, jobs: list[StoredJobRun]) -> tuple[str, dict[str, int]]:
    core_id = parent.input.get("coreJobId")
    if not isinstance(core_id, str) or not core_id:
        return "attention", {"completed": 0, "total": 5}
    suffix = core_id.removeprefix("job-")
    stages = (
        ("core_destroy_preview", "provider_keyed_mixed_zero_apply_core_destroy_preview",
         f"job-provider-keyed-mixed-core-destroy-preview-{suffix}"),
        ("core_destroy_apply", "provider_keyed_mixed_zero_apply_core_destroy_apply",
         f"job-provider-keyed-mixed-core-destroy-apply-{suffix}"),
        ("core_absence", "provider_keyed_mixed_zero_apply_core_destroy_absence",
         f"job-provider-keyed-mixed-core-destroy-absence-{suffix}-attempt-"),
        ("public_negative", "provider_keyed_mixed_zero_apply_inspector_negative",
         f"job-provider-keyed-mixed-inspector-negative-{suffix}"),
        ("inspector_retirement", "provider_keyed_mixed_zero_apply_inspector_retirement",
         f"job-provider-keyed-mixed-inspector-retirement-{suffix}"),
    )
    completed = 0
    for phase, action, identity in stages:
        matches = [row for row in jobs if row.action == action
                   and (row.id.startswith(identity) if phase == "core_absence"
                        else row.id == identity)
                   and row.target_id == parent.target_id
                   and row.input.get("teardownParentId") == parent.id]
        if not matches:
            return phase, {"completed": completed, "total": len(stages)}
        if any(row.status == "succeeded" for row in matches):
            completed += 1
            continue
        if any(row.status == "failed" for row in matches):
            return "attention", {"completed": completed, "total": len(stages)}
        return phase, {"completed": completed, "total": len(stages)}
    return "lifecycle_reconciliation", {"completed": completed, "total": len(stages)}


def _mixed_interrupted_progress(parent: StoredJobRun,
                                jobs: list[StoredJobRun]) -> tuple[str, dict[str, int]]:
    core_id = parent.input.get("coreJobId")
    source = parent.input.get("source")
    order = source.get("ordered_providers") if type(source) is dict else None
    if (type(core_id) is not str or not core_id or type(order) is not list
            or set(order) != {"linode", "digitalocean"} or len(order) != 2):
        return "attention", {"completed": 0, "total": 8}
    suffix = core_id.removeprefix("job-")
    stages = [
        ("destroy_plans", "provider_keyed_mixed_interrupted_plan_worker",
         f"job-provider-keyed-mixed-interrupted-plan-{suffix}"),
        *((f"{provider}_absence", "provider_keyed_mixed_interrupted_destroy_apply",
           f"job-provider-keyed-mixed-interrupted-destroy-{suffix}-{provider}")
          for provider in order),
        ("core_destroy_preview", "provider_keyed_mixed_zero_apply_core_destroy_preview",
         f"job-provider-keyed-mixed-core-destroy-preview-{suffix}"),
        ("core_destroy_apply", "provider_keyed_mixed_zero_apply_core_destroy_apply",
         f"job-provider-keyed-mixed-core-destroy-apply-{suffix}"),
        ("core_absence", "provider_keyed_mixed_zero_apply_core_destroy_absence",
         f"job-provider-keyed-mixed-core-destroy-absence-{suffix}"),
        ("public_negative", "provider_keyed_mixed_zero_apply_inspector_negative",
         f"job-provider-keyed-mixed-inspector-negative-{suffix}"),
    ]
    scopes = source.get("scopes")
    if (type(scopes) is list and any(type(scope) is dict
            and scope.get("provider") == "digitalocean"
            and scope.get("selector_retirement_pending") is True for scope in scopes)):
        stages.append(("selector_retirement",
                       "provider_keyed_mixed_interrupted_selector_retirement",
                       f"job-provider-keyed-mixed-interrupted-selector-retirement-{suffix}"))
    stages.append(("inspector_retirement",
                   "provider_keyed_mixed_zero_apply_inspector_retirement",
                   f"job-provider-keyed-mixed-inspector-retirement-{suffix}"))
    by_stage: list[list[StoredJobRun]] = []
    for phase, action, identity in stages:
        by_stage.append([row for row in jobs if row.action == action
                         and row.target_id == parent.target_id
                         and (row.id.startswith(identity + "-attempt-")
                              if phase == "core_absence" else row.id == identity)])
    if any(row.status == "failed" for rows in by_stage for row in rows):
        return "attention", {"completed": 0, "total": len(stages)}
    completed = 0
    for index, (phase, _action, _identity) in enumerate(stages):
        rows = by_stage[index]
        later_started = any(by_stage[later]
                            for later in range(index + 1, len(stages)))
        if phase == "destroy_plans":
            done = parent.input.get("phase") == "plans_sealed"
        elif phase.endswith("_absence") and phase != "core_absence":
            # Provider GO children remain journalled as running after their
            # empty-state result. The next stage can start only after exact
            # absence proof, including a provider that needed no destroy.
            done = later_started
        else:
            done = any(row.status == "succeeded" for row in rows)
        if not done:
            return phase, {"completed": completed, "total": len(stages)}
        completed += 1
    return "lifecycle_reconciliation", {"completed": completed, "total": len(stages)}


def _published_display_source(parent: StoredJobRun):
    """Decode a complete tagged checkpoint for display; no live/source I/O."""
    from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
        saved_published_mixed_initial_review, parent_id,
    )
    if (parent.action != MIXED_PUBLISHED_TEARDOWN_ACTION
            or parent.input.get("schema") != "mixed-published-initial-cleanup-v1"
            or parent.input.get("sourceKind") not in (None, "published-six-node-v1", "unpublished-six-node-cleanup-v1")
            or type(parent.input.get("coreJobId")) is not str or not parent.input["coreJobId"]
            or parent.input.get("engagementId") != parent.target_id
            or parent.id != parent_id(parent.input["coreJobId"])
            or parent.target_type != "engagement"
            or parent.target != f"engagement:{parent.target_id}"):
        return None
    try:
        source = saved_published_mixed_initial_review(parent).source
        order = source.ordered_providers
        if (type(order) is not tuple or len(order) != 2
                or any(type(provider) is not str for provider in order)
                or set(order) != {"linode", "digitalocean"}
                or tuple(state.provider for state in source.provider_states) != order):
            return None
        return source
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


def _mixed_published_progress(parent: StoredJobRun,
                              jobs: list[StoredJobRun]) -> tuple[str, dict[str, int]]:
    """Show the one-action published cleanup's saved child boundaries."""
    core_id = parent.input.get("coreJobId")
    source = _published_display_source(parent)
    order = source.ordered_providers if source is not None else ()
    if (type(core_id) is not str or not core_id or len(order) != 2
            or any(type(provider) is not str for provider in order)
            or set(order) != {"linode", "digitalocean"}):
        return "attention", {"completed": 0, "total": 9}
    suffix = core_id.removeprefix("job-")
    stages = [
        (f"{provider}_absence", "provider_keyed_mixed_published_destroy_apply",
         f"job-provider-keyed-mixed-published-destroy-{suffix}-{provider}")
        for provider in order
    ]
    stages.extend([
        ("core_destroy_preview", "provider_keyed_mixed_zero_apply_core_destroy_preview",
         f"job-provider-keyed-mixed-core-destroy-preview-{suffix}"),
        ("core_destroy_apply", "provider_keyed_mixed_zero_apply_core_destroy_apply",
         f"job-provider-keyed-mixed-core-destroy-apply-{suffix}"),
        ("core_absence", "provider_keyed_mixed_zero_apply_core_destroy_absence",
         f"job-provider-keyed-mixed-core-destroy-absence-{suffix}-attempt-"),
        ("public_negative", "provider_keyed_mixed_zero_apply_inspector_negative",
         f"job-provider-keyed-mixed-inspector-negative-{suffix}"),
        ("selector_retirement", "provider_keyed_mixed_published_selector_retirement",
         f"job-provider-keyed-mixed-published-selector-retirement-{suffix}"),
        ("inspector_retirement", "provider_keyed_mixed_published_inspector_retirement",
         f"job-provider-keyed-mixed-published-inspector-retirement-{suffix}"),
    ])
    total = len(stages) + 1
    if parent.input.get("phase") == "awaiting_both_destroy_plans":
        return "destroy_plans", {"completed": 0, "total": total}
    if parent.input.get("phase") != "plans_sealed":
        return "attention", {"completed": 0, "total": total}
    completed = 1
    for phase, action, identity in stages:
        rows = [row for row in jobs if row.action == action
                and row.target_type == "engagement" and row.target_id == parent.target_id
                and row.input.get("cleanupParentId" if action == "provider_keyed_mixed_published_destroy_apply" else "teardownParentId") == parent.id
                and row.input.get("coreJobId") == core_id
                and (re.fullmatch(re.escape(identity) + r"[0-9]+", row.id) is not None if phase == "core_absence"
                     else row.id == identity)]
        if any(row.status == "failed" for row in rows):
            return "attention", {"completed": completed, "total": total}
        if not any(row.status == "succeeded" for row in rows):
            return phase, {"completed": completed, "total": total}
        completed += 1
    return "lifecycle_reconciliation", {"completed": completed, "total": total}


def _sealed_initial_terminal_projection(parent, core, jobs):
    """Recognize saved sealed cleanup history; never obtain fresh provider proof."""
    if (parent.action != ENGAGEMENT_TEARDOWN_ACTION
            or type(parent.input.get("publishedSource")) is not dict
            or type(parent.input.get("scopeSnapshot")) is not dict):
        return False
    from app.services.provider_keyed_published_initial_cleanup_authority import validate_saved_cleanup

    try:
        # Semantic SQL reads format timestamps differently and Dashboard may
        # trim journals. They select the generation, but cannot authenticate an
        # exact seal produced from full persisted records.
        authority_jobs = getattr(jobs, "authority_repository", jobs)
        full_parent = authority_jobs.get(parent.id)
        full_core = authority_jobs.get(core.id)
        for selected, full in ((parent, full_parent), (core, full_core)):
            if full is None or any(getattr(selected, field) != getattr(full, field)
                    for field in ("id", "action", "status", "target", "target_type",
                                  "target_id", "requested_by", "input", "artifact_refs")):
                return False
        if (full_core.action not in CORE_DEPLOYMENT_ACTIONS or full_core.status != "succeeded"
                or full_core.input.get("engagementId") != full_parent.target_id
                or not full_core.input.get("corePlanId")
                or full_parent.input.get("coreJobId") != full_core.id
                or full_parent.finished_at is None
                or comprehensive_teardown_recovery_state(full_parent) != "complete"):
            return False
        return validate_saved_cleanup(full_parent, full_core,
                                      full_parent.input["scopeSnapshot"], authority_jobs) is not None
    except (ValueError, TypeError, KeyError, AttributeError, IndexError):
        # Incomplete or malformed provenance must leave the original projection
        # intact, rather than claim absence or make Operations unavailable.
        return False


def _current_teardown_selection(jobs, core, fallback, engagement_id):
    """Select one recorded cleanup for this core generation, never by recency."""
    actions = {ENGAGEMENT_TEARDOWN_ACTION, MIXED_ZERO_APPLY_TEARDOWN_ACTION,
               MIXED_INTERRUPTED_TEARDOWN_ACTION, MIXED_PUBLISHED_TEARDOWN_ACTION}
    if core is None:
        if fallback is not None and fallback.action == MIXED_PUBLISHED_TEARDOWN_ACTION:
            return None, {"state": "unavailable"}
        return fallback, {"state": "exact" if fallback else "absent"}
    candidates = [row for row in jobs if row.action in actions
                  and row.target_type == "engagement" and row.target_id == engagement_id
                  and row.input.get("coreJobId") == core.id]
    if len(candidates) > 1:
        return None, {"state": "ambiguous"}
    if not candidates:
        if fallback is not None and fallback.action == MIXED_PUBLISHED_TEARDOWN_ACTION:
            return None, {"state": "unavailable" if fallback.status in {"queued", "running"} else "absent"}
        return fallback, {"state": "exact" if fallback else "absent"}
    candidate = candidates[0]
    if candidate.action == MIXED_PUBLISHED_TEARDOWN_ACTION:
        source = _published_display_source(candidate)
        if (source is None or candidate.input.get("engagementId") != engagement_id
                or source.engagement_id != engagement_id or source.core_job_id != core.id
                or source.core_plan_id != core.input.get("corePlanId")):
            return None, {"state": "unavailable"}
    return candidate, {"state": "exact"}


def _published_dispatch_progress(parent, jobs, repository):
    """Read-only scheduler/child visibility; never authorize claim takeover."""
    from app.services.provider_keyed_mixed_published_dispatch_claim import _marker_id, _valid_marker
    from app.storage.job_repository import _stored_utc_instant
    getter = getattr(repository, "get", None)
    marker = getter(_marker_id(parent.id)) if callable(getter) else next(
        (row for row in jobs if row.id == _marker_id(parent.id)), None)
    dispatch = {"status": "unknown", "claimState": "unknown", "heartbeatAt": None, "startedAt": None, "finishedAt": None}
    try:
        valid_marker = marker is not None and _valid_marker(marker, parent)
    except (KeyError, TypeError, ValueError):
        valid_marker = False
    if valid_marker:
        dispatch["status"] = marker.status
        for field, value in (("startedAt", marker.started_at), ("finishedAt", marker.finished_at)):
            stamp = _stored_utc_instant(value)
            if stamp is not None:
                dispatch[field] = stamp.isoformat()
        try:
            if (re.fullmatch(r"mixed-published-dispatch-[0-9a-f]{32}", marker.input.get("claimOwner", "")) is None
                    or re.fullmatch(r"[0-9a-f]{32}", marker.input.get("claimToken", "")) is None):
                raise ValueError("invalid claim identity")
            claimed = datetime.fromisoformat(marker.input["claimClaimedAt"])
            heartbeat = datetime.fromisoformat(marker.input["claimHeartbeatAt"])
            expires = datetime.fromisoformat(marker.input["claimExpiresAt"])
            if claimed.tzinfo is None or heartbeat.tzinfo is None or expires.tzinfo is None or not claimed <= heartbeat <= expires:
                raise ValueError("invalid claim clock")
            dispatch["heartbeatAt"] = heartbeat.isoformat()
            dispatch["claimState"] = "live" if expires > datetime.now(timezone.utc) else "expired"
        except (KeyError, TypeError, ValueError):
            pass
    active = [row for row in jobs if row.status in {"queued", "running"}
              and row.target_id == parent.target_id and row.target_type == "engagement"
              and row.input.get("cleanupParentId" if row.action == "provider_keyed_mixed_published_destroy_apply" else "teardownParentId") == parent.id
              and row.input.get("coreJobId") == parent.input.get("coreJobId")
              and row.action in {"provider_keyed_mixed_published_destroy_apply",
                  "provider_keyed_mixed_zero_apply_core_destroy_preview", "provider_keyed_mixed_zero_apply_core_destroy_apply",
                  "provider_keyed_mixed_zero_apply_core_destroy_absence", "provider_keyed_mixed_zero_apply_inspector_negative",
                  "provider_keyed_mixed_published_selector_retirement", "provider_keyed_mixed_published_inspector_retirement"}]
    core_id = parent.input.get("coreJobId")
    suffix = core_id.removeprefix("job-") if type(core_id) is str else ""
    identities = {
        "provider_keyed_mixed_published_destroy_apply": tuple(f"job-provider-keyed-mixed-published-destroy-{suffix}-{provider}" for provider in ("linode", "digitalocean")),
        "provider_keyed_mixed_zero_apply_core_destroy_preview": (f"job-provider-keyed-mixed-core-destroy-preview-{suffix}",),
        "provider_keyed_mixed_zero_apply_core_destroy_apply": (f"job-provider-keyed-mixed-core-destroy-apply-{suffix}",),
        "provider_keyed_mixed_zero_apply_inspector_negative": (f"job-provider-keyed-mixed-inspector-negative-{suffix}",),
        "provider_keyed_mixed_published_selector_retirement": (f"job-provider-keyed-mixed-published-selector-retirement-{suffix}",),
        "provider_keyed_mixed_published_inspector_retirement": (f"job-provider-keyed-mixed-published-inspector-retirement-{suffix}",),
    }
    active = [row for row in active if row.id in identities.get(row.action, ()) or (
        row.action == "provider_keyed_mixed_zero_apply_core_destroy_absence" and
        re.fullmatch(re.escape(f"job-provider-keyed-mixed-core-destroy-absence-{suffix}-attempt-") + r"[0-9]+", row.id))]
    child = active[0] if len(active) == 1 else None
    return {"dispatch": dispatch, "activeChild": None if child is None else {
        "id": child.id, "action": child.action, "status": child.status,
        "message": child.events[-1].message if child.events else "Waiting for worker"},
        "activeChildState": "ambiguous" if len(active) > 1 else "exact" if child else "absent"}


def _teardown_job_summary(job: StoredJobRun | None,
                          jobs: list[StoredJobRun] | None = None, *, job_repository=None) -> dict[str, Any] | None:
    summary = _job_summary(job)
    if summary is not None:
        if job.action == MIXED_ZERO_APPLY_TEARDOWN_ACTION:
            terminal = job.events[-1] if job.events else None
            summary["recoveryState"] = (
                "in_progress" if job.status in {"queued", "running"} else
                "complete" if job.status == "succeeded" and terminal is not None
                and terminal.message == "mixed zero-Apply teardown complete"
                and terminal.data.get("finalCleanupStatus") == "verified_clean"
                else "blocked")
            phase, progress = _mixed_cleanup_progress(job, jobs or [])
            summary["phase"] = ("complete" if summary["recoveryState"] == "complete"
                                else phase)
            summary["progress"] = ({"completed": 5, "total": 5}
                                   if summary["recoveryState"] == "complete" else progress)
        elif job.action == MIXED_INTERRUPTED_TEARDOWN_ACTION:
            terminal = job.events[-1] if job.events else None
            complete = (job.status == "succeeded" and terminal is not None
                        and terminal.message == "mixed interrupted teardown complete"
                        and terminal.data.get("finalCleanupStatus") == "verified_clean")
            phase, progress = _mixed_interrupted_progress(job, jobs or [])
            summary["recoveryState"] = (
                "complete" if complete else "blocked" if phase == "attention" else
                "in_progress" if job.status in {"queued", "running"}
                else "blocked")
            summary["phase"] = "complete" if complete else phase
            summary["progress"] = ({"completed": progress["total"],
                                    "total": progress["total"]}
                                   if complete else progress)
        elif job.action == MIXED_PUBLISHED_TEARDOWN_ACTION:
            summary.update(_published_dispatch_progress(job, jobs or [], job_repository))
            terminal = job.events[-1] if job.events else None
            complete = (job.status == "succeeded" and terminal is not None
                        and terminal.message == "published mixed teardown complete"
                        and terminal.data.get("finalCleanupStatus") == "verified_clean")
            phase, progress = _mixed_published_progress(job, jobs or [])
            summary["recoveryState"] = (
                "complete" if complete else "blocked" if phase == "attention"
                else "in_progress" if job.status in {"queued", "running"}
                else "blocked")
            summary["phase"] = "complete" if complete else phase
            summary["progress"] = ({"completed": progress["total"],
                                    "total": progress["total"]}
                                   if complete else progress)
        else:
            summary["recoveryState"] = comprehensive_teardown_recovery_state(job)
    return summary


def _health_summary(hosts: list[dict[str, Any]], last_checked_at: str | None) -> dict[str, Any]:
    active_host_count = sum(1 for host in hosts if host.get("lifecycleState") == "active")
    if not hosts:
        status = "unknown"
    elif all(host.get("lifecycleState") == "destroyed" for host in hosts):
        status = "destroyed"
    elif any(host["health"]["status"] in {"attention", "burned"} for host in hosts):
        status = "attention"
    elif all(host["health"]["status"] == "healthy" for host in hosts):
        status = "healthy"
    else:
        status = "unknown"
    return {
        "status": status,
        "lastCheckedAt": last_checked_at,
        "stale": _is_stale(last_checked_at),
        "hostCount": len(hosts),
        "activeHostCount": active_host_count,
        "detail": (
            "Infrastructure has been torn down; rows are retained as last-known deployment history."
            if status == "destroyed"
            else "Last-known deployment validation status; probes are not real-time."
        ),
    }


def _housekeeping_items(engagement_id: str) -> str:
    from app.storage.models import EngagementOperationsModel

    row = EngagementOperationsModel.query.get(engagement_id)
    return "" if row is None else row.housekeeping_items


def _save_housekeeping_items(engagement_id: str, housekeeping_items: str) -> None:
    from app.storage.database import db
    from app.storage.models import EngagementOperationsModel

    row = EngagementOperationsModel.query.get(engagement_id)
    if row is None:
        row = EngagementOperationsModel(engagement_id=engagement_id)
        db.session.add(row)
    row.housekeeping_items = housekeeping_items
    db.session.commit()


def _record_channels_update(
    engagement_id: str,
    outbound_channels: list[dict[str, Any]],
    inbound_channels: list[dict[str, Any]],
) -> None:
    timestamp = _now()
    from app.storage.job_repository import MixedAppendBindingFenceError
    try:
        _job_repository(None).save(
            StoredJobRun(
                id=f"job-{uuid4().hex[:12]}",
                action=CHANNELS_UPDATE_ACTION,
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={"engagementId": engagement_id},
                artifact_refs=[],
                created_at=timestamp,
                started_at=timestamp,
                finished_at=timestamp,
                events=[
                    JobEvent(
                        1,
                        "info",
                        "engagement channels updated",
                        {
                            "outboundChannels": outbound_channels,
                            "inboundChannels": inbound_channels,
                        },
                    )
                ],
            )
        )
    except MixedAppendBindingFenceError as exc:
        raise EngagementOperationsValidationError([str(exc)]) from exc


def _latest_raw_event_rows(engagement_id: str, key: str) -> list[dict[str, Any]]:
    jobs = _engagement_jobs(engagement_id, _job_repository(None))
    job = _latest_job_with_event_key(jobs, key)
    if job is None:
        return []
    for event in reversed(job.events):
        rows = event.data.get(key)
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _normalize_outbound_channels(value: Any) -> list[dict[str, Any]]:
    rows = _channel_rows(value, "outboundChannels")
    normalized = []
    for index, row in enumerate(rows, start=1):
        if not _has_channel_content(row):
            continue
        chain_id = _first_value(row, "chainId", "id")
        generated_id = _generated_id("outbound", index, row, "domain", "proxy", "middle", "edge", "port", "listenerPort")
        channel_id = _first_value(row, "channelId") or chain_id or generated_id
        channel = {
            "channelId": channel_id,
            "chainId": chain_id or channel_id,
            "proxy": _first_value(row, "proxy"),
            "middle": _first_value(row, "middle"),
            "edge": _first_value(row, "edge"),
            "port": _first_value(row, "port", "listenerPort"),
            "region": _first_value(row, "region"),
            "provider": _first_value(row, "provider"),
            "domain": _first_value(row, "domain"),
            "purpose": _first_value(row, "purpose"),
            "status": _first_value(row, "status"),
        }
        normalized.append({**_without_empty_values(channel), **_outbound_compact_metadata(row)})
    return normalized


def _normalize_inbound_channels(value: Any) -> list[dict[str, Any]]:
    rows = _channel_rows(value, "inboundChannels")
    normalized = []
    active_listener_ports: dict[tuple[str, str, str, str], tuple[str, bool]] = {}
    errors: list[str] = []
    for index, row in enumerate(rows, start=1):
        if not _has_channel_content(row):
            continue
        channel = {
            "channelId": _first_value(row, "channelId", "id", "name")
            or _generated_id("inbound", index, row, "domain", "service", "externalPort", "port", "internalPort"),
            "domain": _first_value(row, "domain"),
            "protocol": _first_value(row, "protocol"),
            "mode": _first_value(row, "mode"),
            "externalPort": _first_value(row, "externalPort", "port"),
            "relayPort": _first_value(row, "relayPort", "proxyRelayPort"),
            "middleRelayPort": _first_value(row, "middleRelayPort", "relayPort", "proxyRelayPort"),
            "proxyRelayPort": _first_value(row, "proxyRelayPort", "relayPort"),
            "edge": _first_value(row, "edge"),
            "edgeComponentId": _first_value(row, "edgeComponentId"),
            "middle": _first_value(row, "middle"),
            "middleComponentId": _first_value(row, "middleComponentId"),
            "proxy": _first_value(row, "proxy"),
            "terminatesOn": _first_value(row, "terminatesOn", "destinationHost", "targetHost"),
            "service": _first_value(row, "service", "destinationService"),
            "serviceId": _first_value(row, "serviceId"),
            "serviceType": _first_value(row, "serviceType"),
            "internalPort": _first_value(row, "internalPort", "destinationPort"),
            "purpose": _first_value(row, "purpose"),
            "status": _first_value(row, "status"),
        }
        normalized_channel = {**_without_empty_values(channel), **_inbound_compact_metadata(row)}
        status = normalized_channel.get("status", "").strip().lower()
        shared_web_ingress = _is_shared_web_inbound_channel(normalized_channel)
        edge = normalized_channel.get("edge", "").strip()
        middle = normalized_channel.get("middle", "").strip()
        proxy = normalized_channel.get("proxy", "").strip()
        protocol = (
            "udp"
            if normalized_channel.get("mode", "").strip().lower() == "udp-forward"
            or normalized_channel.get("protocol", "TCP").strip().upper() == "UDP"
            else "tcp"
        )
        edge_identity = normalized_channel.get("edgeComponentId", "").strip() or edge
        middle_identity = normalized_channel.get("middleComponentId", "").strip() or middle
        external_port = normalized_channel.get("externalPort", "").strip()
        middle_relay_port = normalized_channel.get("middleRelayPort", "").strip() or normalized_channel.get("relayPort", "").strip() or external_port
        proxy_relay_port = normalized_channel.get("proxyRelayPort", "").strip() or normalized_channel.get("relayPort", "").strip() or external_port
        if status not in {"disabled", "removed"}:
            for role, identity, host, port in (
                ("edge", edge_identity, edge, external_port),
                ("middle", middle_identity, middle, middle_relay_port),
                ("proxy", proxy, proxy, proxy_relay_port),
            ):
                if not host or not port:
                    continue
                listener = (role, identity, protocol, port)
                existing = active_listener_ports.get(listener)
                if existing:
                    existing_channel_id, existing_shared_web_ingress = existing
                    if not (shared_web_ingress and existing_shared_web_ingress):
                        errors.append(f"inbound channel {normalized_channel['channelId']} conflicts with {existing_channel_id} on {role} {host}:{port}/{protocol}")
                active_listener_ports[listener] = (normalized_channel["channelId"], shared_web_ingress)
        normalized.append(normalized_channel)
    if errors:
        raise EngagementOperationsValidationError(errors)
    return normalized


def _validate_applied_inbound_channel_updates(
    previous_channels: list[dict[str, Any]],
    next_channels: list[dict[str, Any]],
) -> None:
    next_by_id = {str(channel.get("channelId") or "").strip(): channel for channel in next_channels}
    errors: list[str] = []
    for previous in previous_channels:
        channel_id = str(previous.get("channelId") or "").strip()
        if not channel_id or not _inbound_channel_has_live_artifacts(previous):
            continue
        current = next_by_id.get(channel_id)
        if current is None:
            errors.append(f"applied inbound channel {channel_id} must be removed with the inbound channel remove workflow before deleting the record")
            continue
        next_status = str(current.get("status") or "").strip().lower()
        if next_status not in APPLIED_INBOUND_CHANNEL_STATUSES:
            errors.append(f"applied inbound channel {channel_id} must be removed with the inbound channel remove workflow before changing status to {current.get('status') or 'blank'}")
        changed_fields = [
            field
            for field in INBOUND_ROUTE_SHAPE_FIELDS
            if _inbound_route_shape_value(previous, field) != _inbound_route_shape_value(current, field)
        ]
        if changed_fields:
            errors.append(
                f"applied inbound channel {channel_id} cannot change live route fields {', '.join(changed_fields)}; remove it first, then record a new channel"
            )
    if errors:
        raise EngagementOperationsValidationError(errors)


def _inbound_channel_has_live_artifacts(channel: dict[str, Any]) -> bool:
    return str(channel.get("status") or "").strip().lower() in APPLIED_INBOUND_CHANNEL_STATUSES


def _inbound_route_shape_value(channel: dict[str, Any], field: str) -> str:
    value = str(channel.get(field) or "").strip()
    if field == "mode" and not value:
        return "tcp-forward"
    if field == "protocol":
        return value.upper()
    return value


def _channel_rows(value: Any, field_name: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise EngagementOperationsValidationError([f"{field_name} must be an array"])
    errors = [
        f"{field_name}[{index}] must be an object"
        for index, row in enumerate(value)
        if not isinstance(row, dict)
    ]
    if errors:
        raise EngagementOperationsValidationError(errors)
    return value


def _has_channel_content(row: dict[str, Any]) -> bool:
    return any(_string(value).strip() for value in row.values() if not isinstance(value, (dict, list)))


def _first_value(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = _string(row.get(key)).strip()
        if value:
            return value
    return ""


def _generated_id(prefix: str, index: int, row: dict[str, Any], *keys: str) -> str:
    parts = [_slug_part(_first_value(row, key)) for key in keys]
    slug = "-".join(part for part in parts if part)
    return f"{prefix}-{slug}" if slug else f"{prefix}-{index:02d}"


def _slug_part(value: str) -> str:
    cleaned = "".join(character.lower() if character.isalnum() else "-" for character in value)
    return "-".join(part for part in cleaned.split("-") if part)


def _without_empty_values(row: dict[str, str]) -> dict[str, str]:
    return {key: value for key, value in row.items() if value}


def _outbound_compact_metadata(row: dict[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    edge_index = _safe_compact_text(row.get("edgeIndex"))
    if edge_index:
        metadata["edgeIndex"] = edge_index
    edge_count = _safe_compact_text(row.get("edgeCount"))
    if edge_count:
        metadata["edgeCount"] = edge_count
    profile_name = _safe_compact_text(row.get("profileName"))
    if profile_name:
        metadata["profileName"] = profile_name
    publication_path = _safe_compact_text(row.get("publicationPath"))
    if publication_path:
        metadata["publicationPath"] = publication_path
    validation = _compact_validation(row.get("validation"))
    if validation:
        metadata["validation"] = validation
    artifact_targets = _compact_artifact_targets(row.get("artifactTargets"))
    if artifact_targets:
        metadata["artifactTargets"] = artifact_targets
    return metadata


def _outbound_row_identity(row: dict[str, Any]) -> str:
    channel_id = _string(row.get("channelId")).strip()
    if channel_id and channel_id != "N/A":
        return channel_id
    chain_id = _string(row.get("chainId")).strip()
    if not chain_id or chain_id == "N/A":
        return ""
    edge = _string(row.get("edge")).strip()
    if edge and edge != "Not Deployed":
        return f"{chain_id}::{edge}"
    return chain_id


def _compact_inbound_certificate(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    compact: dict[str, Any] = {}
    for field in INBOUND_CERTIFICATE_SCALAR_FIELDS:
        text = _safe_metadata_text(value.get(field), field)
        if text:
            compact[field] = text
    paths = value.get("paths")
    if isinstance(paths, dict):
        compact_paths = {
            field: _safe_metadata_text(paths.get(field), f"certificate.paths.{field}", preserve_edges=True)
            for field in INBOUND_CERTIFICATE_PATH_FIELDS
        }
        compact_paths = {key: val for key, val in compact_paths.items() if val}
        if compact_paths:
            compact["paths"] = compact_paths
    prereqs = value.get("prerequisites")
    if isinstance(prereqs, dict):
        compact_prereqs = {
            field: _safe_metadata_text(prereqs.get(field), f"certificate.prerequisites.{field}", preserve_edges=True)
            for field in INBOUND_CERTIFICATE_PREREQ_FIELDS
        }
        compact_prereqs = {key: val for key, val in compact_prereqs.items() if val}
        checks = prereqs.get("checks")
        if isinstance(checks, list):
            compact_checks = [_compact_certificate_check(check) for check in checks if isinstance(check, dict)]
            if compact_checks:
                compact_prereqs["checks"] = compact_checks
        if compact_prereqs:
            compact["prerequisites"] = compact_prereqs
    return compact


def _compact_certificate_check(value: dict[str, Any]) -> dict[str, str]:
    fields = ("id", "label", "status", "detail", "correctiveAction")
    compact = {
        field: _safe_metadata_text(value.get(field), f"certificate.prerequisites.checks.{field}", preserve_edges=True)
        for field in fields
    }
    return {key: val for key, val in compact.items() if val}


def _compact_certificate_support(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    compact = {
        field: _safe_metadata_text(value.get(field), f"certificateSupport.{field}", preserve_edges=True)
        for field in INBOUND_CERTIFICATE_SUPPORT_FIELDS
    }
    return {key: val for key, val in compact.items() if val}


def _inbound_compact_metadata(row: dict[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    chain_id = _safe_metadata_text(row.get("chainId"), "chainId")
    if chain_id:
        metadata["chainId"] = chain_id
    backend_port = _safe_metadata_text(row.get("backendPort"), "backendPort")
    if backend_port:
        metadata["backendPort"] = backend_port
    batch_id = _safe_metadata_text(row.get("batchId"), "batchId")
    if batch_id:
        metadata["batchId"] = batch_id
    route_family = _safe_metadata_text(row.get("routeFamily"), "routeFamily")
    if route_family:
        metadata["routeFamily"] = route_family
    if isinstance(row.get("sharedWebIngress"), bool):
        metadata["sharedWebIngress"] = bool(row.get("sharedWebIngress"))
    routing_owner = _safe_metadata_text(row.get("routingOwner"), "routingOwner")
    if routing_owner:
        metadata["routingOwner"] = routing_owner
    validation_profile = _compact_validation_profile(row.get("validationProfile"))
    if validation_profile:
        metadata["validationProfile"] = validation_profile
    validation = _compact_validation(row.get("validation"), fields=INBOUND_VALIDATION_SCALAR_FIELDS)
    if validation:
        metadata["validation"] = validation
    artifact_targets = _compact_artifact_targets(row.get("artifactTargets"))
    if artifact_targets:
        metadata["artifactTargets"] = artifact_targets
    certificate = _compact_inbound_certificate(row.get("certificate"))
    if certificate:
        metadata["certificate"] = certificate
    certificate_support = _compact_certificate_support(row.get("certificateSupport"))
    if certificate_support:
        metadata["certificateSupport"] = certificate_support
    try:
        metadata.update(raw_route_metadata(row))
    except InboundRawRoutePlanError as exc:
        raise EngagementOperationsValidationError(exc.errors) from exc
    return metadata


def _is_shared_web_inbound_channel(row: dict[str, Any]) -> bool:
    if row.get("sharedWebIngress") is True:
        return True
    if _string(row.get("routeFamily")).strip().lower() == "shared-web-ingress":
        return True
    mode = _string(row.get("mode")).strip().lower()
    service = _string(row.get("service")).strip().lower()
    service_type = _string(row.get("serviceType")).strip().lower()
    return mode == "https-openresty" or service_type == "web-static" or service == "static web"


def _compact_validation_profile(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    compact: dict[str, str] = {}
    profile_type = _safe_validation_profile_text(value.get("type"), "type") or "temporary-listener"
    if profile_type not in SUPPORTED_INBOUND_VALIDATION_PROFILE_TYPES:
        raise EngagementOperationsValidationError(
            ["validationProfile.type must be temporary-listener, tcp-send-receive, udp-send-receive, tcp-connect, http, or manual"]
        )
    compact["type"] = profile_type
    label = _safe_validation_profile_text(value.get("label"), "label")
    if label:
        compact["label"] = label
    request_text = _safe_validation_profile_text(value.get("requestText"), "requestText", preserve_edges=True)
    expected_response = _safe_validation_profile_text(value.get("expectedResponse"), "expectedResponse", preserve_edges=True)
    if profile_type in {"tcp-send-receive", "udp-send-receive"} and not expected_response:
        raise EngagementOperationsValidationError(["validationProfile.expectedResponse is required for tcp-send-receive and udp-send-receive"])
    if profile_type == "udp-send-receive" and not request_text:
        raise EngagementOperationsValidationError(["validationProfile.requestText is required for udp-send-receive"])
    if request_text:
        compact["requestText"] = request_text
    if expected_response:
        compact["expectedResponse"] = expected_response
    return compact


def _safe_validation_profile_text(value: Any, field_name: str, *, preserve_edges: bool = False) -> str:
    if isinstance(value, (dict, list)):
        return ""
    text = _string(value)
    normalized = text.strip()
    if not normalized:
        return ""
    if "\x00" in text:
        raise EngagementOperationsValidationError([f"validationProfile.{field_name} must not contain null bytes"])
    if _looks_secretish_value(text):
        raise EngagementOperationsValidationError([f"validationProfile.{field_name} appears to contain credential material"])
    return text if preserve_edges else normalized


def _safe_metadata_text(value: Any, field_name: str, *, preserve_edges: bool = False) -> str:
    if isinstance(value, (dict, list)):
        return ""
    text = _string(value)
    normalized = text.strip()
    if not normalized:
        return ""
    if "\x00" in text:
        raise EngagementOperationsValidationError([f"{field_name} must not contain null bytes"])
    if _looks_secretish_value(text):
        raise EngagementOperationsValidationError([f"{field_name} appears to contain credential material"])
    return text if preserve_edges else normalized


def _compact_validation(value: Any, fields: tuple[str, ...] = OUTBOUND_VALIDATION_SCALAR_FIELDS) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    compact: dict[str, Any] = {}
    for key in fields:
        raw_value = value.get(key)
        if isinstance(raw_value, bool):
            compact[key] = raw_value
            continue
        field_value = _safe_compact_text(raw_value)
        if field_value:
            compact[key] = field_value
    for command_key in ("command", "listenerCommand", "probeCommand"):
        command = value.get(command_key)
        if isinstance(command, list):
            command_values = [_safe_compact_text(item) for item in command]
            if command_values and all(command_values):
                compact[command_key] = command_values
    return compact


def _compact_artifact_targets(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    compact = {}
    for key, target in value.items():
        if not isinstance(key, str) or _is_secretish_key(key):
            continue
        target_value = _safe_compact_text(target)
        if target_value:
            compact[key] = target_value
    return compact


def _safe_compact_text(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return ""
    text = _string(value).strip()
    if not text or _looks_secretish_value(text):
        return ""
    return text


def _is_secretish_key(key: str) -> bool:
    normalized = "".join(character.lower() if character.isalnum() else "_" for character in key)
    return any(part in normalized for part in SECRETISH_KEY_PARTS)


def _looks_secretish_value(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in SECRETISH_VALUE_MARKERS_LOWER) or any(
        pattern.search(value) for pattern in SECRETISH_VALUE_PATTERNS
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _last_checked_at(job: StoredJobRun | None) -> str | None:
    if job is None:
        return None
    return job.finished_at or job.started_at or job.created_at


def _is_stale(value: str | None) -> bool:
    if not value:
        return False
    checked_at = _parse_timestamp(value)
    if checked_at is None:
        return False
    return datetime.now(timezone.utc) - checked_at > PROBE_STALE_AFTER


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _field(row: dict[str, Any], *keys: str, fallback: str) -> str:
    for key in keys:
        value = _string(row.get(key)).strip()
        if value:
            return value
    return fallback


def _string(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item is not None and str(item)]
