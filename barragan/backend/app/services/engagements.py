# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import replace
from typing import Any
from uuid import uuid4

from app.core.runtime import runtime_value
from app.domain import EngagementDetail, EngagementSummary
from app.integrations.oci_deployment_targets import (
    OciDeploymentTargetError,
    normalized_oci_deployment_target,
    resolve_oci_deployment_target,
)
from app.services.catalog import validate_template_input
from app.services import provider_reconciliation
from app.services.provider_region_policy import DEFAULT_ALLOWED_REGIONS
from app.storage.engagement_repository import (
    EngagementRepository,
    SqlAlchemyEngagementRepository,
    StoredEngagement,
)
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.observer_settings_repository import (
    DEFAULT_INSPECTOR_CHECK_FAMILIES,
    DEFAULT_INSPECTOR_MODE,
    DEFAULT_INSPECTOR_SCHEDULE_TIME_UTC,
    DEFAULT_INSPECTOR_SCHEDULE_WEEKDAYS,
    SqlAlchemyObserverSettingsRepository,
    StoredObserverSettings,
)
from app.storage.provider_resource_repository import ProviderResourceRepository, SqlAlchemyProviderResourceRepository


class EngagementValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("engagement validation failed")
        self.errors = errors


class ActiveInfrastructureError(ValueError):
    def __init__(
        self,
        engagement_id: str,
        job_id: str = "",
        orphan_candidates: list[dict[str, Any]] | None = None,
        provider_records: list[dict[str, Any]] | None = None,
        lifecycle: dict[str, Any] | None = None,
    ):
        message = "Engagement has active infrastructure. Tear down the infrastructure before archiving or retiring the engagement."
        if orphan_candidates:
            message = (
                "Provider inventory reports active infrastructure for this engagement. "
                "Reconcile or tear down the provider resources before archiving or retiring the engagement."
            )
        if provider_records:
            message = (
                "Barragan has tracked provider resource records for this engagement. "
                "Mark them destroyed or tear them down before archiving or retiring the engagement."
            )
        super().__init__(message)
        self.engagement_id = engagement_id
        self.job_id = job_id
        self.orphan_candidates = orphan_candidates or []
        self.provider_records = provider_records or []
        self.lifecycle = lifecycle or {}


INACTIVE_STATUSES = {"archived", "retired"}
PILOT_JOB_ACTION = "pilot_standard_rti_guarded_execute"


def list_engagements(
    repository: EngagementRepository | None = None,
    include_inactive: bool = False,
) -> list[EngagementSummary]:
    engagements = _repository(repository).list()
    if not include_inactive:
        engagements = [engagement for engagement in engagements if engagement.status not in INACTIVE_STATUSES]
    return [
        replace(
            engagement.to_summary(),
            lifecycle=_lifecycle_for(engagement.id, engagement.status, repository=repository),
        )
        for engagement in engagements
    ]


def get_engagement(engagement_id: str, repository: EngagementRepository | None = None) -> EngagementDetail | None:
    engagement = _repository(repository).get(engagement_id)
    if engagement is None:
        return None
    return replace(
        engagement.to_detail(),
        lifecycle=_lifecycle_for(engagement.id, engagement.status, repository=repository),
    )


def create_draft_engagement(
    payload: dict[str, Any],
    repository: EngagementRepository | None = None,
) -> EngagementDetail:
    template_id = str(payload.get("templateId", "")).strip()
    owner = str(payload.get("owner", "unassigned")).strip()
    name = str(payload.get("name", "")).strip()
    description = str(payload.get("description", "")).strip()
    documentation_url = str(payload.get("documentationUrl", "")).strip()
    jira_url = str(payload.get("jiraUrl", "")).strip()
    input_parameters = dict(payload.get("inputParameters", {}))

    errors = []
    schema = payload.get("sketchStateSchema", "split-v1")
    _validate_sketch_schema(schema, None, errors)
    if not owner:
        errors.append("owner is required")
    if not template_id and not name:
        errors.append("name is required")

    validation = None
    if template_id:
        validation = validate_template_input(template_id, input_parameters)
        errors.extend(validation.errors)
        if validation.valid and repository is None:
            _validate_runtime_deployment_target(validation.normalized, errors)
        if validation.valid:
            _validate_sketch_schema(schema, validation.normalized, errors)
            from app.services.sketch_chains import validate_template_sketch_chain_intents

            errors.extend(
                validate_template_sketch_chain_intents(
                    validation.normalized,
                    use_runtime_region_policy=repository is None,
                )
            )
    if errors:
        raise EngagementValidationError(errors)

    engagement = StoredEngagement(
        id=f"eng-{uuid4().hex[:12]}",
        name=validation.normalized["engagementName"] if validation else name,
        status="draft",
        owner=owner,
        template_id=template_id,
        active_revision=None,
        input_parameters=validation.normalized if validation else {},
        sketch_state_schema=schema,
        description=description,
        documentation_url=documentation_url,
        jira_url=jira_url,
    )
    saved = _repository(repository).save(engagement).to_detail()
    if repository is None:
        from app.services.sketch_chains import seed_template_sketch_chains

        seed_template_sketch_chains(saved.id, engagement.input_parameters)
        _create_default_inspector_settings(saved.id)
    return saved


def update_engagement_metadata(
    engagement_id: str,
    payload: dict[str, Any],
    repository: EngagementRepository | None = None,
) -> EngagementDetail | None:
    repo = _repository(repository)
    current = repo.get(engagement_id)
    if current is None:
        return None

    name = str(payload.get("name", current.name)).strip()
    owner = str(payload.get("owner", current.owner)).strip()
    description = str(payload.get("description", current.description)).strip()
    documentation_url = str(payload.get("documentationUrl", current.documentation_url)).strip()
    jira_url = str(payload.get("jiraUrl", current.jira_url)).strip()

    errors = []
    if not name:
        errors.append("name is required")
    if not owner:
        errors.append("owner is required")
    if errors:
        raise EngagementValidationError(errors)

    updated = repo.update_metadata(
        engagement_id,
        name=name,
        owner=owner,
        description=description,
        documentation_url=documentation_url,
        jira_url=jira_url,
    )
    return updated.to_detail() if updated else None


def archive_engagement(
    engagement_id: str,
    repository: EngagementRepository | None = None,
    job_repository: JobRepository | None = None,
    provider_resource_repository: ProviderResourceRepository | None = None,
) -> EngagementDetail | None:
    repo = _repository(repository)
    current = repo.get(engagement_id)
    if current is None:
        return None
    from app.services.engagement_lifecycle import assert_administrative_transition_allowed

    try:
        assert_administrative_transition_allowed(
            engagement_id,
            "archived",
            administrative_status=current.status,
            job_repository=job_repository,
            provider_resource_repository=provider_resource_repository,
            use_runtime_repositories=repository is None,
        )
    except Exception as exc:
        from app.services.engagement_lifecycle import UnsafeLifecycleTransitionError

        if not isinstance(exc, UnsafeLifecycleTransitionError):
            raise
        job_id = next((str(row.get("id")) for row in exc.lifecycle["evidence"] if row.get("kind") == "core_job"), "")
        raise ActiveInfrastructureError(engagement_id, job_id=job_id, lifecycle=exc.lifecycle) from exc
    engagement = repo.update_status(engagement_id, "archived")
    return replace(
        engagement.to_detail(),
        lifecycle=_lifecycle_for(engagement_id, "archived", repository=repository),
    ) if engagement else None


def retire_engagement(
    engagement_id: str,
    repository: EngagementRepository | None = None,
    job_repository: JobRepository | None = None,
    provider_resource_repository: ProviderResourceRepository | None = None,
) -> EngagementDetail | None:
    repo = _repository(repository)
    current = repo.get(engagement_id)
    if current is None:
        return None
    from app.services.engagement_lifecycle import assert_administrative_transition_allowed

    try:
        assert_administrative_transition_allowed(
            engagement_id,
            "retired",
            administrative_status=current.status,
            job_repository=job_repository,
            provider_resource_repository=provider_resource_repository,
            use_runtime_repositories=repository is None,
        )
    except Exception as exc:
        from app.services.engagement_lifecycle import UnsafeLifecycleTransitionError

        if not isinstance(exc, UnsafeLifecycleTransitionError):
            raise
        job_id = next((str(row.get("id")) for row in exc.lifecycle["evidence"] if row.get("kind") == "core_job"), "")
        raise ActiveInfrastructureError(engagement_id, job_id=job_id, lifecycle=exc.lifecycle) from exc
    engagement = repo.update_status(engagement_id, "retired")
    return replace(
        engagement.to_detail(),
        lifecycle=_lifecycle_for(engagement_id, "retired", repository=repository),
    ) if engagement else None


def configure_engagement_infrastructure(
    engagement_id: str,
    payload: dict[str, Any],
    repository: EngagementRepository | None = None,
) -> EngagementDetail | None:
    template_id = str(payload.get("templateId", "")).strip()
    input_parameters = dict(payload.get("inputParameters", {}))

    errors = []
    if not template_id:
        errors.append("templateId is required")
    validation = validate_template_input(template_id, input_parameters) if template_id else None
    if validation:
        errors.extend(validation.errors)
        if validation.valid and repository is None:
            _validate_runtime_deployment_target(validation.normalized, errors)
        if validation.valid:
            from app.services.sketch_chains import validate_template_sketch_chain_intents

            errors.extend(
                validate_template_sketch_chain_intents(
                    validation.normalized,
                    use_runtime_region_policy=repository is None,
                )
            )
    if errors:
        raise EngagementValidationError(errors)

    current = _repository(repository).get(engagement_id)
    if current is None:
        return None
    if "sketchStateSchema" in payload and payload["sketchStateSchema"] != current.sketch_state_schema:
        raise EngagementValidationError(["Sketch state schema is immutable after engagement creation"])
    scope_errors: list[str] = []
    _validate_sketch_schema(current.sketch_state_schema, validation.normalized if validation else None, scope_errors)
    if scope_errors:
        raise EngagementValidationError(scope_errors)
    current_target = normalized_oci_deployment_target(current.input_parameters.get("deploymentTarget"))
    next_target = normalized_oci_deployment_target(validation.normalized.get("deploymentTarget") if validation else None)
    if current_target != next_target and current.status not in {"draft", "planned"}:
        raise EngagementValidationError(
            ["deploymentTarget cannot change after infrastructure deployment has started"]
        )

    engagement = _repository(repository).configure_infrastructure(
        engagement_id,
        template_id=template_id,
        input_parameters=validation.normalized if validation else {},
    )
    if engagement is not None and repository is None:
        from app.services.sketch_chains import seed_template_sketch_chains

        seed_template_sketch_chains(engagement_id, engagement.input_parameters)
    return engagement.to_detail() if engagement else None


def _validate_runtime_deployment_target(parameters: dict[str, Any], errors: list[str]) -> None:
    try:
        environment = str(runtime_value("ENVIRONMENT", "local") or "local")
        resolve_oci_deployment_target(parameters.get("deploymentTarget"), environment=environment)
    except (OciDeploymentTargetError, RuntimeError) as exc:
        errors.append(str(exc))


def _validate_sketch_schema(schema: str, parameters: dict[str, Any] | None, errors: list[str]) -> None:
    if schema == "split-v1":
        return
    if schema != "provider-keyed-v2":
        errors.append("unsupported Sketch state schema")
        return
    try:
        environment = str(runtime_value("ENVIRONMENT", "local") or "local")
    except RuntimeError:
        environment = "local"
    if environment != "devtest":
        errors.append("provider-keyed-v2 is available only in DevTest")
    if parameters is None:
        return
    try:
        target = normalized_oci_deployment_target(parameters.get("deploymentTarget"))
    except OciDeploymentTargetError:
        errors.append("provider-keyed-v2 requires the barragan-testing deployment target")
        return
    if target["name"] != "barragan-testing":
        errors.append("provider-keyed-v2 requires the barragan-testing deployment target")
    chains = parameters.get("sketchChains")
    if (not isinstance(chains, list) or len(chains) != 2
            or any(not isinstance(chain, dict) for chain in chains)
            or [chain.get("middleProvider") for chain in chains] not in (
                ["digitalocean", "digitalocean"], ["digitalocean", "linode"],
                ["linode", "digitalocean"])
            or any(
                chain.get("edgeProvider") != chain.get("middleProvider")
                or not isinstance(chain.get("edges", []), list)
                or any(not isinstance(edge, dict)
                       or edge.get("provider") != chain.get("middleProvider")
                       for edge in chain.get("edges", []))
                for chain in chains)):
        errors.append("provider-keyed-v2 pilot requires exactly two same-provider Sketch chains: "
                      "both DigitalOcean or one Linode and one DigitalOcean")


def _repository(repository: EngagementRepository | None) -> EngagementRepository:
    return repository or SqlAlchemyEngagementRepository()


def _lifecycle_for(
    engagement_id: str,
    administrative_status: str,
    *,
    repository: EngagementRepository | None,
) -> dict[str, Any] | None:
    # Unit-level repository injections intentionally stay independent from the
    # runtime database. API/runtime reads always include the durable projection.
    if repository is not None:
        return None
    from app.services.engagement_lifecycle import get_engagement_lifecycle

    return get_engagement_lifecycle(engagement_id, administrative_status=administrative_status)


def _create_default_inspector_settings(engagement_id: str) -> None:
    now = _now()
    SqlAlchemyObserverSettingsRepository().save(
        StoredObserverSettings(
            engagement_id=engagement_id,
            enabled=True,
            provider="linode",
            region=DEFAULT_ALLOWED_REGIONS["linode"][0],
            size="g6-nanode-1",
            mode=DEFAULT_INSPECTOR_MODE,
            schedule_weekdays=list(DEFAULT_INSPECTOR_SCHEDULE_WEEKDAYS),
            schedule_time_utc=DEFAULT_INSPECTOR_SCHEDULE_TIME_UTC,
            check_families=list(DEFAULT_INSPECTOR_CHECK_FAMILIES),
            forbidden_tcp_ports=[2222, 5000, 5173, 5900],
            port_scan_profiles=[],
            current_host={},
            idle_retention_until="",
            last_scheduled_slot="",
            last_mutation_job_inspected="",
            created_at=now,
            updated_at=now,
        )
    )


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _active_infrastructure_job(
    engagement_id: str,
    job_repository: JobRepository | None = None,
) -> StoredJobRun | None:
    for job in (job_repository or SqlAlchemyJobRepository()).list():
        if job.action != PILOT_JOB_ACTION or job.input.get("engagementId") != engagement_id:
            continue
        if job.status in {"queued", "running"}:
            return job
        final_cleanup_status = _latest_event_value(job, "finalCleanupStatus")
        mutation_status = _latest_event_value(job, "mutationStatus")
        if final_cleanup_status == "pending_operator_teardown":
            return job
        if final_cleanup_status == "verified_clean" and job.status != "succeeded" and _inspector_teardown_gate_failed(job):
            return job
        if job.status == "succeeded" and mutation_status == "deployed" and final_cleanup_status != "verified_clean":
            return job
    return None


def _inspector_teardown_gate_failed(job: StoredJobRun) -> bool:
    verification = _latest_event_value(job, "inspectorTeardownVerification")
    cleanup = _latest_event_value(job, "inspectorCleanup")
    for value in (verification, cleanup):
        if isinstance(value, dict) and value.get("ok") is False:
            return True
    for event in job.events:
        if event.message in {
            "Inspector teardown verification failed",
            "Inspector cleanup failed",
        }:
            return True
    return False


def _active_infrastructure(
    engagement_id: str,
    repository: EngagementRepository | None = None,
    job_repository: JobRepository | None = None,
    provider_resource_repository: ProviderResourceRepository | None = None,
) -> tuple[StoredJobRun | None, list[dict[str, Any]]]:
    job_repo = job_repository or SqlAlchemyJobRepository()
    active_job = _active_infrastructure_job(engagement_id, job_repo)
    if active_job is not None:
        return active_job, []
    provider_resource_repo = provider_resource_repository or (
        SqlAlchemyProviderResourceRepository() if repository is None and job_repository is None else None
    )
    provider_records = []
    if provider_resource_repo is not None:
        provider_records = [
            record.to_dict()
            for record in provider_resource_repo.list_for_engagement(engagement_id)
            if str(record.status or "").lower() not in {"destroyed", "deleted", "retired", "absent"}
        ]
    if provider_records:
        raise ActiveInfrastructureError(engagement_id, provider_records=provider_records)
    engagements = _repository(repository).list()
    jobs = job_repo.list()
    local_provider_resources = [record.provider_resource_dict() for record in provider_resource_repo.list_active()] if provider_resource_repo is not None else []
    return None, provider_reconciliation.orphan_candidates_for_engagement(
        engagement_id,
        engagements,
        jobs,
        local_provider_resources=local_provider_resources,
    )


def _latest_event_value(job: StoredJobRun, key: str) -> Any:
    event = next((entry for entry in reversed(job.events) if entry.data.get(key) is not None), None)
    return event.data.get(key) if event is not None else None
