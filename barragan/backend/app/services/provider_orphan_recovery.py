# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import subprocess
from typing import Any, Callable
from uuid import uuid4

from app.core.runtime import start_runtime_task
from app.domain import JobEvent
from app.integrations.oci_read_validation import OciDevelopmentTarget, OciSafetyError, resolve_oci_cli
from app.services import provider_reconciliation
from app.services.provider_catalog import ProviderCatalogError, ProviderCatalogTransport, UrllibProviderCatalogTransport
from app.storage.engagement_repository import EngagementRepository, SqlAlchemyEngagementRepository
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.provider_resource_repository import (
    ProviderResourceRepository,
    SqlAlchemyProviderResourceRepository,
    StoredProviderResourceRecord,
)


RECOVERY_ACTIONS = {"track", "adopt", "mark_destroyed", "tear_down"}
NON_MUTATING_ACTIONS = {"track", "adopt", "mark_destroyed"}
OCI_MUTATION_TIMEOUT_SECONDS = 60
BackgroundRunner = Callable[[Callable[[], None]], None]


class ProviderOrphanRecoveryError(ValueError):
    def __init__(self, errors: list[str], *, status_code: int = 400, job: StoredJobRun | None = None):
        super().__init__("provider orphan recovery validation failed")
        self.errors = errors
        self.status_code = status_code
        self.job = job


@dataclass(frozen=True)
class ProviderOrphanRecoveryResult:
    candidate: dict[str, Any]
    job: StoredJobRun
    status: str
    confirmation_token: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate": self.candidate,
            "job": self.job.to_detail().to_dict(),
            "status": self.status,
            "confirmationToken": self.confirmation_token,
        }


@dataclass(frozen=True)
class OciTeardownResult:
    resources: list[dict[str, Any]]
    commands: list[list[str]]
    verification_commands: list[list[str]]


OCI_TEARDOWN_RESOURCE_TYPES = {
    "compute_instance",
    "subnet",
    "route_table",
    "internet_gateway",
    "security_list",
    "vcn",
}
OCI_GROUPED_VCN_TEARDOWN_ORDER = {
    "compute_instance": 10,
    "subnet": 20,
    "route_table": 30,
    "internet_gateway": 40,
    "security_list": 50,
    "vcn": 60,
}
OCI_TERMINAL_LIFECYCLE_STATES = {"deleted", "deleting", "terminated", "terminating"}


def recover_provider_orphan_candidate(
    body: dict[str, Any],
    *,
    engagement_repository: EngagementRepository | None = None,
    job_repository: JobRepository | None = None,
    provider_resource_repository: ProviderResourceRepository | None = None,
    provider_resources: list[dict[str, Any]] | None = None,
    transport: ProviderCatalogTransport | None = None,
    background_runner: BackgroundRunner | None = None,
) -> ProviderOrphanRecoveryResult:
    action = str(body.get("action") or "").strip().lower()
    if action == "adopt":
        action = "track"
    candidate_id = str(body.get("candidateId") or "").strip()
    requested_by = str(body.get("requestedBy") or "operator").strip() or "operator"
    mutation = bool(body.get("mutation"))
    confirmation = str(body.get("confirmation") or "").strip()

    errors = []
    if not candidate_id:
        errors.append("candidateId is required")
    if action not in RECOVERY_ACTIONS:
        errors.append("action must be one of: track, mark_destroyed, tear_down")
    if mutation and action in NON_MUTATING_ACTIONS:
        errors.append(f"{action} is a non-mutating recovery note action")
    if errors:
        raise ProviderOrphanRecoveryError(errors)

    engagement_repo = engagement_repository or SqlAlchemyEngagementRepository()
    job_repo = job_repository or SqlAlchemyJobRepository()
    provider_resource_repo = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    engagements = engagement_repo.list()
    jobs = job_repo.list()
    local_provider_resources = [record.provider_resource_dict() for record in provider_resource_repo.list_active()]
    reconciliation = provider_reconciliation.reconcile_provider_inventory(
        engagements,
        jobs,
        provider_resources,
        local_provider_resources,
    )
    candidate = next((row for row in reconciliation.orphan_candidates if row.get("candidateId") == candidate_id), None)
    if candidate is None:
        raise ProviderOrphanRecoveryError(["orphan candidate is no longer present in provider reconciliation"], status_code=404)
    allowed_actions = {str(candidate_action) for candidate_action in candidate.get("actions", [])}
    if action not in allowed_actions:
        raise ProviderOrphanRecoveryError(
            [f"{action} is not available for this provider reconciliation finding"],
            status_code=400,
        )

    confirmation_token = confirmation_token_for_candidate(candidate)
    if action == "tear_down" and mutation and confirmation != confirmation_token:
        raise ProviderOrphanRecoveryError([f"confirmation must be {confirmation_token}"], status_code=400)

    if action == "track":
        job = _record_tracking(candidate, requested_by, job_repo, provider_resource_repo)
        return ProviderOrphanRecoveryResult(candidate=candidate, job=job, status="tracked", confirmation_token=confirmation_token)

    if action == "mark_destroyed":
        job = _record_mark_destroyed_note(candidate, requested_by, job_repo)
        return ProviderOrphanRecoveryResult(candidate=candidate, job=job, status="recorded", confirmation_token=confirmation_token)

    if not mutation:
        job = _record_teardown_plan(candidate, requested_by, job_repo, confirmation_token)
        return ProviderOrphanRecoveryResult(candidate=candidate, job=job, status="planned", confirmation_token=confirmation_token)

    job = _save_job(
        job_repo,
        action="provider_orphan_teardown",
        requested_by=requested_by,
        candidate=candidate,
        status="running",
        events=[_event(1, "info", "provider orphan teardown requested", {"candidate": candidate, "mutation": True})],
    )
    task_runner = background_runner or _start_background_task
    task_runner(
        lambda: _run_provider_teardown(
            candidate,
            requested_by,
            job_repo,
            transport,
            reconciliation.orphan_candidates,
            job_id=job.id,
        )
    )
    job = job_repo.get(job.id) or job
    return ProviderOrphanRecoveryResult(candidate=candidate, job=job, status=job.status, confirmation_token=confirmation_token)


def _start_background_task(task: Callable[[], None]) -> None:
    start_runtime_task(
        task,
        name="barragan-provider-orphan-teardown",
        synchronous_when_testing=True,
    )


def confirmation_token_for_candidate(candidate: dict[str, Any]) -> str:
    safe = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(candidate.get("candidateId") or "resource"))
    safe = "-".join(part for part in safe.split("-") if part)
    return f"tear-down-{safe or 'resource'}"


def _record_tracking(
    candidate: dict[str, Any],
    requested_by: str,
    repository: JobRepository,
    provider_resource_repository: ProviderResourceRepository,
) -> StoredJobRun:
    engagement_id = str(candidate.get("engagementId") or "").strip()
    if not engagement_id:
        raise ProviderOrphanRecoveryError(["tracking requires a matching local engagement"])

    now = datetime.now(timezone.utc).isoformat()
    provisional_job_id = f"job-{uuid4().hex[:12]}"
    provider_record = _provider_record_from_candidate(candidate, provisional_job_id, now)
    provider_resource_repository.save(provider_record)
    return _save_job(
        repository,
        job_id=provisional_job_id,
        action="provider_orphan_track",
        requested_by=requested_by,
        candidate=candidate,
        status="succeeded",
        events=[
            _event(
                1,
                "info",
                "provider resource tracked in Barragan records",
                {
                    "candidate": candidate,
                    "providerRecord": provider_record.to_dict(),
                    "mutation": False,
                    "trackingMode": "visibility_only",
                },
            )
        ],
    )


def _provider_record_from_candidate(candidate: dict[str, Any], adoption_job_id: str, timestamp: str) -> StoredProviderResourceRecord:
    candidate_metadata = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
    barragan_owned = bool(candidate_metadata.get("barraganOwned"))
    metadata = {
        "barraganOwned": barragan_owned,
        "trackedFrom": "provider_orphan_reconciliation",
        "trackingMode": "visibility_only",
        "classification": str(candidate.get("classification") or ("barragan_orphan" if barragan_owned else "unmanaged_rti")),
        "publicIps": candidate.get("publicIps") if isinstance(candidate.get("publicIps"), list) else [],
    }
    compartment_id = str(candidate_metadata.get("compartmentId") or "").strip()
    if compartment_id:
        metadata["compartmentId"] = compartment_id
    return StoredProviderResourceRecord(
        id=str(candidate.get("candidateId") or "").strip(),
        engagement_id=str(candidate.get("engagementId") or "").strip(),
        engagement_name=str(candidate.get("engagementName") or "").strip(),
        provider=str(candidate.get("provider") or "").strip().lower(),
        resource_type=str(candidate.get("resourceType") or "").strip().lower(),
        resource_id=str(candidate.get("resourceId") or "").strip(),
        name=str(candidate.get("name") or "").strip(),
        region=str(candidate.get("region") or "").strip(),
        lifecycle_state=str(candidate.get("lifecycleState") or "unknown").strip(),
        status="tracked",
        source=str(candidate.get("source") or "provider_inventory").strip(),
        metadata=metadata,
        adoption_job_id=adoption_job_id,
        adopted_at=timestamp,
        updated_at=timestamp,
        destroyed_at=None,
    )


def _record_mark_destroyed_note(candidate: dict[str, Any], requested_by: str, repository: JobRepository) -> StoredJobRun:
    return _save_job(
        repository,
        action="provider_orphan_mark_destroyed_note",
        requested_by=requested_by,
        candidate=candidate,
        status="succeeded",
        events=[
            _event(
                1,
                "warning",
                "operator mark-destroyed note recorded without suppressing active provider finding",
                {
                    "candidate": candidate,
                    "mutation": False,
                    "suppressesProviderFinding": False,
                    "reason": "Provider inventory still reports this resource as active; Barragan keeps warning until provider reconciliation no longer sees it.",
                },
            )
        ],
    )


def _record_teardown_plan(candidate: dict[str, Any], requested_by: str, repository: JobRepository, confirmation_token: str) -> StoredJobRun:
    return _save_job(
        repository,
        action="provider_orphan_teardown_plan",
        requested_by=requested_by,
        candidate=candidate,
        status="succeeded",
        events=[
            _event(
                1,
                "info",
                "provider orphan teardown plan recorded",
                {
                    "candidate": candidate,
                    "mutation": False,
                    "confirmationToken": confirmation_token,
                    "supportedLiveMutation": _teardown_supported(candidate),
                    "nextStep": "Repeat with mutation=true and the confirmation token only after operator review.",
                },
            )
        ],
    )


def _run_provider_teardown(
    candidate: dict[str, Any],
    requested_by: str,
    repository: JobRepository,
    transport: ProviderCatalogTransport | None,
    orphan_candidates: list[dict[str, Any]] | None = None,
    *,
    job_id: str | None = None,
) -> StoredJobRun:
    provider = str(candidate.get("provider") or "").strip().lower()
    resource_type = str(candidate.get("resourceType") or "").strip().lower()
    resource_id = str(candidate.get("resourceId") or "").strip()
    existing = repository.get(job_id) if job_id else None
    events = list(existing.events) if existing is not None else [
        _event(1, "info", "provider orphan teardown requested", {"candidate": candidate, "mutation": True}),
    ]
    status = "succeeded"

    try:
        if not _candidate_is_barragan_owned(candidate):
            status = "failed"
            events.append(
                _event(
                    2,
                    "error",
                    "provider orphan teardown requires explicit Barragan ownership identity",
                    {
                        "provider": provider,
                        "resourceType": resource_type,
                        "resourceId": resource_id,
                        "barraganOwned": False,
                    },
                )
            )
        elif provider == "linode" and resource_type == "instance":
            _delete_linode_instance(resource_id, transport)
            events.append(_event(2, "info", "Linode instance delete requested", {"provider": provider, "resourceId": resource_id}))
        elif provider == "digitalocean" and resource_type == "droplet":
            _delete_digitalocean_droplet(resource_id, transport)
            events.append(_event(2, "info", "DigitalOcean droplet delete requested", {"provider": provider, "resourceId": resource_id}))
        elif provider == "oci" and resource_type in OCI_TEARDOWN_RESOURCE_TYPES:
            result = _teardown_oci_resources(candidate, orphan_candidates or [candidate])
            events.append(
                _event(
                    2,
                    "info",
                    _oci_teardown_message(candidate, result.resources),
                    {
                        "provider": provider,
                        "resourceId": resource_id,
                        "resourceType": resource_type,
                        "resourceCount": len(result.resources),
                        "commands": result.commands,
                    },
                )
            )
            events.append(
                _event(
                    3,
                    "info",
                    "OCI orphan teardown verification completed",
                    {
                        "provider": provider,
                        "resourceId": resource_id,
                        "resourceType": resource_type,
                        "verificationCommands": result.verification_commands,
                    },
                )
            )
        else:
            status = "failed"
            events.append(
                _event(
                    2,
                    "error",
                    "provider orphan teardown is not implemented for this resource type",
                    {
                        "provider": provider,
                        "resourceType": resource_type,
                        "supported": [
                            "linode instance",
                            "digitalocean droplet",
                            "oci compute_instance",
                            "oci subnet",
                            "oci route_table",
                            "oci internet_gateway",
                            "oci security_list",
                            "oci vcn",
                        ],
                    },
                )
            )
    except ProviderCatalogError as exc:
        status = "failed"
        events.append(_event(2, "error", "provider resource delete request failed", {"provider": provider, "detail": str(exc)}))
    except Exception as exc:
        status = "failed"
        events.append(
            _event(
                2,
                "error",
                "provider resource teardown failed",
                {"provider": provider, "errorType": type(exc).__name__},
            )
        )

    if existing is not None:
        return repository.save(
            StoredJobRun(
                id=existing.id,
                action=existing.action,
                status=status,
                target=existing.target,
                target_type=existing.target_type,
                target_id=existing.target_id,
                requested_by=existing.requested_by,
                input=existing.input,
                artifact_refs=existing.artifact_refs,
                created_at=existing.created_at,
                started_at=existing.started_at,
                finished_at=datetime.now(timezone.utc).isoformat(),
                events=events,
            )
        )
    return _save_job(repository, action="provider_orphan_teardown", requested_by=requested_by, candidate=candidate, status=status, events=events)


def _delete_linode_instance(resource_id: str, transport: ProviderCatalogTransport | None) -> None:
    if not resource_id:
        raise ProviderCatalogError("Linode resource id is required")
    token = provider_reconciliation._provider_token("linode")
    if not token:
        raise ProviderCatalogError("Linode default credential is unavailable")
    (transport or UrllibProviderCatalogTransport()).request(
        "https://api.linode.com/v4",
        "DELETE",
        f"/linode/instances/{resource_id}",
        token,
    )


def _delete_digitalocean_droplet(resource_id: str, transport: ProviderCatalogTransport | None) -> None:
    if not resource_id:
        raise ProviderCatalogError("DigitalOcean resource id is required")
    token = provider_reconciliation._provider_token("digitalocean")
    if not token:
        raise ProviderCatalogError("DigitalOcean default credential is unavailable")
    (transport or UrllibProviderCatalogTransport()).request(
        "https://api.digitalocean.com/v2",
        "DELETE",
        f"/droplets/{resource_id}",
        token,
    )


def _teardown_oci_resources(candidate: dict[str, Any], orphan_candidates: list[dict[str, Any]]) -> OciTeardownResult:
    target = OciDevelopmentTarget()
    try:
        target.validate()
    except OciSafetyError as exc:
        raise ProviderCatalogError(str(exc)) from exc

    resolution = resolve_oci_cli()
    if not resolution.ok:
        raise ProviderCatalogError(resolution.error or "OCI CLI is unavailable")

    resources = _oci_teardown_resources(candidate, orphan_candidates)
    commands: list[list[str]] = []
    for resource in resources:
        command = _oci_delete_command(resource, target, resolution.command or "oci")
        completed = _run_oci_command(command)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip() or "OCI resource delete failed"
            raise ProviderCatalogError(detail)
        commands.append(command)

    verification_commands = _verify_oci_resources_absent(resources, target, resolution.command or "oci")
    return OciTeardownResult(resources=resources, commands=commands, verification_commands=verification_commands)


def _oci_teardown_resources(candidate: dict[str, Any], orphan_candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    resource_type = str(candidate.get("resourceType") or "").strip().lower()
    if resource_type == "vcn":
        resources = [
            row
            for row in orphan_candidates
            if _same_oci_vcn_teardown_group(candidate, row)
            and str(row.get("resourceType") or "").strip().lower() in OCI_TEARDOWN_RESOURCE_TYPES
        ]
        if not any(str(row.get("candidateId") or "") == str(candidate.get("candidateId") or "") for row in resources):
            resources.append(candidate)
        return sorted(resources, key=_oci_teardown_sort_key)
    return [candidate]


def _same_oci_vcn_teardown_group(vcn_candidate: dict[str, Any], row: dict[str, Any]) -> bool:
    if str(row.get("provider") or "").strip().lower() != "oci":
        return False
    if not _candidate_is_barragan_owned(row):
        return False
    try:
        _validate_oci_candidate(row)
    except ProviderCatalogError:
        return False

    vcn_id = str(vcn_candidate.get("resourceId") or "").strip()
    row_resource_type = str(row.get("resourceType") or "").strip().lower()
    if row_resource_type == "vcn":
        return str(row.get("resourceId") or "").strip() == vcn_id

    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    if str(metadata.get("vcnId") or "").strip() == vcn_id:
        return True

    vcn_engagement_id = str(vcn_candidate.get("engagementId") or "").strip()
    row_engagement_id = str(row.get("engagementId") or "").strip()
    if vcn_engagement_id and row_engagement_id == vcn_engagement_id:
        return True

    vcn_engagement_name = str(vcn_candidate.get("engagementName") or "").strip().lower()
    row_engagement_name = str(row.get("engagementName") or "").strip().lower()
    return bool(vcn_engagement_name and row_engagement_name == vcn_engagement_name)


def _oci_teardown_sort_key(row: dict[str, Any]) -> tuple[int, str, str]:
    resource_type = str(row.get("resourceType") or "").strip().lower()
    return (
        OCI_GROUPED_VCN_TEARDOWN_ORDER.get(resource_type, 999),
        str(row.get("name") or ""),
        str(row.get("resourceId") or ""),
    )


def _validate_oci_candidate(candidate: dict[str, Any]) -> str:
    resource_id = str(candidate.get("resourceId") or "").strip()
    if not resource_id:
        raise ProviderCatalogError("OCI resource OCID is required")
    metadata = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
    target = OciDevelopmentTarget()
    try:
        target.validate()
    except OciSafetyError as exc:
        raise ProviderCatalogError(str(exc)) from exc

    compartment_id = str(metadata.get("compartmentId") or "").strip()
    if compartment_id and compartment_id != target.compartment_id:
        raise ProviderCatalogError("OCI orphan teardown is limited to the barragan-testing compartment")
    candidate_region = str(candidate.get("region") or "").strip()
    if candidate_region and candidate_region != target.region:
        raise ProviderCatalogError(f"OCI orphan teardown is limited to {target.region}")
    return resource_id


def _oci_delete_command(candidate: dict[str, Any], target: OciDevelopmentTarget, oci: str) -> list[str]:
    resource_type = str(candidate.get("resourceType") or "").strip().lower()
    resource_id = _validate_oci_candidate(candidate)
    base = [oci, "--auth", target.auth, "--region", target.region]
    if resource_type == "compute_instance":
        return [*base, "compute", "instance", "terminate", "--instance-id", resource_id, "--force"]
    if resource_type == "subnet":
        return [*base, "network", "subnet", "delete", "--subnet-id", resource_id, "--force"]
    if resource_type == "route_table":
        return [*base, "network", "route-table", "delete", "--rt-id", resource_id, "--force"]
    if resource_type == "internet_gateway":
        return [*base, "network", "internet-gateway", "delete", "--ig-id", resource_id, "--force"]
    if resource_type == "security_list":
        return [*base, "network", "security-list", "delete", "--security-list-id", resource_id, "--force"]
    if resource_type == "vcn":
        return [*base, "network", "vcn", "delete", "--vcn-id", resource_id, "--force"]
    raise ProviderCatalogError(f"OCI orphan teardown is not implemented for {resource_type}")


def _verify_oci_resources_absent(resources: list[dict[str, Any]], target: OciDevelopmentTarget, oci: str) -> list[list[str]]:
    verification_commands: list[list[str]] = []
    for resource_type in sorted({str(row.get("resourceType") or "").strip().lower() for row in resources}):
        command = _oci_list_command(resource_type, target, oci)
        completed = _run_oci_command(command)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip() or f"OCI {resource_type} verification failed"
            raise ProviderCatalogError(detail)
        verification_commands.append(command)
        try:
            body = json.loads(completed.stdout or "{}")
        except Exception as exc:
            raise ProviderCatalogError(f"OCI {resource_type} verification returned invalid JSON") from exc
        active_ids = _active_oci_resource_ids(body)
        remaining_ids = [
            str(row.get("resourceId") or "").strip()
            for row in resources
            if str(row.get("resourceType") or "").strip().lower() == resource_type
            and str(row.get("resourceId") or "").strip() in active_ids
        ]
        if remaining_ids:
            raise ProviderCatalogError(f"OCI {resource_type} teardown did not verify clean: {', '.join(remaining_ids)}")
    return verification_commands


def _oci_list_command(resource_type: str, target: OciDevelopmentTarget, oci: str) -> list[str]:
    base = [oci, "--auth", target.auth, "--region", target.region]
    scope = ["--compartment-id", target.compartment_id, "--all", "--output", "json"]
    if resource_type == "compute_instance":
        return [*base, "compute", "instance", "list", *scope]
    if resource_type == "subnet":
        return [*base, "network", "subnet", "list", *scope]
    if resource_type == "route_table":
        return [*base, "network", "route-table", "list", *scope]
    if resource_type == "internet_gateway":
        return [*base, "network", "internet-gateway", "list", *scope]
    if resource_type == "security_list":
        return [*base, "network", "security-list", "list", *scope]
    if resource_type == "vcn":
        return [*base, "network", "vcn", "list", *scope]
    raise ProviderCatalogError(f"OCI orphan verification is not implemented for {resource_type}")


def _active_oci_resource_ids(body: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for row in body.get("data", []):
        if not isinstance(row, dict):
            continue
        resource_id = str(row.get("id") or "").strip()
        state = str(row.get("lifecycle-state") or row.get("lifecycleState") or "").strip().lower()
        if resource_id and state not in OCI_TERMINAL_LIFECYCLE_STATES:
            ids.add(resource_id)
    return ids


def _oci_teardown_message(candidate: dict[str, Any], resources: list[dict[str, Any]]) -> str:
    resource_type = str(candidate.get("resourceType") or "").strip().lower()
    if resource_type == "vcn" and len(resources) > 1:
        return "OCI VCN recovery teardown requested for grouped core resources"
    if resource_type == "compute_instance":
        return "OCI compute instance terminate requested"
    return f"OCI {resource_type.replace('_', ' ')} delete requested"


def _run_oci_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=OCI_MUTATION_TIMEOUT_SECONDS, check=False)


def _teardown_supported(candidate: dict[str, Any]) -> bool:
    provider = str(candidate.get("provider") or "").strip().lower()
    resource_type = str(candidate.get("resourceType") or "").strip().lower()
    if not _candidate_is_barragan_owned(candidate):
        return False
    return (provider, resource_type) in {("linode", "instance"), ("digitalocean", "droplet")} or (
        provider == "oci" and resource_type in OCI_TEARDOWN_RESOURCE_TYPES
    )


def _candidate_is_barragan_owned(candidate: dict[str, Any]) -> bool:
    metadata = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
    return bool(metadata.get("barraganOwned"))


def _save_job(
    repository: JobRepository,
    *,
    job_id: str | None = None,
    action: str,
    requested_by: str,
    candidate: dict[str, Any],
    status: str,
    events: list[JobEvent],
) -> StoredJobRun:
    now = datetime.now(timezone.utc).isoformat()
    job = StoredJobRun(
        id=job_id or f"job-{uuid4().hex[:12]}",
        action=action,
        status=status,
        target=str(candidate.get("name") or candidate.get("resourceId") or candidate.get("candidateId") or "provider orphan"),
        target_type="provider_orphan",
        target_id=str(candidate.get("candidateId") or ""),
        requested_by=requested_by,
        input={
            "candidateId": candidate.get("candidateId") or "",
            "provider": candidate.get("provider") or "",
            "resourceType": candidate.get("resourceType") or "",
            "resourceId": candidate.get("resourceId") or "",
            "engagementId": candidate.get("engagementId") or "",
            "engagementName": candidate.get("engagementName") or "",
        },
        artifact_refs=[f"provider-orphan:{candidate.get('candidateId') or 'unknown'}"],
        created_at=now,
        started_at=now,
        finished_at=None if status in {"queued", "running"} else now,
        events=events,
    )
    return repository.save(job)


def _event(sequence: int, level: str, message: str, data: dict[str, Any]) -> JobEvent:
    return JobEvent(sequence=sequence, level=level, message=message, data=data)
